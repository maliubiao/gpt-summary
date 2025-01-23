Response:
The user wants a summary of the functionalities of the provided C++ code snippet, which is the second part of the `ssl_client_socket_impl.cc` file in Chromium's network stack.

I need to identify the main responsibilities of the code within this section, paying attention to:
- Handling the completion of the TLS handshake
- Certificate verification process
- Data reading and writing over the secure connection
- Client certificate handling
- Session management
- Error handling and logging
- Interaction with other components of the network stack

I will also look for connections to JavaScript functionalities, though given the nature of this code (low-level TLS handling), these might be indirect.

Finally, I need to synthesize a concise summary of the code's purpose.
这段代码是 `net/socket/ssl_client_socket_impl.cc` 文件的第二部分，主要负责 TLS 客户端连接建立后的处理，包括完成握手、验证证书、处理数据传输等。以下是其功能的归纳：

**主要功能归纳:**

1. **完成 TLS 握手并记录握手详情:**
   - `DoHandshakeComplete(int rv)`:  在 TLS 握手完成后被调用。
   - 记录协商的签名算法 (using `SSL_get_signature_algorithm`).
   - 获取并记录 SSL 信息 (using `GetSSLInfo`).
   - 判断并记录 TLS 握手的详细阶段 (如完整握手、会话恢复、False Start、TLS 1.3 的不同阶段等)，并通过 UMA 记录到 `Net.SSLHandshakeDetails`。
   - 记录是否支持 renegotiation_info 和 EMS 扩展。
   - 设置 `completed_connect_` 标志为 true。
   - 调用 `DoPeek()` 尝试读取数据，即使没有立即调用 Read，这对于处理 0-RTT 和延迟到达的 TLS 票据很重要。

2. **处理证书验证:**
   - `VerifyCertCallback(SSL* ssl, uint8_t* out_alert)`:  BoringSSL 调用的证书验证回调函数，用于启动证书验证流程。
   - `VerifyCert()`:  实际执行证书验证的逻辑。
     - 从 BoringSSL 获取服务器证书链 (`SSL_get0_peer_certificates`).
     - 使用 `x509_util::CreateX509CertificateFromBuffers` 创建 `X509Certificate` 对象。
     - 检查是否允许忽略此坏证书 (`IsAllowedBadCert`).
     - 如果提供了 ECH 名称覆盖 (`GetECHNameOverride`)，则使用覆盖的名称进行验证。
     - 获取 OCSP 响应和 SCT 列表。
     - 调用 `context_->cert_verifier()->Verify` 异步地进行证书验证。
   - `OnVerifyComplete(int result)`:  证书验证完成后的回调函数，更新 `cert_verification_result_`。
   - `HandleVerifyResult()`:  处理证书验证的结果。
     - 如果验证还在进行中，返回 `ssl_verify_retry`。
     - 如果验证完成，根据结果判断是否为致命错误。
     - 检查 HPKP 和 CT 的要求。
     - 将证书错误映射到相应的网络错误码。

3. **处理数据读取:**
   - `DoPayloadRead(IOBuffer* buf, int buf_len)`:  从 SSL 连接读取数据的核心函数。
     - 使用 `SSL_read` 从 OpenSSL 读取数据。
     - 处理 `SSL_ERROR_WANT_RENEGOTIATE` 错误，尝试重新协商。
     - 处理读取错误，包括 `SSL_ERROR_ZERO_RETURN` (连接关闭) 和客户端证书请求等情况。
     - 将 `ERR_CONNECTION_CLOSED` 映射为 EOF (0)。
     - 记录读取的字节数和错误信息。

4. **处理数据写入:**
   - `DoPayloadWrite()`:  向 SSL 连接写入数据的核心函数。
     - 使用 `SSL_write` 向 OpenSSL 写入数据。
     - 处理 `SSL_ERROR_WANT_PRIVATE_KEY_OPERATION` 错误。
     - 记录写入的字节数和错误信息。

5. **执行预读取 (Peek):**
   - `DoPeek()`:  在握手完成后尝试从 socket 预读取一个字节，用于及早处理 TLS 票据和检测连接状态。
   - 处理 0-RTT 早期数据被拒绝的情况，并记录拒绝原因。

6. **重试所有操作:**
   - `RetryAllOperations()`:  当底层 I/O 操作准备好重试时被调用，例如在异步私钥操作完成后。

7. **处理客户端证书请求:**
   - `ClientCertRequestCallback(SSL* ssl)`:  当服务器请求客户端证书时被 BoringSSL 调用。
   - 根据 `send_client_cert_` 标志和 `client_cert_` 是否存在来决定是否发送客户端证书。
   - 如果需要发送证书，则调用 `SetSSLChainAndKey` 设置证书链和私钥。

8. **处理新会话:**
   - `NewSessionCallback(SSL_SESSION* session)`:  当创建新的 SSL 会话时被 BoringSSL 调用。
   - 将新的会话添加到 SSL 客户端会话缓存中。

9. **私钥签名回调:**
   - `PrivateKeySignCallback(uint8_t* out, size_t* out_len, size_t max_out, uint16_t algorithm, const uint8_t* in, size_t in_len)`:  当需要使用客户端私钥进行签名时被 BoringSSL 调用。
   - 调用 `client_private_key_->Sign` 异步地进行签名操作。
   - `PrivateKeyCompleteCallback(uint8_t* out, size_t* out_len, size_t max_out)`:  私钥签名完成后被 BoringSSL 调用，将签名结果复制到输出缓冲区。
   - `OnPrivateKeyComplete(Error error, const std::vector<uint8_t>& signature)`:  私钥签名完成后的回调函数，记录结果并重试所有操作。

10. **消息回调:**
    - `MessageCallback(int is_write, int content_type, const void* buf, size_t len)`:  记录 SSL 握手过程中的消息，用于调试和日志记录。

11. **记录连接结束事件:**
    - `LogConnectEndEvent(int rv)`:  记录 SSL 连接结束事件，包括成功或失败。

12. **记录协商的协议:**
    - `RecordNegotiatedProtocol()`:  记录协商的 ALPN 协议。

13. **映射 OpenSSL 错误:**
    - `MapLastOpenSSLError(int ssl_error, const crypto::OpenSSLErrStackTracer& tracer, OpenSSLErrorInfo* info)`:  将 OpenSSL 错误码映射到 Chromium 的网络错误码。

14. **获取 ECH 名称覆盖:**
    - `GetECHNameOverride() const`: 获取加密客户端 Hello (ECH) 的名称覆盖。

15. **检查是否允许坏证书:**
    - `IsAllowedBadCert(X509Certificate* cert, CertStatus* cert_status) const`: 检查是否允许忽略特定的坏证书。

**与 JavaScript 的关系:**

此 C++ 代码主要处理底层的 TLS 连接建立和数据传输，与 JavaScript 的交互是间接的。JavaScript 通过 Chromium 的渲染进程发起网络请求，这些请求最终会通过网络栈到达这个 C++ 代码。

**举例说明:**

假设一个 JavaScript 代码发起一个 HTTPS 请求：

```javascript
fetch('https://example.com');
```

1. Chrome 的渲染进程会处理这个 `fetch` 请求。
2. 网络服务 (Network Service) 会创建一个 `SSLClientSocketImpl` 实例来建立与 `example.com` 的 TLS 连接.
3. 这段 C++ 代码负责执行 TLS 握手，包括证书验证。
4. 如果服务器需要客户端证书，`ClientCertRequestCallback` 会被调用。此时，如果 JavaScript 中通过 `navigator.mediaDevices.getUserMedia` 等 API 选择了证书，相关信息会被传递到 C++ 层。
5. TLS 握手成功后，JavaScript 发送的数据会通过 `DoPayloadWrite` 函数进行加密和发送。
6. 服务器返回的数据会通过 `DoPayloadRead` 函数接收和解密，最终传递回 JavaScript。

**逻辑推理和假设输入输出:**

假设输入：TLS 握手已完成，服务器发送了证书链。

- **输入 (到 `VerifyCert`)**:  从 OpenSSL 获取的服务器证书链。
- **处理**:  `VerifyCert` 函数会创建 `X509Certificate` 对象，并调用证书验证器进行验证。
- **输出 (通过 `HandleVerifyResult`)**:
    - 如果证书验证成功，`HandleVerifyResult` 返回 `ssl_verify_ok`。
    - 如果证书验证失败，`HandleVerifyResult` 返回 `ssl_verify_invalid`，并且会设置相应的网络错误码 (例如 `ERR_CERT_AUTHORITY_INVALID`)。

**用户或编程常见的使用错误:**

1. **客户端未安装必要的根证书:** 用户访问一个使用了自签名证书或者不常见 CA 签名的网站，会导致证书验证失败，`HandleVerifyResult` 会返回错误，最终浏览器会显示证书错误。
2. **客户端时间不正确:**  证书的有效期可能与客户端的时间不一致，导致证书验证失败。
3. **开发者错误地配置了 HSTS 或 Public Key Pinning:** 如果网站配置了 HSTS 或 Public Key Pinning，但服务器返回的证书不符合要求，`CheckPublicKeyPins` 会检测到错误，`HandleVerifyResult` 会返回 `ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN`。
4. **忘记处理 `ERR_SSL_CLIENT_AUTH_CERT_NEEDED` 错误:** 当服务器请求客户端证书但客户端没有提供时，`DoPayloadRead` 会返回此错误。开发者需要在应用层处理此错误，例如提示用户选择证书。

**用户操作如何一步步到达这里 (调试线索):**

1. 用户在浏览器地址栏输入 `https://example.com` 并回车。
2. 浏览器发起一个导航请求。
3. 网络服务创建一个 `SSLClientSocketImpl` 实例来建立与 `example.com` 的连接。
4. `DoConnect` 函数开始执行 TLS 握手。
5. 在握手过程中，如果需要验证服务器证书，会调用 `VerifyCertCallback` 和 `VerifyCert`。
6. 如果握手成功完成，会调用 `DoHandshakeComplete`。
7. 当需要发送数据时，例如 JavaScript 发起 `fetch` 请求，会调用 `DoPayloadWrite`。
8. 当接收到数据时，会调用 `DoPayloadRead`。

如果在调试过程中发现连接问题，可以在 Chrome 的 `chrome://net-export/` 页面录制网络日志，查看 `SSL_CONNECT` 事件及其子事件，可以追踪到 `VerifyCert` 的调用和证书验证的结果，以及数据传输过程中的 `SSL_SOCKET_BYTES_SENT` 和 `SSL_SOCKET_BYTES_RECEIVED` 事件。

总而言之，这段代码是 Chromium 网络栈中处理 HTTPS 连接的关键部分，负责安全连接的建立、维护和数据传输，并与浏览器的其他组件协同工作，最终为用户提供安全的浏览体验。

### 提示词
```
这是目录为net/socket/ssl_client_socket_impl.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ure_algorithm(ssl_.get());
  if (signature_algorithm != 0) {
    base::UmaHistogramSparse("Net.SSLSignatureAlgorithm", signature_algorithm);
  }

  SSLInfo ssl_info;
  bool ok = GetSSLInfo(&ssl_info);
  // Ensure the verify callback was called, and got far enough to fill
  // in server_cert_.
  CHECK(ok);

  SSLHandshakeDetails details;
  if (SSL_version(ssl_.get()) < TLS1_3_VERSION) {
    if (SSL_session_reused(ssl_.get())) {
      details = SSLHandshakeDetails::kTLS12Resume;
    } else if (SSL_in_false_start(ssl_.get())) {
      details = SSLHandshakeDetails::kTLS12FalseStart;
    } else {
      details = SSLHandshakeDetails::kTLS12Full;
    }
  } else {
    bool used_hello_retry_request = SSL_used_hello_retry_request(ssl_.get());
    if (SSL_in_early_data(ssl_.get())) {
      DCHECK(!used_hello_retry_request);
      details = SSLHandshakeDetails::kTLS13Early;
    } else if (SSL_session_reused(ssl_.get())) {
      details = used_hello_retry_request
                    ? SSLHandshakeDetails::kTLS13ResumeWithHelloRetryRequest
                    : SSLHandshakeDetails::kTLS13Resume;
    } else {
      details = used_hello_retry_request
                    ? SSLHandshakeDetails::kTLS13FullWithHelloRetryRequest
                    : SSLHandshakeDetails::kTLS13Full;
    }
  }
  UMA_HISTOGRAM_ENUMERATION("Net.SSLHandshakeDetails", details);

  // Measure TLS connections that implement the renegotiation_info and EMS
  // extensions. TLS 1.3 is already patched for both bugs, so these functions
  // record true in TLS 1.3 although the extensions are not actually negotiated.
  // See https://crbug.com/850800.
  base::UmaHistogramBoolean("Net.SSLRenegotiationInfoSupported",
                            SSL_get_secure_renegotiation_support(ssl_.get()));
  base::UmaHistogramBoolean("Net.SSLExtendedMainSecretSupported",
                            SSL_get_extms_support(ssl_.get()));

  completed_connect_ = true;
  next_handshake_state_ = STATE_NONE;

  // Read from the transport immediately after the handshake, whether Read() is
  // called immediately or not. This serves several purposes:
  //
  // First, if this socket is preconnected and negotiates 0-RTT, the ServerHello
  // will not be processed. See https://crbug.com/950706
  //
  // Second, in False Start and TLS 1.3, the tickets arrive after immediately
  // after the handshake. This allows preconnected sockets to process the
  // tickets sooner. This also avoids a theoretical deadlock if the tickets are
  // too large. See
  // https://boringssl-review.googlesource.com/c/boringssl/+/34948.
  //
  // TODO(crbug.com/41456237): It is also a step in making TLS 1.3 client
  // certificate alerts less unreliable.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&SSLClientSocketImpl::DoPeek, weak_factory_.GetWeakPtr()));

  return OK;
}

ssl_verify_result_t SSLClientSocketImpl::VerifyCertCallback(
    SSL* ssl,
    uint8_t* out_alert) {
  SSLClientSocketImpl* socket =
      SSLContext::GetInstance()->GetClientSocketFromSSL(ssl);
  DCHECK(socket);
  return socket->VerifyCert();
}

// This function is called by BoringSSL, so it has to return an
// ssl_verify_result_t. When specific //net errors need to be
// returned, use OpenSSLPutNetError to add them directly to the
// OpenSSL error queue.
ssl_verify_result_t SSLClientSocketImpl::VerifyCert() {
  if (cert_verification_result_ != kCertVerifyPending) {
    // The certificate verifier updates cert_verification_result_ when
    // it returns asynchronously. If there is a result in
    // cert_verification_result_, return it instead of triggering
    // another verify.
    return HandleVerifyResult();
  }

  // In this configuration, BoringSSL will perform exactly one certificate
  // verification, so there cannot be state from a previous verification.
  CHECK(!server_cert_);
  server_cert_ = x509_util::CreateX509CertificateFromBuffers(
      SSL_get0_peer_certificates(ssl_.get()));

  // OpenSSL decoded the certificate, but the X509Certificate implementation
  // could not. This is treated as a fatal SSL-level protocol error rather than
  // a certificate error. See https://crbug.com/91341.
  if (!server_cert_) {
    OpenSSLPutNetError(FROM_HERE, ERR_SSL_SERVER_CERT_BAD_FORMAT);
    return ssl_verify_invalid;
  }

  net_log_.AddEvent(NetLogEventType::SSL_CERTIFICATES_RECEIVED, [&] {
    return base::Value::Dict().Set(
        "certificates", NetLogX509CertificateList(server_cert_.get()));
  });

  // If the certificate is bad and has been previously accepted, use
  // the previous status and bypass the error.
  CertStatus cert_status;
  if (IsAllowedBadCert(server_cert_.get(), &cert_status)) {
    server_cert_verify_result_.Reset();
    server_cert_verify_result_.cert_status = cert_status;
    server_cert_verify_result_.verified_cert = server_cert_;
    cert_verification_result_ = OK;
    return HandleVerifyResult();
  }

  std::string_view ech_name_override = GetECHNameOverride();
  if (!ech_name_override.empty()) {
    // If ECH was offered but not negotiated, BoringSSL will ask to verify a
    // different name than the origin. If verification succeeds, we continue the
    // handshake, but BoringSSL will not report success from SSL_do_handshake().
    // If all else succeeds, BoringSSL will report |SSL_R_ECH_REJECTED|, mapped
    // to |ERR_R_ECH_NOT_NEGOTIATED|. |ech_name_override| is only used to
    // authenticate GetECHRetryConfigs().
    DCHECK(!ssl_config_.ech_config_list.empty());
    used_ech_name_override_ = true;

    // CertVerifier::Verify takes a string host and internally interprets it as
    // either a DNS name or IP address. However, the ECH public name is only
    // defined to be an DNS name. Thus, reject all public names that would not
    // be interpreted as IP addresses. Distinguishing IPv4 literals from DNS
    // names varies by spec, however. BoringSSL internally checks for an LDH
    // string, and that the last component is non-numeric. This should be
    // sufficient for the web, but check with Chromium's parser, in case they
    // diverge.
    //
    // See section 6.1.7 of draft-ietf-tls-esni-13.
    if (HostIsIPAddressNoBrackets(ech_name_override)) {
      NOTREACHED();
    }
  }

  const uint8_t* ocsp_response_raw;
  size_t ocsp_response_len;
  SSL_get0_ocsp_response(ssl_.get(), &ocsp_response_raw, &ocsp_response_len);
  std::string_view ocsp_response(
      reinterpret_cast<const char*>(ocsp_response_raw), ocsp_response_len);

  const uint8_t* sct_list_raw;
  size_t sct_list_len;
  SSL_get0_signed_cert_timestamp_list(ssl_.get(), &sct_list_raw, &sct_list_len);
  std::string_view sct_list(reinterpret_cast<const char*>(sct_list_raw),
                            sct_list_len);

  cert_verification_result_ = context_->cert_verifier()->Verify(
      CertVerifier::RequestParams(
          server_cert_,
          ech_name_override.empty() ? host_and_port_.host() : ech_name_override,
          ssl_config_.GetCertVerifyFlags(), std::string(ocsp_response),
          std::string(sct_list)),
      &server_cert_verify_result_,
      base::BindOnce(&SSLClientSocketImpl::OnVerifyComplete,
                     base::Unretained(this)),
      &cert_verifier_request_, net_log_);

  return HandleVerifyResult();
}

void SSLClientSocketImpl::OnVerifyComplete(int result) {
  cert_verification_result_ = result;
  // In handshake phase. The parameter to OnHandshakeIOComplete is unused.
  OnHandshakeIOComplete(OK);
}

ssl_verify_result_t SSLClientSocketImpl::HandleVerifyResult() {
  // Verification is in progress. Inform BoringSSL it should retry the
  // callback later. The next call to VerifyCertCallback will be a
  // continuation of the same verification, so leave
  // cert_verification_result_ as-is.
  if (cert_verification_result_ == ERR_IO_PENDING)
    return ssl_verify_retry;

  // In BoringSSL's calling convention for asynchronous callbacks,
  // after a callback returns a non-retry value, the operation has
  // completed. Subsequent calls are of new operations with potentially
  // different arguments. Reset cert_verification_result_ to inform
  // VerifyCertCallback not to replay the result on subsequent calls.
  int result = cert_verification_result_;
  cert_verification_result_ = kCertVerifyPending;

  cert_verifier_request_.reset();

  // If the connection was good, check HPKP and CT status simultaneously,
  // but prefer to treat the HPKP error as more serious, if there was one.
  if (result == OK) {
    int ct_result = CheckCTRequirements();
    TransportSecurityState::PKPStatus pin_validity =
        context_->transport_security_state()->CheckPublicKeyPins(
            host_and_port_, server_cert_verify_result_.is_issued_by_known_root,
            server_cert_verify_result_.public_key_hashes);
    switch (pin_validity) {
      case TransportSecurityState::PKPStatus::VIOLATED:
        server_cert_verify_result_.cert_status |=
            CERT_STATUS_PINNED_KEY_MISSING;
        result = ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN;
        break;
      case TransportSecurityState::PKPStatus::BYPASSED:
        pkp_bypassed_ = true;
        [[fallthrough]];
      case TransportSecurityState::PKPStatus::OK:
        // Do nothing.
        break;
    }
    if (result != ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN && ct_result != OK)
      result = ct_result;
  }

  is_fatal_cert_error_ =
      IsCertStatusError(server_cert_verify_result_.cert_status) &&
      result != ERR_CERT_KNOWN_INTERCEPTION_BLOCKED &&
      context_->transport_security_state()->ShouldSSLErrorsBeFatal(
          host_and_port_.host());

  if (IsCertificateError(result)) {
    if (!GetECHNameOverride().empty()) {
      // Certificate exceptions are only applicable for the origin name. For
      // simplicity, we do not allow certificate exceptions for the public name
      // and map all bypassable errors to fatal ones.
      result = ERR_ECH_FALLBACK_CERTIFICATE_INVALID;
    }
    if (ssl_config_.ignore_certificate_errors) {
      result = OK;
    }
  }

  if (result == OK) {
    return ssl_verify_ok;
  }

  OpenSSLPutNetError(FROM_HERE, result);
  return ssl_verify_invalid;
}

int SSLClientSocketImpl::CheckCTRequirements() {
  TransportSecurityState::CTRequirementsStatus ct_requirement_status =
      context_->transport_security_state()->CheckCTRequirements(
          host_and_port_, server_cert_verify_result_.is_issued_by_known_root,
          server_cert_verify_result_.public_key_hashes,
          server_cert_verify_result_.verified_cert.get(),
          server_cert_verify_result_.policy_compliance);

  if (context_->sct_auditing_delegate()) {
    context_->sct_auditing_delegate()->MaybeEnqueueReport(
        host_and_port_, server_cert_verify_result_.verified_cert.get(),
        server_cert_verify_result_.scts);
  }

  switch (ct_requirement_status) {
    case TransportSecurityState::CT_REQUIREMENTS_NOT_MET:
      server_cert_verify_result_.cert_status |=
          CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED;
      return ERR_CERTIFICATE_TRANSPARENCY_REQUIRED;
    case TransportSecurityState::CT_REQUIREMENTS_MET:
    case TransportSecurityState::CT_NOT_REQUIRED:
      return OK;
  }

  NOTREACHED();
}

void SSLClientSocketImpl::DoConnectCallback(int rv) {
  if (!user_connect_callback_.is_null()) {
    std::move(user_connect_callback_).Run(rv > OK ? OK : rv);
  }
}

void SSLClientSocketImpl::OnHandshakeIOComplete(int result) {
  int rv = DoHandshakeLoop(result);
  if (rv != ERR_IO_PENDING) {
    if (in_confirm_handshake_) {
      in_confirm_handshake_ = false;
      net_log_.EndEvent(NetLogEventType::SSL_CONFIRM_HANDSHAKE);
    } else {
      LogConnectEndEvent(rv);
    }
    DoConnectCallback(rv);
  }
}

int SSLClientSocketImpl::DoHandshakeLoop(int last_io_result) {
  TRACE_EVENT0(NetTracingCategory(), "SSLClientSocketImpl::DoHandshakeLoop");
  int rv = last_io_result;
  do {
    // Default to STATE_NONE for next state.
    // (This is a quirk carried over from the windows
    // implementation.  It makes reading the logs a bit harder.)
    // State handlers can and often do call GotoState just
    // to stay in the current state.
    State state = next_handshake_state_;
    next_handshake_state_ = STATE_NONE;
    switch (state) {
      case STATE_HANDSHAKE:
        rv = DoHandshake();
        break;
      case STATE_HANDSHAKE_COMPLETE:
        rv = DoHandshakeComplete(rv);
        break;
      case STATE_NONE:
      default:
        NOTREACHED() << "unexpected state" << state;
    }
  } while (rv != ERR_IO_PENDING && next_handshake_state_ != STATE_NONE);
  return rv;
}

int SSLClientSocketImpl::DoPayloadRead(IOBuffer* buf, int buf_len) {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  DCHECK_LT(0, buf_len);
  DCHECK(buf);

  int rv;
  if (pending_read_error_ != kSSLClientSocketNoPendingResult) {
    rv = pending_read_error_;
    pending_read_error_ = kSSLClientSocketNoPendingResult;
    if (rv == 0) {
      net_log_.AddByteTransferEvent(NetLogEventType::SSL_SOCKET_BYTES_RECEIVED,
                                    rv, buf->data());
    } else {
      NetLogOpenSSLError(net_log_, NetLogEventType::SSL_READ_ERROR, rv,
                         pending_read_ssl_error_, pending_read_error_info_);
    }
    pending_read_ssl_error_ = SSL_ERROR_NONE;
    pending_read_error_info_ = OpenSSLErrorInfo();
    return rv;
  }

  int total_bytes_read = 0;
  int ssl_ret, ssl_err;
  do {
    ssl_ret = SSL_read(ssl_.get(), buf->data() + total_bytes_read,
                       buf_len - total_bytes_read);
    ssl_err = SSL_get_error(ssl_.get(), ssl_ret);
    if (ssl_ret > 0) {
      total_bytes_read += ssl_ret;
    } else if (ssl_err == SSL_ERROR_WANT_RENEGOTIATE) {
      if (!SSL_renegotiate(ssl_.get())) {
        ssl_err = SSL_ERROR_SSL;
      }
    }
    // Continue processing records as long as there is more data available
    // synchronously.
  } while (ssl_err == SSL_ERROR_WANT_RENEGOTIATE ||
           (total_bytes_read < buf_len && ssl_ret > 0 &&
            transport_adapter_->HasPendingReadData()));

  // Although only the final SSL_read call may have failed, the failure needs to
  // processed immediately, while the information still available in OpenSSL's
  // error queue.
  if (ssl_ret <= 0) {
    pending_read_ssl_error_ = ssl_err;
    if (pending_read_ssl_error_ == SSL_ERROR_ZERO_RETURN) {
      pending_read_error_ = 0;
    } else if (pending_read_ssl_error_ == SSL_ERROR_WANT_X509_LOOKUP &&
               !send_client_cert_) {
      pending_read_error_ = ERR_SSL_CLIENT_AUTH_CERT_NEEDED;
    } else if (pending_read_ssl_error_ ==
               SSL_ERROR_WANT_PRIVATE_KEY_OPERATION) {
      DCHECK(client_private_key_);
      DCHECK_NE(kSSLClientSocketNoPendingResult, signature_result_);
      pending_read_error_ = ERR_IO_PENDING;
    } else {
      pending_read_error_ = MapLastOpenSSLError(
          pending_read_ssl_error_, err_tracer, &pending_read_error_info_);
    }

    // Many servers do not reliably send a close_notify alert when shutting down
    // a connection, and instead terminate the TCP connection. This is reported
    // as ERR_CONNECTION_CLOSED. Because of this, map the unclean shutdown to a
    // graceful EOF, instead of treating it as an error as it should be.
    if (pending_read_error_ == ERR_CONNECTION_CLOSED)
      pending_read_error_ = 0;
  }

  if (total_bytes_read > 0) {
    // Return any bytes read to the caller. The error will be deferred to the
    // next call of DoPayloadRead.
    rv = total_bytes_read;

    // Do not treat insufficient data as an error to return in the next call to
    // DoPayloadRead() - instead, let the call fall through to check SSL_read()
    // again. The transport may have data available by then.
    if (pending_read_error_ == ERR_IO_PENDING)
      pending_read_error_ = kSSLClientSocketNoPendingResult;
  } else {
    // No bytes were returned. Return the pending read error immediately.
    DCHECK_NE(kSSLClientSocketNoPendingResult, pending_read_error_);
    rv = pending_read_error_;
    pending_read_error_ = kSSLClientSocketNoPendingResult;
  }

  if (rv >= 0) {
    net_log_.AddByteTransferEvent(NetLogEventType::SSL_SOCKET_BYTES_RECEIVED,
                                  rv, buf->data());
  } else if (rv != ERR_IO_PENDING) {
    NetLogOpenSSLError(net_log_, NetLogEventType::SSL_READ_ERROR, rv,
                       pending_read_ssl_error_, pending_read_error_info_);
    pending_read_ssl_error_ = SSL_ERROR_NONE;
    pending_read_error_info_ = OpenSSLErrorInfo();
  }
  return rv;
}

int SSLClientSocketImpl::DoPayloadWrite() {
  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);
  int rv = SSL_write(ssl_.get(), user_write_buf_->data(), user_write_buf_len_);

  if (rv >= 0) {
    CHECK_LE(rv, user_write_buf_len_);
    net_log_.AddByteTransferEvent(NetLogEventType::SSL_SOCKET_BYTES_SENT, rv,
                                  user_write_buf_->data());
    return rv;
  }

  int ssl_error = SSL_get_error(ssl_.get(), rv);
  if (ssl_error == SSL_ERROR_WANT_PRIVATE_KEY_OPERATION)
    return ERR_IO_PENDING;
  OpenSSLErrorInfo error_info;
  int net_error = MapLastOpenSSLError(ssl_error, err_tracer, &error_info);

  if (net_error != ERR_IO_PENDING) {
    NetLogOpenSSLError(net_log_, NetLogEventType::SSL_WRITE_ERROR, net_error,
                       ssl_error, error_info);
  }
  return net_error;
}

void SSLClientSocketImpl::DoPeek() {
  if (!completed_connect_) {
    return;
  }

  crypto::OpenSSLErrStackTracer err_tracer(FROM_HERE);

  if (ssl_config_.early_data_enabled && !handled_early_data_result_) {
    // |SSL_peek| will implicitly run |SSL_do_handshake| if needed, but run it
    // manually to pick up the reject reason.
    int rv = SSL_do_handshake(ssl_.get());
    int ssl_err = SSL_get_error(ssl_.get(), rv);
    int err = rv > 0 ? OK : MapOpenSSLError(ssl_err, err_tracer);
    if (err == ERR_IO_PENDING) {
      return;
    }

    // Since the two-parameter version of the macro (which asks for a max value)
    // requires that the max value sentinel be named |kMaxValue|, transform the
    // max-value sentinel into a one-past-the-end ("boundary") sentinel by
    // adding 1, in order to be able to use the three-parameter macro.
    ssl_early_data_reason_t early_data_reason =
        SSL_get_early_data_reason(ssl_.get());
    UMA_HISTOGRAM_ENUMERATION("Net.SSLHandshakeEarlyDataReason",
                              early_data_reason,
                              ssl_early_data_reason_max_value + 1);
    if (IsGoogleHost(host_and_port_.host())) {
      // Most Google hosts are known to implement 0-RTT, so this gives more
      // targeted metrics as we initially roll out client support. See
      // https://crbug.com/641225.
      UMA_HISTOGRAM_ENUMERATION("Net.SSLHandshakeEarlyDataReason.Google",
                                early_data_reason,
                                ssl_early_data_reason_max_value + 1);
    }
    net_log_.AddEvent(NetLogEventType::SSL_HANDSHAKE_EARLY_DATA_REASON, [&] {
      base::Value::Dict dict;
      dict.Set("early_data_reason", early_data_reason);
      return dict;
    });

    // On early data reject, clear early data on any other sessions in the
    // cache, so retries do not get stuck attempting 0-RTT. See
    // https://crbug.com/1066623.
    if (err == ERR_EARLY_DATA_REJECTED ||
        err == ERR_WRONG_VERSION_ON_EARLY_DATA) {
      context_->ssl_client_session_cache()->ClearEarlyData(
          GetSessionCacheKey(std::nullopt));
    }

    handled_early_data_result_ = true;

    if (err != OK) {
      peek_complete_ = true;
      return;
    }
  }

  if (ssl_config_.disable_post_handshake_peek_for_testing || peek_complete_) {
    return;
  }

  char byte;
  int rv = SSL_peek(ssl_.get(), &byte, 1);
  int ssl_err = SSL_get_error(ssl_.get(), rv);
  if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
    peek_complete_ = true;
  }
}

void SSLClientSocketImpl::RetryAllOperations() {
  // SSL_do_handshake, SSL_read, and SSL_write may all be retried when blocked,
  // so retry all operations for simplicity. (Otherwise, SSL_get_error for each
  // operation may be remembered to retry only the blocked ones.)

  // Performing these callbacks may cause |this| to be deleted. If this
  // happens, the other callbacks should not be invoked. Guard against this by
  // holding a WeakPtr to |this| and ensuring it's still valid.
  base::WeakPtr<SSLClientSocketImpl> guard(weak_factory_.GetWeakPtr());
  if (next_handshake_state_ == STATE_HANDSHAKE) {
    // In handshake phase. The parameter to OnHandshakeIOComplete is unused.
    OnHandshakeIOComplete(OK);
  }

  if (!guard.get())
    return;

  DoPeek();

  int rv_read = ERR_IO_PENDING;
  int rv_write = ERR_IO_PENDING;
  if (user_read_buf_) {
    rv_read = DoPayloadRead(user_read_buf_.get(), user_read_buf_len_);
  } else if (!user_read_callback_.is_null()) {
    // ReadIfReady() is called by the user. Skip DoPayloadRead() and just let
    // the user know that read can be retried.
    rv_read = OK;
  }

  if (user_write_buf_)
    rv_write = DoPayloadWrite();

  if (rv_read != ERR_IO_PENDING)
    DoReadCallback(rv_read);

  if (!guard.get())
    return;

  if (rv_write != ERR_IO_PENDING)
    DoWriteCallback(rv_write);
}

int SSLClientSocketImpl::ClientCertRequestCallback(SSL* ssl) {
  DCHECK(ssl == ssl_.get());

  net_log_.AddEvent(NetLogEventType::SSL_CLIENT_CERT_REQUESTED);
  certificate_requested_ = true;

  // Clear any currently configured certificates.
  SSL_certs_clear(ssl_.get());

#if !BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)
  LOG(WARNING) << "Client auth is not supported";
#else   // BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)
  if (!send_client_cert_) {
    // First pass: we know that a client certificate is needed, but we do not
    // have one at hand. Suspend the handshake. SSL_get_error will return
    // SSL_ERROR_WANT_X509_LOOKUP.
    return -1;
  }

  // Second pass: a client certificate should have been selected.
  if (client_cert_.get()) {
    if (!client_private_key_) {
      // The caller supplied a null private key. Fail the handshake and surface
      // an appropriate error to the caller.
      LOG(WARNING) << "Client cert found without private key";
      OpenSSLPutNetError(FROM_HERE, ERR_SSL_CLIENT_AUTH_CERT_NO_PRIVATE_KEY);
      return -1;
    }

    if (!SetSSLChainAndKey(ssl_.get(), client_cert_.get(), nullptr,
                           &SSLContext::kPrivateKeyMethod)) {
      OpenSSLPutNetError(FROM_HERE, ERR_SSL_CLIENT_AUTH_CERT_BAD_FORMAT);
      return -1;
    }

    std::vector<uint16_t> preferences =
        client_private_key_->GetAlgorithmPreferences();
    // If the key supports rsa_pkcs1_sha256, automatically add support for
    // rsa_pkcs1_sha256_legacy, for use with TLS 1.3. We convert here so that
    // not every `SSLPrivateKey` needs to implement it explicitly.
    if (base::FeatureList::IsEnabled(features::kLegacyPKCS1ForTLS13) &&
        base::Contains(preferences, SSL_SIGN_RSA_PKCS1_SHA256)) {
      preferences.push_back(SSL_SIGN_RSA_PKCS1_SHA256_LEGACY);
    }
    SSL_set_signing_algorithm_prefs(ssl_.get(), preferences.data(),
                                    preferences.size());

    net_log_.AddEventWithIntParams(
        NetLogEventType::SSL_CLIENT_CERT_PROVIDED, "cert_count",
        base::checked_cast<int>(1 +
                                client_cert_->intermediate_buffers().size()));
    return 1;
  }
#endif  // !BUILDFLAG(ENABLE_CLIENT_CERTIFICATES)

  // Send no client certificate.
  net_log_.AddEventWithIntParams(NetLogEventType::SSL_CLIENT_CERT_PROVIDED,
                                 "cert_count", 0);
  return 1;
}

int SSLClientSocketImpl::NewSessionCallback(SSL_SESSION* session) {
  if (!IsCachingEnabled())
    return 0;

  std::optional<IPAddress> ip_addr;
  if (SSL_CIPHER_get_kx_nid(SSL_SESSION_get0_cipher(session)) == NID_kx_rsa) {
    // If RSA key exchange was used, additionally key the cache with the
    // destination IP address. Of course, if a proxy is being used, the
    // semantics of this are a little complex, but we're doing our best. See
    // https://crbug.com/969684
    IPEndPoint ip_endpoint;
    if (stream_socket_->GetPeerAddress(&ip_endpoint) != OK) {
      return 0;
    }
    ip_addr = ip_endpoint.address();
  }

  // OpenSSL optionally passes ownership of |session|. Returning one signals
  // that this function has claimed it.
  context_->ssl_client_session_cache()->Insert(
      GetSessionCacheKey(ip_addr), bssl::UniquePtr<SSL_SESSION>(session));
  return 1;
}

SSLClientSessionCache::Key SSLClientSocketImpl::GetSessionCacheKey(
    std::optional<IPAddress> dest_ip_addr) const {
  SSLClientSessionCache::Key key;
  key.server = host_and_port_;
  key.dest_ip_addr = dest_ip_addr;
  if (NetworkAnonymizationKey::IsPartitioningEnabled()) {
    key.network_anonymization_key = ssl_config_.network_anonymization_key;
  }
  key.privacy_mode = ssl_config_.privacy_mode;
  return key;
}

bool SSLClientSocketImpl::IsRenegotiationAllowed() const {
  if (negotiated_protocol_ == kProtoUnknown)
    return ssl_config_.renego_allowed_default;

  for (NextProto allowed : ssl_config_.renego_allowed_for_protos) {
    if (negotiated_protocol_ == allowed)
      return true;
  }
  return false;
}

bool SSLClientSocketImpl::IsCachingEnabled() const {
  return context_->ssl_client_session_cache() != nullptr;
}

ssl_private_key_result_t SSLClientSocketImpl::PrivateKeySignCallback(
    uint8_t* out,
    size_t* out_len,
    size_t max_out,
    uint16_t algorithm,
    const uint8_t* in,
    size_t in_len) {
  DCHECK_EQ(kSSLClientSocketNoPendingResult, signature_result_);
  DCHECK(signature_.empty());
  DCHECK(client_private_key_);

  net_log_.BeginEvent(NetLogEventType::SSL_PRIVATE_KEY_OP, [&] {
    return NetLogPrivateKeyOperationParams(
        algorithm,
        // Pass the SSLPrivateKey pointer to avoid making copies of the
        // provider name in the common case with logging disabled.
        client_private_key_.get());
  });
  base::UmaHistogramSparse("Net.SSLClientCertSignatureAlgorithm", algorithm);

  // Map rsa_pkcs1_sha256_legacy back to rsa_pkcs1_sha256. We convert it here,
  // so that not every `SSLPrivateKey` needs to implement it explicitly.
  if (base::FeatureList::IsEnabled(features::kLegacyPKCS1ForTLS13) &&
      algorithm == SSL_SIGN_RSA_PKCS1_SHA256_LEGACY) {
    algorithm = SSL_SIGN_RSA_PKCS1_SHA256;
  }

  signature_result_ = ERR_IO_PENDING;
  client_private_key_->Sign(
      algorithm, base::make_span(in, in_len),
      base::BindOnce(&SSLClientSocketImpl::OnPrivateKeyComplete,
                     weak_factory_.GetWeakPtr()));
  return ssl_private_key_retry;
}

ssl_private_key_result_t SSLClientSocketImpl::PrivateKeyCompleteCallback(
    uint8_t* out,
    size_t* out_len,
    size_t max_out) {
  DCHECK_NE(kSSLClientSocketNoPendingResult, signature_result_);
  DCHECK(client_private_key_);

  if (signature_result_ == ERR_IO_PENDING)
    return ssl_private_key_retry;
  if (signature_result_ != OK) {
    OpenSSLPutNetError(FROM_HERE, signature_result_);
    return ssl_private_key_failure;
  }
  if (signature_.size() > max_out) {
    OpenSSLPutNetError(FROM_HERE, ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED);
    return ssl_private_key_failure;
  }
  memcpy(out, signature_.data(), signature_.size());
  *out_len = signature_.size();
  signature_.clear();
  return ssl_private_key_success;
}

void SSLClientSocketImpl::OnPrivateKeyComplete(
    Error error,
    const std::vector<uint8_t>& signature) {
  DCHECK_EQ(ERR_IO_PENDING, signature_result_);
  DCHECK(signature_.empty());
  DCHECK(client_private_key_);

  net_log_.EndEventWithNetErrorCode(NetLogEventType::SSL_PRIVATE_KEY_OP, error);

  signature_result_ = error;
  if (signature_result_ == OK)
    signature_ = signature;

  // During a renegotiation, either Read or Write calls may be blocked on an
  // asynchronous private key operation.
  RetryAllOperations();
}

void SSLClientSocketImpl::MessageCallback(int is_write,
                                          int content_type,
                                          const void* buf,
                                          size_t len) {
  switch (content_type) {
    case SSL3_RT_ALERT:
      net_log_.AddEvent(is_write ? NetLogEventType::SSL_ALERT_SENT
                                 : NetLogEventType::SSL_ALERT_RECEIVED,
                        [&] { return NetLogSSLAlertParams(buf, len); });
      break;
    case SSL3_RT_HANDSHAKE:
      net_log_.AddEvent(
          is_write ? NetLogEventType::SSL_HANDSHAKE_MESSAGE_SENT
                   : NetLogEventType::SSL_HANDSHAKE_MESSAGE_RECEIVED,
          [&](NetLogCaptureMode capture_mode) {
            return NetLogSSLMessageParams(!!is_write, buf, len, capture_mode);
          });
      break;
    case SSL3_RT_CLIENT_HELLO_INNER:
      DCHECK(is_write);
      net_log_.AddEvent(NetLogEventType::SSL_ENCRYPTED_CLIENT_HELLO,
                        [&](NetLogCaptureMode capture_mode) {
                          return NetLogSSLMessageParams(!!is_write, buf, len,
                                                        capture_mode);
                        });
      break;
  }
}

void SSLClientSocketImpl::LogConnectEndEvent(int rv) {
  if (rv != OK) {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::SSL_CONNECT, rv);
    return;
  }

  net_log_.EndEvent(NetLogEventType::SSL_CONNECT,
                    [&] { return NetLogSSLInfoParams(this); });
}

void SSLClientSocketImpl::RecordNegotiatedProtocol() const {
  UMA_HISTOGRAM_ENUMERATION("Net.SSLNegotiatedAlpnProtocol",
                            negotiated_protocol_, kProtoLast + 1);
}

int SSLClientSocketImpl::MapLastOpenSSLError(
    int ssl_error,
    const crypto::OpenSSLErrStackTracer& tracer,
    OpenSSLErrorInfo* info) {
  int net_error = MapOpenSSLErrorWithDetails(ssl_error, tracer, info);

  if (ssl_error == SSL_ERROR_SSL &&
      ERR_GET_LIB(info->error_code) == ERR_LIB_SSL) {
    // TLS does not provide an alert for missing client certificates, so most
    // servers send a generic handshake_failure alert. Detect this case by
    // checking if we have received a CertificateRequest but sent no
    // certificate. See https://crbug.com/646567.
    if (ERR_GET_REASON(info->error_code) ==
            SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE &&
        certificate_requested_ && send_client_cert_ && !client_cert_) {
      net_error = ERR_BAD_SSL_CLIENT_AUTH_CERT;
    }

    // Per spec, access_denied is only for client-certificate-based access
    // control, but some buggy firewalls use it when blocking a page. To avoid a
    // confusing error, map it to a generic protocol error if no
    // CertificateRequest was sent. See https://crbug.com/630883.
    if (ERR_GET_REASON(info->error_code) == SSL_R_TLSV1_ALERT_ACCESS_DENIED &&
        !certificate_requested_) {
      net_error = ERR_SSL_PROTOCOL_ERROR;
    }

    // This error is specific to the client, so map it here.
    if (ERR_GET_REASON(info->error_code) ==
        SSL_R_NO_COMMON_SIGNATURE_ALGORITHMS) {
      net_error = ERR_SSL_CLIENT_AUTH_NO_COMMON_ALGORITHMS;
    }
  }

  return net_error;
}

std::string_view SSLClientSocketImpl::GetECHNameOverride() const {
  const char* data;
  size_t len;
  SSL_get0_ech_name_override(ssl_.get(), &data, &len);
  return std::string_view(data, len);
}

bool SSLClientSocketImpl::IsAllowedBadCert(X509Certificate* cert,
                                           CertStatus* cert_status) const {
  if (!GetECHNameOverride().empty()) {
    // Certificate exceptions are only applicable for the origin name. For
    // simplicity, we do not allow certificate exceptions for the public name.
    return false;
  }
  return ssl_config_.IsAllowedBadCert(cert, cert_status);
}

}  // namespace net
```