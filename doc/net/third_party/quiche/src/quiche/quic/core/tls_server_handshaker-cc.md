Response:
The user is asking for a summary of the functionality of the `tls_server_handshaker.cc` file in the Chromium network stack. I need to analyze the code and identify its key responsibilities. The request also includes specific points to address: its relation to Javascript, logical reasoning with input/output examples, common usage errors, debugging information, and finally a general summary for this first part of the file.

Here's a breakdown of how I'll approach this:

1. **Identify Core Functionality:** I'll scan the code for class definitions, key methods, and interactions with other components. The name "TlsServerHandshaker" strongly suggests its primary role is handling the TLS handshake on the server side in a QUIC connection.

2. **Analyze Key Methods:** I'll pay close attention to methods like `AdvanceHandshake`, `ProcessTransportParameters`, `SetTransportParameters`, `ComputeSignature`, `SessionTicketSeal`, and `SessionTicketOpen`. These seem crucial for the handshake process.

3. **Look for External Dependencies:** I'll note the usage of OpenSSL (`SSL_*`), QuicCrypto components, ProofSource, and other Quic core classes. These indicate how the handshaker interacts with the broader system.

4. **Address Specific Requirements:**
    * **Javascript Relation:**  I'll consider how the TLS handshake affects the security and establishment of a web connection that might involve Javascript.
    * **Logical Reasoning:** I'll devise hypothetical scenarios with specific input to the handshaker and predict the output or actions taken.
    * **User/Programming Errors:** I'll think about common mistakes developers might make when configuring or using this component.
    * **Debugging:** I'll analyze how user actions might lead to execution within this file, acting as debugging hints.
    * **Summary (Part 1):** I'll synthesize the identified functionalities into a concise summary for the first part of the file.

5. **Structure the Response:** I'll organize the information clearly, addressing each point of the user's request systematically.

**Pre-computation/Pre-analysis:**

* The file clearly implements a server-side TLS handshake within the QUIC protocol.
* It interacts heavily with the `ProofSource` for certificate management and signature generation.
* Session tickets for resumption are a significant part of its functionality.
* Transport parameters negotiation is handled within this class.
* Error handling and connection closure are also part of its responsibilities.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 如果它与javascript的功能有关系，请做出对应的举例说明: Yes
* 如果做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
* 请归纳一下它的功能: Yes

Confidence Score: 5/5  I'm confident I can address all aspects of the request.

**Mental Sandbox Simulation:**

I imagine scenarios like:

* A client connecting to a server, triggering the server-side handshake logic within this file.
* The server needing to retrieve its certificate chain via the `ProofSource`.
* The client offering a session ticket, leading to the decryption process.
* The negotiation of QUIC transport parameters between client and server.
* Potential errors during certificate verification or signature generation.

These simulations help me anticipate the flow of execution and the data being processed.

Strategizing complete. I will now generate the response.

这是 Chromium 网络栈中处理 QUIC 协议服务器端 TLS 握手的核心组件。它负责管理 TLS 握手的服务端逻辑，确保安全地建立连接。

以下是 `net/third_party/quiche/src/quiche/quic/core/tls_server_handshaker.cc` 文件的功能归纳：

**核心功能:**

1. **处理 TLS 服务端握手:**  这是该文件的主要职责。它实现了 QUIC 服务器端在 TLS 握手期间所需的各种操作，包括接收和处理客户端的握手消息，并发送服务器端的握手消息。

2. **证书管理和签名:**
   - **证书选择:**  与 `ProofSource` 接口交互，根据客户端请求的主机名 (SNI) 和其他信息选择合适的服务器证书。
   - **签名计算:** 使用 `ProofSource` 提供的私钥对握手消息进行签名，以证明服务器的身份。

3. **会话恢复 (Session Resumption):**
   - **会话票据 (Session Ticket) 处理:**  接收和解密客户端提供的会话票据，如果票据有效，则可以跳过完整的密钥交换，加速连接建立。
   - **会话票据加密:**  在握手完成后，创建并加密新的会话票据，以便客户端在后续连接中恢复会话。

4. **传输参数协商:**  处理客户端发送的传输参数，并设置服务器端的传输参数，例如最大连接数、流控参数等。

5. **密钥派生和管理:**  基于 TLS 握手过程中的密钥交换，生成用于加密和解密数据的密钥。

6. **处理早期数据 (Early Data / 0-RTT):**  允许客户端在握手完成前发送少量数据 (0-RTT 数据)，并处理这些数据。

7. **ALPN (应用层协议协商) 处理:**  确定连接使用的应用层协议 (例如 HTTP/3)。

8. **错误处理和连接关闭:**  在握手过程中发生错误时，发送连接关闭帧并终止连接。

**与 Javascript 的关系举例:**

虽然这个 C++ 文件本身不包含 Javascript 代码，但它直接影响着浏览器中 Javascript 代码的网络连接安全和性能。

* **HTTPS 连接建立:** 当用户在浏览器中访问一个 HTTPS 网站时，浏览器会使用 QUIC 协议与服务器建立连接（如果支持）。`TlsServerHandshaker` 负责服务器端的 TLS 握手，确保连接是加密的，Javascript 代码才能安全地发送和接收敏感数据。
* **Performance 提升:**  会话恢复功能由 `TlsServerHandshaker` 管理，允许浏览器跳过完整的握手过程，更快地建立与之前访问过的服务器的连接，从而提高 Javascript 应用的加载速度和响应速度。
* **0-RTT 数据:** 如果服务器支持 0-RTT，浏览器中的 Javascript 代码可以在连接建立的早期就开始发送请求，减少延迟。`TlsServerHandshaker` 负责处理这些早期数据。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. **客户端 Hello 消息:**  包含客户端支持的 TLS 版本、密码套件、扩展信息 (例如 SNI, 传输参数, 会话票据)。
2. **服务器配置:**  包括服务器证书、私钥、支持的 QUIC 版本、ALPN 列表。
3. **会话票据 (如果存在):**  客户端提供的用于会话恢复的加密票据。

**假设输出:**

1. **服务器 Hello 消息:**  包含服务器选择的 TLS 版本、密码套件、服务器证书、服务器的传输参数。
2. **签名:**  对握手消息的数字签名。
3. **会话票据 (如果创建):**  新的加密会话票据，用于后续的会话恢复。
4. **加密密钥:**  用于加密和解密后续的应用层数据的密钥。
5. **连接建立成功/失败:**  基于握手过程的结果。

**用户或编程常见的使用错误举例:**

1. **服务器证书配置错误:**  如果 `ProofSource` 配置不正确，导致服务器无法找到或提供正确的证书，握手将失败。
   * **错误现象:** 客户端收到证书相关的错误，连接无法建立。
   * **调试线索:** 服务器日志中会显示 `ProofSource` 相关的错误信息。

2. **ALPN 配置不匹配:**  如果服务器配置的 ALPN 列表与客户端请求的不匹配，握手将失败。
   * **错误现象:** 客户端收到协议错误，例如 `no_application_protocol`.
   * **调试线索:**  查看握手过程中协商的 ALPN 值。

3. **传输参数配置错误:**  例如，服务器配置的最大流数过小，导致客户端无法创建足够的流。
   * **错误现象:**  应用层出现流创建失败或受限的情况。
   * **调试线索:**  检查连接建立后双方协商的传输参数。

4. **会话票据解密失败:**  如果服务器的密钥轮换导致无法解密客户端提供的旧会话票据，会话恢复将失败。
   * **错误现象:**  客户端无法进行 0-RTT 连接，需要进行完整的握手。
   * **调试线索:**  查看服务器是否尝试解密会话票据，并检查解密结果。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入一个 `https://` 开头的网址，并且该网站支持 QUIC 协议。**
2. **浏览器尝试与服务器建立 QUIC 连接。**
3. **操作系统发起网络连接请求。**
4. **Chromium 网络栈 (QuicConnection) 开始 QUIC 握手过程。**
5. **在服务器端，接收到客户端的初始握手包。**
6. **QuicConnection 将握手包交给 `TlsServerHandshaker` 进行处理。**
7. **`TlsServerHandshaker` 开始解析客户端的 Client Hello 消息，并根据配置进行后续的证书选择、签名、会话票据处理、传输参数协商等操作。**
8. **如果握手成功，连接建立完成，浏览器可以开始发送 HTTP/3 请求。**
9. **如果握手失败，`TlsServerHandshaker` 会通知 `QuicConnection` 关闭连接，并可能记录错误信息。**

**功能归纳 (第 1 部分):**

`TlsServerHandshaker` 的主要功能是作为 QUIC 服务器端 TLS 握手的核心处理模块。它负责证书管理和签名、会话恢复、传输参数协商等关键步骤，确保安全可靠地建立 QUIC 连接。 该文件的代码主要集中在握手初期的证书选择、客户端传输参数的处理以及服务器端传输参数的设置。它还涉及到了异步操作的处理，例如证书签名和会话票据解密。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/tls_server_handshaker.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/tls_server_handshaker.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "absl/types/variant.h"
#include "openssl/base.h"
#include "openssl/bytestring.h"
#include "openssl/ssl.h"
#include "openssl/tls1.h"
#include "quiche/quic/core/crypto/crypto_handshake.h"
#include "quiche/quic/core/crypto/crypto_message_parser.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/crypto/proof_source.h"
#include "quiche/quic/core/crypto/proof_verifier.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/frames/quic_connection_close_frame.h"
#include "quiche/quic/core/http/http_encoder.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_connection_context.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_connection_stats.h"
#include "quiche/quic/core/quic_crypto_server_stream_base.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_time_accumulator.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/core/tls_handshaker.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_hostname_utils.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_server_stats.h"
#include "quiche/quic/platform/api/quic_socket_address.h"

#define RECORD_LATENCY_IN_US(stat_name, latency, comment)                   \
  do {                                                                      \
    const int64_t latency_in_us = (latency).ToMicroseconds();               \
    QUIC_DVLOG(1) << "Recording " stat_name ": " << latency_in_us;          \
    QUIC_SERVER_HISTOGRAM_COUNTS(stat_name, latency_in_us, 1, 10000000, 50, \
                                 comment);                                  \
  } while (0)

namespace quic {

namespace {

// Default port for HTTP/3.
uint16_t kDefaultPort = 443;

}  // namespace

TlsServerHandshaker::DefaultProofSourceHandle::DefaultProofSourceHandle(
    TlsServerHandshaker* handshaker, ProofSource* proof_source)
    : handshaker_(handshaker), proof_source_(proof_source) {}

TlsServerHandshaker::DefaultProofSourceHandle::~DefaultProofSourceHandle() {
  CloseHandle();
}

void TlsServerHandshaker::DefaultProofSourceHandle::CloseHandle() {
  QUIC_DVLOG(1) << "CloseHandle. is_signature_pending="
                << (signature_callback_ != nullptr);
  if (signature_callback_) {
    signature_callback_->Cancel();
    signature_callback_ = nullptr;
  }
}

QuicAsyncStatus
TlsServerHandshaker::DefaultProofSourceHandle::SelectCertificate(
    const QuicSocketAddress& server_address,
    const QuicSocketAddress& client_address,
    const QuicConnectionId& /*original_connection_id*/,
    absl::string_view /*ssl_capabilities*/, const std::string& hostname,
    absl::string_view /*client_hello*/, const std::string& /*alpn*/,
    std::optional<std::string> /*alps*/,
    const std::vector<uint8_t>& /*quic_transport_params*/,
    const std::optional<std::vector<uint8_t>>& /*early_data_context*/,
    const QuicSSLConfig& /*ssl_config*/) {
  if (!handshaker_ || !proof_source_) {
    QUIC_BUG(quic_bug_10341_1)
        << "SelectCertificate called on a detached handle";
    return QUIC_FAILURE;
  }

  bool cert_matched_sni;
  quiche::QuicheReferenceCountedPointer<ProofSource::Chain> chain =
      proof_source_->GetCertChain(server_address, client_address, hostname,
                                  &cert_matched_sni);

  handshaker_->OnSelectCertificateDone(
      /*ok=*/true, /*is_sync=*/true,
      ProofSourceHandleCallback::LocalSSLConfig{chain.get(),
                                                QuicDelayedSSLConfig()},
      /*ticket_encryption_key=*/absl::string_view(), cert_matched_sni);
  if (!handshaker_->select_cert_status().has_value()) {
    QUIC_BUG(quic_bug_12423_1)
        << "select_cert_status() has no value after a synchronous select cert";
    // Return success to continue the handshake.
    return QUIC_SUCCESS;
  }
  return *handshaker_->select_cert_status();
}

QuicAsyncStatus TlsServerHandshaker::DefaultProofSourceHandle::ComputeSignature(
    const QuicSocketAddress& server_address,
    const QuicSocketAddress& client_address, const std::string& hostname,
    uint16_t signature_algorithm, absl::string_view in,
    size_t max_signature_size) {
  if (!handshaker_ || !proof_source_) {
    QUIC_BUG(quic_bug_10341_2)
        << "ComputeSignature called on a detached handle";
    return QUIC_FAILURE;
  }

  if (signature_callback_) {
    QUIC_BUG(quic_bug_10341_3) << "ComputeSignature called while pending";
    return QUIC_FAILURE;
  }

  signature_callback_ = new DefaultSignatureCallback(this);
  proof_source_->ComputeTlsSignature(
      server_address, client_address, hostname, signature_algorithm, in,
      std::unique_ptr<DefaultSignatureCallback>(signature_callback_));

  if (signature_callback_) {
    QUIC_DVLOG(1) << "ComputeTlsSignature is pending";
    signature_callback_->set_is_sync(false);
    return QUIC_PENDING;
  }

  bool success = handshaker_->HasValidSignature(max_signature_size);
  QUIC_DVLOG(1) << "ComputeTlsSignature completed synchronously. success:"
                << success;
  // OnComputeSignatureDone should have been called by signature_callback_->Run.
  return success ? QUIC_SUCCESS : QUIC_FAILURE;
}

TlsServerHandshaker::DecryptCallback::DecryptCallback(
    TlsServerHandshaker* handshaker)
    : handshaker_(handshaker) {}

void TlsServerHandshaker::DecryptCallback::Run(std::vector<uint8_t> plaintext) {
  if (handshaker_ == nullptr) {
    // The callback was cancelled before we could run.
    return;
  }

  TlsServerHandshaker* handshaker = handshaker_;
  handshaker_ = nullptr;

  handshaker->decrypted_session_ticket_ = std::move(plaintext);
  const bool is_async =
      (handshaker->expected_ssl_error() == SSL_ERROR_PENDING_TICKET);

  std::optional<QuicConnectionContextSwitcher> context_switcher;

  if (is_async) {
    context_switcher.emplace(handshaker->connection_context());
  }
  QUIC_TRACESTRING(
      absl::StrCat("TLS ticket decryption done. len(decrypted_ticket):",
                   handshaker->decrypted_session_ticket_.size()));

  // DecryptCallback::Run could be called synchronously. When that happens, we
  // are currently in the middle of a call to AdvanceHandshake.
  // (AdvanceHandshake called SSL_do_handshake, which through some layers
  // called SessionTicketOpen, which called TicketCrypter::Decrypt, which
  // synchronously called this function.) In that case, the handshake will
  // continue to be processed when this function returns.
  //
  // When this callback is called asynchronously (i.e. the ticket decryption
  // is pending), TlsServerHandshaker is not actively processing handshake
  // messages. We need to have it resume processing handshake messages by
  // calling AdvanceHandshake.
  if (is_async) {
    handshaker->AdvanceHandshakeFromCallback();
  }

  handshaker->ticket_decryption_callback_ = nullptr;
}

void TlsServerHandshaker::DecryptCallback::Cancel() {
  QUICHE_DCHECK(handshaker_);
  handshaker_ = nullptr;
}

TlsServerHandshaker::TlsServerHandshaker(
    QuicSession* session, const QuicCryptoServerConfig* crypto_config)
    : TlsHandshaker(this, session),
      QuicCryptoServerStreamBase(session),
      proof_source_(crypto_config->proof_source()),
      pre_shared_key_(crypto_config->pre_shared_key()),
      crypto_negotiated_params_(new QuicCryptoNegotiatedParameters),
      tls_connection_(crypto_config->ssl_ctx(), this, session->GetSSLConfig()),
      crypto_config_(crypto_config) {
  QUIC_DVLOG(1) << "TlsServerHandshaker:  client_cert_mode initial value: "
                << client_cert_mode();

  QUICHE_DCHECK_EQ(PROTOCOL_TLS1_3,
                   session->connection()->version().handshake_protocol);

  // Configure the SSL to be a server.
  SSL_set_accept_state(ssl());

  // Make sure we use the right TLS extension codepoint.
  int use_legacy_extension = 0;
  if (session->version().UsesLegacyTlsExtension()) {
    use_legacy_extension = 1;
  }
  SSL_set_quic_use_legacy_codepoint(ssl(), use_legacy_extension);

  if (session->connection()->context()->tracer) {
    tls_connection_.EnableInfoCallback();
  }
#if BORINGSSL_API_VERSION >= 22
  if (!crypto_config->preferred_groups().empty()) {
    SSL_set1_group_ids(ssl(), crypto_config->preferred_groups().data(),
                       crypto_config->preferred_groups().size());
  }
#endif  // BORINGSSL_API_VERSION
}

TlsServerHandshaker::~TlsServerHandshaker() { CancelOutstandingCallbacks(); }

void TlsServerHandshaker::CancelOutstandingCallbacks() {
  if (proof_source_handle_) {
    proof_source_handle_->CloseHandle();
  }
  if (ticket_decryption_callback_) {
    ticket_decryption_callback_->Cancel();
    ticket_decryption_callback_ = nullptr;
  }
}

void TlsServerHandshaker::InfoCallback(int type, int value) {
  QuicConnectionTracer* tracer =
      session()->connection()->context()->tracer.get();

  if (tracer == nullptr) {
    return;
  }

  if (type & SSL_CB_LOOP) {
    tracer->PrintString(
        absl::StrCat("SSL:ACCEPT_LOOP:", SSL_state_string_long(ssl())));
  } else if (type & SSL_CB_ALERT) {
    const char* prefix =
        (type & SSL_CB_READ) ? "SSL:READ_ALERT:" : "SSL:WRITE_ALERT:";
    tracer->PrintString(absl::StrCat(prefix, SSL_alert_type_string_long(value),
                                     ":", SSL_alert_desc_string_long(value)));
  } else if (type & SSL_CB_EXIT) {
    const char* prefix =
        (value == 1) ? "SSL:ACCEPT_EXIT_OK:" : "SSL:ACCEPT_EXIT_FAIL:";
    tracer->PrintString(absl::StrCat(prefix, SSL_state_string_long(ssl())));
  } else if (type & SSL_CB_HANDSHAKE_START) {
    tracer->PrintString(
        absl::StrCat("SSL:HANDSHAKE_START:", SSL_state_string_long(ssl())));
  } else if (type & SSL_CB_HANDSHAKE_DONE) {
    tracer->PrintString(
        absl::StrCat("SSL:HANDSHAKE_DONE:", SSL_state_string_long(ssl())));
  } else {
    QUIC_DLOG(INFO) << "Unknown event type " << type << ": "
                    << SSL_state_string_long(ssl());
    tracer->PrintString(
        absl::StrCat("SSL:unknown:", value, ":", SSL_state_string_long(ssl())));
  }
}

std::unique_ptr<ProofSourceHandle>
TlsServerHandshaker::MaybeCreateProofSourceHandle() {
  return std::make_unique<DefaultProofSourceHandle>(this, proof_source_);
}

bool TlsServerHandshaker::GetBase64SHA256ClientChannelID(
    std::string* /*output*/) const {
  // Channel ID is not supported when TLS is used in QUIC.
  return false;
}

void TlsServerHandshaker::SendServerConfigUpdate(
    const CachedNetworkParameters* /*cached_network_params*/) {
  // SCUP messages aren't supported when using the TLS handshake.
}

bool TlsServerHandshaker::DisableResumption() {
  if (!can_disable_resumption_ || !session()->connection()->connected()) {
    return false;
  }
  tls_connection_.DisableTicketSupport();
  return true;
}

bool TlsServerHandshaker::IsZeroRtt() const {
  return SSL_early_data_accepted(ssl());
}

bool TlsServerHandshaker::IsResumption() const {
  return SSL_session_reused(ssl());
}

bool TlsServerHandshaker::ResumptionAttempted() const {
  return ticket_received_;
}

bool TlsServerHandshaker::EarlyDataAttempted() const {
  QUIC_BUG_IF(quic_tls_early_data_attempted_too_early,
              !select_cert_status_.has_value())
      << "EarlyDataAttempted must be called after EarlySelectCertCallback is "
         "started";
  return early_data_attempted_;
}

int TlsServerHandshaker::NumServerConfigUpdateMessagesSent() const {
  // SCUP messages aren't supported when using the TLS handshake.
  return 0;
}

const CachedNetworkParameters*
TlsServerHandshaker::PreviousCachedNetworkParams() const {
  return last_received_cached_network_params_.get();
}

void TlsServerHandshaker::SetPreviousCachedNetworkParams(
    CachedNetworkParameters cached_network_params) {
  last_received_cached_network_params_ =
      std::make_unique<CachedNetworkParameters>(cached_network_params);
}

void TlsServerHandshaker::OnPacketDecrypted(EncryptionLevel level) {
  if (level == ENCRYPTION_HANDSHAKE && state_ < HANDSHAKE_PROCESSED) {
    state_ = HANDSHAKE_PROCESSED;
    handshaker_delegate()->DiscardOldEncryptionKey(ENCRYPTION_INITIAL);
    handshaker_delegate()->DiscardOldDecryptionKey(ENCRYPTION_INITIAL);
  }
}

void TlsServerHandshaker::OnHandshakeDoneReceived() { QUICHE_DCHECK(false); }

void TlsServerHandshaker::OnNewTokenReceived(absl::string_view /*token*/) {
  QUICHE_DCHECK(false);
}

std::string TlsServerHandshaker::GetAddressToken(
    const CachedNetworkParameters* cached_network_params) const {
  SourceAddressTokens empty_previous_tokens;
  const QuicConnection* connection = session()->connection();
  return crypto_config_->NewSourceAddressToken(
      crypto_config_->source_address_token_boxer(), empty_previous_tokens,
      connection->effective_peer_address().host(),
      connection->random_generator(), connection->clock()->WallNow(),
      cached_network_params);
}

bool TlsServerHandshaker::ValidateAddressToken(absl::string_view token) const {
  SourceAddressTokens tokens;
  HandshakeFailureReason reason = crypto_config_->ParseSourceAddressToken(
      crypto_config_->source_address_token_boxer(), token, tokens);
  if (reason != HANDSHAKE_OK) {
    QUIC_DLOG(WARNING) << "Failed to parse source address token: "
                       << CryptoUtils::HandshakeFailureReasonToString(reason);
    return false;
  }
  auto cached_network_params = std::make_unique<CachedNetworkParameters>();
  reason = crypto_config_->ValidateSourceAddressTokens(
      tokens, session()->connection()->effective_peer_address().host(),
      session()->connection()->clock()->WallNow(), cached_network_params.get());
  if (reason != HANDSHAKE_OK) {
    QUIC_DLOG(WARNING) << "Failed to validate source address token: "
                       << CryptoUtils::HandshakeFailureReasonToString(reason);
    return false;
  }

  last_received_cached_network_params_ = std::move(cached_network_params);
  return true;
}

bool TlsServerHandshaker::ShouldSendExpectCTHeader() const { return false; }

bool TlsServerHandshaker::DidCertMatchSni() const { return cert_matched_sni_; }

const ProofSource::Details* TlsServerHandshaker::ProofSourceDetails() const {
  return proof_source_details_.get();
}

bool TlsServerHandshaker::ExportKeyingMaterial(absl::string_view label,
                                               absl::string_view context,
                                               size_t result_len,
                                               std::string* result) {
  return ExportKeyingMaterialForLabel(label, context, result_len, result);
}

void TlsServerHandshaker::OnConnectionClosed(
    const QuicConnectionCloseFrame& frame, ConnectionCloseSource source) {
  TlsHandshaker::OnConnectionClosed(frame.quic_error_code, source);
}

ssl_early_data_reason_t TlsServerHandshaker::EarlyDataReason() const {
  return TlsHandshaker::EarlyDataReason();
}

bool TlsServerHandshaker::encryption_established() const {
  return encryption_established_;
}

bool TlsServerHandshaker::one_rtt_keys_available() const {
  return state_ == HANDSHAKE_CONFIRMED;
}

const QuicCryptoNegotiatedParameters&
TlsServerHandshaker::crypto_negotiated_params() const {
  return *crypto_negotiated_params_;
}

CryptoMessageParser* TlsServerHandshaker::crypto_message_parser() {
  return TlsHandshaker::crypto_message_parser();
}

HandshakeState TlsServerHandshaker::GetHandshakeState() const { return state_; }

void TlsServerHandshaker::SetServerApplicationStateForResumption(
    std::unique_ptr<ApplicationState> state) {
  application_state_ = std::move(state);
}

size_t TlsServerHandshaker::BufferSizeLimitForLevel(
    EncryptionLevel level) const {
  return TlsHandshaker::BufferSizeLimitForLevel(level);
}

std::unique_ptr<QuicDecrypter>
TlsServerHandshaker::AdvanceKeysAndCreateCurrentOneRttDecrypter() {
  return TlsHandshaker::AdvanceKeysAndCreateCurrentOneRttDecrypter();
}

std::unique_ptr<QuicEncrypter>
TlsServerHandshaker::CreateCurrentOneRttEncrypter() {
  return TlsHandshaker::CreateCurrentOneRttEncrypter();
}

void TlsServerHandshaker::OverrideQuicConfigDefaults(QuicConfig* /*config*/) {}

void TlsServerHandshaker::AdvanceHandshakeFromCallback() {
  QuicConnection::ScopedPacketFlusher flusher(session()->connection());

  AdvanceHandshake();
  if (!is_connection_closed()) {
    handshaker_delegate()->OnHandshakeCallbackDone();
  }
}

bool TlsServerHandshaker::ProcessTransportParameters(
    const SSL_CLIENT_HELLO* client_hello, std::string* error_details) {
  TransportParameters client_params;
  const uint8_t* client_params_bytes;
  size_t params_bytes_len;

  // Make sure we use the right TLS extension codepoint.
  uint16_t extension_type = TLSEXT_TYPE_quic_transport_parameters_standard;
  if (session()->version().UsesLegacyTlsExtension()) {
    extension_type = TLSEXT_TYPE_quic_transport_parameters_legacy;
  }
  // When using early select cert callback, SSL_get_peer_quic_transport_params
  // can not be used to retrieve the client's transport parameters, but we can
  // use SSL_early_callback_ctx_extension_get to do that.
  if (!SSL_early_callback_ctx_extension_get(client_hello, extension_type,
                                            &client_params_bytes,
                                            &params_bytes_len)) {
    params_bytes_len = 0;
  }

  if (params_bytes_len == 0) {
    *error_details = "Client's transport parameters are missing";
    return false;
  }
  std::string parse_error_details;
  if (!ParseTransportParameters(session()->connection()->version(),
                                Perspective::IS_CLIENT, client_params_bytes,
                                params_bytes_len, &client_params,
                                &parse_error_details)) {
    QUICHE_DCHECK(!parse_error_details.empty());
    *error_details =
        "Unable to parse client's transport parameters: " + parse_error_details;
    return false;
  }

  // Notify QuicConnectionDebugVisitor.
  session()->connection()->OnTransportParametersReceived(client_params);

  if (client_params.legacy_version_information.has_value() &&
      CryptoUtils::ValidateClientHelloVersion(
          client_params.legacy_version_information->version,
          session()->connection()->version(), session()->supported_versions(),
          error_details) != QUIC_NO_ERROR) {
    return false;
  }

  if (client_params.version_information.has_value() &&
      !CryptoUtils::ValidateChosenVersion(
          client_params.version_information->chosen_version,
          session()->version(), error_details)) {
    QUICHE_DCHECK(!error_details->empty());
    return false;
  }

  if (handshaker_delegate()->ProcessTransportParameters(
          client_params, /* is_resumption = */ false, error_details) !=
      QUIC_NO_ERROR) {
    return false;
  }

  if (!ProcessAdditionalTransportParameters(client_params)) {
    *error_details = "Failed to process additional transport parameters";
    return false;
  }

  return true;
}

TlsServerHandshaker::SetTransportParametersResult
TlsServerHandshaker::SetTransportParameters() {
  SetTransportParametersResult result;
  QUICHE_DCHECK(!result.success);

  server_params_.perspective = Perspective::IS_SERVER;
  server_params_.legacy_version_information =
      TransportParameters::LegacyVersionInformation();
  server_params_.legacy_version_information->supported_versions =
      CreateQuicVersionLabelVector(session()->supported_versions());
  server_params_.legacy_version_information->version =
      CreateQuicVersionLabel(session()->connection()->version());
  server_params_.version_information =
      TransportParameters::VersionInformation();
  server_params_.version_information->chosen_version =
      CreateQuicVersionLabel(session()->version());
  server_params_.version_information->other_versions =
      CreateQuicVersionLabelVector(session()->supported_versions());

  if (!handshaker_delegate()->FillTransportParameters(&server_params_)) {
    return result;
  }

  // Notify QuicConnectionDebugVisitor.
  session()->connection()->OnTransportParametersSent(server_params_);

  {  // Ensure |server_params_bytes| is not accessed out of the scope.
    std::vector<uint8_t> server_params_bytes;
    if (!SerializeTransportParameters(server_params_, &server_params_bytes) ||
        SSL_set_quic_transport_params(ssl(), server_params_bytes.data(),
                                      server_params_bytes.size()) != 1) {
      return result;
    }
    result.quic_transport_params = std::move(server_params_bytes);
  }

  if (application_state_) {
    std::vector<uint8_t> early_data_context;
    if (!SerializeTransportParametersForTicket(
            server_params_, *application_state_, &early_data_context)) {
      QUIC_BUG(quic_bug_10341_4)
          << "Failed to serialize Transport Parameters for ticket.";
      result.early_data_context = std::vector<uint8_t>();
      return result;
    }
    SSL_set_quic_early_data_context(ssl(), early_data_context.data(),
                                    early_data_context.size());
    result.early_data_context = std::move(early_data_context);
    application_state_.reset(nullptr);
  }
  result.success = true;
  return result;
}

bool TlsServerHandshaker::TransportParametersMatch(
    absl::Span<const uint8_t> serialized_params) const {
  TransportParameters params;
  std::string error_details;

  bool parse_ok = ParseTransportParameters(
      session()->version(), Perspective::IS_SERVER, serialized_params.data(),
      serialized_params.size(), &params, &error_details);

  if (!parse_ok) {
    return false;
  }

  DegreaseTransportParameters(params);

  return params == server_params_;
}

void TlsServerHandshaker::SetWriteSecret(
    EncryptionLevel level, const SSL_CIPHER* cipher,
    absl::Span<const uint8_t> write_secret) {
  if (is_connection_closed()) {
    return;
  }
  if (level == ENCRYPTION_FORWARD_SECURE) {
    encryption_established_ = true;
    // Fill crypto_negotiated_params_:
    const SSL_CIPHER* ssl_cipher = SSL_get_current_cipher(ssl());
    if (ssl_cipher) {
      crypto_negotiated_params_->cipher_suite =
          SSL_CIPHER_get_protocol_id(ssl_cipher);
    }
    crypto_negotiated_params_->key_exchange_group = SSL_get_curve_id(ssl());
    crypto_negotiated_params_->encrypted_client_hello = SSL_ech_accepted(ssl());
  }
  TlsHandshaker::SetWriteSecret(level, cipher, write_secret);
}

std::string TlsServerHandshaker::GetAcceptChValueForHostname(
    const std::string& /*hostname*/) const {
  return {};
}

bool TlsServerHandshaker::UseAlpsNewCodepoint() const {
  if (!select_cert_status_.has_value()) {
    QUIC_BUG(quic_tls_check_alps_new_codepoint_too_early)
        << "UseAlpsNewCodepoint must be called after "
           "EarlySelectCertCallback is started";
    return false;
  }

  return alps_new_codepoint_received_;
}

void TlsServerHandshaker::FinishHandshake() {
  QUICHE_DCHECK(!SSL_in_early_data(ssl()));

  if (!valid_alpn_received_) {
    QUIC_DLOG(ERROR)
        << "Server: handshake finished without receiving a known ALPN";
    // TODO(b/130164908) this should send no_application_protocol
    // instead of QUIC_HANDSHAKE_FAILED.
    CloseConnection(QUIC_HANDSHAKE_FAILED,
                    "Server did not receive a known ALPN");
    return;
  }

  ssl_early_data_reason_t reason_code = EarlyDataReason();
  QUIC_DLOG(INFO) << "Server: handshake finished. Early data reason "
                  << reason_code << " ("
                  << CryptoUtils::EarlyDataReasonToString(reason_code) << ")";
  state_ = HANDSHAKE_CONFIRMED;

  handshaker_delegate()->OnTlsHandshakeComplete();
  handshaker_delegate()->DiscardOldEncryptionKey(ENCRYPTION_HANDSHAKE);
  handshaker_delegate()->DiscardOldDecryptionKey(ENCRYPTION_HANDSHAKE);
  // ENCRYPTION_ZERO_RTT decryption key is not discarded here as "Servers MAY
  // temporarily retain 0-RTT keys to allow decrypting reordered packets
  // without requiring their contents to be retransmitted with 1-RTT keys."
  // It is expected that QuicConnection will discard the key at an
  // appropriate time.
}

QuicAsyncStatus TlsServerHandshaker::VerifyCertChain(
    const std::vector<std::string>& /*certs*/, std::string* /*error_details*/,
    std::unique_ptr<ProofVerifyDetails>* /*details*/, uint8_t* /*out_alert*/,
    std::unique_ptr<ProofVerifierCallback> /*callback*/) {
  QUIC_DVLOG(1) << "VerifyCertChain returning success";

  // No real verification here. A subclass can override this function to verify
  // the client cert if needed.
  return QUIC_SUCCESS;
}

void TlsServerHandshaker::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& /*verify_details*/) {}

ssl_private_key_result_t TlsServerHandshaker::PrivateKeySign(
    uint8_t* out, size_t* out_len, size_t max_out, uint16_t sig_alg,
    absl::string_view in) {
  QUICHE_DCHECK_EQ(expected_ssl_error(), SSL_ERROR_WANT_READ);

  QuicAsyncStatus status = proof_source_handle_->ComputeSignature(
      session()->connection()->self_address(),
      session()->connection()->peer_address(), crypto_negotiated_params_->sni,
      sig_alg, in, max_out);
  if (status == QUIC_PENDING) {
    set_expected_ssl_error(SSL_ERROR_WANT_PRIVATE_KEY_OPERATION);
    if (async_op_timer_.has_value()) {
      QUIC_CODE_COUNT(
          quic_tls_server_computing_signature_while_another_op_pending);
    }
    async_op_timer_ = QuicTimeAccumulator();
    async_op_timer_->Start(now());
  }
  return PrivateKeyComplete(out, out_len, max_out);
}

ssl_private_key_result_t TlsServerHandshaker::PrivateKeyComplete(
    uint8_t* out, size_t* out_len, size_t max_out) {
  if (expected_ssl_error() == SSL_ERROR_WANT_PRIVATE_KEY_OPERATION) {
    return ssl_private_key_retry;
  }

  const bool success = HasValidSignature(max_out);
  QuicConnectionStats::TlsServerOperationStats compute_signature_stats;
  compute_signature_stats.success = success;
  if (async_op_timer_.has_value()) {
    async_op_timer_->Stop(now());
    compute_signature_stats.async_latency =
        async_op_timer_->GetTotalElapsedTime();
    async_op_timer_.reset();
    RECORD_LATENCY_IN_US("tls_server_async_compute_signature_latency_us",
                         compute_signature_stats.async_latency,
                         "Async compute signature latency in microseconds");
  }
  connection_stats().tls_server_compute_signature_stats =
      std::move(compute_signature_stats);

  if (!success) {
    return ssl_private_key_failure;
  }
  *out_len = cert_verify_sig_.size();
  memcpy(out, cert_verify_sig_.data(), *out_len);
  cert_verify_sig_.clear();
  cert_verify_sig_.shrink_to_fit();
  return ssl_private_key_success;
}

void TlsServerHandshaker::OnComputeSignatureDone(
    bool ok, bool is_sync, std::string signature,
    std::unique_ptr<ProofSource::Details> details) {
  QUIC_DVLOG(1) << "OnComputeSignatureDone. ok:" << ok
                << ", is_sync:" << is_sync
                << ", len(signature):" << signature.size();
  std::optional<QuicConnectionContextSwitcher> context_switcher;

  if (!is_sync) {
    context_switcher.emplace(connection_context());
  }

  QUIC_TRACESTRING(absl::StrCat("TLS compute signature done. ok:", ok,
                                ", len(signature):", signature.size()));

  if (ok) {
    cert_verify_sig_ = std::move(signature);
    proof_source_details_ = std::move(details);
  }
  const int last_expected_ssl_error = expected_ssl_error();
  set_expected_ssl_error(SSL_ERROR_WANT_READ);
  if (!is_sync) {
    QUICHE_DCHECK_EQ(last_expected_ssl_error,
                     SSL_ERROR_WANT_PRIVATE_KEY_OPERATION);
    AdvanceHandshakeFromCallback();
  }
}

bool TlsServerHandshaker::HasValidSignature(size_t max_signature_size) const {
  return !cert_verify_sig_.empty() &&
         cert_verify_sig_.size() <= max_signature_size;
}

size_t TlsServerHandshaker::SessionTicketMaxOverhead() {
  QUICHE_DCHECK(proof_source_->GetTicketCrypter());
  return proof_source_->GetTicketCrypter()->MaxOverhead();
}

int TlsServerHandshaker::SessionTicketSeal(uint8_t* out, size_t* out_len,
                                           size_t max_out_len,
                                           absl::string_view in) {
  QUICHE_DCHECK(proof_source_->GetTicketCrypter());
  std::vector<uint8_t> ticket =
      proof_source_->GetTicketCrypter()->Encrypt(in, ticket_encryption_key_);
  if (GetQuicReloadableFlag(
          quic_send_placeholder_ticket_when_encrypt_ticket_fails) &&
      ticket.empty()) {
    QUIC_CODE_COUNT(quic_tls_server_handshaker_send_placeholder_ticket);
    const absl::string_view kTicketFailurePlaceholder = "TICKET FAILURE";
    const absl::string_view kTicketWithSizeLimit =
        kTicketFailurePlaceholder.substr(0, max_out_len);
    ticket.assign(kTicketWithSizeLimit.begin(), kTicketWithSizeLimit.end());
  }
  if (max_out_len < ticket.size()) {
    QUIC_BUG(quic_bug_12423_2)
        << "TicketCrypter returned " << ticket.size()
        << " bytes of ciphertext, which is larger than its max overhead of "
        << max_out_len;
    return 0;  // failure
  }
  *out_len = ticket.size();
  memcpy(out, ticket.data(), ticket.size());
  QUIC_CODE_COUNT(quic_tls_server_handshaker_tickets_sealed);
  return 1;  // success
}

ssl_ticket_aead_result_t TlsServerHandshaker::SessionTicketOpen(
    uint8_t* out, size_t* out_len, size_t max_out_len, absl::string_view in) {
  QUICHE_DCHECK(proof_source_->GetTicketCrypter());

  if (ignore_ticket_open_) {
    // SetIgnoreTicketOpen has been called. Typically this means the caller is
    // using handshake hints and expect the hints to contain ticket decryption
    // results.
    QUIC_CODE_COUNT(quic_tls_server_handshaker_tickets_ignored_1);
    return ssl_ticket_aead_ignore_ticket;
  }

  if (!ticket_decryption_callback_) {
    ticket_decryption_callback_ = std::make_shared<DecryptCallback>(this);
    proof_source_->GetTicketCrypter()->Decrypt(in, ticket_decryption_callback_);

    // Decrypt can run the callback synchronously. In that case, the callback
    // will clear the ticket_decryption_callback_ pointer, and instead of
    // returning ssl_ticket_aead_retry, we should continue processing to
    // return the decrypted ticket.
    //
    // If the callback is not run synchronously, return ssl_ticket_aead_retry
    // and when the callback is complete this function will be run again to
    // return the result.
    if (ticket_decryption_callback_) {
      QUICHE_DCHECK(!ticket_decryption_callback_->IsDone());
      set_expected_ssl_error(SSL_ERROR_PENDING_TICKET);
      if (async_op_timer_.has_value()) {
        QUIC_CODE_COUNT(
            quic_tls_server_decrypting_ticket_while_another_op_pending);
      }
      async_op_timer_ = QuicTimeAccumulator();
      async_op_timer_->Start(now());
    }
  }

  // If the async ticket decryption is pending, either started by this
  // SessionTicketOpen call or one that happened earlier, return
  // ssl_ticket_aead_retry.
  if (ticket_decryption_callback_ && !ticket_decryption_callback_->IsDone()) {
    return ssl_ticket_aead_retry;
  }

  ssl_ticket_aead_result_t result =
      FinalizeSessionTicketOpen(out, out_len, max_out_len);

  QuicConnectionStats::TlsServerOperationStats decrypt_ticket_stats;
  decrypt_ticket_stats.success = (result == ssl_ticket_aead_success);
  if (async_op_timer_.has_value()) {
    async_op_timer_->Stop(now());
    decrypt_ticket_stats.async_latency = async_op_timer_->GetTotalElapsedTime();
    async_op_timer_.reset();
    RECORD_LATENCY_IN_US("tls_server_async_decrypt_ticket_latency_us",
                         decrypt_ticket_stats.async_latency,
                         "Async decrypt ticket latency in microseconds");
  }
  connection_stats().tls_server_decrypt_ti
"""


```