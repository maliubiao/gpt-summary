Response:
Let's break down the thought process for analyzing this `tls_handshaker.cc` file.

**1. Initial Understanding of the Context:**

The prompt clearly states this is a Chromium network stack file, specifically within the QUIC implementation, dealing with TLS handshakes. Keywords like "tls_handshaker," "quic," and the file path itself (`net/third_party/quiche/src/quiche/quic/core/`) immediately point to the core functionality: managing the TLS negotiation process within a QUIC connection.

**2. High-Level Functionality Identification:**

The filename `tls_handshaker.cc` strongly suggests its primary role is to handle the TLS handshake process. Scanning the code confirms this:

* **`ProcessInput`:** Takes incoming data, a core function for processing handshake messages.
* **`AdvanceHandshake`:**  The heart of the process, driving the handshake forward.
* **`SetWriteSecret`, `SetReadSecret`:**  Key management, crucial for establishing secure communication.
* **`VerifyCert`:** Handles certificate verification, a critical security step.
* **`ExportKeyingMaterialForLabel`:**  Allows for exporting derived keys for specific purposes.
* **`WriteMessage`, `SendAlert`:** Sending handshake messages and error notifications.

**3. Detailed Examination of Key Methods:**

I'd then delve into the more complex methods:

* **`ProcessInput`:**  Note the call to `SSL_provide_quic_data`. This connects the QUIC layer to the underlying BoringSSL TLS library. The error handling logic regarding encryption levels is important.

* **`AdvanceHandshake`:** This is where the main handshake logic resides. The calls to `SSL_do_handshake` are central. The handling of early data (`SSL_in_early_data`) and error conditions (`SSL_get_error`) are significant. The `QUICHE_BUG_IF` macro hints at potential edge cases or past issues encountered.

* **`VerifyCert`:**  The asynchronous nature of certificate verification is evident by the use of `ProofVerifierCallbackImpl` and `QuicAsyncStatus`. The interaction with a `ProofVerifier` (not shown in this snippet) is implied.

* **`SetWriteSecret`/`SetReadSecret`:** These methods demonstrate how TLS secrets are translated into QUIC encryption and decryption keys using `QuicEncrypter`/`QuicDecrypter` and `CryptoUtils`. The header protection key generation is also important.

**4. Identifying Relationships with JavaScript (and Browser Context):**

This requires thinking about *where* QUIC and TLS are used in a browser:

* **Network Requests:**  JavaScript initiates network requests using APIs like `fetch` or `XMLHttpRequest`. Underneath, the browser's network stack handles the protocol negotiation, including QUIC and TLS.
* **WebSockets:**  QUIC can also be the underlying transport for WebSockets.
* **Service Workers:**  Service workers can intercept network requests, and the same underlying network stack is used.

The connection is indirect. JavaScript doesn't directly call these C++ functions. Instead, it triggers actions (like fetching a resource) that cause the browser's network stack to initiate a QUIC connection, which in turn uses this `TlsHandshaker` for the secure handshake.

**5. Logical Reasoning and Examples:**

For logical reasoning, focusing on input and output of key methods is crucial:

* **`ProcessInput`:**  Input: Raw bytes of a TLS handshake message. Output: Triggers internal state changes within the `TlsHandshaker` and potentially sends out new handshake messages.
* **`VerifyCert`:** Input: The server's certificate chain. Output:  A success or failure indication (`ssl_verify_ok`, `ssl_verify_invalid`, `ssl_verify_retry`).

**6. User/Programming Errors:**

Consider common mistakes when *implementing* or *interacting* with a system like this (though direct user interaction with this low-level code is unlikely):

* **Incorrect Encryption Levels:** Sending data at the wrong encryption level is explicitly handled in `ProcessInput`.
* **Mismatched Configurations:** While not directly shown, issues could arise if the client and server have incompatible TLS configurations.
* **Certificate Issues:** Invalid or expired certificates are a common problem that this code handles.

**7. Debugging Clues and User Steps:**

To connect user actions to this code, trace the path:

1. **User Action:**  User types a URL in the address bar or clicks a link.
2. **Browser Initiates Request:** The browser resolves the domain name and determines a QUIC connection can be attempted.
3. **QUIC Connection Attempt:** The browser starts the QUIC handshake.
4. **TLS Handshake:** This `TlsHandshaker` class is instantiated to manage the TLS part of the QUIC handshake.
5. **`ProcessInput` is Called:**  As the server sends TLS handshake messages, the browser's QUIC implementation feeds these bytes into `ProcessInput`.
6. **`AdvanceHandshake` Drives the Process:** The `AdvanceHandshake` method orchestrates the TLS negotiation.
7. **`VerifyCert` is Called (Client-Side):**  The client verifies the server's certificate.
8. **Key Derivation:**  `SetWriteSecret` and `SetReadSecret` are called to establish encryption keys.
9. **Secure Communication:** Once the handshake is complete, data is exchanged using the established keys.

**Self-Correction/Refinement during the thought process:**

* Initially, I might focus too much on the low-level TLS details. It's important to pull back and remember the *purpose* of this code within the broader QUIC context.
*  The connection to JavaScript is indirect but crucial to understand. Don't get bogged down in thinking JavaScript *directly* calls these functions.
*  The error handling and debugging aspects are important for practical understanding. Think about what could go wrong and how this code handles it.
*  Realize that some components (like the `ProofVerifier`) are external and only interacted with through interfaces.

By following these steps, moving from a high-level understanding to detailed analysis and then connecting it to the broader context, one can effectively analyze a complex piece of code like this `tls_handshaker.cc` file.
这个C++源代码文件 `tls_handshaker.cc` 是 Chromium 网络栈中 QUIC 协议实现的关键部分，它的主要功能是**处理 QUIC 连接中的 TLS 握手过程**。更具体地说，它负责管理使用 TLS 协议在 QUIC 连接的两端（客户端和服务器）之间建立安全加密连接的复杂过程。

以下是该文件更详细的功能列表：

**核心 TLS 握手管理:**

* **状态机管理:**  它维护 TLS 握手的状态，并驱动握手过程的各个阶段，例如发送和接收 ClientHello、ServerHello、证书交换、密钥协商等。
* **BoringSSL 集成:** 它与 BoringSSL 库紧密集成，BoringSSL 是 Chromium 使用的 OpenSSL 的分支，负责底层的 TLS 加密和解密操作。
* **数据收发:**  它处理接收来自网络的 TLS 握手数据 (使用 `ProcessInput`)，并准备和发送 TLS 握手消息 (使用 `WriteMessage`)。
* **加密级别管理:** 它跟踪和管理连接的不同加密级别（例如，初始加密、握手加密、完全加密）。
* **错误处理:**  它处理 TLS 握手过程中可能发生的错误，并决定如何关闭连接。

**密钥协商与管理:**

* **密钥生成和设置:**  当 TLS 握手进行到密钥交换阶段时，它负责生成加密和解密密钥，并将其提供给 QUIC 连接的加密器和解密器 (`SetWriteSecret`, `SetReadSecret`)。
* **密钥滚动 (Key Rotation):**  它支持 QUIC 的密钥滚动机制，允许在连接生命周期内更新加密密钥，提高安全性 (`AdvanceKeysAndCreateCurrentOneRttDecrypter`, `CreateCurrentOneRttEncrypter`)。
* **导出密钥材料:**  它提供导出密钥材料的功能，用于派生其他安全密钥 (`ExportKeyingMaterialForLabel`)。

**证书验证 (服务器端和客户端):**

* **服务器证书验证 (客户端):**  当作为 QUIC 客户端时，它负责验证服务器提供的证书链，确保连接到可信的服务器 (`VerifyCert`)。这通常涉及调用一个单独的 `ProofVerifier` 组件。
* **客户端证书处理 (服务器端):** 当作为 QUIC 服务器时，它可能需要处理和验证客户端提供的证书（尽管在这个文件中可能看不到完整的服务器端证书处理逻辑）。

**与 QUIC 协议的集成:**

* **`QuicCryptoStream` 交互:** 它与 `QuicCryptoStream` 类交互，后者是 QUIC 中专门用于传输加密握手数据的流。
* **`QuicSession` 交互:** 它通过 `handshaker_delegate_` 与 `QuicSession` 类交互，获取连接的上下文信息并通知会话关于握手状态的改变。

**调试和监控:**

* **日志记录:**  代码中包含大量的日志记录，用于跟踪握手过程中的各种事件和状态，方便调试。
* **度量指标:**  虽然在这个文件中没有直接体现，但握手过程中的某些事件可能会被记录为度量指标，用于性能分析和监控。

**与 JavaScript 的关系:**

`tls_handshaker.cc` 本身是用 C++ 编写的，位于 Chromium 的网络栈深处，**不直接与 JavaScript 代码交互**。JavaScript 代码（在网页或 Node.js 环境中运行）通过浏览器或 Node.js 提供的 API 发起网络请求。当这些请求使用 QUIC 协议时，浏览器或 Node.js 的底层网络实现（包括 `tls_handshaker.cc` 这样的组件）会负责处理 QUIC 连接的建立和安全握手。

**举例说明:**

假设你在浏览器中访问一个使用 QUIC 协议的 HTTPS 网站 (例如 `https://example.com`)：

1. **JavaScript 发起请求:**  你的 JavaScript 代码可以使用 `fetch()` API 发起对 `https://example.com` 的请求。
2. **浏览器网络栈介入:** 浏览器会解析 URL，确定目标服务器支持 QUIC，并尝试建立 QUIC 连接。
3. **TlsHandshaker 启动:**  `tls_handshaker.cc` 中的代码会被实例化，作为 QUIC 连接建立过程的一部分。
4. **TLS 握手进行:** `TlsHandshaker` 会处理与服务器之间的 TLS 握手消息交换，例如发送 ClientHello，接收 ServerHello 和证书，并验证服务器证书。
5. **安全连接建立:**  一旦握手完成，加密密钥协商完成，浏览器和服务器之间就建立了一个安全的 QUIC 连接。
6. **数据传输:**  后续的 HTTP 请求和响应数据将通过这个安全的 QUIC 连接传输。

**逻辑推理 - 假设输入与输出:**

**假设输入 (客户端视角):**

* **输入 1:**  接收到来自服务器的 `ServerHello` TLS 消息（包含服务器选择的协议版本、加密套件等）。
* **输入 2:**  接收到来自服务器的 `Certificate` TLS 消息（包含服务器的证书链）。
* **输入 3:**  接收到来自服务器的 `ServerKeyExchange` 或 `EncryptedExtensions` 消息（取决于密钥协商方法）。

**预期输出 (客户端视角):**

* **输出 1:**  解析 `ServerHello` 消息，检查服务器是否支持客户端提议的协议版本和加密套件。
* **输出 2:**  调用证书验证逻辑 (`VerifyCert`)，尝试验证服务器证书的有效性和可信度。如果验证失败，可能会触发连接关闭。
* **输出 3:**  根据收到的密钥交换信息，生成共享密钥。
* **状态更新:**  更新内部握手状态，准备发送客户端的后续握手消息，例如 `ClientKeyExchange` 或 `Finished`。
* **触发密钥设置:**  调用 `SetReadSecret` 和 `SetWriteSecret`，设置相应的加密和解密密钥。

**用户或编程常见的使用错误:**

1. **配置错误的 TLS 证书 (服务器端):**  如果服务器配置了无效、过期或不匹配的 TLS 证书，客户端的 `VerifyCert` 过程会失败，导致连接无法建立。这通常是用户配置服务器时的错误。
    * **举例:**  网站管理员更新了网站的 IP 地址，但忘记更新 TLS 证书中的域名信息。当用户尝试连接时，客户端会因为证书域名不匹配而拒绝连接。
2. **客户端缺少必要的 CA 证书:** 如果客户端操作系统或浏览器缺少用于验证服务器证书链中 CA 证书的根证书，证书验证也会失败。这可能是用户操作系统配置问题。
    * **举例:**  用户使用一个过时的操作系统，其信任的根证书列表不包含某些新的证书颁发机构。
3. **TLS 版本或加密套件不兼容:**  如果客户端和服务器配置了不兼容的 TLS 版本或加密套件，握手过程可能会失败。这通常是服务器或客户端配置问题。
    * **举例:**  服务器只支持 TLS 1.3，而客户端只支持到 TLS 1.2。
4. **中间人攻击 (Man-in-the-middle attack):**  如果存在中间人拦截连接并篡改握手消息，`TlsHandshaker` 中的验证机制应该能够检测到这种攻击，并阻止连接建立。
5. **在不正确的加密级别发送数据:**  开发者如果错误地在握手完成前使用完全加密发送数据，`ProcessInput` 可能会因为加密级别不匹配而返回错误。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在浏览器中访问一个网站 `https://example.com`，并且连接过程中出现了 TLS 握手错误。作为调试人员，可以按照以下步骤追踪到 `tls_handshaker.cc`：

1. **用户操作:** 用户在浏览器地址栏输入 `https://example.com` 并按下回车键。
2. **DNS 解析:** 浏览器查询 `example.com` 的 IP 地址。
3. **建立连接:** 浏览器尝试与服务器的 IP 地址和端口建立 TCP 或 UDP 连接（如果是 QUIC）。
4. **QUIC 协商 (如果适用):** 如果客户端和服务器都支持 QUIC，浏览器会尝试升级到 QUIC 连接。这可能涉及到发送和接收 `QUIC Version Negotiation` 数据包。
5. **QUIC 握手开始:**  一旦确定使用 QUIC，就开始 QUIC 的握手过程，其中一部分是 TLS 握手。
6. **TlsHandshaker 初始化:**  Chromium 网络栈会创建 `TlsHandshaker` 的实例来管理 TLS 握手。
7. **TLS 消息交换:**
    * **客户端发送 ClientHello:** `TlsHandshaker` 会调用 BoringSSL 生成并发送 `ClientHello` 消息。
    * **服务器响应 (可能出错):** 服务器可能会发送 `ServerHello`，`Certificate`，或其他握手消息。如果服务器配置有问题，可能会发送错误的证书或触发其他错误。
    * **`ProcessInput` 被调用:** 客户端接收到服务器的消息后，Chromium 网络栈会将接收到的数据传递给 `TlsHandshaker::ProcessInput` 进行处理。
8. **证书验证 (`VerifyCert`):** 客户端的 `TlsHandshaker` 会调用 `VerifyCert` 来验证服务器提供的证书。
9. **错误发生:** 如果证书验证失败（例如，证书过期、域名不匹配、无法验证签名），或者在握手的其他阶段发生错误（例如，加密套件不匹配），`TlsHandshaker` 会检测到错误。
10. **连接关闭:**  `TlsHandshaker` 会调用 `CloseConnection` 方法，并可能记录错误信息。
11. **浏览器显示错误:** 浏览器最终会显示一个错误页面，例如 "您的连接不是私密连接" 或类似的 TLS 握手失败错误。

通过查看浏览器的网络调试工具 (例如 Chrome 的 "开发者工具" -> "Network")，或者 Chromium 的内部日志，可以更详细地查看握手过程中的消息交换和错误信息，从而定位到 `tls_handshaker.cc` 中可能出现问题的代码段。例如，如果日志显示证书验证失败，那么很可能是 `VerifyCert` 方法中的逻辑出现了问题。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/tls_handshaker.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/tls_handshaker.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "quiche/quic/core/quic_crypto_stream.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_stack_trace.h"

namespace quic {

#define ENDPOINT (SSL_is_server(ssl()) ? "TlsServer: " : "TlsClient: ")

TlsHandshaker::ProofVerifierCallbackImpl::ProofVerifierCallbackImpl(
    TlsHandshaker* parent)
    : parent_(parent) {}

TlsHandshaker::ProofVerifierCallbackImpl::~ProofVerifierCallbackImpl() {}

void TlsHandshaker::ProofVerifierCallbackImpl::Run(
    bool ok, const std::string& /*error_details*/,
    std::unique_ptr<ProofVerifyDetails>* details) {
  if (parent_ == nullptr) {
    return;
  }

  parent_->verify_details_ = std::move(*details);
  parent_->verify_result_ = ok ? ssl_verify_ok : ssl_verify_invalid;
  parent_->set_expected_ssl_error(SSL_ERROR_WANT_READ);
  parent_->proof_verify_callback_ = nullptr;
  if (parent_->verify_details_) {
    parent_->OnProofVerifyDetailsAvailable(*parent_->verify_details_);
  }
  parent_->AdvanceHandshake();
}

void TlsHandshaker::ProofVerifierCallbackImpl::Cancel() { parent_ = nullptr; }

TlsHandshaker::TlsHandshaker(QuicCryptoStream* stream, QuicSession* session)
    : stream_(stream), handshaker_delegate_(session) {}

TlsHandshaker::~TlsHandshaker() {
  if (proof_verify_callback_) {
    proof_verify_callback_->Cancel();
  }
}

bool TlsHandshaker::ProcessInput(absl::string_view input,
                                 EncryptionLevel level) {
  if (parser_error_ != QUIC_NO_ERROR) {
    return false;
  }
  // TODO(nharper): Call SSL_quic_read_level(ssl()) and check whether the
  // encryption level BoringSSL expects matches the encryption level that we
  // just received input at. If they mismatch, should ProcessInput return true
  // or false? If data is for a future encryption level, it should be queued for
  // later?
  if (SSL_provide_quic_data(ssl(), TlsConnection::BoringEncryptionLevel(level),
                            reinterpret_cast<const uint8_t*>(input.data()),
                            input.size()) != 1) {
    // SSL_provide_quic_data can fail for 3 reasons:
    // - API misuse (calling it before SSL_set_custom_quic_method, which we
    //   call in the TlsHandshaker c'tor)
    // - Memory exhaustion when appending data to its buffer
    // - Data provided at the wrong encryption level
    //
    // Of these, the only sensible error to handle is data provided at the wrong
    // encryption level.
    //
    // Note: the error provided below has a good-sounding enum value, although
    // it doesn't match the description as it's a QUIC Crypto specific error.
    parser_error_ = QUIC_INVALID_CRYPTO_MESSAGE_TYPE;
    parser_error_detail_ = "TLS stack failed to receive data";
    return false;
  }
  AdvanceHandshake();
  return true;
}

void TlsHandshaker::AdvanceHandshake() {
  if (is_connection_closed()) {
    return;
  }
  if (GetHandshakeState() >= HANDSHAKE_COMPLETE) {
    ProcessPostHandshakeMessage();
    return;
  }

  QUICHE_BUG_IF(
      quic_tls_server_async_done_no_flusher,
      SSL_is_server(ssl()) && !handshaker_delegate_->PacketFlusherAttached())
      << "is_server:" << SSL_is_server(ssl());

  QUIC_VLOG(1) << ENDPOINT << "Continuing handshake";
  last_tls_alert_.reset();
  int rv = SSL_do_handshake(ssl());

  if (is_connection_closed()) {
    return;
  }

  // If SSL_do_handshake return success(1) and we are in early data, it is
  // possible that we have provided ServerHello to BoringSSL but it hasn't been
  // processed. Retry SSL_do_handshake once will advance the handshake more in
  // that case. If there are no unprocessed ServerHello, the retry will return a
  // non-positive number.
  if (rv == 1 && SSL_in_early_data(ssl())) {
    OnEnterEarlyData();
    rv = SSL_do_handshake(ssl());

    if (is_connection_closed()) {
      return;
    }

    QUIC_VLOG(1) << ENDPOINT
                 << "SSL_do_handshake returned when entering early data. After "
                 << "retry, rv=" << rv
                 << ", SSL_in_early_data=" << SSL_in_early_data(ssl());
    // The retry should either
    // - Return <= 0 if the handshake is still pending, likely still in early
    //   data.
    // - Return 1 if the handshake has _actually_ finished. i.e.
    //   SSL_in_early_data should be false.
    //
    // In either case, it should not both return 1 and stay in early data.
    if (rv == 1 && SSL_in_early_data(ssl()) && !is_connection_closed()) {
      QUIC_BUG(quic_handshaker_stay_in_early_data)
          << "The original and the retry of SSL_do_handshake both returned "
             "success and in early data";
      CloseConnection(QUIC_HANDSHAKE_FAILED,
                      "TLS handshake failed: Still in early data after retry");
      return;
    }
  }

  if (rv == 1) {
    FinishHandshake();
    return;
  }
  int ssl_error = SSL_get_error(ssl(), rv);
  if (ssl_error == expected_ssl_error_) {
    return;
  }
  if (ShouldCloseConnectionOnUnexpectedError(ssl_error) &&
      !is_connection_closed()) {
    std::string ssl_error_stack = CryptoUtils::GetSSLErrorStack();
    QUIC_VLOG(1) << "SSL_do_handshake failed; SSL_get_error returns "
                 << ssl_error << ", SSLErrorStack: " << ssl_error_stack;
    if (last_tls_alert_.has_value()) {
      std::string error_details =
          absl::StrCat("TLS handshake failure (",
                       EncryptionLevelToString(last_tls_alert_->level), ") ",
                       static_cast<int>(last_tls_alert_->desc), ": ",
                       SSL_alert_desc_string_long(last_tls_alert_->desc),
                       ". SSLErrorStack:", ssl_error_stack);
      QUIC_DLOG(ERROR) << error_details;
      CloseConnection(TlsAlertToQuicErrorCode(last_tls_alert_->desc)
                          .value_or(QUIC_HANDSHAKE_FAILED),
                      static_cast<QuicIetfTransportErrorCodes>(
                          CRYPTO_ERROR_FIRST + last_tls_alert_->desc),
                      error_details);
    } else {
      CloseConnection(QUIC_HANDSHAKE_FAILED,
                      absl::StrCat("TLS handshake failed. SSLErrorStack:",
                                   ssl_error_stack));
    }
  }
}

void TlsHandshaker::CloseConnection(QuicErrorCode error,
                                    const std::string& reason_phrase) {
  QUICHE_DCHECK(!reason_phrase.empty());
  if (extra_error_details_.empty()) {
    stream()->OnUnrecoverableError(error, reason_phrase);
  } else {
    stream()->OnUnrecoverableError(
        error,
        absl::StrCat(reason_phrase, ". ExtraDetail:", extra_error_details_));
  }
  is_connection_closed_ = true;
}

void TlsHandshaker::CloseConnection(QuicErrorCode error,
                                    QuicIetfTransportErrorCodes ietf_error,
                                    const std::string& reason_phrase) {
  QUICHE_DCHECK(!reason_phrase.empty());
  if (extra_error_details_.empty()) {
    stream()->OnUnrecoverableError(error, ietf_error, reason_phrase);
  } else {
    stream()->OnUnrecoverableError(
        error, ietf_error,
        absl::StrCat(reason_phrase, ". ExtraDetail:", extra_error_details_));
  }
  is_connection_closed_ = true;
}

void TlsHandshaker::OnConnectionClosed(QuicErrorCode /*error*/,
                                       ConnectionCloseSource /*source*/) {
  is_connection_closed_ = true;
}

bool TlsHandshaker::ShouldCloseConnectionOnUnexpectedError(int /*ssl_error*/) {
  return true;
}

size_t TlsHandshaker::BufferSizeLimitForLevel(EncryptionLevel level) const {
  return SSL_quic_max_handshake_flight_len(
      ssl(), TlsConnection::BoringEncryptionLevel(level));
}

ssl_early_data_reason_t TlsHandshaker::EarlyDataReason() const {
  return SSL_get_early_data_reason(ssl());
}

const EVP_MD* TlsHandshaker::Prf(const SSL_CIPHER* cipher) {
#if BORINGSSL_API_VERSION >= 23
  return SSL_CIPHER_get_handshake_digest(cipher);
#else
  return EVP_get_digestbynid(SSL_CIPHER_get_prf_nid(cipher));
#endif
}

enum ssl_verify_result_t TlsHandshaker::VerifyCert(uint8_t* out_alert) {
  if (verify_result_ != ssl_verify_retry ||
      expected_ssl_error() == SSL_ERROR_WANT_CERTIFICATE_VERIFY) {
    enum ssl_verify_result_t result = verify_result_;
    verify_result_ = ssl_verify_retry;
    *out_alert = cert_verify_tls_alert_;
    return result;
  }
  const STACK_OF(CRYPTO_BUFFER)* cert_chain = SSL_get0_peer_certificates(ssl());
  if (cert_chain == nullptr) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    return ssl_verify_invalid;
  }
  // TODO(nharper): Pass the CRYPTO_BUFFERs into the QUIC stack to avoid copies.
  std::vector<std::string> certs;
  for (CRYPTO_BUFFER* cert : cert_chain) {
    certs.push_back(
        std::string(reinterpret_cast<const char*>(CRYPTO_BUFFER_data(cert)),
                    CRYPTO_BUFFER_len(cert)));
  }
  QUIC_DVLOG(1) << "VerifyCert: peer cert_chain length: " << certs.size();

  ProofVerifierCallbackImpl* proof_verify_callback =
      new ProofVerifierCallbackImpl(this);

  cert_verify_tls_alert_ = *out_alert;
  QuicAsyncStatus verify_result = VerifyCertChain(
      certs, &cert_verify_error_details_, &verify_details_,
      &cert_verify_tls_alert_,
      std::unique_ptr<ProofVerifierCallback>(proof_verify_callback));
  switch (verify_result) {
    case QUIC_SUCCESS:
      if (verify_details_) {
        OnProofVerifyDetailsAvailable(*verify_details_);
      }
      return ssl_verify_ok;
    case QUIC_PENDING:
      proof_verify_callback_ = proof_verify_callback;
      set_expected_ssl_error(SSL_ERROR_WANT_CERTIFICATE_VERIFY);
      return ssl_verify_retry;
    case QUIC_FAILURE:
    default:
      *out_alert = cert_verify_tls_alert_;
      QUIC_LOG(INFO) << "Cert chain verification failed: "
                     << cert_verify_error_details_;
      return ssl_verify_invalid;
  }
}

void TlsHandshaker::SetWriteSecret(EncryptionLevel level,
                                   const SSL_CIPHER* cipher,
                                   absl::Span<const uint8_t> write_secret) {
  QUIC_DVLOG(1) << ENDPOINT << "SetWriteSecret level=" << level;
  std::unique_ptr<QuicEncrypter> encrypter =
      QuicEncrypter::CreateFromCipherSuite(SSL_CIPHER_get_id(cipher));
  const EVP_MD* prf = Prf(cipher);
  CryptoUtils::SetKeyAndIV(prf, write_secret,
                           handshaker_delegate_->parsed_version(),
                           encrypter.get());
  std::vector<uint8_t> header_protection_key =
      CryptoUtils::GenerateHeaderProtectionKey(
          prf, write_secret, handshaker_delegate_->parsed_version(),
          encrypter->GetKeySize());
  encrypter->SetHeaderProtectionKey(
      absl::string_view(reinterpret_cast<char*>(header_protection_key.data()),
                        header_protection_key.size()));
  if (level == ENCRYPTION_FORWARD_SECURE) {
    QUICHE_DCHECK(latest_write_secret_.empty());
    latest_write_secret_.assign(write_secret.begin(), write_secret.end());
    one_rtt_write_header_protection_key_ = header_protection_key;
  }
  handshaker_delegate_->OnNewEncryptionKeyAvailable(level,
                                                    std::move(encrypter));
}

bool TlsHandshaker::SetReadSecret(EncryptionLevel level,
                                  const SSL_CIPHER* cipher,
                                  absl::Span<const uint8_t> read_secret) {
  QUIC_DVLOG(1) << ENDPOINT << "SetReadSecret level=" << level
                << ", connection_closed=" << is_connection_closed();

  if (is_connection_closed()) {
    return false;
  }

  std::unique_ptr<QuicDecrypter> decrypter =
      QuicDecrypter::CreateFromCipherSuite(SSL_CIPHER_get_id(cipher));
  const EVP_MD* prf = Prf(cipher);
  CryptoUtils::SetKeyAndIV(prf, read_secret,
                           handshaker_delegate_->parsed_version(),
                           decrypter.get());
  std::vector<uint8_t> header_protection_key =
      CryptoUtils::GenerateHeaderProtectionKey(
          prf, read_secret, handshaker_delegate_->parsed_version(),
          decrypter->GetKeySize());
  decrypter->SetHeaderProtectionKey(
      absl::string_view(reinterpret_cast<char*>(header_protection_key.data()),
                        header_protection_key.size()));
  if (level == ENCRYPTION_FORWARD_SECURE) {
    QUICHE_DCHECK(latest_read_secret_.empty());
    latest_read_secret_.assign(read_secret.begin(), read_secret.end());
    one_rtt_read_header_protection_key_ = header_protection_key;
  }
  return handshaker_delegate_->OnNewDecryptionKeyAvailable(
      level, std::move(decrypter),
      /*set_alternative_decrypter=*/false,
      /*latch_once_used=*/false);
}

std::unique_ptr<QuicDecrypter>
TlsHandshaker::AdvanceKeysAndCreateCurrentOneRttDecrypter() {
  if (latest_read_secret_.empty() || latest_write_secret_.empty() ||
      one_rtt_read_header_protection_key_.empty() ||
      one_rtt_write_header_protection_key_.empty()) {
    std::string error_details = "1-RTT secret(s) not set yet.";
    QUIC_BUG(quic_bug_10312_1) << error_details;
    CloseConnection(QUIC_INTERNAL_ERROR, error_details);
    return nullptr;
  }
  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl());
  const EVP_MD* prf = Prf(cipher);
  latest_read_secret_ = CryptoUtils::GenerateNextKeyPhaseSecret(
      prf, handshaker_delegate_->parsed_version(), latest_read_secret_);
  latest_write_secret_ = CryptoUtils::GenerateNextKeyPhaseSecret(
      prf, handshaker_delegate_->parsed_version(), latest_write_secret_);

  std::unique_ptr<QuicDecrypter> decrypter =
      QuicDecrypter::CreateFromCipherSuite(SSL_CIPHER_get_id(cipher));
  CryptoUtils::SetKeyAndIV(prf, latest_read_secret_,
                           handshaker_delegate_->parsed_version(),
                           decrypter.get());
  decrypter->SetHeaderProtectionKey(absl::string_view(
      reinterpret_cast<char*>(one_rtt_read_header_protection_key_.data()),
      one_rtt_read_header_protection_key_.size()));

  return decrypter;
}

std::unique_ptr<QuicEncrypter> TlsHandshaker::CreateCurrentOneRttEncrypter() {
  if (latest_write_secret_.empty() ||
      one_rtt_write_header_protection_key_.empty()) {
    std::string error_details = "1-RTT write secret not set yet.";
    QUIC_BUG(quic_bug_10312_2) << error_details;
    CloseConnection(QUIC_INTERNAL_ERROR, error_details);
    return nullptr;
  }
  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl());
  std::unique_ptr<QuicEncrypter> encrypter =
      QuicEncrypter::CreateFromCipherSuite(SSL_CIPHER_get_id(cipher));
  CryptoUtils::SetKeyAndIV(Prf(cipher), latest_write_secret_,
                           handshaker_delegate_->parsed_version(),
                           encrypter.get());
  encrypter->SetHeaderProtectionKey(absl::string_view(
      reinterpret_cast<char*>(one_rtt_write_header_protection_key_.data()),
      one_rtt_write_header_protection_key_.size()));
  return encrypter;
}

bool TlsHandshaker::ExportKeyingMaterialForLabel(absl::string_view label,
                                                 absl::string_view context,
                                                 size_t result_len,
                                                 std::string* result) {
  if (result == nullptr) {
    return false;
  }
  result->resize(result_len);
  return SSL_export_keying_material(
             ssl(), reinterpret_cast<uint8_t*>(&*result->begin()), result_len,
             label.data(), label.size(),
             reinterpret_cast<const uint8_t*>(context.data()), context.size(),
             !context.empty()) == 1;
}

void TlsHandshaker::WriteMessage(EncryptionLevel level,
                                 absl::string_view data) {
  stream_->WriteCryptoData(level, data);
}

void TlsHandshaker::FlushFlight() {}

void TlsHandshaker::SendAlert(EncryptionLevel level, uint8_t desc) {
  TlsAlert tls_alert;
  tls_alert.level = level;
  tls_alert.desc = desc;
  last_tls_alert_ = tls_alert;
}

void TlsHandshaker::MessageCallback(bool is_write, int /*version*/,
                                    int content_type, absl::string_view data) {
#if BORINGSSL_API_VERSION >= 17
  if (content_type == SSL3_RT_CLIENT_HELLO_INNER) {
    // Notify QuicConnectionDebugVisitor. Most TLS messages can be seen in
    // CRYPTO frames, but, with ECH enabled, the ClientHelloInner is encrypted
    // separately.
    if (is_write) {
      handshaker_delegate_->OnEncryptedClientHelloSent(data);
    } else {
      handshaker_delegate_->OnEncryptedClientHelloReceived(data);
    }
  }
#else   // BORINGSSL_API_VERSION
  (void)is_write;
  (void)content_type;
  (void)data;
#endif  // BORINGSSL_API_VERSION
}

}  // namespace quic

"""

```