Response:
Let's break down the thought process for analyzing this C++ file and addressing the prompt's requirements.

1. **Understand the Core Purpose:** The file path `net/third_party/quiche/src/quiche/quic/core/tls_client_handshaker.cc` and the class name `TlsClientHandshaker` immediately suggest this code is responsible for handling the client-side TLS handshake within a QUIC connection. The `.cc` extension signifies it's a C++ source file.

2. **Identify Key Dependencies:** The `#include` directives at the beginning reveal the file's dependencies. Notable ones include:
    * Standard C++ libraries (`<algorithm>`, `<cstring>`, etc.)
    * BoringSSL (`openssl/ssl.h`) - indicating the use of TLS.
    * QUIC core components (`quiche/quic/core/crypto/...`, `quiche/quic/core/quic_session.h`, etc.)
    * Abseil libraries (`absl/strings/...`) - common in Chromium projects.
    * Quiche platform APIs (`quiche/quic/platform/api/...`).

3. **Analyze the Class Structure:**  The `TlsClientHandshaker` class inherits from `TlsHandshaker`, implying a base class handles common TLS handshake logic, and this derived class handles client-specific aspects. The constructor takes several key parameters, suggesting the necessary information to initiate a client handshake: `QuicServerId`, `QuicCryptoStream`, `QuicSession`, `ProofVerifyContext`, `QuicCryptoClientConfig`, and `ProofHandler`.

4. **Deconstruct Functionality by Method:**  Go through the public methods and their implementations to understand the key actions the `TlsClientHandshaker` performs. Look for verbs and nouns that indicate purpose:
    * `CryptoConnect()`: Initiates the handshake.
    * `PrepareZeroRttConfig()`: Sets up for 0-RTT data.
    * `SetAlpn()`: Negotiates the application layer protocol.
    * `SetTransportParameters()`: Sends QUIC-specific configuration.
    * `ProcessTransportParameters()`: Handles the server's QUIC configuration.
    * `VerifyCertChain()`:  Verifies the server's certificate.
    * `FinishHandshake()`: Completes the handshake process.
    * `OnEnterEarlyData()`:  Handles entering 0-RTT.
    * `HandleZeroRttReject()`: Responds to a 0-RTT rejection.
    * Methods related to key management (`SetWriteSecret`, `AdvanceKeysAndCreateCurrentOneRttDecrypter`, etc.).
    * Methods querying handshake state (`encryption_established`, `one_rtt_keys_available`, `GetHandshakeState`).

5. **Connect to the Bigger Picture (QUIC Handshake):** Recognize how the methods fit into the overall QUIC handshake process. Client Hello, Server Hello, certificate verification, key exchange, transport parameter negotiation, etc. This context helps interpret the code's actions.

6. **Address Specific Prompt Questions:**

    * **Functionality List:**  Summarize the identified functionalities concisely.

    * **Relationship to JavaScript:**  Consider where TLS and networking interact with JavaScript in a browser. The primary link is through browser APIs like `fetch` or WebSockets over HTTPS (which QUIC underpins). Focus on the *outcome* of this code (establishing a secure connection) rather than direct code interaction. Mention the role in enabling secure data transfer for web applications.

    * **Logical Reasoning (Input/Output):** Choose a relatively straightforward function like `SetAlpn()`. Define a clear input (a list of ALPN strings) and analyze the output (success/failure and the side effect of configuring the SSL object). Consider edge cases like empty ALPN lists or invalid ALPN strings.

    * **User/Programming Errors:** Think about common mistakes when setting up a QUIC client. Invalid server names (SNI), incorrect ALPN configurations, or issues with certificate handling are good examples. Explain *why* these are errors in the context of the handshake.

    * **User Operation and Debugging:**  Trace back how a user action might lead to this code being executed. A simple browser navigation is a good starting point. Then, consider common debugging steps a developer might take when encountering connection issues. This involves network inspection tools and understanding the handshake flow.

7. **Refine and Organize:**  Structure the answer logically with clear headings and concise explanations. Use examples where appropriate. Ensure the language is clear and avoids overly technical jargon where possible, while still being accurate.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:** Maybe focus heavily on the OpenSSL API calls.
* **Correction:** While important, the *purpose* of those calls within the QUIC handshake is more relevant to the prompt. Shift the focus to the overall functionality and how it contributes to establishing a connection.

* **Initial Thought:**  Try to find specific JavaScript code that calls this C++ code.
* **Correction:**  Direct calls are unlikely. Focus on the *impact* on JavaScript developers and how this code enables secure communication that JavaScript relies on. Think about the abstraction layers involved.

* **Initial Thought:**  Go into extreme detail about every TLS concept.
* **Correction:**  Keep the explanations focused on the core function of the `TlsClientHandshaker` and avoid getting bogged down in low-level TLS details unless directly relevant to the prompt's questions.

By following these steps, combining domain knowledge with a systematic analysis of the code, and then refining the explanations, a comprehensive and accurate answer can be constructed.
这个文件 `net/third_party/quiche/src/quiche/quic/core/tls_client_handshaker.cc` 是 Chromium 网络栈中 QUIC 协议客户端握手过程的核心实现。它使用 TLS 协议来建立安全的 QUIC 连接。以下是它的主要功能：

**主要功能:**

1. **发起和管理 TLS 客户端握手:**
   - 负责启动 TLS 握手过程，生成 ClientHello 消息。
   - 处理服务器发来的 ServerHello、证书等消息。
   - 管理握手状态，从初始状态到密钥交换完成。

2. **配置 TLS 连接:**
   - 设置服务器名称指示 (SNI)，用于服务器选择正确的虚拟主机。
   - 设置应用层协议协商 (ALPN)，用于协商使用的应用层协议 (例如 HTTP/3)。
   - 设置传输参数，例如最大连接 ID、空闲超时等 QUIC 特有的参数。
   - 配置椭圆曲线 Diffie-Hellman (ECDHE) 群组。
   - 设置客户端证书 (如果需要)。
   - 支持并处理加密客户端Hello (ECH)。

3. **处理会话恢复 (Session Resumption):**
   - 查找并使用之前缓存的会话信息 (SSL_SESSION) 来加速握手过程 (0-RTT 或 1-RTT 恢复)。
   - 处理服务器的会话票证 (NewSessionTicket)。
   - 管理 0-RTT 数据的发送和处理，并处理 0-RTT 被拒绝的情况。

4. **验证服务器证书:**
   - 使用 `ProofVerifier` 接口来验证服务器提供的证书链的有效性。
   - 处理 OCSP Stapling 和 Signed Certificate Timestamps (SCTs)。
   - 将证书验证结果通知 `ProofHandler`。

5. **协商加密参数:**
   - 获取协商的密码套件、密钥交换群组、签名算法等信息。

6. **密钥派生和管理:**
   - 使用 TLS 协议协商的密钥材料来派生 QUIC 连接所需的加密密钥。
   - 管理不同加密级别的密钥 (Initial, Handshake, 1-RTT)。
   - 在密钥更新时安全地切换密钥。

7. **处理传输参数:**
   - 序列化客户端的传输参数并在 ClientHello 中发送。
   - 解析服务器返回的传输参数。
   - 将协商的传输参数通知 `QuicSession`。

8. **处理应用状态恢复:**
   - 如果启用了应用状态恢复，则在会话恢复时恢复之前的应用状态。

9. **处理握手完成消息:**
   - 接收并处理服务器的 HandshakeDone 消息。

10. **导出密钥材料 (Export Keying Material):**
    - 允许导出用于其他目的的密钥材料。

**与 JavaScript 功能的关系:**

`TlsClientHandshaker` 本身是用 C++ 编写的，与 JavaScript 没有直接的代码级别的交互。然而，它在浏览器网络栈中扮演着至关重要的角色，直接影响着 JavaScript 中发起的网络请求的安全性：

- **HTTPS 连接:** 当 JavaScript 代码使用 `fetch` API 或其他网络 API 发起 HTTPS 请求时，如果底层使用了 QUIC 协议，那么 `TlsClientHandshaker` 就负责建立这个安全连接。它确保了 JavaScript 发送和接收的数据是加密的，防止中间人攻击。
- **WebSockets over QUIC:**  如果 WebSocket 连接建立在 QUIC 之上，`TlsClientHandshaker` 同样负责建立安全的 TLS 通道，保护 WebSocket 通信的安全。
- **Service Worker 等:**  Service Worker 拦截的网络请求也可能使用 QUIC，并通过 `TlsClientHandshaker` 建立安全连接。

**举例说明:**

假设一个 JavaScript 应用程序使用 `fetch` API 向一个支持 QUIC 的 HTTPS 服务器发起请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当浏览器执行这段代码时，如果浏览器和服务器都支持 QUIC，并且网络条件允许，浏览器网络栈会尝试使用 QUIC 建立连接。`TlsClientHandshaker` 的工作流程如下：

1. **JavaScript 发起请求:**  `fetch` API 调用触发网络栈开始连接。
2. **QUIC 连接尝试:**  网络栈尝试建立 QUIC 连接。
3. **`TlsClientHandshaker` 启动:** `TlsClientHandshaker` 被创建并负责 TLS 握手。
4. **ClientHello 发送:**  `TlsClientHandshaker` 生成并发送包含 SNI、ALPN、传输参数等的 ClientHello 消息。
5. **ServerHello 处理:** 接收并处理服务器的 ServerHello 消息。
6. **证书验证:** `TlsClientHandshaker` 使用配置的 `ProofVerifier` 验证服务器证书。
7. **密钥交换:**  执行 TLS 密钥交换过程。
8. **传输参数协商:**  交换 QUIC 特有的传输参数。
9. **加密连接建立:**  TLS 握手完成，加密连接建立。
10. **数据传输:**  JavaScript 发起的请求数据通过加密的 QUIC 连接发送到服务器。
11. **响应处理:**  服务器的响应数据通过加密的 QUIC 连接返回，JavaScript 代码接收并处理。

**逻辑推理 (假设输入与输出):**

**假设输入:**

- **服务器 ID (`server_id_`):**  `example.com:443`
- **支持的 ALPN 列表:** `["h3", "http/1.1"]`
- **是否启用会话恢复:**  是，存在有效的缓存会话。

**输出:**

1. **`CryptoConnect()` 返回 `true`:**  握手启动成功。
2. **发送的 ClientHello 消息包含:**
   - SNI: `example.com`
   - ALPN:  包含 "h3" 和 "http/1.1"
   - 客户端传输参数，例如最大连接 ID 等。
   - 如果存在缓存会话，则包含会话 ID 以尝试恢复。
3. **如果会话恢复成功:**
   - `IsResumption()` 返回 `true`。
   - 可能发送 0-RTT 数据。
4. **如果证书验证成功:**
   - `VerifyCertChain()` 返回成功。
   - `OnProofVerifyDetailsAvailable()` 被调用，提供验证详情。
5. **最终 `FinishHandshake()` 完成后:**
   - `encryption_established()` 返回 `true`。
   - `one_rtt_keys_available()` 返回 `true`。
   - `crypto_negotiated_params()` 包含协商的密码套件等信息。
   - `session()->OnAlpnSelected()` 被调用，通知会话选择的 ALPN (例如 "h3")。

**用户或编程常见的使用错误:**

1. **SNI 配置错误:**  用户在配置客户端时，可能错误地设置了服务器的主机名，导致 `SSL_set_tlsext_host_name()` 失败，握手无法进行。
   ```c++
   // 错误的 SNI
   QuicServerId server_id("invalid.example.com", 443);
   ```
   **现象:** 连接失败，可能收到证书相关的错误。

2. **ALPN 配置不匹配:**  客户端提供的 ALPN 列表与服务器支持的 ALPN 列表没有交集。
   ```c++
   // 客户端只支持 http/1.1
   session()->GetAlpnsToOffer() = {"http/1.1"};
   // 服务器只支持 h3
   ```
   **现象:** 握手失败，服务器可能发送 `no_application_protocol` 警报。

3. **传输参数配置错误:**  配置的传输参数不符合规范或超出服务器支持的范围。
   ```c++
   // 设置一个非常大的最大连接 ID
   TransportParameters params;
   params.max_cid_length = 255; // 超出范围
   ```
   **现象:**  握手失败，服务器可能报告传输参数解析错误。

4. **证书验证失败:**  服务器提供的证书无效 (过期、自签名、域名不匹配等)。
   ```
   // 服务器配置了无效的证书
   ```
   **现象:** `VerifyCertChain()` 返回失败，连接被终止，`ProofHandler` 收到验证失败的通知。

5. **会话缓存问题:**  会话缓存失效或损坏，导致本应成功的 0-RTT 恢复失败。
   ```c++
   // 清空会话缓存进行测试
   crypto_config->session_cache()->Clear();
   ```
   **现象:**  即使之前成功连接过，也会进行完整的握手，而不是 0-RTT 或 1-RTT 恢复。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 HTTPS URL 并回车，或者 JavaScript 代码发起 `fetch` 请求。** 这是触发网络连接的起点。
2. **浏览器解析 URL，确定目标服务器的主机名和端口。**
3. **浏览器网络栈查找是否有可用的 QUIC 连接到该服务器。**
4. **如果不存在 QUIC 连接，则创建一个新的 `QuicSession`。**
5. **`TlsClientHandshaker` 被创建，负责该连接的 TLS 握手。** 此时，`TlsClientHandshaker` 的构造函数被调用，传递相关的配置信息。
6. **`CryptoConnect()` 方法被调用，启动握手过程。**  这是 `tls_client_handshaker.cc` 中代码开始执行的关键点。
7. **在 `CryptoConnect()` 中，会执行设置 SNI、ALPN、传输参数等操作。** 如果在这些步骤中出现问题，例如 SNI 设置失败，就会导致握手无法继续。
8. **BoringSSL 库的函数 (例如 `SSL_set_tlsext_host_name()`, `SSL_set_alpn_protos()`) 被调用来配置 TLS 连接。**  如果在这些底层函数中出现错误，可能是由于参数配置不当。
9. **`AdvanceHandshake()` 方法被调用，驱动 TLS 状态机前进。** 这会导致发送 ClientHello 消息。
10. **当收到服务器的消息时，例如 ServerHello，`TlsClientHandshaker` 中的回调函数会被调用来处理这些消息。**  例如，处理证书的逻辑在 `VerifyCertChain()` 中。
11. **如果证书验证失败，或者传输参数解析失败，连接会被关闭，并可能记录错误信息。**  调试时，查看网络日志和 Chromium 的内部日志 (chrome://net-internals/#quic) 可以提供线索。
12. **如果握手成功完成，`FinishHandshake()` 会被调用，通知上层连接已建立。**

**调试线索:**

- **网络日志 (如 Wireshark):** 可以捕获 QUIC 数据包，查看 ClientHello、ServerHello 等消息的内容，分析 SNI、ALPN、传输参数是否正确。
- **Chromium 内部日志 (chrome://net-internals/#quic):**  提供了 QUIC 连接的详细信息，包括握手过程中的状态、错误信息、传输参数等。
- **BoringSSL 日志 (需要编译时开启):** 可以提供更底层的 TLS 握手细节。
- **断点调试:**  在 `TlsClientHandshaker` 的关键方法中设置断点，例如 `CryptoConnect()`, `SetAlpn()`, `VerifyCertChain()`, `ProcessTransportParameters()`, 可以单步执行代码，查看变量的值和执行流程，定位问题所在。
- **错误码和错误信息:**  关注 `CloseConnection()` 调用时的错误码和错误信息，这可以指示握手失败的原因。

总而言之，`tls_client_handshaker.cc` 是 QUIC 客户端安全连接建立的核心，理解它的功能和工作流程对于调试 QUIC 连接问题至关重要。它虽然不直接与 JavaScript 交互，但它成功运行是 JavaScript 发起的安全网络请求的基础。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/tls_client_handshaker.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/tls_client_handshaker.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/ssl.h"
#include "quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_hostname_utils.h"
#include "quiche/common/quiche_text_utils.h"

namespace quic {

TlsClientHandshaker::TlsClientHandshaker(
    const QuicServerId& server_id, QuicCryptoStream* stream,
    QuicSession* session, std::unique_ptr<ProofVerifyContext> verify_context,
    QuicCryptoClientConfig* crypto_config,
    QuicCryptoClientStream::ProofHandler* proof_handler,
    bool has_application_state)
    : TlsHandshaker(stream, session),
      session_(session),
      server_id_(server_id),
      proof_verifier_(crypto_config->proof_verifier()),
      verify_context_(std::move(verify_context)),
      proof_handler_(proof_handler),
      session_cache_(crypto_config->session_cache()),
      user_agent_id_(crypto_config->user_agent_id()),
      pre_shared_key_(crypto_config->pre_shared_key()),
      crypto_negotiated_params_(new QuicCryptoNegotiatedParameters),
      has_application_state_(has_application_state),
      tls_connection_(crypto_config->ssl_ctx(), this, session->GetSSLConfig()) {
  if (crypto_config->tls_signature_algorithms().has_value()) {
    SSL_set1_sigalgs_list(ssl(),
                          crypto_config->tls_signature_algorithms()->c_str());
  }
  if (crypto_config->proof_source() != nullptr) {
    std::shared_ptr<const ClientProofSource::CertAndKey> cert_and_key =
        crypto_config->proof_source()->GetCertAndKey(server_id.host());
    if (cert_and_key != nullptr) {
      QUIC_DVLOG(1) << "Setting client cert and key for " << server_id.host();
      tls_connection_.SetCertChain(cert_and_key->chain->ToCryptoBuffers().value,
                                   cert_and_key->private_key.private_key());
    }
  }
#if BORINGSSL_API_VERSION >= 22
  if (!crypto_config->preferred_groups().empty()) {
    SSL_set1_group_ids(ssl(), crypto_config->preferred_groups().data(),
                       crypto_config->preferred_groups().size());
  }
#endif  // BORINGSSL_API_VERSION

#if BORINGSSL_API_VERSION >= 27
  // Make sure we use the right ALPS codepoint.
  SSL_set_alps_use_new_codepoint(ssl(),
                                 crypto_config->alps_use_new_codepoint());
#endif  // BORINGSSL_API_VERSION
}

TlsClientHandshaker::~TlsClientHandshaker() {}

bool TlsClientHandshaker::CryptoConnect() {
  if (!pre_shared_key_.empty()) {
    // TODO(b/154162689) add PSK support to QUIC+TLS.
    std::string error_details =
        "QUIC client pre-shared keys not yet supported with TLS";
    QUIC_BUG(quic_bug_10576_1) << error_details;
    CloseConnection(QUIC_HANDSHAKE_FAILED, error_details);
    return false;
  }

  // Make sure we use the right TLS extension codepoint.
  int use_legacy_extension = 0;
  if (session()->version().UsesLegacyTlsExtension()) {
    use_legacy_extension = 1;
  }
  SSL_set_quic_use_legacy_codepoint(ssl(), use_legacy_extension);

  // TODO(b/193650832) Add SetFromConfig to QUIC handshakers and remove reliance
  // on session pointer.
#if BORINGSSL_API_VERSION >= 16
  // Ask BoringSSL to randomize the order of TLS extensions.
  SSL_set_permute_extensions(ssl(), true);
#endif  // BORINGSSL_API_VERSION

  // Set the SNI to send, if any.
  SSL_set_connect_state(ssl());
  const bool allow_invalid_sni_for_test =
      GetQuicFlag(quic_client_allow_invalid_sni_for_test);
  if (QUIC_DLOG_INFO_IS_ON() &&
      !QuicHostnameUtils::IsValidSNI(server_id_.host())) {
    QUIC_DLOG(INFO) << "Client configured with invalid hostname \""
                    << server_id_.host() << "\", "
                    << (allow_invalid_sni_for_test
                            ? "sending it anyway for test."
                            : "not sending as SNI.");
  }
  if (!server_id_.host().empty() &&
      (QuicHostnameUtils::IsValidSNI(server_id_.host()) ||
       allow_invalid_sni_for_test) &&
      SSL_set_tlsext_host_name(ssl(), server_id_.host().c_str()) != 1) {
    return false;
  }

  if (!SetAlpn()) {
    CloseConnection(QUIC_HANDSHAKE_FAILED, "Client failed to set ALPN");
    return false;
  }

  // Set the Transport Parameters to send in the ClientHello
  if (!SetTransportParameters()) {
    CloseConnection(QUIC_HANDSHAKE_FAILED,
                    "Client failed to set Transport Parameters");
    return false;
  }

  // Set a session to resume, if there is one.
  if (session_cache_) {
    cached_state_ = session_cache_->Lookup(
        server_id_, session()->GetClock()->WallNow(), SSL_get_SSL_CTX(ssl()));
  }
  if (cached_state_) {
    SSL_set_session(ssl(), cached_state_->tls_session.get());
    if (!cached_state_->token.empty()) {
      session()->SetSourceAddressTokenToSend(cached_state_->token);
    }
  }

  SSL_set_enable_ech_grease(ssl(),
                            tls_connection_.ssl_config().ech_grease_enabled);
  if (!tls_connection_.ssl_config().ech_config_list.empty() &&
      !SSL_set1_ech_config_list(
          ssl(),
          reinterpret_cast<const uint8_t*>(
              tls_connection_.ssl_config().ech_config_list.data()),
          tls_connection_.ssl_config().ech_config_list.size())) {
    CloseConnection(QUIC_HANDSHAKE_FAILED,
                    "Client failed to set ECHConfigList");
    return false;
  }

  // Start the handshake.
  AdvanceHandshake();
  return session()->connection()->connected();
}

bool TlsClientHandshaker::PrepareZeroRttConfig(
    QuicResumptionState* cached_state) {
  std::string error_details;
  if (!cached_state->transport_params ||
      handshaker_delegate()->ProcessTransportParameters(
          *(cached_state->transport_params),
          /*is_resumption = */ true, &error_details) != QUIC_NO_ERROR) {
    QUIC_BUG(quic_bug_10576_2)
        << "Unable to parse cached transport parameters.";
    CloseConnection(QUIC_HANDSHAKE_FAILED,
                    "Client failed to parse cached Transport Parameters.");
    return false;
  }

  session()->connection()->OnTransportParametersResumed(
      *(cached_state->transport_params));
  session()->OnConfigNegotiated();

  if (has_application_state_) {
    if (!cached_state->application_state ||
        !session()->ResumeApplicationState(
            cached_state->application_state.get())) {
      QUIC_BUG(quic_bug_10576_3) << "Unable to parse cached application state.";
      CloseConnection(QUIC_HANDSHAKE_FAILED,
                      "Client failed to parse cached application state.");
      return false;
    }
  }
  return true;
}

static bool IsValidAlpn(const std::string& alpn_string) {
  return alpn_string.length() <= std::numeric_limits<uint8_t>::max();
}

bool TlsClientHandshaker::SetAlpn() {
  std::vector<std::string> alpns = session()->GetAlpnsToOffer();
  if (alpns.empty()) {
    if (allow_empty_alpn_for_tests_) {
      return true;
    }

    QUIC_BUG(quic_bug_10576_4) << "ALPN missing";
    return false;
  }
  if (!std::all_of(alpns.begin(), alpns.end(), IsValidAlpn)) {
    QUIC_BUG(quic_bug_10576_5) << "ALPN too long";
    return false;
  }

  // SSL_set_alpn_protos expects a sequence of one-byte-length-prefixed
  // strings.
  uint8_t alpn[1024];
  QuicDataWriter alpn_writer(sizeof(alpn), reinterpret_cast<char*>(alpn));
  bool success = true;
  for (const std::string& alpn_string : alpns) {
    success = success && alpn_writer.WriteUInt8(alpn_string.size()) &&
              alpn_writer.WriteStringPiece(alpn_string);
  }
  success =
      success && (SSL_set_alpn_protos(ssl(), alpn, alpn_writer.length()) == 0);
  if (!success) {
    QUIC_BUG(quic_bug_10576_6)
        << "Failed to set ALPN: "
        << quiche::QuicheTextUtils::HexDump(
               absl::string_view(alpn_writer.data(), alpn_writer.length()));
    return false;
  }

  // Enable ALPS only for versions that use HTTP/3 frames.
  for (const std::string& alpn_string : alpns) {
    for (const ParsedQuicVersion& version : session()->supported_versions()) {
      if (!version.UsesHttp3() || AlpnForVersion(version) != alpn_string) {
        continue;
      }
      if (SSL_add_application_settings(
              ssl(), reinterpret_cast<const uint8_t*>(alpn_string.data()),
              alpn_string.size(), nullptr, /* settings_len = */ 0) != 1) {
        QUIC_BUG(quic_bug_10576_7) << "Failed to enable ALPS.";
        return false;
      }
      break;
    }
  }

  QUIC_DLOG(INFO) << "Client using ALPN: '" << alpns[0] << "'";
  return true;
}

bool TlsClientHandshaker::SetTransportParameters() {
  TransportParameters params;
  params.perspective = Perspective::IS_CLIENT;
  params.legacy_version_information =
      TransportParameters::LegacyVersionInformation();
  params.legacy_version_information->version =
      CreateQuicVersionLabel(session()->supported_versions().front());
  params.version_information = TransportParameters::VersionInformation();
  const QuicVersionLabel version = CreateQuicVersionLabel(session()->version());
  params.version_information->chosen_version = version;
  params.version_information->other_versions.push_back(version);

  if (!handshaker_delegate()->FillTransportParameters(&params)) {
    return false;
  }

  // Notify QuicConnectionDebugVisitor.
  session()->connection()->OnTransportParametersSent(params);

  std::vector<uint8_t> param_bytes;
  return SerializeTransportParameters(params, &param_bytes) &&
         SSL_set_quic_transport_params(ssl(), param_bytes.data(),
                                       param_bytes.size()) == 1;
}

bool TlsClientHandshaker::ProcessTransportParameters(
    std::string* error_details) {
  received_transport_params_ = std::make_unique<TransportParameters>();
  const uint8_t* param_bytes;
  size_t param_bytes_len;
  SSL_get_peer_quic_transport_params(ssl(), &param_bytes, &param_bytes_len);
  if (param_bytes_len == 0) {
    *error_details = "Server's transport parameters are missing";
    return false;
  }
  std::string parse_error_details;
  if (!ParseTransportParameters(
          session()->connection()->version(), Perspective::IS_SERVER,
          param_bytes, param_bytes_len, received_transport_params_.get(),
          &parse_error_details)) {
    QUICHE_DCHECK(!parse_error_details.empty());
    *error_details =
        "Unable to parse server's transport parameters: " + parse_error_details;
    return false;
  }

  // Notify QuicConnectionDebugVisitor.
  session()->connection()->OnTransportParametersReceived(
      *received_transport_params_);

  if (received_transport_params_->legacy_version_information.has_value()) {
    if (received_transport_params_->legacy_version_information->version !=
        CreateQuicVersionLabel(session()->connection()->version())) {
      *error_details = "Version mismatch detected";
      return false;
    }
    if (CryptoUtils::ValidateServerHelloVersions(
            received_transport_params_->legacy_version_information
                ->supported_versions,
            session()->connection()->server_supported_versions(),
            error_details) != QUIC_NO_ERROR) {
      QUICHE_DCHECK(!error_details->empty());
      return false;
    }
  }
  if (received_transport_params_->version_information.has_value()) {
    if (!CryptoUtils::ValidateChosenVersion(
            received_transport_params_->version_information->chosen_version,
            session()->version(), error_details)) {
      QUICHE_DCHECK(!error_details->empty());
      return false;
    }
    if (!CryptoUtils::CryptoUtils::ValidateServerVersions(
            received_transport_params_->version_information->other_versions,
            session()->version(),
            session()->client_original_supported_versions(), error_details)) {
      QUICHE_DCHECK(!error_details->empty());
      return false;
    }
  }

  if (handshaker_delegate()->ProcessTransportParameters(
          *received_transport_params_, /* is_resumption = */ false,
          error_details) != QUIC_NO_ERROR) {
    QUICHE_DCHECK(!error_details->empty());
    return false;
  }

  session()->OnConfigNegotiated();
  if (is_connection_closed()) {
    *error_details =
        "Session closed the connection when parsing negotiated config.";
    return false;
  }
  return true;
}

int TlsClientHandshaker::num_sent_client_hellos() const { return 0; }

bool TlsClientHandshaker::ResumptionAttempted() const {
  QUIC_BUG_IF(quic_tls_client_resumption_attempted, !encryption_established_);
  return cached_state_ != nullptr;
}

bool TlsClientHandshaker::IsResumption() const {
  QUIC_BUG_IF(quic_bug_12736_1, !one_rtt_keys_available());
  return SSL_session_reused(ssl()) == 1;
}

bool TlsClientHandshaker::EarlyDataAccepted() const {
  QUIC_BUG_IF(quic_bug_12736_2, !one_rtt_keys_available());
  return SSL_early_data_accepted(ssl()) == 1;
}

ssl_early_data_reason_t TlsClientHandshaker::EarlyDataReason() const {
  return TlsHandshaker::EarlyDataReason();
}

bool TlsClientHandshaker::ReceivedInchoateReject() const {
  QUIC_BUG_IF(quic_bug_12736_3, !one_rtt_keys_available());
  // REJ messages are a QUIC crypto feature, so TLS always returns false.
  return false;
}

int TlsClientHandshaker::num_scup_messages_received() const {
  // SCUP messages aren't sent or received when using the TLS handshake.
  return 0;
}

std::string TlsClientHandshaker::chlo_hash() const { return ""; }

bool TlsClientHandshaker::ExportKeyingMaterial(absl::string_view label,
                                               absl::string_view context,
                                               size_t result_len,
                                               std::string* result) {
  return ExportKeyingMaterialForLabel(label, context, result_len, result);
}

bool TlsClientHandshaker::encryption_established() const {
  return encryption_established_;
}

bool TlsClientHandshaker::IsCryptoFrameExpectedForEncryptionLevel(
    EncryptionLevel level) const {
  return level != ENCRYPTION_ZERO_RTT;
}

EncryptionLevel TlsClientHandshaker::GetEncryptionLevelToSendCryptoDataOfSpace(
    PacketNumberSpace space) const {
  switch (space) {
    case INITIAL_DATA:
      return ENCRYPTION_INITIAL;
    case HANDSHAKE_DATA:
      return ENCRYPTION_HANDSHAKE;
    default:
      QUICHE_DCHECK(false);
      return NUM_ENCRYPTION_LEVELS;
  }
}

bool TlsClientHandshaker::one_rtt_keys_available() const {
  return state_ >= HANDSHAKE_COMPLETE;
}

const QuicCryptoNegotiatedParameters&
TlsClientHandshaker::crypto_negotiated_params() const {
  return *crypto_negotiated_params_;
}

CryptoMessageParser* TlsClientHandshaker::crypto_message_parser() {
  return TlsHandshaker::crypto_message_parser();
}

HandshakeState TlsClientHandshaker::GetHandshakeState() const { return state_; }

size_t TlsClientHandshaker::BufferSizeLimitForLevel(
    EncryptionLevel level) const {
  return TlsHandshaker::BufferSizeLimitForLevel(level);
}

std::unique_ptr<QuicDecrypter>
TlsClientHandshaker::AdvanceKeysAndCreateCurrentOneRttDecrypter() {
  return TlsHandshaker::AdvanceKeysAndCreateCurrentOneRttDecrypter();
}

std::unique_ptr<QuicEncrypter>
TlsClientHandshaker::CreateCurrentOneRttEncrypter() {
  return TlsHandshaker::CreateCurrentOneRttEncrypter();
}

void TlsClientHandshaker::OnOneRttPacketAcknowledged() {
  OnHandshakeConfirmed();
}

void TlsClientHandshaker::OnHandshakePacketSent() {
  if (initial_keys_dropped_) {
    return;
  }
  initial_keys_dropped_ = true;
  handshaker_delegate()->DiscardOldEncryptionKey(ENCRYPTION_INITIAL);
  handshaker_delegate()->DiscardOldDecryptionKey(ENCRYPTION_INITIAL);
}

void TlsClientHandshaker::OnConnectionClosed(QuicErrorCode error,
                                             ConnectionCloseSource source) {
  TlsHandshaker::OnConnectionClosed(error, source);
}

void TlsClientHandshaker::OnHandshakeDoneReceived() {
  if (!one_rtt_keys_available()) {
    CloseConnection(QUIC_HANDSHAKE_FAILED,
                    "Unexpected handshake done received");
    return;
  }
  OnHandshakeConfirmed();
}

void TlsClientHandshaker::OnNewTokenReceived(absl::string_view token) {
  if (token.empty()) {
    return;
  }
  if (session_cache_ != nullptr) {
    session_cache_->OnNewTokenReceived(server_id_, token);
  }
}

void TlsClientHandshaker::SetWriteSecret(
    EncryptionLevel level, const SSL_CIPHER* cipher,
    absl::Span<const uint8_t> write_secret) {
  if (is_connection_closed()) {
    return;
  }
  if (level == ENCRYPTION_FORWARD_SECURE || level == ENCRYPTION_ZERO_RTT) {
    encryption_established_ = true;
  }
  TlsHandshaker::SetWriteSecret(level, cipher, write_secret);
  if (level == ENCRYPTION_FORWARD_SECURE) {
    handshaker_delegate()->DiscardOldEncryptionKey(ENCRYPTION_ZERO_RTT);
  }
}

void TlsClientHandshaker::OnHandshakeConfirmed() {
  QUICHE_DCHECK(one_rtt_keys_available());
  if (state_ >= HANDSHAKE_CONFIRMED) {
    return;
  }
  state_ = HANDSHAKE_CONFIRMED;
  handshaker_delegate()->OnTlsHandshakeConfirmed();
  handshaker_delegate()->DiscardOldEncryptionKey(ENCRYPTION_HANDSHAKE);
  handshaker_delegate()->DiscardOldDecryptionKey(ENCRYPTION_HANDSHAKE);
}

QuicAsyncStatus TlsClientHandshaker::VerifyCertChain(
    const std::vector<std::string>& certs, std::string* error_details,
    std::unique_ptr<ProofVerifyDetails>* details, uint8_t* out_alert,
    std::unique_ptr<ProofVerifierCallback> callback) {
  const uint8_t* ocsp_response_raw;
  size_t ocsp_response_len;
  SSL_get0_ocsp_response(ssl(), &ocsp_response_raw, &ocsp_response_len);
  std::string ocsp_response(reinterpret_cast<const char*>(ocsp_response_raw),
                            ocsp_response_len);
  const uint8_t* sct_list_raw;
  size_t sct_list_len;
  SSL_get0_signed_cert_timestamp_list(ssl(), &sct_list_raw, &sct_list_len);
  std::string sct_list(reinterpret_cast<const char*>(sct_list_raw),
                       sct_list_len);

  return proof_verifier_->VerifyCertChain(
      server_id_.host(), server_id_.port(), certs, ocsp_response, sct_list,
      verify_context_.get(), error_details, details, out_alert,
      std::move(callback));
}

void TlsClientHandshaker::OnProofVerifyDetailsAvailable(
    const ProofVerifyDetails& verify_details) {
  proof_handler_->OnProofVerifyDetailsAvailable(verify_details);
}

void TlsClientHandshaker::FinishHandshake() {
  FillNegotiatedParams();

  QUICHE_CHECK(!SSL_in_early_data(ssl()));

  QUIC_DLOG(INFO) << "Client: handshake finished";

  std::string error_details;
  if (!ProcessTransportParameters(&error_details)) {
    QUICHE_DCHECK(!error_details.empty());
    CloseConnection(QUIC_HANDSHAKE_FAILED, error_details);
    return;
  }

  const uint8_t* alpn_data = nullptr;
  unsigned alpn_length = 0;
  SSL_get0_alpn_selected(ssl(), &alpn_data, &alpn_length);

  if (alpn_length == 0) {
    QUIC_DLOG(ERROR) << "Client: server did not select ALPN";
    // TODO(b/130164908) this should send no_application_protocol
    // instead of QUIC_HANDSHAKE_FAILED.
    CloseConnection(QUIC_HANDSHAKE_FAILED, "Server did not select ALPN");
    return;
  }

  std::string received_alpn_string(reinterpret_cast<const char*>(alpn_data),
                                   alpn_length);
  std::vector<std::string> offered_alpns = session()->GetAlpnsToOffer();
  if (std::find(offered_alpns.begin(), offered_alpns.end(),
                received_alpn_string) == offered_alpns.end()) {
    QUIC_LOG(ERROR) << "Client: received mismatched ALPN '"
                    << received_alpn_string;
    // TODO(b/130164908) this should send no_application_protocol
    // instead of QUIC_HANDSHAKE_FAILED.
    CloseConnection(QUIC_HANDSHAKE_FAILED, "Client received mismatched ALPN");
    return;
  }
  session()->OnAlpnSelected(received_alpn_string);
  QUIC_DLOG(INFO) << "Client: server selected ALPN: '" << received_alpn_string
                  << "'";

  // Parse ALPS extension.
  const uint8_t* alps_data;
  size_t alps_length;
  SSL_get0_peer_application_settings(ssl(), &alps_data, &alps_length);
  if (alps_length > 0) {
    auto error = session()->OnAlpsData(alps_data, alps_length);
    if (error.has_value()) {
      // Calling CloseConnection() is safe even in case OnAlpsData() has
      // already closed the connection.
      CloseConnection(QUIC_HANDSHAKE_FAILED,
                      absl::StrCat("Error processing ALPS data: ", *error));
      return;
    }
  }

  state_ = HANDSHAKE_COMPLETE;
  handshaker_delegate()->OnTlsHandshakeComplete();
}

void TlsClientHandshaker::OnEnterEarlyData() {
  QUICHE_DCHECK(SSL_in_early_data(ssl()));

  // TODO(wub): It might be unnecessary to FillNegotiatedParams() at this time,
  // because we fill it again when handshake completes.
  FillNegotiatedParams();

  // If we're attempting a 0-RTT handshake, then we need to let the transport
  // and application know what state to apply to early data.
  PrepareZeroRttConfig(cached_state_.get());
}

void TlsClientHandshaker::FillNegotiatedParams() {
  const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl());
  if (cipher) {
    crypto_negotiated_params_->cipher_suite =
        SSL_CIPHER_get_protocol_id(cipher);
  }
  crypto_negotiated_params_->key_exchange_group = SSL_get_curve_id(ssl());
  crypto_negotiated_params_->peer_signature_algorithm =
      SSL_get_peer_signature_algorithm(ssl());
  crypto_negotiated_params_->encrypted_client_hello = SSL_ech_accepted(ssl());
}

void TlsClientHandshaker::ProcessPostHandshakeMessage() {
  int rv = SSL_process_quic_post_handshake(ssl());
  if (rv != 1) {
    CloseConnection(QUIC_HANDSHAKE_FAILED, "Unexpected post-handshake data");
  }
}

bool TlsClientHandshaker::ShouldCloseConnectionOnUnexpectedError(
    int ssl_error) {
  if (ssl_error != SSL_ERROR_EARLY_DATA_REJECTED) {
    return true;
  }
  HandleZeroRttReject();
  return false;
}

void TlsClientHandshaker::HandleZeroRttReject() {
  QUIC_DLOG(INFO) << "0-RTT handshake attempted but was rejected by the server";
  QUICHE_DCHECK(session_cache_);
  // Disable encrytion to block outgoing data until 1-RTT keys are available.
  encryption_established_ = false;
  handshaker_delegate()->OnZeroRttRejected(EarlyDataReason());
  SSL_reset_early_data_reject(ssl());
  session_cache_->ClearEarlyData(server_id_);
  AdvanceHandshake();
}

void TlsClientHandshaker::InsertSession(bssl::UniquePtr<SSL_SESSION> session) {
  if (!received_transport_params_) {
    QUIC_BUG(quic_bug_10576_8) << "Transport parameters isn't received";
    return;
  }
  if (session_cache_ == nullptr) {
    QUIC_DVLOG(1) << "No session cache, not inserting a session";
    return;
  }
  if (has_application_state_ && !received_application_state_) {
    // Application state is not received yet. cache the sessions.
    if (cached_tls_sessions_[0] != nullptr) {
      cached_tls_sessions_[1] = std::move(cached_tls_sessions_[0]);
    }
    cached_tls_sessions_[0] = std::move(session);
    return;
  }
  session_cache_->Insert(server_id_, std::move(session),
                         *received_transport_params_,
                         received_application_state_.get());
}

void TlsClientHandshaker::WriteMessage(EncryptionLevel level,
                                       absl::string_view data) {
  if (level == ENCRYPTION_HANDSHAKE && state_ < HANDSHAKE_PROCESSED) {
    state_ = HANDSHAKE_PROCESSED;
  }
  TlsHandshaker::WriteMessage(level, data);
}

void TlsClientHandshaker::SetServerApplicationStateForResumption(
    std::unique_ptr<ApplicationState> application_state) {
  QUICHE_DCHECK(one_rtt_keys_available());
  received_application_state_ = std::move(application_state);
  // At least one tls session is cached before application state is received. So
  // insert now.
  if (session_cache_ != nullptr && cached_tls_sessions_[0] != nullptr) {
    if (cached_tls_sessions_[1] != nullptr) {
      // Insert the older session first.
      session_cache_->Insert(server_id_, std::move(cached_tls_sessions_[1]),
                             *received_transport_params_,
                             received_application_state_.get());
    }
    session_cache_->Insert(server_id_, std::move(cached_tls_sessions_[0]),
                           *received_transport_params_,
                           received_application_state_.get());
  }
}

}  // namespace quic

"""

```