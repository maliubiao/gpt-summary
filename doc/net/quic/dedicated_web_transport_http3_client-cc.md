Response:
My thinking process to analyze the provided C++ code snippet for `dedicated_web_transport_http3_client.cc` went through these stages:

1. **Identify the Core Purpose:** The filename itself gives a strong clue: `dedicated_web_transport_http3_client`. This suggests it's a client implementation specifically for the Dedicated WebTransport protocol over HTTP/3.

2. **Scan for Key Classes and Data Structures:**  I looked for prominent class names and data structures to understand the major components involved. I noted:
    * `DedicatedWebTransportHttp3Client`: The central class, likely managing the connection lifecycle.
    * `WebTransportClientVisitor`: An interface, suggesting a callback mechanism for informing the user of events.
    * `DedicatedWebTransportHttp3ClientSession`:  A QUIC session specialized for WebTransport.
    * `ConnectStream`: A stream specifically for the initial CONNECT request.
    * `WebTransportSession`:  The quiche::quic class representing the WebTransport session.
    * Various QUIC-related classes like `QuicConnection`, `QuicConfig`, `QuicCryptoClientConfig`, etc.

3. **Analyze Functionality by Examining Key Methods:** I then focused on the public and important private methods to understand the sequence of operations:
    * `DedicatedWebTransportHttp3Client` (constructor): Initialization, taking URL, origin, visitor, etc.
    * `Connect()`:  Initiates the connection process. The `DoLoop` method and the `CONNECT_STATE_` enums clearly indicate a state machine for connection establishment.
    * `Close()`:  Handles closing the WebTransport session.
    * `session()`:  Returns the underlying WebTransport session.
    * `DoLoop()`:  The core state machine logic for the connection process. I mentally traced the different states and what each state likely does (proxy checking, host resolution, QUIC connection setup, sending the CONNECT request).
    * `TransitionToState()`: Manages the WebTransport state and notifies the visitor.
    * Callback methods like `OnSessionReady()`, `OnSessionClosed()`, `OnDatagramReceived()`, etc.: These indicate how the client reacts to events from the underlying QUIC connection and WebTransport session.

4. **Look for JavaScript Interaction Clues:** I searched for any keywords or concepts that might link to JavaScript. The primary connection is the *purpose* of WebTransport itself. It's designed to provide low-latency, bidirectional communication between a web browser (running JavaScript) and a server. While the C++ code doesn't *directly* call JavaScript functions, its actions are essential for enabling the WebTransport API in the browser.

5. **Identify Potential User Errors:**  I considered common mistakes a developer might make when using this client indirectly via the JavaScript API:
    * Invalid URL or scheme.
    * Trying to connect when QUIC is disabled.
    * Network issues (proxy configuration).
    * Server not supporting WebTransport.
    * Incorrect certificate fingerprints.

6. **Trace the User Interaction Path:**  I imagined the steps a user takes in a browser to trigger this code:
    1. Open a web page containing JavaScript.
    2. The JavaScript uses the `WebTransport` API to initiate a connection to a server.
    3. The browser's network stack (including this C++ code) handles the underlying protocol negotiation and connection management.

7. **Infer Logic and Assumptions:**  Based on the code structure, I made assumptions about the flow:
    * The connection process is asynchronous, relying on callbacks.
    * It handles proxy configuration.
    * It performs TLS handshake using QUIC's crypto mechanisms.
    * It manages the lifecycle of the underlying QUIC connection.

8. **Summarize the Functionality:**  Finally, I synthesized the information gathered into a concise summary of the file's purpose and key responsibilities. I focused on the "what" and "why" of the code.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on the QUIC details. I then realized the prompt specifically asked about the *WebTransport* client, so I shifted my focus to the parts of the code that directly dealt with WebTransport concepts (like `WebTransportSession`, the CONNECT request, and the visitor pattern).
* I also initially missed the significance of the `WebTransportParameters` struct and how it influences certificate verification. Re-reading the code helped me identify this.
* I made sure to explicitly connect the C++ implementation to the JavaScript API, even though the direct interaction isn't in this code snippet. The C++ code is the *implementation* behind the browser's JavaScript API.
好的，让我们来分析一下 `net/quic/dedicated_web_transport_http3_client.cc` 这个 Chromium 网络栈的源代码文件。

**功能归纳:**

这个文件实现了 Chromium 中 **Dedicated WebTransport over HTTP/3** 的客户端功能。  它的主要职责是建立、维护和管理与服务器之间的 WebTransport 连接，并处理 WebTransport 会话的生命周期。

更具体地说，它负责以下几个核心任务：

1. **连接建立 (Connection Establishment):**
   - 处理与服务器的 QUIC 连接握手。
   - 发送 HTTP/3 的 `CONNECT` 请求来升级到 WebTransport 协议。
   - 处理服务器的响应，确认 WebTransport 会话的建立。
   - 管理连接建立过程中的各种状态和错误。

2. **会话管理 (Session Management):**
   - 维护 WebTransport 会话的状态（例如：连接中、已连接、已关闭、失败）。
   - 监听并处理来自服务器的 WebTransport 事件（例如：会话准备就绪、会话关闭）。
   - 管理底层 QUIC 连接的生命周期，并在 WebTransport 会话关闭时关闭 QUIC 连接。

3. **数据传输 (Data Transfer):**
   - 通过底层的 QUIC 连接发送和接收 WebTransport 数据报 (Datagrams)。
   - 管理 WebTransport 的双向流 (Bidirectional Streams) 和单向流 (Unidirectional Streams) 的创建和接收。

4. **错误处理 (Error Handling):**
   - 捕获并处理连接建立和会话运行期间发生的各种错误。
   - 将错误信息传递给上层 (通常是通过 `WebTransportClientVisitor`)。

5. **配置管理 (Configuration Management):**
   - 处理 WebTransport 相关的配置参数，例如服务器证书指纹。
   - 支持开发者模式下的特殊配置。

6. **日志记录和指标 (Logging and Metrics):**
   - 使用 Chromium 的 NetLog 框架记录连接和会话事件，用于调试和监控。
   - 记录 WebTransport 相关的指标数据 (例如，协商的协议版本)。

**与 JavaScript 的关系及举例说明:**

这个 C++ 文件是浏览器实现 WebTransport API 的一部分。JavaScript 代码通过浏览器提供的 `WebTransport` 接口与这个 C++ 代码进行交互。

**举例说明:**

假设 JavaScript 代码在网页中尝试建立一个 WebTransport 连接：

```javascript
const wt = new WebTransport('https://example.com/webtransport');

wt.ready.then(() => {
  console.log('WebTransport connection is ready!');
  // 可以开始发送和接收数据了
});

wt.closed.then(() => {
  console.log('WebTransport connection closed.');
});

wt.datagrams.readable.getReader().read().then(({ value, done }) => {
  if (done) {
    console.log('No more datagrams!');
    return;
  }
  console.log('Received datagram:', new TextDecoder().decode(value));
  // 进一步处理接收到的数据报
});

// ... 发送数据报和流的操作 ...
```

当 JavaScript 执行 `new WebTransport('https://example.com/webtransport')` 时，浏览器内部会调用相应的 C++ 代码，最终会涉及到 `DedicatedWebTransportHttp3Client` 类的创建和 `Connect()` 方法的调用。

- `DedicatedWebTransportHttp3Client` 负责发起与 `example.com` 的 QUIC 连接。
- 它会发送一个 HTTP/3 `CONNECT` 请求，其中包含 `sec-webtransport-http3-draft02` 或其他协议标识头，告知服务器客户端希望使用 WebTransport 协议。
- 当 QUIC 连接建立并且服务器接受了 WebTransport 的升级请求后，`DedicatedWebTransportHttp3Client` 会通知 JavaScript 代码，使得 `wt.ready` Promise 被 resolve。
- 当接收到来自服务器的 WebTransport 数据报时，`DedicatedWebTransportHttp3Client` 会将数据传递给 JavaScript，使得 `wt.datagrams.readable` 可读流可以读取数据。

**逻辑推理 (假设输入与输出):**

**假设输入:**

- 用户在浏览器中打开一个支持 WebTransport 的网页。
- 网页中的 JavaScript 代码尝试连接到 `wss://example.com/webtransport` (请注意，这里虽然是 `wss://`，但 WebTransport over HTTP/3 实际上是在 HTTP/3 上运行的)。
- 用户的网络环境允许 QUIC 连接。

**输出:**

1. **成功连接:**
   - `DedicatedWebTransportHttp3Client` 成功建立与 `example.com` 的 QUIC 连接。
   - 发送的 HTTP/3 `CONNECT` 请求被服务器接受。
   - `WebTransportClientVisitor::OnConnected()` 被调用，通知上层连接已建立。
   - JavaScript 的 `wt.ready` Promise 被 resolve。

2. **连接失败 (例如，服务器不支持 WebTransport):**
   - `DedicatedWebTransportHttp3Client` 尝试连接。
   - 服务器可能返回一个表示不支持 WebTransport 的 HTTP 错误响应 (例如，400 Bad Request)。
   - `DedicatedWebTransportHttp3Client::OnHeadersComplete()` 会解析响应头并检测错误。
   - `WebTransportClientVisitor::OnConnectionFailed()` 被调用，并传递错误信息。
   - JavaScript 的 `wt.ready` Promise 会被 reject，并且 `wt.closed` Promise 可能会 resolve 并带有错误信息。

**用户或编程常见的使用错误:**

1. **尝试连接到非 HTTPS 的 URL:** WebTransport over HTTP/3 只能在 HTTPS 连接上建立。如果 JavaScript 代码尝试连接到 `http://` URL，`DedicatedWebTransportHttp3Client::DoInit()` 会返回 `ERR_DISALLOWED_URL_SCHEME` 错误。

2. **目标服务器不支持 WebTransport:** 如果服务器没有实现 WebTransport 协议，或者不支持客户端请求的版本，服务器可能会拒绝 `CONNECT` 请求。 这会导致连接失败，并且 `DedicatedWebTransportHttp3Client` 会将错误传递给上层。

3. **QUIC 被阻止或禁用:** 如果用户的网络环境阻止了 QUIC 协议（例如，防火墙），或者浏览器策略禁用了 QUIC，WebTransport 连接将无法建立。`DedicatedWebTransportHttp3Client` 在尝试建立 QUIC 连接时会遇到网络错误。

4. **证书错误:** 如果服务器的 TLS 证书无效或无法验证，QUIC 连接握手会失败，从而导致 WebTransport 连接失败。`ProofVerifierChromium` 类负责证书验证，如果验证失败，会返回相应的错误。

5. **错误的服务器证书指纹配置:** 如果在 `WebTransportParameters` 中指定了错误的服务器证书指纹，`ChromiumWebTransportFingerprintProofVerifier` 将无法验证服务器的证书，导致连接失败。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接:**  如果该 URL 的网页包含使用 WebTransport API 的 JavaScript 代码，那么加载网页会触发后续步骤。

2. **网页加载，JavaScript 代码执行:**  浏览器解析 HTML，下载并执行 JavaScript 代码。

3. **JavaScript 代码创建 `WebTransport` 对象:**  例如，`const wt = new WebTransport('https://example.com/webtransport');`。

4. **浏览器网络栈开始处理 WebTransport 连接请求:**
   - 浏览器会查找与目标主机相关的现有 QUIC 连接。
   - 如果没有，会创建一个新的 QUIC 连接。这会涉及到 DNS 解析、TCP 握手 (如果需要)、QUIC 握手等底层操作。
   - **`DedicatedWebTransportHttp3Client` 对象被创建:** 当 JavaScript 创建 `WebTransport` 对象时，浏览器内部会创建对应的 `DedicatedWebTransportHttp3Client` C++ 对象来处理连接。

5. **调用 `DedicatedWebTransportHttp3Client::Connect()`:**  开始 WebTransport 特定的连接建立过程，包括发送 HTTP/3 `CONNECT` 请求。

6. **`DedicatedWebTransportHttp3Client` 中的状态机驱动连接过程:**  `DoLoop()` 方法以及相关的 `CONNECT_STATE_*` 枚举值控制着连接建立的各个阶段，例如检查代理、解析主机名、建立 QUIC 连接、发送请求等。

**调试线索:**

如果在调试 WebTransport 连接问题时，可以关注以下几点：

- **NetLog (chrome://net-export/):**  启用 NetLog 可以记录详细的网络事件，包括 QUIC 连接、HTTP/3 请求和 WebTransport 相关的事件，有助于追踪连接建立过程中的错误。搜索 `QUIC_SESSION_WEBTRANSPORT_CLIENT_ALIVE` 或其他包含 `WEBTRANSPORT` 的事件。
- **断点调试:** 在 `DedicatedWebTransportHttp3Client` 的关键方法中设置断点，例如 `Connect()`, `DoLoop()`, `OnHeadersComplete()`, `OnConnectionClosed()` 等，可以逐步跟踪代码执行流程，查看变量状态。
- **QUIC Internals (chrome://quic-internals/):**  查看 QUIC 连接的状态信息，例如握手状态、连接错误、数据包收发情况等。
- **HTTP/3 请求:** 使用网络抓包工具 (如 Wireshark) 查看发送的 HTTP/3 `CONNECT` 请求和服务器的响应，确认请求头和响应状态码是否正确。

**DedicatedWebTransportHttp3Client 的功能归纳 (针对第 1 部分):**

在提供的代码片段中，`DedicatedWebTransportHttp3Client` 的主要功能集中在 **连接的初始化和建立阶段**。它负责：

- **初始化连接所需的参数和状态。**
- **执行连接前的必要检查**，例如 URL 格式、协议、端口以及代理设置。
- **解析目标主机的 IP 地址。**
- **建立底层的 QUIC 连接。**
- **配置 QUIC 连接参数。**
- **等待 QUIC 连接建立完成并接收到服务器的 SETTINGS 帧。**

代码的第 1 部分尚未涉及到发送实际的 WebTransport `CONNECT` 请求 (这通常发生在 `DoSendRequest()` 方法中，该方法在提供的代码片段的末尾附近)，以及后续的会话管理和数据传输。

### 提示词
```
这是目录为net/quic/dedicated_web_transport_http3_client.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/dedicated_web_transport_http3_client.h"

#include <string_view>
#include <vector>

#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/task/single_thread_task_runner.h"
#include "net/base/address_list.h"
#include "net/base/port_util.h"
#include "net/base/url_util.h"
#include "net/http/http_network_session.h"
#include "net/log/net_log_values.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_resolution_request.h"
#include "net/quic/address_utils.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/http/web_transport_http3.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/url_request/url_request_context.h"
#include "url/scheme_host_port.h"

namespace net {

namespace {

// From
// https://wicg.github.io/web-transport/#dom-quictransportconfiguration-server_certificate_fingerprints
constexpr int kCustomCertificateMaxValidityDays = 14;

// The time the client would wait for the server to acknowledge the session
// being closed.
constexpr base::TimeDelta kMaxCloseTimeout = base::Seconds(2);

// Enables custom congestion control for WebTransport over HTTP/3.
BASE_FEATURE(kWebTransportCongestionControl,
             "WebTransportCongestionControl",
             base::FEATURE_DISABLED_BY_DEFAULT);
constexpr base::FeatureParam<quic::CongestionControlType>::Option
    kWebTransportCongestionControlAlgorithms[] = {
        {quic::kCubicBytes, "CUBIC"},
        {quic::kRenoBytes, "Reno"},
        {quic::kBBR, "BBRv1"},
        {quic::kBBRv2, "BBRv2"},
};
constexpr base::FeatureParam<quic::CongestionControlType>
    kWebTransportCongestionControlAlgorithm{
        &kWebTransportCongestionControl, /*name=*/"algorithm",
        /*default_value=*/quic::kCubicBytes,
        &kWebTransportCongestionControlAlgorithms};

std::set<std::string> HostsFromOrigins(std::set<HostPortPair> origins) {
  std::set<std::string> hosts;
  for (const auto& origin : origins) {
    hosts.insert(origin.host());
  }
  return hosts;
}

// A version of WebTransportFingerprintProofVerifier that enforces
// Chromium-specific policies.
class ChromiumWebTransportFingerprintProofVerifier
    : public quic::WebTransportFingerprintProofVerifier {
 public:
  using WebTransportFingerprintProofVerifier::
      WebTransportFingerprintProofVerifier;

 protected:
  bool IsKeyTypeAllowedByPolicy(
      const quic::CertificateView& certificate) override {
    if (certificate.public_key_type() == quic::PublicKeyType::kRsa) {
      return false;
    }
    return WebTransportFingerprintProofVerifier::IsKeyTypeAllowedByPolicy(
        certificate);
  }
};

std::unique_ptr<quic::ProofVerifier> CreateProofVerifier(
    const NetworkAnonymizationKey& anonymization_key,
    URLRequestContext* context,
    const WebTransportParameters& parameters) {
  if (parameters.server_certificate_fingerprints.empty()) {
    std::set<std::string> hostnames_to_allow_unknown_roots = HostsFromOrigins(
        context->quic_context()->params()->origins_to_force_quic_on);
    if (context->quic_context()->params()->webtransport_developer_mode) {
      hostnames_to_allow_unknown_roots.insert("");
    }
    return std::make_unique<ProofVerifierChromium>(
        context->cert_verifier(), context->transport_security_state(),
        context->sct_auditing_delegate(),
        std::move(hostnames_to_allow_unknown_roots), anonymization_key);
  }

  auto verifier =
      std::make_unique<ChromiumWebTransportFingerprintProofVerifier>(
          context->quic_context()->clock(), kCustomCertificateMaxValidityDays);
  for (const quic::CertificateFingerprint& fingerprint :
       parameters.server_certificate_fingerprints) {
    bool success = verifier->AddFingerprint(fingerprint);
    if (!success) {
      DLOG(WARNING) << "Failed to add a certificate fingerprint: "
                    << fingerprint.fingerprint;
    }
  }
  return verifier;
}

void RecordNetLogQuicSessionClientStateChanged(
    NetLogWithSource& net_log,
    WebTransportState last_state,
    WebTransportState next_state,
    const std::optional<WebTransportError>& error) {
  net_log.AddEvent(
      NetLogEventType::QUIC_SESSION_WEBTRANSPORT_CLIENT_STATE_CHANGED, [&] {
        auto dict = base::Value::Dict()
                        .Set("last_state", WebTransportStateString(last_state))
                        .Set("next_state", WebTransportStateString(next_state));
        if (error.has_value()) {
          dict.Set("error",
                   base::Value::Dict()
                       .Set("net_error", error->net_error)
                       .Set("quic_error", static_cast<int>(error->quic_error))
                       .Set("details", error->details));
        }
        return dict;
      });
}

// The stream associated with an extended CONNECT request for the WebTransport
// session.
class ConnectStream : public quic::QuicSpdyClientStream {
 public:
  ConnectStream(quic::QuicStreamId id,
                quic::QuicSpdyClientSession* session,
                quic::StreamType type,
                DedicatedWebTransportHttp3Client* client)
      : quic::QuicSpdyClientStream(id, session, type), client_(client) {}

  ~ConnectStream() override { client_->OnConnectStreamDeleted(); }

  void OnInitialHeadersComplete(
      bool fin,
      size_t frame_len,
      const quic::QuicHeaderList& header_list) override {
    quic::QuicSpdyClientStream::OnInitialHeadersComplete(fin, frame_len,
                                                         header_list);
    client_->OnHeadersComplete(response_headers());
  }

  void OnClose() override {
    quic::QuicSpdyClientStream::OnClose();
    if (fin_received() && fin_sent()) {
      // Clean close.
      return;
    }
    if (stream_error() == quic::QUIC_STREAM_CONNECTION_ERROR) {
      // If stream is closed due to the connection error, OnConnectionClosed()
      // will populate the correct error details.
      return;
    }
    client_->OnConnectStreamAborted();
  }

  void OnWriteSideInDataRecvdState() override {
    quic::QuicSpdyClientStream::OnWriteSideInDataRecvdState();
    client_->OnConnectStreamWriteSideInDataRecvdState();
  }

 private:
  raw_ptr<DedicatedWebTransportHttp3Client> client_;
};

class DedicatedWebTransportHttp3ClientSession
    : public quic::QuicSpdyClientSession {
 public:
  DedicatedWebTransportHttp3ClientSession(
      const quic::QuicConfig& config,
      const quic::ParsedQuicVersionVector& supported_versions,
      quic::QuicConnection* connection,
      const quic::QuicServerId& server_id,
      quic::QuicCryptoClientConfig* crypto_config,
      DedicatedWebTransportHttp3Client* client)
      : quic::QuicSpdyClientSession(config,
                                    supported_versions,
                                    connection,
                                    server_id,
                                    crypto_config),
        client_(client) {}

  bool OnSettingsFrame(const quic::SettingsFrame& frame) override {
    if (!quic::QuicSpdyClientSession::OnSettingsFrame(frame)) {
      return false;
    }
    client_->OnSettingsReceived();
    return true;
  }

  quic::WebTransportHttp3VersionSet LocallySupportedWebTransportVersions()
      const override {
    quic::WebTransportHttp3VersionSet versions =
        quic::WebTransportHttp3VersionSet(
            {quic::WebTransportHttp3Version::kDraft02});
    if (base::FeatureList::IsEnabled(features::kEnableWebTransportDraft07)) {
      versions.Set(quic::WebTransportHttp3Version::kDraft07);
    }
    return versions;
  }

  quic::HttpDatagramSupport LocalHttpDatagramSupport() override {
    return quic::HttpDatagramSupport::kRfcAndDraft04;
  }

  void OnConnectionClosed(const quic::QuicConnectionCloseFrame& frame,
                          quic::ConnectionCloseSource source) override {
    quic::QuicSpdyClientSession::OnConnectionClosed(frame, source);
    client_->OnConnectionClosed(frame.quic_error_code, frame.error_details,
                                source);
  }

  ConnectStream* CreateConnectStream() {
    if (!ShouldCreateOutgoingBidirectionalStream()) {
      return nullptr;
    }
    std::unique_ptr<ConnectStream> stream =
        std::make_unique<ConnectStream>(GetNextOutgoingBidirectionalStreamId(),
                                        this, quic::BIDIRECTIONAL, client_);
    ConnectStream* stream_ptr = stream.get();
    ActivateStream(std::move(stream));
    return stream_ptr;
  }

  void OnDatagramProcessed(std::optional<quic::MessageStatus> status) override {
    client_->OnDatagramProcessed(
        status.has_value() ? std::optional<quic::MessageStatus>(*status)
                           : std::optional<quic::MessageStatus>());
  }

 private:
  raw_ptr<DedicatedWebTransportHttp3Client> client_;
};

class WebTransportVisitorProxy : public quic::WebTransportVisitor {
 public:
  explicit WebTransportVisitorProxy(quic::WebTransportVisitor* visitor)
      : visitor_(visitor) {}

  void OnSessionReady() override { visitor_->OnSessionReady(); }
  void OnSessionClosed(quic::WebTransportSessionError error_code,
                       const std::string& error_message) override {
    visitor_->OnSessionClosed(error_code, error_message);
  }
  void OnIncomingBidirectionalStreamAvailable() override {
    visitor_->OnIncomingBidirectionalStreamAvailable();
  }
  void OnIncomingUnidirectionalStreamAvailable() override {
    visitor_->OnIncomingUnidirectionalStreamAvailable();
  }
  void OnDatagramReceived(std::string_view datagram) override {
    visitor_->OnDatagramReceived(datagram);
  }
  void OnCanCreateNewOutgoingBidirectionalStream() override {
    visitor_->OnCanCreateNewOutgoingBidirectionalStream();
  }
  void OnCanCreateNewOutgoingUnidirectionalStream() override {
    visitor_->OnCanCreateNewOutgoingUnidirectionalStream();
  }

 private:
  raw_ptr<quic::WebTransportVisitor> visitor_;
};

bool IsTerminalState(WebTransportState state) {
  return state == WebTransportState::CLOSED ||
         state == WebTransportState::FAILED;
}

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum class NegotiatedHttpDatagramVersion {
  kNone = 0,
  kDraft04 = 1,
  kRfc = 2,
  kMaxValue = kRfc,
};

void RecordNegotiatedHttpDatagramSupport(quic::HttpDatagramSupport support) {
  NegotiatedHttpDatagramVersion negotiated;
  switch (support) {
    case quic::HttpDatagramSupport::kNone:
      negotiated = NegotiatedHttpDatagramVersion::kNone;
      break;
    case quic::HttpDatagramSupport::kDraft04:
      negotiated = NegotiatedHttpDatagramVersion::kDraft04;
      break;
    case quic::HttpDatagramSupport::kRfc:
      negotiated = NegotiatedHttpDatagramVersion::kRfc;
      break;
    case quic::HttpDatagramSupport::kRfcAndDraft04:
      NOTREACHED();
  }
  base::UmaHistogramEnumeration(
      "Net.WebTransport.NegotiatedHttpDatagramVersion", negotiated);
}

const char* WebTransportHttp3VersionString(
    quic::WebTransportHttp3Version version) {
  switch (version) {
    case quic::WebTransportHttp3Version::kDraft02:
      return "draft-02";
    case quic::WebTransportHttp3Version::kDraft07:
      return "draft-07";
  }
}

enum class NegotiatedWebTransportVersion {
  kDraft02 = 0,
  kDraft07 = 1,
  kMaxValue = kDraft07,
};

void RecordNegotiatedWebTransportVersion(
    quic::WebTransportHttp3Version version) {
  NegotiatedWebTransportVersion negotiated;
  switch (version) {
    case quic::WebTransportHttp3Version::kDraft02:
      negotiated = NegotiatedWebTransportVersion::kDraft02;
      break;
    case quic::WebTransportHttp3Version::kDraft07:
      negotiated = NegotiatedWebTransportVersion::kDraft07;
      break;
  }
  base::UmaHistogramEnumeration(
      "Net.WebTransport.NegotiatedWebTransportVersion", negotiated);
}

void AdjustSendAlgorithm(quic::QuicConnection& connection) {
  if (!base::FeatureList::IsEnabled(kWebTransportCongestionControl)) {
    return;
  }
  connection.sent_packet_manager().SetSendAlgorithm(
      kWebTransportCongestionControlAlgorithm.Get());
}

}  // namespace

DedicatedWebTransportHttp3Client::DedicatedWebTransportHttp3Client(
    const GURL& url,
    const url::Origin& origin,
    WebTransportClientVisitor* visitor,
    const NetworkAnonymizationKey& anonymization_key,
    URLRequestContext* context,
    const WebTransportParameters& parameters)
    : url_(url),
      origin_(origin),
      anonymization_key_(anonymization_key),
      context_(context),
      visitor_(visitor),
      quic_context_(context->quic_context()),
      net_log_(NetLogWithSource::Make(context->net_log(),
                                      NetLogSourceType::WEB_TRANSPORT_CLIENT)),
      task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault().get()),
      alarm_factory_(
          std::make_unique<QuicChromiumAlarmFactory>(task_runner_,
                                                     quic_context_->clock())),
      // TODO(vasilvv): proof verifier should have proper error reporting
      // (currently, all certificate verification errors result in "TLS
      // handshake error" even when more detailed message is available).  This
      // requires implementing ProofHandler::OnProofVerifyDetailsAvailable.
      crypto_config_(
          CreateProofVerifier(anonymization_key_, context, parameters),
          /* session_cache */ nullptr) {
  ConfigureQuicCryptoClientConfig(crypto_config_);
  net_log_.BeginEvent(
      NetLogEventType::QUIC_SESSION_WEBTRANSPORT_CLIENT_ALIVE, [&] {
        base::Value::Dict dict;
        dict.Set("url", url.possibly_invalid_spec());
        dict.Set("network_anonymization_key",
                 anonymization_key.ToDebugString());
        return dict;
      });
}

DedicatedWebTransportHttp3Client::~DedicatedWebTransportHttp3Client() {
  net_log_.EndEventWithNetErrorCode(
      NetLogEventType::QUIC_SESSION_WEBTRANSPORT_CLIENT_ALIVE,
      error_ ? error_->net_error : OK);
  // |session_| owns this, so we need to make sure we release it before
  // it gets dangling.
  connection_ = nullptr;
}

void DedicatedWebTransportHttp3Client::Connect() {
  if (state_ != WebTransportState::NEW ||
      next_connect_state_ != CONNECT_STATE_NONE) {
    NOTREACHED();
  }

  TransitionToState(WebTransportState::CONNECTING);
  next_connect_state_ = CONNECT_STATE_INIT;
  DoLoop(OK);
}

void DedicatedWebTransportHttp3Client::Close(
    const std::optional<WebTransportCloseInfo>& close_info) {
  CHECK(session());
  base::TimeDelta probe_timeout = base::Microseconds(
      connection_->sent_packet_manager().GetPtoDelay().ToMicroseconds());
  // Wait for at least three PTOs similar to what's used in
  // https://www.rfc-editor.org/rfc/rfc9000.html#name-immediate-close
  base::TimeDelta close_timeout = std::min(3 * probe_timeout, kMaxCloseTimeout);
  close_timeout_timer_.Start(
      FROM_HERE, close_timeout,
      base::BindOnce(&DedicatedWebTransportHttp3Client::OnCloseTimeout,
                     weak_factory_.GetWeakPtr()));
  if (close_info.has_value()) {
    session()->CloseSession(close_info->code, close_info->reason);
  } else {
    session()->CloseSession(0, "");
  }
}

quic::WebTransportSession* DedicatedWebTransportHttp3Client::session() {
  if (web_transport_session_ == nullptr)
    return nullptr;
  return web_transport_session_;
}

void DedicatedWebTransportHttp3Client::DoLoop(int rv) {
  do {
    ConnectState connect_state = next_connect_state_;
    next_connect_state_ = CONNECT_STATE_NONE;
    switch (connect_state) {
      case CONNECT_STATE_INIT:
        DCHECK_EQ(rv, OK);
        rv = DoInit();
        break;
      case CONNECT_STATE_CHECK_PROXY:
        DCHECK_EQ(rv, OK);
        rv = DoCheckProxy();
        break;
      case CONNECT_STATE_CHECK_PROXY_COMPLETE:
        rv = DoCheckProxyComplete(rv);
        break;
      case CONNECT_STATE_RESOLVE_HOST:
        DCHECK_EQ(rv, OK);
        rv = DoResolveHost();
        break;
      case CONNECT_STATE_RESOLVE_HOST_COMPLETE:
        rv = DoResolveHostComplete(rv);
        break;
      case CONNECT_STATE_CONNECT:
        DCHECK_EQ(rv, OK);
        rv = DoConnect();
        break;
      case CONNECT_STATE_CONNECT_CONFIGURE:
        rv = DoConnectConfigure(rv);
        break;
      case CONNECT_STATE_CONNECT_COMPLETE:
        rv = DoConnectComplete();
        break;
      case CONNECT_STATE_SEND_REQUEST:
        DCHECK_EQ(rv, OK);
        rv = DoSendRequest();
        break;
      case CONNECT_STATE_CONFIRM_CONNECTION:
        DCHECK_EQ(rv, OK);
        rv = DoConfirmConnection();
        break;
      default:
        NOTREACHED() << "Invalid state reached: " << connect_state;
    }
  } while (rv == OK && next_connect_state_ != CONNECT_STATE_NONE);

  if (rv == OK || rv == ERR_IO_PENDING)
    return;
  SetErrorIfNecessary(rv);
  TransitionToState(WebTransportState::FAILED);
}

int DedicatedWebTransportHttp3Client::DoInit() {
  if (!url_.is_valid())
    return ERR_INVALID_URL;
  if (url_.scheme_piece() != url::kHttpsScheme)
    return ERR_DISALLOWED_URL_SCHEME;

  if (!IsPortAllowedForScheme(url_.EffectiveIntPort(), url_.scheme_piece()))
    return ERR_UNSAFE_PORT;

  // TODO(vasilvv): check if QUIC is disabled by policy.

  // Ensure that RFC 9000 is always supported.
  supported_versions_ = quic::ParsedQuicVersionVector{
      quic::ParsedQuicVersion::RFCv1(),
  };
  // Add other supported versions if available.
  for (quic::ParsedQuicVersion& version :
       quic_context_->params()->supported_versions) {
    if (base::Contains(supported_versions_, version))
      continue;  // Skip as we've already added it above.
    supported_versions_.push_back(version);
  }
  if (supported_versions_.empty()) {
    DLOG(ERROR) << "Attempted using WebTransport with no compatible QUIC "
                   "versions available";
    return ERR_NOT_IMPLEMENTED;
  }

  next_connect_state_ = CONNECT_STATE_CHECK_PROXY;
  return OK;
}

int DedicatedWebTransportHttp3Client::DoCheckProxy() {
  next_connect_state_ = CONNECT_STATE_CHECK_PROXY_COMPLETE;
  return context_->proxy_resolution_service()->ResolveProxy(
      url_, /* method */ "CONNECT", anonymization_key_, &proxy_info_,
      base::BindOnce(&DedicatedWebTransportHttp3Client::DoLoop,
                     base::Unretained(this)),
      &proxy_resolution_request_, net_log_);
}

int DedicatedWebTransportHttp3Client::DoCheckProxyComplete(int rv) {
  if (rv != OK)
    return rv;

  // If a proxy is configured, we fail the connection.
  if (!proxy_info_.is_direct())
    return ERR_TUNNEL_CONNECTION_FAILED;

  next_connect_state_ = CONNECT_STATE_RESOLVE_HOST;
  return OK;
}

int DedicatedWebTransportHttp3Client::DoResolveHost() {
  next_connect_state_ = CONNECT_STATE_RESOLVE_HOST_COMPLETE;
  HostResolver::ResolveHostParameters parameters;
  resolve_host_request_ = context_->host_resolver()->CreateRequest(
      url::SchemeHostPort(url_), anonymization_key_, net_log_, std::nullopt);
  return resolve_host_request_->Start(base::BindOnce(
      &DedicatedWebTransportHttp3Client::DoLoop, base::Unretained(this)));
}

int DedicatedWebTransportHttp3Client::DoResolveHostComplete(int rv) {
  if (rv != OK)
    return rv;

  DCHECK(resolve_host_request_->GetAddressResults());
  next_connect_state_ = CONNECT_STATE_CONNECT;
  return OK;
}

int DedicatedWebTransportHttp3Client::DoConnect() {
  next_connect_state_ = CONNECT_STATE_CONNECT_CONFIGURE;

  // TODO(vasilvv): consider unifying parts of this code with QuicSocketFactory
  // (which currently has a lot of code specific to QuicChromiumClientSession).
  socket_ = context_->GetNetworkSessionContext()
                ->client_socket_factory->CreateDatagramClientSocket(
                    DatagramSocket::DEFAULT_BIND, net_log_.net_log(),
                    net_log_.source());
  if (quic_context_->params()->enable_socket_recv_optimization)
    socket_->EnableRecvOptimization();
  socket_->UseNonBlockingIO();

  IPEndPoint server_address =
      *resolve_host_request_->GetAddressResults()->begin();
  return socket_->ConnectAsync(
      server_address, base::BindOnce(&DedicatedWebTransportHttp3Client::DoLoop,
                                     base::Unretained(this)));
}

void DedicatedWebTransportHttp3Client::CreateConnection() {
  // Delete the objects in the same order they would be normally deleted by the
  // destructor.
  session_ = nullptr;
  packet_reader_ = nullptr;

  IPEndPoint server_address =
      *resolve_host_request_->GetAddressResults()->begin();
  quic::QuicConnectionId connection_id =
      quic::QuicUtils::CreateRandomConnectionId(
          quic_context_->random_generator());
  auto connection = std::make_unique<quic::QuicConnection>(
      connection_id, quic::QuicSocketAddress(),
      ToQuicSocketAddress(server_address), quic_context_->helper(),
      alarm_factory_.get(),
      new QuicChromiumPacketWriter(socket_.get(), task_runner_),
      /* owns_writer */ true, quic::Perspective::IS_CLIENT, supported_versions_,
      connection_id_generator_);
  connection_ = connection.get();
  connection->SetMaxPacketLength(quic_context_->params()->max_packet_length);

  session_ = std::make_unique<DedicatedWebTransportHttp3ClientSession>(
      InitializeQuicConfig(*quic_context_->params()), supported_versions_,
      connection.release(),
      quic::QuicServerId(url_.host(), url_.EffectiveIntPort()), &crypto_config_,
      this);
  if (!original_supported_versions_.empty()) {
    session_->set_client_original_supported_versions(
        original_supported_versions_);
  }

  packet_reader_ = std::make_unique<QuicChromiumPacketReader>(
      std::move(socket_), quic_context_->clock(), this,
      kQuicYieldAfterPacketsRead,
      quic::QuicTime::Delta::FromMilliseconds(
          kQuicYieldAfterDurationMilliseconds),
      quic_context_->params()->report_ecn, net_log_);

  event_logger_ = std::make_unique<QuicEventLogger>(session_.get(), net_log_);
  connection_->set_debug_visitor(event_logger_.get());
  connection_->set_creator_debug_delegate(event_logger_.get());
  AdjustSendAlgorithm(*connection_);

  session_->Initialize();
  packet_reader_->StartReading();

  DCHECK(session_->WillNegotiateWebTransport());
  session_->CryptoConnect();
}

int DedicatedWebTransportHttp3Client::DoConnectComplete() {
  if (!connection_->connected()) {
    return ERR_QUIC_PROTOCOL_ERROR;
  }
  // Fail the connection if the received SETTINGS do not support WebTransport.
  if (!session_->SupportsWebTransport()) {
    return ERR_METHOD_NOT_SUPPORTED;
  }
  safe_to_report_error_details_ = true;
  next_connect_state_ = CONNECT_STATE_SEND_REQUEST;
  return OK;
}

int DedicatedWebTransportHttp3Client::DoConnectConfigure(int rv) {
  if (rv != OK) {
    return rv;
  }

  rv = socket_->SetReceiveBufferSize(kQuicSocketReceiveBufferSize);
  if (rv != OK) {
    return rv;
  }

  rv = socket_->SetDoNotFragment();
  if (rv == ERR_NOT_IMPLEMENTED) {
    rv = OK;
  }
  if (rv != OK) {
    return rv;
  }

  rv = socket_->SetSendBufferSize(quic::kMaxOutgoingPacketSize * 20);
  if (rv != OK) {
    return rv;
  }

  next_connect_state_ = CONNECT_STATE_CONNECT_COMPLETE;
  CreateConnection();
  return ERR_IO_PENDING;
}

void DedicatedWebTransportHttp3Client::OnSettingsReceived() {
  DCHECK_EQ(next_connect_state_, CONNECT_STATE_CONNECT_COMPLETE);
  // Wait until the SETTINGS parser is finished, and then send the request.
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&DedicatedWebTransportHttp3Client::DoLoop,
                                weak_factory_.GetWeakPtr(), OK));
}

void DedicatedWebTransportHttp3Client::OnHeadersComplete(
    const quiche::HttpHeaderBlock& headers) {
  http_response_info_ = std::make_unique<HttpResponseInfo>();
  const int rv = SpdyHeadersToHttpResponse(headers, http_response_info_.get());
  if (rv != OK) {
    SetErrorIfNecessary(ERR_QUIC_PROTOCOL_ERROR);
    TransitionToState(WebTransportState::FAILED);
    return;
  }
  // TODO(vasilvv): add support for this header in downstream tests and remove
  // this.
  DCHECK(http_response_info_->headers);
  http_response_info_->headers->RemoveHeader("sec-webtransport-http3-draft");

  DCHECK_EQ(next_connect_state_, CONNECT_STATE_CONFIRM_CONNECTION);
  DoLoop(OK);
}

void DedicatedWebTransportHttp3Client::
    OnConnectStreamWriteSideInDataRecvdState() {
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&DedicatedWebTransportHttp3Client::TransitionToState,
                     weak_factory_.GetWeakPtr(), WebTransportState::CLOSED));
}

void DedicatedWebTransportHttp3Client::OnConnectStreamAborted() {
  SetErrorIfNecessary(session_ready_ ? ERR_FAILED : ERR_METHOD_NOT_SUPPORTED);
  TransitionToState(WebTransportState::FAILED);
}

void DedicatedWebTransportHttp3Client::OnConnectStreamDeleted() {
  // `web_transport_session_` is owned by ConnectStream. Clear so that it
  // doesn't get dangling.
  web_transport_session_ = nullptr;
}

void DedicatedWebTransportHttp3Client::OnCloseTimeout() {
  SetErrorIfNecessary(ERR_TIMED_OUT);
  TransitionToState(WebTransportState::FAILED);
}

int DedicatedWebTransportHttp3Client::DoSendRequest() {
  quic::QuicConnection::ScopedPacketFlusher scope(connection_);

  DedicatedWebTransportHttp3ClientSession* session =
      static_cast<DedicatedWebTransportHttp3ClientSession*>(session_.get());
  ConnectStream* stream = session->CreateConnectStream();
  if (stream == nullptr) {
    return ERR_QUIC_PROTOCOL_ERROR;
  }

  quiche::HttpHeaderBlock headers;
  DCHECK_EQ(url_.scheme(), url::kHttpsScheme);
  headers[":scheme"] = url_.scheme();
  headers[":method"] = "CONNECT";
  headers[":authority"] = GetHostAndOptionalPort(url_);
  headers[":path"] = url_.PathForRequest();
  headers[":protocol"] = "webtransport";
  headers["sec-webtransport-http3-draft02"] = "1";
  headers["origin"] = origin_.Serialize();
  stream->WriteHeaders(std::move(headers), /*fin=*/false, nullptr);

  web_transport_session_ = stream->web_transport();
  if (web_transport_session_ == nullptr) {
    return ERR_METHOD_NOT_SUPPORTED;
  }
  stream->web_transport()->SetVisitor(
      std::make_unique<WebTransportVisitorProxy>(this));

  next_connect_state_ = CONNECT_STATE_CONFIRM_CONNECTION;
  return ERR_IO_PENDING;
}

int DedicatedWebTransportHttp3Client::DoConfirmConnection() {
  if (!session_ready_) {
    return ERR_METHOD_NOT_SUPPORTED;
  }

  TransitionToState(WebTransportState::CONNECTED);
  return OK;
}

void DedicatedWebTransportHttp3Client::TransitionToState(
    WebTransportState next_state) {
  // Ignore all state transition requests if we have reached the terminal
  // state.
  if (IsTerminalState(state_)) {
    DCHECK(IsTerminalState(next_state))
        << "from: " << state_ << ", to: " << next_state;
    return;
  }

  DCHECK_NE(state_, next_state);
  const WebTransportState last_state = state_;
  state_ = next_state;
  RecordNetLogQuicSessionClientStateChanged(net_log_, last_state, next_state,
                                            error_);
  switch (next_state) {
    case WebTransportState::CONNECTING:
      DCHECK_EQ(last_state, WebTransportState::NEW);
      break;

    case WebTransportState::CONNECTED:
      DCHECK_EQ(last_state, WebTransportState::CONNECTING);
      visitor_->OnConnected(http_response_info_->headers);
      break;

    case WebTransportState::CLOSED:
      DCHECK_EQ(last_state, WebTransportState::CONNECTED);
      connection_->CloseConnection(quic::QUIC_NO_ERROR,
                                   "WebTransport client terminated",
                                   quic::ConnectionCloseBehavior::SILENT_CLOSE);
      visitor_->OnClosed(close_info_);
      break;

    case WebTransportState::FAILED:
      DCHECK(error_.has_value());
      if (last_state == WebTransportState::CONNECTING) {
        visitor_->OnConnectionFailed(*error_);
        break;
      }
      DCHECK_EQ(last_state, WebTransportState::CONNECTED);
      // Ensure the connection is properly closed before deleting it.
      connection_->CloseConnection(
          quic::QUIC_INTERNAL_ERROR,
          "WebTransportState::ERROR reached but the connection still open",
          quic::ConnectionCloseBehavior::SILENT_CLOSE);
      visitor_->OnError(*error_);
      break;

    default:
      NOTREACHED() << "Invalid state reached: " << next_state;
  }
}

void DedicatedWebTransportHttp3Client::SetErrorIfNecessary(int error) {
  SetErrorIfNecessary(error, quic::QUIC_NO_ERROR, ErrorToString(error));
}

void DedicatedWebTransportHttp3Client::SetErrorIfNecessary(
    int error,
    quic::QuicErrorCode quic_error,
    std::string_view details) {
  if (!error_) {
    error_ = WebTransportError(error, quic_error, details,
                               safe_to_report_error_details_);
  }
}

void DedicatedWebTransportHttp3Client::OnSessionReady() {
  CHECK(session_->SupportsWebTransport());

  session_ready_ = true;

  RecordNegotiatedWebTransportVersion(
      *session_->SupportedWebTransportVersion());
  RecordNegotiatedHttpDatagramSupport(session_->http_datagram_support());
  net_log_.AddEvent(NetLogEventType::QUIC_SESSION_WEBTRANSPORT_SESSION_READY,
                    [&] {
                      base::Value::Dict dict;
                      dict.Set("http_datagram_version",
                               quic::HttpDatagramSupportToString(
                                   session_->http_datagram_support()));
                      dict.Set("webtransport_http3_version",
                               WebTransportHttp3VersionString(
                                   *session_->SupportedWebTransportVersion()));
                      return dict;
                    });
}

void DedicatedWebTransportHttp3Client::OnSessionClosed(
    quic::WebTransportSessionError error_code,
    const std::string& error_message) {
  close_info_ = WebTransportCloseInfo(error_code, error_message);
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&DedicatedWebTransportHttp3Client::TransitionToState,
                     weak_factory_.GetWeakPtr(), WebTransportState::CLOSED));
}

void DedicatedWebTransportHttp3Client::
    OnIncomingBidirectionalStreamAvailable() {
  visitor_->OnIncomingBidirectionalStreamAvailable();
}

void DedicatedWebTransportHttp3Client::
    OnIncomingUnidirectionalStreamAvailable() {
  visitor_->OnIncomingUnidirectionalStreamAvailable();
}

void DedicatedWebTransportHttp3Client::OnDatagramReceived(
    std::string_view datagram) {
  visitor_->OnDatagramReceived(datagram);
}

void DedicatedWebTransportHttp3Client::
    OnCanCreateNewOutgoingBidirectionalStream() {
  visitor_->OnCanCreateNewOutgoingBidirectionalStream();
}

void DedicatedWebTransportHttp3Client::
    OnCanCreateNewOutgoingUnidirectionalStream() {
  visitor_->OnCanCreateNewOutgoingUnidirectionalStream();
}

bool DedicatedWebTransportHttp3Client::OnReadError(
    int result,
    const DatagramClientSocket* socket) {
  SetErrorIfNecessary(result);
  connection_->CloseConnection(quic::QUIC_PACKET_READ_ERROR,
                               ErrorToString(result),
                               quic::ConnectionCloseBehavior::SILENT_CLOSE);
  return false;
}

bool DedicatedWebTransportHttp3Client::OnPacket(
    const quic::QuicReceivedPacket& packet,
    const quic::QuicSocketAddress& local_address,
    const quic::QuicSocketAddress& peer_address) {
  session_->ProcessUdpPacket(local_address, peer_address, packet);
  return connection_->connected();
}

int DedicatedWebTransportHttp3Client::HandleWriteError(
    int error_code,
    scoped_refptr<QuicChromiumPacketWriter::ReusableIOBuffer> /*last_packet*/) {
  return error_code;
}

void DedicatedWebTransportHttp3Client::OnWriteError(int error_code) {
  SetErrorIfNecessary(error_code);
  connection_->OnWriteError(error_code);
}

void DedicatedWebTransportHttp3Client::OnWriteUnblocked() {
  connection_->OnCanWrite();
}

void DedicatedWebTransportHttp3Client::OnConnectionClosed(
    quic::QuicErrorCode error,
    const std::string& error_details,
    quic::ConnectionCloseSource source) {
  // If the session is already in a terminal state due to reasons other than
  // connection close, we should ignore it; otherwise we risk re-entering the
  // connection te
```