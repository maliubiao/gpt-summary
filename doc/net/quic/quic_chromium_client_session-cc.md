Response:
My thinking process for analyzing the provided code snippet goes like this:

1. **Identify the Core Component:** The file name `net/quic/quic_chromium_client_session.cc` and the class name `QuicChromiumClientSession` clearly indicate this code defines the client-side QUIC session within the Chromium network stack.

2. **High-Level Functionality (Based on Includes and Class Name):**  I start by looking at the included headers. These give broad hints about the class's responsibilities:
    * `net/quic/...`:  Deals with QUIC protocol specifics.
    * `net/base/...`:  Interacts with core networking concepts like sockets, errors, and network interfaces.
    * `net/http/...`: Suggests interaction with HTTP semantics over QUIC.
    * `net/ssl/...`:  Implies handling TLS/SSL as part of the QUIC handshake.
    * `net/log/...`:  Indicates logging and debugging capabilities.
    * `base/...`: Uses general Chromium utilities like callbacks, memory management, and metrics.

3. **Examine Key Data Structures and Methods (Based on the Code):**  I scan the provided code, looking for prominent data structures and methods. This helps me understand the specific actions the session performs. Some key observations from the provided snippet include:

    * **`Handle` Inner Class:** This immediately suggests a mechanism for managing and interacting with the session from other parts of the code. It likely represents a lightweight interface to the underlying session.
    * **`StreamRequest` Inner Class:** This points to the process of requesting and creating QUIC streams within the session. The asynchronous nature with callbacks is evident.
    * **Migration-related Classes (`QuicChromiumPathValidationContext`, `ConnectionMigrationValidationResultDelegate`, etc.):** These classes strongly suggest the session handles connection migration, including probing new network paths.
    * **Logging and Metrics:** The frequent use of `base::UmaHistogram...` and `net_log().AddEvent` signifies the importance of monitoring and debugging the session's behavior.
    * **Callbacks and Asynchronous Operations:**  The presence of `CompletionOnceCallback` and methods like `WaitForHandshakeConfirmation` indicate asynchronous operations are central to the class's design.
    * **Socket Management:** The constructor takes a `DatagramClientSocket`, clearly linking the session to an underlying UDP socket.

4. **Infer Detailed Functionality (Connecting the Dots):** Based on the high-level overview and the identified components, I infer the more detailed functionalities:

    * **Establishing QUIC Connections:**  The session manages the connection lifecycle, from initial handshake to closing.
    * **Creating and Managing QUIC Streams:**  It allows creating unidirectional and bidirectional streams for sending and receiving data.
    * **Handling the QUIC Handshake:** It interacts with the `QuicCryptoClientStream` to establish secure connections.
    * **Connection Migration:** It implements logic for seamlessly switching to a new network or IP address if the current connection degrades or fails. This involves path validation and probing.
    * **Error Handling:** It manages various network and QUIC-specific errors.
    * **Logging and Debugging:** It provides detailed logs of session events and collects metrics for performance analysis.
    * **Integration with Chromium Networking:** It interacts with other parts of the Chromium networking stack, like DNS resolution, proxy handling, and SSL certificate verification.

5. **Address Specific Questions:**  Now I address the specific questions from the prompt:

    * **Relationship to JavaScript:** I consider how a QUIC client session might be relevant to JavaScript running in a browser. The key link is that the browser uses this code to fetch web resources (HTML, CSS, JavaScript, images, etc.) over QUIC. Therefore, any website loaded in a Chromium-based browser that uses QUIC will involve this class. Examples of JavaScript interactions include:
        * Initiating a fetch request (`fetch()`).
        * Loading images (`<img>` tags).
        * Establishing WebSocket connections.
    * **Logical Reasoning (Hypothetical Input/Output):** I construct a simple scenario to illustrate the flow. For example, a JavaScript `fetch()` call would lead to a `StreamRequest` being initiated in the `QuicChromiumClientSession`. The output would be either a successful stream creation or an error.
    * **Common User/Programming Errors:** I think about common mistakes that could lead to issues involving this class. Examples include:
        * Network connectivity problems.
        * Server-side QUIC configuration issues.
        * Misconfigured proxy settings.
    * **User Actions Leading to This Code:** I trace back user actions in the browser that would trigger the use of a QUIC session: typing a URL, clicking a link, or a web page making a request.
    * **Summary of Functionality (Part 1):** I synthesize the key functionalities observed in the provided snippet, focusing on session management, stream requests, and the initial aspects of connection migration.

6. **Refine and Organize:** Finally, I organize the information into a clear and structured answer, using headings and bullet points to improve readability. I ensure the language is precise and avoids jargon where possible.
这是 Chromium 网络栈中 `net/quic/quic_chromium_client_session.cc` 文件的第一部分代码。从代码结构和包含的头文件来看，这个文件主要负责实现 **QUIC 客户端会话**的核心功能。

以下是代码的功能归纳：

**核心功能:**

* **管理和维护 QUIC 客户端连接:**  `QuicChromiumClientSession` 类是 QUIC 客户端会话的实现，它负责建立、维护和关闭与 QUIC 服务器的连接。
* **创建和管理 QUIC 流 (Streams):**  会话负责创建和管理在连接上运行的多个独立的 QUIC 流，用于发送和接收数据。`StreamRequest` 内部类处理创建流的请求。
* **处理 QUIC 握手 (Handshake):**  会话与 `QuicCryptoClientStream` 协同工作，处理 QUIC 的加密握手过程，确保连接的安全。
* **处理连接迁移 (Connection Migration):**  代码中包含处理连接迁移的逻辑，例如当网络发生变化时，会话尝试迁移到新的网络连接，保持连接的持续性。相关的类如 `QuicChromiumPathValidationContext` 和相关的代理类都支持这个功能。
* **管理会话生命周期:**  包括连接的建立、空闲超时、错误处理和优雅关闭等。
* **集成 Chromium 网络栈:**  与 Chromium 的其他网络组件（如 Socket、NetLog、TransportSecurityState 等）进行集成。
* **统计和日志记录:**  使用 `base::metrics::Histogram...` 和 `net::NetLog...` 记录会话的各种状态、事件和错误，用于性能监控和调试。
* **支持 0-RTT 连接:**  代码中提到了对 0-RTT 连接的支持 (`gquic_zero_rtt_disabled()`)，允许客户端在握手完成前发送数据，以减少延迟。
* **处理服务器首选地址 (Server Preferred Address):**  会话可以尝试连接到服务器提供的首选地址，这可能提供更好的性能。
* **支持 Accept-CH 框架:**  代码中包含了处理 `Accept-CH` HTTP 框架的逻辑，允许服务器声明它支持的客户端提示。
* **提供会话句柄 (Handle):** `Handle` 内部类提供了对 `QuicChromiumClientSession` 的轻量级访问方式，用于发起流请求等操作。

**与 JavaScript 的关系举例:**

QUIC 客户端会话直接为浏览器中运行的 JavaScript 代码提供底层的网络传输能力。当 JavaScript 代码发起网络请求 (例如使用 `fetch()` API 或加载图片) 时，如果服务器支持 QUIC，Chromium 网络栈可能会选择使用 `QuicChromiumClientSession` 来建立连接和传输数据。

**举例说明:**

假设 JavaScript 代码尝试加载一个图片：

```javascript
fetch('https://example.com/image.png');
```

1. **DNS 解析:** 浏览器首先会解析 `example.com` 的 IP 地址。
2. **会话查找或创建:** Chromium 网络栈会检查是否已经存在与 `example.com` 的 QUIC 会话。如果存在，则尝试复用该会话。如果不存在，则会创建一个新的 `QuicChromiumClientSession`。
3. **连接建立:**  新的 `QuicChromiumClientSession` 会与服务器建立 QUIC 连接，包括 TLS 握手。
4. **流请求:**  当需要传输图片数据时，`QuicChromiumClientSession` 会创建一个新的 QUIC 流 (`StreamRequest` 会被使用)。
5. **数据传输:** 图片数据通过新创建的 QUIC 流进行传输。
6. **数据接收:**  浏览器接收到图片数据，并将其提供给 JavaScript 代码。

**逻辑推理 (假设输入与输出):**

假设输入：

* JavaScript 发起一个 HTTPS GET 请求到 `https://quic-enabled-server.com/data`。
* `QuicChromiumClientSession` 尚未与 `quic-enabled-server.com` 建立连接。

输出 (简化流程):

1. `QuicChromiumClientSession` 被创建。
2. 进行 QUIC 握手，包括与 `QuicCryptoClientStream` 交互。
3. 握手成功后，创建一个新的 QUIC 流。
4. 发送包含 GET 请求的 HTTP/3 (或 HTTP over QUIC) 请求头到服务器。
5. 从服务器接收响应数据。
6. 将响应数据传递给上层网络层，最终传递给 JavaScript。

**用户或编程常见的使用错误举例:**

* **网络问题:** 用户网络不稳定或服务器 QUIC 配置错误可能导致连接建立失败。
* **服务器不支持 QUIC:**  如果服务器没有启用 QUIC 或版本不匹配，`QuicChromiumClientSession` 可能无法建立连接，会回退到 TCP。
* **证书问题:**  服务器的 TLS 证书无效或不受信任会导致握手失败。
* **中间件拦截:**  某些网络中间件可能不支持或错误地处理 QUIC 连接，导致连接中断或失败。
* **编程错误 (在 Chromium 内部):**  例如，在调用 `RequestStream` 时没有正确处理回调，或者在连接迁移过程中出现错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 `https://quic-enabled-website.com` 并按下回车。**
2. **浏览器开始解析域名 `quic-enabled-website.com` 的 IP 地址。**
3. **浏览器检查是否已经存在与该域名的活跃 QUIC 会话。**
4. **如果不存在活跃会话，或者现有的会话不适用，则会尝试创建一个新的 `QuicChromiumClientSession`。**
5. **`QuicChromiumClientSession` 尝试与服务器建立 UDP 连接，并开始 QUIC 握手。**
6. **如果握手成功，后续的 HTTP 请求（例如加载网页的 HTML、CSS、JavaScript 等资源）将通过这个 `QuicChromiumClientSession` 创建的 QUIC 流进行传输。**

**总结 (第 1 部分的功能):**

这部分代码主要定义了 `QuicChromiumClientSession` 类的基本结构和关键成员，以及处理流请求的 `Handle` 和 `StreamRequest` 内部类。它涵盖了 QUIC 客户端会话的创建、基本生命周期管理和流的请求过程。此外，它也初步引入了连接迁移的概念，并定义了相关的上下文和代理类，为后续的连接迁移功能打下基础。代码中还包含了大量的日志记录和统计功能，用于监控和调试会话的行为。

### 提示词
```
这是目录为net/quic/quic_chromium_client_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/quic/quic_chromium_client_session.h"

#include <memory>
#include <set>
#include <string_view>
#include <utility>

#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/metrics/sparse_histogram.h"
#include "base/no_destructor.h"
#include "base/observer_list.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/tick_clock.h"
#include "base/trace_event/memory_usage_estimator.h"
#include "base/values.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/features.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/network_activity_monitor.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/privacy_mode.h"
#include "net/base/session_usage.h"
#include "net/base/url_util.h"
#include "net/cert/signed_certificate_timestamp_and_status.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_values.h"
#include "net/quic/address_utils.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/quic/quic_crypto_client_stream_factory.h"
#include "net/quic/quic_server_info.h"
#include "net/quic/quic_session_pool.h"
#include "net/socket/datagram_client_socket.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/spdy/spdy_log_util.h"
#include "net/spdy/spdy_session.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_stream_priority.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_flags.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/websockets/websocket_quic_spdy_stream.h"
#include "third_party/boringssl/src/include/openssl/ssl.h"
#include "url/origin.h"
#include "url/scheme_host_port.h"

namespace net {

namespace features {

BASE_FEATURE(kQuicMigrationIgnoreDisconnectSignalDuringProbing,
             "kQuicMigrationIgnoreDisconnectSignalDuringProbing",
             base::FEATURE_DISABLED_BY_DEFAULT);

}  // namespace features

namespace {

base::OnceClosure& MidMigrationCallbackForTesting() {
  static base::NoDestructor<base::OnceClosure> callback;
  return *callback;
}

// IPv6 packets have an additional 20 bytes of overhead than IPv4 packets.
const size_t kAdditionalOverheadForIPv6 = 20;

// Maximum number of Readers that are created for any session due to
// connection migration. A new Reader is created every time this endpoint's
// IP address changes.
const size_t kMaxReadersPerQuicSession = 5;

// Time to wait (in seconds) when no networks are available and
// migrating sessions need to wait for a new network to connect.
const size_t kWaitTimeForNewNetworkSecs = 10;

const size_t kMinRetryTimeForDefaultNetworkSecs = 1;

// These values are persisted to logs. Entries should not be renumbered,
// and numeric values should never be reused.
enum class AcceptChEntries {
  kNoEntries = 0,
  kOnlyValidEntries = 1,
  kOnlyInvalidEntries = 2,
  kBothValidAndInvalidEntries = 3,
  kMaxValue = kBothValidAndInvalidEntries,
};

void LogAcceptChFrameReceivedHistogram(bool has_valid_entry,
                                       bool has_invalid_entry) {
  AcceptChEntries value;
  if (has_valid_entry) {
    if (has_invalid_entry) {
      value = AcceptChEntries::kBothValidAndInvalidEntries;
    } else {
      value = AcceptChEntries::kOnlyValidEntries;
    }
  } else {
    if (has_invalid_entry) {
      value = AcceptChEntries::kOnlyInvalidEntries;
    } else {
      value = AcceptChEntries::kNoEntries;
    }
  }
  base::UmaHistogramEnumeration("Net.QuicSession.AcceptChFrameReceivedViaAlps",
                                value);
}

void LogAcceptChForOriginHistogram(bool value) {
  base::UmaHistogramBoolean("Net.QuicSession.AcceptChForOrigin", value);
}

void RecordConnectionCloseErrorCodeImpl(const std::string& histogram,
                                        uint64_t error,
                                        bool is_google_host,
                                        bool handshake_confirmed,
                                        bool has_ech_config_list) {
  base::UmaHistogramSparse(histogram, error);

  if (handshake_confirmed) {
    base::UmaHistogramSparse(histogram + ".HandshakeConfirmed", error);
  } else {
    base::UmaHistogramSparse(histogram + ".HandshakeNotConfirmed", error);
  }

  if (is_google_host) {
    base::UmaHistogramSparse(histogram + "Google", error);

    if (handshake_confirmed) {
      base::UmaHistogramSparse(histogram + "Google.HandshakeConfirmed", error);
    } else {
      base::UmaHistogramSparse(histogram + "Google.HandshakeNotConfirmed",
                               error);
    }
  }

  // Record a set of metrics based on whether ECH was advertised in DNS. The ECH
  // experiment does not change DNS behavior, so this measures the same servers
  // in both experiment and control groups.
  if (has_ech_config_list) {
    base::UmaHistogramSparse(histogram + "ECH", error);

    if (handshake_confirmed) {
      base::UmaHistogramSparse(histogram + "ECH.HandshakeConfirmed", error);
    } else {
      base::UmaHistogramSparse(histogram + "ECH.HandshakeNotConfirmed", error);
    }
  }
}

void LogMigrateToSocketStatus(bool success) {
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.MigrateToSocketSuccess", success);
}

void RecordConnectionCloseErrorCode(const quic::QuicConnectionCloseFrame& frame,
                                    quic::ConnectionCloseSource source,
                                    std::string_view hostname,
                                    bool handshake_confirmed,
                                    bool has_ech_config_list) {
  bool is_google_host = IsGoogleHost(hostname);
  std::string histogram = "Net.QuicSession.ConnectionCloseErrorCode";

  if (source == quic::ConnectionCloseSource::FROM_SELF) {
    // When sending a CONNECTION_CLOSE frame, it is sufficient to record
    // |quic_error_code|.
    histogram += "Client";
    RecordConnectionCloseErrorCodeImpl(histogram, frame.quic_error_code,
                                       is_google_host, handshake_confirmed,
                                       has_ech_config_list);
    return;
  }

  histogram += "Server";

  // Record |quic_error_code|.  Note that when using IETF QUIC, this is
  // extracted from the CONNECTION_CLOSE frame reason phrase, and might be
  // QUIC_IETF_GQUIC_ERROR_MISSING.
  RecordConnectionCloseErrorCodeImpl(histogram, frame.quic_error_code,
                                     is_google_host, handshake_confirmed,
                                     has_ech_config_list);

  // For IETF QUIC frames, also record the error code received on the wire.
  if (frame.close_type == quic::IETF_QUIC_TRANSPORT_CONNECTION_CLOSE) {
    histogram += "IetfTransport";
    RecordConnectionCloseErrorCodeImpl(histogram, frame.wire_error_code,
                                       is_google_host, handshake_confirmed,
                                       has_ech_config_list);
    if (frame.quic_error_code == quic::QUIC_IETF_GQUIC_ERROR_MISSING) {
      histogram += "GQuicErrorMissing";
      RecordConnectionCloseErrorCodeImpl(histogram, frame.wire_error_code,
                                         is_google_host, handshake_confirmed,
                                         has_ech_config_list);
    }
  } else if (frame.close_type == quic::IETF_QUIC_APPLICATION_CONNECTION_CLOSE) {
    histogram += "IetfApplication";
    RecordConnectionCloseErrorCodeImpl(histogram, frame.wire_error_code,
                                       is_google_host, handshake_confirmed,
                                       has_ech_config_list);
    if (frame.quic_error_code == quic::QUIC_IETF_GQUIC_ERROR_MISSING) {
      histogram += "GQuicErrorMissing";
      RecordConnectionCloseErrorCodeImpl(histogram, frame.wire_error_code,
                                         is_google_host, handshake_confirmed,
                                         has_ech_config_list);
    }
  }
}

base::Value::Dict NetLogQuicMigrationFailureParams(
    quic::QuicConnectionId connection_id,
    std::string_view reason) {
  return base::Value::Dict()
      .Set("connection_id", connection_id.ToString())
      .Set("reason", reason);
}

base::Value::Dict NetLogQuicMigrationSuccessParams(
    quic::QuicConnectionId connection_id) {
  return base::Value::Dict().Set("connection_id", connection_id.ToString());
}

base::Value::Dict NetLogProbingResultParams(
    handles::NetworkHandle network,
    const quic::QuicSocketAddress* peer_address,
    bool is_success) {
  return base::Value::Dict()
      .Set("network", base::NumberToString(network))
      .Set("peer address", peer_address->ToString())
      .Set("is_success", is_success);
}

base::Value::Dict NetLogAcceptChFrameReceivedParams(
    spdy::AcceptChOriginValuePair entry) {
  return base::Value::Dict()
      .Set("origin", entry.origin)
      .Set("accept_ch", entry.value);
}

base::Value::Dict NetLogReceivedOrigins(
    const std::set<url::SchemeHostPort>& received_origins) {
  base::Value::List origins;
  for (const auto& origin : received_origins) {
    origins.Append(origin.Serialize());
  }
  return base::Value::Dict().Set("origins", std::move(origins));
}

// Histogram for recording the different reasons that a QUIC session is unable
// to complete the handshake.
enum HandshakeFailureReason {
  HANDSHAKE_FAILURE_UNKNOWN = 0,
  HANDSHAKE_FAILURE_BLACK_HOLE = 1,
  HANDSHAKE_FAILURE_PUBLIC_RESET = 2,
  NUM_HANDSHAKE_FAILURE_REASONS = 3,
};

void RecordHandshakeFailureReason(HandshakeFailureReason reason) {
  UMA_HISTOGRAM_ENUMERATION(
      "Net.QuicSession.ConnectionClose.HandshakeNotConfirmed.Reason", reason,
      NUM_HANDSHAKE_FAILURE_REASONS);
}

// Note: these values must be kept in sync with the corresponding values in:
// tools/metrics/histograms/histograms.xml
enum HandshakeState {
  STATE_STARTED = 0,
  STATE_ENCRYPTION_ESTABLISHED = 1,
  STATE_HANDSHAKE_CONFIRMED = 2,
  STATE_FAILED = 3,
  NUM_HANDSHAKE_STATES = 4
};

enum class ZeroRttState {
  kAttemptedAndSucceeded = 0,
  kAttemptedAndRejected = 1,
  kNotAttempted = 2,
  kMaxValue = kNotAttempted,
};

void RecordHandshakeState(HandshakeState state) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicHandshakeState", state,
                            NUM_HANDSHAKE_STATES);
}

std::string MigrationCauseToString(MigrationCause cause) {
  switch (cause) {
    case UNKNOWN_CAUSE:
      return "Unknown";
    case ON_NETWORK_CONNECTED:
      return "OnNetworkConnected";
    case ON_NETWORK_DISCONNECTED:
      return "OnNetworkDisconnected";
    case ON_WRITE_ERROR:
      return "OnWriteError";
    case ON_NETWORK_MADE_DEFAULT:
      return "OnNetworkMadeDefault";
    case ON_MIGRATE_BACK_TO_DEFAULT_NETWORK:
      return "OnMigrateBackToDefaultNetwork";
    case CHANGE_NETWORK_ON_PATH_DEGRADING:
      return "OnPathDegrading";
    case CHANGE_PORT_ON_PATH_DEGRADING:
      return "ChangePortOnPathDegrading";
    case NEW_NETWORK_CONNECTED_POST_PATH_DEGRADING:
      return "NewNetworkConnectedPostPathDegrading";
    case ON_SERVER_PREFERRED_ADDRESS_AVAILABLE:
      return "OnServerPreferredAddressAvailable";
    default:
      QUICHE_NOTREACHED();
      break;
  }
  return "InvalidCause";
}

base::Value::Dict NetLogQuicClientSessionParams(
    const NetLogWithSource& net_log,
    const QuicSessionKey* session_key,
    const quic::QuicConnectionId& connection_id,
    const quic::QuicConnectionId& client_connection_id,
    const quic::ParsedQuicVersionVector& supported_versions,
    int cert_verify_flags,
    bool require_confirmation,
    base::span<const uint8_t> ech_config_list) {
  auto dict =
      base::Value::Dict()
          .Set("host", session_key->server_id().host())
          .Set("port", session_key->server_id().port())
          .Set("connection_id", connection_id.ToString())
          .Set("versions", ParsedQuicVersionVectorToString(supported_versions))
          .Set("require_confirmation", require_confirmation)
          .Set("cert_verify_flags", cert_verify_flags)
          .Set("privacy_mode",
               PrivacyModeToDebugString(session_key->privacy_mode()))
          .Set("proxy_chain", session_key->proxy_chain().ToDebugString())
          .Set("session_usage",
               session_key->session_usage() == SessionUsage::kDestination
                   ? "destination"
                   : "proxy")
          .Set("network_anonymization_key",
               session_key->network_anonymization_key().ToDebugString())
          .Set("secure_dns_policy",
               SecureDnsPolicyToDebugString(session_key->secure_dns_policy()))
          .Set("require_dns_https_alpn", session_key->require_dns_https_alpn());
  if (!client_connection_id.IsEmpty()) {
    dict.Set("client_connection_id", client_connection_id.ToString());
  }
  if (!ech_config_list.empty()) {
    dict.Set("ech_config_list", NetLogBinaryValue(ech_config_list));
  }
  net_log.source().AddToEventParameters(dict);
  return dict;
}

// TODO(fayang): Remove this when necessary data is collected.
void LogProbeResultToHistogram(MigrationCause cause, bool success) {
  UMA_HISTOGRAM_BOOLEAN("Net.QuicSession.PathValidationSuccess", success);
  const std::string histogram_name =
      "Net.QuicSession.PathValidationSuccess." + MigrationCauseToString(cause);
  STATIC_HISTOGRAM_POINTER_GROUP(
      histogram_name, cause, MIGRATION_CAUSE_MAX, AddBoolean(success),
      base::BooleanHistogram::FactoryGet(
          histogram_name, base::HistogramBase::kUmaTargetedHistogramFlag));
}

void LogSessionCreationInitiatorToHistogram(
    MultiplexedSessionCreationInitiator session_creation,
    bool is_used) {
  std::string histogram_name =
      base::StrCat({"Net.QuicSession.GoogleSearch.SessionCreationInitiator",
                    is_used ? ".Used" : ".Unused"});

  base::UmaHistogramEnumeration(histogram_name, session_creation);
}

}  // namespace

// static
void QuicChromiumClientSession::SetMidMigrationCallbackForTesting(
    base::OnceClosure callback) {
  MidMigrationCallbackForTesting() = std::move(callback);  // IN-TEST
}

QuicChromiumClientSession::Handle::Handle(
    const base::WeakPtr<QuicChromiumClientSession>& session,
    url::SchemeHostPort destination)
    : MultiplexedSessionHandle(session),
      session_(session),
      destination_(std::move(destination)),
      net_log_(session_->net_log()),
      was_handshake_confirmed_(session->OneRttKeysAvailable()),
      server_id_(session_->server_id()),
      quic_version_(session->connection()->version()) {
  DCHECK(session_);
  session_->AddHandle(this);
}

QuicChromiumClientSession::Handle::~Handle() {
  if (session_) {
    session_->RemoveHandle(this);
  }
}

void QuicChromiumClientSession::Handle::OnCryptoHandshakeConfirmed() {
  was_handshake_confirmed_ = true;
}

void QuicChromiumClientSession::Handle::OnSessionClosed(
    quic::ParsedQuicVersion quic_version,
    int net_error,
    quic::QuicErrorCode quic_error,
    quic::ConnectionCloseSource source,
    bool port_migration_detected,
    bool quic_connection_migration_attempted,
    bool quic_connection_migration_successful,
    LoadTimingInfo::ConnectTiming connect_timing,
    bool was_ever_used) {
  session_ = nullptr;
  port_migration_detected_ = port_migration_detected;
  quic_connection_migration_attempted_ = quic_connection_migration_attempted;
  quic_connection_migration_successful_ = quic_connection_migration_successful;
  net_error_ = net_error;
  quic_error_ = quic_error;
  source_ = source;
  quic_version_ = quic_version;
  connect_timing_ = connect_timing;
  was_ever_used_ = was_ever_used;
}

bool QuicChromiumClientSession::Handle::IsConnected() const {
  return session_ != nullptr;
}

bool QuicChromiumClientSession::Handle::OneRttKeysAvailable() const {
  return was_handshake_confirmed_;
}

const LoadTimingInfo::ConnectTiming&
QuicChromiumClientSession::Handle::GetConnectTiming() {
  if (!session_) {
    return connect_timing_;
  }

  return session_->GetConnectTiming();
}

void QuicChromiumClientSession::Handle::PopulateNetErrorDetails(
    NetErrorDetails* details) const {
  if (session_) {
    session_->PopulateNetErrorDetails(details);
  } else {
    details->quic_port_migration_detected = port_migration_detected_;
    details->quic_connection_error = quic_error_;
    details->source = source_;
    details->quic_connection_migration_attempted =
        quic_connection_migration_attempted_;
    details->quic_connection_migration_successful =
        quic_connection_migration_successful_;
  }
}

quic::ParsedQuicVersion QuicChromiumClientSession::Handle::GetQuicVersion()
    const {
  if (!session_) {
    return quic_version_;
  }

  return session_->GetQuicVersion();
}

std::unique_ptr<quic::QuicConnection::ScopedPacketFlusher>
QuicChromiumClientSession::Handle::CreatePacketBundler() {
  if (!session_) {
    return nullptr;
  }

  return std::make_unique<quic::QuicConnection::ScopedPacketFlusher>(
      session_->connection());
}

bool QuicChromiumClientSession::Handle::SharesSameSession(
    const Handle& other) const {
  return session_.get() == other.session_.get();
}

int QuicChromiumClientSession::Handle::RequestStream(
    bool requires_confirmation,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(!stream_request_);

  if (!session_ || session_->going_away_) {
    return ERR_CONNECTION_CLOSED;
  }

  requires_confirmation |= session_->gquic_zero_rtt_disabled();

  // std::make_unique does not work because the StreamRequest constructor
  // is private.
  stream_request_ = base::WrapUnique(
      new StreamRequest(this, requires_confirmation, traffic_annotation));
  return stream_request_->StartRequest(std::move(callback));
}

std::unique_ptr<QuicChromiumClientStream::Handle>
QuicChromiumClientSession::Handle::ReleaseStream() {
  DCHECK(stream_request_);

  auto handle = stream_request_->ReleaseStream();
  stream_request_.reset();
  return handle;
}

int QuicChromiumClientSession::Handle::WaitForHandshakeConfirmation(
    CompletionOnceCallback callback) {
  if (!session_) {
    return ERR_CONNECTION_CLOSED;
  }

  return session_->WaitForHandshakeConfirmation(std::move(callback));
}

void QuicChromiumClientSession::Handle::CancelRequest(StreamRequest* request) {
  if (session_) {
    session_->CancelRequest(request);
  }
}

int QuicChromiumClientSession::Handle::TryCreateStream(StreamRequest* request) {
  if (!session_) {
    return ERR_CONNECTION_CLOSED;
  }

  return session_->TryCreateStream(request);
}

int QuicChromiumClientSession::Handle::GetPeerAddress(
    IPEndPoint* address) const {
  if (!session_) {
    return ERR_CONNECTION_CLOSED;
  }

  *address = ToIPEndPoint(session_->peer_address());
  return OK;
}

int QuicChromiumClientSession::Handle::GetSelfAddress(
    IPEndPoint* address) const {
  if (!session_) {
    return ERR_CONNECTION_CLOSED;
  }

  *address = ToIPEndPoint(session_->self_address());
  return OK;
}

bool QuicChromiumClientSession::Handle::WasEverUsed() const {
  if (!session_) {
    return was_ever_used_;
  }

  return session_->WasConnectionEverUsed();
}

const std::set<std::string>&
QuicChromiumClientSession::Handle::GetDnsAliasesForSessionKey(
    const QuicSessionKey& key) const {
  static const base::NoDestructor<std::set<std::string>> emptyset_result;
  return session_ ? session_->GetDnsAliasesForSessionKey(key)
                  : *emptyset_result;
}

#if BUILDFLAG(ENABLE_WEBSOCKETS)
std::unique_ptr<WebSocketQuicStreamAdapter>
QuicChromiumClientSession::Handle::CreateWebSocketQuicStreamAdapter(
    WebSocketQuicStreamAdapter::Delegate* delegate,
    base::OnceCallback<void(std::unique_ptr<WebSocketQuicStreamAdapter>)>
        callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(!stream_request_);
  // std::make_unique does not work because the StreamRequest constructor
  // is private.
  stream_request_ = base::WrapUnique(new StreamRequest(
      this, /*requires_confirmation=*/false, traffic_annotation));
  return session_->CreateWebSocketQuicStreamAdapter(
      delegate, std::move(callback), stream_request_.get());
}
#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)

QuicChromiumClientSession::StreamRequest::StreamRequest(
    QuicChromiumClientSession::Handle* session,
    bool requires_confirmation,
    const NetworkTrafficAnnotationTag& traffic_annotation)
    : session_(session),
      requires_confirmation_(requires_confirmation),
      traffic_annotation_(traffic_annotation) {}

QuicChromiumClientSession::StreamRequest::~StreamRequest() {
  if (stream_) {
    stream_->Reset(quic::QUIC_STREAM_CANCELLED);
  }

  if (session_) {
    session_->CancelRequest(this);
  }
}

int QuicChromiumClientSession::StreamRequest::StartRequest(
    CompletionOnceCallback callback) {
  if (!session_->IsConnected()) {
    return ERR_CONNECTION_CLOSED;
  }

  next_state_ = STATE_WAIT_FOR_CONFIRMATION;
  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING) {
    callback_ = std::move(callback);
  }

  return rv;
}

std::unique_ptr<QuicChromiumClientStream::Handle>
QuicChromiumClientSession::StreamRequest::ReleaseStream() {
  DCHECK(stream_);
  return std::move(stream_);
}

void QuicChromiumClientSession::StreamRequest::OnRequestCompleteSuccess(
    std::unique_ptr<QuicChromiumClientStream::Handle> stream) {
  DCHECK_EQ(STATE_REQUEST_STREAM_COMPLETE, next_state_);

  stream_ = std::move(stream);
  // This method is called even when the request completes synchronously.
  if (callback_) {
    DoCallback(OK);
  }
}

void QuicChromiumClientSession::StreamRequest::OnRequestCompleteFailure(
    int rv) {
  DCHECK_EQ(STATE_REQUEST_STREAM_COMPLETE, next_state_);
  // This method is called even when the request completes synchronously.
  if (callback_) {
    // Avoid re-entrancy if the callback calls into the session.
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&QuicChromiumClientSession::StreamRequest::DoCallback,
                       weak_factory_.GetWeakPtr(), rv));
  }
}

void QuicChromiumClientSession::StreamRequest::OnIOComplete(int rv) {
  rv = DoLoop(rv);

  if (rv != ERR_IO_PENDING && !callback_.is_null()) {
    DoCallback(rv);
  }
}

void QuicChromiumClientSession::StreamRequest::DoCallback(int rv) {
  CHECK_NE(rv, ERR_IO_PENDING);
  CHECK(!callback_.is_null());

  // The client callback can do anything, including destroying this class,
  // so any pending callback must be issued after everything else is done.
  std::move(callback_).Run(rv);
}

int QuicChromiumClientSession::StreamRequest::DoLoop(int rv) {
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_WAIT_FOR_CONFIRMATION:
        CHECK_EQ(OK, rv);
        rv = DoWaitForConfirmation();
        break;
      case STATE_WAIT_FOR_CONFIRMATION_COMPLETE:
        rv = DoWaitForConfirmationComplete(rv);
        break;
      case STATE_REQUEST_STREAM:
        CHECK_EQ(OK, rv);
        rv = DoRequestStream();
        break;
      case STATE_REQUEST_STREAM_COMPLETE:
        rv = DoRequestStreamComplete(rv);
        break;
      default:
        NOTREACHED() << "next_state_: " << next_state_;
    }
  } while (next_state_ != STATE_NONE && next_state_ && rv != ERR_IO_PENDING);

  return rv;
}

int QuicChromiumClientSession::StreamRequest::DoWaitForConfirmation() {
  next_state_ = STATE_WAIT_FOR_CONFIRMATION_COMPLETE;
  if (requires_confirmation_) {
    return session_->WaitForHandshakeConfirmation(
        base::BindOnce(&QuicChromiumClientSession::StreamRequest::OnIOComplete,
                       weak_factory_.GetWeakPtr()));
  }

  return OK;
}

int QuicChromiumClientSession::StreamRequest::DoWaitForConfirmationComplete(
    int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  if (rv < 0) {
    return rv;
  }

  next_state_ = STATE_REQUEST_STREAM;
  return OK;
}

int QuicChromiumClientSession::StreamRequest::DoRequestStream() {
  next_state_ = STATE_REQUEST_STREAM_COMPLETE;

  return session_->TryCreateStream(this);
}

int QuicChromiumClientSession::StreamRequest::DoRequestStreamComplete(int rv) {
  DCHECK(rv == OK || !stream_);

  return rv;
}

QuicChromiumClientSession::QuicChromiumPathValidationContext::
    QuicChromiumPathValidationContext(
        const quic::QuicSocketAddress& self_address,
        const quic::QuicSocketAddress& peer_address,
        handles::NetworkHandle network,
        std::unique_ptr<QuicChromiumPacketWriter> writer,
        std::unique_ptr<QuicChromiumPacketReader> reader)
    : QuicPathValidationContext(self_address, peer_address),
      network_handle_(network),
      reader_(std::move(reader)),
      writer_(std::move(writer)) {}

QuicChromiumClientSession::QuicChromiumPathValidationContext::
    ~QuicChromiumPathValidationContext() = default;

handles::NetworkHandle
QuicChromiumClientSession::QuicChromiumPathValidationContext::network() {
  return network_handle_;
}
quic::QuicPacketWriter*
QuicChromiumClientSession::QuicChromiumPathValidationContext::WriterToUse() {
  return writer_.get();
}
std::unique_ptr<QuicChromiumPacketWriter>
QuicChromiumClientSession::QuicChromiumPathValidationContext::ReleaseWriter() {
  return std::move(writer_);
}
std::unique_ptr<QuicChromiumPacketReader>
QuicChromiumClientSession::QuicChromiumPathValidationContext::ReleaseReader() {
  return std::move(reader_);
}

QuicChromiumClientSession::ConnectionMigrationValidationResultDelegate::
    ConnectionMigrationValidationResultDelegate(
        QuicChromiumClientSession* session)
    : session_(session) {}

void QuicChromiumClientSession::ConnectionMigrationValidationResultDelegate::
    OnPathValidationSuccess(
        std::unique_ptr<quic::QuicPathValidationContext> context,
        quic::QuicTime start_time) {
  auto* chrome_context =
      static_cast<QuicChromiumPathValidationContext*>(context.get());
  session_->OnConnectionMigrationProbeSucceeded(
      chrome_context->network(), chrome_context->peer_address(),
      chrome_context->self_address(), chrome_context->ReleaseWriter(),
      chrome_context->ReleaseReader());
}

void QuicChromiumClientSession::ConnectionMigrationValidationResultDelegate::
    OnPathValidationFailure(
        std::unique_ptr<quic::QuicPathValidationContext> context) {
  session_->connection()->OnPathValidationFailureAtClient(
      /*is_multi_port=*/false, *context);
  // Note that socket, packet writer, and packet reader in |context| will be
  // discarded.
  auto* chrome_context =
      static_cast<QuicChromiumPathValidationContext*>(context.get());
  session_->OnProbeFailed(chrome_context->network(),
                          chrome_context->peer_address());
}

QuicChromiumClientSession::PortMigrationValidationResultDelegate::
    PortMigrationValidationResultDelegate(QuicChromiumClientSession* session)
    : session_(session) {}

void QuicChromiumClientSession::PortMigrationValidationResultDelegate::
    OnPathValidationSuccess(
        std::unique_ptr<quic::QuicPathValidationContext> context,
        quic::QuicTime start_time) {
  auto* chrome_context =
      static_cast<QuicChromiumPathValidationContext*>(context.get());
  session_->OnPortMigrationProbeSucceeded(
      chrome_context->network(), chrome_context->peer_address(),
      chrome_context->self_address(), chrome_context->ReleaseWriter(),
      chrome_context->ReleaseReader());
}

void QuicChromiumClientSession::PortMigrationValidationResultDelegate::
    OnPathValidationFailure(
        std::unique_ptr<quic::QuicPathValidationContext> context) {
  session_->connection()->OnPathValidationFailureAtClient(
      /*is_multi_port=*/false, *context);
  // Note that socket, packet writer, and packet reader in |context| will be
  // discarded.
  auto* chrome_context =
      static_cast<QuicChromiumPathValidationContext*>(context.get());
  session_->OnProbeFailed(chrome_context->network(),
                          chrome_context->peer_address());
}

QuicChromiumClientSession::ServerPreferredAddressValidationResultDelegate::
    ServerPreferredAddressValidationResultDelegate(
        QuicChromiumClientSession* session)
    : session_(session) {}

void QuicChromiumClientSession::ServerPreferredAddressValidationResultDelegate::
    OnPathValidationSuccess(
        std::unique_ptr<quic::QuicPathValidationContext> context,
        quic::QuicTime start_time) {
  auto* chrome_context =
      static_cast<QuicChromiumPathValidationContext*>(context.get());
  session_->OnServerPreferredAddressProbeSucceeded(
      chrome_context->network(), chrome_context->peer_address(),
      chrome_context->self_address(), chrome_context->ReleaseWriter(),
      chrome_context->ReleaseReader());
}

void QuicChromiumClientSession::ServerPreferredAddressValidationResultDelegate::
    OnPathValidationFailure(
        std::unique_ptr<quic::QuicPathValidationContext> context) {
  session_->connection()->OnPathValidationFailureAtClient(
      /*is_multi_port=*/false, *context);
  // Note that socket, packet writer, and packet reader in |context| will be
  // discarded.
  auto* chrome_context =
      static_cast<QuicChromiumPathValidationContext*>(context.get());
  session_->OnProbeFailed(chrome_context->network(),
                          chrome_context->peer_address());
}

QuicChromiumClientSession::QuicChromiumPathValidationWriterDelegate::
    QuicChromiumPathValidationWriterDelegate(
        QuicChromiumClientSession* session,
        base::SequencedTaskRunner* task_runner)
    : session_(session),
      task_runner_(task_runner),
      network_(handles::kInvalidNetworkHandle) {}

QuicChromiumClientSession::QuicChromiumPathValidationWriterDelegate::
    ~QuicChromiumPathValidationWriterDelegate() = default;

int QuicChromiumClientSession::QuicChromiumPathValidationWriterDelegate::
    HandleWriteError(
        int error_code,
        scoped_refptr<QuicChromiumPacketWriter::ReusableIOBuffer> last_packet) {
  // Write error on the probing network is not recoverable.
  DVLOG(1) << "Probing packet encounters write error " << error_code;
  // Post a task to notify |session_| that this probe failed and cancel
  // undergoing probing, which will delete the packet writer.
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &QuicChromiumPathValidationWriterDelegate::NotifySessionProbeFailed,
          weak_factory_.GetWeakPtr(), network_));
  return error_code;
}

void QuicChromiumClientSession::QuicChromiumPathValidationWriterDelegate::
    OnWriteError(int error_code) {
  NotifySessionProbeFailed(network_);
}
void QuicChromiumClientSession::QuicChromiumPathValidationWriterDelegate::
    OnWriteUnblocked() {}

void QuicChromiumClientSession::QuicChromiumPathValidationWriterDelegate::
    NotifySessionProbeFailed(handles::NetworkHandle network) {
  session_->OnProbeFailed(network, peer_address_);
}

void QuicChromiumClientSession::QuicChromiumPathValidationWriterDelegate::
    set_peer_address(const quic::QuicSocketAddress& peer_address) {
  peer_address_ = peer_address;
}

void QuicChromiumClientSession::QuicChromiumPathValidationWriterDelegate::
    set_network(handles::NetworkHandle network) {
  network_ = network;
}

QuicChromiumClientSession::QuicChromiumClientSession(
    quic::QuicConnection* connection,
    std::unique_ptr<DatagramClientSocket> socket,
    QuicSessionPool* session_pool,
    QuicCryptoClientStreamFactory* crypto_client_stream_factory,
    const quic::QuicClock* clock,
    TransportSecurityState* transport_security_state,
    SSLConfigService* ssl_config_service,
    std::unique_ptr<QuicServerInfo> server_info,
    QuicSessionAliasKey se
```