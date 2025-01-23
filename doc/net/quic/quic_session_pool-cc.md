Response:
The user wants a summary of the functionality of the provided C++ code file `net/quic/quic_session_pool.cc`. I need to identify the key responsibilities and data structures involved in managing QUIC sessions. I also need to look for potential relationships with JavaScript, common user errors, and how a user action might lead to this code being executed.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the core purpose:** The file name `quic_session_pool.cc` strongly suggests that this code is responsible for managing a pool of QUIC sessions.

2. **Scan for key data structures:** Look for class definitions and data structures that are central to session management. `active_sessions_`, `all_sessions_`, `active_jobs_`, `active_crypto_config_map_`, and `recent_crypto_config_map_` are prominent examples. These suggest the code manages both active and all sessions, pending session creation attempts (jobs), and configurations for establishing secure connections.

3. **Analyze key methods:**  Identify methods that perform core functions. `RequestSession`, `FindExistingSession`, `CreateSessionAttempt`, `OnSessionGoingAway`, `OnSessionClosed`, `CloseAllSessions` are crucial. These methods indicate the lifecycle management of QUIC sessions, including creation, lookup, removal, and closure.

4. **Look for connections to network operations:** The inclusion of `HostResolver`, `ClientSocketFactory`, and mentions of proxies suggests the code handles the network aspects of establishing QUIC connections.

5. **Search for security-related components:**  References to `CertVerifier`, `TransportSecurityState`, and `QuicCryptoClientConfig` highlight the code's involvement in secure connection establishment.

6. **Consider the "pool" aspect:** The "pool" in the name implies reuse of connections. The code likely has logic to determine if an existing session can be reused for a new request.

7. **Think about asynchronous operations:** The use of callbacks (`CompletionOnceCallback`) and the `ERR_IO_PENDING` return code point towards asynchronous operations involved in establishing connections.

8. **Relate to JavaScript (if possible):**  Consider how web browsers interact with network protocols. JavaScript code initiates network requests. The browser's network stack, including this QUIC session pool, handles these requests. The connection is indirect: JavaScript triggers a request, which might lead to the QUIC session pool being used.

9. **Consider user errors:**  Think about common network-related errors users might encounter that could involve QUIC. Name resolution failures and certificate errors are good candidates.

10. **Trace user actions:**  Imagine a user browsing a website over HTTPS. The browser needs to establish a secure connection, which could involve QUIC. The process involves resolving the hostname, establishing a connection, and potentially reusing an existing QUIC session.

11. **Formulate the summary based on the above points:** Combine the observations into a concise description of the file's functionality.

12. **Refine the summary:** Ensure the language is clear and accurately reflects the code's purpose. For example, emphasize the pooling and reuse aspects.

By following this thought process, I can arrive at a comprehensive summary like the example provided in the prompt's instructions. The iterative nature of analysis—scanning, identifying key elements, and then synthesizing—is crucial for understanding complex codebases.
这是 `net/quic/quic_session_pool.cc` 文件的第一部分，它主要负责 **管理和复用 QUIC 客户端会话**。

以下是其功能的详细归纳：

**核心功能:**

* **会话池管理:**  维护着一个 QUIC 客户端会话池 (`active_sessions_`, `all_sessions_`)，用于存储和管理已建立的 QUIC 会话。
* **会话查找和复用:**  能够根据目标地址、代理配置等信息查找现有的可用 QUIC 会话，并将其复用于新的连接请求，从而提高效率并减少延迟。
* **会话创建请求处理:**  处理创建新 QUIC 会话的请求 (`RequestSession`)，并管理这些请求的状态。
* **会话创建过程:** 协调 QUIC 会话的创建过程，包括 DNS 解析、连接建立、握手等步骤。
* **会话生命周期管理:**  监控和管理 QUIC 会话的生命周期，包括会话的激活、关闭、以及在网络状态变化时的处理。
* **连接尝试管理:**  通过 `QuicSessionAttempt` 类管理单个 QUIC 连接尝试。
* **加密配置管理:**  管理 QUIC 加密客户端配置 (`QuicCryptoClientConfig`)，并支持配置的缓存和复用。
* **处理网络事件:**  响应网络状态变化事件（例如网络连接/断开、IP 地址变化），并采取相应的措施，例如关闭或标记会话为不可用。
* **性能指标收集:**  收集 QUIC 会话相关的性能指标，例如会话创建失败的原因，用于监控和分析。

**与其他模块的交互:**

* **HostResolver:** 用于解析目标主机的 IP 地址。
* **ClientSocketFactory:** 用于创建底层网络 Socket。
* **SSLConfigService:** 用于获取 SSL 配置信息。
* **CertVerifier:** 用于验证服务器证书。
* **TransportSecurityState:** 用于管理 HSTS 和 HPKP 等安全策略。
* **ProxyDelegate:** 用于处理代理相关的逻辑。
* **QuicCryptoClientStreamFactory:** 用于创建 QUIC 加密流。
* **NetLog:** 用于记录 QUIC 会话相关的事件，方便调试和分析。

**与 JavaScript 的关系 (间接):**

JavaScript 代码在浏览器中发起网络请求（例如通过 `fetch` 或 `XMLHttpRequest`）。当浏览器决定使用 QUIC 协议时，会调用网络栈中相应的模块来处理连接。`QuicSessionPool` 位于这个网络栈中，负责管理和复用 QUIC 会话。

**举例说明:**

假设 JavaScript 代码发起了一个 HTTPS 请求到一个支持 QUIC 的网站 `https://example.com`:

1. JavaScript 调用浏览器的网络 API 发起请求。
2. 浏览器的网络栈判断是否可以使用 QUIC。
3. 如果可以使用 QUIC，网络栈会调用 `QuicSessionPool::RequestSession` 方法，尝试获取或创建一个到 `example.com` 的 QUIC 会话。
4. `QuicSessionPool` 会检查是否已经存在一个到 `example.com` 的可用 QUIC 会话。
5. 如果存在，则复用该会话，并将请求关联到该会话上。
6. 如果不存在，则创建一个新的 QUIC 会话。

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 用户在浏览器中访问 `https://www.google.com`.
* `QuicSessionPool` 中不存在到 `www.google.com` 的可用 QUIC 会话。

**输出:**

* `QuicSessionPool::RequestSession` 方法会被调用。
* `QuicSessionPool` 会创建一个 `DirectJob` (因为是直连)。
* `DirectJob` 会调用 `HostResolver` 解析 `www.google.com` 的 IP 地址。
* `DirectJob` 会使用 `ClientSocketFactory` 创建 UDP Socket。
* `DirectJob` 会创建一个 `QuicChromiumClientSession` 并进行握手。
* 新创建的 `QuicChromiumClientSession` 会被添加到 `active_sessions_` 和 `all_sessions_` 中。
* 请求会关联到这个新创建的会话。

**用户或编程常见的使用错误:**

* **错误地配置代理:** 如果用户配置了错误的代理，可能会导致 QUIC 连接失败，并且 `QuicSessionPool` 可能会不断尝试连接。
* **防火墙阻止 QUIC:** 如果用户的防火墙阻止了 UDP 流量或特定的 QUIC 端口，会导致连接失败。
* **服务器不支持 QUIC:** 如果目标服务器不支持 QUIC，浏览器会回退到其他协议，但在这个过程中 `QuicSessionPool` 可能会尝试连接并最终失败。
* **客户端 QUIC 配置错误:**  开发者可能错误地配置了浏览器的 QUIC 相关设置，导致连接问题。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并按下回车键，或者点击一个链接。**
2. **浏览器解析 URL，判断是否可以使用 HTTPS。**
3. **浏览器网络栈检查是否支持 QUIC 协议以及是否启用。**
4. **如果支持并启用 QUIC，网络栈会尝试使用 QUIC 建立连接。**
5. **网络栈会查找 `QuicSessionPool` 中是否有可用的到目标服务器的 QUIC 会话。**
6. **如果没有找到，网络栈会调用 `QuicSessionPool::RequestSession` 来请求创建一个新的 QUIC 会话。**
7. **`QuicSessionPool` 内部会启动相应的 Job（`DirectJob` 或 `ProxyJob`）来执行连接建立过程。**

**本部分功能归纳:**

总而言之，这部分代码的核心职责是 **高效地管理和复用 QUIC 客户端会话，以支持基于 QUIC 协议的网络连接**。它负责接收会话请求、查找现有会话、创建新会话、并维护会话的生命周期。它在浏览器的网络栈中扮演着关键角色，直接影响着 QUIC 连接的性能和可靠性。

### 提示词
```
这是目录为net/quic/quic_session_pool.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_session_pool.h"

#include <memory>
#include <optional>
#include <set>
#include <string_view>
#include <tuple>
#include <utility>

#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/no_destructor.h"
#include "base/not_fatal_until.h"
#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/strings/escape.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/values.h"
#include "crypto/openssl_util.h"
#include "net/base/address_list.h"
#include "net/base/connection_endpoint_metadata.h"
#include "net/base/features.h"
#include "net/base/http_user_agent_settings.h"
#include "net/base/ip_address.h"
#include "net/base/net_errors.h"
#include "net/base/network_anonymization_key.h"
#include "net/base/network_handle.h"
#include "net/base/proxy_delegate.h"
#include "net/base/session_usage.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "net/base/url_util.h"
#include "net/cert/cert_verifier.h"
#include "net/dns/host_resolver.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/http/http_proxy_connect_job.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/quic/address_utils.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/quic/properties_based_quic_server_info.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_client_session.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/quic/quic_context.h"
#include "net/quic/quic_crypto_client_stream_factory.h"
#include "net/quic/quic_server_info.h"
#include "net/quic/quic_session_key.h"
#include "net/quic/quic_session_pool_direct_job.h"
#include "net/quic/quic_session_pool_job.h"
#include "net/quic/quic_session_pool_proxy_job.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/next_proto.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"
#include "net/socket/udp_client_socket.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/null_decrypter.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/proof_verifier.h"
#include "net/third_party/quiche/src/quiche/quic/core/crypto/quic_random.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_clock.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quiche/quic/platform/api/quic_flags.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "third_party/boringssl/src/include/openssl/aead.h"
#include "url/gurl.h"
#include "url/scheme_host_port.h"
#include "url/url_constants.h"

namespace net {

namespace {

enum InitialRttEstimateSource {
  INITIAL_RTT_DEFAULT,
  INITIAL_RTT_CACHED,
  INITIAL_RTT_2G,
  INITIAL_RTT_3G,
  INITIAL_RTT_SOURCE_MAX,
};

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
enum FindMatchingIpSessionResult {
  MATCHING_IP_SESSION_FOUND,
  CAN_POOL_BUT_DIFFERENT_IP,
  CANNOT_POOL_WITH_EXISTING_SESSIONS,
  POOLED_WITH_DIFFERENT_IP_SESSION,
  FIND_MATCHING_IP_SESSION_RESULT_MAX
};

std::string QuicPlatformNotificationToString(
    QuicPlatformNotification notification) {
  switch (notification) {
    case NETWORK_CONNECTED:
      return "OnNetworkConnected";
    case NETWORK_MADE_DEFAULT:
      return "OnNetworkMadeDefault";
    case NETWORK_DISCONNECTED:
      return "OnNetworkDisconnected";
    case NETWORK_SOON_TO_DISCONNECT:
      return "OnNetworkSoonToDisconnect";
    case NETWORK_IP_ADDRESS_CHANGED:
      return "OnIPAddressChanged";
    default:
      QUICHE_NOTREACHED();
      break;
  }
  return "InvalidNotification";
}

const char* AllActiveSessionsGoingAwayReasonToString(
    AllActiveSessionsGoingAwayReason reason) {
  switch (reason) {
    case kClockSkewDetected:
      return "ClockSkewDetected";
    case kIPAddressChanged:
      return "IPAddressChanged";
    case kCertDBChanged:
      return "CertDBChanged";
    case kCertVerifierChanged:
      return "CertVerifierChanged";
  }
}

void HistogramCreateSessionFailure(enum CreateSessionFailure error) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.CreationError", error,
                            CREATION_ERROR_MAX);
}

void LogFindMatchingIpSessionResult(const NetLogWithSource& net_log,
                                    FindMatchingIpSessionResult result,
                                    QuicChromiumClientSession* session,
                                    const url::SchemeHostPort& destination) {
  NetLogEventType type =
      NetLogEventType::QUIC_SESSION_POOL_CANNOT_POOL_WITH_EXISTING_SESSIONS;
  switch (result) {
    case MATCHING_IP_SESSION_FOUND:
      type = NetLogEventType::QUIC_SESSION_POOL_MATCHING_IP_SESSION_FOUND;
      break;
    case POOLED_WITH_DIFFERENT_IP_SESSION:
      type =
          NetLogEventType::QUIC_SESSION_POOL_POOLED_WITH_DIFFERENT_IP_SESSION;
      break;
    case CAN_POOL_BUT_DIFFERENT_IP:
      type = NetLogEventType::QUIC_SESSION_POOL_CAN_POOL_BUT_DIFFERENT_IP;
      break;
    case CANNOT_POOL_WITH_EXISTING_SESSIONS:
    case FIND_MATCHING_IP_SESSION_RESULT_MAX:
      break;
  }
  net_log.AddEvent(type, [&] {
    base::Value::Dict dict;
    dict.Set("destination", destination.Serialize());
    if (session != nullptr) {
      session->net_log().source().AddToEventParameters(dict);
    }
    return dict;
  });
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.FindMatchingIpSessionResult",
                            result, FIND_MATCHING_IP_SESSION_RESULT_MAX);
  if (IsGoogleHost(destination.host()) &&
      !destination.host().ends_with(".googlevideo.com")) {
    UMA_HISTOGRAM_ENUMERATION(
        "Net.QuicSession.FindMatchingIpSessionResultGoogle", result,
        FIND_MATCHING_IP_SESSION_RESULT_MAX);
  }
}

void SetInitialRttEstimate(base::TimeDelta estimate,
                           enum InitialRttEstimateSource source,
                           quic::QuicConfig* config) {
  UMA_HISTOGRAM_ENUMERATION("Net.QuicSession.InitialRttEsitmateSource", source,
                            INITIAL_RTT_SOURCE_MAX);
  if (estimate != base::TimeDelta()) {
    config->SetInitialRoundTripTimeUsToSend(
        base::checked_cast<uint64_t>(estimate.InMicroseconds()));
  }
}

// An implementation of quic::QuicCryptoClientConfig::ServerIdFilter that wraps
// an |origin_filter|.
class ServerIdOriginFilter
    : public quic::QuicCryptoClientConfig::ServerIdFilter {
 public:
  explicit ServerIdOriginFilter(
      const base::RepeatingCallback<bool(const GURL&)> origin_filter)
      : origin_filter_(origin_filter) {}

  bool Matches(const quic::QuicServerId& server_id) const override {
    if (origin_filter_.is_null()) {
      return true;
    }

    GURL url(base::StringPrintf("%s%s%s:%d", url::kHttpsScheme,
                                url::kStandardSchemeSeparator,
                                server_id.host().c_str(), server_id.port()));
    DCHECK(url.is_valid());
    return origin_filter_.Run(url);
  }

 private:
  const base::RepeatingCallback<bool(const GURL&)> origin_filter_;
};

std::set<std::string> HostsFromOrigins(std::set<HostPortPair> origins) {
  std::set<std::string> hosts;
  for (const auto& origin : origins) {
    hosts.insert(origin.host());
  }
  return hosts;
}

void LogUsingExistingSession(const NetLogWithSource& request_net_log,
                             QuicChromiumClientSession* session,
                             const url::SchemeHostPort& destination) {
  request_net_log.AddEvent(
      NetLogEventType::QUIC_SESSION_POOL_USE_EXISTING_SESSION, [&] {
        base::Value::Dict dict;
        dict.Set("destination", destination.Serialize());
        session->net_log().source().AddToEventParameters(dict);
        return dict;
      });
  session->net_log().AddEventReferencingSource(
      NetLogEventType::
          QUIC_SESSION_POOL_ATTACH_HTTP_STREAM_JOB_TO_EXISTING_SESSION,
      request_net_log.source());
}

}  // namespace

QuicSessionRequest::QuicSessionRequest(QuicSessionPool* pool) : pool_(pool) {}

QuicSessionRequest::~QuicSessionRequest() {
  if (pool_ && !callback_.is_null()) {
    pool_->CancelRequest(this);
  }
}

int QuicSessionRequest::Request(
    url::SchemeHostPort destination,
    quic::ParsedQuicVersion quic_version,
    const ProxyChain& proxy_chain,
    std::optional<NetworkTrafficAnnotationTag> proxy_annotation_tag,
    const HttpUserAgentSettings* http_user_agent_settings,
    SessionUsage session_usage,
    PrivacyMode privacy_mode,
    RequestPriority priority,
    const SocketTag& socket_tag,
    const NetworkAnonymizationKey& network_anonymization_key,
    SecureDnsPolicy secure_dns_policy,
    bool require_dns_https_alpn,
    int cert_verify_flags,
    const GURL& url,
    const NetLogWithSource& net_log,
    NetErrorDetails* net_error_details,
    MultiplexedSessionCreationInitiator session_creation_initiator,
    CompletionOnceCallback failed_on_default_network_callback,
    CompletionOnceCallback callback) {
  DCHECK_EQ(quic_version.IsKnown(), !require_dns_https_alpn);
  DCHECK(net_error_details);
  DCHECK(callback_.is_null());
  DCHECK(host_resolution_callback_.is_null());
  DCHECK(pool_);

  net_error_details_ = net_error_details;
  failed_on_default_network_callback_ =
      std::move(failed_on_default_network_callback);

  session_key_ =
      QuicSessionKey(HostPortPair::FromURL(url), privacy_mode, proxy_chain,
                     session_usage, socket_tag, network_anonymization_key,
                     secure_dns_policy, require_dns_https_alpn);
  bool use_dns_aliases = session_usage == SessionUsage::kProxy ? false : true;

  int rv = pool_->RequestSession(
      session_key_, std::move(destination), quic_version,
      std::move(proxy_annotation_tag), session_creation_initiator,
      http_user_agent_settings, priority, use_dns_aliases, cert_verify_flags,
      url, net_log, this);
  if (rv == ERR_IO_PENDING) {
    net_log_ = net_log;
    callback_ = std::move(callback);
  } else {
    DCHECK(!expect_on_host_resolution_);
    pool_ = nullptr;
  }

  if (rv == OK) {
    DCHECK(session_);
  }
  return rv;
}

bool QuicSessionRequest::WaitForHostResolution(
    CompletionOnceCallback callback) {
  DCHECK(host_resolution_callback_.is_null());
  if (expect_on_host_resolution_) {
    host_resolution_callback_ = std::move(callback);
  }
  return expect_on_host_resolution_;
}

void QuicSessionRequest::ExpectOnHostResolution() {
  expect_on_host_resolution_ = true;
}

void QuicSessionRequest::OnHostResolutionComplete(
    int rv,
    base::TimeTicks dns_resolution_start_time,
    base::TimeTicks dns_resolution_end_time) {
  DCHECK(expect_on_host_resolution_);
  expect_on_host_resolution_ = false;
  dns_resolution_start_time_ = dns_resolution_start_time;
  dns_resolution_end_time_ = dns_resolution_end_time;
  if (!host_resolution_callback_.is_null()) {
    std::move(host_resolution_callback_).Run(rv);
  }
}

bool QuicSessionRequest::WaitForQuicSessionCreation(
    CompletionOnceCallback callback) {
  DCHECK(create_session_callback_.is_null());
  if (expect_on_quic_session_creation_) {
    create_session_callback_ = std::move(callback);
  }
  return expect_on_quic_session_creation_;
}

void QuicSessionRequest::ExpectQuicSessionCreation() {
  expect_on_quic_session_creation_ = true;
}

void QuicSessionRequest::OnQuicSessionCreationComplete(int rv) {
  // DCHECK(expect_on_quic_session_creation_);
  expect_on_quic_session_creation_ = false;
  if (!create_session_callback_.is_null()) {
    std::move(create_session_callback_).Run(rv);
  }
}

void QuicSessionRequest::OnRequestComplete(int rv) {
  pool_ = nullptr;
  std::move(callback_).Run(rv);
}

void QuicSessionRequest::OnConnectionFailedOnDefaultNetwork() {
  if (!failed_on_default_network_callback_.is_null()) {
    std::move(failed_on_default_network_callback_).Run(OK);
  }
}

base::TimeDelta QuicSessionRequest::GetTimeDelayForWaitingJob() const {
  if (!pool_) {
    return base::TimeDelta();
  }
  return pool_->GetTimeDelayForWaitingJob(session_key_);
}

void QuicSessionRequest::SetPriority(RequestPriority priority) {
  if (pool_) {
    pool_->SetRequestPriority(this, priority);
  }
}

std::unique_ptr<QuicChromiumClientSession::Handle>
QuicSessionRequest::ReleaseSessionHandle() {
  if (!session_ || !session_->IsConnected()) {
    return nullptr;
  }

  return std::move(session_);
}

void QuicSessionRequest::SetSession(
    std::unique_ptr<QuicChromiumClientSession::Handle> session) {
  session_ = std::move(session);
}

QuicEndpoint::QuicEndpoint(quic::ParsedQuicVersion quic_version,
                           IPEndPoint ip_endpoint,
                           ConnectionEndpointMetadata metadata)
    : quic_version(quic_version),
      ip_endpoint(ip_endpoint),
      metadata(metadata) {}

QuicEndpoint::~QuicEndpoint() = default;

base::Value::Dict QuicEndpoint::ToValue() const {
  base::Value::Dict dict;
  dict.Set("quic_version", quic::ParsedQuicVersionToString(quic_version));
  dict.Set("ip_endpoint", ip_endpoint.ToString());
  dict.Set("metadata", metadata.ToValue());
  return dict;
}

QuicSessionPool::QuicCryptoClientConfigOwner::QuicCryptoClientConfigOwner(
    std::unique_ptr<quic::ProofVerifier> proof_verifier,
    std::unique_ptr<quic::QuicClientSessionCache> session_cache,
    QuicSessionPool* quic_session_pool)
    : config_(std::move(proof_verifier), std::move(session_cache)),
      clock_(base::DefaultClock::GetInstance()),
      quic_session_pool_(quic_session_pool) {
  DCHECK(quic_session_pool_);
  memory_pressure_listener_ = std::make_unique<base::MemoryPressureListener>(
      FROM_HERE,
      base::BindRepeating(&QuicCryptoClientConfigOwner::OnMemoryPressure,
                          base::Unretained(this)));
  if (quic_session_pool_->ssl_config_service_->GetSSLContextConfig()
          .PostQuantumKeyAgreementEnabled()) {
    uint16_t postquantum_group =
        base::FeatureList::IsEnabled(features::kUseMLKEM)
            ? SSL_GROUP_X25519_MLKEM768
            : SSL_GROUP_X25519_KYBER768_DRAFT00;
    config_.set_preferred_groups({postquantum_group, SSL_GROUP_X25519,
                                  SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1});
  }
}
QuicSessionPool::QuicCryptoClientConfigOwner::~QuicCryptoClientConfigOwner() {
  DCHECK_EQ(num_refs_, 0);
}

void QuicSessionPool::QuicCryptoClientConfigOwner::OnMemoryPressure(
    base::MemoryPressureListener::MemoryPressureLevel memory_pressure_level) {
  quic::SessionCache* session_cache = config_.session_cache();
  if (!session_cache) {
    return;
  }
  time_t now = clock_->Now().ToTimeT();
  uint64_t now_u64 = 0;
  if (now > 0) {
    now_u64 = static_cast<uint64_t>(now);
  }
  switch (memory_pressure_level) {
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_NONE:
      break;
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_MODERATE:
      session_cache->RemoveExpiredEntries(
          quic::QuicWallTime::FromUNIXSeconds(now_u64));
      break;
    case base::MemoryPressureListener::MEMORY_PRESSURE_LEVEL_CRITICAL:
      session_cache->Clear();
      break;
  }
}

QuicSessionPool::CryptoClientConfigHandle::CryptoClientConfigHandle(
    const QuicCryptoClientConfigMap::iterator& map_iterator)
    : map_iterator_(map_iterator) {
  DCHECK_GE(map_iterator_->second->num_refs(), 0);
  map_iterator->second->AddRef();
}

QuicSessionPool::CryptoClientConfigHandle::~CryptoClientConfigHandle() {
  DCHECK_GT(map_iterator_->second->num_refs(), 0);
  map_iterator_->second->ReleaseRef();
  if (map_iterator_->second->num_refs() == 0) {
    map_iterator_->second->quic_session_pool()->OnAllCryptoClientRefReleased(
        map_iterator_);
  }
}

quic::QuicCryptoClientConfig*
QuicSessionPool::CryptoClientConfigHandle::GetConfig() const {
  return map_iterator_->second->config();
}

QuicSessionPool::QuicSessionPool(
    NetLog* net_log,
    HostResolver* host_resolver,
    SSLConfigService* ssl_config_service,
    ClientSocketFactory* client_socket_factory,
    HttpServerProperties* http_server_properties,
    CertVerifier* cert_verifier,
    TransportSecurityState* transport_security_state,
    ProxyDelegate* proxy_delegate,
    SCTAuditingDelegate* sct_auditing_delegate,
    SocketPerformanceWatcherFactory* socket_performance_watcher_factory,
    QuicCryptoClientStreamFactory* quic_crypto_client_stream_factory,
    QuicContext* quic_context)
    : net_log_(
          NetLogWithSource::Make(net_log, NetLogSourceType::QUIC_SESSION_POOL)),
      host_resolver_(host_resolver),
      client_socket_factory_(client_socket_factory),
      http_server_properties_(http_server_properties),
      cert_verifier_(cert_verifier),
      transport_security_state_(transport_security_state),
      proxy_delegate_(proxy_delegate),
      sct_auditing_delegate_(sct_auditing_delegate),
      quic_crypto_client_stream_factory_(quic_crypto_client_stream_factory),
      random_generator_(quic_context->random_generator()),
      clock_(quic_context->clock()),
      // TODO(vasilvv): figure out how to avoid having multiple copies of
      // QuicParams.
      params_(*quic_context->params()),
      clock_skew_detector_(base::TimeTicks::Now(), base::Time::Now()),
      socket_performance_watcher_factory_(socket_performance_watcher_factory),
      recent_crypto_config_map_(kMaxRecentCryptoConfigs),
      config_(InitializeQuicConfig(*quic_context->params())),
      ping_timeout_(quic::QuicTime::Delta::FromSeconds(quic::kPingTimeoutSecs)),
      reduced_ping_timeout_(quic::QuicTime::Delta::FromMicroseconds(
          quic_context->params()->reduced_ping_timeout.InMicroseconds())),
      retransmittable_on_wire_timeout_(quic::QuicTime::Delta::FromMicroseconds(
          quic_context->params()
              ->retransmittable_on_wire_timeout.InMicroseconds())),
      yield_after_packets_(kQuicYieldAfterPacketsRead),
      yield_after_duration_(quic::QuicTime::Delta::FromMilliseconds(
          kQuicYieldAfterDurationMilliseconds)),
      default_network_(handles::kInvalidNetworkHandle),
      connectivity_monitor_(default_network_),
      task_runner_(base::SequencedTaskRunner::GetCurrentDefault()),
      tick_clock_(base::DefaultTickClock::GetInstance()),
      ssl_config_service_(ssl_config_service),
      use_network_anonymization_key_for_crypto_configs_(
          NetworkAnonymizationKey::IsPartitioningEnabled()),
      report_ecn_(quic_context->params()->report_ecn),
      skip_dns_with_origin_frame_(
          quic_context->params()->skip_dns_with_origin_frame),
      ignore_ip_matching_when_finding_existing_sessions_(
          quic_context->params()
              ->ignore_ip_matching_when_finding_existing_sessions) {
  DCHECK(transport_security_state_);
  DCHECK(http_server_properties_);
  if (params_.disable_tls_zero_rtt) {
    SetQuicFlag(quic_disable_client_tls_zero_rtt, true);
  }
  InitializeMigrationOptions();
  cert_verifier_->AddObserver(this);
  CertDatabase::GetInstance()->AddObserver(this);
}

QuicSessionPool::~QuicSessionPool() {
  UMA_HISTOGRAM_COUNTS_1000("Net.NumQuicSessionsAtShutdown",
                            all_sessions_.size());
  CloseAllSessions(ERR_ABORTED, quic::QUIC_CONNECTION_CANCELLED);
  all_sessions_.clear();

  // Clear the active jobs, first moving out of the instance variable so that
  // calls to CancelRequest for any pending requests do not cause recursion.
  JobMap active_jobs = std::move(active_jobs_);
  active_jobs.clear();

  DCHECK(dns_aliases_by_session_key_.empty());

  // This should have been moved to the recent map when all consumers of
  // QuicCryptoClientConfigs were deleted, in the above lines.
  DCHECK(active_crypto_config_map_.empty());

  CertDatabase::GetInstance()->RemoveObserver(this);
  cert_verifier_->RemoveObserver(this);
  if (params_.close_sessions_on_ip_change ||
      params_.goaway_sessions_on_ip_change) {
    NetworkChangeNotifier::RemoveIPAddressObserver(this);
  }
  if (NetworkChangeNotifier::AreNetworkHandlesSupported()) {
    NetworkChangeNotifier::RemoveNetworkObserver(this);
  }
}

bool QuicSessionPool::CanUseExistingSession(
    const QuicSessionKey& session_key,
    const url::SchemeHostPort& destination) const {
  return FindExistingSession(session_key, destination) != nullptr;
}

QuicChromiumClientSession* QuicSessionPool::FindExistingSession(
    const QuicSessionKey& session_key,
    const url::SchemeHostPort& destination) const {
  auto active_session_it = active_sessions_.find(session_key);
  if (active_session_it != active_sessions_.end()) {
    return active_session_it->second;
  }

  for (const auto& key_value : active_sessions_) {
    QuicChromiumClientSession* session = key_value.second;
    if (CanWaiveIpMatching(destination, session) &&
        session->CanPool(session_key.host(), session_key)) {
      return session;
    }
  }

  return nullptr;
}

bool QuicSessionPool::HasMatchingIpSessionForServiceEndpoint(
    const QuicSessionAliasKey& session_alias_key,
    const ServiceEndpoint& service_endpoint,
    const std::set<std::string>& dns_aliases,
    bool use_dns_aliases) {
  return HasMatchingIpSession(session_alias_key,
                              service_endpoint.ipv6_endpoints, dns_aliases,
                              use_dns_aliases) ||
         HasMatchingIpSession(session_alias_key,
                              service_endpoint.ipv4_endpoints, dns_aliases,
                              use_dns_aliases);
}

int QuicSessionPool::RequestSession(
    const QuicSessionKey& session_key,
    url::SchemeHostPort destination,
    quic::ParsedQuicVersion quic_version,
    std::optional<NetworkTrafficAnnotationTag> proxy_annotation_tag,
    MultiplexedSessionCreationInitiator session_creation_initiator,
    const HttpUserAgentSettings* http_user_agent_settings,
    RequestPriority priority,
    bool use_dns_aliases,
    int cert_verify_flags,
    const GURL& url,
    const NetLogWithSource& net_log,
    QuicSessionRequest* request) {
  if (clock_skew_detector_.ClockSkewDetected(base::TimeTicks::Now(),
                                             base::Time::Now())) {
    MarkAllActiveSessionsGoingAway(kClockSkewDetected);
  }
  DCHECK(HostPortPair(session_key.server_id().host(),
                      session_key.server_id().port())
             .Equals(HostPortPair::FromURL(url)));

  // Use active session for `session_key` if such exists, or pool to active
  // session to `destination` if possible.
  QuicChromiumClientSession* existing_session =
      FindExistingSession(session_key, destination);
  if (existing_session) {
    LogUsingExistingSession(net_log, existing_session, destination);
    if (!HasActiveSession(session_key)) {
      QuicSessionAliasKey key(destination, session_key);
      std::set<std::string> dns_aliases;
      ActivateAndMapSessionToAliasKey(existing_session, key,
                                      std::move(dns_aliases));
    }
    request->SetSession(existing_session->CreateHandle(std::move(destination)));
    return OK;
  }

  // Associate with active job to |session_key| if such exists.
  auto active_job = active_jobs_.find(session_key);
  if (active_job != active_jobs_.end()) {
    active_job->second->AssociateWithNetLogSource(net_log);
    active_job->second->AddRequest(request);
    return ERR_IO_PENDING;
  }

  // If a proxy is in use, then a traffic annotation is required.
  if (!session_key.proxy_chain().is_direct()) {
    DCHECK(proxy_annotation_tag);
  }

  QuicSessionAliasKey key(destination, session_key);
  std::unique_ptr<Job> job;
  // Connect start time, but only for direct connections to a proxy.
  std::optional<base::TimeTicks> proxy_connect_start_time = std::nullopt;
  if (session_key.proxy_chain().is_direct()) {
    if (session_key.session_usage() == SessionUsage::kProxy) {
      proxy_connect_start_time = base::TimeTicks::Now();
    }
    job = std::make_unique<DirectJob>(
        this, quic_version, host_resolver_, std::move(key),
        CreateCryptoConfigHandle(session_key.network_anonymization_key()),
        params_.retry_on_alternate_network_before_handshake, priority,
        use_dns_aliases, session_key.require_dns_https_alpn(),
        cert_verify_flags, session_creation_initiator, net_log);
  } else {
    job = std::make_unique<ProxyJob>(
        this, quic_version, std::move(key), *proxy_annotation_tag,
        session_creation_initiator, http_user_agent_settings,
        CreateCryptoConfigHandle(session_key.network_anonymization_key()),
        priority, cert_verify_flags, net_log);
  }
  job->AssociateWithNetLogSource(net_log);
  int rv = job->Run(base::BindOnce(&QuicSessionPool::OnJobComplete,
                                   weak_factory_.GetWeakPtr(), job.get(),
                                   proxy_connect_start_time));
  if (rv == ERR_IO_PENDING) {
    job->AddRequest(request);
    active_jobs_[session_key] = std::move(job);
    return rv;
  }
  if (rv == OK) {
    auto it = active_sessions_.find(session_key);
    CHECK(it != active_sessions_.end(), base::NotFatalUntil::M130);
    if (it == active_sessions_.end()) {
      return ERR_QUIC_PROTOCOL_ERROR;
    }
    QuicChromiumClientSession* session = it->second;
    request->SetSession(session->CreateHandle(std::move(destination)));
  }
  return rv;
}

std::unique_ptr<QuicSessionAttempt> QuicSessionPool::CreateSessionAttempt(
    QuicSessionAttempt::Delegate* delegate,
    const QuicSessionKey& session_key,
    QuicEndpoint quic_endpoint,
    int cert_verify_flags,
    base::TimeTicks dns_resolution_start_time,
    base::TimeTicks dns_resolution_end_time,
    bool use_dns_aliases,
    std::set<std::string> dns_aliases,
    MultiplexedSessionCreationInitiator session_creation_initiator) {
  CHECK(!HasActiveSession(session_key));
  CHECK(!HasActiveJob(session_key));

  return std::make_unique<QuicSessionAttempt>(
      delegate, quic_endpoint.ip_endpoint, std::move(quic_endpoint.metadata),
      quic_endpoint.quic_version, cert_verify_flags, dns_resolution_start_time,
      dns_resolution_end_time,
      params_.retry_on_alternate_network_before_handshake, use_dns_aliases,
      std::move(dns_aliases),
      CreateCryptoConfigHandle(session_key.network_anonymization_key()),
      session_creation_initiator);
}

void QuicSessionPool::OnSessionGoingAway(QuicChromiumClientSession* session) {
  const AliasSet& aliases = session_aliases_[session];
  for (const auto& alias : aliases) {
    const QuicSessionKey& session_key = alias.session_key();
    DCHECK(active_sessions_.count(session_key));
    DCHECK_EQ(session, active_sessions_[session_key]);
    // Track sessions which have recently gone away so that we can disable
    // port suggestions.
    if (session->goaway_received()) {
      gone_away_aliases_.insert(alias);
    }

    active_sessions_.erase(session_key);
    ProcessGoingAwaySession(session, session_key.server_id(), true);
  }
  ProcessGoingAwaySession(session, session->session_alias_key().server_id(),
                          false);
  if (!aliases.empty()) {
    DCHECK(base::Contains(session_peer_ip_, session));
    const IPEndPoint peer_address = session_peer_ip_[session];
    ip_aliases_[peer_address].erase(session);
    if (ip_aliases_[peer_address].empty()) {
      ip_aliases_.erase(peer_address);
    }
    session_peer_ip_.erase(session);
  }
  UnmapSessionFromSessionAliases(session);
}

void QuicSessionPool::OnSessionClosed(QuicChromiumClientSession* session) {
  DCHECK_EQ(0u, session->GetNumActiveStreams());
  OnSessionGoingAway(session);
  auto it = all_sessions_.find(session);
  CHECK(it != all_sessions_.end());
  all_sessions_.erase(it);
}

void QuicSessionPool::OnBlackholeAfterHandshakeConfirmed(
    QuicChromiumClientSession* session) {
  // Reduce PING timeout when connection blackholes after the handshake.
  if (ping_timeout_ > reduced_ping_timeout_) {
    ping_timeout_ = reduced_ping_timeout_;
  }
}

void QuicSessionPool::CancelRequest(QuicSessionRequest* request) {
  auto job_iter = active_jobs_.find(request->session_key());
  // If an error (or network context shutdown) happens early in a
  // `QuicSessionRequest`, before it has been added to `active_jobs_`, then
  // this method may be called and should be resilient to the job not
  // being in the map.
  if (job_iter != active_jobs_.end()) {
    job_iter->second->RemoveRequest(request);
  }
}

void QuicSessionPool::SetRequestPriority(QuicSessionRequest* request,
                                         RequestPriority priority) {
  auto job_iter = active_jobs_.find(request->session_key());
  if (job_iter == active_jobs_.end()) {
    return;
  }
  job_iter->second->SetPriority(priority);
}

void QuicSessionPool::CloseAllSessions(int error,
                                       quic::QuicErrorCode quic_error) {
  base::UmaHistogramSparse("Net.QuicSession.CloseAllSessionsError", -error);
  size_t before_active_sessions_size = active_sessions_.size();
  size_t before_all_sessions_size = active_sessions_.size();
  while (!active_sessions_.empty()) {
    size_t initial_size = active_sessions_.size();
    active_sessions_.begin()->second->CloseSessionOnError(
        error, quic_error,
        quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    DCHECK_NE(initial_size, active_sessions_.size());
  }
  while (!all_sessions_.empty()) {
    size_t initial_size = all_sessions_.size();
    (*all_sessions_.begin())
        ->CloseSessionOnError(
            error, quic_error,
            quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    DCHECK_NE(initial_size, all_sessions_.size());
  }
  DCHECK(all_sessions_.empty());
  // TODO(crbug.com/347984574): Remove before/after counts once we identified
  // the cause.
  net_log_.AddEvent(NetLogEventType::QUIC_SESSION_POOL_CLOSE_ALL_SESSIONS, [&] {
    base::Value::Dict dict;
    dict.Set("net_error", error);
    dict.Set("quic_error", quic::QuicErrorCodeToString(quic_error));
    dict.Set("before_active_sessions_size",
             static_cast<int>(before_active_sessions_size));
    dict.Set("before_all_sessions_size",
             static_cast<int>(before_all_sessions_size));
    dict.Set("after_active_sessions_size",
             static_cast<int>(active_sessions_.size()));
    dict.Set("after_all_sessions_size", static_cast<int>(all_sessions_.size()));
    return dict;
  });
}

base::Value QuicSessionPool::QuicSessionPoolInfoToValue() const {
  base::Value::List list;

  for (const auto& active_session : active_sessions_) {
    const quic::QuicServerId& server_id = active_session.first.server_id();
    QuicChromiumClientSession* session = active_session.second;
    const AliasSet& aliases = session_aliases_.find(session)->second;
    // Only add a session to the list once.
    if (server_id == aliases.begin()->server_id()) {
      std::set<HostPortPair> hosts;
      for (const auto& alias : aliases) {
        hosts.insert(
            HostPortPair(alias.server_id().host(), alias.server_id().port()));
      }
      list.Append(session->GetInfoAsValue(hosts));
    }
  }
  return base::Value(std::move(list));
}

void QuicSessionPool::ClearCachedStatesInCryptoConfig(
    const base::RepeatingCallback<bool(const GURL&)>& origin_filter) {
  ServerIdOriginFilter filter(origin_filter);
  for (const auto& crypto_config : active_crypto_config_map_) {
    crypto_config.second->config()->ClearCachedStates(filter);
  }

  for (const auto& crypto_config : recent_crypto_config_map_) {
    crypto_config.second->config()->ClearCachedStates(filter);
  }
}

void QuicSessionPool::ConnectAndConfigureSocket(CompletionOnceCallback callback,
                                                DatagramClientSocket* socket,
```