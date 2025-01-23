Response:
My thinking process to analyze the provided C++ code goes through these stages:

1. **Understand the Goal:** The request asks for the functionality of `SpdySessionPool`, its relationship to JavaScript, logical inference with inputs/outputs, common user errors, debugging hints, and a summary of its function for this part of the file.

2. **Identify Core Data Structures and Classes:**  I scan the code for prominent data structures and classes. Key ones include:
    * `SpdySessionPool`: The central class.
    * `SpdySession`: Represents an active HTTP/2 or QUIC session.
    * `SpdySessionKey`: Identifies a session (host, port, proxy, etc.).
    * `SpdySessionRequest`: Represents a request for a session.
    * `available_sessions_`: A map of available, active sessions.
    * `sessions_`: A set of all active sessions (regardless of availability).
    * `spdy_session_request_map_`:  Tracks pending requests for sessions.
    * `aliases_`: Maps IP addresses to `SpdySessionKey`s for IP-based pooling.

3. **Trace Key Operations:** I look for methods that perform crucial actions related to session management:
    * **Session Creation:** `CreateAvailableSessionFromSocketHandle`, `CreateAvailableSessionFromSocket`, `CreateSession`.
    * **Session Retrieval:** `FindAvailableSession`, `RequestSession`.
    * **Session Availability:** `MakeSessionUnavailable`, `IsSessionAvailable`.
    * **Session Management:** `InsertSession`, `RemoveUnavailableSession`, `CloseAllSessions`, `MakeCurrentSessionsGoingAway`.
    * **IP-based Pooling:** `FindMatchingIpSessionForServiceEndpoint`, `OnHostResolutionComplete`.
    * **Request Handling:** `RequestSession`, `UpdatePendingRequests`, `RemoveRequestForSpdySession`.

4. **Analyze Functionality based on Operations:** Based on the traced operations, I infer the core responsibilities of `SpdySessionPool`:
    * **Managing a pool of active HTTP/2 and QUIC sessions.** This includes creating, storing, and retrieving sessions.
    * **Session Keying and Lookup:**  Efficiently finding existing sessions based on `SpdySessionKey`.
    * **Handling Concurrent Requests:** Managing multiple requests for the same session using `SpdySessionRequest`.
    * **IP-based Session Pooling:** Optimizing connections by reusing sessions with the same IP address, even for different hostnames. This involves the `aliases_` map and the logic in `OnHostResolutionComplete`.
    * **Session Availability Tracking:** Keeping track of which sessions are available for immediate use.
    * **Session Closure and Cleanup:**  Gracefully closing sessions when needed (network changes, errors, etc.).
    * **Integration with Network Stack:** Interacting with `HostResolver`, `SSLClientContext`, `HttpServerProperties`, etc.

5. **Consider JavaScript Relevance (and Lack Thereof):** I specifically look for interactions with JavaScript concepts. In this code snippet, there are *no direct interactions* with JavaScript. The network stack in Chromium is written in C++. While JavaScript in the browser *triggers* network requests, the underlying implementation (like this code) is in C++.

6. **Logical Inference (Hypothetical):** To demonstrate logical inference, I create a scenario:
    * **Input:** A request for a session for `https://example.com`. No existing session.
    * **Processing:** `RequestSession` is called. A `SpdySessionRequest` is created. A connection attempt begins (not shown in this snippet).
    * **Output (Hypothetical):**  Once a connection is established, `InsertSession` is called. The `SpdySessionRequest`'s delegate is notified via `OnSpdySessionAvailable`.

7. **Identify Potential User/Programming Errors:** I think about how developers or the system might misuse this component:
    * **Incorrect Key Usage:**  Providing an inconsistent `SpdySessionKey`.
    * **Resource Leaks:** Not properly managing or closing sessions (though the pool aims to handle this).
    * **Race Conditions (Internal):** While not strictly a *user* error, I consider potential internal race conditions, especially around session availability and request handling.

8. **Debugging Hints (User Journey):** I trace back how a user action might lead to this code:
    * User types `https://example.com` in the address bar.
    * The browser's networking code needs to establish a connection.
    * `HttpNetworkSession` (or similar) checks the `SpdySessionPool` for an existing session.
    * If no session exists, a request is made, potentially leading to the creation logic in this file.

9. **Summarize Functionality for Part 1:** Based on the analysis of the first part of the file, I synthesize a concise summary focusing on the core responsibilities covered in this segment. I look for the introduction of key concepts and methods.

10. **Review and Refine:** I reread my analysis and the code to ensure accuracy, clarity, and completeness. I check if I've addressed all aspects of the prompt. For instance, I made sure to explicitly state the lack of direct JavaScript interaction.

This systematic approach allows me to break down a complex piece of code, understand its purpose, and answer the specific questions in the prompt. It involves a combination of code reading, pattern recognition, logical deduction, and some domain knowledge about networking concepts.
好的，让我们一起来分析一下 `net/spdy/spdy_session_pool.cc` 文件的功能。

**文件功能归纳 (第 1 部分):**

这个文件的主要作用是实现了 `SpdySessionPool` 类，负责管理和维护 HTTP/2 (SPDY) 会话的连接池。  其核心功能可以归纳为以下几点：

1. **会话的创建和管理:**
   - 负责创建新的 `SpdySession` 对象，用于与服务器建立 HTTP/2 连接。
   - 维护一个活跃的 `SpdySession` 集合 (`sessions_`)。
   - 维护一个可用 `SpdySession` 的映射 (`available_sessions_`)，方便快速查找可重用的会话。
   - 提供了从已建立的套接字 (`StreamSocketHandle` 或 `StreamSocket`) 创建可用会话的机制。

2. **会话的查找和重用:**
   - 提供了根据 `SpdySessionKey` (包含主机、端口、代理等信息) 查找现有可用会话的功能 (`FindAvailableSession`)。
   - 支持基于 IP 地址的会话池化 (`enable_ip_based_pooling_`)，允许在某些情况下重用与相同 IP 地址服务器的会话，即使目标主机名不同。

3. **处理会话请求:**
   - 实现了 `SpdySessionRequest` 类，用于管理对 `SpdySession` 的请求。
   - 当没有可用的会话时，将请求放入队列 (`spdy_session_request_map_`)，并在有新的会话可用时通知请求者。
   - 支持阻塞请求的概念 (`is_blocking_request_for_session_`)，用于优化会话建立。

4. **会话的关闭和清理:**
   - 提供了关闭所有会话 (`CloseAllSessions`) 或当前会话 (`CloseCurrentSessions`) 的方法。
   - 提供了使会话进入 "going away" 状态的方法 (`MakeCurrentSessionsGoingAway`)，用于平滑地关闭会话。
   - 在网络状态变化 (例如 IP 地址改变) 或 SSL 配置改变时，能够清理或标记会话为不可用。

5. **IP 地址别名管理 (IP-based pooling 的一部分):**
   - 维护一个 IP 地址到 `SpdySessionKey` 的映射 (`aliases_`)，用于实现基于 IP 的会话重用。
   - `OnHostResolutionComplete` 方法负责在 DNS 解析完成后，查找是否有可以与新解析到的 IP 地址共享的现有会话。

6. **监控和日志:**
   - 使用 NetLog 记录会话池的状态和事件，方便调试和分析。
   - 使用 UMA (User Metrics Analysis) 记录会话获取的统计信息。

**与 JavaScript 的关系:**

这个 C++ 代码本身不直接与 JavaScript 交互。  JavaScript 代码在浏览器中发起网络请求时，会通过 Chromium 的网络栈最终到达这个 `SpdySessionPool`。

**举例说明:**

1. **JavaScript 发起 HTTPS 请求:** 当 JavaScript 代码使用 `fetch` API 或 `XMLHttpRequest` 向一个 HTTPS 网站 (例如 `https://example.com`) 发起请求时，Chromium 的网络栈会判断是否需要建立一个新的 HTTP/2 连接。`SpdySessionPool` 会被用来查找是否已经存在与 `example.com` 或其 IP 地址的可用会话。

2. **会话重用:**  如果 JavaScript 随后向另一个与 `example.com` 共享同一个 IP 地址的网站 (并且符合 IP-based pooling 的条件) 发起请求，`SpdySessionPool` 可能会找到之前为 `example.com` 创建的会话并重用它，而不需要建立新的 TCP 连接和 TLS 握手。这对性能有很大提升。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. `SpdySessionPool` 当前没有与 `https://www.example.com` 建立的可用会话。
2. JavaScript 代码发起一个对 `https://www.example.com/index.html` 的请求。
3. `RequestSession` 方法被调用，传入 `SpdySessionKey` 对应 `https://www.example.com` 的信息。

**逻辑推理:**

1. `FindAvailableSession` 会返回空，因为没有匹配的可用会话。
2. `RequestSession` 会创建一个新的 `SpdySessionRequest` 对象，并将请求添加到 `spdy_session_request_map_` 中。
3. 由于是第一个请求，`is_blocking_request_for_session` 会被设置为 `true`。
4. 网络栈会开始建立与 `www.example.com` 的 TCP 连接和 TLS 握手 (这部分代码不在当前文件中)。
5. 一旦连接建立成功，`CreateAvailableSessionFromSocket` 或类似方法会被调用，创建一个新的 `SpdySession` 对象。
6. `InsertSession` 会将新的 `SpdySession` 添加到 `available_sessions_` 和 `sessions_` 中。
7. `UpdatePendingRequests` 会被调用，找到之前添加到 `spdy_session_request_map_` 中的请求。
8. `SpdySessionRequest` 的 `Delegate` 的 `OnSpdySessionAvailable` 方法会被调用，将新创建的 `SpdySession` 返回给请求者。

**输出:**

*   一个新的 `SpdySession` 对象被创建并添加到会话池中。
*   与该请求关联的回调函数被触发，请求可以开始通过新建立的会话发送 HTTP/2 数据。

**用户或编程常见的使用错误:**

1. **不正确的 `SpdySessionKey`:**  在需要重用会话时，如果传入的 `SpdySessionKey` 与现有会话不匹配 (例如，主机名、端口或代理设置不同)，则无法重用会话，可能导致建立不必要的连接。

2. **过早地关闭会话:**  手动调用会话的关闭方法，而其他部分的代码可能仍然需要使用该会话。`SpdySessionPool` 内部有自己的会话生命周期管理机制，通常不需要外部代码显式关闭。

3. **假设会话总是可用:**  在发起请求前，没有正确处理 `SpdySession` 可能不可用的情况 (例如，连接错误、服务器主动关闭等)。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 并访问一个 HTTPS 网站 (例如 `https://mail.google.com`).**
2. **浏览器开始解析域名 `mail.google.com` 的 IP 地址 (DNS Lookup).**
3. **浏览器检查 `SpdySessionPool` 中是否已经存在与 `mail.google.com` 建立的可用 HTTP/2 会话。**
    -  如果存在，则直接重用该会话。
    -  如果不存在，则会触发创建新会话的流程。
4. **如果需要创建新会话，网络栈会尝试建立 TCP 连接并进行 TLS 握手。**
5. **在 TLS 握手完成后，如果协商的协议是 HTTP/2，则会调用 `SpdySessionPool::CreateAvailableSessionFromSocket` 或类似方法，将底层的套接字与一个新的 `SpdySession` 对象关联。**
6. **新创建的 `SpdySession` 对象会被添加到 `SpdySessionPool` 的管理中，使其可以被后续的请求重用。**

在调试网络问题时，查看 NetLog 可以追踪到 `SpdySessionPool` 中会话的创建、查找和关闭等事件，帮助理解连接是如何被管理和重用的。

希望以上分析对您有所帮助！如果还有其他问题，请随时提出。

### 提示词
```
这是目录为net/spdy/spdy_session_pool.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_session_pool.h"

#include <set>
#include <utility>

#include "base/check_op.h"
#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/ranges/algorithm.h"
#include "base/task/single_thread_task_runner.h"
#include "base/types/expected.h"
#include "base/values.h"
#include "build/build_config.h"
#include "net/base/features.h"
#include "net/base/ip_endpoint.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "net/dns/host_resolver.h"
#include "net/dns/public/host_resolver_source.h"
#include "net/http/http_network_session.h"
#include "net/http/http_server_properties.h"
#include "net/http/http_stream_request.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/stream_socket_handle.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/spdy/spdy_session.h"
#include "net/third_party/quiche/src/quiche/http2/hpack/hpack_constants.h"
#include "net/third_party/quiche/src/quiche/http2/hpack/hpack_static_table.h"

namespace net {

namespace {

enum SpdySessionGetTypes {
  CREATED_NEW                 = 0,
  FOUND_EXISTING              = 1,
  FOUND_EXISTING_FROM_IP_POOL = 2,
  IMPORTED_FROM_SOCKET        = 3,
  SPDY_SESSION_GET_MAX        = 4
};

}  // namespace

SpdySessionPool::SpdySessionRequest::Delegate::Delegate() = default;
SpdySessionPool::SpdySessionRequest::Delegate::~Delegate() = default;

SpdySessionPool::SpdySessionRequest::SpdySessionRequest(
    const SpdySessionKey& key,
    bool enable_ip_based_pooling,
    bool is_websocket,
    bool is_blocking_request_for_session,
    Delegate* delegate,
    SpdySessionPool* spdy_session_pool)
    : key_(key),
      enable_ip_based_pooling_(enable_ip_based_pooling),
      is_websocket_(is_websocket),
      is_blocking_request_for_session_(is_blocking_request_for_session),
      delegate_(delegate),
      spdy_session_pool_(spdy_session_pool) {}

SpdySessionPool::SpdySessionRequest::~SpdySessionRequest() {
  if (spdy_session_pool_)
    spdy_session_pool_->RemoveRequestForSpdySession(this);
}

void SpdySessionPool::SpdySessionRequest::OnRemovedFromPool() {
  DCHECK(spdy_session_pool_);
  spdy_session_pool_ = nullptr;
}

SpdySessionPool::SpdySessionPool(
    HostResolver* resolver,
    SSLClientContext* ssl_client_context,
    HttpServerProperties* http_server_properties,
    TransportSecurityState* transport_security_state,
    const quic::ParsedQuicVersionVector& quic_supported_versions,
    bool enable_ping_based_connection_checking,
    bool is_http2_enabled,
    bool is_quic_enabled,
    size_t session_max_recv_window_size,
    int session_max_queued_capped_frames,
    const spdy::SettingsMap& initial_settings,
    bool enable_http2_settings_grease,
    const std::optional<GreasedHttp2Frame>& greased_http2_frame,
    bool http2_end_stream_with_data_frame,
    bool enable_priority_update,
    bool go_away_on_ip_change,
    SpdySessionPool::TimeFunc time_func,
    NetworkQualityEstimator* network_quality_estimator,
    bool cleanup_sessions_on_ip_address_changed)
    : http_server_properties_(http_server_properties),
      transport_security_state_(transport_security_state),
      ssl_client_context_(ssl_client_context),
      resolver_(resolver),
      quic_supported_versions_(quic_supported_versions),
      enable_ping_based_connection_checking_(
          enable_ping_based_connection_checking),
      is_http2_enabled_(is_http2_enabled),
      is_quic_enabled_(is_quic_enabled),
      session_max_recv_window_size_(session_max_recv_window_size),
      session_max_queued_capped_frames_(session_max_queued_capped_frames),
      initial_settings_(initial_settings),
      enable_http2_settings_grease_(enable_http2_settings_grease),
      greased_http2_frame_(greased_http2_frame),
      http2_end_stream_with_data_frame_(http2_end_stream_with_data_frame),
      enable_priority_update_(enable_priority_update),
      go_away_on_ip_change_(go_away_on_ip_change),
      time_func_(time_func),
      network_quality_estimator_(network_quality_estimator),
      cleanup_sessions_on_ip_address_changed_(
          cleanup_sessions_on_ip_address_changed) {
  if (cleanup_sessions_on_ip_address_changed_)
    NetworkChangeNotifier::AddIPAddressObserver(this);
  if (ssl_client_context_)
    ssl_client_context_->AddObserver(this);
}

SpdySessionPool::~SpdySessionPool() {
#if DCHECK_IS_ON()
  for (const auto& request_info : spdy_session_request_map_) {
    // The should be no pending SpdySessionRequests on destruction, though there
    // may be callbacks waiting to be invoked, since they use weak pointers and
    // there's no API to unregister them.
    DCHECK(request_info.second.request_set.empty());
  }
#endif  // DCHECK_IS_ON()

  // TODO(bnc): CloseAllSessions() is also called in HttpNetworkSession
  // destructor, one of the two calls should be removed.
  CloseAllSessions();

  while (!sessions_.empty()) {
    // Destroy sessions to enforce that lifetime is scoped to SpdySessionPool.
    // Write callbacks queued upon session drain are not invoked.
    RemoveUnavailableSession((*sessions_.begin())->GetWeakPtr());
  }

  if (ssl_client_context_)
    ssl_client_context_->RemoveObserver(this);
  if (cleanup_sessions_on_ip_address_changed_)
    NetworkChangeNotifier::RemoveIPAddressObserver(this);
}

int SpdySessionPool::CreateAvailableSessionFromSocketHandle(
    const SpdySessionKey& key,
    std::unique_ptr<StreamSocketHandle> stream_socket_handle,
    const NetLogWithSource& net_log,
    const MultiplexedSessionCreationInitiator session_creation_initiator,
    base::WeakPtr<SpdySession>* session) {
  TRACE_EVENT0(NetTracingCategory(),
               "SpdySessionPool::CreateAvailableSessionFromSocketHandle");

  std::unique_ptr<SpdySession> new_session =
      CreateSession(key, net_log.net_log(), session_creation_initiator);
  std::set<std::string> dns_aliases =
      stream_socket_handle->socket()->GetDnsAliases();

  new_session->InitializeWithSocketHandle(std::move(stream_socket_handle),
                                          this);

  base::expected<base::WeakPtr<SpdySession>, int> insert_result = InsertSession(
      key, std::move(new_session), net_log, std::move(dns_aliases),
      /*perform_post_insertion_checks=*/true);
  if (insert_result.has_value()) {
    *session = std::move(insert_result.value());
    return OK;
  }
  return insert_result.error();
}

base::expected<base::WeakPtr<SpdySession>, int>
SpdySessionPool::CreateAvailableSessionFromSocket(
    const SpdySessionKey& key,
    std::unique_ptr<StreamSocket> socket_stream,
    const LoadTimingInfo::ConnectTiming& connect_timing,
    const NetLogWithSource& net_log) {
  TRACE_EVENT0(NetTracingCategory(),
               "SpdySessionPool::CreateAvailableSessionFromSocket");

  std::unique_ptr<SpdySession> new_session = CreateSession(
      key, net_log.net_log(), MultiplexedSessionCreationInitiator::kUnknown);
  std::set<std::string> dns_aliases = socket_stream->GetDnsAliases();

  new_session->InitializeWithSocket(std::move(socket_stream), connect_timing,
                                    this);

  const bool perform_post_insertion_checks = base::FeatureList::IsEnabled(
      features::kSpdySessionForProxyAdditionalChecks);
  return InsertSession(key, std::move(new_session), net_log,
                       std::move(dns_aliases), perform_post_insertion_checks);
}

base::WeakPtr<SpdySession> SpdySessionPool::FindAvailableSession(
    const SpdySessionKey& key,
    bool enable_ip_based_pooling,
    bool is_websocket,
    const NetLogWithSource& net_log) {
  auto it = LookupAvailableSessionByKey(key);
  if (it == available_sessions_.end() ||
      (is_websocket && !it->second->support_websocket())) {
    return base::WeakPtr<SpdySession>();
  }

  if (key == it->second->spdy_session_key()) {
    UMA_HISTOGRAM_ENUMERATION("Net.SpdySessionGet", FOUND_EXISTING,
                              SPDY_SESSION_GET_MAX);
    net_log.AddEventReferencingSource(
        NetLogEventType::HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION,
        it->second->net_log().source());
    return it->second;
  }

  if (enable_ip_based_pooling) {
    UMA_HISTOGRAM_ENUMERATION("Net.SpdySessionGet", FOUND_EXISTING_FROM_IP_POOL,
                              SPDY_SESSION_GET_MAX);
    net_log.AddEventReferencingSource(
        NetLogEventType::HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION_FROM_IP_POOL,
        it->second->net_log().source());
    return it->second;
  }

  return base::WeakPtr<SpdySession>();
}

base::WeakPtr<SpdySession>
SpdySessionPool::FindMatchingIpSessionForServiceEndpoint(
    const SpdySessionKey& key,
    const ServiceEndpoint& service_endpoint,
    const std::set<std::string>& dns_aliases) {
  CHECK(!HasAvailableSession(key, /*is_websocket=*/false));
  CHECK(key.socket_tag() == SocketTag());

  base::WeakPtr<SpdySession> session =
      FindMatchingIpSession(key, service_endpoint.ipv6_endpoints, dns_aliases);
  if (session) {
    return session;
  }
  return FindMatchingIpSession(key, service_endpoint.ipv4_endpoints,
                               dns_aliases);
}

bool SpdySessionPool::HasAvailableSession(const SpdySessionKey& key,
                                          bool is_websocket) const {
  const auto it = available_sessions_.find(key);
  return it != available_sessions_.end() &&
         (!is_websocket || it->second->support_websocket());
}

base::WeakPtr<SpdySession> SpdySessionPool::RequestSession(
    const SpdySessionKey& key,
    bool enable_ip_based_pooling,
    bool is_websocket,
    const NetLogWithSource& net_log,
    base::RepeatingClosure on_blocking_request_destroyed_callback,
    SpdySessionRequest::Delegate* delegate,
    std::unique_ptr<SpdySessionRequest>* spdy_session_request,
    bool* is_blocking_request_for_session) {
  DCHECK(delegate);

  base::WeakPtr<SpdySession> spdy_session =
      FindAvailableSession(key, enable_ip_based_pooling, is_websocket, net_log);
  if (spdy_session) {
    // This value doesn't really matter, but best to always populate it, for
    // consistency.
    *is_blocking_request_for_session = true;
    return spdy_session;
  }

  RequestInfoForKey* request_info = &spdy_session_request_map_[key];
  *is_blocking_request_for_session = !request_info->has_blocking_request;
  *spdy_session_request = std::make_unique<SpdySessionRequest>(
      key, enable_ip_based_pooling, is_websocket,
      *is_blocking_request_for_session, delegate, this);
  request_info->request_set.insert(spdy_session_request->get());

  if (*is_blocking_request_for_session) {
    request_info->has_blocking_request = true;
  } else if (on_blocking_request_destroyed_callback) {
    request_info->deferred_callbacks.push_back(
        on_blocking_request_destroyed_callback);
  }
  return nullptr;
}

OnHostResolutionCallbackResult SpdySessionPool::OnHostResolutionComplete(
    const SpdySessionKey& key,
    bool is_websocket,
    const std::vector<HostResolverEndpointResult>& endpoint_results,
    const std::set<std::string>& aliases) {
  // If there are no pending requests for that alias, nothing to do.
  if (spdy_session_request_map_.find(key) == spdy_session_request_map_.end())
    return OnHostResolutionCallbackResult::kContinue;

  // Check if there's already a matching session. If so, there may already
  // be a pending task to inform consumers of the alias. In this case, do
  // nothing, but inform the caller to wait for such a task to run.
  auto existing_session_it = LookupAvailableSessionByKey(key);
  if (existing_session_it != available_sessions_.end()) {
    if (is_websocket && !existing_session_it->second->support_websocket()) {
      // We don't look for aliased sessions because it would not be possible to
      // add them to the available_sessions_ map. See https://crbug.com/1220771.
      return OnHostResolutionCallbackResult::kContinue;
    }

    return OnHostResolutionCallbackResult::kMayBeDeletedAsync;
  }

  for (const auto& endpoint : endpoint_results) {
    // If `endpoint` has no associated ALPN protocols, it is TCP-based and thus
    // would have been eligible for connecting with HTTP/2.
    if (!endpoint.metadata.supported_protocol_alpns.empty() &&
        !base::Contains(endpoint.metadata.supported_protocol_alpns, "h2")) {
      continue;
    }
    for (const auto& address : endpoint.ip_endpoints) {
      auto range = aliases_.equal_range(address);
      for (auto alias_it = range.first; alias_it != range.second; ++alias_it) {
        // We found a potential alias.
        const SpdySessionKey& alias_key = alias_it->second;

        auto available_session_it = LookupAvailableSessionByKey(alias_key);
        // It shouldn't be in the aliases table if it doesn't exist!
        CHECK(available_session_it != available_sessions_.end(),
              base::NotFatalUntil::M130);

        SpdySessionKey::CompareForAliasingResult compare_result =
            alias_key.CompareForAliasing(key);
        // Keys must be aliasable.
        if (!compare_result.is_potentially_aliasable) {
          continue;
        }

        if (is_websocket &&
            !available_session_it->second->support_websocket()) {
          continue;
        }

        // Make copy of WeakPtr as call to UnmapKey() will delete original.
        const base::WeakPtr<SpdySession> available_session =
            available_session_it->second;

        // Need to verify that the server is authenticated to serve traffic for
        // |host_port_proxy_pair| too.
        if (!available_session->VerifyDomainAuthentication(
                key.host_port_pair().host())) {
          UMA_HISTOGRAM_ENUMERATION("Net.SpdyIPPoolDomainMatch", 0, 2);
          continue;
        }

        UMA_HISTOGRAM_ENUMERATION("Net.SpdyIPPoolDomainMatch", 1, 2);

        bool adding_pooled_alias = true;

        // If socket tags differ, see if session's socket tag can be changed.
        if (!compare_result.is_socket_tag_match) {
          SpdySessionKey old_key = available_session->spdy_session_key();
          SpdySessionKey new_key(
              old_key.host_port_pair(), old_key.privacy_mode(),
              old_key.proxy_chain(), old_key.session_usage(), key.socket_tag(),
              old_key.network_anonymization_key(), old_key.secure_dns_policy(),
              old_key.disable_cert_verification_network_fetches());

          // If there is already a session with |new_key|, skip this one.
          // It will be found in |aliases_| in a future iteration.
          if (available_sessions_.find(new_key) != available_sessions_.end()) {
            continue;
          }

          if (!available_session->ChangeSocketTag(key.socket_tag())) {
            continue;
          }

          DCHECK(available_session->spdy_session_key() == new_key);

          // If this isn't a pooled alias, but the actual session that needs to
          // have its socket tag change, there's no need to add an alias.
          if (new_key == key) {
            adding_pooled_alias = false;
          }

          // Remap main session key.
          std::set<std::string> main_session_old_dns_aliases =
              GetDnsAliasesForSessionKey(old_key);
          UnmapKey(old_key);
          MapKeyToAvailableSession(new_key, available_session,
                                   std::move(main_session_old_dns_aliases));

          // Remap alias. From this point on |alias_it| is invalid, so no more
          // iterations of the loop should be allowed.
          aliases_.insert(AliasMap::value_type(alias_it->first, new_key));
          aliases_.erase(alias_it);

          // Remap pooled session keys.
          const auto& pooled_aliases = available_session->pooled_aliases();
          for (auto it = pooled_aliases.begin(); it != pooled_aliases.end();) {
            // Ignore aliases this loop is inserting.
            if (it->socket_tag() == key.socket_tag()) {
              ++it;
              continue;
            }

            std::set<std::string> pooled_alias_old_dns_aliases =
                GetDnsAliasesForSessionKey(*it);
            UnmapKey(*it);
            SpdySessionKey new_pool_alias_key = SpdySessionKey(
                it->host_port_pair(), it->privacy_mode(), it->proxy_chain(),
                it->session_usage(), key.socket_tag(),
                it->network_anonymization_key(), it->secure_dns_policy(),
                it->disable_cert_verification_network_fetches());
            MapKeyToAvailableSession(new_pool_alias_key, available_session,
                                     std::move(pooled_alias_old_dns_aliases));
            auto old_it = it;
            ++it;
            available_session->RemovePooledAlias(*old_it);
            available_session->AddPooledAlias(new_pool_alias_key);

            // If this is desired key, no need to add an alias for the desired
            // key at the end of this method.
            if (new_pool_alias_key == key) {
              adding_pooled_alias = false;
            }
          }
        }

        if (adding_pooled_alias) {
          // Add this session to the map so that we can find it next time.
          MapKeyToAvailableSession(key, available_session, aliases);
          available_session->AddPooledAlias(key);
        }

        // Post task to inform pending requests for session for |key| that a
        // matching session is now available.
        base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
            FROM_HERE, base::BindOnce(&SpdySessionPool::UpdatePendingRequests,
                                      weak_ptr_factory_.GetWeakPtr(), key));

        // Inform the caller that the Callback may be deleted if the consumer is
        // switched over to the newly aliased session. It's not guaranteed to be
        // deleted, as the session may be closed, or taken by yet another
        // pending request with a different SocketTag before the the request can
        // try and use the session.
        return OnHostResolutionCallbackResult::kMayBeDeletedAsync;
      }
    }
  }
  return OnHostResolutionCallbackResult::kContinue;
}

void SpdySessionPool::MakeSessionUnavailable(
    const base::WeakPtr<SpdySession>& available_session) {
  UnmapKey(available_session->spdy_session_key());
  RemoveAliases(available_session->spdy_session_key());
  const std::set<SpdySessionKey>& aliases = available_session->pooled_aliases();
  for (const auto& alias : aliases) {
    UnmapKey(alias);
    RemoveAliases(alias);
  }
  DCHECK(!IsSessionAvailable(available_session));
}

void SpdySessionPool::RemoveUnavailableSession(
    const base::WeakPtr<SpdySession>& unavailable_session) {
  DCHECK(!IsSessionAvailable(unavailable_session));

  unavailable_session->net_log().AddEvent(
      NetLogEventType::HTTP2_SESSION_POOL_REMOVE_SESSION);

  auto it = sessions_.find(unavailable_session.get());
  CHECK(it != sessions_.end());
  std::unique_ptr<SpdySession> owned_session(*it);
  sessions_.erase(it);
}

// Make a copy of |sessions_| in the Close* functions below to avoid
// reentrancy problems. Since arbitrary functions get called by close
// handlers, it doesn't suffice to simply increment the iterator
// before closing.

void SpdySessionPool::CloseCurrentSessions(Error error) {
  CloseCurrentSessionsHelper(error, "Closing current sessions.",
                             false /* idle_only */);
}

void SpdySessionPool::CloseCurrentIdleSessions(const std::string& description) {
  CloseCurrentSessionsHelper(ERR_ABORTED, description, true /* idle_only */);
}

void SpdySessionPool::CloseAllSessions() {
  auto is_draining = [](const SpdySession* s) { return s->IsDraining(); };
  // Repeat until every SpdySession owned by |this| is draining.
  while (!base::ranges::all_of(sessions_, is_draining)) {
    CloseCurrentSessionsHelper(ERR_ABORTED, "Closing all sessions.",
                               false /* idle_only */);
  }
}

void SpdySessionPool::MakeCurrentSessionsGoingAway(Error error) {
  WeakSessionList current_sessions = GetCurrentSessions();
  for (base::WeakPtr<SpdySession>& session : current_sessions) {
    if (!session) {
      continue;
    }

    session->MakeUnavailable();
    session->StartGoingAway(kLastStreamId, error);
    session->MaybeFinishGoingAway();
    DCHECK(!IsSessionAvailable(session));
  }
}

std::unique_ptr<base::Value> SpdySessionPool::SpdySessionPoolInfoToValue()
    const {
  base::Value::List list;

  for (const auto& available_session : available_sessions_) {
    // Only add the session if the key in the map matches the main
    // host_port_proxy_pair (not an alias).
    const SpdySessionKey& key = available_session.first;
    const SpdySessionKey& session_key =
        available_session.second->spdy_session_key();
    if (key == session_key)
      list.Append(available_session.second->GetInfoAsValue());
  }
  return std::make_unique<base::Value>(std::move(list));
}

void SpdySessionPool::OnIPAddressChanged() {
  DCHECK(cleanup_sessions_on_ip_address_changed_);
  if (go_away_on_ip_change_) {
    MakeCurrentSessionsGoingAway(ERR_NETWORK_CHANGED);
  } else {
    CloseCurrentSessions(ERR_NETWORK_CHANGED);
  }
}

void SpdySessionPool::OnSSLConfigChanged(
    SSLClientContext::SSLConfigChangeType change_type) {
  switch (change_type) {
    case SSLClientContext::SSLConfigChangeType::kSSLConfigChanged:
      MakeCurrentSessionsGoingAway(ERR_NETWORK_CHANGED);
      break;
    case SSLClientContext::SSLConfigChangeType::kCertDatabaseChanged:
      MakeCurrentSessionsGoingAway(ERR_CERT_DATABASE_CHANGED);
      break;
    case SSLClientContext::SSLConfigChangeType::kCertVerifierChanged:
      MakeCurrentSessionsGoingAway(ERR_CERT_VERIFIER_CHANGED);
      break;
  };
}

void SpdySessionPool::OnSSLConfigForServersChanged(
    const base::flat_set<HostPortPair>& servers) {
  WeakSessionList current_sessions = GetCurrentSessions();
  for (base::WeakPtr<SpdySession>& session : current_sessions) {
    bool session_matches = false;
    if (!session)
      continue;

    // If the destination for this session is invalidated, or any of the proxy
    // hops along the way, make the session go away.
    if (servers.contains(session->host_port_pair())) {
      session_matches = true;
    } else {
      const ProxyChain& proxy_chain = session->spdy_session_key().proxy_chain();

      for (const ProxyServer& proxy_server : proxy_chain.proxy_servers()) {
        if (proxy_server.is_http_like() && !proxy_server.is_http() &&
            servers.contains(proxy_server.host_port_pair())) {
          session_matches = true;
          break;
        }
      }
    }

    if (session_matches) {
      session->MakeUnavailable();
      // Note this call preserves active streams but fails any streams that are
      // waiting on a stream ID.
      // TODO(crbug.com/40768859): This is not ideal, but SpdySession
      // does not have a state that supports this.
      session->StartGoingAway(kLastStreamId, ERR_NETWORK_CHANGED);
      session->MaybeFinishGoingAway();
      DCHECK(!IsSessionAvailable(session));
    }
  }
}

std::set<std::string> SpdySessionPool::GetDnsAliasesForSessionKey(
    const SpdySessionKey& key) const {
  auto it = dns_aliases_by_session_key_.find(key);
  if (it == dns_aliases_by_session_key_.end())
    return {};

  return it->second;
}

void SpdySessionPool::RemoveRequestForSpdySession(SpdySessionRequest* request) {
  DCHECK_EQ(this, request->spdy_session_pool());

  auto iter = spdy_session_request_map_.find(request->key());
  CHECK(iter != spdy_session_request_map_.end(), base::NotFatalUntil::M130);

  // Resume all pending requests if it is the blocking request, which is either
  // being canceled, or has completed.
  if (request->is_blocking_request_for_session() &&
      !iter->second.deferred_callbacks.empty()) {
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE,
        base::BindOnce(&SpdySessionPool::UpdatePendingRequests,
                       weak_ptr_factory_.GetWeakPtr(), request->key()));
  }

  DCHECK(base::Contains(iter->second.request_set, request));
  RemoveRequestInternal(iter, iter->second.request_set.find(request));
}

SpdySessionPool::RequestInfoForKey::RequestInfoForKey() = default;
SpdySessionPool::RequestInfoForKey::~RequestInfoForKey() = default;

bool SpdySessionPool::IsSessionAvailable(
    const base::WeakPtr<SpdySession>& session) const {
  for (const auto& available_session : available_sessions_) {
    if (available_session.second.get() == session.get())
      return true;
  }
  return false;
}

void SpdySessionPool::MapKeyToAvailableSession(
    const SpdySessionKey& key,
    const base::WeakPtr<SpdySession>& session,
    std::set<std::string> dns_aliases) {
  DCHECK(base::Contains(sessions_, session.get()));
  std::pair<AvailableSessionMap::iterator, bool> result =
      available_sessions_.emplace(key, session);
  CHECK(result.second);

  dns_aliases_by_session_key_[key] = std::move(dns_aliases);
}

SpdySessionPool::AvailableSessionMap::iterator
SpdySessionPool::LookupAvailableSessionByKey(
    const SpdySessionKey& key) {
  return available_sessions_.find(key);
}

void SpdySessionPool::UnmapKey(const SpdySessionKey& key) {
  auto it = LookupAvailableSessionByKey(key);
  CHECK(it != available_sessions_.end());
  available_sessions_.erase(it);
  dns_aliases_by_session_key_.erase(key);
}

void SpdySessionPool::RemoveAliases(const SpdySessionKey& key) {
  // Walk the aliases map, find references to this pair.
  // TODO(mbelshe):  Figure out if this is too expensive.
  for (auto it = aliases_.begin(); it != aliases_.end();) {
    if (it->second == key) {
      auto old_it = it;
      ++it;
      aliases_.erase(old_it);
    } else {
      ++it;
    }
  }
}

SpdySessionPool::WeakSessionList SpdySessionPool::GetCurrentSessions() const {
  WeakSessionList current_sessions;
  for (SpdySession* session : sessions_) {
    current_sessions.push_back(session->GetWeakPtr());
  }
  return current_sessions;
}

void SpdySessionPool::CloseCurrentSessionsHelper(Error error,
                                                 const std::string& description,
                                                 bool idle_only) {
  WeakSessionList current_sessions = GetCurrentSessions();
  for (base::WeakPtr<SpdySession>& session : current_sessions) {
    if (!session)
      continue;

    if (idle_only && session->is_active())
      continue;

    if (session->IsDraining())
      continue;

    session->CloseSessionOnError(error, description);

    DCHECK(!IsSessionAvailable(session));
    DCHECK(!session || session->IsDraining());
  }
}

std::unique_ptr<SpdySession> SpdySessionPool::CreateSession(
    const SpdySessionKey& key,
    NetLog* net_log,
    const MultiplexedSessionCreationInitiator session_creation_initiator) {
  UMA_HISTOGRAM_ENUMERATION("Net.SpdySessionGet", IMPORTED_FROM_SOCKET,
                            SPDY_SESSION_GET_MAX);

  // If there's a pre-existing matching session, it has to be an alias. Remove
  // the alias.
  auto it = LookupAvailableSessionByKey(key);
  if (it != available_sessions_.end()) {
    DCHECK(key != it->second->spdy_session_key());

    // Remove session from available sessions and from aliases, and remove
    // key from the session's pooled alias set, so that a new session can be
    // created with this |key|.
    it->second->RemovePooledAlias(key);
    UnmapKey(key);
    RemoveAliases(key);
  }

  return std::make_unique<SpdySession>(
      key, http_server_properties_, transport_security_state_,
      ssl_client_context_ ? ssl_client_context_->ssl_config_service() : nullptr,
      quic_supported_versions_, enable_sending_initial_data_,
      enable_ping_based_connection_checking_, is_http2_enabled_,
      is_quic_enabled_, session_max_recv_window_size_,
      session_max_queued_capped_frames_, initial_settings_,
      enable_http2_settings_grease_, greased_http2_frame_,
      http2_end_stream_with_data_frame_, enable_priority_update_, time_func_,
      network_quality_estimator_, net_log, session_creation_initiator);
}

base::expected<base::WeakPtr<SpdySession>, int> SpdySessionPool::InsertSession(
    const SpdySessionKey& key,
    std::unique_ptr<SpdySession> new_session,
    const NetLogWithSource& source_net_log,
    std::set<std::string> dns_aliases,
    bool perform_post_insertion_checks) {
  base::WeakPtr<SpdySession> available_session = new_session->GetWeakPtr();
  sessions_.insert(new_session.release());
  MapKeyToAvailableSession(key, available_session, std::move(dns_aliases));

  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&SpdySessionPool::UpdatePendingRequests,
                                weak_ptr_factory_.GetWeakPtr(), key));

  source_net_log.AddEventReferencingSource(
      NetLogEventType::HTTP2_SESSION_POOL_IMPORTED_SESSION_FROM_SOCKET,
      available_session->net_log().source());

  // Look up the IP address for this session so that we can match
  // future sessions (potentially to different domains) which can
  // potentially be pooled with this one. Because GetPeerAddress()
  // reports the proxy's address instead of the origin server, check
  // to see if this is a direct connection.
  if (key.proxy_chain().is_direct()) {
    IPEndPoint address;
    if (available_session->GetPeerAddress(&address) == OK)
      aliases_.insert(AliasMap::value_type(address, key));
  }

  if (!perform_post_insertion_checks) {
    return available_session;
  }

  if (!available_session->HasAcceptableTransportSecurity()) {
    available_session->CloseSessionOnError(
        ERR_HTTP2_INADEQUATE_TRANSPORT_SECURITY, "");
    return base::unexpected(ERR_HTTP2_INADEQUATE_TRANSPORT_SECURITY);
  }

  int rv = available_session->ParseAlps();
  if (rv != OK) {
    DCHECK_NE(ERR_IO_PENDING, rv);
    // ParseAlps() already closed the connection on error.
    return base::unexpected(rv);
  }

  return available_session;
}

void SpdySessionPool::UpdatePendingRequests(const SpdySessionKey& key) {
  auto it = LookupAvailableSessionByKey(key);
  if (it != available_sessions_.end()) {
    base::WeakPtr<SpdySession> new_session = it->second->GetWeakPtr();
    bool is_pooled = (key != new_session->spdy_session_key());
    while (new_session && new_session->IsAvailable()) {
      // Each iteration may empty out the RequestSet for |spdy_session_key| in
      // |spdy_session_request_map_|. So each time, check for RequestSet and use
      // the first one. Could just keep track if the last iteration removed the
      // final request, but it's possible that responding to one request will
      // result in cancelling another one.
      //
      // TODO(willchan): If it's important, switch RequestSet out for a FIFO
      // queue (Order by priority first, then FIFO within same priority).
      // Unclear that it matters here.
      auto iter = spdy_session_request_map_.find(key);
      if (iter == spdy_session_request_map_.end())
        break;
      RequestSet* request_set = &iter->second.request_set;
      // Find a request that can use the socket, if any.
      RequestSet::iterator request;
      for (request = request_set->begin(); request != request_set->end();
           ++request) {
        // If the request is for use with websockets, and the session doesn't
        // support websockets, skip over the request.
        if ((*request)->is_websocket() && !new_session->support_websocket())
          continue;
        // Don't use IP pooled session if not allowed.
        if (!(*request)->enable_ip_based_pooling() && is_pooled)
          continue;
        break;
      }
      if (request == request_set->end())
        break;

      SpdySessionRequest::Delegate* delegate = (*request)->delegate();
      RemoveRequestInternal(iter, request);
      delegate->OnSpdySessionAvailable(new_session);
    }
  }

  auto iter = spdy_session_request_map_.find(key);
  if (iter == spdy_session_request_map_.end())
    return;
  // Remove all pending requests, if there are any. As a result, if one of these
  // callbacks triggers a new RequestSession() call,
  // |is_blocking_request_for_session| will be true.
  std::list<base::RepeatingClosure> deferred_requests =
      std::move(iter->second.deferred_callbacks);

  // Delete the RequestMap if there are no SpdySessionRequests, and no deferred
  // requests.
  if (iter->second.request_set.empty())
    spdy_session_request_map_.erase(iter);

  // Resume any deferred requ
```