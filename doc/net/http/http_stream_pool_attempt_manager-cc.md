Response:
My thinking process to analyze the provided C++ code snippet and answer the user's request goes through these stages:

1. **Identify the Core Purpose:** The filename `http_stream_pool_attempt_manager.cc` and the surrounding context (Chromium network stack, `#include "net/http/..."`) immediately suggest this code manages attempts to establish HTTP connections. The word "attempt" is key.

2. **Break Down Functionality by Class/Method:** I'll go through the main class (`HttpStreamPool::AttemptManager`) and its key member classes/structs (`InFlightAttempt`, `PreconnectEntry`) and methods, noting their purpose. I'll focus on the public interface and important private methods.

    * **`AttemptManager` (Constructor/Destructor):** Initializes and cleans up resources, logs events. The logging reveals key configuration parameters like `stream_attempt_delay`.
    * **`StartJob`:**  Initiates a connection attempt for a specific request (`Job`). Handles priorities, allowed certificates, and protocol preferences (QUIC). Crucially, it checks for existing idle connections.
    * **`Preconnect`:** Initiates pre-emptive connection attempts to reduce latency.
    * **`OnServiceEndpointsUpdated/Finished`:**  Handles the asynchronous DNS resolution of service endpoints (SVCB/HTTPS records).
    * **`WaitForSSLConfigReady/GetSSLConfig`:** Manages the retrieval and provision of SSL configuration for TLS connections, including handling ECH.
    * **`ProcessPendingJob`:**  Checks for pending requests and attempts new connections if resources are available.
    * **`CancelInFlightAttempts/CancelJobs`:**  Aborts ongoing connection attempts and cancels pending requests.
    * **`PendingJobCount/PendingPreconnectCount`:**  Returns the number of pending connection requests.
    * **`GetLoadState/GetPriority`:** Provides information about the current state and priority of connection attempts.
    * **`IsStalledByPoolLimit`:**  Determines if connection attempts are blocked due to resource limits.
    * **`OnRequiredHttp11`:** Handles the case where HTTP/1.1 is required and an HTTP/2 connection exists.
    * **`OnQuicTaskComplete`:**  Handles the result of the QUIC connection attempt.
    * **`MaybeAttemptQuic/MaybeAttemptConnection`:**  Decision points for initiating QUIC or TCP-based connection attempts.
    * **`ProcessServiceEndpointChanges`:** Reacts to changes in resolved service endpoints.

3. **Identify Relationships to JavaScript:**  I know that JavaScript in a browser triggers network requests. Therefore, the connection to JavaScript is indirect but fundamental.

    * JavaScript makes a request (e.g., `fetch()`, `XMLHttpRequest`).
    * The browser's network stack (where this code resides) takes over.
    * This `AttemptManager` is responsible for establishing the underlying TCP/TLS/QUIC connection to fulfill that request.

4. **Look for Logical Reasoning and Examples:** The code makes decisions based on the state of the connection attempts, available resources, and network conditions.

    * **Assumption/Input:**  A new HTTP request comes in.
    * **Logic:** The code checks for idle connections. If none are found, it initiates a new connection attempt, considering priorities and protocol preferences.
    * **Output:** Either an existing connection is reused, or a new connection is established.

5. **Consider User/Programming Errors:**  What could go wrong from a user or programmer's perspective that would lead to this code being involved?

    * **User Error:**  Typing an incorrect URL (leading to DNS resolution errors handled here). Having network connectivity issues.
    * **Programming Error:**  Incorrectly configuring SSL (leading to certificate errors). Trying to establish too many connections.

6. **Trace User Actions:**  How does a user's action lead to this code being executed?

    * User types a URL or clicks a link.
    * The browser initiates a network request.
    * DNS resolution happens (handled by `ServiceEndpointRequest`).
    * The `AttemptManager` is invoked to establish the connection to the resolved IP address.

7. **Focus on Part 1 and Summarize:**  The prompt specifically asks for a summary of the *first part*. I need to condense the identified functionalities into a concise description.

**Self-Correction/Refinement during the process:**

* Initially, I might just list the methods without grouping them by function. I would then refine this by grouping related methods (e.g., those dealing with service endpoint resolution).
* I'd double-check if any functionality is missed. For instance, the handling of preconnects is a separate, important function.
* I would ensure the JavaScript connection is clearly explained – it's not a direct function call, but a crucial part of the request lifecycle.
* I would reread the prompt to make sure I've addressed all aspects (functionality, JavaScript relation, logic examples, errors, user actions, and the "part 1" summary).
好的，让我们来分析一下 `net/http/http_stream_pool_attempt_manager.cc` 文件的第一部分代码的功能。

**功能归纳 (Part 1):**

`HttpStreamPool::AttemptManager` 类是 Chromium 网络栈中负责管理 HTTP(S) 连接尝试的关键组件。它的主要功能可以归纳为：

1. **管理和协调连接尝试:**  负责启动、跟踪和管理建立 HTTP(S) 连接的各种尝试，包括 TCP 连接、TLS 握手以及 QUIC 连接。它决定何时尝试连接，使用哪个协议，以及在连接失败时如何重试。

2. **服务于 `HttpStreamPool::Group`:** `AttemptManager` 隶属于 `HttpStreamPool::Group`，为同一个目标服务器（HostPortPair）管理连接尝试。每个 `Group` 可以有多个 `AttemptManager`，可能对应不同的网络配置或优先级。

3. **处理连接请求 (`Job`):** 接收来自 `HttpStreamPool::Job` 的连接请求。`Job` 代表一个需要 HTTP(S) 连接的请求。`AttemptManager` 负责为这些 `Job` 找到或建立连接。

4. **支持预连接 (`Preconnect`):**  允许提前建立连接，即使当前没有具体的请求，以降低后续请求的延迟。

5. **DNS 服务端点解析:**  负责发起和管理 DNS 服务端点 (SVCB/HTTPS RR) 的解析，以获取目标服务器的最佳连接方式（IP 地址、端口、协议等）。

6. **管理连接尝试的状态:**  跟踪正在进行的连接尝试 (`InFlightAttempt`)，记录连接尝试的成功或失败，以及连接尝试的耗时等信息。

7. **处理连接限制:**  考虑连接池的限制（例如，每个 Group 或整个 Pool 的最大连接数），避免过度建立连接。

8. **协议选择和协商:**  根据服务器支持的协议（例如 HTTP/1.1、HTTP/2、QUIC）以及客户端的配置，选择合适的协议进行连接。

9. **处理 SSL/TLS 配置:**  负责获取和提供 SSL/TLS 连接所需的配置信息，包括允许的坏证书、隐私模式、ALPN 协议等。

10. **延迟连接尝试:**  在某些情况下（例如，避免过快地重试连接），会延迟发起新的连接尝试。

**与 JavaScript 的关系：**

`HttpStreamPool::AttemptManager` 本身不直接与 JavaScript 代码交互。但是，它在幕后支撑着由 JavaScript 发起的网络请求。

**举例说明：**

假设一个网页的 JavaScript 代码使用 `fetch()` API 发起一个 HTTPS 请求：

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

当浏览器执行这段 JavaScript 代码时，会经历以下步骤，最终涉及到 `AttemptManager`：

1. **JavaScript 发起请求:** `fetch()` API 调用会触发浏览器网络栈发起对 `https://example.com/data.json` 的请求。

2. **`HttpStreamPool` 接管:**  `HttpStreamPool` 会接收到这个请求，并根据请求的目标（`example.com`）找到对应的 `HttpStreamPool::Group`。

3. **`AttemptManager` 启动连接尝试:** `Group` 中的 `AttemptManager` 会负责实际的连接建立过程。这可能包括：
   - **DNS 解析:**  如果尚未解析 `example.com` 的 IP 地址，`AttemptManager` 会触发 DNS 解析。
   - **连接尝试:** `AttemptManager` 会根据配置和服务器支持的协议，尝试建立 TCP 连接、TLS 握手（对于 HTTPS）或 QUIC 连接。

4. **连接成功:** 如果连接建立成功，`AttemptManager` 会将建立的连接（例如 `HttpStream` 或 `QuicHttpStream`) 提供给请求，用于数据传输。

5. **数据传输和 JavaScript 响应:**  数据通过建立的连接传输，最终 `fetch()` API 的 Promise 会 resolve，JavaScript 代码可以处理响应数据。

**逻辑推理 (假设输入与输出):**

**假设输入:**

- 一个新的 `Job` 被添加到 `AttemptManager`，请求连接到 `https://www.example.com:443`。
- 当前没有可用的 idle 连接。
- 服务器支持 HTTP/2 和 QUIC。
- 客户端配置为优先尝试 QUIC。

**逻辑推理过程:**

1. **检查 QUIC 会话:** `AttemptManager` 会首先检查是否已经存在可重用的、到 `www.example.com` 的 QUIC 会话。

2. **尝试 QUIC 连接:** 如果没有可用的 QUIC 会话，并且客户端配置优先尝试 QUIC，`AttemptManager` 可能会启动一个 `QuicTask` 来尝试建立 QUIC 连接。

3. **延迟或尝试 TCP/TLS:** 如果 QUIC 连接尝试失败或被延迟（例如，由于之前的 QUIC 连接失败记录），`AttemptManager` 可能会回退到尝试建立 TCP 连接并进行 TLS 握手以使用 HTTP/2 或 HTTP/1.1。

4. **选择最佳 IP 地址:** 在尝试 TCP 连接时，`AttemptManager` 会考虑 DNS 解析返回的多个 IP 地址，并选择合适的 IP 进行连接尝试。

**假设输出:**

- 最终成功建立了一个到 `www.example.com:443` 的 QUIC 连接，并创建了一个 `QuicHttpStream` 来处理该 `Job` 的请求。
- 或者，如果 QUIC 连接失败，则成功建立了一个 TCP 连接并完成 TLS 握手，使用 HTTP/2 或 HTTP/1.1 创建了一个 `SpdyHttpStream` 或 `HttpBasicStream`。

**用户或编程常见的使用错误 (导致到达这里):**

1. **网络配置错误:** 用户的网络配置有问题，例如防火墙阻止了特定端口的连接，导致连接尝试失败。`AttemptManager` 会记录这些失败并可能尝试其他连接方式。

2. **服务器配置错误:**  服务器的 SSL/TLS 配置不正确，例如证书过期或不匹配，会导致 TLS 握手失败。`AttemptManager` 会收到错误信息。

3. **DNS 解析问题:**  DNS 服务器无法解析目标域名，或者返回错误的 IP 地址，导致连接到错误的服务器或无法连接。`AttemptManager` 会在 DNS 解析阶段或后续连接尝试中遇到错误。

4. **客户端配置限制:**  客户端的网络配置限制了可以建立的连接数量，导致 `AttemptManager` 无法创建新的连接。

5. **代码逻辑错误 (开发者):**  应用程序代码频繁地发起新的连接，超过了连接池的限制，导致 `AttemptManager` 无法满足所有请求。

**用户操作是如何一步步的到达这里 (调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接:** 这是网络请求的起点。

2. **浏览器解析 URL:** 浏览器会解析 URL，确定协议、域名和端口。

3. **查找或创建 `HttpStreamPool::Group`:** 网络栈会查找或创建一个与目标域名对应的 `HttpStreamPool::Group`。

4. **创建或使用 `AttemptManager`:** `Group` 会创建或使用一个 `AttemptManager` 来处理连接尝试。

5. **DNS 解析 (如果需要):**  `AttemptManager` 可能会发起 DNS 解析来获取目标服务器的 IP 地址。你可以在浏览器的开发者工具的网络面板中看到 DNS 查询过程。

6. **连接尝试:** `AttemptManager` 开始尝试建立连接。你可以在浏览器的 `chrome://net-export/` 页面记录网络日志，查看详细的连接尝试过程，包括 TCP 连接、TLS 握手等。

7. **连接成功或失败:**  如果连接成功，请求可以继续进行。如果失败，`AttemptManager` 可能会尝试重连或报告错误。网络日志会详细记录连接尝试的结果和错误信息。

**总结 (Part 1 功能):**

`HttpStreamPool::AttemptManager` 的第一部分代码定义了该类的基本结构和核心功能，即**管理 HTTP(S) 连接尝试**。它负责接收连接请求、进行 DNS 解析、尝试建立连接（包括 QUIC 和 TCP/TLS）、处理连接限制，并与 `HttpStreamPool::Group` 协作，为上层网络请求提供底层的连接支持。它在用户发起网络请求到成功建立连接的过程中扮演着至关重要的角色。

Prompt: 
```
这是目录为net/http/http_stream_pool_attempt_manager.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_pool_attempt_manager.h"

#include <memory>
#include <utility>

#include "base/containers/contains.h"
#include "base/containers/enum_set.h"
#include "base/functional/bind.h"
#include "base/notreached.h"
#include "base/task/sequenced_task_runner.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/completion_once_callback.h"
#include "net/base/host_port_pair.h"
#include "net/base/load_states.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_error_details.h"
#include "net/base/net_errors.h"
#include "net/base/request_priority.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_network_session.h"
#include "net/http/http_stream_key.h"
#include "net/http/http_stream_pool_group.h"
#include "net/http/http_stream_pool_handle.h"
#include "net/http/http_stream_pool_job.h"
#include "net/http/http_stream_pool_quic_task.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/quic_http_stream.h"
#include "net/quic/quic_session_alias_key.h"
#include "net/socket/connection_attempts.h"
#include "net/socket/next_proto.h"
#include "net/socket/stream_attempt.h"
#include "net/socket/stream_socket_handle.h"
#include "net/socket/tcp_stream_attempt.h"
#include "net/socket/tls_stream_attempt.h"
#include "net/spdy/multiplexed_session_creation_initiator.h"
#include "net/spdy/spdy_http_stream.h"
#include "net/spdy/spdy_session.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"

namespace net {

namespace {

constexpr NextProtoSet kTcpBasedProtocols = {
    NextProto::kProtoUnknown, NextProto::kProtoHTTP11, NextProto::kProtoHTTP2};

constexpr NextProtoSet kQuicBasedProtocols = {NextProto::kProtoUnknown,
                                              NextProto::kProtoQUIC};

StreamSocketHandle::SocketReuseType GetReuseTypeFromIdleStreamSocket(
    const StreamSocket& stream_socket) {
  return stream_socket.WasEverUsed()
             ? StreamSocketHandle::SocketReuseType::kReusedIdle
             : StreamSocketHandle::SocketReuseType::kUnusedIdle;
}

}  // namespace

// Represents an in-flight stream attempt.
class HttpStreamPool::AttemptManager::InFlightAttempt
    : public TlsStreamAttempt::SSLConfigProvider {
 public:
  explicit InFlightAttempt(AttemptManager* manager) : manager_(manager) {}

  InFlightAttempt(const InFlightAttempt&) = delete;
  InFlightAttempt& operator=(const InFlightAttempt&) = delete;

  ~InFlightAttempt() override = default;

  int Start(std::unique_ptr<StreamAttempt> attempt) {
    CHECK(!attempt_);
    attempt_ = std::move(attempt);
    // SAFETY: `manager_` owns `this` so using base::Unretained() is safe.
    return attempt_->Start(
        base::BindOnce(&AttemptManager::OnInFlightAttemptComplete,
                       base::Unretained(manager_), this));
  }

  StreamAttempt* attempt() { return attempt_.get(); }

  const IPEndPoint& ip_endpoint() const { return attempt_->ip_endpoint(); }

  bool is_slow() const { return is_slow_; }
  void set_is_slow(bool is_slow) { is_slow_ = is_slow; }

  base::OneShotTimer& slow_timer() { return slow_timer_; }

  // Set to true when the attempt is aborted. When true, the attempt will fail
  // but not be considered as an actual failure.
  bool is_aborted() const { return is_aborted_; }
  void set_is_aborted(bool is_aborted) { is_aborted_ = is_aborted; }

  // TlsStreamAttempt::SSLConfigProvider implementation:
  int WaitForSSLConfigReady(CompletionOnceCallback callback) override {
    return manager_->WaitForSSLConfigReady(std::move(callback));
  }

  base::expected<SSLConfig, TlsStreamAttempt::GetSSLConfigError> GetSSLConfig()
      override {
    return manager_->GetSSLConfig(this);
  }

 private:
  const raw_ptr<AttemptManager> manager_;
  std::unique_ptr<StreamAttempt> attempt_;
  // Timer to start a next attempt. When fired, `this` is treated as a slow
  // attempt but `this` is not timed out yet.
  base::OneShotTimer slow_timer_;
  bool is_slow_ = false;
  bool is_aborted_ = false;
};

// Represents a preconnect request.
struct HttpStreamPool::AttemptManager::PreconnectEntry {
  PreconnectEntry(size_t num_streams, CompletionOnceCallback callback)
      : num_streams(num_streams), callback(std::move(callback)) {}

  PreconnectEntry(const PreconnectEntry&) = delete;
  PreconnectEntry& operator=(const PreconnectEntry&) = delete;

  ~PreconnectEntry() = default;

  size_t num_streams;
  CompletionOnceCallback callback;
  // Set to the latest error when errors happened.
  int result = OK;
};

HttpStreamPool::AttemptManager::AttemptManager(Group* group, NetLog* net_log)
    : group_(group),
      net_log_(NetLogWithSource::Make(
          net_log,
          NetLogSourceType::HTTP_STREAM_POOL_ATTEMPT_MANAGER)),
      jobs_(NUM_PRIORITIES),
      stream_attempt_delay_(GetStreamAttemptDelay()),
      should_block_stream_attempt_(!stream_attempt_delay_.is_zero()) {
  CHECK(group_);
  net_log_.BeginEvent(
      NetLogEventType::HTTP_STREAM_POOL_ATTEMPT_MANAGER_ALIVE, [&] {
        base::Value::Dict dict;
        dict.Set("stream_attempt_delay",
                 static_cast<int>(stream_attempt_delay_.InMilliseconds()));
        group_->net_log().source().AddToEventParameters(dict);
        return dict;
      });
  group_->net_log().AddEventReferencingSource(
      NetLogEventType::HTTP_STREAM_POOL_GROUP_ATTEMPT_MANAGER_CREATED,
      net_log_.source());
}

HttpStreamPool::AttemptManager::~AttemptManager() {
  net_log().EndEvent(NetLogEventType::HTTP_STREAM_POOL_ATTEMPT_MANAGER_ALIVE);
  group_->net_log().AddEventReferencingSource(
      NetLogEventType::HTTP_STREAM_POOL_GROUP_ATTEMPT_MANAGER_DESTROYED,
      net_log_.source());
}

void HttpStreamPool::AttemptManager::StartJob(
    Job* job,
    RequestPriority priority,
    const std::vector<SSLConfig::CertAndStatus>& allowed_bad_certs,
    RespectLimits respect_limits,
    bool enable_ip_based_pooling,
    bool enable_alternative_services,
    quic::ParsedQuicVersion quic_version,
    const NetLogWithSource& net_log) {
  MaybeUpdateQuicVersionWhenForced(quic_version);
  net_log_.AddEvent(
      NetLogEventType::HTTP_STREAM_POOL_ATTEMPT_MANAGER_START_JOB, [&] {
        base::Value::Dict dict;
        dict.Set("priority", priority);
        base::Value::List allowed_bad_certs_list;
        for (const auto& cert_and_status : allowed_bad_certs) {
          allowed_bad_certs_list.Append(
              cert_and_status.cert->subject().GetDisplayName());
        }
        dict.Set("allowed_bad_certs", std::move(allowed_bad_certs_list));
        dict.Set("enable_ip_based_pooling", enable_ip_based_pooling);
        dict.Set("quic_version", quic::ParsedQuicVersionToString(quic_version));
        net_log.source().AddToEventParameters(dict);
        return dict;
      });
  net_log.AddEventReferencingSource(
      NetLogEventType::HTTP_STREAM_POOL_ATTEMPT_MANAGER_JOB_BOUND,
      net_log_.source());

  if (respect_limits == RespectLimits::kIgnore) {
    respect_limits_ = RespectLimits::kIgnore;
  }

  if (!enable_ip_based_pooling) {
    enable_ip_based_pooling_ = enable_ip_based_pooling;
  }

  if (!enable_alternative_services) {
    enable_alternative_services_ = enable_alternative_services;
  }

  // HttpStreamPool should check the existing QUIC/SPDY sessions before calling
  // this method.
  DCHECK(!CanUseExistingQuicSession());
  CHECK(!spdy_session_);
  DCHECK(!spdy_session_pool()->FindAvailableSession(
      spdy_session_key(), enable_ip_based_pooling_,
      /*is_websocket=*/false, net_log));

  jobs_.Insert(job, priority);

  if (is_failing_) {
    // `this` is failing, notify the failure.
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&AttemptManager::NotifyJobOfFailure,
                                  weak_ptr_factory_.GetWeakPtr()));
    return;
  }

  RestrictAllowedProtocols(job->allowed_alpns());

  MaybeChangeServiceEndpointRequestPriority();

  // Check idle streams. If found, notify the job that an HttpStream is ready.
  std::unique_ptr<StreamSocket> stream_socket = group_->GetIdleStreamSocket();
  if (stream_socket) {
    CHECK(!group_->force_quic());
    const StreamSocketHandle::SocketReuseType reuse_type =
        GetReuseTypeFromIdleStreamSocket(*stream_socket);
    // It's important to create an HttpBasicStream synchronously because we
    // already took the ownership of the idle stream socket. If we don't create
    // an HttpBasicStream here, another call of this method might exceed the
    // per-group limit.
    CreateTextBasedStreamAndNotify(std::move(stream_socket), reuse_type,
                                   LoadTimingInfo::ConnectTiming());
    return;
  }

  allowed_bad_certs_ = allowed_bad_certs;
  quic_version_ = quic_version;

  StartInternal(priority);

  return;
}

int HttpStreamPool::AttemptManager::Preconnect(
    size_t num_streams,
    quic::ParsedQuicVersion quic_version,
    CompletionOnceCallback callback) {
  MaybeUpdateQuicVersionWhenForced(quic_version);
  net_log_.AddEvent(
      NetLogEventType::HTTP_STREAM_POOL_ATTEMPT_MANAGER_PRECONNECT, [&] {
        base::Value::Dict dict;
        dict.Set("num_streams", static_cast<int>(num_streams));
        dict.Set("quic_version", quic::ParsedQuicVersionToString(quic_version));
        return dict;
      });

  // HttpStreamPool should check the existing QUIC/SPDY sessions before calling
  // this method.
  CHECK(!CanUseExistingQuicSession());
  CHECK(!spdy_session_);
  CHECK(!spdy_session_pool()->HasAvailableSession(spdy_session_key(),
                                                  /*is_websocket=*/false));
  CHECK(group_->ActiveStreamSocketCount() < num_streams);

  if (is_failing_) {
    return error_to_notify_;
  }

  auto entry =
      std::make_unique<PreconnectEntry>(num_streams, std::move(callback));
  preconnects_.emplace(std::move(entry));

  quic_version_ = quic_version;

  StartInternal(RequestPriority::IDLE);
  return ERR_IO_PENDING;
}

void HttpStreamPool::AttemptManager::OnServiceEndpointsUpdated() {
  // For plain HTTP request, we need to wait for HTTPS RR because we could
  // trigger HTTP -> HTTPS upgrade when HTTPS RR is received during the endpoint
  // resolution.
  if (UsingTls() || service_endpoint_request_->EndpointsCryptoReady()) {
    ProcessServiceEndpointChanges();
  }
}

void HttpStreamPool::AttemptManager::OnServiceEndpointRequestFinished(int rv) {
  CHECK(!service_endpoint_request_finished_);
  CHECK(service_endpoint_request_);

  service_endpoint_request_finished_ = true;
  dns_resolution_end_time_ = base::TimeTicks::Now();
  resolve_error_info_ = service_endpoint_request_->GetResolveErrorInfo();

  if (rv != OK) {
    error_to_notify_ = rv;
    // If service endpoint resolution failed, record an empty endpoint and the
    // result.
    connection_attempts_.emplace_back(IPEndPoint(), rv);
    NotifyFailure();
    return;
  }

  CHECK(!service_endpoint_request_->GetEndpointResults().empty());
  ProcessServiceEndpointChanges();
}

bool HttpStreamPool::AttemptManager::IsSvcbOptional() {
  CHECK(service_endpoint_request_);
  CHECK(pool()->stream_attempt_params()->ssl_client_context);

  // Optional when the destination is not a SVCB-capable or ECH is disabled.
  if (!UsingTls() || !IsEchEnabled()) {
    return true;
  }

  base::span<const ServiceEndpoint> endpoints =
      service_endpoint_request_->GetEndpointResults();
  return !HostResolver::AllProtocolEndpointsHaveEch(endpoints);
}

int HttpStreamPool::AttemptManager::WaitForSSLConfigReady(
    CompletionOnceCallback callback) {
  if (ssl_config_.has_value()) {
    return OK;
  }

  ssl_config_waiting_callbacks_.emplace_back(std::move(callback));
  return ERR_IO_PENDING;
}

base::expected<SSLConfig, TlsStreamAttempt::GetSSLConfigError>
HttpStreamPool::AttemptManager::GetSSLConfig(InFlightAttempt* attempt) {
  CHECK(ssl_config_.has_value());
  CHECK(service_endpoint_request_);
  CHECK(!attempt->is_aborted());

  if (!IsEchEnabled()) {
    return *ssl_config_;
  }

  const bool svcb_optional = IsSvcbOptional();
  for (auto& endpoint : service_endpoint_request_->GetEndpointResults()) {
    if (!IsEndpointUsableForTcpBasedAttempt(endpoint, svcb_optional)) {
      continue;
    }
    const std::vector<IPEndPoint>& ip_endpoints =
        attempt->ip_endpoint().address().IsIPv4() ? endpoint.ipv4_endpoints
                                                  : endpoint.ipv6_endpoints;
    if (base::Contains(ip_endpoints, attempt->ip_endpoint())) {
      SSLConfig ssl_config = *ssl_config_;
      ssl_config.ech_config_list = endpoint.metadata.ech_config_list;
      return ssl_config;
    }
  }

  attempt->set_is_aborted(true);
  return base::unexpected(TlsStreamAttempt::GetSSLConfigError::kAbort);
}

void HttpStreamPool::AttemptManager::ProcessPendingJob() {
  if (is_failing_) {
    return;
  }

  // Try to assign an idle stream to a job.
  if (jobs_.size() > 0 && group_->IdleStreamSocketCount() > 0) {
    std::unique_ptr<StreamSocket> stream_socket = group_->GetIdleStreamSocket();
    CHECK(stream_socket);
    const StreamSocketHandle::SocketReuseType reuse_type =
        GetReuseTypeFromIdleStreamSocket(*stream_socket);
    CreateTextBasedStreamAndNotify(std::move(stream_socket), reuse_type,
                                   LoadTimingInfo::ConnectTiming());
    return;
  }

  const size_t pending_job_count = PendingJobCount();
  const size_t pending_preconnect_count = PendingPreconnectCount();

  if (pending_job_count == 0 && pending_preconnect_count == 0) {
    return;
  }

  CHECK(!CanUseExistingQuicSession());
  CHECK(!spdy_session_);

  MaybeAttemptConnection(/*max_attempts=*/1);
}

void HttpStreamPool::AttemptManager::CancelInFlightAttempts() {
  pool()->DecrementTotalConnectingStreamCount(in_flight_attempts_.size());
  in_flight_attempts_.clear();
  slow_attempt_count_ = 0;
}

void HttpStreamPool::AttemptManager::OnJobComplete(Job* job) {
  auto notified_it = notified_jobs_.find(job);
  if (notified_it != notified_jobs_.end()) {
    notified_jobs_.erase(notified_it);
  } else {
    for (JobQueue::Pointer pointer = jobs_.FirstMax(); !pointer.is_null();
         pointer = jobs_.GetNextTowardsLastMin(pointer)) {
      if (pointer.value() == job) {
        jobs_.Erase(pointer);
        break;
      }
    }
  }
  MaybeComplete();
}

void HttpStreamPool::AttemptManager::CancelJobs(int error) {
  error_to_notify_ = error;
  is_canceling_jobs_ = true;
  NotifyFailure();
}

size_t HttpStreamPool::AttemptManager::PendingJobCount() const {
  return PendingCountInternal(jobs_.size());
}

size_t HttpStreamPool::AttemptManager::PendingPreconnectCount() const {
  size_t num_streams = 0;
  for (const auto& entry : preconnects_) {
    num_streams = std::max(num_streams, entry->num_streams);
  }
  return PendingCountInternal(num_streams);
}

const HttpStreamKey& HttpStreamPool::AttemptManager::stream_key() const {
  return group_->stream_key();
}

const SpdySessionKey& HttpStreamPool::AttemptManager::spdy_session_key() const {
  return group_->spdy_session_key();
}

const QuicSessionAliasKey&
HttpStreamPool::AttemptManager::quic_session_alias_key() const {
  return group_->quic_session_alias_key();
}

HttpNetworkSession* HttpStreamPool::AttemptManager::http_network_session() {
  return group_->http_network_session();
}

SpdySessionPool* HttpStreamPool::AttemptManager::spdy_session_pool() {
  return http_network_session()->spdy_session_pool();
}

QuicSessionPool* HttpStreamPool::AttemptManager::quic_session_pool() {
  return http_network_session()->quic_session_pool();
}

HttpStreamPool* HttpStreamPool::AttemptManager::pool() {
  return group_->pool();
}

const HttpStreamPool* HttpStreamPool::AttemptManager::pool() const {
  return group_->pool();
}

const NetLogWithSource& HttpStreamPool::AttemptManager::net_log() {
  return net_log_;
}

bool HttpStreamPool::AttemptManager::UsingTls() const {
  return GURL::SchemeIsCryptographic(stream_key().destination().scheme());
}

bool HttpStreamPool::AttemptManager::RequiresHTTP11() {
  return pool()->RequiresHTTP11(stream_key().destination(),
                                stream_key().network_anonymization_key());
}

LoadState HttpStreamPool::AttemptManager::GetLoadState() const {
  if (group_->ReachedMaxStreamLimit()) {
    return LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET;
  }

  if (pool()->ReachedMaxStreamLimit()) {
    return LOAD_STATE_WAITING_FOR_STALLED_SOCKET_POOL;
  }

  LoadState load_state = LOAD_STATE_IDLE;

  // When there are in-flight attempts, use most advanced one.
  for (const auto& in_flight_attempt : in_flight_attempts_) {
    load_state =
        std::max(load_state, in_flight_attempt->attempt()->GetLoadState());
    // There should not be a load state later than LOAD_STATE_SSL_HANDSHAKE.
    if (load_state == LOAD_STATE_SSL_HANDSHAKE) {
      break;
    }
  }

  if (load_state != LOAD_STATE_IDLE) {
    return load_state;
  }

  if (service_endpoint_request_ && !service_endpoint_request_finished_) {
    return LOAD_STATE_RESOLVING_HOST;
  }

  return LOAD_STATE_IDLE;
}

RequestPriority HttpStreamPool::AttemptManager::GetPriority() const {
  if (jobs_.empty()) {
    CHECK(!preconnects_.empty());
    // Preconnets have IDLE priority.
    return RequestPriority::IDLE;
  }
  return static_cast<RequestPriority>(jobs_.FirstMax().priority());
}

bool HttpStreamPool::AttemptManager::IsStalledByPoolLimit() {
  if (is_failing_) {
    return false;
  }

  if (!GetIPEndPointToAttempt().has_value()) {
    return false;
  }

  if (CanUseExistingQuicSession() || spdy_session_) {
    CHECK_EQ(PendingPreconnectCount(), 0u);
    return false;
  }

  switch (CanAttemptConnection()) {
    case CanAttemptResult::kAttempt:
    case CanAttemptResult::kReachedPoolLimit:
      return true;
    case CanAttemptResult::kNoPendingJob:
    case CanAttemptResult::kBlockedStreamAttempt:
    case CanAttemptResult::kThrottledForSpdy:
    case CanAttemptResult::kReachedGroupLimit:
      return false;
  }
}

void HttpStreamPool::AttemptManager::OnRequiredHttp11() {
  if (spdy_session_) {
    spdy_session_.reset();
    is_failing_ = true;
    error_to_notify_ = ERR_HTTP_1_1_REQUIRED;
  }
}

void HttpStreamPool::AttemptManager::OnQuicTaskComplete(
    int rv,
    NetErrorDetails details) {
  CHECK(!quic_task_result_.has_value());
  quic_task_result_ = rv;
  net_error_details_ = std::move(details);
  quic_task_.reset();

  net_log().AddEvent(
      NetLogEventType::HTTP_STREAM_POOL_ATTEMPT_MANAGER_QUIC_TASK_COMPLETED,
      [&] {
        base::Value::Dict dict = GetStatesAsNetLogParams();
        if (rv != 0) {
          dict.Set("net_error", rv);
        }
        return dict;
      });

  MaybeMarkQuicBroken();

  const bool has_jobs = !jobs_.empty() || !notified_jobs_.empty();

  if (rv == OK) {
    HandleQuicSessionReady();
    if (has_jobs) {
      CreateQuicStreamAndNotify();
      return;
    }
  }

  if (rv != OK &&
      (tcp_based_attempt_state_ == TcpBasedAttemptState::kAllAttemptsFailed ||
       group_->force_quic() || !CanUseTcpBasedProtocols())) {
    error_to_notify_ = rv;
    NotifyFailure();
    return;
  }

  if (rv != OK || should_block_stream_attempt_) {
    should_block_stream_attempt_ = false;
    stream_attempt_delay_timer_.Stop();
    MaybeAttemptConnection();
  } else {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&AttemptManager::MaybeComplete,
                                  weak_ptr_factory_.GetWeakPtr()));
  }
}

base::Value::Dict HttpStreamPool::AttemptManager::GetInfoAsValue() {
  base::Value::Dict dict;
  dict.Set("pending_job_count", static_cast<int>(PendingJobCount()));
  dict.Set("pending_preconnect_count",
           static_cast<int>(PendingPreconnectCount()));
  dict.Set("in_flight_attempt_count", static_cast<int>(InFlightAttemptCount()));
  dict.Set("slow_attempt_count", static_cast<int>(slow_attempt_count_));
  dict.Set("is_stalled", IsStalledByPoolLimit());
  return dict;
}

MultiplexedSessionCreationInitiator
HttpStreamPool::AttemptManager::CalculateMultiplexedSessionCreationInitiator() {
  // Iff we only have preconnect jobs, return `kPreconnect`.
  if (!preconnects_.empty() && jobs_.empty() && notified_jobs_.empty()) {
    return MultiplexedSessionCreationInitiator::kPreconnect;
  }
  return MultiplexedSessionCreationInitiator::kUnknown;
}

void HttpStreamPool::AttemptManager::StartInternal(RequestPriority priority) {
  UpdateStreamAttemptState();

  if (service_endpoint_request_ || service_endpoint_request_finished_) {
    MaybeAttemptQuic();
    MaybeAttemptConnection();
  } else {
    ResolveServiceEndpoint(priority);
  }
}

void HttpStreamPool::AttemptManager::ResolveServiceEndpoint(
    RequestPriority initial_priority) {
  CHECK(!service_endpoint_request_);
  HostResolver::ResolveHostParameters parameters;
  parameters.initial_priority = initial_priority;
  parameters.secure_dns_policy = stream_key().secure_dns_policy();
  service_endpoint_request_ =
      http_network_session()->host_resolver()->CreateServiceEndpointRequest(
          HostResolver::Host(stream_key().destination()),
          stream_key().network_anonymization_key(), net_log(),
          std::move(parameters));

  dns_resolution_start_time_ = base::TimeTicks::Now();
  int rv = service_endpoint_request_->Start(this);
  if (rv != ERR_IO_PENDING) {
    OnServiceEndpointRequestFinished(rv);
  }
}

void HttpStreamPool::AttemptManager::RestrictAllowedProtocols(
    NextProtoSet allowed_alpns) {
  allowed_alpns_ = base::Intersection(allowed_alpns_, allowed_alpns);
  CHECK(!allowed_alpns_.empty());

  if (!CanUseTcpBasedProtocols()) {
    CancelInFlightAttempts();
  }

  if (!CanUseQuic()) {
    if (quic_task_) {
      // TODO(crbug.com/346835898): Use other error code?
      quic_task_result_ = ERR_ABORTED;
      quic_task_.reset();
    }
    UpdateStreamAttemptState();
  }
}

void HttpStreamPool::AttemptManager::
    MaybeChangeServiceEndpointRequestPriority() {
  if (service_endpoint_request_ && !service_endpoint_request_finished_) {
    service_endpoint_request_->ChangeRequestPriority(GetPriority());
  }
}

void HttpStreamPool::AttemptManager::ProcessServiceEndpointChanges() {
  if (CanUseExistingSessionAfterEndpointChanges()) {
    return;
  }
  MaybeRunStreamAttemptDelayTimer();
  MaybeCalculateSSLConfig();
  MaybeAttemptQuic();
  MaybeAttemptConnection();
}

bool HttpStreamPool::AttemptManager::
    CanUseExistingSessionAfterEndpointChanges() {
  CHECK(service_endpoint_request_);

  if (!UsingTls()) {
    return false;
  }

  if (CanUseExistingQuicSession()) {
    return true;
  }

  if (CanUseQuic()) {
    for (const auto& endpoint :
         service_endpoint_request_->GetEndpointResults()) {
      if (quic_session_pool()->HasMatchingIpSessionForServiceEndpoint(
              quic_session_alias_key(), endpoint,
              service_endpoint_request_->GetDnsAliasResults(), true)) {
        if (quic_task_) {
          quic_task_result_ = OK;
          quic_task_.reset();
        }
        HandleQuicSessionReady();
        // Use PostTask() because we could reach here from RequestStream()
        // synchronously when the DNS resolution finishes immediately.
        base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
            FROM_HERE,
            base::BindOnce(&AttemptManager::CreateQuicStreamAndNotify,
                           weak_ptr_factory_.GetWeakPtr()));
        return true;
      }
    }
  }

  if (spdy_session_) {
    return true;
  }

  if (!enable_ip_based_pooling_) {
    return false;
  }

  for (const auto& endpoint : service_endpoint_request_->GetEndpointResults()) {
    spdy_session_ =
        spdy_session_pool()->FindMatchingIpSessionForServiceEndpoint(
            spdy_session_key(), endpoint,
            service_endpoint_request_->GetDnsAliasResults());
    if (spdy_session_) {
      HandleSpdySessionReady();
      // Use PostTask() because we could reach here from RequestStream()
      // synchronously when the DNS resolution finishes immediately.
      base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&AttemptManager::CreateSpdyStreamAndNotify,
                                    weak_ptr_factory_.GetWeakPtr()));
      return true;
    }
  }

  return false;
}

void HttpStreamPool::AttemptManager::MaybeRunStreamAttemptDelayTimer() {
  if (!should_block_stream_attempt_ ||
      stream_attempt_delay_timer_.IsRunning()) {
    return;
  }
  CHECK(!stream_attempt_delay_.is_zero());
  stream_attempt_delay_timer_.Start(
      FROM_HERE, stream_attempt_delay_,
      base::BindOnce(&AttemptManager::OnStreamAttemptDelayPassed,
                     weak_ptr_factory_.GetWeakPtr()));
}

void HttpStreamPool::AttemptManager::MaybeCalculateSSLConfig() {
  if (!UsingTls() || ssl_config_.has_value()) {
    return;
  }

  CHECK(service_endpoint_request_);
  if (!service_endpoint_request_->EndpointsCryptoReady()) {
    return;
  }

  SSLConfig ssl_config;

  ssl_config.allowed_bad_certs = allowed_bad_certs_;
  ssl_config.privacy_mode = stream_key().privacy_mode();
  ssl_config.disable_cert_verification_network_fetches =
      stream_key().disable_cert_network_fetches();
  ssl_config.early_data_enabled =
      http_network_session()->params().enable_early_data;

  ssl_config.alpn_protos = http_network_session()->GetAlpnProtos();
  ssl_config.application_settings =
      http_network_session()->GetApplicationSettings();
  http_network_session()->http_server_properties()->MaybeForceHTTP11(
      stream_key().destination(), stream_key().network_anonymization_key(),
      &ssl_config);

  ssl_config.ignore_certificate_errors =
      http_network_session()->params().ignore_certificate_errors;
  ssl_config.network_anonymization_key =
      stream_key().network_anonymization_key();

  ssl_config_.emplace(std::move(ssl_config));

  // Restart slow timer for in-flight attempts that have already completed
  // TCP handshakes.
  for (auto& in_flight_attempt : in_flight_attempts_) {
    if (!in_flight_attempt->is_slow() &&
        !in_flight_attempt->slow_timer().IsRunning()) {
      // TODO(crbug.com/346835898): Should we use a different delay other than
      // the connection attempt delay?
      // base::Unretained() is safe here because `this` owns the
      // `in_flight_attempt` and `slow_timer`.
      in_flight_attempt->slow_timer().Start(
          FROM_HERE, kConnectionAttemptDelay,
          base::BindOnce(&AttemptManager::OnInFlightAttemptSlow,
                         base::Unretained(this), in_flight_attempt.get()));
    }
  }

  for (auto& callback : ssl_config_waiting_callbacks_) {
    std::move(callback).Run(OK);
  }
  ssl_config_waiting_callbacks_.clear();
}

void HttpStreamPool::AttemptManager::MaybeAttemptQuic() {
  CHECK(service_endpoint_request_);
  if (!CanUseQuic() || quic_task_result_.has_value() ||
      !service_endpoint_request_->EndpointsCryptoReady()) {
    return;
  }

  if (!quic_task_) {
    quic_task_ = std::make_unique<QuicTask>(this, quic_version_);
  }
  quic_task_->MaybeAttempt();
}

void HttpStreamPool::AttemptManager::MaybeAttemptConnection(
    std::optional<size_t> max_attempts) {
  if (PendingJobCount() == 0 && preconnects_.empty()) {
    // There are no jobs waiting for streams.
    return;
  }

  if (group_->force_quic()) {
    return;
  }

  if (!CanUseTcpBasedProtocols()) {
    return;
  }

  if (CanUseQuic() && quic_task_result_.has_value() &&
      *quic_task_result_ == OK) {
    return;
  }

  CHECK(!preconnects_.empty() || group_->IdleStreamSocketCount() == 0);

  // TODO(crbug.com/346835898): Ensure that we don't attempt connections when
  // failing or creating HttpStream on top of a SPDY session.
  CHECK(!is_failing_);
  CHECK(!spdy_session_);

  std::optional<IPEndPoint> ip_endpoint = GetIPEndPointToAttempt();
  if (!ip_endpoint.has_value()) {
    if (service_endpoint_request_finished_ && in_flight_attempts_.empty()) {
      tcp_based_attempt_state_ = TcpBasedAttemptState::kAllAttemptsFailed;
    }
    if (tcp_based_attempt_state_ == TcpBasedAttemptState::kAllAttemptsFailed &&
        !quic_task_) {
      // Tried all endpoints.
      MaybeMarkQuicBroken();
      NotifyFailure();
    }
    return;
  }

  if (tcp_based_attempt_state_ == TcpBasedAttemptState::kNotStarted) {
    tcp_based_attempt_state_ = TcpBasedAttemptState::kAttempting;
  }

  // There might be multiple pending jobs. Make attempts as much as needed
  // and allowed.
  size_t num_attempts = 0;
  const bool using_tls = UsingTls();
  while (IsConnectionAttemptReady()) {
    auto in_flight_attempt = std::make_unique<InFlightAttempt>(this);
    InFlightAttempt* raw_attempt = in_flight_attempt.get();
    in_flight_attempts_.emplace(std::move(in_flight_attempt));
    pool()->IncrementTotalConnectingStreamCount();

    std::unique_ptr<StreamAttempt> attempt;
    // Set to non-null if the attempt is a TLS attempt.
    TlsStreamAttempt* tls_attempt_ptr = nullptr;
    if (using_tls) {
      attempt = std::make_unique<TlsStreamAttempt>(
          pool()->stream_attempt_params(), *ip_endpoint,
          HostPortPair::FromSchemeHostPort(stream_key().destination()),
          /*ssl_config_provider=*/raw_attempt);
      tls_attempt_ptr = static_cast<TlsStreamAttempt*>(attempt.get());
    } else {
      attempt = std::make_unique<TcpStreamAttempt>(
          pool()->stream_attempt_params(), *ip_endpoint);
    }

    net_log().AddEvent(
        NetLogEventType::HTTP_STREAM_POOL_ATTEMPT_MANAGER_ATTEMPT_START, [&] {
          base::Value::Dict dict = GetStatesAsNetLogParams();
          attempt->net_log().source().AddToEventParameters(dict);
          return dict;
        });

    int rv = raw_attempt->Start(std::move(attempt));
    // Add NetLog dependency after Start() so that the first event of the
    // attempt can have meaningful description in the NetLog viewer.
    raw_attempt->attempt()->net_log().AddEventReferencingSource(
        NetLogEventType::STREAM_ATTEMPT_BOUND_TO_POOL, net_log().source());
    if (rv != ERR_IO_PENDING) {
      base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE, base::BindOnce(&AttemptManager::OnInFlightAttemptComplete,
                                    base::Unretained(this), raw_attempt, rv));
    } else {
      raw_attempt->slow_timer().Start(
          FROM_HERE, kConnectionAttemptDelay,
          base::BindOnce(&AttemptManager::OnInFlightAttemptSlow,
                         base::Unretained(this), raw_attempt));
      if (tls_attempt_ptr && !tls_attempt_ptr->IsTcpHandshakeCompleted()) {
        tls_attempt_ptr->SetTcpHandshakeCompletionCallback(base::BindOnce(
            &AttemptManager::OnInFlightAttemptTcpHandshakeComplete,
            base::Unretained(this), raw_attempt));
      }
    }

    ++num_attempts;
    if (max_attempts.has_value() && num_attempts >= *max_attempts) {
      break;
    }
  }
}

bool HttpStreamPool::AttemptManager::IsConnectionAttemptReady() {
  switch (CanAttemptConnection()) {
    case CanAttemptResult::kAttempt:
      return true;
    case CanAttemptResult::kNoPendingJob:
      return false;
    case CanAttemptResult::kBlockedStreamAttempt:
      return false;
    case CanAttemptResult::kThrottledForSpdy:
      // TODO(crbug.com/346835898): Consider throttling less aggressively (e.g.
      // allow TCP handshake but throttle TLS handshake) so that endpoints we've
      // used HTTP/2 on aren't penalised on slow or lossy connections.
      if (!spdy_throttle_timer_.IsRunning()) {
        spdy_throttle_timer_.Start(
            FROM_HERE, kSpdyThrottleDelay,
            base::BindOnce(&AttemptManager::OnSpdyThrottleDelayPassed,
                           base::Unretained(this)));
      }
      return false;
    case CanAttemptResult::kReachedGroupLimit:
      // TODO(crbug.com/346835898): Better to handle cases where we partially
      // attempted some connections.
      NotifyPreconnectsComplete(ERR_PRECONNECT_MAX_SOCKET_LIMIT);
      return false;
    case CanAttemptResult::kReachedPoolLimit:
      // If we can't attempt connection due to the pool's limit, try to close an
      // idle stream in the pool.
      if (!pool()->CloseOneIdleStreamSocket()) {
        // Try to close idle SPDY sessions. SPDY sessions never release the
        // underlying sockets immediately on close, so return false anyway.
        spdy_session_pool()->CloseCurrentIdleSessions("Closing idle sessions");
        // TODO(crbug.com/346835898): Better to handle cases where we partially
        // attempted some connections.
        NotifyPreconnectsComplet
"""


```