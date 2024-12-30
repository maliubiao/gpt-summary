Response:
The user wants to understand the functionality of the `HttpStreamPool::AttemptManager` class in Chromium's networking stack, based on the provided C++ source code. They are particularly interested in:

1. **Listing its functionalities.**
2. **Its relationship with JavaScript (if any).**
3. **Logical reasoning with input/output examples.**
4. **Common user/programming errors related to it.**
5. **How user actions lead to this code (debugging perspective).**
6. **A summary of its functions (as this is part 2).**

**Thinking Process:**

1. **High-Level Understanding:** The class name `AttemptManager` suggests its core responsibility is managing attempts to establish HTTP stream connections. It likely deals with connection pooling, handling failures, and optimizing connection attempts (like pre-connecting).

2. **Functionality Breakdown (Code Analysis):**
   - **Managing Connection Attempts:**  Look for methods related to starting, tracking, and completing connection attempts (e.g., `MaybeAttemptConnection`, `OnInFlightAttemptComplete`, `HandleAttemptFailure`).
   - **Prioritization:**  Methods like `SetJobPriority` indicate the ability to prioritize connection requests.
   - **Pre-connection:** The presence of `preconnects_`, `PreconnectEntry`, and `NotifyPreconnectsComplete` clearly points to pre-connection functionality.
   - **Protocol Handling (HTTP/1.1, HTTP/2, QUIC):**  Methods like `CreateTextBasedStreamAndNotify`, `CreateSpdyStreamAndNotify`, `CreateQuicStreamAndNotify`, and checks for `NextProto` indicate handling of different HTTP protocols.
   - **Error Handling:** Methods like `NotifyFailure`, `DetermineFailureKind`, and handling specific error codes (e.g., `ERR_SSL_CLIENT_AUTH_CERT_NEEDED`) are important.
   - **Throttling:** `ShouldThrottleAttemptForSpdy` and related logic suggests mechanisms to prevent overwhelming servers.
   - **Session Management (SPDY/QUIC):**  Interaction with `spdy_session_pool()` and `quic_session_pool()` is evident.
   - **Address Selection:**  `GetIPEndPointToAttempt` and `FindPreferredIPEndpoint` suggest intelligent selection of IP addresses for connection attempts.
   - **State Management:** Tracking in-flight attempts (`in_flight_attempts_`), slow attempts (`slow_attempt_count_`), and attempt states (`tcp_based_attempt_state_`).
   - **Integration with Higher Layers:**  The interaction with `Job` objects (through `jobs_`, `notified_jobs_`, and methods like `ExtractFirstJobToNotify`, `NotifyStreamReady`) shows how this class interacts with requests.
   - **Net Logging:** The usage of `net_log()` for debugging and tracking.
   - **Respecting Limits:** The `respect_limits_` flag and checks against `ReachedMaxStreamLimit`.

3. **JavaScript Relationship:**  Think about how the network stack interacts with the browser's rendering engine. JavaScript initiates network requests, but this C++ code is lower-level. The connection is indirect. Focus on how JavaScript *triggers* network requests that eventually reach this code.

4. **Logical Reasoning (Input/Output):**  Choose a specific scenario, like a new request for an HTTPS resource. Trace how the `AttemptManager` might handle it. Consider different outcomes (successful connection, connection failure, throttling).

5. **User/Programming Errors:**  Consider common mistakes that might lead to issues handled by this code. Incorrect configurations, exceeding connection limits, or network issues.

6. **User Actions as Debugging Clues:**  Think about user actions that initiate network requests: typing a URL, clicking a link, a webpage loading resources. How do these actions propagate through the browser to reach this code?

7. **Summarization (Part 2 Focus):** Since this is part 2, focus on the functionalities within *this specific code block*. Avoid repeating details from part 1 if possible. Look for overall themes and responsibilities within this segment. Notice it's heavily involved in handling the completion and consequences of connection attempts.

8. **Refine and Organize:**  Structure the answer clearly, using headings and bullet points for readability. Provide concrete examples where possible. Ensure the language is accurate and avoids overly technical jargon where simpler terms suffice.

**(Self-Correction during thought process):** Initially, I might focus too much on the low-level socket details. However, the `AttemptManager` works at a slightly higher level, orchestrating these attempts. I need to balance the low-level details with the overall management responsibility. Also, remember the "part 2" constraint – focus on the code provided in *this* specific snippet.
这是 `net/http/http_stream_pool_attempt_manager.cc` 文件的第二部分，主要涵盖了 `HttpStreamPool::AttemptManager` 类在处理连接尝试完成后的各种操作，以及一些辅助方法。以下是这部分代码的功能归纳：

**核心功能：处理连接尝试的完成和失败**

* **`OnInFlightAttemptComplete(InFlightAttempt* raw_attempt, int rv)`:**  这是处理单个连接尝试完成的核心方法。
    * **成功情况 (`rv == OK`)：**
        * 记录连接成功事件。
        * 停止慢速连接定时器。
        * 更新连接尝试状态 (`tcp_based_attempt_state_`)。
        * 提取并设置连接的 `LoadTimingInfo`。
        * 释放底层的 `StreamSocket`。
        * 如果协商的协议是 HTTP/2：
            * 尝试在 SPDY 会话池中创建或复用会话。
            * 调用 `HandleSpdySessionReady()` 通知 SPDY 会话已准备好。
            * 调用 `CreateSpdyStreamAndNotify()` 为等待的请求创建 HTTP/2 流。
        * 如果协商的协议不是 HTTP/2 (通常是 HTTP/1.1)：
            * 调用 `ProcessPreconnectsAfterAttemptComplete()` 处理预连接请求。
            * 调用 `CreateTextBasedStreamAndNotify()` 为等待的请求创建 HTTP/1.1 流。
    * **失败情况 (`rv != OK`)：**
        * 调用 `HandleAttemptFailure()` 处理连接尝试失败的情况。
* **`HandleAttemptFailure(std::unique_ptr<InFlightAttempt> in_flight_attempt, int rv)`:** 处理连接尝试失败。
    * 记录连接尝试的失败，包括 IP 地址和错误码。
    * 将失败的 IP 地址添加到黑名单 (`failed_ip_endpoints_`)。
    * 如果尝试被中止，则直接返回。
    * 调用 `ProcessPreconnectsAfterAttemptComplete()` 处理预连接请求。
    * 如果 `AttemptManager` 已经处于失败状态 (`is_failing_`)，则直接返回。
    * 记录错误码 (`error_to_notify_`)。
    * 如果是客户端认证相关的错误 (`ERR_SSL_CLIENT_AUTH_CERT_NEEDED`)，则保存证书请求信息并调用 `NotifyFailure()`。
    * 如果是证书错误 (`IsCertificateError(rv)`)，则获取 SSL 信息并调用 `NotifyFailure()`。
    * 否则，调用 `MaybeAttemptConnection()` 尝试其他连接方式。

**处理连接过程中的中间状态**

* **`OnInFlightAttemptTcpHandshakeComplete(InFlightAttempt* raw_attempt, int rv)`:** 在 TCP 握手完成后被调用，但这段代码中似乎没有实际操作，可能用于记录或未来扩展。
* **`OnInFlightAttemptSlow(InFlightAttempt* raw_attempt)`:** 当一个连接尝试被认为是慢速时调用。
    * 将该尝试标记为慢速 (`set_is_slow(true)`)。
    * 增加慢速尝试计数器 (`slow_attempt_count_`).
    * 将慢速的 IP 地址添加到慢速列表 (`slow_ip_endpoints_`)。
    * 根据慢速连接的 IP 地址类型调整 IP 地址偏好 (`prefer_ipv6_`)。
    * 调用 `MaybeAttemptConnection()` 尝试其他连接方式。

**处理 SPDY 节流延迟**

* **`OnSpdyThrottleDelayPassed()`:** 当 SPDY 节流延迟过后被调用。
    * 设置 `spdy_throttle_delay_passed_` 为 `true`。
    * 调用 `MaybeAttemptConnection()` 尝试建立 SPDY 连接。

**处理 QUIC 连接**

* **`CreateQuicStreamAndNotify()`:**  在 QUIC 会话准备好后，为等待的请求创建 QUIC 流。
    * 从 QUIC 会话池中查找现有的会话。
    * 为剩余的请求发布任务以创建更多 QUIC 流（如果有多于一个请求）。
    * 创建 `QuicHttpStream` 并调用 `NotifyStreamReady()`。
* **`HandleQuicSessionReady()`:** 当 QUIC 会话准备好时调用。
    * 标记 `AttemptManager` 不再有 QUIC 任务 (`quic_task_`)。
    * 刷新组状态，指示正在切换到 HTTP/3。
    * 调用 `NotifyPreconnectsComplete(OK)` 通知预连接完成。
* **`MaybeMarkQuicBroken()`:**  根据 QUIC 任务的结果以及 TCP 连接尝试的状态，判断是否需要将 QUIC 标记为不可用。

**流就绪通知**

* **`NotifyStreamReady(std::unique_ptr<HttpStream> stream, NextProto negotiated_protocol)`:** 当一个 HTTP 流准备好后，通知等待的 `Job`。
    * 从 `jobs_` 队列中提取第一个等待的 `Job`。
    * 如果没有等待的 `Job`，则释放 `stream` 的所有权（因为它即将被销毁）。
    * 调用 `job->OnStreamReady()` 通知 `Job` 流已准备好。

**会话就绪通知**

* **`HandleSpdySessionReady()`:** 当 SPDY 会话准备好时调用。
    * 刷新组状态，指示正在切换到 HTTP/2。
    * 调用 `NotifyPreconnectsComplete(OK)` 通知预连接完成。

**其他辅助方法**

* **`GetStreamAttemptDelay()`:** 获取流尝试的延迟时间（主要用于 QUIC）。
* **`UpdateStreamAttemptState()`:** 根据 QUIC 的可用性更新是否应该阻止流尝试。
* **`OnStreamAttemptDelayPassed()`:** 当流尝试延迟时间过后被调用，允许进行流尝试。
* **`MaybeUpdateQuicVersionWhenForced(quic::ParsedQuicVersion& quic_version)`:** 如果被强制使用 QUIC，则更新 QUIC 版本。
* **`CanUseTcpBasedProtocols()`**, **`CanUseQuic()`**, **`CanUseExistingQuicSession()`**, **`IsEchEnabled()`**, **`IsEndpointUsableForTcpBasedAttempt()`:**  用于判断是否可以使用特定的协议或会话。
* **`GetStatesAsNetLogParams()`:**  返回当前 `AttemptManager` 状态的 NetLog 参数。
* **`MaybeComplete()`:**  检查是否所有任务都已完成，如果是，则通知 `HttpStreamPool::Group`。

**与 JavaScript 的关系**

与第一部分类似，`HttpStreamPool::AttemptManager` 本身并不直接与 JavaScript 交互。但是，JavaScript 发起的网络请求（例如通过 `fetch()` API 或 `XMLHttpRequest`）最终会通过 Chromium 的网络栈到达这里。

**举例说明:**

当 JavaScript 代码执行 `fetch("https://example.com")` 时，会触发网络请求。这个请求经过一系列处理，最终可能导致 `HttpStreamPool::AttemptManager` 尝试建立到 `example.com` 的连接。如果连接成功并协商了 HTTP/2，`CreateSpdyStreamAndNotify()` 会被调用，创建一个 `SpdyHttpStream` 对象，该对象最终会被传递回上层，用于处理响应数据并返回给 JavaScript。

**假设输入与输出 (逻辑推理)**

假设输入：一个连接尝试完成，`rv` 为 `OK`，协商的协议是 HTTP/1.1。

输出：

1. `OnInFlightAttemptComplete()` 被调用。
2. 连接尝试被标记为成功。
3. `LoadTimingInfo` 被提取和设置。
4. `ProcessPreconnectsAfterAttemptComplete()` 被调用，可能会完成一些预连接请求的回调。
5. `CreateTextBasedStreamAndNotify()` 被调用，创建一个 `HttpStream` 对象。
6. 该 `HttpStream` 对象通过 `NotifyStreamReady()` 通知等待的 `Job`。

假设输入：一个连接尝试完成，`rv` 为 `ERR_CONNECTION_REFUSED`。

输出：

1. `OnInFlightAttemptComplete()` 被调用。
2. `HandleAttemptFailure()` 被调用。
3. 连接尝试信息（IP 地址和错误码）被记录。
4. `ProcessPreconnectsAfterAttemptComplete()` 被调用。
5. `MaybeAttemptConnection()` 被调用，尝试其他连接方式（如果适用）。

**用户或编程常见的使用错误**

由于 `HttpStreamPool::AttemptManager` 是网络栈的内部组件，用户或前端开发者通常不会直接与之交互。常见的错误更多发生在网络配置或服务器端，但这些错误会影响到 `AttemptManager` 的行为。

* **服务器配置错误:** 例如，服务器不支持客户端请求的协议（ALPN 不匹配），导致连接失败。`AttemptManager` 会尝试回退到其他协议或报告连接错误。
* **达到连接限制:**  Chromium 有连接池限制。如果请求过多，可能会导致新的连接请求被延迟或拒绝，虽然这不是 `AttemptManager` 的错误，但它会处理这些限制。
* **网络问题:**  间歇性的网络连接问题会导致连接尝试失败。`AttemptManager` 会尝试重试或通知上层连接失败。

**用户操作如何一步步的到达这里 (调试线索)**

1. **用户在浏览器地址栏输入 URL 或点击链接:**  这会触发一个导航或资源请求。
2. **浏览器解析 URL:**  确定请求的协议、主机和端口。
3. **DNS 查询:** 浏览器或操作系统会查询目标主机的 IP 地址。
4. **HttpStreamFactory (或其他网络请求发起者) 创建请求:**  根据请求信息创建 `HttpRequestInfo` 等对象。
5. **HttpStreamPool 查找或创建连接:**  `HttpStreamPool` 会尝试复用现有的连接，如果需要创建新连接，则会创建 `AttemptManager`。
6. **AttemptManager 启动连接尝试:**  根据配置和当前状态，选择合适的协议和 IP 地址进行连接尝试。
7. **底层 Socket 连接:**  `AttemptManager` 使用 `ClientSocketFactory` 创建 `StreamSocket` 并尝试建立 TCP 连接，可能包括 TLS 握手。
8. **连接完成 (`OnInFlightAttemptComplete`):**  当底层连接成功或失败时，会调用 `AttemptManager` 的 `OnInFlightAttemptComplete` 方法。

在调试网络问题时，查看 NetLog (chrome://net-export/) 可以提供详细的连接尝试信息，包括何时创建了 `AttemptManager`，进行了哪些连接尝试，以及每次尝试的结果，这有助于追踪问题发生的具体阶段。

**总结其功能 (第二部分)**

`HttpStreamPool::AttemptManager` 的第二部分主要负责处理连接尝试完成后的各种后续操作。它根据连接尝试的结果（成功或失败）以及协商的协议（HTTP/1.1, HTTP/2, QUIC）采取不同的行动，例如创建相应的 HTTP 流，处理预连接请求，以及在连接失败时尝试其他连接方式或通知上层。 这一部分是连接管理流程中的关键环节，确保了连接的正确建立和资源的有效利用。它还负责处理 SPDY 节流和 QUIC 会话的管理，以及在必要时标记 QUIC 为不可用。

Prompt: 
```
这是目录为net/http/http_stream_pool_attempt_manager.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
e(ERR_PRECONNECT_MAX_SOCKET_LIMIT);
        return false;
      }
      return true;
  }
}

HttpStreamPool::AttemptManager::CanAttemptResult
HttpStreamPool::AttemptManager::CanAttemptConnection() {
  size_t pending_count = std::max(PendingJobCount(), PendingPreconnectCount());
  if (pending_count == 0) {
    return CanAttemptResult::kNoPendingJob;
  }

  if (ShouldThrottleAttemptForSpdy()) {
    return CanAttemptResult::kThrottledForSpdy;
  }

  if (should_block_stream_attempt_) {
    return CanAttemptResult::kBlockedStreamAttempt;
  }

  if (respect_limits_ == RespectLimits::kRespect) {
    if (group_->ReachedMaxStreamLimit()) {
      return CanAttemptResult::kReachedGroupLimit;
    }

    if (pool()->ReachedMaxStreamLimit()) {
      return CanAttemptResult::kReachedPoolLimit;
    }
  }

  return CanAttemptResult::kAttempt;
}

bool HttpStreamPool::AttemptManager::ShouldThrottleAttemptForSpdy() {
  if (!http_network_session()->http_server_properties()->GetSupportsSpdy(
          stream_key().destination(),
          stream_key().network_anonymization_key())) {
    return false;
  }

  CHECK(UsingTls());

  // The first attempt should not be blocked.
  if (in_flight_attempts_.empty()) {
    return false;
  }

  if (spdy_throttle_delay_passed_) {
    return false;
  }

  CHECK(!spdy_session_);
  return true;
}

size_t HttpStreamPool::AttemptManager::PendingCountInternal(
    size_t pending_count) const {
  CHECK_GE(in_flight_attempts_.size(), slow_attempt_count_);
  // When SPDY throttle delay passed, treat all in-flight attempts as non-slow,
  // to avoid attempting connections more than requested.
  // TODO(crbug.com/346835898): This behavior is tricky. Figure out a better
  // way to handle this situation.
  size_t slow_count = spdy_throttle_delay_passed_ ? 0 : slow_attempt_count_;
  size_t non_slow_count = in_flight_attempts_.size() - slow_count;
  // The number of in-flight, non-slow attempts could be larger than the number
  // of jobs (e.g. a job was cancelled in the middle of an attempt).
  if (pending_count <= non_slow_count) {
    return 0;
  }

  return pending_count - non_slow_count;
}

std::optional<IPEndPoint>
HttpStreamPool::AttemptManager::GetIPEndPointToAttempt() {
  if (!service_endpoint_request_ ||
      service_endpoint_request_->GetEndpointResults().empty()) {
    return std::nullopt;
  }

  const bool svcb_optional = IsSvcbOptional();

  // Look for an IPEndPoint from the preferred address family first.
  for (auto& endpoint : service_endpoint_request_->GetEndpointResults()) {
    if (!IsEndpointUsableForTcpBasedAttempt(endpoint, svcb_optional)) {
      continue;
    }
    std::optional<IPEndPoint> ip_endpoint =
        prefer_ipv6_ ? FindPreferredIPEndpoint(endpoint.ipv6_endpoints)
                     : FindPreferredIPEndpoint(endpoint.ipv4_endpoints);
    if (ip_endpoint.has_value()) {
      return ip_endpoint;
    }
  }

  // If there is no IPEndPoint from the preferred address family, check the
  // another address family.
  for (auto& endpoint : service_endpoint_request_->GetEndpointResults()) {
    if (!IsEndpointUsableForTcpBasedAttempt(endpoint, svcb_optional)) {
      continue;
    }
    std::optional<IPEndPoint> ip_endpoint =
        prefer_ipv6_ ? FindPreferredIPEndpoint(endpoint.ipv4_endpoints)
                     : FindPreferredIPEndpoint(endpoint.ipv6_endpoints);
    if (ip_endpoint.has_value()) {
      return ip_endpoint;
    }
  }

  return std::nullopt;
}

std::optional<IPEndPoint>
HttpStreamPool::AttemptManager::FindPreferredIPEndpoint(
    const std::vector<IPEndPoint>& ip_endpoints) {
  // Prefer the first unattempted endpoint in `ip_endpoints`. Allow to use
  // the first slow endpoint when SPDY throttle delay passed.

  std::optional<IPEndPoint> slow_endpoint;
  for (const auto& ip_endpoint : ip_endpoints) {
    if (base::Contains(failed_ip_endpoints_, ip_endpoint)) {
      continue;
    }
    if (base::Contains(slow_ip_endpoints_, ip_endpoint)) {
      if (!slow_endpoint.has_value()) {
        slow_endpoint = ip_endpoint;
      }
      continue;
    }
    return ip_endpoint;
  }

  if (spdy_throttle_delay_passed_) {
    return slow_endpoint;
  }
  return std::nullopt;
}

HttpStreamPool::AttemptManager::FailureKind
HttpStreamPool::AttemptManager::DetermineFailureKind() {
  if (is_canceling_jobs_) {
    return FailureKind::kStreamFailed;
  }

  if (IsCertificateError(error_to_notify_)) {
    return FailureKind::kCertifcateError;
  }

  if (error_to_notify_ == ERR_SSL_CLIENT_AUTH_CERT_NEEDED) {
    return FailureKind::kNeedsClientAuth;
  }

  return FailureKind::kStreamFailed;
}

void HttpStreamPool::AttemptManager::NotifyFailure() {
  is_failing_ = true;
  NotifyPreconnectsComplete(error_to_notify_);
  NotifyJobOfFailure();
  // `this` may be deleted.
}

void HttpStreamPool::AttemptManager::NotifyJobOfFailure() {
  CHECK(is_failing_);
  Job* job = ExtractFirstJobToNotify();
  if (!job) {
    // TODO(crbug.com/346835898): Ensure that MaybeComplete() is called
    // eventually.
    return;
  }

  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&AttemptManager::NotifyJobOfFailure,
                                weak_ptr_factory_.GetWeakPtr()));

  job->AddConnectionAttempts(connection_attempts_);

  FailureKind kind = DetermineFailureKind();
  switch (kind) {
    case FailureKind::kStreamFailed:
      job->OnStreamFailed(error_to_notify_, net_error_details_,
                          resolve_error_info_);
      break;
    case FailureKind::kCertifcateError:
      CHECK(cert_error_ssl_info_.has_value());
      job->OnCertificateError(error_to_notify_, *cert_error_ssl_info_);
      break;
    case FailureKind::kNeedsClientAuth:
      CHECK(client_auth_cert_info_.get());
      job->OnNeedsClientAuth(client_auth_cert_info_.get());
      break;
  }
  // `this` may be deleted.
}

void HttpStreamPool::AttemptManager::NotifyPreconnectsComplete(int rv) {
  while (!preconnects_.empty()) {
    std::unique_ptr<PreconnectEntry> entry =
        std::move(preconnects_.extract(preconnects_.begin()).value());
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(entry->callback), rv));
  }
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&AttemptManager::MaybeComplete,
                                weak_ptr_factory_.GetWeakPtr()));
}

void HttpStreamPool::AttemptManager::ProcessPreconnectsAfterAttemptComplete(
    int rv) {
  std::vector<PreconnectEntry*> completed;
  for (auto& entry : preconnects_) {
    CHECK_GT(entry->num_streams, 0u);
    --entry->num_streams;
    if (rv != OK) {
      entry->result = rv;
    }
    if (entry->num_streams == 0) {
      completed.emplace_back(entry.get());
    }
  }

  for (auto* entry_ptr : completed) {
    auto it = preconnects_.find(entry_ptr);
    CHECK(it != preconnects_.end());
    std::unique_ptr<PreconnectEntry> entry =
        std::move(preconnects_.extract(it).value());
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(std::move(entry->callback), entry->result));
  }
  if (preconnects_.empty()) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&AttemptManager::MaybeComplete,
                                  weak_ptr_factory_.GetWeakPtr()));
  }
}

void HttpStreamPool::AttemptManager::CreateTextBasedStreamAndNotify(
    std::unique_ptr<StreamSocket> stream_socket,
    StreamSocketHandle::SocketReuseType reuse_type,
    LoadTimingInfo::ConnectTiming connect_timing) {
  NextProto negotiated_protocol = stream_socket->GetNegotiatedProtocol();
  CHECK_NE(negotiated_protocol, NextProto::kProtoHTTP2);

  std::unique_ptr<HttpStream> http_stream = group_->CreateTextBasedStream(
      std::move(stream_socket), reuse_type, std::move(connect_timing));
  CHECK(respect_limits_ == RespectLimits::kIgnore ||
        group_->ActiveStreamSocketCount() <=
            pool()->max_stream_sockets_per_group())
      << "active=" << group_->ActiveStreamSocketCount()
      << ", limit=" << pool()->max_stream_sockets_per_group();

  NotifyStreamReady(std::move(http_stream), negotiated_protocol);
  // `this` may be deleted.
}

void HttpStreamPool::AttemptManager::CreateSpdyStreamAndNotify() {
  CHECK(!is_canceling_jobs_);
  CHECK(!is_failing_);

  if (!spdy_session_ || !spdy_session_->IsAvailable()) {
    // There was an available SPDY session but the session has gone while
    // notifying to jobs. Do another attempt.

    spdy_session_.reset();
    // We may not have calculated SSLConfig yet. Try to calculate it before
    // attempting connections.
    MaybeCalculateSSLConfig();
    MaybeAttemptConnection();
    return;
  }

  // If there are more than one remaining job, post a task to create
  // HttpStreams for these jobs.
  if (jobs_.size() > 1) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&AttemptManager::CreateSpdyStreamAndNotify,
                                  weak_ptr_factory_.GetWeakPtr()));
  }

  std::set<std::string> dns_aliases =
      http_network_session()->spdy_session_pool()->GetDnsAliasesForSessionKey(
          spdy_session_key());
  auto http_stream = std::make_unique<SpdyHttpStream>(
      spdy_session_, net_log().source(), std::move(dns_aliases));
  NotifyStreamReady(std::move(http_stream), NextProto::kProtoHTTP2);
  // `this` may be deleted.
}

void HttpStreamPool::AttemptManager::CreateQuicStreamAndNotify() {
  QuicChromiumClientSession* quic_session =
      quic_session_pool()->FindExistingSession(
          quic_session_alias_key().session_key(),
          quic_session_alias_key().destination());
  CHECK(quic_session);

  // If there are more than one remaining job, post a task to create
  // HttpStreams for these jobs.
  if (jobs_.size() > 1) {
    base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, base::BindOnce(&AttemptManager::CreateQuicStreamAndNotify,
                                  weak_ptr_factory_.GetWeakPtr()));
  }

  std::set<std::string> dns_aliases = quic_session->GetDnsAliasesForSessionKey(
      quic_session_alias_key().session_key());
  auto http_stream = std::make_unique<QuicHttpStream>(
      quic_session->CreateHandle(stream_key().destination()),
      std::move(dns_aliases));
  NotifyStreamReady(std::move(http_stream), NextProto::kProtoQUIC);
  // `this` may be deleted.
}

void HttpStreamPool::AttemptManager::NotifyStreamReady(
    std::unique_ptr<HttpStream> stream,
    NextProto negotiated_protocol) {
  Job* job = ExtractFirstJobToNotify();
  if (!job) {
    // The ownership of the stream will be moved to the group as `stream` is
    // going to be destructed.
    return;
  }
  job->OnStreamReady(std::move(stream), negotiated_protocol);
}

void HttpStreamPool::AttemptManager::HandleSpdySessionReady() {
  CHECK(!group_->force_quic());
  CHECK(!is_failing_);
  CHECK(spdy_session_);

  group_->Refresh(kSwitchingToHttp2);
  NotifyPreconnectsComplete(OK);
}

void HttpStreamPool::AttemptManager::HandleQuicSessionReady() {
  CHECK(!is_failing_);
  CHECK(!quic_task_);
  DCHECK(CanUseExistingQuicSession());

  group_->Refresh(kSwitchingToHttp3);
  NotifyPreconnectsComplete(OK);
}

HttpStreamPool::Job* HttpStreamPool::AttemptManager::ExtractFirstJobToNotify() {
  if (jobs_.empty()) {
    return nullptr;
  }
  raw_ptr<Job> job = jobs_.Erase(jobs_.FirstMax());
  Job* job_raw_ptr = job.get();
  notified_jobs_.emplace(std::move(job));
  return job_raw_ptr;
}

void HttpStreamPool::AttemptManager::SetJobPriority(Job* job,
                                                    RequestPriority priority) {
  for (JobQueue::Pointer pointer = jobs_.FirstMax(); !pointer.is_null();
       pointer = jobs_.GetNextTowardsLastMin(pointer)) {
    if (pointer.value() == job) {
      if (pointer.priority() == priority) {
        break;
      }

      raw_ptr<Job> entry = jobs_.Erase(pointer);
      jobs_.Insert(std::move(entry), priority);
      break;
    }
  }

  MaybeChangeServiceEndpointRequestPriority();
}

void HttpStreamPool::AttemptManager::OnInFlightAttemptComplete(
    InFlightAttempt* raw_attempt,
    int rv) {
  net_log().AddEvent(
      NetLogEventType::HTTP_STREAM_POOL_ATTEMPT_MANAGER_ATTEMPT_END, [&] {
        base::Value::Dict dict = GetStatesAsNetLogParams();
        raw_attempt->attempt()->net_log().source().AddToEventParameters(dict);
        return dict;
      });
  raw_attempt->slow_timer().Stop();
  if (raw_attempt->is_slow()) {
    CHECK_GT(slow_attempt_count_, 0u);
    --slow_attempt_count_;
  }

  auto it = in_flight_attempts_.find(raw_attempt);
  CHECK(it != in_flight_attempts_.end());
  std::unique_ptr<InFlightAttempt> in_flight_attempt =
      std::move(in_flight_attempts_.extract(it).value());
  pool()->DecrementTotalConnectingStreamCount();

  if (rv != OK) {
    HandleAttemptFailure(std::move(in_flight_attempt), rv);
    return;
  }

  CHECK_NE(tcp_based_attempt_state_, TcpBasedAttemptState::kAllAttemptsFailed);
  if (tcp_based_attempt_state_ == TcpBasedAttemptState::kAttempting) {
    tcp_based_attempt_state_ = TcpBasedAttemptState::kSucceededAtLeastOnce;
    MaybeMarkQuicBroken();
  }

  LoadTimingInfo::ConnectTiming connect_timing =
      in_flight_attempt->attempt()->connect_timing();
  connect_timing.domain_lookup_start = dns_resolution_start_time_;
  // If the attempt started before DNS resolution completion, `connect_start`
  // could be smaller than `dns_resolution_end_time_`. Use the smallest one.
  connect_timing.domain_lookup_end =
      dns_resolution_end_time_.is_null()
          ? connect_timing.connect_start
          : std::min(connect_timing.connect_start, dns_resolution_end_time_);

  std::unique_ptr<StreamSocket> stream_socket =
      in_flight_attempt->attempt()->ReleaseStreamSocket();
  CHECK(stream_socket);
  CHECK(service_endpoint_request_);
  stream_socket->SetDnsAliases(service_endpoint_request_->GetDnsAliasResults());

  spdy_throttle_timer_.Stop();

  const auto reuse_type = StreamSocketHandle::SocketReuseType::kUnused;
  if (stream_socket->GetNegotiatedProtocol() == NextProto::kProtoHTTP2) {
    CHECK(!spdy_session_pool()->FindAvailableSession(
        group_->spdy_session_key(), enable_ip_based_pooling_,
        /*is_websocket=*/false, net_log()));
    std::unique_ptr<HttpStreamPoolHandle> handle = group_->CreateHandle(
        std::move(stream_socket), reuse_type, std::move(connect_timing));
    int create_result =
        spdy_session_pool()->CreateAvailableSessionFromSocketHandle(
            spdy_session_key(), std::move(handle), net_log(),
            MultiplexedSessionCreationInitiator::kUnknown, &spdy_session_);
    if (create_result != OK) {
      HandleAttemptFailure(std::move(in_flight_attempt), create_result);
      return;
    }

    HandleSpdySessionReady();
    CreateSpdyStreamAndNotify();
    return;
  }

  ProcessPreconnectsAfterAttemptComplete(rv);

  CHECK_NE(stream_socket->GetNegotiatedProtocol(), NextProto::kProtoHTTP2);
  CreateTextBasedStreamAndNotify(std::move(stream_socket), reuse_type,
                                 std::move(connect_timing));
}

void HttpStreamPool::AttemptManager::OnInFlightAttemptTcpHandshakeComplete(
    InFlightAttempt* raw_attempt,
    int rv) {
  auto it = in_flight_attempts_.find(raw_attempt);
  CHECK(it != in_flight_attempts_.end());
  if (raw_attempt->is_slow() || !raw_attempt->slow_timer().IsRunning()) {
    return;
  }

  raw_attempt->slow_timer().Stop();
}

void HttpStreamPool::AttemptManager::OnInFlightAttemptSlow(
    InFlightAttempt* raw_attempt) {
  auto it = in_flight_attempts_.find(raw_attempt);
  CHECK(it != in_flight_attempts_.end());

  raw_attempt->set_is_slow(true);
  ++slow_attempt_count_;
  slow_ip_endpoints_.emplace(raw_attempt->attempt()->ip_endpoint());
  prefer_ipv6_ = !raw_attempt->attempt()->ip_endpoint().address().IsIPv6();

  MaybeAttemptConnection();
}

void HttpStreamPool::AttemptManager::HandleAttemptFailure(
    std::unique_ptr<InFlightAttempt> in_flight_attempt,
    int rv) {
  CHECK_NE(rv, ERR_IO_PENDING);
  connection_attempts_.emplace_back(in_flight_attempt->ip_endpoint(), rv);
  failed_ip_endpoints_.emplace(in_flight_attempt->attempt()->ip_endpoint());

  if (in_flight_attempt->is_aborted()) {
    CHECK_EQ(rv, ERR_ABORTED);
    return;
  }

  ProcessPreconnectsAfterAttemptComplete(rv);

  if (is_failing_) {
    // `this` has already failed and is notifying jobs to the failure.
    return;
  }

  error_to_notify_ = rv;

  if (rv == ERR_SSL_CLIENT_AUTH_CERT_NEEDED) {
    CHECK(UsingTls());
    client_auth_cert_info_ = in_flight_attempt->attempt()->GetCertRequestInfo();
    in_flight_attempt.reset();
    NotifyFailure();
    return;
  }

  if (IsCertificateError(rv)) {
    // When a certificate error happened for an attempt, notifies all jobs of
    // the error.
    CHECK(UsingTls());
    CHECK(in_flight_attempt->attempt()->stream_socket());
    SSLInfo ssl_info;
    bool has_ssl_info =
        in_flight_attempt->attempt()->stream_socket()->GetSSLInfo(&ssl_info);
    CHECK(has_ssl_info);
    cert_error_ssl_info_ = ssl_info;
    in_flight_attempt.reset();
    NotifyFailure();
  } else {
    in_flight_attempt.reset();
    MaybeAttemptConnection();
  }
}

void HttpStreamPool::AttemptManager::OnSpdyThrottleDelayPassed() {
  CHECK(!spdy_throttle_delay_passed_);
  spdy_throttle_delay_passed_ = true;
  MaybeAttemptConnection();
}

base::TimeDelta HttpStreamPool::AttemptManager::GetStreamAttemptDelay() {
  if (!CanUseQuic()) {
    return base::TimeDelta();
  }

  return quic_session_pool()->GetTimeDelayForWaitingJob(
      quic_session_alias_key().session_key());
}

void HttpStreamPool::AttemptManager::UpdateStreamAttemptState() {
  if (!should_block_stream_attempt_) {
    return;
  }

  if (!CanUseQuic()) {
    should_block_stream_attempt_ = false;
    stream_attempt_delay_timer_.Stop();
    return;
  }
}

void HttpStreamPool::AttemptManager::OnStreamAttemptDelayPassed() {
  net_log().AddEvent(
      NetLogEventType::
          HTTP_STREAM_POOL_ATTEMPT_MANAGER_STREAM_ATTEMPT_DELAY_PASSED,
      [&] {
        base::Value::Dict dict;
        dict.Set("stream_attempt_delay",
                 static_cast<int>(stream_attempt_delay_.InMilliseconds()));
        return dict;
      });
  CHECK(should_block_stream_attempt_);
  should_block_stream_attempt_ = false;
  MaybeAttemptConnection();
}

void HttpStreamPool::AttemptManager::MaybeUpdateQuicVersionWhenForced(
    quic::ParsedQuicVersion& quic_version) {
  if (!quic_version.IsKnown() && group_->force_quic()) {
    quic_version = http_network_session()
                       ->context()
                       .quic_context->params()
                       ->supported_versions[0];
  }
}

bool HttpStreamPool::AttemptManager::CanUseTcpBasedProtocols() {
  return allowed_alpns_.HasAny(kTcpBasedProtocols);
}

bool HttpStreamPool::AttemptManager::CanUseQuic() {
  return allowed_alpns_.HasAny(kQuicBasedProtocols) &&
         pool()->CanUseQuic(stream_key().destination(),
                            stream_key().network_anonymization_key(),
                            enable_ip_based_pooling_,
                            enable_alternative_services_);
}

bool HttpStreamPool::AttemptManager::CanUseExistingQuicSession() {
  return pool()->CanUseExistingQuicSession(quic_session_alias_key(),
                                           enable_ip_based_pooling_,
                                           enable_alternative_services_);
}

bool HttpStreamPool::AttemptManager::IsEchEnabled() const {
  return pool()
      ->stream_attempt_params()
      ->ssl_client_context->config()
      .ech_enabled;
}

bool HttpStreamPool::AttemptManager::IsEndpointUsableForTcpBasedAttempt(
    const ServiceEndpoint& endpoint,
    bool svcb_optional) {
  // No ALPNs means that the endpoint is an authority A/AAAA endpoint, even if
  // we are still in the middle of DNS resolution.
  if (endpoint.metadata.supported_protocol_alpns.empty()) {
    return svcb_optional;
  }

  // See https://www.rfc-editor.org/rfc/rfc9460.html#section-9.3. Endpoints are
  // usable if there is an overlap between the endpoint's ALPNs and the
  // configured ones.
  for (const auto& alpn : endpoint.metadata.supported_protocol_alpns) {
    if (base::Contains(http_network_session()->GetAlpnProtos(),
                       NextProtoFromString(alpn))) {
      return true;
    }
  }
  return false;
}

void HttpStreamPool::AttemptManager::MaybeMarkQuicBroken() {
  if (!quic_task_result_.has_value() ||
      tcp_based_attempt_state_ == TcpBasedAttemptState::kAttempting) {
    return;
  }

  if (*quic_task_result_ == OK ||
      *quic_task_result_ == ERR_DNS_NO_MATCHING_SUPPORTED_ALPN ||
      *quic_task_result_ == ERR_NETWORK_CHANGED ||
      *quic_task_result_ == ERR_INTERNET_DISCONNECTED) {
    return;
  }

  // No brokenness to report if we didn't attempt TCP-based connection or all
  // TCP-based attempts failed.
  if (tcp_based_attempt_state_ == TcpBasedAttemptState::kNotStarted ||
      tcp_based_attempt_state_ == TcpBasedAttemptState::kAllAttemptsFailed) {
    return;
  }

  const url::SchemeHostPort& destination = stream_key().destination();
  http_network_session()
      ->http_server_properties()
      ->MarkAlternativeServiceBroken(
          AlternativeService(NextProto::kProtoQUIC, destination.host(),
                             destination.port()),
          stream_key().network_anonymization_key());
}

base::Value::Dict HttpStreamPool::AttemptManager::GetStatesAsNetLogParams() {
  base::Value::Dict dict;
  dict.Set("num_jobs", static_cast<int>(jobs_.size()));
  dict.Set("num_notified_jobs", static_cast<int>(notified_jobs_.size()));
  dict.Set("num_preconnects", static_cast<int>(preconnects_.size()));
  dict.Set("num_inflight_attempts",
           static_cast<int>(in_flight_attempts_.size()));
  dict.Set("num_slow_attempts", static_cast<int>(slow_attempt_count_));
  dict.Set("quic_task_alive", !!quic_task_);
  if (quic_task_result_.has_value()) {
    dict.Set("quic_task_result", ErrorToString(*quic_task_result_));
  }
  return dict;
}

void HttpStreamPool::AttemptManager::MaybeComplete() {
  if (!jobs_.empty() || !notified_jobs_.empty() || !preconnects_.empty() ||
      !in_flight_attempts_.empty()) {
    return;
  }

  if (quic_task_) {
    return;
  }

  group_->OnAttemptManagerComplete();
  // `this` is deleted.
}

}  // namespace net

"""


```