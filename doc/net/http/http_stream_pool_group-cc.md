Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of `HttpStreamPool::Group`, its relationship to JavaScript (if any), logical reasoning with input/output examples, common usage errors, and debugging clues.

2. **Initial Scan for Core Functionality:** The class name `HttpStreamPool::Group` and the file name `http_stream_pool_group.cc` immediately suggest it's part of a system managing HTTP connections. Keywords like "stream," "socket," "idle," "connect," "pool," and "attempt" stand out. The `#include` directives confirm it interacts with network-related components within Chromium's `net` namespace.

3. **Decomposition by Function:** The most effective way to understand the functionality is to go through each method of the class:

    * **Constructor/Destructor:**  The constructor initializes the group, logs its creation, and notes if QUIC is forced. The destructor logs the group's destruction. This signals the lifecycle management aspect of the class.

    * **`IsIdleStreamSocketUsable`:** This static method checks if an idle socket is still valid for reuse. It considers timeout, connection status, and whether data was unexpectedly received. This points to connection reuse optimization.

    * **`CreateJob`:** This creates a `Job` object, suggesting asynchronous connection attempts. The `AttemptManager` is involved, reinforcing this idea.

    * **`Preconnect`:** This method proactively establishes connections, hinting at performance optimization by reducing connection latency.

    * **`CreateHandle`:** This seems to wrap a `StreamSocket` into a `HttpStreamPoolHandle`. The handle likely represents a usable connection.

    * **`CreateTextBasedStream`:**  This creates an `HttpBasicStream` from a socket, specifically for text-based protocols (HTTP/1.1). This separates the creation of different types of HTTP streams.

    * **`ReleaseStreamSocket`:**  This is crucial for connection reuse. It determines if a socket can be returned to the idle pool or needs to be closed. It also triggers processing of pending requests.

    * **`AddIdleStreamSocket`:** This adds a reusable socket to the idle pool.

    * **`GetIdleStreamSocket`:** This retrieves a reusable socket from the idle pool, prioritizing used sockets for better performance.

    * **`ProcessPendingRequest`:**  Delegates to the `AttemptManager` to start connection attempts for pending requests.

    * **`CloseOneIdleStreamSocket`:**  Removes an idle socket, likely for resource management.

    * **`ConnectingStreamSocketCount`, `ActiveStreamSocketCount`, `ReachedMaxStreamLimit`:** These provide information about the group's connection state and help enforce connection limits.

    * **`GetPriorityIfStalledByPoolLimit`:**  Indicates if requests are waiting due to connection limits, useful for prioritization.

    * **`FlushWithError`, `Refresh`, `CloseIdleStreams`, `CancelJobs`:** These methods handle error conditions and connection cleanup, ensuring resources are released and pending requests are handled appropriately. `Refresh` also suggests a mechanism for invalidating existing connections.

    * **`OnRequiredHttp11`:**  Signals a requirement for HTTP/1.1, influencing connection attempts.

    * **`OnAttemptManagerComplete`:**  Called when the `AttemptManager` finishes its work, potentially triggering the group's completion.

    * **`GetInfoAsValue`:**  Provides debugging information.

    * **`CleanupTimedoutIdleStreamSocketsForTesting`, `CleanupIdleStreamSockets`:**  Methods for cleaning up idle sockets based on timeout or force.

    * **`EnsureAttemptManager`:**  Lazy initialization of the `AttemptManager`.

    * **`MaybeComplete`:** Determines if the group is no longer needed and signals its completion.

4. **Identify Key Concepts:**  From the function analysis, several key concepts emerge:

    * **Connection Pooling:** The core purpose is to reuse HTTP connections to improve performance.
    * **Idle Socket Management:**  Keeping track of and reusing idle connections.
    * **Connection Attempts:**  Managing the process of establishing new connections.
    * **Connection Limits:**  Enforcing maximum connections per group.
    * **Prioritization:**  Handling request priorities, especially when limits are reached.
    * **Error Handling and Cleanup:** Gracefully handling connection errors and releasing resources.
    * **Asynchronous Operations:** The use of `CompletionOnceCallback` and the `AttemptManager` suggest asynchronous operations.

5. **Relate to JavaScript (if applicable):**  Directly, this C++ code doesn't interact with JavaScript. However, the *outcomes* of this code are highly relevant to JavaScript running in a browser. Network requests initiated by JavaScript rely on the underlying network stack, including the connection pooling mechanisms implemented here. This leads to the example of a JavaScript `fetch` request and how the `HttpStreamPool::Group` helps optimize it.

6. **Construct Logical Reasoning Examples:** Choose a representative scenario, like requesting a resource. Trace the steps, making reasonable assumptions about the internal state and decisions. Provide a clear input (a request) and potential output (a successfully created stream or an error).

7. **Identify Common User/Programming Errors:** Think about how misconfiguration or improper usage *outside* of this specific class could lead to issues that this class might encounter or handle. Examples include server errors, network issues, or incorrect proxy settings. Also, consider programming errors within the Chromium codebase that might affect this component.

8. **Develop Debugging Clues:** Think about how a developer might investigate issues related to connection pooling. Focus on user actions that trigger network requests and how to trace the execution flow to this class. The Network panel in DevTools is a crucial tool.

9. **Structure the Answer:** Organize the findings logically, using clear headings and bullet points. Start with a high-level summary, then delve into the details of each aspect of the request.

10. **Review and Refine:** Read through the answer to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might not have explicitly mentioned the role of `HttpNetworkSession` which is clearly important, so a review would add that. Also ensuring the JavaScript connection is clear and not implying direct interaction is important.
Based on the provided source code for `net/http/http_stream_pool_group.cc`, here's a breakdown of its functionality, its relation to JavaScript, logical reasoning, potential errors, and debugging clues:

**Functionality of `HttpStreamPool::Group`:**

The `HttpStreamPool::Group` class in Chromium's network stack is responsible for managing a group of HTTP stream (TCP socket) connections for a specific origin (host and port). Its main functionalities include:

1. **Maintaining a Pool of Idle Sockets:** It keeps track of reusable, idle TCP sockets that can be used for new HTTP requests to the same origin. This avoids the overhead of establishing a new connection for each request.

2. **Managing Active Sockets:** It tracks sockets that are currently in use for active HTTP streams.

3. **Handling Connection Establishment:**  It utilizes an `AttemptManager` (a nested class or related component not fully shown here, but implied by its usage) to manage the process of establishing new TCP connections when no suitable idle socket is available.

4. **Connection Reuse Logic:** It implements logic to determine if an idle socket is still usable (e.g., not timed out, still connected, no unexpected data received).

5. **Pre-connecting Sockets:**  It supports pre-connecting a specified number of sockets to reduce latency for subsequent requests.

6. **Releasing and Adding Sockets:** It handles the release of used sockets back to the idle pool if they are reusable.

7. **Enforcing Connection Limits:**  It participates in enforcing the maximum number of concurrent connections allowed to a specific origin.

8. **Handling Connection Errors:** It manages the closing of sockets due to errors or other reasons and cleans up associated resources.

9. **Integration with `HttpStreamPool`:** It's a component managed by the `HttpStreamPool`, which is responsible for managing groups of connections for different origins.

10. **Logging and Debugging:** It includes logging using Chromium's `NetLog` system to record events related to connection management, aiding in debugging.

**Relationship with JavaScript Functionality:**

While the C++ code itself doesn't directly execute JavaScript, it plays a crucial role in enabling network requests initiated by JavaScript in a web browser. Here's how they relate:

* **`fetch()` API and XMLHttpRequest:** When JavaScript code in a web page uses the `fetch()` API or `XMLHttpRequest` to make an HTTP request, the browser's network stack (including this `HttpStreamPool::Group` class) is responsible for handling the underlying connection.
* **Connection Reuse for Performance:**  The connection pooling implemented by `HttpStreamPool::Group` directly benefits JavaScript applications by making subsequent requests to the same origin much faster, as a new TCP handshake isn't required.
* **Example:**
    ```javascript
    // JavaScript making multiple requests to the same domain
    fetch('https://example.com/data1.json')
      .then(response => response.json())
      .then(data => console.log(data));

    fetch('https://example.com/data2.json')
      .then(response => response.json())
      .then(data => console.log(data));
    ```
    In this scenario, the first `fetch()` might establish a new TCP connection. The `HttpStreamPool::Group` for `example.com` would then store this connection as idle. The second `fetch()` request would likely reuse this idle connection, resulting in a faster response time compared to establishing a new connection.

**Logical Reasoning with Assumptions, Input, and Output:**

**Scenario:** JavaScript makes two consecutive `fetch()` requests to `https://test.example.net/resource1` and `https://test.example.net/resource2`. Assume the maximum connections per group is 6.

**Assumptions:**

* The `HttpStreamPool` already has a `Group` for `test.example.net`.
* No idle connections are available initially.
* Both requests are HTTP/1.1.

**Input:**

1. **First `fetch()`:** A request to `https://test.example.net/resource1`.
2. **Second `fetch()`:** A request to `https://test.example.net/resource2`.

**Steps within `HttpStreamPool::Group` (Simplified):**

1. **First `fetch()`:**
   - The `HttpStreamPool` identifies the target origin (`test.example.net`).
   - It finds the corresponding `HttpStreamPool::Group`.
   - `GetIdleStreamSocket()` is called, returning `nullptr` (no idle socket).
   - `CreateJob()` is called to initiate a new connection attempt via the `AttemptManager`.
   - The `AttemptManager` establishes a TCP connection and negotiates HTTP/1.1.
   - A `StreamSocket` is created and handed out using `CreateHandle()`.
   - The HTTP stream for the first request is established.

2. **Second `fetch()` (While the first request is ongoing or just completed):**
   - The `HttpStreamPool` identifies the target origin.
   - It finds the same `HttpStreamPool::Group`.
   - **Possibility A (First request still active):**
     - If the first connection is still active (processing the response), `GetIdleStreamSocket()` still returns `nullptr`.
     - If the `ActiveStreamSocketCount()` is less than the maximum (6), a new connection attempt is initiated by `CreateJob()`.
   - **Possibility B (First request just completed and socket released):**
     - The `ReleaseStreamSocket()` method for the first connection is called.
     - If the socket is reusable and within limits, it's added to `idle_stream_sockets_`.
     - `GetIdleStreamSocket()` for the second `fetch()` might now return this idle socket.
     - A new `HttpBasicStream` is created using `CreateTextBasedStream()` with the reused socket.

**Output:**

* **Possibility A:** Two separate TCP connections are established and used for the two requests.
* **Possibility B:** One TCP connection is established for the first request and then reused for the second request.

**Common User or Programming Usage Errors:**

1. **Server-Side Issues:** While not directly a user error with this specific C++ code, server-side issues like the server closing connections prematurely or having keep-alive timeouts that are too short can impact the effectiveness of connection pooling. This can lead to the `IsIdleStreamSocketUsable()` method returning `base::unexpected` and forcing the closure of seemingly idle connections.

2. **Network Instability:** Intermittent network connectivity issues can cause sockets to become unusable unexpectedly, leading to connection re-establishment and reduced performance.

3. **Incorrect Proxy Configuration:** Misconfigured proxy settings can interfere with connection establishment and reuse.

4. **Excessive Connection Attempts:**  Although the code manages connection attempts, if there are underlying issues causing repeated connection failures, it could lead to resource exhaustion or performance degradation. This isn't a direct usage error of *this class*, but a consequence of broader system issues.

5. **Forcing Connection Closure:**  While less common, if other parts of the browser's networking code force the closure of connections without proper handling, it can disrupt the pooling mechanism.

**Example of a Usage Error Manifesting Here:**

Imagine a scenario where a server has a very aggressive keep-alive timeout (e.g., 5 seconds).

**User Action:**

1. User loads a webpage with several images from `images.example.com`.
2. The browser establishes connections to `images.example.com` and downloads the images.
3. The user then idles on the page for 7 seconds.
4. The user clicks a link that requires fetching more resources from `images.example.com`.

**How it Reaches `HttpStreamPool::Group`:**

1. When the initial images are downloaded, `HttpStreamPool::Group` manages the sockets. After the downloads are complete, the sockets become idle and are stored in `idle_stream_sockets_`.
2. The user's 7-second idle time exceeds the server's keep-alive timeout. The server might close the idle connections.
3. When the user clicks the link, the browser attempts to fetch new resources from `images.example.com`.
4. `HttpStreamPool::Group::GetIdleStreamSocket()` is called to find a reusable connection.
5. Inside `IsIdleStreamSocketUsable()`, the check `idle.stream_socket->IsConnectedAndIdle()` will likely return `false` because the server has closed the connection.
6. `IsIdleStreamSocketUsable()` will return `base::unexpected(kRemoteSideClosedConnection)`.
7. The code in `GetIdleStreamSocket()` will then log the closing of the socket and remove it from the idle pool.
8. A new connection attempt will be initiated, effectively negating the benefit of the previously pooled connection due to the server's short timeout.

**Debugging Clues (How to reach this code during debugging):**

1. **Network Panel in DevTools:** Observe the "Timing" tab for requests. Look for:
   - **"Stalled" time:**  If requests are stalled waiting for an available connection, it could indicate issues with the connection pool limits or the inability to reuse connections.
   - **"Connection Start" time:**  Long connection start times for subsequent requests to the same origin might suggest that connection reuse is not happening as expected.
   - **"Queueing" time:** Can indicate the browser is waiting for a socket to become available.

2. **`chrome://net-internals/#http_stream`:** This page provides detailed information about the HTTP stream pool, including:
   - Active and idle connections for each origin.
   - Connection state (idle, active, connecting).
   - Whether connections are being reused.
   - Error logs related to connection management.

3. **NetLog (using `chrome://net-internals/#events`):** Capture a NetLog and filter for events related to `HTTP_STREAM_POOL_GROUP`. Look for events like:
   - `HTTP_STREAM_POOL_GROUP_ALIVE`: When a new group is created.
   - `HTTP_STREAM_POOL_CLOSING_SOCKET`:  Reasons for closing sockets (e.g., `kIdleTimeLimitExpired`, `kRemoteSideClosedConnection`).
   - Events within the `HttpStreamPool::Job` and `AttemptManager` (though not fully visible in this code snippet) which would provide details on connection attempts.

4. **Breakpoints in the C++ Code:** If you are developing or debugging Chromium itself, you can set breakpoints in `net/http/http_stream_pool_group.cc`, particularly in methods like:
   - `GetIdleStreamSocket()`: To see why an idle socket is (or isn't) being returned.
   - `ReleaseStreamSocket()`: To understand why a socket is being marked as reusable or not.
   - `IsIdleStreamSocketUsable()`: To inspect the conditions under which an idle socket is deemed unusable.
   - `CreateJob()`: To trace when new connection attempts are initiated.

By using these debugging tools and understanding the functionality of `HttpStreamPool::Group`, developers can diagnose issues related to HTTP connection management and optimize network performance in Chromium-based browsers.

### 提示词
```
这是目录为net/http/http_stream_pool_group.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_stream_pool_group.h"

#include "base/task/sequenced_task_runner.h"
#include "base/types/expected.h"
#include "net/base/completion_once_callback.h"
#include "net/base/load_timing_info.h"
#include "net/base/net_errors.h"
#include "net/http/http_basic_stream.h"
#include "net/http/http_network_session.h"
#include "net/http/http_stream.h"
#include "net/http/http_stream_key.h"
#include "net/http/http_stream_pool_attempt_manager.h"
#include "net/http/http_stream_pool_handle.h"
#include "net/log/net_log_event_type.h"
#include "net/socket/next_proto.h"
#include "net/socket/stream_socket.h"
#include "net/third_party/quiche/src/quiche/quic/core/quic_versions.h"

namespace net {

namespace {

bool IsNegotiatedProtocolTextBased(NextProto next_proto) {
  return next_proto == kProtoUnknown || next_proto == kProtoHTTP11;
}

void RecordNetLogClosingSocket(const StreamSocket& stream_socket,
                               std::string_view reason) {
  stream_socket.NetLog().AddEventWithStringParams(
      NetLogEventType::HTTP_STREAM_POOL_CLOSING_SOCKET, "reason", reason);
}

}  // namespace

// static
base::expected<void, std::string_view>
HttpStreamPool::Group::IsIdleStreamSocketUsable(const IdleStreamSocket& idle) {
  base::TimeDelta timeout = idle.stream_socket->WasEverUsed()
                                ? kUsedIdleStreamSocketTimeout
                                : kUnusedIdleStreamSocketTimeout;
  if (base::TimeTicks::Now() - idle.time_became_idle >= timeout) {
    return base::unexpected(kIdleTimeLimitExpired);
  }

  if (idle.stream_socket->WasEverUsed()) {
    if (idle.stream_socket->IsConnectedAndIdle()) {
      return base::ok();
    }
    if (idle.stream_socket->IsConnected()) {
      return base::unexpected(kDataReceivedUnexpectedly);
    } else {
      return base::unexpected(kRemoteSideClosedConnection);
    }
  }

  if (idle.stream_socket->IsConnected()) {
    return base::ok();
  }

  return base::unexpected(kRemoteSideClosedConnection);
}

HttpStreamPool::Group::IdleStreamSocket::IdleStreamSocket(
    std::unique_ptr<StreamSocket> stream_socket,
    base::TimeTicks time_became_idle)
    : stream_socket(std::move(stream_socket)),
      time_became_idle(time_became_idle) {}

HttpStreamPool::Group::IdleStreamSocket::~IdleStreamSocket() = default;

HttpStreamPool::Group::Group(
    HttpStreamPool* pool,
    HttpStreamKey stream_key,
    std::optional<QuicSessionAliasKey> quic_session_alias_key)
    : pool_(pool),
      stream_key_(std::move(stream_key)),
      spdy_session_key_(stream_key_.CalculateSpdySessionKey()),
      quic_session_alias_key_(quic_session_alias_key.has_value()
                                  ? std::move(*quic_session_alias_key)
                                  : stream_key_.CalculateQuicSessionAliasKey()),
      net_log_(
          NetLogWithSource::Make(http_network_session()->net_log(),
                                 NetLogSourceType::HTTP_STREAM_POOL_GROUP)),
      force_quic_(
          http_network_session()->ShouldForceQuic(stream_key_.destination(),
                                                  ProxyInfo::Direct(),
                                                  /*is_websocket=*/false)) {
  net_log_.BeginEvent(NetLogEventType::HTTP_STREAM_POOL_GROUP_ALIVE, [&] {
    base::Value::Dict dict;
    dict.Set("stream_key", stream_key_.ToValue());
    dict.Set("force_quic", force_quic_);
    return dict;
  });
}

HttpStreamPool::Group::~Group() {
  // TODO(crbug.com/346835898): Ensure `pool_`'s total active stream counts
  // are consistent.
  net_log_.EndEvent(NetLogEventType::HTTP_STREAM_POOL_GROUP_ALIVE);
}

std::unique_ptr<HttpStreamPool::Job> HttpStreamPool::Group::CreateJob(
    Job::Delegate* delegate,
    NextProto expected_protocol,
    bool is_http1_allowed,
    ProxyInfo proxy_info) {
  EnsureAttemptManager();
  return std::make_unique<Job>(delegate, attempt_manager_.get(),
                               expected_protocol, is_http1_allowed,
                               std::move(proxy_info));
}

int HttpStreamPool::Group::Preconnect(size_t num_streams,
                                      quic::ParsedQuicVersion quic_version,
                                      CompletionOnceCallback callback) {
  if (ActiveStreamSocketCount() >= num_streams) {
    return OK;
  }

  EnsureAttemptManager();
  return attempt_manager_->Preconnect(num_streams, quic_version,
                                      std::move(callback));
}

std::unique_ptr<HttpStreamPoolHandle> HttpStreamPool::Group::CreateHandle(
    std::unique_ptr<StreamSocket> socket,
    StreamSocketHandle::SocketReuseType reuse_type,
    LoadTimingInfo::ConnectTiming connect_timing) {
  ++handed_out_stream_count_;
  pool_->IncrementTotalHandedOutStreamCount();

  auto handle = std::make_unique<HttpStreamPoolHandle>(
      weak_ptr_factory_.GetWeakPtr(), std::move(socket), generation_);
  handle->set_connect_timing(connect_timing);
  handle->set_reuse_type(reuse_type);
  return handle;
}

std::unique_ptr<HttpStream> HttpStreamPool::Group::CreateTextBasedStream(
    std::unique_ptr<StreamSocket> socket,
    StreamSocketHandle::SocketReuseType reuse_type,
    LoadTimingInfo::ConnectTiming connect_timing) {
  CHECK(IsNegotiatedProtocolTextBased(socket->GetNegotiatedProtocol()));
  return std::make_unique<HttpBasicStream>(
      CreateHandle(std::move(socket), reuse_type, std::move(connect_timing)),
      /*is_for_get_to_http_proxy=*/false);
}

void HttpStreamPool::Group::ReleaseStreamSocket(
    std::unique_ptr<StreamSocket> socket,
    int64_t generation) {
  CHECK_GT(handed_out_stream_count_, 0u);
  --handed_out_stream_count_;
  pool_->DecrementTotalHandedOutStreamCount();

  bool reusable = false;
  std::string_view not_reusable_reason;
  if (!socket->IsConnectedAndIdle()) {
    not_reusable_reason = socket->IsConnected()
                              ? kDataReceivedUnexpectedly
                              : kClosedConnectionReturnedToPool;
  } else if (generation != generation_) {
    not_reusable_reason = kSocketGenerationOutOfDate;
  } else {
    reusable = true;
  }

  if (reusable) {
    AddIdleStreamSocket(std::move(socket));
    ProcessPendingRequest();
  } else {
    RecordNetLogClosingSocket(*socket, not_reusable_reason);
    socket.reset();
  }

  pool_->ProcessPendingRequestsInGroups();
  MaybeComplete();
}

void HttpStreamPool::Group::AddIdleStreamSocket(
    std::unique_ptr<StreamSocket> socket) {
  CHECK(socket->IsConnectedAndIdle());
  CHECK(IsNegotiatedProtocolTextBased(socket->GetNegotiatedProtocol()));
  CHECK_LE(ActiveStreamSocketCount(), pool_->max_stream_sockets_per_group());

  idle_stream_sockets_.emplace_back(std::move(socket), base::TimeTicks::Now());
  pool_->IncrementTotalIdleStreamCount();
  CleanupIdleStreamSockets(CleanupMode::kTimeoutOnly, kIdleTimeLimitExpired);
  MaybeComplete();
}

std::unique_ptr<StreamSocket> HttpStreamPool::Group::GetIdleStreamSocket() {
  // Iterate through the idle streams from oldtest to newest and try to find a
  // used idle stream. Prefer the newest used idle stream.
  auto idle_it = idle_stream_sockets_.end();
  for (auto it = idle_stream_sockets_.begin();
       it != idle_stream_sockets_.end();) {
    const base::expected<void, std::string_view> usable_result =
        IsIdleStreamSocketUsable(*it);
    if (!usable_result.has_value()) {
      RecordNetLogClosingSocket(*it->stream_socket, usable_result.error());
      it = idle_stream_sockets_.erase(it);
      pool_->DecrementTotalIdleStreamCount();
      continue;
    }
    if (it->stream_socket->WasEverUsed()) {
      idle_it = it;
    }
    ++it;
  }

  if (idle_stream_sockets_.empty()) {
    return nullptr;
  }

  if (idle_it == idle_stream_sockets_.end()) {
    // There are no used idle streams. Pick the oldest (first) idle streams
    // (FIFO).
    idle_it = idle_stream_sockets_.begin();
  }

  CHECK(idle_it != idle_stream_sockets_.end());

  std::unique_ptr<StreamSocket> stream_socket =
      std::move(idle_it->stream_socket);
  idle_stream_sockets_.erase(idle_it);
  pool_->DecrementTotalIdleStreamCount();

  return stream_socket;
}

void HttpStreamPool::Group::ProcessPendingRequest() {
  if (!attempt_manager_) {
    return;
  }
  attempt_manager_->ProcessPendingJob();
}

bool HttpStreamPool::Group::CloseOneIdleStreamSocket() {
  if (idle_stream_sockets_.empty()) {
    return false;
  }

  idle_stream_sockets_.pop_front();
  pool_->DecrementTotalIdleStreamCount();
  return true;
}

size_t HttpStreamPool::Group::ConnectingStreamSocketCount() const {
  return attempt_manager_ ? attempt_manager_->InFlightAttemptCount() : 0;
}

size_t HttpStreamPool::Group::ActiveStreamSocketCount() const {
  return handed_out_stream_count_ + idle_stream_sockets_.size() +
         ConnectingStreamSocketCount();
}

bool HttpStreamPool::Group::ReachedMaxStreamLimit() const {
  return ActiveStreamSocketCount() >= pool_->max_stream_sockets_per_group();
}

std::optional<RequestPriority>
HttpStreamPool::Group::GetPriorityIfStalledByPoolLimit() const {
  if (!attempt_manager_) {
    return std::nullopt;
  }

  return attempt_manager_->IsStalledByPoolLimit()
             ? std::make_optional(attempt_manager_->GetPriority())
             : std::nullopt;
}

void HttpStreamPool::Group::FlushWithError(
    int error,
    std::string_view net_log_close_reason_utf8) {
  // Refresh() may delete this. Get a weak pointer to this and call CancelJobs()
  // only when this is still alive.
  base::WeakPtr<Group> weak_this = weak_ptr_factory_.GetWeakPtr();
  Refresh(net_log_close_reason_utf8);
  if (weak_this) {
    CancelJobs(error);
  }
}

void HttpStreamPool::Group::Refresh(
    std::string_view net_log_close_reason_utf8) {
  ++generation_;
  CleanupIdleStreamSockets(CleanupMode::kForce, net_log_close_reason_utf8);
  if (attempt_manager_) {
    attempt_manager_->CancelInFlightAttempts();
  }
}

void HttpStreamPool::Group::CloseIdleStreams(
    std::string_view net_log_close_reason_utf8) {
  CleanupIdleStreamSockets(CleanupMode::kForce, net_log_close_reason_utf8);
  // Use PostTask since MaybeComplete() may delete `this`, and this method could
  // be called while iterating all groups.
  base::SequencedTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&Group::MaybeComplete, weak_ptr_factory_.GetWeakPtr()));
}

void HttpStreamPool::Group::CancelJobs(int error) {
  if (attempt_manager_) {
    attempt_manager_->CancelJobs(error);
  }
}

void HttpStreamPool::Group::OnRequiredHttp11() {
  if (attempt_manager_) {
    attempt_manager_->OnRequiredHttp11();
  }
}

void HttpStreamPool::Group::OnAttemptManagerComplete() {
  CHECK(attempt_manager_);
  attempt_manager_.reset();
  MaybeComplete();
}

base::Value::Dict HttpStreamPool::Group::GetInfoAsValue() const {
  base::Value::Dict dict;
  dict.Set("active_socket_count", static_cast<int>(ActiveStreamSocketCount()));
  dict.Set("idle_socket_count", static_cast<int>(IdleStreamSocketCount()));
  if (attempt_manager_) {
    dict.Merge(attempt_manager_->GetInfoAsValue());
  }
  return dict;
}

void HttpStreamPool::Group::CleanupTimedoutIdleStreamSocketsForTesting() {
  CleanupIdleStreamSockets(CleanupMode::kTimeoutOnly, "For testing");
}

void HttpStreamPool::Group::CleanupIdleStreamSockets(
    CleanupMode mode,
    std::string_view net_log_close_reason_utf8) {
  // Iterate though the idle sockets to delete any disconnected ones.
  for (auto it = idle_stream_sockets_.begin();
       it != idle_stream_sockets_.end();) {
    bool should_delete = mode == CleanupMode::kForce;
    const base::expected<void, std::string_view> usable_result =
        IsIdleStreamSocketUsable(*it);
    if (!usable_result.has_value()) {
      should_delete = true;
    }

    if (should_delete) {
      RecordNetLogClosingSocket(*it->stream_socket, net_log_close_reason_utf8);
      it = idle_stream_sockets_.erase(it);
      pool_->DecrementTotalIdleStreamCount();
    } else {
      ++it;
    }
  }
}

void HttpStreamPool::Group::EnsureAttemptManager() {
  if (attempt_manager_) {
    return;
  }
  attempt_manager_ =
      std::make_unique<AttemptManager>(this, http_network_session()->net_log());
}

void HttpStreamPool::Group::MaybeComplete() {
  if (ActiveStreamSocketCount() > 0 || attempt_manager_) {
    return;
  }

  pool_->OnGroupComplete(this);
  // `this` is deleted.
}

}  // namespace net
```