Response:
The user wants to understand the functionality of the `transport_client_socket_pool.cc` file in Chromium's networking stack. They're interested in how it relates to JavaScript, its internal logic, potential errors, and how user actions lead to its usage. The request is split into three parts, and this is part 1, focusing on summarizing the file's functions.

Here's a breakdown of the key functionalities I can identify from the provided code:

1. **Socket Pooling:** The core function is to manage a pool of transport layer sockets (likely TCP). This involves:
    * **Acquiring Sockets:**  Handling requests for sockets from higher layers.
    * **Reusing Sockets:**  Prioritizing the reuse of existing idle sockets to improve performance.
    * **Creating New Sockets:**  Establishing new connections when no suitable idle socket is available.
    * **Returning Sockets:** Managing sockets returned to the pool after use.
    * **Idle Socket Management:** Cleaning up idle sockets based on timeouts and events.
    * **Limits:** Enforcing limits on the total number of sockets and the number of sockets per destination group.

2. **Connection Management:**  Managing the underlying connections:
    * **Connect Jobs:**  Using `ConnectJob` objects to handle the asynchronous connection establishment process.
    * **Connection Backup:**  Potentially initiating backup connection attempts to improve latency if the initial connection is slow.
    * **Prioritization:**  Handling request priorities and applying them to connection attempts.
    * **Cancellation:**  Allowing the cancellation of socket requests and in-progress connections.

3. **State Tracking:**  Maintaining information about the state of the socket pool:
    * **Idle Sockets:**  Tracking available, reusable sockets.
    * **Active Sockets:**  Tracking sockets currently in use.
    * **Connecting Sockets:** Tracking sockets in the process of being established.
    * **Pending Requests:**  Managing requests that are waiting for an available socket.

4. **Integration with Network Events:** Reacting to changes in the network environment:
    * **IP Address Changes:**  Potentially invalidating and closing sockets on IP address changes.
    * **SSL Configuration Changes:**  Handling updates to SSL configurations and invalidating related sockets.

5. **Logging and Debugging:**  Providing mechanisms for logging network events for debugging and analysis.

6. **Interactions with Higher Layers:** Providing an interface for higher layers (like HTTP implementations) to request and manage sockets.

**Relation to JavaScript:** While the C++ code itself doesn't directly execute JavaScript, it's crucial for the functionality of web browsers, where JavaScript heavily relies on network requests. When a JavaScript application (e.g., using `fetch` or `XMLHttpRequest`) makes a network request, this code is involved in acquiring and managing the underlying TCP socket used for that request.

**Hypothetical Input/Output (Illustrative):**

* **Input:** A JavaScript `fetch()` call initiates a request to `https://example.com`.
* **Output:** The `RequestSocket` function in `transport_client_socket_pool.cc` is called, potentially leading to:
    * Returning an existing idle socket for `example.com` if one is available.
    * Creating a new `ConnectJob` to establish a TCP connection to `example.com` if no suitable idle socket exists.
    * Returning `ERR_IO_PENDING` if a new connection is being established asynchronously.

**User/Programming Errors:**

* **Premature Socket Release:** A higher-level component might incorrectly release a socket back to the pool while it's still in use. This can lead to unexpected data being received on subsequent requests. The code has checks (`IsUsable`) to try and detect this.
* **Not Handling `ERR_IO_PENDING`:** A component using the socket pool might fail to handle the asynchronous nature of socket acquisition, leading to errors if it expects a socket to be immediately available.

**User Actions Leading to This Code:**

1. **User types a URL in the address bar or clicks a link.**
2. **The browser's rendering engine starts loading resources for the page.**
3. **JavaScript code on the page makes an AJAX request.**
4. **The browser's network stack determines that a TCP connection is needed.**
5. **The request for a TCP socket reaches the `TransportClientSocketPool`.**

**Summary of Functionality (Part 1):**

The `TransportClientSocketPool` class is responsible for managing a pool of transport layer sockets (likely TCP) in Chromium's networking stack. It handles requests for sockets, prioritizes reuse of idle connections, establishes new connections when needed, and manages the lifecycle of these sockets. It interacts with higher layers of the network stack to provide reusable connections for network requests initiated by the browser, including those triggered by JavaScript code. It also incorporates mechanisms for handling network environment changes and logging for debugging.

这是 `net/socket/transport_client_socket_pool.cc` 文件的第一部分代码，其主要功能是**管理和复用传输层（通常是 TCP）的客户端套接字连接**。  它作为一个连接池，旨在提高网络请求的性能和效率。

以下是其功能的详细归纳：

**核心功能：客户端套接字连接池管理**

1. **请求套接字 (RequestSocket, RequestSockets, RequestSocketInternal):**
    *   接收来自上层（例如 HTTP 客户端）的套接字连接请求。
    *   可以请求单个或多个套接字。
    *   根据 `GroupId`（通常代表目标服务器的地址和端口）对连接进行分组。
    *   支持预连接 (preconnect) 以提前建立连接。

2. **套接字复用 (AssignIdleSocketToRequest):**
    *   优先尝试复用池中空闲的、已经建立的套接字，避免重复建立连接的开销。
    *   区分使用过和未使用过的空闲套接字，并根据情况进行复用。
    *   检查空闲套接字是否仍然可用（例如，是否已断开连接或收到意外数据）。

3. **建立新连接 (CreateConnectJob):**
    *   当没有可复用的空闲套接字时，创建 `ConnectJob` 对象来异步建立新的连接。
    *   `ConnectJob` 负责实际的连接过程。
    *   支持“备份连接”机制 (connect_backup_jobs_enabled)，在初始连接超时后尝试建立新的连接以提高性能。

4. **空闲套接字管理 (CleanupIdleSockets, CloseIdleSockets, CloseIdleSocketsInGroup):**
    *   定期清理超时未使用的空闲套接字，释放资源。
    *   可以强制关闭所有或特定组的空闲套接字。

5. **连接状态跟踪:**
    *   维护当前连接池的状态，包括空闲连接数、正在连接的连接数、已分配的连接数等。
    *   跟踪每个连接组的状态。

6. **请求排队和优先级 (Request 结构体, SetPriority):**
    *   当没有可用连接时，将请求放入队列中等待。
    *   支持请求优先级，高优先级的请求会优先获得连接。

7. **连接取消 (CancelRequest):**
    *   允许取消正在进行的套接字请求。
    *   可以选择是否取消正在进行的连接建立任务。

8. **网络事件处理 (OnIPAddressChanged, OnSSLConfigChanged, OnSSLConfigForServersChanged):**
    *   监听网络状态变化事件（例如 IP 地址变化），并根据需要清理连接池中的连接。
    *   监听 SSL 配置变化事件，并使旧的 SSL 连接失效。

9. **负载状态查询 (GetLoadState):**
    *   允许查询特定连接组的负载状态，例如是否正在连接、等待可用连接等。

10. **调试和监控 (GetInfoAsValue):**
    *   提供获取连接池内部状态信息的方法，用于调试和监控。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不包含 JavaScript 代码，但它是 Chromium 浏览器网络栈的核心组成部分，直接支持了 JavaScript 发起的网络请求。

**举例说明：**

当 JavaScript 代码通过 `fetch()` API 或 `XMLHttpRequest` 对象发起一个 HTTPS 请求时，底层的网络请求过程会涉及 `TransportClientSocketPool`：

1. **JavaScript 发起请求:**  `fetch('https://example.com')`
2. **网络栈处理:**  Chromium 的网络栈接收到请求，需要建立到 `example.com` 的 HTTPS 连接。
3. **请求套接字:**  会调用 `TransportClientSocketPool::RequestSocket`，传入目标地址（`example.com` 的主机名和端口）等信息。
4. **连接池查找:**
    *   如果连接池中存在到 `example.com` 的空闲连接，`AssignIdleSocketToRequest` 会将其分配给该请求。
    *   如果没有空闲连接，`RequestSocketInternal` 会创建一个新的 `ConnectJob` 来建立连接。
5. **连接建立:**  `ConnectJob` 执行实际的 TCP 握手和 TLS 握手。
6. **套接字返回:**  连接建立成功后，套接字会被返回给上层，用于发送和接收 HTTP 数据。

**逻辑推理：**

**假设输入：**

*   一个 JavaScript 发起的 `fetch('https://api.example.com/data')` 请求。
*   连接池中没有到 `api.example.com` 的空闲连接。
*   `max_sockets_per_group` 设置为 5。
*   当前连接池中到 `api.example.com` 的正在连接的套接字数量为 3。

**输出：**

*   `RequestSocketInternal` 会创建一个新的 `ConnectJob` 来建立到 `api.example.com` 的连接。
*   `connecting_socket_count_` 会增加。
*   如果当前总的连接数没有超过 `max_sockets_` 限制，连接建立过程会继续。

**用户或编程常见的使用错误：**

1. **过早释放套接字：**  上层代码（例如 HTTP 客户端）可能在连接还在使用时就错误地将其释放回连接池。这会导致后续的请求可能会在未完成的连接上发送数据，导致错误。
2. **未处理 `ERR_IO_PENDING`：**  `RequestSocket` 等方法在需要异步建立连接时会返回 `ERR_IO_PENDING`。如果上层代码没有正确处理这种情况，可能会导致程序逻辑错误。
3. **不合理的连接池大小配置：**  `max_sockets` 和 `max_sockets_per_group` 的配置不合理可能导致连接池资源不足或浪费。

**用户操作到达此处的调试线索：**

1. 用户在浏览器地址栏输入 `https://example.com` 并按下回车。
2. 浏览器解析 URL，发现需要建立 HTTPS 连接。
3. 浏览器网络栈开始处理该请求。
4. `TransportClientSocketPool::RequestSocket` 被调用，尝试获取到 `example.com` 的 TCP 连接。
5. 如果在调试器中设置断点在这个文件中，就可以观察到连接池的状态和请求的处理流程。

**总结：**

`TransportClientSocketPool` 是 Chromium 网络栈中负责高效管理和复用传输层客户端套接字连接的关键组件。它接收来自上层的连接请求，尝试复用现有连接，并在必要时建立新的连接。它与 JavaScript 发起的网络请求紧密相关，并通过复用连接来提高网络性能。理解其工作原理有助于调试网络问题和优化网络性能。

### 提示词
```
这是目录为net/socket/transport_client_socket_pool.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/socket/transport_client_socket_pool.h"

#include <string_view>
#include <utility>

#include "base/auto_reset.h"
#include "base/barrier_closure.h"
#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/containers/contains.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/host_port_pair.h"
#include "net/base/net_errors.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_server.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/socket/connect_job_factory.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "url/gurl.h"

namespace net {

namespace {

// Indicate whether or not we should establish a new transport layer connection
// after a certain timeout has passed without receiving an ACK.
bool g_connect_backup_jobs_enabled = true;

base::Value::Dict NetLogCreateConnectJobParams(
    bool backup_job,
    const ClientSocketPool::GroupId* group_id) {
  return base::Value::Dict()
      .Set("backup_job", backup_job)
      .Set("group_id", group_id->ToString());
}

}  // namespace

const char TransportClientSocketPool::kCertDatabaseChanged[] =
    "Cert database changed";
const char TransportClientSocketPool::kCertVerifierChanged[] =
    "Cert verifier changed";
const char TransportClientSocketPool::kClosedConnectionReturnedToPool[] =
    "Connection was closed when it was returned to the pool";
const char TransportClientSocketPool::kDataReceivedUnexpectedly[] =
    "Data received unexpectedly";
const char TransportClientSocketPool::kIdleTimeLimitExpired[] =
    "Idle time limit expired";
const char TransportClientSocketPool::kNetworkChanged[] = "Network changed";
const char TransportClientSocketPool::kRemoteSideClosedConnection[] =
    "Remote side closed connection";
const char TransportClientSocketPool::kSocketGenerationOutOfDate[] =
    "Socket generation out of date";
const char TransportClientSocketPool::kSocketPoolDestroyed[] =
    "Socket pool destroyed";
const char TransportClientSocketPool::kSslConfigChanged[] =
    "SSL configuration changed";

TransportClientSocketPool::Request::Request(
    ClientSocketHandle* handle,
    CompletionOnceCallback callback,
    const ProxyAuthCallback& proxy_auth_callback,
    RequestPriority priority,
    const SocketTag& socket_tag,
    RespectLimits respect_limits,
    Flags flags,
    scoped_refptr<SocketParams> socket_params,
    const std::optional<NetworkTrafficAnnotationTag>& proxy_annotation_tag,
    const NetLogWithSource& net_log)
    : handle_(handle),
      callback_(std::move(callback)),
      proxy_auth_callback_(proxy_auth_callback),
      priority_(priority),
      respect_limits_(respect_limits),
      flags_(flags),
      socket_params_(std::move(socket_params)),
      proxy_annotation_tag_(proxy_annotation_tag),
      net_log_(net_log),
      socket_tag_(socket_tag) {
  if (respect_limits_ == ClientSocketPool::RespectLimits::DISABLED)
    DCHECK_EQ(priority_, MAXIMUM_PRIORITY);
}

TransportClientSocketPool::Request::~Request() = default;

void TransportClientSocketPool::Request::AssignJob(ConnectJob* job) {
  DCHECK(job);
  DCHECK(!job_);
  job_ = job;
  if (job_->priority() != priority_)
    job_->ChangePriority(priority_);
}

ConnectJob* TransportClientSocketPool::Request::ReleaseJob() {
  DCHECK(job_);
  ConnectJob* job = job_;
  job_ = nullptr;
  return job;
}

struct TransportClientSocketPool::IdleSocket {
  // An idle socket can't be used if it is disconnected or has been used
  // before and has received data unexpectedly (hence no longer idle).  The
  // unread data would be mistaken for the beginning of the next response if
  // we were to use the socket for a new request.
  //
  // Note that a socket that has never been used before (like a preconnected
  // socket) may be used even with unread data.  This may be, e.g., a SPDY
  // SETTINGS frame.
  //
  // If the socket is not usable, |net_log_reason_utf8| is set to a string
  // indicating why the socket is not usable.
  bool IsUsable(const char** net_log_reason_utf8) const;

  std::unique_ptr<StreamSocket> socket;
  base::TimeTicks start_time;
};

TransportClientSocketPool::TransportClientSocketPool(
    int max_sockets,
    int max_sockets_per_group,
    base::TimeDelta unused_idle_socket_timeout,
    const ProxyChain& proxy_chain,
    bool is_for_websockets,
    const CommonConnectJobParams* common_connect_job_params,
    bool cleanup_on_ip_address_change)
    : TransportClientSocketPool(max_sockets,
                                max_sockets_per_group,
                                unused_idle_socket_timeout,
                                ClientSocketPool::used_idle_socket_timeout(),
                                proxy_chain,
                                is_for_websockets,
                                common_connect_job_params,
                                cleanup_on_ip_address_change,
                                std::make_unique<ConnectJobFactory>(),
                                common_connect_job_params->ssl_client_context,
                                /*connect_backup_jobs_enabled=*/true) {}

TransportClientSocketPool::~TransportClientSocketPool() {
  // Clean up any idle sockets and pending connect jobs.  Assert that we have no
  // remaining active sockets or pending requests.  They should have all been
  // cleaned up prior to |this| being destroyed.
  FlushWithError(ERR_ABORTED, kSocketPoolDestroyed);
  DCHECK(group_map_.empty());
  DCHECK(pending_callback_map_.empty());
  DCHECK_EQ(0, connecting_socket_count_);
  DCHECK_EQ(0, handed_out_socket_count_);
  CHECK(higher_pools_.empty());

  if (ssl_client_context_)
    ssl_client_context_->RemoveObserver(this);

  if (cleanup_on_ip_address_change_)
    NetworkChangeNotifier::RemoveIPAddressObserver(this);
}

std::unique_ptr<TransportClientSocketPool>
TransportClientSocketPool::CreateForTesting(
    int max_sockets,
    int max_sockets_per_group,
    base::TimeDelta unused_idle_socket_timeout,
    base::TimeDelta used_idle_socket_timeout,
    const ProxyChain& proxy_chain,
    bool is_for_websockets,
    const CommonConnectJobParams* common_connect_job_params,
    std::unique_ptr<ConnectJobFactory> connect_job_factory,
    SSLClientContext* ssl_client_context,
    bool connect_backup_jobs_enabled) {
  return base::WrapUnique<TransportClientSocketPool>(
      new TransportClientSocketPool(
          max_sockets, max_sockets_per_group, unused_idle_socket_timeout,
          used_idle_socket_timeout, proxy_chain, is_for_websockets,
          common_connect_job_params, /*cleanup_on_ip_address_change=*/true,
          std::move(connect_job_factory), ssl_client_context,
          connect_backup_jobs_enabled));
}

TransportClientSocketPool::CallbackResultPair::CallbackResultPair()
    : result(OK) {}

TransportClientSocketPool::CallbackResultPair::CallbackResultPair(
    CompletionOnceCallback callback_in,
    int result_in)
    : callback(std::move(callback_in)), result(result_in) {}

TransportClientSocketPool::CallbackResultPair::CallbackResultPair(
    TransportClientSocketPool::CallbackResultPair&& other) = default;

TransportClientSocketPool::CallbackResultPair&
TransportClientSocketPool::CallbackResultPair::operator=(
    TransportClientSocketPool::CallbackResultPair&& other) = default;

TransportClientSocketPool::CallbackResultPair::~CallbackResultPair() = default;

bool TransportClientSocketPool::IsStalled() const {
  // If fewer than |max_sockets_| are in use, then clearly |this| is not
  // stalled.
  if ((handed_out_socket_count_ + connecting_socket_count_) < max_sockets_)
    return false;
  // So in order to be stalled, |this| must be using at least |max_sockets_| AND
  // |this| must have a request that is actually stalled on the global socket
  // limit.  To find such a request, look for a group that has more requests
  // than jobs AND where the number of sockets is less than
  // |max_sockets_per_group_|.  (If the number of sockets is equal to
  // |max_sockets_per_group_|, then the request is stalled on the group limit,
  // which does not count.)
  for (const auto& it : group_map_) {
    if (it.second->CanUseAdditionalSocketSlot(max_sockets_per_group_))
      return true;
  }
  return false;
}

void TransportClientSocketPool::AddHigherLayeredPool(
    HigherLayeredPool* higher_pool) {
  CHECK(higher_pool);
  CHECK(!base::Contains(higher_pools_, higher_pool));
  higher_pools_.insert(higher_pool);
}

void TransportClientSocketPool::RemoveHigherLayeredPool(
    HigherLayeredPool* higher_pool) {
  CHECK(higher_pool);
  CHECK(base::Contains(higher_pools_, higher_pool));
  higher_pools_.erase(higher_pool);
}

int TransportClientSocketPool::RequestSocket(
    const GroupId& group_id,
    scoped_refptr<SocketParams> params,
    const std::optional<NetworkTrafficAnnotationTag>& proxy_annotation_tag,
    RequestPriority priority,
    const SocketTag& socket_tag,
    RespectLimits respect_limits,
    ClientSocketHandle* handle,
    CompletionOnceCallback callback,
    const ProxyAuthCallback& proxy_auth_callback,
    const NetLogWithSource& net_log) {
  CHECK(callback);
  CHECK(handle);

  NetLogTcpClientSocketPoolRequestedSocket(net_log, group_id);

  std::unique_ptr<Request> request = std::make_unique<Request>(
      handle, std::move(callback), proxy_auth_callback, priority, socket_tag,
      respect_limits, NORMAL, std::move(params), proxy_annotation_tag, net_log);

  // Cleanup any timed-out idle sockets.
  CleanupIdleSockets(false, nullptr /* net_log_reason_utf8 */);

  request->net_log().BeginEvent(NetLogEventType::SOCKET_POOL);

  int rv =
      RequestSocketInternal(group_id, *request,
                            /*preconnect_done_closure=*/base::OnceClosure());
  if (rv != ERR_IO_PENDING) {
    if (rv == OK) {
      request->handle()->socket()->ApplySocketTag(request->socket_tag());
    }
    request->net_log().EndEventWithNetErrorCode(NetLogEventType::SOCKET_POOL,
                                                rv);
    CHECK(!request->handle()->is_initialized());
    request.reset();
  } else {
    Group* group = GetOrCreateGroup(group_id);
    group->InsertUnboundRequest(std::move(request));
    // Have to do this asynchronously, as closing sockets in higher level pools
    // call back in to |this|, which will cause all sorts of fun and exciting
    // re-entrancy issues if the socket pool is doing something else at the
    // time.
    if (group->CanUseAdditionalSocketSlot(max_sockets_per_group_)) {
      base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
          FROM_HERE,
          base::BindOnce(
              &TransportClientSocketPool::TryToCloseSocketsInLayeredPools,
              weak_factory_.GetWeakPtr()));
    }
  }
  return rv;
}

int TransportClientSocketPool::RequestSockets(
    const GroupId& group_id,
    scoped_refptr<SocketParams> params,
    const std::optional<NetworkTrafficAnnotationTag>& proxy_annotation_tag,
    int num_sockets,
    CompletionOnceCallback callback,
    const NetLogWithSource& net_log) {
  // TODO(eroman): Split out the host and port parameters.
  net_log.AddEvent(NetLogEventType::TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKETS,
                   [&] { return NetLogGroupIdParams(group_id); });

  Request request(nullptr /* no handle */, CompletionOnceCallback(),
                  ProxyAuthCallback(), IDLE, SocketTag(),
                  RespectLimits::ENABLED, NO_IDLE_SOCKETS, std::move(params),
                  proxy_annotation_tag, net_log);

  // Cleanup any timed-out idle sockets.
  CleanupIdleSockets(false, nullptr /* net_log_reason_utf8 */);

  if (num_sockets > max_sockets_per_group_) {
    num_sockets = max_sockets_per_group_;
  }

  request.net_log().BeginEventWithIntParams(
      NetLogEventType::SOCKET_POOL_CONNECTING_N_SOCKETS, "num_sockets",
      num_sockets);

  Group* group = GetOrCreateGroup(group_id);

  // RequestSocketsInternal() may delete the group.
  bool deleted_group = false;

  int rv = OK;

  base::RepeatingClosure preconnect_done_closure = base::BarrierClosure(
      num_sockets,
      base::BindOnce(
          [](CompletionOnceCallback callback) {
            base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
                FROM_HERE, base::BindOnce(std::move(callback), OK));
          },
          std::move(callback)));
  int pending_connect_job_count = 0;
  for (int num_iterations_left = num_sockets;
       group->NumActiveSocketSlots() < num_sockets && num_iterations_left > 0;
       num_iterations_left--) {
    rv = RequestSocketInternal(group_id, request, preconnect_done_closure);
    if (rv == ERR_IO_PENDING) {
      ++pending_connect_job_count;
    }
    if (rv < 0 && rv != ERR_IO_PENDING) {
      // We're encountering a synchronous error.  Give up.
      if (!base::Contains(group_map_, group_id))
        deleted_group = true;
      break;
    }
    if (!base::Contains(group_map_, group_id)) {
      // Unexpected.  The group should only be getting deleted on synchronous
      // error.
      NOTREACHED();
    }
  }

  if (!deleted_group && group->IsEmpty())
    RemoveGroup(group_id);

  if (rv == ERR_IO_PENDING)
    rv = OK;
  request.net_log().EndEventWithNetErrorCode(
      NetLogEventType::SOCKET_POOL_CONNECTING_N_SOCKETS, rv);

  // Currently we don't handle preconnect errors. So this method returns OK even
  // if failed to preconnect.
  // TODO(crbug.com/40843081): Consider support error handlings when needed.
  if (pending_connect_job_count == 0)
    return OK;
  for (int i = 0; i < num_sockets - pending_connect_job_count; ++i) {
    preconnect_done_closure.Run();
  }

  return ERR_IO_PENDING;
}

int TransportClientSocketPool::RequestSocketInternal(
    const GroupId& group_id,
    const Request& request,
    base::OnceClosure preconnect_done_closure) {
#if DCHECK_IS_ON()
  DCHECK(!request_in_process_);
  base::AutoReset<bool> auto_reset(&request_in_process_, true);
#endif  // DCHECK_IS_ON()

  ClientSocketHandle* const handle = request.handle();
  const bool preconnecting = !handle;
  DCHECK_EQ(preconnecting, !!preconnect_done_closure);

  Group* group = nullptr;
  auto group_it = group_map_.find(group_id);
  if (group_it != group_map_.end()) {
    group = group_it->second;

    if (!(request.flags() & NO_IDLE_SOCKETS)) {
      // Try to reuse a socket.
      if (AssignIdleSocketToRequest(request, group))
        return OK;
    }

    // If there are more ConnectJobs than pending requests, don't need to do
    // anything.  Can just wait for the extra job to connect, and then assign it
    // to the request.
    if (!preconnecting && group->TryToUseNeverAssignedConnectJob())
      return ERR_IO_PENDING;

    // Can we make another active socket now?
    if (!group->HasAvailableSocketSlot(max_sockets_per_group_) &&
        request.respect_limits() == RespectLimits::ENABLED) {
      // TODO(willchan): Consider whether or not we need to close a socket in a
      // higher layered group. I don't think this makes sense since we would
      // just reuse that socket then if we needed one and wouldn't make it down
      // to this layer.
      request.net_log().AddEvent(
          NetLogEventType::SOCKET_POOL_STALLED_MAX_SOCKETS_PER_GROUP);
      return preconnecting ? ERR_PRECONNECT_MAX_SOCKET_LIMIT : ERR_IO_PENDING;
    }
  }

  if (ReachedMaxSocketsLimit() &&
      request.respect_limits() == RespectLimits::ENABLED) {
    // NOTE(mmenke):  Wonder if we really need different code for each case
    // here.  Only reason for them now seems to be preconnects.
    if (idle_socket_count_ > 0) {
      // There's an idle socket in this pool. Either that's because there's
      // still one in this group, but we got here due to preconnecting
      // bypassing idle sockets, or because there's an idle socket in another
      // group.
      bool closed = CloseOneIdleSocketExceptInGroup(group);
      if (preconnecting && !closed)
        return ERR_PRECONNECT_MAX_SOCKET_LIMIT;
    } else {
      // We could check if we really have a stalled group here, but it
      // requires a scan of all groups, so just flip a flag here, and do the
      // check later.
      request.net_log().AddEvent(
          NetLogEventType::SOCKET_POOL_STALLED_MAX_SOCKETS);
      return preconnecting ? ERR_PRECONNECT_MAX_SOCKET_LIMIT : ERR_IO_PENDING;
    }
  }

  // We couldn't find a socket to reuse, and there's space to allocate one,
  // so allocate and connect a new one.
  group = GetOrCreateGroup(group_id);
  std::unique_ptr<ConnectJob> connect_job(
      CreateConnectJob(group_id, request.socket_params(), proxy_chain_,
                       request.proxy_annotation_tag(), request.priority(),
                       request.socket_tag(), group));
  connect_job->net_log().AddEvent(
      NetLogEventType::SOCKET_POOL_CONNECT_JOB_CREATED, [&] {
        return NetLogCreateConnectJobParams(false /* backup_job */, &group_id);
      });

  int rv = connect_job->Connect();
  if (rv == ERR_IO_PENDING) {
    if (preconnect_done_closure) {
      DCHECK(preconnecting);
      connect_job->set_done_closure(std::move(preconnect_done_closure));
    }
    // If we didn't have any sockets in this group, set a timer for potentially
    // creating a new one.  If the SYN is lost, this backup socket may complete
    // before the slow socket, improving end user latency.
    if (connect_backup_jobs_enabled_ && group->IsEmpty())
      group->StartBackupJobTimer(group_id);
    group->AddJob(std::move(connect_job), preconnecting);
    connecting_socket_count_++;
    return rv;
  }

  LogBoundConnectJobToRequest(connect_job->net_log().source(), request);
  if (preconnecting) {
    if (rv == OK)
      AddIdleSocket(connect_job->PassSocket(), group);
  } else {
    DCHECK(handle);
    if (rv != OK)
      handle->SetAdditionalErrorState(connect_job.get());
    std::unique_ptr<StreamSocket> socket = connect_job->PassSocket();
    if (socket) {
      HandOutSocket(std::move(socket),
                    StreamSocketHandle::SocketReuseType::kUnused,
                    connect_job->connect_timing(), handle,
                    /*time_idle=*/base::TimeDelta(), group, request.net_log());
    }
  }
  if (group->IsEmpty())
    RemoveGroup(group_id);

  return rv;
}

bool TransportClientSocketPool::AssignIdleSocketToRequest(
    const Request& request,
    Group* group) {
  std::list<IdleSocket>* idle_sockets = group->mutable_idle_sockets();
  auto idle_socket_it = idle_sockets->end();

  // Iterate through the idle sockets forwards (oldest to newest)
  //   * Delete any disconnected ones.
  //   * If we find a used idle socket, assign to |idle_socket|.  At the end,
  //   the |idle_socket_it| will be set to the newest used idle socket.
  for (auto it = idle_sockets->begin(); it != idle_sockets->end();) {
    // Check whether socket is usable. Note that it's unlikely that the socket
    // is not usable because this function is always invoked after a
    // reusability check, but in theory socket can be closed asynchronously.
    const char* net_log_reason_utf8;
    if (!it->IsUsable(&net_log_reason_utf8)) {
      it->socket->NetLog().AddEventWithStringParams(
          NetLogEventType::SOCKET_POOL_CLOSING_SOCKET, "reason",
          net_log_reason_utf8);
      DecrementIdleCount();
      it = idle_sockets->erase(it);
      continue;
    }

    if (it->socket->WasEverUsed()) {
      // We found one we can reuse!
      idle_socket_it = it;
    }

    ++it;
  }

  // If we haven't found an idle socket, that means there are no used idle
  // sockets.  Pick the oldest (first) idle socket (FIFO).

  if (idle_socket_it == idle_sockets->end() && !idle_sockets->empty())
    idle_socket_it = idle_sockets->begin();

  if (idle_socket_it != idle_sockets->end()) {
    DecrementIdleCount();
    base::TimeDelta idle_time =
        base::TimeTicks::Now() - idle_socket_it->start_time;
    std::unique_ptr<StreamSocket> socket = std::move(idle_socket_it->socket);
    idle_sockets->erase(idle_socket_it);
    // TODO(davidben): If |idle_time| is under some low watermark, consider
    // treating as UNUSED rather than UNUSED_IDLE. This will avoid
    // HttpNetworkTransaction retrying on some errors.
    ClientSocketHandle::SocketReuseType reuse_type =
        socket->WasEverUsed()
            ? StreamSocketHandle::SocketReuseType::kReusedIdle
            : StreamSocketHandle::SocketReuseType::kUnusedIdle;

    HandOutSocket(std::move(socket), reuse_type,
                  LoadTimingInfo::ConnectTiming(), request.handle(), idle_time,
                  group, request.net_log());
    return true;
  }

  return false;
}

// static
void TransportClientSocketPool::LogBoundConnectJobToRequest(
    const NetLogSource& connect_job_source,
    const Request& request) {
  request.net_log().AddEventReferencingSource(
      NetLogEventType::SOCKET_POOL_BOUND_TO_CONNECT_JOB, connect_job_source);
}

void TransportClientSocketPool::SetPriority(const GroupId& group_id,
                                            ClientSocketHandle* handle,
                                            RequestPriority priority) {
  auto group_it = group_map_.find(group_id);
  if (group_it == group_map_.end()) {
    DCHECK(base::Contains(pending_callback_map_, handle));
    // The Request has already completed and been destroyed; nothing to
    // reprioritize.
    return;
  }

  group_it->second->SetPriority(handle, priority);
}

void TransportClientSocketPool::CancelRequest(const GroupId& group_id,
                                              ClientSocketHandle* handle,
                                              bool cancel_connect_job) {
  auto callback_it = pending_callback_map_.find(handle);
  if (callback_it != pending_callback_map_.end()) {
    int result = callback_it->second.result;
    pending_callback_map_.erase(callback_it);
    std::unique_ptr<StreamSocket> socket = handle->PassSocket();
    if (socket) {
      if (result != OK) {
        socket->Disconnect();
      } else if (cancel_connect_job) {
        // Close the socket if |cancel_connect_job| is true and there are no
        // other pending requests.
        Group* group = GetOrCreateGroup(group_id);
        if (group->unbound_request_count() == 0)
          socket->Disconnect();
      }
      ReleaseSocket(handle->group_id(), std::move(socket),
                    handle->group_generation());
    }
    return;
  }

  CHECK(base::Contains(group_map_, group_id));
  Group* group = GetOrCreateGroup(group_id);

  std::unique_ptr<Request> request = group->FindAndRemoveBoundRequest(handle);
  if (request) {
    --connecting_socket_count_;
    OnAvailableSocketSlot(group_id, group);
    CheckForStalledSocketGroups();
    return;
  }

  // Search |unbound_requests_| for matching handle.
  request = group->FindAndRemoveUnboundRequest(handle);
  if (request) {
    request->net_log().AddEvent(NetLogEventType::CANCELLED);
    request->net_log().EndEvent(NetLogEventType::SOCKET_POOL);

    // Let the job run, unless |cancel_connect_job| is true, or we're at the
    // socket limit and there are no other requests waiting on the job.
    bool reached_limit = ReachedMaxSocketsLimit();
    if (group->jobs().size() > group->unbound_request_count() &&
        (cancel_connect_job || reached_limit)) {
      RemoveConnectJob(group->jobs().begin()->get(), group);
      if (group->IsEmpty())
        RemoveGroup(group->group_id());
      if (reached_limit)
        CheckForStalledSocketGroups();
    }
  }
}

void TransportClientSocketPool::CloseIdleSockets(
    const char* net_log_reason_utf8) {
  CleanupIdleSockets(true, net_log_reason_utf8);
  DCHECK_EQ(0, idle_socket_count_);
}

void TransportClientSocketPool::CloseIdleSocketsInGroup(
    const GroupId& group_id,
    const char* net_log_reason_utf8) {
  if (idle_socket_count_ == 0)
    return;
  auto it = group_map_.find(group_id);
  if (it == group_map_.end())
    return;
  CleanupIdleSocketsInGroup(true, it->second, base::TimeTicks::Now(),
                            net_log_reason_utf8);
  if (it->second->IsEmpty())
    RemoveGroup(it);
}

int TransportClientSocketPool::IdleSocketCount() const {
  return idle_socket_count_;
}

size_t TransportClientSocketPool::IdleSocketCountInGroup(
    const GroupId& group_id) const {
  auto i = group_map_.find(group_id);
  CHECK(i != group_map_.end());

  return i->second->idle_sockets().size();
}

LoadState TransportClientSocketPool::GetLoadState(
    const GroupId& group_id,
    const ClientSocketHandle* handle) const {
  if (base::Contains(pending_callback_map_, handle))
    return LOAD_STATE_CONNECTING;

  auto group_it = group_map_.find(group_id);
  if (group_it == group_map_.end()) {
    // TODO(mmenke):  This is actually reached in the wild, for unknown reasons.
    // Would be great to understand why, and if it's a bug, fix it.  If not,
    // should have a test for that case.
    NOTREACHED();
  }

  const Group& group = *group_it->second;
  ConnectJob* job = group.GetConnectJobForHandle(handle);
  if (job)
    return job->GetLoadState();

  if (group.CanUseAdditionalSocketSlot(max_sockets_per_group_))
    return LOAD_STATE_WAITING_FOR_STALLED_SOCKET_POOL;
  return LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET;
}

base::Value TransportClientSocketPool::GetInfoAsValue(
    const std::string& name,
    const std::string& type) const {
  // TODO(mmenke): This currently doesn't return bound Requests or ConnectJobs.
  auto dict = base::Value::Dict()
                  .Set("name", name)
                  .Set("type", type)
                  .Set("handed_out_socket_count", handed_out_socket_count_)
                  .Set("connecting_socket_count", connecting_socket_count_)
                  .Set("idle_socket_count", idle_socket_count_)
                  .Set("max_socket_count", max_sockets_)
                  .Set("max_sockets_per_group", max_sockets_per_group_);

  if (group_map_.empty())
    return base::Value(std::move(dict));

  base::Value::Dict all_groups_dict;
  for (const auto& entry : group_map_) {
    const Group* group = entry.second;

    base::Value::List idle_socket_list;
    for (const auto& idle_socket : group->idle_sockets()) {
      int source_id = idle_socket.socket->NetLog().source().id;
      idle_socket_list.Append(source_id);
    }

    base::Value::List connect_jobs_list;
    for (const auto& job : group->jobs()) {
      int source_id = job->net_log().source().id;
      connect_jobs_list.Append(source_id);
    }

    auto group_dict =
        base::Value::Dict()
            .Set("pending_request_count",
                 static_cast<int>(group->unbound_request_count()))
            .Set("active_socket_count", group->active_socket_count())
            .Set("idle_sockets", std::move(idle_socket_list))
            .Set("connect_jobs", std::move(connect_jobs_list))
            .Set("is_stalled",
                 group->CanUseAdditionalSocketSlot(max_sockets_per_group_))
            .Set("backup_job_timer_is_running",
                 group->BackupJobTimerIsRunning());

    if (group->has_unbound_requests()) {
      group_dict.Set("top_pending_priority",
                     RequestPriorityToString(group->TopPendingPriority()));
    }

    all_groups_dict.Set(entry.first.ToString(), std::move(group_dict));
  }
  dict.Set("groups", std::move(all_groups_dict));
  return base::Value(std::move(dict));
}

bool TransportClientSocketPool::HasActiveSocket(const GroupId& group_id) const {
  return HasGroup(group_id);
}

bool TransportClientSocketPool::IdleSocket::IsUsable(
    const char** net_log_reason_utf8) const {
  DCHECK(net_log_reason_utf8);
  if (socket->WasEverUsed()) {
    if (!socket->IsConnectedAndIdle()) {
      if (!socket->IsConnected()) {
        *net_log_reason_utf8 = kRemoteSideClosedConnection;
      } else {
        *net_log_reason_utf8 = kDataReceivedUnexpectedly;
      }
      return false;
    }
    return true;
  }

  if (!socket->IsConnected()) {
    *net_log_reason_utf8 = kRemoteSideClosedConnection;
    return false;
  }
  return true;
}

TransportClientSocketPool::TransportClientSocketPool(
    int max_sockets,
    int max_sockets_per_group,
    base::TimeDelta unused_idle_socket_timeout,
    base::TimeDelta used_idle_socket_timeout,
    const ProxyChain& proxy_chain,
    bool is_for_websockets,
    const CommonConnectJobParams* common_connect_job_params,
    bool cleanup_on_ip_address_change,
    std::unique_ptr<ConnectJobFactory> connect_job_factory,
    SSLClientContext* ssl_client_context,
    bool connect_backup_jobs_enabled)
    : ClientSocketPool(is_for_websockets,
                       common_connect_job_params,
                       std::move(connect_job_factory)),
      max_sockets_(max_sockets),
      max_sockets_per_group_(max_sockets_per_group),
      unused_idle_socket_timeout_(unused_idle_socket_timeout),
      used_idle_socket_timeout_(used_idle_socket_timeout),
      proxy_chain_(proxy_chain),
      cleanup_on_ip_address_change_(cleanup_on_ip_address_change),
      connect_backup_jobs_enabled_(connect_backup_jobs_enabled &&
                                   g_connect_backup_jobs_enabled),
      ssl_client_context_(ssl_client_context) {
  DCHECK_LE(0, max_sockets_per_group);
  DCHECK_LE(max_sockets_per_group, max_sockets);

  if (cleanup_on_ip_address_change_)
    NetworkChangeNotifier::AddIPAddressObserver(this);

  if (ssl_client_context_)
    ssl_client_context_->AddObserver(this);
}

void TransportClientSocketPool::OnSSLConfigChanged(
    SSLClientContext::SSLConfigChangeType change_type) {
  const char* message = nullptr;
  // When the SSL config or cert verifier config changes, flush all idle
  // sockets so they won't get re-used, and allow any active sockets to finish,
  // but don't put them back in the socket pool.
  switch (change_type) {
    case SSLClientContext::SSLConfigChangeType::kSSLConfigChanged:
      message = kNetworkChanged;
      break;
    case SSLClientContext::SSLConfigChangeType::kCertDatabaseChanged:
      message = kCertDatabaseChanged;
      break;
    case SSLClientContext::SSLConfigChangeType::kCertVerifierChanged:
      message = kCertVerifierChanged;
      break;
  };

  base::TimeTicks now = base::TimeTicks::Now();
  for (auto it = group_map_.begin(); it != group_map_.end();) {
    it = RefreshGroup(it, now, message);
  }
  CheckForStalledSocketGroups();
}

// TODO(crbug.com/40181080): Get `server` as SchemeHostPort?
void TransportClientSocketPool::OnSSLConfigForServersChanged(
    const base::flat_set<HostPortPair>& servers) {
  // Current time value. Retrieving it once at the function start rather than
  // inside the inner loop, since it shouldn't change by any meaningful amount.
  //
  // TODO(davidben): This value is not actually needed because
  // CleanupIdleSocketsInGroup() is called with |force| = true. Tidy up
  // interfaces so the parameter is not necessary.
  base::TimeTicks now = base::TimeTicks::Now();

  // If the proxy chain includes a server from `servers` and uses SSL settings
  // (HTTPS or QUIC), refresh every group.
  bool proxy_matches = false;
  for (const ProxyServer& proxy_server : proxy_chain_.proxy_servers()) {
    if (proxy_server.is_secure_http_like() &&
        servers.contains(proxy_server.host_port_pair())) {
      proxy_matches = true;
    }
  }

  bool refreshed_any = false;
  for (auto it = group_map_.begin(); it != group_map_.end();) {
    if (proxy_matches ||
        (GURL::SchemeIsCryptographic(it->first.destination().scheme()) &&
         servers.contains(
             HostPortPair::FromSchemeHostPort(it->first.destination())))) {
      refreshed_any = true;
      // Note this call may destroy the group and invalidate |to_refresh|.
      it = RefreshGroup(it, now, kSslConfigChanged);
    } else {
      ++it;
    }
  }

  if (refreshed_any) {
    // Check to see if any group can use the freed up socket slots. It would be
    // more efficient to give the slots to the refreshed groups, if the still
    // exists and need them, but this should be rare enough that it doesn't
    // matter. This will also make sure the slots are given to the group with
    // the highest priority request
```