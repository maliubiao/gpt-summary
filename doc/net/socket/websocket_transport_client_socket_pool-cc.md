Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Initial Understanding and Purpose:**

The first step is to recognize this is a C++ source file within the Chromium project, specifically within the "net" (network) stack and related to WebSockets. The filename `websocket_transport_client_socket_pool.cc` strongly suggests it's responsible for managing a pool of client sockets used for WebSocket connections.

**2. Core Functionality Identification (Reading the Code):**

I started reading the code, paying attention to the class name (`WebSocketTransportClientSocketPool`) and its methods. Key methods that immediately stand out are:

* **Constructor and Destructor:** Indicate initialization and cleanup.
* **`RequestSocket`:**  This is the primary function for requesting a WebSocket connection. The parameters give hints about the connection details (group ID, parameters, priority, etc.).
* **`ReleaseSocket`:**  Handles returning a socket to the pool.
* **`CancelRequest`:**  Allows canceling an ongoing or pending request.
* **`FlushWithError`:**  Deals with closing all connections due to an error.
* **`ActivateStalledRequest`:**  Manages a queue of requests that are waiting because the pool is full.
* **`OnConnectJobComplete`:**  Called when a connection attempt finishes.

**3. Internal Structure and Data Structures:**

I then looked at the private members of the class to understand how it manages the socket pool:

* **`pending_connects_`:**  A map of sockets currently being connected.
* **`stalled_request_queue_` and `stalled_request_map_`:** Manage requests waiting for available sockets.
* **`handed_out_socket_count_`:**  Tracks the number of sockets currently in use.
* **`max_sockets_`:** The maximum number of sockets the pool can manage.
* **`ConnectJobDelegate`:**  An inner class that helps manage the connection process.

**4. Key Concepts and Logic:**

* **Socket Pooling:**  The fundamental idea is to reuse existing connections to improve performance and reduce resource usage.
* **Connection Limiting (`max_sockets_`):** The pool enforces a limit on the number of concurrent connections.
* **Stalled Requests:** When the limit is reached, new requests are queued.
* **Early Binding:**  The code mentions that the `ClientSocketHandle` is bound to the `ConnectJob` early in the process.
* **Connect Jobs:**  The `ConnectJob` (and `ConnectJobDelegate`) encapsulate the asynchronous connection process.
* **NetLog:** The use of `NetLog` indicates this code integrates with Chromium's network logging infrastructure for debugging and monitoring.
* **Error Handling:**  Functions like `FlushWithError` and the checks within `OnConnectJobComplete` show how errors are managed.

**5. Relationship to JavaScript:**

This is a crucial part of the prompt. I considered how JavaScript interacts with WebSockets in a browser:

* **`WebSocket` API:** This is the core JavaScript interface. When a JavaScript calls `new WebSocket(...)`, it triggers the browser's network stack to establish a connection.
* **Underlying C++ Implementation:** This C++ code is *part* of that underlying implementation. The `WebSocketTransportClientSocketPool` is responsible for managing the low-level sockets used by the JavaScript `WebSocket` API.
* **No Direct Access:** JavaScript doesn't directly manipulate this C++ class. It uses the higher-level `WebSocket` API, and the browser's internal logic handles the interaction with the socket pool.

**6. Logic and Reasoning (Hypothetical Input/Output):**

To illustrate the logic, I created a simple scenario:

* **Input:** Multiple JavaScript `WebSocket` connections are attempted simultaneously.
* **Reasoning:** The C++ pool will try to satisfy the requests. If the `max_sockets_` limit is reached, subsequent requests will be added to the stalled queue. Once a connection completes or is closed, a stalled request will be activated.
* **Output:** Some connections will be established immediately, while others will wait in the stalled queue until resources become available. The NetLog will record these events.

**7. Common User/Programming Errors:**

I thought about how developers might misuse WebSockets, leading to issues that could involve this code:

* **Opening Too Many Connections:** Exceeding browser or server limits can lead to connection failures or performance problems. The C++ code helps manage this on the client side.
* **Not Handling Connection Errors:**  If the WebSocket connection fails (due to network issues, server problems, etc.), the JavaScript code needs to handle the `onerror` event. This C++ code is involved in detecting and reporting those errors.
* **Resource Leaks (Less Direct):** While this C++ code manages socket lifecycle, not closing WebSocket connections properly in JavaScript can indirectly contribute to resource issues.

**8. Debugging Path (User Steps to Reach This Code):**

This involves tracing the steps from a user action to this specific C++ file:

1. **User Action:**  The user opens a web page that uses WebSockets.
2. **JavaScript:** The JavaScript code on the page creates a `WebSocket` object.
3. **Browser Internal Communication:** The browser's JavaScript engine communicates with the network stack.
4. **WebSocket Implementation:** The request to establish a WebSocket connection eventually reaches the `WebSocketTransportClientSocketPool`.
5. **Socket Request:** The `RequestSocket` method of this class is called.

**9. Refining and Structuring the Explanation:**

Finally, I organized the information into logical sections (Functionality, JavaScript Relationship, Logic, Errors, Debugging) and provided clear explanations and examples for each point. I made sure to use the correct terminology and explain the concepts in a way that's understandable even without deep knowledge of Chromium's internals. I also paid attention to the specific requests in the prompt, like giving examples and explaining the debugging path.
这个C++源代码文件 `websocket_transport_client_socket_pool.cc` 属于 Chromium 浏览器的网络栈，其核心功能是 **管理 WebSocket 客户端 socket 的连接池**。

以下是该文件功能的详细说明：

**核心功能：WebSocket 客户端 Socket 连接池管理**

* **连接复用:**  它维护一个已经建立的 WebSocket 连接的池子，当新的 WebSocket 连接请求到达时，如果池中有可用的连接，则可以直接复用，避免了重新建立连接的开销，提高了性能。
* **连接限制:**  它控制着可以同时存在的 WebSocket 连接的最大数量 (`max_sockets_`)，防止资源过度消耗。
* **连接排队:**  当达到最大连接数限制时，新的连接请求会被放入一个等待队列 (`stalled_request_queue_`)，直到有空闲的连接释放。
* **连接建立:**  当需要建立新的连接时，它会创建一个 `ConnectJob` 来执行连接握手等操作。
* **连接释放:**  当 WebSocket 连接不再需要时，它会将连接释放回连接池，以便后续复用。
* **连接取消:**  允许取消正在进行或等待中的连接请求。
* **错误处理:**  当发生错误时，例如连接失败，它可以清理相关的资源并通知请求方。
* **优先级管理 (有限):**  虽然代码中有 `RequestPriority` 的参数，但注释中提到，对于 `RequestSocket` 方法，优先级管理目前实现有限，主要是在排队机制中。
* **网络日志:**  集成了 Chromium 的网络日志系统，方便调试和监控 WebSocket 连接的生命周期。

**与 JavaScript 的关系及举例说明:**

该 C++ 文件是 Chromium 浏览器网络栈的底层实现，它不直接与 JavaScript 代码交互。然而，JavaScript 中使用的 `WebSocket` API 的底层实现会依赖于像 `WebSocketTransportClientSocketPool` 这样的 C++ 组件。

**举例说明:**

1. **JavaScript 发起 WebSocket 连接:** 当 JavaScript 代码执行 `new WebSocket('ws://example.com/socket')` 时，浏览器内部会经过一系列流程，最终会调用到 C++ 网络栈的代码来建立连接。`WebSocketTransportClientSocketPool` 就负责管理这个连接。
2. **连接池的复用:** 假设 JavaScript 连续创建了两个连接到同一个服务器的 WebSocket。如果第一个连接完成后没有被立即关闭，`WebSocketTransportClientSocketPool` 可能会将第一个连接放入池中。当创建第二个连接时，如果满足复用条件（例如，目标服务器相同），则可以直接从连接池中取出第一个连接进行复用，而无需重新进行 TCP 握手和 WebSocket 握手。这对于 JavaScript 来说是透明的，但底层的 C++ 代码在发挥作用。
3. **连接数限制的影响:** 如果 JavaScript 尝试创建大量 WebSocket 连接，超过了 `WebSocketTransportClientSocketPool` 设置的 `max_sockets_` 限制，那么后续的 `new WebSocket()` 调用可能会进入等待状态，直到有连接被释放。这会导致 JavaScript 中的 WebSocket 连接建立的时间变长。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. `max_sockets_` 设置为 2。
2. JavaScript 代码连续请求创建 3 个连接到 `ws://example.com/socket`。

**逻辑推理:**

1. 第一个 `new WebSocket()` 调用会成功，`WebSocketTransportClientSocketPool` 创建一个新的连接，`handed_out_socket_count_` 变为 1。
2. 第二个 `new WebSocket()` 调用也会成功，`WebSocketTransportClientSocketPool` 创建第二个新的连接，`handed_out_socket_count_` 变为 2。
3. 第三个 `new WebSocket()` 调用到达时，`ReachedMaxSocketsLimit()` 返回 true，因为 `handed_out_socket_count_` 达到了 `max_sockets_`。
4. 第三个连接请求会被添加到 `stalled_request_queue_` 中。
5. 当第一个或第二个 WebSocket 连接关闭并被释放回连接池时，`ActivateStalledRequest()` 会被调用。
6. `ActivateStalledRequest()` 会检查 `stalled_request_queue_`，发现有等待的请求，并且连接池中有可用空间。
7. `ActivateStalledRequest()` 会从队列中取出第三个连接请求，并调用 `RequestSocket()` 来建立连接。
8. 第三个 WebSocket 连接最终建立成功。

**假设输出:**

*   前两个 WebSocket 连接会立即建立。
*   第三个 WebSocket 连接会进入等待状态，直到前两个连接中的一个被释放后才建立。
*   网络日志会记录每个连接的创建、等待和释放过程。

**用户或编程常见的使用错误及举例说明:**

1. **尝试创建过多的 WebSocket 连接:** 用户在短时间内打开过多的标签页或应用程序，每个标签页或应用程序都尝试建立 WebSocket 连接。如果连接数超过了浏览器的限制或服务器的承受能力，可能会导致连接失败或性能下降。
    *   **错误体现:** JavaScript 中 `WebSocket` 对象的 `onerror` 事件被触发，或者连接建立时间过长。在网络栈的日志中，可能会看到大量的连接请求被阻塞或失败。

2. **未正确关闭 WebSocket 连接:**  JavaScript 代码在不再需要 WebSocket 连接时，没有调用 `websocket.close()` 来显式关闭连接。这会导致连接在池中占用资源，可能导致连接池满，影响后续连接的建立。
    *   **错误体现:**  长时间运行的网页或应用程序可能消耗过多的资源，因为连接没有被及时释放。

3. **依赖于连接池的特定行为:**  程序员可能错误地假设连接池的行为，例如假设每次请求都会返回一个新的连接，或者假设连接会一直保持活跃。连接池的实现细节可能会变化，依赖这些假设可能导致程序出现 bug。
    *   **错误体现:**  程序逻辑错误，例如在连接被复用后，旧的状态没有被正确清理，导致数据处理错误。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户打开一个网页:** 用户在浏览器中输入网址或点击链接，打开了一个包含 WebSocket 功能的网页。
2. **网页加载并执行 JavaScript:** 浏览器加载 HTML、CSS 和 JavaScript 代码。
3. **JavaScript 代码创建 WebSocket 对象:**  网页的 JavaScript 代码执行了类似 `const ws = new WebSocket('ws://example.com/socket');` 的语句。
4. **浏览器调用网络栈 API:**  JavaScript 引擎会调用浏览器底层的网络栈 API，请求建立 WebSocket 连接。
5. **WebSocket 协议处理:** 网络栈的 WebSocket 协议处理模块接收到连接请求。
6. **`WebSocketTransportClientSocketPool::RequestSocket()` 被调用:**  为了获取或创建一个用于 WebSocket 连接的 socket，会调用 `WebSocketTransportClientSocketPool` 的 `RequestSocket()` 方法。

**调试线索:**

*   **网络日志 (netlog):**  Chromium 的 `chrome://net-export/` 可以记录详细的网络事件，包括 WebSocket 连接的建立、状态变化和错误。通过分析网络日志，可以追踪 WebSocket 连接请求是否到达 `WebSocketTransportClientSocketPool`，以及连接池的状态和决策。
*   **断点调试:**  如果需要深入了解代码的执行流程，可以在 `WebSocketTransportClientSocketPool.cc` 相关的代码中设置断点，例如在 `RequestSocket()`, `ActivateStalledRequest()`, `OnConnectJobComplete()` 等关键方法中设置断点，观察连接池的状态变化。
*   **查看连接池状态:**  通过 Chromium 提供的内部页面 (例如 `chrome://webrtc-internals/`)，可能可以查看当前 WebSocket 连接的状态，但这可能不直接显示连接池的内部状态。

总而言之，`websocket_transport_client_socket_pool.cc` 是 Chromium 网络栈中负责高效管理 WebSocket 客户端连接的关键组件，它通过连接复用、连接限制和连接排队等机制来优化 WebSocket 连接的性能和资源利用。虽然 JavaScript 代码不直接操作这个类，但其行为受到这个 C++ 组件的底层实现影响。理解这个类的工作原理有助于调试 WebSocket 相关的问题。

### 提示词
```
这是目录为net/socket/websocket_transport_client_socket_pool.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/websocket_transport_client_socket_pool.h"

#include <algorithm>

#include "base/check_op.h"
#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/string_util.h"
#include "base/task/single_thread_task_runner.h"
#include "base/values.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/connect_job.h"
#include "net/socket/connect_job_factory.h"
#include "net/socket/stream_socket_handle.h"
#include "net/socket/websocket_endpoint_lock_manager.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace net {

WebSocketTransportClientSocketPool::WebSocketTransportClientSocketPool(
    int max_sockets,
    int max_sockets_per_group,
    const ProxyChain& proxy_chain,
    const CommonConnectJobParams* common_connect_job_params)
    : ClientSocketPool(/*is_for_websockets=*/true,
                       common_connect_job_params,
                       std::make_unique<ConnectJobFactory>()),
      proxy_chain_(proxy_chain),
      max_sockets_(max_sockets) {
  DCHECK(common_connect_job_params->websocket_endpoint_lock_manager);
}

WebSocketTransportClientSocketPool::~WebSocketTransportClientSocketPool() {
  // Clean up any pending connect jobs.
  FlushWithError(ERR_ABORTED, "");
  CHECK(pending_connects_.empty());
  CHECK_EQ(0, handed_out_socket_count_);
  CHECK(stalled_request_queue_.empty());
  CHECK(stalled_request_map_.empty());
}

// static
void WebSocketTransportClientSocketPool::UnlockEndpoint(
    StreamSocketHandle* handle,
    WebSocketEndpointLockManager* websocket_endpoint_lock_manager) {
  DCHECK(handle->is_initialized());
  DCHECK(handle->socket());
  IPEndPoint address;
  if (handle->socket()->GetPeerAddress(&address) == OK)
    websocket_endpoint_lock_manager->UnlockEndpoint(address);
}

int WebSocketTransportClientSocketPool::RequestSocket(
    const GroupId& group_id,
    scoped_refptr<SocketParams> params,
    const std::optional<NetworkTrafficAnnotationTag>& proxy_annotation_tag,
    RequestPriority priority,
    const SocketTag& socket_tag,
    RespectLimits respect_limits,
    ClientSocketHandle* handle,
    CompletionOnceCallback callback,
    const ProxyAuthCallback& proxy_auth_callback,
    const NetLogWithSource& request_net_log) {
  DCHECK(params);
  CHECK(!callback.is_null());
  CHECK(handle);
  DCHECK(socket_tag == SocketTag());

  NetLogTcpClientSocketPoolRequestedSocket(request_net_log, group_id);
  request_net_log.BeginEvent(NetLogEventType::SOCKET_POOL);

  if (ReachedMaxSocketsLimit() &&
      respect_limits == ClientSocketPool::RespectLimits::ENABLED) {
    request_net_log.AddEvent(NetLogEventType::SOCKET_POOL_STALLED_MAX_SOCKETS);
    stalled_request_queue_.emplace_back(group_id, params, proxy_annotation_tag,
                                        priority, handle, std::move(callback),
                                        proxy_auth_callback, request_net_log);
    auto iterator = stalled_request_queue_.end();
    --iterator;
    DCHECK_EQ(handle, iterator->handle);
    // Because StalledRequestQueue is a std::list, its iterators are guaranteed
    // to remain valid as long as the elements are not removed. As long as
    // stalled_request_queue_ and stalled_request_map_ are updated in sync, it
    // is safe to dereference an iterator in stalled_request_map_ to find the
    // corresponding list element.
    stalled_request_map_.insert(
        StalledRequestMap::value_type(handle, iterator));
    return ERR_IO_PENDING;
  }

  std::unique_ptr<ConnectJobDelegate> connect_job_delegate =
      std::make_unique<ConnectJobDelegate>(this, std::move(callback), handle,
                                           request_net_log);

  std::unique_ptr<ConnectJob> connect_job =
      CreateConnectJob(group_id, params, proxy_chain_, proxy_annotation_tag,
                       priority, SocketTag(), connect_job_delegate.get());

  int result = connect_job_delegate->Connect(std::move(connect_job));

  // Regardless of the outcome of |connect_job|, it will always be bound to
  // |handle|, since this pool uses early-binding. So the binding is logged
  // here, without waiting for the result.
  request_net_log.AddEventReferencingSource(
      NetLogEventType::SOCKET_POOL_BOUND_TO_CONNECT_JOB,
      connect_job_delegate->connect_job_net_log().source());

  if (result == ERR_IO_PENDING) {
    // TODO(ricea): Implement backup job timer?
    AddJob(handle, std::move(connect_job_delegate));
  } else {
    TryHandOutSocket(result, connect_job_delegate.get());
  }

  return result;
}

int WebSocketTransportClientSocketPool::RequestSockets(
    const GroupId& group_id,
    scoped_refptr<SocketParams> params,
    const std::optional<NetworkTrafficAnnotationTag>& proxy_annotation_tag,
    int num_sockets,
    CompletionOnceCallback callback,
    const NetLogWithSource& net_log) {
  NOTIMPLEMENTED();
  return OK;
}

void WebSocketTransportClientSocketPool::SetPriority(const GroupId& group_id,
                                                     ClientSocketHandle* handle,
                                                     RequestPriority priority) {
  // Since sockets requested by RequestSocket are bound early and
  // stalled_request_{queue,map} don't take priorities into account, there's
  // nothing to do within the pool to change priority of the request.
  // TODO(rdsmith, ricea): Make stalled_request_{queue,map} take priorities
  // into account.
  // TODO(rdsmith, chlily): Investigate plumbing the reprioritization request to
  // the connect job.
}

void WebSocketTransportClientSocketPool::CancelRequest(
    const GroupId& group_id,
    ClientSocketHandle* handle,
    bool cancel_connect_job) {
  DCHECK(!handle->is_initialized());
  if (DeleteStalledRequest(handle))
    return;
  std::unique_ptr<StreamSocket> socket = handle->PassSocket();
  if (socket)
    ReleaseSocket(handle->group_id(), std::move(socket),
                  handle->group_generation());
  if (DeleteJob(handle)) {
    CHECK(!base::Contains(pending_callbacks_,
                          reinterpret_cast<ClientSocketHandleID>(handle)));
  } else {
    pending_callbacks_.erase(reinterpret_cast<ClientSocketHandleID>(handle));
  }

  ActivateStalledRequest();
}

void WebSocketTransportClientSocketPool::ReleaseSocket(
    const GroupId& group_id,
    std::unique_ptr<StreamSocket> socket,
    int64_t generation) {
  CHECK_GT(handed_out_socket_count_, 0);
  --handed_out_socket_count_;

  ActivateStalledRequest();
}

void WebSocketTransportClientSocketPool::FlushWithError(
    int error,
    const char* net_log_reason_utf8) {
  DCHECK_NE(error, OK);

  // Sockets which are in LOAD_STATE_CONNECTING are in danger of unlocking
  // sockets waiting for the endpoint lock. If they connected synchronously,
  // then OnConnectJobComplete(). The |flushing_| flag tells this object to
  // ignore spurious calls to OnConnectJobComplete(). It is safe to ignore those
  // calls because this method will delete the jobs and call their callbacks
  // anyway.
  flushing_ = true;
  for (auto it = pending_connects_.begin(); it != pending_connects_.end();) {
    InvokeUserCallbackLater(it->second->socket_handle(),
                            it->second->release_callback(), error);
    it->second->connect_job_net_log().AddEventWithStringParams(
        NetLogEventType::SOCKET_POOL_CLOSING_SOCKET, "reason",
        net_log_reason_utf8);
    it = pending_connects_.erase(it);
  }
  for (auto& stalled_request : stalled_request_queue_) {
    InvokeUserCallbackLater(stalled_request.handle,
                            std::move(stalled_request.callback), error);
  }
  stalled_request_map_.clear();
  stalled_request_queue_.clear();
  flushing_ = false;
}

void WebSocketTransportClientSocketPool::CloseIdleSockets(
    const char* net_log_reason_utf8) {
  // We have no idle sockets.
}

void WebSocketTransportClientSocketPool::CloseIdleSocketsInGroup(
    const GroupId& group_id,
    const char* net_log_reason_utf8) {
  // We have no idle sockets.
}

int WebSocketTransportClientSocketPool::IdleSocketCount() const {
  return 0;
}

size_t WebSocketTransportClientSocketPool::IdleSocketCountInGroup(
    const GroupId& group_id) const {
  return 0;
}

LoadState WebSocketTransportClientSocketPool::GetLoadState(
    const GroupId& group_id,
    const ClientSocketHandle* handle) const {
  if (stalled_request_map_.find(handle) != stalled_request_map_.end())
    return LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET;
  if (pending_callbacks_.count(reinterpret_cast<ClientSocketHandleID>(handle)))
    return LOAD_STATE_CONNECTING;
  return LookupConnectJob(handle)->GetLoadState();
}

base::Value WebSocketTransportClientSocketPool::GetInfoAsValue(
    const std::string& name,
    const std::string& type) const {
  auto dict = base::Value::Dict()
                  .Set("name", name)
                  .Set("type", type)
                  .Set("handed_out_socket_count", handed_out_socket_count_)
                  .Set("connecting_socket_count",
                       static_cast<int>(pending_connects_.size()))
                  .Set("idle_socket_count", 0)
                  .Set("max_socket_count", max_sockets_)
                  .Set("max_sockets_per_group", max_sockets_);
  return base::Value(std::move(dict));
}

bool WebSocketTransportClientSocketPool::HasActiveSocket(
    const GroupId& group_id) const {
  // This method is not supported for WebSocket.
  NOTREACHED();
}

bool WebSocketTransportClientSocketPool::IsStalled() const {
  return !stalled_request_queue_.empty();
}

void WebSocketTransportClientSocketPool::AddHigherLayeredPool(
    HigherLayeredPool* higher_pool) {
  // This class doesn't use connection limits like the pools for HTTP do, so no
  // need to track higher layered pools.
}

void WebSocketTransportClientSocketPool::RemoveHigherLayeredPool(
    HigherLayeredPool* higher_pool) {
  // This class doesn't use connection limits like the pools for HTTP do, so no
  // need to track higher layered pools.
}

bool WebSocketTransportClientSocketPool::TryHandOutSocket(
    int result,
    ConnectJobDelegate* connect_job_delegate) {
  DCHECK_NE(result, ERR_IO_PENDING);

  std::unique_ptr<StreamSocket> socket =
      connect_job_delegate->connect_job()->PassSocket();
  LoadTimingInfo::ConnectTiming connect_timing =
      connect_job_delegate->connect_job()->connect_timing();
  ClientSocketHandle* const handle = connect_job_delegate->socket_handle();
  NetLogWithSource request_net_log = connect_job_delegate->request_net_log();

  if (result == OK) {
    DCHECK(socket);

    HandOutSocket(std::move(socket), connect_timing, handle, request_net_log);

    request_net_log.EndEvent(NetLogEventType::SOCKET_POOL);

    return true;
  }

  bool handed_out_socket = false;

  // If we got a socket, it must contain error information so pass that
  // up so that the caller can retrieve it.
  handle->SetAdditionalErrorState(connect_job_delegate->connect_job());
  if (socket) {
    HandOutSocket(std::move(socket), connect_timing, handle, request_net_log);
    handed_out_socket = true;
  }

  request_net_log.EndEventWithNetErrorCode(NetLogEventType::SOCKET_POOL,
                                           result);

  return handed_out_socket;
}

void WebSocketTransportClientSocketPool::OnConnectJobComplete(
    int result,
    ConnectJobDelegate* connect_job_delegate) {
  DCHECK_NE(ERR_IO_PENDING, result);

  // See comment in FlushWithError.
  if (flushing_) {
    // Just delete the socket.
    std::unique_ptr<StreamSocket> socket =
        connect_job_delegate->connect_job()->PassSocket();
    return;
  }

  bool handed_out_socket = TryHandOutSocket(result, connect_job_delegate);

  CompletionOnceCallback callback = connect_job_delegate->release_callback();

  ClientSocketHandle* const handle = connect_job_delegate->socket_handle();

  bool delete_succeeded = DeleteJob(handle);
  CHECK(delete_succeeded);

  connect_job_delegate = nullptr;

  if (!handed_out_socket)
    ActivateStalledRequest();

  InvokeUserCallbackLater(handle, std::move(callback), result);
}

void WebSocketTransportClientSocketPool::InvokeUserCallbackLater(
    ClientSocketHandle* handle,
    CompletionOnceCallback callback,
    int rv) {
  const auto handle_id = reinterpret_cast<ClientSocketHandleID>(handle);
  CHECK(!pending_callbacks_.count(handle_id));
  pending_callbacks_.insert(handle_id);
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&WebSocketTransportClientSocketPool::InvokeUserCallback,
                     weak_factory_.GetWeakPtr(), handle_id,
                     handle->GetWeakPtr(), std::move(callback), rv));
}

void WebSocketTransportClientSocketPool::InvokeUserCallback(
    ClientSocketHandleID handle_id,
    base::WeakPtr<ClientSocketHandle> weak_handle,
    CompletionOnceCallback callback,
    int rv) {
  if (pending_callbacks_.erase(handle_id)) {
    CHECK(weak_handle);
    std::move(callback).Run(rv);
  }
}

bool WebSocketTransportClientSocketPool::ReachedMaxSocketsLimit() const {
  return handed_out_socket_count_ >= max_sockets_ ||
         base::checked_cast<int>(pending_connects_.size()) >=
             max_sockets_ - handed_out_socket_count_;
}

void WebSocketTransportClientSocketPool::HandOutSocket(
    std::unique_ptr<StreamSocket> socket,
    const LoadTimingInfo::ConnectTiming& connect_timing,
    ClientSocketHandle* handle,
    const NetLogWithSource& net_log) {
  DCHECK(socket);
  DCHECK_EQ(StreamSocketHandle::SocketReuseType::kUnused, handle->reuse_type());
  DCHECK_EQ(0, handle->idle_time().InMicroseconds());

  handle->SetSocket(std::move(socket));
  handle->set_group_generation(0);
  handle->set_connect_timing(connect_timing);

  net_log.AddEventReferencingSource(
      NetLogEventType::SOCKET_POOL_BOUND_TO_SOCKET,
      handle->socket()->NetLog().source());

  ++handed_out_socket_count_;
}

void WebSocketTransportClientSocketPool::AddJob(
    ClientSocketHandle* handle,
    std::unique_ptr<ConnectJobDelegate> delegate) {
  bool inserted =
      pending_connects_
          .insert(PendingConnectsMap::value_type(handle, std::move(delegate)))
          .second;
  CHECK(inserted);
}

bool WebSocketTransportClientSocketPool::DeleteJob(ClientSocketHandle* handle) {
  auto it = pending_connects_.find(handle);
  if (it == pending_connects_.end())
    return false;
  // Deleting a ConnectJob which holds an endpoint lock can lead to a different
  // ConnectJob proceeding to connect. If the connect proceeds synchronously
  // (usually because of a failure) then it can trigger that job to be
  // deleted.
  pending_connects_.erase(it);
  return true;
}

const ConnectJob* WebSocketTransportClientSocketPool::LookupConnectJob(
    const ClientSocketHandle* handle) const {
  auto it = pending_connects_.find(handle);
  CHECK(it != pending_connects_.end());
  return it->second->connect_job();
}

void WebSocketTransportClientSocketPool::ActivateStalledRequest() {
  // Usually we will only be able to activate one stalled request at a time,
  // however if all the connects fail synchronously for some reason, we may be
  // able to clear the whole queue at once.
  while (!stalled_request_queue_.empty() && !ReachedMaxSocketsLimit()) {
    StalledRequest request = std::move(stalled_request_queue_.front());
    stalled_request_queue_.pop_front();
    stalled_request_map_.erase(request.handle);

    auto split_callback = base::SplitOnceCallback(std::move(request.callback));

    int rv = RequestSocket(
        request.group_id, request.params, request.proxy_annotation_tag,
        request.priority, SocketTag(),
        // Stalled requests can't have |respect_limits|
        // DISABLED.
        RespectLimits::ENABLED, request.handle, std::move(split_callback.first),
        request.proxy_auth_callback, request.net_log);

    // ActivateStalledRequest() never returns synchronously, so it is never
    // called re-entrantly.
    if (rv != ERR_IO_PENDING)
      InvokeUserCallbackLater(request.handle, std::move(split_callback.second),
                              rv);
  }
}

bool WebSocketTransportClientSocketPool::DeleteStalledRequest(
    ClientSocketHandle* handle) {
  auto it = stalled_request_map_.find(handle);
  if (it == stalled_request_map_.end())
    return false;
  stalled_request_queue_.erase(it->second);
  stalled_request_map_.erase(it);
  return true;
}

WebSocketTransportClientSocketPool::ConnectJobDelegate::ConnectJobDelegate(
    WebSocketTransportClientSocketPool* owner,
    CompletionOnceCallback callback,
    ClientSocketHandle* socket_handle,
    const NetLogWithSource& request_net_log)
    : owner_(owner),
      callback_(std::move(callback)),
      socket_handle_(socket_handle),
      request_net_log_(request_net_log) {}

WebSocketTransportClientSocketPool::ConnectJobDelegate::~ConnectJobDelegate() =
    default;

void
WebSocketTransportClientSocketPool::ConnectJobDelegate::OnConnectJobComplete(
    int result,
    ConnectJob* job) {
  DCHECK_EQ(job, connect_job_.get());
  owner_->OnConnectJobComplete(result, this);
}

void WebSocketTransportClientSocketPool::ConnectJobDelegate::OnNeedsProxyAuth(
    const HttpResponseInfo& response,
    HttpAuthController* auth_controller,
    base::OnceClosure restart_with_auth_callback,
    ConnectJob* job) {
  // This class isn't used for proxies.
  NOTREACHED();
}

int WebSocketTransportClientSocketPool::ConnectJobDelegate::Connect(
    std::unique_ptr<ConnectJob> connect_job) {
  connect_job_ = std::move(connect_job);
  return connect_job_->Connect();
}

const NetLogWithSource&
WebSocketTransportClientSocketPool::ConnectJobDelegate::connect_job_net_log() {
  return connect_job_->net_log();
}

WebSocketTransportClientSocketPool::StalledRequest::StalledRequest(
    const GroupId& group_id,
    const scoped_refptr<SocketParams>& params,
    const std::optional<NetworkTrafficAnnotationTag>& proxy_annotation_tag,
    RequestPriority priority,
    ClientSocketHandle* handle,
    CompletionOnceCallback callback,
    const ProxyAuthCallback& proxy_auth_callback,
    const NetLogWithSource& net_log)
    : group_id(group_id),
      params(params),
      proxy_annotation_tag(proxy_annotation_tag),
      priority(priority),
      handle(handle),
      callback(std::move(callback)),
      proxy_auth_callback(proxy_auth_callback),
      net_log(net_log) {}

WebSocketTransportClientSocketPool::StalledRequest::StalledRequest(
    StalledRequest&& other) = default;

WebSocketTransportClientSocketPool::StalledRequest::~StalledRequest() = default;

}  // namespace net
```