Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand the function of the `transport_connect_sub_job.cc` file within the Chromium networking stack and then connect it to JavaScript if applicable. The prompt also asks for logical reasoning with examples, potential user errors, and how the user reaches this code.

**2. Initial Code Scan and Key Observations:**

I started by quickly scanning the code, looking for keywords and patterns. Here's what jumped out:

* **Includes:**  `net/socket/...` suggests this file deals with network sockets. `base/functional/bind.h` and `base/notreached.h` are common Chromium utilities.
* **Namespace `net`:** Clearly part of the Chromium networking library.
* **Class `TransportConnectSubJob`:** The central class of interest. The name itself suggests it's a sub-task within a larger transport connection process.
* **`TransportConnectJob* parent_job_`:**  Indicates this is a subordinate object, and it interacts with a parent job.
* **`std::vector<IPEndPoint> addresses_`:**  Suggests it tries to connect to one of a list of IP addresses.
* **`enum SubJobType type_`:** Implies there might be different types of sub-jobs.
* **State Machine (`next_state_`):**  The `DoLoop` function and the `STATE_*` enums strongly indicate a state machine managing the connection process.
* **`WebSocketEndpointLockManager`:**  This is a significant component, suggesting this code is involved in WebSocket connection establishment and managing concurrent connections to the same endpoint.
* **`StreamSocket` and `WebSocketStreamSocket`:** The code wraps a standard `StreamSocket` in a `WebSocketStreamSocket`, which handles locking. This confirms the WebSocket involvement.
* **`ClientSocketFactory`:** Used to create the underlying transport socket.
* **`SocketPerformanceWatcherFactory`:**  Indicates performance monitoring is involved.
* **`NetLogWithSource`:**  Crucial for debugging and logging network events.
* **Callbacks and `base::BindOnce`:**  Asynchronous operations are central to network programming, and these are used for managing them.
* **`ConnectionAttempts`:**  Keeps track of connection failures.

**3. Deeper Analysis - Functionality Breakdown:**

Based on the observations, I started to piece together the workflow:

* **Initialization:** `TransportConnectSubJob` is created with a list of addresses and a reference to the parent job.
* **Starting the Connection:** `Start()` initiates the state machine.
* **Endpoint Locking:**  If the parent job has a `WebSocketEndpointLockManager`, the sub-job attempts to acquire a lock for the target IP address. This is likely to prevent too many WebSocket connections to the same server at once.
* **Socket Creation:**  A transport-level client socket is created using the `ClientSocketFactory`. If WebSocket locking is involved, the socket is wrapped in `WebSocketStreamSocket`.
* **Connecting:** The underlying transport socket's `Connect()` method is called.
* **Connection Completion:** The `OnIOComplete` callback is invoked when the connection attempt finishes (success or failure).
* **State Transitions:** The `DoLoop` function manages the state transitions based on the result of each operation.
* **Retry Logic:** If the connection fails, the sub-job tries the next IP address in the list (unless it's a suspend error).
* **Reporting to Parent:** The sub-job informs the parent job about the completion of its task.

**4. Connecting to JavaScript:**

This required understanding how JavaScript interacts with the Chromium networking stack.

* **`fetch()` API and WebSockets:** These are the primary ways JavaScript interacts with the network.
* **Renderer Process and Browser Process:**  JavaScript runs in the renderer process, and network requests are handled in the browser process. There's communication between these processes.
* **High-Level vs. Low-Level:** This C++ code is at a relatively low level in the networking stack. JavaScript doesn't directly interact with these classes.

Based on this, I concluded that while there isn't *direct* interaction, the `TransportConnectSubJob` plays a crucial role in fulfilling network requests initiated by JavaScript. I used the examples of `fetch()` and WebSocket API usage in JavaScript to illustrate how user actions trigger the underlying network operations.

**5. Logical Reasoning (Input/Output):**

I focused on the core function: attempting to connect to an IP address.

* **Input:** A list of IP addresses.
* **Output:** Either a successfully connected socket or an error.

I created simple scenarios to demonstrate this, covering both success and failure cases.

**6. Common Usage Errors:**

I thought about common programming or user errors that could lead to issues at this level:

* **Incorrect IP address/port:**  The most basic error.
* **Firewall blocking:** A common network issue.
* **Server down:**  The target server might not be reachable.
* **Network connectivity issues:**  General network problems on the user's machine.
* **WebSocket-specific errors:**  Issues related to the WebSocket protocol.

**7. Debugging Path:**

I outlined how a developer might reach this code during debugging:

* **Start with user action:** A `fetch()` call or WebSocket connection.
* **Network stack tracing:** Use browser developer tools or internal Chromium logging to follow the network request.
* **Breakpoints:** Set breakpoints in `TransportConnectSubJob::Start()`, `DoLoop()`, or other key methods.
* **NetLog:** Analyze the NetLog events to see the sequence of network operations and potential errors.

**8. Structuring the Answer:**

Finally, I organized the information into the requested sections: functionality, JavaScript relation, logical reasoning, common errors, and debugging. I tried to use clear and concise language, providing examples where necessary.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe there's some obscure JavaScript API that directly maps to this C++ class. *Correction:* Realized the interaction is indirect, through higher-level APIs.
* **Logical Reasoning:**  Initially considered more complex scenarios. *Refinement:* Simplified to focus on the core connection attempt.
* **Debugging:**  Initially focused solely on code debugging. *Refinement:* Added user actions as the starting point for tracing.

By following this systematic approach, I could provide a comprehensive and accurate answer to the prompt.
好的，让我们来分析一下 `net/socket/transport_connect_sub_job.cc` 这个文件。

**功能列举：**

这个文件定义了 `TransportConnectSubJob` 类，它是 Chromium 网络栈中负责尝试连接到单个 IP 地址的子任务。  更具体地说，它的主要功能包括：

1. **管理单个连接尝试:**  `TransportConnectSubJob` 负责尝试连接到 `addresses_` 列表中指定的一个 IP 地址。它可以处理 TCP 连接。
2. **WebSocket Endpoint Lock 管理:**  如果涉及到 WebSocket 连接，并且配置了 `WebSocketEndpointLockManager`，`TransportConnectSubJob` 会负责获取和释放特定端点（IP 地址和端口）的锁。这避免了同时建立过多的到相同服务器的 WebSocket 连接。
3. **状态管理:**  它使用状态机 (`next_state_`) 来管理连接尝试的各个阶段，例如获取锁、创建 socket、执行连接等。
4. **Socket 创建:**  它使用 `ClientSocketFactory` 创建底层的 `StreamSocket` 对象，用于实际的网络连接。
5. **性能监控:**  它支持通过 `SocketPerformanceWatcherFactory` 创建 `SocketPerformanceWatcher` 来监控连接性能。
6. **网络日志记录:**  它使用 `NetLogWithSource` 记录连接尝试的事件，用于调试和分析。
7. **连接结果通知:**  连接尝试完成后，无论成功还是失败，它都会通知其父任务 (`TransportConnectJob`)。
8. **连接失败回退:**  如果连接尝试失败，并且 `addresses_` 列表中还有其他地址，它可以回退到下一个地址并尝试连接。
9. **处理网络挂起:**  它可以识别 `ERR_NETWORK_IO_SUSPENDED` 错误，并停止进一步的连接尝试。

**与 JavaScript 功能的关系及举例：**

虽然 `TransportConnectSubJob` 是 C++ 代码，运行在 Chromium 的浏览器进程中，但它直接支撑着 JavaScript 发起的网络请求。  以下是一些 JavaScript 功能与 `TransportConnectSubJob` 间接相关的例子：

1. **`fetch()` API:** 当 JavaScript 代码使用 `fetch()` 发起一个 HTTP 或 HTTPS 请求时，底层的网络栈（包括 `TransportConnectSubJob`）负责建立到服务器的 TCP 连接。
    * **举例:**  假设 JavaScript 代码执行 `fetch('https://www.example.com')`。 Chromium 的网络栈会解析 URL，进行 DNS 查询，然后创建一个 `TransportConnectJob` 来尝试连接到 `www.example.com` 的 IP 地址。每个 `TransportConnectSubJob` 负责尝试连接到解析出的一个 IP 地址。

2. **WebSocket API:** 当 JavaScript 代码使用 `WebSocket` API 创建一个 WebSocket 连接时，`TransportConnectSubJob` 在建立初始的 TCP 连接阶段会发挥作用，并且还会处理 WebSocket Endpoint Lock 的逻辑。
    * **举例:**  JavaScript 代码执行 `new WebSocket('wss://echo.websocket.org')`。Chromium 的网络栈会创建一个 `TransportConnectJob` 来连接到 `echo.websocket.org`。如果启用了 WebSocket Endpoint Lock，一个 `TransportConnectSubJob` 会首先尝试获取目标服务器的锁，成功后才会创建 socket 并尝试连接。

3. **资源加载 (例如 `<img src="...">`, `<script src="...">`):** 当浏览器加载网页上的资源时，网络栈也会参与建立连接，`TransportConnectSubJob` 同样负责底层的连接尝试。

**逻辑推理及假设输入与输出：**

假设我们有一个 `TransportConnectSubJob` 实例，其 `addresses_` 列表包含两个 IP 地址：`192.168.1.1:80` 和 `10.0.0.1:8080`。

**假设输入：**

* `addresses_`: `[{address: "192.168.1.1", port: 80}, {address: "10.0.0.1", port: 8080}]`
* `websocket_endpoint_lock_manager_`: `nullptr` (假设未启用 WebSocket Endpoint Lock)

**场景 1：连接第一个地址成功**

1. **输入状态:** `next_state_` 为 `STATE_NONE`
2. **执行 `Start()`:**  `next_state_` 变为 `STATE_OBTAIN_LOCK`，由于 `websocket_endpoint_lock_manager_` 为空，直接进入 `DoEndpointLockComplete`。
3. **`DoEndpointLockComplete`:** 创建连接到 `192.168.1.1:80` 的 socket，并调用 `Connect()`。
4. **假设 `Connect()` 返回 `OK` (连接成功):** `OnIOComplete(OK)` 被调用。
5. **`DoLoop(OK)`:**  进入 `STATE_TRANSPORT_CONNECT_COMPLETE`，`DoTransportConnectComplete(OK)` 被调用。
6. **`DoTransportConnectComplete(OK)`:** `next_state_` 变为 `STATE_DONE`，返回 `OK`。
7. **输出:**  连接成功，`parent_job_->OnSubJobComplete(OK, this)` 被调用。

**场景 2：连接第一个地址失败，连接第二个地址成功**

1. **输入状态:** `next_state_` 为 `STATE_NONE`
2. **执行 `Start()`:** 过程同上，尝试连接 `192.168.1.1:80`。
3. **假设 `Connect()` 返回 `ERR_CONNECTION_REFUSED` (连接被拒绝):** `OnIOComplete(ERR_CONNECTION_REFUSED)` 被调用。
4. **`DoLoop(ERR_CONNECTION_REFUSED)`:** 进入 `STATE_TRANSPORT_CONNECT_COMPLETE`，`DoTransportConnectComplete(ERR_CONNECTION_REFUSED)` 被调用。
5. **`DoTransportConnectComplete(ERR_CONNECTION_REFUSED)`:**  记录连接尝试失败，由于还有下一个地址，`next_state_` 变为 `STATE_OBTAIN_LOCK`，`current_address_index_` 递增，返回 `OK`。
6. **再次进入 `DoLoop`:**  尝试连接 `10.0.0.1:8080`。
7. **假设连接 `10.0.0.1:8080` 成功:** 后续流程如同场景 1，最终返回 `OK`。
8. **输出:**  连接成功（在尝试了多个地址后），`parent_job_->OnSubJobComplete(OK, this)` 被调用。

**涉及的用户或编程常见的使用错误：**

1. **网络配置错误:** 用户的网络配置可能存在问题，导致无法连接到指定的 IP 地址和端口。例如，防火墙阻止了连接，或者路由配置不正确。
    * **举例:** 用户尝试访问一个位于局域网内的服务器，但他们的计算机没有正确的网关或子网掩码设置，导致无法路由到该服务器。`TransportConnectSubJob` 会尝试连接并最终失败，返回相应的网络错误码。

2. **服务器未运行或端口错误:**  用户尝试连接的服务器可能没有运行，或者目标端口上没有服务监听。
    * **举例:**  JavaScript 代码尝试连接到 `wss://example.com:8080`，但 `example.com` 上运行的 WebSocket 服务器监听的是 8443 端口。`TransportConnectSubJob` 会尝试连接 8080 端口，最终会收到 `ERR_CONNECTION_REFUSED` 或类似的错误。

3. **WebSocket Endpoint Lock 冲突（编程错误）:** 如果开发者没有正确处理 WebSocket 连接的生命周期，可能会导致 Endpoint Lock 被错误地持有，阻止后续的连接。
    * **举例:**  开发者在一个循环中快速创建并关闭 WebSocket 连接，但没有等待连接真正关闭，导致锁没有及时释放。后续的 `TransportConnectSubJob` 可能会因为无法获取锁而进入等待状态。

4. **DNS 解析问题:**  如果用户尝试连接的主机名无法被解析为 IP 地址，那么 `TransportConnectSubJob` 根本不会被创建或执行，错误会发生在更早的 DNS 解析阶段。但如果 DNS 解析返回了错误的 IP 地址，`TransportConnectSubJob` 会尝试连接到错误的地址，导致连接失败。

**用户操作是如何一步步的到达这里，作为调试线索：**

以下是一个典型的用户操作流程，以及如何追踪到 `TransportConnectSubJob`：

1. **用户在浏览器中输入网址或点击链接:** 例如，用户在地址栏输入 `https://www.example.com` 并按下回车，或者点击一个指向该网址的链接。
2. **浏览器解析 URL:** 浏览器解析 URL，提取主机名 (`www.example.com`) 和端口 (默认 443 for HTTPS)。
3. **DNS 查询:** 浏览器发起 DNS 查询，将主机名解析为 IP 地址。
4. **创建 `TransportConnectJob`:**  网络栈创建一个 `TransportConnectJob` 实例，负责建立到解析出的 IP 地址的连接。`TransportConnectJob` 会包含解析出的所有 IP 地址（如果域名解析返回多个 A 记录）。
5. **创建 `TransportConnectSubJob`:**  `TransportConnectJob` 为每个需要尝试的 IP 地址创建一个 `TransportConnectSubJob` 实例。
6. **`TransportConnectSubJob::Start()` 被调用:**  每个 `TransportConnectSubJob` 开始尝试连接到其负责的 IP 地址。
7. **Socket 创建和连接尝试:** `TransportConnectSubJob` 调用 `ClientSocketFactory` 创建 `StreamSocket`，并调用其 `Connect()` 方法。
8. **连接结果处理:** 连接成功或失败，`TransportConnectSubJob` 的回调函数被调用，更新状态并通知父任务。

**调试线索：**

* **Chrome 的 `net-internals` 工具 (`chrome://net-internals/#sockets` 和 `chrome://net-internals/#events`):**  这个工具可以提供非常详细的网络事件日志，包括 socket 的创建、连接尝试、状态变化等。你可以在这里看到 `TransportConnectJob` 和 `TransportConnectSubJob` 的生命周期和状态。
* **设置断点:**  在 `TransportConnectSubJob::Start()`, `TransportConnectSubJob::DoLoop()`, `TransportConnectSubJob::DoTransportConnectComplete()` 等关键方法设置断点，可以逐步跟踪代码执行流程。
* **查看 NetLog 输出:**  Chromium 的网络库会产生 NetLog 输出，记录各种网络事件。通过分析 NetLog，可以了解连接尝试的细节，例如尝试连接的 IP 地址、返回的错误码等。
* **检查父任务 `TransportConnectJob` 的状态:**  `TransportConnectSubJob` 的行为受到其父任务的控制。检查 `TransportConnectJob` 的状态可以帮助理解为什么创建了特定的 `TransportConnectSubJob`，以及它的目标是什么。

总而言之，`net/socket/transport_connect_sub_job.cc` 定义的 `TransportConnectSubJob` 类是 Chromium 网络栈中一个关键的组件，负责执行实际的 TCP 连接尝试，并处理与 WebSocket Endpoint Lock 相关的逻辑，它支撑着浏览器中各种网络功能的正常运行。

### 提示词
```
这是目录为net/socket/transport_connect_sub_job.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "net/socket/transport_connect_sub_job.h"

#include <set>
#include <string>
#include <utility>

#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/notreached.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_with_source.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/connection_attempts.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"
#include "net/socket/websocket_endpoint_lock_manager.h"

namespace net {

namespace {

// StreamSocket wrapper that registers/unregisters the wrapped StreamSocket with
// a WebSocketEndpointLockManager on creation/destruction.
class WebSocketStreamSocket final : public StreamSocket {
 public:
  WebSocketStreamSocket(
      std::unique_ptr<StreamSocket> wrapped_socket,
      WebSocketEndpointLockManager* websocket_endpoint_lock_manager,
      const IPEndPoint& address)
      : wrapped_socket_(std::move(wrapped_socket)),
        lock_releaser_(websocket_endpoint_lock_manager, address) {}

  WebSocketStreamSocket(const WebSocketStreamSocket&) = delete;
  WebSocketStreamSocket& operator=(const WebSocketStreamSocket&) = delete;

  ~WebSocketStreamSocket() override = default;

  // Socket implementation:
  int Read(IOBuffer* buf,
           int buf_len,
           CompletionOnceCallback callback) override {
    return wrapped_socket_->Read(buf, buf_len, std::move(callback));
  }
  int ReadIfReady(IOBuffer* buf,
                  int buf_len,
                  CompletionOnceCallback callback) override {
    return wrapped_socket_->ReadIfReady(buf, buf_len, std::move(callback));
  }
  int CancelReadIfReady() override {
    return wrapped_socket_->CancelReadIfReady();
  }
  int Write(IOBuffer* buf,
            int buf_len,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) override {
    return wrapped_socket_->Write(buf, buf_len, std::move(callback),
                                  traffic_annotation);
  }
  int SetReceiveBufferSize(int32_t size) override {
    return wrapped_socket_->SetReceiveBufferSize(size);
  }
  int SetSendBufferSize(int32_t size) override {
    return wrapped_socket_->SetSendBufferSize(size);
  }
  void SetDnsAliases(std::set<std::string> aliases) override {
    wrapped_socket_->SetDnsAliases(std::move(aliases));
  }
  const std::set<std::string>& GetDnsAliases() const override {
    return wrapped_socket_->GetDnsAliases();
  }

  // StreamSocket implementation:
  int Connect(CompletionOnceCallback callback) override {
    return wrapped_socket_->Connect(std::move(callback));
  }
  void Disconnect() override { wrapped_socket_->Disconnect(); }
  bool IsConnected() const override { return wrapped_socket_->IsConnected(); }
  bool IsConnectedAndIdle() const override {
    return wrapped_socket_->IsConnectedAndIdle();
  }
  int GetPeerAddress(IPEndPoint* address) const override {
    return wrapped_socket_->GetPeerAddress(address);
  }
  int GetLocalAddress(IPEndPoint* address) const override {
    return wrapped_socket_->GetLocalAddress(address);
  }
  const NetLogWithSource& NetLog() const override {
    return wrapped_socket_->NetLog();
  }
  bool WasEverUsed() const override { return wrapped_socket_->WasEverUsed(); }
  NextProto GetNegotiatedProtocol() const override {
    return wrapped_socket_->GetNegotiatedProtocol();
  }
  bool GetSSLInfo(SSLInfo* ssl_info) override {
    return wrapped_socket_->GetSSLInfo(ssl_info);
  }
  int64_t GetTotalReceivedBytes() const override {
    return wrapped_socket_->GetTotalReceivedBytes();
  }
  void ApplySocketTag(const SocketTag& tag) override {
    wrapped_socket_->ApplySocketTag(tag);
  }

 private:
  std::unique_ptr<StreamSocket> wrapped_socket_;
  WebSocketEndpointLockManager::LockReleaser lock_releaser_;
};

}  // namespace

TransportConnectSubJob::TransportConnectSubJob(
    std::vector<IPEndPoint> addresses,
    TransportConnectJob* parent_job,
    SubJobType type)
    : parent_job_(parent_job), addresses_(std::move(addresses)), type_(type) {}

TransportConnectSubJob::~TransportConnectSubJob() = default;

// Start connecting.
int TransportConnectSubJob::Start() {
  DCHECK_EQ(STATE_NONE, next_state_);
  next_state_ = STATE_OBTAIN_LOCK;
  return DoLoop(OK);
}

// Called by WebSocketEndpointLockManager when the lock becomes available.
void TransportConnectSubJob::GotEndpointLock() {
  DCHECK_EQ(STATE_OBTAIN_LOCK_COMPLETE, next_state_);
  OnIOComplete(OK);
}

LoadState TransportConnectSubJob::GetLoadState() const {
  switch (next_state_) {
    case STATE_OBTAIN_LOCK:
    case STATE_OBTAIN_LOCK_COMPLETE:
      // TODO(ricea): Add a WebSocket-specific LOAD_STATE ?
      return LOAD_STATE_WAITING_FOR_AVAILABLE_SOCKET;
    case STATE_TRANSPORT_CONNECT_COMPLETE:
    case STATE_DONE:
      return LOAD_STATE_CONNECTING;
    case STATE_NONE:
      return LOAD_STATE_IDLE;
  }
  NOTREACHED();
}

const IPEndPoint& TransportConnectSubJob::CurrentAddress() const {
  DCHECK_LT(current_address_index_, addresses_.size());
  return addresses_[current_address_index_];
}

void TransportConnectSubJob::OnIOComplete(int result) {
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING)
    parent_job_->OnSubJobComplete(rv, this);  // |this| deleted
}

int TransportConnectSubJob::DoLoop(int result) {
  DCHECK_NE(next_state_, STATE_NONE);

  int rv = result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_OBTAIN_LOCK:
        DCHECK_EQ(OK, rv);
        rv = DoEndpointLock();
        break;
      case STATE_OBTAIN_LOCK_COMPLETE:
        DCHECK_EQ(OK, rv);
        rv = DoEndpointLockComplete();
        break;
      case STATE_TRANSPORT_CONNECT_COMPLETE:
        rv = DoTransportConnectComplete(rv);
        break;
      default:
        NOTREACHED();
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE &&
           next_state_ != STATE_DONE);

  return rv;
}

int TransportConnectSubJob::DoEndpointLock() {
  next_state_ = STATE_OBTAIN_LOCK_COMPLETE;
  if (!parent_job_->websocket_endpoint_lock_manager()) {
    return OK;
  }
  return parent_job_->websocket_endpoint_lock_manager()->LockEndpoint(
      CurrentAddress(), this);
}

int TransportConnectSubJob::DoEndpointLockComplete() {
  next_state_ = STATE_TRANSPORT_CONNECT_COMPLETE;
  AddressList one_address(CurrentAddress());

  // Create a `SocketPerformanceWatcher`, and pass the ownership.
  std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher;
  if (auto* factory = parent_job_->socket_performance_watcher_factory();
      factory != nullptr) {
    socket_performance_watcher = factory->CreateSocketPerformanceWatcher(
        SocketPerformanceWatcherFactory::PROTOCOL_TCP,
        CurrentAddress().address());
  }

  const NetLogWithSource& net_log = parent_job_->net_log();
  transport_socket_ =
      parent_job_->client_socket_factory()->CreateTransportClientSocket(
          one_address, std::move(socket_performance_watcher),
          parent_job_->network_quality_estimator(), net_log.net_log(),
          net_log.source());

  net_log.AddEvent(NetLogEventType::TRANSPORT_CONNECT_JOB_CONNECT_ATTEMPT, [&] {
    auto dict = base::Value::Dict().Set("address", CurrentAddress().ToString());
    transport_socket_->NetLog().source().AddToEventParameters(dict);
    return dict;
  });

  // If `websocket_endpoint_lock_manager_` is non-null, this class now owns an
  // endpoint lock. Wrap `socket` in a `WebSocketStreamSocket` to take ownership
  // of the lock and release it when the socket goes out of scope. This must
  // happen before any early returns in this method.
  if (parent_job_->websocket_endpoint_lock_manager()) {
    transport_socket_ = std::make_unique<WebSocketStreamSocket>(
        std::move(transport_socket_),
        parent_job_->websocket_endpoint_lock_manager(), CurrentAddress());
  }

  transport_socket_->ApplySocketTag(parent_job_->socket_tag());

  // This use of base::Unretained() is safe because transport_socket_ is
  // destroyed in the destructor.
  return transport_socket_->Connect(base::BindOnce(
      &TransportConnectSubJob::OnIOComplete, base::Unretained(this)));
}

int TransportConnectSubJob::DoTransportConnectComplete(int result) {
  next_state_ = STATE_DONE;
  if (result != OK) {
    // Drop the socket to release the endpoint lock, if any.
    transport_socket_.reset();

    parent_job_->connection_attempts_.push_back(
        ConnectionAttempt(CurrentAddress(), result));

    // Don't try the next address if entering suspend mode.
    if (result != ERR_NETWORK_IO_SUSPENDED &&
        current_address_index_ + 1 < addresses_.size()) {
      // Try falling back to the next address in the list.
      next_state_ = STATE_OBTAIN_LOCK;
      ++current_address_index_;
      result = OK;
    }

    return result;
  }

  return result;
}

}  // namespace net
```