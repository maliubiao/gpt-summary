Response:
Let's break down the thought process for analyzing this `TCPClientSocket.cc` file.

1. **Understand the Goal:** The request asks for the functionality, relationship to JavaScript, logical reasoning examples, common user errors, and debugging steps. This requires a multi-faceted approach.

2. **Initial Skim for Core Functionality:**  Start by reading the class name and the high-level purpose. "TCPClientSocket" clearly indicates this is about establishing TCP client connections. The `#include` statements give clues about dependencies (like `TCPSocket`, `IOBuffer`, `AddressList`, `NetLog`).

3. **Identify Key Methods:** Look for public methods, especially those involved in the connection lifecycle:
    * Constructors (`TCPClientSocket(...)`): How is the object created? Notice the various overloads for different scenarios (existing socket, new connection, bound socket).
    * `Connect()`:  The main entry point for establishing a connection.
    * `Read()`, `Write()`:  Data transfer.
    * `Disconnect()`:  Closing the connection.
    * `Bind()`:  Binding to a local address.
    * `SetKeepAlive()`, `SetNoDelay()`: Socket options.
    * `GetPeerAddress()`, `GetLocalAddress()`:  Getting address information.

4. **Analyze Core Logic - The Connection Process:**  Focus on the `Connect()` method and its related parts:
    * **Multiple Addresses:** The constructor takes an `AddressList`. The `Connect()` method iterates through these addresses. This immediately suggests a fallback mechanism.
    * **Asynchronous Operations:** The use of `CompletionOnceCallback` strongly indicates asynchronous operations. This is crucial for understanding how the code interacts.
    * **State Machine:** The `next_connect_state_` variable and the `DoConnectLoop()` function clearly implement a state machine to manage the connection attempts. This helps track the progression through different stages.
    * **Error Handling:** Notice the handling of `ERR_IO_PENDING` and other error codes. The fallback logic in `DoConnectComplete()` is important.
    * **Timeouts:** The `connect_attempt_timer_` and `OnConnectAttemptTimeout()` indicate handling of connection timeouts.
    * **Before Connect Callback:** The `before_connect_callback_` allows for custom logic before the actual connection attempt.

5. **Consider JavaScript Relevance:** Think about how web browsers (which Chromium powers) use TCP sockets.
    * **`fetch()` API:**  The most obvious connection. `fetch()` initiates HTTP requests, which rely on TCP.
    * **WebSockets:**  Another direct user of TCP.
    * **Underlying Network Abstraction:** JavaScript doesn't directly manipulate sockets, but it uses browser APIs that internally manage them. The `TCPClientSocket` is part of that internal mechanism. Focus on how high-level JavaScript actions translate to this low-level code.

6. **Identify Potential User/Programming Errors:**  Think about common mistakes when dealing with network connections:
    * **Incorrect Addresses:**  Providing the wrong hostname or IP address.
    * **Firewall Issues:**  The server might be unreachable due to firewall rules.
    * **Network Problems:**  General connectivity issues.
    * **Server Not Listening:**  The target server isn't running or listening on the specified port.
    * **Calling methods in the wrong order:**  Trying to `Read()` before connecting, for instance.

7. **Trace User Actions to the Code:** Consider how a user's action in the browser might lead to this code being executed:
    * Typing a URL and pressing Enter.
    * Clicking a link.
    * JavaScript using `fetch()` or WebSockets. Focus on the initial steps of establishing the connection.

8. **Look for Hints in Code Comments and Pragmas:** The comments provide valuable context. For example, the comment about the `PowerMonitor` and suspend mode highlights a specific feature.

9. **Structure the Answer:** Organize the information logically:
    * **Functionality Overview:** Start with a summary of what the class does.
    * **Relationship to JavaScript:** Explain the connection through browser APIs.
    * **Logical Reasoning Examples:** Create concrete scenarios with inputs and outputs for key methods like `Connect()`.
    * **Common Errors:** List potential mistakes and explain why they occur.
    * **Debugging Steps:** Describe the user journey and how it leads to this code.

10. **Refine and Add Detail:** Go back through the code and add more specific details about each function. For example, describe the purpose of the `NetworkQualityEstimator`. Ensure the examples are clear and the explanations are concise.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just handles connecting."  **Correction:** Realized it also handles retries with multiple addresses, timeouts, and suspend/resume scenarios.
* **Initial thought:** "JavaScript directly uses this." **Correction:**  JavaScript uses browser APIs that *internally* use this. Clarified the abstraction layer.
* **Reviewing examples:**  Ensured the input and output examples were realistic and covered different outcomes (success, failure, pending).
* **Checking for completeness:**  Made sure to address all aspects of the prompt (functionality, JavaScript, reasoning, errors, debugging).

By following this systematic approach, combining code analysis with an understanding of networking concepts and browser architecture, a comprehensive and accurate answer can be constructed.
这个 `net/socket/tcp_client_socket.cc` 文件是 Chromium 网络栈中 `TCPClientSocket` 类的实现。 `TCPClientSocket` 的主要功能是作为 TCP 客户端套接字的抽象，用于建立和管理与服务器的 TCP 连接。

以下是该文件的主要功能列表：

**核心功能：**

* **建立 TCP 连接 (Connect):**
    * 尝试连接到由 `AddressList` 提供的多个 IP 地址和端口的服务器。
    * 支持连接重试机制，如果连接第一个地址失败，会尝试连接列表中的下一个地址。
    * 提供异步连接接口，通过回调函数通知连接结果。
    * 可以设置连接前的回调函数 (`BeforeConnectCallback`)，允许在连接前执行一些自定义操作。
    * 可以绑定到特定的本地 IP 地址 (`Bind`)。
    * 支持连接超时机制 (`connect_attempt_timer_`)，防止无限期等待连接。
* **数据传输 (Read, Write):**
    * 提供 `Read` 方法从连接的套接字接收数据。
    * 提供 `Write` 方法向连接的套接字发送数据。
    * 提供 `ReadIfReady` 和 `CancelReadIfReady` 方法，用于非阻塞读取。
    * 数据传输操作是异步的，通过回调函数通知结果。
* **套接字管理:**
    * 创建和销毁底层的 `TCPSocket` 对象。
    * 设置套接字选项，例如 Keep-Alive (`SetKeepAlive`) 和 No-Delay (Nagle 算法) (`SetNoDelay`)。
    * 获取本地和远程地址信息 (`GetLocalAddress`, `GetPeerAddress`)。
    * 关闭连接 (`Disconnect`)。
* **网络状态监控:**
    * 集成 `NetworkQualityEstimator` 用于获取网络质量信息，并可能根据网络状况调整连接超时时间。
    * 监听系统挂起事件 (`OnSuspend`)，并在挂起时断开连接并记录状态。
* **性能监控:**
    * 使用 `SocketPerformanceWatcher` 监控连接性能。
* **日志记录:**
    * 使用 `NetLog` 记录连接和数据传输事件，用于调试。
* **流量注解:**
    * 支持 `NetworkTrafficAnnotationTag`，用于标记网络流量的用途。

**与 JavaScript 功能的关系及举例说明：**

`TCPClientSocket` 位于 Chromium 的网络栈底层，JavaScript 代码本身并不能直接访问或操作它。然而，JavaScript 通过浏览器提供的 Web API（例如 `fetch`、`XMLHttpRequest`、`WebSocket`）进行网络通信时，底层的实现会涉及到 `TCPClientSocket`。

**举例说明：**

当 JavaScript 代码使用 `fetch` API 发起一个 HTTP 请求时，浏览器会执行以下（简化的）步骤：

1. **DNS 解析:**  根据 URL 中的域名解析出服务器的 IP 地址。
2. **建立 TCP 连接:**  Chromium 网络栈会使用 `TCPClientSocket` 来建立与服务器的 TCP 连接。这包括选择合适的 IP 地址（如果解析出多个）、执行 TCP 三次握手等操作。
3. **发送 HTTP 请求:** 一旦 TCP 连接建立，浏览器会通过该连接发送 HTTP 请求头和请求体。`TCPClientSocket` 的 `Write` 方法会被调用来发送这些数据。
4. **接收 HTTP 响应:** 服务器通过 TCP 连接返回 HTTP 响应。`TCPClientSocket` 的 `Read` 方法会被调用来接收这些数据。
5. **关闭 TCP 连接 (可能):**  根据 HTTP 协议和连接策略，TCP 连接可能会被保持或关闭。如果关闭，会调用 `TCPClientSocket` 的 `Disconnect` 方法。

**假设输入与输出 (逻辑推理)：**

假设我们创建一个 `TCPClientSocket` 实例，并尝试连接到 `www.example.com:80`。

**假设输入：**

* `addresses`:  经过 DNS 解析后得到的 `www.example.com` 的 IP 地址列表，例如 `[192.0.2.1:80, 192.0.2.2:80]`。
* 调用 `Connect(callback)` 方法。

**可能输出：**

* **成功连接:** 回调函数 `callback` 被调用，参数为 `net::OK`。可以通过 `GetPeerAddress` 获取连接的服务器地址。
* **连接失败 (例如，服务器不可达):** 回调函数 `callback` 被调用，参数为错误码，例如 `net::ERR_CONNECTION_REFUSED` 或 `net::ERR_CONNECTION_TIMED_OUT`。
* **连接超时:** 如果启用了连接超时功能，且在设定的时间内未能建立连接，回调函数 `callback` 被调用，参数为 `net::ERR_TIMED_OUT`。
* **网络挂起 (如果系统进入挂起状态):** 回调函数 `callback` 被调用，参数为 `net::ERR_NETWORK_IO_SUSPENDED`。

**用户或编程常见的使用错误举例说明：**

1. **未进行 DNS 解析就尝试连接:**  `TCPClientSocket` 需要提供服务器的 IP 地址才能建立连接。如果直接使用域名，需要先进行 DNS 解析。
   * **错误示例:**  直接将 `AddressList("www.example.com:80")` 传递给构造函数，而不是先解析出 IP 地址。
   * **后果:** 连接会失败，返回相关的 DNS 解析错误码。

2. **在连接建立之前尝试读写数据:**  必须在 `Connect` 方法成功返回（回调函数收到 `net::OK`）后才能进行数据传输。
   * **错误示例:**  在调用 `Connect` 后立即调用 `Read` 或 `Write`。
   * **后果:**  `Read` 或 `Write` 操作可能会失败，返回错误码，或者行为未定义。

3. **忘记处理异步操作的回调:**  `Connect`、`Read` 和 `Write` 都是异步操作，需要通过回调函数获取结果。如果忘记设置或处理回调函数，将无法知道操作是否成功或失败。
   * **错误示例:**  调用 `Connect` 但不提供回调函数。
   * **后果:**  程序无法得知连接状态，可能导致后续操作出现错误。

4. **在套接字已经连接或正在连接时尝试绑定:**  `Bind` 方法只能在套接字未连接且未尝试连接时调用。
   * **错误示例:**  在调用 `Connect` 之后再次调用 `Bind`。
   * **后果:**  `Bind` 方法会断言失败 (`NOTREACHED()`)。

**用户操作如何一步步地到达这里 (作为调试线索)：**

以下是一个用户在浏览器中输入网址并访问网页的场景，以及如何追踪到 `TCPClientSocket`:

1. **用户在地址栏输入 `https://www.example.com` 并按下 Enter 键。**
2. **浏览器 UI 进程接收到请求。**
3. **UI 进程将请求传递给网络进程 (Network Service)。**
4. **网络进程开始处理请求：**
    * **DNS 解析:** 网络进程会查询 DNS 服务器以获取 `www.example.com` 的 IP 地址。
    * **建立 TLS 连接 (如果使用 HTTPS):**
        * 网络进程会创建一个 `TCPClientSocket` 实例。
        * `TCPClientSocket` 的构造函数会被调用，传入解析得到的 IP 地址和端口 (443)。
        * 调用 `TCPClientSocket::Connect()` 方法尝试建立 TCP 连接。
        * 如果连接成功，后续会进行 TLS 握手。TLS 握手可能会涉及到 `net::SSLClientSocket` 等其他类，但底层仍然依赖于建立好的 TCP 连接。
    * **建立 TCP 连接 (如果使用 HTTP):**
        * 网络进程会创建一个 `TCPClientSocket` 实例。
        * `TCPClientSocket` 的构造函数会被调用，传入解析得到的 IP 地址和端口 (80)。
        * 调用 `TCPClientSocket::Connect()` 方法尝试建立 TCP 连接。
5. **发送 HTTP 请求:** 一旦 TCP 连接建立（以及 TLS 握手完成，如果是 HTTPS），网络进程会构建 HTTP 请求，并调用 `TCPClientSocket::Write()` 方法通过 TCP 连接发送请求数据。
6. **接收 HTTP 响应:** 服务器返回 HTTP 响应数据，网络进程调用 `TCPClientSocket::Read()` 方法接收数据。
7. **数据处理和渲染:**  接收到的数据会被网络进程处理，并最终传递给渲染进程进行页面渲染。

**调试线索:**

* **网络日志 (NetLog):** Chromium 提供了强大的网络日志功能，可以记录详细的网络事件，包括 `TCPClientSocket` 的连接尝试、状态变化、数据传输等。通过查看 NetLog，可以追踪连接建立的每一步，包括尝试连接的 IP 地址、连接结果、错误信息等。
* **断点调试:** 可以在 `TCPClientSocket` 的关键方法（例如 `Connect`、`Read`、`Write`）设置断点，观察程序的执行流程和变量状态。
* **抓包工具 (例如 Wireshark):**  可以使用抓包工具捕获网络数据包，分析 TCP 三次握手过程、数据传输内容等，从而验证 `TCPClientSocket` 的行为是否符合预期。

总而言之，`net/socket/tcp_client_socket.cc` 中实现的 `TCPClientSocket` 类是 Chromium 网络栈中处理 TCP 客户端连接的核心组件，它为上层网络协议（如 HTTP、WebSocket）提供了可靠的传输基础。理解其功能对于调试网络问题和理解 Chromium 的网络架构至关重要。

Prompt: 
```
这是目录为net/socket/tcp_client_socket.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/tcp_client_socket.h"

#include <memory>
#include <utility>

#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/time/time.h"
#include "net/base/features.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

#if defined(TCP_CLIENT_SOCKET_OBSERVES_SUSPEND)
#include "base/power_monitor/power_monitor.h"
#endif

namespace net {

class NetLogWithSource;

TCPClientSocket::TCPClientSocket(
    const AddressList& addresses,
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetworkQualityEstimator* network_quality_estimator,
    net::NetLog* net_log,
    const net::NetLogSource& source,
    handles::NetworkHandle network)
    : TCPClientSocket(TCPSocket::Create(std::move(socket_performance_watcher),
                                        net_log,
                                        source),
                      addresses,
                      -1 /* current_address_index */,
                      nullptr /* bind_address */,
                      network_quality_estimator,
                      network) {}

TCPClientSocket::TCPClientSocket(std::unique_ptr<TCPSocket> connected_socket,
                                 const IPEndPoint& peer_address)
    : TCPClientSocket(std::move(connected_socket),
                      AddressList(peer_address),
                      0 /* current_address_index */,
                      nullptr /* bind_address */,
                      // TODO(https://crbug.com/1123197: Pass non-null
                      // NetworkQualityEstimator
                      nullptr /* network_quality_estimator */,
                      handles::kInvalidNetworkHandle) {}

TCPClientSocket::TCPClientSocket(
    std::unique_ptr<TCPSocket> unconnected_socket,
    const AddressList& addresses,
    std::unique_ptr<IPEndPoint> bound_address,
    NetworkQualityEstimator* network_quality_estimator)
    : TCPClientSocket(std::move(unconnected_socket),
                      addresses,
                      -1 /* current_address_index */,
                      std::move(bound_address),
                      network_quality_estimator,
                      handles::kInvalidNetworkHandle) {}

TCPClientSocket::~TCPClientSocket() {
  Disconnect();
#if defined(TCP_CLIENT_SOCKET_OBSERVES_SUSPEND)
  base::PowerMonitor::GetInstance()->RemovePowerSuspendObserver(this);
#endif  // defined(TCP_CLIENT_SOCKET_OBSERVES_SUSPEND)
}

std::unique_ptr<TCPClientSocket> TCPClientSocket::CreateFromBoundSocket(
    std::unique_ptr<TCPSocket> bound_socket,
    const AddressList& addresses,
    const IPEndPoint& bound_address,
    NetworkQualityEstimator* network_quality_estimator) {
  return base::WrapUnique(new TCPClientSocket(
      std::move(bound_socket), addresses, -1 /* current_address_index */,
      std::make_unique<IPEndPoint>(bound_address), network_quality_estimator,
      handles::kInvalidNetworkHandle));
}

int TCPClientSocket::Bind(const IPEndPoint& address) {
  if (current_address_index_ >= 0 || bind_address_) {
    // Cannot bind the socket if we are already connected or connecting.
    NOTREACHED();
  }

  int result = OK;
  if (!socket_->IsValid()) {
    result = OpenSocket(address.GetFamily());
    if (result != OK)
      return result;
  }

  result = socket_->Bind(address);
  if (result != OK)
    return result;

  bind_address_ = std::make_unique<IPEndPoint>(address);
  return OK;
}

bool TCPClientSocket::SetKeepAlive(bool enable, int delay) {
  return socket_->SetKeepAlive(enable, delay);
}

bool TCPClientSocket::SetNoDelay(bool no_delay) {
  return socket_->SetNoDelay(no_delay);
}

void TCPClientSocket::SetBeforeConnectCallback(
    const BeforeConnectCallback& before_connect_callback) {
  DCHECK_EQ(CONNECT_STATE_NONE, next_connect_state_);
  before_connect_callback_ = before_connect_callback;
}

int TCPClientSocket::Connect(CompletionOnceCallback callback) {
  DCHECK(!callback.is_null());

  // If connecting or already connected, then just return OK.
  if (socket_->IsValid() && current_address_index_ >= 0)
    return OK;

  DCHECK(!read_callback_);
  DCHECK(!write_callback_);

  if (was_disconnected_on_suspend_) {
    Disconnect();
    was_disconnected_on_suspend_ = false;
  }

  socket_->StartLoggingMultipleConnectAttempts(addresses_);

  // We will try to connect to each address in addresses_. Start with the
  // first one in the list.
  next_connect_state_ = CONNECT_STATE_CONNECT;
  current_address_index_ = 0;

  int rv = DoConnectLoop(OK);
  if (rv == ERR_IO_PENDING) {
    connect_callback_ = std::move(callback);
  } else {
    socket_->EndLoggingMultipleConnectAttempts(rv);
  }

  return rv;
}

TCPClientSocket::TCPClientSocket(
    std::unique_ptr<TCPSocket> socket,
    const AddressList& addresses,
    int current_address_index,
    std::unique_ptr<IPEndPoint> bind_address,
    NetworkQualityEstimator* network_quality_estimator,
    handles::NetworkHandle network)
    : socket_(std::move(socket)),
      bind_address_(std::move(bind_address)),
      addresses_(addresses),
      current_address_index_(current_address_index),
      network_quality_estimator_(network_quality_estimator),
      network_(network) {
  DCHECK(socket_);
  if (socket_->IsValid())
    socket_->SetDefaultOptionsForClient();
#if defined(TCP_CLIENT_SOCKET_OBSERVES_SUSPEND)
  base::PowerMonitor::GetInstance()->AddPowerSuspendObserver(this);
#endif  // defined(TCP_CLIENT_SOCKET_OBSERVES_SUSPEND)
}

int TCPClientSocket::ReadCommon(IOBuffer* buf,
                                int buf_len,
                                CompletionOnceCallback callback,
                                bool read_if_ready) {
  DCHECK(!callback.is_null());
  DCHECK(read_callback_.is_null());

  if (was_disconnected_on_suspend_)
    return ERR_NETWORK_IO_SUSPENDED;

  // |socket_| is owned by |this| and the callback won't be run once |socket_|
  // is gone/closed. Therefore, it is safe to use base::Unretained() here.
  CompletionOnceCallback complete_read_callback =
      base::BindOnce(&TCPClientSocket::DidCompleteRead, base::Unretained(this));
  int result =
      read_if_ready
          ? socket_->ReadIfReady(buf, buf_len,
                                 std::move(complete_read_callback))
          : socket_->Read(buf, buf_len, std::move(complete_read_callback));
  if (result == ERR_IO_PENDING) {
    read_callback_ = std::move(callback);
  } else if (result > 0) {
    was_ever_used_ = true;
    total_received_bytes_ += result;
  }

  return result;
}

int TCPClientSocket::DoConnectLoop(int result) {
  DCHECK_NE(next_connect_state_, CONNECT_STATE_NONE);

  int rv = result;
  do {
    ConnectState state = next_connect_state_;
    next_connect_state_ = CONNECT_STATE_NONE;
    switch (state) {
      case CONNECT_STATE_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = DoConnect();
        break;
      case CONNECT_STATE_CONNECT_COMPLETE:
        rv = DoConnectComplete(rv);
        break;
      default:
        NOTREACHED() << "bad state " << state;
    }
  } while (rv != ERR_IO_PENDING && next_connect_state_ != CONNECT_STATE_NONE);

  return rv;
}

int TCPClientSocket::DoConnect() {
  DCHECK_GE(current_address_index_, 0);
  DCHECK_LT(current_address_index_, static_cast<int>(addresses_.size()));

  const IPEndPoint& endpoint = addresses_[current_address_index_];

  if (previously_disconnected_) {
    was_ever_used_ = false;
    previously_disconnected_ = false;
  }

  next_connect_state_ = CONNECT_STATE_CONNECT_COMPLETE;

  if (!socket_->IsValid()) {
    int result = OpenSocket(endpoint.GetFamily());
    if (result != OK)
      return result;

    if (bind_address_) {
      result = socket_->Bind(*bind_address_);
      if (result != OK) {
        socket_->Close();
        return result;
      }
    }
  }

  if (before_connect_callback_) {
    int result = before_connect_callback_.Run();
    DCHECK_NE(ERR_IO_PENDING, result);
    if (result != net::OK)
      return result;
  }

  // Notify |socket_performance_watcher_| only if the |socket_| is reused to
  // connect to a different IP Address.
  if (socket_->socket_performance_watcher() && current_address_index_ != 0)
    socket_->socket_performance_watcher()->OnConnectionChanged();

  start_connect_attempt_ = base::TimeTicks::Now();

  // Start a timer to fail the connect attempt if it takes too long.
  base::TimeDelta attempt_timeout = GetConnectAttemptTimeout();
  if (!attempt_timeout.is_max()) {
    DCHECK(!connect_attempt_timer_.IsRunning());
    connect_attempt_timer_.Start(
        FROM_HERE, attempt_timeout,
        base::BindOnce(&TCPClientSocket::OnConnectAttemptTimeout,
                       base::Unretained(this)));
  }

  return ConnectInternal(endpoint);
}

int TCPClientSocket::DoConnectComplete(int result) {
  if (start_connect_attempt_) {
    EmitConnectAttemptHistograms(result);
    start_connect_attempt_ = std::nullopt;
    connect_attempt_timer_.Stop();
  }

  if (result == OK)
    return OK;  // Done!

  // Don't try the next address if entering suspend mode.
  if (result == ERR_NETWORK_IO_SUSPENDED)
    return result;

  // Close whatever partially connected socket we currently have.
  DoDisconnect();

  // Try to fall back to the next address in the list.
  if (current_address_index_ + 1 < static_cast<int>(addresses_.size())) {
    next_connect_state_ = CONNECT_STATE_CONNECT;
    ++current_address_index_;
    return OK;
  }

  // Otherwise there is nothing to fall back to, so give up.
  return result;
}

void TCPClientSocket::OnConnectAttemptTimeout() {
  DidCompleteConnect(ERR_TIMED_OUT);
}

int TCPClientSocket::ConnectInternal(const IPEndPoint& endpoint) {
  // |socket_| is owned by this class and the callback won't be run once
  // |socket_| is gone. Therefore, it is safe to use base::Unretained() here.
  return socket_->Connect(endpoint,
                          base::BindOnce(&TCPClientSocket::DidCompleteConnect,
                                         base::Unretained(this)));
}

void TCPClientSocket::Disconnect() {
  DoDisconnect();
  current_address_index_ = -1;
  bind_address_.reset();

  // Cancel any pending callbacks. Not done in DoDisconnect() because that's
  // called on connection failure, when the connect callback will need to be
  // invoked.
  was_disconnected_on_suspend_ = false;
  connect_callback_.Reset();
  read_callback_.Reset();
  write_callback_.Reset();
}

void TCPClientSocket::DoDisconnect() {
  if (start_connect_attempt_) {
    EmitConnectAttemptHistograms(ERR_ABORTED);
    start_connect_attempt_ = std::nullopt;
    connect_attempt_timer_.Stop();
  }

  total_received_bytes_ = 0;

  // If connecting or already connected, record that the socket has been
  // disconnected.
  previously_disconnected_ = socket_->IsValid() && current_address_index_ >= 0;
  socket_->Close();

  // Invalidate weak pointers, so if in the middle of a callback in OnSuspend,
  // and something destroys this, no other callback is invoked.
  weak_ptr_factory_.InvalidateWeakPtrs();
}

bool TCPClientSocket::IsConnected() const {
  return socket_->IsConnected();
}

bool TCPClientSocket::IsConnectedAndIdle() const {
  return socket_->IsConnectedAndIdle();
}

int TCPClientSocket::GetPeerAddress(IPEndPoint* address) const {
  return socket_->GetPeerAddress(address);
}

int TCPClientSocket::GetLocalAddress(IPEndPoint* address) const {
  DCHECK(address);

  if (!socket_->IsValid()) {
    if (bind_address_) {
      *address = *bind_address_;
      return OK;
    }
    return ERR_SOCKET_NOT_CONNECTED;
  }

  return socket_->GetLocalAddress(address);
}

const NetLogWithSource& TCPClientSocket::NetLog() const {
  return socket_->net_log();
}

bool TCPClientSocket::WasEverUsed() const {
  return was_ever_used_;
}

NextProto TCPClientSocket::GetNegotiatedProtocol() const {
  return kProtoUnknown;
}

bool TCPClientSocket::GetSSLInfo(SSLInfo* ssl_info) {
  return false;
}

int TCPClientSocket::Read(IOBuffer* buf,
                          int buf_len,
                          CompletionOnceCallback callback) {
  return ReadCommon(buf, buf_len, std::move(callback), /*read_if_ready=*/false);
}

int TCPClientSocket::ReadIfReady(IOBuffer* buf,
                                 int buf_len,
                                 CompletionOnceCallback callback) {
  return ReadCommon(buf, buf_len, std::move(callback), /*read_if_ready=*/true);
}

int TCPClientSocket::CancelReadIfReady() {
  DCHECK(read_callback_);
  read_callback_.Reset();
  return socket_->CancelReadIfReady();
}

int TCPClientSocket::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(!callback.is_null());
  DCHECK(write_callback_.is_null());

  if (was_disconnected_on_suspend_)
    return ERR_NETWORK_IO_SUSPENDED;

  // |socket_| is owned by this class and the callback won't be run once
  // |socket_| is gone. Therefore, it is safe to use base::Unretained() here.
  CompletionOnceCallback complete_write_callback = base::BindOnce(
      &TCPClientSocket::DidCompleteWrite, base::Unretained(this));
  int result = socket_->Write(buf, buf_len, std::move(complete_write_callback),
                              traffic_annotation);
  if (result == ERR_IO_PENDING) {
    write_callback_ = std::move(callback);
  } else if (result > 0) {
    was_ever_used_ = true;
  }

  return result;
}

int TCPClientSocket::SetReceiveBufferSize(int32_t size) {
  return socket_->SetReceiveBufferSize(size);
}

int TCPClientSocket::SetSendBufferSize(int32_t size) {
  return socket_->SetSendBufferSize(size);
}

SocketDescriptor TCPClientSocket::SocketDescriptorForTesting() const {
  return socket_->SocketDescriptorForTesting();
}

int64_t TCPClientSocket::GetTotalReceivedBytes() const {
  return total_received_bytes_;
}

void TCPClientSocket::ApplySocketTag(const SocketTag& tag) {
  socket_->ApplySocketTag(tag);
}

void TCPClientSocket::OnSuspend() {
#if defined(TCP_CLIENT_SOCKET_OBSERVES_SUSPEND)
  // If the socket is connected, or connecting, act as if current and future
  // operations on the socket fail with ERR_NETWORK_IO_SUSPENDED, until the
  // socket is reconnected.

  if (next_connect_state_ != CONNECT_STATE_NONE) {
    socket_->Close();
    DidCompleteConnect(ERR_NETWORK_IO_SUSPENDED);
    return;
  }

  // Nothing to do. Use IsValid() rather than IsConnected() because it results
  // in more testable code, as when calling OnSuspend mode on two sockets
  // connected to each other will otherwise cause two sockets to behave
  // differently from each other.
  if (!socket_->IsValid())
    return;

  // Use Close() rather than Disconnect() / DoDisconnect() to avoid mutating
  // state, which more closely matches normal read/write error behavior.
  socket_->Close();

  was_disconnected_on_suspend_ = true;

  // Grab a weak pointer just in case calling read callback results in |this|
  // being destroyed, or disconnected. In either case, should not run the write
  // callback.
  base::WeakPtr<TCPClientSocket> weak_this = weak_ptr_factory_.GetWeakPtr();

  // Have to grab the write callback now, as it's theoretically possible for the
  // read callback to reconnects the socket, that reconnection to complete
  // synchronously, and then for it to start a new write. That also means this
  // code can't use DidCompleteWrite().
  CompletionOnceCallback write_callback = std::move(write_callback_);
  if (read_callback_)
    DidCompleteRead(ERR_NETWORK_IO_SUSPENDED);
  if (weak_this && write_callback)
    std::move(write_callback).Run(ERR_NETWORK_IO_SUSPENDED);
#endif  // defined(TCP_CLIENT_SOCKET_OBSERVES_SUSPEND)
}

void TCPClientSocket::DidCompleteConnect(int result) {
  DCHECK_EQ(next_connect_state_, CONNECT_STATE_CONNECT_COMPLETE);
  DCHECK_NE(result, ERR_IO_PENDING);
  DCHECK(!connect_callback_.is_null());

  result = DoConnectLoop(result);
  if (result != ERR_IO_PENDING) {
    socket_->EndLoggingMultipleConnectAttempts(result);
    std::move(connect_callback_).Run(result);
  }
}

void TCPClientSocket::DidCompleteRead(int result) {
  DCHECK(!read_callback_.is_null());

  if (result > 0)
    total_received_bytes_ += result;
  DidCompleteReadWrite(std::move(read_callback_), result);
}

void TCPClientSocket::DidCompleteWrite(int result) {
  DCHECK(!write_callback_.is_null());

  DidCompleteReadWrite(std::move(write_callback_), result);
}

void TCPClientSocket::DidCompleteReadWrite(CompletionOnceCallback callback,
                                           int result) {
  if (result > 0)
    was_ever_used_ = true;
  std::move(callback).Run(result);
}

int TCPClientSocket::OpenSocket(AddressFamily family) {
  DCHECK(!socket_->IsValid());

  int result = socket_->Open(family);
  if (result != OK)
    return result;

  if (network_ != handles::kInvalidNetworkHandle) {
    result = socket_->BindToNetwork(network_);
    if (result != OK) {
      socket_->Close();
      return result;
    }
  }

  socket_->SetDefaultOptionsForClient();

  return OK;
}

void TCPClientSocket::EmitConnectAttemptHistograms(int result) {
  // This should only be called in response to completing a connect attempt.
  DCHECK(start_connect_attempt_);

  base::TimeDelta duration =
      base::TimeTicks::Now() - start_connect_attempt_.value();

  // Histogram the total time the connect attempt took, grouped by success and
  // failure. Note that failures also include cases when the connect attempt
  // was cancelled by the client before the handshake completed.
  if (result == OK) {
    DEPRECATED_UMA_HISTOGRAM_MEDIUM_TIMES(
        "Net.TcpConnectAttempt.Latency.Success", duration);
  } else {
    DEPRECATED_UMA_HISTOGRAM_MEDIUM_TIMES("Net.TcpConnectAttempt.Latency.Error",
                                          duration);
  }
}

base::TimeDelta TCPClientSocket::GetConnectAttemptTimeout() {
  if (!base::FeatureList::IsEnabled(features::kTimeoutTcpConnectAttempt))
    return base::TimeDelta::Max();

  std::optional<base::TimeDelta> transport_rtt = std::nullopt;
  if (network_quality_estimator_)
    transport_rtt = network_quality_estimator_->GetTransportRTT();

  base::TimeDelta min_timeout = features::kTimeoutTcpConnectAttemptMin.Get();
  base::TimeDelta max_timeout = features::kTimeoutTcpConnectAttemptMax.Get();

  if (!transport_rtt)
    return max_timeout;

  base::TimeDelta adaptive_timeout =
      transport_rtt.value() *
      features::kTimeoutTcpConnectAttemptRTTMultiplier.Get();

  if (adaptive_timeout <= min_timeout)
    return min_timeout;

  if (adaptive_timeout >= max_timeout)
    return max_timeout;

  return adaptive_timeout;
}

}  // namespace net

"""

```