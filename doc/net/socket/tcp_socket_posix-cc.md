Response:
Let's break down the thought process for analyzing this C++ Chromium source code file.

**1. Understanding the Goal:**

The request asks for a breakdown of `net/socket/tcp_socket_posix.cc`. Specifically, it wants:

* **Functionality:** What does this code *do*?
* **JavaScript Relationship:**  Does it interact with the JavaScript layer in Chromium?
* **Logic and Examples:** Show how key functions work with input/output examples.
* **Common Errors:** What mistakes do users or programmers often make?
* **Debugging:** How does a user action lead to this code being executed?

**2. Initial Scan and Keyword Identification:**

First, I quickly scanned the code looking for familiar networking terms and patterns. Keywords like `socket`, `TCP`, `connect`, `bind`, `listen`, `read`, `write`, `close`, `keepalive`, and `nodelay` immediately jumped out. The `#include` directives also give clues about the underlying POSIX system calls being used (e.g., `<sys/socket.h>`, `<netinet/tcp.h>`). The filename itself, `tcp_socket_posix.cc`, is a strong indicator of its role.

**3. Identifying Core Classes and Structures:**

I noticed the class `TCPSocketPosix`. This is clearly the central class in the file. I also saw the use of `SocketPosix`, suggesting an internal helper class for lower-level socket operations. The use of `IOBuffer` indicates the handling of data being sent and received. `IPEndPoint` suggests the representation of network addresses.

**4. Mapping Functions to Functionality:**

I started going through the methods of `TCPSocketPosix` and mapping them to their corresponding networking actions:

* **`Open()`:**  Creates a new socket.
* **`Bind()`:**  Associates the socket with a local address and port.
* **`Listen()`:**  Marks the socket as listening for incoming connections.
* **`Accept()`:**  Accepts an incoming connection.
* **`Connect()`:**  Initiates a connection to a remote address.
* **`Read()`/`ReadIfReady()`:**  Receives data.
* **`Write()`:** Sends data.
* **`Close()`:**  Closes the socket.
* **`Set*()` methods:** Configure socket options (keepalive, nodelay, buffer sizes, etc.).
* **`GetLocalAddress()`/`GetPeerAddress()`:**  Retrieve socket addresses.

**5. Connecting to JavaScript (The "Bridge" Concept):**

The key here is understanding Chromium's architecture. JavaScript in the browser doesn't directly call POSIX socket functions. There's a layer of abstraction. I looked for clues about how this C++ code might be invoked from higher layers.

* **Network Stack:** The file is part of the `net` namespace, indicating it's part of Chromium's network stack.
* **`net_log_`:** The extensive use of `net_log_` suggests this code is involved in logging network events for debugging and monitoring. These logs can be accessed by developers.
* **`SocketPerformanceWatcher`:**  This suggests a mechanism for monitoring socket performance, likely used by higher-level network components.

The core idea is that JavaScript makes requests (e.g., fetch a web page), and this request travels down through Chromium's layers. Eventually, code like this `TCPSocketPosix` is used to establish the actual TCP connection.

**6. Developing Examples (Input/Output):**

For key functions like `Connect()`, `Read()`, and `Write()`, I considered the typical inputs and outputs:

* **`Connect()`:** Input: `IPEndPoint` (target address). Output: `OK` (success) or an `ERR_...` code (failure).
* **`Read()`:** Input: `IOBuffer` (to store data), buffer size. Output: Number of bytes read, or an `ERR_...` code.
* **`Write()`:** Input: `IOBuffer` (data to send), buffer size. Output: Number of bytes written, or an `ERR_...` code.

**7. Identifying Common Errors:**

I thought about common pitfalls when working with sockets:

* **Incorrect Address:** Trying to connect to an invalid IP address or port.
* **Socket Not Open/Connected:**  Trying to read or write on a socket that hasn't been opened or connected.
* **Firewall Issues:** External factors blocking connections.
* **Resource Limits:** Running out of available ports or file descriptors.
* **Network Unreachable:**  The destination network being unavailable.

**8. Tracing User Actions (Debugging Path):**

This requires thinking about how a user interacts with a web browser and how that triggers network activity:

* **Typing a URL:** This is the most common trigger. The browser needs to resolve the domain name (DNS), then establish a TCP connection to the server.
* **Clicking a Link:**  Similar to typing a URL.
* **Submitting a Form:**  Data needs to be sent to the server, involving a TCP connection.
* **JavaScript `fetch()` or `XMLHttpRequest`:** JavaScript can initiate network requests, which eventually lead to the underlying socket code.

The debugging path involves tracing the execution flow from the initial user action down through the browser's layers to the point where `TCPSocketPosix` is instantiated and its methods are called.

**9. Structuring the Answer:**

Finally, I organized the information into the categories requested by the prompt, using clear headings and examples. I tried to use precise language and explain concepts in a way that's understandable even to someone who isn't a networking expert. I also made sure to highlight the connection to JavaScript and provide concrete examples.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe I should go deep into the `SocketPosix` class.
* **Correction:**  The focus is on `TCPSocketPosix`. `SocketPosix` is an internal detail. Briefly mention it as a helper.
* **Initial thought:** Explain all the socket options in detail.
* **Correction:**  Focus on the most relevant ones like keepalive and nodelay, and why they're important in a browser context.
* **Initial thought:** Just list the errors.
* **Correction:** Provide specific examples of *how* these errors might occur.
* **Initial thought:**  The JavaScript connection is too abstract.
* **Correction:** Provide examples of JavaScript APIs (like `fetch`) that trigger this code. Emphasize the bridge concept.

By following this structured approach, identifying key concepts, and providing concrete examples, I was able to generate a comprehensive answer that addresses all aspects of the prompt.
好的，让我们来详细分析一下 `net/socket/tcp_socket_posix.cc` 这个文件。

**文件功能概述**

`net/socket/tcp_socket_posix.cc` 文件是 Chromium 网络栈中用于实现 TCP socket 在 POSIX 系统（例如 Linux, macOS, Android 等）上的操作的关键组件。它提供了一个 `TCPSocketPosix` 类，该类封装了底层的 POSIX socket API，并提供了 Chromium 网络栈中更高层使用的 TCP socket 功能。

主要功能包括：

1. **创建和管理 TCP Socket:**
   - `Open()`: 创建一个新的 TCP socket。
   - `AdoptConnectedSocket()`:  接管一个已连接的 socket 文件描述符。
   - `AdoptUnconnectedSocket()`: 接管一个未连接的 socket 文件描述符。
   - `Close()`: 关闭 socket。

2. **连接和监听:**
   - `Connect()`: 连接到远程主机。
   - `Bind()`: 绑定到本地地址和端口。
   - `Listen()`: 开始监听连接请求。
   - `Accept()`: 接受一个传入的连接。

3. **数据传输:**
   - `Read()`: 从 socket 读取数据。
   - `ReadIfReady()`:  如果 socket 可读则读取数据，非阻塞。
   - `CancelReadIfReady()`: 取消 `ReadIfReady()` 操作。
   - `Write()`: 向 socket 写入数据。

4. **获取 Socket 信息:**
   - `GetLocalAddress()`: 获取本地 socket 地址。
   - `GetPeerAddress()`: 获取远程 socket 地址。

5. **设置 Socket 选项:**
   - `SetDefaultOptionsForServer()`: 设置服务器端 socket 的默认选项 (例如，允许地址重用)。
   - `SetDefaultOptionsForClient()`: 设置客户端 socket 的默认选项 (例如，禁用 Nagle 算法，启用 Keep-Alive)。
   - `AllowAddressReuse()`: 允许地址重用 (SO_REUSEADDR)。
   - `SetReceiveBufferSize()`: 设置接收缓冲区大小。
   - `SetSendBufferSize()`: 设置发送缓冲区大小。
   - `SetKeepAlive()`: 设置 TCP Keep-Alive 选项。
   - `SetNoDelay()`: 设置 TCP_NODELAY 选项 (禁用 Nagle 算法)。
   - `SetIPv6Only()`:  设置 socket 为 IPv6-only。

6. **性能监控和日志:**
   - 使用 `SocketPerformanceWatcher` 监控 socket 性能。
   - 使用 `NetLog` 记录 socket 事件，用于调试和分析。

7. **与其他 Chromium 组件集成:**
   - 与 `NetworkChangeNotifier` 集成，监听网络状态变化。
   - 与 `NetworkTrafficAnnotationTag` 集成，标记网络流量类型。

**与 JavaScript 的关系及举例说明**

`TCPSocketPosix` 本身是一个底层的 C++ 类，JavaScript 代码无法直接调用它。然而，它为 Chromium 浏览器中由 JavaScript 发起的网络请求提供了底层支撑。当 JavaScript 代码执行网络操作时，例如：

* **使用 `fetch()` API 发起 HTTP 请求:**
  ```javascript
  fetch('https://www.example.com')
    .then(response => response.text())
    .then(data => console.log(data));
  ```
  在这个过程中，Chromium 的网络栈会创建 `TCPSocketPosix` 对象，并通过其 `Connect()` 方法建立与 `www.example.com` 服务器的 TCP 连接。然后，使用 `Write()` 发送 HTTP 请求，并使用 `Read()` 接收 HTTP 响应。

* **使用 `WebSocket` API 创建 WebSocket 连接:**
  ```javascript
  const websocket = new WebSocket('wss://echo.websocket.events');

  websocket.onopen = () => {
    console.log('WebSocket connected');
    websocket.send('Hello');
  };

  websocket.onmessage = (event) => {
    console.log('Received:', event.data);
  };
  ```
  `WebSocket` 连接也基于 TCP。当 JavaScript 创建 `WebSocket` 对象时，底层也会使用 `TCPSocketPosix` 来建立连接和进行双向数据传输。

**逻辑推理及假设输入输出**

**假设场景：客户端发起 HTTP GET 请求**

1. **假设输入:**
   - JavaScript 代码调用 `fetch('https://www.example.com/data.json')`。
   - 假设 DNS 解析已完成，`www.example.com` 的 IP 地址为 `93.184.216.34`，端口为 `443`（HTTPS）。

2. **`TCPSocketPosix::Connect()` 的调用:**
   - 输入：`IPEndPoint(93.184.216.34, 443)`，以及一个完成回调函数。
   - 底层会调用 `socket()->Connect()`，即 POSIX 的 `connect()` 系统调用。

3. **`connect()` 系统调用的行为 (简化):**
   - 如果连接成功，`connect()` 返回 0，`TCPSocketPosix::HandleConnectCompleted()` 被调用，并执行完成回调，返回 `OK`。
   - 如果连接失败，`connect()` 返回 -1，并设置 `errno`。`TCPSocketPosix::HandleConnectCompleted()` 会根据 `errno` 将其转换为 Chromium 的网络错误码（例如 `ERR_CONNECTION_REFUSED`, `ERR_TIMEOUT` 等），并执行完成回调，返回相应的错误码。

4. **假设连接成功:**
   - `TCPSocketPosix::Connect()` 的输出将是 `OK`。
   - NetLog 中会记录连接成功的事件，包括本地和远程地址。

5. **发送 HTTP 请求 (涉及 `TCPSocketPosix::Write()`):**
   - 输入：一个包含 HTTP GET 请求头的 `IOBuffer`，以及请求头的长度。
   - 底层调用 `socket()->Write()`，即 POSIX 的 `send()` 系统调用。
   - 如果发送成功，`send()` 返回发送的字节数。`TCPSocketPosix::HandleWriteCompleted()` 被调用，执行完成回调，返回发送的字节数。

6. **接收 HTTP 响应 (涉及 `TCPSocketPosix::Read()`):**
   - 输入：一个用于存储接收数据的 `IOBuffer`，以及期望接收的最大字节数。
   - 底层调用 `socket()->Read()`，即 POSIX 的 `recv()` 系统调用。
   - 如果接收到数据，`recv()` 返回接收到的字节数。`TCPSocketPosix::HandleReadCompleted()` 被调用，执行完成回调，返回接收到的字节数。
   - 如果连接关闭，`recv()` 返回 0。
   - 如果发生错误，`recv()` 返回 -1，并设置 `errno`。`TCPSocketPosix::HandleReadCompleted()` 将其转换为 Chromium 的网络错误码。

**用户或编程常见的使用错误举例**

1. **尝试在未连接的 Socket 上进行读写操作:**
   - **用户操作:** 用户点击了一个需要加载资源的链接，但由于网络问题，连接一直未能建立成功。
   - **编程错误:** 在连接完成的回调函数被调用之前，尝试调用 `Read()` 或 `Write()`。
   - **结果:** `Read()` 或 `Write()` 方法会检查 socket 状态，如果未连接，通常会返回 `ERR_SOCKET_NOT_CONNECTED`。NetLog 中会记录相应的错误。

2. **忘记处理 `ERR_IO_PENDING`:**
   - **编程错误:** 在调用 `Connect()`, `Accept()`, `Read()`, `Write()` 等异步操作时，如果没有正确处理 `ERR_IO_PENDING` 返回值，可能会导致程序逻辑错误。这些操作在异步完成时会通过回调函数通知结果。

3. **不正确的 Socket 选项设置:**
   - **编程错误:**  例如，在需要低延迟的应用中，忘记调用 `SetNoDelay(true)`，导致 Nagle 算法延迟小包的发送。
   - **用户操作:** 用户可能会感受到网页加载速度缓慢。
   - **调试线索:** 通过 NetLog 可以查看 socket 选项的设置情况，以及数据包的发送和接收时间。

4. **资源泄漏:**
   - **编程错误:**  忘记在不再需要时调用 `Close()` 关闭 socket，导致文件描述符泄漏。
   - **用户操作:**  长时间使用浏览器，打开大量连接的网页或应用。
   - **结果:**  最终可能导致系统资源耗尽，新的连接无法建立。

5. **地址冲突 (在服务器端):**
   - **用户操作:**  尝试启动一个网络服务，但指定的端口已经被其他程序占用。
   - **编程错误:**  在调用 `Bind()` 之前没有检查端口是否可用。
   - **结果:** `Bind()` 方法会返回错误码，例如 `ERR_ADDRESS_IN_USE`。

**用户操作如何一步步到达这里 (作为调试线索)**

以下是一个用户在浏览器中输入网址并加载网页的简化流程，以及如何逐步触达到 `tcp_socket_posix.cc`:

1. **用户在地址栏输入 URL 并按下回车键，例如 `https://www.example.com`。**

2. **浏览器 UI 进程接收到用户输入，并启动导航。**

3. **浏览器 UI 进程向网络进程 (Network Service) 发起请求，请求加载该 URL。**

4. **网络进程接收到请求，开始处理：**
   - **DNS 解析:**  网络进程首先需要将域名 `www.example.com` 解析为 IP 地址。这可能涉及到 DNS 查询。
   - **建立 TCP 连接:**  一旦获取到 IP 地址，网络进程会创建一个 `TCPSocketPosix` 对象 (或其他平台相关的 Socket 实现)。
   - **调用 `TCPSocketPosix::Open()`:** 创建底层的 socket 文件描述符。
   - **调用 `TCPSocketPosix::Connect()`:**  尝试连接到服务器的 IP 地址和端口 (HTTPS 默认 443)。
     - 这会调用底层的 `connect()` 系统调用。
     - 如果连接是异步的，会返回 `ERR_IO_PENDING`，并注册回调函数。

5. **连接建立成功后：**
   - **发送 HTTP 请求:**  网络进程构建 HTTP 请求报文，并调用 `TCPSocketPosix::Write()` 将数据发送到服务器。这会调用底层的 `send()` 系统调用。

6. **接收 HTTP 响应：**
   - 网络进程调用 `TCPSocketPosix::Read()` 尝试从 socket 读取数据。这会调用底层的 `recv()` 系统调用。
   - 当接收到数据后，`Read()` 方法会将数据放入提供的缓冲区。

7. **数据处理和渲染：**
   - 网络进程接收到完整的 HTTP 响应后，会进行解析。
   - 响应数据会被传递回浏览器进程，最终由渲染引擎进行渲染，显示在用户的浏览器窗口中。

**调试线索:**

* **NetLog (chrome://net-internals/#events):**  这是调试 Chromium 网络问题的关键工具。NetLog 会记录所有网络相关的事件，包括 socket 的创建、连接、数据传输、错误等。通过 NetLog，你可以看到 `TCPSocketPosix` 的方法何时被调用，以及它们的返回值和参数。你可以搜索与特定连接或主机相关的事件，以跟踪整个过程。

* **断点调试:**  如果你有 Chromium 的源代码和调试环境，可以在 `tcp_socket_posix.cc` 中的关键方法（如 `Connect`, `Read`, `Write`）设置断点，逐步跟踪代码的执行，查看变量的值，以及系统调用的返回值。

* **系统工具:**  使用系统提供的网络工具，如 `tcpdump` 或 Wireshark，可以捕获网络数据包，查看 TCP 连接的建立过程、数据传输内容等，从而辅助理解 `TCPSocketPosix` 的行为。

总而言之，`net/socket/tcp_socket_posix.cc` 是 Chromium 网络栈中负责实际 TCP 通信的基石。理解它的功能和工作原理，对于理解 Chromium 的网络行为和进行网络相关的调试至关重要。

### 提示词
```
这是目录为net/socket/tcp_socket_posix.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/tcp_socket.h"

#include <errno.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <algorithm>
#include <memory>

#include "base/atomicops.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/posix/eintr_wrapper.h"
#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "net/base/address_list.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_activity_monitor.h"
#include "net/base/network_change_notifier.h"
#include "net/base/sockaddr_storage.h"
#include "net/base/sys_addrinfo.h"
#include "net/base/tracing.h"
#include "net/http/http_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_values.h"
#include "net/socket/socket_net_log_params.h"
#include "net/socket/socket_options.h"
#include "net/socket/socket_posix.h"
#include "net/socket/socket_tag.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

#if BUILDFLAG(IS_ANDROID)
#include "net/android/network_library.h"
#endif  // BUILDFLAG(IS_ANDROID)

// If we don't have a definition for TCPI_OPT_SYN_DATA, create one.
#if !defined(TCPI_OPT_SYN_DATA)
#define TCPI_OPT_SYN_DATA 32
#endif

// Fuchsia defines TCP_INFO, but it's not implemented.
// TODO(crbug.com/42050612): Enable TCP_INFO on Fuchsia once it's implemented
// there (see NET-160).
#if defined(TCP_INFO) && !BUILDFLAG(IS_FUCHSIA)
#define HAVE_TCP_INFO
#endif

namespace net {

namespace {

// SetTCPKeepAlive sets SO_KEEPALIVE.
bool SetTCPKeepAlive(int fd, bool enable, int delay) {
  // Enabling TCP keepalives is the same on all platforms.
  int on = enable ? 1 : 0;
  if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on))) {
    PLOG(ERROR) << "Failed to set SO_KEEPALIVE on fd: " << fd;
    return false;
  }

  // If we disabled TCP keep alive, our work is done here.
  if (!enable)
    return true;

  // A delay of 0 doesn't work, and is the default, so ignore that and rely on
  // whatever the OS defaults are once we turned it on above.
  if (delay) {
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID)
    // Setting the keepalive interval varies by platform.

    // Set seconds until first TCP keep alive.
    if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &delay, sizeof(delay))) {
      PLOG(ERROR) << "Failed to set TCP_KEEPIDLE on fd: " << fd;
      return false;
    }
    // Set seconds between TCP keep alives.
    if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &delay, sizeof(delay))) {
      PLOG(ERROR) << "Failed to set TCP_KEEPINTVL on fd: " << fd;
      return false;
    }
#elif BUILDFLAG(IS_APPLE)
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &delay, sizeof(delay))) {
      PLOG(ERROR) << "Failed to set TCP_KEEPALIVE on fd: " << fd;
      return false;
    }
#endif
  }

  return true;
}

#if defined(HAVE_TCP_INFO)
// Returns a zero value if the transport RTT is unavailable.
base::TimeDelta GetTransportRtt(SocketDescriptor fd) {
  // It is possible for the value returned by getsockopt(TCP_INFO) to be
  // legitimately zero due to the way the RTT is calculated where fractions are
  // rounded down. This is specially true for virtualized environments with
  // paravirtualized clocks.
  //
  // If getsockopt(TCP_INFO) succeeds and the tcpi_rtt is zero, this code
  // assumes that the RTT got rounded down to zero and rounds it back up to this
  // value so that callers can assume that no packets defy the laws of physics.
  constexpr uint32_t kMinValidRttMicros = 1;

  tcp_info info;
  // Reset |tcpi_rtt| to verify if getsockopt() actually updates |tcpi_rtt|.
  info.tcpi_rtt = 0;

  socklen_t info_len = sizeof(tcp_info);
  if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &info_len) != 0)
    return base::TimeDelta();

  // Verify that |tcpi_rtt| in tcp_info struct was updated. Note that it's
  // possible that |info_len| is shorter than |sizeof(tcp_info)| which implies
  // that only a subset of values in |info| may have been updated by
  // getsockopt().
  if (info_len < static_cast<socklen_t>(offsetof(tcp_info, tcpi_rtt) +
                                        sizeof(info.tcpi_rtt))) {
    return base::TimeDelta();
  }

  return base::Microseconds(std::max(info.tcpi_rtt, kMinValidRttMicros));
}

#endif  // defined(TCP_INFO)

}  // namespace

//-----------------------------------------------------------------------------

// static
std::unique_ptr<TCPSocketPosix> TCPSocketPosix::Create(
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetLog* net_log,
    const NetLogSource& source) {
  return base::WrapUnique(new TCPSocketPosix(
      std::move(socket_performance_watcher), net_log, source));
}

// static
std::unique_ptr<TCPSocketPosix> TCPSocketPosix::Create(
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetLogWithSource net_log_source) {
  return base::WrapUnique(new TCPSocketPosix(
      std::move(socket_performance_watcher), net_log_source));
}

TCPSocketPosix::TCPSocketPosix(
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetLog* net_log,
    const NetLogSource& source)
    : socket_performance_watcher_(std::move(socket_performance_watcher)),
      net_log_(NetLogWithSource::Make(net_log, NetLogSourceType::SOCKET)) {
  net_log_.BeginEventReferencingSource(NetLogEventType::SOCKET_ALIVE, source);
}

TCPSocketPosix::TCPSocketPosix(
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetLogWithSource net_log_source)
    : socket_performance_watcher_(std::move(socket_performance_watcher)),
      net_log_(net_log_source) {
  net_log_.BeginEvent(NetLogEventType::SOCKET_ALIVE);
}

TCPSocketPosix::~TCPSocketPosix() {
  net_log_.EndEvent(NetLogEventType::SOCKET_ALIVE);
  Close();
}

int TCPSocketPosix::Open(AddressFamily family) {
  DCHECK(!socket_);
  socket_ = std::make_unique<SocketPosix>();
  int rv = socket_->Open(ConvertAddressFamily(family));
  if (rv != OK)
    socket_.reset();
  if (rv == OK && tag_ != SocketTag())
    tag_.Apply(socket_->socket_fd());
  return rv;
}

int TCPSocketPosix::BindToNetwork(handles::NetworkHandle network) {
  DCHECK(IsValid());
  DCHECK(!IsConnected());
#if BUILDFLAG(IS_ANDROID)
  return net::android::BindToNetwork(socket_->socket_fd(), network);
#else
  NOTIMPLEMENTED();
  return ERR_NOT_IMPLEMENTED;
#endif  // BUILDFLAG(IS_ANDROID)
}

int TCPSocketPosix::AdoptConnectedSocket(SocketDescriptor socket,
                                         const IPEndPoint& peer_address) {
  DCHECK(!socket_);

  SockaddrStorage storage;
  if (!peer_address.ToSockAddr(storage.addr, &storage.addr_len) &&
      // For backward compatibility, allows the empty address.
      !(peer_address == IPEndPoint())) {
    return ERR_ADDRESS_INVALID;
  }

  socket_ = std::make_unique<SocketPosix>();
  int rv = socket_->AdoptConnectedSocket(socket, storage);
  if (rv != OK)
    socket_.reset();
  if (rv == OK && tag_ != SocketTag())
    tag_.Apply(socket_->socket_fd());
  return rv;
}

int TCPSocketPosix::AdoptUnconnectedSocket(SocketDescriptor socket) {
  DCHECK(!socket_);

  socket_ = std::make_unique<SocketPosix>();
  int rv = socket_->AdoptUnconnectedSocket(socket);
  if (rv != OK)
    socket_.reset();
  if (rv == OK && tag_ != SocketTag())
    tag_.Apply(socket_->socket_fd());
  return rv;
}

int TCPSocketPosix::Bind(const IPEndPoint& address) {
  DCHECK(socket_);

  SockaddrStorage storage;
  if (!address.ToSockAddr(storage.addr, &storage.addr_len))
    return ERR_ADDRESS_INVALID;

  return socket_->Bind(storage);
}

int TCPSocketPosix::Listen(int backlog) {
  DCHECK(socket_);
  return socket_->Listen(backlog);
}

int TCPSocketPosix::Accept(std::unique_ptr<TCPSocketPosix>* tcp_socket,
                           IPEndPoint* address,
                           CompletionOnceCallback callback) {
  DCHECK(tcp_socket);
  DCHECK(!callback.is_null());
  DCHECK(socket_);
  DCHECK(!accept_socket_);

  net_log_.BeginEvent(NetLogEventType::TCP_ACCEPT);

  int rv = socket_->Accept(
      &accept_socket_,
      base::BindOnce(&TCPSocketPosix::AcceptCompleted, base::Unretained(this),
                     tcp_socket, address, std::move(callback)));
  if (rv != ERR_IO_PENDING)
    rv = HandleAcceptCompleted(tcp_socket, address, rv);
  return rv;
}

int TCPSocketPosix::Connect(const IPEndPoint& address,
                            CompletionOnceCallback callback) {
  DCHECK(socket_);

  if (!logging_multiple_connect_attempts_)
    LogConnectBegin(AddressList(address));

  net_log_.BeginEvent(NetLogEventType::TCP_CONNECT_ATTEMPT,
                      [&] { return CreateNetLogIPEndPointParams(&address); });

  SockaddrStorage storage;
  if (!address.ToSockAddr(storage.addr, &storage.addr_len))
    return ERR_ADDRESS_INVALID;

  int rv = socket_->Connect(
      storage, base::BindOnce(&TCPSocketPosix::ConnectCompleted,
                              base::Unretained(this), std::move(callback)));
  if (rv != ERR_IO_PENDING)
    rv = HandleConnectCompleted(rv);
  return rv;
}

bool TCPSocketPosix::IsConnected() const {
  if (!socket_)
    return false;

  return socket_->IsConnected();
}

bool TCPSocketPosix::IsConnectedAndIdle() const {
  return socket_ && socket_->IsConnectedAndIdle();
}

int TCPSocketPosix::Read(IOBuffer* buf,
                         int buf_len,
                         CompletionOnceCallback callback) {
  DCHECK(socket_);
  DCHECK(!callback.is_null());

  int rv = socket_->Read(
      buf, buf_len,
      base::BindOnce(
          &TCPSocketPosix::ReadCompleted,
          // Grab a reference to |buf| so that ReadCompleted() can still
          // use it when Read() completes, as otherwise, this transfers
          // ownership of buf to socket.
          base::Unretained(this), base::WrapRefCounted(buf),
          std::move(callback)));
  if (rv != ERR_IO_PENDING)
    rv = HandleReadCompleted(buf, rv);
  return rv;
}

int TCPSocketPosix::ReadIfReady(IOBuffer* buf,
                                int buf_len,
                                CompletionOnceCallback callback) {
  DCHECK(socket_);
  DCHECK(!callback.is_null());

  int rv = socket_->ReadIfReady(
      buf, buf_len,
      base::BindOnce(&TCPSocketPosix::ReadIfReadyCompleted,
                     base::Unretained(this), std::move(callback)));
  if (rv != ERR_IO_PENDING)
    rv = HandleReadCompleted(buf, rv);
  return rv;
}

int TCPSocketPosix::CancelReadIfReady() {
  DCHECK(socket_);

  return socket_->CancelReadIfReady();
}

int TCPSocketPosix::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(socket_);
  DCHECK(!callback.is_null());

  CompletionOnceCallback write_callback = base::BindOnce(
      &TCPSocketPosix::WriteCompleted,
      // Grab a reference to |buf| so that WriteCompleted() can still
      // use it when Write() completes, as otherwise, this transfers
      // ownership of buf to socket.
      base::Unretained(this), base::WrapRefCounted(buf), std::move(callback));
  int rv;

  rv = socket_->Write(buf, buf_len, std::move(write_callback),
                      traffic_annotation);

  if (rv != ERR_IO_PENDING)
    rv = HandleWriteCompleted(buf, rv);
  return rv;
}

int TCPSocketPosix::GetLocalAddress(IPEndPoint* address) const {
  DCHECK(address);

  if (!socket_)
    return ERR_SOCKET_NOT_CONNECTED;

  SockaddrStorage storage;
  int rv = socket_->GetLocalAddress(&storage);
  if (rv != OK)
    return rv;

  if (!address->FromSockAddr(storage.addr, storage.addr_len))
    return ERR_ADDRESS_INVALID;

  return OK;
}

int TCPSocketPosix::GetPeerAddress(IPEndPoint* address) const {
  DCHECK(address);

  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;

  SockaddrStorage storage;
  int rv = socket_->GetPeerAddress(&storage);
  if (rv != OK)
    return rv;

  if (!address->FromSockAddr(storage.addr, storage.addr_len))
    return ERR_ADDRESS_INVALID;

  return OK;
}

int TCPSocketPosix::SetDefaultOptionsForServer() {
  DCHECK(socket_);
  return AllowAddressReuse();
}

void TCPSocketPosix::SetDefaultOptionsForClient() {
  DCHECK(socket_);

  // This mirrors the behaviour on Windows. See the comment in
  // tcp_socket_win.cc after searching for "NODELAY".
  // If SetTCPNoDelay fails, we don't care.
  SetTCPNoDelay(socket_->socket_fd(), true);

  // TCP keep alive wakes up the radio, which is expensive on mobile. Do not
  // enable it there. It's useful to prevent TCP middleboxes from timing out
  // connection mappings. Packets for timed out connection mappings at
  // middleboxes will either lead to:
  // a) Middleboxes sending TCP RSTs. It's up to higher layers to check for this
  // and retry. The HTTP network transaction code does this.
  // b) Middleboxes just drop the unrecognized TCP packet. This leads to the TCP
  // stack retransmitting packets per TCP stack retransmission timeouts, which
  // are very high (on the order of seconds). Given the number of
  // retransmissions required before killing the connection, this can lead to
  // tens of seconds or even minutes of delay, depending on OS.
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  const int kTCPKeepAliveSeconds = 45;

  SetTCPKeepAlive(socket_->socket_fd(), true, kTCPKeepAliveSeconds);
#endif
}

int TCPSocketPosix::AllowAddressReuse() {
  DCHECK(socket_);

  return SetReuseAddr(socket_->socket_fd(), true);
}

int TCPSocketPosix::SetReceiveBufferSize(int32_t size) {
  DCHECK(socket_);

  return SetSocketReceiveBufferSize(socket_->socket_fd(), size);
}

int TCPSocketPosix::SetSendBufferSize(int32_t size) {
  DCHECK(socket_);

  return SetSocketSendBufferSize(socket_->socket_fd(), size);
}

bool TCPSocketPosix::SetKeepAlive(bool enable, int delay) {
  if (!socket_)
    return false;

  return SetTCPKeepAlive(socket_->socket_fd(), enable, delay);
}

bool TCPSocketPosix::SetNoDelay(bool no_delay) {
  if (!socket_)
    return false;

  return SetTCPNoDelay(socket_->socket_fd(), no_delay) == OK;
}

int TCPSocketPosix::SetIPv6Only(bool ipv6_only) {
  CHECK(socket_);
  return ::net::SetIPv6Only(socket_->socket_fd(), ipv6_only);
}

void TCPSocketPosix::Close() {
  TRACE_EVENT("base", perfetto::StaticString{"CloseSocketTCP"});
  socket_.reset();
  tag_ = SocketTag();
}

bool TCPSocketPosix::IsValid() const {
  return socket_ != nullptr && socket_->socket_fd() != kInvalidSocket;
}

void TCPSocketPosix::DetachFromThread() {
  socket_->DetachFromThread();
}

void TCPSocketPosix::StartLoggingMultipleConnectAttempts(
    const AddressList& addresses) {
  if (!logging_multiple_connect_attempts_) {
    logging_multiple_connect_attempts_ = true;
    LogConnectBegin(addresses);
  } else {
    NOTREACHED();
  }
}

void TCPSocketPosix::EndLoggingMultipleConnectAttempts(int net_error) {
  if (logging_multiple_connect_attempts_) {
    LogConnectEnd(net_error);
    logging_multiple_connect_attempts_ = false;
  } else {
    NOTREACHED();
  }
}

SocketDescriptor TCPSocketPosix::ReleaseSocketDescriptorForTesting() {
  SocketDescriptor socket_descriptor = socket_->ReleaseConnectedSocket();
  socket_.reset();
  return socket_descriptor;
}

SocketDescriptor TCPSocketPosix::SocketDescriptorForTesting() const {
  return socket_->socket_fd();
}

void TCPSocketPosix::ApplySocketTag(const SocketTag& tag) {
  if (IsValid() && tag != tag_) {
    tag.Apply(socket_->socket_fd());
  }
  tag_ = tag;
}

void TCPSocketPosix::AcceptCompleted(
    std::unique_ptr<TCPSocketPosix>* tcp_socket,
    IPEndPoint* address,
    CompletionOnceCallback callback,
    int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  std::move(callback).Run(HandleAcceptCompleted(tcp_socket, address, rv));
}

int TCPSocketPosix::HandleAcceptCompleted(
    std::unique_ptr<TCPSocketPosix>* tcp_socket,
    IPEndPoint* address,
    int rv) {
  if (rv == OK)
    rv = BuildTcpSocketPosix(tcp_socket, address);

  if (rv == OK) {
    net_log_.EndEvent(NetLogEventType::TCP_ACCEPT,
                      [&] { return CreateNetLogIPEndPointParams(address); });
  } else {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::TCP_ACCEPT, rv);
  }

  return rv;
}

int TCPSocketPosix::BuildTcpSocketPosix(
    std::unique_ptr<TCPSocketPosix>* tcp_socket,
    IPEndPoint* address) {
  DCHECK(accept_socket_);

  SockaddrStorage storage;
  if (accept_socket_->GetPeerAddress(&storage) != OK ||
      !address->FromSockAddr(storage.addr, storage.addr_len)) {
    accept_socket_.reset();
    return ERR_ADDRESS_INVALID;
  }

  *tcp_socket =
      TCPSocketPosix::Create(nullptr, net_log_.net_log(), net_log_.source());
  (*tcp_socket)->socket_ = std::move(accept_socket_);
  return OK;
}

void TCPSocketPosix::ConnectCompleted(CompletionOnceCallback callback, int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  std::move(callback).Run(HandleConnectCompleted(rv));
}

int TCPSocketPosix::HandleConnectCompleted(int rv) {
  // Log the end of this attempt (and any OS error it threw).
  if (rv != OK) {
    net_log_.EndEventWithIntParams(NetLogEventType::TCP_CONNECT_ATTEMPT,
                                   "os_error", errno);
    tag_ = SocketTag();
  } else {
    net_log_.EndEvent(NetLogEventType::TCP_CONNECT_ATTEMPT);
    NotifySocketPerformanceWatcher();
  }

  // Give a more specific error when the user is offline.
  if (rv == ERR_ADDRESS_UNREACHABLE && NetworkChangeNotifier::IsOffline())
    rv = ERR_INTERNET_DISCONNECTED;

  if (!logging_multiple_connect_attempts_)
    LogConnectEnd(rv);

  return rv;
}

void TCPSocketPosix::LogConnectBegin(const AddressList& addresses) const {
  net_log_.BeginEvent(NetLogEventType::TCP_CONNECT,
                      [&] { return addresses.NetLogParams(); });
}

void TCPSocketPosix::LogConnectEnd(int net_error) const {
  if (net_error != OK) {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::TCP_CONNECT, net_error);
    return;
  }

  net_log_.EndEvent(NetLogEventType::TCP_CONNECT, [&] {
    net::IPEndPoint local_address;
    int net_error = GetLocalAddress(&local_address);
    net::IPEndPoint remote_address;
    if (net_error == net::OK)
      net_error = GetPeerAddress(&remote_address);
    if (net_error != net::OK)
      return NetLogParamsWithInt("get_address_net_error", net_error);
    return CreateNetLogAddressPairParams(local_address, remote_address);
  });
}

void TCPSocketPosix::ReadCompleted(const scoped_refptr<IOBuffer>& buf,
                                   CompletionOnceCallback callback,
                                   int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);

  std::move(callback).Run(HandleReadCompleted(buf.get(), rv));
}

void TCPSocketPosix::ReadIfReadyCompleted(CompletionOnceCallback callback,
                                          int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  DCHECK_GE(OK, rv);

  HandleReadCompletedHelper(rv);
  std::move(callback).Run(rv);
}

int TCPSocketPosix::HandleReadCompleted(IOBuffer* buf, int rv) {
  HandleReadCompletedHelper(rv);

  if (rv < 0)
    return rv;

  // Notify the watcher only if at least 1 byte was read.
  if (rv > 0)
    NotifySocketPerformanceWatcher();

  net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_RECEIVED, rv,
                                buf->data());
  activity_monitor::IncrementBytesReceived(rv);

  return rv;
}

void TCPSocketPosix::HandleReadCompletedHelper(int rv) {
  if (rv < 0) {
    NetLogSocketError(net_log_, NetLogEventType::SOCKET_READ_ERROR, rv, errno);
  }
}

void TCPSocketPosix::WriteCompleted(const scoped_refptr<IOBuffer>& buf,
                                    CompletionOnceCallback callback,
                                    int rv) {
  DCHECK_NE(ERR_IO_PENDING, rv);
  std::move(callback).Run(HandleWriteCompleted(buf.get(), rv));
}

int TCPSocketPosix::HandleWriteCompleted(IOBuffer* buf, int rv) {
  if (rv < 0) {
    NetLogSocketError(net_log_, NetLogEventType::SOCKET_WRITE_ERROR, rv, errno);
    return rv;
  }

  // Notify the watcher only if at least 1 byte was written.
  if (rv > 0)
    NotifySocketPerformanceWatcher();

  net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_SENT, rv,
                                buf->data());
  return rv;
}

void TCPSocketPosix::NotifySocketPerformanceWatcher() {
#if defined(HAVE_TCP_INFO)
  // Check if |socket_performance_watcher_| is interested in receiving a RTT
  // update notification.
  if (!socket_performance_watcher_ ||
      !socket_performance_watcher_->ShouldNotifyUpdatedRTT()) {
    return;
  }

  base::TimeDelta rtt = GetTransportRtt(socket_->socket_fd());
  if (rtt.is_zero())
    return;

  socket_performance_watcher_->OnUpdatedRTTAvailable(rtt);
#endif  // defined(TCP_INFO)
}

bool TCPSocketPosix::GetEstimatedRoundTripTime(base::TimeDelta* out_rtt) const {
  DCHECK(out_rtt);
  if (!socket_)
    return false;

#if defined(HAVE_TCP_INFO)
  base::TimeDelta rtt = GetTransportRtt(socket_->socket_fd());
  if (rtt.is_zero())
    return false;
  *out_rtt = rtt;
  return true;
#else
  return false;
#endif  // defined(TCP_INFO)
}

}  // namespace net
```