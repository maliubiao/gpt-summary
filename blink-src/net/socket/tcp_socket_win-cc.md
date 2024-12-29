Response:
My thinking process for analyzing the `tcp_socket_win.cc` file goes through several stages, aiming to fulfill all the requirements of the prompt:

1. **Understanding the Core Request:** The primary goal is to understand the functionality of this specific Chromium network stack file. Beyond that, I need to explore its relationship with JavaScript, consider potential logical inferences, identify common user errors, trace user interactions leading to this code, and finally, summarize its purpose.

2. **Initial Scan and Keyword Identification:** I start by quickly scanning the file for keywords and structural elements. I notice `#include` statements (indicating dependencies), namespaces (`net`), class definitions (`TCPSocketWin`, `TCPSocketDefaultWin`, `CoreImpl`), function names (`Read`, `Write`, `Connect`, `Accept`, `Bind`, `Listen`, `Close`), and Windows-specific types and functions (e.g., `SOCKET`, `WSA*`, `OVERLAPPED`, `HANDLE`). This immediately tells me the file deals with TCP socket implementation on Windows.

3. **Dissecting Class Structure and Relationships:** I focus on the main classes:
    * `TCPSocketWin`: This is the base class, likely providing a common interface for TCP sockets on Windows. It's abstract (has virtual methods).
    * `TCPSocketDefaultWin`: This is a concrete implementation of `TCPSocketWin`, using Windows-specific APIs directly (like `WSASend`, `recv`, `connect`).
    * `CoreImpl`:  This nested class seems to manage the underlying Windows resources and asynchronous operations, particularly using `WSAEventSelect` for event notification. It acts as a helper to `TCPSocketDefaultWin`.

4. **Analyzing Key Functionality (Method by Method):** I go through the prominent methods, understanding their purpose based on their names and code:
    * **Lifecycle Management:** `Open`, `Close`, destructors.
    * **Connection Management:** `Connect`, `Accept`, `Bind`, `Listen`, `IsConnected`, `IsConnectedAndIdle`.
    * **Data Transfer:** `Read`, `ReadIfReady`, `CancelReadIfReady`, `Write`. I notice the asynchronous nature, involving callbacks and the `OVERLAPPED` structure for writes and `WSAEventSelect` for reads and connects.
    * **Socket Options:** `Set*` methods for keep-alive, no-delay, buffer sizes, etc.
    * **Address Handling:** `GetLocalAddress`, `GetPeerAddress`.
    * **Error Handling:** The use of `MapSystemError` and `MapConnectError` to translate Windows error codes to Chromium's `net::ERR_*` values is crucial.
    * **Asynchronous Operations:**  The interaction between the main socket class and `CoreImpl` for managing asynchronous I/O using Windows event objects.

5. **Identifying Windows-Specific Aspects:** The extensive use of `WSA*` functions, the `OVERLAPPED` structure, and event handles (`HANDLE`) clearly marks this as a Windows-specific implementation. The inclusion of `<mstcpip.h>` further confirms this.

6. **Considering the Relationship with JavaScript:** This requires understanding how network operations in a browser relate to JavaScript. JavaScript running in a web page can't directly interact with these low-level socket APIs. Instead, it uses higher-level APIs like:
    * **`XMLHttpRequest` (XHR) / `fetch`:** These are the most common ways JavaScript makes network requests. The browser's networking stack (including this `tcp_socket_win.cc` file) handles the underlying TCP/IP communication when these APIs are used.
    * **WebSockets:**  A persistent, bidirectional communication protocol. The browser's WebSocket implementation would rely on lower-level socket code.
    * **WebRTC:** For real-time communication, which involves UDP and potentially TCP connections.

7. **Logical Inferences and Input/Output:**  For functions like `MapConnectError`, I can infer the input (a Windows error code like `WSAEACCES`) and the output (a `net::ERR_*` value like `ERR_NETWORK_ACCESS_DENIED`). For `SetTCPKeepAlive`, the input is a `SOCKET`, a boolean for enabling, and an integer for delay, while the output is a boolean indicating success.

8. **Identifying Common User Errors:** These typically arise from misuse of the higher-level APIs or misunderstanding network concepts. Examples include:
    * Trying to connect to a non-existent server (leading to timeouts).
    * Firewalls blocking connections (resulting in access denied errors).
    * Network connectivity issues (like being offline).

9. **Tracing User Operations (Debugging Perspective):** To reach this code, a user would likely:
    * Enter a URL in the browser.
    * Interact with a web page that makes network requests (using XHR, fetch, WebSockets, etc.).
    * The browser's networking stack would then create a TCP socket using this code to establish a connection with the remote server.

10. **Structuring the Response:** I organize the information logically, addressing each point of the prompt:
    * **Functionality:** A high-level overview, followed by detailed explanations of key areas like connection management, data transfer, and socket options.
    * **Relationship with JavaScript:** Explaining the indirect interaction through browser APIs.
    * **Logical Inferences:** Providing examples of input and output for specific functions.
    * **Common User Errors:**  Illustrating typical scenarios and their potential causes.
    * **User Operation Trace:**  Describing the steps leading to this code from a user's perspective.
    * **Summary:** A concise recap of the file's purpose.

11. **Refinement and Review:** I reread my analysis to ensure accuracy, clarity, and completeness, making any necessary corrections or additions. I double-check if all parts of the prompt are addressed adequately. For instance, I specifically look for examples related to JavaScript, even if the connection is indirect.

This systematic approach helps me thoroughly analyze the code and address all aspects of the prompt, going beyond just a superficial understanding of the file.
好的，我们来分析一下 `net/socket/tcp_socket_win.cc` 文件的功能。

**文件功能归纳**

这个文件是 Chromium 网络栈中用于 Windows 平台下 TCP 套接字的实现。它提供了创建、连接、监听、发送和接收 TCP 数据的功能，并处理了 Windows 平台特有的套接字操作和错误处理。

**详细功能列表**

1. **TCP 套接字的基本操作:**
   - **创建:**  `Open()` 函数用于创建 TCP 套接字 (使用 Windows 的 `WSASocketW` 或 `socket` 函数)。
   - **绑定地址:** `Bind()` 函数将套接字绑定到本地 IP 地址和端口。
   - **监听连接:** `Listen()` 函数使套接字开始监听传入的连接请求。
   - **接受连接:** `Accept()` 函数接受来自客户端的连接请求，创建一个新的 `TCPSocketWin` 对象来处理该连接。
   - **连接到服务器:** `Connect()` 函数用于连接到远程服务器。
   - **关闭连接:** `Close()` 函数关闭套接字，释放相关资源。

2. **数据传输:**
   - **发送数据:** `Write()` 函数用于向连接的另一端发送数据 (使用 Windows 的 `WSASend` 函数，支持异步操作)。
   - **接收数据:** `Read()` 和 `ReadIfReady()` 函数用于从连接的另一端接收数据 (使用 Windows 的 `recv` 函数，支持异步读取和非阻塞读取)。
   - **取消读取:** `CancelReadIfReady()` 用于取消正在进行的非阻塞读取操作。

3. **套接字属性和选项设置:**
   - **获取本地地址:** `GetLocalAddress()` 获取套接字绑定的本地 IP 地址和端口。
   - **获取对端地址:** `GetPeerAddress()` 获取连接的远程 IP 地址和端口。
   - **设置接收缓冲区大小:** `SetReceiveBufferSize()`。
   - **设置发送缓冲区大小:** `SetSendBufferSize()`。
   - **设置 Keep-Alive:** `SetKeepAlive()` 用于启用或禁用 TCP Keep-Alive 机制，防止连接因 NAT 超时而断开。
   - **禁用 Nagle 算法:** `SetNoDelay()` 用于禁用 Nagle 算法，减少小包延迟。
   - **设置 SO_EXCLUSIVEADDRUSE:** `SetExclusiveAddrUse()` 用于防止其他进程占用相同的本地地址和端口。
   - **设置 IPV6_V6ONLY:** `SetIPv6Only()` 用于限制套接字仅使用 IPv6。
   - **设置 SO_RANDOMIZE_PORT:** 在 Windows 10 20H1 及以上版本中，`DoConnect()` 函数中会尝试设置 `SO_RANDOMIZE_PORT` 选项，以提高客户端连接的安全性。

4. **异步操作处理 (通过 `CoreImpl` 类):**
   - 使用 `WSAEventSelect` 或 IO 完成端口 (通过 `TcpSocketIoCompletionPortWin`，由宏控制) 来处理异步的连接、读取和写入操作。
   - `CoreImpl` 类管理用于异步操作的 Windows 事件对象 (`read_event_`, `write_overlapped_.hEvent`) 和 `OVERLAPPED` 结构。
   - 使用 `base::win::ObjectWatcher` 来监听这些事件。

5. **错误处理:**
   - 使用 `WSAGetLastError()` 获取 Windows 套接字 API 的错误代码。
   - 使用 `MapSystemError()` 和 `MapConnectError()` 将 Windows 错误代码映射到 Chromium 的 `net::ERR_*` 错误代码。

6. **网络日志记录:**
   - 使用 `net_log_` 记录套接字事件，例如连接开始、连接结束、数据发送、数据接收、错误等，用于调试和性能分析。

7. **性能监控:**
   - 使用 `SocketPerformanceWatcher` (如果提供) 来监控套接字的性能。

**与 JavaScript 的关系**

这个 C++ 文件本身不直接包含 JavaScript 代码。然而，它是 Chromium 浏览器网络栈的核心组成部分，负责处理底层的 TCP 连接。当 JavaScript 代码通过浏览器提供的网络 API (例如 `fetch`, `XMLHttpRequest`, WebSocket API) 发起网络请求时，最终会调用到这里的 C++ 代码来建立和维护 TCP 连接，发送和接收数据。

**举例说明:**

假设一个网页中的 JavaScript 代码使用 `fetch` API 发送一个 HTTP 请求到服务器：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

**用户操作和代码路径:**

1. **用户在浏览器中打开网页，执行上述 JavaScript 代码。**
2. **JavaScript `fetch` API 被调用。**
3. **浏览器内部的网络栈开始处理该请求。**
4. **如果需要建立新的 TCP 连接到 `example.com` 的 443 端口，Chromium 的网络栈会调用 `TCPSocketWin::Create()` 创建一个 `TCPSocketDefaultWin` (或 `TcpSocketIoCompletionPortWin`) 对象。**
5. **调用 `TCPSocketWin::Connect()` 方法尝试连接到服务器。**  这将最终调用 Windows 的 `connect` 函数。
6. **连接建立后，当需要发送 HTTP 请求头和数据时，会调用 `TCPSocketWin::Write()` 方法。**
7. **当服务器返回响应数据时，会调用 `TCPSocketWin::Read()` 方法接收数据。**
8. **接收到的数据会被传递回 JavaScript 的 `fetch` API，最终被 `then` 方法处理。**

**逻辑推理，假设输入与输出**

**函数:** `MapConnectError(int os_error)`

**假设输入:**
- `os_error = WSAEACCES` (Windows 防火墙阻止连接)
- `os_error = WSAETIMEDOUT` (连接超时)
- `os_error = 10061` (WSAECONNREFUSED, 目标主机拒绝连接)

**对应输出:**
- 输入 `WSAEACCES`，输出 `ERR_NETWORK_ACCESS_DENIED`
- 输入 `WSAETIMEDOUT`，输出 `ERR_CONNECTION_TIMED_OUT`
- 输入 `10061`，输出 `ERR_CONNECTION_REFUSED` (通过 `MapSystemError` 映射)

**函数:** `SetTCPKeepAlive(SOCKET socket, BOOL enable, int delay_secs)`

**假设输入:**
- `socket`: 一个有效的 Windows 套接字句柄。
- `enable = TRUE`
- `delay_secs = 60`

**对应输出:**
- 函数会调用 `WSAIoctl` 设置 `SIO_KEEPALIVE_VALS`，启用 TCP Keep-Alive，并将首次探测延迟和探测间隔都设置为 60 秒。如果设置成功，返回 `true`，否则返回 `false`。

**用户或编程常见的使用错误**

1. **在未调用 `Open()` 的情况下尝试使用套接字:**  会导致 `socket_` 为 `INVALID_SOCKET`，后续操作会失败。
   ```c++
   TCPSocketWin socket(nullptr, nullptr, NetLogSource());
   // 忘记调用 socket.Open();
   int result = socket.Connect(address, callback); // 可能会崩溃或返回错误
   ```

2. **在异步操作完成前销毁 `TCPSocketWin` 对象:**  可能导致回调函数访问已释放的内存。需要正确管理对象的生命周期，或者使用智能指针。

3. **在多线程环境下不正确地使用套接字:**  `TCPSocketWin` 的某些操作需要在特定的线程上执行（通过 `thread_checker_` 检查），跨线程访问可能导致数据竞争或崩溃。

4. **忘记处理异步操作的结果:**  例如，调用 `Connect()` 或 `Write()` 返回 `ERR_IO_PENDING` 时，需要等待回调函数执行才能知道操作是否成功。

5. **在 `Accept()` 之后没有正确地处理新创建的套接字:**  `Accept()` 返回一个新的 `TCPSocketWin` 对象，需要妥善管理该对象的生命周期和操作。

**用户操作如何一步步到达这里 (调试线索)**

1. **用户在浏览器地址栏输入一个 HTTPS 网址并回车。**
2. **浏览器解析 URL，确定目标服务器的 IP 地址和端口 (443)。**
3. **浏览器网络栈需要建立一个到目标服务器的 TLS 连接，这首先需要一个底层的 TCP 连接。**
4. **Chromium 的网络代码会创建一个 `TCPSocketWin` 对象。**
5. **调用 `TCPSocketWin::Open(ADDRESS_FAMILY_INET)` 创建一个 IPv4 的 TCP 套接字。**
6. **调用 `TCPSocketWin::SetDefaultOptionsForClient()` 设置客户端的默认套接字选项，例如禁用 Nagle 算法，启用 Keep-Alive。**
7. **调用 `TCPSocketWin::Connect(server_address, connect_callback)` 尝试连接到服务器。**  这里的 `server_address` 包含了目标服务器的 IP 地址和端口。`connect_callback` 是连接完成后的回调函数。
8. **Windows 的 `connect` 函数被调用。由于套接字是非阻塞的，`connect` 通常会返回 `SOCKET_ERROR` 并设置 `WSAGetLastError()` 为 `WSAEWOULDBLOCK`。**
9. **`TCPSocketWin` 内部使用 `WSAEventSelect` 或 IO 完成端口来监听套接字上的 `FD_CONNECT` 事件，等待连接完成。**
10. **当连接建立成功或失败时，Windows 会通知应用程序。相应的事件处理函数会被调用。**
11. **在 `TCPSocketWin` 中，`CoreImpl::ReadDelegate::OnObjectSignaled` (对于 `WSAEventSelect`) 或 IO 完成端口的回调函数会被触发。**
12. **`TCPSocketWin::DidCompleteConnect()` 被调用，处理连接结果，并执行 `connect_callback`。**

如果调试时需要在 `tcp_socket_win.cc` 中设置断点，可以根据上述步骤，在 `Open()`, `Connect()`, `Write()`, `Read()` 等关键函数处设置断点，观察套接字的创建、连接和数据传输过程中的状态和参数。

**第 1 部分功能总结**

`net/socket/tcp_socket_win.cc` 文件的主要功能是提供了 Windows 平台上 TCP 套接字的具体实现。它封装了 Windows 的套接字 API，提供了创建、连接、监听、发送和接收数据的接口，并处理了异步操作和错误处理。这个文件是 Chromium 网络栈与底层操作系统进行 TCP 通信的关键桥梁。

Prompt: 
```
这是目录为net/socket/tcp_socket_win.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/socket/tcp_socket.h"

#include <errno.h>
#include <mstcpip.h>

#include <memory>
#include <utility>

#include "base/check_op.h"
#include "base/feature_list.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/win/windows_version.h"
#include "net/base/address_list.h"
#include "net/base/features.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/network_activity_monitor.h"
#include "net/base/network_change_notifier.h"
#include "net/base/sockaddr_storage.h"
#include "net/base/winsock_init.h"
#include "net/base/winsock_util.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/log/net_log_values.h"
#include "net/socket/socket_descriptor.h"
#include "net/socket/socket_net_log_params.h"
#include "net/socket/socket_options.h"
#include "net/socket/socket_tag.h"
#include "net/socket/tcp_socket_io_completion_port_win.h"
#include "net/socket/tcp_socket_win.h"

namespace net {

namespace {

const int kTCPKeepAliveSeconds = 45;

// Disable Nagle.
// Enable TCP Keep-Alive to prevent NAT routers from timing out TCP
// connections. See http://crbug.com/27400 for details.
bool SetTCPKeepAlive(SOCKET socket, BOOL enable, int delay_secs) {
  unsigned delay = delay_secs * 1000;
  struct tcp_keepalive keepalive_vals = {
      enable ? 1u : 0u,  // TCP keep-alive on.
      delay,  // Delay seconds before sending first TCP keep-alive packet.
      delay,  // Delay seconds between sending TCP keep-alive packets.
  };
  DWORD bytes_returned = 0xABAB;
  int rv = WSAIoctl(socket, SIO_KEEPALIVE_VALS, &keepalive_vals,
                    sizeof(keepalive_vals), nullptr, 0, &bytes_returned,
                    nullptr, nullptr);
  int os_error = WSAGetLastError();
  DCHECK(!rv) << "Could not enable TCP Keep-Alive for socket: " << socket
              << " [error: " << os_error << "].";

  // Disregard any failure in disabling nagle or enabling TCP Keep-Alive.
  return rv == 0;
}

int MapConnectError(int os_error) {
  switch (os_error) {
    // connect fails with WSAEACCES when Windows Firewall blocks the
    // connection.
    case WSAEACCES:
      return ERR_NETWORK_ACCESS_DENIED;
    case WSAETIMEDOUT:
      return ERR_CONNECTION_TIMED_OUT;
    default: {
      int net_error = MapSystemError(os_error);
      if (net_error == ERR_FAILED)
        return ERR_CONNECTION_FAILED;  // More specific than ERR_FAILED.

      // Give a more specific error when the user is offline.
      if (net_error == ERR_ADDRESS_UNREACHABLE &&
          NetworkChangeNotifier::IsOffline()) {
        return ERR_INTERNET_DISCONNECTED;
      }

      return net_error;
    }
  }
}

bool SetNonBlockingAndGetError(int fd, int* os_error) {
  bool ret = base::SetNonBlocking(fd);
  *os_error = WSAGetLastError();

  return ret;
}

}  // namespace

//-----------------------------------------------------------------------------

class NET_EXPORT TCPSocketDefaultWin : public TCPSocketWin {
 public:
  TCPSocketDefaultWin(
      std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
      NetLog* net_log,
      const NetLogSource& source);

  TCPSocketDefaultWin(
      std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
      NetLogWithSource net_log_source);

  ~TCPSocketDefaultWin() override;

  // TCPSocketWin:
  int Read(IOBuffer* buf,
           int buf_len,
           CompletionOnceCallback callback) override;
  int ReadIfReady(IOBuffer* buf,
                  int buf_len,
                  CompletionOnceCallback callback) override;
  int CancelReadIfReady() override;
  int Write(IOBuffer* buf,
            int buf_len,
            CompletionOnceCallback callback,
            const NetworkTrafficAnnotationTag& traffic_annotation) override;

 protected:
  // TCPSocketWin:
  scoped_refptr<Core> CreateCore() override;
  bool HasPendingRead() const override;
  void OnClosed() override;

 private:
  class CoreImpl;

  void RetryRead(int rv);
  void DidCompleteWrite();
  void DidSignalRead();

  CoreImpl& GetCoreImpl();

  // External callback; called when read is complete.
  CompletionOnceCallback read_callback_;

  // Non-null if a ReadIfReady() is to be completed asynchronously. This is an
  // external callback if user used ReadIfReady() instead of Read(), but a
  // wrapped callback on top of RetryRead() if Read() is used.
  CompletionOnceCallback read_if_ready_callback_;

  // External callback; called when write is complete.
  CompletionOnceCallback write_callback_;
};

class TCPSocketDefaultWin::CoreImpl : public TCPSocketWin::Core {
 public:
  explicit CoreImpl(TCPSocketDefaultWin* socket);

  CoreImpl(const CoreImpl&) = delete;
  CoreImpl& operator=(const CoreImpl&) = delete;

  // Start watching for the end of a read or write operation.
  void WatchForRead();
  void WatchForWrite();

  // Stops watching for read.
  void StopWatchingForRead();

  // TCPSocketWin::Core:
  void Detach() override;
  HANDLE GetConnectEvent() override;
  void WatchForConnect() override;

  // Event handle for monitoring connect and read events through WSAEventSelect.
  HANDLE read_event_;

  // OVERLAPPED variable for overlapped writes.
  // TODO(mmenke): Can writes be switched to WSAEventSelect as well? That would
  // allow removing this class. The only concern is whether that would have a
  // negative perf impact.
  OVERLAPPED write_overlapped_;

  // The buffers used in Read() and Write().
  scoped_refptr<IOBuffer> read_iobuffer_;
  scoped_refptr<IOBuffer> write_iobuffer_;
  int read_buffer_length_ = 0;
  int write_buffer_length_ = 0;

  bool non_blocking_reads_initialized_ = false;

 private:
  class ReadDelegate : public base::win::ObjectWatcher::Delegate {
   public:
    explicit ReadDelegate(CoreImpl* core) : core_(core) {}
    ~ReadDelegate() override = default;

    // base::ObjectWatcher::Delegate methods:
    void OnObjectSignaled(HANDLE object) override;

   private:
    const raw_ptr<CoreImpl> core_;
  };

  class WriteDelegate : public base::win::ObjectWatcher::Delegate {
   public:
    explicit WriteDelegate(CoreImpl* core) : core_(core) {}
    ~WriteDelegate() override = default;

    // base::ObjectWatcher::Delegate methods:
    void OnObjectSignaled(HANDLE object) override;

   private:
    const raw_ptr<CoreImpl> core_;
  };

  ~CoreImpl() override;

  // The socket that created this object.
  raw_ptr<TCPSocketDefaultWin> socket_;

  // |reader_| handles the signals from |read_watcher_|.
  ReadDelegate reader_;
  // |writer_| handles the signals from |write_watcher_|.
  WriteDelegate writer_;

  // |read_watcher_| watches for events from Connect() and Read().
  base::win::ObjectWatcher read_watcher_;
  // |write_watcher_| watches for events from Write();
  base::win::ObjectWatcher write_watcher_;
};

TCPSocketWin::Core::Core() = default;
TCPSocketWin::Core::~Core() = default;

TCPSocketDefaultWin::CoreImpl::CoreImpl(TCPSocketDefaultWin* socket)
    : read_event_(WSACreateEvent()),
      socket_(socket),
      reader_(this),
      writer_(this) {
  memset(&write_overlapped_, 0, sizeof(write_overlapped_));
  write_overlapped_.hEvent = WSACreateEvent();
}

TCPSocketDefaultWin::CoreImpl::~CoreImpl() {
  // Detach should already have been called.
  DCHECK(!socket_);

  // Stop the write watcher.  The read watcher should already have been stopped
  // in Detach().
  write_watcher_.StopWatching();
  WSACloseEvent(write_overlapped_.hEvent);
  memset(&write_overlapped_, 0xaf, sizeof(write_overlapped_));
}

void TCPSocketDefaultWin::CoreImpl::WatchForRead() {
  // Reads use WSAEventSelect, which closesocket() cancels so unlike writes,
  // there's no need to increment the reference count here.
  read_watcher_.StartWatchingOnce(read_event_, &reader_);
}

void TCPSocketDefaultWin::CoreImpl::WatchForWrite() {
  // We grab an extra reference because there is an IO operation in progress.
  // Balanced in WriteDelegate::OnObjectSignaled().
  AddRef();
  write_watcher_.StartWatchingOnce(write_overlapped_.hEvent, &writer_);
}

void TCPSocketDefaultWin::CoreImpl::StopWatchingForRead() {
  DCHECK(!socket_->connect_callback_);

  read_watcher_.StopWatching();
}

void TCPSocketDefaultWin::CoreImpl::Detach() {
  // Stop watching the read watcher. A read won't be signalled after the Detach
  // call, since the socket has been closed, but it's possible the event was
  // signalled when the socket was closed, but hasn't been handled yet, so need
  // to stop watching now to avoid trying to handle the event. See
  // https://crbug.com/831149
  read_watcher_.StopWatching();
  WSACloseEvent(read_event_);

  socket_ = nullptr;
}

HANDLE TCPSocketDefaultWin::CoreImpl::GetConnectEvent() {
  // `read_event_` is used to watch for connect.
  return read_event_;
}

void TCPSocketDefaultWin::CoreImpl::WatchForConnect() {
  // `read_event_` is used to watch for connect.
  WatchForRead();
}

void TCPSocketDefaultWin::CoreImpl::ReadDelegate::OnObjectSignaled(
    HANDLE object) {
  DCHECK_EQ(object, core_->read_event_);
  DCHECK(core_->socket_);
  if (core_->socket_->connect_callback_) {
    core_->socket_->DidCompleteConnect();
  } else {
    core_->socket_->DidSignalRead();
  }
}

void TCPSocketDefaultWin::CoreImpl::WriteDelegate::OnObjectSignaled(
    HANDLE object) {
  DCHECK_EQ(object, core_->write_overlapped_.hEvent);
  if (core_->socket_)
    core_->socket_->DidCompleteWrite();

  // Matches the AddRef() in WatchForWrite().
  core_->Release();
}

//-----------------------------------------------------------------------------

// static
std::unique_ptr<TCPSocketWin> TCPSocketWin::Create(
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetLog* net_log,
    const NetLogSource& source) {
  if (base::FeatureList::IsEnabled(features::kTcpSocketIoCompletionPortWin)) {
    return std::make_unique<TcpSocketIoCompletionPortWin>(
        std::move(socket_performance_watcher), net_log, source);
  }
  return std::make_unique<TCPSocketDefaultWin>(
      std::move(socket_performance_watcher), net_log, source);
}

// static
std::unique_ptr<TCPSocketWin> TCPSocketWin::Create(
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetLogWithSource net_log_source) {
  if (base::FeatureList::IsEnabled(features::kTcpSocketIoCompletionPortWin)) {
    return std::make_unique<TcpSocketIoCompletionPortWin>(
        std::move(socket_performance_watcher), net_log_source);
  }
  return std::make_unique<TCPSocketDefaultWin>(
      std::move(socket_performance_watcher), std::move(net_log_source));
}

TCPSocketWin::TCPSocketWin(
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    net::NetLog* net_log,
    const net::NetLogSource& source)
    : socket_(INVALID_SOCKET),
      socket_performance_watcher_(std::move(socket_performance_watcher)),
      accept_event_(WSA_INVALID_EVENT),
      net_log_(NetLogWithSource::Make(net_log, NetLogSourceType::SOCKET)) {
  net_log_.BeginEventReferencingSource(NetLogEventType::SOCKET_ALIVE, source);
  EnsureWinsockInit();
}

TCPSocketWin::TCPSocketWin(
    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
    NetLogWithSource net_log_source)
    : socket_(INVALID_SOCKET),
      socket_performance_watcher_(std::move(socket_performance_watcher)),
      accept_event_(WSA_INVALID_EVENT),
      net_log_(std::move(net_log_source)) {
  net_log_.BeginEvent(NetLogEventType::SOCKET_ALIVE);
  EnsureWinsockInit();
}

TCPSocketWin::~TCPSocketWin() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // The subclass must call `Close`. See comment in header file.
  CHECK(!core_);

  net_log_.EndEvent(NetLogEventType::SOCKET_ALIVE);
}

int TCPSocketWin::Open(AddressFamily family) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_EQ(socket_, INVALID_SOCKET);

  socket_ = CreatePlatformSocket(ConvertAddressFamily(family), SOCK_STREAM,
                                 IPPROTO_TCP);
  int os_error = WSAGetLastError();
  if (socket_ == INVALID_SOCKET) {
    PLOG(ERROR) << "CreatePlatformSocket() returned an error";
    return MapSystemError(os_error);
  }

  if (!SetNonBlockingAndGetError(socket_, &os_error)) {
    int result = MapSystemError(os_error);
    Close();
    return result;
  }

  return OK;
}

int TCPSocketWin::AdoptConnectedSocket(SocketDescriptor socket,
                                       const IPEndPoint& peer_address) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_EQ(socket_, INVALID_SOCKET);
  DCHECK(!core_.get());

  socket_ = socket;

  int os_error;
  if (!SetNonBlockingAndGetError(socket_, &os_error)) {
    int result = MapSystemError(os_error);
    Close();
    return result;
  }

  core_ = CreateCore();
  peer_address_ = std::make_unique<IPEndPoint>(peer_address);

  return OK;
}

int TCPSocketWin::AdoptUnconnectedSocket(SocketDescriptor socket) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_EQ(socket_, INVALID_SOCKET);

  socket_ = socket;

  int os_error;
  if (!SetNonBlockingAndGetError(socket_, &os_error)) {
    int result = MapSystemError(os_error);
    Close();
    return result;
  }

  // |core_| is not needed for sockets that are used to accept connections.
  // The operation here is more like Open but with an existing socket.

  return OK;
}

int TCPSocketWin::Bind(const IPEndPoint& address) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(socket_, INVALID_SOCKET);

  SockaddrStorage storage;
  if (!address.ToSockAddr(storage.addr, &storage.addr_len))
    return ERR_ADDRESS_INVALID;

  int result = bind(socket_, storage.addr, storage.addr_len);
  int os_error = WSAGetLastError();
  if (result < 0) {
    PLOG(ERROR) << "bind() returned an error";
    return MapSystemError(os_error);
  }

  return OK;
}

int TCPSocketWin::Listen(int backlog) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_GT(backlog, 0);
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK_EQ(accept_event_, WSA_INVALID_EVENT);

  accept_event_ = WSACreateEvent();
  int os_error = WSAGetLastError();
  if (accept_event_ == WSA_INVALID_EVENT) {
    PLOG(ERROR) << "WSACreateEvent()";
    return MapSystemError(os_error);
  }

  int result = listen(socket_, backlog);
  os_error = WSAGetLastError();
  if (result < 0) {
    PLOG(ERROR) << "listen() returned an error";
    return MapSystemError(os_error);
  }

  return OK;
}

int TCPSocketWin::Accept(std::unique_ptr<TCPSocketWin>* socket,
                         IPEndPoint* address,
                         CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(socket);
  DCHECK(address);
  DCHECK(!callback.is_null());
  DCHECK(accept_callback_.is_null());

  net_log_.BeginEvent(NetLogEventType::TCP_ACCEPT);

  int result = AcceptInternal(socket, address);

  if (result == ERR_IO_PENDING) {
    // Start watching.
    WSAEventSelect(socket_, accept_event_, FD_ACCEPT);
    accept_watcher_.StartWatchingOnce(accept_event_, this);

    accept_socket_ = socket;
    accept_address_ = address;
    accept_callback_ = std::move(callback);
  }

  return result;
}

int TCPSocketWin::Connect(const IPEndPoint& address,
                          CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK(!connect_callback_);
  DCHECK(callback);

  // |peer_address_| and |core_| will be non-NULL if Connect() has been called.
  // Unless Close() is called to reset the internal state, a second call to
  // Connect() is not allowed.
  // Please note that we enforce this even if the previous Connect() has
  // completed and failed. Although it is allowed to connect the same |socket_|
  // again after a connection attempt failed on Windows, it results in
  // unspecified behavior according to POSIX. Therefore, we make it behave in
  // the same way as TCPSocketPosix.
  DCHECK(!peer_address_ && !core_.get());

  if (!logging_multiple_connect_attempts_)
    LogConnectBegin(AddressList(address));

  peer_address_ = std::make_unique<IPEndPoint>(address);

  int rv = DoConnect();
  if (rv == ERR_IO_PENDING) {
    // Synchronous operation not supported.
    connect_callback_ = std::move(callback);
  } else {
    DoConnectComplete(rv);
  }

  return rv;
}

bool TCPSocketWin::IsConnected() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (socket_ == INVALID_SOCKET || connect_callback_) {
    // Outstanding connect attempt pending.
    return false;
  }

  if (HasPendingRead()) {
    return true;
  }

  char c;
  int rv = recv(socket_, &c, 1, MSG_PEEK);
  if (rv == 0) {
    // Connection gracefully closed.
    return false;
  }
  int os_error = WSAGetLastError();
  if (rv == SOCKET_ERROR && os_error != WSAEWOULDBLOCK) {
    // Connection dropped/terminated due to error.
    return false;
  }

  // One byte available or would block waiting for one byte.
  return true;
}

bool TCPSocketWin::IsConnectedAndIdle() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (socket_ == INVALID_SOCKET || connect_callback_) {
    // Outstanding connect attempt pending.
    return false;
  }

  if (HasPendingRead()) {
    return true;
  }

  char c;
  int rv = recv(socket_, &c, 1, MSG_PEEK);
  if (rv >= 0) {
    // Connection gracefully closed or one byte available to read without
    // blocking.
    return false;
  }
  int os_error = WSAGetLastError();
  if (os_error != WSAEWOULDBLOCK) {
    // Connection dropped/terminated due to error.
    return false;
  }

  // No data available; blocking required.
  return true;
}

int TCPSocketDefaultWin::Read(IOBuffer* buf,
                              int buf_len,
                              CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  CoreImpl& core = GetCoreImpl();
  DCHECK(!core.read_iobuffer_.get());
  // base::Unretained() is safe because RetryRead() won't be called when |this|
  // is gone.
  int rv = ReadIfReady(
      buf, buf_len,
      base::BindOnce(&TCPSocketDefaultWin::RetryRead, base::Unretained(this)));
  if (rv != ERR_IO_PENDING)
    return rv;
  read_callback_ = std::move(callback);
  core.read_iobuffer_ = buf;
  core.read_buffer_length_ = buf_len;
  return ERR_IO_PENDING;
}

int TCPSocketDefaultWin::ReadIfReady(IOBuffer* buf,
                                     int buf_len,
                                     CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK(read_if_ready_callback_.is_null());

  CoreImpl& core = GetCoreImpl();
  if (!core.non_blocking_reads_initialized_) {
    WSAEventSelect(socket_, core.read_event_, FD_READ | FD_CLOSE);
    core.non_blocking_reads_initialized_ = true;
  }
  int rv = recv(socket_, buf->data(), buf_len, 0);
  int os_error = WSAGetLastError();
  if (rv == SOCKET_ERROR) {
    if (os_error != WSAEWOULDBLOCK) {
      int net_error = MapSystemError(os_error);
      NetLogSocketError(net_log_, NetLogEventType::SOCKET_READ_ERROR, net_error,
                        os_error);
      return net_error;
    }
  } else {
    net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_RECEIVED, rv,
                                  buf->data());
    activity_monitor::IncrementBytesReceived(rv);
    return rv;
  }

  read_if_ready_callback_ = std::move(callback);
  core.WatchForRead();
  return ERR_IO_PENDING;
}

int TCPSocketDefaultWin::CancelReadIfReady() {
  DCHECK(read_callback_.is_null());
  DCHECK(!read_if_ready_callback_.is_null());

  GetCoreImpl().StopWatchingForRead();
  read_if_ready_callback_.Reset();
  return net::OK;
}

int TCPSocketDefaultWin::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& /* traffic_annotation */) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(socket_, INVALID_SOCKET);
  CHECK(write_callback_.is_null());
  DCHECK_GT(buf_len, 0);
  CoreImpl& core = GetCoreImpl();
  DCHECK(!core.write_iobuffer_.get());

  WSABUF write_buffer;
  write_buffer.len = buf_len;
  write_buffer.buf = buf->data();

  DWORD num;
  int rv = WSASend(socket_, &write_buffer, 1, &num, 0, &core.write_overlapped_,
                   nullptr);
  int os_error = WSAGetLastError();
  if (rv == 0) {
    if (ResetEventIfSignaled(core.write_overlapped_.hEvent)) {
      rv = static_cast<int>(num);
      if (rv > buf_len || rv < 0) {
        // It seems that some winsock interceptors report that more was written
        // than was available. Treat this as an error.  http://crbug.com/27870
        LOG(ERROR) << "Detected broken LSP: Asked to write " << buf_len
                   << " bytes, but " << rv << " bytes reported.";
        return ERR_WINSOCK_UNEXPECTED_WRITTEN_BYTES;
      }
      net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_SENT, rv,
                                    buf->data());
      return rv;
    }
  } else {
    if (os_error != WSA_IO_PENDING) {
      int net_error = MapSystemError(os_error);
      NetLogSocketError(net_log_, NetLogEventType::SOCKET_WRITE_ERROR,
                        net_error, os_error);
      return net_error;
    }
  }
  write_callback_ = std::move(callback);
  core.write_iobuffer_ = buf;
  core.write_buffer_length_ = buf_len;
  core.WatchForWrite();
  return ERR_IO_PENDING;
}

int TCPSocketWin::GetLocalAddress(IPEndPoint* address) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(address);

  SockaddrStorage storage;
  if (getsockname(socket_, storage.addr, &storage.addr_len)) {
    int os_error = WSAGetLastError();
    return MapSystemError(os_error);
  }
  if (!address->FromSockAddr(storage.addr, storage.addr_len))
    return ERR_ADDRESS_INVALID;

  return OK;
}

int TCPSocketWin::GetPeerAddress(IPEndPoint* address) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(address);
  if (!IsConnected())
    return ERR_SOCKET_NOT_CONNECTED;
  *address = *peer_address_;
  return OK;
}

int TCPSocketWin::SetDefaultOptionsForServer() {
  return SetExclusiveAddrUse();
}

void TCPSocketWin::SetDefaultOptionsForClient() {
  SetTCPNoDelay(socket_, /*no_delay=*/true);
  SetTCPKeepAlive(socket_, true, kTCPKeepAliveSeconds);
}

int TCPSocketWin::SetExclusiveAddrUse() {
  // On Windows, a bound end point can be hijacked by another process by
  // setting SO_REUSEADDR. Therefore a Windows-only option SO_EXCLUSIVEADDRUSE
  // was introduced in Windows NT 4.0 SP4. If the socket that is bound to the
  // end point has SO_EXCLUSIVEADDRUSE enabled, it is not possible for another
  // socket to forcibly bind to the end point until the end point is unbound.
  // It is recommend that all server applications must use SO_EXCLUSIVEADDRUSE.
  // MSDN: http://goo.gl/M6fjQ.
  //
  // Unlike on *nix, on Windows a TCP server socket can always bind to an end
  // point in TIME_WAIT state without setting SO_REUSEADDR, therefore it is not
  // needed here.
  //
  // SO_EXCLUSIVEADDRUSE will prevent a TCP client socket from binding to an end
  // point in TIME_WAIT status. It does not have this effect for a TCP server
  // socket.

  BOOL true_value = 1;
  int rv = setsockopt(socket_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                      reinterpret_cast<const char*>(&true_value),
                      sizeof(true_value));
  if (rv < 0)
    return MapSystemError(errno);
  return OK;
}

int TCPSocketWin::SetReceiveBufferSize(int32_t size) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return SetSocketReceiveBufferSize(socket_, size);
}

int TCPSocketWin::SetSendBufferSize(int32_t size) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return SetSocketSendBufferSize(socket_, size);
}

bool TCPSocketWin::SetKeepAlive(bool enable, int delay) {
  if (socket_ == INVALID_SOCKET)
    return false;

  return SetTCPKeepAlive(socket_, enable, delay);
}

bool TCPSocketWin::SetNoDelay(bool no_delay) {
  if (socket_ == INVALID_SOCKET)
    return false;

  return SetTCPNoDelay(socket_, no_delay) == OK;
}

int TCPSocketWin::SetIPv6Only(bool ipv6_only) {
  return ::net::SetIPv6Only(socket_, ipv6_only);
}

void TCPSocketWin::Close() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (socket_ != INVALID_SOCKET) {
    // Only log the close event if there's actually a socket to close.
    net_log_.AddEvent(NetLogEventType::SOCKET_CLOSED);

    // Note: don't use CancelIo to cancel pending IO because it doesn't work
    // when there is a Winsock layered service provider.

    // In most socket implementations, closing a socket results in a graceful
    // connection shutdown, but in Winsock we have to call shutdown explicitly.
    // See the MSDN page "Graceful Shutdown, Linger Options, and Socket Closure"
    // at http://msdn.microsoft.com/en-us/library/ms738547.aspx
    shutdown(socket_, SD_SEND);

    // This cancels any pending IO.
    if (closesocket(socket_) < 0)
      PLOG(ERROR) << "closesocket";
    socket_ = INVALID_SOCKET;
  }

  if (!accept_callback_.is_null()) {
    accept_watcher_.StopWatching();
    accept_socket_ = nullptr;
    accept_address_ = nullptr;
    accept_callback_.Reset();
  }

  if (accept_event_) {
    WSACloseEvent(accept_event_);
    accept_event_ = WSA_INVALID_EVENT;
  }

  if (core_.get()) {
    core_->Detach();
    core_ = nullptr;

    // |core_| may still exist and own a reference to itself, if there's a
    // pending write. It has to stay alive until the operation completes, even
    // when the socket is closed. This is not the case for reads.
  }

  connect_callback_.Reset();
  OnClosed();

  peer_address_.reset();
  connect_os_error_ = 0;
}

void TCPSocketWin::DetachFromThread() {
  DETACH_FROM_THREAD(thread_checker_);
}

void TCPSocketWin::StartLoggingMultipleConnectAttempts(
    const AddressList& addresses) {
  if (!logging_multiple_connect_attempts_) {
    logging_multiple_connect_attempts_ = true;
    LogConnectBegin(addresses);
  } else {
    NOTREACHED();
  }
}

void TCPSocketWin::EndLoggingMultipleConnectAttempts(int net_error) {
  if (logging_multiple_connect_attempts_) {
    LogConnectEnd(net_error);
    logging_multiple_connect_attempts_ = false;
  } else {
    NOTREACHED();
  }
}

SocketDescriptor TCPSocketWin::ReleaseSocketDescriptorForTesting() {
  CHECK(!registered_as_io_handler_);

  SocketDescriptor socket_descriptor = socket_;
  socket_ = INVALID_SOCKET;
  Close();
  return socket_descriptor;
}

SocketDescriptor TCPSocketWin::SocketDescriptorForTesting() const {
  return socket_;
}

void TCPSocketWin::CloseSocketDescriptorForTesting() {
  CHECK_NE(socket_, INVALID_SOCKET);
  CHECK_EQ(closesocket(socket_), 0);
  // Clear `socket_` so that `Close()` doesn't attempt to close it again.
  socket_ = INVALID_SOCKET;
}

int TCPSocketWin::AcceptInternal(std::unique_ptr<TCPSocketWin>* socket,
                                 IPEndPoint* address) {
  SockaddrStorage storage;
  int new_socket = accept(socket_, storage.addr, &storage.addr_len);
  int os_error = WSAGetLastError();
  if (new_socket < 0) {
    int net_error = MapSystemError(os_error);
    if (net_error != ERR_IO_PENDING)
      net_log_.EndEventWithNetErrorCode(NetLogEventType::TCP_ACCEPT, net_error);
    return net_error;
  }

  IPEndPoint ip_end_point;
  if (!ip_end_point.FromSockAddr(storage.addr, storage.addr_len)) {
    NOTREACHED();
  }
  auto tcp_socket =
      TCPSocketWin::Create(nullptr, net_log_.net_log(), net_log_.source());
  int adopt_result = tcp_socket->AdoptConnectedSocket(new_socket, ip_end_point);
  if (adopt_result != OK) {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::TCP_ACCEPT,
                                      adopt_result);
    return adopt_result;
  }
  *socket = std::move(tcp_socket);
  *address = ip_end_point;
  net_log_.EndEvent(NetLogEventType::TCP_ACCEPT, [&] {
    return CreateNetLogIPEndPointParams(&ip_end_point);
  });
  return OK;
}

void TCPSocketWin::OnObjectSignaled(HANDLE object) {
  WSANETWORKEVENTS ev;
  if (WSAEnumNetworkEvents(socket_, accept_event_, &ev) == SOCKET_ERROR) {
    PLOG(ERROR) << "WSAEnumNetworkEvents()";
    return;
  }

  if (ev.lNetworkEvents & FD_ACCEPT) {
    int result = AcceptInternal(accept_socket_, accept_address_);
    if (result != ERR_IO_PENDING) {
      accept_socket_ = nullptr;
      accept_address_ = nullptr;
      std::move(accept_callback_).Run(result);
    }
  } else {
    // This happens when a client opens a connection and closes it before we
    // have a chance to accept it.
    DCHECK(ev.lNetworkEvents == 0);

    // Start watching the next FD_ACCEPT event.
    WSAEventSelect(socket_, accept_event_, FD_ACCEPT);
    accept_watcher_.StartWatchingOnce(accept_event_, this);
  }
}

int TCPSocketWin::DoConnect() {
  DCHECK_EQ(connect_os_error_, 0);
  DCHECK(!core_.get());

  net_log_.BeginEvent(NetLogEventType::TCP_CONNECT_ATTEMPT, [&] {
    return CreateNetLogIPEndPointParams(peer_address_.get());
  });

  core_ = CreateCore();

  // WSAEventSelect sets the socket to non-blocking mode as a side effect.
  // Our connect() and recv() calls require that the socket be non-blocking.
  WSAEventSelect(socket_, core_->GetConnectEvent(), FD_CONNECT);

  SockaddrStorage storage;
  if (!peer_address_->ToSockAddr(storage.addr, &storage.addr_len))
    return ERR_ADDRESS_INVALID;

  // Set option to choose a random port, if the socket is not already bound.
  // Ignore failures, which may happen if the socket was already bound.
  if (base::win::GetVersion() >= base::win::Version::WIN10_20H1 &&
      base::FeatureList::IsEnabled(features::kEnableTcpPortRandomization)) {
    BOOL randomize_port = TRUE;
    setsockopt(socket_, SOL_SOCKET, SO_RANDOMIZE_PORT,
               reinterpret_cast<const char*>(&randomize_port),
               sizeof(randomize_port));
  }

  if (!connect(socket_, storage.addr, storage.addr_len)) {
    // Connected without waiting!
    //
    // The MSDN page for connect says:
    //   With a nonblocking socket, the connection attempt cannot be completed
    //   immediately. In this case, connect will return SOCKET_ERROR, and
    //   WSAGetLastError will return WSAEWOULDBLOCK.
    // which implies that for a nonblocking socket, connect never returns 0.
    // It's not documented whether the event object will be signaled or not
    // if connect does return 0.
    NOTREACHED();
  } else {
    int os_error = WSAGetLastError();
    if (os_error != WSAEWOULDBLOCK) {
      LOG(ERROR) << "connect failed: " << os_error;
      connect_os_error_ = os_error;
      int rv = MapConnectError(os_error);
      CHECK_NE(ERR_IO_PENDING, rv);
      return rv;
    }
  }

  core_->WatchForConnect();
  return ERR_IO_PENDING;
}

void TCPSocketWin::DoConnectComplete(int result) {
  // Log the end of this attempt (and any OS error it threw).
  int os_error = connect_os_error_;
  connect_os_error_ = 0;
  if (result != OK) {
    net_log_.EndEventWithIntParams(NetLogEventType::TCP_CONNECT_ATTEMPT,
                                   "os_error", os_error);
  } else {
    net_log_.EndEvent(NetLogEventType::TCP_CONNECT_ATTEMPT);
  }

  if (!logging_multiple_connect_attempts_)
    LogConnectEnd(result);
}

void TCPSocketWin::LogConnectBegin(const AddressList& addresses) {
  net_log_.BeginEvent(NetLogEventType::TCP_CONNECT,
                      [&] { return addresses.NetLogParams(); });
}

void TCPSocketWin::LogConnectEnd(int net_error) {
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

void TCPSocketDefaultWin::RetryRead(int rv) {
  CoreImpl& core = GetCoreImpl();
  DCHECK(core.read_iobuffer_);

  if (rv == OK) {
    // base::Unretained() is safe because RetryRead() won't be called when
    // |this| is gone.
    rv = ReadIfReady(core.read_iobuffer_.get(), core.read_buffer_length_,
                     base::B
"""


```