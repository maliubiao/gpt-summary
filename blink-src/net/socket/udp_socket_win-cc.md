Response:
The user is asking for a functional summary of the provided C++ code, which is part of Chromium's network stack and specifically handles UDP sockets on Windows. I need to extract the key functionalities and relate them to potential JavaScript interactions (since Chromium powers the browser). I also need to identify error scenarios and explain how a user's actions might lead to this code being executed.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The filename `udp_socket_win.cc` and the class name `UDPSocketWin` immediately point to the core function: managing UDP sockets on Windows.

2. **Analyze Key Classes and Methods:**  Go through the code and identify the major classes and their methods.
    * `UDPSocketWin`: The main class, responsible for creating, configuring, and managing the UDP socket. Key methods include `Open`, `Bind`, `Connect`, `Read`, `Write`, `SendTo`, `RecvFrom`, `Close`, and various `Set` options.
    * `UDPSocketWin::Core`: Handles asynchronous I/O operations (read/write) using overlapped structures. This is crucial for non-blocking behavior. Key methods are `WatchForRead`, `WatchForWrite`, and the delegate classes `ReadDelegate` and `WriteDelegate`.
    * `QwaveApi`:  Deals with Quality of Service (QoS) settings using the Windows Qwave API.

3. **Summarize Functionality (Imperative Verbs):**  Based on the classes and methods, create a list of actions the code performs. Use strong verbs. Examples: creates, opens, binds, connects, sends, receives, closes, sets options, handles asynchronous operations.

4. **Relate to JavaScript (Bridging the Gap):** Consider how these low-level socket operations are exposed to JavaScript in a browser context.
    * **`chrome.sockets.udp` API:**  This is the most direct connection. Functions like `create`, `bind`, `send`, `receive`, `connect`, `disconnect`, `close`, and `setBroadcast` map directly to the C++ code's functionality.
    * **WebRTC:**  Uses UDP for media and data transmission. The `RTCSocket` or underlying network code in WebRTC would use these UDP socket functions.
    * **QUIC:** While a higher-level protocol, it often runs over UDP. The code involved in setting up and managing QUIC connections would indirectly utilize these UDP socket functions.

5. **Illustrate with JavaScript Examples:** Provide concise JavaScript code snippets demonstrating how the identified browser APIs interact with the underlying UDP socket functionality. This clarifies the connection.

6. **Identify Logic and Assumptions (Hypothetical Inputs and Outputs):**  Look for specific functions that perform actions based on input.
    * `Open(AddressFamily)`:  Input is the address family (IPv4/IPv6). Output is a success or error code, and the creation of the socket.
    * `Bind(IPEndPoint)`: Input is the local address and port. Output is success or error, and the socket bound to the address.
    * `Connect(IPEndPoint)`: Input is the remote address and port. Output is success or error, and potentially a connection established.
    * `Read/RecvFrom`: Input is a buffer. Output is the number of bytes read or an error, and the received data.
    * `Write/SendTo`: Input is data and optionally a destination address. Output is the number of bytes sent or an error.

7. **Common User/Programming Errors:** Think about mistakes developers might make when using UDP sockets and how this C++ code might be involved in handling those errors.
    * **Attempting to read/write on a closed socket:**  The code checks for `INVALID_SOCKET`.
    * **Providing invalid addresses:**  Functions like `Bind` and `Connect` validate addresses.
    * **Incorrect buffer sizes:**  The `Read` and `Write` functions take buffer lengths as parameters.
    * **Not handling asynchronous operations correctly:** The `Core` class is designed to handle this, but the developer using the `UDPSocketWin` class needs to provide proper callbacks.

8. **Trace User Actions (Debugging Clues):** Consider a typical user scenario and how it leads to the execution of this code. Focus on network-related browser features.
    * **Browsing a website:**  While HTTP primarily uses TCP, DNS resolution often involves UDP.
    * **Using WebRTC for video calls:** This heavily relies on UDP.
    * **Applications using `chrome.sockets.udp`:** This is a direct path.

9. **Summarize Functionality (Concise Overview):**  Reiterate the main purpose of the code in a single, clear statement at the end.

10. **Review and Refine:**  Read through the entire response to ensure clarity, accuracy, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially I might have focused too much on specific Windows API calls. Broadening the scope to how these calls contribute to the overall UDP socket management is important. Also, ensuring the JavaScript examples are practical and illustrative is key.
好的，让我们来分析一下 `net/socket/udp_socket_win.cc` 文件的功能。

**功能归纳**

这个 C++ 源代码文件实现了 Chromium 在 Windows 平台上操作 UDP 套接字的核心功能。它封装了底层的 Windows Socket API (Winsock) 调用，并提供了 Chromium 网络栈中其他模块可以使用的、更高级别的 UDP 套接字抽象。

**具体功能列表**

1. **创建和管理 UDP 套接字:**
   - `Open()`:  创建一个新的 UDP 套接字。
   - `AdoptOpenedSocket()`:  接管一个已经创建的 Windows 套接字。
   - `Close()`: 关闭 UDP 套接字，释放相关资源。
   - 维护套接字描述符 (`socket_`).

2. **绑定地址:**
   - `Bind()`: 将套接字绑定到本地 IP 地址和端口。
   - `BindToNetwork()`: (未实现) 绑定到特定的网络接口。

3. **连接到远程地址:**
   - `Connect()`: 连接到指定的远程 IP 地址和端口 (虽然 UDP 是无连接的，但 `connect()` 可以用于简化后续的 `send()` 和接收操作，并可以用于某些安全策略)。
   - 维护远程地址 (`remote_address_`) 和本地地址 (`local_address_`).

4. **发送和接收数据:**
   - `Write()` / `SendTo()`: 发送数据到指定的远程地址。
   - `Read()` / `RecvFrom()`: 从套接字接收数据，并获取发送端的地址。
   - 使用异步 I/O (`OVERLAPPED` 结构) 实现非阻塞的发送和接收操作。
   - 使用 `WSARecvMsg` 和 `WSASendMsg` (如果可用) 来处理扩展的接收和发送功能，例如获取 ECN (Explicit Congestion Notification) 信息。

5. **设置套接字选项:**
   - `SetReceiveBufferSize()`: 设置接收缓冲区大小。
   - `SetSendBufferSize()`: 设置发送缓冲区大小。
   - `SetDoNotFragment()`: 设置 IP 分片禁止标志。
   - `AllowAddressReuse()`: 允许地址重用。
   - `SetBroadcast()`: 允许发送广播消息。
   - `AllowAddressSharingForMulticast()`: 允许组播地址共享。
   - `SetRecvTos()`: 尝试接收 IP 报文头的 TOS (Type of Service) 或 ECN 信息。
   - `SetMsgConfirm()`: (空实现) 设置消息确认。

6. **处理异步 I/O:**
   - 使用内部类 `Core` 管理异步操作的状态和 `OVERLAPPED` 结构。
   - 使用 `base::win::ObjectWatcher` 监听异步操作完成的事件。
   - 提供 `DidCompleteRead()` 和 `DidCompleteWrite()` 回调函数来处理异步操作的完成。

7. **网络日志记录:**
   - 使用 `net::NetLog` 记录套接字事件和数据传输。

8. **QoS (Quality of Service) 支持:**
   - 包含 `QwaveApi` 类，用于与 Windows Qwave API 交互，实现 QoS 功能 (例如，设置 DSCP 值)。

9. **流量注解:**
   - 在发送数据时可以关联网络流量注解 (`NetworkTrafficAnnotationTag`).

**与 JavaScript 的关系 (及举例说明)**

Chromium 是一个跨平台的浏览器，其网络栈为浏览器中的各种网络功能提供支持。 JavaScript 代码本身不能直接操作底层的操作系统套接字。 然而，Chromium 提供了 API，允许 JavaScript 通过这些 API 间接地使用底层的网络功能。

以下是 `udp_socket_win.cc` 的功能与 JavaScript 可能存在的关联：

* **`chrome.sockets.udp` API:** Chrome 扩展程序可以使用 `chrome.sockets.udp` API 来创建和管理 UDP 套接字。这个 API 的实现会调用 Chromium 网络栈中相应的 C++ 代码，包括 `udp_socket_win.cc` 中的功能。

   **JavaScript 示例：**

   ```javascript
   chrome.sockets.udp.create({}, function(createInfo) {
     var socketId = createInfo.socketId;
     chrome.sockets.udp.bind(socketId, "0.0.0.0", 0, function(result) {
       if (result === 0) {
         console.log("UDP socket bound successfully.");
         chrome.sockets.udp.send(socketId, stringToUint8Array("Hello"), "192.168.1.100", 12345, function(sendInfo) {
           console.log("Bytes sent: " + sendInfo.bytesSent);
         });
         chrome.sockets.udp.onReceive.addListener(function(info) {
           if (info.socketId === socketId) {
             console.log("Received data: " + uint8ArrayToString(info.data));
           }
         });
       } else {
         console.error("Error binding UDP socket: " + result);
       }
     });
   });
   ```

   在这个例子中，`chrome.sockets.udp.create`, `bind`, `send`, 和 `onReceive` 等 API 的底层实现最终会调用 `udp_socket_win.cc` 中的 `Open`, `Bind`, `SendTo`, 和相关的接收函数。

* **WebRTC (Real-Time Communication):** WebRTC 技术允许在浏览器中进行实时的音视频通信和数据传输。  WebRTC 的底层传输层可以使用 UDP 协议进行数据传输。  当 WebRTC 连接建立时，Chromium 的网络栈会创建 UDP 套接字，而 `udp_socket_win.cc` 中的代码负责管理这些套接字。

   **JavaScript 示例：**

   ```javascript
   // (WebRTC 代码片段，简化)
   const peerConnection = new RTCPeerConnection(configuration);
   peerConnection.createOffer()
     .then(offer => peerConnection.setLocalDescription(offer))
     .then(() => {
       // 发送 offer 给对等端
     });

   peerConnection.ontrack = event => {
     // 处理接收到的媒体流
   };
   ```

   在幕后，当 WebRTC 连接协商成功并需要通过 UDP 发送媒体或数据时，`udp_socket_win.cc` 的代码会被调用来发送和接收这些数据包。

* **QUIC 协议:** QUIC 是一种基于 UDP 的传输层网络协议，旨在提供更可靠和安全的连接。  如果 Chromium 使用 QUIC 连接到服务器，那么 `udp_socket_win.cc` 中的代码会处理 QUIC 连接底层的 UDP 数据包的发送和接收。

**逻辑推理、假设输入与输出**

让我们以 `Read()` 函数为例进行逻辑推理：

**假设输入：**

1. 一个已经打开并绑定的 `UDPSocketWin` 对象。
2. 一个指向 `IOBuffer` 的指针 `buf`，用于存储接收到的数据。
3. 一个整数 `buf_len`，表示 `buf` 的大小。
4. 一个 `CompletionOnceCallback` 回调函数 `callback`。

**逻辑推理：**

1. `Read()` 函数会调用内部的 `InternalRecvFromOverlapped()` 或 `InternalRecvFromNonBlocking()`，取决于是否使用了非阻塞 I/O。
2. 如果使用 Overlapped I/O (`core_` 不为空)，`InternalRecvFromOverlapped()` 会准备一个 `WSABUF` 结构指向 `buf`，并调用 `WSARecvFrom()` 或 `wsa_recv_msg_()` (如果支持 ECN)。
3. 如果 `WSARecvFrom()` 或 `wsa_recv_msg_()` 返回 0，表示同步接收成功。函数会从接收到的 `sockaddr` 填充地址信息（如果提供了地址参数），并调用 `LogRead()` 记录日志，然后直接调用回调函数 `callback`，参数为接收到的字节数。
4. 如果 `WSARecvFrom()` 或 `wsa_recv_msg_()` 返回 `SOCKET_ERROR` 且错误码为 `WSA_IO_PENDING`，表示异步操作正在进行。函数会调用 `core_->WatchForRead()` 启动监听，并将 `buf` 和 `callback` 保存起来，等待异步操作完成。
5. 当异步操作完成时，`DidCompleteRead()` 会被调用，它会通过 `WSAGetOverlappedResult()` 获取结果，然后调用 `DoReadCallback()` 执行用户提供的回调函数。

**假设输出：**

*   **同步成功：** 返回接收到的字节数（大于等于 0）。回调函数 `callback` 会被立即调用，参数为接收到的字节数。
*   **异步操作正在进行：** 返回 `ERR_IO_PENDING`。回调函数 `callback` 会在稍后异步操作完成时被调用，参数为接收到的字节数或错误码。
*   **错误：** 返回一个负数的 `net::Error` 代码，例如 `ERR_SOCKET_NOT_CONNECTED` 或 `ERR_ADDRESS_INVALID`。回调函数 `callback` 会被立即调用，参数为该错误码。

**用户或编程常见的使用错误 (及举例说明)**

1. **在未打开的套接字上进行操作：**
   ```c++
   UDPSocketWin socket(...);
   // 没有调用 Open()
   IOBuffer buf(1024);
   socket.Read(buf.get(), 1024, ...); // 错误：套接字未打开
   ```
   这个代码会因为 `socket_ == INVALID_SOCKET` 而导致错误，最终 `WSAGetLastError()` 可能会返回 `WSAENOTSOCK`。

2. **在未绑定的套接字上接收数据 (如果需要知道发送方地址)：**
   虽然可以接收数据，但如果需要知道发送方的地址，需要在接收前绑定套接字。

3. **提供的缓冲区大小不足：**
   ```c++
   UDPSocketWin socket(...);
   socket.Open(...);
   socket.Bind(...);
   IOBuffer buf(10); // 缓冲区大小为 10 字节
   socket.Read(buf.get(), 10, ...);

   // 如果接收到的 UDP 数据包大于 10 字节，则会发生截断。
   ```
   这会导致数据丢失。

4. **忘记处理异步操作的回调：**
   如果使用了异步的 `Read()` 或 `Write()`，但没有正确设置和处理 `CompletionOnceCallback`，程序将无法正确处理 I/O 操作的结果。

5. **在套接字 `Close()` 之后尝试操作：**
   ```c++
   UDPSocketWin socket(...);
   socket.Open(...);
   socket.Close();
   IOBuffer buf(1024);
   socket.Read(buf.get(), 1024, ...); // 错误：套接字已关闭
   ```
   这会导致使用无效的套接字描述符。

**用户操作是如何一步步的到达这里，作为调试线索**

假设用户在 Chrome 浏览器中访问一个使用了 WebRTC 的网站进行视频通话：

1. **用户打开 Chrome 浏览器，并访问支持 WebRTC 的网站。**
2. **网站的 JavaScript 代码使用 WebRTC API (`RTCPeerConnection`) 发起或接受视频通话。**
3. **WebRTC 协商过程确定使用 UDP 作为传输协议。**
4. **Chromium 的 WebRTC 实现会请求网络栈创建一个 UDP 套接字。** 这会调用 `UDPSocketWin` 的构造函数和 `Open()` 方法。
5. **如果需要绑定到特定的本地地址和端口，会调用 `Bind()` 方法。**
6. **为了与远程对等端通信，可能会调用 `Connect()` (虽然 UDP 是无连接的，但在某些情况下会使用 `connect()` 简化操作)。**
7. **当需要发送音视频数据时，WebRTC 会调用 `Write()` 或 `SendTo()` 方法，将数据发送到远程对等端的 IP 地址和端口。**  数据会被写入 `IOBuffer`，然后传递给底层的 Winsock API。
8. **当接收到来自远程对等端的数据时，`Read()` 或 `RecvFrom()` 方法会被调用。**  Windows 会通过事件通知 Chromium 数据已到达，`Core` 类中的 `ObjectWatcher` 会捕获到这个事件，并触发 `DidCompleteRead()` 回调。
9. **如果在通话过程中出现网络问题，例如连接中断或数据发送失败，`udp_socket_win.cc` 中的错误处理逻辑会被触发，并通过 `net::NetLog` 记录相关信息，这可以作为调试线索。**  例如，如果 `sendto()` 返回错误，`MapSystemError(WSAGetLastError())` 会将 Winsock 的错误码转换为 Chromium 的网络错误码。

**总结**

总而言之，`net/socket/udp_socket_win.cc` 是 Chromium 在 Windows 平台上进行 UDP 网络通信的关键组成部分。它负责管理 UDP 套接字的生命周期，处理数据的发送和接收，并提供了必要的配置选项。理解这个文件的功能对于理解 Chromium 如何在 Windows 上处理基于 UDP 的网络请求至关重要，尤其是在涉及 `chrome.sockets.udp` API、WebRTC 或 QUIC 等技术时。

Prompt: 
```
这是目录为net/socket/udp_socket_win.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/socket/udp_socket_win.h"

#include <winsock2.h>

#include <mstcpip.h>

#include <memory>

#include "base/check_op.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/lazy_instance.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/rand_util.h"
#include "base/task/thread_pool.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_address.h"
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
#include "net/socket/socket_descriptor.h"
#include "net/socket/socket_options.h"
#include "net/socket/socket_tag.h"
#include "net/socket/udp_net_log_parameters.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace net {

// This class encapsulates all the state that has to be preserved as long as
// there is a network IO operation in progress. If the owner UDPSocketWin
// is destroyed while an operation is in progress, the Core is detached and it
// lives until the operation completes and the OS doesn't reference any resource
// declared on this class anymore.
class UDPSocketWin::Core : public base::RefCounted<Core> {
 public:
  explicit Core(UDPSocketWin* socket);

  Core(const Core&) = delete;
  Core& operator=(const Core&) = delete;

  // Start watching for the end of a read or write operation.
  void WatchForRead();
  void WatchForWrite();

  // The UDPSocketWin is going away.
  void Detach() { socket_ = nullptr; }

  // The separate OVERLAPPED variables for asynchronous operation.
  OVERLAPPED read_overlapped_;
  OVERLAPPED write_overlapped_;

  // The buffers used in Read() and Write().
  scoped_refptr<IOBuffer> read_iobuffer_;
  scoped_refptr<IOBuffer> write_iobuffer_;
  // The struct for packet metadata passed to WSARecvMsg().
  std::unique_ptr<WSAMSG> read_message_ = nullptr;
  // Big enough for IP_ECN or IPV6_ECN, nothing more.
  char read_control_buffer_[WSA_CMSG_SPACE(sizeof(int))];

  // The address storage passed to WSARecvFrom().
  SockaddrStorage recv_addr_storage_;

 private:
  friend class base::RefCounted<Core>;

  class ReadDelegate : public base::win::ObjectWatcher::Delegate {
   public:
    explicit ReadDelegate(Core* core) : core_(core) {}
    ~ReadDelegate() override = default;

    // base::ObjectWatcher::Delegate methods:
    void OnObjectSignaled(HANDLE object) override;

   private:
    const raw_ptr<Core> core_;
  };

  class WriteDelegate : public base::win::ObjectWatcher::Delegate {
   public:
    explicit WriteDelegate(Core* core) : core_(core) {}
    ~WriteDelegate() override = default;

    // base::ObjectWatcher::Delegate methods:
    void OnObjectSignaled(HANDLE object) override;

   private:
    const raw_ptr<Core> core_;
  };

  ~Core();

  // The socket that created this object.
  raw_ptr<UDPSocketWin> socket_;

  // |reader_| handles the signals from |read_watcher_|.
  ReadDelegate reader_;
  // |writer_| handles the signals from |write_watcher_|.
  WriteDelegate writer_;

  // |read_watcher_| watches for events from Read().
  base::win::ObjectWatcher read_watcher_;
  // |write_watcher_| watches for events from Write();
  base::win::ObjectWatcher write_watcher_;
};

UDPSocketWin::Core::Core(UDPSocketWin* socket)
    : socket_(socket),
      reader_(this),
      writer_(this) {
  memset(&read_overlapped_, 0, sizeof(read_overlapped_));
  memset(&write_overlapped_, 0, sizeof(write_overlapped_));

  read_overlapped_.hEvent = WSACreateEvent();
  write_overlapped_.hEvent = WSACreateEvent();
}

UDPSocketWin::Core::~Core() {
  // Make sure the message loop is not watching this object anymore.
  read_watcher_.StopWatching();
  write_watcher_.StopWatching();

  WSACloseEvent(read_overlapped_.hEvent);
  memset(&read_overlapped_, 0xaf, sizeof(read_overlapped_));
  WSACloseEvent(write_overlapped_.hEvent);
  memset(&write_overlapped_, 0xaf, sizeof(write_overlapped_));
}

void UDPSocketWin::Core::WatchForRead() {
  // We grab an extra reference because there is an IO operation in progress.
  // Balanced in ReadDelegate::OnObjectSignaled().
  AddRef();
  read_watcher_.StartWatchingOnce(read_overlapped_.hEvent, &reader_);
}

void UDPSocketWin::Core::WatchForWrite() {
  // We grab an extra reference because there is an IO operation in progress.
  // Balanced in WriteDelegate::OnObjectSignaled().
  AddRef();
  write_watcher_.StartWatchingOnce(write_overlapped_.hEvent, &writer_);
}

void UDPSocketWin::Core::ReadDelegate::OnObjectSignaled(HANDLE object) {
  DCHECK_EQ(object, core_->read_overlapped_.hEvent);
  if (core_->socket_)
    core_->socket_->DidCompleteRead();

  core_->Release();
}

void UDPSocketWin::Core::WriteDelegate::OnObjectSignaled(HANDLE object) {
  DCHECK_EQ(object, core_->write_overlapped_.hEvent);
  if (core_->socket_)
    core_->socket_->DidCompleteWrite();

  core_->Release();
}
//-----------------------------------------------------------------------------

QwaveApi::QwaveApi() {
  HMODULE qwave = LoadLibrary(L"qwave.dll");
  if (!qwave)
    return;
  create_handle_func_ =
      (CreateHandleFn)GetProcAddress(qwave, "QOSCreateHandle");
  close_handle_func_ =
      (CloseHandleFn)GetProcAddress(qwave, "QOSCloseHandle");
  add_socket_to_flow_func_ =
      (AddSocketToFlowFn)GetProcAddress(qwave, "QOSAddSocketToFlow");
  remove_socket_from_flow_func_ =
      (RemoveSocketFromFlowFn)GetProcAddress(qwave, "QOSRemoveSocketFromFlow");
  set_flow_func_ = (SetFlowFn)GetProcAddress(qwave, "QOSSetFlow");

  if (create_handle_func_ && close_handle_func_ &&
      add_socket_to_flow_func_ && remove_socket_from_flow_func_ &&
      set_flow_func_) {
    qwave_supported_ = true;
  }
}

QwaveApi* QwaveApi::GetDefault() {
  static base::LazyInstance<QwaveApi>::Leaky lazy_qwave =
      LAZY_INSTANCE_INITIALIZER;
  return lazy_qwave.Pointer();
}

bool QwaveApi::qwave_supported() const {
  return qwave_supported_;
}

void QwaveApi::OnFatalError() {
  // Disable everything moving forward.
  qwave_supported_ = false;
}

BOOL QwaveApi::CreateHandle(PQOS_VERSION version, PHANDLE handle) {
  return create_handle_func_(version, handle);
}

BOOL QwaveApi::CloseHandle(HANDLE handle) {
  return close_handle_func_(handle);
}

BOOL QwaveApi::AddSocketToFlow(HANDLE handle,
                               SOCKET socket,
                               PSOCKADDR addr,
                               QOS_TRAFFIC_TYPE traffic_type,
                               DWORD flags,
                               PQOS_FLOWID flow_id) {
  return add_socket_to_flow_func_(handle, socket, addr, traffic_type, flags,
                                  flow_id);
}

BOOL QwaveApi::RemoveSocketFromFlow(HANDLE handle,
                                    SOCKET socket,
                                    QOS_FLOWID flow_id,
                                    DWORD reserved) {
  return remove_socket_from_flow_func_(handle, socket, flow_id, reserved);
}

BOOL QwaveApi::SetFlow(HANDLE handle,
                       QOS_FLOWID flow_id,
                       QOS_SET_FLOW op,
                       ULONG size,
                       PVOID data,
                       DWORD reserved,
                       LPOVERLAPPED overlapped) {
  return set_flow_func_(handle, flow_id, op, size, data, reserved, overlapped);
}

//-----------------------------------------------------------------------------

UDPSocketWin::UDPSocketWin(DatagramSocket::BindType bind_type,
                           net::NetLog* net_log,
                           const net::NetLogSource& source)
    : socket_(INVALID_SOCKET),
      socket_options_(SOCKET_OPTION_MULTICAST_LOOP),
      net_log_(NetLogWithSource::Make(net_log, NetLogSourceType::UDP_SOCKET)) {
  EnsureWinsockInit();
  net_log_.BeginEventReferencingSource(NetLogEventType::SOCKET_ALIVE, source);
}

UDPSocketWin::UDPSocketWin(DatagramSocket::BindType bind_type,
                           NetLogWithSource source_net_log)
    : socket_(INVALID_SOCKET),
      socket_options_(SOCKET_OPTION_MULTICAST_LOOP),
      net_log_(source_net_log) {
  EnsureWinsockInit();
  net_log_.BeginEventReferencingSource(NetLogEventType::SOCKET_ALIVE,
                                       net_log_.source());
}

UDPSocketWin::~UDPSocketWin() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  Close();
  net_log_.EndEvent(NetLogEventType::SOCKET_ALIVE);
}

int UDPSocketWin::Open(AddressFamily address_family) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_EQ(socket_, INVALID_SOCKET);

  auto owned_socket_count = TryAcquireGlobalUDPSocketCount();
  if (owned_socket_count.empty())
    return ERR_INSUFFICIENT_RESOURCES;

  owned_socket_count_ = std::move(owned_socket_count);
  addr_family_ = ConvertAddressFamily(address_family);
  socket_ = CreatePlatformSocket(addr_family_, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_ == INVALID_SOCKET) {
    owned_socket_count_.Reset();
    return MapSystemError(WSAGetLastError());
  }
  ConfigureOpenedSocket();
  return OK;
}

int UDPSocketWin::AdoptOpenedSocket(AddressFamily address_family,
                                    SOCKET socket) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  auto owned_socket_count = TryAcquireGlobalUDPSocketCount();
  if (owned_socket_count.empty()) {
    return ERR_INSUFFICIENT_RESOURCES;
  }

  owned_socket_count_ = std::move(owned_socket_count);
  addr_family_ = ConvertAddressFamily(address_family);
  socket_ = socket;
  ConfigureOpenedSocket();
  return OK;
}

void UDPSocketWin::ConfigureOpenedSocket() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!use_non_blocking_io_) {
    core_ = base::MakeRefCounted<Core>(this);
  } else {
    read_write_event_.Set(WSACreateEvent());
    WSAEventSelect(socket_, read_write_event_.Get(), FD_READ | FD_WRITE);
  }
}

void UDPSocketWin::Close() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  owned_socket_count_.Reset();

  if (socket_ == INVALID_SOCKET)
    return;

  // Remove socket_ from the QoS subsystem before we invalidate it.
  dscp_manager_ = nullptr;

  // Zero out any pending read/write callback state.
  read_callback_.Reset();
  recv_from_address_ = nullptr;
  write_callback_.Reset();

  base::TimeTicks start_time = base::TimeTicks::Now();
  closesocket(socket_);
  UMA_HISTOGRAM_TIMES("Net.UDPSocketWinClose",
                      base::TimeTicks::Now() - start_time);
  socket_ = INVALID_SOCKET;
  addr_family_ = 0;
  is_connected_ = false;

  // Release buffers to free up memory.
  read_iobuffer_ = nullptr;
  read_iobuffer_len_ = 0;
  write_iobuffer_ = nullptr;
  write_iobuffer_len_ = 0;

  read_write_watcher_.StopWatching();
  read_write_event_.Close();

  event_pending_.InvalidateWeakPtrs();

  if (core_) {
    core_->Detach();
    core_ = nullptr;
  }
}

int UDPSocketWin::GetPeerAddress(IPEndPoint* address) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(address);
  if (!is_connected())
    return ERR_SOCKET_NOT_CONNECTED;

  // TODO(szym): Simplify. http://crbug.com/126152
  if (!remote_address_.get()) {
    SockaddrStorage storage;
    if (getpeername(socket_, storage.addr, &storage.addr_len))
      return MapSystemError(WSAGetLastError());
    auto remote_address = std::make_unique<IPEndPoint>();
    if (!remote_address->FromSockAddr(storage.addr, storage.addr_len))
      return ERR_ADDRESS_INVALID;
    remote_address_ = std::move(remote_address);
  }

  *address = *remote_address_;
  return OK;
}

int UDPSocketWin::GetLocalAddress(IPEndPoint* address) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(address);
  if (!is_connected())
    return ERR_SOCKET_NOT_CONNECTED;

  // TODO(szym): Simplify. http://crbug.com/126152
  if (!local_address_.get()) {
    SockaddrStorage storage;
    if (getsockname(socket_, storage.addr, &storage.addr_len))
      return MapSystemError(WSAGetLastError());
    auto local_address = std::make_unique<IPEndPoint>();
    if (!local_address->FromSockAddr(storage.addr, storage.addr_len))
      return ERR_ADDRESS_INVALID;
    local_address_ = std::move(local_address);
    net_log_.AddEvent(NetLogEventType::UDP_LOCAL_ADDRESS, [&] {
      return CreateNetLogUDPConnectParams(*local_address_,
                                          handles::kInvalidNetworkHandle);
    });
  }

  *address = *local_address_;
  return OK;
}

int UDPSocketWin::Read(IOBuffer* buf,
                       int buf_len,
                       CompletionOnceCallback callback) {
  return RecvFrom(buf, buf_len, nullptr, std::move(callback));
}

int UDPSocketWin::RecvFrom(IOBuffer* buf,
                           int buf_len,
                           IPEndPoint* address,
                           CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(INVALID_SOCKET, socket_);
  CHECK(read_callback_.is_null());
  DCHECK(!recv_from_address_);
  DCHECK(!callback.is_null());  // Synchronous operation not supported.
  DCHECK_GT(buf_len, 0);

  int nread = core_ ? InternalRecvFromOverlapped(buf, buf_len, address)
                    : InternalRecvFromNonBlocking(buf, buf_len, address);
  if (nread != ERR_IO_PENDING)
    return nread;

  read_callback_ = std::move(callback);
  recv_from_address_ = address;
  return ERR_IO_PENDING;
}

int UDPSocketWin::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& /* traffic_annotation */) {
  return SendToOrWrite(buf, buf_len, remote_address_.get(),
                       std::move(callback));
}

int UDPSocketWin::SendTo(IOBuffer* buf,
                         int buf_len,
                         const IPEndPoint& address,
                         CompletionOnceCallback callback) {
  if (dscp_manager_) {
    // Alert DscpManager in case this is a new remote address.  Failure to
    // apply Dscp code is never fatal.
    int rv = dscp_manager_->PrepareForSend(address);
    if (rv != OK)
      net_log_.AddEventWithNetErrorCode(NetLogEventType::UDP_SEND_ERROR, rv);
  }
  return SendToOrWrite(buf, buf_len, &address, std::move(callback));
}

int UDPSocketWin::SendToOrWrite(IOBuffer* buf,
                                int buf_len,
                                const IPEndPoint* address,
                                CompletionOnceCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_NE(INVALID_SOCKET, socket_);
  CHECK(write_callback_.is_null());
  DCHECK(!callback.is_null());  // Synchronous operation not supported.
  DCHECK_GT(buf_len, 0);
  DCHECK(!send_to_address_.get());

  int nwrite = core_ ? InternalSendToOverlapped(buf, buf_len, address)
                     : InternalSendToNonBlocking(buf, buf_len, address);
  if (nwrite != ERR_IO_PENDING)
    return nwrite;

  if (address)
    send_to_address_ = std::make_unique<IPEndPoint>(*address);
  write_callback_ = std::move(callback);
  return ERR_IO_PENDING;
}

int UDPSocketWin::Connect(const IPEndPoint& address) {
  DCHECK_NE(socket_, INVALID_SOCKET);
  net_log_.BeginEvent(NetLogEventType::UDP_CONNECT, [&] {
    return CreateNetLogUDPConnectParams(address,
                                        handles::kInvalidNetworkHandle);
  });
  int rv = SetMulticastOptions();
  if (rv != OK)
    return rv;
  rv = InternalConnect(address);
  net_log_.EndEventWithNetErrorCode(NetLogEventType::UDP_CONNECT, rv);
  is_connected_ = (rv == OK);
  return rv;
}

int UDPSocketWin::InternalConnect(const IPEndPoint& address) {
  DCHECK(!is_connected());
  DCHECK(!remote_address_.get());

  // Always do a random bind.
  // Ignore failures, which may happen if the socket was already bound.
  DWORD randomize_port_value = 1;
  setsockopt(socket_, SOL_SOCKET, SO_RANDOMIZE_PORT,
             reinterpret_cast<const char*>(&randomize_port_value),
             sizeof(randomize_port_value));

  SockaddrStorage storage;
  if (!address.ToSockAddr(storage.addr, &storage.addr_len))
    return ERR_ADDRESS_INVALID;

  int rv = connect(socket_, storage.addr, storage.addr_len);
  if (rv < 0)
    return MapSystemError(WSAGetLastError());

  remote_address_ = std::make_unique<IPEndPoint>(address);

  if (dscp_manager_)
    dscp_manager_->PrepareForSend(*remote_address_.get());

  return rv;
}

int UDPSocketWin::Bind(const IPEndPoint& address) {
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK(!is_connected());

  int rv = SetMulticastOptions();
  if (rv < 0)
    return rv;

  rv = DoBind(address);
  if (rv < 0)
    return rv;

  local_address_.reset();
  is_connected_ = true;
  return rv;
}

int UDPSocketWin::BindToNetwork(handles::NetworkHandle network) {
  NOTIMPLEMENTED();
  return ERR_NOT_IMPLEMENTED;
}

int UDPSocketWin::SetReceiveBufferSize(int32_t size) {
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  int rv = SetSocketReceiveBufferSize(socket_, size);

  if (rv != 0)
    return MapSystemError(WSAGetLastError());

  // According to documentation, setsockopt may succeed, but we need to check
  // the results via getsockopt to be sure it works on Windows.
  int32_t actual_size = 0;
  int option_size = sizeof(actual_size);
  rv = getsockopt(socket_, SOL_SOCKET, SO_RCVBUF,
                  reinterpret_cast<char*>(&actual_size), &option_size);
  if (rv != 0)
    return MapSystemError(WSAGetLastError());
  if (actual_size >= size)
    return OK;
  UMA_HISTOGRAM_CUSTOM_COUNTS("Net.SocketUnchangeableReceiveBuffer",
                              actual_size, 1000, 1000000, 50);
  return ERR_SOCKET_RECEIVE_BUFFER_SIZE_UNCHANGEABLE;
}

int UDPSocketWin::SetSendBufferSize(int32_t size) {
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  int rv = SetSocketSendBufferSize(socket_, size);
  if (rv != 0)
    return MapSystemError(WSAGetLastError());
  // According to documentation, setsockopt may succeed, but we need to check
  // the results via getsockopt to be sure it works on Windows.
  int32_t actual_size = 0;
  int option_size = sizeof(actual_size);
  rv = getsockopt(socket_, SOL_SOCKET, SO_SNDBUF,
                  reinterpret_cast<char*>(&actual_size), &option_size);
  if (rv != 0)
    return MapSystemError(WSAGetLastError());
  if (actual_size >= size)
    return OK;
  UMA_HISTOGRAM_CUSTOM_COUNTS("Net.SocketUnchangeableSendBuffer",
                              actual_size, 1000, 1000000, 50);
  return ERR_SOCKET_SEND_BUFFER_SIZE_UNCHANGEABLE;
}

int UDPSocketWin::SetDoNotFragment() {
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (addr_family_ == AF_INET6)
    return OK;

  DWORD val = 1;
  int rv = setsockopt(socket_, IPPROTO_IP, IP_DONTFRAGMENT,
                      reinterpret_cast<const char*>(&val), sizeof(val));
  return rv == 0 ? OK : MapSystemError(WSAGetLastError());
}

LPFN_WSARECVMSG UDPSocketWin::GetRecvMsgPointer() {
  LPFN_WSARECVMSG rv;
  GUID message_code = WSAID_WSARECVMSG;
  DWORD size;
  if (WSAIoctl(socket_, SIO_GET_EXTENSION_FUNCTION_POINTER, &message_code,
               sizeof(message_code), &rv, sizeof(rv), &size, NULL,
               NULL) == SOCKET_ERROR) {
    return nullptr;
  }
  return rv;
}

LPFN_WSASENDMSG UDPSocketWin::GetSendMsgPointer() {
  LPFN_WSASENDMSG rv;
  GUID message_code = WSAID_WSASENDMSG;
  DWORD size;
  if (WSAIoctl(socket_, SIO_GET_EXTENSION_FUNCTION_POINTER, &message_code,
               sizeof(message_code), &rv, sizeof(rv), &size, NULL,
               NULL) == SOCKET_ERROR) {
    return nullptr;
  }
  return rv;
}

int UDPSocketWin::LogAndReturnError() const {
  int result = MapSystemError(WSAGetLastError());
  LogRead(result, nullptr, nullptr);
  return result;
}

// Windows documentation recommends using WSASetRecvIPEcn(). However,
// this does not set the option for IPv4 packets on a dual-stack socket.
// It also returns an error when bound to an IPv4-mapped IPv6 address.
int UDPSocketWin::SetRecvTos() {
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  IPEndPoint address;
  int rv = GetLocalAddress(&address);
  if (rv != OK) {
    return rv;
  }
  int v6_only = 0;
  int ecn = 1;
  if (addr_family_ == AF_INET6 && !address.address().IsIPv4MappedIPv6()) {
    rv = setsockopt(socket_, IPPROTO_IPV6, IPV6_RECVECN,
                    reinterpret_cast<const char*>(&ecn), sizeof(ecn));
    if (rv != 0) {
      return LogAndReturnError();
    }
    if (!address.address().IsZero()) {
      // If a socket is bound to an address besides IPV6_ANY, it won't receive
      // any v4 packets, and therefore is not truly dual-stack.
      v6_only = 1;
    } else {
      int option_size = sizeof(v6_only);
      rv = getsockopt(socket_, IPPROTO_IPV6, IPV6_V6ONLY,
                      reinterpret_cast<char*>(&v6_only), &option_size);
      if (rv != 0) {
        return LogAndReturnError();
      }
    }
  }
  if (v6_only == 0) {
    rv = setsockopt(socket_, IPPROTO_IP, IP_RECVECN,
                    reinterpret_cast<const char*>(&ecn), sizeof(ecn));
    if (rv != 0) {
      return LogAndReturnError();
    }
  }
  wsa_recv_msg_ = GetRecvMsgPointer();
  if (wsa_recv_msg_ == nullptr) {
    return LogAndReturnError();
  }
  report_ecn_ = true;
  return 0;
}

void UDPSocketWin::SetMsgConfirm(bool confirm) {}

int UDPSocketWin::AllowAddressReuse() {
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!is_connected());

  BOOL true_value = TRUE;
  int rv = setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR,
                      reinterpret_cast<const char*>(&true_value),
                      sizeof(true_value));
  return rv == 0 ? OK : MapSystemError(WSAGetLastError());
}

int UDPSocketWin::SetBroadcast(bool broadcast) {
  DCHECK_NE(socket_, INVALID_SOCKET);
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  BOOL value = broadcast ? TRUE : FALSE;
  int rv = setsockopt(socket_, SOL_SOCKET, SO_BROADCAST,
                      reinterpret_cast<const char*>(&value), sizeof(value));
  return rv == 0 ? OK : MapSystemError(WSAGetLastError());
}

int UDPSocketWin::AllowAddressSharingForMulticast() {
  // When proper multicast groups are used, Windows further defines the
  // address reuse option (SO_REUSEADDR) to ensure all listening sockets can
  // receive all incoming messages for the multicast group.
  return AllowAddressReuse();
}

void UDPSocketWin::DoReadCallback(int rv) {
  DCHECK_NE(rv, ERR_IO_PENDING);
  DCHECK(!read_callback_.is_null());

  // since Run may result in Read being called, clear read_callback_ up front.
  std::move(read_callback_).Run(rv);
}

void UDPSocketWin::DoWriteCallback(int rv) {
  DCHECK_NE(rv, ERR_IO_PENDING);
  DCHECK(!write_callback_.is_null());

  // since Run may result in Write being called, clear write_callback_ up
  // front.
  std::move(write_callback_).Run(rv);
}

void UDPSocketWin::DidCompleteRead() {
  DWORD num_bytes, flags;
  BOOL ok = WSAGetOverlappedResult(socket_, &core_->read_overlapped_,
                                   &num_bytes, FALSE, &flags);
  WSAResetEvent(core_->read_overlapped_.hEvent);
  int result = ok ? num_bytes : MapSystemError(WSAGetLastError());
  // Convert address.
  IPEndPoint address;
  IPEndPoint* address_to_log = nullptr;
  if (result >= 0) {
    if (address.FromSockAddr(core_->recv_addr_storage_.addr,
                             core_->recv_addr_storage_.addr_len)) {
      if (recv_from_address_) {
        *recv_from_address_ = address;
      }
      address_to_log = &address;
    } else {
      result = ERR_ADDRESS_INVALID;
    }
    if (core_->read_message_ != nullptr) {
      SetLastTosFromWSAMSG(*core_->read_message_);
    }
  }
  LogRead(result, core_->read_iobuffer_->data(), address_to_log);
  core_->read_iobuffer_ = nullptr;
  core_->read_message_ = nullptr;
  recv_from_address_ = nullptr;
  DoReadCallback(result);
}

void UDPSocketWin::DidCompleteWrite() {
  DWORD num_bytes, flags;
  BOOL ok = WSAGetOverlappedResult(socket_, &core_->write_overlapped_,
                                   &num_bytes, FALSE, &flags);
  WSAResetEvent(core_->write_overlapped_.hEvent);
  int result = ok ? num_bytes : MapSystemError(WSAGetLastError());
  LogWrite(result, core_->write_iobuffer_->data(), send_to_address_.get());

  send_to_address_.reset();
  core_->write_iobuffer_ = nullptr;
  DoWriteCallback(result);
}

void UDPSocketWin::OnObjectSignaled(HANDLE object) {
  DCHECK(object == read_write_event_.Get());
  WSANETWORKEVENTS network_events;
  int os_error = 0;
  int rv =
      WSAEnumNetworkEvents(socket_, read_write_event_.Get(), &network_events);
  // Protects against trying to call the write callback if the read callback
  // either closes or destroys |this|.
  base::WeakPtr<UDPSocketWin> event_pending = event_pending_.GetWeakPtr();
  if (rv == SOCKET_ERROR) {
    os_error = WSAGetLastError();
    rv = MapSystemError(os_error);

    if (read_iobuffer_) {
      read_iobuffer_ = nullptr;
      read_iobuffer_len_ = 0;
      recv_from_address_ = nullptr;
      DoReadCallback(rv);
    }

    // Socket may have been closed or destroyed here.
    if (event_pending && write_iobuffer_) {
      write_iobuffer_ = nullptr;
      write_iobuffer_len_ = 0;
      send_to_address_.reset();
      DoWriteCallback(rv);
    }
    return;
  }

  if ((network_events.lNetworkEvents & FD_READ) && read_iobuffer_) {
    OnReadSignaled();
  }
  if (!event_pending) {
    return;
  }

  if ((network_events.lNetworkEvents & FD_WRITE) && write_iobuffer_) {
    OnWriteSignaled();
  }
  if (!event_pending) {
    return;
  }

  // There's still pending read / write. Watch for further events.
  if (read_iobuffer_ || write_iobuffer_) {
    WatchForReadWrite();
  }
}

void UDPSocketWin::OnReadSignaled() {
  int rv = InternalRecvFromNonBlocking(read_iobuffer_.get(), read_iobuffer_len_,
                                       recv_from_address_);
  if (rv == ERR_IO_PENDING) {
    return;
  }
  read_iobuffer_ = nullptr;
  read_iobuffer_len_ = 0;
  recv_from_address_ = nullptr;
  DoReadCallback(rv);
}

void UDPSocketWin::OnWriteSignaled() {
  int rv = InternalSendToNonBlocking(write_iobuffer_.get(), write_iobuffer_len_,
                                     send_to_address_.get());
  if (rv == ERR_IO_PENDING) {
    return;
  }
  write_iobuffer_ = nullptr;
  write_iobuffer_len_ = 0;
  send_to_address_.reset();
  DoWriteCallback(rv);
}

void UDPSocketWin::WatchForReadWrite() {
  if (read_write_watcher_.IsWatching()) {
    return;
  }
  bool watched =
      read_write_watcher_.StartWatchingOnce(read_write_event_.Get(), this);
  DCHECK(watched);
}

void UDPSocketWin::LogRead(int result,
                           const char* bytes,
                           const IPEndPoint* address) const {
  if (result < 0) {
    net_log_.AddEventWithNetErrorCode(NetLogEventType::UDP_RECEIVE_ERROR,
                                      result);
    return;
  }

  if (net_log_.IsCapturing()) {
    NetLogUDPDataTransfer(net_log_, NetLogEventType::UDP_BYTES_RECEIVED, result,
                          bytes, address);
  }

  activity_monitor::IncrementBytesReceived(result);
}

void UDPSocketWin::LogWrite(int result,
                            const char* bytes,
                            const IPEndPoint* address) const {
  if (result < 0) {
    net_log_.AddEventWithNetErrorCode(NetLogEventType::UDP_SEND_ERROR, result);
    return;
  }

  if (net_log_.IsCapturing()) {
    NetLogUDPDataTransfer(net_log_, NetLogEventType::UDP_BYTES_SENT, result,
                          bytes, address);
  }
}

void UDPSocketWin::PopulateWSAMSG(WSAMSG& message,
                                  SockaddrStorage& storage,
                                  WSABUF* data_buffer,
                                  WSABUF& control_buffer,
                                  bool send) {
  bool is_ipv6;
  if (send && remote_address_.get() != nullptr) {
    is_ipv6 = (remote_address_->GetSockAddrFamily() == AF_INET6);
  } else {
    is_ipv6 = (addr_family_ == AF_INET6);
  }
  message.name = storage.addr;
  message.namelen = storage.addr_len;
  message.lpBuffers = data_buffer;
  message.dwBufferCount = 1;
  message.Control.buf = control_buffer.buf;
  message.dwFlags = 0;
  if (send) {
    message.Control.len = 0;
    WSACMSGHDR* cmsg;
    message.Control.len += WSA_CMSG_SPACE(sizeof(int));
    cmsg = WSA_CMSG_FIRSTHDR(&message);
    cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = is_ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
    cmsg->cmsg_type = is_ipv6 ? IPV6_ECN : IP_ECN;
    *(int*)WSA_CMSG_DATA(cmsg) = static_cast<int>(send_ecn_);
  } else {
    message.Control.len = control_buffer.len;
  }
}

void UDPSocketWin::SetLastTosFromWSAMSG(WSAMSG& message) {
  int ecn = 0;
  for (WSACMSGHDR* cmsg = WSA_CMSG_FIRSTHDR(&message); cmsg != NULL;
       cmsg = WSA_CMSG_NXTHDR(&message, cmsg)) {
    if ((cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_ECN) ||
        (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_ECN)) {
      ecn = *(int*)WSA_CMSG_DATA(cmsg);
      break;
    }
  }
  last_tos_.ecn = static_cast<EcnCodePoint>(ecn);
}

int UDPSocketWin::InternalRecvFromOverlapped(IOBuffer* buf,
                                             int buf_len,
                                             IPEndPoint* address) {
  DCHECK(!core_->read_iobuffer_.get());
  DCHECK(!core_->read_message_.get());
  SockaddrStorage& storage = core_->recv_addr_storage_;
  storage.addr_len = sizeof(storage.addr_storage);

  WSABUF read_buffer;
  read_buffer.buf = buf->data();
  read_buffer.len = buf_len;

  DWORD flags = 0;
  DWORD num;
  CHECK_NE(INVALID_SOCKET, socket_);
  int rv;
  std::unique_ptr<WSAMSG> message;
  if (report_ecn_) {
    WSABUF control_buffer;
    control_buffer.buf = core_->read_control_buffer_;
    control_buffer.len = sizeof(core_->read_control_buffer_);
    message = std::make_unique<WSAMSG>();
    if (message == nullptr) {
      return WSA_NOT_ENOUGH_MEMORY;
    }
    PopulateWSAMSG(*message, storage, &read_buffer, control_buffer, false);
    rv = wsa_recv_msg_(socket_, message.get(), &num, &core_->read_overlapped_,
                       nullptr);
    if (rv == 0) {
      SetLastTosFromWSAMSG(*message);
    }
  } else {
    rv = WSARecvFrom(socket_, &read_buffer, 1, &num, &flags, storage.addr,
                     &storage.addr_len, &core_->read_overlapped_, nullptr);
  }
  if (rv == 0) {
    if (ResetEventIfSignaled(core_->read_overlapped_.hEvent)) {
      int result = num;
      // Convert address.
      IPEndPoint address_storage;
      IPEndPoint* address_to_log = nullptr;
      if (result >= 0) {
        if (address_storage.FromSockAddr(core_->recv_addr_storage_.addr,
                                         core_->recv_addr_storage_.addr_len)) {
          if (address) {
            *address = address_storage;
          }
          address_to_log = &address_storage;
        } else {
          result = ERR_ADDRESS_INVALID;
        }
      }
      LogRead(result, buf->data(), address_to_log);
      return result;
    }
  } else {
    int os_error = WSAGetLastError();
    if (os_error != WSA_IO_PENDING) {
      int result = MapSystemError(os_error);
      LogRead(result, nullptr, nullptr);
      return result;
    }
  }
  core_->WatchForRead();
  core_->read_iobuffer_ = buf;
  core_->read_message_ = std::move(message);
  return ERR_IO_PENDING;
}

int UDPSocketWin::InternalSendToOverlapped(IOBuffer* buf,
                                           int buf_len,
                                           const IPEndPoint* address) {
  DCHECK(!core_->write_iobuffer_.get());
  SockaddrStorage storage;
  struct sockaddr* addr = storage.addr;
  // Convert address.
  if (!address) {
    addr = nullptr;
    storage.addr_len = 0;
  } else {
    if (!address->ToSockAddr(addr, &storage.addr_len)) {
      int result = ERR_ADDRESS_INVALID;
      LogWrite(result, nullptr, nullptr);
      return result;
    }
  }

  WSABUF write_buffer;
  write_buffer.buf = buf->data();
  write_buffer.len = buf_len;

  DWORD flags = 0;
  DWORD num;
  int rv;
  if (send_ecn_ != ECN_NOT_ECT) {
    WSABUF control_buffer;
    char raw_control_buffer[WSA_CMSG_SPACE(sizeof(int))];
    co
"""


```