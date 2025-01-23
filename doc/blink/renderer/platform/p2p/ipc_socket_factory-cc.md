Response: Let's break down the thought process to analyze the `ipc_socket_factory.cc` file and generate the requested information.

**1. Understanding the Core Functionality:**

The filename `ipc_socket_factory.cc` immediately suggests its primary role: creating sockets that communicate over Inter-Process Communication (IPC). The `blink/renderer/platform/p2p` path points towards its use in WebRTC's peer-to-peer communication within the Blink rendering engine.

Reading the initial comments confirms this. It's about managing P2P socket creation and interaction with the browser process.

**2. Identifying Key Classes and Structures:**

I scanned the code for prominent class definitions. The most important ones are:

* `IpcPacketSocket`:  This class *implements* `rtc::AsyncPacketSocket`, indicating it's the concrete socket implementation used for IPC. It also inherits from `blink::P2PSocketClientDelegate`, which is crucial for receiving events from the browser process. This immediately tells me it's the central class handling sending and receiving data.

* `IpcPacketSocketFactory`: This is the factory class responsible for creating instances of `IpcPacketSocket`. Its methods like `CreateUdpSocket` and `CreateClientTcpSocket` confirm this.

* `AsyncDnsAddressResolverImpl`: This handles asynchronous DNS resolution. Its implementation of `webrtc::AsyncDnsResolverInterface` is the key here.

* `InFlightPacketRecord`:  A simple struct for tracking packets sent but not yet acknowledged, useful for flow control.

**3. Tracing the Data Flow and Interactions:**

I then looked for how these classes interact:

* **Factory Creation:** The `IpcPacketSocketFactory` is instantiated somewhere (not in this file), likely in a higher-level WebRTC component within Blink.

* **Socket Creation:**  When the JavaScript WebRTC API requests a socket (e.g., `RTCPeerConnection`), the factory's methods (`CreateUdpSocket`, `CreateClientTcpSocket`) are called.

* **IPC Communication:**  Inside the `IpcPacketSocket`, the `client_` member (a `P2PSocketClientImpl`) is used to send messages to the browser process. The `P2PSocketDispatcher` is involved in obtaining the `P2PSocketManager` in the browser process.

* **Delegate Callbacks:**  The `IpcPacketSocket` implements the `P2PSocketClientDelegate` interface. Methods like `OnOpen`, `OnSendComplete`, `OnError`, and `OnDataReceived` are callbacks *from* the browser process, informing the renderer about socket events.

* **DNS Resolution:** When a hostname needs to be resolved, `IpcPacketSocketFactory::CreateAsyncDnsResolver` creates an `AsyncDnsAddressResolverImpl`. This class interacts with `P2PAsyncAddressResolver` to perform the actual resolution.

**4. Identifying Connections to JavaScript/HTML/CSS:**

This requires understanding the context of the code within a browser. While this C++ file doesn't directly manipulate the DOM or CSS, it's *part* of the implementation of WebRTC, which is exposed to JavaScript.

* **`RTCPeerConnection`:** The most direct link is through the JavaScript `RTCPeerConnection` API. When a `RTCPeerConnection` is created, it internally uses this factory to create the underlying network sockets.

* **Signaling (Indirect):**  Although this file doesn't handle signaling directly, the sockets it creates are used for the data channel within a WebRTC connection, which is set up based on signaling information exchanged via JavaScript.

**5. Inferring Logic and Examples:**

Based on the identified functionality, I started to reason about the logic:

* **Flow Control (`send_bytes_available_`, `in_flight_packet_records_`):** The code clearly implements a mechanism to prevent overwhelming the browser process with too much data. The `SendToInternal` method checks `send_bytes_available_` before sending. `OnSendComplete` updates this counter.

* **Error Handling:** The `OnError` method and the `error_` member indicate error reporting.

* **Socket Options:** The `GetOption` and `SetOption` methods show how socket options (like buffer sizes) are managed.

Then, I constructed examples:

* **JavaScript:**  Showing how `RTCPeerConnection` usage in JavaScript relates to the underlying socket creation.

* **Assumptions:**  Creating scenarios to illustrate the flow control logic (sending too much data).

**6. Identifying Common Errors:**

I looked for potential issues based on how the code is structured and its purpose:

* **Port Blocking:** The check in `CreateClientTcpSocket` for allowed ports immediately flags this as a potential user error.

* **Incorrect Signaling:**  Although not directly handled here, misconfigured signaling can lead to connection failures, which manifest as errors in these sockets.

* **Firewall Issues:** Firewalls can block the ports used by these sockets, leading to connectivity problems.

**7. Structuring the Output:**

Finally, I organized the information into the requested categories:

* **Functionality:** A high-level summary of what the file does.

* **Relationship to JS/HTML/CSS:** Explaining the connection through the WebRTC API and providing a JavaScript example.

* **Logic and Reasoning:**  Describing the flow control mechanism with input/output assumptions.

* **Common Errors:** Listing potential mistakes users or developers might make.

This iterative process of reading, identifying key components, tracing interactions, inferring logic, and finally structuring the output allows for a comprehensive analysis of the given source code. The understanding of WebRTC concepts is also crucial for making the connections to JavaScript and identifying common errors.
这个文件 `ipc_socket_factory.cc` 是 Chromium Blink 引擎中负责创建和管理用于 WebRTC P2P 连接的 socket 的工厂类。它主要负责在渲染进程（Renderer Process）中创建 `rtc::AsyncPacketSocket` 对象，这些对象实际上是通过进程间通信 (IPC) 与浏览器进程（Browser Process）中的 P2P socket 进行交互。

**主要功能:**

1. **Socket 创建:**  根据不同的 socket 类型（UDP, TCP client, SSL TCP client, TLS client 等），负责创建相应的 `IpcPacketSocket` 对象。这些 `IpcPacketSocket` 对象并非直接的操作系统 socket，而是 Blink 渲染进程中对 socket 的抽象表示。

2. **IPC 通信桥梁:** `IpcPacketSocket` 内部使用 `P2PSocketClientImpl` 与浏览器进程中的 `P2PSocket` 进行通信。它将渲染进程的 socket 操作（如发送数据、设置选项等）通过 IPC 传递给浏览器进程，并接收来自浏览器进程的 socket 事件（如收到数据、连接成功等）。

3. **流量控制:**  `IpcPacketSocket` 实现了一定的流量控制机制，通过维护 `send_bytes_available_` 和 `in_flight_packet_records_` 来限制发送到浏览器进程的数据量，防止渲染进程过度发送数据导致问题。

4. **异步 DNS 解析:** 提供创建异步 DNS 解析器 (`AsyncDnsAddressResolverImpl`) 的功能，用于解析 P2P 连接中使用的域名。

5. **Socket 选项管理:**  支持设置和获取 socket 的一些选项，例如接收和发送缓冲区大小 (`OPT_RCVBUF`, `OPT_SNDBUF`) 和 DSCP 值 (`OPT_DSCP`)。

**与 JavaScript, HTML, CSS 的关系 (通过 WebRTC API):**

这个文件本身是 C++ 代码，不直接涉及 JavaScript, HTML 或 CSS。但是，它是 WebRTC API 在 Blink 渲染引擎中的底层实现的一部分。

* **JavaScript:**  当 JavaScript 代码使用 `RTCPeerConnection` API 创建 P2P 连接时，Blink 引擎会调用 `IpcPacketSocketFactory` 来创建用于数据传输的 socket。例如，当调用 `createDataChannel()` 或通过 ICE negotiation建立连接后，会用到这里创建的 socket。

   ```javascript
   // JavaScript 示例
   const pc = new RTCPeerConnection();
   const dataChannel = pc.createDataChannel("myLabel");

   pc.onicecandidate = event => {
       // 发送 ICE candidate 到信令服务器
   };

   pc.onconnectionstatechange = event => {
       if (pc.connectionState === 'connected') {
           // 数据通道已连接，底层使用了 IpcPacketSocket 创建的 socket
           dataChannel.send("Hello from JavaScript!");
       }
   };

   dataChannel.onmessage = event => {
       console.log("Received message:", event.data);
   };
   ```

   在这个 JavaScript 例子中，当 `RTCPeerConnection` 建立连接并创建数据通道后，底层就会涉及到 `IpcPacketSocketFactory` 创建的 socket 进行数据传输。

* **HTML:** HTML 主要负责页面的结构，不直接与 `ipc_socket_factory.cc` 交互。但是，嵌入在 HTML 中的 JavaScript 代码会使用 WebRTC API，从而间接地使用到这个文件中的功能。

* **CSS:** CSS 负责页面的样式，与网络通信和 socket 创建没有直接关系。

**逻辑推理和假设输入/输出:**

**假设输入:**

1. **JavaScript 调用:** JavaScript 代码创建了一个 `RTCPeerConnection` 对象，并尝试建立一个 UDP 数据通道。
2. **Factory 调用:**  Blink 引擎根据 WebRTC 的需求，调用 `IpcPacketSocketFactory::CreateUdpSocket` 方法。
3. **参数:**  `CreateUdpSocket` 方法接收本地地址、端口范围等参数。

**逻辑推理:**

* `IpcPacketSocketFactory::CreateUdpSocket` 方法会创建一个 `IpcPacketSocket` 对象。
* `IpcPacketSocket` 的构造函数会初始化状态。
* `Init` 方法会被调用，它会：
    * 创建一个 `P2PSocketClientImpl` 对象，用于与浏览器进程通信。
    * 通过 IPC 向浏览器进程发送创建 socket 的请求，携带 socket 类型、本地地址、端口范围等信息。
    * 绑定 `P2PSocketClientDelegate` 的回调函数，以便接收来自浏览器进程的事件。

**假设输出:**

* 一个 `IpcPacketSocket` 对象被成功创建。
* 该 `IpcPacketSocket` 对象内部的 `P2PSocketClientImpl` 开始与浏览器进程的 P2P socket 进行通信。
* 当浏览器进程成功创建 socket 后，会通过 IPC 调用 `IpcPacketSocket::OnOpen` 方法，通知渲染进程 socket 已打开，并提供本地地址。

**用户或编程常见的使用错误举例:**

1. **端口冲突或权限问题:**
   * **错误:**  在创建 socket 时指定的端口已经被其他程序占用，或者渲染进程没有权限绑定到指定的端口。
   * **现象:**  `CreateUdpSocket` 或 `CreateClientTcpSocket` 返回 `nullptr`，或者 `Init` 方法失败。
   * **日志:**  可能会在控制台看到与端口绑定失败相关的错误信息。

2. **网络策略阻止连接:**
   * **错误:**  浏览器的安全策略或操作系统的防火墙阻止了 P2P 连接尝试。
   * **现象:**  `RTCPeerConnection` 的连接状态停留在 "connecting" 或最终变为 "failed"。虽然 `IpcPacketSocket` 可能成功创建，但数据无法正常传输。
   * **日志:**  可能在控制台或网络面板看到连接被拒绝或超时的错误。

3. **错误使用 Socket 选项:**
   * **错误:**  尝试设置不支持的 socket 选项，或者设置了无效的值。
   * **现象:**  `SetOption` 方法返回 -1，表示设置失败。
   * **日志:**  可能会有 `NOTREACHED()` 相关的日志输出，因为代码中对不支持的选项有判断。

4. **过度发送数据导致流量控制阻塞:**
   * **错误:**  在短时间内通过数据通道发送大量数据，超过了 `IpcPacketSocket` 的流量控制限制。
   * **现象:**  `Send` 或 `SendTo` 方法会返回表示阻塞的错误码（例如 `EWOULDBLOCK`），并且在 WebRTC 日志中可能会看到 "MaxPendingBytesWouldBlock" 的消息。
   * **代码层面:** 这不是用户的直接错误，而是 WebRTC 内部流量控制机制的体现，但开发者需要注意避免这种情况，合理控制发送速率。

5. **DNS 解析失败:**
   * **错误:**  尝试连接到一个无法解析的域名。
   * **现象:**  `RTCPeerConnection` 建立连接失败。在 `IpcPacketSocketFactory` 中创建的 `AsyncDnsAddressResolverImpl` 在解析地址时会失败。
   * **日志:**  可能会看到 DNS 解析失败的错误信息。

总而言之，`ipc_socket_factory.cc` 是 Blink 引擎中 WebRTC P2P 通信的关键组成部分，它负责在渲染进程中创建和管理与浏览器进程进行 IPC 通信的抽象 socket，从而支持 JavaScript WebRTC API 的功能。理解这个文件的工作原理有助于理解 WebRTC 在浏览器内部的实现机制。

### 提示词
```
这是目录为blink/renderer/platform/p2p/ipc_socket_factory.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/p2p/ipc_socket_factory.h"

#include <stddef.h>

#include <algorithm>
#include <list>
#include <memory>

#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/logging.h"
#include "base/memory/weak_ptr.h"
#include "base/strings/stringprintf.h"
#include "base/task/bind_post_task.h"
#include "base/threading/thread_checker.h"
#include "base/trace_event/trace_event.h"
#include "base/unguessable_token.h"
#include "components/webrtc/net_address_utils.h"
#include "net/base/ip_address.h"
#include "net/base/port_util.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_persistent.h"
#include "third_party/blink/renderer/platform/p2p/host_address_request.h"
#include "third_party/blink/renderer/platform/p2p/socket_client_delegate.h"
#include "third_party/blink/renderer/platform/p2p/socket_client_impl.h"
#include "third_party/blink/renderer/platform/p2p/socket_dispatcher.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/webrtc/api/async_dns_resolver.h"
#include "third_party/webrtc/rtc_base/async_packet_socket.h"
#include "third_party/webrtc/rtc_base/network/received_packet.h"

namespace blink {

namespace {

const int kDefaultNonSetOptionValue = -1;

bool IsTcpClientSocket(network::P2PSocketType type) {
  return (type == network::P2P_SOCKET_STUN_TCP_CLIENT) ||
         (type == network::P2P_SOCKET_TCP_CLIENT) ||
         (type == network::P2P_SOCKET_STUN_SSLTCP_CLIENT) ||
         (type == network::P2P_SOCKET_SSLTCP_CLIENT) ||
         (type == network::P2P_SOCKET_TLS_CLIENT) ||
         (type == network::P2P_SOCKET_STUN_TLS_CLIENT);
}

bool JingleSocketOptionToP2PSocketOption(rtc::Socket::Option option,
                                         network::P2PSocketOption* ipc_option) {
  switch (option) {
    case rtc::Socket::OPT_RCVBUF:
      *ipc_option = network::P2P_SOCKET_OPT_RCVBUF;
      break;
    case rtc::Socket::OPT_SNDBUF:
      *ipc_option = network::P2P_SOCKET_OPT_SNDBUF;
      break;
    case rtc::Socket::OPT_DSCP:
      *ipc_option = network::P2P_SOCKET_OPT_DSCP;
      break;
    case rtc::Socket::OPT_RECV_ECN:
      *ipc_option = network::P2P_SOCKET_OPT_RECV_ECN;
      break;
    case rtc::Socket::OPT_DONTFRAGMENT:
    case rtc::Socket::OPT_NODELAY:
    case rtc::Socket::OPT_IPV6_V6ONLY:
    case rtc::Socket::OPT_RTP_SENDTIME_EXTN_ID:
      return false;  // Not supported by the chrome sockets.
    default:
      NOTREACHED();
  }
  return true;
}

// 640KB, 10x max UDP packet size. This controls the maximum size we can write
// to the IPC buffer, which is consumed by the shared network service process.
//
// If this buffer is too small, we'll see more MaxPendingBytesWouldBlock
// events and text log entries from WebRTC (search for kSendErrorLogLimit).
// As is, rate limiting in the layer in WebRTC that calls this layer, isn't very
// sophisticated and the cost of being blocked by this limit can be quite high.
// After being blocked, this implementation will fire an event once bytes have
// been freed up, which is then fanned out to all potentially waiting writers.
// That can create a storm of calls to `Send[To]` which may then cause multiple
// blocking errors again, both wasting CPU and spamming the log.
// The network service is single threaded and shared with other render
// processes. So having this max value large enough to accommodate multiple
// buffers, allows for more efficient bulk processing and less back-and-forth
// synchronizing between the render processes and network service.
// See also: bugs.webrtc.org/9622 and crbug/856088.
const size_t kDefaultMaximumInFlightBytes = 10 * 64 * 1024;

// IpcPacketSocket implements rtc::AsyncPacketSocket interface
// using P2PSocketClient that works over IPC-channel. It must be used
// on the thread it was created.
class IpcPacketSocket : public rtc::AsyncPacketSocket,
                        public blink::P2PSocketClientDelegate {
 public:
  IpcPacketSocket();
  IpcPacketSocket(const IpcPacketSocket&) = delete;
  IpcPacketSocket& operator=(const IpcPacketSocket&) = delete;
  ~IpcPacketSocket() override;

  // Struct to track information when a packet is received by this socket for
  // send. The information tracked here will be used to match with the
  // P2PSendPacketMetrics from the underneath system socket.
  struct InFlightPacketRecord {
    InFlightPacketRecord(uint64_t packet_id, size_t packet_size)
        : packet_id(packet_id), packet_size(packet_size) {}

    uint64_t packet_id;
    size_t packet_size;
  };

  typedef std::list<InFlightPacketRecord> InFlightPacketList;

  // Always takes ownership of client even if initialization fails.
  bool Init(
      P2PSocketDispatcher* dispatcher,
      const net::NetworkTrafficAnnotationTag& traffic_annotation,
      network::P2PSocketType type,
      std::unique_ptr<P2PSocketClientImpl> client,
      const rtc::SocketAddress& local_address,
      uint16_t min_port,
      uint16_t max_port,
      const rtc::SocketAddress& remote_address,
      WTF::CrossThreadFunction<void(
          base::OnceCallback<void(std::optional<base::UnguessableToken>)>)>&
          devtools_token);

  // rtc::AsyncPacketSocket interface.
  rtc::SocketAddress GetLocalAddress() const override;
  rtc::SocketAddress GetRemoteAddress() const override;
  int Send(const void* pv,
           size_t cb,
           const rtc::PacketOptions& options) override;
  int SendTo(const void* pv,
             size_t cb,
             const rtc::SocketAddress& addr,
             const rtc::PacketOptions& options) override;
  int Close() override;
  State GetState() const override;
  int GetOption(rtc::Socket::Option option, int* value) override;
  int SetOption(rtc::Socket::Option option, int value) override;
  int GetError() const override;
  void SetError(int error) override;

  // P2PSocketClientDelegate implementation.
  void OnOpen(const net::IPEndPoint& local_address,
              const net::IPEndPoint& remote_address) override;
  void OnSendComplete(
      const network::P2PSendPacketMetrics& send_metrics) override;
  void OnError() override;
  void OnDataReceived(const net::IPEndPoint& address,
                      base::span<const uint8_t> data,
                      const base::TimeTicks& timestamp,
                      rtc::EcnMarking ecn) override;

 private:
  static void DoCreateSocket(
      network::P2PSocketType type,
      P2PSocketDispatcher* dispatcher,
      net::IPEndPoint local_endpoint,
      uint16_t min_port,
      uint16_t max_port,
      network::P2PHostAndIPEndPoint remote_info,
      net::NetworkTrafficAnnotationTag traffic_annotation,
      mojo::PendingRemote<network::mojom::blink::P2PSocketClient> remote,
      mojo::PendingReceiver<network::mojom::blink::P2PSocket> receiver,
      std::optional<base::UnguessableToken> devtools_token);
  int SendToInternal(const void* pv,
                     size_t cb,
                     const rtc::SocketAddress& addr,
                     const rtc::PacketOptions& options);

  enum InternalState {
    kIsUninitialized,
    kIsOpening,
    kIsOpen,
    kIsClosed,
    kIsError,
  };

  // Increment the counter for consecutive bytes discarded as socket is running
  // out of buffer.
  void IncrementDiscardCounters(size_t bytes_discarded);

  // Update trace of send throttling internal state. This should be called
  // immediately after any changes to |send_bytes_available_| and/or
  // |in_flight_packet_records_|.
  void TraceSendThrottlingState() const;

  int DoSetOption(network::P2PSocketOption option, int value);

  network::P2PSocketType type_;

  // Used to verify that a method runs on the thread that created this socket.
  THREAD_CHECKER(thread_checker_);

  // Corresponding P2P socket client.
  std::unique_ptr<blink::P2PSocketClientImpl> client_;

  // Local address is allocated by the browser process, and the
  // renderer side doesn't know the address until it receives OnOpen()
  // event from the browser.
  rtc::SocketAddress local_address_;

  // Remote address for client TCP connections.
  rtc::SocketAddress remote_address_;

  // Current state of the object.
  InternalState state_;

  // Track the number of bytes allowed to be sent non-blocking. This is used to
  // throttle the sending of packets to the browser process. For each packet
  // sent, the value is decreased. As callbacks to OnSendComplete() (as IPCs
  // from the browser process) are made, the value is increased back. This
  // allows short bursts of high-rate sending without dropping packets, but
  // quickly restricts the client to a sustainable steady-state rate.
  size_t send_bytes_available_;

  // The current limit for maximum bytes in flight.
  size_t max_in_flight_bytes_;

  // Used to detect when browser doesn't send SendComplete message for some
  // packets. In normal case, the first packet should be the one that we're
  // going to receive the next completion signal.
  InFlightPacketList in_flight_packet_records_;

  // Set to true once EWOULDBLOCK was returned from Send(). Indicates that the
  // caller expects SignalWritable notification.
  bool writable_signal_expected_;

  // Current error code. Valid when state_ == IS_ERROR.
  int error_;
  int options_[network::P2P_SOCKET_OPT_MAX];

  // Track the maximum and current consecutive bytes discarded due to not enough
  // send_bytes_available_.
  size_t max_discard_bytes_sequence_;
  size_t current_discard_bytes_sequence_;
};

// Simple wrapper around P2PAsyncAddressResolver. The main purpose of this
// class is to call the right callback after OnDone callback from
// P2PAsyncAddressResolver, and keep track of the result.
// Thread jumping is handled by P2PAsyncAddressResolver.
class AsyncDnsAddressResolverImpl : public webrtc::AsyncDnsResolverInterface,
                                    public webrtc::AsyncDnsResolverResult {
 public:
  explicit AsyncDnsAddressResolverImpl(P2PSocketDispatcher* dispatcher);
  ~AsyncDnsAddressResolverImpl() override;

  // webrtc::AsyncDnsResolverInterface interface.
  void Start(const rtc::SocketAddress& addr,
             absl::AnyInvocable<void()> callback) override;
  void Start(const rtc::SocketAddress& addr,
             int address_family,
             absl::AnyInvocable<void()> callback) override;
  const AsyncDnsResolverResult& result() const override { return *this; }
  // webrtc::AsyncDnsResolverResult interface
  bool GetResolvedAddress(int family, rtc::SocketAddress* addr) const override;
  int GetError() const override;

 private:
  virtual void OnAddressResolved(const Vector<net::IPAddress>& addresses);

  scoped_refptr<P2PAsyncAddressResolver> resolver_;

  THREAD_CHECKER(thread_checker_);

  rtc::SocketAddress addr_;           // Address to resolve.
  bool started_ = false;
  absl::AnyInvocable<void()> callback_;
  Vector<rtc::IPAddress> addresses_;  // Resolved addresses.

  base::WeakPtrFactory<AsyncDnsAddressResolverImpl> weak_factory_{this};
};

IpcPacketSocket::IpcPacketSocket()
    : type_(network::P2P_SOCKET_UDP),
      state_(kIsUninitialized),
      send_bytes_available_(kDefaultMaximumInFlightBytes),
      max_in_flight_bytes_(kDefaultMaximumInFlightBytes),
      writable_signal_expected_(false),
      error_(0),
      max_discard_bytes_sequence_(0),
      current_discard_bytes_sequence_(0) {
  static_assert(kDefaultMaximumInFlightBytes > 0, "would send at zero rate");
  std::fill_n(options_, static_cast<int>(network::P2P_SOCKET_OPT_MAX),
              kDefaultNonSetOptionValue);
}

IpcPacketSocket::~IpcPacketSocket() {
  if (state_ == kIsOpening || state_ == kIsOpen || state_ == kIsError) {
    Close();
  }
}

void IpcPacketSocket::TraceSendThrottlingState() const {
  TRACE_COUNTER_ID1("p2p", "P2PSendBytesAvailable", local_address_.port(),
                    send_bytes_available_);
  TRACE_COUNTER_ID1("p2p", "P2PSendPacketsInFlight", local_address_.port(),
                    in_flight_packet_records_.size());
}

void IpcPacketSocket::IncrementDiscardCounters(size_t bytes_discarded) {
  current_discard_bytes_sequence_ += bytes_discarded;

  if (current_discard_bytes_sequence_ > max_discard_bytes_sequence_) {
    max_discard_bytes_sequence_ = current_discard_bytes_sequence_;
  }
}

bool IpcPacketSocket::Init(
    P2PSocketDispatcher* dispatcher,
    const net::NetworkTrafficAnnotationTag& traffic_annotation,
    network::P2PSocketType type,
    std::unique_ptr<P2PSocketClientImpl> client,
    const rtc::SocketAddress& local_address,
    uint16_t min_port,
    uint16_t max_port,
    const rtc::SocketAddress& remote_address,
    WTF::CrossThreadFunction<
        void(base::OnceCallback<void(std::optional<base::UnguessableToken>)>)>&
        devtools_token_getter) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_EQ(state_, kIsUninitialized);

  type_ = type;
  client_ = std::move(client);
  local_address_ = local_address;
  remote_address_ = remote_address;
  state_ = kIsOpening;

  net::IPEndPoint local_endpoint;
  if (!webrtc::SocketAddressToIPEndPoint(local_address, &local_endpoint)) {
    return false;
  }

  net::IPEndPoint remote_endpoint;
  if (!remote_address.IsNil()) {
    DCHECK(IsTcpClientSocket(type_));

    if (remote_address.IsUnresolvedIP()) {
      remote_endpoint =
          net::IPEndPoint(net::IPAddress(), remote_address.port());
    } else {
      if (!webrtc::SocketAddressToIPEndPoint(remote_address,
                                             &remote_endpoint)) {
        return false;
      }
    }
  }

  // We need to send both resolved and unresolved address in Init. Unresolved
  // address will be used in case of TLS for certificate hostname matching.
  // Certificate will be tied to domain name not to IP address.
  network::P2PHostAndIPEndPoint remote_info(remote_address.hostname(),
                                            remote_endpoint);

  devtools_token_getter.Run(base::BindPostTaskToCurrentDefault(WTF::BindOnce(
      &IpcPacketSocket::DoCreateSocket, type_,
      WrapCrossThreadPersistent(dispatcher), local_endpoint, min_port, max_port,
      remote_info, traffic_annotation, client_->CreatePendingRemote(),
      client_->CreatePendingReceiver())));

  client_->Init(this);

  return true;
}

void IpcPacketSocket::DoCreateSocket(
    network::P2PSocketType type,
    P2PSocketDispatcher* dispatcher,
    net::IPEndPoint local_endpoint,
    uint16_t min_port,
    uint16_t max_port,
    network::P2PHostAndIPEndPoint remote_info,
    net::NetworkTrafficAnnotationTag traffic_annotation,
    mojo::PendingRemote<network::mojom::blink::P2PSocketClient> remote,
    mojo::PendingReceiver<network::mojom::blink::P2PSocket> receiver,
    std::optional<base::UnguessableToken> devtools_token) {
  CHECK(dispatcher);

  dispatcher->GetP2PSocketManager()->CreateSocket(
      type, local_endpoint, network::P2PPortRange(min_port, max_port),
      remote_info, net::MutableNetworkTrafficAnnotationTag(traffic_annotation),
      devtools_token, std::move(remote), std::move(receiver));
}

// rtc::AsyncPacketSocket interface.
rtc::SocketAddress IpcPacketSocket::GetLocalAddress() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return local_address_;
}

rtc::SocketAddress IpcPacketSocket::GetRemoteAddress() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return remote_address_;
}

int IpcPacketSocket::Send(const void* data,
                          size_t data_size,
                          const rtc::PacketOptions& options) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return SendTo(data, data_size, remote_address_, options);
}

int IpcPacketSocket::SendTo(const void* data,
                            size_t data_size,
                            const rtc::SocketAddress& address,
                            const rtc::PacketOptions& options) {
  int result = SendToInternal(data, data_size, address, options);
  // Ensure a batch is sent in case the packet in the batch has been dropped.
  if (result < 0 && options.last_packet_in_batch) {
    client_->FlushBatch();
  }
  return result;
}

int IpcPacketSocket::SendToInternal(const void* data,
                                    size_t data_size,
                                    const rtc::SocketAddress& address,
                                    const rtc::PacketOptions& options) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  switch (state_) {
    case kIsUninitialized:
      NOTREACHED();
    case kIsOpening:
      error_ = EWOULDBLOCK;
      return -1;
    case kIsClosed:
      error_ = ENOTCONN;
      return -1;
    case kIsError:
      return -1;
    case kIsOpen:
      // Continue sending the packet.
      break;
  }

  if (data_size == 0) {
    NOTREACHED();
  }

  if (data_size > send_bytes_available_) {
    TRACE_EVENT_INSTANT1("p2p", "MaxPendingBytesWouldBlock",
                         TRACE_EVENT_SCOPE_THREAD, "id",
                         client_->GetSocketID());
    if (!writable_signal_expected_) {
      blink::WebRtcLogMessage(base::StringPrintf(
          "IpcPacketSocket: sending is blocked. %d packets_in_flight.",
          static_cast<int>(in_flight_packet_records_.size())));

      writable_signal_expected_ = true;
    }

    error_ = EWOULDBLOCK;
    IncrementDiscardCounters(data_size);
    return -1;
  } else {
    current_discard_bytes_sequence_ = 0;
  }

  net::IPEndPoint address_chrome;
  if (address.IsUnresolvedIP()) {
    address_chrome = net::IPEndPoint(net::IPAddress(), address.port());
  } else {
    if (!webrtc::SocketAddressToIPEndPoint(address, &address_chrome)) {
      LOG(WARNING) << "Failed to convert remote address to IPEndPoint: address="
                   << address.ipaddr().ToSensitiveString()
                   << ", remote_address_="
                   << remote_address_.ipaddr().ToSensitiveString();
      NOTREACHED();
    }
  }

  DCHECK_GE(send_bytes_available_, data_size);
  send_bytes_available_ -= data_size;

  uint64_t packet_id = client_->Send(
      address_chrome,
      base::make_span(static_cast<const uint8_t*>(data), data_size), options);

  // Ensure packet_id is not 0. It can't be the case according to
  // P2PSocketClientImpl::Send().
  DCHECK_NE(packet_id, 0uL);
  in_flight_packet_records_.push_back(
      InFlightPacketRecord(packet_id, data_size));
  TraceSendThrottlingState();

  // Fake successful send. The caller ignores result anyway.
  return base::checked_cast<int>(data_size);
}

int IpcPacketSocket::Close() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  client_->Close();
  state_ = kIsClosed;

  return 0;
}

rtc::AsyncPacketSocket::State IpcPacketSocket::GetState() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  switch (state_) {
    case kIsUninitialized:
      NOTREACHED();

    case kIsOpening:
      return STATE_BINDING;

    case kIsOpen:
      if (IsTcpClientSocket(type_)) {
        return STATE_CONNECTED;
      } else {
        return STATE_BOUND;
      }

    case kIsClosed:
    case kIsError:
      return STATE_CLOSED;
  }

  NOTREACHED();
}

int IpcPacketSocket::GetOption(rtc::Socket::Option option, int* value) {
  network::P2PSocketOption p2p_socket_option = network::P2P_SOCKET_OPT_MAX;
  if (!JingleSocketOptionToP2PSocketOption(option, &p2p_socket_option)) {
    // unsupported option.
    return -1;
  }

  *value = options_[p2p_socket_option];
  return 0;
}

int IpcPacketSocket::SetOption(rtc::Socket::Option option, int value) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  network::P2PSocketOption p2p_socket_option = network::P2P_SOCKET_OPT_MAX;
  if (!JingleSocketOptionToP2PSocketOption(option, &p2p_socket_option)) {
    // Option is not supported.
    return -1;
  }

  options_[p2p_socket_option] = value;

  if (state_ == kIsOpen) {
    // Options will be applied when state becomes kIsOPEN in OnOpen.
    return DoSetOption(p2p_socket_option, value);
  }
  return 0;
}

int IpcPacketSocket::DoSetOption(network::P2PSocketOption option, int value) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_EQ(state_, kIsOpen);

  client_->SetOption(option, value);
  if (option == network::P2PSocketOption::P2P_SOCKET_OPT_SNDBUF && value > 0) {
    LOG(INFO) << "Setting new p2p socket buffer limit to " << value;

    // Allow socket option to increase in-flight limit above default, but not
    // reduce it.
    size_t new_limit =
        std::max(static_cast<size_t>(value), kDefaultMaximumInFlightBytes);
    size_t in_flight_bytes = max_in_flight_bytes_ - send_bytes_available_;
    if (in_flight_bytes > new_limit) {
      // New limit is lower than the current number of in flight bytes - just
      // set availability to 0 but allow the current excess to still be sent.
      send_bytes_available_ = 0;
    } else {
      send_bytes_available_ = new_limit - in_flight_bytes;
    }
    max_in_flight_bytes_ = new_limit;
  }

  return 0;
}

int IpcPacketSocket::GetError() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return error_;
}

void IpcPacketSocket::SetError(int error) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  error_ = error;
}

void IpcPacketSocket::OnOpen(const net::IPEndPoint& local_address,
                             const net::IPEndPoint& remote_address) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!webrtc::IPEndPointToSocketAddress(local_address, &local_address_)) {
    // Always expect correct IPv4 address to be allocated.
    NOTREACHED();
  }

  state_ = kIsOpen;
  TraceSendThrottlingState();

  // Set all pending options if any.
  for (int i = 0; i < network::P2P_SOCKET_OPT_MAX; ++i) {
    if (options_[i] != kDefaultNonSetOptionValue)
      DoSetOption(static_cast<network::P2PSocketOption>(i), options_[i]);
  }

  SignalAddressReady(this, local_address_);
  if (IsTcpClientSocket(type_)) {
    // If remote address is unresolved, set resolved remote IP address received
    // in the callback. This address will be used while sending the packets
    // over the network.
    if (remote_address_.IsUnresolvedIP()) {
      rtc::SocketAddress jingle_socket_address;
      // |remote_address| could be unresolved if the connection is behind a
      // proxy.
      if (!remote_address.address().empty() &&
          webrtc::IPEndPointToSocketAddress(remote_address,
                                            &jingle_socket_address)) {
        // Set only the IP address.
        remote_address_.SetResolvedIP(jingle_socket_address.ipaddr());
      }
    }

    // SignalConnect after updating the |remote_address_| so that the listener
    // can get the resolved remote address.
    SignalConnect(this);
  }
}

void IpcPacketSocket::OnSendComplete(
    const network::P2PSendPacketMetrics& send_metrics) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  CHECK(!in_flight_packet_records_.empty());

  const InFlightPacketRecord& record = in_flight_packet_records_.front();

  // Tracking is not turned on for TCP so it's always 0. For UDP, this will
  // cause a crash when the packet ids don't match.
  CHECK(send_metrics.packet_id == 0 ||
        record.packet_id == send_metrics.packet_id);

  send_bytes_available_ = std::min(send_bytes_available_ + record.packet_size,
                                   max_in_flight_bytes_);

  in_flight_packet_records_.pop_front();
  TraceSendThrottlingState();

  SignalSentPacket(this, rtc::SentPacket(send_metrics.rtc_packet_id,
                                         send_metrics.send_time_ms));

  if (writable_signal_expected_ &&
      send_bytes_available_ > (max_in_flight_bytes_ / 2)) {
    blink::WebRtcLogMessage(base::StringPrintf(
        "IpcPacketSocket: sending is unblocked. %d packets in flight.",
        static_cast<int>(in_flight_packet_records_.size())));

    writable_signal_expected_ = false;
    SignalReadyToSend(this);
  }
}

void IpcPacketSocket::OnError() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  bool was_closed = (state_ == kIsError || state_ == kIsClosed);
  state_ = kIsError;
  error_ = ECONNABORTED;
  if (!was_closed) {
    SignalClose(this, 0);
  }
}

void IpcPacketSocket::OnDataReceived(const net::IPEndPoint& address,
                                     base::span<const uint8_t> data,
                                     const base::TimeTicks& timestamp,
                                     rtc::EcnMarking ecn) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  rtc::SocketAddress address_lj;

  if (address.address().empty()) {
    DCHECK(IsTcpClientSocket(type_));
    // |address| could be empty for TCP connections behind a proxy.
    address_lj = remote_address_;
  } else {
    if (!webrtc::IPEndPointToSocketAddress(address, &address_lj)) {
      // We should always be able to convert address here because we
      // don't expect IPv6 address on IPv4 connections.
      NOTREACHED();
    }
  }
  NotifyPacketReceived(rtc::ReceivedPacket(
      data, address_lj,
      webrtc::Timestamp::Micros(timestamp.since_origin().InMicroseconds()),
      ecn));
}

AsyncDnsAddressResolverImpl::AsyncDnsAddressResolverImpl(
    P2PSocketDispatcher* dispatcher)
    : resolver_(base::MakeRefCounted<P2PAsyncAddressResolver>(dispatcher)) {}

AsyncDnsAddressResolverImpl::~AsyncDnsAddressResolverImpl() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

void AsyncDnsAddressResolverImpl::Start(const rtc::SocketAddress& addr,
                                        absl::AnyInvocable<void()> callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!started_);
  started_ = true;
  // Port and hostname must be copied to the resolved address returned from
  // GetResolvedAddress.
  addr_ = addr;
  callback_ = std::move(callback);

  resolver_->Start(
      addr, /*address_family=*/std::nullopt,
      WTF::BindOnce(&AsyncDnsAddressResolverImpl::OnAddressResolved,
                    weak_factory_.GetWeakPtr()));
}

void AsyncDnsAddressResolverImpl::Start(const rtc::SocketAddress& addr,
                                        int address_family,
                                        absl::AnyInvocable<void()> callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!started_);
  started_ = true;
  // Port and hostname must be copied to the resolved address returned from
  // GetResolvedAddress.
  addr_ = addr;
  callback_ = std::move(callback);
  resolver_->Start(
      addr, std::make_optional(address_family),
      WTF::BindOnce(&AsyncDnsAddressResolverImpl::OnAddressResolved,
                    weak_factory_.GetWeakPtr()));
}

bool AsyncDnsAddressResolverImpl::GetResolvedAddress(
    int family,
    rtc::SocketAddress* addr) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  for (auto& address : addresses_) {
    if (family == address.family()) {
      *addr = addr_;
      addr->SetResolvedIP(address);
      return true;
    }
  }
  return false;
}

int AsyncDnsAddressResolverImpl::GetError() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return addresses_.empty() ? -1 : 0;
}

void AsyncDnsAddressResolverImpl::OnAddressResolved(
    const Vector<net::IPAddress>& addresses) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  for (wtf_size_t i = 0; i < addresses.size(); ++i) {
    rtc::SocketAddress socket_address;
    if (!webrtc::IPEndPointToSocketAddress(net::IPEndPoint(addresses[i], 0),
                                           &socket_address)) {
      NOTREACHED();
    }
    addresses_.push_back(socket_address.ipaddr());
  }
  callback_();
}

}  // namespace

IpcPacketSocketFactory::IpcPacketSocketFactory(
    WTF::CrossThreadFunction<
        void(base::OnceCallback<void(std::optional<base::UnguessableToken>)>)>
        devtools_token_getter,
    P2PSocketDispatcher* socket_dispatcher,
    const net::NetworkTrafficAnnotationTag& traffic_annotation,
    bool batch_udp_packets)
    : devtools_token_getter_(std::move(devtools_token_getter)),
      batch_udp_packets_(batch_udp_packets),
      socket_dispatcher_(socket_dispatcher),
      traffic_annotation_(traffic_annotation) {}

IpcPacketSocketFactory::~IpcPacketSocketFactory() {}

rtc::AsyncPacketSocket* IpcPacketSocketFactory::CreateUdpSocket(
    const rtc::SocketAddress& local_address,
    uint16_t min_port,
    uint16_t max_port) {
  auto socket_dispatcher = socket_dispatcher_.Lock();
  DCHECK(socket_dispatcher);
  auto socket_client =
      std::make_unique<P2PSocketClientImpl>(batch_udp_packets_);
  std::unique_ptr<IpcPacketSocket> socket(new IpcPacketSocket());

  if (!socket->Init(socket_dispatcher, traffic_annotation_,
                    network::P2P_SOCKET_UDP, std::move(socket_client),
                    local_address, min_port, max_port, rtc::SocketAddress(),
                    devtools_token_getter_)) {
    return nullptr;
  }
  return socket.release();
}

rtc::AsyncListenSocket* IpcPacketSocketFactory::CreateServerTcpSocket(
    const rtc::SocketAddress& local_address,
    uint16_t min_port,
    uint16_t max_port,
    int opts) {
  NOTREACHED();
}

rtc::AsyncPacketSocket* IpcPacketSocketFactory::CreateClientTcpSocket(
    const rtc::SocketAddress& local_address,
    const rtc::SocketAddress& remote_address,
    const rtc::PacketSocketTcpOptions& opts) {
  if (!net::IsPortAllowedForScheme(remote_address.port(), "stun")) {
    // Attempt to create IPC TCP socket on blocked port
    return nullptr;
  }
  network::P2PSocketType type;
  if (opts.opts & rtc::PacketSocketFactory::OPT_SSLTCP) {
    type = (opts.opts & rtc::PacketSocketFactory::OPT_STUN)
               ? network::P2P_SOCKET_STUN_SSLTCP_CLIENT
               : network::P2P_SOCKET_SSLTCP_CLIENT;
  } else if (opts.opts & rtc::PacketSocketFactory::OPT_TLS) {
    type = (opts.opts & rtc::PacketSocketFactory::OPT_STUN)
               ? network::P2P_SOCKET_STUN_TLS_CLIENT
               : network::P2P_SOCKET_TLS_CLIENT;
  } else {
    type = (opts.opts & rtc::PacketSocketFactory::OPT_STUN)
               ? network::P2P_SOCKET_STUN_TCP_CLIENT
               : network::P2P_SOCKET_TCP_CLIENT;
  }
  auto socket_dispatcher = socket_dispatcher_.Lock();
  DCHECK(socket_dispatcher);
  auto socket_client =
      std::make_unique<P2PSocketClientImpl>(/*batch_packets=*/false);
  std::unique_ptr<IpcPacketSocket> socket(new IpcPacketSocket());
  if (!socket->Init(socket_dispatcher, traffic_annotation_, type,
                    std::move(socket_client), local_address, 0, 0,
                    remote_address, devtools_token_getter_)) {
    return nullptr;
  }
  return socket.release();
}

std::unique_ptr<webrtc::AsyncDnsResolverInterface>
IpcPacketSocketFactory::CreateAsyncDnsResolver() {
  auto socket_dispatcher = socket_dispatcher_.Lock();
  DCHECK(socket_dispatcher);
  return absl::make_unique<AsyncDnsAddressResolverImpl>(socket_dispatcher);
}

}  // namespace blink
```