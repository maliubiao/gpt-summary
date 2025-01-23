Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

**1. Understanding the Goal:**

The core request is to understand the functionality of `EventLoopConnectingClientSocket.cc`, its relation to JavaScript (if any), and to identify potential issues and usage patterns. The request also asks for examples of logic, errors, and a debug scenario.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly read through the code, looking for keywords and patterns that reveal the class's purpose. Key observations include:

* **`EventLoopConnectingClientSocket`:** The name strongly suggests it's a client-side socket that interacts with an event loop, and it handles the connection process.
* **`#include` directives:**  These reveal dependencies on networking concepts (`socket.h`, `quic_socket_address.h`), event loops (`quic_event_loop.h`), and memory management (`quiche_mem_slice.h`). The `quiche` namespace suggests this is part of the QUIC protocol implementation.
* **Member variables:**  These provide clues about the class's state and responsibilities: `protocol_`, `peer_address_`, buffer sizes, `event_loop_`, `async_visitor_`, `descriptor_` (file descriptor), `connect_status_`, and variables related to sending and receiving (`receive_max_size_`, `send_data_`, `send_remaining_`).
* **Methods:**  The public methods (`ConnectBlocking`, `ConnectAsync`, `Disconnect`, `ReceiveBlocking`, `ReceiveAsync`, `SendBlocking`, `SendAsync`) clearly define the core operations of a socket. The private methods (`Open`, `Close`, `DoInitialConnect`, `GetConnectResult`, `ReceiveInternal`, `SendInternal`, `OneBytePeek`) indicate the internal workings.
* **`async_visitor_`:** This suggests an asynchronous design pattern where callbacks are used for events.
* **Error handling:**  The code uses `absl::Status` and `absl::StatusOr` for error management.
* **Assertions (`QUICHE_DCHECK`) and logging (`QUICHE_LOG`)**: These are used for internal consistency checks and debugging.

**3. Dissecting Key Functionalities:**

After the initial scan, the next step is to examine the core methods in more detail:

* **Connection:**  `ConnectBlocking` and `ConnectAsync` clearly handle establishing a connection. The blocking version uses synchronous calls, while the asynchronous version relies on the event loop. `DoInitialConnect` performs the underlying socket `connect()` call.
* **Disconnection:** `Disconnect` handles closing the socket and cleaning up resources. It also manages callbacks for pending operations.
* **Sending and Receiving:** `ReceiveBlocking`, `ReceiveAsync`, `SendBlocking`, and `SendAsync` implement the core data transfer operations. The "Blocking" versions use synchronous socket calls, while the "Async" versions integrate with the event loop. `ReceiveInternal` and `SendInternal` handle the low-level socket I/O.
* **Event Handling:** `OnSocketEvent` is the crucial method that links the socket to the event loop. It's triggered when the event loop detects activity on the socket's file descriptor.
* **Asynchronous Operations:** The interaction with `async_visitor_` is vital. The `FinishOrRearmAsync...` methods manage the callbacks and potentially re-arm the socket in the event loop for further notifications.

**4. Identifying the Role of the Event Loop:**

The presence of `QuicEventLoop` is central. The code registers the socket with the event loop and reacts to events signaled by the loop. This is a classic non-blocking I/O pattern.

**5. Considering the JavaScript Connection (or Lack Thereof):**

The code is C++ and directly interacts with operating system socket APIs. While JavaScript in a browser or Node.js environment interacts with networking, it does so through higher-level APIs. The connection is *indirect*. Chromium's network stack, including this code, provides the underlying implementation for networking features used by the browser's JavaScript engine. Therefore, actions in JavaScript like `fetch()` or `WebSocket` eventually rely on code like this at a lower level.

**6. Constructing Examples and Scenarios:**

Based on the understanding of the code, I started formulating the examples:

* **Logic Reasoning:**  Focus on the asynchronous connect flow, demonstrating how `DoInitialConnect` and `GetConnectResult` are used, and the role of `OnSocketEvent`.
* **User Errors:** Think about common mistakes when using sockets: not disconnecting properly, using blocking calls in an asynchronous context, or providing incorrect buffer sizes.
* **Debugging Scenario:**  Trace the path of an asynchronous `connect()` call, highlighting the role of the event loop and the callbacks.

**7. Refining the Explanation:**

The initial analysis might be somewhat technical. The next step is to explain the functionality in a clear and concise manner, focusing on the "what" and "why" rather than just the "how."

**8. Review and Iteration:**

Finally, I would review the generated response to ensure accuracy, clarity, and completeness. Are the explanations easy to understand? Are the examples relevant?  Does it address all parts of the original request?  This might involve rephrasing sentences, adding more detail in certain areas, or simplifying complex concepts. For instance, initially, I might focus too much on the low-level socket API calls, but then realize I need to emphasize the higher-level purpose of the class.

This iterative process of reading, analyzing, understanding, and explaining allows for a comprehensive and accurate response to the initial request. The focus is on understanding the code's purpose, its design patterns (like asynchronous I/O), and how it fits within a larger system like Chromium.
这个文件 `event_loop_connecting_client_socket.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，它定义了一个名为 `EventLoopConnectingClientSocket` 的类。这个类的主要功能是 **在事件循环中异步地建立客户端连接，并提供同步和异步的发送和接收数据的功能。**

以下是其功能的详细列表：

**主要功能:**

1. **异步连接管理:**
   -  它允许客户端以非阻塞的方式发起连接到远程服务器。连接过程与事件循环集成，当连接建立或失败时，会通过回调通知调用者。
   -  提供了 `ConnectAsync()` 方法用于发起异步连接。
   -  使用 `connect_status_` 成员变量跟踪连接状态（未连接、连接中、已连接）。
   -  依赖于 `QuicEventLoop` 来监听套接字事件（可读、可写、错误）。

2. **同步连接管理:**
   -  也提供了 `ConnectBlocking()` 方法用于同步地建立连接，会阻塞当前线程直到连接建立或失败。

3. **数据发送 (同步和异步):**
   -  提供了 `SendBlocking()` 和 `SendAsync()` 方法用于发送数据。
   -  `SendBlocking()` 会阻塞直到数据完全发送或发生错误。
   -  `SendAsync()` 会将数据发送操作添加到事件循环，并在数据发送完成后通过回调通知调用者。
   -  支持发送 `std::string` 和 `quiche::QuicheMemSlice` 类型的数据。

4. **数据接收 (同步和异步):**
   -  提供了 `ReceiveBlocking()` 和 `ReceiveAsync()` 方法用于接收数据。
   -  `ReceiveBlocking()` 会阻塞直到接收到指定大小的数据或发生错误。
   -  `ReceiveAsync()` 会在套接字可读时通过回调通知调用者接收数据。
   -  接收的数据以 `quiche::QuicheMemSlice` 的形式返回。

5. **断开连接:**
   -  提供了 `Disconnect()` 方法用于关闭套接字并清理相关资源。
   -  在异步操作进行中调用 `Disconnect()` 会取消这些操作并通知调用者。

6. **获取本地地址:**
   -  提供了 `GetLocalAddress()` 方法用于获取套接字绑定的本地地址。

7. **事件处理:**
   -  实现了 `OnSocketEvent()` 方法，当关联的 `QuicEventLoop` 检测到套接字事件时会被调用。这个方法根据不同的事件类型和当前状态，执行连接完成、接收或发送完成的回调。

8. **套接字管理:**
   -  使用底层的 `socket_api` 来创建、打开、关闭和设置套接字属性（如阻塞模式、缓冲区大小）。

**与 JavaScript 的关系：**

这个 C++ 代码本身不直接与 JavaScript 交互。 然而，作为 Chromium 网络栈的一部分，它为浏览器中 JavaScript 发起的网络请求提供了底层的实现。

**举例说明：**

当 JavaScript 代码使用 `fetch()` API 或 `WebSocket` API 发起一个连接到服务器的请求时，Chromium 浏览器会使用其网络栈来处理这个请求。 `EventLoopConnectingClientSocket` 类就可能被用来建立底层的 TCP 或 UDP 连接（基于 QUIC 协议）来支持这些 JavaScript API。

例如，以下 JavaScript 代码：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

在这个过程中，Chromium 的网络栈可能会创建一个 `EventLoopConnectingClientSocket` 实例来建立与 `example.com` 服务器的连接，并使用其提供的发送和接收功能来传输 HTTP 请求和响应数据。 JavaScript 的 `fetch()` API 并不直接操作 `EventLoopConnectingClientSocket`，而是通过 Chromium 提供的更高级别的接口进行交互，这些接口在底层会使用到像 `EventLoopConnectingClientSocket` 这样的类。

**逻辑推理示例 (假设输入与输出):**

**假设输入:**

- 调用 `ConnectAsync()` 方法，目标地址为 `192.168.1.100:443`。
- 事件循环检测到套接字变为可写状态。

**逻辑推理过程:**

1. `ConnectAsync()` 调用 `Open()` 创建一个非阻塞套接字。
2. `DoInitialConnect()` 尝试连接，由于是非阻塞套接字，通常会立即返回 `absl::UnavailableError` 表示连接正在进行中，并将连接状态设置为 `kConnecting`。
3. 套接字被注册到 `QuicEventLoop`，监听可写事件。
4. 当网络条件允许连接建立时，操作系统会通知事件循环，套接字变为可写状态。
5. `QuicEventLoop` 调用 `EventLoopConnectingClientSocket` 的 `OnSocketEvent()` 方法，并传递 `kSocketEventWritable` 事件。
6. `OnSocketEvent()` 检测到 `connect_status_` 为 `kConnecting` 并且事件包含 `kSocketEventWritable`。
7. 它调用 `GetConnectResult()` 来获取连接结果。
8. `GetConnectResult()` 调用 `socket_api::GetSocketError()` 检查是否有错误。如果没有错误，并且通过 `OneBytePeek()` 确认连接存活，则将 `connect_status_` 设置为 `kConnected`。
9. 最后，`FinishOrRearmAsyncConnect()` 被调用，如果连接成功，它会调用 `async_visitor_->ConnectComplete(absl::OkStatus())` 通知调用者连接已建立。

**假设输出:**

- `async_visitor_->ConnectComplete()` 被调用，参数为 `absl::OkStatus()`，表示连接成功。

**用户或编程常见的使用错误:**

1. **未调用 `Disconnect()` 就销毁对象:**  如果在连接建立后（`connect_status_` 为 `kConnecting` 或 `kConnected`），没有先调用 `Disconnect()` 就销毁 `EventLoopConnectingClientSocket` 对象，会导致断言失败并可能引发程序崩溃。 这是因为对象析构时需要确保套接字已经正确关闭，并且没有未完成的异步回调。

   ```c++
   // 错误示例
   {
       EventLoopConnectingClientSocket socket(...);
       socket.ConnectAsync();
       // ... 假设异步连接尚未完成 ...
   } // socket 对象在这里被销毁，但连接可能还在进行中
   ```

2. **在异步操作完成前尝试同步操作:**  在调用 `ConnectAsync()` 后，如果在连接完成的回调之前尝试调用 `ReceiveBlocking()` 或 `SendBlocking()`，可能会导致状态不一致或其他未定义的行为。

3. **忘记处理异步操作的回调:**  使用异步方法 (`ConnectAsync()`, `ReceiveAsync()`, `SendAsync()`) 时，必须提供有效的 `AsyncVisitor` 来处理操作完成后的回调。如果 `async_visitor_` 为空指针，会导致程序崩溃。

4. **在错误的时间调用同步/异步方法:** 例如，在 `connect_status_` 为 `kConnecting` 时调用 `ReceiveBlocking()` 或 `SendBlocking()` 可能不安全。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在浏览器中访问一个使用 HTTPS 的网站：

1. **用户在浏览器地址栏输入 URL (例如 `https://example.com`) 并按下回车键。**
2. **浏览器开始解析 URL，识别出需要建立 HTTPS 连接。**
3. **浏览器查找或建立与目标服务器的 TCP 连接。如果启用了 QUIC，浏览器可能会尝试建立 QUIC 连接。**
4. **Chromium 的网络栈开始工作，涉及到多个组件，包括 QUIC 的实现。**
5. **如果决定使用 QUIC，可能会创建一个 `EventLoopConnectingClientSocket` 实例。**
   -  这个实例会初始化目标服务器的地址和端口。
   -  一个实现了 `AsyncVisitor` 接口的对象会被传递给 `EventLoopConnectingClientSocket`，用于接收连接、发送和接收完成的通知。
6. **调用 `ConnectAsync()` 方法发起异步连接。**
7. **底层的套接字 API (例如 `connect()`) 被调用，通常会立即返回，因为是非阻塞模式。**
8. **套接字的文件描述符被注册到 `QuicEventLoop` 中，监听可写事件（表示连接尝试完成）。**
9. **`QuicEventLoop` 监视所有注册的套接字的文件描述符。**
10. **当操作系统通知连接尝试完成（成功或失败）时，`QuicEventLoop` 会检测到套接字变为可写或发生错误。**
11. **`QuicEventLoop` 调用 `EventLoopConnectingClientSocket` 的 `OnSocketEvent()` 方法。**
12. **在 `OnSocketEvent()` 中，根据事件类型，会调用 `GetConnectResult()` 来检查连接结果，并最终通过 `async_visitor_` 通知上层组件连接状态。**

**调试线索:**

- **检查 `QuicEventLoop` 的状态:** 查看事件循环中是否注册了与该 `EventLoopConnectingClientSocket` 相关的套接字。
- **断点设置在 `OnSocketEvent()`:** 观察当套接字事件发生时，程序是否进入了这个方法，以及事件的类型。
- **检查 `connect_status_` 的变化:** 跟踪连接状态的变化，从 `kNotConnected` 到 `kConnecting` 再到 `kConnected` 或回到 `kNotConnected` (如果连接失败)。
- **查看 `async_visitor_` 的回调函数是否被调用:**  确认连接成功或失败的回调是否被触发，以及传递的参数。
- **使用网络抓包工具 (如 Wireshark):**  捕获网络数据包，验证是否成功发送了 SYN 包，以及是否收到了 SYN-ACK 包 (对于 TCP)，或者 QUIC 的握手包。
- **查看日志输出:**  QUIC 相关的日志可能会提供关于连接过程的更详细信息。

理解 `EventLoopConnectingClientSocket` 的功能和其在异步网络操作中的作用，有助于调试 Chromium 网络栈中 QUIC 相关的连接问题。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/io/event_loop_connecting_client_socket.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/io/event_loop_connecting_client_socket.h"

#include <limits>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "absl/types/variant.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"

namespace quic {

EventLoopConnectingClientSocket::EventLoopConnectingClientSocket(
    socket_api::SocketProtocol protocol,
    const quic::QuicSocketAddress& peer_address,
    QuicByteCount receive_buffer_size, QuicByteCount send_buffer_size,
    QuicEventLoop* event_loop, quiche::QuicheBufferAllocator* buffer_allocator,
    AsyncVisitor* async_visitor)
    : protocol_(protocol),
      peer_address_(peer_address),
      receive_buffer_size_(receive_buffer_size),
      send_buffer_size_(send_buffer_size),
      event_loop_(event_loop),
      buffer_allocator_(buffer_allocator),
      async_visitor_(async_visitor) {
  QUICHE_DCHECK(event_loop_);
  QUICHE_DCHECK(buffer_allocator_);
}

EventLoopConnectingClientSocket::~EventLoopConnectingClientSocket() {
  // Connected socket must be closed via Disconnect() before destruction. Cannot
  // safely recover if state indicates caller may be expecting async callbacks.
  QUICHE_DCHECK(connect_status_ != ConnectStatus::kConnecting);
  QUICHE_DCHECK(!receive_max_size_.has_value());
  QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));
  if (descriptor_ != kInvalidSocketFd) {
    QUICHE_BUG(quic_event_loop_connecting_socket_invalid_destruction)
        << "Must call Disconnect() on connected socket before destruction.";
    Close();
  }

  QUICHE_DCHECK(connect_status_ == ConnectStatus::kNotConnected);
  QUICHE_DCHECK(send_remaining_.empty());
}

absl::Status EventLoopConnectingClientSocket::ConnectBlocking() {
  QUICHE_DCHECK_EQ(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kNotConnected);
  QUICHE_DCHECK(!receive_max_size_.has_value());
  QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));

  absl::Status status = Open();
  if (!status.ok()) {
    return status;
  }

  status = socket_api::SetSocketBlocking(descriptor_, /*blocking=*/true);
  if (!status.ok()) {
    QUICHE_LOG_FIRST_N(WARNING, 100)
        << "Failed to set socket to address: " << peer_address_.ToString()
        << " as blocking for connect with error: " << status;
    Close();
    return status;
  }

  status = DoInitialConnect();

  if (absl::IsUnavailable(status)) {
    QUICHE_LOG_FIRST_N(ERROR, 100)
        << "Non-blocking connect to should-be blocking socket to address:"
        << peer_address_.ToString() << ".";
    Close();
    connect_status_ = ConnectStatus::kNotConnected;
    return status;
  } else if (!status.ok()) {
    // DoInitialConnect() closes the socket on failures.
    QUICHE_DCHECK_EQ(descriptor_, kInvalidSocketFd);
    QUICHE_DCHECK(connect_status_ == ConnectStatus::kNotConnected);
    return status;
  }

  status = socket_api::SetSocketBlocking(descriptor_, /*blocking=*/false);
  if (!status.ok()) {
    QUICHE_LOG_FIRST_N(WARNING, 100)
        << "Failed to return socket to address: " << peer_address_.ToString()
        << " to non-blocking after connect with error: " << status;
    Close();
    connect_status_ = ConnectStatus::kNotConnected;
  }

  QUICHE_DCHECK(connect_status_ != ConnectStatus::kConnecting);
  return status;
}

void EventLoopConnectingClientSocket::ConnectAsync() {
  QUICHE_DCHECK(async_visitor_);
  QUICHE_DCHECK_EQ(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kNotConnected);
  QUICHE_DCHECK(!receive_max_size_.has_value());
  QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));

  absl::Status status = Open();
  if (!status.ok()) {
    async_visitor_->ConnectComplete(status);
    return;
  }

  FinishOrRearmAsyncConnect(DoInitialConnect());
}

void EventLoopConnectingClientSocket::Disconnect() {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ != ConnectStatus::kNotConnected);

  Close();
  QUICHE_DCHECK_EQ(descriptor_, kInvalidSocketFd);

  // Reset all state before invoking any callbacks.
  bool require_connect_callback = connect_status_ == ConnectStatus::kConnecting;
  connect_status_ = ConnectStatus::kNotConnected;
  bool require_receive_callback = receive_max_size_.has_value();
  receive_max_size_.reset();
  bool require_send_callback =
      !absl::holds_alternative<absl::monostate>(send_data_);
  send_data_ = absl::monostate();
  send_remaining_ = "";

  if (require_connect_callback) {
    QUICHE_DCHECK(async_visitor_);
    async_visitor_->ConnectComplete(absl::CancelledError());
  }
  if (require_receive_callback) {
    QUICHE_DCHECK(async_visitor_);
    async_visitor_->ReceiveComplete(absl::CancelledError());
  }
  if (require_send_callback) {
    QUICHE_DCHECK(async_visitor_);
    async_visitor_->SendComplete(absl::CancelledError());
  }
}

absl::StatusOr<QuicSocketAddress>
EventLoopConnectingClientSocket::GetLocalAddress() {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kConnected);

  return socket_api::GetSocketAddress(descriptor_);
}

absl::StatusOr<quiche::QuicheMemSlice>
EventLoopConnectingClientSocket::ReceiveBlocking(QuicByteCount max_size) {
  QUICHE_DCHECK_GT(max_size, 0u);
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kConnected);
  QUICHE_DCHECK(!receive_max_size_.has_value());

  absl::Status status =
      socket_api::SetSocketBlocking(descriptor_, /*blocking=*/true);
  if (!status.ok()) {
    QUICHE_LOG_FIRST_N(WARNING, 100)
        << "Failed to set socket to address: " << peer_address_.ToString()
        << " as blocking for receive with error: " << status;
    return status;
  }

  receive_max_size_ = max_size;
  absl::StatusOr<quiche::QuicheMemSlice> buffer = ReceiveInternal();

  if (!buffer.ok() && absl::IsUnavailable(buffer.status())) {
    QUICHE_LOG_FIRST_N(ERROR, 100)
        << "Non-blocking receive from should-be blocking socket to address:"
        << peer_address_.ToString() << ".";
    receive_max_size_.reset();
  } else {
    QUICHE_DCHECK(!receive_max_size_.has_value());
  }

  absl::Status set_non_blocking_status =
      socket_api::SetSocketBlocking(descriptor_, /*blocking=*/false);
  if (!set_non_blocking_status.ok()) {
    QUICHE_LOG_FIRST_N(WARNING, 100)
        << "Failed to return socket to address: " << peer_address_.ToString()
        << " to non-blocking after receive with error: "
        << set_non_blocking_status;
    return set_non_blocking_status;
  }

  return buffer;
}

void EventLoopConnectingClientSocket::ReceiveAsync(QuicByteCount max_size) {
  QUICHE_DCHECK(async_visitor_);
  QUICHE_DCHECK_GT(max_size, 0u);
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kConnected);
  QUICHE_DCHECK(!receive_max_size_.has_value());

  receive_max_size_ = max_size;

  FinishOrRearmAsyncReceive(ReceiveInternal());
}

absl::Status EventLoopConnectingClientSocket::SendBlocking(std::string data) {
  QUICHE_DCHECK(!data.empty());
  QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));

  send_data_ = std::move(data);
  return SendBlockingInternal();
}

absl::Status EventLoopConnectingClientSocket::SendBlocking(
    quiche::QuicheMemSlice data) {
  QUICHE_DCHECK(!data.empty());
  QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));

  send_data_ = std::move(data);
  return SendBlockingInternal();
}

void EventLoopConnectingClientSocket::SendAsync(std::string data) {
  QUICHE_DCHECK(!data.empty());
  QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));

  send_data_ = std::move(data);
  send_remaining_ = absl::get<std::string>(send_data_);

  FinishOrRearmAsyncSend(SendInternal());
}

void EventLoopConnectingClientSocket::SendAsync(quiche::QuicheMemSlice data) {
  QUICHE_DCHECK(!data.empty());
  QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));

  send_data_ = std::move(data);
  send_remaining_ =
      absl::get<quiche::QuicheMemSlice>(send_data_).AsStringView();

  FinishOrRearmAsyncSend(SendInternal());
}

void EventLoopConnectingClientSocket::OnSocketEvent(
    QuicEventLoop* event_loop, SocketFd fd, QuicSocketEventMask events) {
  QUICHE_DCHECK_EQ(event_loop, event_loop_);
  QUICHE_DCHECK_EQ(fd, descriptor_);

  if (connect_status_ == ConnectStatus::kConnecting &&
      (events & (kSocketEventWritable | kSocketEventError))) {
    FinishOrRearmAsyncConnect(GetConnectResult());
    return;
  }

  if (receive_max_size_.has_value() &&
      (events & (kSocketEventReadable | kSocketEventError))) {
    FinishOrRearmAsyncReceive(ReceiveInternal());
  }
  if (!send_remaining_.empty() &&
      (events & (kSocketEventWritable | kSocketEventError))) {
    FinishOrRearmAsyncSend(SendInternal());
  }
}

absl::Status EventLoopConnectingClientSocket::Open() {
  QUICHE_DCHECK_EQ(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kNotConnected);
  QUICHE_DCHECK(!receive_max_size_.has_value());
  QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));
  QUICHE_DCHECK(send_remaining_.empty());

  absl::StatusOr<SocketFd> descriptor =
      socket_api::CreateSocket(peer_address_.host().address_family(), protocol_,
                               /*blocking=*/false);
  if (!descriptor.ok()) {
    QUICHE_DVLOG(1) << "Failed to open socket for connection to address: "
                    << peer_address_.ToString()
                    << " with error: " << descriptor.status();
    return descriptor.status();
  }
  QUICHE_DCHECK_NE(*descriptor, kInvalidSocketFd);

  descriptor_ = *descriptor;

  if (async_visitor_) {
    bool registered;
    if (event_loop_->SupportsEdgeTriggered()) {
      registered = event_loop_->RegisterSocket(
          descriptor_,
          kSocketEventReadable | kSocketEventWritable | kSocketEventError,
          this);
    } else {
      // Just register the socket without any armed events for now.  Will rearm
      // with specific events as needed.  Registering now before events are
      // needed makes it easier to ensure the socket is registered only once
      // and can always be unregistered on socket close.
      registered = event_loop_->RegisterSocket(descriptor_, /*events=*/0, this);
    }
    QUICHE_DCHECK(registered);
  }

  if (receive_buffer_size_ != 0) {
    absl::Status status =
        socket_api::SetReceiveBufferSize(descriptor_, receive_buffer_size_);
    if (!status.ok()) {
      QUICHE_LOG_FIRST_N(WARNING, 100)
          << "Failed to set receive buffer size to: " << receive_buffer_size_
          << " for socket to address: " << peer_address_.ToString()
          << " with error: " << status;
      Close();
      return status;
    }
  }

  if (send_buffer_size_ != 0) {
    absl::Status status =
        socket_api::SetSendBufferSize(descriptor_, send_buffer_size_);
    if (!status.ok()) {
      QUICHE_LOG_FIRST_N(WARNING, 100)
          << "Failed to set send buffer size to: " << send_buffer_size_
          << " for socket to address: " << peer_address_.ToString()
          << " with error: " << status;
      Close();
      return status;
    }
  }

  return absl::OkStatus();
}

void EventLoopConnectingClientSocket::Close() {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);

  bool unregistered = event_loop_->UnregisterSocket(descriptor_);
  QUICHE_DCHECK_EQ(unregistered, !!async_visitor_);

  absl::Status status = socket_api::Close(descriptor_);
  if (!status.ok()) {
    QUICHE_LOG_FIRST_N(WARNING, 100)
        << "Could not close socket to address: " << peer_address_.ToString()
        << " with error: " << status;
  }

  descriptor_ = kInvalidSocketFd;
}

absl::Status EventLoopConnectingClientSocket::DoInitialConnect() {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kNotConnected);
  QUICHE_DCHECK(!receive_max_size_.has_value());
  QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));

  absl::Status connect_result = socket_api::Connect(descriptor_, peer_address_);

  if (connect_result.ok()) {
    connect_status_ = ConnectStatus::kConnected;
  } else if (absl::IsUnavailable(connect_result)) {
    connect_status_ = ConnectStatus::kConnecting;
  } else {
    QUICHE_DVLOG(1) << "Synchronously failed to connect socket to address: "
                    << peer_address_.ToString()
                    << " with error: " << connect_result;
    Close();
    connect_status_ = ConnectStatus::kNotConnected;
  }

  return connect_result;
}

absl::Status EventLoopConnectingClientSocket::GetConnectResult() {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kConnecting);
  QUICHE_DCHECK(!receive_max_size_.has_value());
  QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));

  absl::Status error = socket_api::GetSocketError(descriptor_);

  if (!error.ok()) {
    QUICHE_DVLOG(1) << "Asynchronously failed to connect socket to address: "
                    << peer_address_.ToString() << " with error: " << error;
    Close();
    connect_status_ = ConnectStatus::kNotConnected;
    return error;
  }

  // Peek at one byte to confirm the connection is actually alive. Motivation:
  // 1) Plausibly could have a lot of cases where the connection operation
  //    itself technically succeeds but the socket then quickly fails.  Don't
  //    want to claim connection success here if, by the time this code is
  //    running after event triggers and such, the socket has already failed.
  //    Lot of undefined room around whether or not such errors would be saved
  //    into SO_ERROR and returned by socket_api::GetSocketError().
  // 2) With the various platforms and event systems involved, less than 100%
  //    trust that it's impossible to end up in this method before the async
  //    connect has completed/errored. Given that Connect() and GetSocketError()
  //    does not difinitevely differentiate between success and
  //    still-in-progress, and given that there's a very simple and performant
  //    way to positively confirm the socket is connected (peek), do that here.
  //    (Could consider making the not-connected case a QUIC_BUG if a way is
  //    found to differentiate it from (1).)
  absl::StatusOr<bool> peek_data = OneBytePeek();
  if (peek_data.ok() || absl::IsUnavailable(peek_data.status())) {
    connect_status_ = ConnectStatus::kConnected;
  } else {
    error = peek_data.status();
    QUICHE_LOG_FIRST_N(WARNING, 100)
        << "Socket to address: " << peer_address_.ToString()
        << " signalled writable after connect and no connect error found, "
           "but socket does not appear connected with error: "
        << error;
    Close();
    connect_status_ = ConnectStatus::kNotConnected;
  }

  return error;
}

void EventLoopConnectingClientSocket::FinishOrRearmAsyncConnect(
    absl::Status status) {
  if (absl::IsUnavailable(status)) {
    if (!event_loop_->SupportsEdgeTriggered()) {
      bool result = event_loop_->RearmSocket(
          descriptor_, kSocketEventWritable | kSocketEventError);
      QUICHE_DCHECK(result);
    }
    QUICHE_DCHECK(connect_status_ == ConnectStatus::kConnecting);
  } else {
    QUICHE_DCHECK(connect_status_ != ConnectStatus::kConnecting);
    async_visitor_->ConnectComplete(status);
  }
}

absl::StatusOr<quiche::QuicheMemSlice>
EventLoopConnectingClientSocket::ReceiveInternal() {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kConnected);
  QUICHE_CHECK(receive_max_size_.has_value());
  QUICHE_DCHECK_GE(*receive_max_size_, 1u);
  QUICHE_DCHECK_LE(*receive_max_size_, std::numeric_limits<size_t>::max());

  // Before allocating a buffer, do a 1-byte peek to determine if needed.
  if (*receive_max_size_ > 1) {
    absl::StatusOr<bool> peek_data = OneBytePeek();
    if (!peek_data.ok()) {
      if (!absl::IsUnavailable(peek_data.status())) {
        receive_max_size_.reset();
      }
      return peek_data.status();
    } else if (!*peek_data) {
      receive_max_size_.reset();
      return quiche::QuicheMemSlice();
    }
  }

  quiche::QuicheBuffer buffer(buffer_allocator_, *receive_max_size_);
  absl::StatusOr<absl::Span<char>> received = socket_api::Receive(
      descriptor_, absl::MakeSpan(buffer.data(), buffer.size()));

  if (received.ok()) {
    QUICHE_DCHECK_LE(received->size(), buffer.size());
    QUICHE_DCHECK_EQ(received->data(), buffer.data());

    receive_max_size_.reset();
    return quiche::QuicheMemSlice(
        quiche::QuicheBuffer(buffer.Release(), received->size()));
  } else {
    if (!absl::IsUnavailable(received.status())) {
      QUICHE_DVLOG(1) << "Failed to receive from socket to address: "
                      << peer_address_.ToString()
                      << " with error: " << received.status();
      receive_max_size_.reset();
    }
    return received.status();
  }
}

void EventLoopConnectingClientSocket::FinishOrRearmAsyncReceive(
    absl::StatusOr<quiche::QuicheMemSlice> buffer) {
  QUICHE_DCHECK(async_visitor_);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kConnected);

  if (!buffer.ok() && absl::IsUnavailable(buffer.status())) {
    if (!event_loop_->SupportsEdgeTriggered()) {
      bool result = event_loop_->RearmSocket(
          descriptor_, kSocketEventReadable | kSocketEventError);
      QUICHE_DCHECK(result);
    }
    QUICHE_DCHECK(receive_max_size_.has_value());
  } else {
    QUICHE_DCHECK(!receive_max_size_.has_value());
    async_visitor_->ReceiveComplete(std::move(buffer));
  }
}

absl::StatusOr<bool> EventLoopConnectingClientSocket::OneBytePeek() {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);

  char peek_buffer;
  absl::StatusOr<absl::Span<char>> peek_received = socket_api::Receive(
      descriptor_, absl::MakeSpan(&peek_buffer, /*size=*/1), /*peek=*/true);
  if (!peek_received.ok()) {
    return peek_received.status();
  } else {
    return !peek_received->empty();
  }
}

absl::Status EventLoopConnectingClientSocket::SendBlockingInternal() {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kConnected);
  QUICHE_DCHECK(!absl::holds_alternative<absl::monostate>(send_data_));
  QUICHE_DCHECK(send_remaining_.empty());

  absl::Status status =
      socket_api::SetSocketBlocking(descriptor_, /*blocking=*/true);
  if (!status.ok()) {
    QUICHE_LOG_FIRST_N(WARNING, 100)
        << "Failed to set socket to address: " << peer_address_.ToString()
        << " as blocking for send with error: " << status;
    send_data_ = absl::monostate();
    return status;
  }

  if (absl::holds_alternative<std::string>(send_data_)) {
    send_remaining_ = absl::get<std::string>(send_data_);
  } else {
    send_remaining_ =
        absl::get<quiche::QuicheMemSlice>(send_data_).AsStringView();
  }

  status = SendInternal();
  if (absl::IsUnavailable(status)) {
    QUICHE_LOG_FIRST_N(ERROR, 100)
        << "Non-blocking send for should-be blocking socket to address:"
        << peer_address_.ToString();
    send_data_ = absl::monostate();
    send_remaining_ = "";
  } else {
    QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));
    QUICHE_DCHECK(send_remaining_.empty());
  }

  absl::Status set_non_blocking_status =
      socket_api::SetSocketBlocking(descriptor_, /*blocking=*/false);
  if (!set_non_blocking_status.ok()) {
    QUICHE_LOG_FIRST_N(WARNING, 100)
        << "Failed to return socket to address: " << peer_address_.ToString()
        << " to non-blocking after send with error: "
        << set_non_blocking_status;
    return set_non_blocking_status;
  }

  return status;
}

absl::Status EventLoopConnectingClientSocket::SendInternal() {
  QUICHE_DCHECK_NE(descriptor_, kInvalidSocketFd);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kConnected);
  QUICHE_DCHECK(!absl::holds_alternative<absl::monostate>(send_data_));
  QUICHE_DCHECK(!send_remaining_.empty());

  // Repeat send until all data sent, unavailable, or error.
  while (!send_remaining_.empty()) {
    absl::StatusOr<absl::string_view> remainder =
        socket_api::Send(descriptor_, send_remaining_);

    if (remainder.ok()) {
      QUICHE_DCHECK(remainder->empty() ||
                    (remainder->data() >= send_remaining_.data() &&
                     remainder->data() <
                         send_remaining_.data() + send_remaining_.size()));
      QUICHE_DCHECK(remainder->empty() ||
                    (remainder->data() + remainder->size() ==
                     send_remaining_.data() + send_remaining_.size()));
      send_remaining_ = *remainder;
    } else {
      if (!absl::IsUnavailable(remainder.status())) {
        QUICHE_DVLOG(1) << "Failed to send to socket to address: "
                        << peer_address_.ToString()
                        << " with error: " << remainder.status();
        send_data_ = absl::monostate();
        send_remaining_ = "";
      }
      return remainder.status();
    }
  }

  send_data_ = absl::monostate();
  return absl::OkStatus();
}

void EventLoopConnectingClientSocket::FinishOrRearmAsyncSend(
    absl::Status status) {
  QUICHE_DCHECK(async_visitor_);
  QUICHE_DCHECK(connect_status_ == ConnectStatus::kConnected);

  if (absl::IsUnavailable(status)) {
    if (!event_loop_->SupportsEdgeTriggered()) {
      bool result = event_loop_->RearmSocket(
          descriptor_, kSocketEventWritable | kSocketEventError);
      QUICHE_DCHECK(result);
    }
    QUICHE_DCHECK(!absl::holds_alternative<absl::monostate>(send_data_));
    QUICHE_DCHECK(!send_remaining_.empty());
  } else {
    QUICHE_DCHECK(absl::holds_alternative<absl::monostate>(send_data_));
    QUICHE_DCHECK(send_remaining_.empty());
    async_visitor_->SendComplete(status);
  }
}

}  // namespace quic
```