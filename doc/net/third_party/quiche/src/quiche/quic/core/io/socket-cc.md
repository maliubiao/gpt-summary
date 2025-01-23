Response:
Let's break down the thought process to answer the request about `net/third_party/quiche/src/quiche/quic/core/io/socket.cc`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C++ code snippet and explain its functionality, its relationship to JavaScript (if any), logical reasoning, potential user errors, and how a user might reach this code during debugging.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code and identify key elements. Keywords like `SocketFd`, `QuicSocketAddress`, `Accept`, `Bind`, `Connect`, `Listen`, `Send`, `Receive`, `setsockopt`, `getsockopt`, and system calls like `accept`, `bind`, `connect`, `listen`, `send`, `recv`, etc., immediately jump out. The inclusion of platform-specific includes (`socket_win.inc` and `socket_posix.inc`) indicates OS-level interaction.

**3. Determining Primary Functionality:**

Based on the keywords, the central purpose of this code is clearly to provide an abstraction layer over raw network socket operations. It's about managing and interacting with network connections using sockets. The `quic::socket_api` namespace further reinforces this.

**4. Analyzing Individual Functions:**

Next, I'd go through each function and understand its specific role:

* **`AcceptInternal`:**  Handles the low-level acceptance of a new connection.
* **`SetSockOptInt`:** A helper function for setting socket options.
* **`SetReceiveBufferSize` and `SetSendBufferSize`:**  Specific wrappers for setting receive and send buffer sizes using `SetSockOptInt`.
* **`Connect`:**  Initiates a connection to a remote address.
* **`GetSocketError`:** Retrieves the pending error status of a socket.
* **`Bind`:** Associates a socket with a local address and port.
* **`GetSocketAddress`:** Retrieves the local address and port bound to a socket.
* **`Listen`:**  Marks a socket as passive, ready to accept incoming connections.
* **`Accept`:** A higher-level accept function that handles both blocking and non-blocking scenarios, and potentially sets the non-blocking flag.
* **`Receive`:** Reads data from a socket. The `peek` option is important to note.
* **`Send`:** Sends data over a connected socket.
* **`SendTo`:** Sends data to a specific address, often used for connectionless protocols.

**5. Identifying Abstraction and Error Handling:**

The code uses `absl::StatusOr` and `absl::Status` for error handling, providing a more structured way to manage potential failures in socket operations. The `LastSocketOperationError` function (likely defined in the included files) is used to retrieve system-level error information. This indicates an attempt to provide more informative error messages.

**6. Considering the Relationship with JavaScript:**

This is a crucial part of the request. Since this is C++ code within Chromium's network stack, it doesn't directly interact with JavaScript at the source code level. However, the *services* this code provides are *essential* for web browsing and, therefore, indirectly related to JavaScript.

* **Direct Relationship (None):**  No direct JavaScript code is present or invoked.
* **Indirect Relationship (Very Strong):** JavaScript in a web browser uses APIs (like `fetch`, `XMLHttpRequest`, WebSockets) that rely on the underlying network stack. This C++ code is a fundamental part of that stack. When a JavaScript function makes a network request, the browser's internal mechanisms eventually invoke code like this to perform the actual socket operations.

**7. Constructing Examples for JavaScript Interaction:**

To illustrate the indirect relationship, I'd think about common JavaScript network operations and how they map down to the C++ code:

* `fetch('https://example.com')`:  This eventually leads to a `Connect` call to establish a TCP connection to `example.com`. Data transfer during the fetch would involve `Send` and `Receive` calls.
* `new WebSocket('ws://example.com/socket')`:  The WebSocket handshake would involve `Connect`, `Send`, and `Receive`. Subsequent data exchange would also use `Send` and `Receive`.
* A server using Node.js with the `net` module's `createServer` and `socket.on('data', ...)`:  The server would use something akin to `Bind` and `Listen` to accept connections, and then `Accept`, `Send`, and `Receive` for each client.

**8. Developing Logical Reasoning Examples:**

For each function, I'd consider simple input scenarios and the expected output (success or failure with potential error information). This demonstrates an understanding of the function's behavior.

* **`Connect`:**  Input: Valid socket FD, valid remote address. Output: `absl::OkStatus()`. Input: Valid socket FD, invalid remote address. Output: Error status indicating connection failure (e.g., "Connection refused").
* **`Receive`:** Input: Valid socket FD, non-empty buffer. Output: `absl::Span` containing received data or an error status. Input: Valid socket FD, empty buffer. Output: Likely a DCHECK failure or an error indicating an invalid buffer.

**9. Identifying Common User Errors:**

Thinking about how developers or the system might misuse these functions leads to error examples:

* Using an invalid socket FD.
* Trying to `Bind` to an already bound address.
* Calling `Accept` on a socket that hasn't been `Listen`ed on.
* Providing a buffer that's too small for the expected data in `Receive`.
* Trying to `Connect` to a non-existent server.

**10. Tracing User Operations to the Code:**

This requires thinking about the layers involved in a network request. Starting from a user action in the browser and working backward:

1. **User Action:** Clicks a link, types a URL, a web page makes an API call.
2. **Browser Engine (Blink/Gecko):**  JavaScript interacts with browser APIs (fetch, XHR).
3. **Network Service:** The browser's network component (likely implemented in C++) handles the request. This involves DNS resolution, connection management, etc.
4. **QUIC Implementation (if applicable):** For QUIC connections, this `socket.cc` file comes into play for the underlying UDP socket operations. For TCP, similar socket handling code exists elsewhere in Chromium.
5. **System Calls:**  The functions in `socket.cc` eventually call the operating system's socket APIs (`accept`, `bind`, `connect`, etc.).

**11. Structuring the Answer:**

Finally, organize the information logically, addressing each part of the original request. Use clear headings and bullet points for readability. Provide code examples and concrete scenarios to illustrate the points. Emphasize the indirect nature of the JavaScript relationship.

By following these steps, a comprehensive and accurate answer to the request can be constructed. The process involves a combination of code analysis, understanding network concepts, and thinking about the software architecture involved.
这个文件 `net/third_party/quiche/src/quiche/quic/core/io/socket.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门负责提供与底层操作系统网络套接字（socket）交互的抽象层。它的主要功能可以归纳如下：

**主要功能:**

1. **套接字操作的封装:**  它封装了底层的系统调用，如 `accept`, `bind`, `connect`, `listen`, `send`, `recv`, `setsockopt`, `getsockopt` 等，并提供了更易于使用的 C++ 接口。
2. **QUIC 特定的套接字管理:** 虽然是通用的套接字操作，但它位于 QUIC 相关的代码路径下，因此很可能被 QUIC 协议栈用来创建和管理 UDP 套接字，因为 QUIC 通常运行在 UDP 之上。
3. **错误处理:** 它处理了系统调用的错误，并将这些错误转换为 `absl::Status` 对象，方便上层代码进行统一的错误处理。
4. **地址处理:** 它使用了 `QuicSocketAddress` 类来表示网络地址，并提供了与底层 `sockaddr_storage` 结构体之间的转换。
5. **平台差异处理:**  通过包含 `socket_win.inc` 或 `socket_posix.inc` 文件，它处理了不同操作系统（Windows 和 POSIX 系统）之间套接字 API 的差异。
6. **设置套接字选项:**  提供了设置套接字选项（如接收和发送缓冲区大小）的功能。
7. **非阻塞 I/O 支持:**  通过 `Accept` 函数的 `blocking` 参数，以及内部对 `SOCK_NONBLOCK` 的处理，支持非阻塞的套接字操作。

**与 JavaScript 的关系:**

这个 C++ 文件本身不包含任何 JavaScript 代码，也不直接与 JavaScript 交互。但是，它在 Chromium 浏览器中扮演着至关重要的角色，使得 JavaScript 能够进行网络通信。

当 JavaScript 代码（例如，通过 `fetch` API 或 `WebSocket` API）发起一个网络请求时，浏览器的底层网络栈（包括这个 `socket.cc` 文件中的代码）负责实际的网络数据传输。

**举例说明:**

假设一个网页中的 JavaScript 代码使用 `fetch` API 向服务器发送一个 HTTP 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.json())
  .then(data => console.log(data));
```

当执行这段 JavaScript 代码时，浏览器会经历以下步骤，最终会涉及到 `socket.cc` 中的代码：

1. **JavaScript 发起请求:**  JavaScript 代码调用 `fetch`。
2. **浏览器处理请求:** 浏览器内核（Blink）接收到请求，并开始处理。
3. **网络栈介入:**  Blink 将请求传递给浏览器的网络服务组件。
4. **连接建立 (QUIC 或 TCP):**
   - 如果使用 QUIC，网络服务会尝试建立一个 QUIC 连接。这会涉及到创建 UDP 套接字，并调用 `socket.cc` 中的 `Connect` 和 `SendTo` 等函数来发送和接收 QUIC 数据包。
   - 如果使用 TCP，则会使用 Chromium 中其他处理 TCP 套接字的代码，但概念类似。
5. **数据传输:** 一旦连接建立，当需要发送 HTTP 请求头和数据时，以及接收服务器响应时，会调用 `socket.cc` 中的 `Send` 和 `Receive` 函数来通过套接字发送和接收数据。
6. **JavaScript 接收数据:**  接收到的数据最终会传递回 JavaScript 代码，触发 `fetch` promise 的 resolve。

**逻辑推理，假设输入与输出:**

假设调用 `Connect` 函数：

**假设输入:**

* `fd`: 一个已经创建的套接字的文件描述符 (例如，通过 `socket()` 系统调用获得)。
* `peer_address`: 一个 `QuicSocketAddress` 对象，包含了目标服务器的 IP 地址和端口号 (例如，`192.168.1.100:8080`)。

**预期输出:**

* **成功:** `absl::OkStatus()`，表示连接请求已成功发起 (对于非阻塞套接字，可能只是表示连接发起，实际连接建立可能需要等待)。
* **失败:** 一个包含错误信息的 `absl::Status` 对象，例如：
    * `网络不可达` (Network is unreachable)
    * `连接被拒绝` (Connection refused)
    * `连接超时` (Connection timed out)

假设调用 `Receive` 函数：

**假设输入:**

* `fd`: 一个已经连接的套接字的文件描述符。
* `buffer`: 一个 `absl::Span<char>`，用于存储接收到的数据。
* `peek`: `false`，表示接收数据后从缓冲区移除。

**预期输出:**

* **成功接收到数据:** `absl::Span<char>`，指向 `buffer` 中接收到的数据部分。
* **没有数据可接收 (阻塞套接字):** 函数会阻塞，直到有数据到达。
* **没有数据可接收 (非阻塞套接字):** 返回一个表示没有数据的错误状态，例如 `EAGAIN` 或 `EWOULDBLOCK`。
* **发生错误:** 一个包含错误信息的 `absl::Status` 对象，例如：
    * `连接已关闭` (Connection reset by peer)
    * `读取超时` (Read timeout)

**用户或编程常见的使用错误:**

1. **使用无效的套接字文件描述符:**  例如，传递一个未初始化的或者已经关闭的套接字 FD 给任何函数。这会导致程序崩溃或未定义的行为。
   ```c++
   quic::socket_api::SocketFd invalid_fd = -1;
   absl::Status result = quic::socket_api::Connect(invalid_fd, peer_addr); // 错误
   ```
2. **在未绑定或监听的套接字上调用 `Accept`:**  `Accept` 只能在通过 `Bind` 绑定了本地地址，并通过 `Listen` 进入监听状态的套接字上调用。
   ```c++
   quic::socket_api::SocketFd listen_fd = SyscallSocket(...);
   absl::StatusOr<quic::socket_api::AcceptResult> accept_result = 
       quic::socket_api::Accept(listen_fd, true); // 错误，listen_fd 还未 bind 和 listen
   ```
3. **尝试绑定到已被占用的地址和端口:**  如果尝试使用 `Bind` 绑定到一个已经被其他进程或套接字占用的地址和端口，会失败。
   ```c++
   quic::socket_api::SocketFd server_fd = SyscallSocket(...);
   quic::QuicSocketAddress address("127.0.0.1", 80);
   absl::Status result1 = quic::socket_api::Bind(server_fd, address);
   // ... 假设另一个进程也在监听 127.0.0.1:80
   quic::socket_api::SocketFd another_server_fd = SyscallSocket(...);
   absl::Status result2 = quic::socket_api::Bind(another_server_fd, address); // 可能失败
   ```
4. **在未连接的套接字上调用 `Send` 或 `Receive` (对于面向连接的协议):** 对于 TCP 等面向连接的协议，必须先通过 `Connect` 建立连接，才能使用 `Send` 和 `Receive` 进行数据传输。
   ```c++
   quic::socket_api::SocketFd client_fd = SyscallSocket(...);
   absl::string_view data = "Hello";
   absl::StatusOr<absl::string_view> send_result = 
       quic::socket_api::Send(client_fd, data); // 错误，client_fd 还未连接
   ```
5. **提供的缓冲区大小不足以接收数据:** 在调用 `Receive` 时，如果提供的缓冲区 `buffer` 太小，可能会导致数据截断或其他问题。
   ```c++
   char small_buffer[10];
   absl::Span<char> recv_buffer(small_buffer);
   absl::StatusOr<absl::Span<char>> received = 
       quic::socket_api::Receive(connected_fd, recv_buffer, false);
   if (received.ok() && received.value().size() > sizeof(small_buffer)) {
       // 数据被截断
   }
   ```

**用户操作如何一步步的到达这里，作为调试线索:**

假设用户在 Chrome 浏览器中访问一个使用了 QUIC 协议的网站 `https://example.com`，并且遇到了连接问题，想要调试网络请求：

1. **用户在 Chrome 地址栏输入 `https://example.com` 并回车。**
2. **Chrome 浏览器开始解析 URL，并确定需要建立连接。**
3. **浏览器检查是否支持 QUIC 协议，以及服务器是否支持 QUIC。** 这可能涉及到 DNS 查询和 ALPN 协商。
4. **如果确定使用 QUIC，Chrome 的网络服务组件会尝试建立 QUIC 连接。**
5. **QUIC 连接建立过程会涉及到创建 UDP 套接字。**  这时，可能会调用 `socket()` 系统调用（在 `socket_posix.inc` 或 `socket_win.inc` 中）。
6. **网络服务组件会调用 `socket.cc` 中的 `Connect` 函数，尝试连接到服务器的 IP 地址和端口。**
7. **如果连接建立过程中出现问题（例如，网络不可达、服务器拒绝连接），`Connect` 函数会返回一个包含错误信息的 `absl::Status`。**
8. **作为调试线索，开发者可以使用 Chrome 的开发者工具 (DevTools)。** 在 "Network" 标签页中，可以看到请求的状态。如果连接失败，可能会显示相应的错误信息。
9. **更深入的调试可能需要查看 Chrome 的内部日志 (net-internals)。** 在地址栏输入 `chrome://net-internals/#quic` 可以查看 QUIC 相关的事件，包括套接字操作的详细信息和错误。
10. **如果怀疑是底层的套接字操作问题，开发者可能需要查看 Chromium 的源代码，或者使用调试器来跟踪 `socket.cc` 中的代码执行流程。**  例如，可以在 `Connect`, `Bind`, `SendTo`, `Receive` 等函数入口设置断点，查看参数和返回值，以确定问题发生在哪里。

总而言之，`net/third_party/quiche/src/quiche/quic/core/io/socket.cc` 文件是 QUIC 协议在 Chromium 中进行底层网络通信的关键组件，它封装了操作系统提供的套接字 API，使得 QUIC 协议栈可以方便地进行网络数据传输。虽然 JavaScript 不直接操作这个文件中的代码，但用户的 JavaScript 网络请求最终会依赖于这些底层的 C++ 代码来完成。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/io/socket.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/core/io/socket.h"

#include <cerrno>
#include <climits>
#include <cstddef>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/io/socket_internal.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/platform/api/quiche_logging.h"

#if defined(_WIN32)
#include "quiche/quic/core/io/socket_win.inc"
#else
#include "quiche/quic/core/io/socket_posix.inc"
#endif

namespace quic::socket_api {

namespace {

absl::StatusOr<AcceptResult> AcceptInternal(SocketFd fd) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);

  sockaddr_storage peer_addr;
  PlatformSocklen peer_addr_len = sizeof(peer_addr);
  SocketFd connection_socket = SyscallAccept(
      fd, reinterpret_cast<struct sockaddr*>(&peer_addr), &peer_addr_len);

  if (connection_socket == kInvalidSocketFd) {
    absl::Status status = LastSocketOperationError("::accept()");
    QUICHE_DVLOG(1) << "Failed to accept connection from socket " << fd
                    << " with error: " << status;
    return status;
  }

  absl::StatusOr<QuicSocketAddress> peer_address =
      ValidateAndConvertAddress(peer_addr, peer_addr_len);

  if (peer_address.ok()) {
    return AcceptResult{connection_socket, *peer_address};
  } else {
    return peer_address.status();
  }
}

absl::Status SetSockOptInt(SocketFd fd, int level, int option, int value) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);

  int result = SyscallSetsockopt(fd, level, option, &value, sizeof(value));

  if (result >= 0) {
    return absl::OkStatus();
  } else {
    absl::Status status = LastSocketOperationError("::setsockopt()");
    QUICHE_DVLOG(1) << "Failed to set socket " << fd << " option " << option
                    << " to " << value << " with error: " << status;
    return status;
  }
}

}  // namespace

absl::Status SetReceiveBufferSize(SocketFd fd, QuicByteCount size) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);
  QUICHE_DCHECK_LE(size, QuicByteCount{INT_MAX});

  return SetSockOptInt(fd, SOL_SOCKET, SO_RCVBUF, static_cast<int>(size));
}

absl::Status SetSendBufferSize(SocketFd fd, QuicByteCount size) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);
  QUICHE_DCHECK_LE(size, QuicByteCount{INT_MAX});

  return SetSockOptInt(fd, SOL_SOCKET, SO_SNDBUF, static_cast<int>(size));
}

absl::Status Connect(SocketFd fd, const QuicSocketAddress& peer_address) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);
  QUICHE_DCHECK(peer_address.IsInitialized());

  sockaddr_storage addr = peer_address.generic_address();
  PlatformSocklen addrlen = GetAddrlen(peer_address.host().address_family());

  int connect_result =
      SyscallConnect(fd, reinterpret_cast<sockaddr*>(&addr), addrlen);

  if (connect_result >= 0) {
    return absl::OkStatus();
  } else {
    // For ::connect(), only `EINPROGRESS` indicates unavailable.
    absl::Status status =
        LastSocketOperationError("::connect()", /*unavailable_error_numbers=*/
                                 {EINPROGRESS});
    QUICHE_DVLOG(1) << "Failed to connect socket " << fd
                    << " to address: " << peer_address.ToString()
                    << " with error: " << status;
    return status;
  }
}

absl::Status GetSocketError(SocketFd fd) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);

  int socket_error = 0;
  PlatformSocklen len = sizeof(socket_error);
  int sockopt_result =
      SyscallGetsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &len);

  if (sockopt_result >= 0) {
    if (socket_error == 0) {
      return absl::OkStatus();
    } else {
      return ToStatus(socket_error, "SO_ERROR");
    }
  } else {
    absl::Status status = LastSocketOperationError("::getsockopt()");
    QUICHE_LOG_FIRST_N(ERROR, 100)
        << "Failed to get socket error information from socket " << fd
        << " with error: " << status;
    return status;
  }
}

absl::Status Bind(SocketFd fd, const QuicSocketAddress& address) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);
  QUICHE_DCHECK(address.IsInitialized());

  sockaddr_storage addr = address.generic_address();
  PlatformSocklen addr_len = GetAddrlen(address.host().address_family());

  int result = SyscallBind(fd, reinterpret_cast<sockaddr*>(&addr), addr_len);

  if (result >= 0) {
    return absl::OkStatus();
  } else {
    absl::Status status = LastSocketOperationError("::bind()");
    QUICHE_DVLOG(1) << "Failed to bind socket " << fd
                    << " to address: " << address.ToString()
                    << " with error: " << status;
    return status;
  }
}

absl::StatusOr<QuicSocketAddress> GetSocketAddress(SocketFd fd) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);

  sockaddr_storage addr;
  PlatformSocklen addr_len = sizeof(addr);

  int result =
      SyscallGetsockname(fd, reinterpret_cast<sockaddr*>(&addr), &addr_len);

  if (result >= 0) {
    return ValidateAndConvertAddress(addr, addr_len);
  } else {
    absl::Status status = LastSocketOperationError("::getsockname()");
    QUICHE_DVLOG(1) << "Failed to get socket " << fd
                    << " name with error: " << status;
    return status;
  }
}

absl::Status Listen(SocketFd fd, int backlog) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);
  QUICHE_DCHECK_GT(backlog, 0);

  int result = SyscallListen(fd, backlog);

  if (result >= 0) {
    return absl::OkStatus();
  } else {
    absl::Status status = LastSocketOperationError("::listen()");
    QUICHE_DVLOG(1) << "Failed to mark socket: " << fd
                    << " to listen with error :" << status;
    return status;
  }
}

absl::StatusOr<AcceptResult> Accept(SocketFd fd, bool blocking) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);

#if defined(HAS_ACCEPT4)
  if (!blocking) {
    return AcceptWithFlags(fd, SOCK_NONBLOCK);
  }
#endif

  absl::StatusOr<AcceptResult> accept_result = AcceptInternal(fd);
  if (!accept_result.ok() || blocking) {
    return accept_result;
  }

#if !defined(__linux__) || !defined(SOCK_NONBLOCK)
  // If non-blocking could not be set directly on socket acceptance, need to
  // do it now.
  absl::Status set_non_blocking_result =
      SetSocketBlocking(accept_result->fd, /*blocking=*/false);
  if (!set_non_blocking_result.ok()) {
    QUICHE_LOG_FIRST_N(ERROR, 100)
        << "Failed to set socket " << fd << " as non-blocking on acceptance.";
    if (!Close(accept_result->fd).ok()) {
      QUICHE_LOG_FIRST_N(ERROR, 100)
          << "Failed to close socket " << accept_result->fd
          << " after error setting non-blocking on acceptance.";
    }
    return set_non_blocking_result;
  }
#endif

  return accept_result;
}

absl::StatusOr<absl::Span<char>> Receive(SocketFd fd, absl::Span<char> buffer,
                                         bool peek) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);
  QUICHE_DCHECK(!buffer.empty());

  PlatformSsizeT num_read = SyscallRecv(fd, buffer.data(), buffer.size(),
                                        /*flags=*/peek ? MSG_PEEK : 0);

  if (num_read > 0 && static_cast<size_t>(num_read) > buffer.size()) {
    QUICHE_LOG_FIRST_N(WARNING, 100)
        << "Received more bytes (" << num_read << ") from socket " << fd
        << " than buffer size (" << buffer.size() << ").";
    return absl::OutOfRangeError(
        "::recv(): Received more bytes than buffer size.");
  } else if (num_read >= 0) {
    return buffer.subspan(0, num_read);
  } else {
    absl::Status status = LastSocketOperationError("::recv()");
    QUICHE_DVLOG(1) << "Failed to receive from socket: " << fd
                    << " with error: " << status;
    return status;
  }
}

absl::StatusOr<absl::string_view> Send(SocketFd fd, absl::string_view buffer) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);
  QUICHE_DCHECK(!buffer.empty());

  PlatformSsizeT num_sent =
      SyscallSend(fd, buffer.data(), buffer.size(), /*flags=*/0);

  if (num_sent > 0 && static_cast<size_t>(num_sent) > buffer.size()) {
    QUICHE_LOG_FIRST_N(WARNING, 100)
        << "Sent more bytes (" << num_sent << ") to socket " << fd
        << " than buffer size (" << buffer.size() << ").";
    return absl::OutOfRangeError("::send(): Sent more bytes than buffer size.");
  } else if (num_sent >= 0) {
    return buffer.substr(num_sent);
  } else {
    absl::Status status = LastSocketOperationError("::send()");
    QUICHE_DVLOG(1) << "Failed to send to socket: " << fd
                    << " with error: " << status;
    return status;
  }
}

absl::StatusOr<absl::string_view> SendTo(SocketFd fd,
                                         const QuicSocketAddress& peer_address,
                                         absl::string_view buffer) {
  QUICHE_DCHECK_NE(fd, kInvalidSocketFd);
  QUICHE_DCHECK(peer_address.IsInitialized());
  QUICHE_DCHECK(!buffer.empty());

  sockaddr_storage addr = peer_address.generic_address();
  PlatformSocklen addrlen = GetAddrlen(peer_address.host().address_family());

  PlatformSsizeT num_sent =
      SyscallSendTo(fd, buffer.data(), buffer.size(),
                    /*flags=*/0, reinterpret_cast<sockaddr*>(&addr), addrlen);

  if (num_sent > 0 && static_cast<size_t>(num_sent) > buffer.size()) {
    QUICHE_LOG_FIRST_N(WARNING, 100)
        << "Sent more bytes (" << num_sent << ") to socket " << fd
        << " to address: " << peer_address.ToString() << " than buffer size ("
        << buffer.size() << ").";
    return absl::OutOfRangeError(
        "::sendto(): Sent more bytes than buffer size.");
  } else if (num_sent >= 0) {
    return buffer.substr(num_sent);
  } else {
    absl::Status status = LastSocketOperationError("::sendto()");
    QUICHE_DVLOG(1) << "Failed to send to socket: " << fd
                    << " to address: " << peer_address.ToString()
                    << " with error: " << status;
    return status;
  }
}

}  // namespace quic::socket_api
```