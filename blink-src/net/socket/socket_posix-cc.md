Response:
Let's break down the thought process to analyze the `socket_posix.cc` file and answer the user's request.

**1. Initial Understanding and Goal Setting:**

The core goal is to understand the functionality of `socket_posix.cc` and connect it to the user's points of interest: JavaScript interaction, logical reasoning with inputs/outputs, common user errors, and debugging information.

**2. High-Level Overview of the Code:**

My first step is to skim the code to get a general idea. I see includes related to sockets, POSIX, and Chromium's base library (`base/`). I recognize keywords like `SocketPosix`, `Open`, `Bind`, `Listen`, `Accept`, `Connect`, `Read`, `Write`, and event handling (`OnFileCanReadWithoutBlocking`, `OnFileCanWriteWithoutBlocking`). This immediately tells me this file is a low-level implementation of sockets, likely for POSIX-compliant systems.

**3. Deconstructing Functionality (Line by Line/Section by Section):**

Now, I'll go through the code more carefully, function by function, noting key actions and data flow:

* **Includes:** Identify external dependencies and what functionalities they bring (e.g., `<sys/socket.h>` for socket primitives, `base/files/file_util.h` for non-blocking operations).
* **Namespaces:** Understand the context (`net` namespace).
* **Anonymous Namespace:**  Recognize helper functions like `MapAcceptError` and `MapConnectError` for translating OS-specific errors to Chromium's `net::` error codes. This is important for error handling consistency.
* **`SocketPosix` Class:**  This is the central class. I look at the member variables:
    * `socket_fd_`:  The raw file descriptor. Fundamental.
    * `accept_socket_watcher_`, `read_socket_watcher_`, `write_socket_watcher_`:  IO event watchers. This signals the use of an event loop for asynchronous I/O.
    * Callbacks (`accept_callback_`, `read_callback_`, `write_callback_`, `read_if_ready_callback_`):  Essential for asynchronous operations and notifying when events occur.
    * Buffers (`read_buf_`, `write_buf_`):  For storing data during read/write operations.
    * `peer_address_`:  Stores the address of the connected remote endpoint.
    * `waiting_connect_`:  A flag to track if a connection is in progress.
    * `thread_checker_`: Ensures operations happen on the correct thread.
* **Public Methods:** I analyze each public method, understanding its purpose and how it interacts with the underlying OS socket API:
    * `Open()`: Creates a new socket.
    * `AdoptConnectedSocket()`, `AdoptUnconnectedSocket()`: Allows using pre-existing sockets.
    * `ReleaseConnectedSocket()`:  Releases ownership of the socket.
    * `Bind()`: Associates the socket with a local address.
    * `Listen()`:  Marks the socket for accepting incoming connections.
    * `Accept()`: Accepts a new connection. Key here is the asynchronous nature using the watcher.
    * `Connect()`: Establishes a connection. Also asynchronous.
    * `IsConnected()`, `IsConnectedAndIdle()`: Checks the connection state.
    * `Read()`, `ReadIfReady()`, `CancelReadIfReady()`:  Reads data from the socket. `ReadIfReady` is a non-blocking read attempt.
    * `Write()`: Sends data.
    * `WaitForWrite()`: Sets up the watcher for write readiness.
    * `GetLocalAddress()`, `GetPeerAddress()`: Retrieves socket addresses.
    * `Close()`: Closes the socket.
    * `DetachFromThread()`:  Allows the object to be moved to a different thread (with caution).
* **Private Methods and Event Handlers:**  These are crucial for the asynchronous nature of the socket:
    * `DoAccept()`, `DoConnect()`, `DoRead()`, `DoWrite()`:  Directly interact with the OS socket calls.
    * `AcceptCompleted()`, `ConnectCompleted()`, `ReadCompleted()`, `WriteCompleted()`:  Called when the socket watcher signals readiness. These methods trigger the user-provided callbacks.
    * `RetryRead()`: Handles retries for read operations.
    * `StopWatchingAndCleanUp()`:  Releases resources.
* **Error Handling:** Observe how `MapSystemError`, `MapAcceptError`, and `MapConnectError` are used to convert OS-level errors to `net::` error codes.

**4. Connecting to User Concerns:**

* **JavaScript Interaction:**  I need to bridge the gap between this C++ code and JavaScript. I know that JavaScript in a browser environment interacts with network functionalities through higher-level APIs like `fetch`, `XMLHttpRequest`, and WebSockets. These APIs are eventually implemented using the browser's network stack, which includes code like this. I need to illustrate how a high-level JavaScript operation translates down.
* **Logical Reasoning (Inputs/Outputs):**  For key functions like `Connect`, `Read`, and `Write`, I consider what the inputs would be (e.g., an address to connect to, a buffer to read into) and the possible outputs (success, failure, error codes, data read). I'll create simple scenarios.
* **Common User Errors:**  I think about typical programming mistakes when dealing with sockets: using uninitialized sockets, trying to read/write on closed sockets, incorrect address formats, connection timeouts.
* **Debugging:** I consider how a developer might reach this code. Setting breakpoints in network-related code, using network inspection tools, and looking at error messages are common scenarios. The asynchronous nature is a key debugging challenge.

**5. Structuring the Answer:**

Finally, I organize the information into clear sections, addressing each part of the user's request:

* **Functionality:** A concise summary of what the file does.
* **Relationship to JavaScript:** Concrete examples of how JavaScript network APIs relate to this low-level implementation.
* **Logical Reasoning (Inputs/Outputs):**  Clear examples for key functions.
* **Common User/Programming Errors:** Specific examples with explanations.
* **User Operations and Debugging:** Steps to reach this code and debugging tips.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Focus too much on low-level socket details without connecting to the user's JavaScript context.
* **Correction:**  Realize the need to explicitly link the C++ implementation to high-level JavaScript APIs.
* **Initial Thought:** Provide overly technical input/output scenarios.
* **Correction:** Simplify the scenarios to make them easily understandable.
* **Initial Thought:**  Assume the user is a networking expert.
* **Correction:**  Explain concepts clearly and avoid jargon where possible. Focus on the *user's* perspective.

By following these steps, combining code analysis with an understanding of the user's needs, I can construct a comprehensive and helpful answer.
This C++ source file, `socket_posix.cc`, within the Chromium network stack, provides a **platform-specific implementation of sockets for POSIX-compliant operating systems** (like Linux, macOS, Android, etc.). It essentially wraps the raw POSIX socket API (`socket()`, `bind()`, `listen()`, `accept()`, `connect()`, `read()`, `write()`, etc.) and integrates it with Chromium's asynchronous I/O model.

Here's a breakdown of its key functionalities:

**Core Socket Operations:**

* **Creating Sockets:** The `Open()` method creates a new socket file descriptor using the `socket()` system call. It supports `AF_INET` (IPv4), `AF_INET6` (IPv6), and `AF_UNIX` (Unix domain sockets). It also sets the socket to non-blocking mode.
* **Adopting Existing Sockets:**  `AdoptConnectedSocket()` and `AdoptUnconnectedSocket()` allow the class to take ownership of already existing socket file descriptors, potentially created externally.
* **Releasing Sockets:** `ReleaseConnectedSocket()` relinquishes ownership of the socket.
* **Binding to an Address:** The `Bind()` method associates the socket with a local IP address and port using the `bind()` system call.
* **Listening for Connections:** `Listen()` puts the socket into a listening state, ready to accept incoming connections using the `listen()` system call.
* **Accepting Connections:** `Accept()` handles incoming connection requests on a listening socket. It uses asynchronous I/O (via `base::CurrentIOThread::Get()->WatchFileDescriptor`) to avoid blocking the thread while waiting for a connection.
* **Connecting to a Server:** `Connect()` initiates a connection to a remote server using the `connect()` system call. It also uses asynchronous I/O to handle the potentially long-running connection process.
* **Checking Connection Status:** `IsConnected()` and `IsConnectedAndIdle()` provide ways to check if a socket is currently connected and whether there's any pending data to be read.
* **Reading Data:** `Read()` and `ReadIfReady()` read data from the socket using the `read()` system call. `ReadIfReady()` attempts a non-blocking read. Both integrate with Chromium's asynchronous I/O.
* **Writing Data:** `Write()` sends data over the socket using the `write()` or `send()` (with `MSG_NOSIGNAL` on some platforms) system call. It also utilizes asynchronous I/O.
* **Getting Socket Addresses:** `GetLocalAddress()` and `GetPeerAddress()` retrieve the local and remote IP addresses and ports associated with the socket using `getsockname()` and stored information, respectively.
* **Closing Sockets:** The `Close()` method closes the socket file descriptor using the `close()` system call and cleans up associated resources.

**Asynchronous I/O Integration:**

* **`base::CurrentIOThread::Get()->WatchFileDescriptor()`:** This is crucial. The class uses Chromium's I/O thread to monitor the socket file descriptor for readability or writability. This allows the socket operations (accept, connect, read, write) to be non-blocking.
* **`OnFileCanReadWithoutBlocking()` and `OnFileCanWriteWithoutBlocking()`:** These methods are callbacks invoked by the I/O thread when the socket becomes readable or writable, respectively. They handle the completion of asynchronous operations.
* **Completion Callbacks:**  Methods like `Accept()`, `Connect()`, `Read()`, and `Write()` take `CompletionOnceCallback` as arguments. These callbacks are executed when the asynchronous operation completes (successfully or with an error).

**Error Handling:**

* **`MapSystemError()`:**  This helper function (likely defined elsewhere in Chromium) maps POSIX `errno` values to Chromium's `net::NetError` codes, providing a consistent error reporting mechanism across the network stack.
* **`MapAcceptError()` and `MapConnectError()`:** These provide specialized error mapping for the `accept()` and `connect()` system calls, handling specific error conditions like `ECONNABORTED` and `EINPROGRESS`.

**Relationship to JavaScript Functionality:**

While `socket_posix.cc` is a C++ file, it plays a foundational role in enabling network communication initiated from JavaScript within a Chromium-based browser (like Chrome or Edge). Here's how they are related:

* **Underlying Implementation:** When JavaScript code uses network APIs like `fetch`, `XMLHttpRequest`, `WebSocket`, or `WebRTC` data channels, the browser's network stack (written in C++) handles the actual low-level network operations. `socket_posix.cc` (or platform-specific equivalents) is often part of this underlying implementation for establishing and managing TCP connections.
* **Abstraction Layer:** JavaScript interacts with high-level abstractions. The browser engine (e.g., Blink) translates these high-level requests into lower-level C++ calls. For instance, a JavaScript `fetch()` request for an HTTPS URL will eventually involve creating a TCP socket (using code like in `socket_posix.cc`), performing a TLS handshake, and then sending and receiving HTTP data.
* **Example:**
    * **JavaScript (using `fetch`):**
      ```javascript
      fetch('https://www.example.com/data')
        .then(response => response.json())
        .then(data => console.log(data));
      ```
    * **C++ (`socket_posix.cc` involvement):**
      When this JavaScript code runs, the browser will:
      1. Resolve the IP address of `www.example.com`.
      2. Call a C++ function (likely within `net/socket`) that will eventually create a TCP socket using `SocketPosix::Open(AF_INET)`.
      3. Initiate a connection using `SocketPosix::Connect()` to the resolved IP address and port 443.
      4. Once connected, perform a TLS handshake (handled by other components).
      5. Send the HTTP request using `SocketPosix::Write()`.
      6. Receive the HTTP response using `SocketPosix::Read()`.
      7. Parse the response and deliver the JSON data back to the JavaScript `then()` block.

**Logical Reasoning with Inputs and Outputs:**

Let's consider the `Connect()` method:

**Hypothetical Input:**

* `address`: A `SockaddrStorage` object containing the IP address (e.g., `192.168.1.100`) and port (e.g., `8080`) of the server to connect to.
* `callback`: A `CompletionOnceCallback` function that will be executed when the connection attempt is completed (either successfully or with an error).

**Logical Flow:**

1. `Connect()` is called with the target address and callback.
2. The peer address is stored (`SetPeerAddress`).
3. `DoConnect()` is called, which attempts the non-blocking `connect()` system call.
4. If `connect()` returns `EINPROGRESS` (meaning the connection is in progress), the socket is registered with the I/O thread to watch for writability.
5. The `write_callback_` is stored, and `waiting_connect_` is set to `true`.
6. When the connection succeeds or fails, the I/O thread will call `OnFileCanWriteWithoutBlocking()`.
7. `ConnectCompleted()` is executed:
   - It checks the result of the `connect()` operation using `getsockopt(SO_ERROR)`.
   - It maps the OS error to a `net::NetError` code.
   - The stored `write_callback_` is executed with the result.

**Possible Outputs (passed to the callback):**

* `net::OK`:  The connection was established successfully.
* `net::ERR_CONNECTION_REFUSED`: The server actively refused the connection.
* `net::ERR_TIMED_OUT`: The connection attempt timed out.
* `net::ERR_NETWORK_ACCESS_DENIED`:  The connection was blocked by network policy.
* Other `net::NetError` codes indicating various connection failures.

**User or Programming Common Usage Errors:**

1. **Calling Socket Methods on the Wrong Thread:** Many methods in `SocketPosix` (`Open`, `Bind`, `Connect`, `Read`, `Write`, `Close`) have `DCHECK(thread_checker_.CalledOnValidThread())`. Calling these from a thread other than the intended I/O thread will lead to crashes or unexpected behavior.
   * **Example:**  A developer might try to directly read data from a socket created on the I/O thread from a worker thread without proper synchronization mechanisms.

2. **Not Handling Asynchronous Completion:** Since socket operations are asynchronous, it's a common mistake to assume they complete immediately. Developers must rely on the provided completion callbacks to know when an operation finishes and to handle the result (success or error).
   * **Example:**  Calling `Connect()` and immediately trying to send data without waiting for the connection callback to be invoked.

3. **Using an Invalid or Closed Socket:** Attempting to perform operations (read, write, close) on a socket that hasn't been opened, has been closed, or is in an invalid state will lead to errors.
   * **Example:**  Calling `Read()` on a `SocketPosix` object where `Open()` was never successfully called, or after `Close()` has been executed.

4. **Incorrect Address Formats:** Providing an invalid IP address or port to `Connect()` or `Bind()` will result in connection failures or binding errors.
   * **Example:**  Trying to connect to an IP address with an invalid format (e.g., "256.0.0.1") or a port number outside the valid range (0-65535).

5. **Ignoring Error Codes:**  Failing to check the return values of socket methods or the error codes passed to completion callbacks can lead to incorrect program behavior and make debugging difficult.
   * **Example:**  Not checking if `Connect()` returned `net::OK` before attempting to send data.

**User Operations Leading to This Code (Debugging Clues):**

A user's actions in a web browser can trigger the execution of code in `socket_posix.cc` indirectly. Here's a breakdown:

1. **Opening a Webpage (HTTP/HTTPS):**
   - User types a URL in the address bar or clicks a link.
   - The browser needs to establish a TCP connection to the web server.
   - This involves DNS resolution (handled elsewhere), and then `SocketPosix::Open()` and `SocketPosix::Connect()` (for TCP) are used to create and connect the socket.

2. **Using WebSockets:**
   - A website uses the JavaScript WebSocket API to establish a persistent bidirectional connection.
   - Under the hood, `SocketPosix` (or a similar class) is used to create and manage the TCP socket for the WebSocket connection. `SocketPosix::Read()` and `SocketPosix::Write()` handle the data transfer.

3. **Making `fetch()` or `XMLHttpRequest` Requests:**
   - JavaScript code uses these APIs to send HTTP requests to a server.
   - Similar to opening a webpage, `SocketPosix` is involved in creating, connecting, and transferring data over the TCP socket.

4. **WebRTC Data Channels:**
   - WebRTC enables real-time communication in the browser. Data channels often use SCTP over UDP, but can fall back to TCP in certain scenarios. If TCP is used, `SocketPosix` would be involved.

**Debugging Steps to Reach `socket_posix.cc`:**

1. **Network Inspection Tools:**
   - **Chrome DevTools (Network tab):** Observe network requests, connection states, timing information, and potential errors. This can indicate issues at the socket level.
   - **Wireshark/tcpdump:** Capture network packets to analyze the raw TCP communication, including SYN/ACK packets, data transfer, and potential errors like RST (reset) packets.

2. **Browser Logging:**
   - Chromium has extensive logging capabilities. Enabling network-related logging flags can provide detailed information about socket operations, error codes, and internal state transitions. Look for logs related to "socket", "tcp", or specific error codes.

3. **Code Breakpoints:**
   - If you have access to the Chromium source code and are building it, you can set breakpoints in `socket_posix.cc` (or related files like `tcp_socket_posix.cc`) to step through the code during network operations. Pay attention to:
     - The values of `errno` after system calls like `connect`, `read`, `write`.
     - The arguments passed to these system calls (e.g., socket file descriptor, address, buffer).
     - The execution flow within the asynchronous callbacks (`OnFileCanReadWithoutBlocking`, `OnFileCanWriteWithoutBlocking`).

4. **Error Messages and Stack Traces:**
   - When network errors occur, the browser often displays error messages or provides stack traces in the developer console. These can point to the source of the error, potentially leading back to the socket implementation. Look for error codes like `net::ERR_CONNECTION_REFUSED` or stack frames involving `SocketPosix`.

5. **System-Level Tools:**
   - **`netstat` or `ss`:** These command-line tools can show active network connections, including the state of TCP sockets (e.g., ESTABLISHED, SYN_SENT, CLOSED). This can help diagnose connection issues.

By understanding the role of `socket_posix.cc` and the sequence of operations involved in network communication, developers can effectively debug network-related issues in Chromium-based browsers.

Prompt: 
```
这是目录为net/socket/socket_posix.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/socket_posix.h"

#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <memory>
#include <utility>

#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/posix/eintr_wrapper.h"
#include "base/task/current_thread.h"
#include "build/build_config.h"
#include "net/base/io_buffer.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/base/sockaddr_storage.h"
#include "net/base/trace_constants.h"
#include "net/base/tracing.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

#if BUILDFLAG(IS_FUCHSIA)
#include <poll.h>
#include <sys/ioctl.h>
#endif  // BUILDFLAG(IS_FUCHSIA)

namespace net {

namespace {

int MapAcceptError(int os_error) {
  switch (os_error) {
    // If the client aborts the connection before the server calls accept,
    // POSIX specifies accept should fail with ECONNABORTED. The server can
    // ignore the error and just call accept again, so we map the error to
    // ERR_IO_PENDING. See UNIX Network Programming, Vol. 1, 3rd Ed., Sec.
    // 5.11, "Connection Abort before accept Returns".
    case ECONNABORTED:
      return ERR_IO_PENDING;
    default:
      return MapSystemError(os_error);
  }
}

int MapConnectError(int os_error) {
  switch (os_error) {
    case EINPROGRESS:
      return ERR_IO_PENDING;
    case EACCES:
      return ERR_NETWORK_ACCESS_DENIED;
    case ETIMEDOUT:
      return ERR_CONNECTION_TIMED_OUT;
    default: {
      int net_error = MapSystemError(os_error);
      if (net_error == ERR_FAILED)
        return ERR_CONNECTION_FAILED;  // More specific than ERR_FAILED.
      return net_error;
    }
  }
}

}  // namespace

SocketPosix::SocketPosix()
    : socket_fd_(kInvalidSocket),
      accept_socket_watcher_(FROM_HERE),
      read_socket_watcher_(FROM_HERE),
      write_socket_watcher_(FROM_HERE) {}

SocketPosix::~SocketPosix() {
  Close();
}

int SocketPosix::Open(int address_family) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_EQ(kInvalidSocket, socket_fd_);
  DCHECK(address_family == AF_INET ||
         address_family == AF_INET6 ||
         address_family == AF_UNIX);

  socket_fd_ = CreatePlatformSocket(
      address_family,
      SOCK_STREAM,
      address_family == AF_UNIX ? 0 : IPPROTO_TCP);
  if (socket_fd_ < 0) {
    PLOG(ERROR) << "CreatePlatformSocket() failed";
    return MapSystemError(errno);
  }

  if (!base::SetNonBlocking(socket_fd_)) {
    int rv = MapSystemError(errno);
    Close();
    return rv;
  }

  return OK;
}

int SocketPosix::AdoptConnectedSocket(SocketDescriptor socket,
                                      const SockaddrStorage& address) {
  int rv = AdoptUnconnectedSocket(socket);
  if (rv != OK)
    return rv;

  SetPeerAddress(address);
  return OK;
}

int SocketPosix::AdoptUnconnectedSocket(SocketDescriptor socket) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_EQ(kInvalidSocket, socket_fd_);

  socket_fd_ = socket;

  if (!base::SetNonBlocking(socket_fd_)) {
    int rv = MapSystemError(errno);
    Close();
    return rv;
  }

  return OK;
}

SocketDescriptor SocketPosix::ReleaseConnectedSocket() {
  // It's not safe to release a socket with a pending write.
  DCHECK(!write_buf_);

  StopWatchingAndCleanUp(false /* close_socket */);
  SocketDescriptor socket_fd = socket_fd_;
  socket_fd_ = kInvalidSocket;
  return socket_fd;
}

int SocketPosix::Bind(const SockaddrStorage& address) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(kInvalidSocket, socket_fd_);

  int rv = bind(socket_fd_, address.addr, address.addr_len);
  if (rv < 0) {
    PLOG(ERROR) << "bind() failed";
    return MapSystemError(errno);
  }

  return OK;
}

int SocketPosix::Listen(int backlog) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(kInvalidSocket, socket_fd_);
  DCHECK_LT(0, backlog);

  int rv = listen(socket_fd_, backlog);
  if (rv < 0) {
    PLOG(ERROR) << "listen() failed";
    return MapSystemError(errno);
  }

  return OK;
}

int SocketPosix::Accept(std::unique_ptr<SocketPosix>* socket,
                        CompletionOnceCallback callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(kInvalidSocket, socket_fd_);
  DCHECK(accept_callback_.is_null());
  DCHECK(socket);
  DCHECK(!callback.is_null());

  int rv = DoAccept(socket);
  if (rv != ERR_IO_PENDING)
    return rv;

  if (!base::CurrentIOThread::Get()->WatchFileDescriptor(
          socket_fd_, true, base::MessagePumpForIO::WATCH_READ,
          &accept_socket_watcher_, this)) {
    PLOG(ERROR) << "WatchFileDescriptor failed on accept";
    return MapSystemError(errno);
  }

  accept_socket_ = socket;
  accept_callback_ = std::move(callback);
  return ERR_IO_PENDING;
}

int SocketPosix::Connect(const SockaddrStorage& address,
                         CompletionOnceCallback callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(kInvalidSocket, socket_fd_);
  DCHECK(!waiting_connect_);
  DCHECK(!callback.is_null());

  SetPeerAddress(address);

  int rv = DoConnect();
  if (rv != ERR_IO_PENDING)
    return rv;

  if (!base::CurrentIOThread::Get()->WatchFileDescriptor(
          socket_fd_, true, base::MessagePumpForIO::WATCH_WRITE,
          &write_socket_watcher_, this)) {
    PLOG(ERROR) << "WatchFileDescriptor failed on connect";
    return MapSystemError(errno);
  }

  // There is a race-condition in the above code if the kernel receive a RST
  // packet for the "connect" call before the registration of the socket file
  // descriptor to the message loop pump. On most platform it is benign as the
  // message loop pump is awakened for that socket in an error state, but on
  // iOS this does not happens. Check the status of the socket at this point
  // and if in error, consider the connection as failed.
  int os_error = 0;
  socklen_t len = sizeof(os_error);
  if (getsockopt(socket_fd_, SOL_SOCKET, SO_ERROR, &os_error, &len) == 0) {
    // TCPSocketPosix expects errno to be set.
    errno = os_error;
  }

  rv = MapConnectError(errno);
  if (rv != OK && rv != ERR_IO_PENDING) {
    write_socket_watcher_.StopWatchingFileDescriptor();
    return rv;
  }

  write_callback_ = std::move(callback);
  waiting_connect_ = true;
  return ERR_IO_PENDING;
}

bool SocketPosix::IsConnected() const {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (socket_fd_ == kInvalidSocket || waiting_connect_)
    return false;

  // Checks if connection is alive.
  char c;
  int rv = HANDLE_EINTR(recv(socket_fd_, &c, 1, MSG_PEEK));
  if (rv == 0)
    return false;
  if (rv == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
    return false;

  return true;
}

bool SocketPosix::IsConnectedAndIdle() const {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (socket_fd_ == kInvalidSocket || waiting_connect_)
    return false;

  // Check if connection is alive and we haven't received any data
  // unexpectedly.
  char c;
  int rv = HANDLE_EINTR(recv(socket_fd_, &c, 1, MSG_PEEK));
  if (rv >= 0)
    return false;
  if (errno != EAGAIN && errno != EWOULDBLOCK)
    return false;

  return true;
}

int SocketPosix::Read(IOBuffer* buf,
                      int buf_len,
                      CompletionOnceCallback callback) {
  // Use base::Unretained() is safe here because OnFileCanReadWithoutBlocking()
  // won't be called if |this| is gone.
  int rv = ReadIfReady(
      buf, buf_len,
      base::BindOnce(&SocketPosix::RetryRead, base::Unretained(this)));
  if (rv == ERR_IO_PENDING) {
    read_buf_ = buf;
    read_buf_len_ = buf_len;
    read_callback_ = std::move(callback);
  }
  return rv;
}

int SocketPosix::ReadIfReady(IOBuffer* buf,
                             int buf_len,
                             CompletionOnceCallback callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(kInvalidSocket, socket_fd_);
  DCHECK(!waiting_connect_);
  CHECK(read_if_ready_callback_.is_null());
  DCHECK(!callback.is_null());
  DCHECK_LT(0, buf_len);

  int rv = DoRead(buf, buf_len);
  if (rv != ERR_IO_PENDING)
    return rv;

  if (!base::CurrentIOThread::Get()->WatchFileDescriptor(
          socket_fd_, true, base::MessagePumpForIO::WATCH_READ,
          &read_socket_watcher_, this)) {
    PLOG(ERROR) << "WatchFileDescriptor failed on read";
    return MapSystemError(errno);
  }

  read_if_ready_callback_ = std::move(callback);
  return ERR_IO_PENDING;
}

int SocketPosix::CancelReadIfReady() {
  DCHECK(read_if_ready_callback_);

  bool ok = read_socket_watcher_.StopWatchingFileDescriptor();
  DCHECK(ok);

  read_if_ready_callback_.Reset();
  return net::OK;
}

int SocketPosix::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& /* traffic_annotation */) {
  DCHECK(thread_checker_.CalledOnValidThread());
  CHECK_NE(kInvalidSocket, socket_fd_);
  CHECK(!waiting_connect_);
  CHECK(write_callback_.is_null());
  // Synchronous operation not supported
  CHECK(!callback.is_null());
  CHECK_LT(0, buf_len);

  int rv = DoWrite(buf, buf_len);
  if (rv == ERR_IO_PENDING)
    rv = WaitForWrite(buf, buf_len, std::move(callback));
  return rv;
}

int SocketPosix::WaitForWrite(IOBuffer* buf,
                              int buf_len,
                              CompletionOnceCallback callback) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK_NE(kInvalidSocket, socket_fd_);
  DCHECK(write_callback_.is_null());
  // Synchronous operation not supported
  DCHECK(!callback.is_null());
  DCHECK_LT(0, buf_len);

  if (!base::CurrentIOThread::Get()->WatchFileDescriptor(
          socket_fd_, true, base::MessagePumpForIO::WATCH_WRITE,
          &write_socket_watcher_, this)) {
    PLOG(ERROR) << "WatchFileDescriptor failed on write";
    return MapSystemError(errno);
  }

  write_buf_ = buf;
  write_buf_len_ = buf_len;
  write_callback_ = std::move(callback);
  return ERR_IO_PENDING;
}

int SocketPosix::GetLocalAddress(SockaddrStorage* address) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(address);

  if (getsockname(socket_fd_, address->addr, &address->addr_len) < 0)
    return MapSystemError(errno);
  return OK;
}

int SocketPosix::GetPeerAddress(SockaddrStorage* address) const {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(address);

  if (!HasPeerAddress())
    return ERR_SOCKET_NOT_CONNECTED;

  *address = *peer_address_;
  return OK;
}

void SocketPosix::SetPeerAddress(const SockaddrStorage& address) {
  DCHECK(thread_checker_.CalledOnValidThread());
  // |peer_address_| will be non-nullptr if Connect() has been called. Unless
  // Close() is called to reset the internal state, a second call to Connect()
  // is not allowed.
  // Please note that we don't allow a second Connect() even if the previous
  // Connect() has failed. Connecting the same |socket_| again after a
  // connection attempt failed results in unspecified behavior according to
  // POSIX.
  DCHECK(!peer_address_);
  peer_address_ = std::make_unique<SockaddrStorage>(address);
}

bool SocketPosix::HasPeerAddress() const {
  DCHECK(thread_checker_.CalledOnValidThread());
  return peer_address_ != nullptr;
}

void SocketPosix::Close() {
  DCHECK(thread_checker_.CalledOnValidThread());

  StopWatchingAndCleanUp(true /* close_socket */);
}

void SocketPosix::DetachFromThread() {
  thread_checker_.DetachFromThread();
}

void SocketPosix::OnFileCanReadWithoutBlocking(int fd) {
  TRACE_EVENT0(NetTracingCategory(),
               "SocketPosix::OnFileCanReadWithoutBlocking");
  if (!accept_callback_.is_null()) {
    AcceptCompleted();
  } else {
    DCHECK(!read_if_ready_callback_.is_null());
    ReadCompleted();
  }
}

void SocketPosix::OnFileCanWriteWithoutBlocking(int fd) {
  DCHECK(!write_callback_.is_null());
  if (waiting_connect_) {
    ConnectCompleted();
  } else {
    WriteCompleted();
  }
}

int SocketPosix::DoAccept(std::unique_ptr<SocketPosix>* socket) {
  SockaddrStorage new_peer_address;
  int new_socket = HANDLE_EINTR(accept(socket_fd_,
                                       new_peer_address.addr,
                                       &new_peer_address.addr_len));
  if (new_socket < 0)
    return MapAcceptError(errno);

  auto accepted_socket = std::make_unique<SocketPosix>();
  int rv = accepted_socket->AdoptConnectedSocket(new_socket, new_peer_address);
  if (rv != OK)
    return rv;

  *socket = std::move(accepted_socket);
  return OK;
}

void SocketPosix::AcceptCompleted() {
  DCHECK(accept_socket_);
  int rv = DoAccept(accept_socket_);
  if (rv == ERR_IO_PENDING)
    return;

  bool ok = accept_socket_watcher_.StopWatchingFileDescriptor();
  DCHECK(ok);
  accept_socket_ = nullptr;
  std::move(accept_callback_).Run(rv);
}

int SocketPosix::DoConnect() {
  int rv = HANDLE_EINTR(connect(socket_fd_,
                                peer_address_->addr,
                                peer_address_->addr_len));
  DCHECK_GE(0, rv);
  return rv == 0 ? OK : MapConnectError(errno);
}

void SocketPosix::ConnectCompleted() {
  // Get the error that connect() completed with.
  int os_error = 0;
  socklen_t len = sizeof(os_error);
  if (getsockopt(socket_fd_, SOL_SOCKET, SO_ERROR, &os_error, &len) == 0) {
    // TCPSocketPosix expects errno to be set.
    errno = os_error;
  }

  int rv = MapConnectError(errno);
  if (rv == ERR_IO_PENDING)
    return;

  bool ok = write_socket_watcher_.StopWatchingFileDescriptor();
  DCHECK(ok);
  waiting_connect_ = false;
  std::move(write_callback_).Run(rv);
}

int SocketPosix::DoRead(IOBuffer* buf, int buf_len) {
  int rv = HANDLE_EINTR(read(socket_fd_, buf->data(), buf_len));
  return rv >= 0 ? rv : MapSystemError(errno);
}

void SocketPosix::RetryRead(int rv) {
  DCHECK(read_callback_);
  DCHECK(read_buf_);
  DCHECK_LT(0, read_buf_len_);

  if (rv == OK) {
    rv = ReadIfReady(
        read_buf_.get(), read_buf_len_,
        base::BindOnce(&SocketPosix::RetryRead, base::Unretained(this)));
    if (rv == ERR_IO_PENDING)
      return;
  }
  read_buf_ = nullptr;
  read_buf_len_ = 0;
  std::move(read_callback_).Run(rv);
}

void SocketPosix::ReadCompleted() {
  DCHECK(read_if_ready_callback_);

  bool ok = read_socket_watcher_.StopWatchingFileDescriptor();
  DCHECK(ok);
  std::move(read_if_ready_callback_).Run(OK);
}

int SocketPosix::DoWrite(IOBuffer* buf, int buf_len) {
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS) || BUILDFLAG(IS_ANDROID)
  // Disable SIGPIPE for this write. Although Chromium globally disables
  // SIGPIPE, the net stack may be used in other consumers which do not do
  // this. MSG_NOSIGNAL is a Linux-only API. On OS X, this is a setsockopt on
  // socket creation.
  int rv = HANDLE_EINTR(send(socket_fd_, buf->data(), buf_len, MSG_NOSIGNAL));
#else
  int rv = HANDLE_EINTR(write(socket_fd_, buf->data(), buf_len));
#endif
  if (rv >= 0) {
    CHECK_LE(rv, buf_len);
  }
  return rv >= 0 ? rv : MapSystemError(errno);
}

void SocketPosix::WriteCompleted() {
  int rv = DoWrite(write_buf_.get(), write_buf_len_);
  if (rv == ERR_IO_PENDING)
    return;

  bool ok = write_socket_watcher_.StopWatchingFileDescriptor();
  DCHECK(ok);
  write_buf_.reset();
  write_buf_len_ = 0;
  std::move(write_callback_).Run(rv);
}

void SocketPosix::StopWatchingAndCleanUp(bool close_socket) {
  bool ok = accept_socket_watcher_.StopWatchingFileDescriptor();
  DCHECK(ok);
  ok = read_socket_watcher_.StopWatchingFileDescriptor();
  DCHECK(ok);
  ok = write_socket_watcher_.StopWatchingFileDescriptor();
  DCHECK(ok);

  // These needs to be done after the StopWatchingFileDescriptor() calls, but
  // before deleting the write buffer.
  if (close_socket) {
    if (socket_fd_ != kInvalidSocket) {
      if (IGNORE_EINTR(close(socket_fd_)) < 0)
        DPLOG(ERROR) << "close() failed";
      socket_fd_ = kInvalidSocket;
    }
  }

  if (!accept_callback_.is_null()) {
    accept_socket_ = nullptr;
    accept_callback_.Reset();
  }

  if (!read_callback_.is_null()) {
    read_buf_.reset();
    read_buf_len_ = 0;
    read_callback_.Reset();
  }

  read_if_ready_callback_.Reset();

  if (!write_callback_.is_null()) {
    write_buf_.reset();
    write_buf_len_ = 0;
    write_callback_.Reset();
  }

  waiting_connect_ = false;
  peer_address_.reset();
}

}  // namespace net

"""

```