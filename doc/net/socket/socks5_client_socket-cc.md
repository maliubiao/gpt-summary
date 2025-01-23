Response:
Let's break down the thought process for analyzing this C++ Chromium network stack code.

1. **Understand the Goal:** The request asks for the functionality of the `SOCKS5ClientSocket`, its relation to JavaScript, logical reasoning examples, common user/programming errors, and how a user's actions lead to this code.

2. **Initial Scan for Keywords and Structure:** Quickly read through the code, looking for key terms like "SOCKS5," "Connect," "Read," "Write," states (like `STATE_GREET_WRITE`), logging (`net_log_`), and any interactions with a "transport socket." This provides a high-level understanding of its purpose.

3. **Identify Core Functionality:** Based on the keywords, the class is clearly a client-side implementation of the SOCKS5 protocol. It wraps another `StreamSocket` (the `transport_socket_`) to establish a connection through a SOCKS5 proxy. The core functions will be connection establishment (handshake) and data transfer (read/write).

4. **Analyze Key Methods:** Focus on the public interface methods:
    * `Connect()`:  This is the entry point for initiating the SOCKS5 connection. Trace its execution flow by looking at what states it sets and what functions it calls (`DoLoop`).
    * `Read()` and `Write()`: These are for sending and receiving data *after* the connection is established. Note the `DCHECK(completed_handshake_)`.
    * `Disconnect()`:  Cleans up the connection.
    * `IsConnected()` and `IsConnectedAndIdle()`:  Check the connection state.
    *  Other getters like `GetNegotiatedProtocol()`, `GetSSLInfo()`, `GetTotalReceivedBytes()`: These delegate to the underlying `transport_socket_`, indicating this class is a wrapper.

5. **Deconstruct the Handshake:** The `DoLoop()` method and the various `STATE_*` constants are crucial. Map out the sequence of states in the SOCKS5 handshake:
    * Greeting (client sends version and supported authentication methods, server responds with selected method).
    * Handshake (client sends connection request, server responds with success or failure).
    * Pay attention to the data formats being sent and received (bytes representing version, command, address type, etc.).

6. **Look for JavaScript Relevance:**  Consider where JavaScript interacts with networking in a browser. JavaScript makes requests (e.g., `fetch`, `XMLHttpRequest`). These requests might need to go through a proxy. The browser's network stack handles the proxy negotiation, and `SOCKS5ClientSocket` would be a component of that. *Crucially, note that JavaScript doesn't directly *call* this C++ code. The browser's internal architecture bridges the gap.*

7. **Construct Logical Reasoning Examples:**
    * **Connect:**  Think about the input (destination host/port) and the expected output (success or a specific error).
    * **Read/Write:**  Consider the data being sent and received. If the handshake fails, read/write shouldn't work.

8. **Identify Potential Errors:**  Look for error conditions and how they're handled:
    * Incorrect SOCKS version.
    * Unsupported authentication methods.
    * Server errors during handshake.
    * Unexpected closure of the connection.
    * Hostname too long.
    * Incorrect state transitions (indicated by `DCHECK` statements).

9. **Trace User Actions:**  Think about a typical browsing scenario:
    * User types a URL.
    * Browser checks proxy settings.
    * If a SOCKS proxy is configured, the browser's network stack will use a `SOCKS5ClientSocket`.
    * The `Connect()` method is called with the proxy address and the target website's address.

10. **Structure the Answer:** Organize the findings into clear sections as requested by the prompt:
    * Functionality overview.
    * JavaScript relationship (emphasizing the indirect connection).
    * Logical reasoning examples with inputs and outputs.
    * Common usage errors.
    * User action tracing.

11. **Refine and Elaborate:** Review the generated text for clarity, accuracy, and completeness. Add details and context where needed. For instance, explain *why* certain errors occur and what the consequences are. Explain the purpose of the different states in the handshake process.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  JavaScript directly uses this class. **Correction:** Realize the browser's architecture and the layers involved. JavaScript uses higher-level APIs, and the browser's networking implementation uses classes like `SOCKS5ClientSocket` internally.
* **Focusing too much on implementation details:**  Remember the prompt asks for *functionality*. While understanding the states is important, avoid getting bogged down in every single line of code. Focus on the *what* and *why*.
* **Not providing concrete examples:**  Initially, the logical reasoning might be too abstract. **Refinement:** Add specific examples of input and output values to illustrate the behavior.
* **Assuming direct user interaction:**  Realize that users don't directly interact with this class. Their actions trigger higher-level browser functions that eventually lead to the use of this class.

By following these steps, combining code analysis with an understanding of networking concepts and browser architecture, a comprehensive and accurate answer can be constructed.
这个 C++ 源代码文件 `socks5_client_socket.cc` 实现了 Chromium 网络栈中的 **SOCKS5 客户端套接字**。它的主要功能是：

**核心功能:**

1. **建立与 SOCKS5 代理服务器的连接:**
   - 它负责与指定的 SOCKS5 代理服务器建立 TCP 连接。
   - 它实现了 SOCKS5 协议的握手过程，包括：
     - **问候阶段 (Greeting Phase):**  客户端发送支持的认证方法列表，服务器选择一种。目前的代码只支持 "no authentication"。
     - **请求阶段 (Request Phase):** 客户端发送连接请求，指定要连接的目标主机和端口。

2. **通过 SOCKS5 代理转发数据:**
   - 一旦与 SOCKS5 代理服务器建立了连接并完成握手，该套接字就可以作为应用程序与目标服务器之间的隧道。
   - 它将应用程序发送的数据转发给 SOCKS5 代理服务器，代理服务器再将数据发送给目标服务器。
   - 它接收来自 SOCKS5 代理服务器的数据，这些数据是目标服务器响应的，然后将其传递给应用程序。

**具体功能点:**

* **封装 `StreamSocket`:** 它使用一个底层的 `StreamSocket` (通常是 `TCPClientSocket`) 来建立与 SOCKS5 代理服务器的 TCP 连接。
* **状态管理:**  使用状态机 (`next_state_`) 来管理 SOCKS5 握手的不同阶段 (例如，`STATE_GREET_WRITE`, `STATE_HANDSHAKE_READ`)。
* **数据缓冲:** 使用 `buffer_` 来存储在握手过程中发送和接收的数据。
* **网络日志记录:** 使用 `net_log_` 记录 SOCKS5 连接过程中的事件，用于调试和监控。
* **流量标注:**  使用 `traffic_annotation_` 来标记通过此套接字发送的网络流量，以便进行策略控制和计费。
* **错误处理:**  处理 SOCKS5 协议相关的错误，例如不支持的认证方法、连接失败等。

**与 Javascript 功能的关系 (间接关系):**

Javascript 在浏览器环境中通常无法直接操作底层的网络套接字。然而，当浏览器需要通过 SOCKS5 代理服务器访问网络资源时，就会涉及到 `SOCKS5ClientSocket` 的使用。

**举例说明:**

1. **用户配置代理:**  用户在浏览器的设置中配置了 SOCKS5 代理服务器的地址和端口。
2. **Javascript 发起网络请求:**  网页上的 Javascript 代码使用 `fetch()` API 或 `XMLHttpRequest` 发起一个到远程服务器的请求 (例如，`fetch('https://example.com')`)。
3. **浏览器路由请求:** 浏览器会检查代理设置，发现需要通过 SOCKS5 代理。
4. **创建 `SOCKS5ClientSocket`:** 浏览器网络栈会创建一个 `SOCKS5ClientSocket` 实例，并将 SOCKS5 代理服务器的地址和目标服务器的地址传递给它。
5. **`SOCKS5ClientSocket` 建立连接:**  `SOCKS5ClientSocket` 内部会执行其 `Connect()` 方法，与 SOCKS5 代理服务器建立连接并完成握手。
6. **数据转发:** 一旦连接建立，当 Javascript 发起的请求需要发送数据时，浏览器会将数据交给 `SOCKS5ClientSocket`，它会通过代理转发。同样，从目标服务器返回的数据也会通过 `SOCKS5ClientSocket` 传递回浏览器，最终交给 Javascript。

**总结:** Javascript 本身不直接调用 `SOCKS5ClientSocket` 的方法。 它的作用是发起网络请求。浏览器作为运行环境，会根据配置决定是否使用 SOCKS5 代理，如果使用，就会在底层使用 `SOCKS5ClientSocket` 来处理与代理服务器的通信。

**逻辑推理 (假设输入与输出):**

**场景:**  尝试通过 SOCKS5 代理连接到 `example.com:80`。

**假设输入:**
* `destination_`: HostPortPair("example.com", 80)
* SOCKS5 代理服务器地址: `proxy.example.net:1080` (假设底层 `transport_socket_` 已经连接到这个地址)

**步骤和预期输出:**

1. **`Connect()` 调用:**  `SOCKS5ClientSocket::Connect()` 被调用。
2. **`STATE_GREET_WRITE`:**  发送问候消息 `{0x05, 0x01, 0x00}` (SOCKS5 版本, 支持 1 种认证方法, No Authentication)。
   * **预期输出:**  底层 `transport_socket_` 发送这 3 个字节的数据到代理服务器。
3. **`STATE_GREET_READ`:**  等待代理服务器的问候响应。
   * **假设代理服务器响应成功:** 接收到 `{0x05, 0x00}` (SOCKS5 版本, 选择 No Authentication)。
   * **预期输出:**  `DoGreetReadComplete()` 检查版本和认证方法，如果匹配，进入下一个状态。
4. **`STATE_HANDSHAKE_WRITE`:**  构建并发送连接请求。
   * **构建握手消息:**  `BuildHandshakeWriteBuffer()` 会构建类似这样的消息 (假设 example.com 的长度为 11):
     `{0x05, 0x01, 0x00, 0x03, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x50}`
     (版本, Connect 命令, 保留, 域名地址类型, 域名长度, 域名, 端口 80 的网络字节序表示)。
   * **预期输出:** 底层 `transport_socket_` 发送构建的握手消息。
5. **`STATE_HANDSHAKE_READ`:** 等待代理服务器的连接响应。
   * **假设代理服务器连接成功:** 接收到类似 `{0x05, 0x00, 0x00, 0x01, 192, 168, 1, 100, 0x00, 0x50}` 的响应 (版本, 成功, 保留, IPv4 地址类型,  代理连接到的目标服务器的 IP 地址, 端口)。
   * **预期输出:** `DoHandshakeReadComplete()` 检查响应状态，如果成功 (`0x00`)，则 `completed_handshake_` 设置为 `true`。
6. **连接完成:** `Connect()` 方法返回 `OK`。

**假设输入导致错误:**

* **代理服务器不支持 No Authentication:** 在 `STATE_GREET_READ` 阶段，代理服务器可能返回 `{0x05, 0xFF}` 表示不支持客户端提供的认证方法。
   * **预期输出:** `DoGreetReadComplete()` 会检测到 `buffer_[1]` 不是 `0x00`，记录错误日志，并返回 `ERR_SOCKS_CONNECTION_FAILED`。

**用户或编程常见的使用错误:**

1. **配置错误的代理服务器地址或端口:**  如果传递给 `SOCKS5ClientSocket` 构造函数的代理服务器地址或端口不正确，则底层 `transport_socket_` 的连接会失败，导致 SOCKS5 连接也无法建立。
   * **例子:**  用户在浏览器中输入了错误的代理 IP 地址。
   * **结果:** `transport_socket_->Connect()` 返回错误，`SOCKS5ClientSocket::Connect()` 也会返回错误。

2. **目标主机名过长:** SOCKS5 协议使用一个字节来表示目标主机名的长度。如果目标主机名超过 255 个字符，则无法构建握手消息。
   * **例子:**  尝试连接到一个非常长的域名，例如 `verylonghostname------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------.com`。
   * **结果:**  在 `DoGreetWrite()` 中，会检查 `destination_.host().size()`，如果超过 255，则会记录 `NetLogEventType::SOCKS_HOSTNAME_TOO_BIG` 事件，并返回 `ERR_SOCKS_CONNECTION_FAILED`。

3. **在握手完成前尝试读写数据:**  `Read()` 和 `Write()` 方法内部有 `DCHECK(completed_handshake_)` 的断言。如果在 `Connect()` 返回 `OK` 之前就调用这两个方法，程序会崩溃 (在 Debug 构建中)。
   * **例子:**  应用程序在收到 `Connect()` 的回调之前，就尝试使用该套接字发送数据。
   * **结果:**  断言失败，程序崩溃。

4. **未正确处理连接错误:**  应用程序可能没有正确处理 `Connect()` 方法返回的错误码，导致程序行为异常。
   * **例子:**  `Connect()` 返回 `ERR_PROXY_CONNECTION_FAILED`，但应用程序没有捕获并处理这个错误，仍然尝试使用该套接字。
   * **结果:** 后续的读写操作可能会失败或导致未定义的行为。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户想要访问 `https://www.example.com` 并且配置了 SOCKS5 代理。

1. **用户在浏览器地址栏输入 `https://www.example.com` 并按下回车。**
2. **浏览器解析 URL 并确定需要建立 HTTPS 连接。**
3. **浏览器检查代理设置。** 假设用户在浏览器设置中配置了 SOCKS5 代理服务器 `proxy.mycompany.com:1080`。
4. **浏览器网络栈决定使用 SOCKS5 代理连接目标服务器。**
5. **Chromium 网络栈会创建一个 `SOCKS5ClientSocket` 实例。**
   - 构造函数的参数包括：
     - 一个用于连接到代理服务器的 `StreamSocket` (可能是一个 `TCPClientSocket`，已经连接到 `proxy.mycompany.com:1080`)。
     - 目标主机和端口 `HostPortPair("www.example.com", 443)` (因为是 HTTPS)。
     - 相关的流量标注信息。
6. **调用 `SOCKS5ClientSocket::Connect()` 方法。** 这会启动 SOCKS5 握手过程，与 `proxy.mycompany.com:1080` 建立连接，并告知代理服务器要连接到 `www.example.com:443`。
7. **在 `Connect()` 方法的执行过程中，会依次进入不同的状态 (如上面逻辑推理部分所示)。**  可以通过查看网络日志 (`net_log_`) 来跟踪这些状态转换和发送/接收的数据。
8. **如果握手成功，`Connect()` 方法返回 `OK`。**
9. **浏览器就可以使用这个 `SOCKS5ClientSocket` 来发送 HTTPS 请求到 `www.example.com`，数据会通过 SOCKS5 代理转发。**
10. **如果握手失败，`Connect()` 方法会返回一个错误码 (例如 `ERR_SOCKS_CONNECTION_FAILED`)。**  可以通过查看网络日志来确定失败的原因 (例如，代理服务器拒绝连接，认证失败等)。

**调试线索:**

* **网络日志 (`chrome://net-export/`):**  这是最重要的调试工具。可以记录详细的网络事件，包括 SOCKS5 握手的每个步骤、发送和接收的数据、以及发生的错误。
* **断点调试:** 在 `SOCKS5ClientSocket` 的关键方法 (例如 `Connect()`, `DoLoop()`, `DoGreetWrite()`, `DoHandshakeReadComplete()`) 设置断点，可以单步执行代码，查看变量的值，理解握手过程中的数据交换和状态变化。
* **抓包工具 (如 Wireshark):** 可以抓取与 SOCKS5 代理服务器之间的网络包，查看实际发送和接收的 SOCKS5 协议数据，验证代码的实现是否符合协议规范。

总而言之，`socks5_client_socket.cc` 是 Chromium 网络栈中实现 SOCKS5 客户端功能的核心组件，它使得浏览器能够通过 SOCKS5 代理服务器访问互联网资源。理解其功能和工作原理对于调试网络连接问题至关重要。

### 提示词
```
这是目录为net/socket/socks5_client_socket.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/socket/socks5_client_socket.h"

#include <utility>

#include "base/compiler_specific.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/strings/string_util.h"
#include "base/sys_byteorder.h"
#include "net/base/io_buffer.h"
#include "net/base/sys_addrinfo.h"
#include "net/base/tracing.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace net {

const unsigned int SOCKS5ClientSocket::kGreetReadHeaderSize = 2;
const unsigned int SOCKS5ClientSocket::kWriteHeaderSize = 10;
const unsigned int SOCKS5ClientSocket::kReadHeaderSize = 5;
const uint8_t SOCKS5ClientSocket::kSOCKS5Version = 0x05;
const uint8_t SOCKS5ClientSocket::kTunnelCommand = 0x01;
const uint8_t SOCKS5ClientSocket::kNullByte = 0x00;

static_assert(sizeof(struct in_addr) == 4, "incorrect system size of IPv4");
static_assert(sizeof(struct in6_addr) == 16, "incorrect system size of IPv6");

SOCKS5ClientSocket::SOCKS5ClientSocket(
    std::unique_ptr<StreamSocket> transport_socket,
    const HostPortPair& destination,
    const NetworkTrafficAnnotationTag& traffic_annotation)
    : io_callback_(base::BindRepeating(&SOCKS5ClientSocket::OnIOComplete,
                                       base::Unretained(this))),
      transport_socket_(std::move(transport_socket)),
      read_header_size(kReadHeaderSize),
      destination_(destination),
      net_log_(transport_socket_->NetLog()),
      traffic_annotation_(traffic_annotation) {}

SOCKS5ClientSocket::~SOCKS5ClientSocket() {
  Disconnect();
}

int SOCKS5ClientSocket::Connect(CompletionOnceCallback callback) {
  DCHECK(transport_socket_);
  DCHECK_EQ(STATE_NONE, next_state_);
  DCHECK(user_callback_.is_null());

  // If already connected, then just return OK.
  if (completed_handshake_)
    return OK;

  net_log_.BeginEvent(NetLogEventType::SOCKS5_CONNECT);

  next_state_ = STATE_GREET_WRITE;
  buffer_.clear();

  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING) {
    user_callback_ = std::move(callback);
  } else {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::SOCKS5_CONNECT, rv);
  }
  return rv;
}

void SOCKS5ClientSocket::Disconnect() {
  completed_handshake_ = false;
  transport_socket_->Disconnect();

  // Reset other states to make sure they aren't mistakenly used later.
  // These are the states initialized by Connect().
  next_state_ = STATE_NONE;
  user_callback_.Reset();
}

bool SOCKS5ClientSocket::IsConnected() const {
  return completed_handshake_ && transport_socket_->IsConnected();
}

bool SOCKS5ClientSocket::IsConnectedAndIdle() const {
  return completed_handshake_ && transport_socket_->IsConnectedAndIdle();
}

const NetLogWithSource& SOCKS5ClientSocket::NetLog() const {
  return net_log_;
}

bool SOCKS5ClientSocket::WasEverUsed() const {
  return was_ever_used_;
}

NextProto SOCKS5ClientSocket::GetNegotiatedProtocol() const {
  if (transport_socket_)
    return transport_socket_->GetNegotiatedProtocol();
  NOTREACHED();
}

bool SOCKS5ClientSocket::GetSSLInfo(SSLInfo* ssl_info) {
  if (transport_socket_)
    return transport_socket_->GetSSLInfo(ssl_info);
  NOTREACHED();
}

int64_t SOCKS5ClientSocket::GetTotalReceivedBytes() const {
  return transport_socket_->GetTotalReceivedBytes();
}

void SOCKS5ClientSocket::ApplySocketTag(const SocketTag& tag) {
  return transport_socket_->ApplySocketTag(tag);
}

// Read is called by the transport layer above to read. This can only be done
// if the SOCKS handshake is complete.
int SOCKS5ClientSocket::Read(IOBuffer* buf,
                             int buf_len,
                             CompletionOnceCallback callback) {
  DCHECK(completed_handshake_);
  DCHECK_EQ(STATE_NONE, next_state_);
  DCHECK(user_callback_.is_null());
  DCHECK(!callback.is_null());

  int rv = transport_socket_->Read(
      buf, buf_len,
      base::BindOnce(&SOCKS5ClientSocket::OnReadWriteComplete,
                     base::Unretained(this), std::move(callback)));
  if (rv > 0)
    was_ever_used_ = true;
  return rv;
}

// Write is called by the transport layer. This can only be done if the
// SOCKS handshake is complete.
int SOCKS5ClientSocket::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(completed_handshake_);
  DCHECK_EQ(STATE_NONE, next_state_);
  DCHECK(user_callback_.is_null());
  DCHECK(!callback.is_null());

  int rv = transport_socket_->Write(
      buf, buf_len,
      base::BindOnce(&SOCKS5ClientSocket::OnReadWriteComplete,
                     base::Unretained(this), std::move(callback)),
      traffic_annotation);
  if (rv > 0)
    was_ever_used_ = true;
  return rv;
}

int SOCKS5ClientSocket::SetReceiveBufferSize(int32_t size) {
  return transport_socket_->SetReceiveBufferSize(size);
}

int SOCKS5ClientSocket::SetSendBufferSize(int32_t size) {
  return transport_socket_->SetSendBufferSize(size);
}

void SOCKS5ClientSocket::DoCallback(int result) {
  DCHECK_NE(ERR_IO_PENDING, result);
  DCHECK(!user_callback_.is_null());

  // Since Run() may result in Read being called,
  // clear user_callback_ up front.
  std::move(user_callback_).Run(result);
}

void SOCKS5ClientSocket::OnIOComplete(int result) {
  DCHECK_NE(STATE_NONE, next_state_);
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    net_log_.EndEvent(NetLogEventType::SOCKS5_CONNECT);
    DoCallback(rv);
  }
}

void SOCKS5ClientSocket::OnReadWriteComplete(CompletionOnceCallback callback,
                                             int result) {
  DCHECK_NE(ERR_IO_PENDING, result);
  DCHECK(!callback.is_null());

  if (result > 0)
    was_ever_used_ = true;
  std::move(callback).Run(result);
}

int SOCKS5ClientSocket::DoLoop(int last_io_result) {
  DCHECK_NE(next_state_, STATE_NONE);
  int rv = last_io_result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_GREET_WRITE:
        DCHECK_EQ(OK, rv);
        net_log_.BeginEvent(NetLogEventType::SOCKS5_GREET_WRITE);
        rv = DoGreetWrite();
        break;
      case STATE_GREET_WRITE_COMPLETE:
        rv = DoGreetWriteComplete(rv);
        net_log_.EndEventWithNetErrorCode(NetLogEventType::SOCKS5_GREET_WRITE,
                                          rv);
        break;
      case STATE_GREET_READ:
        DCHECK_EQ(OK, rv);
        net_log_.BeginEvent(NetLogEventType::SOCKS5_GREET_READ);
        rv = DoGreetRead();
        break;
      case STATE_GREET_READ_COMPLETE:
        rv = DoGreetReadComplete(rv);
        net_log_.EndEventWithNetErrorCode(NetLogEventType::SOCKS5_GREET_READ,
                                          rv);
        break;
      case STATE_HANDSHAKE_WRITE:
        DCHECK_EQ(OK, rv);
        net_log_.BeginEvent(NetLogEventType::SOCKS5_HANDSHAKE_WRITE);
        rv = DoHandshakeWrite();
        break;
      case STATE_HANDSHAKE_WRITE_COMPLETE:
        rv = DoHandshakeWriteComplete(rv);
        net_log_.EndEventWithNetErrorCode(
            NetLogEventType::SOCKS5_HANDSHAKE_WRITE, rv);
        break;
      case STATE_HANDSHAKE_READ:
        DCHECK_EQ(OK, rv);
        net_log_.BeginEvent(NetLogEventType::SOCKS5_HANDSHAKE_READ);
        rv = DoHandshakeRead();
        break;
      case STATE_HANDSHAKE_READ_COMPLETE:
        rv = DoHandshakeReadComplete(rv);
        net_log_.EndEventWithNetErrorCode(
            NetLogEventType::SOCKS5_HANDSHAKE_READ, rv);
        break;
      default:
        NOTREACHED() << "bad state";
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);
  return rv;
}

const char kSOCKS5GreetWriteData[] = { 0x05, 0x01, 0x00 };  // no authentication

int SOCKS5ClientSocket::DoGreetWrite() {
  // Since we only have 1 byte to send the hostname length in, if the
  // URL has a hostname longer than 255 characters we can't send it.
  if (0xFF < destination_.host().size()) {
    net_log_.AddEvent(NetLogEventType::SOCKS_HOSTNAME_TOO_BIG);
    return ERR_SOCKS_CONNECTION_FAILED;
  }

  if (buffer_.empty()) {
    buffer_ =
        std::string(kSOCKS5GreetWriteData, std::size(kSOCKS5GreetWriteData));
    bytes_sent_ = 0;
  }

  next_state_ = STATE_GREET_WRITE_COMPLETE;
  size_t handshake_buf_len = buffer_.size() - bytes_sent_;
  handshake_buf_ = base::MakeRefCounted<IOBufferWithSize>(handshake_buf_len);
  memcpy(handshake_buf_->data(), &buffer_.data()[bytes_sent_],
         handshake_buf_len);
  return transport_socket_->Write(handshake_buf_.get(), handshake_buf_len,
                                  io_callback_, traffic_annotation_);
}

int SOCKS5ClientSocket::DoGreetWriteComplete(int result) {
  if (result < 0)
    return result;

  bytes_sent_ += result;
  if (bytes_sent_ == buffer_.size()) {
    buffer_.clear();
    bytes_received_ = 0;
    next_state_ = STATE_GREET_READ;
  } else {
    next_state_ = STATE_GREET_WRITE;
  }
  return OK;
}

int SOCKS5ClientSocket::DoGreetRead() {
  next_state_ = STATE_GREET_READ_COMPLETE;
  size_t handshake_buf_len = kGreetReadHeaderSize - bytes_received_;
  handshake_buf_ = base::MakeRefCounted<IOBufferWithSize>(handshake_buf_len);
  return transport_socket_->Read(handshake_buf_.get(), handshake_buf_len,
                                 io_callback_);
}

int SOCKS5ClientSocket::DoGreetReadComplete(int result) {
  if (result < 0)
    return result;

  if (result == 0) {
    net_log_.AddEvent(
        NetLogEventType::SOCKS_UNEXPECTEDLY_CLOSED_DURING_GREETING);
    return ERR_SOCKS_CONNECTION_FAILED;
  }

  bytes_received_ += result;
  buffer_.append(handshake_buf_->data(), result);
  if (bytes_received_ < kGreetReadHeaderSize) {
    next_state_ = STATE_GREET_READ;
    return OK;
  }

  // Got the greet data.
  if (buffer_[0] != kSOCKS5Version) {
    net_log_.AddEventWithIntParams(NetLogEventType::SOCKS_UNEXPECTED_VERSION,
                                   "version", buffer_[0]);
    return ERR_SOCKS_CONNECTION_FAILED;
  }
  if (buffer_[1] != 0x00) {
    net_log_.AddEventWithIntParams(NetLogEventType::SOCKS_UNEXPECTED_AUTH,
                                   "method", buffer_[1]);
    return ERR_SOCKS_CONNECTION_FAILED;
  }

  buffer_.clear();
  next_state_ = STATE_HANDSHAKE_WRITE;
  return OK;
}

int SOCKS5ClientSocket::BuildHandshakeWriteBuffer(std::string* handshake)
    const {
  DCHECK(handshake->empty());

  handshake->push_back(kSOCKS5Version);
  handshake->push_back(kTunnelCommand);  // Connect command
  handshake->push_back(kNullByte);  // Reserved null

  handshake->push_back(kEndPointDomain);  // The type of the address.

  DCHECK_GE(static_cast<size_t>(0xFF), destination_.host().size());

  // First add the size of the hostname, followed by the hostname.
  handshake->push_back(static_cast<unsigned char>(destination_.host().size()));
  handshake->append(destination_.host());

  uint16_t nw_port = base::HostToNet16(destination_.port());
  handshake->append(reinterpret_cast<char*>(&nw_port), sizeof(nw_port));
  return OK;
}

// Writes the SOCKS handshake data to the underlying socket connection.
int SOCKS5ClientSocket::DoHandshakeWrite() {
  next_state_ = STATE_HANDSHAKE_WRITE_COMPLETE;

  if (buffer_.empty()) {
    int rv = BuildHandshakeWriteBuffer(&buffer_);
    if (rv != OK)
      return rv;
    bytes_sent_ = 0;
  }

  int handshake_buf_len = buffer_.size() - bytes_sent_;
  DCHECK_LT(0, handshake_buf_len);
  handshake_buf_ = base::MakeRefCounted<IOBufferWithSize>(handshake_buf_len);
  memcpy(handshake_buf_->data(), &buffer_[bytes_sent_],
         handshake_buf_len);
  return transport_socket_->Write(handshake_buf_.get(), handshake_buf_len,
                                  io_callback_, traffic_annotation_);
}

int SOCKS5ClientSocket::DoHandshakeWriteComplete(int result) {
  if (result < 0)
    return result;

  // We ignore the case when result is 0, since the underlying Write
  // may return spurious writes while waiting on the socket.

  bytes_sent_ += result;
  if (bytes_sent_ == buffer_.size()) {
    next_state_ = STATE_HANDSHAKE_READ;
    buffer_.clear();
  } else if (bytes_sent_ < buffer_.size()) {
    next_state_ = STATE_HANDSHAKE_WRITE;
  } else {
    NOTREACHED();
  }

  return OK;
}

int SOCKS5ClientSocket::DoHandshakeRead() {
  next_state_ = STATE_HANDSHAKE_READ_COMPLETE;

  if (buffer_.empty()) {
    bytes_received_ = 0;
    read_header_size = kReadHeaderSize;
  }

  int handshake_buf_len = read_header_size - bytes_received_;
  handshake_buf_ = base::MakeRefCounted<IOBufferWithSize>(handshake_buf_len);
  return transport_socket_->Read(handshake_buf_.get(), handshake_buf_len,
                                 io_callback_);
}

int SOCKS5ClientSocket::DoHandshakeReadComplete(int result) {
  if (result < 0)
    return result;

  // The underlying socket closed unexpectedly.
  if (result == 0) {
    net_log_.AddEvent(
        NetLogEventType::SOCKS_UNEXPECTEDLY_CLOSED_DURING_HANDSHAKE);
    return ERR_SOCKS_CONNECTION_FAILED;
  }

  buffer_.append(handshake_buf_->data(), result);
  bytes_received_ += result;

  // When the first few bytes are read, check how many more are required
  // and accordingly increase them
  if (bytes_received_ == kReadHeaderSize) {
    if (buffer_[0] != kSOCKS5Version || buffer_[2] != kNullByte) {
      net_log_.AddEventWithIntParams(NetLogEventType::SOCKS_UNEXPECTED_VERSION,
                                     "version", buffer_[0]);
      return ERR_SOCKS_CONNECTION_FAILED;
    }
    if (buffer_[1] != 0x00) {
      net_log_.AddEventWithIntParams(NetLogEventType::SOCKS_SERVER_ERROR,
                                     "error_code", buffer_[1]);
      return ERR_SOCKS_CONNECTION_FAILED;
    }

    // We check the type of IP/Domain the server returns and accordingly
    // increase the size of the response. For domains, we need to read the
    // size of the domain, so the initial request size is upto the domain
    // size. Since for IPv4/IPv6 the size is fixed and hence no 'size' is
    // read, we substract 1 byte from the additional request size.
    SocksEndPointAddressType address_type =
        static_cast<SocksEndPointAddressType>(buffer_[3]);
    if (address_type == kEndPointDomain) {
      read_header_size += static_cast<uint8_t>(buffer_[4]);
    } else if (address_type == kEndPointResolvedIPv4) {
      read_header_size += sizeof(struct in_addr) - 1;
    } else if (address_type == kEndPointResolvedIPv6) {
      read_header_size += sizeof(struct in6_addr) - 1;
    } else {
      net_log_.AddEventWithIntParams(
          NetLogEventType::SOCKS_UNKNOWN_ADDRESS_TYPE, "address_type",
          buffer_[3]);
      return ERR_SOCKS_CONNECTION_FAILED;
    }

    read_header_size += 2;  // for the port.
    next_state_ = STATE_HANDSHAKE_READ;
    return OK;
  }

  // When the final bytes are read, setup handshake. We ignore the rest
  // of the response since they represent the SOCKSv5 endpoint and have
  // no use when doing a tunnel connection.
  if (bytes_received_ == read_header_size) {
    completed_handshake_ = true;
    buffer_.clear();
    next_state_ = STATE_NONE;
    return OK;
  }

  next_state_ = STATE_HANDSHAKE_READ;
  return OK;
}

int SOCKS5ClientSocket::GetPeerAddress(IPEndPoint* address) const {
  return transport_socket_->GetPeerAddress(address);
}

int SOCKS5ClientSocket::GetLocalAddress(IPEndPoint* address) const {
  return transport_socket_->GetLocalAddress(address);
}

}  // namespace net
```