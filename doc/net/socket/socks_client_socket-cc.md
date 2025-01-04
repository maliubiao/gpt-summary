Response:
Let's break down the thought process for analyzing this code and generating the response.

1. **Understand the Core Purpose:** The first step is to read the initial comments and the class name: `SOCKSClientSocket`. This immediately tells you this code is about implementing a SOCKS client, specifically for establishing connections through a SOCKS proxy. The file path `net/socket/socks_client_socket.cc` reinforces this.

2. **Identify Key Components and Data Structures:**  Scan the code for important members and data structures. Notice:
    * `#include` directives:  These point to dependencies and provide clues about what the class uses (e.g., `StreamSocket`, `HostResolver`, `IOBuffer`).
    * Static constants:  `kEmptyUserId`, `kWriteHeaderSize`, `kReadHeaderSize`, `kServerResponse*`, `kSOCKSVersion4`, `kSOCKSStreamRequest`. These define the SOCKS protocol specifics.
    * Structs: `SOCKS4ServerRequest` and `SOCKS4ServerResponse`. These are the data formats for communication with the SOCKS server.
    * Member variables: `transport_socket_`, `host_resolver_`, `destination_`, `network_anonymization_key_`, `priority_`, `net_log_`, `traffic_annotation_`,  `completed_handshake_`, `resolve_host_request_`, `next_state_`, `user_callback_`, `buffer_`, `bytes_sent_`, `bytes_received_`, `handshake_buf_`, `resolve_error_info_`, `was_ever_used_`. These represent the state and dependencies of the `SOCKSClientSocket`.
    * Enumerated states (implicitly through `next_state_`): `STATE_NONE`, `STATE_RESOLVE_HOST`, `STATE_RESOLVE_HOST_COMPLETE`, `STATE_HANDSHAKE_WRITE`, `STATE_HANDSHAKE_WRITE_COMPLETE`, `STATE_HANDSHAKE_READ`, `STATE_HANDSHAKE_READ_COMPLETE`. This indicates a state machine approach for the connection process.

3. **Trace the Connection Flow (State Machine):** The `Connect()` method is the entry point for establishing a connection. Follow the state transitions driven by `DoLoop()` and the various `Do...` methods. Visualize the sequence:
    * `STATE_RESOLVE_HOST`: Resolve the target hostname.
    * `STATE_RESOLVE_HOST_COMPLETE`: Handle the resolution result.
    * `STATE_HANDSHAKE_WRITE`: Send the SOCKS handshake request.
    * `STATE_HANDSHAKE_WRITE_COMPLETE`: Handle the write result.
    * `STATE_HANDSHAKE_READ`: Read the SOCKS handshake response.
    * `STATE_HANDSHAKE_READ_COMPLETE`: Process the response.

4. **Analyze Individual Methods:**  Understand the purpose of each public and significant private method:
    * `Connect()`: Initiates the connection.
    * `Disconnect()`: Closes the connection.
    * `IsConnected()`, `IsConnectedAndIdle()`: Check connection status.
    * `Read()`, `Write()`:  Send and receive data after the handshake.
    * `DoResolveHost()`, `DoResolveHostComplete()`: Implement hostname resolution.
    * `BuildHandshakeWriteBuffer()`: Constructs the SOCKS request message.
    * `DoHandshakeWrite()`, `DoHandshakeWriteComplete()`: Send the handshake request.
    * `DoHandshakeRead()`, `DoHandshakeReadComplete()`: Receive and process the handshake response.
    * `DoCallback()`, `OnIOComplete()`, `OnReadWriteComplete()`: Handle asynchronous operations and callbacks.

5. **Identify Relationships with JavaScript (if any):**  Consider where this code fits in the broader Chromium architecture. Network requests initiated in the browser's JavaScript engine will eventually reach the network stack. The `SOCKSClientSocket` is responsible for handling the SOCKS proxy part of such requests. The connection happens *below* the JavaScript layer, but JavaScript configuration (like setting a proxy) *influences* whether this code is executed.

6. **Think About Logic and Assumptions:**
    * **Input:**  A `HostPortPair` representing the target destination, a pre-existing `StreamSocket` to the SOCKS proxy, and other configuration parameters.
    * **Output:**  Success (connection established) or failure (various `ERR_` codes).
    * **Assumptions:** The code assumes a SOCKS4 proxy. It explicitly disables IPv6 resolution because SOCKS4 doesn't natively support it.

7. **Consider Potential Errors:** Look for error handling and common issues:
    * DNS resolution failures.
    * Connection refused by the SOCKS server.
    * Incorrect SOCKS server responses.
    * Underlying socket errors.

8. **Trace User Actions:** Think about how a user's actions lead to this code being executed. The key is understanding the proxy configuration.

9. **Structure the Response:** Organize the information logically according to the prompt's requests:
    * Functionality overview.
    * Relationship to JavaScript.
    * Logic and examples.
    * Common errors.
    * Debugging steps.

10. **Refine and Elaborate:** Add details and explanations to make the response clear and comprehensive. For example, explain the state machine concept, the meaning of the SOCKS protocol constants, and the error codes.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe this code directly interacts with JavaScript.
* **Correction:** Realize the interaction is indirect. JavaScript sets proxy settings, which then cause the network stack to use `SOCKSClientSocket`. The direct communication is lower-level.
* **Initial thought:** Focus only on the happy path of a successful connection.
* **Correction:**  Pay attention to error handling and the various failure scenarios described by the `ERR_` codes. These are important for understanding the robustness of the code.
* **Initial thought:**  Describe every single line of code.
* **Correction:** Focus on the key functionalities and the overall flow. Highlighting the state machine is more valuable than explaining every assignment.

By following these steps, combining code analysis with a high-level understanding of the networking stack, one can effectively analyze and explain the functionality of this `SOCKSClientSocket` code.
好的，让我们来详细分析一下 `net/socket/socks_client_socket.cc` 这个 Chromium 网络栈的源代码文件。

**功能概述:**

`SOCKSClientSocket` 类的主要功能是实现一个 SOCKS 协议的客户端套接字。更具体地说，它实现了 SOCKS4 版本的客户端。其核心职责是在现有的 `StreamSocket` (通常是一个 TCP 连接) 的基础上，与 SOCKS 服务器进行握手，以便后续的网络请求可以通过该 SOCKS 代理服务器进行。

主要功能点包括：

1. **建立与 SOCKS 服务器的连接：** 通过传入的 `transport_socket_` (已经连接到 SOCKS 服务器的套接字) 进行通信。
2. **SOCKS4 握手协议实现：**
   - **主机名解析：** 解析目标主机的 IP 地址，因为 SOCKS4 协议直接使用 IP 地址（虽然也存在 SOCKS4a 扩展，但此代码似乎只实现了 SOCKS4）。
   - **发送握手请求：**  构建并发送符合 SOCKS4 协议的连接请求报文，包括版本号、命令（连接请求）、目标端口和目标 IP 地址。
   - **接收握手响应：**  接收来自 SOCKS 服务器的响应报文，并根据响应码判断连接是否成功。
3. **数据传输：**  在握手成功后，将上层协议的数据通过与 SOCKS 服务器建立的隧道进行读写。`SOCKSClientSocket` 本身不处理应用层协议，它只是作为一个管道。
4. **错误处理：**  处理 SOCKS 握手过程中的各种错误，例如连接被拒绝、主机不可达、用户 ID 不匹配等。
5. **日志记录：** 使用 `net_log_` 记录 SOCKS 连接过程中的事件，用于调试和监控。

**与 JavaScript 功能的关系及举例:**

`SOCKSClientSocket` 本身是用 C++ 编写的，JavaScript 代码不能直接调用它。但是，JavaScript 可以通过 Chromium 浏览器提供的 API (例如 `fetch` 或 `XMLHttpRequest`) 发起网络请求。当浏览器配置了使用 SOCKS 代理时，网络栈会根据配置使用 `SOCKSClientSocket` 来处理这些请求。

**举例说明：**

假设用户在浏览器的设置中配置了使用 SOCKS4 代理服务器，地址为 `socks4://192.168.1.100:1080`。

1. **JavaScript 发起请求：**  页面中的 JavaScript 代码执行了 `fetch('https://www.example.com')`。
2. **浏览器网络栈介入：** 浏览器网络栈检测到需要使用 SOCKS 代理。
3. **建立到 SOCKS 服务器的连接：** 网络栈会先建立一个 TCP 连接到 `192.168.1.100:1080`。这个连接对应了 `SOCKSClientSocket` 构造函数中传入的 `transport_socket_`。
4. **创建 `SOCKSClientSocket` 对象：**  Chromium 会创建一个 `SOCKSClientSocket` 对象，并将已经建立的到 SOCKS 服务器的 `StreamSocket` 传递给它。同时，也会传递目标地址 `www.example.com` 和端口 `443`。
5. **`SOCKSClientSocket::Connect()` 被调用：**  开始执行 SOCKS4 握手过程。
   - **`STATE_RESOLVE_HOST`:**  `SOCKSClientSocket` 会尝试解析 `www.example.com` 的 IP 地址。
   - **`STATE_HANDSHAKE_WRITE`:**  构建 SOCKS4 连接请求报文，例如：
     ```
     Version: 0x04
     Command: 0x01 (Connect)
     Port:    网络字节序的 443 (0x01BB)
     IP:      解析出的 www.example.com 的 IPv4 地址 (假设是 192.0.2.1，则为 0xC0000201)
     UserID:  "" (空字符串)
     NULL byte: 0x00
     ```
     并将这个报文通过 `transport_socket_` 发送给 SOCKS 服务器。
   - **`STATE_HANDSHAKE_READ`:**  等待并接收来自 SOCKS 服务器的 8 字节响应报文。
   - **`STATE_HANDSHAKE_READ_COMPLETE`:**  解析响应报文。如果响应码是 `0x5A` (kServerResponseOk)，则握手成功，`completed_handshake_` 被设置为 `true`。
6. **数据传输：**  握手成功后，当 JavaScript 发起的 `fetch` 请求需要发送 HTTP 请求头和数据时，这些数据会通过 `SOCKSClientSocket::Write()` 方法发送给 SOCKS 服务器。同样，服务器返回的响应数据会通过 `SOCKSClientSocket::Read()` 方法接收。

**逻辑推理的假设输入与输出:**

**假设输入：**

- `transport_socket_`: 一个已经连接到 SOCKS4 服务器 `192.168.1.100:1080` 的 `StreamSocket` 对象。
- `destination_`:  `HostPortPair("www.example.com", 443)`。
- `host_resolver_`: 一个能够解析主机名的 `HostResolver` 对象。

**模拟 `DoLoop` 过程：**

1. **`STATE_RESOLVE_HOST`:**
   - **假设输入:** `destination_` 为 `www.example.com:443`。
   - **操作:** 调用 `host_resolver_->CreateRequest()` 发起 DNS 解析请求。
   - **假设输出:** DNS 解析成功，`resolve_host_request_->GetAddressResults()` 返回一个包含 `192.0.2.1` 的 `AddressList`。
2. **`STATE_RESOLVE_HOST_COMPLETE`:**
   - **假设输入:**  DNS 解析结果为成功 (`OK`)。
   - **操作:**  将 `next_state_` 设置为 `STATE_HANDSHAKE_WRITE`。
   - **输出:** `OK`。
3. **`STATE_HANDSHAKE_WRITE`:**
   - **假设输入:**  `destination_.port()` 为 `443`，解析出的 IP 地址为 `192.0.2.1`。
   - **操作:** 调用 `BuildHandshakeWriteBuffer()` 构建握手请求报文。
   - **假设输出:**  `buffer_` 包含 SOCKS4 连接请求的字节流 (如上例所示)。调用 `transport_socket_->Write()` 发送数据。
4. **`STATE_HANDSHAKE_WRITE_COMPLETE`:**
   - **假设输入:** `transport_socket_->Write()` 返回发送的字节数，假设一次性发送完成。
   - **操作:** 将 `next_state_` 设置为 `STATE_HANDSHAKE_READ`。
   - **输出:** `OK`。
5. **`STATE_HANDSHAKE_READ`:**
   - **操作:** 调用 `transport_socket_->Read()` 尝试读取 8 字节的 SOCKS 服务器响应。
6. **`STATE_HANDSHAKE_READ_COMPLETE`:**
   - **假设输入:** `transport_socket_->Read()` 成功读取到 8 字节的响应，例如 `0x00 0x5A 0xXX 0xXX 0xXX 0xXX` (表示连接成功)。
   - **操作:** 解析响应码。
   - **假设输出:** 如果响应码是 `0x5A`，则 `completed_handshake_` 设置为 `true`，返回 `OK`。

**涉及用户或编程常见的使用错误及举例:**

1. **SOCKS 服务器不可用或配置错误：**
   - **错误场景：** 用户配置了错误的 SOCKS 服务器地址或端口。
   - **后果：** `transport_socket_` 可能无法建立连接，或者在握手过程中 SOCKS 服务器没有响应，导致超时或连接被拒绝。`SOCKSClientSocket::Connect()` 会返回相应的错误码，例如 `ERR_CONNECTION_REFUSED` 或 `ERR_TIMED_OUT`.
2. **SOCKS 版本不匹配：**
   - **错误场景：** 用户配置的 SOCKS 服务器是 SOCKS5，而客户端只实现了 SOCKS4。
   - **后果：**  握手请求的格式不符合服务器的预期，服务器可能会关闭连接或者返回错误的响应，导致 `SOCKSClientSocket::DoHandshakeReadComplete()` 中解析错误，返回 `ERR_SOCKS_CONNECTION_FAILED`。
3. **目标地址无法通过 SOCKS 服务器访问：**
   - **错误场景：**  SOCKS 服务器配置了访问控制策略，不允许访问特定的目标地址。
   - **后果：** SOCKS 服务器在收到连接请求后，会返回 `kServerResponseRejected` 或 `kServerResponseNotReachable`，`SOCKSClientSocket::DoHandshakeReadComplete()` 会根据响应码返回 `ERR_SOCKS_CONNECTION_FAILED` 或 `ERR_SOCKS_CONNECTION_HOST_UNREACHABLE`。
4. **编程错误：**
   - **错误场景：** 在调用 `SOCKSClientSocket` 的方法之前，底层的 `transport_socket_` 没有正确连接到 SOCKS 服务器。
   - **后果：**  `SOCKSClientSocket` 的方法调用会失败，因为底层的连接不可用。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户配置代理服务器：** 用户在浏览器的设置中，手动配置了 SOCKS4 代理服务器的地址和端口。
2. **用户发起网络请求：** 用户在浏览器中访问一个网页 (例如 `https://www.example.com`)，或者执行了一些 JavaScript 代码发起网络请求 (例如使用 `fetch`)。
3. **浏览器网络栈处理请求：**
   - 网络栈检查代理设置，发现需要使用 SOCKS4 代理。
   - 网络栈会尝试建立到 SOCKS 服务器的 TCP 连接。
   - 如果连接成功，网络栈会创建一个 `SOCKSClientSocket` 对象。
4. **`SOCKSClientSocket` 开始握手：** `SOCKSClientSocket::Connect()` 方法被调用，开始与 SOCKS 服务器进行握手。

**调试线索：**

- **NetLog:** Chromium 的 NetLog 是一个强大的调试工具。通过捕获 NetLog，可以查看 SOCKS 连接过程中的详细事件，包括 DNS 解析、连接建立、SOCKS 握手请求和响应的内容、错误信息等。可以关注以下 NetLog 事件类型：
    - `NetLogEventType::SOCKS_CONNECT` (开始和结束)
    - 与 DNS 解析相关的事件
    - 底层 `StreamSocket` 的读写事件
- **抓包工具：** 使用 Wireshark 或 tcpdump 等抓包工具，可以捕获与 SOCKS 服务器之间的网络数据包，查看握手请求和响应的具体内容，以及 TCP 连接的状态。
- **断点调试：** 如果你有 Chromium 的源代码，可以在 `SOCKSClientSocket` 的关键方法 (例如 `Connect`, `DoLoop`, `DoHandshakeWrite`, `DoHandshakeReadComplete`) 设置断点，单步执行代码，查看变量的值和程序执行流程，帮助理解握手过程中的状态变化和错误发生的原因。

通过结合这些调试线索，可以有效地诊断 SOCKS 客户端连接问题，例如连接失败、握手错误等。

Prompt: 
```
这是目录为net/socket/socks_client_socket.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/socks_client_socket.h"

#include <utility>

#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/sys_byteorder.h"
#include "net/base/address_list.h"
#include "net/base/io_buffer.h"
#include "net/dns/public/dns_query_type.h"
#include "net/dns/public/secure_dns_policy.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace net {

// Every SOCKS server requests a user-id from the client. It is optional
// and we send an empty string.
static const char kEmptyUserId[] = "";

// For SOCKS4, the client sends 8 bytes  plus the size of the user-id.
static const unsigned int kWriteHeaderSize = 8;

// For SOCKS4 the server sends 8 bytes for acknowledgement.
static const unsigned int kReadHeaderSize = 8;

// Server Response codes for SOCKS.
static const uint8_t kServerResponseOk = 0x5A;
static const uint8_t kServerResponseRejected = 0x5B;
static const uint8_t kServerResponseNotReachable = 0x5C;
static const uint8_t kServerResponseMismatchedUserId = 0x5D;

static const uint8_t kSOCKSVersion4 = 0x04;
static const uint8_t kSOCKSStreamRequest = 0x01;

// A struct holding the essential details of the SOCKS4 Server Request.
// The port in the header is stored in network byte order.
struct SOCKS4ServerRequest {
  uint8_t version;
  uint8_t command;
  uint16_t nw_port;
  uint8_t ip[4];
};
static_assert(sizeof(SOCKS4ServerRequest) == kWriteHeaderSize,
              "socks4 server request struct has incorrect size");

// A struct holding details of the SOCKS4 Server Response.
struct SOCKS4ServerResponse {
  uint8_t reserved_null;
  uint8_t code;
  uint16_t port;
  uint8_t ip[4];
};
static_assert(sizeof(SOCKS4ServerResponse) == kReadHeaderSize,
              "socks4 server response struct has incorrect size");

SOCKSClientSocket::SOCKSClientSocket(
    std::unique_ptr<StreamSocket> transport_socket,
    const HostPortPair& destination,
    const NetworkAnonymizationKey& network_anonymization_key,
    RequestPriority priority,
    HostResolver* host_resolver,
    SecureDnsPolicy secure_dns_policy,
    const NetworkTrafficAnnotationTag& traffic_annotation)
    : transport_socket_(std::move(transport_socket)),
      host_resolver_(host_resolver),
      secure_dns_policy_(secure_dns_policy),
      destination_(destination),
      network_anonymization_key_(network_anonymization_key),
      priority_(priority),
      net_log_(transport_socket_->NetLog()),
      traffic_annotation_(traffic_annotation) {}

SOCKSClientSocket::~SOCKSClientSocket() {
  Disconnect();
}

int SOCKSClientSocket::Connect(CompletionOnceCallback callback) {
  DCHECK(transport_socket_);
  DCHECK_EQ(STATE_NONE, next_state_);
  DCHECK(user_callback_.is_null());

  // If already connected, then just return OK.
  if (completed_handshake_)
    return OK;

  next_state_ = STATE_RESOLVE_HOST;

  net_log_.BeginEvent(NetLogEventType::SOCKS_CONNECT);

  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING) {
    user_callback_ = std::move(callback);
  } else {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::SOCKS_CONNECT, rv);
  }
  return rv;
}

void SOCKSClientSocket::Disconnect() {
  completed_handshake_ = false;
  resolve_host_request_.reset();
  transport_socket_->Disconnect();

  // Reset other states to make sure they aren't mistakenly used later.
  // These are the states initialized by Connect().
  next_state_ = STATE_NONE;
  user_callback_.Reset();
}

bool SOCKSClientSocket::IsConnected() const {
  return completed_handshake_ && transport_socket_->IsConnected();
}

bool SOCKSClientSocket::IsConnectedAndIdle() const {
  return completed_handshake_ && transport_socket_->IsConnectedAndIdle();
}

const NetLogWithSource& SOCKSClientSocket::NetLog() const {
  return net_log_;
}

bool SOCKSClientSocket::WasEverUsed() const {
  return was_ever_used_;
}

NextProto SOCKSClientSocket::GetNegotiatedProtocol() const {
  if (transport_socket_)
    return transport_socket_->GetNegotiatedProtocol();
  NOTREACHED();
}

bool SOCKSClientSocket::GetSSLInfo(SSLInfo* ssl_info) {
  if (transport_socket_)
    return transport_socket_->GetSSLInfo(ssl_info);
  NOTREACHED();
}

int64_t SOCKSClientSocket::GetTotalReceivedBytes() const {
  return transport_socket_->GetTotalReceivedBytes();
}

void SOCKSClientSocket::ApplySocketTag(const SocketTag& tag) {
  return transport_socket_->ApplySocketTag(tag);
}

// Read is called by the transport layer above to read. This can only be done
// if the SOCKS handshake is complete.
int SOCKSClientSocket::Read(IOBuffer* buf,
                            int buf_len,
                            CompletionOnceCallback callback) {
  DCHECK(completed_handshake_);
  DCHECK_EQ(STATE_NONE, next_state_);
  DCHECK(user_callback_.is_null());
  DCHECK(!callback.is_null());

  int rv = transport_socket_->Read(
      buf, buf_len,
      base::BindOnce(&SOCKSClientSocket::OnReadWriteComplete,
                     base::Unretained(this), std::move(callback)));
  if (rv > 0)
    was_ever_used_ = true;
  return rv;
}

int SOCKSClientSocket::ReadIfReady(IOBuffer* buf,
                                   int buf_len,
                                   CompletionOnceCallback callback) {
  DCHECK(completed_handshake_);
  DCHECK_EQ(STATE_NONE, next_state_);
  DCHECK(user_callback_.is_null());
  DCHECK(!callback.is_null());

  // Pass |callback| directly instead of wrapping it with OnReadWriteComplete.
  // This is to avoid setting |was_ever_used_| unless data is actually read.
  int rv = transport_socket_->ReadIfReady(buf, buf_len, std::move(callback));
  if (rv > 0)
    was_ever_used_ = true;
  return rv;
}

int SOCKSClientSocket::CancelReadIfReady() {
  return transport_socket_->CancelReadIfReady();
}

// Write is called by the transport layer. This can only be done if the
// SOCKS handshake is complete.
int SOCKSClientSocket::Write(
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
      base::BindOnce(&SOCKSClientSocket::OnReadWriteComplete,
                     base::Unretained(this), std::move(callback)),
      traffic_annotation);
  if (rv > 0)
    was_ever_used_ = true;
  return rv;
}

int SOCKSClientSocket::SetReceiveBufferSize(int32_t size) {
  return transport_socket_->SetReceiveBufferSize(size);
}

int SOCKSClientSocket::SetSendBufferSize(int32_t size) {
  return transport_socket_->SetSendBufferSize(size);
}

void SOCKSClientSocket::DoCallback(int result) {
  DCHECK_NE(ERR_IO_PENDING, result);
  DCHECK(!user_callback_.is_null());

  // Since Run() may result in Read being called,
  // clear user_callback_ up front.
  DVLOG(1) << "Finished setting up SOCKS handshake";
  std::move(user_callback_).Run(result);
}

void SOCKSClientSocket::OnIOComplete(int result) {
  DCHECK_NE(STATE_NONE, next_state_);
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    net_log_.EndEventWithNetErrorCode(NetLogEventType::SOCKS_CONNECT, rv);
    DoCallback(rv);
  }
}

void SOCKSClientSocket::OnReadWriteComplete(CompletionOnceCallback callback,
                                            int result) {
  DCHECK_NE(ERR_IO_PENDING, result);
  DCHECK(!callback.is_null());

  if (result > 0)
    was_ever_used_ = true;
  std::move(callback).Run(result);
}

int SOCKSClientSocket::DoLoop(int last_io_result) {
  DCHECK_NE(next_state_, STATE_NONE);
  int rv = last_io_result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_RESOLVE_HOST:
        DCHECK_EQ(OK, rv);
        rv = DoResolveHost();
        break;
      case STATE_RESOLVE_HOST_COMPLETE:
        rv = DoResolveHostComplete(rv);
        break;
      case STATE_HANDSHAKE_WRITE:
        DCHECK_EQ(OK, rv);
        rv = DoHandshakeWrite();
        break;
      case STATE_HANDSHAKE_WRITE_COMPLETE:
        rv = DoHandshakeWriteComplete(rv);
        break;
      case STATE_HANDSHAKE_READ:
        DCHECK_EQ(OK, rv);
        rv = DoHandshakeRead();
        break;
      case STATE_HANDSHAKE_READ_COMPLETE:
        rv = DoHandshakeReadComplete(rv);
        break;
      default:
        NOTREACHED() << "bad state";
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);
  return rv;
}

int SOCKSClientSocket::DoResolveHost() {
  next_state_ = STATE_RESOLVE_HOST_COMPLETE;
  // SOCKS4 only supports IPv4 addresses, so only try getting the IPv4
  // addresses for the target host.
  HostResolver::ResolveHostParameters parameters;
  parameters.dns_query_type = DnsQueryType::A;
  parameters.initial_priority = priority_;
  parameters.secure_dns_policy = secure_dns_policy_;
  resolve_host_request_ = host_resolver_->CreateRequest(
      destination_, network_anonymization_key_, net_log_, parameters);

  return resolve_host_request_->Start(
      base::BindOnce(&SOCKSClientSocket::OnIOComplete, base::Unretained(this)));
}

int SOCKSClientSocket::DoResolveHostComplete(int result) {
  resolve_error_info_ = resolve_host_request_->GetResolveErrorInfo();
  if (result != OK) {
    // Resolving the hostname failed; fail the request rather than automatically
    // falling back to SOCKS4a (since it can be confusing to see invalid IP
    // addresses being sent to the SOCKS4 server when it doesn't support 4A.)
    return result;
  }

  next_state_ = STATE_HANDSHAKE_WRITE;
  return OK;
}

// Builds the buffer that is to be sent to the server.
const std::string SOCKSClientSocket::BuildHandshakeWriteBuffer() const {
  SOCKS4ServerRequest request;
  request.version = kSOCKSVersion4;
  request.command = kSOCKSStreamRequest;
  request.nw_port = base::HostToNet16(destination_.port());

  DCHECK(resolve_host_request_->GetAddressResults() &&
         !resolve_host_request_->GetAddressResults()->empty());
  const IPEndPoint& endpoint =
      resolve_host_request_->GetAddressResults()->front();

  // We disabled IPv6 results when resolving the hostname, so none of the
  // results in the list will be IPv6.
  // TODO(eroman): we only ever use the first address in the list. It would be
  //               more robust to try all the IP addresses we have before
  //               failing the connect attempt.
  CHECK_EQ(ADDRESS_FAMILY_IPV4, endpoint.GetFamily());
  CHECK_LE(endpoint.address().size(), sizeof(request.ip));
  memcpy(&request.ip, &endpoint.address().bytes()[0],
         endpoint.address().size());

  DVLOG(1) << "Resolved Host is : " << endpoint.ToStringWithoutPort();

  std::string handshake_data(reinterpret_cast<char*>(&request),
                             sizeof(request));
  handshake_data.append(kEmptyUserId, std::size(kEmptyUserId));

  return handshake_data;
}

// Writes the SOCKS handshake data to the underlying socket connection.
int SOCKSClientSocket::DoHandshakeWrite() {
  next_state_ = STATE_HANDSHAKE_WRITE_COMPLETE;

  if (buffer_.empty()) {
    buffer_ = BuildHandshakeWriteBuffer();
    bytes_sent_ = 0;
  }

  int handshake_buf_len = buffer_.size() - bytes_sent_;
  DCHECK_GT(handshake_buf_len, 0);
  handshake_buf_ = base::MakeRefCounted<IOBufferWithSize>(handshake_buf_len);
  memcpy(handshake_buf_->data(), &buffer_[bytes_sent_],
         handshake_buf_len);
  return transport_socket_->Write(
      handshake_buf_.get(), handshake_buf_len,
      base::BindOnce(&SOCKSClientSocket::OnIOComplete, base::Unretained(this)),
      traffic_annotation_);
}

int SOCKSClientSocket::DoHandshakeWriteComplete(int result) {
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
    return ERR_UNEXPECTED;
  }

  return OK;
}

int SOCKSClientSocket::DoHandshakeRead() {
  next_state_ = STATE_HANDSHAKE_READ_COMPLETE;

  if (buffer_.empty()) {
    bytes_received_ = 0;
  }

  int handshake_buf_len = kReadHeaderSize - bytes_received_;
  handshake_buf_ = base::MakeRefCounted<IOBufferWithSize>(handshake_buf_len);
  return transport_socket_->Read(
      handshake_buf_.get(), handshake_buf_len,
      base::BindOnce(&SOCKSClientSocket::OnIOComplete, base::Unretained(this)));
}

int SOCKSClientSocket::DoHandshakeReadComplete(int result) {
  if (result < 0)
    return result;

  // The underlying socket closed unexpectedly.
  if (result == 0)
    return ERR_CONNECTION_CLOSED;

  if (bytes_received_ + result > kReadHeaderSize) {
    // TODO(eroman): Describe failure in NetLog.
    return ERR_SOCKS_CONNECTION_FAILED;
  }

  buffer_.append(handshake_buf_->data(), result);
  bytes_received_ += result;
  if (bytes_received_ < kReadHeaderSize) {
    next_state_ = STATE_HANDSHAKE_READ;
    return OK;
  }

  const SOCKS4ServerResponse* response =
      reinterpret_cast<const SOCKS4ServerResponse*>(buffer_.data());

  if (response->reserved_null != 0x00) {
    DVLOG(1) << "Unknown response from SOCKS server.";
    return ERR_SOCKS_CONNECTION_FAILED;
  }

  switch (response->code) {
    case kServerResponseOk:
      completed_handshake_ = true;
      return OK;
    case kServerResponseRejected:
      DVLOG(1) << "SOCKS request rejected or failed";
      return ERR_SOCKS_CONNECTION_FAILED;
    case kServerResponseNotReachable:
      DVLOG(1) << "SOCKS request failed because client is not running "
               << "identd (or not reachable from the server)";
      return ERR_SOCKS_CONNECTION_HOST_UNREACHABLE;
    case kServerResponseMismatchedUserId:
      DVLOG(1) << "SOCKS request failed because client's identd could "
               << "not confirm the user ID string in the request";
      return ERR_SOCKS_CONNECTION_FAILED;
    default:
      DVLOG(1) << "SOCKS server sent unknown response";
      return ERR_SOCKS_CONNECTION_FAILED;
  }

  // Note: we ignore the last 6 bytes as specified by the SOCKS protocol
}

int SOCKSClientSocket::GetPeerAddress(IPEndPoint* address) const {
  return transport_socket_->GetPeerAddress(address);
}

int SOCKSClientSocket::GetLocalAddress(IPEndPoint* address) const {
  return transport_socket_->GetLocalAddress(address);
}

ResolveErrorInfo SOCKSClientSocket::GetResolveErrorInfo() const {
  return resolve_error_info_;
}

}  // namespace net

"""

```