Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Initial Understanding of the File and its Purpose:**

The filename `net/quic/quic_proxy_datagram_client_socket.cc` immediately suggests a few key things:

* **Network Stack:** It's part of Chromium's networking stack (`net/`).
* **QUIC Protocol:**  It involves the QUIC protocol.
* **Proxy:**  The "proxy" in the name indicates it's about connecting through a proxy server.
* **Datagrams:**  The "datagram" part signals that it's dealing with UDP-like messages, unlike the reliable byte streams of TCP.
* **Client Socket:**  It's a client-side component for initiating connections.

Therefore, the core purpose is likely to establish a connection to a destination server *through a QUIC proxy* and exchange UDP datagrams.

**2. High-Level Functional Breakdown (Reading the Code Top-Down):**

I'll read through the code, focusing on the class definition and its methods. As I go, I'll make notes about what each part does.

* **Constructor:** Takes a URL, proxy chain, user agent, and logging information. Initializes member variables. Notably sets the request method to "CONNECT".
* **Destructor:** Closes the socket and logs the end of its lifetime.
* **`GetConnectResponseInfo()`:** Returns the HTTP response headers from the proxy connection.
* **`IsConnected()`:** Checks if the connection is established and the underlying stream is open.
* **`ConnectViaStream()`:** This is the *key* connection method. It takes an existing QUIC stream. This strongly suggests that the QUIC connection to the proxy is handled *outside* this class. It registers a datagram visitor.
* **`Connect()` and related `Connect*` methods:** These are explicitly marked `NOTREACHED()`. This confirms the expectation that the underlying QUIC connection is pre-established.
* **`Close()`:** Cleans up resources, unregisters the datagram visitor, and resets the stream.
* **`SetReceiveBufferSize()` and `SetSendBufferSize()`:**  Do nothing (return OK). This might be a simplification or a point where future implementation would go.
* **`OnHttp3Datagram()`:** This is the core logic for handling incoming datagrams. It reads a context ID, checks it, and then either pushes the payload to a queue or directly calls a read callback.
* **`OnUnknownCapsule()`:**  Silently ignores unknown QUIC capsules.
* **`GetBoundNetwork()`:** Returns `kInvalidNetworkHandle`, indicating it's not bound to a specific network.
* **`ApplySocketTag()`:**  A placeholder.
* **`SetMulticastInterface()`, `SetIOSNetworkServiceType()`, `SetDoNotFragment()`, `SetRecvTos()`, `SetMsgConfirm()`:** Also `NOTREACHED()`. These are likely features not needed for this specific proxy datagram socket implementation.
* **`GetPeerAddress()` and `GetLocalAddress()`:** Return the proxy's and local addresses.
* **`UseNonBlockingIO()`:** `NOTREACHED()`.
* **`SetTos()`:**  Sets the Type of Service field (returns OK).
* **`NetLog()` and `GetLastTos()`:** Accessors for logging and TOS.
* **`Read()`:** Attempts to read from the datagram queue. If empty, it sets up a read callback to be triggered when `OnHttp3Datagram()` is called.
* **`Write()`:** Sends a datagram payload over the underlying QUIC stream.
* **`OnIOComplete()`:**  A callback for asynchronous operations in the connection establishment process.
* **`DoLoop()`:** A state machine that drives the connection establishment (sending the CONNECT request and receiving the response).
* **`DoSendRequest()`:** Constructs and sends the "CONNECT-UDP" request to the proxy.
* **`DoSendRequestComplete()`:** Handles the result of sending the request.
* **`DoReadReply()`:** Reads the initial headers from the proxy's response.
* **`DoReadReplyComplete()`:** Processes the received headers, checking the status code.
* **`OnReadResponseHeadersComplete()`:** A callback for when response headers are fully read.
* **`ProcessResponseHeaders()`:** Parses the raw headers into an `HttpResponseInfo` object.

**3. Answering the Specific Questions:**

* **Functionality:** Based on the breakdown, I can list the functionalities. The key is establishing a QUIC-based tunnel through a proxy to send and receive UDP-like datagrams.
* **Relationship to JavaScript:** This is where I need to connect the C++ code to the browser's JavaScript environment. I know that JavaScript in a browser can't directly manipulate network sockets at this low level. Instead, it uses higher-level APIs. The key connection is the `fetch` API, particularly for making requests through proxies. This code likely forms the *underlying implementation* when a `fetch` request goes through a QUIC proxy and needs to send/receive UDP data. I'll illustrate with a hypothetical JavaScript `fetch` call.
* **Logical Reasoning (Input/Output):**  For `ConnectViaStream`, I'll define a scenario where a stream is successfully provided and the connection succeeds. I'll also consider a failure case where the stream is already closed. For `OnHttp3Datagram`, I'll demonstrate the cases where the datagram is queued and where the read callback is immediately invoked.
* **User/Programming Errors:**  I'll think about common errors related to network programming, like not connecting before reading/writing, trying to read more data than the buffer can hold, and the implications of a full datagram queue.
* **User Operation Debugging:**  I'll trace the steps a user might take that would lead to this code being executed. This involves making a network request (likely a `fetch`) that goes through a configured QUIC proxy and involves sending or receiving UDP data.

**4. Structuring the Answer:**

I'll organize the answer according to the prompt's questions, providing clear explanations and examples. I'll use formatting (like code blocks and bullet points) to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this directly handles the QUIC connection.
* **Correction:**  The `ConnectViaStream` method taking a pre-existing `QuicChromiumClientStream::Handle` strongly suggests this class operates *on top* of an established QUIC connection. The `NOTREACHED()` `Connect` methods reinforce this.
* **Initial thought:** How does this relate to WebSockets?
* **Refinement:** While both involve persistent connections, this specifically mentions "datagrams" and the "CONNECT-UDP" method. This points towards a more direct UDP-over-QUIC tunneling mechanism, distinct from the TCP-based nature of standard WebSockets (although QUIC can be an underlying transport for WebSockets). The "capsule-protocol: ?1" header further confirms this is a specific protocol for UDP encapsulation.
* **Clarity:** Ensure the JavaScript example clearly demonstrates the *indirect* relationship. The JavaScript doesn't *directly* call this C++ code, but actions in JavaScript trigger the execution of this code within the browser's networking stack.

By following this structured approach and constantly refining my understanding as I analyze the code, I can generate a comprehensive and accurate answer to the prompt.
这个文件 `net/quic/quic_proxy_datagram_client_socket.cc` 是 Chromium 网络栈中用于通过 QUIC 代理建立和管理数据报（datagram）连接的客户端 socket 的实现。它允许客户端通过一个 QUIC 连接的代理服务器发送和接收 UDP 风格的数据包。

以下是它的主要功能：

1. **建立通过 QUIC 代理的连接:**
   - 它处理通过 QUIC 连接到代理服务器的握手过程，使用 HTTP/3 的 `CONNECT-UDP` 方法建立隧道。
   - 它使用 `QuicChromiumClientStream` 来发送和接收控制信息以及数据报。

2. **发送和接收数据报:**
   - 它允许应用程序通过 `Write` 方法发送数据报。这些数据报会被封装在 QUIC 流中发送到代理服务器。
   - 它通过 `OnHttp3Datagram` 方法接收来自代理服务器的数据报。接收到的数据报会被缓存，并通过 `Read` 方法传递给应用程序。

3. **管理连接状态:**
   - 它跟踪连接的生命周期，包括连接、断开连接等状态。
   - 它提供了 `IsConnected` 方法来检查连接是否已建立。

4. **处理代理认证 (TODO):**
   - 代码中包含了关于处理代理认证的注释 (`// TODO(crbug.com/326437102):  Add Proxy-Authentication headers.`)，表明未来可能会支持需要认证的代理服务器。

5. **集成到 Chromium 网络栈:**
   - 它使用 Chromium 的网络日志系统 (`net_log_`) 进行调试和监控。
   - 它与 `ProxyDelegate` 交互，以处理代理相关的策略和事件。

**与 JavaScript 功能的关系及举例说明:**

该 C++ 代码本身不直接与 JavaScript 交互。然而，当网页中的 JavaScript 代码发起需要通过 QUIC 代理发送 UDP 风格数据的请求时，这个 C++ 类会在幕后工作。

**举例说明:**

假设一个网页应用需要使用 WebTransport 的 UDP-over-QUIC 功能通过一个配置的 HTTP 代理进行通信。

1. **JavaScript 发起请求:**
   ```javascript
   const transport = new WebTransport("https://example.com", {
       proxy: 'https://my-quic-proxy.com'
   });

   transport.ready.then(() => {
       const sendStream = transport.createUnidirectionalStream();
       const writer = sendStream.writable.getWriter();
       writer.write(new Uint8Array([0, 1, 2, 3])); // 发送数据报
       writer.close();

       transport.datagrams.readable.getReader().read().then(({ value, done }) => {
           if (value) {
               console.log("Received datagram:", value);
           }
       });
   });
   ```

2. **Chromium 网络栈处理:**
   - 当 `WebTransport` 对象被创建时，Chromium 的网络栈会解析代理设置。
   - 如果确定需要使用 QUIC 代理，并且需要发送/接收数据报，则会创建 `QuicProxyDatagramClientSocket` 的实例。
   - `QuicProxyDatagramClientSocket` 会使用一个现有的或新建的 QUIC 连接连接到 `https://my-quic-proxy.com`。
   - 当 JavaScript 调用 `writer.write()` 发送数据时，数据会被传递到这个 C++ 类的 `Write` 方法。
   - 当代理服务器发送数据报回来时，数据会被 `OnHttp3Datagram` 方法接收，并最终传递给 JavaScript 的 `transport.datagrams.readable`.

**逻辑推理及假设输入与输出:**

**假设输入 (在 `ConnectViaStream` 方法中):**

* `local_address`: 本地 IP 地址和端口 (例如: `192.168.1.100:12345`).
* `proxy_peer_address`: 代理服务器的 IP 地址和端口 (例如: `203.0.113.5:443`).
* `stream`: 一个已经建立的到代理服务器的 `QuicChromiumClientStream::Handle`，用于发送控制信息和数据报。
* `callback`: 一个在连接完成或失败时调用的回调函数。

**假设输出 (如果连接成功):**

* `ConnectViaStream` 返回 `OK` (0)。
* `IsConnected()` 返回 `true`.
* 可以使用 `Write` 方法发送数据报。
* 可以使用 `Read` 方法接收数据报。

**假设输入 (在 `OnHttp3Datagram` 方法中):**

* `stream_id`: 接收到数据报的 QUIC 流 ID。
* `payload`: 包含数据报内容的 `std::string_view`。  假设 `payload` 的前几个字节是 context ID (例如 0)，后面是实际的 UDP 数据。 例如: `"\x00\x01\x02\x03"` (context ID 0, 数据 `0x01 0x02 0x03`).

**假设输出 (在 `OnHttp3Datagram` 方法中):**

* 如果有挂起的 `Read` 回调，并且 `payload` 大小不超过 `read_buf_len_`，则数据会被复制到 `read_buf_`，`read_callback_` 会被调用，输出 `bytes_read` (例如 3)。
* 如果没有挂起的 `Read` 回调，数据报会被添加到内部的 `datagrams_` 队列中。

**用户或编程常见的使用错误及举例说明:**

1. **在连接建立之前尝试读写:**
   - **错误:** 在 `ConnectViaStream` 完成之前 (回调被调用之前) 调用 `Read` 或 `Write`。
   - **后果:** `Read` 方法可能会返回 `ERR_SOCKET_NOT_CONNECTED`。 `Write` 方法也会返回 `ERR_SOCKET_NOT_CONNECTED`。
   - **代码示例:**
     ```c++
     // ... 连接代码 ...
     socket->Write(buffer, len, callback, traffic_annotation); // 错误：可能在连接完成前调用
     ```

2. **提供的缓冲区太小，无法容纳接收到的数据报:**
   - **错误:** `Read` 方法提供的 `buf_len` 小于 `OnHttp3Datagram` 接收到的数据报的大小。
   - **后果:** `Read` 方法会返回 `ERR_MSG_TOO_BIG`，数据会被截断或丢失。
   - **代码示例:**
     ```c++
     char small_buffer[1];
     IOBuffer buffer(small_buffer, 1);
     socket->Read(buffer.get(), 1, callback); // 错误：缓冲区可能太小
     ```

3. **忘记处理 `ERR_IO_PENDING`:**
   - **错误:** 在调用异步操作 (`ConnectViaStream`, `Read`) 后，没有正确处理 `ERR_IO_PENDING` 的返回值并等待回调。
   - **后果:** 程序可能会继续执行，而操作尚未完成，导致逻辑错误。

4. **数据报队列溢出:**
   - **错误:**  应用程序接收数据的速度慢于数据到达的速度，导致 `datagrams_` 队列达到 `kMaxDatagramQueueSize` 限制。
   - **后果:**  后续到达的数据报会被丢弃，并在日志中记录警告 (`DLOG(WARNING) << "Dropping datagram because queue is full";`).

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个网站或应用程序:** 该网站或应用程序配置为使用需要通过 QUIC 代理的连接来发送或接收数据报。

2. **浏览器解析代理设置:** 浏览器会检查用户的代理配置（例如，通过操作系统设置或 PAC 文件）。如果配置了 HTTP 代理，并且协议支持（例如，配置了使用 CONNECT 方法进行隧道传输）。

3. **发起需要数据报的连接:**  JavaScript 代码（例如，使用 WebTransport API）尝试建立连接。

4. **Chromium 网络栈选择合适的 Socket 类:**  根据连接的目标和代理配置，网络栈会决定使用 `QuicProxyDatagramClientSocket` 来处理通过 QUIC 代理的数据报连接。

5. **建立 QUIC 连接到代理:** 如果到代理服务器的 QUIC 连接尚未建立，Chromium 会先建立 QUIC 连接。这涉及到 TLS 握手和 QUIC 连接协商。

6. **调用 `QuicProxyDatagramClientSocket` 的 `ConnectViaStream`:**  一旦到代理的 QUIC 连接建立，并且创建了一个新的 `QuicChromiumClientStream`，就会调用 `QuicProxyDatagramClientSocket` 的 `ConnectViaStream` 方法，传入相关的地址信息和 stream handle。

7. **发送 `CONNECT-UDP` 请求:** `DoLoop` 方法驱动状态机，首先会发送一个 `CONNECT-UDP` 请求到代理服务器，请求建立一个用于传输数据报的隧道。

8. **接收代理服务器的响应:**  `DoReadReply` 和 `DoReadReplyComplete` 方法处理代理服务器的响应头。如果响应状态码是 200 OK，表示隧道建立成功。

9. **JavaScript 发送数据报:** 当 JavaScript 代码调用 WebTransport 的 `send()` 方法或类似 API 发送数据时，数据最终会通过 `QuicProxyDatagramClientSocket` 的 `Write` 方法发送到代理。

10. **代理服务器转发或返回数据报:** 代理服务器可能会将数据报转发到目标服务器，或者将来自目标服务器的数据报返回给客户端。

11. **`OnHttp3Datagram` 接收数据报:** 当代理服务器通过 QUIC 连接发送数据报时，`QuicProxyDatagramClientSocket` 的 `OnHttp3Datagram` 方法会被调用。

12. **JavaScript 接收数据报:**  接收到的数据报会通过 `Read` 方法传递给上层，最终到达 JavaScript 代码。

**调试线索:**

* **网络日志 (`net_log_`):**  查看网络日志可以了解连接建立的详细过程，包括发送的请求头、接收的响应头、以及发生的错误。
* **QUIC 连接状态:** 检查底层的 QUIC 连接状态可以帮助确定是否是 QUIC 连接本身的问题。
* **`CONNECT-UDP` 请求和响应:**  确保 `CONNECT-UDP` 请求被正确发送，并且代理服务器返回了正确的响应。
* **数据报的封装和解封装:**  检查数据报在发送和接收过程中是否被正确地封装在 QUIC 帧中。
* **代理服务器行为:**  确认代理服务器是否正确处理了 `CONNECT-UDP` 请求，并且能够正确地转发和接收数据报。
* **JavaScript 代码逻辑:** 检查 JavaScript 代码是否正确使用了 WebTransport 或其他相关 API，并且正确处理了发送和接收的数据。

总而言之，`QuicProxyDatagramClientSocket` 是 Chromium 中实现通过 QUIC 代理传输 UDP 风格数据报的关键组件，它在幕后支撑着像 WebTransport 这样的现代 Web 技术。 理解其功能和交互方式有助于调试网络连接问题。

### 提示词
```
这是目录为net/quic/quic_proxy_datagram_client_socket.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_proxy_datagram_client_socket.h"

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "net/base/net_errors.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_delegate.h"
#include "net/http/http_log_util.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/spdy/spdy_http_utils.h"

namespace net {

QuicProxyDatagramClientSocket::QuicProxyDatagramClientSocket(
    const GURL& url,
    const ProxyChain& proxy_chain,
    const std::string& user_agent,
    const NetLogWithSource& source_net_log,
    ProxyDelegate* proxy_delegate)
    : url_(url),
      proxy_chain_(proxy_chain),
      proxy_delegate_(proxy_delegate),
      user_agent_(user_agent),
      net_log_(NetLogWithSource::Make(
          source_net_log.net_log(),
          NetLogSourceType::QUIC_PROXY_DATAGRAM_CLIENT_SOCKET)) {
  CHECK_GE(proxy_chain.length(), 1u);
  request_.method = "CONNECT";
  request_.url = url_;

  net_log_.BeginEventReferencingSource(NetLogEventType::SOCKET_ALIVE,
                                       source_net_log.source());
}

QuicProxyDatagramClientSocket::~QuicProxyDatagramClientSocket() {
  Close();
  net_log_.EndEvent(NetLogEventType::SOCKET_ALIVE);
}

const HttpResponseInfo* QuicProxyDatagramClientSocket::GetConnectResponseInfo()
    const {
  return response_.headers.get() ? &response_ : nullptr;
}

bool QuicProxyDatagramClientSocket::IsConnected() const {
  return next_state_ == STATE_CONNECT_COMPLETE && stream_handle_->IsOpen();
}

int QuicProxyDatagramClientSocket::ConnectViaStream(
    const IPEndPoint& local_address,
    const IPEndPoint& proxy_peer_address,
    std::unique_ptr<QuicChromiumClientStream::Handle> stream,
    CompletionOnceCallback callback) {
  DCHECK(connect_callback_.is_null());

  local_address_ = local_address;
  proxy_peer_address_ = proxy_peer_address;
  stream_handle_ = std::move(stream);

  if (!stream_handle_->IsOpen()) {
    return ERR_CONNECTION_CLOSED;
  }

  // Register stream to receive HTTP/3 datagrams.
  stream_handle_->RegisterHttp3DatagramVisitor(this);
  datagram_visitor_registered_ = true;

  DCHECK_EQ(STATE_DISCONNECTED, next_state_);
  next_state_ = STATE_SEND_REQUEST;

  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING) {
    connect_callback_ = std::move(callback);
  }
  return rv;
}

int QuicProxyDatagramClientSocket::Connect(const IPEndPoint& address) {
  NOTREACHED();
}

int QuicProxyDatagramClientSocket::ConnectAsync(
    const IPEndPoint& address,
    CompletionOnceCallback callback) {
  NOTREACHED();
}

int QuicProxyDatagramClientSocket::ConnectUsingDefaultNetworkAsync(
    const IPEndPoint& address,
    CompletionOnceCallback callback) {
  NOTREACHED();
}

int QuicProxyDatagramClientSocket::ConnectUsingNetwork(
    handles::NetworkHandle network,
    const IPEndPoint& address) {
  NOTREACHED();
}

int QuicProxyDatagramClientSocket::ConnectUsingDefaultNetwork(
    const IPEndPoint& address) {
  NOTREACHED();
}

int QuicProxyDatagramClientSocket::ConnectUsingNetworkAsync(
    handles::NetworkHandle network,
    const IPEndPoint& address,
    CompletionOnceCallback callback) {
  NOTREACHED();
}

void QuicProxyDatagramClientSocket::Close() {
  connect_callback_.Reset();
  read_callback_.Reset();
  read_buf_len_ = 0;
  read_buf_ = nullptr;

  next_state_ = STATE_DISCONNECTED;

  if (datagram_visitor_registered_) {
    stream_handle_->UnregisterHttp3DatagramVisitor();
    datagram_visitor_registered_ = false;
  }
  stream_handle_->Reset(quic::QUIC_STREAM_CANCELLED);
}

int QuicProxyDatagramClientSocket::SetReceiveBufferSize(int32_t size) {
  return OK;
}

int QuicProxyDatagramClientSocket::SetSendBufferSize(int32_t size) {
  return OK;
}

void QuicProxyDatagramClientSocket::OnHttp3Datagram(
    quic::QuicStreamId stream_id,
    std::string_view payload) {
  DCHECK_EQ(stream_id, stream_handle_->id())
      << "Received datagram for unexpected stream.";

  quic::QuicDataReader reader(payload);
  uint64_t context_id;
  if (!reader.ReadVarInt62(&context_id)) {
    DLOG(WARNING)
        << "Ignoring HTTP Datagram payload. Failed to read context ID";
    return;
  }
  if (context_id != 0) {
    DLOG(WARNING) << "Ignoring HTTP Datagram with unrecognized context ID "
                  << context_id;
    return;
  }
  std::string_view http_payload = reader.ReadRemainingPayload();

  // If there's a read callback, process the payload immediately.
  if (read_callback_) {
    int result;
    int bytes_read = http_payload.size();
    if (http_payload.size() > static_cast<std::size_t>(read_buf_len_)) {
      result = ERR_MSG_TOO_BIG;
    } else {
      CHECK(read_buf_ != nullptr);
      CHECK(read_buf_len_ > 0);

      std::memcpy(read_buf_->data(), http_payload.data(), http_payload.size());
      result = bytes_read;
    }

    read_buf_ = nullptr;
    read_buf_len_ = 0;
    std::move(read_callback_).Run(result);

  } else {
    base::UmaHistogramBoolean(kMaxQueueSizeHistogram,
                              datagrams_.size() >= kMaxDatagramQueueSize);
    if (datagrams_.size() >= kMaxDatagramQueueSize) {
      DLOG(WARNING) << "Dropping datagram because queue is full";
      return;
    }

    // If no read callback, store the payload in the queue.
    datagrams_.emplace(http_payload.data(), http_payload.size());
  }
}

// Silently ignore unknown capsules.
void QuicProxyDatagramClientSocket::OnUnknownCapsule(
    quic::QuicStreamId stream_id,
    const quiche::UnknownCapsule& capsule) {}

// Proxied connections are not on any specific network.
handles::NetworkHandle QuicProxyDatagramClientSocket::GetBoundNetwork() const {
  return handles::kInvalidNetworkHandle;
}

// TODO(crbug.com/41497362): Implement method.
void QuicProxyDatagramClientSocket::ApplySocketTag(const SocketTag& tag) {}

int QuicProxyDatagramClientSocket::SetMulticastInterface(
    uint32_t interface_index) {
  NOTREACHED();
}

void QuicProxyDatagramClientSocket::SetIOSNetworkServiceType(
    int ios_network_service_type) {}

int QuicProxyDatagramClientSocket::GetPeerAddress(IPEndPoint* address) const {
  *address = proxy_peer_address_;
  return OK;
}

int QuicProxyDatagramClientSocket::GetLocalAddress(IPEndPoint* address) const {
  *address = local_address_;
  return OK;
}

void QuicProxyDatagramClientSocket::UseNonBlockingIO() {
  NOTREACHED();
}

int QuicProxyDatagramClientSocket::SetDoNotFragment() {
  NOTREACHED();
}

int QuicProxyDatagramClientSocket::SetRecvTos() {
  NOTREACHED();
}

int QuicProxyDatagramClientSocket::SetTos(net::DiffServCodePoint dscp,
                                          net::EcnCodePoint ecn) {
  return OK;
}

void QuicProxyDatagramClientSocket::SetMsgConfirm(bool confirm) {
  NOTREACHED();
}

const NetLogWithSource& QuicProxyDatagramClientSocket::NetLog() const {
  return net_log_;
}

net::DscpAndEcn QuicProxyDatagramClientSocket::GetLastTos() const {
  return {net::DSCP_DEFAULT, net::ECN_DEFAULT};
}

int QuicProxyDatagramClientSocket::Read(IOBuffer* buf,
                                        int buf_len,
                                        CompletionOnceCallback callback) {
  CHECK(connect_callback_.is_null());
  CHECK(read_callback_.is_null());
  CHECK(!read_buf_);
  CHECK(read_buf_len_ == 0);

  if (next_state_ == STATE_DISCONNECTED) {
    return ERR_SOCKET_NOT_CONNECTED;
  }

  // Return 0 if stream closed, signaling end-of-file or no more data.
  if (!stream_handle_->IsOpen()) {
    return 0;
  }

  // If there are datagrams available, attempt to read the first one into the
  // buffer.
  if (!datagrams_.empty()) {
    auto& datagram = datagrams_.front();
    int result;
    int bytes_read = datagram.size();

    if (datagram.size() > static_cast<std::size_t>(buf_len)) {
      result = ERR_MSG_TOO_BIG;
    } else {
      std::memcpy(buf->data(), datagram.data(), datagram.size());
      result = bytes_read;
    }
    datagrams_.pop();
    return result;
  }

  // Save read callback so we can call it next time we receive a datagram.
  read_callback_ = std::move(callback);
  read_buf_ = buf;
  read_buf_len_ = buf_len;
  return ERR_IO_PENDING;
}

int QuicProxyDatagramClientSocket::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(connect_callback_.is_null());

  if (next_state_ != STATE_CONNECT_COMPLETE) {
    return ERR_SOCKET_NOT_CONNECTED;
  }

  net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_SENT, buf_len,
                                buf->data());

  std::string_view packet(buf->data(), buf_len);
  int rv = stream_handle_->WriteConnectUdpPayload(packet);
  if (rv == OK) {
    return buf_len;
  }
  return rv;
}

void QuicProxyDatagramClientSocket::OnIOComplete(int result) {
  DCHECK_NE(STATE_DISCONNECTED, next_state_);
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    // Connect() finished (successfully or unsuccessfully).
    DCHECK(!connect_callback_.is_null());
    std::move(connect_callback_).Run(rv);
  }
}

int QuicProxyDatagramClientSocket::DoLoop(int last_io_result) {
  DCHECK_NE(next_state_, STATE_DISCONNECTED);
  int rv = last_io_result;
  do {
    State state = next_state_;
    next_state_ = STATE_DISCONNECTED;
    // TODO(crbug.com/326437102): Add support for generate auth token request
    // and complete states.
    switch (state) {
      case STATE_SEND_REQUEST:
        DCHECK_EQ(OK, rv);
        net_log_.BeginEvent(
            NetLogEventType::HTTP_TRANSACTION_TUNNEL_SEND_REQUEST);
        rv = DoSendRequest();
        break;
      case STATE_SEND_REQUEST_COMPLETE:
        net_log_.EndEventWithNetErrorCode(
            NetLogEventType::HTTP_TRANSACTION_TUNNEL_SEND_REQUEST, rv);
        rv = DoSendRequestComplete(rv);
        break;
      case STATE_READ_REPLY:
        rv = DoReadReply();
        break;
      case STATE_READ_REPLY_COMPLETE:
        rv = DoReadReplyComplete(rv);
        net_log_.EndEventWithNetErrorCode(
            NetLogEventType::HTTP_TRANSACTION_TUNNEL_READ_HEADERS, rv);
        break;
      default:
        NOTREACHED() << "bad state";
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_DISCONNECTED &&
           next_state_ != STATE_CONNECT_COMPLETE);
  return rv;
}

int QuicProxyDatagramClientSocket::DoSendRequest() {
  next_state_ = STATE_SEND_REQUEST_COMPLETE;

  if (!url_.has_host()) {
    return ERR_ADDRESS_INVALID;
  }
  std::string host = url_.host();
  int port = url_.IntPort();
  std::string host_and_port =
      url_.has_port() ? base::StrCat({host, ":", base::NumberToString(port)})
                      : std::move(host);
  request_.extra_headers.SetHeader(HttpRequestHeaders::kHost, host_and_port);

  HttpRequestHeaders authorization_headers;
  // TODO(crbug.com/326437102):  Add Proxy-Authentication headers.
  request_.extra_headers.MergeFrom(authorization_headers);

  if (proxy_delegate_) {
    HttpRequestHeaders proxy_delegate_headers;
    int result = proxy_delegate_->OnBeforeTunnelRequest(
        proxy_chain(), proxy_chain_index(), &proxy_delegate_headers);
    if (result < 0) {
      return result;
    }
    request_.extra_headers.MergeFrom(proxy_delegate_headers);
  }

  if (!user_agent_.empty()) {
    request_.extra_headers.SetHeader(HttpRequestHeaders::kUserAgent,
                                     user_agent_);
  }

  request_.extra_headers.SetHeader("capsule-protocol", "?1");

  // Generate a fake request line for logging purposes.
  std::string request_line =
      base::StringPrintf("CONNECT-UDP %s HTTP/3\r\n", url_.path().c_str());
  NetLogRequestHeaders(net_log_,
                       NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
                       request_line, &request_.extra_headers);

  quiche::HttpHeaderBlock headers;
  CreateSpdyHeadersFromHttpRequestForExtendedConnect(
      request_, /*priority=*/std::nullopt, "connect-udp",
      request_.extra_headers, &headers);

  return stream_handle_->WriteHeaders(std::move(headers), false, nullptr);
}

int QuicProxyDatagramClientSocket::DoSendRequestComplete(int result) {
  if (result >= 0) {
    // Wait for HEADERS frame from the server
    next_state_ = STATE_READ_REPLY;  // STATE_READ_REPLY_COMPLETE;
    result = OK;
  }

  if (result >= 0 || result == ERR_IO_PENDING) {
    // Emit extra event so can use the same events as HttpProxyClientSocket.
    net_log_.BeginEvent(NetLogEventType::HTTP_TRANSACTION_TUNNEL_READ_HEADERS);
  }

  return result;
}

int QuicProxyDatagramClientSocket::DoReadReply() {
  next_state_ = STATE_READ_REPLY_COMPLETE;

  int rv = stream_handle_->ReadInitialHeaders(
      &response_header_block_,
      base::BindOnce(
          &QuicProxyDatagramClientSocket::OnReadResponseHeadersComplete,
          weak_factory_.GetWeakPtr()));
  if (rv == ERR_IO_PENDING) {
    return ERR_IO_PENDING;
  }
  if (rv < 0) {
    return rv;
  }

  return ProcessResponseHeaders(response_header_block_);
}

int QuicProxyDatagramClientSocket::DoReadReplyComplete(int result) {
  if (result < 0) {
    return result;
  }

  NetLogResponseHeaders(
      net_log_, NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      response_.headers.get());

  // TODO(crbug.com/326437102): Add case for Proxy Authentication.
  if (proxy_delegate_) {
    int rv = proxy_delegate_->OnTunnelHeadersReceived(
        proxy_chain(), proxy_chain_index(), *response_.headers);
    if (rv != OK) {
      CHECK_NE(ERR_IO_PENDING, rv);
      return rv;
    }
  }

  switch (response_.headers->response_code()) {
    case 200:  // OK
      next_state_ = STATE_CONNECT_COMPLETE;
      return OK;

    default:
      // Ignore response to avoid letting the proxy impersonate the target
      // server.  (See http://crbug.com/137891.)
      return ERR_TUNNEL_CONNECTION_FAILED;
  }
}

void QuicProxyDatagramClientSocket::OnReadResponseHeadersComplete(int result) {
  // Convert the now-populated quiche::HttpHeaderBlock to HttpResponseInfo
  if (result > 0) {
    result = ProcessResponseHeaders(response_header_block_);
  }

  if (result != ERR_IO_PENDING) {
    OnIOComplete(result);
  }
}

int QuicProxyDatagramClientSocket::ProcessResponseHeaders(
    const quiche::HttpHeaderBlock& headers) {
  if (SpdyHeadersToHttpResponse(headers, &response_) != OK) {
    DLOG(WARNING) << "Invalid headers";
    return ERR_QUIC_PROTOCOL_ERROR;
  }
  return OK;
}

}  // namespace net
```