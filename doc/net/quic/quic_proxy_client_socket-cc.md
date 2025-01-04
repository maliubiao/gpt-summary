Response:
Let's break down the thought process for analyzing the `QuicProxyClientSocket.cc` file.

**1. Understanding the Core Purpose:**

* **Initial Reading:** The filename `quic_proxy_client_socket.cc` immediately suggests this component handles client-side proxy connections using the QUIC protocol. The `#include` directives confirm interaction with QUIC streams, sessions, and general network concepts like proxies and authentication.
* **Key Class:** The primary focus is the `QuicProxyClientSocket` class. Its constructor and member variables hint at its responsibilities: managing a QUIC stream and session for a proxy connection, dealing with authentication, and logging.

**2. Deconstructing Functionality (Method by Method):**

I'll go through the important methods, mimicking a detective approach:

* **Constructor:** What are the inputs? What does it initialize?  It takes a `QuicChromiumClientStream::Handle` and `QuicChromiumClientSession::Handle`, proxy information, user agent, endpoint, logging, and authentication details. It initializes member variables, sets the initial request method to "CONNECT," and logs the socket creation. *Hypothesis:* This class sets up the basic context for the QUIC proxy connection.

* **Destructor:** What cleanup does it perform? It disconnects and logs the socket destruction. *Hypothesis:* Simple resource cleanup.

* **`GetConnectResponseInfo`:** Returns the CONNECT response headers. *Hypothesis:* Provides access to the proxy's response to the initial CONNECT request.

* **`GetAuthController`:** Returns the authentication controller. *Hypothesis:*  Allows access to the authentication mechanism used with the proxy.

* **`RestartWithAuth`:** Returns an error indicating connection reuse is not supported for proxy authentication with QUIC streams. *Hypothesis:* This confirms the one-request-per-stream limitation in this context.

* **`SetStreamPriority`:**  A no-op (does nothing). The comment explains why: prioritization is complex with pooled connections. *Hypothesis:* Highlights a limitation of the current implementation.

* **`Connect`:** The core connection logic. It sets the `next_state_` to initiate the connection process and starts the `DoLoop`. It handles the `ERR_IO_PENDING` case for asynchronous operations. *Hypothesis:* This method orchestrates the steps needed to establish the tunnel through the proxy.

* **`Disconnect`:** Resets callbacks, the read buffer, write buffer length, sets `next_state_` to disconnected, and resets the QUIC stream. *Hypothesis:*  Performs a clean shutdown of the proxy connection.

* **`IsConnected` and `IsConnectedAndIdle`:**  Check the connection state and stream activity. *Hypothesis:* Provide ways to query the connection status.

* **`NetLog`:** Returns the net log object. *Hypothesis:* Allows logging events related to this socket.

* **`WasEverUsed`:** Delegates to the session to check if it was ever used. *Hypothesis:* Indicates if any data was transferred over the underlying QUIC session.

* **`GetNegotiatedProtocol` and `GetSSLInfo`:** Return default values. Crucially, they *don't* delegate to the underlying QUIC session. The comments explain this: this socket represents the *tunneled* connection, not the connection to the proxy itself. *Key Insight:* This is a crucial distinction and important for understanding the layered nature of the connection.

* **`GetTotalReceivedBytes`:** Delegates to the stream to get the consumed bytes. *Hypothesis:* Measures data received through the tunnel.

* **`ApplySocketTag`:**  Asserts that a non-default socket tag isn't being applied. The comment explains why: to avoid incorrectly tagging multiplexed streams when using HTTP/2 or 3 to the proxy (which isn't expected in the scenarios where socket tagging is currently used). *Hypothesis:*  Shows awareness of the complexities of socket tagging with multiplexing.

* **`Read` and `OnReadComplete`:** Handle reading data from the tunneled connection. They interact with the underlying QUIC stream's read functionality and logging. *Hypothesis:*  Responsible for receiving data from the target server through the proxy.

* **`Write` and `OnWriteComplete`:** Handle writing data to the tunneled connection. They interact with the underlying QUIC stream's write functionality and logging. *Hypothesis:* Responsible for sending data to the target server through the proxy.

* **`SetReceiveBufferSize` and `SetSendBufferSize`:** Not implemented. *Hypothesis:*  Likely handled at a lower level in the QUIC stack.

* **`GetPeerAddress` and `GetLocalAddress`:** Delegate to the session if connected. *Hypothesis:* Provide information about the proxy's address.

* **`OnIOComplete`:**  A callback for asynchronous operations in the state machine. It drives the `DoLoop`. *Hypothesis:*  A key part of the asynchronous connection process.

* **`DoLoop`:** The central state machine. It transitions through different states (`STATE_GENERATE_AUTH_TOKEN`, `STATE_SEND_REQUEST`, `STATE_READ_REPLY`, etc.) based on the results of asynchronous operations. *Crucial Insight:* This is the heart of the connection logic, orchestrating authentication, sending the CONNECT request, and receiving the response.

* **`DoGenerateAuthToken` and `DoGenerateAuthTokenComplete`:**  Handle the asynchronous process of obtaining an authentication token. *Hypothesis:* Deals with proxy authentication challenges.

* **`DoSendRequest` and `DoSendRequestComplete`:**  Construct and send the "CONNECT" request to the proxy. This includes handling authentication headers and proxy delegate interactions. *Hypothesis:* Sends the initial request to establish the tunnel.

* **`DoReadReply` and `DoReadReplyComplete`:** Read and process the proxy's response to the "CONNECT" request. This includes checking the status code and handling authentication challenges. *Hypothesis:*  Receives and interprets the proxy's response.

* **`OnReadResponseHeadersComplete` and `ProcessResponseHeaders`:** Handle the completion of reading response headers and convert them to `HttpResponseInfo`. *Hypothesis:* Parses the proxy's response headers.

**3. Identifying Relationships and Javascript Relevance:**

* **Network Stack Integration:** The code clearly operates within Chromium's network stack. It interacts with concepts like `ProxyChain`, `HttpAuthController`, `NetLog`, and `SocketTag`.
* **Javascript Connection (Indirect):**  Javascript in a web browser would initiate network requests. If a proxy is configured and the underlying connection uses QUIC, the request *could* eventually reach this code path. The connection is indirect – Javascript doesn't directly call methods in this class. It interacts with higher-level browser APIs that then utilize the network stack.
* **Example:** A Javascript `fetch()` call to an HTTPS website when a QUIC proxy is configured. The browser will handle the proxy negotiation and, if QUIC is chosen for the proxy connection, this code might be involved in establishing the tunnel to the proxy.

**4. Inferring Logic and Providing Examples:**

For the state machine (`DoLoop`), I'd trace the execution flow for a successful connection and a failed authentication scenario. This helps visualize the transitions and the role of each state.

**5. Considering User/Programming Errors:**

I'd look for potential misuse scenarios, such as:

* Calling `Read` or `Write` before `Connect` is successful.
* Incorrectly handling the `ERR_UNABLE_TO_REUSE_CONNECTION_FOR_PROXY_AUTH` error.

**6. Tracing User Actions:**

I'd connect user actions (typing a URL, clicking a link) to the eventual execution of this code by outlining the browser's process of proxy resolution and connection establishment.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:**  Maybe Javascript can directly interact with this class.
* **Correction:** Realized the interaction is indirect through browser APIs.
* **Initial thought:** Focus solely on the QUIC aspects.
* **Refinement:** Recognized the importance of the proxy context and the distinction between the connection to the proxy and the tunneled connection.
* **Initial thought:** Explain every single method in detail.
* **Refinement:** Focus on the most important methods and their roles in the connection establishment process.

By following this structured approach, combining code analysis with domain knowledge of networking and browser architecture, I can generate a comprehensive explanation of the `QuicProxyClientSocket.cc` file.
这个文件 `net/quic/quic_proxy_client_socket.cc` 是 Chromium 网络栈中处理通过 QUIC 协议连接到 HTTP 代理服务器的核心组件。它实现了 `TransportClientSocket` 接口，负责建立和管理到代理服务器的隧道连接。

**主要功能:**

1. **建立到代理服务器的 CONNECT 隧道:**
   - 该类使用 QUIC 流与代理服务器进行通信。
   - 它发送一个 HTTP `CONNECT` 请求到代理服务器，请求建立到目标服务器的隧道。
   - 它处理代理服务器的响应，验证隧道是否成功建立。

2. **处理代理身份验证:**
   - 如果代理服务器需要身份验证 (HTTP 407 Proxy Authentication Required)，该类会与 `HttpAuthController` 协同工作，生成必要的身份验证凭据 (例如，Basic 或 Digest 认证)。
   - 它会重试发送 `CONNECT` 请求，包含身份验证头。

3. **充当透明的 TCP 连接:**
   - 一旦隧道建立，该类就充当一个到目标服务器的 TCP 连接的代理。
   - 它将从上层接收到的数据（原本要发送到目标服务器）通过 QUIC 流发送到代理服务器。
   - 它将从代理服务器接收到的数据（来自目标服务器）传递给上层。

4. **管理 QUIC 流和会话:**
   - 该类拥有一个 `QuicChromiumClientStream::Handle` 和 `QuicChromiumClientSession::Handle`，用于与代理服务器进行 QUIC 通信。
   - 它负责管理这些对象的生命周期。

5. **网络日志记录:**
   - 该类使用 Chromium 的 `NetLog` 系统记录与代理连接相关的事件，用于调试和监控。

**与 Javascript 功能的关系:**

`QuicProxyClientSocket` 本身不直接与 Javascript 代码交互。Javascript 代码通过浏览器提供的 Web API (例如 `fetch`, `XMLHttpRequest`) 发起网络请求。当用户配置了 HTTP 代理并且浏览器决定使用 QUIC 连接到该代理时，网络栈的底层组件（包括 `QuicProxyClientSocket`）才会被调用。

**举例说明:**

假设一个 Javascript 代码发起一个 `fetch` 请求到一个 HTTPS 网站，并且用户的浏览器配置了使用一个支持 QUIC 的 HTTP 代理。

```javascript
fetch('https://www.example.com');
```

1. 浏览器会检测到需要使用代理。
2. 如果浏览器决定使用 QUIC 连接到代理，它会创建一个 `QuicProxyClientSocket` 实例。
3. `QuicProxyClientSocket` 会发送一个 `CONNECT` 请求到代理服务器，例如：

   ```
   CONNECT www.example.com:443 HTTP/1.1
   Host: your-proxy-server.com
   Proxy-Connection: keep-alive
   User-Agent: [浏览器User-Agent]
   ```

4. 如果代理服务器需要身份验证，`QuicProxyClientSocket` 会收到一个 407 响应，并与 `HttpAuthController` 协商生成身份验证头。然后重新发送 `CONNECT` 请求，例如：

   ```
   CONNECT www.example.com:443 HTTP/1.1
   Host: your-proxy-server.com
   Proxy-Connection: keep-alive
   User-Agent: [浏览器User-Agent]
   Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==
   ```

5. 一旦代理服务器返回 200 OK 响应，隧道建立成功。
6. 随后，当 Javascript 代码发送请求体时，`QuicProxyClientSocket` 会将这些数据通过 QUIC 流发送给代理服务器。
7. 当代理服务器从 `www.example.com` 接收到响应后，它会将响应数据通过 QUIC 流发送回客户端，`QuicProxyClientSocket` 再将这些数据传递给浏览器的上层，最终到达 Javascript 代码。

**逻辑推理 (假设输入与输出):**

**假设输入:**

- `endpoint_`: `HostPortPair("www.example.com", 443)` (目标服务器地址和端口)
- 代理服务器不需要身份验证。

**处理流程:**

1. **STATE_GENERATE_AUTH_TOKEN:** `DoGenerateAuthToken` 返回 `OK`，因为不需要身份验证。
2. **STATE_SEND_REQUEST:** `DoSendRequest` 构建并发送 `CONNECT` 请求到代理服务器。
   - **假设输出 (发送到代理服务器的数据):**
     ```
     CONNECT www.example.com:443 HTTP/1.1
     Host: your-proxy-server.com
     Proxy-Connection: keep-alive
     User-Agent: [浏览器User-Agent]
     ```
3. **STATE_SEND_REQUEST_COMPLETE:** `DoSendRequestComplete` 等待代理服务器的响应头。
4. **STATE_READ_REPLY:** `DoReadReply` 读取代理服务器的响应头。
   - **假设输出 (从代理服务器接收的响应头):**
     ```
     HTTP/1.1 200 Connection Established
     Proxy-Connection: keep-alive
     ```
5. **STATE_READ_REPLY_COMPLETE:** `DoReadReplyComplete` 解析响应头，如果状态码是 200，则进入 `STATE_CONNECT_COMPLETE`。
   - **假设输出 (返回给上层的状态):** `OK`

**假设输入:**

- `endpoint_`: `HostPortPair("www.example.com", 443)`
- 代理服务器需要 Basic 身份验证。

**处理流程:**

1. **STATE_GENERATE_AUTH_TOKEN:** `DoGenerateAuthToken` 返回 `OK`，因为需要生成身份验证令牌。
2. **STATE_SEND_REQUEST:** `DoSendRequest` 构建并发送 **不带** 身份验证头的 `CONNECT` 请求。
3. **STATE_SEND_REQUEST_COMPLETE:** `DoSendRequestComplete` 等待代理服务器的响应头。
4. **STATE_READ_REPLY:** `DoReadReply` 读取代理服务器的响应头。
   - **假设输出 (从代理服务器接收的响应头):**
     ```
     HTTP/1.1 407 Proxy Authentication Required
     Proxy-Authenticate: Basic realm="proxy"
     Proxy-Connection: close
     ```
5. **STATE_READ_REPLY_COMPLETE:** `DoReadReplyComplete` 解析响应头，识别出 407 状态码，并调用 `HandleProxyAuthChallenge`。
   - `HandleProxyAuthChallenge` 会指示 `HttpAuthController` 处理身份验证挑战。
   - `RestartWithAuth` 被调用，返回 `ERR_UNABLE_TO_REUSE_CONNECTION_FOR_PROXY_AUTH`，意味着需要建立新的连接并重新尝试身份验证。 (注意：实际的重试逻辑可能发生在更高层)

**用户或编程常见的使用错误:**

1. **在 `Connect()` 完成之前调用 `Read()` 或 `Write()`:**  这会导致 `ERR_SOCKET_NOT_CONNECTED` 错误。用户操作层面，这意味着在代理隧道建立完成之前就尝试发送或接收数据。
   - **例子:**  一个网络请求库在收到 `Connect()` 回调之前就尝试发送请求体。

2. **没有正确处理代理身份验证错误:**  如果代理需要身份验证，而客户端没有提供正确的凭据，连接将无法建立。
   - **例子:**  用户在浏览器中配置了需要身份验证的代理，但没有输入用户名和密码。

3. **QUIC 会话或流的意外关闭:**  由于网络问题或其他原因，底层的 QUIC 连接可能会中断，导致 `QuicProxyClientSocket` 无法正常工作。
   - **例子:**  网络不稳定导致 QUIC 连接断开。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中发起一个需要通过代理访问的 HTTPS 请求。** 例如，在地址栏输入 `https://www.example.com` 并回车。

2. **浏览器检查代理设置。**  如果配置了 HTTP 代理，浏览器会尝试使用该代理。

3. **浏览器网络栈尝试建立到代理服务器的连接。** 如果浏览器决定使用 QUIC 连接到代理服务器（可能是因为之前协商过或者配置了实验性 QUIC 支持），就会创建 `QuicProxyClientSocket` 实例。

4. **`QuicProxyClientSocket` 的构造函数被调用，** 初始化 QUIC 流和会话的句柄，以及其他必要的参数。

5. **调用 `Connect()` 方法，** 开始建立到目标服务器的 CONNECT 隧道。

6. **`DoLoop()` 方法驱动状态机，**  根据代理服务器的响应进行不同的操作，例如发送 `CONNECT` 请求、处理身份验证挑战等。

7. **如果在 `DoLoop()` 过程中出现问题，例如网络错误或身份验证失败，** 相应的错误码会被返回，并且可能会记录到 NetLog 中。

8. **开发人员可以使用 Chromium 的 `chrome://net-export/` 功能导出网络日志，** 其中包含了 `QuicProxyClientSocket` 相关的事件，例如发送的 HEADERS 帧、接收到的 HEADERS 帧、状态转换等。这些日志可以帮助诊断连接问题。

9. **在 Chromium 源代码中设置断点，** 可以逐步跟踪 `QuicProxyClientSocket` 的执行流程，查看变量的值，理解代码的执行逻辑。

**总结:**

`QuicProxyClientSocket` 是 Chromium 网络栈中一个关键的低级组件，负责处理通过 QUIC 协议连接到 HTTP 代理服务器的细节。它不直接与 Javascript 交互，但为基于浏览器的网络请求提供了必要的代理支持。理解其功能和状态机对于调试与 QUIC 代理连接相关的问题至关重要。

Prompt: 
```
这是目录为net/quic/quic_proxy_client_socket.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_proxy_client_socket.h"

#include <cstdio>
#include <string_view>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/values.h"
#include "net/base/proxy_chain.h"
#include "net/base/proxy_delegate.h"
#include "net/http/http_auth_controller.h"
#include "net/http/http_log_util.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_source_type.h"
#include "net/quic/quic_http_utils.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

namespace net {

QuicProxyClientSocket::QuicProxyClientSocket(
    std::unique_ptr<QuicChromiumClientStream::Handle> stream,
    std::unique_ptr<QuicChromiumClientSession::Handle> session,
    const ProxyChain& proxy_chain,
    size_t proxy_chain_index,
    const std::string& user_agent,
    const HostPortPair& endpoint,
    const NetLogWithSource& net_log,
    scoped_refptr<HttpAuthController> auth_controller,
    ProxyDelegate* proxy_delegate)
    : stream_(std::move(stream)),
      session_(std::move(session)),
      endpoint_(endpoint),
      auth_(std::move(auth_controller)),
      proxy_chain_(proxy_chain),
      proxy_chain_index_(proxy_chain_index),
      proxy_delegate_(proxy_delegate),
      user_agent_(user_agent),
      net_log_(net_log) {
  DCHECK(stream_->IsOpen());

  request_.method = "CONNECT";
  request_.url = GURL("https://" + endpoint.ToString());

  net_log_.BeginEventReferencingSource(NetLogEventType::SOCKET_ALIVE,
                                       net_log_.source());
  net_log_.AddEventReferencingSource(
      NetLogEventType::HTTP2_PROXY_CLIENT_SESSION, stream_->net_log().source());
}

QuicProxyClientSocket::~QuicProxyClientSocket() {
  Disconnect();
  net_log_.EndEvent(NetLogEventType::SOCKET_ALIVE);
}

const HttpResponseInfo* QuicProxyClientSocket::GetConnectResponseInfo() const {
  return response_.headers.get() ? &response_ : nullptr;
}

const scoped_refptr<HttpAuthController>&
QuicProxyClientSocket::GetAuthController() const {
  return auth_;
}

int QuicProxyClientSocket::RestartWithAuth(CompletionOnceCallback callback) {
  // A QUIC Stream can only handle a single request, so the underlying
  // stream may not be reused and a new QuicProxyClientSocket must be
  // created (possibly on top of the same QUIC Session).
  next_state_ = STATE_DISCONNECTED;
  return ERR_UNABLE_TO_REUSE_CONNECTION_FOR_PROXY_AUTH;
}

// Ignore priority changes, just use priority of initial request. Since multiple
// requests are pooled on the QuicProxyClientSocket, reprioritization doesn't
// really work.
//
// TODO(mmenke):  Use a single priority value for all QuicProxyClientSockets,
// regardless of what priority they're created with.
void QuicProxyClientSocket::SetStreamPriority(RequestPriority priority) {}

// Sends a HEADERS frame to the proxy with a CONNECT request
// for the specified endpoint.  Waits for the server to send back
// a HEADERS frame.  OK will be returned if the status is 200.
// ERR_TUNNEL_CONNECTION_FAILED will be returned for any other status.
// In any of these cases, Read() may be called to retrieve the HTTP
// response body.  Any other return values should be considered fatal.
int QuicProxyClientSocket::Connect(CompletionOnceCallback callback) {
  DCHECK(connect_callback_.is_null());
  if (!stream_->IsOpen())
    return ERR_CONNECTION_CLOSED;

  DCHECK_EQ(STATE_DISCONNECTED, next_state_);
  next_state_ = STATE_GENERATE_AUTH_TOKEN;

  int rv = DoLoop(OK);
  if (rv == ERR_IO_PENDING)
    connect_callback_ = std::move(callback);
  return rv;
}

void QuicProxyClientSocket::Disconnect() {
  connect_callback_.Reset();
  read_callback_.Reset();
  read_buf_ = nullptr;
  write_callback_.Reset();
  write_buf_len_ = 0;

  next_state_ = STATE_DISCONNECTED;

  stream_->Reset(quic::QUIC_STREAM_CANCELLED);
}

bool QuicProxyClientSocket::IsConnected() const {
  return next_state_ == STATE_CONNECT_COMPLETE && stream_->IsOpen();
}

bool QuicProxyClientSocket::IsConnectedAndIdle() const {
  return IsConnected() && !stream_->HasBytesToRead();
}

const NetLogWithSource& QuicProxyClientSocket::NetLog() const {
  return net_log_;
}

bool QuicProxyClientSocket::WasEverUsed() const {
  return session_->WasEverUsed();
}

NextProto QuicProxyClientSocket::GetNegotiatedProtocol() const {
  // Do not delegate to `session_`. While `session_` negotiates ALPN with the
  // proxy, this object represents the tunneled TCP connection to the origin.
  return kProtoUnknown;
}

bool QuicProxyClientSocket::GetSSLInfo(SSLInfo* ssl_info) {
  // Do not delegate to `session_`. While `session_` has a secure channel to the
  // proxy, this object represents the tunneled TCP connection to the origin.
  return false;
}

int64_t QuicProxyClientSocket::GetTotalReceivedBytes() const {
  return stream_->NumBytesConsumed();
}

void QuicProxyClientSocket::ApplySocketTag(const SocketTag& tag) {
  // In the case of a connection to the proxy using HTTP/2 or HTTP/3 where the
  // underlying socket may multiplex multiple streams, applying this request's
  // socket tag to the multiplexed session would incorrectly apply the socket
  // tag to all mutliplexed streams. Fortunately socket tagging is only
  // supported on Android without the data reduction proxy, so only simple HTTP
  // proxies are supported, so proxies won't be using HTTP/2 or HTTP/3. Enforce
  // that a specific (non-default) tag isn't being applied.
  CHECK(tag == SocketTag());
}

int QuicProxyClientSocket::Read(IOBuffer* buf,
                                int buf_len,
                                CompletionOnceCallback callback) {
  DCHECK(connect_callback_.is_null());
  DCHECK(read_callback_.is_null());
  DCHECK(!read_buf_);

  if (next_state_ == STATE_DISCONNECTED)
    return ERR_SOCKET_NOT_CONNECTED;

  if (!stream_->IsOpen()) {
    return 0;
  }

  int rv =
      stream_->ReadBody(buf, buf_len,
                        base::BindOnce(&QuicProxyClientSocket::OnReadComplete,
                                       weak_factory_.GetWeakPtr()));

  if (rv == ERR_IO_PENDING) {
    read_callback_ = std::move(callback);
    read_buf_ = buf;
  } else if (rv == 0) {
    net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_RECEIVED, 0,
                                  nullptr);
  } else if (rv > 0) {
    net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_RECEIVED, rv,
                                  buf->data());
  }
  return rv;
}

void QuicProxyClientSocket::OnReadComplete(int rv) {
  if (!stream_->IsOpen())
    rv = 0;

  if (!read_callback_.is_null()) {
    DCHECK(read_buf_);
    if (rv >= 0) {
      net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_RECEIVED, rv,
                                    read_buf_->data());
    }
    read_buf_ = nullptr;
    std::move(read_callback_).Run(rv);
  }
}

int QuicProxyClientSocket::Write(
    IOBuffer* buf,
    int buf_len,
    CompletionOnceCallback callback,
    const NetworkTrafficAnnotationTag& traffic_annotation) {
  DCHECK(connect_callback_.is_null());
  DCHECK(write_callback_.is_null());

  if (next_state_ != STATE_CONNECT_COMPLETE)
    return ERR_SOCKET_NOT_CONNECTED;

  net_log_.AddByteTransferEvent(NetLogEventType::SOCKET_BYTES_SENT, buf_len,
                                buf->data());

  int rv = stream_->WriteStreamData(
      std::string_view(buf->data(), buf_len), false,
      base::BindOnce(&QuicProxyClientSocket::OnWriteComplete,
                     weak_factory_.GetWeakPtr()));
  if (rv == OK)
    return buf_len;

  if (rv == ERR_IO_PENDING) {
    write_callback_ = std::move(callback);
    write_buf_len_ = buf_len;
  }

  return rv;
}

void QuicProxyClientSocket::OnWriteComplete(int rv) {
  if (!write_callback_.is_null()) {
    if (rv == OK)
      rv = write_buf_len_;
    write_buf_len_ = 0;
    std::move(write_callback_).Run(rv);
  }
}

int QuicProxyClientSocket::SetReceiveBufferSize(int32_t size) {
  return ERR_NOT_IMPLEMENTED;
}

int QuicProxyClientSocket::SetSendBufferSize(int32_t size) {
  return ERR_NOT_IMPLEMENTED;
}

int QuicProxyClientSocket::GetPeerAddress(IPEndPoint* address) const {
  return IsConnected() ? session_->GetPeerAddress(address)
                       : ERR_SOCKET_NOT_CONNECTED;
}

int QuicProxyClientSocket::GetLocalAddress(IPEndPoint* address) const {
  return IsConnected() ? session_->GetSelfAddress(address)
                       : ERR_SOCKET_NOT_CONNECTED;
}

void QuicProxyClientSocket::OnIOComplete(int result) {
  DCHECK_NE(STATE_DISCONNECTED, next_state_);
  int rv = DoLoop(result);
  if (rv != ERR_IO_PENDING) {
    // Connect() finished (successfully or unsuccessfully).
    DCHECK(!connect_callback_.is_null());
    std::move(connect_callback_).Run(rv);
  }
}

int QuicProxyClientSocket::DoLoop(int last_io_result) {
  DCHECK_NE(next_state_, STATE_DISCONNECTED);
  int rv = last_io_result;
  do {
    State state = next_state_;
    next_state_ = STATE_DISCONNECTED;
    switch (state) {
      case STATE_GENERATE_AUTH_TOKEN:
        DCHECK_EQ(OK, rv);
        rv = DoGenerateAuthToken();
        break;
      case STATE_GENERATE_AUTH_TOKEN_COMPLETE:
        rv = DoGenerateAuthTokenComplete(rv);
        break;
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

int QuicProxyClientSocket::DoGenerateAuthToken() {
  next_state_ = STATE_GENERATE_AUTH_TOKEN_COMPLETE;
  return auth_->MaybeGenerateAuthToken(
      &request_,
      base::BindOnce(&QuicProxyClientSocket::OnIOComplete,
                     weak_factory_.GetWeakPtr()),
      net_log_);
}

int QuicProxyClientSocket::DoGenerateAuthTokenComplete(int result) {
  DCHECK_NE(ERR_IO_PENDING, result);
  if (result == OK)
    next_state_ = STATE_SEND_REQUEST;
  return result;
}

int QuicProxyClientSocket::DoSendRequest() {
  next_state_ = STATE_SEND_REQUEST_COMPLETE;

  // Add Proxy-Authentication header if necessary.
  HttpRequestHeaders authorization_headers;
  if (auth_->HaveAuth()) {
    auth_->AddAuthorizationHeader(&authorization_headers);
  }

  if (proxy_delegate_) {
    HttpRequestHeaders proxy_delegate_headers;
    int result = proxy_delegate_->OnBeforeTunnelRequest(
        proxy_chain_, proxy_chain_index_, &proxy_delegate_headers);
    if (result < 0) {
      return result;
    }
    request_.extra_headers.MergeFrom(proxy_delegate_headers);
  }

  std::string request_line;
  BuildTunnelRequest(endpoint_, authorization_headers, user_agent_,
                     &request_line, &request_.extra_headers);

  NetLogRequestHeaders(net_log_,
                       NetLogEventType::HTTP_TRANSACTION_SEND_TUNNEL_HEADERS,
                       request_line, &request_.extra_headers);

  quiche::HttpHeaderBlock headers;
  CreateSpdyHeadersFromHttpRequest(request_, std::nullopt,
                                   request_.extra_headers, &headers);

  return stream_->WriteHeaders(std::move(headers), false, nullptr);
}

int QuicProxyClientSocket::DoSendRequestComplete(int result) {
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

int QuicProxyClientSocket::DoReadReply() {
  next_state_ = STATE_READ_REPLY_COMPLETE;

  int rv = stream_->ReadInitialHeaders(
      &response_header_block_,
      base::BindOnce(&QuicProxyClientSocket::OnReadResponseHeadersComplete,
                     weak_factory_.GetWeakPtr()));
  if (rv == ERR_IO_PENDING)
    return ERR_IO_PENDING;
  if (rv < 0)
    return rv;

  return ProcessResponseHeaders(response_header_block_);
}

int QuicProxyClientSocket::DoReadReplyComplete(int result) {
  if (result < 0)
    return result;

  // Require the "HTTP/1.x" status line for SSL CONNECT.
  if (response_.headers->GetHttpVersion() < HttpVersion(1, 0))
    return ERR_TUNNEL_CONNECTION_FAILED;

  NetLogResponseHeaders(
      net_log_, NetLogEventType::HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS,
      response_.headers.get());

  if (proxy_delegate_) {
    int rv = proxy_delegate_->OnTunnelHeadersReceived(
        proxy_chain_, proxy_chain_index_, *response_.headers);
    if (rv != OK) {
      DCHECK_NE(ERR_IO_PENDING, rv);
      return rv;
    }
  }

  switch (response_.headers->response_code()) {
    case 200:  // OK
      next_state_ = STATE_CONNECT_COMPLETE;
      return OK;

    case 407:  // Proxy Authentication Required
      next_state_ = STATE_CONNECT_COMPLETE;
      SanitizeProxyAuth(response_);
      return HandleProxyAuthChallenge(auth_.get(), &response_, net_log_);

    default:
      // Ignore response to avoid letting the proxy impersonate the target
      // server.  (See http://crbug.com/137891.)
      return ERR_TUNNEL_CONNECTION_FAILED;
  }
}

void QuicProxyClientSocket::OnReadResponseHeadersComplete(int result) {
  // Convert the now-populated quiche::HttpHeaderBlock to HttpResponseInfo
  if (result > 0)
    result = ProcessResponseHeaders(response_header_block_);

  if (result != ERR_IO_PENDING)
    OnIOComplete(result);
}

int QuicProxyClientSocket::ProcessResponseHeaders(
    const quiche::HttpHeaderBlock& headers) {
  if (SpdyHeadersToHttpResponse(headers, &response_) != OK) {
    DLOG(WARNING) << "Invalid headers";
    return ERR_QUIC_PROTOCOL_ERROR;
  }
  return OK;
}

}  // namespace net

"""

```