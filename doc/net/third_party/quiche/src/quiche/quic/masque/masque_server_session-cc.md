Response:
The user wants to understand the functionality of the `masque_server_session.cc` file in Chromium's network stack. They are particularly interested in its relationship with JavaScript, logical inferences, common user errors, and debugging steps.

Here's a breakdown of the thought process to address each of these points:

1. **Overall Functionality:** The file name and the included headers (`quiche/quic/masque/...`) clearly indicate that this file implements the server-side logic for the MASQUE protocol within a QUIC session. Reading the initial comments confirms this. The code interacts with network sockets, handles incoming connections, and manages the forwarding of UDP, IP, and Ethernet packets.

2. **Relationship with JavaScript:** MASQUE operates at a lower network level. JavaScript, running in a browser, interacts with web servers via higher-level APIs like `fetch` or WebSockets. While JavaScript *triggers* the network requests that eventually lead to the MASQUE server session being used, it doesn't directly interact with the C++ code in this file. The connection is indirect. Therefore, the example should focus on how a JavaScript request initiates the process.

3. **Logical Inference (Hypothetical Input/Output):**  Focus on the core functionality of the `HandleMasqueRequest` method. This method parses the incoming HTTP CONNECT request. Consider the different "connect-*" protocols.

    *   **Input:**  A `CONNECT` request with `:protocol` set to `connect-udp` and a specific path. The path needs to be correctly formatted to contain the target host and port.
    *   **Output:**  If successful, a `200` response and the creation of a UDP socket forwarding packets between the client and the target server. If there's an error (e.g., bad path), a `400` or `500` error response with details.

4. **User/Programming Errors:**  Think about common mistakes when setting up or using MASQUE.

    *   **Incorrect Path:**  Users might construct the `CONNECT` URL with the wrong format.
    *   **Missing Headers:**  Crucial headers like `:authority`, `:scheme`, `:path`, `:method`, and `:protocol` are required.
    *   **DNS Resolution Issues:** The server needs to be able to resolve the target host.

5. **User Steps to Reach This Code (Debugging):**  Trace the user's actions that would lead to this server-side code being executed.

    *   A user clicks a link or initiates a network request in a browser or application.
    *   The browser/application uses the MASQUE protocol, generating a `CONNECT` request.
    *   This request is sent over a QUIC connection to the MASQUE server.
    *   The server-side QUIC stack processes the connection, and this file's code handles the `CONNECT` request.

6. **Summarize Functionality (for Part 1):**  Condense the core responsibilities of the code based on the analysis. It's the server-side component responsible for establishing and managing MASQUE connections, handling different "connect-*" protocols, and relaying data.

**Self-Correction/Refinement during thought process:**

*   Initially, I might have considered explaining the QUIC handshake process in detail. However, the request focuses specifically on *this* file. While the QUIC handshake is a prerequisite, it's not the direct responsibility of `masque_server_session.cc`. So, focus on what happens *after* the QUIC connection is established.
*   The concealed authentication logic is complex but a key feature. It's important to mention it and its purpose.
*   The `OnSocketEvent` handling is crucial for the data forwarding. Make sure to include that.
*   Be precise about the HTTP methods and headers used in MASQUE `CONNECT` requests.
*   When discussing JavaScript, emphasize the *indirect* relationship. Avoid implying direct JavaScript code execution within this C++ file.
这是 Chromium 网络栈中处理 MASQUE 服务器会话的关键源代码文件。MASQUE (Multiplexed Application Substrate over QUIC Encryption) 是一种允许客户端通过代理服务器创建隧道的技术，用于例如访问被网络限制的内容或提高隐私性。

**功能归纳 (第 1 部分):**

`MasqueServerSession` 类的主要职责是：

1. **处理客户端发起的 MASQUE 连接请求 (CONNECT 方法):**  它接收客户端通过 QUIC 连接发送的 HTTP/3 `CONNECT` 请求，这些请求的目标是建立一个 UDP、IP 或 Ethernet 隧道。
2. **管理不同类型的 MASQUE 隧道:**
   - **CONNECT-UDP:**  允许客户端通过服务器代理转发 UDP 数据包到目标服务器。
   - **CONNECT-IP:** 允许客户端创建一个虚拟网络接口（TUN 设备），并通过服务器代理转发 IP 数据包。
   - **CONNECT-Ethernet:** 允许客户端创建一个虚拟网络接口（TAP 设备），并通过服务器代理转发以太网帧。
3. **处理 "connect-udp" 请求:**
   - 解析请求路径中的目标主机和端口。
   - 执行 DNS 解析以获取目标服务器的地址。
   - 创建一个本地 UDP socket，用于与目标服务器通信。
   - 将创建的 socket 注册到事件循环中，以便监听来自目标服务器的数据。
   - 将来自目标服务器的 UDP 数据包封装在 HTTP/3 DATAGRAM 帧中，并发送回客户端。
4. **处理 "connect-ip" 请求:**
   - 创建一个 TUN (网络隧道) 接口。
   - 将创建的 TUN 接口的文件描述符注册到事件循环中，以便监听来自 TUN 接口的数据。
   - 将通过 TUN 接口接收到的 IP 数据包封装在 HTTP/3 DATAGRAM 帧中，并发送回客户端。
5. **处理 "connect-ethernet" 请求:**
   - 创建一个 TAP (网络分接头) 接口。
   - 将创建的 TAP 接口的文件描述符注册到事件循环中，以便监听来自 TAP 接口的数据。
   - 将通过 TAP 接口接收到的以太网帧封装在 HTTP/3 DATAGRAM 帧中，并发送回客户端。
6. **处理 HTTP/3 DATAGRAM 帧的 ACK 和丢失事件:**  跟踪发送给客户端的 DATAGRAM 帧的状态。
7. **连接关闭处理:**  在 QUIC 连接关闭时，清理与该会话相关的状态，例如关闭打开的 sockets 和注销后端客户端。
8. **流关闭处理:** 在 QUIC 流关闭时，清理与该流相关的隧道状态。
9. **支持 Concealed Authentication (隐藏身份验证):**  可选地验证客户端的身份，以增强安全性。这涉及到检查 `Authorization` 请求头中的特定参数和签名。
10. **管理与后端服务的交互:**  `masque_server_backend_` 负责管理和路由 MASQUE 连接。
11. **使用事件循环 (QuicEventLoop):**  非阻塞地监听和处理来自网络 sockets 和 TUN/TAP 接口的事件。
12. **处理 SETTINGS 帧:**  确保启用了 HTTP/3 Datagram 功能，这是 MASQUE 正常运行的前提。

**与 JavaScript 的关系:**

`MasqueServerSession.cc` 是服务器端的 C++ 代码，本身不直接包含 JavaScript 代码或执行 JavaScript。 然而，它的功能与 JavaScript 有着重要的间接关系：

- **JavaScript 发起 MASQUE 连接:**  在浏览器或使用 Chromium 内核的应用中，JavaScript 代码可以使用 Fetch API 或其他网络 API 发起一个到 MASQUE 服务器的 `CONNECT` 请求。这个请求会最终到达 `MasqueServerSession::HandleMasqueRequest` 方法进行处理。

**举例说明:**

假设一个使用了 MASQUE 的 JavaScript 应用，需要通过代理连接到一个 UDP 服务。

```javascript
// JavaScript 代码 (运行在浏览器或 Node.js 环境中)
async function connectToUdpService(proxyUrl, targetHost, targetPort) {
  const url = `${proxyUrl}/.well-known/masque/udp/${encodeURIComponent(targetHost)}/${encodeURIComponent(targetPort)}/`;
  const response = await fetch(url, {
    method: 'CONNECT',
    headers: {
      ':protocol': 'connect-udp',
      // 可能包含 Concealed Authentication 相关的 Authorization 头
    },
    // ... 其他 fetch 配置
  });

  if (response.status === 200) {
    console.log("Successfully established MASQUE UDP tunnel.");
    // 接下来，应用可以通过 QUIC 流发送和接收 UDP 数据
  } else {
    console.error("Failed to establish MASQUE UDP tunnel:", response.status);
  }
}

// 使用示例
const proxyUrl = 'https://masque-server.example.com';
const targetHost = 'example.org';
const targetPort = '1234';
connectToUdpService(proxyUrl, targetHost, targetPort);
```

在这个例子中，JavaScript 代码构造了一个带有特定路径和协议头的 `CONNECT` 请求。当这个请求发送到 MASQUE 服务器时，`MasqueServerSession::HandleMasqueRequest` 会被调用来处理这个请求，并建立相应的 UDP 隧道。

**逻辑推理 (假设输入与输出):**

**假设输入 (针对 "connect-udp" 请求):**

- QUIC 连接已建立。
- 接收到一个带有以下头的 HTTP/3 `CONNECT` 请求：
  ```
  :method: CONNECT
  :scheme: https
  :authority: masque-server.example.com
  :path: /.well-known/masque/udp/target.example.net/8080/
  :protocol: connect-udp
  ```

**输出:**

1. **成功:**
   - 服务器会解析路径，提取目标主机 `target.example.net` 和端口 `8080`。
   - 服务器会尝试解析 `target.example.net:8080` 的 IP 地址。
   - 如果解析成功，服务器会创建一个本地 UDP socket 并绑定。
   - 服务器会将该 socket 注册到事件循环。
   - 服务器会发送一个 `200 OK` 响应给客户端。
   - 后续客户端发送到该 QUIC 流的数据会被服务器通过创建的 UDP socket 转发到 `target.example.net:8080`，反之亦然。

2. **失败 (例如，路径错误):**
   - 服务器解析路径时发现格式不正确。
   - 服务器会创建一个 `QuicBackendResponse`，设置状态码为 `400`，并包含错误详情，例如 "Bad path"。
   - 服务器会将此响应发送回客户端。

**用户或编程常见的使用错误:**

1. **错误的请求路径:** 用户或开发者可能构建了不符合 MASQUE 路径规范的 `CONNECT` 请求，例如缺少必要的片段或格式错误。
   ```
   // 错误的路径示例
   const url = 'https://masque-server.example.com/.well-known/masque/udp/target.example.net/';
   ```
   服务器会返回 `400 Bad path` 错误。

2. **缺少必要的请求头:**  `CONNECT` 请求必须包含 `:protocol` 头，对于某些配置，可能还需要 `Authorization` 头。
   ```javascript
   // 缺少 :protocol 头的示例
   await fetch('https://masque-server.example.com/...', { method: 'CONNECT' });
   ```
   服务器会返回 `400 Missing :protocol` 错误。

3. **目标主机无法解析:**  如果 MASQUE 服务器无法解析请求路径中指定的目标主机名，会导致连接失败。
   ```
   const targetHost = 'invalid-hostname-that-does-not-exist.example';
   // ... 构建包含上述 targetHost 的 CONNECT 请求
   ```
   服务器会返回 `500 DNS resolution failed` 错误。

4. **Concealed Authentication 配置错误:** 如果启用了 Concealed Authentication，客户端提供的 `Authorization` 头信息不正确（例如，签名错误，密钥 ID 不匹配），会导致身份验证失败。
   服务器会返回 `401` 状态码以及相关的错误信息。

**用户操作是如何一步步的到达这里 (调试线索):**

1. **用户在浏览器或应用中执行了某些操作，需要访问位于受限网络或需要隐藏真实 IP 地址的服务。**
2. **应用或浏览器配置为使用 MASQUE 代理服务器。**
3. **JavaScript 代码 (或应用内部的网络请求逻辑) 构建并发送一个到 MASQUE 服务器的 HTTP/3 `CONNECT` 请求。**  这个请求的目的地是 MASQUE 服务器的特定端点，路径包含了目标服务的信息，并且 `:protocol` 头指定了要建立的隧道类型 (例如 `connect-udp`)。
4. **Chromium 的网络栈接收到这个 `CONNECT` 请求。**
5. **QUIC 协议栈处理该连接，并将该请求路由到相应的 `MasqueServerSession` 实例。**
6. **`MasqueServerSession::HandleMasqueRequest` 方法被调用，开始处理这个 MASQUE 连接请求。**  该方法会检查请求头，解析路径，并根据请求的协议类型执行相应的操作 (创建 UDP socket，TUN/TAP 接口等)。
7. **在处理过程中，可能会调用其他 `MasqueServerSession` 的方法，例如 `OnSocketEvent` 来处理 socket 事件，或者与其他后端服务进行交互。**

通过查看网络请求日志 (例如 Chrome 的 `chrome://net-export/`)，可以观察到客户端发送的 `CONNECT` 请求的详细信息。在服务器端，可以通过添加日志输出来跟踪 `MasqueServerSession` 中各个方法的执行情况，以及请求头的解析结果和 socket 的创建状态等，从而进行调试。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/masque/masque_server_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/masque/masque_server_session.h"

#include <fcntl.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>

#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>


#include "absl/algorithm/container.h"
#include "absl/cleanup/cleanup.h"
#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "openssl/curve25519.h"
#include "quiche/quic/core/crypto/quic_compressed_certs_cache.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/frames/quic_connection_close_frame.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/http/quic_spdy_stream.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_crypto_server_stream_base.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_udp_socket.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/masque/masque_server_backend.h"
#include "quiche/quic/masque/masque_utils.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quic_backend_response.h"
#include "quiche/quic/tools/quic_simple_server_backend.h"
#include "quiche/quic/tools/quic_simple_server_session.h"
#include "quiche/quic/tools/quic_url.h"
#include "quiche/common/capsule.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_url_utils.h"
#include "quiche/common/quiche_ip_address.h"
#include "quiche/common/quiche_text_utils.h"

namespace quic {

namespace {

using ::quiche::AddressAssignCapsule;
using ::quiche::AddressRequestCapsule;
using ::quiche::Capsule;
using ::quiche::IpAddressRange;
using ::quiche::PrefixWithId;
using ::quiche::RouteAdvertisementCapsule;

// RAII wrapper for QuicUdpSocketFd.
class FdWrapper {
 public:
  // Takes ownership of |fd| and closes the file descriptor on destruction.
  explicit FdWrapper(int address_family) {
    QuicUdpSocketApi socket_api;
    fd_ =
        socket_api.Create(address_family,
                          /*receive_buffer_size =*/kDefaultSocketReceiveBuffer,
                          /*send_buffer_size =*/kDefaultSocketReceiveBuffer);
  }

  ~FdWrapper() {
    if (fd_ == kQuicInvalidSocketFd) {
      return;
    }
    QuicUdpSocketApi socket_api;
    socket_api.Destroy(fd_);
  }

  // Hands ownership of the file descriptor to the caller.
  QuicUdpSocketFd extract_fd() {
    QuicUdpSocketFd fd = fd_;
    fd_ = kQuicInvalidSocketFd;
    return fd;
  }

  // Keeps ownership of the file descriptor.
  QuicUdpSocketFd fd() { return fd_; }

  // Disallow copy and move.
  FdWrapper(const FdWrapper&) = delete;
  FdWrapper(FdWrapper&&) = delete;
  FdWrapper& operator=(const FdWrapper&) = delete;
  FdWrapper& operator=(FdWrapper&&) = delete;

 private:
  QuicUdpSocketFd fd_;
};

std::unique_ptr<QuicBackendResponse> CreateBackendErrorResponse(
    absl::string_view status, absl::string_view error_details) {
  quiche::HttpHeaderBlock response_headers;
  response_headers[":status"] = status;
  response_headers["masque-debug-info"] = error_details;
  auto response = std::make_unique<QuicBackendResponse>();
  response->set_response_type(QuicBackendResponse::REGULAR_RESPONSE);
  response->set_headers(std::move(response_headers));
  return response;
}

}  // namespace

MasqueServerSession::MasqueServerSession(
    MasqueMode masque_mode, const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection, QuicSession::Visitor* visitor,
    QuicEventLoop* event_loop, QuicCryptoServerStreamBase::Helper* helper,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    MasqueServerBackend* masque_server_backend)
    : QuicSimpleServerSession(config, supported_versions, connection, visitor,
                              helper, crypto_config, compressed_certs_cache,
                              masque_server_backend),
      masque_server_backend_(masque_server_backend),
      event_loop_(event_loop),
      masque_mode_(masque_mode) {
  // Artificially increase the max packet length to ensure we can fit QUIC
  // packets inside DATAGRAM frames.
  // TODO(b/181606597) Remove this workaround once we use PMTUD.
  connection->SetMaxPacketLength(kDefaultMaxPacketSizeForTunnels);

  masque_server_backend_->RegisterBackendClient(connection_id(), this);
  QUICHE_DCHECK_NE(event_loop_, nullptr);

  // We don't currently use `masque_mode_` but will in the future. To silence
  // clang's `-Wunused-private-field` warning for this when building QUICHE for
  // Chrome, add a use of it here.
  (void)masque_mode_;
}

void MasqueServerSession::OnMessageAcked(QuicMessageId message_id,
                                         QuicTime /*receive_timestamp*/) {
  QUIC_DVLOG(1) << "Received ack for DATAGRAM frame " << message_id;
}

void MasqueServerSession::OnMessageLost(QuicMessageId message_id) {
  QUIC_DVLOG(1) << "We believe DATAGRAM frame " << message_id << " was lost";
}

void MasqueServerSession::OnConnectionClosed(
    const QuicConnectionCloseFrame& frame, ConnectionCloseSource source) {
  QuicSimpleServerSession::OnConnectionClosed(frame, source);
  QUIC_DLOG(INFO) << "Closing connection for " << connection_id();
  masque_server_backend_->RemoveBackendClient(connection_id());
  // Clearing this state will close all sockets.
  connect_udp_server_states_.clear();
}

void MasqueServerSession::OnStreamClosed(QuicStreamId stream_id) {
  connect_udp_server_states_.remove_if(
      [stream_id](const ConnectUdpServerState& connect_udp) {
        return connect_udp.stream()->id() == stream_id;
      });
  connect_ip_server_states_.remove_if(
      [stream_id](const ConnectIpServerState& connect_ip) {
        return connect_ip.stream()->id() == stream_id;
      });
  connect_ethernet_server_states_.remove_if(
      [stream_id](const ConnectEthernetServerState& connect_ethernet) {
        return connect_ethernet.stream()->id() == stream_id;
      });

  QuicSimpleServerSession::OnStreamClosed(stream_id);
}

std::unique_ptr<QuicBackendResponse>
MasqueServerSession::MaybeCheckConcealedAuth(
    const quiche::HttpHeaderBlock& request_headers, absl::string_view authority,
    absl::string_view scheme,
    QuicSimpleServerBackend::RequestHandler* request_handler) {
  // TODO(dschinazi) Add command-line flag that makes this implementation
  // probe-resistant by returning the usual failure instead of 401.
  constexpr absl::string_view kConcealedAuthStatus = "401";
  if (!masque_server_backend_->IsConcealedAuthEnabled()) {
    return nullptr;
  }
  auto authorization_pair = request_headers.find("authorization");
  if (authorization_pair == request_headers.end()) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Missing authorization header");
  }
  absl::string_view credentials = authorization_pair->second;
  quiche::QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(&credentials);
  std::vector<absl::string_view> v =
      absl::StrSplit(credentials, absl::MaxSplits(' ', 1));
  if (v.size() != 2) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Authorization header missing space");
  }
  absl::string_view auth_scheme = v[0];
  if (auth_scheme != "Concealed") {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Unexpected auth scheme");
  }
  absl::string_view auth_parameters = v[1];
  std::vector<absl::string_view> auth_parameters_split =
      absl::StrSplit(auth_parameters, ',');
  std::optional<std::string> key_id;
  std::optional<std::string> header_public_key;
  std::optional<std::string> proof;
  std::optional<uint16_t> signature_scheme;
  std::optional<std::string> verification;
  for (absl::string_view auth_parameter : auth_parameters_split) {
    std::vector<absl::string_view> auth_parameter_split =
        absl::StrSplit(auth_parameter, absl::MaxSplits('=', 1));
    if (auth_parameter_split.size() != 2) {
      continue;
    }
    absl::string_view param_name = auth_parameter_split[0];
    quiche::QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(&param_name);
    if (param_name.size() != 1) {
      // All currently known authentication parameters are one character long.
      continue;
    }
    absl::string_view param_value = auth_parameter_split[1];
    quiche::QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(&param_value);
    std::string decoded_param;
    switch (param_name[0]) {
      case 'k': {
        if (key_id.has_value()) {
          return CreateBackendErrorResponse(kConcealedAuthStatus,
                                            "Duplicate k");
        }
        if (!absl::WebSafeBase64Unescape(param_value, &decoded_param)) {
          return CreateBackendErrorResponse(kConcealedAuthStatus,
                                            "Failed to base64 decode k");
        }
        key_id = decoded_param;
      } break;
      case 'a': {
        if (header_public_key.has_value()) {
          return CreateBackendErrorResponse(kConcealedAuthStatus,
                                            "Duplicate a");
        }
        if (!absl::WebSafeBase64Unescape(param_value, &decoded_param)) {
          return CreateBackendErrorResponse(kConcealedAuthStatus,
                                            "Failed to base64 decode a");
        }
        header_public_key = decoded_param;
      } break;
      case 'p': {
        if (proof.has_value()) {
          return CreateBackendErrorResponse(kConcealedAuthStatus,
                                            "Duplicate p");
        }
        if (!absl::WebSafeBase64Unescape(param_value, &decoded_param)) {
          return CreateBackendErrorResponse(kConcealedAuthStatus,
                                            "Failed to base64 decode p");
        }
        proof = decoded_param;
      } break;
      case 's': {
        if (signature_scheme.has_value()) {
          return CreateBackendErrorResponse(kConcealedAuthStatus,
                                            "Duplicate s");
        }
        int signature_scheme_int = 0;
        if (!absl::SimpleAtoi(param_value, &signature_scheme_int) ||
            signature_scheme_int < 0 ||
            signature_scheme_int > std::numeric_limits<uint16_t>::max()) {
          return CreateBackendErrorResponse(kConcealedAuthStatus,
                                            "Failed to parse s");
        }
        signature_scheme = static_cast<uint16_t>(signature_scheme_int);
      } break;
      case 'v': {
        if (verification.has_value()) {
          return CreateBackendErrorResponse(kConcealedAuthStatus,
                                            "Duplicate v");
        }
        if (!absl::WebSafeBase64Unescape(param_value, &decoded_param)) {
          return CreateBackendErrorResponse(kConcealedAuthStatus,
                                            "Failed to base64 decode v");
        }
        verification = decoded_param;
      } break;
    }
  }
  if (!key_id.has_value()) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Missing k auth parameter");
  }
  if (!header_public_key.has_value()) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Missing a auth parameter");
  }
  if (!proof.has_value()) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Missing p auth parameter");
  }
  if (!signature_scheme.has_value()) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Missing s auth parameter");
  }
  if (!verification.has_value()) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Missing v auth parameter");
  }
  uint8_t config_public_key[ED25519_PUBLIC_KEY_LEN];
  if (!masque_server_backend_->GetConcealedAuthKeyForId(*key_id,
                                                        config_public_key)) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Unexpected key id");
  }
  if (*header_public_key !=
      std::string(reinterpret_cast<const char*>(config_public_key),
                  sizeof(config_public_key))) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Unexpected public key in header");
  }
  std::string realm = "";
  QuicUrl url(absl::StrCat(scheme, "://", authority, "/"));
  std::optional<std::string> key_exporter_context = ComputeConcealedAuthContext(
      kEd25519SignatureScheme, *key_id, *header_public_key, scheme, url.host(),
      url.port(), realm);
  if (!key_exporter_context.has_value()) {
    return CreateBackendErrorResponse(
        "500", "Failed to generate key exporter context");
  }
  QUIC_DVLOG(1) << "key_exporter_context: "
                << absl::WebSafeBase64Escape(*key_exporter_context);
  QUICHE_DCHECK(!key_exporter_context->empty());
  std::string key_exporter_output;
  if (!GetMutableCryptoStream()->ExportKeyingMaterial(
          kConcealedAuthLabel, *key_exporter_context,
          kConcealedAuthExporterSize, &key_exporter_output)) {
    return CreateBackendErrorResponse("500", "Key exporter failed");
  }
  QUICHE_CHECK_EQ(key_exporter_output.size(), kConcealedAuthExporterSize);
  std::string signature_input =
      key_exporter_output.substr(0, kConcealedAuthSignatureInputSize);
  QUIC_DVLOG(1) << "signature_input: "
                << absl::WebSafeBase64Escape(signature_input);
  std::string expected_verification = key_exporter_output.substr(
      kConcealedAuthSignatureInputSize, kConcealedAuthVerificationSize);
  if (verification != expected_verification) {
    return CreateBackendErrorResponse(
        kConcealedAuthStatus,
        absl::StrCat("Unexpected verification, expected ",
                     absl::WebSafeBase64Escape(expected_verification),
                     " but got ", absl::WebSafeBase64Escape(*verification),
                     " - key exporter context was ",
                     absl::WebSafeBase64Escape(*key_exporter_context)));
  }
  std::string data_covered_by_signature =
      ConcealedAuthDataCoveredBySignature(signature_input);
  QUIC_DVLOG(1) << "data_covered_by_signature: "
                << absl::WebSafeBase64Escape(data_covered_by_signature);
  if (*signature_scheme != kEd25519SignatureScheme) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Unexpected signature scheme");
  }
  if (proof->size() != ED25519_SIGNATURE_LEN) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Unexpected proof length");
  }
  if (ED25519_verify(
          reinterpret_cast<const uint8_t*>(data_covered_by_signature.data()),
          data_covered_by_signature.size(),
          reinterpret_cast<const uint8_t*>(proof->data()),
          config_public_key) != 1) {
    return CreateBackendErrorResponse(kConcealedAuthStatus,
                                      "Signature failed to validate");
  }
  QUIC_LOG(INFO) << "Successfully validated signature auth for stream ID "
                 << request_handler->stream_id();
  return nullptr;
}

std::unique_ptr<QuicBackendResponse> MasqueServerSession::HandleMasqueRequest(
    const quiche::HttpHeaderBlock& request_headers,
    QuicSimpleServerBackend::RequestHandler* request_handler) {
  // Authority.
  auto authority_pair = request_headers.find(":authority");
  if (authority_pair == request_headers.end()) {
    QUIC_DLOG(ERROR) << "MASQUE request is missing :authority";
    return CreateBackendErrorResponse("400", "Missing :authority");
  }
  absl::string_view authority = authority_pair->second;
  // Scheme.
  auto scheme_pair = request_headers.find(":scheme");
  if (scheme_pair == request_headers.end()) {
    QUIC_DLOG(ERROR) << "MASQUE request is missing :scheme";
    return CreateBackendErrorResponse("400", "Missing :scheme");
  }
  absl::string_view scheme = scheme_pair->second;
  if (scheme.empty()) {
    return CreateBackendErrorResponse("400", "Empty scheme");
  }
  // Concealed authentication.
  auto concealed_auth_reply = MaybeCheckConcealedAuth(
      request_headers, authority, scheme, request_handler);
  if (concealed_auth_reply) {
    return concealed_auth_reply;
  }
  // Path.
  auto path_pair = request_headers.find(":path");
  if (path_pair == request_headers.end()) {
    QUIC_DLOG(ERROR) << "MASQUE request is missing :path";
    return CreateBackendErrorResponse("400", "Missing :path");
  }
  absl::string_view path = path_pair->second;
  if (path.empty()) {
    QUIC_DLOG(ERROR) << "MASQUE request with empty path";
    return CreateBackendErrorResponse("400", "Empty path");
  }
  // Method.
  auto method_pair = request_headers.find(":method");
  if (method_pair == request_headers.end()) {
    QUIC_DLOG(ERROR) << "MASQUE request is missing :method";
    return CreateBackendErrorResponse("400", "Missing :method");
  }
  absl::string_view method = method_pair->second;
  if (method != "CONNECT") {
    QUIC_DLOG(ERROR) << "MASQUE request with bad method \"" << method << "\"";
    if (masque_server_backend_->IsConcealedAuthOnAllRequests()) {
      return nullptr;
    } else {
      return CreateBackendErrorResponse("400", "Bad method");
    }
  }
  // Protocol.
  auto protocol_pair = request_headers.find(":protocol");
  if (protocol_pair == request_headers.end()) {
    QUIC_DLOG(ERROR) << "MASQUE request is missing :protocol";
    if (masque_server_backend_->IsConcealedAuthOnAllRequests()) {
      return nullptr;
    } else {
      return CreateBackendErrorResponse("400", "Missing :protocol");
    }
  }
  absl::string_view protocol = protocol_pair->second;
  if (protocol != "connect-udp" && protocol != "connect-ip" &&
      protocol != "connect-ethernet") {
    QUIC_DLOG(ERROR) << "MASQUE request with bad protocol \"" << protocol
                     << "\"";
    if (masque_server_backend_->IsConcealedAuthOnAllRequests()) {
      return nullptr;
    } else {
      return CreateBackendErrorResponse("400", "Bad protocol");
    }
  }

  if (protocol == "connect-ip") {
    QuicSpdyStream* stream = static_cast<QuicSpdyStream*>(
        GetActiveStream(request_handler->stream_id()));
    if (stream == nullptr) {
      QUIC_BUG(bad masque server stream type)
          << "Unexpected stream type for stream ID "
          << request_handler->stream_id();
      return CreateBackendErrorResponse("500", "Bad stream type");
    }
    QuicIpAddress client_ip = masque_server_backend_->GetNextClientIpAddress();
    QUIC_DLOG(INFO) << "Using client IP " << client_ip.ToString()
                    << " for CONNECT-IP stream ID "
                    << request_handler->stream_id();
    int fd = CreateTunInterface(client_ip);
    if (fd < 0) {
      QUIC_LOG(ERROR) << "Failed to create TUN interface for stream ID "
                      << request_handler->stream_id();
      return CreateBackendErrorResponse("500",
                                        "Failed to create TUN interface");
    }
    if (!event_loop_->RegisterSocket(fd, kSocketEventReadable, this)) {
      QUIC_DLOG(ERROR) << "Failed to register TUN fd with the event loop";
      close(fd);
      return CreateBackendErrorResponse("500", "Registering TUN socket failed");
    }
    connect_ip_server_states_.push_back(
        ConnectIpServerState(client_ip, stream, fd, this));

    quiche::HttpHeaderBlock response_headers;
    response_headers[":status"] = "200";
    auto response = std::make_unique<QuicBackendResponse>();
    response->set_response_type(QuicBackendResponse::INCOMPLETE_RESPONSE);
    response->set_headers(std::move(response_headers));
    response->set_body("");

    return response;
  }
  if (protocol == "connect-ethernet") {
    QuicSpdyStream* stream = static_cast<QuicSpdyStream*>(
        GetActiveStream(request_handler->stream_id()));
    if (stream == nullptr) {
      QUIC_BUG(bad masque server stream type)
          << "Unexpected stream type for stream ID "
          << request_handler->stream_id();
      return CreateBackendErrorResponse("500", "Bad stream type");
    }
    int fd = CreateTapInterface();
    if (fd < 0) {
      QUIC_LOG(ERROR) << "Failed to create TAP interface for stream ID "
                      << request_handler->stream_id();
      return CreateBackendErrorResponse("500",
                                        "Failed to create TAP interface");
    }
    if (!event_loop_->RegisterSocket(fd, kSocketEventReadable, this)) {
      QUIC_DLOG(ERROR) << "Failed to register TAP fd with the event loop";
      close(fd);
      return CreateBackendErrorResponse("500", "Registering TAP socket failed");
    }
    connect_ethernet_server_states_.push_back(
        ConnectEthernetServerState(stream, fd, this));

    quiche::HttpHeaderBlock response_headers;
    response_headers[":status"] = "200";
    auto response = std::make_unique<QuicBackendResponse>();
    response->set_response_type(QuicBackendResponse::INCOMPLETE_RESPONSE);
    response->set_headers(std::move(response_headers));
    response->set_body("");

    return response;
  }
  // Extract target host and port from path using default template.
  std::vector<absl::string_view> path_split = absl::StrSplit(path, '/');
  if (path_split.size() != 7 || !path_split[0].empty() ||
      path_split[1] != ".well-known" || path_split[2] != "masque" ||
      path_split[3] != "udp" || path_split[4].empty() ||
      path_split[5].empty() || !path_split[6].empty()) {
    QUIC_DLOG(ERROR) << "MASQUE request with bad path \"" << path << "\"";
    return CreateBackendErrorResponse("400", "Bad path");
  }
  std::optional<std::string> host = quiche::AsciiUrlDecode(path_split[4]);
  if (!host.has_value()) {
    QUIC_DLOG(ERROR) << "Failed to decode host \"" << path_split[4] << "\"";
    return CreateBackendErrorResponse("500", "Failed to decode host");
  }
  std::optional<std::string> port = quiche::AsciiUrlDecode(path_split[5]);
  if (!port.has_value()) {
    QUIC_DLOG(ERROR) << "Failed to decode port \"" << path_split[5] << "\"";
    return CreateBackendErrorResponse("500", "Failed to decode port");
  }

  // Perform DNS resolution.
  addrinfo hint = {};
  hint.ai_protocol = IPPROTO_UDP;

  addrinfo* info_list = nullptr;
  int result = getaddrinfo(host->c_str(), port->c_str(), &hint, &info_list);
  if (result != 0 || info_list == nullptr) {
    QUIC_DLOG(ERROR) << "Failed to resolve " << authority << ": "
                     << gai_strerror(result);
    return CreateBackendErrorResponse("500", "DNS resolution failed");
  }

  std::unique_ptr<addrinfo, void (*)(addrinfo*)> info_list_owned(info_list,
                                                                 freeaddrinfo);
  QuicSocketAddress target_server_address(info_list->ai_addr,
                                          info_list->ai_addrlen);
  QUIC_DLOG(INFO) << "Got CONNECT_UDP request on stream ID "
                  << request_handler->stream_id() << " target_server_address=\""
                  << target_server_address << "\"";

  FdWrapper fd_wrapper(target_server_address.host().AddressFamilyToInt());
  if (fd_wrapper.fd() == kQuicInvalidSocketFd) {
    QUIC_DLOG(ERROR) << "Socket creation failed";
    return CreateBackendErrorResponse("500", "Socket creation failed");
  }
  QuicSocketAddress empty_address(QuicIpAddress::Any6(), 0);
  if (target_server_address.host().IsIPv4()) {
    empty_address = QuicSocketAddress(QuicIpAddress::Any4(), 0);
  }
  QuicUdpSocketApi socket_api;
  if (!socket_api.Bind(fd_wrapper.fd(), empty_address)) {
    QUIC_DLOG(ERROR) << "Socket bind failed";
    return CreateBackendErrorResponse("500", "Socket bind failed");
  }
  if (!event_loop_->RegisterSocket(fd_wrapper.fd(), kSocketEventReadable,
                                   this)) {
    QUIC_DLOG(ERROR) << "Failed to register socket with the event loop";
    return CreateBackendErrorResponse("500", "Registering socket failed");
  }

  QuicSpdyStream* stream =
      static_cast<QuicSpdyStream*>(GetActiveStream(request_handler->stream_id()));
  if (stream == nullptr) {
    QUIC_BUG(bad masque server stream type)
        << "Unexpected stream type for stream ID "
        << request_handler->stream_id();
    return CreateBackendErrorResponse("500", "Bad stream type");
  }
  connect_udp_server_states_.push_back(ConnectUdpServerState(
      stream, target_server_address, fd_wrapper.extract_fd(), this));

  quiche::HttpHeaderBlock response_headers;
  response_headers[":status"] = "200";
  auto response = std::make_unique<QuicBackendResponse>();
  response->set_response_type(QuicBackendResponse::INCOMPLETE_RESPONSE);
  response->set_headers(std::move(response_headers));
  response->set_body("");

  return response;
}

void MasqueServerSession::OnSocketEvent(QuicEventLoop* /*event_loop*/,
                                        QuicUdpSocketFd fd,
                                        QuicSocketEventMask events) {
  if ((events & kSocketEventReadable) == 0) {
    QUIC_DVLOG(1) << "Ignoring OnEvent fd " << fd << " event mask " << events;
    return;
  }

  auto rearm = absl::MakeCleanup([&]() {
    if (!event_loop_->SupportsEdgeTriggered()) {
      if (!event_loop_->RearmSocket(fd, kSocketEventReadable)) {
        QUIC_BUG(MasqueServerSession_OnSocketEvent_Rearm)
            << "Failed to re-arm socket " << fd << " for reading";
      }
    }
  });

  if (!(HandleConnectUdpSocketEvent(fd, events) ||
        HandleConnectIpSocketEvent(fd, events) ||
        HandleConnectEthernetSocketEvent(fd, events))) {
    QUIC_BUG(MasqueServerSession_OnSocketEvent_UnhandledEvent)
        << "Got unexpected event mask " << events << " on unknown fd " << fd;
    std::move(rearm).Cancel();
  }
}

bool MasqueServerSession::HandleConnectUdpSocketEvent(
    QuicUdpSocketFd fd, QuicSocketEventMask events) {
  auto it = absl::c_find_if(connect_udp_server_states_,
                            [fd](const ConnectUdpServerState& connect_udp) {
                              return connect_udp.fd() == fd;
                            });
  if (it == connect_udp_server_states_.end()) {
    return false;
  }
  QuicSocketAddress expected_target_server_address =
      it->target_server_address();
  QUICHE_DCHECK(expected_target_server_address.IsInitialized());
  QUIC_DVLOG(1) << "Received readable event on fd " << fd << " (mask " << events
                << ") stream ID " << it->stream()->id() << " server "
                << expected_target_server_address;
  QuicUdpSocketApi socket_api;
  QuicUdpPacketInfoBitMask packet_info_interested(
      {QuicUdpPacketInfoBit::PEER_ADDRESS});
  char packet_buffer[1 + kMaxIncomingPacketSize];
  packet_buffer[0] = 0;  // context ID.
  char control_buffer[kDefaultUdpPacketControlBufferSize];
  while (true) {
    QuicUdpSocketApi::ReadPacketResult read_result;
    read_result.packet_buffer = {packet_buffer + 1, sizeof(packet_buffer) - 1};
    read_result.control_buffer = {control_buffer, sizeof(control_buffer)};
    socket_api.ReadPacket(fd, packet_info_interested, &read_result);
    if (!read_result.ok) {
      // Most likely there is nothing left to read, break out of read loop.
      break;
    }
    if (!read_result.packet_info.HasValue(QuicUdpPacketInfoBit::PEER_ADDRESS)) {
      QUIC_BUG(MasqueServerSession_HandleConnectUdpSocketEvent_MissingPeer)
          << "Missing peer address when reading from fd " << fd;
      continue;
    }
    if (read_result.packet_info.peer_address() !=
        expected_target_server_address) {
      QUIC_DLOG(ERROR) << "Ignoring UDP packet on fd " << fd
                       << " from unexpected server address "
                       << read_result.packet_info.peer_address()
                       << " (expected " << expected_target_server_address
                       << ")";
      continue;
    }
    if (!connection()->connected()) {
      QUIC_BUG(MasqueServerSession_HandleConnectUdpSocketEvent_ConnectionClosed)
          << "Unexpected incoming UDP packet on fd " << fd << " from "
          << expected_target_server_address
          << " because MASQUE connection is closed";
      return true;
    }
    // The packet is valid, send it to the client in a DATAGRAM frame.
    MessageStatus message_status =
        it->stream()->SendHttp3Datagram(absl::string_view(
            packet_buffer, read_result.packet_buffer.buffer_len + 1));
    QUIC_DVLOG(1) << "Sent UDP packet from " << expected_target_server_address
                  << " of length " << read_result.packet_buffer.buffer_len
                  << " with stream ID " << it->stream()->id()
                  << " and got message status "
                  << MessageStatusToString(message_status);
  }
  return true;
}

bool MasqueServerSession::HandleConnectIpSocketEvent(
    QuicUdpSocketFd fd, QuicSocketEventMask events) {
  auto it = absl::c_find_if(connect_ip_server_states_,
                            [fd](const ConnectIpServerState& connect_ip) {
                              return connect_ip.fd() == fd;
                            });
  if (it == connect_ip_server_states_.end()) {
    return false;
  }
  QUIC_DVLOG(1) << "Received readable event on fd " << fd << " (mask " << events
                << ") stream ID " << it->stream()->id();
  char datagram[kMasqueIpPacketBufferSize];
  datagram[0] = 0;  // Context ID.
  while (true) {
    ssize_t read_size = read(fd, datagram + 1, sizeof(datagram) - 1);
    if (read_size < 0) {
      break;
    }
    MessageStatus message_status = it->stream()->SendHttp3Datagram(
        absl::string_view(datagram, 1 + read_size));
    QUIC_DVLOG(1) << "Encapsulated IP packet of length " << read_size
                  << " with stream ID " << it->stream()->id()
                  << " and got message status "
                  << MessageStatusToString(message_status);
  }
  return true;
}

bool MasqueServerSession::HandleConnectEthernetSocketEvent(
    QuicUdpSocketFd fd, QuicSocketEventMask events) {
  auto it =
      absl::c_find_if(connect_ethernet_server_states_,
                      [fd](const ConnectEthernetServerState& connect_ethernet) {
                        return connect_ethernet.fd() == fd;
                      });
  if (it == connect_ethernet_server_states_.end()) {
    return false;
  }
  QUIC_DVLOG(1) << "Received readable event on fd " << fd << " (mask " << events
                << ") stream ID " << it->stream()->id();
  char datagram[kMasqueEthernetFrameBufferSize];
  datagram[0] = 0;  // Context ID.
  while (true) {
    ssize_t read_size = read(fd, datagram + 1, sizeof(datagram) - 1);
    if (read_size < 0) {
      break;
    }
    MessageStatus message_status = it->stream()->SendHttp3Datagram(
        absl::string_view(datagram, 1 + read_size));
    QUIC_DVLOG(1) << "Encapsulated Ethernet frame of length " << read_size
                  << " with stream ID " << it->stream()->id()
                  << " and got message status "
                  << MessageStatusToString(message_status);
  }
  return true;
}

bool MasqueServerSession::OnSettingsFrame(const SettingsFrame& frame) {
  QUIC_DLOG(INFO) << "Received SETTINGS: " << frame;
  if (!QuicSimpleServerSession::OnSettingsFrame(frame)) {
    return false;
  }
  if (!SupportsH3Datagram()) {
    QUIC_DLOG(ERROR) << "Refusing to use MASQUE without HTTP Datagrams";
    return false;
  }
  QUIC_DLOG(INFO) << "Using HTTP Datagram: " << http_datagram_support();
  return true;
}

MasqueServerSession::ConnectUdpServerState::ConnectUdpServerState(
    QuicSpdyStream* stream, const QuicSocketAddress& target_server_address,
    QuicUdpSocketFd fd, MasqueServerSession* masque_session)
    : stream_(stream),
      target_server_address_(target_server_address),
      fd_(fd),
"""


```