Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Initial Skim and Keyword Spotting:**

The first step is to quickly read through the code, paying attention to keywords and structure. I noticed:

* `#include` directives suggest this code interacts with network functionalities, including QUIC, UDP, and HTTP.
* Class name `ConnectUdpTunnel` strongly hints at its core purpose.
* Methods like `OpenTunnel`, `ReceiveComplete`, `SendUdpPacketToTarget` reinforce the tunneling idea.
* Mentions of `HttpHeaderBlock`, `QuicServerId`, `SocketFactory` connect it to the Chromium networking stack.
* References to MASQUE (`/.well-known/masque/udp/...`) point to a specific proxying mechanism.
* The `Validate...` functions indicate input sanitization and security considerations.

**2. Identifying the Core Functionality:**

Based on the keywords and method names, the primary function becomes clear: establishing a UDP tunnel through a QUIC connection. This means taking UDP packets from a client, encapsulating them, sending them over QUIC to a target server, and vice-versa.

**3. Deconstructing the Key Methods:**

Next, I analyzed the most important methods to understand the workflow:

* **`ConnectUdpTunnel` (constructor):**  Initializes the tunnel with necessary dependencies like a socket factory and acceptable target servers. This suggests a configuration step.
* **`OpenTunnel`:** This is the entry point for establishing the tunnel. It validates headers, parses the target address from the path, and creates a UDP socket to the target. The header validation is crucial for security and correctness.
* **`ReceiveComplete`:** Handles incoming UDP packets from the target server. It encapsulates these packets into QUIC datagrams and sends them back to the client.
* **`SendUdpPacketToTarget`:** Handles incoming QUIC datagrams from the client. It decapsulates the UDP packet and sends it to the target server.
* **`OnHttp3Datagram`:**  Receives QUIC datagrams and determines if they contain UDP data. This is the core of the QUIC encapsulation/decapsulation.
* **`SendConnectResponse`:** Sends a successful HTTP response to the client, indicating the tunnel is established.
* **`SendErrorResponse`:** Sends an error response to the client if something goes wrong.
* **`TerminateClientStream`:** Closes the QUIC stream associated with the tunnel.

**4. Mapping Functionality to Use Cases and Error Scenarios:**

With a good understanding of the methods, I started thinking about how this code would be used and where things could go wrong:

* **Successful Tunneling:** A client sends a `CONNECT` request with the correct headers and target information. The server successfully connects to the target and relays UDP packets.
* **Invalid Requests:**  Incorrect headers, malformed paths, or disallowed target addresses would lead to errors.
* **Network Issues:** DNS resolution failures, connection refused errors, or other network problems on either the client or target side could occur.
* **Data Corruption/Parsing Errors:** Incorrectly formatted QUIC datagrams could cause parsing failures.

**5. Considering JavaScript Relevance:**

The key connection to JavaScript is in the context of web browsers. Browsers might use this mechanism (via the underlying Chromium networking stack) for:

* **WebSockets over UDP:**  Although not directly mentioned, this could be a building block for future extensions.
* **QUIC-based VPNs or Proxies:**  This is the most direct relevance, as the code is clearly for a proxying mechanism (MASQUE).
* **Specialized Browser Features:**  Certain experimental or browser-specific features might leverage UDP tunneling.

**6. Constructing Examples (Input/Output, User Errors):**

To illustrate the functionality and potential issues, I created concrete examples:

* **Input/Output:**  Showing the expected format of the CONNECT request and the data flow for UDP packets.
* **User Errors:**  Focusing on common mistakes like incorrect URL formatting or specifying disallowed ports.

**7. Tracing User Actions (Debugging):**

To address the debugging aspect, I thought about how a user's actions in a browser could lead to this code being executed:

* **Clicking a link:**  The link could point to a resource requiring a CONNECT-UDP tunnel.
* **Using a browser extension:** The extension might initiate such a connection.
* **Automatic browser processes:**  Certain browser features might internally use this mechanism.

**8. Structuring the Explanation:**

Finally, I organized the information into logical sections:

* **Functionality:** A high-level overview.
* **JavaScript Relationship:**  Connecting the C++ code to web browser behavior.
* **Logic and Examples:** Illustrating the process with input/output scenarios.
* **User Errors:**  Highlighting common pitfalls.
* **Debugging:**  Providing steps to trace the execution flow.

**Self-Correction/Refinement:**

During the process, I might have initially focused too much on low-level details. I had to step back and ensure the explanation was clear and addressed the user's request comprehensively. For instance, I initially overlooked the significance of the MASQUE protocol, but then realized its central role and emphasized it. I also made sure to use clear and concise language, avoiding overly technical jargon where possible.
这个C++源代码文件 `connect_udp_tunnel.cc` 的主要功能是**在QUIC连接之上建立一个UDP隧道（UDP-over-QUIC tunneling）**。它实现了MASQUE（Multiplexed Application Substrate over QUIC Encryption）协议中定义的CONNECT-UDP功能，允许客户端通过QUIC连接向目标服务器发送和接收UDP数据包，就像直接与目标服务器建立UDP连接一样。

**以下是该文件的详细功能分解：**

1. **接收和解析客户端的CONNECT-UDP请求:**
   - 当QUIC服务器接收到一个针对特定路径（`/.well-known/masque/udp/{target_host}/{target_port}/`）且方法为`CONNECT`，协议为`connect-udp`的HTTP/3请求时，这个文件中的代码会被调用。
   - `ValidateHeadersAndGetTarget` 函数会验证请求头（例如 `:method`, `:protocol`, `:authority`, `:scheme`, `:path`）是否符合CONNECT-UDP规范。
   - `ValidateAndParseTargetFromPath` 函数会从请求路径中解析出目标服务器的主机名和端口号。

2. **验证目标服务器:**
   - `ValidateTarget` 函数会检查解析出的目标服务器是否在允许的目标列表中 (`acceptable_targets_`)，这是一个安全措施，防止代理服务器被滥用。

3. **建立到目标服务器的UDP连接:**
   - 使用 `SocketFactory` 创建一个非阻塞的UDP客户端套接字，并尝试连接到解析出的目标服务器地址。

4. **在QUIC连接和UDP连接之间转发数据:**
   - **从目标服务器接收UDP数据:**  当目标服务器发送UDP数据时，`ReceiveComplete` 函数会被调用。它将接收到的UDP数据封装成MASQUE CONNECT-UDP数据报载荷（`quiche::ConnectUdpDatagramUdpPacketPayload`），并通过QUIC流发送回客户端。
   - **从客户端接收QUIC数据报:** 当客户端通过QUIC流发送HTTP/3数据报时，`OnHttp3Datagram` 函数会被调用。它解析数据报载荷，如果载荷类型是UDP数据包（`quiche::ConnectUdpDatagramPayload::Type::kUdpPacket`），则将UDP数据包内容提取出来，并通过之前建立的UDP套接字发送到目标服务器。

5. **处理连接状态和错误:**
   - `ConnectComplete` 函数处理UDP连接的完成状态（在本代码中，由于使用了阻塞连接，所以这个函数实际上不会被调用）。
   - 如果建立UDP连接失败，或者请求头不合法，或者目标服务器不允许，会发送相应的HTTP错误响应给客户端 (`SendErrorResponse`)。
   - 如果客户端QUIC流关闭 (`OnClientStreamClose`)，也会关闭与目标服务器的UDP连接。

6. **发送CONNECT成功响应:**
   - 一旦成功建立到目标服务器的UDP连接，会发送一个HTTP 200 OK响应，并在响应头中包含 `Capsule-Protocol: 1`，表明支持HTTP/3数据报。

**与JavaScript的功能关系：**

这个C++代码本身不直接包含JavaScript代码，但它为浏览器中的JavaScript代码提供了底层网络能力。

**举例说明：**

假设一个运行在浏览器中的JavaScript应用需要通过代理服务器与一个特定的UDP服务器通信。

1. **JavaScript 发起请求:** JavaScript 代码可以使用 Fetch API 或其他网络 API 发起一个 `CONNECT` 请求到代理服务器的特定路径，例如：

   ```javascript
   fetch('https://proxy.example.com/.well-known/masque/udp/target.example.net/1234/', {
       method: 'CONNECT',
       headers: {
           ':protocol': 'connect-udp'
       }
   }).then(response => {
       if (response.ok) {
           console.log('UDP tunnel established!');
           // 可以开始通过 QUIC 数据报发送/接收 UDP 数据
       } else {
           console.error('Failed to establish UDP tunnel:', response.status);
       }
   });
   ```

2. **C++ 代码处理请求:**  `connect_udp_tunnel.cc` 中的代码会在代理服务器端接收并处理这个 `CONNECT` 请求，解析出目标地址 `target.example.net:1234`，并尝试建立到该地址的UDP连接。

3. **JavaScript 发送 UDP 数据:** 一旦隧道建立，JavaScript 可以通过 WebTransport API 发送 HTTP/3 数据报，其中包含要发送到目标服务器的 UDP 数据。浏览器底层会将这些数据报封装并通过 QUIC 连接发送到代理服务器。

   ```javascript
   // 假设已经建立了 WebTransport 会话 'transport'
   const sendStream = await transport.createSendStream();
   const writer = sendStream.writable.getWriter();
   const udpData = new Uint8Array([0x01, 0x02, 0x03]); // 要发送的 UDP 数据
   const encoder = new TextEncoder();
   const payload = encoder.encode('\x00' + String.fromCharCode(...udpData)); // 封装成 MASQUE 数据报
   writer.write(payload);
   writer.close();
   ```

4. **C++ 代码转发 UDP 数据:** `connect_udp_tunnel.cc` 会接收到这些 QUIC 数据报，提取出 UDP 数据，并通过建立的 UDP 连接发送到 `target.example.net:1234`。

5. **C++ 代码接收 UDP 数据并转发:** 当 `target.example.net` 的服务器响应时，`connect_udp_tunnel.cc` 接收到 UDP 数据，并将其封装成 QUIC 数据报发送回浏览器。

6. **JavaScript 接收 UDP 数据:** JavaScript 代码可以通过 WebTransport API 接收到包含 UDP 数据的 QUIC 数据报。

**逻辑推理、假设输入与输出：**

**假设输入（客户端请求）：**

```
CONNECT /.well-known/masque/udp/example.com/8080/ HTTP/3
:method: CONNECT
:authority: proxy.example.net
:scheme: https
:path: /.well-known/masque/udp/example.com/8080/
:protocol: connect-udp
```

**假设输出（服务器响应，如果成功）：**

```
HTTP/3 200 OK
capsule-protocol: 1
```

**假设输入（客户端发送的 UDP 数据，封装在 QUIC 数据报中）：**

一个包含 UDP 数据的 HTTP/3 数据报，其 payload 结构如 MASQUE 规范定义，例如以 `\x00` 开头表示 UDP 数据包。

**假设输出（转发到目标服务器的 UDP 数据）：**

直接发送到 `example.com:8080` 的原始 UDP 数据包。

**假设输入（从目标服务器接收的 UDP 数据）：**

从 `example.com:8080` 发送回来的原始 UDP 数据包。

**假设输出（发送回客户端的 QUIC 数据报）：**

将接收到的 UDP 数据封装成 MASQUE CONNECT-UDP 数据报载荷后的 HTTP/3 数据报。

**用户或编程常见的使用错误：**

1. **错误的请求路径:**  用户或程序可能发送到错误的路径，例如 `/masque/udp/example.com/8080/` (缺少 `.well-known`) 或路径格式不正确。这会导致 `ValidateAndParseTargetFromPath` 返回 `nullopt`。

   ```
   // 假设的错误请求
   CONNECT /masque/udp/example.com/8080/ HTTP/3
   ...
   ```

   **后果:** 服务器会发送一个错误响应，因为无法解析目标地址。

2. **请求头不完整或错误:** 缺少必要的请求头（如 `:method`, `:protocol`），或者请求头的值不符合规范。这会导致 `ValidateHeadersAndGetTarget` 返回 `nullopt`。

   ```
   // 假设的错误请求
   CONNECT /.well-known/masque/udp/example.com/8080/ HTTP/3
   :method: GET  // 错误的方法
   ...
   ```

   **后果:** 服务器会发送一个错误响应，指示请求头无效。

3. **目标服务器不在允许列表中:** 如果 `acceptable_targets_` 中没有包含请求中的目标服务器，`ValidateTarget` 会返回 `false`。

   **后果:** 服务器会发送一个 "403 Forbidden" 错误响应，并带有 "Proxy-Status" 头，指示目标被禁止。

4. **DNS 解析失败:**  如果无法解析目标服务器的主机名，`tools::LookupAddress` 会返回未初始化的地址。

   **后果:** 服务器会发送一个 "500 Internal Server Error" 错误响应，并带有 "Proxy-Status" 头，指示 DNS 错误。

5. **无法连接到目标服务器的 UDP 端口:**  目标服务器可能没有监听指定的 UDP 端口，或者存在网络连接问题。

   **后果:** `target_socket_->ConnectBlocking()` 会返回错误状态，服务器会发送一个 "502 Bad Gateway" 错误响应，并带有 "Proxy-Status" 头，指示 UDP 套接字错误。

6. **发送或接收数据时出错:**  在与目标服务器或客户端之间发送或接收 UDP 数据时，可能发生网络错误。

   **后果:** 可能会打印警告日志，并且连接可能被断开。

7. **客户端发送了格式错误的 HTTP/3 数据报:** 客户端发送的 HTTP/3 数据报的 payload 格式不符合 MASQUE 规范，导致无法解析。

   **后果:** `OnHttp3Datagram` 中解析 payload 失败，数据报会被忽略。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个需要建立 UDP 连接的网页或应用。**
2. **网页中的 JavaScript 代码（或浏览器扩展）尝试通过代理服务器建立 UDP 隧道。** 这通常涉及到使用 Fetch API 或 WebTransport API 发送一个 `CONNECT` 请求到代理服务器的特定 MASQUE 路径。
3. **浏览器将该 `CONNECT` 请求通过 QUIC 连接发送到代理服务器。**
4. **代理服务器接收到该 QUIC 连接上的 HTTP/3 请求。**
5. **代理服务器的网络栈根据请求的路径和方法，将请求路由到处理 CONNECT-UDP 请求的模块，即 `connect_udp_tunnel.cc` 中的代码。**
6. **`connect_udp_tunnel.cc` 中的代码开始执行，进行请求解析、目标验证、UDP 连接建立等操作。**

**调试线索：**

- **检查浏览器开发者工具的网络面板:** 查看发送的 `CONNECT` 请求的状态码、请求头和响应头。
- **检查代理服务器的日志:**  查看是否有收到 `CONNECT` 请求，以及处理过程中的日志信息（例如目标解析结果、连接状态、错误信息）。`QUICHE_DVLOG` 和 `QUICHE_LOG(WARNING)` 产生的日志会非常有用。
- **使用网络抓包工具（如 Wireshark）:**  抓取客户端和代理服务器之间的 QUIC 数据包，以及代理服务器和目标服务器之间的 UDP 数据包，以分析网络通信的细节。
- **在 `connect_udp_tunnel.cc` 中添加调试日志:**  在关键函数中添加 `QUICHE_DLOG` 或 `std::cout` 输出，以便跟踪代码的执行流程和变量的值。例如，可以在 `ValidateAndParseTargetFromPath`、`ValidateTarget` 和 UDP 连接建立前后添加日志，查看目标地址是否正确解析，以及连接是否成功。
- **检查代理服务器的配置:** 确保代理服务器已启用 MASQUE CONNECT-UDP 功能，并且配置了允许的目标服务器列表。

通过以上分析，可以更深入地理解 `connect_udp_tunnel.cc` 的功能、它与 JavaScript 的关系，以及在出现问题时如何进行调试。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/tools/connect_udp_tunnel.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/connect_udp_tunnel.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/socket_factory.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quic_backend_response.h"
#include "quiche/quic/tools/quic_name_lookup.h"
#include "quiche/quic/tools/quic_simple_server_backend.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/masque/connect_udp_datagram_payload.h"
#include "quiche/common/platform/api/quiche_googleurl.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/platform/api/quiche_url_utils.h"
#include "quiche/common/structured_headers.h"

namespace quic {

namespace structured_headers = quiche::structured_headers;

namespace {

// Arbitrarily chosen. No effort has been made to figure out an optimal size.
constexpr size_t kReadSize = 4 * 1024;

// Only support the default path
// ("/.well-known/masque/udp/{target_host}/{target_port}/")
std::optional<QuicServerId> ValidateAndParseTargetFromPath(
    absl::string_view path) {
  std::string canonicalized_path_str;
  url::StdStringCanonOutput canon_output(&canonicalized_path_str);
  url::Component path_component;
  url::CanonicalizePath(path.data(), url::Component(0, path.size()),
                        &canon_output, &path_component);
  if (!path_component.is_nonempty()) {
    QUICHE_DVLOG(1) << "CONNECT-UDP request with non-canonicalizable path: "
                    << path;
    return std::nullopt;
  }
  canon_output.Complete();
  absl::string_view canonicalized_path =
      absl::string_view(canonicalized_path_str)
          .substr(path_component.begin, path_component.len);

  std::vector<absl::string_view> path_split =
      absl::StrSplit(canonicalized_path, '/');
  if (path_split.size() != 7 || !path_split[0].empty() ||
      path_split[1] != ".well-known" || path_split[2] != "masque" ||
      path_split[3] != "udp" || path_split[4].empty() ||
      path_split[5].empty() || !path_split[6].empty()) {
    QUICHE_DVLOG(1) << "CONNECT-UDP request with bad path: "
                    << canonicalized_path;
    return std::nullopt;
  }

  std::optional<std::string> decoded_host =
      quiche::AsciiUrlDecode(path_split[4]);
  if (!decoded_host.has_value()) {
    QUICHE_DVLOG(1) << "CONNECT-UDP request with undecodable host: "
                    << path_split[4];
    return std::nullopt;
  }
  // Empty host checked above after path split. Expect decoding to never result
  // in an empty decoded host from non-empty encoded host.
  QUICHE_DCHECK(!decoded_host->empty());

  std::optional<std::string> decoded_port =
      quiche::AsciiUrlDecode(path_split[5]);
  if (!decoded_port.has_value()) {
    QUICHE_DVLOG(1) << "CONNECT-UDP request with undecodable port: "
                    << path_split[5];
    return std::nullopt;
  }
  // Empty port checked above after path split. Expect decoding to never result
  // in an empty decoded port from non-empty encoded port.
  QUICHE_DCHECK(!decoded_port->empty());

  int parsed_port_number = url::ParsePort(
      decoded_port->data(), url::Component(0, decoded_port->size()));
  // Negative result is either invalid or unspecified, either of which is
  // disallowed for this parse. Port 0 is technically valid but reserved and not
  // really usable in practice, so easiest to just disallow it here.
  if (parsed_port_number <= 0) {
    QUICHE_DVLOG(1) << "CONNECT-UDP request with bad port: " << *decoded_port;
    return std::nullopt;
  }
  // Expect url::ParsePort() to validate port is uint16_t and otherwise return
  // negative number checked for above.
  QUICHE_DCHECK_LE(parsed_port_number, std::numeric_limits<uint16_t>::max());

  return QuicServerId(*decoded_host, static_cast<uint16_t>(parsed_port_number));
}

// Validate header expectations from RFC 9298, section 3.4.
std::optional<QuicServerId> ValidateHeadersAndGetTarget(
    const quiche::HttpHeaderBlock& request_headers) {
  QUICHE_DCHECK(request_headers.contains(":method"));
  QUICHE_DCHECK(request_headers.find(":method")->second == "CONNECT");
  QUICHE_DCHECK(request_headers.contains(":protocol"));
  QUICHE_DCHECK(request_headers.find(":protocol")->second == "connect-udp");

  auto authority_it = request_headers.find(":authority");
  if (authority_it == request_headers.end() || authority_it->second.empty()) {
    QUICHE_DVLOG(1) << "CONNECT-UDP request missing authority";
    return std::nullopt;
  }
  // For toy server simplicity, skip validating that the authority matches the
  // current server.

  auto scheme_it = request_headers.find(":scheme");
  if (scheme_it == request_headers.end() || scheme_it->second.empty()) {
    QUICHE_DVLOG(1) << "CONNECT-UDP request missing scheme";
    return std::nullopt;
  } else if (scheme_it->second != "https") {
    QUICHE_DVLOG(1) << "CONNECT-UDP request contains unexpected scheme: "
                    << scheme_it->second;
    return std::nullopt;
  }

  auto path_it = request_headers.find(":path");
  if (path_it == request_headers.end() || path_it->second.empty()) {
    QUICHE_DVLOG(1) << "CONNECT-UDP request missing path";
    return std::nullopt;
  }
  std::optional<QuicServerId> target_server_id =
      ValidateAndParseTargetFromPath(path_it->second);

  return target_server_id;
}

bool ValidateTarget(
    const QuicServerId& target,
    const absl::flat_hash_set<QuicServerId>& acceptable_targets) {
  if (acceptable_targets.contains(target)) {
    return true;
  }

  QUICHE_DVLOG(1)
      << "CONNECT-UDP request target is not an acceptable allow-listed target: "
      << target.ToHostPortString();
  return false;
}

}  // namespace

ConnectUdpTunnel::ConnectUdpTunnel(
    QuicSimpleServerBackend::RequestHandler* client_stream_request_handler,
    SocketFactory* socket_factory, std::string server_label,
    absl::flat_hash_set<QuicServerId> acceptable_targets)
    : acceptable_targets_(std::move(acceptable_targets)),
      socket_factory_(socket_factory),
      server_label_(std::move(server_label)),
      client_stream_request_handler_(client_stream_request_handler) {
  QUICHE_DCHECK(client_stream_request_handler_);
  QUICHE_DCHECK(socket_factory_);
  QUICHE_DCHECK(!server_label_.empty());
}

ConnectUdpTunnel::~ConnectUdpTunnel() {
  // Expect client and target sides of tunnel to both be closed before
  // destruction.
  QUICHE_DCHECK(!IsTunnelOpenToTarget());
  QUICHE_DCHECK(!receive_started_);
  QUICHE_DCHECK(!datagram_visitor_registered_);
}

void ConnectUdpTunnel::OpenTunnel(
    const quiche::HttpHeaderBlock& request_headers) {
  QUICHE_DCHECK(!IsTunnelOpenToTarget());

  std::optional<QuicServerId> target =
      ValidateHeadersAndGetTarget(request_headers);
  if (!target.has_value()) {
    // Malformed request.
    TerminateClientStream(
        "invalid request headers",
        QuicResetStreamError::FromIetf(QuicHttp3ErrorCode::MESSAGE_ERROR));
    return;
  }

  if (!ValidateTarget(*target, acceptable_targets_)) {
    SendErrorResponse("403", "destination_ip_prohibited",
                      "disallowed proxy target");
    return;
  }

  // TODO(ericorth): Validate that the IP address doesn't fall into diallowed
  // ranges per RFC 9298, Section 7.
  QuicSocketAddress address = tools::LookupAddress(AF_UNSPEC, *target);
  if (!address.IsInitialized()) {
    SendErrorResponse("500", "dns_error", "host resolution error");
    return;
  }

  target_socket_ = socket_factory_->CreateConnectingUdpClientSocket(
      address,
      /*receive_buffer_size=*/0,
      /*send_buffer_size=*/0,
      /*async_visitor=*/this);
  QUICHE_DCHECK(target_socket_);

  absl::Status connect_result = target_socket_->ConnectBlocking();
  if (!connect_result.ok()) {
    SendErrorResponse(
        "502", "destination_ip_unroutable",
        absl::StrCat("UDP socket error: ", connect_result.ToString()));
    return;
  }

  QUICHE_DVLOG(1) << "CONNECT-UDP tunnel opened from stream "
                  << client_stream_request_handler_->stream_id() << " to "
                  << target->ToHostPortString();

  client_stream_request_handler_->GetStream()->RegisterHttp3DatagramVisitor(
      this);
  datagram_visitor_registered_ = true;

  SendConnectResponse();
  BeginAsyncReadFromTarget();
}

bool ConnectUdpTunnel::IsTunnelOpenToTarget() const { return !!target_socket_; }

void ConnectUdpTunnel::OnClientStreamClose() {
  QUICHE_CHECK(client_stream_request_handler_);

  QUICHE_DVLOG(1) << "CONNECT-UDP stream "
                  << client_stream_request_handler_->stream_id() << " closed";

  if (datagram_visitor_registered_) {
    client_stream_request_handler_->GetStream()
        ->UnregisterHttp3DatagramVisitor();
    datagram_visitor_registered_ = false;
  }
  client_stream_request_handler_ = nullptr;

  if (IsTunnelOpenToTarget()) {
    target_socket_->Disconnect();
  }

  // Clear socket pointer.
  target_socket_.reset();
}

void ConnectUdpTunnel::ConnectComplete(absl::Status /*status*/) {
  // Async connect not expected.
  QUICHE_NOTREACHED();
}

void ConnectUdpTunnel::ReceiveComplete(
    absl::StatusOr<quiche::QuicheMemSlice> data) {
  QUICHE_DCHECK(IsTunnelOpenToTarget());
  QUICHE_DCHECK(receive_started_);

  receive_started_ = false;

  if (!data.ok()) {
    if (client_stream_request_handler_) {
      QUICHE_LOG(WARNING) << "Error receiving CONNECT-UDP data from target: "
                          << data.status();
    } else {
      // This typically just means a receive operation was cancelled on calling
      // target_socket_->Disconnect().
      QUICHE_DVLOG(1) << "Error receiving CONNECT-UDP data from target after "
                         "stream already closed.";
    }
    return;
  }

  QUICHE_DCHECK(client_stream_request_handler_);
  quiche::ConnectUdpDatagramUdpPacketPayload payload(data->AsStringView());
  client_stream_request_handler_->GetStream()->SendHttp3Datagram(
      payload.Serialize());

  BeginAsyncReadFromTarget();
}

void ConnectUdpTunnel::SendComplete(absl::Status /*status*/) {
  // Async send not expected.
  QUICHE_NOTREACHED();
}

void ConnectUdpTunnel::OnHttp3Datagram(QuicStreamId stream_id,
                                       absl::string_view payload) {
  QUICHE_DCHECK(IsTunnelOpenToTarget());
  QUICHE_DCHECK_EQ(stream_id, client_stream_request_handler_->stream_id());
  QUICHE_DCHECK(!payload.empty());

  std::unique_ptr<quiche::ConnectUdpDatagramPayload> parsed_payload =
      quiche::ConnectUdpDatagramPayload::Parse(payload);
  if (!parsed_payload) {
    QUICHE_DVLOG(1) << "Ignoring HTTP Datagram payload, due to inability to "
                       "parse as CONNECT-UDP payload.";
    return;
  }

  switch (parsed_payload->GetType()) {
    case quiche::ConnectUdpDatagramPayload::Type::kUdpPacket:
      SendUdpPacketToTarget(parsed_payload->GetUdpProxyingPayload());
      break;
    case quiche::ConnectUdpDatagramPayload::Type::kUnknown:
      QUICHE_DVLOG(1)
          << "Ignoring HTTP Datagram payload with unrecognized context ID.";
  }
}

void ConnectUdpTunnel::BeginAsyncReadFromTarget() {
  QUICHE_DCHECK(IsTunnelOpenToTarget());
  QUICHE_DCHECK(client_stream_request_handler_);
  QUICHE_DCHECK(!receive_started_);

  receive_started_ = true;
  target_socket_->ReceiveAsync(kReadSize);
}

void ConnectUdpTunnel::SendUdpPacketToTarget(absl::string_view packet) {
  absl::Status send_result = target_socket_->SendBlocking(std::string(packet));
  if (!send_result.ok()) {
    QUICHE_LOG(WARNING) << "Error sending CONNECT-UDP datagram to target: "
                        << send_result;
  }
}

void ConnectUdpTunnel::SendConnectResponse() {
  QUICHE_DCHECK(IsTunnelOpenToTarget());
  QUICHE_DCHECK(client_stream_request_handler_);

  quiche::HttpHeaderBlock response_headers;
  response_headers[":status"] = "200";

  std::optional<std::string> capsule_protocol_value =
      structured_headers::SerializeItem(structured_headers::Item(true));
  QUICHE_CHECK(capsule_protocol_value.has_value());
  response_headers["Capsule-Protocol"] = *capsule_protocol_value;

  QuicBackendResponse response;
  response.set_headers(std::move(response_headers));
  // Need to leave the stream open after sending the CONNECT response.
  response.set_response_type(QuicBackendResponse::INCOMPLETE_RESPONSE);

  client_stream_request_handler_->OnResponseBackendComplete(&response);
}

void ConnectUdpTunnel::SendErrorResponse(absl::string_view status,
                                         absl::string_view proxy_status_error,
                                         absl::string_view error_details) {
  QUICHE_DCHECK(!status.empty());
  QUICHE_DCHECK(!proxy_status_error.empty());
  QUICHE_DCHECK(!error_details.empty());
  QUICHE_DCHECK(client_stream_request_handler_);

#ifndef NDEBUG
  // Expect a valid status code (number, 100 to 599 inclusive) and not a
  // Successful code (200 to 299 inclusive).
  int status_num = 0;
  bool is_num = absl::SimpleAtoi(status, &status_num);
  QUICHE_DCHECK(is_num);
  QUICHE_DCHECK_GE(status_num, 100);
  QUICHE_DCHECK_LT(status_num, 600);
  QUICHE_DCHECK(status_num < 200 || status_num >= 300);
#endif  // !NDEBUG

  quiche::HttpHeaderBlock headers;
  headers[":status"] = status;

  structured_headers::Item proxy_status_item(server_label_);
  structured_headers::Item proxy_status_error_item(
      std::string{proxy_status_error});
  structured_headers::Item proxy_status_details_item(
      std::string{error_details});
  structured_headers::ParameterizedMember proxy_status_member(
      std::move(proxy_status_item),
      {{"error", std::move(proxy_status_error_item)},
       {"details", std::move(proxy_status_details_item)}});
  std::optional<std::string> proxy_status_value =
      structured_headers::SerializeList({proxy_status_member});
  QUICHE_CHECK(proxy_status_value.has_value());
  headers["Proxy-Status"] = *proxy_status_value;

  QuicBackendResponse response;
  response.set_headers(std::move(headers));

  client_stream_request_handler_->OnResponseBackendComplete(&response);
}

void ConnectUdpTunnel::TerminateClientStream(
    absl::string_view error_description, QuicResetStreamError error_code) {
  QUICHE_DCHECK(client_stream_request_handler_);

  std::string error_description_str =
      error_description.empty() ? ""
                                : absl::StrCat(" due to ", error_description);
  QUICHE_DVLOG(1) << "Terminating CONNECT stream "
                  << client_stream_request_handler_->stream_id()
                  << " with error code " << error_code.ietf_application_code()
                  << error_description_str;

  client_stream_request_handler_->TerminateStreamWithError(error_code);
}

}  // namespace quic
```