Response:
Let's break down the thought process for analyzing this code snippet and generating the response.

1. **Understand the Request:** The request asks for the functionality of a specific C++ source file within Chromium's network stack, focusing on its relation to JavaScript, logical reasoning with input/output, common usage errors, debugging information, and a final summary. It's the *second part* of the analysis.

2. **Initial Code Scan (Skimming):**  The first step is to quickly read through the code to get a general idea of what it's doing. Keywords like `MasqueServerSession`, `ConnectUdpServerState`, `ConnectIpServerState`, `ConnectEthernetServerState`, `Http3DatagramVisitor`, `ConnectIpVisitor`, `QuicUdpSocketFd`, `write`, `Capsule`, and `event_loop` stand out. This immediately suggests it's about handling different connection types within a MASQUE server using QUIC.

3. **Identify Core Classes and Their Roles:**  The code defines three key inner classes within `MasqueServerSession`:
    * `ConnectUdpServerState`: Handles UDP connections.
    * `ConnectIpServerState`: Handles IP-level connections.
    * `ConnectEthernetServerState`: Handles Ethernet-level connections.

4. **Analyze Each Class Individually:**

    * **`ConnectUdpServerState`:**  Notice the `OnHttp3Datagram` method. It reads a context ID and then forwards the remaining payload to a UDP socket (`fd_`). The presence of `target_server_address_` suggests it's acting as a proxy.

    * **`ConnectIpServerState`:** This is more complex. It also handles `OnHttp3Datagram`, forwarding the payload to a socket. However, it *also* implements `ConnectIpVisitor` with methods like `OnAddressAssignCapsule`, `OnAddressRequestCapsule`, `OnRouteAdvertisementCapsule`, and `OnHeadersWritten`. This indicates it's involved in network address assignment and routing, suggesting VPN-like functionality. The `OnHeadersWritten` method specifically sends `AddressAssign` and `RouteAdvertisement` capsules.

    * **`ConnectEthernetServerState`:** Similar to `ConnectUdpServerState`, but it deals with raw Ethernet frames instead of UDP packets.

5. **Identify Common Functionality and Patterns:**  All three classes share:
    * Holding a file descriptor (`fd_`).
    * Registering and unregistering as `Http3DatagramVisitor` on a stream.
    * A constructor and destructor that manage the socket.
    * An assignment operator.
    * A method to handle incoming HTTP/3 datagrams (`OnHttp3Datagram`).

6. **Look for Connections to JavaScript:**  Scan the code for any direct interaction with JavaScript APIs or data structures. In this particular snippet, there is *no direct interaction*. However, the *purpose* of MASQUE (proxying and potentially VPN-like functionality) is often used in web browsers. This forms the basis of the "indirect relationship" explanation.

7. **Consider Logical Reasoning (Input/Output):**  For each `OnHttp3Datagram` method, consider what happens given a hypothetical input:

    * **UDP:** Input:  `0<varint>payload`. Output: `payload` is written to the UDP socket.
    * **IP:** Input: `0<varint>ip_packet`. Output: `ip_packet` is written to the raw socket.
    * **Ethernet:** Input: `0<varint>ethernet_frame`. Output: `ethernet_frame` is written to the raw socket.

    For `ConnectIpServerState::OnHeadersWritten`, the input is the event of headers being written on the stream. The output is the sending of `AddressAssign` and `RouteAdvertisement` capsules.

8. **Identify Potential Usage Errors:** Focus on things like:

    * **Invalid `context_id`:** The code explicitly checks for this.
    * **Socket errors:**  The `write` calls can fail.
    * **Incorrectly formatted payloads:**  The `ReadVarInt62` can fail.
    * **Resource leaks:** Not unregistering sockets or visitors could be an issue, but the code seems to handle this in the destructors.

9. **Think About Debugging:** How would a developer end up in this code? The file path and class names are clues. The registration of visitors on streams is important. The act of the client initiating a MASQUE connection (CONNECT-UDP, CONNECT-IP, CONNECT-ETHERNET) is the key trigger.

10. **Synthesize the Summary:** Combine the individual class functionalities into a concise overview of the file's purpose. Highlight the different connection types handled.

11. **Structure the Response:** Organize the findings into the requested sections (Functionality, Relationship to JavaScript, Logical Reasoning, Usage Errors, Debugging, Summary). Use clear and concise language. Use examples where appropriate.

12. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness. Double-check that all parts of the original request have been addressed. For example, initially, I might have missed the sending of capsules in `ConnectIpServerState::OnHeadersWritten` and would need to go back and add that detail.

This structured approach ensures that all aspects of the request are considered, and the analysis is thorough and well-organized. It simulates how a developer might approach understanding an unfamiliar piece of code.
```
好的，这是对文件 `net/third_party/quiche/src/quiche/quic/masque/masque_server_session.cc` 功能的第二部分归纳。

**归纳其功能 (第二部分):**

总的来说，这段代码定义了 `MasqueServerSession` 类中的一些内部状态类，用于处理不同类型的 MASQUE 连接请求。这些状态类负责：

* **管理与后端服务器的连接:**  为不同类型的连接（UDP、IP、以太网）创建和管理与目标服务器的底层连接（通常是 UDP socket）。
* **协议转换:**  将 MASQUE 客户端通过 QUIC 发送的封装数据（HTTP/3 Datagram）解封装，并将其转发到与后端服务器的底层连接。
* **地址分配和路由 (仅限 `ConnectIpServerState`):**  处理 CONNECT-IP 请求时，负责为客户端分配 IP 地址，并通告路由信息。
* **资源管理:**  注册和取消注册 HTTP/3 Datagram 访问器以及 Connect-IP 访问器，管理底层 socket 的生命周期，并在状态对象销毁时清理资源。

**更具体地，每个内部状态类负责以下功能：**

* **`ConnectUdpServerState`:**
    * **处理 CONNECT-UDP 请求:**  当客户端请求代理 UDP 连接时创建。
    * **解封装并转发 UDP 数据:**  从 HTTP/3 Datagram 中提取目标服务器地址和 UDP payload，并通过 UDP socket 发送到目标服务器。
    * **资源管理:**  管理与目标服务器的 UDP socket 的创建、注册和销毁。

* **`ConnectIpServerState`:**
    * **处理 CONNECT-IP 请求:** 当客户端请求建立 IP 层连接（类似 VPN）时创建。
    * **解封装并转发 IP 数据包:** 从 HTTP/3 Datagram 中提取 IP 数据包，并通过 raw socket (由 `fd_` 表示) 发送出去。
    * **地址分配:** 在连接建立时，通过发送 `AddressAssignCapsule` 为客户端分配一个 IP 地址。
    * **路由通告:** 通过发送 `RouteAdvertisementCapsule` 向客户端通告路由信息，通常是默认路由。
    * **处理控制信令:**  忽略接收到的 `AddressAssignCapsule`、`AddressRequestCapsule` 和 `RouteAdvertisementCapsule`，这表明服务器在此角色中不主动发起这些操作，而是响应客户端的请求（虽然目前代码中是忽略）。

* **`ConnectEthernetServerState`:**
    * **处理 CONNECT-ETHERNET 请求:**  当客户端请求建立以太网层连接时创建。
    * **解封装并转发以太网帧:**  从 HTTP/3 Datagram 中提取以太网帧，并通过 raw socket 发送出去。
    * **资源管理:**  管理与底层以太网连接相关的 socket 资源。

**与 JavaScript 的关系:**

这段 C++ 代码本身不直接与 JavaScript 交互。它是 Chromium 网络栈的底层实现部分，负责处理网络协议。

然而，JavaScript 代码（例如在浏览器中运行的网页或 Service Worker）可以通过 Web API（例如 `fetch` API 或 WebSocket API）发起网络请求。当这些请求涉及到需要使用 MASQUE 协议的情况（例如，用户启用了相关的隐私或代理功能），浏览器底层就会使用这段 C++ 代码来处理与 MASQUE 服务器的连接。

**举例说明:**

假设一个 JavaScript 应用想要通过一个 MASQUE 代理服务器连接到 `example.com` 的一个 UDP 服务。

1. **用户操作:** 用户在浏览器中访问一个启用了 MASQUE 的网站，或者应用自身配置使用了 MASQUE 代理。
2. **JavaScript 发起请求:** JavaScript 代码使用类似 `fetch` 的 API 发起一个需要通过代理连接到 `example.com` 的请求。浏览器内部判断需要使用 MASQUE。
3. **底层网络栈:** 浏览器网络栈会建立与 MASQUE 服务器的 QUIC 连接。
4. **创建 `MasqueServerSession`:** MASQUE 服务器接收到连接请求，会创建一个 `MasqueServerSession` 实例来处理这个连接。
5. **创建 `ConnectUdpServerState`:**  如果客户端发送的是一个 CONNECT-UDP 请求，`MasqueServerSession` 会创建一个 `ConnectUdpServerState` 实例。
6. **数据传输:**
   * **JavaScript -> 浏览器 -> MASQUE 客户端 (C++) -> QUIC -> MASQUE 服务器 (C++) (`MasqueServerSession`) -> `ConnectUdpServerState`:** JavaScript 发送的数据最终会被封装成 HTTP/3 Datagram，通过 QUIC 连接发送到 MASQUE 服务器，并由 `ConnectUdpServerState::OnHttp3Datagram` 处理。
   * **`ConnectUdpServerState` 处理:** `OnHttp3Datagram` 从 Datagram 中提取目标地址和 UDP payload，并使用 `fd_` 对应的 UDP socket 将数据发送到 `example.com`。

**逻辑推理 (假设输入与输出):**

**`ConnectUdpServerState::OnHttp3Datagram`**

* **假设输入:**
    * `stream_id`: 一个有效的 QUIC 流 ID，与当前状态对象关联的流 ID 相同。
    * `payload`:  包含 MASQUE 封装的 UDP 数据，格式为 `<context_id: varint><udp_payload: bytes>`。 例如，`\x00\x0aHello UDP` (context_id 0, payload "Hello UDP").
* **预期输出:**
    * 如果 `context_id` 为 0，则 "Hello UDP" 会被写入到 `fd_` 对应的 UDP socket，发送到 `target_server_address_`。
    * 如果 `context_id` 非 0，则会打印错误日志，该 Datagram 被忽略。

**`ConnectIpServerState::OnHttp3Datagram`**

* **假设输入:**
    * `stream_id`: 一个有效的 QUIC 流 ID。
    * `payload`: 包含 MASQUE 封装的 IP 数据包，格式为 `<context_id: varint><ip_packet: bytes>`。 例如，`\x00\x14[IP 数据包头和数据]` (context_id 0, 14 字节的 IP 数据包)。
* **预期输出:**
    * 如果 `context_id` 为 0，则 `[IP 数据包头和数据]` 会被写入到 `fd_` 对应的 raw socket。
    * 如果 `context_id` 非 0，则会打印错误日志，该 Datagram 被忽略。

**`ConnectIpServerState::OnHeadersWritten`**

* **假设输入:**  当与该状态对象关联的 QUIC 流的头部被成功写入后触发。
* **预期输出:**
    * 发送一个 `AddressAssignCapsule`，为客户端分配 `client_ip_` 中存储的 IP 地址。
    * 发送一个 `RouteAdvertisementCapsule`，通告默认路由 (0.0.0.0/0)。

**用户或编程常见的使用错误:**

* **服务器配置错误:** MASQUE 服务器未正确配置，导致无法建立或处理特定类型的连接（例如，未启用 CONNECT-IP）。
* **客户端请求错误的连接类型:** 客户端请求了服务器不支持的 MASQUE 连接类型。
* **中间件干扰:** 防火墙或其他网络中间件阻止了 UDP 或 raw socket 的连接。
* **代码错误:**
    * **忘记注册/取消注册访问器:**  如果忘记在状态对象创建时注册 `Http3DatagramVisitor` 或 `ConnectIpVisitor`，或者在销毁时取消注册，可能导致数据无法被正确处理或内存泄漏。
    * **资源泄漏:**  如果 `fd_` 未被正确关闭或取消注册，可能导致 socket 资源泄漏。
    * **未处理 `write` 的返回值:**  `write` 系统调用可能返回错误，如果未检查并处理这些错误，可能导致数据丢失或连接问题。
    * **错误的 Context ID:**  客户端发送的 HTTP/3 Datagram 使用了非 0 的 Context ID，导致服务器忽略。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户发起需要 MASQUE 的网络操作:** 用户可能在浏览器中访问一个配置为使用 MASQUE 的网站，或者某个应用程序使用了 MASQUE 协议。
2. **浏览器/应用建立与 MASQUE 服务器的 QUIC 连接:** 底层网络库会与 MASQUE 服务器建立 QUIC 连接。
3. **客户端发送 MASQUE 连接请求:**  客户端会发送一个 HTTP 请求，其方法可能是 CONNECT-UDP、CONNECT-IP 或 CONNECT-ETHERNET，并在请求头中包含必要的 MASQUE 信息。
4. **`MasqueServerSession` 创建:**  MASQUE 服务器接收到连接请求，会创建一个 `MasqueServerSession` 对象来处理这个连接。
5. **创建对应的状态对象:**  根据客户端的连接请求类型 (`CONNECT-UDP`, `CONNECT-IP`, `CONNECT-ETHERNET`)，`MasqueServerSession` 会创建相应的状态对象 (`ConnectUdpServerState`, `ConnectIpServerState`, 或 `ConnectEthernetServerState`)。
6. **注册访问器:**  在状态对象创建时，会将自身注册为 QUIC 流的 `Http3DatagramVisitor` (以及 `ConnectIpVisitor` 如果是 `ConnectIpServerState`)，以便接收来自该流的数据。
7. **接收和处理数据:** 当客户端通过 QUIC 流发送封装的数据时，相应的 `OnHttp3Datagram` 方法会被调用，开始解封装和转发数据。

**调试线索:**

* **查看 QUIC 连接的日志:**  检查 QUIC 连接建立和数据传输过程中的日志，确认连接是否正常建立，以及是否有数据发送。
* **检查 HTTP 请求头:**  确认客户端发送的连接请求头是否正确包含了 MASQUE 相关的信息，例如请求方法和目标地址。
* **断点调试:**  在 `MasqueServerSession` 和相关的状态类的构造函数、析构函数以及 `OnHttp3Datagram` 等方法中设置断点，跟踪代码执行流程。
* **查看 socket 的状态:**  检查 `fd_` 对应的 socket 是否被成功创建、绑定和连接。
* **抓包分析:**  使用 Wireshark 等工具抓取网络包，分析 QUIC 连接和内部封装的 MASQUE 数据包的格式和内容。
* **检查错误日志:**  关注代码中 `QUIC_DLOG(ERROR)` 输出的日志信息，这些信息通常指示了潜在的问题。

希望这些归纳能够更清晰地理解这段代码的功能。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/masque/masque_server_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""

      masque_session_(masque_session) {
  QUICHE_DCHECK_NE(fd_, kQuicInvalidSocketFd);
  QUICHE_DCHECK_NE(masque_session_, nullptr);
  this->stream()->RegisterHttp3DatagramVisitor(this);
}

MasqueServerSession::ConnectUdpServerState::~ConnectUdpServerState() {
  if (stream() != nullptr) {
    stream()->UnregisterHttp3DatagramVisitor();
  }
  if (fd_ == kQuicInvalidSocketFd) {
    return;
  }
  QuicUdpSocketApi socket_api;
  QUIC_DLOG(INFO) << "Closing fd " << fd_;
  if (!masque_session_->event_loop()->UnregisterSocket(fd_)) {
    QUIC_DLOG(ERROR) << "Failed to unregister FD " << fd_;
  }
  socket_api.Destroy(fd_);
}

MasqueServerSession::ConnectUdpServerState::ConnectUdpServerState(
    MasqueServerSession::ConnectUdpServerState&& other) {
  fd_ = kQuicInvalidSocketFd;
  *this = std::move(other);
}

MasqueServerSession::ConnectUdpServerState&
MasqueServerSession::ConnectUdpServerState::operator=(
    MasqueServerSession::ConnectUdpServerState&& other) {
  if (fd_ != kQuicInvalidSocketFd) {
    QuicUdpSocketApi socket_api;
    QUIC_DLOG(INFO) << "Closing fd " << fd_;
    if (!masque_session_->event_loop()->UnregisterSocket(fd_)) {
      QUIC_DLOG(ERROR) << "Failed to unregister FD " << fd_;
    }
    socket_api.Destroy(fd_);
  }
  stream_ = other.stream_;
  other.stream_ = nullptr;
  target_server_address_ = other.target_server_address_;
  fd_ = other.fd_;
  masque_session_ = other.masque_session_;
  other.fd_ = kQuicInvalidSocketFd;
  if (stream() != nullptr) {
    stream()->ReplaceHttp3DatagramVisitor(this);
  }
  return *this;
}

void MasqueServerSession::ConnectUdpServerState::OnHttp3Datagram(
    QuicStreamId stream_id, absl::string_view payload) {
  QUICHE_DCHECK_EQ(stream_id, stream()->id());
  QuicDataReader reader(payload);
  uint64_t context_id;
  if (!reader.ReadVarInt62(&context_id)) {
    QUIC_DLOG(ERROR) << "Failed to read context ID";
    return;
  }
  if (context_id != 0) {
    QUIC_DLOG(ERROR) << "Ignoring HTTP Datagram with unexpected context ID "
                     << context_id;
    return;
  }
  absl::string_view http_payload = reader.ReadRemainingPayload();
  QuicUdpSocketApi socket_api;
  QuicUdpPacketInfo packet_info;
  packet_info.SetPeerAddress(target_server_address_);
  WriteResult write_result = socket_api.WritePacket(
      fd_, http_payload.data(), http_payload.length(), packet_info);
  QUIC_DVLOG(1) << "Wrote packet of length " << http_payload.length() << " to "
                << target_server_address_ << " with result " << write_result;
}

MasqueServerSession::ConnectIpServerState::ConnectIpServerState(
    QuicIpAddress client_ip, QuicSpdyStream* stream, QuicUdpSocketFd fd,
    MasqueServerSession* masque_session)
    : client_ip_(client_ip),
      stream_(stream),
      fd_(fd),
      masque_session_(masque_session) {
  QUICHE_DCHECK(client_ip_.IsIPv4());
  QUICHE_DCHECK_NE(fd_, kQuicInvalidSocketFd);
  QUICHE_DCHECK_NE(masque_session_, nullptr);
  this->stream()->RegisterHttp3DatagramVisitor(this);
  this->stream()->RegisterConnectIpVisitor(this);
}

MasqueServerSession::ConnectIpServerState::~ConnectIpServerState() {
  if (stream() != nullptr) {
    stream()->UnregisterHttp3DatagramVisitor();
    stream()->UnregisterConnectIpVisitor();
  }
  if (fd_ == kQuicInvalidSocketFd) {
    return;
  }
  QuicUdpSocketApi socket_api;
  QUIC_DLOG(INFO) << "Closing fd " << fd_;
  if (!masque_session_->event_loop()->UnregisterSocket(fd_)) {
    QUIC_DLOG(ERROR) << "Failed to unregister FD " << fd_;
  }
  socket_api.Destroy(fd_);
}

MasqueServerSession::ConnectIpServerState::ConnectIpServerState(
    MasqueServerSession::ConnectIpServerState&& other) {
  fd_ = kQuicInvalidSocketFd;
  *this = std::move(other);
}

MasqueServerSession::ConnectIpServerState&
MasqueServerSession::ConnectIpServerState::operator=(
    MasqueServerSession::ConnectIpServerState&& other) {
  if (fd_ != kQuicInvalidSocketFd) {
    QuicUdpSocketApi socket_api;
    QUIC_DLOG(INFO) << "Closing fd " << fd_;
    if (!masque_session_->event_loop()->UnregisterSocket(fd_)) {
      QUIC_DLOG(ERROR) << "Failed to unregister FD " << fd_;
    }
    socket_api.Destroy(fd_);
  }
  client_ip_ = other.client_ip_;
  stream_ = other.stream_;
  other.stream_ = nullptr;
  fd_ = other.fd_;
  masque_session_ = other.masque_session_;
  other.fd_ = kQuicInvalidSocketFd;
  if (stream() != nullptr) {
    stream()->ReplaceHttp3DatagramVisitor(this);
    stream()->ReplaceConnectIpVisitor(this);
  }
  return *this;
}

void MasqueServerSession::ConnectIpServerState::OnHttp3Datagram(
    QuicStreamId stream_id, absl::string_view payload) {
  QUICHE_DCHECK_EQ(stream_id, stream()->id());
  QuicDataReader reader(payload);
  uint64_t context_id;
  if (!reader.ReadVarInt62(&context_id)) {
    QUIC_DLOG(ERROR) << "Failed to read context ID";
    return;
  }
  if (context_id != 0) {
    QUIC_DLOG(ERROR) << "Ignoring HTTP Datagram with unexpected context ID "
                     << context_id;
    return;
  }
  absl::string_view ip_packet = reader.ReadRemainingPayload();
  ssize_t written = write(fd(), ip_packet.data(), ip_packet.size());
  if (written != static_cast<ssize_t>(ip_packet.size())) {
    QUIC_DLOG(ERROR) << "Failed to write CONNECT-IP packet of length "
                     << ip_packet.size();
  } else {
    QUIC_DLOG(INFO) << "Decapsulated CONNECT-IP packet of length "
                    << ip_packet.size();
  }
}

bool MasqueServerSession::ConnectIpServerState::OnAddressAssignCapsule(
    const AddressAssignCapsule& capsule) {
  QUIC_DLOG(INFO) << "Ignoring received capsule " << capsule.ToString();
  return true;
}

bool MasqueServerSession::ConnectIpServerState::OnAddressRequestCapsule(
    const AddressRequestCapsule& capsule) {
  QUIC_DLOG(INFO) << "Ignoring received capsule " << capsule.ToString();
  return true;
}

bool MasqueServerSession::ConnectIpServerState::OnRouteAdvertisementCapsule(
    const RouteAdvertisementCapsule& capsule) {
  QUIC_DLOG(INFO) << "Ignoring received capsule " << capsule.ToString();
  return true;
}

void MasqueServerSession::ConnectIpServerState::OnHeadersWritten() {
  QUICHE_DCHECK(client_ip_.IsIPv4()) << client_ip_.ToString();
  Capsule address_assign_capsule = Capsule::AddressAssign();
  PrefixWithId assigned_address;
  assigned_address.ip_prefix = quiche::QuicheIpPrefix(client_ip_, 32);
  assigned_address.request_id = 0;
  address_assign_capsule.address_assign_capsule().assigned_addresses.push_back(
      assigned_address);
  stream()->WriteCapsule(address_assign_capsule);
  IpAddressRange default_route;
  default_route.start_ip_address.FromString("0.0.0.0");
  default_route.end_ip_address.FromString("255.255.255.255");
  default_route.ip_protocol = 0;
  Capsule route_advertisement = Capsule::RouteAdvertisement();
  route_advertisement.route_advertisement_capsule().ip_address_ranges.push_back(
      default_route);
  stream()->WriteCapsule(route_advertisement);
}

// Connect Ethernet
MasqueServerSession::ConnectEthernetServerState::ConnectEthernetServerState(
    QuicSpdyStream* stream, QuicUdpSocketFd fd,
    MasqueServerSession* masque_session)
    : stream_(stream), fd_(fd), masque_session_(masque_session) {
  QUICHE_DCHECK_NE(fd_, kQuicInvalidSocketFd);
  QUICHE_DCHECK_NE(masque_session_, nullptr);
  this->stream()->RegisterHttp3DatagramVisitor(this);
}

MasqueServerSession::ConnectEthernetServerState::~ConnectEthernetServerState() {
  if (stream() != nullptr) {
    stream()->UnregisterHttp3DatagramVisitor();
  }
  if (fd_ == kQuicInvalidSocketFd) {
    return;
  }
  QuicUdpSocketApi socket_api;
  QUIC_DLOG(INFO) << "Closing fd " << fd_;
  if (!masque_session_->event_loop()->UnregisterSocket(fd_)) {
    QUIC_DLOG(ERROR) << "Failed to unregister FD " << fd_;
  }
  socket_api.Destroy(fd_);
}

MasqueServerSession::ConnectEthernetServerState::ConnectEthernetServerState(
    MasqueServerSession::ConnectEthernetServerState&& other) {
  fd_ = kQuicInvalidSocketFd;
  *this = std::move(other);
}

MasqueServerSession::ConnectEthernetServerState&
MasqueServerSession::ConnectEthernetServerState::operator=(
    MasqueServerSession::ConnectEthernetServerState&& other) {
  if (fd_ != kQuicInvalidSocketFd) {
    QuicUdpSocketApi socket_api;
    QUIC_DLOG(INFO) << "Closing fd " << fd_;
    if (!masque_session_->event_loop()->UnregisterSocket(fd_)) {
      QUIC_DLOG(ERROR) << "Failed to unregister FD " << fd_;
    }
    socket_api.Destroy(fd_);
  }
  stream_ = other.stream_;
  other.stream_ = nullptr;
  fd_ = other.fd_;
  masque_session_ = other.masque_session_;
  other.fd_ = kQuicInvalidSocketFd;
  if (stream() != nullptr) {
    stream()->ReplaceHttp3DatagramVisitor(this);
  }
  return *this;
}

void MasqueServerSession::ConnectEthernetServerState::OnHttp3Datagram(
    QuicStreamId stream_id, absl::string_view payload) {
  QUICHE_DCHECK_EQ(stream_id, stream()->id());
  QuicDataReader reader(payload);
  uint64_t context_id;
  if (!reader.ReadVarInt62(&context_id)) {
    QUIC_DLOG(ERROR) << "Failed to read context ID";
    return;
  }
  if (context_id != 0) {
    QUIC_DLOG(ERROR) << "Ignoring HTTP Datagram with unexpected context ID "
                     << context_id;
    return;
  }
  absl::string_view ethernet_frame = reader.ReadRemainingPayload();
  ssize_t written = write(fd(), ethernet_frame.data(), ethernet_frame.size());
  if (written != static_cast<ssize_t>(ethernet_frame.size())) {
    QUIC_DLOG(ERROR) << "Failed to write CONNECT-ETHERNET packet of length "
                     << ethernet_frame.size();
  } else {
    QUIC_DLOG(INFO) << "Decapsulated CONNECT-ETHERNET packet of length "
                    << ethernet_frame.size();
  }
}

}  // namespace quic

"""


```