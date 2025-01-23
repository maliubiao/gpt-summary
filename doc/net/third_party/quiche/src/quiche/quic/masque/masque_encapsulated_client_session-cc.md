Response:
My thought process for analyzing the C++ code and generating the detailed explanation goes through these stages:

1. **Understand the Context:** The file path `net/third_party/quiche/src/quiche/quic/masque/masque_encapsulated_client_session.cc` immediately tells me this is part of the QUIC implementation within Chromium and specifically relates to the MASQUE protocol. MASQUE, as I know, involves encapsulating traffic within a QUIC connection.

2. **High-Level Functionality Identification (Skimming):** I quickly scan the code, looking for class names, method names, and included headers. This gives me a general idea of what the code does. I see `MasqueEncapsulatedClientSession`, which confirms the file's purpose. Methods like `ProcessPacket`, `ProcessIpPacket`, `CloseConnection`, and `OnConnectionClosed` hint at its role in handling network traffic and connection management. The inclusion of headers like `quic_connection.h`, `quic_packets.h`, and `capsule.h` further reinforces this.

3. **Detailed Method Analysis (Focusing on Key Functions):** I then go through each method more carefully, understanding its purpose and how it interacts with other parts of the system.

    * **Constructors:**  I note the different constructors and their parameters, understanding how the session is initialized, particularly the relationship with `MasqueClientSession`.
    * **`ProcessPacket`:** This is clearly about handling regular QUIC packets received on the encapsulated connection. It's a straightforward pass-through to the underlying QUIC connection.
    * **`CloseConnection`:** Another pass-through, indicating control over the encapsulated connection's lifecycle.
    * **`OnConnectionClosed`:**  Important for cleanup, especially the interaction with the parent `masque_client_session_`.
    * **`ProcessIpPacket`:** This is the core of the encapsulation logic. I meticulously examine the parsing of the IP and UDP headers to extract the inner QUIC packet. I pay attention to error handling and the different code paths for IPv4 and IPv6.
    * **`CloseIpSession`:**  Another closure mechanism, likely triggered by events specific to the encapsulated IP session.
    * **`OnAddressAssignCapsule`, `OnAddressRequestCapsule`, `OnRouteAdvertisementCapsule`:** These methods deal with MASQUE-specific control messages (capsules). I note their behavior (processing or ignoring).

4. **Relationship to JavaScript (Considering Browser Context):**  Since this is Chromium code, I think about how a browser might use this. JavaScript in a web page wouldn't directly call these C++ functions. Instead, there would be an abstraction layer. I identify the likely connection through WebSockets or a similar API. When a web page initiates a request using MASQUE, the browser's network stack (where this C++ code resides) takes over, handling the low-level QUIC and encapsulation details.

5. **Logical Reasoning (Input/Output):**  For `ProcessIpPacket`, which involves significant parsing, I consider potential inputs (various IP packets) and the expected output (forwarding the inner QUIC packet to the connection). I also think about error cases (malformed packets) and how they are handled (dropped packets).

6. **Common Usage Errors (Considering Developer Perspective):**  I consider how a developer working with MASQUE might misuse the API or encounter problems. Misconfigurations, incorrect packet formats, and not handling connection closures correctly are potential issues.

7. **Debugging Clues (Tracing User Actions):** I trace back how a user's action in the browser could lead to this code being executed. Starting with a user initiating a request to a MASQUE-enabled server, I follow the flow through DNS resolution, connection establishment, and finally, the processing of encapsulated packets within this specific C++ file.

8. **Structure and Refinement:** Finally, I organize my thoughts into a clear and structured explanation, covering the requested aspects: functionality, JavaScript relation, logical reasoning, usage errors, and debugging. I use clear language and provide concrete examples where necessary. I ensure the explanation flows logically and addresses all parts of the prompt.

Essentially, I approach this like reverse-engineering the code and then explaining it from different perspectives: its core purpose, its interaction with higher layers (like JavaScript), its behavior under different conditions, potential pitfalls, and how it fits into the larger user experience. The key is to combine code-level understanding with knowledge of the surrounding system and the user's interaction with it.
这个C++文件 `masque_encapsulated_client_session.cc` 属于 Chromium 网络栈中 QUIC 协议的 MASQUE 功能模块。它定义了 `MasqueEncapsulatedClientSession` 类，该类负责处理通过 MASQUE 代理连接的客户端会话。

以下是该文件的功能列表：

**核心功能：**

1. **封装 QUIC 连接管理:**  `MasqueEncapsulatedClientSession`  作为客户端在一个已有的 MASQUE 会话（由 `MasqueClientSession` 管理）中建立一个新的、被封装的 QUIC 连接。  它继承自 `MasqueClientSession`，并与父会话 `masque_client_session_` 关联。

2. **处理封装的 UDP 数据包:** `ProcessPacket` 函数接收从 MASQUE 服务器收到的 UDP 数据包，这些数据包实际上是目标服务器响应的封装。它将这些数据包解封装并传递给底层的 QUIC 连接进行处理。

3. **处理封装的 IP 数据包 (CONNECT-IP):** `ProcessIpPacket` 函数专门处理通过 CONNECT-IP 扩展发送的 IP 数据包。 它解析 IP 和 UDP 头部，提取出内部的 QUIC 数据包，并将其传递给底层的 QUIC 连接进行处理。 这允许 MASQUE 代理透明地转发任意 IP 数据包。

4. **连接生命周期管理:**  `CloseConnection` 函数用于关闭底层的 QUIC 连接。 `OnConnectionClosed` 函数在连接关闭时被调用，它会通知父 MASQUE 会话 (`masque_client_session_`) 以便进行清理。 `CloseIpSession` 函数则以静默方式关闭连接。

5. **处理 MASQUE 扩展的 Capsule:**  `OnAddressAssignCapsule`, `OnAddressRequestCapsule`, 和 `OnRouteAdvertisementCapsule` 函数处理 MASQUE 协议中定义的控制消息 (Capsule)。 目前的代码中，`OnAddressRequestCapsule` 和 `OnRouteAdvertisementCapsule` 被忽略，而 `OnAddressAssignCapsule` 用于保存分配的本地 IPv4 和 IPv6 地址。

**与 JavaScript 的关系：**

这个 C++ 文件本身不直接与 JavaScript 代码交互。 然而，它是 Chromium 浏览器网络栈的一部分，而浏览器正是运行 JavaScript 代码的环境。

当 JavaScript 代码发起一个需要通过 MASQUE 代理的请求时，例如使用 `fetch` API 或者 WebSocket 连接，Chromium 的网络栈会负责处理底层的网络通信。  在这个过程中，如果确定需要使用 MASQUE，就会创建并使用 `MasqueEncapsulatedClientSession` 的实例来建立和管理与 MASQUE 服务器的连接。

**举例说明:**

假设一个网页中的 JavaScript 代码尝试通过一个支持 MASQUE 的代理服务器访问一个被屏蔽的网站。

1. **JavaScript:**  `fetch('https://blocked-website.com')`
2. **Chromium 网络栈:**  网络栈检测到需要通过 MASQUE 代理来访问 `blocked-website.com`。
3. **MASQUE 会话建立:**  `MasqueClientSession` (或其他相关类) 与 MASQUE 代理服务器建立连接。
4. **封装连接创建:**  `MasqueEncapsulatedClientSession` 被创建，用于管理到 `blocked-website.com` 的封装 QUIC 连接。
5. **请求封装:**  JavaScript 的 `fetch` 请求会被封装成 QUIC 数据包，并可能进一步封装在 CONNECT-IP 消息中。
6. **数据传输:**  封装的数据通过与 MASQUE 代理的 QUIC 连接发送。
7. **代理处理:**  MASQUE 代理解封装数据，并将原始请求发送到 `blocked-website.com`。
8. **响应处理:**  `blocked-website.com` 的响应会被 MASQUE 代理封装成 UDP 或 CONNECT-IP 数据包发送回客户端。
9. **`ProcessPacket` 或 `ProcessIpPacket`:**  `MasqueEncapsulatedClientSession` 的 `ProcessPacket` 或 `ProcessIpPacket` 函数接收到这些封装的响应数据。
10. **解封装和传递:**  这些函数解封装数据，并将原始的 HTTP 响应传递给底层的 QUIC 连接。
11. **传递给浏览器:**  QUIC 连接将响应传递回 Chromium 的更上层，最终到达执行 JavaScript 代码的渲染进程。
12. **JavaScript:**  JavaScript 代码接收到 `fetch` 请求的响应。

**逻辑推理 (假设输入与输出):**

**假设输入 (对于 `ProcessIpPacket`):**

一个包含 IPv4 封装的 UDP 数据包的 `absl::string_view`，例如：

```
45 00 00 35  // IPv4 Header (Version, IHL, DSCP, ECN, Total Length)
00 01 00 00  // Identification, Flags, Fragment Offset
40 11 79 7e  // TTL, Protocol (17 for UDP), Header Checksum
0A 0A 0A 01  // Source IP (10.10.10.1)
0B 0B 0B 02  // Destination IP (11.11.11.2)
C0 01        // Source Port (49153)
00 50        // Destination Port (80)
00 21        // Length (33)
00 00        // Checksum
...          // Encapsulated QUIC packet data
```

**预期输出:**

- 底层的 QUIC 连接的 `ProcessUdpPacket` 函数会被调用。
- 传递给 `ProcessUdpPacket` 的 `server_address` 将是从 IP 头部解析出的源 IP 地址 (10.10.10.1) 和源端口 (49153)。
- 传递给 `ProcessUdpPacket` 的 `received_packet` 将包含解封装的 QUIC 数据包。

**假设输入 (对于 `ProcessPacket`):**

一个普通的 QUIC 数据包的 `absl::string_view`，例如：

```
... // QUIC packet data
```

**预期输出:**

- 底层的 QUIC 连接的 `ProcessUdpPacket` 函数会被调用。
- 传递给 `ProcessUdpPacket` 的 `server_address` 是传递给 `ProcessPacket` 函数的参数 `server_address`。
- 传递给 `ProcessUdpPacket` 的 `received_packet` 将包含接收到的 QUIC 数据包。

**用户或编程常见的使用错误:**

1. **配置错误:**  用户可能错误地配置了 MASQUE 代理服务器的地址或端口，导致连接失败。
2. **代理不支持:**  用户可能尝试使用不支持 MASQUE 协议的代理服务器，导致连接无法建立。
3. **网络问题:**  底层的网络连接可能存在问题，例如防火墙阻止了 UDP 数据包的传输。
4. **服务端错误:**  MASQUE 代理服务器或目标服务器可能出现错误，导致连接中断或响应异常。
5. **版本不兼容:**  客户端和服务器使用的 MASQUE 或 QUIC 版本不兼容，导致握手失败。
6. **代码错误 (开发者):**  在实现使用 MASQUE 的客户端代码时，开发者可能没有正确处理连接状态、错误情况或数据包的发送和接收。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中输入网址并访问:** 用户在地址栏输入一个网址，或者点击一个链接。
2. **浏览器解析 URL:** 浏览器解析 URL，确定需要建立网络连接。
3. **代理配置检查:** 浏览器检查系统或用户的代理配置。 如果配置了 MASQUE 代理，则会尝试使用它。
4. **MASQUE 连接建立 (MasqueClientSession):**  Chromium 网络栈中的代码会尝试与配置的 MASQUE 代理服务器建立连接，这涉及到 `MasqueClientSession` 的创建和初始化。
5. **封装连接请求:**  当需要访问目标服务器时，`MasqueClientSession` 会请求创建一个封装的连接。 这会导致 `MasqueEncapsulatedClientSession` 的实例被创建。
6. **发送封装的请求:**  浏览器将 HTTP 请求或其他网络数据封装成 QUIC 数据包，并通过与 MASQUE 代理的连接发送。 如果使用了 CONNECT-IP，则会进一步封装成 IP 数据包。
7. **代理转发和响应:**  MASQUE 代理接收到封装的数据，解封装后转发到目标服务器。 目标服务器的响应会被代理重新封装。
8. **接收封装的响应:**  Chromium 网络栈接收到来自 MASQUE 代理的封装响应数据包。
9. **`ProcessPacket` 或 `ProcessIpPacket` 被调用:**  根据接收到的数据包类型（普通 QUIC 或 CONNECT-IP），`MasqueEncapsulatedClientSession` 的 `ProcessPacket` 或 `ProcessIpPacket` 函数会被调用来处理这些数据包。
10. **解封装和数据处理:**  这些函数会解封装数据包，并将原始数据传递给底层的 QUIC 连接进行进一步处理，例如处理 HTTP 响应。
11. **数据传递回浏览器:**  最终，解封装后的数据会传递回浏览器的渲染进程，供 JavaScript 代码使用或呈现给用户。

**调试线索:**

当调试与 MASQUE 相关的问题时，可以关注以下几个方面：

* **网络请求日志:**  查看浏览器或操作系统的网络请求日志，可以了解请求是否使用了代理，以及是否有连接错误。
* **QUIC 连接信息:**  查看 QUIC 连接的状态、错误信息和数据包统计，可以帮助定位 QUIC 层面的问题。
* **MASQUE 扩展信息:**  如果可能，查看 MASQUE 协议相关的扩展信息，例如 Capsule 的内容。
* **抓包:**  使用网络抓包工具（如 Wireshark）可以捕获客户端和代理服务器之间的网络数据包，分析封装的格式和内容。
* **断点调试:**  在 `MasqueEncapsulatedClientSession.cc` 中的关键函数（如 `ProcessPacket` 和 `ProcessIpPacket`) 设置断点，可以观察数据包的接收和处理过程，以及变量的值。

通过以上分析，可以更深入地理解 `masque_encapsulated_client_session.cc` 文件的功能，以及它在 Chromium 网络栈中处理 MASQUE 协议时的作用。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/masque/masque_encapsulated_client_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/masque/masque_encapsulated_client_session.h"

#include <cstdint>
#include <string>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "quiche/quic/core/frames/quic_connection_close_frame.h"
#include "quiche/quic/core/http/quic_spdy_client_session.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/masque/masque_client_session.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/capsule.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_data_reader.h"
#include "quiche/common/quiche_ip_address.h"
#include "quiche/common/quiche_text_utils.h"

namespace quic {

using ::quiche::AddressAssignCapsule;
using ::quiche::AddressRequestCapsule;
using ::quiche::RouteAdvertisementCapsule;

MasqueEncapsulatedClientSession::MasqueEncapsulatedClientSession(
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection, const QuicServerId& server_id,
    QuicCryptoClientConfig* crypto_config,
    MasqueClientSession* masque_client_session,
    MasqueClientSession::Owner* owner)
    : MasqueClientSession(config, supported_versions, connection, server_id,
                          crypto_config, owner),
      masque_client_session_(masque_client_session) {}

MasqueEncapsulatedClientSession::MasqueEncapsulatedClientSession(
    MasqueMode masque_mode, const std::string& uri_template,
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection, const QuicServerId& server_id,
    QuicCryptoClientConfig* crypto_config,
    MasqueClientSession* masque_client_session,
    MasqueClientSession::Owner* owner)
    : MasqueClientSession(masque_mode, uri_template, config, supported_versions,
                          connection, server_id, crypto_config, owner),
      masque_client_session_(masque_client_session) {}

void MasqueEncapsulatedClientSession::ProcessPacket(
    absl::string_view packet, QuicSocketAddress server_address) {
  QuicTime now = connection()->clock()->ApproximateNow();
  QuicReceivedPacket received_packet(packet.data(), packet.length(), now);
  connection()->ProcessUdpPacket(connection()->self_address(), server_address,
                                 received_packet);
}

void MasqueEncapsulatedClientSession::CloseConnection(
    QuicErrorCode error, const std::string& details,
    ConnectionCloseBehavior connection_close_behavior) {
  connection()->CloseConnection(error, details, connection_close_behavior);
}

void MasqueEncapsulatedClientSession::OnConnectionClosed(
    const QuicConnectionCloseFrame& frame, ConnectionCloseSource source) {
  MasqueClientSession::OnConnectionClosed(frame, source);
  masque_client_session_->CloseConnectUdpStream(this);
}

void MasqueEncapsulatedClientSession::ProcessIpPacket(
    absl::string_view packet) {
  quiche::QuicheDataReader reader(packet);
  uint8_t first_byte;
  if (!reader.ReadUInt8(&first_byte)) {
    QUIC_DLOG(ERROR) << "Dropping empty CONNECT-IP packet";
    return;
  }
  const uint8_t ip_version = first_byte >> 4;
  quiche::QuicheIpAddress server_ip;
  if (ip_version == 6) {
    if (!reader.Seek(5)) {
      QUICHE_DLOG(ERROR) << "Failed to seek CONNECT-IP IPv6 start\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    uint8_t next_header = 0;
    if (!reader.ReadUInt8(&next_header)) {
      QUICHE_DLOG(ERROR) << "Failed to read CONNECT-IP next header\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    if (next_header != 17) {
      // Note that this drops packets with IPv6 extension headers, since we
      // do not expect to see them in practice.
      QUIC_DLOG(ERROR)
          << "Dropping CONNECT-IP packet with unexpected next header "
          << static_cast<int>(next_header) << "\n"
          << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    if (!reader.Seek(1)) {
      QUICHE_DLOG(ERROR) << "Failed to seek CONNECT-IP hop limit\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    absl::string_view source_ip;
    if (!reader.ReadStringPiece(&source_ip, 16)) {
      QUICHE_DLOG(ERROR) << "Failed to read CONNECT-IP source IPv6\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    server_ip.FromPackedString(source_ip.data(), source_ip.length());
    if (!reader.Seek(16)) {
      QUICHE_DLOG(ERROR) << "Failed to seek CONNECT-IP destination IPv6\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
  } else if (ip_version == 4) {
    uint8_t ihl = first_byte & 0xF;
    if (ihl < 5) {
      QUICHE_DLOG(ERROR) << "Dropping CONNECT-IP packet with invalid IHL "
                         << static_cast<int>(ihl) << "\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    if (!reader.Seek(8)) {
      QUICHE_DLOG(ERROR) << "Failed to seek CONNECT-IP IPv4 start\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    uint8_t ip_proto = 0;
    if (!reader.ReadUInt8(&ip_proto)) {
      QUICHE_DLOG(ERROR) << "Failed to read CONNECT-IP ip_proto\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    if (ip_proto != 17) {
      QUIC_DLOG(ERROR) << "Dropping CONNECT-IP packet with unexpected IP proto "
                       << static_cast<int>(ip_proto) << "\n"
                       << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    if (!reader.Seek(2)) {
      QUICHE_DLOG(ERROR) << "Failed to seek CONNECT-IP IP checksum\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    absl::string_view source_ip;
    if (!reader.ReadStringPiece(&source_ip, 4)) {
      QUICHE_DLOG(ERROR) << "Failed to read CONNECT-IP source IPv4\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    server_ip.FromPackedString(source_ip.data(), source_ip.length());
    if (!reader.Seek(4)) {
      QUICHE_DLOG(ERROR) << "Failed to seek CONNECT-IP destination IPv4\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
    uint8_t ip_options_length = (ihl - 5) * 4;
    if (!reader.Seek(ip_options_length)) {
      QUICHE_DLOG(ERROR) << "Failed to seek CONNECT-IP IP options of length "
                         << static_cast<int>(ip_options_length) << "\n"
                         << quiche::QuicheTextUtils::HexDump(packet);
      return;
    }
  } else {
    QUIC_DLOG(ERROR) << "Dropping CONNECT-IP packet with unexpected IP version "
                     << static_cast<int>(ip_version) << "\n"
                     << quiche::QuicheTextUtils::HexDump(packet);
    return;
  }
  // Parse UDP header.
  uint16_t server_port;
  if (!reader.ReadUInt16(&server_port)) {
    QUICHE_DLOG(ERROR) << "Failed to read CONNECT-IP source port\n"
                       << quiche::QuicheTextUtils::HexDump(packet);
    return;
  }
  if (!reader.Seek(2)) {
    QUICHE_DLOG(ERROR) << "Failed to seek CONNECT-IP destination port\n"
                       << quiche::QuicheTextUtils::HexDump(packet);
    return;
  }
  uint16_t udp_length;
  if (!reader.ReadUInt16(&udp_length)) {
    QUICHE_DLOG(ERROR) << "Failed to read CONNECT-IP UDP length\n"
                       << quiche::QuicheTextUtils::HexDump(packet);
    return;
  }
  if (udp_length < 8) {
    QUICHE_DLOG(ERROR) << "Dropping CONNECT-IP packet with invalid UDP length "
                       << udp_length << "\n"
                       << quiche::QuicheTextUtils::HexDump(packet);
    return;
  }
  if (!reader.Seek(2)) {
    QUICHE_DLOG(ERROR) << "Failed to seek CONNECT-IP UDP checksum\n"
                       << quiche::QuicheTextUtils::HexDump(packet);
    return;
  }
  absl::string_view quic_packet;
  if (!reader.ReadStringPiece(&quic_packet, udp_length - 8)) {
    QUICHE_DLOG(ERROR) << "Failed to read CONNECT-IP UDP payload\n"
                       << quiche::QuicheTextUtils::HexDump(packet);
    return;
  }
  if (!reader.IsDoneReading()) {
    QUICHE_DLOG(INFO) << "Received CONNECT-IP UDP packet with "
                      << reader.BytesRemaining()
                      << " extra bytes after payload\n"
                      << quiche::QuicheTextUtils::HexDump(packet);
  }
  QUIC_DLOG(INFO) << "Received CONNECT-IP encapsulated packet of length "
                  << quic_packet.size();
  QuicTime now = connection()->clock()->ApproximateNow();
  QuicReceivedPacket received_packet(quic_packet.data(), quic_packet.size(),
                                     now);
  QuicSocketAddress server_address = QuicSocketAddress(server_ip, server_port);
  connection()->ProcessUdpPacket(connection()->self_address(), server_address,
                                 received_packet);
}

void MasqueEncapsulatedClientSession::CloseIpSession(
    const std::string& details) {
  connection()->CloseConnection(QUIC_CONNECTION_CANCELLED, details,
                                ConnectionCloseBehavior::SILENT_CLOSE);
}

bool MasqueEncapsulatedClientSession::OnAddressAssignCapsule(
    const AddressAssignCapsule& capsule) {
  QUIC_DLOG(INFO) << "Received capsule " << capsule.ToString();
  for (auto assigned_address : capsule.assigned_addresses) {
    if (assigned_address.ip_prefix.address().IsIPv4() &&
        !local_v4_address_.IsInitialized()) {
      QUIC_LOG(INFO)
          << "MasqueEncapsulatedClientSession saving local IPv4 address "
          << assigned_address.ip_prefix.address();
      local_v4_address_ = assigned_address.ip_prefix.address();
    } else if (assigned_address.ip_prefix.address().IsIPv6() &&
               !local_v6_address_.IsInitialized()) {
      QUIC_LOG(INFO)
          << "MasqueEncapsulatedClientSession saving local IPv6 address "
          << assigned_address.ip_prefix.address();
      local_v6_address_ = assigned_address.ip_prefix.address();
    }
  }
  return true;
}

bool MasqueEncapsulatedClientSession::OnAddressRequestCapsule(
    const AddressRequestCapsule& capsule) {
  QUIC_DLOG(INFO) << "Ignoring received capsule " << capsule.ToString();
  return true;
}

bool MasqueEncapsulatedClientSession::OnRouteAdvertisementCapsule(
    const RouteAdvertisementCapsule& capsule) {
  QUIC_DLOG(INFO) << "Ignoring received capsule " << capsule.ToString();
  return true;
}

}  // namespace quic
```