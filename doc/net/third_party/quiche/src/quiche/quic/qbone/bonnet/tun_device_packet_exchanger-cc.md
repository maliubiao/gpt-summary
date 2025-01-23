Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `TunDevicePacketExchanger` class in the provided Chromium networking code. Secondary goals are to identify any connections to JavaScript, illustrate logical reasoning with examples, highlight potential user errors, and trace the user journey to this code.

**2. Initial Code Scan and Key Class Identification:**

The first step is a quick scan of the code to identify the main class and its key members. I see `TunDevicePacketExchanger` inheriting from `QbonePacketExchanger`. The constructor takes several dependencies: `KernelInterface`, `NetlinkInterface`, `QbonePacketExchanger::Visitor`, and `StatsInterface`. The core methods seem to be `WritePacket` and `ReadPacket`. The presence of `is_tap_` and the logic around `ApplyL2Headers` and `ConsumeL2Headers` suggest it deals with both TUN and TAP devices.

**3. Deciphering Core Functionality (TUN vs. TAP):**

The `is_tap_` flag is crucial. I see the constructor adding `ETH_HLEN` (Ethernet header length) to `mtu_` when `is_tap_` is true. The `ApplyL2Headers` and `ConsumeL2Headers` methods are conditionally executed based on `is_tap_`. This immediately tells me the class handles both TUN (Layer 3) and TAP (Layer 2) virtual network interfaces.

* **TUN Mode:**  Treats packets as raw IP packets. The application reads and writes IP packets directly.
* **TAP Mode:**  Treats packets as Ethernet frames. The application reads and writes Ethernet frames, including MAC addresses and the Ethernet header.

**4. Analyzing `WritePacket`:**

* Checks for a valid file descriptor (`fd_`).
* If in TAP mode, calls `ApplyL2Headers` to add the Ethernet header.
* Uses `kernel_->write` to send the packet to the TUN/TAP device.
* Handles `EWOULDBLOCK` and `EAGAIN` for non-blocking I/O.
* Updates statistics using `stats_`.

**5. Analyzing `ReadPacket`:**

* Checks for a valid file descriptor.
* Uses `kernel_->read` to read a packet from the TUN/TAP device.
* Handles `EAGAIN` and `EWOULDBLOCK`.
* If in TAP mode, calls `ConsumeL2Headers` to process the Ethernet header.
* Updates statistics.

**6. Deeper Dive into `ApplyL2Headers`:**

* Only executed in TAP mode.
* If the MAC address isn't initialized, it tries to fetch it using `netlink_->GetLinkInfo`.
* Constructs an Ethernet header, setting source and destination MAC addresses (to the device's own MAC) and the protocol (IPv6).
* Prepends the Ethernet header to the IP packet.

**7. Deeper Dive into `ConsumeL2Headers`:**

* Only executed in TAP mode.
* Validates the Ethernet header (minimum length, IPv6 protocol).
* Handles Neighbor Solicitation (ICMPv6) messages:
    * Checks if it's a neighbor solicitation for the gateway address.
    * Constructs a Neighbor Advertisement response.
    * Sends the response back using `WritePacket`.
    * **Critically**, it *doesn't* forward the neighbor solicitation itself.
* If it's not a Neighbor Solicitation, it removes the Ethernet header and returns the IP packet.

**8. Identifying JavaScript Connections (or Lack Thereof):**

I carefully review the code for any direct interactions with JavaScript APIs. I see no explicit usage of V8 or any other JavaScript embedding mechanisms. The code operates at a lower network stack level. Therefore, the connection to JavaScript is indirect, through higher-level Chromium networking components.

**9. Constructing Logical Reasoning Examples:**

Based on the understanding of TUN/TAP and the code's behavior, I can create hypothetical input/output scenarios:

* **WritePacket (TUN):**  Input: Raw IPv6 packet. Output: Packet written to the TUN device.
* **WritePacket (TAP):** Input: Raw IPv6 packet. Output: Ethernet frame with IPv6 packet written to the TAP device.
* **ReadPacket (TUN):** Output: Raw IPv6 packet read from the TUN device.
* **ReadPacket (TAP - Normal IPv6):** Output: Raw IPv6 packet after stripping the Ethernet header.
* **ReadPacket (TAP - Neighbor Solicitation):** Output: A Neighbor Advertisement sent back, the original solicitation is dropped.

**10. Identifying User/Programming Errors:**

I look for common pitfalls when working with TUN/TAP interfaces:

* **Incorrect MTU:**  Setting the wrong MTU can lead to fragmentation issues.
* **Incorrect `is_tap`:**  Mismatched configuration between the application and the interface.
* **File Descriptor Errors:** Not opening or closing the device correctly.
* **Permissions Issues:**  Lack of permissions to access the TUN/TAP device.

**11. Tracing the User Journey (Debugging Perspective):**

I think about how a developer might end up looking at this code during debugging:

* **Network Connectivity Issues:** If a user reports network problems with a feature using QBONE, the developer might investigate the packet flow.
* **Performance Problems:**  If there are performance bottlenecks, the read/write operations in this class could be a point of investigation.
* **Neighbor Discovery Issues:**  Problems with address resolution could lead to examining the Neighbor Solicitation handling.
* **Kernel Errors:** Errors reported by the `kernel_->read` or `kernel_->write` calls would lead a developer here.

**12. Structuring the Answer:**

Finally, I organize the findings into the requested sections of the prompt, providing clear explanations and examples. I use the insights gained from the detailed code analysis to provide comprehensive and accurate answers.

This detailed step-by-step process allows for a thorough understanding of the code and the ability to answer the various aspects of the prompt effectively. It combines code reading, understanding networking concepts (TUN/TAP, Ethernet, IPv6, ICMPv6), and thinking from a developer's perspective.
这个 C++ 文件 `tun_device_packet_exchanger.cc` 定义了一个名为 `TunDevicePacketExchanger` 的类，它在 Chromium 网络栈中负责**在用户空间和内核空间的 TUN/TAP 设备之间交换网络数据包**。  更具体地说，它充当了 QBONE (QUIC Bone) 组件和操作系统内核提供的 TUN/TAP 设备之间的桥梁。

让我们详细列举它的功能：

**核心功能:**

1. **读写 TUN/TAP 设备:**
   - `WritePacket()`:  将数据包写入 TUN/TAP 设备。这会将数据包从用户空间发送到内核网络栈。
   - `ReadPacket()`: 从 TUN/TAP 设备读取数据包。这会将内核网络栈接收到的数据包传递到用户空间。

2. **处理 TUN 和 TAP 设备:**
   - 通过 `is_tap_` 标志区分 TUN 和 TAP 设备。
   - **TUN (Network Tunnel):**  处理的是 IP 数据包 (通常是 IPv4 或 IPv6)。
   - **TAP (Network Tap):**  处理的是以太网帧，包括 MAC 地址和以太网头部。

3. **处理 TAP 设备的以太网头部:**
   - `ApplyL2Headers()`:  当作为 TAP 设备运行时，在发送数据包之前添加以太网头部。它会尝试获取本地接口的 MAC 地址并添加到帧头。
   - `ConsumeL2Headers()`: 当作为 TAP 设备运行时，在接收到数据包后移除以太网头部，以便 QBONE 的其他部分处理 IP 数据包。

4. **处理 ICMPv6 邻居发现 (Neighbor Discovery) 协议:**
   - `ConsumeL2Headers()` 中包含了处理 ICMPv6 邻居请求 (Neighbor Solicitation) 的逻辑。
   - 当收到针对网关地址的邻居请求时，它会构造一个邻居通告 (Neighbor Advertisement) 并通过 TUN/TAP 设备发送回去，模拟对该请求的响应。
   - 这对于 QBONE 模拟网络环境并响应地址解析请求至关重要。

5. **阻塞处理:**
   - `WritePacket()` 和 `ReadPacket()` 都处理了非阻塞 I/O 的情况。如果 TUN/TAP 设备当前无法写入或读取数据，它们会设置 `blocked` 参数为 `true` 并返回。

6. **统计信息收集:**
   - 使用 `StatsInterface` 来记录写入和读取的数据包数量以及发生的错误。

**与 JavaScript 功能的关系:**

这个 C++ 文件本身不直接与 JavaScript 代码交互。它是 Chromium 网络栈的底层组件。然而，它为运行在浏览器或 Node.js 环境中的 JavaScript 代码提供了网络连接的基础。

**举例说明:**

假设一个使用 WebRTC 的 JavaScript 应用需要通过 QBONE 连接到对等端。

1. **JavaScript 发起连接:** JavaScript 代码使用 WebRTC API 创建一个连接，并通过 Chromium 的网络栈发送数据。
2. **数据包到达 `TunDevicePacketExchanger`:**  当数据包需要通过 QBONE 发送时，它会最终到达 `TunDevicePacketExchanger::WritePacket()`。
3. **C++ 处理:**  `TunDevicePacketExchanger` 将数据包写入底层的 TUN/TAP 设备。
4. **内核传输:** 操作系统内核的网络栈会将数据包通过虚拟的网络接口 (由 TUN/TAP 设备提供) 发送出去。
5. **接收端:**  目标机器接收到数据包，并通过类似的 QBONE 设置传递到接收端的应用程序。
6. **反向过程:** 当接收端发送响应时，数据包会通过接收端的 TUN/TAP 设备，被 `TunDevicePacketExchanger::ReadPacket()` 读取，并最终传递回 Chromium 的网络栈，最终到达 JavaScript 代码。

**逻辑推理 (假设输入与输出):**

**假设输入 (TAP 设备):**

* **`WritePacket` 输入:**  一个表示 IPv6 数据包的 `char*` 缓冲区，例如，一个 ping 请求的 IPv6 包。
* **`ReadPacket` 输入:**  从 TAP 设备读取到的一个以太网帧，其中包含一个 IPv6 数据包。

**输出:**

* **`WritePacket` 输出:** 如果写入成功，返回 `true`。如果 TUN/TAP 设备阻塞，`blocked` 参数会被设置为 `true`。
* **`ReadPacket` 输出 (正常 IPv6 包):**  一个 `std::unique_ptr<QuicData>`，包含去除了以太网头部的 IPv6 数据包。
* **`ReadPacket` 输出 (ICMPv6 邻居请求):**  函数会发送一个邻居通告，并返回 `nullptr`，因为邻居请求不需要向上层传递。

**假设输入 (TUN 设备):**

* **`WritePacket` 输入:**  一个表示 IPv6 数据包的 `char*` 缓冲区。
* **`ReadPacket` 输入:**  从 TUN 设备读取到的一个 IPv6 数据包。

**输出:**

* **`WritePacket` 输出:**  与 TAP 设备类似。
* **`ReadPacket` 输出:**  一个 `std::unique_ptr<QuicData>`，包含读取到的 IPv6 数据包。

**用户或编程常见的使用错误:**

1. **错误的设备类型配置:**  如果 QBONE 配置为使用 TAP 设备，但操作系统创建的是 TUN 设备，或者反过来，会导致 `ApplyL2Headers` 和 `ConsumeL2Headers` 的行为不符合预期，可能导致数据包格式错误。
   * **示例:** 用户配置 QBONE 使用 `is_tap = true`，但实际的虚拟网卡是通过 `ip tuntap add mode tun ...` 创建的。这时 `ApplyL2Headers` 会添加以太网头，但内核期望的是纯 IP 包，导致发送失败。

2. **MTU 不匹配:**  如果 `TunDevicePacketExchanger` 的 `mtu_` 与底层 TUN/TAP 设备的 MTU 不一致，可能导致数据包被截断或分片，影响网络连接的可靠性。
   * **示例:** `TunDevicePacketExchanger` 初始化时 `mtu_` 设置为 1500，但 TUN 设备的 MTU 实际为 1400。当尝试写入一个 1450 字节的 IP 包时，可能会被截断。

3. **文件描述符无效:**  如果 `fd_` 未正确初始化或被错误关闭，`WritePacket` 和 `ReadPacket` 会因为操作无效的文件描述符而失败。
   * **示例:** 在 `TunDevicePacketExchanger` 对象创建后，忘记调用 `set_file_descriptor()` 设置与 TUN/TAP 设备关联的文件描述符。

4. **权限问题:**  用户运行的程序可能没有足够的权限来打开或操作 TUN/TAP 设备。
   * **示例:** 在 Linux 系统上，通常需要 root 权限才能创建和操作 TUN/TAP 设备。如果程序以普通用户身份运行，可能会遇到权限被拒绝的错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动 Chromium 或一个使用 Chromium 网络栈的应用程序。**
2. **应用程序尝试建立网络连接，例如访问一个网页或连接到一个 WebRTC 对等端。**
3. **如果连接涉及到 QBONE，网络请求会被路由到 QBONE 的处理流程。**
4. **QBONE 组件决定将数据包发送到虚拟网络接口。**
5. **QBONE 调用 `TunDevicePacketExchanger::WritePacket()` 将数据包写入 TUN/TAP 设备。**  如果用户是发送数据，流程会走到这里。
6. **或者，操作系统内核通过 TUN/TAP 设备接收到来自外部网络的数据包。**
7. **内核将数据包传递给与 TUN/TAP 设备关联的文件描述符。**
8. **QBONE 调用 `TunDevicePacketExchanger::ReadPacket()` 从 TUN/TAP 设备读取数据包。** 如果用户是接收数据，流程会走到这里。

**调试线索:**

* **网络连接失败或不稳定:**  如果用户报告网络连接问题，开发人员可能会检查 `TunDevicePacketExchanger` 的日志或使用网络抓包工具来查看通过 TUN/TAP 设备发送和接收的数据包是否正确。
* **性能问题:**  如果网络性能低下，可以检查 `TunDevicePacketExchanger` 的读写操作是否有阻塞或错误，以及统计信息中是否有异常的丢包或错误计数。
* **特定协议问题 (例如 ICMPv6 邻居发现):**  如果涉及到 IPv6 的地址解析问题，开发人员可能会关注 `ConsumeL2Headers` 中处理 ICMPv6 消息的逻辑，检查是否正确地发送了邻居通告。
* **内核错误日志:**  如果内核报告与 TUN/TAP 设备相关的错误，例如设备创建失败或 I/O 错误，则需要检查 `TunDevicePacketExchanger` 与内核交互的部分。

总而言之，`TunDevicePacketExchanger` 是 QBONE 组件中一个关键的底层模块，负责与操作系统内核提供的 TUN/TAP 设备进行交互，实现用户空间和内核空间之间网络数据包的传输。 理解它的功能对于调试涉及 QBONE 的网络问题至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/qbone/bonnet/tun_device_packet_exchanger.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/qbone/bonnet/tun_device_packet_exchanger.h"

#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "quiche/quic/qbone/platform/icmp_packet.h"
#include "quiche/quic/qbone/platform/netlink_interface.h"
#include "quiche/quic/qbone/qbone_constants.h"

namespace quic {

TunDevicePacketExchanger::TunDevicePacketExchanger(
    size_t mtu, KernelInterface* kernel, NetlinkInterface* netlink,
    QbonePacketExchanger::Visitor* visitor, size_t max_pending_packets,
    bool is_tap, StatsInterface* stats, absl::string_view ifname)
    : QbonePacketExchanger(visitor, max_pending_packets),
      mtu_(mtu),
      kernel_(kernel),
      netlink_(netlink),
      ifname_(ifname),
      is_tap_(is_tap),
      stats_(stats) {
  if (is_tap_) {
    mtu_ += ETH_HLEN;
  }
}

bool TunDevicePacketExchanger::WritePacket(const char* packet, size_t size,
                                           bool* blocked, std::string* error) {
  *blocked = false;
  if (fd_ < 0) {
    *error = absl::StrCat("Invalid file descriptor of the TUN device: ", fd_);
    stats_->OnWriteError(error);
    return false;
  }

  auto buffer = std::make_unique<QuicData>(packet, size);
  if (is_tap_) {
    buffer = ApplyL2Headers(*buffer);
  }
  int result = kernel_->write(fd_, buffer->data(), buffer->length());
  if (result == -1) {
    if (errno == EWOULDBLOCK || errno == EAGAIN) {
      // The tunnel is blocked. Note that this does not mean the receive buffer
      // of a TCP connection is filled. This simply means the TUN device itself
      // is blocked on handing packets to the rest of the kernel.
      *error =
          absl::ErrnoToStatus(errno, "Write to the TUN device was blocked.")
              .message();
      *blocked = true;
      stats_->OnWriteError(error);
    }
    return false;
  }
  stats_->OnPacketWritten(result);

  return true;
}

std::unique_ptr<QuicData> TunDevicePacketExchanger::ReadPacket(
    bool* blocked, std::string* error) {
  *blocked = false;
  if (fd_ < 0) {
    *error = absl::StrCat("Invalid file descriptor of the TUN device: ", fd_);
    stats_->OnReadError(error);
    return nullptr;
  }
  // Reading on a TUN device returns a packet at a time. If the packet is longer
  // than the buffer, it's truncated.
  auto read_buffer = std::make_unique<char[]>(mtu_);
  int result = kernel_->read(fd_, read_buffer.get(), mtu_);
  // Note that 0 means end of file, but we're talking about a TUN device - there
  // is no end of file. Therefore 0 also indicates error.
  if (result <= 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      *error =
          absl::ErrnoToStatus(errno, "Read from the TUN device was blocked.")
              .message();
      *blocked = true;
      stats_->OnReadError(error);
    }
    return nullptr;
  }

  auto buffer = std::make_unique<QuicData>(read_buffer.release(), result, true);
  if (is_tap_) {
    buffer = ConsumeL2Headers(*buffer);
  }
  if (buffer) {
    stats_->OnPacketRead(buffer->length());
  }
  return buffer;
}

void TunDevicePacketExchanger::set_file_descriptor(int fd) { fd_ = fd; }

const TunDevicePacketExchanger::StatsInterface*
TunDevicePacketExchanger::stats_interface() const {
  return stats_;
}

std::unique_ptr<QuicData> TunDevicePacketExchanger::ApplyL2Headers(
    const QuicData& l3_packet) {
  if (is_tap_ && !mac_initialized_) {
    NetlinkInterface::LinkInfo link_info{};
    if (netlink_->GetLinkInfo(ifname_, &link_info)) {
      memcpy(tap_mac_, link_info.hardware_address, ETH_ALEN);
      mac_initialized_ = true;
    } else {
      QUIC_LOG_EVERY_N_SEC(ERROR, 30)
          << "Unable to get link info for: " << ifname_;
    }
  }

  const auto l2_packet_size = l3_packet.length() + ETH_HLEN;
  auto l2_buffer = std::make_unique<char[]>(l2_packet_size);

  // Populate the Ethernet header
  auto* hdr = reinterpret_cast<ethhdr*>(l2_buffer.get());
  // Set src & dst to my own address
  memcpy(hdr->h_dest, tap_mac_, ETH_ALEN);
  memcpy(hdr->h_source, tap_mac_, ETH_ALEN);
  // Assume ipv6 for now
  // TODO(b/195113643): Support additional protocols.
  hdr->h_proto = absl::ghtons(ETH_P_IPV6);

  // Copy the l3 packet into buffer, just after the ethernet header.
  memcpy(l2_buffer.get() + ETH_HLEN, l3_packet.data(), l3_packet.length());

  return std::make_unique<QuicData>(l2_buffer.release(), l2_packet_size, true);
}

std::unique_ptr<QuicData> TunDevicePacketExchanger::ConsumeL2Headers(
    const QuicData& l2_packet) {
  if (l2_packet.length() < ETH_HLEN) {
    // Packet is too short for ethernet headers. Drop it.
    return nullptr;
  }
  auto* hdr = reinterpret_cast<const ethhdr*>(l2_packet.data());
  if (hdr->h_proto != absl::ghtons(ETH_P_IPV6)) {
    return nullptr;
  }
  constexpr auto kIp6PrefixLen = ETH_HLEN + sizeof(ip6_hdr);
  constexpr auto kIcmp6PrefixLen = kIp6PrefixLen + sizeof(icmp6_hdr);
  if (l2_packet.length() < kIp6PrefixLen) {
    // Packet is too short to be ipv6. Drop it.
    return nullptr;
  }
  auto* ip_hdr = reinterpret_cast<const ip6_hdr*>(l2_packet.data() + ETH_HLEN);
  const bool is_icmp = ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6;

  bool is_neighbor_solicit = false;
  if (is_icmp) {
    if (l2_packet.length() < kIcmp6PrefixLen) {
      // Packet is too short to be icmp6. Drop it.
      return nullptr;
    }
    is_neighbor_solicit =
        reinterpret_cast<const icmp6_hdr*>(l2_packet.data() + kIp6PrefixLen)
            ->icmp6_type == ND_NEIGHBOR_SOLICIT;
  }

  if (is_neighbor_solicit) {
    // If we've received a neighbor solicitation, craft an advertisement to
    // respond with and write it back to the local interface.
    auto* icmp6_payload = l2_packet.data() + kIcmp6PrefixLen;

    QuicIpAddress target_address(
        *reinterpret_cast<const in6_addr*>(icmp6_payload));
    if (target_address != *QboneConstants::GatewayAddress()) {
      // Only respond to solicitations for our gateway address
      return nullptr;
    }

    // Neighbor Advertisement crafted per:
    // https://datatracker.ietf.org/doc/html/rfc4861#section-4.4
    //
    // Using the Target link-layer address option defined at:
    // https://datatracker.ietf.org/doc/html/rfc4861#section-4.6.1
    constexpr size_t kIcmpv6OptionSize = 8;
    const int payload_size = sizeof(in6_addr) + kIcmpv6OptionSize;
    auto payload = std::make_unique<char[]>(payload_size);
    // Place the solicited IPv6 address at the beginning of the response payload
    memcpy(payload.get(), icmp6_payload, sizeof(in6_addr));
    // Setup the Target link-layer address option:
    //      0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |    Length     |    Link-Layer Address ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    int pos = sizeof(in6_addr);
    payload[pos++] = ND_OPT_TARGET_LINKADDR;    // Type
    payload[pos++] = 1;                         // Length in units of 8 octets
    memcpy(&payload[pos], tap_mac_, ETH_ALEN);  // This interfaces' MAC address

    // Populate the ICMPv6 header
    icmp6_hdr response_hdr{};
    response_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;
    // Set the solicited bit to true
    response_hdr.icmp6_dataun.icmp6_un_data8[0] = 64;
    // Craft the full ICMPv6 packet and then ship it off to WritePacket
    // to have it frame it with L2 headers and send it back to the requesting
    // neighbor.
    CreateIcmpPacket(ip_hdr->ip6_src, ip_hdr->ip6_src, response_hdr,
                     absl::string_view(payload.get(), payload_size),
                     [this](absl::string_view packet) {
                       bool blocked;
                       std::string error;
                       WritePacket(packet.data(), packet.size(), &blocked,
                                   &error);
                     });
    // Do not forward the neighbor solicitation through the tunnel since it's
    // link-local.
    return nullptr;
  }

  // If this isn't a Neighbor Solicitation, remove the L2 headers and forward
  // it as though it were an L3 packet.
  const auto l3_packet_size = l2_packet.length() - ETH_HLEN;
  auto shift_buffer = std::make_unique<char[]>(l3_packet_size);
  memcpy(shift_buffer.get(), l2_packet.data() + ETH_HLEN, l3_packet_size);

  return std::make_unique<QuicData>(shift_buffer.release(), l3_packet_size,
                                    true);
}

}  // namespace quic
```