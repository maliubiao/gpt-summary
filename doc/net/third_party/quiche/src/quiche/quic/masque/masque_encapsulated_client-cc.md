Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C++ source code (`masque_encapsulated_client.cc`) and explain its functionality. The prompt also asks for specific connections to JavaScript, logical reasoning examples, common user errors, and debugging guidance.

**2. Initial Code Scan and Keyword Identification:**

I started by quickly scanning the code, looking for keywords and class names that provide hints about its purpose. Some key terms that stood out were:

* `MasqueEncapsulatedClient`
* `MasqueClient`
* `MasqueClientSession`
* `MasqueEncapsulatedClientSession`
* `QUIC` (which strongly suggests it's related to the QUIC protocol)
* `packet writer` (`MasquePacketWriter`)
* `network helper` (`MasqueClientDefaultNetworkHelper`)
* `encapsulated`
* `ConnectIp` (MasqueMode)
* `ChecksumWriter`
* `IPv4`, `IPv6`, `UDP`

These terms immediately suggested the file deals with a specific type of QUIC client that encapsulates other data, likely IP packets, and interacts with a "parent" `MasqueClient`.

**3. Deconstructing the Class Structure:**

I then focused on the main class, `MasqueEncapsulatedClient`. I noted its inheritance from `QuicDefaultClient` and its internal composition (it holds a pointer to a `MasqueClient`). This indicated it's building upon existing QUIC client functionality and has a specific relationship with another Masque client component.

**4. Analyzing Key Methods and Data Members:**

I examined the key methods of `MasqueEncapsulatedClient`:

* **`Create()`:**  A static factory method, suggesting a controlled way to instantiate the client.
* **Constructors:**  Different constructors to handle variations in setup (with and without `uri_template`).
* **`~MasqueEncapsulatedClient()`:**  The destructor, important for understanding cleanup. The call to `CloseConnectUdpStream` is a crucial piece of information.
* **`CreateQuicClientSession()`:**  Responsible for creating the session object. The conditional logic based on `uri_template` is worth noting.
* **`masque_encapsulated_client_session()`:**  A helper function for type casting the base class session.

I also looked at the helper functions outside the class:

* **`MaxPacketSizeForEncapsulatedConnections()`:**  Calculates the maximum packet size, considering the underlying Masque client.
* **`MasqueEncapsulatedConfig()`:**  Creates a `QuicConfig` with a specific max packet size.

**5. Focusing on the Packet Writer (`MasquePacketWriter`):**

The `MasquePacketWriter` class is critical. Its `WritePacket()` method is where the core encapsulation logic resides. I carefully analyzed:

* The check for `MasqueMode::kConnectIp`.
* The conditional IPv4/IPv6 header construction.
* The UDP header construction.
* The use of `ChecksumWriter`.
* The call to `masque_client()->masque_client_session()->SendIpPacket()` or `SendPacket()`.

This section confirmed the encapsulation of data into IP/UDP packets when in `kConnectIp` mode.

**6. Examining the Network Helper (`MasqueClientDefaultNetworkHelper`):**

This class seemed straightforward – its main function is to inject the custom `MasquePacketWriter`.

**7. Connecting to JavaScript (or Lack Thereof):**

Based on my understanding of the code (dealing with low-level networking and QUIC), I reasoned that direct interaction with JavaScript within this specific file was unlikely. However, I knew that network stacks often have higher-level APIs that *are* used by JavaScript. Therefore, I focused on *indirect* relationships, such as how this code enables features that a browser (and thus JavaScript) might utilize. This led to the example of a browser using a MASQUE proxy.

**8. Logical Reasoning (Input/Output):**

For the logical reasoning example, I chose the `MasquePacketWriter`'s `WritePacket` method in `kConnectIp` mode as it involves clear steps. I defined a simple input (a buffer and peer address) and traced the steps the code would take to construct the IP/UDP packet, highlighting key output components.

**9. Identifying User/Programming Errors:**

I considered common issues when working with network configurations and complex protocols:

* Incorrect server address or port.
* Mismatched protocol settings (like not enabling the MASQUE feature).
* Network connectivity problems.
* Problems with the MASQUE server itself.

**10. Tracing User Actions to the Code:**

This required thinking about how a user's actions in a browser or application could lead to this code being executed. The most likely scenario is a user accessing a resource that requires a MASQUE connection. This led to the step-by-step browser navigation example.

**11. Structuring the Explanation:**

Finally, I organized my findings into a clear and logical structure, covering each point requested in the prompt. I used headings, bullet points, code snippets, and clear language to make the explanation easy to understand. I also included a summary to reinforce the key takeaways.

**Self-Correction/Refinement During the Process:**

* Initially, I might have focused too much on the QUIC aspects. I then realized the core functionality is the *encapsulation*, especially in `kConnectIp` mode.
* I made sure to distinguish between direct interaction with JavaScript (unlikely here) and the broader context of how this code fits into a system that JavaScript might use.
* I reviewed the code multiple times to ensure accuracy and to catch any nuances I might have missed initially. For instance, the checksum calculation logic in `ChecksumWriter` required careful reading.
这个 C++ 文件 `masque_encapsulated_client.cc` 是 Chromium 网络栈中 QUIC 协议 MASQUE (Multiplexed Application Substrate over QUIC Encryption) 功能的一部分，专门负责实现 MASQUE 客户端中**封装连接**的功能。

以下是它的主要功能：

**核心功能：创建一个用于封装的 QUIC 客户端，它可以将普通的网络流量（例如 UDP 数据包）封装在 QUIC 连接中发送。**

具体来说，它做了以下事情：

1. **创建和管理封装的 QUIC 连接：**  它继承自 `QuicDefaultClient` 和 `MasqueClient`，负责建立和维护与 MASQUE 服务端的 QUIC 连接，专门用于传输封装后的数据。
2. **封装数据包：** 当配置为 `MasqueMode::kConnectIp` 时，它会将上层协议的数据包（例如 UDP 数据包）封装成 IP 数据包（包括 IPv4 或 IPv6 头部）和 UDP 头部，然后再作为 QUIC 负载发送出去。 这涉及到手动构造 IP 和 UDP 头部，并计算校验和。
3. **使用自定义的 Packet Writer：**  它使用 `MasquePacketWriter` 这个自定义的包写入器。这个写入器的主要作用是拦截所有要发送的 QUIC 数据包，并根据配置决定是否需要进行封装。
4. **与父 MASQUE 客户端协同工作：** 它与 `MasqueClient` 紧密配合。`MasqueEncapsulatedClient` 依赖于 `MasqueClient` 建立的基础 QUIC 连接和会话，并将封装后的数据发送到 `MasqueClientSession`。
5. **处理最大包大小：**  它会根据底层 `MasqueClientSession` 的最大消息负载大小，计算出封装连接的最大包大小，确保封装后的数据包不会超过限制。
6. **创建特定的 QUIC 会话：** 它创建 `MasqueEncapsulatedClientSession` 类型的 QUIC 会话，该会话负责处理封装连接的特定逻辑。
7. **支持 URI 模板：**  可以配置 URI 模板，用于生成连接到 MASQUE 服务器的特定路径。

**它与 JavaScript 的功能关系：**

这个 C++ 文件本身不直接包含 JavaScript 代码，因此没有直接的功能关系。 然而，它所实现的功能是网络栈的一部分，而网络栈是浏览器（通常通过 Blink 渲染引擎）的核心组件。JavaScript 代码可以通过浏览器提供的 Web API 来间接地使用这个功能。

**举例说明：**

假设一个 Web 应用想要使用 MASQUE 协议来建立一个经过加密和多路复用的 UDP 连接，用于进行实时的媒体传输。

1. **JavaScript 发起请求：**  Web 应用通过 JavaScript 调用浏览器的网络 API (例如 `WebTransport` 或一个自定义的 API，如果浏览器提供了直接操作 MASQUE 的接口) 来请求建立一个 MASQUE 连接。
2. **浏览器处理请求：** 浏览器内部会将这个请求转化为对底层网络栈的调用。
3. **`MasqueEncapsulatedClient` 的创建和使用：**  网络栈会创建 `MasqueEncapsulatedClient` 的实例，并配置其连接到指定的 MASQUE 服务器。
4. **UDP 数据封装：** 当 Web 应用需要发送 UDP 数据时，这些数据会被传递到网络栈。如果配置了 `MasqueMode::kConnectIp`，`MasquePacketWriter` 会将这些 UDP 数据封装到 IP 和 UDP 头部中。
5. **QUIC 传输：** 封装后的数据作为 QUIC 数据包通过 `MasqueClientSession` 发送到 MASQUE 服务器。
6. **服务器解封装和转发：** MASQUE 服务器接收到 QUIC 数据包后，会解封装出原始的 UDP 数据，并将其转发到目标地址。

**逻辑推理的假设输入与输出：**

**场景：** 使用 `MasqueMode::kConnectIp` 发送一个小的 UDP 数据包。

**假设输入：**

* **`buffer` (待发送的数据):**  一个包含 "Hello" 字符串的 char 数组 (5 字节)。
* **`buf_len`:** 5
* **`peer_address`:**  一个 IPv4 地址 `192.168.1.100:12345`。
* **`client_->masque_encapsulated_client_session()->local_v4_address()`:**  客户端本地 IPv4 地址，例如 `192.168.1.10`。

**代码片段（`MasquePacketWriter::WritePacket` 中 `MasqueMode::kConnectIp` 的 IPv4 分支）：**

```c++
    // ... (前面 IPv4 头部写入)
    QUICHE_CHECK(writer.WriteUInt8(0x45));  // Version = 4, IHL = 5.
    QUICHE_CHECK(writer.WriteUInt8(0));     // DSCP/ECN.
    QUICHE_CHECK(writer.WriteUInt16(packet.size()));  // Total Length.
    QUICHE_CHECK(writer.WriteUInt32(0));              // No fragmentation.
    QUICHE_CHECK(writer.WriteUInt8(64));              // TTL = 64.
    QUICHE_CHECK(writer.WriteUInt8(17));              // IP Protocol = UDP.
    QUICHE_CHECK(writer.WriteUInt16(0));  // Checksum = 0 initially.
    in_addr source_address = client_->masque_encapsulated_client_session()
                                 ->local_v4_address()
                                 .GetIPv4();
    QUICHE_CHECK(
        writer.WriteBytes(&source_address, sizeof(source_address)));
    in_addr destination_address = peer_address.host().GetIPv4();
    QUICHE_CHECK(writer.WriteBytes(&destination_address,
                                   sizeof(destination_address)));
    ChecksumWriter ip_checksum_writer(writer);
    QUICHE_CHECK(ip_checksum_writer.IngestData(0, kIPv4HeaderSize));
    QUICHE_CHECK(
        ip_checksum_writer.WriteChecksumAtOffset(kIPv4ChecksumOffset));
    // Write UDP header.
    QUICHE_CHECK(writer.WriteUInt16(0x1234));  // Source port.
    QUICHE_CHECK(
        writer.WriteUInt16(peer_address.port()));  // Destination port.
    QUICHE_CHECK(writer.WriteUInt16(udp_length));  // UDP length.
    QUICHE_CHECK(writer.WriteUInt16(0));           // Checksum = 0 initially.
    // Write UDP payload.
    QUICHE_CHECK(writer.WriteBytes(buffer, buf_len));
    ChecksumWriter udp_checksum_writer(writer);
    QUICHE_CHECK(udp_checksum_writer.IngestData(12, 8));  // IP addresses.
    udp_checksum_writer.IngestUInt8(0);                   // Zeroes.
    udp_checksum_writer.IngestUInt8(17);           // IP Protocol = UDP.
    udp_checksum_writer.IngestUInt16(udp_length));  // UDP length.
    QUICHE_CHECK(udp_checksum_writer.IngestData(
        kIPv4HeaderSize, udp_length));  // UDP header and data.
    QUICHE_CHECK(
        udp_checksum_writer.WriteChecksumAtOffset(kIPv4HeaderSize + 6));
    // ... (发送数据)
```

**预期输出 (封装后的 IP 数据包的十六进制表示，简化表示)：**

```
45 00 00 25 00 00 40 00 40 11 <IP 校验和>  // IPv4 头部
0A 01 A8 C0  // 源 IP: 192.168.1.10 (C0 A8 01 0A 的字节序可能不同)
64 00 01 C0  // 目的 IP: 192.168.1.100 (C0 01 A8 64 的字节序可能不同)
12 34 30 39 00 15 00 00  // UDP 头部 (源端口 4660, 目的端口 12345, 长度 21)
48 65 6c 6c 6f              // UDP 负载: "Hello"
<UDP 校验和>                // UDP 校验和
```

* **IPv4 头部：**  版本、首部长度、总长度、标识、标志、片偏移、TTL、协议（UDP=17）、头部校验和、源 IP 地址、目的 IP 地址。
* **UDP 头部：** 源端口 (假设为 0x1234 = 4660), 目的端口 (12345), 长度 (IP 头部大小 + UDP 头部大小 + 数据长度 = 20 + 8 + 5 = 33, 十六进制 0x21), 校验和。
* **UDP 负载：**  "Hello" 的 ASCII 编码。

**请注意：** 实际的 IP 和 UDP 校验和需要在运行时计算。上述输出只是为了说明封装的过程。

**用户或编程常见的使用错误：**

1. **错误的服务器地址或端口：** 用户可能配置了错误的 MASQUE 服务器地址或端口，导致客户端无法连接。
2. **MASQUE 模式配置错误：** 用户可能没有正确配置 MASQUE 模式（例如，需要封装 IP 数据包但没有设置为 `MasqueMode::kConnectIp`）。
3. **网络连通性问题：** 客户端的网络环境可能存在问题，无法连接到 MASQUE 服务器。
4. **防火墙阻止连接：** 防火墙可能阻止了客户端与 MASQUE 服务器之间的 QUIC 连接。
5. **MASQUE 服务器未运行或配置错误：**  MASQUE 服务器本身可能没有运行，或者配置不正确，导致无法处理客户端的连接请求。
6. **尝试发送过大的数据包：**  用户可能尝试发送超过封装连接最大包大小限制的数据包，导致发送失败。
7. **依赖于未实现的特性：** MASQUE 协议还在发展中，用户可能依赖于尚未实现或支持的特性。
8. **在不支持 MASQUE 的环境中使用：**  用户可能在不支持 MASQUE 协议的环境中尝试使用相关功能。

**用户操作是如何一步步到达这里的，作为调试线索：**

假设用户在使用一个支持 MASQUE 的 Chromium 浏览器或应用。

1. **用户打开一个网页或应用，该网页或应用尝试建立一个需要 MASQUE 的连接。** 这可能是因为该网页或应用配置为使用 MASQUE 代理进行某些网络请求。
2. **浏览器或应用的网络栈检测到需要使用 MASQUE。**  这可能基于一些配置或协议协商。
3. **网络栈开始建立与 MASQUE 服务器的 QUIC 连接。** 这涉及到 DNS 解析、TLS 握手等过程。
4. **如果需要封装 IP 数据包，网络栈会创建 `MasqueEncapsulatedClient` 的实例。**  这通常在建立与 MASQUE 服务器的基础连接之后发生。
5. **用户或应用尝试发送数据，例如通过一个 UDP socket。**
6. **网络栈的 UDP 处理逻辑会将数据传递到 `MasqueEncapsulatedClient` (或者更准确地说，通过其 `MasquePacketWriter`)。**
7. **如果 `MasqueMode` 设置为 `kConnectIp`，`MasquePacketWriter::WritePacket` 方法会被调用。**
8. **在这个方法中，你会进入到构造 IP 和 UDP 头部的逻辑。**

**调试线索：**

* **检查网络配置：** 确认浏览器或应用的 MASQUE 相关配置是否正确，包括服务器地址、端口、MASQUE 模式等。
* **抓包分析：** 使用 Wireshark 等工具抓取网络包，查看客户端与 MASQUE 服务器之间的 QUIC 连接，以及是否有封装的 IP 数据包发送。
* **查看 Chromium 的网络日志：**  Chromium 提供了详细的网络日志，可以查看 QUIC 连接的建立过程、数据包的发送情况等。可以通过 `--log-net-log` 命令行参数启动 Chromium 并查看 `chrome://net-export/`。
* **断点调试：**  如果需要深入分析，可以在 `MasqueEncapsulatedClient.cc` 和相关的代码中设置断点，逐步跟踪代码执行流程，查看变量的值，例如 `masque_mode()` 的值，以及封装后的数据包内容。
* **检查 `MasqueClientSession` 的状态：**  确认与 MASQUE 服务器的基础 QUIC 连接是否已建立且正常工作。
* **验证 MASQUE 服务器的配置和状态：**  确认 MASQUE 服务器是否正在运行，并且配置正确。

总而言之，`masque_encapsulated_client.cc` 负责 Chromium 中 MASQUE 客户端的封装连接功能，它将普通网络流量封装在 QUIC 连接中，为更高层次的应用提供安全的隧道。虽然它本身不包含 JavaScript，但它是浏览器网络功能的重要组成部分，JavaScript 可以通过浏览器提供的 API 间接地使用它的功能。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/masque/masque_encapsulated_client.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/masque/masque_encapsulated_client.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/proof_verifier.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/masque/masque_client.h"
#include "quiche/quic/masque/masque_client_session.h"
#include "quiche/quic/masque/masque_encapsulated_client_session.h"
#include "quiche/quic/masque/masque_utils.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/quic_client_default_network_helper.h"
#include "quiche/quic/tools/quic_default_client.h"
#include "quiche/quic/tools/quic_name_lookup.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_data_reader.h"
#include "quiche/common/quiche_data_writer.h"

namespace quic {

namespace {

class ChecksumWriter {
 public:
  explicit ChecksumWriter(quiche::QuicheDataWriter& writer) : writer_(writer) {}
  void IngestUInt16(uint16_t val) { accumulator_ += val; }
  void IngestUInt8(uint8_t val) {
    uint16_t val16 = odd_ ? val : (val << 8);
    accumulator_ += val16;
    odd_ = !odd_;
  }
  bool IngestData(size_t offset, size_t length) {
    quiche::QuicheDataReader reader(
        writer_.data(), std::min<size_t>(offset + length, writer_.capacity()));
    if (!reader.Seek(offset) || reader.BytesRemaining() < length) {
      return false;
    }
    // Handle any potentially off first byte.
    uint8_t first_byte;
    if (odd_ && reader.ReadUInt8(&first_byte)) {
      IngestUInt8(first_byte);
    }
    // Handle each 16-bit word at a time.
    while (reader.BytesRemaining() >= sizeof(uint16_t)) {
      uint16_t word;
      if (!reader.ReadUInt16(&word)) {
        return false;
      }
      IngestUInt16(word);
    }
    // Handle any leftover odd byte.
    uint8_t last_byte;
    if (reader.ReadUInt8(&last_byte)) {
      IngestUInt8(last_byte);
    }
    return true;
  }
  bool WriteChecksumAtOffset(size_t offset) {
    while (accumulator_ >> 16 > 0) {
      accumulator_ = (accumulator_ & 0xffff) + (accumulator_ >> 16);
    }
    accumulator_ = 0xffff & ~accumulator_;
    quiche::QuicheDataWriter writer2(writer_.capacity(), writer_.data());
    return writer2.Seek(offset) && writer2.WriteUInt16(accumulator_);
  }

 private:
  quiche::QuicheDataWriter& writer_;
  uint32_t accumulator_ = 0xffff;
  bool odd_ = false;
};

// Custom packet writer that allows getting all of a connection's outgoing
// packets.
class MasquePacketWriter : public QuicPacketWriter {
 public:
  explicit MasquePacketWriter(MasqueEncapsulatedClient* client)
      : client_(client) {}
  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const QuicIpAddress& /*self_address*/,
                          const QuicSocketAddress& peer_address,
                          PerPacketOptions* /*options*/,
                          const QuicPacketWriterParams& /*params*/) override {
    QUICHE_DCHECK(peer_address.IsInitialized());
    QUIC_DVLOG(1) << "MasquePacketWriter trying to write " << buf_len
                  << " bytes to " << peer_address;
    if (client_->masque_client()->masque_mode() == MasqueMode::kConnectIp) {
      constexpr size_t kIPv4HeaderSize = 20;
      constexpr size_t kIPv4ChecksumOffset = 10;
      constexpr size_t kIPv6HeaderSize = 40;
      constexpr size_t kUdpHeaderSize = 8;
      const size_t udp_length = kUdpHeaderSize + buf_len;
      std::string packet;
      packet.resize(
          (peer_address.host().IsIPv6() ? kIPv6HeaderSize : kIPv4HeaderSize) +
          udp_length);
      quiche::QuicheDataWriter writer(packet.size(), packet.data());
      if (peer_address.host().IsIPv6()) {
        // Write IPv6 header.
        QUICHE_CHECK(writer.WriteUInt8(0x60));  // Version = 6 and DSCP.
        QUICHE_CHECK(writer.WriteUInt8(0));     // DSCP/ECN and flow label.
        QUICHE_CHECK(writer.WriteUInt16(0));    // Flow label.
        QUICHE_CHECK(writer.WriteUInt16(udp_length));  // Payload Length.
        QUICHE_CHECK(writer.WriteUInt8(17));           // Next header = UDP.
        QUICHE_CHECK(writer.WriteUInt8(64));           // Hop limit = 64.
        in6_addr source_address = {};
        if (client_->masque_encapsulated_client_session()
                ->local_v6_address()
                .IsIPv6()) {
          source_address = client_->masque_encapsulated_client_session()
                               ->local_v6_address()
                               .GetIPv6();
        }
        QUICHE_CHECK(
            writer.WriteBytes(&source_address, sizeof(source_address)));
        in6_addr destination_address = peer_address.host().GetIPv6();
        QUICHE_CHECK(writer.WriteBytes(&destination_address,
                                       sizeof(destination_address)));
      } else {
        // Write IPv4 header.
        QUICHE_CHECK(writer.WriteUInt8(0x45));  // Version = 4, IHL = 5.
        QUICHE_CHECK(writer.WriteUInt8(0));     // DSCP/ECN.
        QUICHE_CHECK(writer.WriteUInt16(packet.size()));  // Total Length.
        QUICHE_CHECK(writer.WriteUInt32(0));              // No fragmentation.
        QUICHE_CHECK(writer.WriteUInt8(64));              // TTL = 64.
        QUICHE_CHECK(writer.WriteUInt8(17));              // IP Protocol = UDP.
        QUICHE_CHECK(writer.WriteUInt16(0));  // Checksum = 0 initially.
        in_addr source_address = {};
        if (client_->masque_encapsulated_client_session()
                ->local_v4_address()
                .IsIPv4()) {
          source_address = client_->masque_encapsulated_client_session()
                               ->local_v4_address()
                               .GetIPv4();
        }
        QUICHE_CHECK(
            writer.WriteBytes(&source_address, sizeof(source_address)));
        in_addr destination_address = peer_address.host().GetIPv4();
        QUICHE_CHECK(writer.WriteBytes(&destination_address,
                                       sizeof(destination_address)));
        ChecksumWriter ip_checksum_writer(writer);
        QUICHE_CHECK(ip_checksum_writer.IngestData(0, kIPv4HeaderSize));
        QUICHE_CHECK(
            ip_checksum_writer.WriteChecksumAtOffset(kIPv4ChecksumOffset));
      }
      // Write UDP header.
      QUICHE_CHECK(writer.WriteUInt16(0x1234));  // Source port.
      QUICHE_CHECK(
          writer.WriteUInt16(peer_address.port()));  // Destination port.
      QUICHE_CHECK(writer.WriteUInt16(udp_length));  // UDP length.
      QUICHE_CHECK(writer.WriteUInt16(0));           // Checksum = 0 initially.
      // Write UDP payload.
      QUICHE_CHECK(writer.WriteBytes(buffer, buf_len));
      ChecksumWriter udp_checksum_writer(writer);
      if (peer_address.host().IsIPv6()) {
        QUICHE_CHECK(udp_checksum_writer.IngestData(8, 32));  // IP addresses.
        udp_checksum_writer.IngestUInt16(0);  // High bits of UDP length.
        udp_checksum_writer.IngestUInt16(
            udp_length);                      // Low bits of UDP length.
        udp_checksum_writer.IngestUInt16(0);  // Zeroes.
        udp_checksum_writer.IngestUInt8(0);   // Zeroes.
        udp_checksum_writer.IngestUInt8(17);  // Next header = UDP.
        QUICHE_CHECK(udp_checksum_writer.IngestData(
            kIPv6HeaderSize, udp_length));  // UDP header and data.
        QUICHE_CHECK(
            udp_checksum_writer.WriteChecksumAtOffset(kIPv6HeaderSize + 6));
      } else {
        QUICHE_CHECK(udp_checksum_writer.IngestData(12, 8));  // IP addresses.
        udp_checksum_writer.IngestUInt8(0);                   // Zeroes.
        udp_checksum_writer.IngestUInt8(17);           // IP Protocol = UDP.
        udp_checksum_writer.IngestUInt16(udp_length);  // UDP length.
        QUICHE_CHECK(udp_checksum_writer.IngestData(
            kIPv4HeaderSize, udp_length));  // UDP header and data.
        QUICHE_CHECK(
            udp_checksum_writer.WriteChecksumAtOffset(kIPv4HeaderSize + 6));
      }
      client_->masque_client()->masque_client_session()->SendIpPacket(
          packet, client_->masque_encapsulated_client_session());
    } else {
      absl::string_view packet(buffer, buf_len);
      client_->masque_client()->masque_client_session()->SendPacket(
          packet, peer_address, client_->masque_encapsulated_client_session());
    }
    return WriteResult(WRITE_STATUS_OK, buf_len);
  }

  bool IsWriteBlocked() const override { return false; }

  void SetWritable() override {}

  std::optional<int> MessageTooBigErrorCode() const override {
    return std::nullopt;
  }

  QuicByteCount GetMaxPacketSize(
      const QuicSocketAddress& /*peer_address*/) const override {
    // This is only used as a min against the other limits, so we set it to the
    // maximum value so it doesn't reduce the MTU.
    return kDefaultMaxPacketSizeForTunnels;
  }

  bool SupportsReleaseTime() const override { return false; }

  bool IsBatchMode() const override { return false; }

  bool SupportsEcn() const override { return false; }
  QuicPacketBuffer GetNextWriteLocation(
      const QuicIpAddress& /*self_address*/,
      const QuicSocketAddress& /*peer_address*/) override {
    return {nullptr, nullptr};
  }

  WriteResult Flush() override { return WriteResult(WRITE_STATUS_OK, 0); }

 private:
  MasqueEncapsulatedClient* client_;  // Unowned.
};

// Custom network helper that allows injecting a custom packet writer in order
// to get all of a connection's outgoing packets.
class MasqueClientDefaultNetworkHelper : public QuicClientDefaultNetworkHelper {
 public:
  MasqueClientDefaultNetworkHelper(QuicEventLoop* event_loop,
                                   MasqueEncapsulatedClient* client)
      : QuicClientDefaultNetworkHelper(event_loop, client), client_(client) {}
  QuicPacketWriter* CreateQuicPacketWriter() override {
    return new MasquePacketWriter(client_);
  }

 private:
  MasqueEncapsulatedClient* client_;  // Unowned.
};

}  // namespace

// static
std::unique_ptr<MasqueEncapsulatedClient> MasqueEncapsulatedClient::Create(
    QuicSocketAddress server_address, const QuicServerId& server_id,
    const std::string& uri_template, MasqueMode masque_mode,
    QuicEventLoop* event_loop, std::unique_ptr<ProofVerifier> proof_verifier,
    MasqueClient* underlying_masque_client) {
  // Use absl::WrapUnique instead of std::make_unique because constructor is
  // private and therefore not accessible from make_unique.
  auto masque_client = absl::WrapUnique(new MasqueEncapsulatedClient(
      server_address, server_id, masque_mode, event_loop,
      std::move(proof_verifier), underlying_masque_client, uri_template));

  if (masque_client == nullptr) {
    QUIC_LOG(ERROR) << "Failed to create masque_client";
    return nullptr;
  }
  if (!masque_client->Prepare(
          MaxPacketSizeForEncapsulatedConnections(underlying_masque_client))) {
    return nullptr;
  }
  return masque_client;
}

MasqueEncapsulatedClient::MasqueEncapsulatedClient(
    QuicSocketAddress server_address, const QuicServerId& server_id,
    QuicEventLoop* event_loop, std::unique_ptr<ProofVerifier> proof_verifier,
    MasqueClient* masque_client)
    : MasqueClient(
          server_address, server_id, event_loop,
          MasqueEncapsulatedConfig(masque_client),
          std::make_unique<MasqueClientDefaultNetworkHelper>(event_loop, this),
          std::move(proof_verifier)),
      masque_client_(masque_client) {}

MasqueEncapsulatedClient::MasqueEncapsulatedClient(
    QuicSocketAddress server_address, const QuicServerId& server_id,
    MasqueMode masque_mode, QuicEventLoop* event_loop,
    std::unique_ptr<ProofVerifier> proof_verifier, MasqueClient* masque_client,
    const std::string& uri_template)
    : MasqueClient(
          server_address, server_id, masque_mode, event_loop,
          MasqueEncapsulatedConfig(masque_client),
          std::make_unique<MasqueClientDefaultNetworkHelper>(event_loop, this),
          std::move(proof_verifier), uri_template),
      masque_client_(masque_client) {}

MasqueEncapsulatedClient::~MasqueEncapsulatedClient() {
  masque_client_->masque_client_session()->CloseConnectUdpStream(
      masque_encapsulated_client_session());
}

std::unique_ptr<QuicSession> MasqueEncapsulatedClient::CreateQuicClientSession(
    const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection) {
  QUIC_DLOG(INFO) << "Creating MASQUE encapsulated session for "
                  << connection->connection_id();
  if (!uri_template().empty()) {
    return std::make_unique<MasqueEncapsulatedClientSession>(
        masque_mode(), uri_template(), *config(), supported_versions,
        connection, server_id(), crypto_config(),
        masque_client_->masque_client_session(), this);
  }
  return std::make_unique<MasqueEncapsulatedClientSession>(
      *config(), supported_versions, connection, server_id(), crypto_config(),
      masque_client_->masque_client_session(), this);
}

MasqueEncapsulatedClientSession*
MasqueEncapsulatedClient::masque_encapsulated_client_session() {
  return static_cast<MasqueEncapsulatedClientSession*>(
      QuicDefaultClient::session());
}

QuicByteCount MaxPacketSizeForEncapsulatedConnections(
    MasqueClient* underlying_masque_client) {
  QuicByteCount max_packet_size =
      underlying_masque_client->masque_client_session()
          ->GetGuaranteedLargestMessagePayload() -
      /* max length of quarter stream ID */ sizeof(QuicStreamId) -
      /* context ID set to zero */ sizeof(uint8_t);
  QUICHE_CHECK_GE(max_packet_size, 1200u)
      << "RFC 9000 requires QUIC max packet size to be above 1200 bytes";
  return max_packet_size;
}

QuicConfig MasqueEncapsulatedConfig(MasqueClient* underlying_masque_client) {
  QuicConfig config;
  config.SetMaxPacketSizeToSend(
      MaxPacketSizeForEncapsulatedConnections(underlying_masque_client));
  return config;
}

}  // namespace quic
```