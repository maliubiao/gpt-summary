Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Request:** The request asks for a functional description of the C++ code, its relation to JavaScript (if any), logical reasoning examples, common usage errors, and how a user might reach this code during debugging.

2. **Initial Scan and Keyword Identification:** I'll start by quickly scanning the code for keywords and familiar patterns:
    * `#include`: Standard C++ includes, some specific to QUIC and Chromium.
    * `namespace quic`:  Indicates this is part of the QUIC library.
    * `Masque`: This is a prominent term, likely the core functionality.
    * `TunInterface`, `TapInterface`: Network interface related functions.
    * `ioctl`, `ifreq`: Linux-specific network interface manipulation.
    * `DEFINE_QUICHE_COMMAND_LINE_FLAG`:  Indicates command-line configuration.
    * `ComputeConcealedAuthContext`, `ConcealedAuthDataCoveredBySignature`: Security/authentication related.
    * `ParsedQuicVersionVector`, `AllSupportedVersions`, `QuicEnableVersion`: Version negotiation.
    * `std::ostream& operator<<`: Overloading the output stream operator for `MasqueMode`.

3. **High-Level Functionality Deduction:** Based on the keywords, I can infer the primary purpose of this file: It provides utility functions related to the "Masque" protocol within the QUIC context. It deals with:
    * Defining supported QUIC versions for Masque.
    * Representing and manipulating the "Masque Mode".
    * Creating virtual network interfaces (TUN and TAP) on Linux.
    * Computing concealed authentication contexts.

4. **Detailed Function Analysis (Function by Function):**

    * **`MasqueSupportedVersions()`:**  This function iterates through supported QUIC versions, filters those suitable for Masque (IETF QUIC, not QUICv2), enables them, and returns the filtered list.

    * **`MasqueModeToString()` and `operator<<`:** These functions handle the string representation of the `MasqueMode` enum, making it easier to log and debug.

    * **`CreateTunInterface()`:** This is the most complex part. The `#if defined(__linux__)` strongly suggests it's Linux-specific. The code uses `open`, `ioctl`, `socket`, and `ifreq` structures. This points directly to creating a TUN (tunnel) interface. The code configures the interface's IP addresses, MTU, and brings it up. The `server` parameter likely distinguishes between the client and server side of the tunnel setup. The error handling with `QUIC_PLOG` is also important to note. The "TODO" comment is a reminder for future work.

    * **`CreateTapInterface()`:** Similar to `CreateTunInterface`, but it creates a TAP (network tap) interface. The key difference is that TAP interfaces operate at the Ethernet frame level (layer 2), while TUN interfaces operate at the IP packet level (layer 3). The inclusion of the `FLAGS_tap_bridge_interface` flag suggests the ability to bridge this TAP interface to an existing physical interface.

    * **`ComputeConcealedAuthContext()`:** This function takes several authentication-related parameters (signature scheme, key ID, public key, etc.) and serializes them into a byte string using `QuicDataWriter` and variable-length integers. The purpose is likely to create a context for cryptographic operations.

    * **`ConcealedAuthDataCoveredBySignature()`:** This function prepends a fixed string and some padding to the provided `signature_input`. This likely forms the data that is actually signed in the concealed authentication process.

5. **JavaScript Relationship:**  I consider the core function of this code: low-level network interface manipulation and cryptographic context creation. JavaScript, especially in web browsers, doesn't directly interact with these system-level functionalities. Browsers rely on the underlying OS and network stack (which this code contributes to). *However*, if this Masque functionality is used within a web browser (Chromium), JavaScript code in the browser would indirectly trigger this C++ code through network requests. The `CONNECT-IP` and `CONNECT-ETHERNET` modes hint at proxying or tunneling, which browsers might initiate.

6. **Logical Reasoning (Input/Output Examples):** I'll pick the simpler functions for these examples. For `MasqueModeToString`, it's straightforward. For `ComputeConcealedAuthContext`, I need to consider how the input parameters affect the output. The use of variable-length integers means the output length will vary.

7. **Common Usage Errors:**  Focus on the functions that interact with the operating system or have external dependencies. Incorrect IP addresses in `CreateTunInterface` or missing permissions are likely issues. For `CreateTapInterface`, specifying a non-existent bridge interface or incorrect command-line flags are possibilities.

8. **Debugging Scenario:** Think about how a developer using Chromium's networking features might encounter issues related to Masque. Setting breakpoints in this C++ code would be a step after suspecting a problem at the network interface or authentication level. The user actions leading to this would involve configuring the browser or a related application to use a Masque proxy or tunnel.

9. **Structure and Refinement:**  Organize the information logically under the requested headings. Ensure the language is clear and concise. Use code snippets and formatting to enhance readability. Review and refine the examples and explanations. For example, initially, I might have only considered the lack of *direct* interaction between this C++ and JavaScript. However, realizing that browser functionality indirectly relies on this code is a crucial refinement. Similarly, initially I might have missed the command-line flag impact on `CreateTapInterface`.

This structured approach ensures all aspects of the request are addressed, moving from a high-level understanding to specific details and potential use cases. The focus on keywords, function-by-function analysis, and considering the broader context of Chromium's networking stack is key to generating a comprehensive response.
这个文件 `net/third_party/quiche/src/quiche/quic/masque/masque_utils.cc` 属于 Chromium 网络栈中 QUIC 协议的扩展部分，专门用于实现 MASQUE (Multiplexed Application Substrate over QUIC Encryption) 协议的相关工具函数。MASQUE 是一种基于 QUIC 的 VPN 或代理技术。

以下是该文件的主要功能分解：

**1. 定义 MASQUE 支持的 QUIC 版本:**

   - `MasqueSupportedVersions()` 函数会返回一个 `ParsedQuicVersionVector`，其中包含了 MASQUE 协议支持的 QUIC 版本。
   - 它会遍历所有支持的 QUIC 版本，并选择那些使用 HTTP/3 并且不是 QUICv2 的版本。
   - `QuicEnableVersion(version)`  表明这些版本被显式地启用。
   - **功能:** 确定哪些 QUIC 版本可以用于 MASQUE 连接，确保兼容性。

**2. MASQUE 模式的字符串表示:**

   - `MasqueModeToString(MasqueMode masque_mode)` 函数将 `MasqueMode` 枚举值转换为易于阅读的字符串，例如 "Invalid", "Open", "CONNECT-IP", "CONNECT-ETHERNET"。
   - `operator<<(std::ostream& os, const MasqueMode& masque_mode)` 重载了输出流操作符，可以直接将 `MasqueMode` 对象输出到 `std::cout` 或其他输出流。
   - **功能:** 提供 MASQUE 操作模式的文本描述，方便日志记录和调试。

**3. 创建 TUN (Tunnel) 接口 (仅限 Linux):**

   - `CreateTunInterface(const QuicIpAddress& client_address, bool server)` 函数在 Linux 系统上创建一个 TUN 虚拟网络接口。
   - 它使用 `open`, `ioctl` 等系统调用来操作 `/dev/net/tun` 设备。
   - 该函数会配置接口的 IP 地址、对端地址、MTU 等参数。
   - `server` 参数用于区分创建的是服务器端的 TUN 接口还是客户端的 TUN 接口，两者配置略有不同。
   - **功能:**  为 MASQUE 的 CONNECT-IP 模式创建虚拟网络隧道，使得数据包可以被路由到用户空间进行处理。

**逻辑推理 (假设输入与输出):**

   - **假设输入 (客户端):** `client_address` 为 `192.168.1.100` (IPv4)。
   - **输出 (客户端):**  会创建一个名为 `tunX` (X为数字) 的 TUN 接口，其本地地址可能被设置为 `192.168.1.100`，对端地址可能被设置为 `192.168.1.1`，MTU 被设置为 1280。该函数返回新创建的 TUN 接口的文件描述符。
   - **假设输入 (服务器):** `client_address` 为 `192.168.1.100` (IPv4)。
   - **输出 (服务器):** 会创建一个名为 `tunX` 的 TUN 接口，其本地地址可能被设置为 `192.168.1.1`，对端地址可能被设置为 `192.168.1.100`。该函数返回新创建的 TUN 接口的文件描述符。

**4. 创建 TAP (Network Tap) 接口 (仅限 Linux):**

   - `CreateTapInterface()` 函数在 Linux 系统上创建一个 TAP 虚拟网络接口。
   - 类似于 TUN 接口，它也使用 `open`, `ioctl` 等系统调用。
   - 与 TUN 接口不同，TAP 接口工作在数据链路层 (Layer 2)，可以接收和发送原始以太网帧。
   - 该函数还可以根据命令行标志 `tap_bridge_interface` 将创建的 TAP 接口桥接到指定的物理网络接口。
   - **功能:** 为 MASQUE 的 CONNECT-ETHERNET 模式创建虚拟网络设备，用于处理原始以太网帧。

**逻辑推理 (假设输入与输出):**

   - **假设没有设置 `tap_bridge_interface` 命令行标志:**
   - **输出:** 会创建一个名为 `tapX` (X为数字) 的 TAP 接口，MTU 被设置为 1280。该函数返回新创建的 TAP 接口的文件描述符。
   - **假设设置了 `tap_bridge_interface` 命令行标志为 `eth0`:**
   - **输出:** 除了创建一个 `tapX` 接口外，还会尝试将该接口添加到名为 `eth0` 的网桥中。如果成功，则返回 `tapX` 的文件描述符，否则可能返回 -1 并记录错误。

**5. 计算隐藏的认证上下文:**

   - `ComputeConcealedAuthContext(uint16_t signature_scheme, ...)` 函数用于构建一个用于隐藏认证的上下文信息。
   - 它接收签名方案、密钥 ID、公钥、协议、主机名、端口号、Realm 等参数。
   - 它使用 `QuicDataWriter` 将这些参数编码成一个字节串。
   - **功能:**  为 MASQUE 协议中的认证机制生成一个经过编码的上下文，用于后续的签名或验证操作。

**逻辑推理 (假设输入与输出):**

   - **假设输入:** `signature_scheme = 0x0403` (TLS_ECDSA_SHA256), `key_id = "key1"`, `public_key = "mypublickey"`, `scheme = "https"`, `host = "example.com"`, `port = 443`, `realm = "myrealm"`.
   - **输出:**  会生成一个包含这些编码后数据的字节串，其具体内容取决于 `QuicDataWriter` 的编码方式 (通常使用变长整数编码字符串长度)。

**6. 构建用于签名的隐藏认证数据:**

   - `ConcealedAuthDataCoveredBySignature(absl::string_view signature_input)` 函数将一个固定的前缀和填充添加到提供的签名输入中。
   - **功能:**  创建一个用于签名的最终数据结构，其中包含了固定的 "HTTP Concealed Authentication" 标识以及实际需要签名的数据。

**与 JavaScript 的关系:**

这个 C++ 文件本身不包含任何 JavaScript 代码，也不直接与 JavaScript 交互。然而，Chromium 是一个包含 JavaScript 引擎 (V8) 的浏览器。

- 当用户在浏览器中执行某些操作，例如通过配置了 MASQUE 的代理访问网站时，浏览器内部的网络栈 (用 C++ 实现) 会处理这些网络请求。
- 对于使用 MASQUE 的连接，这个 `masque_utils.cc` 文件中的函数会被调用，例如创建 TUN/TAP 接口，构建认证上下文等。
- JavaScript 代码可以通过浏览器的 Web API (例如 `fetch`, `XMLHttpRequest`) 发起网络请求，这些请求最终会由底层的 C++ 网络栈处理。
- 因此，虽然 JavaScript 不直接调用这些 C++ 函数，但用户的 JavaScript 代码发起的网络活动会间接地触发这些 C++ 代码的执行。

**举例说明:**

假设一个用户在浏览器中配置了一个使用 MASQUE 的代理服务器。当用户访问 `https://example.com` 时：

1. **JavaScript (在浏览器中):**  用户的 JavaScript 代码 (例如，网页上的脚本) 发起一个 `fetch('https://example.com')` 请求。
2. **Chromium 网络栈 (C++):**
   - 网络栈识别到需要使用 MASQUE 代理。
   - 根据 MASQUE 的配置，可能会调用 `CreateTunInterface` 或 `CreateTapInterface` 来创建虚拟网络接口。
   - `ComputeConcealedAuthContext` 可能会被调用来生成认证信息。
   - QUIC 连接会被建立到 MASQUE 代理服务器。
   - 通过创建的 TUN/TAP 接口或者直接在 QUIC 连接上封装数据，将用户的 HTTP 请求发送出去。

**用户或编程常见的使用错误:**

1. **缺少必要的权限:** 在 Linux 系统上创建 TUN/TAP 接口通常需要 root 权限或特定的能力 (capabilities)。如果用户运行 Chromium 的进程没有这些权限，`CreateTunInterface` 或 `CreateTapInterface` 会失败。
   - **错误信息:**  可能会在日志中看到类似 "Failed to open clone device" 或 "TUNSETIFF failed" 的错误信息，以及 `Permission denied` 的错误码。
   - **用户操作导致:** 用户直接运行 Chromium 而没有给予足够的权限，或者在容器化环境中没有正确配置网络权限。

2. **错误的命令行标志:**  如果用户错误地设置了 `tap_bridge_interface` 命令行标志，例如指定了一个不存在的接口名称，`CreateTapInterface` 可能会失败。
   - **错误信息:**  可能会看到 "SIOCBRADDIF failed" 的错误信息。
   - **用户操作导致:**  用户在启动 Chromium 时使用了错误的命令行参数。

3. **不支持的操作系统:** TUN/TAP 接口的创建代码是 Linux 特有的。在其他操作系统上 (例如 Windows, macOS)，这些函数会直接返回 -1。
   - **表现:** MASQUE 的 CONNECT-IP 或 CONNECT-ETHERNET 模式在这些操作系统上无法正常工作。

4. **配置错误导致网络不通:** 如果 TUN/TAP 接口的 IP 地址、对端地址等配置不正确，或者没有配置路由，可能会导致网络连接失败。

**用户操作如何一步步到达这里 (调试线索):**

假设用户在使用配置了 MASQUE 代理的 Chromium 浏览器时遇到网络连接问题：

1. **用户操作:**
   - 用户打开 Chromium 浏览器。
   - 用户在浏览器的网络设置中配置了一个 MASQUE 代理服务器。
   - 用户尝试访问一个网站 (例如 `https://example.com`)。
2. **Chromium 内部处理:**
   - 浏览器检查代理设置，发现需要使用 MASQUE 代理。
   - Chromium 的网络栈开始建立与 MASQUE 代理服务器的 QUIC 连接。
   - 如果 MASQUE 模式是 CONNECT-IP 或 CONNECT-ETHERNET，会尝试调用 `CreateTunInterface` 或 `CreateTapInterface` 来创建虚拟网络接口。
   - 如果创建接口失败 (例如权限问题)，会在日志中记录错误。
   - 如果接口创建成功，后续的网络数据包会通过这个接口发送和接收。
   - 如果认证失败，`ComputeConcealedAuthContext` 相关的逻辑可能会被检查。
3. **调试线索:**
   - **查看 Chromium 的网络日志 (net-internals):**  可以在 `chrome://net-internals/#quic` 中查看 QUIC 连接的详细信息，包括是否使用了 MASQUE，以及相关的错误信息。
   - **查看系统日志:** 如果是 TUN/TAP 接口创建失败，系统的日志 (例如 `dmesg` 或 `/var/log/syslog`) 可能会包含相关的错误信息。
   - **在 `masque_utils.cc` 中设置断点:** 如果怀疑问题出在这个文件中，可以在相关的函数 (例如 `CreateTunInterface`, `CreateTapInterface`, `ComputeConcealedAuthContext`) 设置断点，查看函数执行时的参数和返回值，以确定问题所在。

通过以上分析，我们可以理解 `net/third_party/quiche/src/quiche/quic/masque/masque_utils.cc` 文件在 Chromium 网络栈中扮演的关键角色，以及它与用户操作和潜在错误之间的联系。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/masque/masque_utils.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/masque/masque_utils.h"

#include <cstdint>
#include <cstring>
#include <ostream>
#include <string>
#include <utility>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"

#if defined(__linux__)
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#endif  // defined(__linux__)

#include "absl/cleanup/cleanup.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, tap_bridge_interface, "",
    "Bridge tap interfaces created by CONNECT-ETHERNET mode to be bridged to "
    "the specified interface, if any.");

namespace quic {

ParsedQuicVersionVector MasqueSupportedVersions() {
  ParsedQuicVersionVector versions;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    // Use all versions that support IETF QUIC except QUICv2.
    if (version.UsesHttp3() && !version.AlpnDeferToRFCv1()) {
      QuicEnableVersion(version);
      versions.push_back(version);
    }
  }
  QUICHE_CHECK(!versions.empty());
  return versions;
}

std::string MasqueModeToString(MasqueMode masque_mode) {
  switch (masque_mode) {
    case MasqueMode::kInvalid:
      return "Invalid";
    case MasqueMode::kOpen:
      return "Open";
    case MasqueMode::kConnectIp:
      return "CONNECT-IP";
    case MasqueMode::kConnectEthernet:
      return "CONNECT-ETHERNET";
  }
  return absl::StrCat("Unknown(", static_cast<int>(masque_mode), ")");
}

std::ostream& operator<<(std::ostream& os, const MasqueMode& masque_mode) {
  os << MasqueModeToString(masque_mode);
  return os;
}

#if defined(__linux__)
int CreateTunInterface(const QuicIpAddress& client_address, bool server) {
  if (!client_address.IsIPv4()) {
    QUIC_LOG(ERROR) << "CreateTunInterface currently only supports IPv4";
    return -1;
  }
  // TODO(b/281517862): add test to validate O_NONBLOCK
  int tun_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
  if (tun_fd < 0) {
    QUIC_PLOG(ERROR) << "Failed to open clone device";
    return -1;
  }
  absl::Cleanup tun_fd_closer = [tun_fd] { close(tun_fd); };

  struct ifreq ifr = {};
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  // If we want to pick a specific device name, we can set it via
  // ifr.ifr_name. Otherwise, the kernel will pick the next available tunX
  // name.
  int err = ioctl(tun_fd, TUNSETIFF, &ifr);
  if (err < 0) {
    QUIC_PLOG(ERROR) << "TUNSETIFF failed";
    return -1;
  }
  int ip_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (ip_fd < 0) {
    QUIC_PLOG(ERROR) << "Failed to open IP configuration socket";
    return -1;
  }
  absl::Cleanup ip_fd_closer = [ip_fd] { close(ip_fd); };

  struct sockaddr_in addr = {};
  addr.sin_family = AF_INET;
  // Local address, unused but needs to be set. We use the same address as the
  // client address, but with last byte set to 1.
  addr.sin_addr = client_address.GetIPv4();
  if (server) {
    addr.sin_addr.s_addr &= htonl(0xffffff00);
    addr.sin_addr.s_addr |= htonl(0x00000001);
  }
  memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
  err = ioctl(ip_fd, SIOCSIFADDR, &ifr);
  if (err < 0) {
    QUIC_PLOG(ERROR) << "SIOCSIFADDR failed";
    return -1;
  }
  // Peer address, needs to match source IP address of sent packets.
  addr.sin_addr = client_address.GetIPv4();
  if (!server) {
    addr.sin_addr.s_addr &= htonl(0xffffff00);
    addr.sin_addr.s_addr |= htonl(0x00000001);
  }
  memcpy(&ifr.ifr_addr, &addr, sizeof(addr));
  err = ioctl(ip_fd, SIOCSIFDSTADDR, &ifr);
  if (err < 0) {
    QUIC_PLOG(ERROR) << "SIOCSIFDSTADDR failed";
    return -1;
  }
  if (!server) {
    // Set MTU, to 1280 for now which should always fit (fingers crossed)
    ifr.ifr_mtu = 1280;
    err = ioctl(ip_fd, SIOCSIFMTU, &ifr);
    if (err < 0) {
      QUIC_PLOG(ERROR) << "SIOCSIFMTU failed";
      return -1;
    }
  }

  err = ioctl(ip_fd, SIOCGIFFLAGS, &ifr);
  if (err < 0) {
    QUIC_PLOG(ERROR) << "SIOCGIFFLAGS failed";
    return -1;
  }
  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
  err = ioctl(ip_fd, SIOCSIFFLAGS, &ifr);
  if (err < 0) {
    QUIC_PLOG(ERROR) << "SIOCSIFFLAGS failed";
    return -1;
  }
  close(ip_fd);
  QUIC_DLOG(INFO) << "Successfully created TUN interface " << ifr.ifr_name
                  << " with fd " << tun_fd;
  std::move(tun_fd_closer).Cancel();
  return tun_fd;
}
#else
int CreateTunInterface(const QuicIpAddress& /*client_address*/,
                       bool /*server*/) {
  // Unsupported.
  return -1;
}
#endif  // defined(__linux__)

#if defined(__linux__)
int CreateTapInterface() {
  int tap_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
  if (tap_fd < 0) {
    QUIC_PLOG(ERROR) << "Failed to open clone device";
    return -1;
  }
  absl::Cleanup tap_fd_closer = [tap_fd] { close(tap_fd); };

  struct ifreq ifr = {};
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  // If we want to pick a specific device name, we can set it via
  // ifr.ifr_name. Otherwise, the kernel will pick the next available tapX
  // name.
  int err = ioctl(tap_fd, TUNSETIFF, &ifr);
  if (err < 0) {
    QUIC_PLOG(ERROR) << "TUNSETIFF failed";
    return -1;
  }

  QUIC_DLOG(INFO) << "Successfully created TAP interface " << ifr.ifr_name
                  << " with fd " << tap_fd;

  int sock_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (sock_fd < 0) {
    QUIC_PLOG(ERROR) << "Error opening configuration socket";
    return -1;
  }
  absl::Cleanup sock_fd_closer = [sock_fd] { close(sock_fd); };

  err = ioctl(sock_fd, SIOCGIFINDEX, &ifr);
  if (err < 0) {
    QUIC_PLOG(ERROR) << "SIOCGIFINDEX failed";
  }
  int tap_ifindex = ifr.ifr_ifindex;

  ifr.ifr_mtu = 1280;
  err = ioctl(sock_fd, SIOCSIFMTU, &ifr);
  if (err < 0) {
    QUIC_PLOG(ERROR) << "SIOCSIFMTU failed";
    return -1;
  }

  err = ioctl(sock_fd, SIOCGIFFLAGS, &ifr);
  if (err < 0) {
    QUIC_PLOG(ERROR) << "SIOCGIFFLAGS failed";
    return -1;
  }
  ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
  err = ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
  if (err < 0) {
    QUIC_PLOG(ERROR) << "SIOCSIFFLAGS failed";
    return -1;
  }

  const std::string tap_bridge_interface =
      quiche::GetQuicheCommandLineFlag(FLAGS_tap_bridge_interface);

  if (!tap_bridge_interface.empty()) {
    if (tap_bridge_interface.size() >= IFNAMSIZ) {
      QUIC_LOG(ERROR) << "tap bridge interface size too long: "
                      << tap_bridge_interface.size();
      return -1;
    }
    strncpy(ifr.ifr_name, tap_bridge_interface.c_str(), IFNAMSIZ);
    ifr.ifr_ifindex = tap_ifindex;
    err = ioctl(sock_fd, SIOCBRADDIF, &ifr);
    if (err < 0) {
      QUIC_PLOG(ERROR) << "SIOCBRADDIF failed";
      return -1;
    }
  }

  std::move(tap_fd_closer).Cancel();
  return tap_fd;
}
#else
int CreateTapInterface() {
  // Unsupported.
  return -1;
}
#endif  // defined(__linux__)

std::string ComputeConcealedAuthContext(uint16_t signature_scheme,
                                        absl::string_view key_id,
                                        absl::string_view public_key,
                                        absl::string_view scheme,
                                        absl::string_view host, uint16_t port,
                                        absl::string_view realm) {
  QUIC_DVLOG(2) << "ComputeConcealedAuthContext: key_id=\"" << key_id
                << "\" public_key=" << absl::WebSafeBase64Escape(public_key)
                << " scheme=\"" << scheme << "\" host=\"" << host
                << "\" port=" << port << " realm=\"" << realm << "\"";
  std::string key_exporter_context;
  key_exporter_context.resize(
      sizeof(signature_scheme) + QuicDataWriter::GetVarInt62Len(key_id.size()) +
      key_id.size() + QuicDataWriter::GetVarInt62Len(public_key.size()) +
      public_key.size() + QuicDataWriter::GetVarInt62Len(scheme.size()) +
      scheme.size() + QuicDataWriter::GetVarInt62Len(host.size()) +
      host.size() + sizeof(port) +
      QuicDataWriter::GetVarInt62Len(realm.size()) + realm.size());
  QuicDataWriter writer(key_exporter_context.size(),
                        key_exporter_context.data());
  if (!writer.WriteUInt16(signature_scheme) ||
      !writer.WriteStringPieceVarInt62(key_id) ||
      !writer.WriteStringPieceVarInt62(public_key) ||
      !writer.WriteStringPieceVarInt62(scheme) ||
      !writer.WriteStringPieceVarInt62(host) || !writer.WriteUInt16(port) ||
      !writer.WriteStringPieceVarInt62(realm) || writer.remaining() != 0) {
    QUIC_LOG(FATAL) << "ComputeConcealedAuthContext failed";
  }
  return key_exporter_context;
}

std::string ConcealedAuthDataCoveredBySignature(
    absl::string_view signature_input) {
  return absl::StrCat(std::string(64, 0x20), "HTTP Concealed Authentication",
                      std::string(1, 0x00), signature_input);
}

}  // namespace quic

"""

```