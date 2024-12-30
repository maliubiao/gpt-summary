Response:
Let's break down the thought process for analyzing the given C++ code and generating the response.

**1. Understanding the Core Task:**

The primary goal is to understand the functionality of the `quiche_ip_address.cc` file and explain it in a way that's understandable, even to someone with potential web development (and thus JavaScript) background. The prompt specifically asks for:

* **Functionality Listing:** What does this code *do*?
* **JavaScript Relation:** How does this relate to JavaScript concepts?
* **Logical Reasoning (Examples):**  Illustrate with input/output.
* **Common Errors:**  Point out potential pitfalls.
* **Debugging Context:**  Explain how a user might reach this code.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code, looking for key terms and patterns. This gives a high-level overview. Keywords like `IPAddress`, `IPv4`, `IPv6`, `Loopback`, `Any`, `FromString`, `ToString`, `InSameSubnet`, and the operators `==`, `!=` immediately stand out. The presence of `inet_ntop` and `inet_pton` hints at network address manipulation.

**3. Function-by-Function Analysis:**

Next, systematically go through each function and understand its purpose.

* **Constructors:** How are `QuicheIpAddress` objects created?  The various constructors handle different initialization scenarios (default, from `in_addr`, from `in6_addr`).
* **Static Factory Methods:** `Loopback4`, `Loopback6`, `Any4`, `Any6` provide convenient ways to create specific IP addresses. Recognize these as design patterns.
* **Comparison Operators (`==`, `!=`):**  How are IP addresses compared?  Crucially, note that the address family is checked first.
* **`IsInitialized`:**  A simple check for a valid address.
* **`address_family` and `AddressFamilyToInt`:**  Getting the IP address version.
* **`ToPackedString`:**  Getting the raw byte representation. This is important for lower-level networking.
* **`ToString`:**  Converting to a human-readable string format (dotted decimal or colon-separated hex). The use of `inet_ntop` is key here.
* **`Normalized`:**  Converting IPv6-mapped IPv4 addresses back to pure IPv4. This shows an awareness of address representation complexities.
* **`DualStacked`:**  Converting IPv4 to IPv6-mapped IPv4. Another aspect of address representation.
* **`FromPackedString` and `FromString`:**  Parsing IP addresses from different string formats. The use of `inet_pton` is key here.
* **`IsIPv4` and `IsIPv6`:**  Simple type checks.
* **`InSameSubnet`:**  The most complex function. Understands subnet masking. This involves bitwise operations.
* **`GetIPv4` and `GetIPv6`:**  Accessing the underlying address structures.
* **`QuicheIpPrefix`:**  A related class representing an IP address and its prefix length (for subnet definition).

**4. Identifying Relationships to JavaScript:**

This is where the bridge between C++ and web development needs to be built. Think about how IP addresses are relevant in the JavaScript world:

* **Network Requests:** JavaScript makes network requests, and IP addresses are fundamental to this.
* **Server-Side (Node.js):** Node.js has modules for network programming that deal with IP addresses.
* **WebSockets:**  IP addresses are involved in establishing WebSocket connections.
* **Client-Side (Limited):** While direct IP manipulation is less common in browser JavaScript, understanding IP addresses is still important for concepts like network security and debugging.

**5. Crafting Examples and Reasoning:**

For logical reasoning, choose representative functions and provide concrete inputs and outputs. Think about simple cases and edge cases. `ToString`, `FromString`, and `InSameSubnet` are good candidates.

**6. Pinpointing Common Errors:**

Focus on the error conditions explicitly handled in the code (e.g., invalid subnet length) or potential misuse based on the function's purpose (e.g., trying to use an uninitialized address).

**7. Simulating User Interaction for Debugging:**

Think about how a network-related issue might arise in a browser or application that uses Chromium's networking stack. Trace the steps that could lead to the execution of this IP address handling code. This often involves network configuration, establishing connections, or handling network events.

**8. Structuring the Response:**

Organize the information logically using clear headings and bullet points. This makes the explanation easier to read and understand. Start with a general overview and then delve into specifics.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe overemphasize the direct use of this C++ code in JavaScript. **Correction:** Focus on the *concepts* and how they manifest in JavaScript, especially in server-side environments.
* **Initial thought:**  Provide very technical C++ explanations. **Correction:**  Explain in simpler terms, relating to more familiar web development concepts where possible.
* **Initial thought:**  Miss some of the less obvious functions like `Normalized` and `DualStacked`. **Correction:** Review the code again to ensure all important functionalities are covered.
* **Initial thought:** The debugging section might be too generic. **Correction:** Try to be a bit more specific about the types of scenarios where IP address issues might occur.

By following these steps, combining code analysis with an understanding of broader web development concepts, and refining the explanation along the way, you can arrive at a comprehensive and helpful answer like the example provided in the prompt.
这个C++源代码文件 `quiche_ip_address.cc`  定义了 `QuicheIpAddress` 和 `QuicheIpPrefix` 两个类，用于表示和操作 IP 地址和 IP 前缀。这两个类是 Chromium 中 QUIC 协议实现（Quiche）的一部分，用于处理网络连接中的 IP 地址相关操作。

以下是该文件的主要功能：

**1. IP 地址的表示和创建 (`QuicheIpAddress` 类):**

* **表示 IPv4 和 IPv6 地址:**  `QuicheIpAddress` 类能够存储 IPv4 和 IPv6 两种类型的 IP 地址。它内部使用一个联合体 `address_` 来存储不同类型的地址结构 (`in_addr` for IPv4, `in6_addr` for IPv6)。
* **静态工厂方法:** 提供了方便的静态方法来创建特定的 IP 地址：
    * `Loopback4()`: 返回 IPv4 回环地址 (127.0.0.1)。
    * `Loopback6()`: 返回 IPv6 回环地址 (::1)。
    * `Any4()`: 返回 IPv4 的任意地址 (0.0.0.0)。
    * `Any6()`: 返回 IPv6 的任意地址 (::)。
* **构造函数:**  允许从 `in_addr` (IPv4) 或 `in6_addr` (IPv6) 结构体创建 `QuicheIpAddress` 对象。
* **默认构造函数:** 创建一个未初始化的 `QuicheIpAddress` 对象。

**2. IP 地址的比较和检查:**

* **相等和不等运算符 (`==`, `!=`):**  重载了这些运算符，用于比较两个 `QuicheIpAddress` 对象是否相等，会同时比较 IP 地址的类型和值。
* **`IsInitialized()`:**  检查 IP 地址是否已经被初始化（即地址类型是否为 `IP_UNSPEC`）。
* **`address_family()`:**  返回 IP 地址的类型 (`IP_V4` 或 `IP_V6`)。
* **`IsIPv4()` 和 `IsIPv6()`:**  方便的函数用于判断 IP 地址是否为 IPv4 或 IPv6。
* **`InSameSubnet()`:**  判断当前 IP 地址是否与另一个 IP 地址在同一个子网内，需要提供子网掩码的长度。

**3. IP 地址的字符串表示和解析:**

* **`ToString()`:**  将 `QuicheIpAddress` 对象转换为人类可读的字符串形式（例如 "192.168.1.1" 或 "2001:db8::1"）。内部使用 `inet_ntop` 系统调用完成转换。
* **`FromString()`:**  尝试从字符串解析 IP 地址，支持 IPv4 和 IPv6 格式。内部使用 `inet_pton` 系统调用完成解析。
* **`ToPackedString()`:**  将 IP 地址转换为原始的字节数组表示。
* **`FromPackedString()`:**  从原始的字节数组解析 IP 地址。

**4. IP 地址的规范化和双栈转换:**

* **`Normalized()`:**  如果 IP 地址是 IPv6 映射的 IPv4 地址 (例如 `::ffff:192.168.1.1`)，则将其转换为纯 IPv4 地址。
* **`DualStacked()`:**  如果 IP 地址是 IPv4 地址，则将其转换为 IPv6 映射的 IPv4 地址。

**5. 获取原始地址结构:**

* **`GetIPv4()`:**  返回底层的 `in_addr` 结构体，前提是该 IP 地址是 IPv4。
* **`GetIPv6()`:**  返回底层的 `in6_addr` 结构体，前提是该 IP 地址是 IPv6。

**6. IP 前缀的表示 (`QuicheIpPrefix` 类):**

* **表示 IP 地址和前缀长度:**  `QuicheIpPrefix` 类表示一个 IP 地址及其相关的网络前缀长度（用于表示子网）。
* **构造函数:**  允许从 `QuicheIpAddress` 对象创建 `QuicheIpPrefix`，如果没有指定前缀长度，则默认为整个 IP 地址（/32 for IPv4, /128 for IPv6）。也可以指定前缀长度。
* **`ToString()`:**  将 IP 前缀转换为字符串表示形式，例如 "192.168.1.0/24"。
* **相等和不等运算符 (`==`, `!=`):**  重载了这些运算符，用于比较两个 `QuicheIpPrefix` 对象是否相等。

**与 JavaScript 的关系：**

虽然这个 C++ 文件本身不是 JavaScript 代码，但它处理的网络概念（IP 地址和子网）与 JavaScript 在网络编程中遇到的概念是相同的。

* **Node.js 网络编程:**  在 Node.js 中，当你使用 `net` 或 `dgram` 模块创建 TCP 或 UDP 服务器/客户端时，你需要处理 IP 地址。例如，指定服务器监听的 IP 地址，或者连接到特定 IP 地址的服务器。`QuicheIpAddress` 中处理的 IP 地址解析、格式化和比较等操作，在 Node.js 中也会涉及到。
    ```javascript
    // Node.js 示例：创建一个监听特定 IP 地址的 HTTP 服务器
    const http = require('http');
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Hello, World!\n');
    });

    const ipAddress = '192.168.1.100'; //  对应 QuicheIpAddress 能处理的 IP 地址
    const port = 3000;

    server.listen(port, ipAddress, () => {
      console.log(`Server running at http://${ipAddress}:${port}/`);
    });
    ```
* **浏览器中的网络请求:** 尽管浏览器 JavaScript 通常不直接操作 IP 地址，但当你发起 `fetch` 请求或使用 `XMLHttpRequest` 时，浏览器底层会使用 IP 地址来建立连接。这个 C++ 文件中的代码就是 Chromium 网络栈的一部分，负责处理这些底层的 IP 地址操作。
    ```javascript
    // 浏览器 JavaScript 示例：发起一个 HTTP 请求
    fetch('http://www.example.com')
      .then(response => response.text())
      .then(data => console.log(data));
    ```
    在这个例子中，`www.example.com` 最终会被解析成一个 IP 地址，然后浏览器会使用该 IP 地址建立连接。`QuicheIpAddress` 类就参与了这部分底层的 IP 地址处理。

**逻辑推理示例：**

假设输入一个 IPv4 字符串 "192.168.1.1"，使用 `FromString()` 函数：

* **假设输入:**  `std::string str = "192.168.1.1";`
* **执行逻辑:** `FromString()` 函数会调用 `inet_pton(AF_INET, str.c_str(), address_.bytes)`。`inet_pton` 会将字符串 "192.168.1.1" 解析成 IPv4 地址的二进制表示，并存储到 `address_.bytes` 中。同时，`family_` 会被设置为 `IpAddressFamily::IP_V4`。
* **预期输出:** 一个 `QuicheIpAddress` 对象，其 `family_` 为 `IpAddressFamily::IP_V4`，并且 `address_.bytes` 包含了 192, 168, 1, 1 的二进制表示。如果后续调用 `ToString()`，则会返回 "192.168.1.1"。

假设有两个 `QuicheIpAddress` 对象，一个为 192.168.1.1，另一个为 192.168.1.2，调用 `InSameSubnet()` 函数判断它们是否在 24 位子网内：

* **假设输入:**
    * `QuicheIpAddress addr1; addr1.FromString("192.168.1.1");`
    * `QuicheIpAddress addr2; addr2.FromString("192.168.1.2");`
    * `int subnet_length = 24;`
* **执行逻辑:** `InSameSubnet()` 函数会比较两个 IP 地址的前 `subnet_length / 8 = 3` 个字节。由于 192.168.1 与 192.168.1 相同，且 `subnet_length % 8 == 0`，所以直接返回 `true`.
* **预期输出:** `true` (因为这两个 IP 地址在 192.168.1.0/24 子网内)。

**用户或编程常见的使用错误：**

1. **尝试从格式错误的字符串创建 `QuicheIpAddress`:**
   ```c++
   QuicheIpAddress ip;
   if (ip.FromString("invalid-ip-address")) { // FromString 返回 false
     // ... 错误地使用了未正确解析的 ip 对象
   }
   ```
   **调试线索:** 检查 `FromString()` 的返回值，确保 IP 地址字符串格式正确。

2. **未初始化的 `QuicheIpAddress` 对象的使用:**
   ```c++
   QuicheIpAddress ip; // 默认构造，未初始化
   ip.ToString();      // 可能会导致崩溃或未定义行为，因为 family_ 为 IP_UNSPEC
   ```
   **调试线索:** 在使用 `QuicheIpAddress` 对象之前，确保它已经被正确初始化，例如通过构造函数或 `FromString()`。检查 `IsInitialized()` 的返回值。

3. **`InSameSubnet()` 中使用了超出范围的 `subnet_length`:**
   ```c++
   QuicheIpAddress ip1, ip2;
   ip1.FromString("192.168.1.1");
   ip2.FromString("192.168.1.2");
   ip1.InSameSubnet(ip2, 33); // 对于 IPv4，subnet_length 不能大于 32
   ```
   **调试线索:** 确保 `subnet_length` 的值在有效范围内（0-32 for IPv4, 0-128 for IPv6）。查看日志或断点调试，确认 `QUICHE_BUG` 宏是否被触发。

**用户操作如何一步步到达这里作为调试线索：**

假设用户在使用 Chrome 浏览器浏览网页时遇到网络连接问题，例如连接超时或无法访问特定网站。以下是一些可能导致最终执行到 `quiche_ip_address.cc` 中代码的步骤：

1. **用户在地址栏输入网址或点击链接:** 浏览器开始解析域名。
2. **DNS 解析:** 浏览器（或操作系统）执行 DNS 查询，将域名转换为 IP 地址。
3. **建立连接:**  Chromium 的网络栈（包括 QUIC 和 TCP/IP 实现）尝试与解析出的 IP 地址建立连接。这可能涉及到创建 socket、执行 TLS 握手等操作。
4. **QUIC 协议处理 (如果适用):** 如果网站支持 QUIC 协议，Chromium 可能会尝试使用 QUIC 连接。 `quiche_ip_address.cc` 中的代码会在 QUIC 连接的建立和维护过程中被使用，例如：
   * **存储和比较对端 IP 地址:**  在 QUIC 连接的上下文中，需要记录连接双方的 IP 地址。
   * **处理连接迁移:**  如果客户端的 IP 地址发生变化，QUIC 协议需要处理连接的迁移，这涉及到新的 IP 地址的验证和使用。
   * **子网一致性检查:**  在某些情况下，QUIC 可能需要检查新的连接尝试是否来自同一个子网。
5. **TCP/IP 协议处理 (如果未使用 QUIC):**  如果未使用 QUIC 或 QUIC 连接失败，则会使用 TCP/IP 协议。即使在这种情况下，`quiche_ip_address.cc` 中的代码也可能被更底层的网络代码间接使用，因为 IP 地址的概念是通用的。

**调试线索:**

* **网络错误信息:** 浏览器显示的错误信息（例如 "ERR_CONNECTION_TIMED_OUT", "ERR_NAME_NOT_RESOLVED"）可以提供初步线索。
* **Chrome 的 net-internals 工具 (`chrome://net-internals`):**  这个工具可以记录详细的网络事件，包括 DNS 查询结果、连接建立过程、QUIC 会话信息等。通过查看这些日志，可以了解在哪个阶段出现了问题，是否与 IP 地址解析或连接有关。
* **抓包工具 (例如 Wireshark):**  可以捕获网络数据包，查看实际的网络通信过程，包括 IP 地址和端口信息，帮助诊断网络层的问题。
* **断点调试:**  如果开发环境允许，可以在 `quiche_ip_address.cc` 相关的代码中设置断点，跟踪代码的执行流程，查看 IP 地址的值和状态，从而定位问题。

总结来说，`quiche_ip_address.cc` 文件是 Chromium 网络栈中处理 IP 地址的核心组件，它提供了表示、操作和比较 IP 地址的功能，为 QUIC 和其他网络协议的实现提供了基础。理解其功能对于理解 Chromium 的网络行为和调试网络问题至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/common/quiche_ip_address.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/quiche_ip_address.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

#include "absl/strings/str_cat.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_ip_address_family.h"

namespace quiche {

QuicheIpAddress QuicheIpAddress::Loopback4() {
  QuicheIpAddress result;
  result.family_ = IpAddressFamily::IP_V4;
  result.address_.bytes[0] = 127;
  result.address_.bytes[1] = 0;
  result.address_.bytes[2] = 0;
  result.address_.bytes[3] = 1;
  return result;
}

QuicheIpAddress QuicheIpAddress::Loopback6() {
  QuicheIpAddress result;
  result.family_ = IpAddressFamily::IP_V6;
  uint8_t* bytes = result.address_.bytes;
  memset(bytes, 0, 15);
  bytes[15] = 1;
  return result;
}

QuicheIpAddress QuicheIpAddress::Any4() {
  in_addr address;
  memset(&address, 0, sizeof(address));
  return QuicheIpAddress(address);
}

QuicheIpAddress QuicheIpAddress::Any6() {
  in6_addr address;
  memset(&address, 0, sizeof(address));
  return QuicheIpAddress(address);
}

QuicheIpAddress::QuicheIpAddress() : family_(IpAddressFamily::IP_UNSPEC) {}

QuicheIpAddress::QuicheIpAddress(const in_addr& ipv4_address)
    : family_(IpAddressFamily::IP_V4) {
  address_.v4 = ipv4_address;
}
QuicheIpAddress::QuicheIpAddress(const in6_addr& ipv6_address)
    : family_(IpAddressFamily::IP_V6) {
  address_.v6 = ipv6_address;
}

bool operator==(QuicheIpAddress lhs, QuicheIpAddress rhs) {
  if (lhs.family_ != rhs.family_) {
    return false;
  }
  switch (lhs.family_) {
    case IpAddressFamily::IP_V4:
      return std::equal(lhs.address_.bytes,
                        lhs.address_.bytes + QuicheIpAddress::kIPv4AddressSize,
                        rhs.address_.bytes);
    case IpAddressFamily::IP_V6:
      return std::equal(lhs.address_.bytes,
                        lhs.address_.bytes + QuicheIpAddress::kIPv6AddressSize,
                        rhs.address_.bytes);
    case IpAddressFamily::IP_UNSPEC:
      return true;
  }
  QUICHE_BUG(quiche_bug_10126_2)
      << "Invalid IpAddressFamily " << static_cast<int32_t>(lhs.family_);
  return false;
}

bool operator!=(QuicheIpAddress lhs, QuicheIpAddress rhs) {
  return !(lhs == rhs);
}

bool QuicheIpAddress::IsInitialized() const {
  return family_ != IpAddressFamily::IP_UNSPEC;
}

IpAddressFamily QuicheIpAddress::address_family() const { return family_; }

int QuicheIpAddress::AddressFamilyToInt() const {
  return ToPlatformAddressFamily(family_);
}

std::string QuicheIpAddress::ToPackedString() const {
  switch (family_) {
    case IpAddressFamily::IP_V4:
      return std::string(address_.chars, sizeof(address_.v4));
    case IpAddressFamily::IP_V6:
      return std::string(address_.chars, sizeof(address_.v6));
    case IpAddressFamily::IP_UNSPEC:
      return "";
  }
  QUICHE_BUG(quiche_bug_10126_3)
      << "Invalid IpAddressFamily " << static_cast<int32_t>(family_);
  return "";
}

std::string QuicheIpAddress::ToString() const {
  if (!IsInitialized()) {
    return "";
  }

  char buffer[INET6_ADDRSTRLEN] = {0};
  const char* result =
      inet_ntop(AddressFamilyToInt(), address_.bytes, buffer, sizeof(buffer));
  QUICHE_BUG_IF(quiche_bug_10126_4, result == nullptr)
      << "Failed to convert an IP address to string";
  return buffer;
}

static const uint8_t kMappedAddressPrefix[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
};

QuicheIpAddress QuicheIpAddress::Normalized() const {
  if (!IsIPv6()) {
    return *this;
  }
  if (!std::equal(std::begin(kMappedAddressPrefix),
                  std::end(kMappedAddressPrefix), address_.bytes)) {
    return *this;
  }

  in_addr result;
  memcpy(&result, &address_.bytes[12], sizeof(result));
  return QuicheIpAddress(result);
}

QuicheIpAddress QuicheIpAddress::DualStacked() const {
  if (!IsIPv4()) {
    return *this;
  }

  QuicheIpAddress result;
  result.family_ = IpAddressFamily::IP_V6;
  memcpy(result.address_.bytes, kMappedAddressPrefix,
         sizeof(kMappedAddressPrefix));
  memcpy(result.address_.bytes + 12, address_.bytes, kIPv4AddressSize);
  return result;
}

bool QuicheIpAddress::FromPackedString(const char* data, size_t length) {
  switch (length) {
    case kIPv4AddressSize:
      family_ = IpAddressFamily::IP_V4;
      break;
    case kIPv6AddressSize:
      family_ = IpAddressFamily::IP_V6;
      break;
    default:
      return false;
  }
  memcpy(address_.chars, data, length);
  return true;
}

bool QuicheIpAddress::FromString(std::string str) {
  for (IpAddressFamily family :
       {IpAddressFamily::IP_V6, IpAddressFamily::IP_V4}) {
    int result =
        inet_pton(ToPlatformAddressFamily(family), str.c_str(), address_.bytes);
    if (result > 0) {
      family_ = family;
      return true;
    }
  }
  return false;
}

bool QuicheIpAddress::IsIPv4() const {
  return family_ == IpAddressFamily::IP_V4;
}

bool QuicheIpAddress::IsIPv6() const {
  return family_ == IpAddressFamily::IP_V6;
}

bool QuicheIpAddress::InSameSubnet(const QuicheIpAddress& other,
                                   int subnet_length) {
  if (!IsInitialized()) {
    QUICHE_BUG(quiche_bug_10126_5)
        << "Attempting to do subnet matching on undefined address";
    return false;
  }
  if ((IsIPv4() && subnet_length > 32) || (IsIPv6() && subnet_length > 128)) {
    QUICHE_BUG(quiche_bug_10126_6) << "Subnet mask is out of bounds";
    return false;
  }

  int bytes_to_check = subnet_length / 8;
  int bits_to_check = subnet_length % 8;
  const uint8_t* const lhs = address_.bytes;
  const uint8_t* const rhs = other.address_.bytes;
  if (!std::equal(lhs, lhs + bytes_to_check, rhs)) {
    return false;
  }
  if (bits_to_check == 0) {
    return true;
  }
  QUICHE_DCHECK_LT(static_cast<size_t>(bytes_to_check), sizeof(address_.bytes));
  int mask = (~0u) << (8u - bits_to_check);
  return (lhs[bytes_to_check] & mask) == (rhs[bytes_to_check] & mask);
}

in_addr QuicheIpAddress::GetIPv4() const {
  QUICHE_DCHECK(IsIPv4());
  return address_.v4;
}

in6_addr QuicheIpAddress::GetIPv6() const {
  QUICHE_DCHECK(IsIPv6());
  return address_.v6;
}

QuicheIpPrefix::QuicheIpPrefix() : prefix_length_(0) {}
QuicheIpPrefix::QuicheIpPrefix(const QuicheIpAddress& address)
    : address_(address) {
  if (address_.IsIPv6()) {
    prefix_length_ = QuicheIpAddress::kIPv6AddressSize * 8;
  } else if (address_.IsIPv4()) {
    prefix_length_ = QuicheIpAddress::kIPv4AddressSize * 8;
  } else {
    prefix_length_ = 0;
  }
}
QuicheIpPrefix::QuicheIpPrefix(const QuicheIpAddress& address,
                               uint8_t prefix_length)
    : address_(address), prefix_length_(prefix_length) {
  QUICHE_DCHECK(prefix_length <= QuicheIpPrefix(address).prefix_length())
      << "prefix_length cannot be longer than the size of the IP address";
}

std::string QuicheIpPrefix::ToString() const {
  return absl::StrCat(address_.ToString(), "/", prefix_length_);
}

bool operator==(const QuicheIpPrefix& lhs, const QuicheIpPrefix& rhs) {
  return lhs.address_ == rhs.address_ &&
         lhs.prefix_length_ == rhs.prefix_length_;
}

bool operator!=(const QuicheIpPrefix& lhs, const QuicheIpPrefix& rhs) {
  return !(lhs == rhs);
}

}  // namespace quiche

"""

```