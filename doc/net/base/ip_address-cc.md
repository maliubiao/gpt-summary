Response:
Let's break down the thought process for analyzing this `ip_address.cc` file.

**1. Understanding the Request:**

The request asks for a breakdown of the file's functionality, its relationship to JavaScript, examples of logical reasoning, common user errors, and debugging clues. This implies a need to understand the code's purpose, identify its core features, consider its context in a web browser, and think about potential misuse.

**2. Initial Skim and Identification of Key Entities:**

The first step is a quick skim to identify the major components. I immediately see:

* **Copyright and License:**  Standard boilerplate, indicates it's part of Chromium.
* **Includes:** Headers like `<cstdint>`, `<string_view>`, `"base/..."`, `"net/..."`, `"url/..."` point to core C++ functionality, base utilities, networking concepts, and URL handling. This hints at the file's purpose: dealing with IP addresses in a networking context.
* **Namespaces:** `net` suggests this is a networking-related file.
* **Static Constants:** `kIPv4MappedPrefix` is a clear indicator of IPv6 to IPv4 mapping functionality.
* **Helper Functions:**  `IPAddressPrefixCheck`, `CreateIPMask`, `IsPubliclyRoutableIPv4/6`, `ParseIPLiteralToBytes` are all internal utility functions for IP address manipulation and validation.
* **Classes:** `IPAddressBytes` and `IPAddress` are the core data structures. The presence of separate `Bytes` suggests a possible optimization or separation of concerns (raw bytes vs. higher-level object).
* **Methods:**  Methods like `IsIPv4`, `IsIPv6`, `IsValid`, `ToString`, `FromIPLiteral`, `MatchesPrefix`, `ParseCIDRBlock` clearly define the API for working with IP addresses.

**3. Deeper Dive into Functionality:**

Now, I go through the code section by section, focusing on what each part does.

* **`IPAddressBytes`:**  This class seems to be a wrapper around a raw byte array, providing basic operations like assignment, comparison, and appending. It acts as a low-level representation of the IP address.
* **`IPAddress`:** This is the main class. I notice:
    * **Constructors:** Various ways to create `IPAddress` objects, including from raw bytes, individual byte components, and IP literal strings.
    * **Type Checking:** `IsIPv4`, `IsIPv6`.
    * **Validation:** `IsValid`.
    * **Property Checks:** `IsPubliclyRoutable`, `IsZero`, `IsLoopback`, `IsLinkLocal`, `IsUniqueLocalIPv6`, `IsIPv4MappedIPv6`. These are crucial for network security and routing.
    * **Conversion:** `ToString`, `ToValue`, `IPAddressToStringWithPort`, `IPAddressToPackedString`, `ConvertIPv4ToIPv4MappedIPv6`, `ConvertIPv4MappedIPv6ToIPv4`, `ConvertIPv4ToIPv4EmbeddedIPv6`. This highlights the need to represent and transform IP addresses in different formats.
    * **Parsing:** `FromIPLiteral`, `ParseCIDRBlock`, `ParseURLHostnameToAddress`. Essential for converting string representations to the internal `IPAddress` format.
    * **Comparison and Matching:** `operator==`, `operator!=`, `operator<`, `MatchesPrefix`.
    * **Masking and Prefixing:** `CreateIPv4Mask`, `CreateIPv6Mask`, `CommonPrefixLength`, `MaskPrefixLength`. These are fundamental concepts in networking for subnetting and routing.
    * **DNS64 Related:** `ExtractPref64FromIpv4onlyArpaAAAA`. This indicates support for DNS64, a technology for IPv6-only networks to access IPv4 resources.

**4. Connecting to JavaScript:**

I consider where IP addresses are relevant in the browser's interaction with JavaScript:

* **Network Requests:**  `fetch()`, `XMLHttpRequest` use URLs, which contain hostnames that need to be resolved to IP addresses.
* **WebSockets:** Establishing WebSocket connections requires resolving the server's address.
* **WebRTC:**  Peer-to-peer connections in WebRTC heavily rely on IP addresses for establishing communication.
* **Network Information API:** JavaScript can access network information, including the device's IP address.
* **Content Security Policy (CSP):**  CSP directives can restrict connections to specific IP addresses or ranges.

This leads to concrete examples of how this C++ code interacts with JavaScript functionality.

**5. Logical Reasoning and Examples:**

For logical reasoning, I select a function like `IPAddressMatchesPrefix` and think about different input scenarios, especially edge cases:

* **Matching Prefixes:**  Basic case, prefixes match.
* **Non-Matching Prefixes:** Prefixes don't match.
* **IPv4 vs. IPv6:** How the function handles address family differences (through IPv4-mapped IPv6 conversion).
* **Prefix Lengths:**  Varying prefix lengths and how they affect the match.

**6. Common User/Programming Errors:**

I consider how developers might misuse the `IPAddress` API:

* **Invalid IP Literals:** Passing malformed strings to `FromIPLiteral`.
* **Incorrect Prefix Lengths:** Providing out-of-range prefix lengths to `CreateIPv4Mask`/`CreateIPv6Mask` or `ParseCIDRBlock`.
* **Mixing IPv4 and IPv6 without Conversion:** Expecting direct comparison or matching without considering the need for IPv4-mapped IPv6.

**7. Debugging Clues and User Actions:**

I trace back how a user action might lead to this code being executed:

* **Typing a URL:**  The browser needs to resolve the hostname to an IP address, which might involve parsing the hostname using `ParseURLHostnameToAddress`.
* **JavaScript `fetch()`:**  Similar to typing a URL, the browser needs to resolve the target of the `fetch()` request.
* **WebRTC Connection:**  The ICE negotiation process involves exchanging IP addresses.
* **Network Configuration Changes:**  The browser might need to update its understanding of the local network's IP addresses.

This helps connect the low-level C++ code to observable user behavior.

**8. Refinement and Organization:**

Finally, I organize the information logically, using clear headings and bullet points, providing code snippets where relevant, and ensuring the language is easy to understand. I review for clarity and accuracy. For instance, I ensure the JavaScript examples are realistic and the debugging steps follow a logical flow. I might also reorder sections to improve readability, starting with the core functionality and then moving to more specific aspects like JavaScript interaction and debugging.
这个文件 `net/base/ip_address.cc` 是 Chromium 网络栈中用于处理和表示 IP 地址的核心组件。它提供了创建、解析、比较和操作 IPv4 和 IPv6 地址的功能。

**主要功能列举:**

1. **IP 地址表示:**
   - 定义了 `IPAddressBytes` 类，用于存储 IP 地址的原始字节数据。
   - 定义了 `IPAddress` 类，作为 IP 地址的高级抽象，封装了 `IPAddressBytes` 并提供了各种操作方法。

2. **IP 地址创建和解析:**
   - 提供了多种构造函数来创建 `IPAddress` 对象，例如从原始字节数组、单个字节、以及 IPv4 或 IPv6 字面量字符串。
   - `FromIPLiteral()` 静态方法用于从 IP 字面量字符串（例如 "192.168.1.1" 或 "2001:db8::1"）解析创建 `IPAddress` 对象。
   - `ParseCIDRBlock()` 函数用于解析 CIDR (Classless Inter-Domain Routing) 表示的 IP 地址和前缀长度。
   - `ParseURLHostnameToAddress()` 函数用于解析 URL 中的主机名并尝试将其转换为 IP 地址。

3. **IP 地址类型判断:**
   - `IsIPv4()` 和 `IsIPv6()` 方法用于判断 IP 地址是 IPv4 还是 IPv6。
   - `IsValid()` 方法用于判断 IP 地址是否有效 (是 IPv4 或 IPv6)。
   - `IsPubliclyRoutable()` 方法判断 IP 地址是否是公网可路由的地址。
   - `IsZero()` 方法判断 IP 地址是否为全零地址。
   - `IsIPv4MappedIPv6()` 方法判断 IPv6 地址是否是 IPv4 映射地址。
   - `IsLoopback()` 方法判断 IP 地址是否是环回地址 (localhost)。
   - `IsLinkLocal()` 方法判断 IP 地址是否是链路本地地址。
   - `IsUniqueLocalIPv6()` 方法判断 IPv6 地址是否是唯一本地地址。

4. **IP 地址比较:**
   - 重载了比较运算符 (`==`, `!=`, `<`)，允许对 `IPAddress` 对象进行比较。
   - `IPAddressMatchesPrefix()` 函数用于检查一个 IP 地址是否匹配给定的 IP 前缀和长度。

5. **IP 地址转换和格式化:**
   - `ToString()` 方法将 `IPAddress` 对象转换为其字符串表示形式。
   - `ToValue()` 方法将 `IPAddress` 对象转换为 `base::Value` 对象，通常用于 JSON 序列化。
   - `IPAddressToStringWithPort()` 函数将 IP 地址和端口号格式化为字符串。
   - `IPAddressToPackedString()` 函数将 IP 地址转换为紧凑的二进制字符串表示。
   - `ConvertIPv4ToIPv4MappedIPv6()` 和 `ConvertIPv4MappedIPv6ToIPv4()` 函数用于在 IPv4 和 IPv4 映射的 IPv6 地址之间进行转换。
   - `ConvertIPv4ToIPv4EmbeddedIPv6()` 函数用于将 IPv4 地址嵌入到 IPv6 地址中，用于 DNS64 等场景。

6. **IP 地址掩码操作:**
   - `CreateIPv4Mask()` 和 `CreateIPv6Mask()` 静态方法用于创建指定前缀长度的 IPv4 和 IPv6 网络掩码。
   - `MaskPrefixLength()` 函数计算 IP 地址掩码的前缀长度。
   - `CommonPrefixLength()` 函数计算两个 IP 地址的公共前缀长度。

7. **DNS64 支持:**
   - `ExtractPref64FromIpv4onlyArpaAAAA()` 函数用于从 IPv4-only.arpa 的 AAAA 记录中提取 DNS64 前缀长度。

**与 JavaScript 的功能关系及举例:**

Chromium 的网络栈是浏览器处理网络请求的基础，而 JavaScript 通过 Web API 与网络进行交互。`net/base/ip_address.cc` 中的功能与 JavaScript 的关系体现在以下几个方面：

1. **网络请求 (fetch, XMLHttpRequest):**
   - 当 JavaScript 发起网络请求时，浏览器需要解析目标 URL 中的主机名。`ParseURLHostnameToAddress()` 函数可能被调用来将主机名转换为 `IPAddress` 对象。
   - 例如，当 JavaScript 执行 `fetch('https://www.example.com')` 时，Chromium 会尝试将 "www.example.com" 解析为 IP 地址。

2. **WebSockets:**
   - 建立 WebSocket 连接时，浏览器也需要将服务器地址解析为 IP 地址。
   - 例如，当 JavaScript 创建 `new WebSocket('wss://example.com/socket')` 时，会用到 IP 地址解析。

3. **WebRTC (Peer-to-peer 连接):**
   - WebRTC 连接需要在对等端之间交换网络地址信息，包括 IP 地址。
   - JavaScript 通过 WebRTC API 获取和交换 ICE candidates，这些 candidates 包含 IP 地址信息。底层实现会使用 `IPAddress` 类来表示和处理这些地址。

4. **网络信息 API:**
   - JavaScript 可以通过 `navigator.connection` 或 `navigator.mozConnection` (Firefox) 获取一些网络信息，虽然通常不会直接暴露原始的 `IPAddress` 对象，但这些 API 背后的实现可能依赖于这些底层的 IP 地址处理逻辑。

5. **Content Security Policy (CSP):**
   - CSP 可以限制浏览器加载资源的来源，包括根据 IP 地址进行限制。Chromium 在执行 CSP 策略时，可能会用到 `IPAddress` 类来比较和匹配 IP 地址。

**JavaScript 举例说明:**

```javascript
// 当 JavaScript 发起一个 fetch 请求
fetch('http://192.168.1.100')
  .then(response => response.text())
  .then(data => console.log(data));

// 当 JavaScript 创建一个 WebSocket 连接
const socket = new WebSocket('ws://[2001:db8::1]:8080');

// 在 WebRTC 中，获取本地 ICE candidate (简化示例)
navigator.mediaDevices.getUserMedia({ audio: true, video: true })
  .then(stream => {
    const peerConnection = new RTCPeerConnection();
    peerConnection.onicecandidate = event => {
      if (event.candidate) {
        console.log('本地 ICE candidate:', event.candidate.candidate);
        // event.candidate.candidate 字符串中包含 IP 地址信息
      }
    };
    // ...
  });
```

在这些 JavaScript 代码的背后，Chromium 的网络栈会使用 `net/base/ip_address.cc` 中的代码来解析和处理相关的 IP 地址。

**逻辑推理的假设输入与输出:**

假设有以下函数调用：

```c++
IPAddress address;
bool success = address.AssignFromIPLiteral("192.168.1.1");
```

**假设输入:** 字符串 "192.168.1.1"

**逻辑推理:** `AssignFromIPLiteral` 函数会调用 `ParseIPLiteralToBytes`，该函数会识别字符串中不包含冒号，因此将其视为 IPv4 地址。它会使用 `url::IPv4AddressToNumber` 将字符串解析为 4 个字节的 IP 地址，并将其存储在 `address` 对象的内部 `ip_address_` 成员中。

**预期输出:**
- `success` 为 `true`。
- `address.IsIPv4()` 返回 `true`。
- `address.ToString()` 返回 "192.168.1.1"。
- `address.bytes()` 将包含 `[192, 168, 1, 1]` 这四个字节。

再例如：

```c++
IPAddress address1 = IPAddress(192, 168, 1, 1);
IPAddress address2;
bool matches = IPAddressMatchesPrefix(address1, IPAddress(192, 168, 1, 0), 24);
```

**假设输入:**
- `address1`: IPv4 地址 192.168.1.1
- `prefix`: IPv4 前缀 192.168.1.0
- `prefix_length_in_bits`: 24

**逻辑推理:** `IPAddressMatchesPrefix` 函数会比较 `address1` 的前 24 位与 `prefix` 的前 24 位是否相同。由于前 24 位都是 192.168.1，因此它们匹配。

**预期输出:** `matches` 为 `true`。

**用户或编程常见的使用错误及举例:**

1. **传入无效的 IP 字面量:**
   - 错误示例: `IPAddress::FromIPLiteral("192.168.1")`  // 缺少一个段
   - 错误示例: `IPAddress::FromIPLiteral("256.168.1.1")` // 第一段超出范围
   - 错误示例: `IPAddress::FromIPLiteral("invalid-ip")` // 非数字字符

2. **CIDR 表示中的前缀长度超出范围:**
   - 错误示例: `ParseCIDRBlock("192.168.1.1/33", &address, &prefix_length)` // IPv4 的前缀长度不能超过 32
   - 错误示例: `ParseCIDRBlock("2001:db8::1/129", &address, &prefix_length)` // IPv6 的前缀长度不能超过 128

3. **在需要特定 IP 版本的地方使用了错误的 IP 版本:**
   - 错误示例: 尝试将一个 IPv6 地址传递给一个只接受 IPv4 地址的函数 (虽然 `IPAddress` 类可以表示两种类型，但某些特定逻辑可能只针对一种)。

4. **忘记处理 `FromIPLiteral` 返回的 `std::optional`:**
   - 错误示例: `IPAddress address = IPAddress::FromIPLiteral(userInput).value();` // 如果 `userInput` 无效，会导致程序崩溃。应该先检查 `optional` 是否包含值。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在浏览器中访问 `http://example.invalid-tld`，这是一个故意设置为无法解析的域名。

1. **用户在地址栏输入 URL:** 用户在浏览器的地址栏中输入 "http://example.invalid-tld" 并按下回车。
2. **浏览器解析 URL:** 浏览器开始解析输入的 URL，提取协议 (http) 和主机名 (example.invalid-tld)。
3. **DNS 查询:** 浏览器尝试解析主机名 "example.invalid-tld" 的 IP 地址。由于这是一个无效的顶级域名，DNS 查询会失败。
4. **网络栈处理 DNS 失败:**  Chromium 的网络栈接收到 DNS 查询失败的通知。
5. **错误处理或提示:** 浏览器会显示一个错误页面，提示用户无法访问该网站。

在这个过程中，虽然 IP 地址解析最终失败了，但网络栈内部仍然会涉及到与 IP 地址相关的操作。例如，在尝试连接之前，系统会尝试将主机名解析为 IP 地址，这时就可能涉及到 `ParseURLHostnameToAddress()` 函数的调用。即使解析失败，也可能涉及到创建表示 "无效" 或 "未解析" 状态的 `IPAddress` 对象。

另一个例子：用户访问一个已知 IP 地址的网站，例如 `http://192.168.1.100`。

1. **用户输入 IP 地址 URL:** 用户在地址栏输入 "http://192.168.1.100"。
2. **浏览器解析 URL:** 浏览器解析 URL，识别出主机名部分是一个 IP 字面量 "192.168.1.100"。
3. **IP 地址解析 (快速路径):**  由于主机名已经是 IP 字面量，浏览器可以直接使用 `IPAddress::FromIPLiteral()` 或类似的函数将其解析为 `IPAddress` 对象，而无需进行 DNS 查询。
4. **建立 TCP 连接:** 浏览器使用解析得到的 `IPAddress` (192.168.1.100) 尝试与目标服务器建立 TCP 连接。
5. **发送 HTTP 请求:** 连接建立成功后，浏览器发送 HTTP 请求。
6. **接收 HTTP 响应:** 服务器返回 HTTP 响应，浏览器处理并渲染页面。

在这种情况下，`net/base/ip_address.cc` 中的代码在解析 URL 中的 IP 地址部分起到了关键作用。如果解析失败（例如，IP 地址格式错误），浏览器将无法建立连接。

作为调试线索，如果开发者怀疑 IP 地址处理有问题，他们可能会：

- **查看网络日志:** Chromium 提供了网络日志功能 (可以通过 `chrome://net-export/` 或命令行参数启用)，可以查看 DNS 查询结果、连接状态以及涉及的 IP 地址信息。
- **使用网络抓包工具:** 工具如 Wireshark 可以捕获网络数据包，查看实际的网络通信中使用的 IP 地址。
- **断点调试:** 在 `net/base/ip_address.cc` 相关的函数中设置断点，例如 `AssignFromIPLiteral` 或 `ParseURLHostnameToAddress`，来观察 IP 地址是如何被解析和处理的。
- **检查错误返回值:** 检查调用 `IPAddress` 相关函数后的返回值，例如 `FromIPLiteral` 返回的 `std::optional` 是否为空，`ParseCIDRBlock` 是否返回 `false` 等。

通过以上分析，可以了解到 `net/base/ip_address.cc` 文件在 Chromium 网络栈中扮演着至关重要的角色，它提供了处理 IP 地址的基础设施，并直接影响着浏览器与网络世界的交互。

Prompt: 
```
这是目录为net/base/ip_address.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/base/ip_address.h"

#include <stddef.h>

#include <algorithm>
#include <array>
#include <climits>
#include <optional>
#include <string_view>

#include "base/check_op.h"
#include "base/debug/alias.h"
#include "base/debug/crash_logging.h"
#include "base/logging.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "base/strings/strcat.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "base/trace_event/memory_usage_estimator.h"
#include "base/values.h"
#include "net/base/parse_number.h"
#include "url/gurl.h"
#include "url/url_canon_ip.h"

namespace net {
namespace {

// The prefix for IPv6 mapped IPv4 addresses.
// https://tools.ietf.org/html/rfc4291#section-2.5.5.2
constexpr uint8_t kIPv4MappedPrefix[] = {0, 0, 0, 0, 0,    0,
                                         0, 0, 0, 0, 0xFF, 0xFF};

// Note that this function assumes:
// * |ip_address| is at least |prefix_length_in_bits| (bits) long;
// * |ip_prefix| is at least |prefix_length_in_bits| (bits) long.
bool IPAddressPrefixCheck(const IPAddressBytes& ip_address,
                          const uint8_t* ip_prefix,
                          size_t prefix_length_in_bits) {
  // Compare all the bytes that fall entirely within the prefix.
  size_t num_entire_bytes_in_prefix = prefix_length_in_bits / 8;
  for (size_t i = 0; i < num_entire_bytes_in_prefix; ++i) {
    if (ip_address[i] != ip_prefix[i])
      return false;
  }

  // In case the prefix was not a multiple of 8, there will be 1 byte
  // which is only partially masked.
  size_t remaining_bits = prefix_length_in_bits % 8;
  if (remaining_bits != 0) {
    uint8_t mask = 0xFF << (8 - remaining_bits);
    size_t i = num_entire_bytes_in_prefix;
    if ((ip_address[i] & mask) != (ip_prefix[i] & mask))
      return false;
  }
  return true;
}

bool CreateIPMask(IPAddressBytes* ip_address,
                  size_t prefix_length_in_bits,
                  size_t ip_address_length) {
  if (ip_address_length != IPAddress::kIPv4AddressSize &&
      ip_address_length != IPAddress::kIPv6AddressSize) {
    return false;
  }
  if (prefix_length_in_bits > ip_address_length * 8) {
    return false;
  }

  ip_address->Resize(ip_address_length);
  size_t idx = 0;
  // Set all fully masked bytes
  size_t num_entire_bytes_in_prefix = prefix_length_in_bits / 8;
  for (size_t i = 0; i < num_entire_bytes_in_prefix; ++i) {
    (*ip_address)[idx++] = 0xff;
  }

  // In case the prefix was not a multiple of 8, there will be 1 byte
  // which is only partially masked.
  size_t remaining_bits = prefix_length_in_bits % 8;
  if (remaining_bits != 0) {
    uint8_t remaining_bits_mask = 0xFF << (8 - remaining_bits);
    (*ip_address)[idx++] = remaining_bits_mask;
  }

  // Zero out any other bytes.
  size_t bytes_remaining = ip_address_length - num_entire_bytes_in_prefix -
                           (remaining_bits != 0 ? 1 : 0);
  for (size_t i = 0; i < bytes_remaining; ++i) {
    (*ip_address)[idx++] = 0;
  }

  return true;
}

// Returns false if |ip_address| matches any of the reserved IPv4 ranges. This
// method operates on a list of reserved IPv4 ranges. Some ranges are
// consolidated.
// Sources for info:
// www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
// www.iana.org/assignments/iana-ipv4-special-registry/
// iana-ipv4-special-registry.xhtml
bool IsPubliclyRoutableIPv4(const IPAddressBytes& ip_address) {
  // Different IP versions have different range reservations.
  DCHECK_EQ(IPAddress::kIPv4AddressSize, ip_address.size());
  struct {
    const uint8_t address[4];
    size_t prefix_length_in_bits;
  } static const kReservedIPv4Ranges[] = {
      {{0, 0, 0, 0}, 8},      {{10, 0, 0, 0}, 8},     {{100, 64, 0, 0}, 10},
      {{127, 0, 0, 0}, 8},    {{169, 254, 0, 0}, 16}, {{172, 16, 0, 0}, 12},
      {{192, 0, 0, 0}, 24},   {{192, 0, 2, 0}, 24},   {{192, 88, 99, 0}, 24},
      {{192, 168, 0, 0}, 16}, {{198, 18, 0, 0}, 15},  {{198, 51, 100, 0}, 24},
      {{203, 0, 113, 0}, 24}, {{224, 0, 0, 0}, 3}};

  for (const auto& range : kReservedIPv4Ranges) {
    if (IPAddressPrefixCheck(ip_address, range.address,
                             range.prefix_length_in_bits)) {
      return false;
    }
  }

  return true;
}

// Returns false if |ip_address| matches any of the IPv6 ranges IANA reserved
// for local networks. This method operates on an allowlist of non-reserved
// IPv6 ranges, plus the list of reserved IPv4 ranges mapped to IPv6.
// Sources for info:
// www.iana.org/assignments/ipv6-address-space/ipv6-address-space.xhtml
bool IsPubliclyRoutableIPv6(const IPAddressBytes& ip_address) {
  DCHECK_EQ(IPAddress::kIPv6AddressSize, ip_address.size());
  struct {
    const uint8_t address_prefix[2];
    size_t prefix_length_in_bits;
  } static const kPublicIPv6Ranges[] = {// 2000::/3  -- Global Unicast
                                        {{0x20, 0}, 3},
                                        // ff00::/8  -- Multicast
                                        {{0xff, 0}, 8}};

  for (const auto& range : kPublicIPv6Ranges) {
    if (IPAddressPrefixCheck(ip_address, range.address_prefix,
                             range.prefix_length_in_bits)) {
      return true;
    }
  }

  IPAddress addr(ip_address);
  if (addr.IsIPv4MappedIPv6()) {
    IPAddress ipv4 = ConvertIPv4MappedIPv6ToIPv4(addr);
    return IsPubliclyRoutableIPv4(ipv4.bytes());
  }

  return false;
}

bool ParseIPLiteralToBytes(std::string_view ip_literal, IPAddressBytes* bytes) {
  // |ip_literal| could be either an IPv4 or an IPv6 literal. If it contains
  // a colon however, it must be an IPv6 address.
  if (ip_literal.find(':') != std::string_view::npos) {
    // GURL expects IPv6 hostnames to be surrounded with brackets.
    std::string host_brackets = base::StrCat({"[", ip_literal, "]"});
    url::Component host_comp(0, host_brackets.size());

    // Try parsing the hostname as an IPv6 literal.
    bytes->Resize(16);  // 128 bits.
    return url::IPv6AddressToNumber(host_brackets.data(), host_comp,
                                    bytes->data());
  }

  // Otherwise the string is an IPv4 address.
  bytes->Resize(4);  // 32 bits.
  url::Component host_comp(0, ip_literal.size());
  int num_components;
  url::CanonHostInfo::Family family = url::IPv4AddressToNumber(
      ip_literal.data(), host_comp, bytes->data(), &num_components);
  return family == url::CanonHostInfo::IPV4;
}

}  // namespace

IPAddressBytes::IPAddressBytes() : size_(0) {}

IPAddressBytes::IPAddressBytes(base::span<const uint8_t> data) {
  Assign(data);
}

IPAddressBytes::~IPAddressBytes() = default;
IPAddressBytes::IPAddressBytes(IPAddressBytes const& other) = default;

void IPAddressBytes::Assign(base::span<const uint8_t> data) {
  CHECK_GE(16u, data.size());
  size_ = data.size();
  base::span(*this).copy_from(data);
}

bool IPAddressBytes::operator<(const IPAddressBytes& other) const {
  if (size_ == other.size_)
    return std::lexicographical_compare(begin(), end(), other.begin(),
                                        other.end());
  return size_ < other.size_;
}

bool IPAddressBytes::operator==(const IPAddressBytes& other) const {
  return base::ranges::equal(*this, other);
}

bool IPAddressBytes::operator!=(const IPAddressBytes& other) const {
  return !(*this == other);
}

void IPAddressBytes::Append(base::span<const uint8_t> data) {
  CHECK_LE(data.size(), static_cast<size_t>(16 - size_));
  size_ += data.size();
  base::span(*this).last(data.size()).copy_from(data);
}

size_t IPAddressBytes::EstimateMemoryUsage() const {
  return base::trace_event::EstimateMemoryUsage(bytes_);
}

// static
std::optional<IPAddress> IPAddress::FromValue(const base::Value& value) {
  if (!value.is_string()) {
    return std::nullopt;
  }

  return IPAddress::FromIPLiteral(value.GetString());
}

// static
std::optional<IPAddress> IPAddress::FromIPLiteral(std::string_view ip_literal) {
  IPAddress address;
  if (!address.AssignFromIPLiteral(ip_literal)) {
    return std::nullopt;
  }
  DCHECK(address.IsValid());
  return address;
}

IPAddress::IPAddress() = default;

IPAddress::IPAddress(const IPAddress& other) = default;

IPAddress::IPAddress(const IPAddressBytes& address) : ip_address_(address) {}

IPAddress::IPAddress(base::span<const uint8_t> address)
    : ip_address_(address) {}

IPAddress::IPAddress(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3) {
  const uint8_t bytes[] = {b0, b1, b2, b3};
  ip_address_.Assign(bytes);
}

IPAddress::IPAddress(uint8_t b0,
                     uint8_t b1,
                     uint8_t b2,
                     uint8_t b3,
                     uint8_t b4,
                     uint8_t b5,
                     uint8_t b6,
                     uint8_t b7,
                     uint8_t b8,
                     uint8_t b9,
                     uint8_t b10,
                     uint8_t b11,
                     uint8_t b12,
                     uint8_t b13,
                     uint8_t b14,
                     uint8_t b15) {
  const uint8_t bytes[] = {b0, b1, b2,  b3,  b4,  b5,  b6,  b7,
                           b8, b9, b10, b11, b12, b13, b14, b15};
  ip_address_.Assign(bytes);
}

IPAddress::~IPAddress() = default;

bool IPAddress::IsIPv4() const {
  return ip_address_.size() == kIPv4AddressSize;
}

bool IPAddress::IsIPv6() const {
  return ip_address_.size() == kIPv6AddressSize;
}

bool IPAddress::IsValid() const {
  return IsIPv4() || IsIPv6();
}

bool IPAddress::IsPubliclyRoutable() const {
  if (IsIPv4()) {
    return IsPubliclyRoutableIPv4(ip_address_);
  } else if (IsIPv6()) {
    return IsPubliclyRoutableIPv6(ip_address_);
  }
  return true;
}

bool IPAddress::IsZero() const {
  for (auto x : ip_address_) {
    if (x != 0)
      return false;
  }

  return !empty();
}

bool IPAddress::IsIPv4MappedIPv6() const {
  return IsIPv6() && IPAddressStartsWith(*this, kIPv4MappedPrefix);
}

bool IPAddress::IsLoopback() const {
  // 127.0.0.1/8
  if (IsIPv4())
    return ip_address_[0] == 127;

  // ::1
  if (IsIPv6()) {
    for (size_t i = 0; i + 1 < ip_address_.size(); ++i) {
      if (ip_address_[i] != 0)
        return false;
    }
    return ip_address_.back() == 1;
  }

  return false;
}

bool IPAddress::IsLinkLocal() const {
  // 169.254.0.0/16
  if (IsIPv4())
    return (ip_address_[0] == 169) && (ip_address_[1] == 254);

  // [::ffff:169.254.0.0]/112
  if (IsIPv4MappedIPv6())
    return (ip_address_[12] == 169) && (ip_address_[13] == 254);

  // [fe80::]/10
  if (IsIPv6())
    return (ip_address_[0] == 0xFE) && ((ip_address_[1] & 0xC0) == 0x80);

  return false;
}

bool IPAddress::IsUniqueLocalIPv6() const {
  // [fc00::]/7
  return IsIPv6() && ((ip_address_[0] & 0xFE) == 0xFC);
}

bool IPAddress::AssignFromIPLiteral(std::string_view ip_literal) {
  bool success = ParseIPLiteralToBytes(ip_literal, &ip_address_);
  if (!success)
    ip_address_.Resize(0);
  return success;
}

std::vector<uint8_t> IPAddress::CopyBytesToVector() const {
  return std::vector<uint8_t>(ip_address_.begin(), ip_address_.end());
}

// static
IPAddress IPAddress::IPv4Localhost() {
  static const uint8_t kLocalhostIPv4[] = {127, 0, 0, 1};
  return IPAddress(kLocalhostIPv4);
}

// static
IPAddress IPAddress::IPv6Localhost() {
  static const uint8_t kLocalhostIPv6[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                           0, 0, 0, 0, 0, 0, 0, 1};
  return IPAddress(kLocalhostIPv6);
}

// static
IPAddress IPAddress::AllZeros(size_t num_zero_bytes) {
  CHECK_LE(num_zero_bytes, 16u);
  IPAddress result;
  for (size_t i = 0; i < num_zero_bytes; ++i)
    result.ip_address_.push_back(0u);
  return result;
}

// static
IPAddress IPAddress::IPv4AllZeros() {
  return AllZeros(kIPv4AddressSize);
}

// static
IPAddress IPAddress::IPv6AllZeros() {
  return AllZeros(kIPv6AddressSize);
}

// static
bool IPAddress::CreateIPv4Mask(IPAddress* ip_address,
                               size_t mask_prefix_length) {
  return CreateIPMask(&(ip_address->ip_address_), mask_prefix_length,
                      kIPv4AddressSize);
}

// static
bool IPAddress::CreateIPv6Mask(IPAddress* ip_address,
                               size_t mask_prefix_length) {
  return CreateIPMask(&(ip_address->ip_address_), mask_prefix_length,
                      kIPv6AddressSize);
}

bool IPAddress::operator==(const IPAddress& that) const {
  return ip_address_ == that.ip_address_;
}

bool IPAddress::operator!=(const IPAddress& that) const {
  return ip_address_ != that.ip_address_;
}

bool IPAddress::operator<(const IPAddress& that) const {
  // Sort IPv4 before IPv6.
  if (ip_address_.size() != that.ip_address_.size()) {
    return ip_address_.size() < that.ip_address_.size();
  }

  return ip_address_ < that.ip_address_;
}

std::string IPAddress::ToString() const {
  std::string str;
  url::StdStringCanonOutput output(&str);

  if (IsIPv4()) {
    url::AppendIPv4Address(ip_address_.data(), &output);
  } else if (IsIPv6()) {
    url::AppendIPv6Address(ip_address_.data(), &output);
  }

  output.Complete();
  return str;
}

base::Value IPAddress::ToValue() const {
  DCHECK(IsValid());
  return base::Value(ToString());
}

size_t IPAddress::EstimateMemoryUsage() const {
  return base::trace_event::EstimateMemoryUsage(ip_address_);
}

std::string IPAddressToStringWithPort(const IPAddress& address, uint16_t port) {
  std::string address_str = address.ToString();
  if (address_str.empty())
    return address_str;

  if (address.IsIPv6()) {
    // Need to bracket IPv6 addresses since they contain colons.
    return base::StringPrintf("[%s]:%d", address_str.c_str(), port);
  }
  return base::StringPrintf("%s:%d", address_str.c_str(), port);
}

std::string IPAddressToPackedString(const IPAddress& address) {
  return std::string(reinterpret_cast<const char*>(address.bytes().data()),
                     address.size());
}

IPAddress ConvertIPv4ToIPv4MappedIPv6(const IPAddress& address) {
  CHECK(address.IsIPv4());
  // IPv4-mapped addresses are formed by:
  // <80 bits of zeros>  + <16 bits of ones> + <32-bit IPv4 address>.
  IPAddressBytes bytes;
  bytes.Append(kIPv4MappedPrefix);
  bytes.Append(address.bytes());
  return IPAddress(bytes);
}

IPAddress ConvertIPv4MappedIPv6ToIPv4(const IPAddress& address) {
  DCHECK(address.IsIPv4MappedIPv6());

  IPAddressBytes bytes;
  bytes.Append(
      base::span(address.bytes()).subspan(std::size(kIPv4MappedPrefix)));
  return IPAddress(bytes);
}

bool IPAddressMatchesPrefix(const IPAddress& ip_address,
                            const IPAddress& ip_prefix,
                            size_t prefix_length_in_bits) {
  // Both the input IP address and the prefix IP address should be either IPv4
  // or IPv6.
  CHECK(ip_address.IsValid());
  CHECK(ip_prefix.IsValid());

  CHECK_LE(prefix_length_in_bits, ip_prefix.size() * 8);

  // In case we have an IPv6 / IPv4 mismatch, convert the IPv4 addresses to
  // IPv6 addresses in order to do the comparison.
  if (ip_address.size() != ip_prefix.size()) {
    if (ip_address.IsIPv4()) {
      return IPAddressMatchesPrefix(ConvertIPv4ToIPv4MappedIPv6(ip_address),
                                    ip_prefix, prefix_length_in_bits);
    }
    return IPAddressMatchesPrefix(ip_address,
                                  ConvertIPv4ToIPv4MappedIPv6(ip_prefix),
                                  96 + prefix_length_in_bits);
  }

  return IPAddressPrefixCheck(ip_address.bytes(), ip_prefix.bytes().data(),
                              prefix_length_in_bits);
}

bool ParseCIDRBlock(std::string_view cidr_literal,
                    IPAddress* ip_address,
                    size_t* prefix_length_in_bits) {
  // We expect CIDR notation to match one of these two templates:
  //   <IPv4-literal> "/" <number of bits>
  //   <IPv6-literal> "/" <number of bits>

  std::vector<std::string_view> parts = base::SplitStringPiece(
      cidr_literal, "/", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (parts.size() != 2)
    return false;

  // Parse the IP address.
  if (!ip_address->AssignFromIPLiteral(parts[0]))
    return false;

  // Parse the prefix length.
  uint32_t number_of_bits;
  if (!ParseUint32(parts[1], ParseIntFormat::NON_NEGATIVE, &number_of_bits)) {
    return false;
  }

  // Make sure the prefix length is in a valid range.
  if (number_of_bits > ip_address->size() * 8)
    return false;

  *prefix_length_in_bits = number_of_bits;
  return true;
}

bool ParseURLHostnameToAddress(std::string_view hostname,
                               IPAddress* ip_address) {
  if (hostname.size() >= 2 && hostname.front() == '[' &&
      hostname.back() == ']') {
    // Strip the square brackets that surround IPv6 literals.
    auto ip_literal = std::string_view(hostname).substr(1, hostname.size() - 2);
    return ip_address->AssignFromIPLiteral(ip_literal) && ip_address->IsIPv6();
  }

  return ip_address->AssignFromIPLiteral(hostname) && ip_address->IsIPv4();
}

size_t CommonPrefixLength(const IPAddress& a1, const IPAddress& a2) {
  DCHECK_EQ(a1.size(), a2.size());
  for (size_t i = 0; i < a1.size(); ++i) {
    unsigned diff = a1.bytes()[i] ^ a2.bytes()[i];
    if (!diff)
      continue;
    for (unsigned j = 0; j < CHAR_BIT; ++j) {
      if (diff & (1 << (CHAR_BIT - 1)))
        return i * CHAR_BIT + j;
      diff <<= 1;
    }
    NOTREACHED();
  }
  return a1.size() * CHAR_BIT;
}

size_t MaskPrefixLength(const IPAddress& mask) {
  IPAddressBytes all_ones;
  all_ones.Resize(mask.size());
  std::fill(all_ones.begin(), all_ones.end(), 0xFF);
  return CommonPrefixLength(mask, IPAddress(all_ones));
}

Dns64PrefixLength ExtractPref64FromIpv4onlyArpaAAAA(const IPAddress& address) {
  DCHECK(address.IsIPv6());
  IPAddress ipv4onlyarpa0(192, 0, 0, 170);
  IPAddress ipv4onlyarpa1(192, 0, 0, 171);
  auto span = base::span(address.bytes());

  if (base::ranges::equal(ipv4onlyarpa0.bytes(), span.subspan(12u)) ||
      base::ranges::equal(ipv4onlyarpa1.bytes(), span.subspan(12u))) {
    return Dns64PrefixLength::k96bit;
  }
  if (base::ranges::equal(ipv4onlyarpa0.bytes(), span.subspan(9u, 4u)) ||
      base::ranges::equal(ipv4onlyarpa1.bytes(), span.subspan(9u, 4u))) {
    return Dns64PrefixLength::k64bit;
  }
  IPAddressBytes ipv4;
  ipv4.Append(span.subspan(7u, 1u));
  ipv4.Append(span.subspan(9u, 3u));
  if (base::ranges::equal(ipv4onlyarpa0.bytes(), ipv4) ||
      base::ranges::equal(ipv4onlyarpa1.bytes(), ipv4)) {
    return Dns64PrefixLength::k56bit;
  }
  ipv4 = IPAddressBytes();
  ipv4.Append(span.subspan(6u, 2u));
  ipv4.Append(span.subspan(9u, 2u));
  if (base::ranges::equal(ipv4onlyarpa0.bytes(), ipv4) ||
      base::ranges::equal(ipv4onlyarpa1.bytes(), ipv4)) {
    return Dns64PrefixLength::k48bit;
  }
  ipv4 = IPAddressBytes();
  ipv4.Append(span.subspan(5u, 3u));
  ipv4.Append(span.subspan(9u, 1u));
  if (base::ranges::equal(ipv4onlyarpa0.bytes(), ipv4) ||
      base::ranges::equal(ipv4onlyarpa1.bytes(), ipv4)) {
    return Dns64PrefixLength::k40bit;
  }
  if (base::ranges::equal(ipv4onlyarpa0.bytes(), span.subspan(4u, 4u)) ||
      base::ranges::equal(ipv4onlyarpa1.bytes(), span.subspan(4u, 4u))) {
    return Dns64PrefixLength::k32bit;
  }
  // if ipv4onlyarpa address is not found return 0
  return Dns64PrefixLength::kInvalid;
}

IPAddress ConvertIPv4ToIPv4EmbeddedIPv6(const IPAddress& ipv4_address,
                                        const IPAddress& ipv6_address,
                                        Dns64PrefixLength prefix_length) {
  DCHECK(ipv4_address.IsIPv4());
  DCHECK(ipv6_address.IsIPv6());

  IPAddressBytes bytes;

  constexpr uint8_t kZeroBits[8] = {0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00};

  switch (prefix_length) {
    case Dns64PrefixLength::k96bit:
      bytes.Append(base::span(ipv6_address.bytes()).first(12u));
      bytes.Append(ipv4_address.bytes());
      return IPAddress(bytes);
    case Dns64PrefixLength::k64bit:
      bytes.Append(base::span(ipv6_address.bytes()).first(8u));
      bytes.Append(base::span(kZeroBits).first(1u));
      bytes.Append(ipv4_address.bytes());
      bytes.Append(base::span(kZeroBits).first(3u));
      return IPAddress(bytes);
    case Dns64PrefixLength::k56bit: {
      bytes.Append(base::span(ipv6_address.bytes()).first(7u));
      auto [first, second] = base::span(ipv4_address.bytes()).split_at(1u);
      bytes.Append(first);
      bytes.Append(base::span(kZeroBits).first(1u));
      bytes.Append(second);
      bytes.Append(base::span(kZeroBits).first(4u));
      return IPAddress(bytes);
    }
    case Dns64PrefixLength::k48bit: {
      bytes.Append(base::span(ipv6_address.bytes()).first(6u));
      auto [first, second] = base::span(ipv4_address.bytes()).split_at(2u);
      bytes.Append(first);
      bytes.Append(base::span(kZeroBits).first(1u));
      bytes.Append(second);
      bytes.Append(base::span(kZeroBits).first(5u));
      return IPAddress(bytes);
    }
    case Dns64PrefixLength::k40bit: {
      bytes.Append(base::span(ipv6_address.bytes()).first(5u));
      auto [first, second] = base::span(ipv4_address.bytes()).split_at(3u);
      bytes.Append(first);
      bytes.Append(base::span(kZeroBits).first(1u));
      bytes.Append(second);
      bytes.Append(base::span(kZeroBits).first(6u));
      return IPAddress(bytes);
    }
    case Dns64PrefixLength::k32bit:
      bytes.Append(base::span(ipv6_address.bytes()).first(4u));
      bytes.Append(ipv4_address.bytes());
      bytes.Append(base::span(kZeroBits).first(8u));
      return IPAddress(bytes);
    case Dns64PrefixLength::kInvalid:
      return ipv4_address;
  }
}

}  // namespace net

"""

```