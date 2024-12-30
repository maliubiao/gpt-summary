Response:
Let's break down the thought process for analyzing this code and generating the response.

**1. Understanding the Request:**

The request asks for several things regarding the `address_sorter_posix.cc` file:

* **Functionality:** What does this code do?
* **JavaScript Relation:** How does it connect to JavaScript functionality in a browser context?
* **Logic Inference:**  Provide examples of input and output based on its logic.
* **Common Errors:** What mistakes can users or programmers make that relate to this code?
* **User Journey:** How does a user action eventually lead to this code being executed?
* **Debugging Clues:** What can this code reveal during debugging?

**2. Initial Code Scan and Keyword Identification:**

I started by scanning the code for keywords and patterns that indicate its purpose. Key terms include:

* `AddressSorterPosix`:  The core class name, suggesting it's responsible for sorting network addresses.
* `RFC3484`: This is a crucial hint, indicating the code implements address sorting based on a specific standard.
* `PolicyEntry`, `PolicyTable`, `Precedence`, `Label`: These terms relate to the rules used for sorting.
* `SourceAddressInfo`:  Information about the local network interfaces.
* `CompareDestinations`:  The function that compares addresses based on the defined rules.
* `ClientSocketFactory`, `DatagramClientSocket`, `ConnectAsync`:  Indicates network socket interaction.
* `NetworkChangeNotifier`, `OnIPAddressChanged`:  Suggests reacting to changes in the network configuration.
* `Sort`, `CallbackType`:  Points to the asynchronous nature of the sorting process.

**3. Deconstructing the Functionality:**

Based on the keywords and the structure of the code, I started piecing together the functionality:

* **Core Purpose:** The primary goal is to sort a list of IP addresses (endpoints) according to RFC 3484. This is essential for choosing the best address to connect to.
* **Policy-Based Sorting:** The code uses precedence and label tables, which can be configured (though default values are provided). These tables define the sorting rules.
* **Source Address Information:** It gathers information about the local network interfaces (IP addresses, scope, deprecation, etc.). This local information is crucial for making informed sorting decisions.
* **Reachability Testing (Implicit):** The `ConnectAsync` calls, even without sending data, seem to be a way to quickly assess the usability of a destination address. If a connection fails, that address is penalized or removed.
* **Asynchronous Operation:** The `Sort` function uses a callback, indicating that the sorting process is asynchronous. This is typical for network operations.
* **Reacting to Network Changes:** The `NetworkChangeNotifier` ensures that the source address information is up-to-date when network configurations change.

**4. Connecting to JavaScript:**

This is where I considered how this low-level C++ code relates to the higher-level JavaScript environment in a browser. The connection is indirect but important:

* **`fetch()` API:**  The most obvious connection. When a JavaScript application uses `fetch()`, the browser's networking stack (which includes this code) handles the underlying connection establishment.
* **`XMLHttpRequest`:** The older API serves the same purpose.
* **WebSockets:** These also rely on the networking stack to establish connections.
* **Other Networking APIs:** Any JavaScript API that involves network communication will ultimately use code like this.

The key takeaway is that while JavaScript developers don't directly interact with `address_sorter_posix.cc`, its correct operation is essential for the functionality of web applications.

**5. Logic Inference (Input/Output):**

To illustrate the logic, I devised a scenario:

* **Input:** A list of IPv4 and IPv6 addresses, and a local interface with a specific IPv6 address.
* **Assumptions:** Using default policy tables.
* **Reasoning:**  I walked through how the `CompareDestinations` function would evaluate the addresses based on the rules (matching scope, precedence, etc.).
* **Output:** The expected sorted order, explaining *why* the addresses are ordered that way.

**6. Identifying Common Errors:**

This required thinking about how developers might misuse or misunderstand networking concepts:

* **Assuming Immediate Availability:**  Not realizing the asynchronous nature of DNS resolution and connection establishment.
* **Ignoring Network Configuration:** Assuming a single network interface or not considering the impact of multiple interfaces.
* **Misinterpreting Error Codes:**  Not handling connection errors correctly.

**7. Tracing the User Journey:**

This involved thinking about common user actions in a browser:

* **Typing a URL:** This triggers DNS resolution and subsequent connection attempts.
* **Clicking a Link:**  Similar to typing a URL.
* **JavaScript Network Requests:** As mentioned earlier, `fetch()`, etc., are the primary drivers.

The key is to connect the high-level user interaction to the low-level networking code.

**8. Debugging Clues:**

I thought about what information this code provides during debugging:

* **Connection Failures:** The logging within `DidCompleteConnect` is crucial for identifying unreachable addresses.
* **Sorting Order:**  While not directly exposed in the logs, understanding the sorting logic helps explain why certain addresses are preferred.
* **Network Interface Information:** The `OnIPAddressChanged` function updates the internal state based on the system's network configuration.

**9. Structuring the Response:**

Finally, I organized the information into the requested categories, providing clear explanations and examples. I used formatting (like bolding and bullet points) to improve readability. I also tried to maintain a logical flow, starting with the core functionality and then moving to the more specific aspects.

**Self-Correction/Refinement:**

During the process, I might have initially focused too much on the low-level socket details. I then refined the JavaScript connection section to emphasize the higher-level APIs that developers actually use. I also made sure the input/output example clearly illustrated the effect of the sorting rules. I considered adding more complex scenarios for logic inference but decided to keep it relatively simple for clarity.
这个文件 `net/dns/address_sorter_posix.cc` 是 Chromium 网络栈的一部分，它的主要功能是**根据一套规则对一组 IP 地址进行排序**。这个排序的目的是为了帮助系统选择最佳的本地源 IP 地址和远程目标 IP 地址组合来建立网络连接，从而提高网络连接的效率和可靠性。  它实现了 RFC 3484 规范以及后续的修订版中定义的地址选择机制。

**以下是它的具体功能点：**

1. **加载和管理策略表：**
   -  它维护了两个主要的策略表：**优先级表 (Precedence Table)** 和 **标签表 (Label Table)**。
   -  这些表定义了不同类型的 IPv6 地址的前缀以及对应的优先级和标签值。
   -  默认的策略表在代码中定义 (`kDefaultPrecedenceTable`, `kDefaultLabelTable`)，这些表遵循 RFC 3484 的建议。
   -  `LoadPolicy` 函数负责从静态数组加载并排序这些策略表，排序的目的是为了能够进行最长前缀匹配。

2. **根据策略表获取优先级和标签：**
   -  `GetPolicyValue` 函数用于查找给定 IP 地址在策略表中匹配的前缀，并返回其对应的优先级或标签值。

3. **确定地址的作用域 (Scope)：**
   -  `GetScope` 函数根据 IP 地址的类型（IPv4 或 IPv6）和其特定的属性（例如，是否为组播地址、环回地址、链路本地地址等）来确定其作用域（例如，全局、站点本地、链路本地）。
   -  对于 IPv4 地址，它使用一个单独的策略表 (`kDefaultIPv4ScopeTable`) 来映射到作用域。

4. **获取本地源地址信息：**
   -  `OnIPAddressChanged` 函数响应操作系统网络配置的变化。
   -  它会获取本地网络接口的 IP 地址、是否已弃用 (deprecated)、是否为本地地址 (home address) 以及前缀长度等信息。
   -  在 Linux 和 ChromeOS 上，它通过 `NetworkChangeNotifier::GetAddressMapOwner()` 来获取这些信息。
   -  在 macOS 和 BSD 系统上，它使用 `getifaddrs` 和 `ioctl` 系统调用来获取接口信息。
   -  这些信息被存储在 `source_map_` 中，用于后续的地址排序。

5. **对目标地址进行排序：**
   -  `Sort` 函数是进行地址排序的入口点。它接收一个 `IPEndPoint` (包含 IP 地址和端口) 的列表作为输入。
   -  它会为每个目标地址创建 `DestinationInfo` 结构，包含地址本身、作用域、优先级、标签以及源地址信息。
   -  关键的一步是它会尝试 **连接到每个目标地址**，即使只是一个简单的 `ConnectAsync` 调用（对于 UDP 套接字）。这个步骤的目的是快速判断目标地址是否可用。
   -  `CompareDestinations` 函数实现了 RFC 3484 中定义的排序规则，比较两个 `DestinationInfo` 对象，决定哪个应该排在前面。排序规则包括：
      -  避免不可用的目标地址。
      -  优先匹配作用域。
      -  避免使用已弃用的地址。
      -  优先使用本地地址。
      -  优先匹配标签。
      -  优先使用更高的优先级。
      -  优先使用本机传输（目前代码中未完全实现）。
      -  优先使用较小的作用域。
      -  对于相同地址族的地址，优先使用最长匹配的前缀。
   -  排序是**稳定排序**，这意味着如果两个地址根据排序规则相等，它们的原始顺序将被保留。
   -  排序完成后，通过回调函数将排序后的 `IPEndPoint` 列表返回给调用者。

6. **异步排序：**
   -  排序过程是异步的，因为它涉及到网络连接尝试。`SortContext` 类用于管理每个排序操作的状态和回调。

**它与 JavaScript 的功能关系：**

`address_sorter_posix.cc` 本身是用 C++ 编写的，**不直接与 JavaScript 代码交互**。 然而，它是 Chromium 浏览器网络栈的关键组成部分，而网络栈是支撑浏览器中所有网络功能的基础。  因此，当 JavaScript 代码发起网络请求时（例如，通过 `fetch` API 或 `XMLHttpRequest` 对象），Chromium 的网络栈会使用 `address_sorter_posix.cc` 来选择最佳的 IP 地址进行连接。

**举例说明：**

假设一个网页上的 JavaScript 代码使用 `fetch` API 请求一个域名，该域名解析到多个 IPv4 和 IPv6 地址。

```javascript
fetch('https://example.com/data.json')
  .then(response => response.json())
  .then(data => console.log(data));
```

当浏览器执行这段代码时，网络栈会执行以下步骤（简化）：

1. **DNS 解析：** 首先，浏览器会进行 DNS 查询，获取 `example.com` 对应的 IP 地址列表（可能包含多个 IPv4 和 IPv6 地址）。
2. **地址排序：**  `address_sorter_posix.cc` 的 `Sort` 函数会被调用，接收这些解析到的 IP 地址作为输入。
3. **连接尝试：**  `Sort` 函数内部会尝试连接到这些 IP 地址（即使只是为了判断可用性）。
4. **应用排序规则：**  根据本地网络接口的信息（例如，本地 IP 地址、作用域）以及预定义的策略表，`CompareDestinations` 函数会对这些 IP 地址进行排序。例如，如果本地网络支持 IPv6 并且目标地址也有 IPv6，那么根据默认策略，IPv6 地址可能会被优先选择。
5. **选择最佳地址：**  排序后的列表的第一个地址被认为是最佳的连接目标。
6. **建立连接：**  网络栈会使用选择的最佳 IP 地址建立与 `example.com` 服务器的 TCP 连接。
7. **数据传输：**  一旦连接建立，JavaScript 代码才能成功地获取 `data.json` 的内容。

**逻辑推理的假设输入与输出：**

**假设输入：**

- 目标域名 `example.com` 解析到以下 IP 地址：
    - `2001:db8::1` (全球 IPv6 地址)
    - `192.0.2.1` (公共 IPv4 地址)
    - `fe80::1234` (链路本地 IPv6 地址)
- 本地计算机拥有一个全局 IPv6 地址和一个私有 IPv4 地址。

**推理过程：**

1. **作用域判断：**
   - `2001:db8::1` 的作用域为 `SCOPE_GLOBAL`。
   - `192.0.2.1` 的作用域为 `SCOPE_GLOBAL`。
   - `fe80::1234` 的作用域为 `SCOPE_LINKLOCAL`。
2. **优先级和标签查找：**  根据默认策略表，不同的前缀会有不同的优先级和标签。例如，全球 IPv6 地址通常有较高的优先级。
3. **连接尝试：** 假设连接到全球 IPv6 地址和公共 IPv4 地址都成功，但连接到链路本地 IPv6 地址失败（因为它可能不在同一个链路上）。
4. **排序规则应用：**
   - 链路本地地址由于连接失败，可能会被排除或排在最后。
   - 如果本地计算机有全局 IPv6 地址，根据“优先匹配作用域”的规则，目标 IPv6 地址可能会被优先选择。
   - 优先级和标签也会影响最终的排序。

**假设输出（排序后的 IP 地址列表，越靠前越优先）：**

1. `2001:db8::1`
2. `192.0.2.1`
3. `fe80::1234` (如果连接尝试失败，可能直接被过滤掉)

**用户或编程常见的使用错误：**

1. **错误地假设地址总是以特定顺序返回：** 开发者不应该依赖于 DNS 解析返回的原始顺序，因为 `address_sorter_posix.cc` 会根据规则重新排序。
2. **忽略网络配置的影响：** 本地网络配置（例如，是否启用 IPv6）会显著影响地址排序的结果。开发者在测试网络功能时需要考虑这些因素。
3. **在不需要的情况下手动选择 IP 地址：**  浏览器已经提供了自动选择最佳地址的机制，通常情况下开发者不需要手动干预。
4. **误解连接尝试的目的：**  `address_sorter_posix.cc` 中的连接尝试是为了快速判断地址的可用性，而不是真正建立完整的连接用于数据传输。

**用户操作如何一步步地到达这里，作为调试线索：**

1. **用户在浏览器地址栏中输入一个 URL 并按下回车键。**
2. **浏览器开始解析 URL 中的域名。**
3. **操作系统进行 DNS 查询，获取域名对应的 IP 地址列表。**
4. **Chromium 网络栈接收到 DNS 解析结果。**
5. **`address_sorter_posix.cc` 中的 `Sort` 函数被调用，传入解析到的 IP 地址列表。**
6. **`Sort` 函数内部会创建套接字并尝试连接到这些 IP 地址。**
7. **`CompareDestinations` 函数根据预定义的规则和本地网络信息对地址进行排序。**
8. **网络栈选择排序后的第一个 IP 地址尝试建立 TCP 连接。**
9. **如果连接成功，浏览器开始下载网页内容。**

**调试线索：**

- **网络连接失败：** 如果用户无法访问某个网站，可能是因为 `address_sorter_posix.cc` 选择的地址无法连接。可以通过抓包工具（如 Wireshark）查看尝试连接的 IP 地址是否正确。
- **连接速度慢：** 如果连接建立缓慢，可能是因为选择的地址不是最优的。可以检查本地网络配置和目标服务器的 IPv6 支持情况。
- **特定网络环境下的问题：** 在某些网络环境下（例如，只有 IPv4 或 IPv6），地址排序的行为可能会有所不同。理解 `address_sorter_posix.cc` 的逻辑可以帮助诊断这些问题。
- **观察日志：** Chromium 的网络日志（可以通过 `chrome://net-export/` 生成）可能会包含与地址排序相关的调试信息。

总而言之，`address_sorter_posix.cc` 是 Chromium 网络栈中一个幕后英雄，它默默地工作以确保浏览器能够选择最佳的网络路径进行连接，从而提供更流畅的网络体验。虽然 JavaScript 开发者不直接操作它，但它的正确运行对于所有基于浏览器的网络应用至关重要。

Prompt: 
```
这是目录为net/dns/address_sorter_posix.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/dns/address_sorter_posix.h"

#include <netinet/in.h>

#include <memory>
#include <utility>
#include <vector>

#include "base/memory/raw_ptr.h"
#include "build/build_config.h"

#if BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_BSD)
#include <sys/socket.h>  // Must be included before ifaddrs.h.
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#if BUILDFLAG(IS_IOS)
// The code in the following header file is copied from [1]. This file has the
// minimum definitions needed to retrieve the IP attributes, since iOS SDK
// doesn't include a necessary header <netinet/in_var.h>.
// [1] https://chromium.googlesource.com/external/webrtc/+/master/rtc_base/mac_ifaddrs_converter.cc
#include "net/dns/netinet_in_var_ios.h"
#else
#include <netinet/in_var.h>
#endif  // BUILDFLAG(IS_IOS)
#endif
#include <vector>

#include "base/containers/unique_ptr_adapters.h"
#include "base/logging.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/log/net_log_source.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/datagram_client_socket.h"

#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
#include "net/base/address_tracker_linux.h"
#endif

namespace net {
namespace {
// Address sorting is performed according to RFC3484 with revisions.
// http://tools.ietf.org/html/draft-ietf-6man-rfc3484bis-06
// Precedence and label are separate to support override through
// /etc/gai.conf.

// Returns true if |p1| should precede |p2| in the table.
// Sorts table by decreasing prefix size to allow longest prefix matching.
bool ComparePolicy(const AddressSorterPosix::PolicyEntry& p1,
                   const AddressSorterPosix::PolicyEntry& p2) {
  return p1.prefix_length > p2.prefix_length;
}

// Creates sorted PolicyTable from |table| with |size| entries.
AddressSorterPosix::PolicyTable LoadPolicy(
    const AddressSorterPosix::PolicyEntry* table,
    size_t size) {
  AddressSorterPosix::PolicyTable result(table, table + size);
  std::sort(result.begin(), result.end(), ComparePolicy);
  return result;
}

// Search |table| for matching prefix of |address|. |table| must be sorted by
// descending prefix (prefix of another prefix must be later in table).
unsigned GetPolicyValue(const AddressSorterPosix::PolicyTable& table,
                        const IPAddress& address) {
  if (address.IsIPv4())
    return GetPolicyValue(table, ConvertIPv4ToIPv4MappedIPv6(address));
  for (const auto& entry : table) {
    IPAddress prefix(entry.prefix);
    if (IPAddressMatchesPrefix(address, prefix, entry.prefix_length))
      return entry.value;
  }
  NOTREACHED();
}

bool IsIPv6Multicast(const IPAddress& address) {
  DCHECK(address.IsIPv6());
  return address.bytes()[0] == 0xFF;
}

AddressSorterPosix::AddressScope GetIPv6MulticastScope(
    const IPAddress& address) {
  DCHECK(address.IsIPv6());
  return static_cast<AddressSorterPosix::AddressScope>(address.bytes()[1] &
                                                       0x0F);
}

bool IsIPv6Loopback(const IPAddress& address) {
  DCHECK(address.IsIPv6());
  return address == IPAddress::IPv6Localhost();
}

bool IsIPv6LinkLocal(const IPAddress& address) {
  DCHECK(address.IsIPv6());
  // IN6_IS_ADDR_LINKLOCAL
  return (address.bytes()[0] == 0xFE) && ((address.bytes()[1] & 0xC0) == 0x80);
}

bool IsIPv6SiteLocal(const IPAddress& address) {
  DCHECK(address.IsIPv6());
  // IN6_IS_ADDR_SITELOCAL
  return (address.bytes()[0] == 0xFE) && ((address.bytes()[1] & 0xC0) == 0xC0);
}

AddressSorterPosix::AddressScope GetScope(
    const AddressSorterPosix::PolicyTable& ipv4_scope_table,
    const IPAddress& address) {
  if (address.IsIPv6()) {
    if (IsIPv6Multicast(address)) {
      return GetIPv6MulticastScope(address);
    } else if (IsIPv6Loopback(address) || IsIPv6LinkLocal(address)) {
      return AddressSorterPosix::SCOPE_LINKLOCAL;
    } else if (IsIPv6SiteLocal(address)) {
      return AddressSorterPosix::SCOPE_SITELOCAL;
    } else {
      return AddressSorterPosix::SCOPE_GLOBAL;
    }
  } else if (address.IsIPv4()) {
    return static_cast<AddressSorterPosix::AddressScope>(
        GetPolicyValue(ipv4_scope_table, address));
  } else {
    NOTREACHED();
  }
}

// Default policy table. RFC 3484, Section 2.1.
const AddressSorterPosix::PolicyEntry kDefaultPrecedenceTable[] = {
    // ::1/128 -- loopback
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 128, 50},
    // ::/0 -- any
    {{}, 0, 40},
    // ::ffff:0:0/96 -- IPv4 mapped
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF}, 96, 35},
    // 2002::/16 -- 6to4
    {{
         0x20,
         0x02,
     },
     16,
     30},
    // 2001::/32 -- Teredo
    {{0x20, 0x01, 0, 0}, 32, 5},
    // fc00::/7 -- unique local address
    {{0xFC}, 7, 3},
    // ::/96 -- IPv4 compatible
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 96, 1},
    // fec0::/10 -- site-local expanded scope
    {{0xFE, 0xC0}, 10, 1},
    // 3ffe::/16 -- 6bone
    {{0x3F, 0xFE}, 16, 1},
};

const AddressSorterPosix::PolicyEntry kDefaultLabelTable[] = {
    // ::1/128 -- loopback
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 128, 0},
    // ::/0 -- any
    {{}, 0, 1},
    // ::ffff:0:0/96 -- IPv4 mapped
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF}, 96, 4},
    // 2002::/16 -- 6to4
    {{
         0x20,
         0x02,
     },
     16,
     2},
    // 2001::/32 -- Teredo
    {{0x20, 0x01, 0, 0}, 32, 5},
    // fc00::/7 -- unique local address
    {{0xFC}, 7, 13},
    // ::/96 -- IPv4 compatible
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 96, 3},
    // fec0::/10 -- site-local expanded scope
    {{0xFE, 0xC0}, 10, 11},
    // 3ffe::/16 -- 6bone
    {{0x3F, 0xFE}, 16, 12},
};

// Default mapping of IPv4 addresses to scope.
const AddressSorterPosix::PolicyEntry kDefaultIPv4ScopeTable[] = {
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0x7F},
     104,
     AddressSorterPosix::SCOPE_LINKLOCAL},
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xA9, 0xFE},
     112,
     AddressSorterPosix::SCOPE_LINKLOCAL},
    {{}, 0, AddressSorterPosix::SCOPE_GLOBAL},
};

struct DestinationInfo {
  IPEndPoint endpoint;
  AddressSorterPosix::AddressScope scope;
  unsigned precedence;
  unsigned label;
  AddressSorterPosix::SourceAddressInfo src;
  std::unique_ptr<DatagramClientSocket> socket;
  size_t common_prefix_length;
  bool failed = false;
};

// Returns true iff |dst_a| should precede |dst_b| in the address list.
// RFC 3484, section 6.
bool CompareDestinations(const DestinationInfo& dst_a,
                         const DestinationInfo& dst_b) {
  // Rule 1: Avoid unusable destinations.
  // Nothing to do here because unusable destinations are already filtered out.

  // Rule 2: Prefer matching scope.
  bool scope_match1 = (dst_a.src.scope == dst_a.scope);
  bool scope_match2 = (dst_b.src.scope == dst_b.scope);
  if (scope_match1 != scope_match2)
    return scope_match1;

  // Rule 3: Avoid deprecated addresses.
  if (dst_a.src.deprecated != dst_b.src.deprecated) {
    return !dst_a.src.deprecated;
  }

  // Rule 4: Prefer home addresses.
  if (dst_a.src.home != dst_b.src.home) {
    return dst_a.src.home;
  }

  // Rule 5: Prefer matching label.
  bool label_match1 = (dst_a.src.label == dst_a.label);
  bool label_match2 = (dst_b.src.label == dst_b.label);
  if (label_match1 != label_match2)
    return label_match1;

  // Rule 6: Prefer higher precedence.
  if (dst_a.precedence != dst_b.precedence)
    return dst_a.precedence > dst_b.precedence;

  // Rule 7: Prefer native transport.
  if (dst_a.src.native != dst_b.src.native) {
    return dst_a.src.native;
  }

  // Rule 8: Prefer smaller scope.
  if (dst_a.scope != dst_b.scope)
    return dst_a.scope < dst_b.scope;

  // Rule 9: Use longest matching prefix. Only for matching address families.
  if (dst_a.endpoint.address().size() == dst_b.endpoint.address().size()) {
    if (dst_a.common_prefix_length != dst_b.common_prefix_length)
      return dst_a.common_prefix_length > dst_b.common_prefix_length;
  }

  // Rule 10: Leave the order unchanged.
  // stable_sort takes care of that.
  return false;
}

}  // namespace

class AddressSorterPosix::SortContext {
 public:
  SortContext(size_t in_num_endpoints,
              AddressSorter::CallbackType callback,
              const AddressSorterPosix* sorter)
      : num_endpoints_(in_num_endpoints),
        callback_(std::move(callback)),
        sorter_(sorter) {}
  ~SortContext() = default;
  void DidCompleteConnect(IPEndPoint dest, size_t info_index, int rv) {
    ++num_completed_;
    if (rv != OK) {
      VLOG(1) << "Could not connect to " << dest.ToStringWithoutPort()
              << " reason " << rv;
      sort_list_[info_index].failed = true;
    }

    MaybeFinishSort();
  }

  std::vector<DestinationInfo>& sort_list() { return sort_list_; }

 private:
  void MaybeFinishSort() {
    // Sort the list of endpoints only after each Connect call has been made.
    if (num_completed_ != num_endpoints_) {
      return;
    }
    for (auto& info : sort_list_) {
      if (info.failed) {
        continue;
      }

      IPEndPoint src;
      // Filter out unusable destinations.
      int rv = info.socket->GetLocalAddress(&src);
      if (rv != OK) {
        LOG(WARNING) << "Could not get local address for "
                     << info.endpoint.ToStringWithoutPort() << " reason " << rv;
        info.failed = true;
        continue;
      }

      auto iter = sorter_->source_map_.find(src.address());
      if (iter == sorter_->source_map_.end()) {
        //  |src.address| may not be in the map if |source_info_| has not been
        //  updated from the OS yet. It will be updated and HostCache cleared
        //  soon, but we still want to sort, so fill in an empty
        info.src = AddressSorterPosix::SourceAddressInfo();
      } else {
        info.src = iter->second;
      }

      if (info.src.scope == AddressSorterPosix::SCOPE_UNDEFINED) {
        sorter_->FillPolicy(src.address(), &info.src);
      }

      if (info.endpoint.address().size() == src.address().size()) {
        info.common_prefix_length =
            std::min(CommonPrefixLength(info.endpoint.address(), src.address()),
                     info.src.prefix_length);
      }
    }
    std::erase_if(sort_list_, [](auto& element) { return element.failed; });
    std::stable_sort(sort_list_.begin(), sort_list_.end(), CompareDestinations);

    std::vector<IPEndPoint> sorted_result;
    for (const auto& info : sort_list_)
      sorted_result.push_back(info.endpoint);

    CallbackType callback = std::move(callback_);
    sorter_->FinishedSort(this);  // deletes this
    std::move(callback).Run(true, std::move(sorted_result));
  }

  const size_t num_endpoints_;
  size_t num_completed_ = 0;
  std::vector<DestinationInfo> sort_list_;
  AddressSorter::CallbackType callback_;

  raw_ptr<const AddressSorterPosix> sorter_;
};

AddressSorterPosix::AddressSorterPosix(ClientSocketFactory* socket_factory)
    : socket_factory_(socket_factory),
      precedence_table_(LoadPolicy(kDefaultPrecedenceTable,
                                   std::size(kDefaultPrecedenceTable))),
      label_table_(
          LoadPolicy(kDefaultLabelTable, std::size(kDefaultLabelTable))),
      ipv4_scope_table_(LoadPolicy(kDefaultIPv4ScopeTable,
                                   std::size(kDefaultIPv4ScopeTable))) {
  NetworkChangeNotifier::AddIPAddressObserver(this);
  OnIPAddressChanged();
}

AddressSorterPosix::~AddressSorterPosix() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  NetworkChangeNotifier::RemoveIPAddressObserver(this);
}

void AddressSorterPosix::Sort(const std::vector<IPEndPoint>& endpoints,
                              CallbackType callback) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  sort_contexts_.insert(std::make_unique<SortContext>(
      endpoints.size(), std::move(callback), this));
  auto* sort_context = sort_contexts_.rbegin()->get();
  for (const IPEndPoint& endpoint : endpoints) {
    DestinationInfo info;
    info.endpoint = endpoint;
    info.scope = GetScope(ipv4_scope_table_, info.endpoint.address());
    info.precedence =
        GetPolicyValue(precedence_table_, info.endpoint.address());
    info.label = GetPolicyValue(label_table_, info.endpoint.address());

    // Each socket can only be bound once.
    info.socket = socket_factory_->CreateDatagramClientSocket(
        DatagramSocket::DEFAULT_BIND, nullptr /* NetLog */, NetLogSource());
    IPEndPoint dest = info.endpoint;
    // Even though no packets are sent, cannot use port 0 in Connect.
    if (dest.port() == 0) {
      dest = IPEndPoint(dest.address(), /*port=*/80);
    }
    sort_context->sort_list().push_back(std::move(info));
    size_t info_index = sort_context->sort_list().size() - 1;
    // Destroying a SortContext destroys the underlying socket.
    int rv = sort_context->sort_list().back().socket->ConnectAsync(
        dest,
        base::BindOnce(&AddressSorterPosix::SortContext::DidCompleteConnect,
                       base::Unretained(sort_context), dest, info_index));
    if (rv != ERR_IO_PENDING) {
      sort_context->DidCompleteConnect(dest, info_index, rv);
    }
  }
}

void AddressSorterPosix::OnIPAddressChanged() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  source_map_.clear();
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
  // TODO(crbug.com/40263501): This always returns nullptr on ChromeOS.
  const AddressMapOwnerLinux* address_map_owner =
      NetworkChangeNotifier::GetAddressMapOwner();
  if (!address_map_owner) {
    return;
  }
  AddressMapOwnerLinux::AddressMap map = address_map_owner->GetAddressMap();
  for (const auto& [address, msg] : map) {
    SourceAddressInfo& info = source_map_[address];
    info.native = false;  // TODO(szym): obtain this via netlink.
    info.deprecated = msg.ifa_flags & IFA_F_DEPRECATED;
    info.home = msg.ifa_flags & IFA_F_HOMEADDRESS;
    info.prefix_length = msg.ifa_prefixlen;
    FillPolicy(address, &info);
  }
#elif BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_BSD)
  // It's not clear we will receive notification when deprecated flag changes.
  // Socket for ioctl.
  int ioctl_socket = socket(AF_INET6, SOCK_DGRAM, 0);
  if (ioctl_socket < 0)
    return;

  struct ifaddrs* addrs;
  int rv = getifaddrs(&addrs);
  if (rv < 0) {
    LOG(WARNING) << "getifaddrs failed " << rv;
    close(ioctl_socket);
    return;
  }

  for (struct ifaddrs* ifa = addrs; ifa != nullptr; ifa = ifa->ifa_next) {
    IPEndPoint src;
    if (!src.FromSockAddr(ifa->ifa_addr, ifa->ifa_addr->sa_len))
      continue;
    SourceAddressInfo& info = source_map_[src.address()];
    // Note: no known way to fill in |native| and |home|.
    info.native = info.home = info.deprecated = false;
    if (ifa->ifa_addr->sa_family == AF_INET6) {
      struct in6_ifreq ifr = {};
      strncpy(ifr.ifr_name, ifa->ifa_name, sizeof(ifr.ifr_name) - 1);
      DCHECK_LE(ifa->ifa_addr->sa_len, sizeof(ifr.ifr_ifru.ifru_addr));
      memcpy(&ifr.ifr_ifru.ifru_addr, ifa->ifa_addr, ifa->ifa_addr->sa_len);
      rv = ioctl(ioctl_socket, SIOCGIFAFLAG_IN6, &ifr);
      if (rv >= 0) {
        info.deprecated = ifr.ifr_ifru.ifru_flags & IN6_IFF_DEPRECATED;
      } else {
        LOG(WARNING) << "SIOCGIFAFLAG_IN6 failed " << rv;
      }
    }
    if (ifa->ifa_netmask) {
      IPEndPoint netmask;
      if (netmask.FromSockAddr(ifa->ifa_netmask, ifa->ifa_addr->sa_len)) {
        info.prefix_length = MaskPrefixLength(netmask.address());
      } else {
        LOG(WARNING) << "FromSockAddr failed on netmask";
      }
    }
    FillPolicy(src.address(), &info);
  }
  freeifaddrs(addrs);
  close(ioctl_socket);
#endif
}

void AddressSorterPosix::FillPolicy(const IPAddress& address,
                                    SourceAddressInfo* info) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  info->scope = GetScope(ipv4_scope_table_, address);
  info->label = GetPolicyValue(label_table_, address);
}

void AddressSorterPosix::FinishedSort(SortContext* sort_context) const {
  auto it = sort_contexts_.find(sort_context);
  sort_contexts_.erase(it);
}

// static
std::unique_ptr<AddressSorter> AddressSorter::CreateAddressSorter() {
  return std::make_unique<AddressSorterPosix>(
      ClientSocketFactory::GetDefaultFactory());
}

}  // namespace net

"""

```