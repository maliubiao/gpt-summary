Response:
Let's break down the thought process for analyzing this `netlink.cc` file and generating the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the `netlink.cc` file within the Chromium network stack, specifically focusing on its interaction with the Linux netlink socket interface. Secondary goals are to identify potential connections to JavaScript, illustrate logical reasoning with input/output examples, point out common usage errors, and describe how a user might reach this code during debugging.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick skim of the code, looking for key terms and patterns:

* **Includes:**  `<linux/fib_rules.h>`, `<sys/socket.h>`, `AF_NETLINK`, `NETLINK_ROUTE`,  These immediately indicate interaction with the Linux kernel's networking subsystem through netlink sockets.
* **Class Name:** `Netlink`. This is the central class responsible for the functionality.
* **Methods:** `OpenSocket`, `CloseSocket`, `GetLinkInfo`, `GetAddresses`, `ChangeLocalAddress`, `GetRouteInfo`, `ChangeRoute`, `GetRuleInfo`, `ChangeRule`, `Send`, `Recv`. These method names strongly suggest the file's purpose: managing network interface information, addresses, routing rules, and IP rules.
* **Data Structures:** `LinkInfo`, `AddressInfo`, `RoutingRule`, `IpRule`. These define the types of data being retrieved and manipulated.
* **Netlink-Specific Structures:** `sockaddr_nl`, `nlmsghdr`, `ifinfomsg`, `ifaddrmsg`, `rtmsg`, `rtattr`. These are standard Linux netlink structures, further confirming the core functionality.
* **Error Handling:** `QUIC_PLOG(ERROR)`, `QUIC_LOG(ERROR)`, conditional checks (`socket_fd_ < 0`), indicating the code handles potential failures in system calls.
* **Parsers:** `LinkInfoParser`, `LocalAddressParser`, `RoutingRuleParser`, `IpRuleParser`, `UnknownParser`. These classes are responsible for interpreting the raw data received from the netlink socket.

**3. Functionality Deduction (Method by Method):**

Now, delve into each public method to understand its specific purpose:

* **`Netlink` (constructor and destructor):** Initializes the object and closes the socket upon destruction. The constructor uses a random number for the sequence number, likely for matching requests and responses.
* **`ResetRecvBuf`:** Manages the receive buffer size.
* **`OpenSocket`:** Creates a netlink socket.
* **`CloseSocket`:** Closes the netlink socket.
* **`GetLinkInfo`:** Retrieves information about a specific network interface (index, type, MAC addresses). It constructs a `RTM_GETLINK` request and uses `LinkInfoParser` to process the response.
* **`GetAddresses`:** Retrieves IP addresses associated with a given interface. It sends a `RTM_GETADDR` request and utilizes `LocalAddressParser`.
* **`ChangeLocalAddress`:** Adds or deletes local IP addresses. It sends `RTM_NEWADDR` or `RTM_DELADDR` requests.
* **`GetRouteInfo`:** Fetches routing table entries. It sends a `RTM_GETROUTE` request and uses `RoutingRuleParser`.
* **`ChangeRoute`:** Adds, deletes, or replaces routing rules. It sends `RTM_NEWROUTE` or `RTM_DELROUTE` requests.
* **`GetRuleInfo`:** Retrieves IP rule information. It sends a `RTM_GETRULE` request and uses `IpRuleParser`.
* **`ChangeRule`:** Adds or deletes IP rules. It sends `RTM_NEWRULE` or `RTM_DELRULE` requests.
* **`Send`:** Sends a message to the netlink socket.
* **`Recv`:** Receives messages from the netlink socket and uses a provided `NetlinkParserInterface` to interpret the data. It handles potential multi-packet responses and error conditions.

**4. Identifying Relationships with JavaScript (or Lack Thereof):**

At this point, consider the context. This is a low-level C++ file dealing directly with the operating system's networking. JavaScript in a browser environment doesn't have direct access to these system calls. Therefore, the connection is *indirect*. JavaScript uses higher-level APIs (like `fetch` or WebSockets), which eventually rely on the browser's network stack, where this C++ code might be involved. The key is that JavaScript doesn't *directly* call functions in this file.

**5. Logical Reasoning, Assumptions, and Examples:**

For each key function (especially the "Get" and "Change" methods), create simple scenarios:

* **`GetLinkInfo`:** Assume an interface name like "eth0". The output would be the interface index, type (e.g., `ARPHRD_ETHER`), and MAC addresses.
* **`GetAddresses`:** Given an interface index, the output would be a list of IP addresses and their prefixes.
* **`ChangeRoute`:**  Assume adding a route to a specific subnet via a gateway. Show the input parameters and the expected outcome (a new route entry in the kernel).

**6. Common Usage Errors:**

Think about potential pitfalls when using these low-level APIs:

* **Incorrect Permissions:** Netlink operations often require root privileges.
* **Invalid Interface Names/Indices:** Providing wrong interface identifiers will lead to errors.
* **Malformed Netlink Messages:** Incorrectly constructing the request messages will cause failures.
* **Resource Leaks:**  Forgetting to close the socket.

**7. Debugging Scenario:**

Imagine a user reporting a connectivity issue. How might a developer end up looking at this `netlink.cc` file?

* **Network Stack Trace:**  A crash or error in the network stack might lead to a stack trace involving this code.
* **Debugging Tools:** Tools like `tcpdump` or `wireshark` might show unusual netlink traffic, prompting investigation.
* **Suspecting Routing Issues:** If a specific network path isn't working, the routing-related functions in this file become relevant.

**8. Structuring the Explanation:**

Organize the findings into logical sections: Functionality, JavaScript Connection, Logical Reasoning, Usage Errors, and Debugging. Use clear and concise language, providing code snippets and examples where helpful.

**Self-Correction/Refinement during the Process:**

* **Initial Thought:** "Maybe JavaScript uses some internal bindings to directly call these functions."  **Correction:** While browser internals are complex, direct calls to these specific netlink functions from standard web JavaScript are highly unlikely due to security and sandboxing. The connection is more abstract.
* **Overly Technical Language:**  Initially, explanations might be too focused on the raw netlink structures. **Refinement:**  Explain the *purpose* of these structures rather than just their names. Focus on the high-level actions the code performs.
* **Lack of Concrete Examples:**  Initially, the logical reasoning section might be too abstract. **Refinement:** Add specific examples with hypothetical inputs and outputs to make the concepts clearer.

By following this structured approach, combining code analysis, domain knowledge (networking, operating systems), and logical thinking, a comprehensive and informative explanation of the `netlink.cc` file can be generated.
这个文件 `net/third_party/quiche/src/quiche/quic/qbone/platform/netlink.cc` 是 Chromium 网络栈中 QUIC (Quick UDP Internet Connections) 协议的一个组件，专门用于与 Linux 内核的 Netlink 套接字接口进行交互。其主要功能是：

**核心功能：与 Linux 内核的 Netlink 接口交互，用于网络配置和监控。**

更具体地说，它提供了以下功能：

1. **打开和关闭 Netlink 套接字：**
   - `OpenSocket()`: 创建一个 `AF_NETLINK` 类型的套接字，用于与内核进行通信，协议族指定为 `NETLINK_ROUTE`，这允许程序接收和发送与路由、接口和地址相关的内核消息。
   - `CloseSocket()`: 关闭已打开的 Netlink 套接字，释放资源。

2. **获取网络接口信息：**
   - `GetLinkInfo(const std::string& interface_name, LinkInfo* link_info)`:  通过 Netlink 查询指定网络接口 (`interface_name`) 的详细信息，例如接口索引、类型、硬件地址 (MAC 地址)、广播地址等。它构建一个 `RTM_GETLINK` 类型的 Netlink 消息并发送给内核，然后解析内核的响应。

3. **获取本地地址信息：**
   - `GetAddresses(int interface_index, uint8_t unwanted_flags, std::vector<AddressInfo>* addresses, int* num_ipv6_nodad_dadfailed_addresses)`: 获取指定网络接口索引 (`interface_index`) 的本地 IP 地址信息。它可以过滤掉带有特定标志的地址。它构建一个 `RTM_GETADDR` 类型的 Netlink 消息并解析内核的响应，获取 IPv4 和 IPv6 地址。

4. **修改本地地址：**
   - `ChangeLocalAddress(uint32_t interface_index, Verb verb, const QuicIpAddress& address, uint8_t prefix_length, uint8_t ifa_flags, uint8_t ifa_scope, const std::vector<struct rtattr*>& additional_attributes)`:  添加 (`Verb::kAdd`) 或删除 (`Verb::kRemove`) 指定网络接口上的本地 IP 地址。它构建 `RTM_NEWADDR` 或 `RTM_DELADDR` 类型的 Netlink 消息。

5. **获取路由信息：**
   - `GetRouteInfo(std::vector<RoutingRule>* routing_rules)`:  获取系统的路由表信息。它发送一个 `RTM_GETROUTE` 类型的 Netlink 消息并解析内核的响应，提取路由规则。

6. **修改路由：**
   - `ChangeRoute(Netlink::Verb verb, uint32_t table, const IpRange& destination_subnet, uint8_t scope, QuicIpAddress preferred_source, int32_t interface_index)`: 添加 (`Verb::kAdd`)、删除 (`Verb::kRemove`) 或替换 (`Verb::kReplace`) 路由规则。它构建 `RTM_NEWROUTE` 或 `RTM_DELROUTE` 类型的 Netlink 消息。

7. **获取 IP 规则信息 (策略路由)：**
   - `GetRuleInfo(std::vector<Netlink::IpRule>* ip_rules)`: 获取系统的 IP 规则信息，用于策略路由。它发送 `RTM_GETRULE` 类型的 Netlink 消息。

8. **修改 IP 规则 (策略路由)：**
   - `ChangeRule(Verb verb, uint32_t table, IpRange source_range)`: 添加 (`Verb::kAdd`) 或删除 (`Verb::kRemove`) IP 规则。它构建 `RTM_NEWRULE` 或 `RTM_DELRULE` 类型的 Netlink 消息。

9. **发送和接收 Netlink 消息：**
   - `Send(struct iovec* iov, size_t iovlen)`: 将构造好的 Netlink 消息通过套接字发送给内核。
   - `Recv(uint32_t seq, NetlinkParserInterface* parser)`:  接收来自内核的 Netlink 消息，并使用提供的 `NetlinkParserInterface` 对象来解析消息内容。`seq` 参数用于匹配请求和响应。

**与 JavaScript 功能的关系：**

这个 C++ 文件直接与操作系统内核交互，JavaScript 运行在浏览器环境中，无法直接调用这些底层的操作系统接口。但是，它们之间存在 **间接关系**：

* **网络连接的基础:** QUIC 协议是构建在 UDP 之上的下一代互联网传输协议，旨在提供可靠、安全的连接。浏览器中的 JavaScript 代码 (例如，通过 `fetch` API 或 WebSockets) 发起的网络请求，在底层可能会使用到 QUIC。
* **网络配置的影响:**  `netlink.cc` 文件的功能是配置和监控网络接口、地址和路由。这些配置会影响到整个系统的网络行为，包括浏览器发起的网络请求。例如，如果路由配置不正确，JavaScript 发起的请求可能无法到达目标服务器。
* **Qbone 的一部分:**  根据文件路径 `quiche/quic/qbone/platform/netlink.cc`，这个文件是 QUIC 的 "Qbone" 组件的一部分。"Qbone" 可能是 Chromium 中用于特定网络拓扑或测试环境的模块，它可能涉及到对网络进行精细的控制。

**举例说明:**

假设一个场景：一个 Chrome 浏览器中的 JavaScript 应用需要连接到一个特定的服务器，并且这个连接是通过 QUIC 建立的。

1. **JavaScript 发起请求:**  JavaScript 代码使用 `fetch('https://example.com')` 发起一个 HTTPS 请求。
2. **浏览器网络栈处理:**  Chrome 的网络栈会尝试建立 QUIC 连接。
3. **Qbone 的介入 (假设启用):** 如果启用了 Qbone，并且需要特定的网络配置，`netlink.cc` 中的代码可能会被调用。
4. **获取接口信息:**  Qbone 可能需要知道特定的网络接口信息，例如使用 `GetLinkInfo` 获取。
5. **配置路由:**  为了确保 QUIC 连接能够正确路由到目标服务器，Qbone 可能会使用 `ChangeRoute` 添加或修改路由规则。
6. **内核执行配置:**  `netlink.cc` 将 Netlink 消息发送给 Linux 内核，内核根据消息内容修改网络配置。
7. **QUIC 连接建立:**  在网络配置完成后，QUIC 连接才能成功建立，JavaScript 的 `fetch` 请求才能完成。

**逻辑推理、假设输入与输出:**

**假设输入:**  调用 `GetLinkInfo("eth0", link_info)`。

**假设:** 系统存在一个名为 "eth0" 的网络接口。

**输出 (`link_info` 的内容):**

```
link_info->index:  // 例如，2 (接口索引)
link_info->type:   // 例如，1 (ARPHRD_ETHER，以太网)
link_info->hardware_address_length: // 例如，6 (MAC 地址长度)
link_info->hardware_address: // 例如，{0x00, 0x11, 0x22, 0x33, 0x44, 0x55} (MAC 地址)
link_info->broadcast_address_length: // 例如，6
link_info->broadcast_address: // 例如，{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
```

**假设输入:** 调用 `GetAddresses(2, 0, addresses, nullptr)`，假设接口索引为 2。

**输出 (`addresses` 的内容):**

```
// 假设接口 2 有一个 IPv4 地址和一个 IPv6 地址
addresses[0].local_address:  // 例如，192.168.1.100 (QuicIpAddress 对象)
addresses[0].interface_address: // 可能与 local_address 相同
addresses[0].prefix_length: // 例如，24 (IPv4 子网掩码)
addresses[0].scope:  // 例如，0

addresses[1].local_address:  // 例如，2001:db8::1 (QuicIpAddress 对象)
addresses[1].interface_address: // 可能与 local_address 相同
addresses[1].prefix_length: // 例如，64 (IPv6 前缀长度)
addresses[1].scope:  // 例如，0
```

**涉及用户或编程常见的使用错误：**

1. **权限不足:**  很多 Netlink 操作需要 root 权限。如果程序没有足够的权限，`OpenSocket()` 或后续的 `Send()` 调用可能会失败，导致连接错误或配置修改失败。
   ```c++
   if (!netlink->OpenSocket()) {
     // 错误处理：可能提示用户需要管理员权限
     QUIC_LOG(ERROR) << "Failed to open Netlink socket. Ensure you have sufficient privileges.";
   }
   ```

2. **接口名称或索引错误:**  在 `GetLinkInfo` 或 `GetAddresses` 中提供不存在或错误的接口名称或索引，会导致无法找到对应的接口信息。
   ```c++
   Netlink::LinkInfo info;
   if (!netlink->GetLinkInfo("nonexistent_interface", &info)) {
     // 错误处理：提示用户检查接口名称
     QUIC_LOG(ERROR) << "Failed to get link info for interface 'nonexistent_interface'.";
   }
   ```

3. **构造错误的 Netlink 消息:**  手动构建 Netlink 消息（虽然这个文件封装了细节）容易出错，例如消息头部的长度字段不正确，或者属性的格式错误。这会导致内核无法解析消息。

4. **忘记处理错误:**  `Send()` 和 `Recv()` 函数都可能返回错误。如果忽略这些错误，程序可能无法正确地与内核通信，导致功能异常。
   ```c++
   if (!netlink->Send(message.BuildIoVec().get(), message.IoVecSize())) {
     QUIC_LOG(ERROR) << "Failed to send Netlink message.";
     // 应该有相应的错误处理逻辑，例如重试或报告错误
   }
   ```

5. **资源泄漏:**  如果 `OpenSocket()` 成功但 `CloseSocket()` 没有在程序退出前调用，可能会导致资源泄漏。

**用户操作如何一步步地到达这里，作为调试线索：**

1. **用户报告网络连接问题:** 用户可能遇到网站无法访问、连接超时等问题。
2. **开发者开始调试:** 开发者可能会检查 Chrome 的网络日志 (chrome://net-internals/)，查看连接状态和错误信息。
3. **怀疑路由或接口配置问题:**  如果网络日志显示与特定接口或路由相关的问题，开发者可能会深入研究 Chromium 的网络栈代码。
4. **定位到 Qbone 组件:**  如果问题与特定的网络拓扑或测试环境有关，开发者可能会注意到 Qbone 组件被激活。
5. **查看 Netlink 代码:**  由于 Qbone 涉及到对网络配置的控制，开发者可能会查看 `netlink.cc` 文件，了解它是如何与内核交互来获取和修改网络配置的。
6. **设置断点或添加日志:**  开发者可能会在 `netlink.cc` 中的关键函数（例如 `GetLinkInfo`, `ChangeRoute`, `Send`, `Recv`) 设置断点或添加日志，以跟踪 Netlink 消息的发送和接收，以及内核的响应。
7. **分析 Netlink 消息:**  使用工具 (如 `tcpdump`) 抓取 Netlink 消息，结合 `netlink.cc` 的代码，可以分析发送给内核的请求是否正确，以及内核的响应是什么。这有助于诊断配置错误或内核行为异常。
8. **检查错误码:**  `Recv()` 函数接收到的 `NLMSG_ERROR` 消息包含错误码。开发者可以根据错误码来判断 Netlink 操作失败的原因。

总而言之，`netlink.cc` 是 Chromium QUIC 协议中一个关键的底层组件，负责与 Linux 内核的网络子系统交互，实现对网络接口、地址和路由的配置和监控。虽然 JavaScript 无法直接调用它，但它影响着浏览器发起的网络连接，并在特定的网络场景或测试环境中发挥着重要作用。理解其功能对于调试网络连接问题至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/qbone/platform/netlink.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/qbone/platform/netlink.h"

#include <linux/fib_rules.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/strings/str_cat.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/qbone/platform/rtnetlink_message.h"
#include "quiche/quic/qbone/qbone_constants.h"

namespace quic {

Netlink::Netlink(KernelInterface* kernel) : kernel_(kernel) {
  seq_ = QuicRandom::GetInstance()->RandUint64();
}

Netlink::~Netlink() { CloseSocket(); }

void Netlink::ResetRecvBuf(size_t size) {
  if (size != 0) {
    recvbuf_ = std::make_unique<char[]>(size);
  } else {
    recvbuf_ = nullptr;
  }
  recvbuf_length_ = size;
}

bool Netlink::OpenSocket() {
  if (socket_fd_ >= 0) {
    return true;
  }

  socket_fd_ = kernel_->socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  if (socket_fd_ < 0) {
    QUIC_PLOG(ERROR) << "can't open netlink socket";
    return false;
  }

  QUIC_LOG(INFO) << "Opened a new netlink socket fd = " << socket_fd_;

  // bind a local address to the socket
  sockaddr_nl myaddr;
  memset(&myaddr, 0, sizeof(myaddr));
  myaddr.nl_family = AF_NETLINK;
  if (kernel_->bind(socket_fd_, reinterpret_cast<struct sockaddr*>(&myaddr),
                    sizeof(myaddr)) < 0) {
    QUIC_LOG(INFO) << "can't bind address to socket";
    CloseSocket();
    return false;
  }

  return true;
}

void Netlink::CloseSocket() {
  if (socket_fd_ >= 0) {
    QUIC_LOG(INFO) << "Closing netlink socket fd = " << socket_fd_;
    kernel_->close(socket_fd_);
  }
  ResetRecvBuf(0);
  socket_fd_ = -1;
}

namespace {

class LinkInfoParser : public NetlinkParserInterface {
 public:
  LinkInfoParser(std::string interface_name, Netlink::LinkInfo* link_info)
      : interface_name_(std::move(interface_name)), link_info_(link_info) {}

  void Run(struct nlmsghdr* netlink_message) override {
    if (netlink_message->nlmsg_type != RTM_NEWLINK) {
      QUIC_LOG(INFO) << absl::StrCat(
          "Unexpected nlmsg_type: ", netlink_message->nlmsg_type,
          " expected: ", RTM_NEWLINK);
      return;
    }

    struct ifinfomsg* interface_info =
        reinterpret_cast<struct ifinfomsg*>(NLMSG_DATA(netlink_message));

    // make sure interface_info is what we asked for.
    if (interface_info->ifi_family != AF_UNSPEC) {
      QUIC_LOG(INFO) << absl::StrCat(
          "Unexpected ifi_family: ", interface_info->ifi_family,
          " expected: ", AF_UNSPEC);
      return;
    }

    char hardware_address[kHwAddrSize];
    size_t hardware_address_length = 0;
    char broadcast_address[kHwAddrSize];
    size_t broadcast_address_length = 0;
    std::string name;

    // loop through the attributes
    struct rtattr* rta;
    int payload_length = IFLA_PAYLOAD(netlink_message);
    for (rta = IFLA_RTA(interface_info); RTA_OK(rta, payload_length);
         rta = RTA_NEXT(rta, payload_length)) {
      int attribute_length;
      switch (rta->rta_type) {
        case IFLA_ADDRESS: {
          attribute_length = RTA_PAYLOAD(rta);
          if (attribute_length > kHwAddrSize) {
            QUIC_VLOG(2) << "IFLA_ADDRESS too long: " << attribute_length;
            break;
          }
          memmove(hardware_address, RTA_DATA(rta), attribute_length);
          hardware_address_length = attribute_length;
          break;
        }
        case IFLA_BROADCAST: {
          attribute_length = RTA_PAYLOAD(rta);
          if (attribute_length > kHwAddrSize) {
            QUIC_VLOG(2) << "IFLA_BROADCAST too long: " << attribute_length;
            break;
          }
          memmove(broadcast_address, RTA_DATA(rta), attribute_length);
          broadcast_address_length = attribute_length;
          break;
        }
        case IFLA_IFNAME: {
          name = std::string(reinterpret_cast<char*>(RTA_DATA(rta)),
                             RTA_PAYLOAD(rta));
          // The name maybe a 0 terminated c string.
          name = name.substr(0, name.find('\0'));
          break;
        }
      }
    }

    QUIC_VLOG(2) << "interface name: " << name
                 << ", index: " << interface_info->ifi_index;

    if (name == interface_name_) {
      link_info_->index = interface_info->ifi_index;
      link_info_->type = interface_info->ifi_type;
      link_info_->hardware_address_length = hardware_address_length;
      if (hardware_address_length > 0) {
        memmove(&link_info_->hardware_address, hardware_address,
                hardware_address_length);
      }
      link_info_->broadcast_address_length = broadcast_address_length;
      if (broadcast_address_length > 0) {
        memmove(&link_info_->broadcast_address, broadcast_address,
                broadcast_address_length);
      }
      found_link_ = true;
    }
  }

  bool found_link() { return found_link_; }

 private:
  const std::string interface_name_;
  Netlink::LinkInfo* const link_info_;
  bool found_link_ = false;
};

}  // namespace

bool Netlink::GetLinkInfo(const std::string& interface_name,
                          LinkInfo* link_info) {
  auto message = LinkMessage::New(RtnetlinkMessage::Operation::GET,
                                  NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST,
                                  seq_, getpid(), nullptr);

  if (!Send(message.BuildIoVec().get(), message.IoVecSize())) {
    QUIC_LOG(ERROR) << "send failed.";
    return false;
  }

  // Pass the parser to the receive routine. It may be called multiple times
  // since there may be multiple reply packets each with multiple reply
  // messages.
  LinkInfoParser parser(interface_name, link_info);
  if (!Recv(seq_++, &parser)) {
    QUIC_LOG(ERROR) << "recv failed.";
    return false;
  }

  return parser.found_link();
}

namespace {

class LocalAddressParser : public NetlinkParserInterface {
 public:
  LocalAddressParser(int interface_index, uint8_t unwanted_flags,
                     std::vector<Netlink::AddressInfo>* local_addresses,
                     int* num_ipv6_nodad_dadfailed_addresses)
      : interface_index_(interface_index),
        unwanted_flags_(unwanted_flags),
        local_addresses_(local_addresses),
        num_ipv6_nodad_dadfailed_addresses_(
            num_ipv6_nodad_dadfailed_addresses) {}

  void Run(struct nlmsghdr* netlink_message) override {
    // each nlmsg contains a header and multiple address attributes.
    if (netlink_message->nlmsg_type != RTM_NEWADDR) {
      QUIC_LOG(INFO) << "Unexpected nlmsg_type: " << netlink_message->nlmsg_type
                     << " expected: " << RTM_NEWADDR;
      return;
    }

    struct ifaddrmsg* interface_address =
        reinterpret_cast<struct ifaddrmsg*>(NLMSG_DATA(netlink_message));

    // Make sure this is for an address family we're interested in.
    if (interface_address->ifa_family != AF_INET &&
        interface_address->ifa_family != AF_INET6) {
      QUIC_VLOG(2) << absl::StrCat("uninteresting ifa family: ",
                                   interface_address->ifa_family);
      return;
    }

    // Keep track of addresses with both 'nodad' and 'dadfailed', this really
    // should't be possible and is likely a kernel bug.
    if (num_ipv6_nodad_dadfailed_addresses_ != nullptr &&
        (interface_address->ifa_flags & IFA_F_NODAD) &&
        (interface_address->ifa_flags & IFA_F_DADFAILED)) {
      ++(*num_ipv6_nodad_dadfailed_addresses_);
    }

    uint8_t unwanted_flags = interface_address->ifa_flags & unwanted_flags_;
    if (unwanted_flags != 0) {
      QUIC_VLOG(2) << absl::StrCat("unwanted ifa flags: ", unwanted_flags);
      return;
    }

    // loop through the attributes
    struct rtattr* rta;
    int payload_length = IFA_PAYLOAD(netlink_message);
    Netlink::AddressInfo address_info;
    for (rta = IFA_RTA(interface_address); RTA_OK(rta, payload_length);
         rta = RTA_NEXT(rta, payload_length)) {
      // There's quite a lot of confusion in Linux over the use of IFA_LOCAL and
      // IFA_ADDRESS (source and destination address). For broadcast links, such
      // as Ethernet, they are identical (see <linux/if_addr.h>), but the kernel
      // sometimes uses only one or the other. We'll return both so that the
      // caller can decide which to use.
      if (rta->rta_type != IFA_LOCAL && rta->rta_type != IFA_ADDRESS) {
        QUIC_VLOG(2) << "Ignoring uninteresting rta_type: " << rta->rta_type;
        continue;
      }

      switch (interface_address->ifa_family) {
        case AF_INET:
          ABSL_FALLTHROUGH_INTENDED;
        case AF_INET6:
          // QuicIpAddress knows how to parse ip from raw bytes as long as they
          // are in network byte order.
          if (RTA_PAYLOAD(rta) == sizeof(struct in_addr) ||
              RTA_PAYLOAD(rta) == sizeof(struct in6_addr)) {
            auto* raw_ip = reinterpret_cast<char*>(RTA_DATA(rta));
            if (rta->rta_type == IFA_LOCAL) {
              address_info.local_address.FromPackedString(raw_ip,
                                                          RTA_PAYLOAD(rta));
            } else {
              address_info.interface_address.FromPackedString(raw_ip,
                                                              RTA_PAYLOAD(rta));
            }
          }
          break;
        default:
          QUIC_LOG(ERROR) << absl::StrCat("Unknown address family: ",
                                          interface_address->ifa_family);
      }
    }

    QUIC_VLOG(2) << "local_address: " << address_info.local_address.ToString()
                 << " interface_address: "
                 << address_info.interface_address.ToString()
                 << " index: " << interface_address->ifa_index;
    if (interface_address->ifa_index != interface_index_) {
      return;
    }

    address_info.prefix_length = interface_address->ifa_prefixlen;
    address_info.scope = interface_address->ifa_scope;
    if (address_info.local_address.IsInitialized() ||
        address_info.interface_address.IsInitialized()) {
      local_addresses_->push_back(address_info);
    }
  }

 private:
  const int interface_index_;
  const uint8_t unwanted_flags_;
  std::vector<Netlink::AddressInfo>* const local_addresses_;
  int* const num_ipv6_nodad_dadfailed_addresses_;
};

}  // namespace

bool Netlink::GetAddresses(int interface_index, uint8_t unwanted_flags,
                           std::vector<AddressInfo>* addresses,
                           int* num_ipv6_nodad_dadfailed_addresses) {
  // the message doesn't contain the index, we'll have to do the filtering while
  // parsing the reply. This is because NLM_F_MATCH, which only returns entries
  // that matches the request criteria, is not yet implemented (see man 3
  // netlink).
  auto message = AddressMessage::New(RtnetlinkMessage::Operation::GET,
                                     NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST,
                                     seq_, getpid(), nullptr);

  // the send routine returns the socket to listen on.
  if (!Send(message.BuildIoVec().get(), message.IoVecSize())) {
    QUIC_LOG(ERROR) << "send failed.";
    return false;
  }

  addresses->clear();
  if (num_ipv6_nodad_dadfailed_addresses != nullptr) {
    *num_ipv6_nodad_dadfailed_addresses = 0;
  }

  LocalAddressParser parser(interface_index, unwanted_flags, addresses,
                            num_ipv6_nodad_dadfailed_addresses);
  // Pass the parser to the receive routine. It may be called multiple times
  // since there may be multiple reply packets each with multiple reply
  // messages.
  if (!Recv(seq_++, &parser)) {
    QUIC_LOG(ERROR) << "recv failed";
    return false;
  }
  return true;
}

namespace {

class UnknownParser : public NetlinkParserInterface {
 public:
  void Run(struct nlmsghdr* netlink_message) override {
    QUIC_LOG(INFO) << "nlmsg reply type: " << netlink_message->nlmsg_type;
  }
};

}  // namespace

bool Netlink::ChangeLocalAddress(
    uint32_t interface_index, Verb verb, const QuicIpAddress& address,
    uint8_t prefix_length, uint8_t ifa_flags, uint8_t ifa_scope,
    const std::vector<struct rtattr*>& additional_attributes) {
  if (verb == Verb::kReplace) {
    return false;
  }
  auto operation = verb == Verb::kAdd ? RtnetlinkMessage::Operation::NEW
                                      : RtnetlinkMessage::Operation::DEL;
  uint8_t address_family;
  if (address.address_family() == IpAddressFamily::IP_V4) {
    address_family = AF_INET;
  } else if (address.address_family() == IpAddressFamily::IP_V6) {
    address_family = AF_INET6;
  } else {
    return false;
  }

  struct ifaddrmsg address_header = {address_family, prefix_length, ifa_flags,
                                     ifa_scope, interface_index};

  auto message = AddressMessage::New(operation, NLM_F_REQUEST | NLM_F_ACK, seq_,
                                     getpid(), &address_header);

  for (const auto& attribute : additional_attributes) {
    if (attribute->rta_type == IFA_LOCAL) {
      continue;
    }
    message.AppendAttribute(attribute->rta_type, RTA_DATA(attribute),
                            RTA_PAYLOAD(attribute));
  }

  message.AppendAttribute(IFA_LOCAL, address.ToPackedString().c_str(),
                          address.ToPackedString().size());

  if (!Send(message.BuildIoVec().get(), message.IoVecSize())) {
    QUIC_LOG(ERROR) << "send failed";
    return false;
  }

  UnknownParser parser;
  if (!Recv(seq_++, &parser)) {
    QUIC_LOG(ERROR) << "receive failed.";
    return false;
  }
  return true;
}

namespace {

class RoutingRuleParser : public NetlinkParserInterface {
 public:
  explicit RoutingRuleParser(std::vector<Netlink::RoutingRule>* routing_rules)
      : routing_rules_(routing_rules) {}

  void Run(struct nlmsghdr* netlink_message) override {
    if (netlink_message->nlmsg_type != RTM_NEWROUTE) {
      QUIC_LOG(WARNING) << absl::StrCat(
          "Unexpected nlmsg_type: ", netlink_message->nlmsg_type,
          " expected: ", RTM_NEWROUTE);
      return;
    }

    auto* route = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(netlink_message));
    int payload_length = RTM_PAYLOAD(netlink_message);

    if (route->rtm_family != AF_INET && route->rtm_family != AF_INET6) {
      QUIC_VLOG(2) << absl::StrCat("Uninteresting family: ", route->rtm_family);
      return;
    }

    Netlink::RoutingRule rule;
    rule.scope = route->rtm_scope;
    rule.table = route->rtm_table;

    struct rtattr* rta;
    for (rta = RTM_RTA(route); RTA_OK(rta, payload_length);
         rta = RTA_NEXT(rta, payload_length)) {
      switch (rta->rta_type) {
        case RTA_TABLE: {
          rule.table = *reinterpret_cast<uint32_t*>(RTA_DATA(rta));
          break;
        }
        case RTA_DST: {
          QuicIpAddress destination;
          destination.FromPackedString(reinterpret_cast<char*> RTA_DATA(rta),
                                       RTA_PAYLOAD(rta));
          rule.destination_subnet = IpRange(destination, route->rtm_dst_len);
          break;
        }
        case RTA_PREFSRC: {
          QuicIpAddress preferred_source;
          rule.preferred_source.FromPackedString(
              reinterpret_cast<char*> RTA_DATA(rta), RTA_PAYLOAD(rta));
          break;
        }
        case RTA_OIF: {
          rule.out_interface = *reinterpret_cast<int*>(RTA_DATA(rta));
          break;
        }
        default: {
          QUIC_VLOG(2) << absl::StrCat("Uninteresting attribute: ",
                                       rta->rta_type);
        }
      }
    }
    routing_rules_->push_back(rule);
  }

 private:
  std::vector<Netlink::RoutingRule>* routing_rules_;
};

}  // namespace

bool Netlink::GetRouteInfo(std::vector<Netlink::RoutingRule>* routing_rules) {
  rtmsg route_message{};
  // Only manipulate main routing table.
  route_message.rtm_table = RT_TABLE_MAIN;

  auto message = RouteMessage::New(RtnetlinkMessage::Operation::GET,
                                   NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH,
                                   seq_, getpid(), &route_message);

  if (!Send(message.BuildIoVec().get(), message.IoVecSize())) {
    QUIC_LOG(ERROR) << "send failed";
    return false;
  }

  RoutingRuleParser parser(routing_rules);
  if (!Recv(seq_++, &parser)) {
    QUIC_LOG(ERROR) << "recv failed";
    return false;
  }

  return true;
}

bool Netlink::ChangeRoute(Netlink::Verb verb, uint32_t table,
                          const IpRange& destination_subnet, uint8_t scope,
                          QuicIpAddress preferred_source,
                          int32_t interface_index) {
  if (!destination_subnet.prefix().IsInitialized()) {
    return false;
  }
  if (destination_subnet.address_family() != IpAddressFamily::IP_V4 &&
      destination_subnet.address_family() != IpAddressFamily::IP_V6) {
    return false;
  }
  if (preferred_source.IsInitialized() &&
      preferred_source.address_family() !=
          destination_subnet.address_family()) {
    return false;
  }

  RtnetlinkMessage::Operation operation;
  uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;
  switch (verb) {
    case Verb::kAdd:
      operation = RtnetlinkMessage::Operation::NEW;
      // Setting NLM_F_EXCL so that an existing entry for this subnet will fail
      // the request. NLM_F_CREATE is necessary to indicate this is trying to
      // create a new entry - simply having RTM_NEWROUTE is not enough even the
      // name suggests so.
      flags |= NLM_F_EXCL | NLM_F_CREATE;
      break;
    case Verb::kRemove:
      operation = RtnetlinkMessage::Operation::DEL;
      break;
    case Verb::kReplace:
      operation = RtnetlinkMessage::Operation::NEW;
      // Setting NLM_F_REPLACE to tell the kernel that existing entry for this
      // subnet should be replaced.
      flags |= NLM_F_REPLACE | NLM_F_CREATE;
      break;
  }

  struct rtmsg route_message;
  memset(&route_message, 0, sizeof(route_message));
  route_message.rtm_family =
      destination_subnet.address_family() == IpAddressFamily::IP_V4 ? AF_INET
                                                                    : AF_INET6;
  // rtm_dst_len and rtm_src_len are actually the subnet prefix lengths. Poor
  // naming.
  route_message.rtm_dst_len = destination_subnet.prefix_length();
  // 0 means no source subnet for this rule.
  route_message.rtm_src_len = 0;
  // Only program the main table. Other tables are intended for the kernel to
  // manage.
  route_message.rtm_table = RT_TABLE_MAIN;
  // Use RTPROT_UNSPEC to match all the different protocol. Rules added by
  // kernel have RTPROT_KERNEL. Rules added by the root user have RTPROT_STATIC
  // instead.
  route_message.rtm_protocol =
      verb == Verb::kRemove ? RTPROT_UNSPEC : RTPROT_STATIC;
  route_message.rtm_scope = scope;
  // Only add unicast routing rule.
  route_message.rtm_type = RTN_UNICAST;
  auto message =
      RouteMessage::New(operation, flags, seq_, getpid(), &route_message);

  message.AppendAttribute(RTA_TABLE, &table, sizeof(table));

  // RTA_OIF is the target interface for this rule.
  message.AppendAttribute(RTA_OIF, &interface_index, sizeof(interface_index));
  // The actual destination subnet must be truncated of all the tailing zeros.
  message.AppendAttribute(
      RTA_DST,
      reinterpret_cast<const void*>(
          destination_subnet.prefix().ToPackedString().c_str()),
      destination_subnet.prefix().ToPackedString().size());
  // This is the source address to use in the IP packet should this routing rule
  // is used.
  if (preferred_source.IsInitialized()) {
    auto src_str = preferred_source.ToPackedString();
    message.AppendAttribute(RTA_PREFSRC,
                            reinterpret_cast<const void*>(src_str.c_str()),
                            src_str.size());
  }

  if (verb != Verb::kRemove) {
    auto gateway_str = QboneConstants::GatewayAddress()->ToPackedString();
    message.AppendAttribute(RTA_GATEWAY,
                            reinterpret_cast<const void*>(gateway_str.c_str()),
                            gateway_str.size());
  }

  if (!Send(message.BuildIoVec().get(), message.IoVecSize())) {
    QUIC_LOG(ERROR) << "send failed";
    return false;
  }

  UnknownParser parser;
  if (!Recv(seq_++, &parser)) {
    QUIC_LOG(ERROR) << "receive failed.";
    return false;
  }
  return true;
}

namespace {

class IpRuleParser : public NetlinkParserInterface {
 public:
  explicit IpRuleParser(std::vector<Netlink::IpRule>* ip_rules)
      : ip_rules_(ip_rules) {}

  void Run(struct nlmsghdr* netlink_message) override {
    if (netlink_message->nlmsg_type != RTM_NEWRULE) {
      QUIC_LOG(WARNING) << absl::StrCat(
          "Unexpected nlmsg_type: ", netlink_message->nlmsg_type,
          " expected: ", RTM_NEWRULE);
      return;
    }

    auto* rule = reinterpret_cast<rtmsg*>(NLMSG_DATA(netlink_message));
    int payload_length = RTM_PAYLOAD(netlink_message);

    if (rule->rtm_family != AF_INET6) {
      QUIC_LOG(ERROR) << absl::StrCat("Unexpected family: ", rule->rtm_family);
      return;
    }

    Netlink::IpRule ip_rule;
    ip_rule.table = rule->rtm_table;

    struct rtattr* rta;
    for (rta = RTM_RTA(rule); RTA_OK(rta, payload_length);
         rta = RTA_NEXT(rta, payload_length)) {
      switch (rta->rta_type) {
        case RTA_TABLE: {
          ip_rule.table = *reinterpret_cast<uint32_t*>(RTA_DATA(rta));
          break;
        }
        case RTA_SRC: {
          QuicIpAddress src_addr;
          src_addr.FromPackedString(reinterpret_cast<char*>(RTA_DATA(rta)),
                                    RTA_PAYLOAD(rta));
          IpRange src_range(src_addr, rule->rtm_src_len);
          ip_rule.source_range = src_range;
          break;
        }
        default: {
          QUIC_VLOG(2) << absl::StrCat("Uninteresting attribute: ",
                                       rta->rta_type);
        }
      }
    }
    ip_rules_->emplace_back(ip_rule);
  }

 private:
  std::vector<Netlink::IpRule>* ip_rules_;
};

}  // namespace

bool Netlink::GetRuleInfo(std::vector<Netlink::IpRule>* ip_rules) {
  rtmsg rule_message{};
  rule_message.rtm_family = AF_INET6;

  auto message = RuleMessage::New(RtnetlinkMessage::Operation::GET,
                                  NLM_F_REQUEST | NLM_F_DUMP, seq_, getpid(),
                                  &rule_message);

  if (!Send(message.BuildIoVec().get(), message.IoVecSize())) {
    QUIC_LOG(ERROR) << "send failed";
    return false;
  }

  IpRuleParser parser(ip_rules);
  if (!Recv(seq_++, &parser)) {
    QUIC_LOG(ERROR) << "receive failed.";
    return false;
  }
  return true;
}

bool Netlink::ChangeRule(Verb verb, uint32_t table, IpRange source_range) {
  RtnetlinkMessage::Operation operation;
  uint16_t flags = NLM_F_REQUEST | NLM_F_ACK;

  rtmsg rule_message{};
  rule_message.rtm_family = AF_INET6;
  rule_message.rtm_protocol = RTPROT_STATIC;
  rule_message.rtm_scope = RT_SCOPE_UNIVERSE;
  rule_message.rtm_table = RT_TABLE_UNSPEC;

  rule_message.rtm_flags |= FIB_RULE_FIND_SADDR;

  switch (verb) {
    case Verb::kAdd:
      if (!source_range.IsInitialized()) {
        QUIC_LOG(ERROR) << "Source range must be initialized.";
        return false;
      }
      operation = RtnetlinkMessage::Operation::NEW;
      flags |= NLM_F_EXCL | NLM_F_CREATE;
      rule_message.rtm_type = FRA_DST;
      rule_message.rtm_src_len = source_range.prefix_length();
      break;
    case Verb::kRemove:
      operation = RtnetlinkMessage::Operation::DEL;
      break;
    case Verb::kReplace:
      QUIC_LOG(ERROR) << "Unsupported verb: kReplace";
      return false;
  }
  auto message =
      RuleMessage::New(operation, flags, seq_, getpid(), &rule_message);

  message.AppendAttribute(RTA_TABLE, &table, sizeof(table));

  if (source_range.IsInitialized()) {
    std::string packed_src = source_range.prefix().ToPackedString();
    message.AppendAttribute(RTA_SRC,
                            reinterpret_cast<const void*>(packed_src.c_str()),
                            packed_src.size());
  }

  if (!Send(message.BuildIoVec().get(), message.IoVecSize())) {
    QUIC_LOG(ERROR) << "send failed";
    return false;
  }

  UnknownParser parser;
  if (!Recv(seq_++, &parser)) {
    QUIC_LOG(ERROR) << "receive failed.";
    return false;
  }
  return true;
}

bool Netlink::Send(struct iovec* iov, size_t iovlen) {
  if (!OpenSocket()) {
    QUIC_LOG(ERROR) << "can't open socket";
    return false;
  }

  // an address for communicating with the kernel netlink code
  sockaddr_nl netlink_address;
  memset(&netlink_address, 0, sizeof(netlink_address));
  netlink_address.nl_family = AF_NETLINK;
  netlink_address.nl_pid = 0;     // destination is kernel
  netlink_address.nl_groups = 0;  // no multicast

  struct msghdr msg = {
      &netlink_address, sizeof(netlink_address), iov, iovlen, nullptr, 0, 0};

  if (kernel_->sendmsg(socket_fd_, &msg, 0) < 0) {
    QUIC_LOG(ERROR) << "sendmsg failed";
    CloseSocket();
    return false;
  }

  return true;
}

bool Netlink::Recv(uint32_t seq, NetlinkParserInterface* parser) {
  sockaddr_nl netlink_address;

  // replies can span multiple packets
  for (;;) {
    socklen_t address_length = sizeof(netlink_address);

    // First, call recvfrom with buffer size of 0 and MSG_PEEK | MSG_TRUNC set
    // so that we know the size of the incoming packet before actually receiving
    // it.
    int next_packet_size = kernel_->recvfrom(
        socket_fd_, recvbuf_.get(), /* len = */ 0, MSG_PEEK | MSG_TRUNC,
        reinterpret_cast<struct sockaddr*>(&netlink_address), &address_length);
    if (next_packet_size < 0) {
      QUIC_LOG(ERROR)
          << "error recvfrom with MSG_PEEK | MSG_TRUNC to get packet length.";
      CloseSocket();
      return false;
    }
    QUIC_VLOG(3) << "netlink packet size: " << next_packet_size;
    if (next_packet_size > recvbuf_length_) {
      QUIC_VLOG(2) << "resizing recvbuf to " << next_packet_size;
      ResetRecvBuf(next_packet_size);
    }

    // Get the packet for real.
    memset(recvbuf_.get(), 0, recvbuf_length_);
    int len = kernel_->recvfrom(
        socket_fd_, recvbuf_.get(), recvbuf_length_, /* flags = */ 0,
        reinterpret_cast<struct sockaddr*>(&netlink_address), &address_length);
    QUIC_VLOG(3) << "recvfrom returned: " << len;
    if (len < 0) {
      QUIC_LOG(INFO) << "can't receive netlink packet";
      CloseSocket();
      return false;
    }

    // there may be multiple nlmsg's in each reply packet
    struct nlmsghdr* netlink_message;
    for (netlink_message = reinterpret_cast<struct nlmsghdr*>(recvbuf_.get());
         NLMSG_OK(netlink_message, len);
         netlink_message = NLMSG_NEXT(netlink_message, len)) {
      QUIC_VLOG(3) << "netlink_message->nlmsg_type = "
                   << netlink_message->nlmsg_type;
      // make sure this is to us
      if (netlink_message->nlmsg_seq != seq) {
        QUIC_LOG(INFO) << "netlink_message not meant for us."
                       << " seq: " << seq
                       << " nlmsg_seq: " << netlink_message->nlmsg_seq;
        continue;
      }

      // done with this whole reply (not just this particular packet)
      if (netlink_message->nlmsg_type == NLMSG_DONE) {
        return true;
      }
      if (netlink_message->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr* err =
            reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(netlink_message));
        if (netlink_message->nlmsg_len <
            NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
          QUIC_LOG(INFO) << "netlink_message ERROR truncated";
        } else {
          // an ACK
          if (err->error == 0) {
            QUIC_VLOG(3) << "Netlink sent an ACK";
            return true;
          }
          QUIC_LOG(INFO) << "netlink_message ERROR: " << err->error;
        }
        return false;
      }

      parser->Run(netlink_message);
    }
  }
}

}  // namespace quic

"""

```