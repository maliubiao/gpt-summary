Response:
Let's break down the thought process for analyzing this C++ test file and generating the comprehensive response.

**1. Understanding the Goal:**

The request asks for an analysis of a specific Chromium network stack test file (`netlink_test.cc`). The core tasks are:

* **Functionality Summary:**  What does this test file do?
* **JavaScript Relevance:** Does it relate to JavaScript, and how?
* **Logical Reasoning (with examples):** Show how the tests work with hypothetical inputs and outputs.
* **Common Usage Errors:** Identify potential mistakes users/programmers could make.
* **Debugging Clues:** Explain how a developer might end up looking at this file during debugging.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for key terms and patterns:

* **Includes:** `netlink.h`, `<sys/socket.h>`, `<netinet/in.h>`, etc. These point to system-level network interaction.
* **Namespaces:** `quic::test`, `testing::`. Indicates this is a unit test within the QUIC library.
* **Classes:** `NetlinkTest`, `MockKernel`. Suggests testing the `Netlink` class by mocking kernel behavior.
* **`TEST_F` macros:**  Clearly define individual test cases.
* **`ExpectNetlinkPacket` function:** A central helper for simulating Netlink interactions.
* **Netlink message structures:** `nlmsghdr`, `ifinfomsg`, `ifaddrmsg`, `rtmsg`, `rtattr`. These are the core data structures for Netlink communication.
* **Netlink constants:** `RTM_GETLINK`, `RTM_NEWADDR`, `RTM_DELADDR`, `RTM_GETROUTE`, `RTM_NEWROUTE`, `RTM_DELROUTE`, `NLM_F_ACK`, etc. These define the types of Netlink messages being tested.
* **IP Address manipulation:**  `QuicIpAddress`, `IpRange`.
* **Assertions:** `EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_THAT`, `ASSERT_EQ`.

**3. Deeper Dive into `NetlinkTest` and `ExpectNetlinkPacket`:**

* **`NetlinkTest`:** The constructor sets up a default behavior for `socket()` which involves an immediate `close()`. This is a common pattern for resource management in tests.
* **`ExpectNetlinkPacket`:** This is the heart of the test setup. It does the following:
    * **Sets up expectations for `sendmsg`:**  Checks that the correct Netlink message type, flags, and structure are sent. It also allows for a custom `send_callback` to inspect the sent data.
    * **Sets up expectations for `recvfrom` (peek):** Simulates the kernel's response by invoking a `recv_callback` to populate `reply_packet_`. The `MSG_PEEK | MSG_TRUNC` is crucial for simulating the kernel providing the message size first.
    * **Sets up expectations for `recvfrom` (actual receive):**  Simulates the actual reception of the kernel's response.

**4. Analyzing Individual Test Cases (Example: `GetLinkInfoWorks`)**

* **Goal:** Verify that `Netlink::GetLinkInfo` correctly retrieves interface information.
* **Setup:** Calls `ExpectNetlinkPacket` to simulate a `RTM_GETLINK` request and a `RTM_NEWLINK` response containing interface details.
* **Response Simulation:** The `recv_callback` within `ExpectNetlinkPacket` crafts a fake Netlink response with specific hardware and broadcast addresses, interface index, and type.
* **Verification:**  Calls `netlink->GetLinkInfo` and asserts that the returned `link_info` struct contains the expected values.

**5. Identifying JavaScript Relevance:**

The core of this test file deals with low-level network interactions through Netlink sockets. JavaScript, especially in web browsers, typically operates at a much higher level of abstraction. The connection is indirect:

* **Underlying Network Stack:** The Chromium network stack (including the QUIC implementation) is written in C++. JavaScript's network requests (e.g., `fetch`, `XMLHttpRequest`, WebSockets) eventually rely on this underlying stack.
* **OS Interaction:** Netlink is a Linux-specific mechanism. While browsers run on various operating systems, understanding how the network stack interacts with the OS (like through Netlink on Linux) is crucial for cross-platform consistency and debugging.
* **No Direct Mapping:**  There's no direct JavaScript API that exposes Netlink.

**6. Developing Logical Reasoning Examples:**

For each test case, consider:

* **Hypothetical Input:** What parameters are passed to the `Netlink` class methods?
* **Simulated Kernel Response:**  What data is crafted in the `recv_callback` within `ExpectNetlinkPacket`?
* **Expected Output:** What are the expected values or side effects after calling the `Netlink` method?

**7. Brainstorming Common Usage Errors:**

Think about mistakes developers might make when interacting with a `Netlink` abstraction:

* **Incorrect Interface Names:**  Typos or incorrect assumptions about interface names.
* **Incorrect Flags:**  Misunderstanding or misuse of Netlink flags.
* **Incorrect IP Address Formats:** Errors in string representations of IP addresses.
* **Incorrect Subnet Masks:**  Mistakes in defining network prefixes.
* **Insufficient Permissions:**  Netlink operations often require root privileges.

**8. Tracing User Operations to the Test:**

Think about the chain of events that might lead a developer to examine this test file:

* **User reports network issues:**  Slow connections, connection failures, routing problems.
* **Developer investigates QUIC:**  Since the file is in the QUIC directory, issues with QUIC connections are a primary suspect.
* **Suspecting OS-level issues:**  If higher-level QUIC logic seems correct, the developer might suspect problems with how QUIC interacts with the operating system's networking.
* **Looking at Netlink interaction:** Netlink is a key interface for managing network configurations on Linux, so the `netlink_test.cc` file becomes relevant for verifying this interaction.

**9. Structuring the Response:**

Organize the information logically with clear headings and bullet points. Provide code snippets where relevant to illustrate points. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Maybe there's a JavaScript library that uses Netlink under the hood."  **Correction:** While theoretically possible, it's highly unlikely for standard web browser JavaScript due to security and platform dependencies. Focus on the indirect relationship through the C++ network stack.
* **Initial thought:**  "Just describe what each individual test does." **Refinement:**  Group related tests by functionality (e.g., getting link info, managing addresses, managing routes) for a more cohesive explanation.
* **Initial thought:**  "Just list the Netlink message types." **Refinement:** Briefly explain the *purpose* of those message types in the context of the tests.

By following this structured approach, combining code analysis with domain knowledge of networking and testing practices, a comprehensive and accurate answer can be generated.
这个文件 `net/third_party/quiche/src/quiche/quic/qbone/platform/netlink_test.cc` 是 Chromium 网络栈中 QUIC (Quick UDP Internet Connections) 协议的 QBONE (QUIC Bone) 组件的一部分，专门用于测试 `netlink.h` 中定义的 Netlink 接口的功能。Netlink 是 Linux 内核与用户空间进程通信的一种方式，常用于网络配置和管理。

**功能总结:**

这个测试文件的主要功能是：

1. **测试 Netlink 接口的封装:**  `netlink.h` 中很可能定义了一个 C++ 类或一组函数，用于简化与 Netlink 套接字的交互。这个测试文件验证了这个封装层的正确性，确保它能够正确地构造、发送和解析 Netlink 消息。

2. **模拟 Netlink 通信:**  测试使用了 `MockKernel` 来模拟 Linux 内核的行为，避免了在实际环境中进行网络配置更改的风险，同时也使得测试更加可控和可预测。

3. **验证 Netlink 消息的发送和接收:**  测试用例会模拟发送各种 Netlink 请求（例如获取链路信息、地址信息、路由信息），并验证发送的请求消息的格式是否正确。同时，它也会模拟接收来自内核的 Netlink 响应，并验证接收到的响应消息是否符合预期。

4. **测试特定的 Netlink 操作:**  测试文件中包含了针对特定 Netlink 操作的测试用例，例如：
    * 获取网络接口的链路信息 (`GetLinkInfoWorks`)
    * 获取网络接口的地址信息 (`GetAddressesWorks`)
    * 添加和删除本地地址 (`ChangeLocalAddressAdd`, `ChangeLocalAddressRemove`)
    * 获取路由信息 (`GetRouteInfoWorks`)
    * 添加、删除和替换路由 (`ChangeRouteAdd`, `ChangeRouteRemove`, `ChangeRouteReplace`)

**与 JavaScript 功能的关系:**

这个 C++ 测试文件直接与 JavaScript 功能没有直接关系。然而，它间接地支撑着基于 Chromium 的浏览器或 Node.js 应用中的网络功能：

* **底层网络支撑:**  QUIC 协议是现代网络通信的重要组成部分，旨在提供更快、更可靠的连接。JavaScript 代码（例如使用 `fetch` API 或 WebSocket）发起的网络请求，在底层会经过 Chromium 的网络栈处理，其中可能包括 QBONE 组件。
* **网络配置影响:**  `netlink_test.cc` 测试的代码负责与操作系统内核进行网络配置交互。网络配置（例如 IP 地址、路由）的正确性直接影响着 JavaScript 发起的网络请求能否成功。
* **没有直接的 JavaScript API:**  JavaScript 自身并没有直接操作 Netlink 套接字的 API。Netlink 是一个操作系统级别的概念，通常在内核或系统级程序中使用。

**举例说明 (间接关系):**

假设一个基于 Chromium 的浏览器中的 JavaScript 代码尝试连接到一个特定的服务器：

```javascript
fetch('https://example.com')
  .then(response => response.text())
  .then(data => console.log(data));
```

当执行这段 JavaScript 代码时，浏览器底层会进行一系列操作，其中可能包括：

1. **域名解析:**  将 `example.com` 解析为 IP 地址。
2. **路由查找:**  确定到达目标 IP 地址的最佳路由。这个过程可能涉及到查询操作系统的路由表，而 `netlink_test.cc` 测试的代码正是为了确保与操作系统交互获取路由信息的功能是正确的。
3. **建立连接:**  通过 TCP 或 QUIC 协议与服务器建立连接。如果使用的是 QUIC，那么 QBONE 组件可能会参与其中。
4. **数据传输:**  发送 HTTP 请求并接收响应。

如果 `netlink_test.cc` 中测试的 Netlink 交互部分存在问题，例如无法正确获取路由信息，那么 JavaScript 发起的 `fetch` 请求可能无法找到正确的路径到达服务器，导致连接失败。

**逻辑推理 (假设输入与输出):**

以 `TEST_F(NetlinkTest, GetLinkInfoWorks)` 为例：

**假设输入:**

* 调用 `netlink->GetLinkInfo("tun0", &link_info)`，尝试获取名为 "tun0" 的网络接口的链路信息。

**模拟的内核响应 (通过 `ExpectNetlinkPacket` 设置):**

* 内核通过 Netlink 返回一个 `RTM_NEWLINK` 消息，包含以下信息：
    * 接口名称: "tun0"
    * 接口索引: 7
    * 接口类型: 1
    * 硬件地址: `{'a', 'b', 'c', 'd', 'e', 'f'}`
    * 广播地址: `{'c', 'b', 'a', 'f', 'e', 'd'}`

**预期输出:**

* `netlink->GetLinkInfo` 函数返回 `true`，表示获取成功。
* `link_info` 结构体中的字段被正确填充：
    * `link_info.index` 等于 7
    * `link_info.type` 等于 1
    * `link_info.hardware_address` 的前 6 个字节分别为 'a', 'b', 'c', 'd', 'e', 'f'
    * `link_info.broadcast_address` 的前 6 个字节分别为 'c', 'b', 'a', 'f', 'e', 'd'

**用户或编程常见的使用错误:**

1. **错误的接口名称:**  如果用户在调用 `GetLinkInfo` 时传递了错误的接口名称（例如 "tun1" 而实际上不存在），测试可能会失败，因为它依赖于模拟的内核返回特定接口的信息。

   ```c++
   // 错误的使用：假设没有名为 "invalid_interface" 的接口
   Netlink::LinkInfo link_info;
   EXPECT_FALSE(netlink->GetLinkInfo("invalid_interface", &link_info));
   ```

2. **对 Netlink 消息结构的理解不足:**  在自定义 Netlink 操作或扩展现有功能时，开发者可能对 Netlink 消息的结构（例如 `nlmsghdr`, `rtattr` 等）理解不足，导致构造或解析消息时出现错误。测试用例通过提供正确的消息结构示例，帮助开发者理解和避免这些错误.

3. **权限问题:**  某些 Netlink 操作（例如修改路由表）需要 root 权限。如果在非 root 权限下运行依赖这些功能的代码，可能会导致操作失败。测试环境通过模拟内核行为来规避了权限问题，但在实际部署中需要注意。

**用户操作到达这里的调试线索:**

一个开发者可能会因为以下原因而查看 `netlink_test.cc` 文件作为调试线索：

1. **QUIC 连接问题:** 用户报告了基于 QUIC 的连接不稳定、速度慢或无法建立。开发者可能会怀疑是底层的网络配置或 QBONE 组件的 Netlink 交互出现了问题。

2. **网络配置错误:**  开发者在配置网络时遇到问题，例如路由配置不生效，或者接口信息获取不正确。他们可能会查看 QBONE 组件中与 Netlink 交互的部分，以确定是否是 QBONE 代码导致的配置问题。

3. **QBone 功能异常:**  如果 QBONE 的特定功能（例如流量整形、路径选择等）出现异常，开发者可能会查看与 Netlink 交互相关的测试用例，以验证底层的网络信息获取和配置操作是否正常。

**用户操作步骤示例 (导致调试 `GetRouteInfoWorks`):**

1. **用户报告:**  用户在使用基于 Chromium 的应用程序时，发现某些网络流量没有按照预期路由到特定的网络接口。
2. **开发者初步排查:**  开发者检查了应用程序的网络配置和 QUIC 连接参数，但没有发现明显的问题。
3. **怀疑路由问题:**  开发者怀疑是底层的路由配置出现了问题，导致数据包没有走正确的路径。
4. **查看 QBONE 代码:**  由于问题可能与 QUIC 的路由管理有关，开发者开始查看 QBONE 组件的代码。
5. **定位到 Netlink 交互:**  开发者发现 QBONE 组件使用 Netlink 与内核交互来获取和管理路由信息。
6. **查看测试用例:**  为了理解 QBONE 如何使用 Netlink 获取路由信息，开发者查看了 `netlink_test.cc` 文件中的 `GetRouteInfoWorks` 测试用例，了解了测试代码如何模拟内核返回路由信息，以及验证 QBONE 代码的正确性。

总而言之，`netlink_test.cc` 是一个重要的测试文件，它确保了 Chromium 网络栈中 QBONE 组件与 Linux 内核的网络配置接口（Netlink）能够正确可靠地工作，从而间接地保障了基于 Chromium 的应用程序的网络功能正常运行。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/qbone/platform/netlink_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/qbone/platform/netlink.h"

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/node_hash_set.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/qbone/platform/mock_kernel.h"
#include "quiche/quic/qbone/qbone_constants.h"

namespace quic::test {
namespace {

using ::testing::_;
using ::testing::Contains;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::Unused;

const int kSocketFd = 101;

class NetlinkTest : public QuicTest {
 protected:
  NetlinkTest() {
    ON_CALL(mock_kernel_, socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE))
        .WillByDefault(Invoke([this](Unused, Unused, Unused) {
          EXPECT_CALL(mock_kernel_, close(kSocketFd)).WillOnce(Return(0));
          return kSocketFd;
        }));
  }

  void ExpectNetlinkPacket(
      uint16_t type, uint16_t flags,
      const std::function<ssize_t(void* buf, size_t len, int seq)>&
          recv_callback,
      const std::function<void(const void* buf, size_t len)>& send_callback =
          nullptr) {
    static int seq = -1;
    InSequence s;

    EXPECT_CALL(mock_kernel_, sendmsg(kSocketFd, _, _))
        .WillOnce(Invoke([type, flags, send_callback](
                             Unused, const struct msghdr* msg, int) {
          EXPECT_EQ(sizeof(struct sockaddr_nl), msg->msg_namelen);
          auto* nl_addr =
              reinterpret_cast<const struct sockaddr_nl*>(msg->msg_name);
          EXPECT_EQ(AF_NETLINK, nl_addr->nl_family);
          EXPECT_EQ(0, nl_addr->nl_pid);
          EXPECT_EQ(0, nl_addr->nl_groups);

          EXPECT_GE(msg->msg_iovlen, 1);
          EXPECT_GE(msg->msg_iov[0].iov_len, sizeof(struct nlmsghdr));

          std::string buf;
          for (int i = 0; i < msg->msg_iovlen; i++) {
            buf.append(
                std::string(reinterpret_cast<char*>(msg->msg_iov[i].iov_base),
                            msg->msg_iov[i].iov_len));
          }

          auto* netlink_message =
              reinterpret_cast<const struct nlmsghdr*>(buf.c_str());
          EXPECT_EQ(type, netlink_message->nlmsg_type);
          EXPECT_EQ(flags, netlink_message->nlmsg_flags);
          EXPECT_GE(buf.size(), netlink_message->nlmsg_len);

          if (send_callback != nullptr) {
            send_callback(buf.c_str(), buf.size());
          }

          QUICHE_CHECK_EQ(seq, -1);
          seq = netlink_message->nlmsg_seq;
          return buf.size();
        }));

    EXPECT_CALL(mock_kernel_,
                recvfrom(kSocketFd, _, 0, MSG_PEEK | MSG_TRUNC, _, _))
        .WillOnce(Invoke([this, recv_callback](Unused, Unused, Unused, Unused,
                                               struct sockaddr* src_addr,
                                               socklen_t* addrlen) {
          auto* nl_addr = reinterpret_cast<struct sockaddr_nl*>(src_addr);
          nl_addr->nl_family = AF_NETLINK;
          nl_addr->nl_pid = 0;     // from kernel
          nl_addr->nl_groups = 0;  // no multicast

          int ret = recv_callback(reply_packet_, sizeof(reply_packet_), seq);
          QUICHE_CHECK_LE(ret, sizeof(reply_packet_));
          return ret;
        }));

    EXPECT_CALL(mock_kernel_, recvfrom(kSocketFd, _, _, _, _, _))
        .WillOnce(Invoke([recv_callback](Unused, void* buf, size_t len, Unused,
                                         struct sockaddr* src_addr,
                                         socklen_t* addrlen) {
          auto* nl_addr = reinterpret_cast<struct sockaddr_nl*>(src_addr);
          nl_addr->nl_family = AF_NETLINK;
          nl_addr->nl_pid = 0;     // from kernel
          nl_addr->nl_groups = 0;  // no multicast

          int ret = recv_callback(buf, len, seq);
          EXPECT_GE(len, ret);
          seq = -1;
          return ret;
        }));
  }

  char reply_packet_[4096];
  MockKernel mock_kernel_;
};

void AddRTA(struct nlmsghdr* netlink_message, uint16_t type, const void* data,
            size_t len) {
  auto* next_header_ptr = reinterpret_cast<char*>(netlink_message) +
                          NLMSG_ALIGN(netlink_message->nlmsg_len);

  auto* rta = reinterpret_cast<struct rtattr*>(next_header_ptr);
  rta->rta_type = type;
  rta->rta_len = RTA_LENGTH(len);
  memcpy(RTA_DATA(rta), data, len);

  netlink_message->nlmsg_len =
      NLMSG_ALIGN(netlink_message->nlmsg_len) + RTA_LENGTH(len);
}

void CreateIfinfomsg(struct nlmsghdr* netlink_message,
                     const std::string& interface_name, uint16_t type,
                     int index, unsigned int flags, unsigned int change,
                     uint8_t address[], int address_len, uint8_t broadcast[],
                     int broadcast_len) {
  auto* interface_info =
      reinterpret_cast<struct ifinfomsg*>(NLMSG_DATA(netlink_message));
  interface_info->ifi_family = AF_UNSPEC;
  interface_info->ifi_type = type;
  interface_info->ifi_index = index;
  interface_info->ifi_flags = flags;
  interface_info->ifi_change = change;
  netlink_message->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));

  // Add address
  AddRTA(netlink_message, IFLA_ADDRESS, address, address_len);

  // Add broadcast address
  AddRTA(netlink_message, IFLA_BROADCAST, broadcast, broadcast_len);

  // Add name
  AddRTA(netlink_message, IFLA_IFNAME, interface_name.c_str(),
         interface_name.size());
}

struct nlmsghdr* CreateNetlinkMessage(void* buf,  // NOLINT
                                      struct nlmsghdr* previous_netlink_message,
                                      uint16_t type, int seq) {
  auto* next_header_ptr = reinterpret_cast<char*>(buf);
  if (previous_netlink_message != nullptr) {
    next_header_ptr = reinterpret_cast<char*>(previous_netlink_message) +
                      NLMSG_ALIGN(previous_netlink_message->nlmsg_len);
  }
  auto* netlink_message = reinterpret_cast<nlmsghdr*>(next_header_ptr);
  netlink_message->nlmsg_len = NLMSG_LENGTH(0);
  netlink_message->nlmsg_type = type;
  netlink_message->nlmsg_flags = NLM_F_MULTI;
  netlink_message->nlmsg_pid = 0;  // from the kernel
  netlink_message->nlmsg_seq = seq;

  return netlink_message;
}

void CreateIfaddrmsg(struct nlmsghdr* nlm, int interface_index,
                     unsigned char prefixlen, unsigned char flags,
                     unsigned char scope, QuicIpAddress ip) {
  QUICHE_CHECK(ip.IsInitialized());
  unsigned char family;
  switch (ip.address_family()) {
    case IpAddressFamily::IP_V4:
      family = AF_INET;
      break;
    case IpAddressFamily::IP_V6:
      family = AF_INET6;
      break;
    default:
      QUIC_BUG(quic_bug_11034_1)
          << absl::StrCat("unexpected address family: ", ip.address_family());
      family = AF_UNSPEC;
  }
  auto* msg = reinterpret_cast<struct ifaddrmsg*>(NLMSG_DATA(nlm));
  msg->ifa_family = family;
  msg->ifa_prefixlen = prefixlen;
  msg->ifa_flags = flags;
  msg->ifa_scope = scope;
  msg->ifa_index = interface_index;
  nlm->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));

  // Add local address
  AddRTA(nlm, IFA_LOCAL, ip.ToPackedString().c_str(),
         ip.ToPackedString().size());
}

void CreateRtmsg(struct nlmsghdr* nlm, unsigned char family,
                 unsigned char destination_length, unsigned char source_length,
                 unsigned char tos, unsigned char table, unsigned char protocol,
                 unsigned char scope, unsigned char type, unsigned int flags,
                 QuicIpAddress destination, int interface_index) {
  auto* msg = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(nlm));
  msg->rtm_family = family;
  msg->rtm_dst_len = destination_length;
  msg->rtm_src_len = source_length;
  msg->rtm_tos = tos;
  msg->rtm_table = table;
  msg->rtm_protocol = protocol;
  msg->rtm_scope = scope;
  msg->rtm_type = type;
  msg->rtm_flags = flags;
  nlm->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));

  // Add destination
  AddRTA(nlm, RTA_DST, destination.ToPackedString().c_str(),
         destination.ToPackedString().size());

  // Add egress interface
  AddRTA(nlm, RTA_OIF, &interface_index, sizeof(interface_index));
}

TEST_F(NetlinkTest, GetLinkInfoWorks) {
  auto netlink = std::make_unique<Netlink>(&mock_kernel_);

  uint8_t hwaddr[] = {'a', 'b', 'c', 'd', 'e', 'f'};
  uint8_t bcaddr[] = {'c', 'b', 'a', 'f', 'e', 'd'};

  ExpectNetlinkPacket(
      RTM_GETLINK, NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST,
      [&hwaddr, &bcaddr](void* buf, size_t len, int seq) {
        int ret = 0;

        struct nlmsghdr* netlink_message =
            CreateNetlinkMessage(buf, nullptr, RTM_NEWLINK, seq);
        CreateIfinfomsg(netlink_message, "tun0", /* type = */ 1,
                        /* index = */ 7,
                        /* flags = */ 0,
                        /* change = */ 0xFFFFFFFF, hwaddr, 6, bcaddr, 6);
        ret += NLMSG_ALIGN(netlink_message->nlmsg_len);

        netlink_message =
            CreateNetlinkMessage(buf, netlink_message, NLMSG_DONE, seq);
        ret += NLMSG_ALIGN(netlink_message->nlmsg_len);

        return ret;
      });

  Netlink::LinkInfo link_info;
  EXPECT_TRUE(netlink->GetLinkInfo("tun0", &link_info));

  EXPECT_EQ(7, link_info.index);
  EXPECT_EQ(1, link_info.type);

  for (int i = 0; i < link_info.hardware_address_length; ++i) {
    EXPECT_EQ(hwaddr[i], link_info.hardware_address[i]);
  }
  for (int i = 0; i < link_info.broadcast_address_length; ++i) {
    EXPECT_EQ(bcaddr[i], link_info.broadcast_address[i]);
  }
}

TEST_F(NetlinkTest, GetAddressesWorks) {
  auto netlink = std::make_unique<Netlink>(&mock_kernel_);

  absl::node_hash_set<std::string> addresses = {
      QuicIpAddress::Any4().ToString(), QuicIpAddress::Any6().ToString()};

  ExpectNetlinkPacket(
      RTM_GETADDR, NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST,
      [&addresses](void* buf, size_t len, int seq) {
        int ret = 0;

        struct nlmsghdr* nlm = nullptr;

        for (const auto& address : addresses) {
          QuicIpAddress ip;
          ip.FromString(address);
          nlm = CreateNetlinkMessage(buf, nlm, RTM_NEWADDR, seq);
          CreateIfaddrmsg(nlm, /* interface_index = */ 7, /* prefixlen = */ 24,
                          /* flags = */ 0, /* scope = */ RT_SCOPE_UNIVERSE, ip);

          ret += NLMSG_ALIGN(nlm->nlmsg_len);
        }

        // Create IPs with unwanted flags.
        {
          QuicIpAddress ip;
          ip.FromString("10.0.0.1");
          nlm = CreateNetlinkMessage(buf, nlm, RTM_NEWADDR, seq);
          CreateIfaddrmsg(nlm, /* interface_index = */ 7, /* prefixlen = */ 16,
                          /* flags = */ IFA_F_OPTIMISTIC, /* scope = */
                          RT_SCOPE_UNIVERSE, ip);

          ret += NLMSG_ALIGN(nlm->nlmsg_len);

          ip.FromString("10.0.0.2");
          nlm = CreateNetlinkMessage(buf, nlm, RTM_NEWADDR, seq);
          CreateIfaddrmsg(nlm, /* interface_index = */ 7, /* prefixlen = */ 16,
                          /* flags = */ IFA_F_TENTATIVE, /* scope = */
                          RT_SCOPE_UNIVERSE, ip);

          ret += NLMSG_ALIGN(nlm->nlmsg_len);
        }

        nlm = CreateNetlinkMessage(buf, nlm, NLMSG_DONE, seq);
        ret += NLMSG_ALIGN(nlm->nlmsg_len);

        return ret;
      });

  std::vector<Netlink::AddressInfo> reported_addresses;
  int num_ipv6_nodad_dadfailed_addresses = 0;
  EXPECT_TRUE(netlink->GetAddresses(7, IFA_F_TENTATIVE | IFA_F_OPTIMISTIC,
                                    &reported_addresses,
                                    &num_ipv6_nodad_dadfailed_addresses));

  for (const auto& reported_address : reported_addresses) {
    EXPECT_TRUE(reported_address.local_address.IsInitialized());
    EXPECT_FALSE(reported_address.interface_address.IsInitialized());
    EXPECT_THAT(addresses, Contains(reported_address.local_address.ToString()));
    addresses.erase(reported_address.local_address.ToString());

    EXPECT_EQ(24, reported_address.prefix_length);
  }

  EXPECT_TRUE(addresses.empty());
}

TEST_F(NetlinkTest, ChangeLocalAddressAdd) {
  auto netlink = std::make_unique<Netlink>(&mock_kernel_);

  QuicIpAddress ip = QuicIpAddress::Any6();
  ExpectNetlinkPacket(
      RTM_NEWADDR, NLM_F_ACK | NLM_F_REQUEST,
      [](void* buf, size_t len, int seq) {
        struct nlmsghdr* netlink_message =
            CreateNetlinkMessage(buf, nullptr, NLMSG_ERROR, seq);
        auto* err =
            reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(netlink_message));
        // Ack the request
        err->error = 0;
        netlink_message->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
        return netlink_message->nlmsg_len;
      },
      [ip](const void* buf, size_t len) {
        auto* netlink_message = reinterpret_cast<const struct nlmsghdr*>(buf);
        auto* ifa = reinterpret_cast<const struct ifaddrmsg*>(
            NLMSG_DATA(netlink_message));
        EXPECT_EQ(19, ifa->ifa_prefixlen);
        EXPECT_EQ(RT_SCOPE_UNIVERSE, ifa->ifa_scope);
        EXPECT_EQ(IFA_F_PERMANENT, ifa->ifa_flags);
        EXPECT_EQ(7, ifa->ifa_index);
        EXPECT_EQ(AF_INET6, ifa->ifa_family);

        const struct rtattr* rta;
        int payload_length = IFA_PAYLOAD(netlink_message);
        int num_rta = 0;
        for (rta = IFA_RTA(ifa); RTA_OK(rta, payload_length);
             rta = RTA_NEXT(rta, payload_length)) {
          switch (rta->rta_type) {
            case IFA_LOCAL: {
              EXPECT_EQ(ip.ToPackedString().size(), RTA_PAYLOAD(rta));
              const auto* raw_address =
                  reinterpret_cast<const char*>(RTA_DATA(rta));
              ASSERT_EQ(sizeof(in6_addr), RTA_PAYLOAD(rta));
              QuicIpAddress address;
              address.FromPackedString(raw_address, RTA_PAYLOAD(rta));
              EXPECT_EQ(ip, address);
              break;
            }
            case IFA_CACHEINFO: {
              EXPECT_EQ(sizeof(struct ifa_cacheinfo), RTA_PAYLOAD(rta));
              const auto* cache_info =
                  reinterpret_cast<const struct ifa_cacheinfo*>(RTA_DATA(rta));
              EXPECT_EQ(8, cache_info->ifa_prefered);  // common_typos_disable
              EXPECT_EQ(6, cache_info->ifa_valid);
              EXPECT_EQ(4, cache_info->cstamp);
              EXPECT_EQ(2, cache_info->tstamp);
              break;
            }
            default:
              EXPECT_TRUE(false) << "Seeing rtattr that should not exist";
          }
          ++num_rta;
        }
        EXPECT_EQ(2, num_rta);
      });

  struct {
    struct rtattr rta;
    struct ifa_cacheinfo cache_info;
  } additional_rta;

  additional_rta.rta.rta_type = IFA_CACHEINFO;
  additional_rta.rta.rta_len = RTA_LENGTH(sizeof(struct ifa_cacheinfo));
  additional_rta.cache_info.ifa_prefered = 8;
  additional_rta.cache_info.ifa_valid = 6;
  additional_rta.cache_info.cstamp = 4;
  additional_rta.cache_info.tstamp = 2;

  EXPECT_TRUE(netlink->ChangeLocalAddress(7, Netlink::Verb::kAdd, ip, 19,
                                          IFA_F_PERMANENT, RT_SCOPE_UNIVERSE,
                                          {&additional_rta.rta}));
}

TEST_F(NetlinkTest, ChangeLocalAddressRemove) {
  auto netlink = std::make_unique<Netlink>(&mock_kernel_);

  QuicIpAddress ip = QuicIpAddress::Any4();
  ExpectNetlinkPacket(
      RTM_DELADDR, NLM_F_ACK | NLM_F_REQUEST,
      [](void* buf, size_t len, int seq) {
        struct nlmsghdr* netlink_message =
            CreateNetlinkMessage(buf, nullptr, NLMSG_ERROR, seq);
        auto* err =
            reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(netlink_message));
        // Ack the request
        err->error = 0;
        netlink_message->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
        return netlink_message->nlmsg_len;
      },
      [ip](const void* buf, size_t len) {
        auto* netlink_message = reinterpret_cast<const struct nlmsghdr*>(buf);
        auto* ifa = reinterpret_cast<const struct ifaddrmsg*>(
            NLMSG_DATA(netlink_message));
        EXPECT_EQ(32, ifa->ifa_prefixlen);
        EXPECT_EQ(RT_SCOPE_UNIVERSE, ifa->ifa_scope);
        EXPECT_EQ(0, ifa->ifa_flags);
        EXPECT_EQ(7, ifa->ifa_index);
        EXPECT_EQ(AF_INET, ifa->ifa_family);

        const struct rtattr* rta;
        int payload_length = IFA_PAYLOAD(netlink_message);
        int num_rta = 0;
        for (rta = IFA_RTA(ifa); RTA_OK(rta, payload_length);
             rta = RTA_NEXT(rta, payload_length)) {
          switch (rta->rta_type) {
            case IFA_LOCAL: {
              const auto* raw_address =
                  reinterpret_cast<const char*>(RTA_DATA(rta));
              ASSERT_EQ(sizeof(in_addr), RTA_PAYLOAD(rta));
              QuicIpAddress address;
              address.FromPackedString(raw_address, RTA_PAYLOAD(rta));
              EXPECT_EQ(ip, address);
              break;
            }
            default:
              EXPECT_TRUE(false) << "Seeing rtattr that should not exist";
          }
          ++num_rta;
        }
        EXPECT_EQ(1, num_rta);
      });

  EXPECT_TRUE(netlink->ChangeLocalAddress(7, Netlink::Verb::kRemove, ip, 32, 0,
                                          RT_SCOPE_UNIVERSE, {}));
}

TEST_F(NetlinkTest, GetRouteInfoWorks) {
  auto netlink = std::make_unique<Netlink>(&mock_kernel_);

  QuicIpAddress destination;
  ASSERT_TRUE(destination.FromString("f800::2"));
  ExpectNetlinkPacket(RTM_GETROUTE, NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST,
                      [destination](void* buf, size_t len, int seq) {
                        int ret = 0;
                        struct nlmsghdr* netlink_message = CreateNetlinkMessage(
                            buf, nullptr, RTM_NEWROUTE, seq);
                        CreateRtmsg(netlink_message, AF_INET6, 48, 0, 0,
                                    RT_TABLE_MAIN, RTPROT_STATIC, RT_SCOPE_LINK,
                                    RTN_UNICAST, 0, destination, 7);
                        ret += NLMSG_ALIGN(netlink_message->nlmsg_len);

                        netlink_message = CreateNetlinkMessage(
                            buf, netlink_message, NLMSG_DONE, seq);
                        ret += NLMSG_ALIGN(netlink_message->nlmsg_len);

                        QUIC_LOG(INFO) << "ret: " << ret;
                        return ret;
                      });

  std::vector<Netlink::RoutingRule> routing_rules;
  EXPECT_TRUE(netlink->GetRouteInfo(&routing_rules));

  ASSERT_EQ(1, routing_rules.size());
  EXPECT_EQ(RT_SCOPE_LINK, routing_rules[0].scope);
  EXPECT_EQ(IpRange(destination, 48).ToString(),
            routing_rules[0].destination_subnet.ToString());
  EXPECT_FALSE(routing_rules[0].preferred_source.IsInitialized());
  EXPECT_EQ(7, routing_rules[0].out_interface);
}

TEST_F(NetlinkTest, ChangeRouteAdd) {
  auto netlink = std::make_unique<Netlink>(&mock_kernel_);

  QuicIpAddress preferred_ip;
  preferred_ip.FromString("ff80:dead:beef::1");
  IpRange subnet;
  subnet.FromString("ff80:dead:beef::/48");
  int egress_interface_index = 7;
  ExpectNetlinkPacket(
      RTM_NEWROUTE, NLM_F_ACK | NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
      [](void* buf, size_t len, int seq) {
        struct nlmsghdr* netlink_message =
            CreateNetlinkMessage(buf, nullptr, NLMSG_ERROR, seq);
        auto* err =
            reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(netlink_message));
        // Ack the request
        err->error = 0;
        netlink_message->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
        return netlink_message->nlmsg_len;
      },
      [preferred_ip, subnet, egress_interface_index](const void* buf,
                                                     size_t len) {
        auto* netlink_message = reinterpret_cast<const struct nlmsghdr*>(buf);
        auto* rtm =
            reinterpret_cast<const struct rtmsg*>(NLMSG_DATA(netlink_message));
        EXPECT_EQ(AF_INET6, rtm->rtm_family);
        EXPECT_EQ(48, rtm->rtm_dst_len);
        EXPECT_EQ(0, rtm->rtm_src_len);
        EXPECT_EQ(RT_TABLE_MAIN, rtm->rtm_table);
        EXPECT_EQ(RTPROT_STATIC, rtm->rtm_protocol);
        EXPECT_EQ(RT_SCOPE_LINK, rtm->rtm_scope);
        EXPECT_EQ(RTN_UNICAST, rtm->rtm_type);

        const struct rtattr* rta;
        int payload_length = RTM_PAYLOAD(netlink_message);
        int num_rta = 0;
        for (rta = RTM_RTA(rtm); RTA_OK(rta, payload_length);
             rta = RTA_NEXT(rta, payload_length)) {
          switch (rta->rta_type) {
            case RTA_PREFSRC: {
              const auto* raw_address =
                  reinterpret_cast<const char*>(RTA_DATA(rta));
              ASSERT_EQ(sizeof(struct in6_addr), RTA_PAYLOAD(rta));
              QuicIpAddress address;
              address.FromPackedString(raw_address, RTA_PAYLOAD(rta));
              EXPECT_EQ(preferred_ip, address);
              break;
            }
            case RTA_GATEWAY: {
              const auto* raw_address =
                  reinterpret_cast<const char*>(RTA_DATA(rta));
              ASSERT_EQ(sizeof(struct in6_addr), RTA_PAYLOAD(rta));
              QuicIpAddress address;
              address.FromPackedString(raw_address, RTA_PAYLOAD(rta));
              EXPECT_EQ(*QboneConstants::GatewayAddress(), address);
              break;
            }
            case RTA_OIF: {
              ASSERT_EQ(sizeof(int), RTA_PAYLOAD(rta));
              const auto* interface_index =
                  reinterpret_cast<const int*>(RTA_DATA(rta));
              EXPECT_EQ(egress_interface_index, *interface_index);
              break;
            }
            case RTA_DST: {
              const auto* raw_address =
                  reinterpret_cast<const char*>(RTA_DATA(rta));
              ASSERT_EQ(sizeof(struct in6_addr), RTA_PAYLOAD(rta));
              QuicIpAddress address;
              address.FromPackedString(raw_address, RTA_PAYLOAD(rta));
              EXPECT_EQ(subnet.ToString(),
                        IpRange(address, rtm->rtm_dst_len).ToString());
              break;
            }
            case RTA_TABLE: {
              ASSERT_EQ(*reinterpret_cast<uint32_t*>(RTA_DATA(rta)),
                        QboneConstants::kQboneRouteTableId);
              break;
            }
            default:
              EXPECT_TRUE(false) << "Seeing rtattr that should not be sent";
          }
          ++num_rta;
        }
        EXPECT_EQ(5, num_rta);
      });
  EXPECT_TRUE(netlink->ChangeRoute(
      Netlink::Verb::kAdd, QboneConstants::kQboneRouteTableId, subnet,
      RT_SCOPE_LINK, preferred_ip, egress_interface_index));
}

TEST_F(NetlinkTest, ChangeRouteRemove) {
  auto netlink = std::make_unique<Netlink>(&mock_kernel_);

  QuicIpAddress preferred_ip;
  preferred_ip.FromString("ff80:dead:beef::1");
  IpRange subnet;
  subnet.FromString("ff80:dead:beef::/48");
  int egress_interface_index = 7;
  ExpectNetlinkPacket(
      RTM_DELROUTE, NLM_F_ACK | NLM_F_REQUEST,
      [](void* buf, size_t len, int seq) {
        struct nlmsghdr* netlink_message =
            CreateNetlinkMessage(buf, nullptr, NLMSG_ERROR, seq);
        auto* err =
            reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(netlink_message));
        // Ack the request
        err->error = 0;
        netlink_message->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
        return netlink_message->nlmsg_len;
      },
      [preferred_ip, subnet, egress_interface_index](const void* buf,
                                                     size_t len) {
        auto* netlink_message = reinterpret_cast<const struct nlmsghdr*>(buf);
        auto* rtm =
            reinterpret_cast<const struct rtmsg*>(NLMSG_DATA(netlink_message));
        EXPECT_EQ(AF_INET6, rtm->rtm_family);
        EXPECT_EQ(48, rtm->rtm_dst_len);
        EXPECT_EQ(0, rtm->rtm_src_len);
        EXPECT_EQ(RT_TABLE_MAIN, rtm->rtm_table);
        EXPECT_EQ(RTPROT_UNSPEC, rtm->rtm_protocol);
        EXPECT_EQ(RT_SCOPE_LINK, rtm->rtm_scope);
        EXPECT_EQ(RTN_UNICAST, rtm->rtm_type);

        const struct rtattr* rta;
        int payload_length = RTM_PAYLOAD(netlink_message);
        int num_rta = 0;
        for (rta = RTM_RTA(rtm); RTA_OK(rta, payload_length);
             rta = RTA_NEXT(rta, payload_length)) {
          switch (rta->rta_type) {
            case RTA_PREFSRC: {
              const auto* raw_address =
                  reinterpret_cast<const char*>(RTA_DATA(rta));
              ASSERT_EQ(sizeof(struct in6_addr), RTA_PAYLOAD(rta));
              QuicIpAddress address;
              address.FromPackedString(raw_address, RTA_PAYLOAD(rta));
              EXPECT_EQ(preferred_ip, address);
              break;
            }
            case RTA_OIF: {
              ASSERT_EQ(sizeof(int), RTA_PAYLOAD(rta));
              const auto* interface_index =
                  reinterpret_cast<const int*>(RTA_DATA(rta));
              EXPECT_EQ(egress_interface_index, *interface_index);
              break;
            }
            case RTA_DST: {
              const auto* raw_address =
                  reinterpret_cast<const char*>(RTA_DATA(rta));
              ASSERT_EQ(sizeof(struct in6_addr), RTA_PAYLOAD(rta));
              QuicIpAddress address;
              address.FromPackedString(raw_address, RTA_PAYLOAD(rta));
              EXPECT_EQ(subnet.ToString(),
                        IpRange(address, rtm->rtm_dst_len).ToString());
              break;
            }
            case RTA_TABLE: {
              ASSERT_EQ(*reinterpret_cast<uint32_t*>(RTA_DATA(rta)),
                        QboneConstants::kQboneRouteTableId);
              break;
            }
            default:
              EXPECT_TRUE(false) << "Seeing rtattr that should not be sent";
          }
          ++num_rta;
        }
        EXPECT_EQ(4, num_rta);
      });
  EXPECT_TRUE(netlink->ChangeRoute(
      Netlink::Verb::kRemove, QboneConstants::kQboneRouteTableId, subnet,
      RT_SCOPE_LINK, preferred_ip, egress_interface_index));
}

TEST_F(NetlinkTest, ChangeRouteReplace) {
  auto netlink = std::make_unique<Netlink>(&mock_kernel_);

  QuicIpAddress preferred_ip;
  preferred_ip.FromString("ff80:dead:beef::1");
  IpRange subnet;
  subnet.FromString("ff80:dead:beef::/48");
  int egress_interface_index = 7;
  ExpectNetlinkPacket(
      RTM_NEWROUTE, NLM_F_ACK | NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
      [](void* buf, size_t len, int seq) {
        struct nlmsghdr* netlink_message =
            CreateNetlinkMessage(buf, nullptr, NLMSG_ERROR, seq);
        auto* err =
            reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(netlink_message));
        // Ack the request
        err->error = 0;
        netlink_message->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
        return netlink_message->nlmsg_len;
      },
      [preferred_ip, subnet, egress_interface_index](const void* buf,
                                                     size_t len) {
        auto* netlink_message = reinterpret_cast<const struct nlmsghdr*>(buf);
        auto* rtm =
            reinterpret_cast<const struct rtmsg*>(NLMSG_DATA(netlink_message));
        EXPECT_EQ(AF_INET6, rtm->rtm_family);
        EXPECT_EQ(48, rtm->rtm_dst_len);
        EXPECT_EQ(0, rtm->rtm_src_len);
        EXPECT_EQ(RT_TABLE_MAIN, rtm->rtm_table);
        EXPECT_EQ(RTPROT_STATIC, rtm->rtm_protocol);
        EXPECT_EQ(RT_SCOPE_LINK, rtm->rtm_scope);
        EXPECT_EQ(RTN_UNICAST, rtm->rtm_type);

        const struct rtattr* rta;
        int payload_length = RTM_PAYLOAD(netlink_message);
        int num_rta = 0;
        for (rta = RTM_RTA(rtm); RTA_OK(rta, payload_length);
             rta = RTA_NEXT(rta, payload_length)) {
          switch (rta->rta_type) {
            case RTA_PREFSRC: {
              const auto* raw_address =
                  reinterpret_cast<const char*>(RTA_DATA(rta));
              ASSERT_EQ(sizeof(struct in6_addr), RTA_PAYLOAD(rta));
              QuicIpAddress address;
              address.FromPackedString(raw_address, RTA_PAYLOAD(rta));
              EXPECT_EQ(preferred_ip, address);
              break;
            }
            case RTA_GATEWAY: {
              const auto* raw_address =
                  reinterpret_cast<const char*>(RTA_DATA(rta));
              ASSERT_EQ(sizeof(struct in6_addr), RTA_PAYLOAD(rta));
              QuicIpAddress address;
              address.FromPackedString(raw_address, RTA_PAYLOAD(rta));
              EXPECT_EQ(*QboneConstants::GatewayAddress(), address);
              break;
            }
            case RTA_OIF: {
              ASSERT_EQ(sizeof(int), RTA_PAYLOAD(rta));
              const auto* interface_index =
                  reinterpret_cast<const int*>(RTA_DATA(rta));
              EXPECT_EQ(egress_interface_index, *interface_index);
              break;
            }
            case RTA_DST: {
              const auto* raw_address =
                  reinterpret_cast<const char*>(RTA_DATA(rta));
              ASSERT_EQ(sizeof(struct in6_addr), RTA_PAYLOAD(rta));
              QuicIpAddress address;
              address.FromPackedString(raw_address, RTA_PAYLOAD(rta));
              EXPECT_EQ(subnet.ToString(),
                        IpRange(address, rtm->rtm_dst_len).ToString());
              break;
            }
            case RTA_TABLE: {
              ASSERT_EQ(*reinterpret_cast<uint32_t*>(RTA_DATA(rta)),
                        QboneConstants::kQboneRouteTableId);
              break;
            }
            default:
              EXPECT_TRUE(false) << "Seeing rtattr that should not be sent";
          }
          ++num_rta;
        }
        EXPECT_EQ(5, num_rta);
      });
  EXPECT_TRUE(netlink->ChangeRoute(
      Netlink::Verb::kReplace, QboneConstants::kQboneRouteTableId, subnet,
      RT_SCOPE_LINK, preferred_ip, egress_interface_index));
}

}  // namespace
}  // namespace quic::test
```