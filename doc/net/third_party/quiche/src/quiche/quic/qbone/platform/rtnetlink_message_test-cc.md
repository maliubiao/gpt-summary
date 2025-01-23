Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to JavaScript (if any), logical inferences, common user errors, and debugging steps. The key is to extract meaningful information from the C++ code and relate it to a broader context.

2. **Identify the Core Functionality:** The file name `rtnetlink_message_test.cc` strongly suggests it's a *test file* for something called `rtnetlink_message`. The `#include "quiche/quic/qbone/platform/rtnetlink_message.h"` confirms this. Therefore, the primary function of this file is to *test the functionality* of `rtnetlink_message.h`.

3. **Analyze the Test Cases:**  The code contains several `TEST` macros. Each test case focuses on a specific aspect of `RtnetlinkMessage`:

    * `LinkMessageCanBeCreatedForGetOperation`: Tests creating a `LinkMessage` for a "GET" operation.
    * `LinkMessageCanBeCreatedForNewOperation`: Tests creating a `LinkMessage` for a "NEW" operation, including appending attributes.
    * `AddressMessageCanBeCreatedForGetOperation`: Tests creating an `AddressMessage` for a "GET" operation.
    * `AddressMessageCanBeCreatedForNewOperation`: Tests creating an `AddressMessage` for a "NEW" operation, including appending attributes.
    * `RouteMessageCanBeCreatedFromNewOperation`: Tests creating a `RouteMessage` for a "NEW" operation, including appending attributes.

4. **Infer the Functionality of `RtnetlinkMessage`:** Based on the test cases, we can deduce the following about `RtnetlinkMessage`:

    * It's related to the Linux rtnetlink protocol, which is used to manage network interfaces, addresses, and routes.
    * It has different message types: `LinkMessage`, `AddressMessage`, `RouteMessage`.
    * It supports operations like "GET" (read) and "NEW" (create/modify).
    * It involves setting flags, sequence numbers, and process IDs.
    * It uses structures like `nlmsghdr`, `ifinfomsg`, `ifaddrmsg`, and `rtmsg` (these are standard Linux networking structures).
    * It allows appending attributes (using `AppendAttribute`) represented by `rtattr` structures.

5. **Consider the JavaScript Connection:** The prompt specifically asks about a connection to JavaScript. Given that this code is deeply embedded in the Chromium network stack and deals with low-level network configuration, a *direct* connection to typical front-end JavaScript is unlikely. However, we can make some indirect connections:

    * **Chromium's Architecture:** Chromium is a large project. While this specific code is C++, Chromium uses JavaScript for its UI and some higher-level features. User actions in the browser (like configuring network proxies or VPNs) might eventually trigger code paths that interact with this C++ code.
    * **Node.js:**  Node.js allows JavaScript to interact with system-level APIs. While not directly related to a *browser*, it represents a way JavaScript could, in theory, interact with network configuration on a Linux system. This is more of a conceptual link.

6. **Logical Inferences (Hypothetical Inputs and Outputs):**  The test cases themselves provide examples of inputs (flags, sequence numbers, data for attributes) and expected outputs (structure member values, sizes). We can generalize this:

    * **Input:**  A request to create a new network interface with a specific name and IP address.
    * **Output:** The `RtnetlinkMessage` code would construct the appropriate rtnetlink messages (likely a `LinkMessage` followed by an `AddressMessage`) containing the specified information in the correct format.

7. **Common User Errors:**  Since this is low-level code, the errors are more likely to be *programming errors* when using the `RtnetlinkMessage` API rather than direct user actions. Examples include:

    * Incorrectly setting flags or message types.
    * Providing invalid attribute data (wrong size, incorrect format).
    * Not handling the asynchronous nature of network operations correctly (though this test file doesn't directly show that).

8. **Debugging Steps (User Interaction to Code):** This requires tracing a user action from the browser UI down to this C++ code. A plausible scenario involves network configuration changes:

    1. **User Action:** The user changes network settings in the Chromium browser (e.g., adds a VPN profile, modifies proxy settings).
    2. **Browser UI:** The browser's UI (written in HTML/JavaScript) captures these changes.
    3. **Renderer Process:** This information is passed to the browser's renderer process.
    4. **Browser Process:** The renderer process communicates with the main browser process, which handles system-level interactions.
    5. **Network Service:** The browser process delegates network configuration tasks to the network service.
    6. **QBONE Integration:**  The `quiche/quic/qbone` component (likely involved in QUIC over specific network interfaces) uses the `RtnetlinkMessage` class to communicate with the Linux kernel via rtnetlink.
    7. **`rtnetlink_message_test.cc` (during development):** Developers use this test file to verify that the `RtnetlinkMessage` class correctly constructs rtnetlink messages based on the desired network configuration changes triggered by the user.

9. **Structure and Refine:** Organize the information into the categories requested by the prompt (functionality, JavaScript relation, logical inferences, user errors, debugging). Use clear and concise language.

10. **Review and Verify:** Double-check the analysis against the code to ensure accuracy and completeness. For example, confirm that the interpretations of the structure members and the `AppendAttribute` calls are correct.
这个文件 `net/third_party/quiche/src/quiche/quic/qbone/platform/rtnetlink_message_test.cc` 是 Chromium 网络栈中 QUIC 协议栈的 QBONE 组件的一部分。它的主要功能是**测试 `RtnetlinkMessage` 类的功能**。`RtnetlinkMessage` 类很可能是用于构建和操作与 Linux 内核的 `rtnetlink` 接口进行通信的消息。`rtnetlink` 是 Linux 内核提供的一种用于获取和修改内核网络配置信息的协议。

以下是该文件功能的详细说明：

**功能:**

1. **测试 `LinkMessage` 类的创建和属性设置:**
   - 测试是否能够为 "GET" 操作创建一个 `LinkMessage`。对于 GET 操作，通常只需要基本的头部信息，不需要额外的属性。
   - 测试是否能够为 "NEW" 操作创建一个 `LinkMessage`，并能够正确地添加网络接口名称 (`IFLA_IFNAME`) 等属性。
   - 验证创建的消息的 `nlmsghdr` 头部（Netlink 消息头）是否正确，包括消息长度、类型 (`RTM_GETLINK`, `RTM_NEWLINK`)、标志、序列号和进程 ID。
   - 验证 `ifinfomsg` 结构体（接口信息消息）是否被正确包含在消息中（对于 "NEW" 操作）。
   - 验证使用 `AppendAttribute` 添加的 `rtattr` 结构体（路由属性）是否被正确构造，包括类型、长度和数据。

2. **测试 `AddressMessage` 类的创建和属性设置:**
   - 测试是否能够为 "GET" 操作创建一个 `AddressMessage`。
   - 测试是否能够为 "NEW" 操作创建一个 `AddressMessage`，并能够正确地添加 IP 地址 (`IFA_ADDRESS`) 等属性。
   - 验证创建的消息的 `nlmsghdr` 头部是否正确，包括消息类型 (`RTM_GETADDR`, `RTM_NEWADDR`)。
   - 验证 `ifaddrmsg` 结构体（接口地址消息）是否被正确包含在消息中（对于 "NEW" 操作）。
   - 验证 IP 地址属性是否被正确添加到消息中。

3. **测试 `RouteMessage` 类的创建和属性设置:**
   - 测试是否能够为 "NEW" 操作创建一个 `RouteMessage`，并能够正确地添加首选源地址 (`RTA_PREFSRC`) 等属性。
   - 验证创建的消息的 `nlmsghdr` 头部是否正确，包括消息类型 (`RTM_NEWROUTE`)。
   - 验证 `rtmsg` 结构体（路由消息）是否被正确包含在消息中。
   - 验证首选源地址属性是否被正确添加到消息中。

**与 Javascript 的关系:**

这个 C++ 文件本身与 Javascript **没有直接的运行关系**。它是 Chromium 的底层网络栈的一部分，用 C++ 编写。然而，Javascript 在 Chromium 中扮演着重要的角色，负责渲染网页、处理用户交互等。

**可能存在的间接关系举例:**

假设一个 Web 应用需要获取或更改用户的网络配置（例如，通过 Chrome 扩展或者某些实验性 API，这种直接操作网络配置的 API 权限会非常严格）。

1. **用户操作 (Javascript 层面):**  一个用户在浏览器设置页面或者一个特殊的 Web 应用中，尝试查看当前的网络接口信息。这个操作会触发一些 Javascript 代码。
2. **浏览器内部通信:** Javascript 代码会通过 Chromium 提供的内部机制（例如，通过消息传递给浏览器进程）请求获取网络信息。
3. **C++ 网络栈处理:** 浏览器进程的网络服务部分会接收到这个请求。为了获取网络接口信息，它可能会使用 `RtnetlinkMessage` 类构建一个 `RTM_GETLINK` 类型的消息，并通过 `rtnetlink` 接口发送给 Linux 内核。
4. **内核响应:** Linux 内核会响应包含网络接口信息的消息。
5. **C++ 网络栈解析:** Chromium 的 C++ 网络栈会解析内核的响应。
6. **信息传递回 Javascript:** 解析后的信息最终会通过浏览器内部机制传递回 Javascript 代码。
7. **Web 应用展示:** Javascript 代码会将获取到的网络接口信息展示给用户。

**逻辑推理 (假设输入与输出):**

**场景:** 测试创建用于获取网络链路信息的 `LinkMessage`。

**假设输入:**
- `RtnetlinkMessage::Operation::GET` (操作类型为获取)
- `flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH` (Netlink 标志，表示这是一个请求，需要 root 权限，并且进行匹配)
- `seq = 42` (消息序列号)
- `pid = 7` (进程 ID)
- `interface_info_header = nullptr` (对于 GET 操作，通常不需要额外的接口信息头)

**预期输出:**
- 创建一个 `LinkMessage` 对象。
- `message.IoVecSize()` 返回 1 (只包含 Netlink 消息头)。
- `message.BuildIoVec()` 返回的第一个 `iovec` 的长度等于 `NLMSG_SPACE(sizeof(struct rtgenmsg))`。
- Netlink 消息头的 `nlmsg_len` 等于 `NLMSG_LENGTH(sizeof(struct rtgenmsg))`。
- Netlink 消息头的 `nlmsg_type` 等于 `RTM_GETLINK`。
- Netlink 消息头的 `nlmsg_flags` 等于输入的 `flags`。
- Netlink 消息头的 `nlmsg_seq` 等于输入的 `seq`。
- Netlink 消息头的 `nlmsg_pid` 等于输入的 `pid`。

**用户或编程常见的使用错误:**

1. **错误的 Netlink 标志:**  使用了不正确的标志组合，例如，在需要 root 权限的操作中忘记设置 `NLM_F_ROOT` 标志，导致操作被内核拒绝。
   ```c++
   // 错误示例：尝试获取链路信息，但没有设置 NLM_F_ROOT
   auto message = LinkMessage::New(RtnetlinkMessage::Operation::GET, NLM_F_REQUEST | NLM_F_MATCH, 42, 7, nullptr);
   ```
   **后果:**  内核可能返回权限错误。

2. **为 GET 操作添加了属性:**  对于某些 GET 操作，添加额外的属性可能没有意义或者会导致内核忽略这些属性。理解 `rtnetlink` 协议的不同消息类型的要求很重要。
   ```c++
   // 潜在错误：尝试为 GET 操作的 LinkMessage 添加接口名称
   auto message = LinkMessage::New(RtnetlinkMessage::Operation::GET, NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH, 42, 7, nullptr);
   std::string device_name = "eth0";
   // 这样做可能没有效果或者是不必要的
   // message.AppendAttribute(IFLA_IFNAME, device_name.c_str(), device_name.size());
   ```

3. **属性数据类型或大小错误:**  在使用 `AppendAttribute` 添加属性时，提供了错误的数据类型或大小，导致构造的 `rtattr` 结构体不正确，内核可能无法解析。
   ```c++
   // 错误示例：假设 IFLA_IFNAME 期望的是一个固定大小的字符串，但提供了错误的大小
   auto message = LinkMessage::New(RtnetlinkMessage::Operation::NEW, NLM_F_REQUEST | NLM_F_ROOT | NLM_F_CREATE, 42, 7, &if_info);
   const char* short_name = "eth"; // 比实际接口名短
   message.AppendAttribute(IFLA_IFNAME, short_name, strlen(short_name)); // 大小可能不匹配预期
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

假设用户在使用 Chrome 浏览器时，更改了网络配置，例如添加了一个 VPN 连接或者修改了代理设置。以下是可能到达 `rtnetlink_message_test.cc` 中测试代码的路径：

1. **用户操作:** 用户通过 Chrome 的设置界面或者操作系统的网络设置界面，配置了一个新的 VPN 连接。
2. **浏览器事件:** 操作系统或浏览器捕获到网络配置更改的事件。
3. **Chrome 内部处理:** Chrome 的网络服务组件（Network Service）接收到这个网络配置更改的通知。
4. **QBONE 组件参与:** 如果涉及 QUIC over specific绑定接口 (这可能是 QBONE 组件的目标)，QBONE 组件可能需要与内核交互来配置相关的网络接口或路由。
5. **`RtnetlinkMessage` 的使用:** QBONE 组件中的代码会使用 `RtnetlinkMessage` 类来构建与内核通信的 `rtnetlink` 消息。例如，为了创建一个新的网络接口或添加一条路由，它会创建一个 `LinkMessage` 或 `RouteMessage` 对象，设置必要的属性。
6. **系统调用:** `RtnetlinkMessage` 构建的消息最终会通过 socket 发送到内核的 `rtnetlink` 接口，这涉及到系统调用，例如 `sendto`。
7. **`rtnetlink_message_test.cc` 的作用 (开发和测试阶段):**  在开发和测试 QBONE 组件时，`rtnetlink_message_test.cc` 中的测试用例会被执行，以确保 `RtnetlinkMessage` 类能够正确地构建各种 `rtnetlink` 消息，例如创建链路、添加地址、添加路由等。这些测试确保了 QBONE 组件与内核的 `rtnetlink` 接口的交互是正确的。

**调试线索:**

- 如果在 Chrome 的网络功能中出现问题，例如 VPN 连接失败，或者 QUIC 连接建立异常，开发人员可能会怀疑是底层的网络配置问题。
- 他们可能会查看与 `rtnetlink` 交互相关的代码，特别是 QBONE 组件中使用了 `RtnetlinkMessage` 的地方。
- 为了验证 `RtnetlinkMessage` 的行为是否符合预期，他们可能会参考 `rtnetlink_message_test.cc` 中的测试用例，查看是否已经覆盖了相关的场景。
- 如果发现 `RtnetlinkMessage` 的消息构造存在问题，他们可能会修改 `RtnetlinkMessage` 的实现，并更新或添加 `rtnetlink_message_test.cc` 中的测试用例来验证修复。

总而言之，`rtnetlink_message_test.cc` 是一个用于确保 Chromium 的 QBONE 组件能够正确地与 Linux 内核的 `rtnetlink` 接口进行通信的关键测试文件。它验证了消息的构建和属性设置的正确性，这对于网络功能的正常运行至关重要。虽然它本身不是 Javascript 代码，但它所测试的功能是支撑 Chromium 网络能力的基础，最终会影响到用户通过浏览器进行的各种网络操作。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/qbone/platform/rtnetlink_message_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/qbone/platform/rtnetlink_message.h"

#include <net/if_arp.h>

#include <string>

#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {
namespace {

using ::testing::StrEq;

TEST(RtnetlinkMessageTest, LinkMessageCanBeCreatedForGetOperation) {
  uint16_t flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
  uint32_t seq = 42;
  uint32_t pid = 7;
  auto message = LinkMessage::New(RtnetlinkMessage::Operation::GET, flags, seq,
                                  pid, nullptr);

  // No rtattr appended.
  EXPECT_EQ(1, message.IoVecSize());

  // nlmsghdr is built properly.
  auto iov = message.BuildIoVec();
  EXPECT_EQ(NLMSG_SPACE(sizeof(struct rtgenmsg)), iov[0].iov_len);
  auto* netlink_message = reinterpret_cast<struct nlmsghdr*>(iov[0].iov_base);
  EXPECT_EQ(NLMSG_LENGTH(sizeof(struct rtgenmsg)), netlink_message->nlmsg_len);
  EXPECT_EQ(RTM_GETLINK, netlink_message->nlmsg_type);
  EXPECT_EQ(flags, netlink_message->nlmsg_flags);
  EXPECT_EQ(seq, netlink_message->nlmsg_seq);
  EXPECT_EQ(pid, netlink_message->nlmsg_pid);

  // We actually included rtgenmsg instead of the passed in ifinfomsg since this
  // is a GET operation.
  EXPECT_EQ(NLMSG_LENGTH(sizeof(struct rtgenmsg)), netlink_message->nlmsg_len);
}

TEST(RtnetlinkMessageTest, LinkMessageCanBeCreatedForNewOperation) {
  struct ifinfomsg interface_info_header = {AF_INET, /* pad */ 0, ARPHRD_TUNNEL,
                                            3,       0,           0xffffffff};
  uint16_t flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
  uint32_t seq = 42;
  uint32_t pid = 7;
  auto message = LinkMessage::New(RtnetlinkMessage::Operation::NEW, flags, seq,
                                  pid, &interface_info_header);

  std::string device_name = "device0";
  message.AppendAttribute(IFLA_IFNAME, device_name.c_str(), device_name.size());

  // One rtattr appended.
  EXPECT_EQ(2, message.IoVecSize());

  // nlmsghdr is built properly.
  auto iov = message.BuildIoVec();
  EXPECT_EQ(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifinfomsg))),
            iov[0].iov_len);
  auto* netlink_message = reinterpret_cast<struct nlmsghdr*>(iov[0].iov_base);
  EXPECT_EQ(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifinfomsg))) +
                RTA_LENGTH(device_name.size()),
            netlink_message->nlmsg_len);
  EXPECT_EQ(RTM_NEWLINK, netlink_message->nlmsg_type);
  EXPECT_EQ(flags, netlink_message->nlmsg_flags);
  EXPECT_EQ(seq, netlink_message->nlmsg_seq);
  EXPECT_EQ(pid, netlink_message->nlmsg_pid);

  // ifinfomsg is included properly.
  auto* parsed_header =
      reinterpret_cast<struct ifinfomsg*>(NLMSG_DATA(netlink_message));
  EXPECT_EQ(interface_info_header.ifi_family, parsed_header->ifi_family);
  EXPECT_EQ(interface_info_header.ifi_type, parsed_header->ifi_type);
  EXPECT_EQ(interface_info_header.ifi_index, parsed_header->ifi_index);
  EXPECT_EQ(interface_info_header.ifi_flags, parsed_header->ifi_flags);
  EXPECT_EQ(interface_info_header.ifi_change, parsed_header->ifi_change);

  // rtattr is handled properly.
  EXPECT_EQ(RTA_SPACE(device_name.size()), iov[1].iov_len);
  auto* rta = reinterpret_cast<struct rtattr*>(iov[1].iov_base);
  EXPECT_EQ(IFLA_IFNAME, rta->rta_type);
  EXPECT_EQ(RTA_LENGTH(device_name.size()), rta->rta_len);
  EXPECT_THAT(device_name,
              StrEq(std::string(reinterpret_cast<char*>(RTA_DATA(rta)),
                                RTA_PAYLOAD(rta))));
}

TEST(RtnetlinkMessageTest, AddressMessageCanBeCreatedForGetOperation) {
  uint16_t flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
  uint32_t seq = 42;
  uint32_t pid = 7;
  auto message = AddressMessage::New(RtnetlinkMessage::Operation::GET, flags,
                                     seq, pid, nullptr);

  // No rtattr appended.
  EXPECT_EQ(1, message.IoVecSize());

  // nlmsghdr is built properly.
  auto iov = message.BuildIoVec();
  EXPECT_EQ(NLMSG_SPACE(sizeof(struct rtgenmsg)), iov[0].iov_len);
  auto* netlink_message = reinterpret_cast<struct nlmsghdr*>(iov[0].iov_base);
  EXPECT_EQ(NLMSG_LENGTH(sizeof(struct rtgenmsg)), netlink_message->nlmsg_len);
  EXPECT_EQ(RTM_GETADDR, netlink_message->nlmsg_type);
  EXPECT_EQ(flags, netlink_message->nlmsg_flags);
  EXPECT_EQ(seq, netlink_message->nlmsg_seq);
  EXPECT_EQ(pid, netlink_message->nlmsg_pid);

  // We actually included rtgenmsg instead of the passed in ifinfomsg since this
  // is a GET operation.
  EXPECT_EQ(NLMSG_LENGTH(sizeof(struct rtgenmsg)), netlink_message->nlmsg_len);
}

TEST(RtnetlinkMessageTest, AddressMessageCanBeCreatedForNewOperation) {
  struct ifaddrmsg interface_address_header = {AF_INET,
                                               /* prefixlen */ 24,
                                               /* flags */ 0,
                                               /* scope */ RT_SCOPE_LINK,
                                               /* index */ 4};
  uint16_t flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
  uint32_t seq = 42;
  uint32_t pid = 7;
  auto message = AddressMessage::New(RtnetlinkMessage::Operation::NEW, flags,
                                     seq, pid, &interface_address_header);

  QuicIpAddress ip;
  QUICHE_CHECK(ip.FromString("10.0.100.3"));
  message.AppendAttribute(IFA_ADDRESS, ip.ToPackedString().c_str(),
                          ip.ToPackedString().size());

  // One rtattr is appended.
  EXPECT_EQ(2, message.IoVecSize());

  // nlmsghdr is built properly.
  auto iov = message.BuildIoVec();
  EXPECT_EQ(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifaddrmsg))),
            iov[0].iov_len);
  auto* netlink_message = reinterpret_cast<struct nlmsghdr*>(iov[0].iov_base);
  EXPECT_EQ(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct ifaddrmsg))) +
                RTA_LENGTH(ip.ToPackedString().size()),
            netlink_message->nlmsg_len);
  EXPECT_EQ(RTM_NEWADDR, netlink_message->nlmsg_type);
  EXPECT_EQ(flags, netlink_message->nlmsg_flags);
  EXPECT_EQ(seq, netlink_message->nlmsg_seq);
  EXPECT_EQ(pid, netlink_message->nlmsg_pid);

  // ifaddrmsg is included properly.
  auto* parsed_header =
      reinterpret_cast<struct ifaddrmsg*>(NLMSG_DATA(netlink_message));
  EXPECT_EQ(interface_address_header.ifa_family, parsed_header->ifa_family);
  EXPECT_EQ(interface_address_header.ifa_prefixlen,
            parsed_header->ifa_prefixlen);
  EXPECT_EQ(interface_address_header.ifa_flags, parsed_header->ifa_flags);
  EXPECT_EQ(interface_address_header.ifa_scope, parsed_header->ifa_scope);
  EXPECT_EQ(interface_address_header.ifa_index, parsed_header->ifa_index);

  // rtattr is handled properly.
  EXPECT_EQ(RTA_SPACE(ip.ToPackedString().size()), iov[1].iov_len);
  auto* rta = reinterpret_cast<struct rtattr*>(iov[1].iov_base);
  EXPECT_EQ(IFA_ADDRESS, rta->rta_type);
  EXPECT_EQ(RTA_LENGTH(ip.ToPackedString().size()), rta->rta_len);
  EXPECT_THAT(ip.ToPackedString(),
              StrEq(std::string(reinterpret_cast<char*>(RTA_DATA(rta)),
                                RTA_PAYLOAD(rta))));
}

TEST(RtnetlinkMessageTest, RouteMessageCanBeCreatedFromNewOperation) {
  struct rtmsg route_message_header = {AF_INET6,
                                       /* rtm_dst_len */ 48,
                                       /* rtm_src_len */ 0,
                                       /* rtm_tos */ 0,
                                       /* rtm_table */ RT_TABLE_MAIN,
                                       /* rtm_protocol */ RTPROT_STATIC,
                                       /* rtm_scope */ RT_SCOPE_LINK,
                                       /* rtm_type */ RTN_LOCAL,
                                       /* rtm_flags */ 0};
  uint16_t flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH;
  uint32_t seq = 42;
  uint32_t pid = 7;
  auto message = RouteMessage::New(RtnetlinkMessage::Operation::NEW, flags, seq,
                                   pid, &route_message_header);

  QuicIpAddress preferred_source;
  QUICHE_CHECK(preferred_source.FromString("ff80::1"));
  message.AppendAttribute(RTA_PREFSRC,
                          preferred_source.ToPackedString().c_str(),
                          preferred_source.ToPackedString().size());

  // One rtattr is appended.
  EXPECT_EQ(2, message.IoVecSize());

  // nlmsghdr is built properly
  auto iov = message.BuildIoVec();
  EXPECT_EQ(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct rtmsg))), iov[0].iov_len);
  auto* netlink_message = reinterpret_cast<struct nlmsghdr*>(iov[0].iov_base);
  EXPECT_EQ(NLMSG_ALIGN(NLMSG_LENGTH(sizeof(struct rtmsg))) +
                RTA_LENGTH(preferred_source.ToPackedString().size()),
            netlink_message->nlmsg_len);
  EXPECT_EQ(RTM_NEWROUTE, netlink_message->nlmsg_type);
  EXPECT_EQ(flags, netlink_message->nlmsg_flags);
  EXPECT_EQ(seq, netlink_message->nlmsg_seq);
  EXPECT_EQ(pid, netlink_message->nlmsg_pid);

  // rtmsg is included properly.
  auto* parsed_header =
      reinterpret_cast<struct rtmsg*>(NLMSG_DATA(netlink_message));
  EXPECT_EQ(route_message_header.rtm_family, parsed_header->rtm_family);
  EXPECT_EQ(route_message_header.rtm_dst_len, parsed_header->rtm_dst_len);
  EXPECT_EQ(route_message_header.rtm_src_len, parsed_header->rtm_src_len);
  EXPECT_EQ(route_message_header.rtm_tos, parsed_header->rtm_tos);
  EXPECT_EQ(route_message_header.rtm_table, parsed_header->rtm_table);
  EXPECT_EQ(route_message_header.rtm_protocol, parsed_header->rtm_protocol);
  EXPECT_EQ(route_message_header.rtm_scope, parsed_header->rtm_scope);
  EXPECT_EQ(route_message_header.rtm_type, parsed_header->rtm_type);
  EXPECT_EQ(route_message_header.rtm_flags, parsed_header->rtm_flags);

  // rtattr is handled properly.
  EXPECT_EQ(RTA_SPACE(preferred_source.ToPackedString().size()),
            iov[1].iov_len);
  auto* rta = reinterpret_cast<struct rtattr*>(iov[1].iov_base);
  EXPECT_EQ(RTA_PREFSRC, rta->rta_type);
  EXPECT_EQ(RTA_LENGTH(preferred_source.ToPackedString().size()), rta->rta_len);
  EXPECT_THAT(preferred_source.ToPackedString(),
              StrEq(std::string(reinterpret_cast<char*>(RTA_DATA(rta)),
                                RTA_PAYLOAD(rta))));
}

}  // namespace
}  // namespace quic
```