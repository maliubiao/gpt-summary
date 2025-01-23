Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Functionality:** The filename `tun_device_controller_test.cc` immediately suggests that this code is testing a component named `TunDeviceController`. The `_test.cc` suffix is a common convention for unit tests in C++.

2. **Examine Includes:**  The `#include` directives provide crucial context:
    * `"quiche/quic/qbone/bonnet/tun_device_controller.h"`: Confirms the tested class.
    * `<linux/if_addr.h>`, `<linux/rtnetlink.h>`:  Indicates interaction with Linux networking internals, specifically dealing with IP addresses and routing.
    * Standard C++ includes like `<string>`, `<vector>` and `absl/strings/string_view`: Show basic data structures and string manipulation.
    * `"quiche/quic/platform/api/quic_test.h"`: Identifies this as a QUIC-related test using their testing framework.
    * `"quiche/quic/qbone/platform/mock_netlink.h"`: Highlights the use of a mock object (`MockNetlink`) for testing interactions with the network layer. This is a key indicator of isolated unit testing.
    * `"quiche/quic/qbone/qbone_constants.h"`: Suggests use of predefined constants relevant to the Qbone project.

3. **Understand the Test Structure:**  The file uses the Google Test framework (implicitly through `quic_test.h`). Look for `TEST_F` macros, which define individual test cases within a test fixture (`TunDeviceControllerTest`). The `public:` and `protected:` sections in the fixture indicate setup and helper methods.

4. **Analyze Test Cases:**  Go through each `TEST_F` and try to understand the scenario being tested:
    * `AddressAppliedWhenNoneExisted`: Tests adding a new IP address when none is present.
    * `OldAddressesAreRemoved`: Tests removing existing IP addresses before applying a new one.
    * `UpdateRoutesRemovedOldRoutes`: Tests removing existing routing rules before adding new ones.
    * `UpdateRoutesAddsNewRoutes`: Tests adding multiple new routing rules.
    * `EmptyUpdateRouteKeepsLinkLocalRoute`: Tests the behavior when no specific routes are provided, ensuring the link-local route remains.
    * `DisablingRoutingRulesSkipsRuleCreation`: Tests the effect of a flag that disables routing rule creation.
    * `DisabledTunDeviceControllerTest`:  A separate fixture testing the behavior when the `TunDeviceController` is initialized in a "disabled" state. The tests here (`UpdateRoutesIsNop`, `UpdateAddressIsNop`) confirm that no operations are performed.

5. **Examine Mock Interactions:** The `EXPECT_CALL` macros are crucial. They define the expected interactions with the `MockNetlink` object. This reveals *how* the `TunDeviceController` interacts with the underlying network system:
    * `GetLinkInfo`:  Retrieving interface information (index).
    * `GetAddresses`:  Retrieving existing IP addresses.
    * `ChangeLocalAddress`: Adding or removing IP addresses.
    * `GetRouteInfo`:  Retrieving existing routing rules.
    * `ChangeRoute`: Adding, removing, or replacing routing rules.
    * `GetRuleInfo`: Retrieving existing routing rules (likely policy routing rules).
    * `ChangeRule`: Adding routing rules.

6. **Identify Key Concepts:** From the test names and mock interactions, identify the core concepts the code is dealing with:
    * Network interfaces (TUN devices).
    * IP addresses (adding, removing).
    * Routing (adding, removing, replacing routes and rules).
    * Network namespaces (implied by the need for explicit routing table IDs).

7. **Look for Flag Usage:** The `ABSL_DECLARE_FLAG` macros indicate configurable behavior. `qbone_tun_device_replace_default_routing_rules` is explicitly tested, showing its role in enabling/disabling route rule creation.

8. **Infer Class Responsibilities:** Based on the tests, the `TunDeviceController` is responsible for:
    * Managing the IP address of a TUN device.
    * Managing the routing rules associated with the TUN device.
    * Interacting with the underlying network system (via `Netlink`).
    * Potentially handling enabled/disabled states.

9. **Consider Javascript Relevance (If Any):**  At this stage, consider how these networking concepts might relate to JavaScript in a browser context. While this specific C++ code doesn't directly call JavaScript, it's part of Chromium's network stack. Features built upon this code (like WebRTC, QUIC itself, or network service workers) *could* expose related functionality to JavaScript APIs. The connection is indirect but important for understanding the broader context.

10. **Think About User Errors and Debugging:**  Based on the operations performed, think about potential user errors (misconfigured IP ranges, conflicting routes) and how debugging might proceed (examining network interface configurations, routing tables, and using network monitoring tools).

11. **Structure the Explanation:** Organize the findings into logical sections: purpose of the file, relationship to JavaScript, logical reasoning (with examples), common errors, and debugging steps. Use clear and concise language.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "Maybe this is directly called by JavaScript."  **Correction:**  Reviewing the includes and the nature of the code, it's clearly a low-level C++ component. The connection to JavaScript is through higher-level APIs that utilize this functionality.
* **Initial thought:** "The flags are just constants." **Correction:**  The `ABSL_DECLARE_FLAG` indicates runtime configurable behavior, which is demonstrated in the `DisablingRoutingRulesSkipsRuleCreation` test.
* **Missed detail:** Initially overlooked the `RegisterAddressUpdateCallback`. **Correction:**  Recognize this as a mechanism for notifying other parts of the system about address changes.

By following this structured approach, combining code analysis with knowledge of networking concepts and testing principles, a comprehensive understanding of the `tun_device_controller_test.cc` file can be achieved.
这个文件 `tun_device_controller_test.cc` 是 Chromium 网络栈中 `quiche` 库的一部分，专门用于测试 `TunDeviceController` 类的功能。`TunDeviceController` 的作用是管理 TUN（Tunnel）网络设备，例如配置 IP 地址和路由。

以下是该文件的详细功能分解：

**主要功能:**

1. **单元测试 `TunDeviceController` 类:**  该文件包含了多个单元测试用例，用于验证 `TunDeviceController` 类的各种方法是否按预期工作。

2. **测试 IP 地址管理:**
   - **添加新 IP 地址:** 测试当 TUN 设备没有 IP 地址时，`UpdateAddress` 方法能否成功添加指定的 IP 地址。
   - **移除旧 IP 地址:** 测试当 TUN 设备已经有旧的 IP 地址时，`UpdateAddress` 方法能否先移除旧地址，再添加新的 IP 地址。
   - **通知 IP 地址更新:** 测试 `TunDeviceController` 是否能在 IP 地址更新后调用注册的回调函数，并传递新的 IP 地址。

3. **测试路由管理:**
   - **移除旧路由:** 测试当需要更新路由时，`UpdateRoutes` 方法能否移除与目标网络接口相关的旧路由。
   - **添加新路由:** 测试 `UpdateRoutes` 方法能否根据提供的 IP 范围添加新的路由规则。
   - **保留链路本地路由:** 测试即使没有提供新的路由，`UpdateRoutes` 方法也能保持链路本地路由的配置。
   - **根据 Flag 禁用路由规则创建:** 测试当特定 Flag 被禁用时，`UpdateRoutes` 方法是否会跳过创建路由规则的步骤。

4. **测试禁用状态:**
   - **禁用状态下不执行操作:**  测试当 `TunDeviceController` 在禁用状态下创建时，`UpdateRoutes` 和 `UpdateAddress` 方法是否不会执行任何网络配置操作。

**与 Javascript 的关系:**

该 C++ 文件本身与 Javascript 没有直接的代码级别的关系。 然而，作为 Chromium 网络栈的一部分，`TunDeviceController` 所管理的功能最终可能会影响到浏览器中运行的 Javascript 代码的网络行为。

**举例说明:**

假设一个使用 WebRTC 的 Javascript 应用需要通过一个 VPN 连接进行通信，而这个 VPN 连接的实现可能就涉及到 TUN 设备。

1. **用户操作:** 用户在浏览器中打开一个支持 VPN 的 Web 应用，并连接到 VPN。
2. **底层 C++ 操作:** 当 VPN 连接建立时，Chromium 的底层 C++ 代码（可能就包括 `TunDeviceController` 相关的代码）会配置一个 TUN 设备，设置其 IP 地址和路由，使得发往 VPN 目标地址的网络包通过该 TUN 设备发送。
3. **Javascript 影响:**  这时，运行在浏览器中的 Javascript WebRTC 应用的网络请求就会被路由到 VPN 连接，从而实现通过 VPN 进行通信。

**逻辑推理 (假设输入与输出):**

**测试用例: `AddressAppliedWhenNoneExisted`**

*   **假设输入:**
    *   `TunDeviceController` 实例已创建，并且与一个虚拟的网络接口关联。
    *   该网络接口当前没有配置任何 IP 地址。
    *   调用 `UpdateAddress` 方法，并传入 `kIpRange` (假设为 "2604:31c0:2::/64")。
*   **预期输出:**
    *   `MockNetlink` 对象的 `ChangeLocalAddress` 方法会被调用，参数包含添加 IP 地址 "2604:31c0:2::1" 和前缀长度 64 的指令。
    *   `notified_address_` 变量会被设置为 "2604:31c0:2::1"。
    *   `UpdateAddress` 方法返回 `true`。

**测试用例: `UpdateRoutesAddsNewRoutes`**

*   **假设输入:**
    *   `TunDeviceController` 实例已创建，并且与一个虚拟的网络接口关联。
    *   调用 `UpdateRoutes` 方法，并传入 `kIpRange` ("2604:31c0:2::/64") 以及一个包含两个 `kIpRange` 的 `std::vector`。
*   **预期输出:**
    *   `MockNetlink` 对象的 `ChangeRoute` 方法会被调用两次，参数包含替换路由到 "2604:31c0:2::/64" 并通过指定接口的指令。
    *   `MockNetlink` 对象的 `ChangeRule` 方法会被调用一次，参数包含添加策略路由规则的指令。
    *   `MockNetlink` 对象的 `ChangeRoute` 方法会被调用一次，参数包含替换链路本地路由的指令。
    *   `UpdateRoutes` 方法返回 `true`。

**用户或编程常见的使用错误:**

1. **错误的 IP 地址范围:**  用户或开发者可能提供了一个无效的 IP 地址范围字符串，导致 `IpRange::FromString` 解析失败。这通常是一个编程错误，需要在配置 `TunDeviceController` 时进行校验。

    ```c++
    // 错误示例
    IpRange invalid_range;
    if (!invalid_range.FromString("invalid-ip-range")) {
      // 处理错误：日志记录，抛出异常等
      std::cerr << "Error: Invalid IP range.\n";
    }
    ```

2. **网络接口名称错误:**  在创建 `TunDeviceController` 时，如果提供的网络接口名称不存在或拼写错误，可能会导致 `GetLinkInfo` 失败，从而影响后续的网络配置。

    ```c++
    // 错误示例
    TunDeviceController controller("wrong_interface_name", true, &netlink_);
    // 后续操作可能因为接口不存在而失败
    ```

3. **权限不足:**  在某些系统中，配置网络接口和路由需要 root 权限。如果运行 Chromium 的进程没有足够的权限，`TunDeviceController` 的操作可能会失败。这通常是用户环境配置问题。

4. **与其他网络配置冲突:**  如果系统中已经存在与 `TunDeviceController` 尝试配置的 IP 地址或路由冲突的配置，可能会导致配置失败或网络行为异常。这需要用户理解网络配置，并避免冲突。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用一个需要配置 TUN 设备的 Chromium 功能，例如一个 VPN 扩展或内置的 VPN 功能。

1. **用户安装或启用 VPN 扩展/功能:**  用户在 Chrome 浏览器中安装了一个 VPN 扩展，或者启用了浏览器内置的 VPN 功能。

2. **用户连接到 VPN 服务器:** 用户通过 VPN 扩展或浏览器设置连接到 VPN 服务器。

3. **VPN 客户端触发底层网络配置:**  连接 VPN 服务器的操作会触发 Chromium 底层的网络代码开始配置网络接口，以便将用户的网络流量路由到 VPN 服务器。

4. **`TunDeviceController` 被调用:**  在 VPN 连接过程中，可能会创建一个 `TunDeviceController` 实例来管理一个 TUN 虚拟网络接口。这个实例负责设置 TUN 接口的 IP 地址和路由规则。

5. **执行 `UpdateAddress` 和 `UpdateRoutes`:**  `TunDeviceController` 的 `UpdateAddress` 方法会被调用以配置 TUN 接口的 IP 地址，`UpdateRoutes` 方法会被调用以设置相关的路由规则，确保发往特定目标地址的网络包通过 TUN 接口。

**调试线索:**

如果在 VPN 连接过程中遇到网络问题，例如无法连接到互联网或特定的网站，可以考虑以下调试步骤，这些步骤可能会涉及到 `TunDeviceController` 的操作：

*   **查看网络接口配置:** 使用 `ip addr show` (Linux) 或 `ifconfig` (macOS) 命令查看系统中是否存在预期的 TUN 接口（例如 `qbone0`）。检查其 IP 地址是否已正确配置。
*   **查看路由表:** 使用 `ip route show table <路由表ID>` (Linux) 或 `netstat -nr` (macOS) 命令查看路由表，确认是否存在由 `TunDeviceController` 添加的路由规则。`QboneConstants::kQboneRouteTableId` 定义了相关的路由表 ID。
*   **查看策略路由规则:** 使用 `ip rule show` (Linux) 命令查看策略路由规则，确认是否存在由 `TunDeviceController` 添加的规则。
*   **查看 Chromium 网络日志:**  Chromium 提供了网络日志功能 (`chrome://net-export/`)，可以捕获详细的网络事件，包括接口配置和路由操作，这些日志可能包含与 `TunDeviceController` 相关的操作信息。
*   **使用 `strace` 或 `dtrace`:**  在 Linux 或 macOS 上，可以使用 `strace` 或 `dtrace` 等工具跟踪 Chromium 进程的系统调用，以查看其是否调用了与网络配置相关的系统调用（例如 `ioctl`，涉及到网络接口和路由操作）。
*   **检查 Chromium 源码 (如果需要更深入的理解):**  如果怀疑是 `TunDeviceController` 的 bug，可以查看相关的 Chromium 源码，包括 `tun_device_controller.cc` 和 `tun_device_controller.h`，理解其实现逻辑。

总而言之，`tun_device_controller_test.cc` 文件通过一系列的单元测试，确保了 `TunDeviceController` 能够正确地管理 TUN 虚拟网络设备的 IP 地址和路由，这是 Chromium 网络栈中一个关键的组件，其正确性直接影响到依赖于 TUN 设备的网络功能的可靠性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/qbone/bonnet/tun_device_controller_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/qbone/bonnet/tun_device_controller.h"

#include <linux/if_addr.h>
#include <linux/rtnetlink.h>

#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/qbone/platform/mock_netlink.h"
#include "quiche/quic/qbone/qbone_constants.h"

ABSL_DECLARE_FLAG(bool, qbone_tun_device_replace_default_routing_rules);
ABSL_DECLARE_FLAG(int, qbone_route_init_cwnd);

namespace quic::test {
namespace {
using ::testing::Eq;

constexpr int kIfindex = 42;
constexpr char kIfname[] = "qbone0";

const IpRange kIpRange = []() {
  IpRange range;
  QCHECK(range.FromString("2604:31c0:2::/64"));
  return range;
}();

constexpr char kOldAddress[] = "1.2.3.4";
constexpr int kOldPrefixLen = 24;

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;

MATCHER_P(IpRangeEq, range,
          absl::StrCat("expected IpRange to equal ", range.ToString())) {
  return arg == range;
}

class TunDeviceControllerTest : public QuicTest {
 public:
  TunDeviceControllerTest()
      : controller_(kIfname, true, &netlink_),
        link_local_range_(*QboneConstants::TerminatorLocalAddressRange()) {
    controller_.RegisterAddressUpdateCallback(
        [this](QuicIpAddress address) { notified_address_ = address; });
  }

 protected:
  void ExpectLinkInfo(const std::string& interface_name, int ifindex) {
    EXPECT_CALL(netlink_, GetLinkInfo(interface_name, _))
        .WillOnce(Invoke([ifindex](absl::string_view ifname,
                                   NetlinkInterface::LinkInfo* link_info) {
          link_info->index = ifindex;
          return true;
        }));
  }

  MockNetlink netlink_;
  TunDeviceController controller_;
  QuicIpAddress notified_address_;

  IpRange link_local_range_;
};

TEST_F(TunDeviceControllerTest, AddressAppliedWhenNoneExisted) {
  ExpectLinkInfo(kIfname, kIfindex);

  EXPECT_CALL(netlink_, GetAddresses(kIfindex, _, _, _)).WillOnce(Return(true));

  EXPECT_CALL(netlink_,
              ChangeLocalAddress(
                  kIfindex, NetlinkInterface::Verb::kAdd,
                  kIpRange.FirstAddressInRange(), kIpRange.prefix_length(),
                  IFA_F_PERMANENT | IFA_F_NODAD, RT_SCOPE_LINK, _))
      .WillOnce(Return(true));

  EXPECT_TRUE(controller_.UpdateAddress(kIpRange));
  EXPECT_THAT(notified_address_, Eq(kIpRange.FirstAddressInRange()));
}

TEST_F(TunDeviceControllerTest, OldAddressesAreRemoved) {
  ExpectLinkInfo(kIfname, kIfindex);

  EXPECT_CALL(netlink_, GetAddresses(kIfindex, _, _, _))
      .WillOnce(Invoke([](int interface_index, uint8_t unwanted_flags,
                          std::vector<NetlinkInterface::AddressInfo>* addresses,
                          int* num_ipv6_nodad_dadfailed_addresses) {
        NetlinkInterface::AddressInfo info{};
        info.interface_address.FromString(kOldAddress);
        info.prefix_length = kOldPrefixLen;
        addresses->emplace_back(info);
        return true;
      }));

  QuicIpAddress old_address;
  old_address.FromString(kOldAddress);

  EXPECT_CALL(netlink_,
              ChangeLocalAddress(kIfindex, NetlinkInterface::Verb::kRemove,
                                 old_address, kOldPrefixLen, _, _, _))
      .WillOnce(Return(true));

  EXPECT_CALL(netlink_,
              ChangeLocalAddress(
                  kIfindex, NetlinkInterface::Verb::kAdd,
                  kIpRange.FirstAddressInRange(), kIpRange.prefix_length(),
                  IFA_F_PERMANENT | IFA_F_NODAD, RT_SCOPE_LINK, _))
      .WillOnce(Return(true));

  EXPECT_TRUE(controller_.UpdateAddress(kIpRange));
  EXPECT_THAT(notified_address_, Eq(kIpRange.FirstAddressInRange()));
}

TEST_F(TunDeviceControllerTest, UpdateRoutesRemovedOldRoutes) {
  ExpectLinkInfo(kIfname, kIfindex);

  const int num_matching_routes = 3;
  EXPECT_CALL(netlink_, GetRouteInfo(_))
      .WillOnce(
          Invoke([](std::vector<NetlinkInterface::RoutingRule>* routing_rules) {
            NetlinkInterface::RoutingRule non_matching_route{};
            non_matching_route.table = QboneConstants::kQboneRouteTableId;
            non_matching_route.out_interface = kIfindex + 1;
            routing_rules->push_back(non_matching_route);

            NetlinkInterface::RoutingRule matching_route{};
            matching_route.table = QboneConstants::kQboneRouteTableId;
            matching_route.out_interface = kIfindex;
            for (int i = 0; i < num_matching_routes; i++) {
              routing_rules->push_back(matching_route);
            }

            NetlinkInterface::RoutingRule non_matching_table{};
            non_matching_table.table = QboneConstants::kQboneRouteTableId + 1;
            non_matching_table.out_interface = kIfindex;
            routing_rules->push_back(non_matching_table);
            return true;
          }));

  EXPECT_CALL(netlink_, ChangeRoute(NetlinkInterface::Verb::kRemove,
                                    QboneConstants::kQboneRouteTableId, _, _, _,
                                    kIfindex))
      .Times(num_matching_routes)
      .WillRepeatedly(Return(true));

  EXPECT_CALL(netlink_, GetRuleInfo(_)).WillOnce(Return(true));

  EXPECT_CALL(netlink_, ChangeRule(NetlinkInterface::Verb::kAdd,
                                   QboneConstants::kQboneRouteTableId,
                                   IpRangeEq(kIpRange)))
      .WillOnce(Return(true));

  EXPECT_CALL(netlink_,
              ChangeRoute(NetlinkInterface::Verb::kReplace,
                          QboneConstants::kQboneRouteTableId,
                          IpRangeEq(link_local_range_), _, _, kIfindex))
      .WillOnce(Return(true));

  EXPECT_TRUE(controller_.UpdateRoutes(kIpRange, {}));
}

TEST_F(TunDeviceControllerTest, UpdateRoutesAddsNewRoutes) {
  ExpectLinkInfo(kIfname, kIfindex);

  EXPECT_CALL(netlink_, GetRouteInfo(_)).WillOnce(Return(true));

  EXPECT_CALL(netlink_, GetRuleInfo(_)).WillOnce(Return(true));

  EXPECT_CALL(netlink_, ChangeRoute(NetlinkInterface::Verb::kReplace,
                                    QboneConstants::kQboneRouteTableId,
                                    IpRangeEq(kIpRange), _, _, kIfindex))
      .Times(2)
      .WillRepeatedly(Return(true))
      .RetiresOnSaturation();

  EXPECT_CALL(netlink_, ChangeRule(NetlinkInterface::Verb::kAdd,
                                   QboneConstants::kQboneRouteTableId,
                                   IpRangeEq(kIpRange)))
      .WillOnce(Return(true));

  EXPECT_CALL(netlink_,
              ChangeRoute(NetlinkInterface::Verb::kReplace,
                          QboneConstants::kQboneRouteTableId,
                          IpRangeEq(link_local_range_), _, _, kIfindex))
      .WillOnce(Return(true));

  EXPECT_TRUE(controller_.UpdateRoutes(kIpRange, {kIpRange, kIpRange}));
}

TEST_F(TunDeviceControllerTest, EmptyUpdateRouteKeepsLinkLocalRoute) {
  ExpectLinkInfo(kIfname, kIfindex);

  EXPECT_CALL(netlink_, GetRouteInfo(_)).WillOnce(Return(true));

  EXPECT_CALL(netlink_, GetRuleInfo(_)).WillOnce(Return(true));

  EXPECT_CALL(netlink_, ChangeRule(NetlinkInterface::Verb::kAdd,
                                   QboneConstants::kQboneRouteTableId,
                                   IpRangeEq(kIpRange)))
      .WillOnce(Return(true));

  EXPECT_CALL(netlink_,
              ChangeRoute(NetlinkInterface::Verb::kReplace,
                          QboneConstants::kQboneRouteTableId,
                          IpRangeEq(link_local_range_), _, _, kIfindex))
      .WillOnce(Return(true));

  EXPECT_TRUE(controller_.UpdateRoutes(kIpRange, {}));
}

TEST_F(TunDeviceControllerTest, DisablingRoutingRulesSkipsRuleCreation) {
  absl::SetFlag(&FLAGS_qbone_tun_device_replace_default_routing_rules, false);
  ExpectLinkInfo(kIfname, kIfindex);

  EXPECT_CALL(netlink_, GetRouteInfo(_)).WillOnce(Return(true));

  EXPECT_CALL(netlink_, ChangeRoute(NetlinkInterface::Verb::kReplace,
                                    QboneConstants::kQboneRouteTableId,
                                    IpRangeEq(kIpRange), _, _, kIfindex))
      .Times(2)
      .WillRepeatedly(Return(true))
      .RetiresOnSaturation();

  EXPECT_CALL(netlink_,
              ChangeRoute(NetlinkInterface::Verb::kReplace,
                          QboneConstants::kQboneRouteTableId,
                          IpRangeEq(link_local_range_), _, _, kIfindex))
      .WillOnce(Return(true));

  EXPECT_TRUE(controller_.UpdateRoutes(kIpRange, {kIpRange, kIpRange}));
}

class DisabledTunDeviceControllerTest : public QuicTest {
 public:
  DisabledTunDeviceControllerTest()
      : controller_(kIfname, false, &netlink_),
        link_local_range_(*QboneConstants::TerminatorLocalAddressRange()) {}

  StrictMock<MockNetlink> netlink_;
  TunDeviceController controller_;

  IpRange link_local_range_;
};

TEST_F(DisabledTunDeviceControllerTest, UpdateRoutesIsNop) {
  EXPECT_THAT(controller_.UpdateRoutes(kIpRange, {}), Eq(true));
}

TEST_F(DisabledTunDeviceControllerTest, UpdateAddressIsNop) {
  EXPECT_THAT(controller_.UpdateAddress(kIpRange), Eq(true));
}

}  // namespace
}  // namespace quic::test
```