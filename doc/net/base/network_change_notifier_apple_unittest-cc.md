Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The primary goal is to understand the functionality of the test file and its relationship to the main code (`network_change_notifier_apple.cc`), particularly concerning network change notifications on macOS. We also need to identify any connections to JavaScript (though unlikely in a low-level networking component test), explain logic through input/output examples, highlight common usage errors, and detail how a user might reach this code.

2. **Identify the Core Class Under Test:** The file name `network_change_notifier_apple_unittest.cc` strongly suggests it's testing the `NetworkChangeNotifierApple` class. This immediately tells us the focus is on how Chrome detects and reacts to network changes on macOS.

3. **Scan for Key Components and Concepts:**  Quickly skim the code for important elements:
    * **Includes:**  These tell us what the test file depends on. We see standard C++ headers (`<optional>`, `<string>`), base library components (`base/apple/scoped_cftyperef`, `base/location`, `base/test/...`, `base/threading/thread`), and crucial `net/` components (`net/base/features.h`, `net/base/network_change_notifier.h`, `net/base/network_config_watcher_apple.h`). This reinforces the focus on network change detection.
    * **Namespaces:** `net` is the primary namespace, confirming the network stack context. The anonymous namespace holds test-specific helper functions and constants.
    * **Constants:** `kIPv4PrivateAddrString1`, `kIPv6PublicAddrString1`, etc., are used for simulating IP address changes.
    * **`TestIPAddressObserver`:** This class implements the `NetworkChangeNotifier::IPAddressObserver` interface. This is a key element – it's how the test verifies that notifications are being sent.
    * **`NetworkChangeNotifierAppleTest`:** This is the main test fixture. It inherits from `WithTaskEnvironment` (for asynchronous testing) and `::testing::TestWithParam` (for parameterized testing). The parameterization with `ReduceIPAddressChangeNotificationEnabled` hints at testing the behavior of a specific feature.
    * **`CreateNetworkChangeNotifierApple()`:**  This helper function creates the `NetworkChangeNotifierApple` instance and sets up necessary callbacks. The callbacks are crucial for simulating the interaction with the macOS system. The use of `SCDynamicStoreRef` points directly to the macOS system configuration framework.
    * **`SimulateDynamicStoreCallback()`:** This function simulates a notification from the macOS dynamic store, which is the core mechanism for receiving network configuration changes.
    * **`TEST_P` macros:** These define the individual test cases. The names of the test cases (`NoInterfaceChange`, `IPv4AddressChange`, etc.) are descriptive and give strong clues about what each test is verifying.

4. **Analyze Individual Test Cases:**  For each `TEST_P`, understand the setup, the action, and the assertion:
    * **Setup:** What initial network state is being simulated (e.g., a single interface with a specific IP address)?
    * **Action:** What event is triggered to simulate a network change (e.g., calling `SimulateDynamicStoreCallback` with a specific `CFStringRef`)?
    * **Assertion:** What is being checked to verify the expected behavior (e.g., `observer.ip_address_changed()` is true or false)?

5. **Identify Relationships to JavaScript (If Any):** Based on the code, the connection to JavaScript is indirect. This C++ code handles the low-level detection of network changes. A higher-level component (potentially written in C++ but exposed to JavaScript) would listen to notifications from `NetworkChangeNotifier` and then propagate those changes to the JavaScript layer through Chrome's inter-process communication mechanisms or bindings.

6. **Formulate Input/Output Examples:** Choose a representative test case (e.g., `IPv4AddressChange`). Describe the initial state (input) and the expected outcome after the simulated event (output).

7. **Identify Common Usage Errors:** Think about how a *developer* using or contributing to this code might make mistakes. Focus on things like incorrect callback setup, misunderstanding the feature flags, or improper simulation of system events.

8. **Trace User Actions (Debugging Perspective):** Consider how a network issue reported by a user might lead a developer to investigate this code. Focus on the user's network-related actions that could trigger network change events.

9. **Structure the Answer:** Organize the findings into logical sections as requested in the prompt: Functionality, JavaScript relationship, Input/Output, Usage Errors, and Debugging. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial Thought:** Maybe the JavaScript connection is direct through some native module.
* **Correction:**  Upon closer inspection, this code is very low-level and deals directly with the operating system's network APIs. The connection to JavaScript would be through a higher-level abstraction layer within Chrome.
* **Initial Thought:** Focus heavily on the details of the macOS API calls.
* **Refinement:** While understanding `SCDynamicStoreRef` is helpful, the core functionality is about *reacting* to these system events. The test code focuses on simulating these events rather than deeply testing the macOS APIs themselves.
* **Initial Thought:** Explain every line of code.
* **Refinement:** Focus on the *purpose* of the code and the key interactions. The explanation should be understandable without requiring detailed C++ knowledge of every construct.

By following this thought process, we can systematically analyze the code and provide a comprehensive answer to the user's request.
这个文件 `net/base/network_change_notifier_apple_unittest.cc` 是 Chromium 网络栈的一部分，专门用于测试 `net/base/network_change_notifier_apple.h` 中定义的 `NetworkChangeNotifierApple` 类的功能。这个类负责监听和报告 macOS 系统上的网络状态变化。

**功能列举:**

1. **测试网络接口变化监听:**  测试 `NetworkChangeNotifierApple` 是否能正确检测到网络接口列表的变化，例如新增或删除网络接口。
2. **测试 IP 地址变化监听:**  测试当网络接口的 IP 地址发生变化时（例如，获取新的 IP 地址，或 IP 地址被移除），`NetworkChangeNotifierApple` 是否能发出通知。
3. **测试 IPv4 地址变化:** 专门测试 IPv4 地址的变化能否被正确检测到。
4. **测试 IPv6 地址变化:** 专门测试 IPv6 地址的变化能否被正确检测到，包括公共 IPv6 地址和本地链路 IPv6 地址。
5. **测试主接口变化:** 测试当系统指定的主 IPv4 或 IPv6 网络接口发生变化时，是否能被检测到。
6. **测试 `ReduceIPAddressChangeNotification` 特性:**  这个特性旨在减少不必要的 IP 地址变化通知。测试文件包含了在启用和禁用此特性时的不同行为。例如，当启用该特性时，某些本地链路 IPv6 地址的变化可能被忽略。
7. **模拟 macOS 系统事件:**  测试文件通过模拟 macOS 的 `SCDynamicStore` 回调来触发网络状态变化，以便在受控的环境下测试 `NetworkChangeNotifierApple` 的反应。
8. **使用观察者模式验证通知:**  测试文件中定义了一个 `TestIPAddressObserver` 类，它实现了 `NetworkChangeNotifier::IPAddressObserver` 接口，用于接收并记录 IP 地址变化的通知，从而验证 `NetworkChangeNotifierApple` 是否正确地发出了通知。

**与 JavaScript 功能的关系:**

`NetworkChangeNotifierApple` 本身是用 C++ 编写的，直接与底层的 macOS 系统 API 交互，因此它本身不包含任何 JavaScript 代码。然而，它的功能对于基于 Chromium 的浏览器（如 Chrome 或 Edge）的 JavaScript 功能至关重要。

当网络状态发生变化时，`NetworkChangeNotifierApple` 会发出通知。Chromium 的其他 C++ 组件会监听这些通知，并将相关信息传递到渲染进程中运行的 JavaScript 代码。这使得网页上的 JavaScript 代码能够感知网络状态的变化，并做出相应的处理，例如：

* **离线检测:**  JavaScript 可以使用 `navigator.onLine` 属性或监听 `online` 和 `offline` 事件来判断当前网络连接状态。`NetworkChangeNotifierApple` 的工作确保了这些 API 能准确反映底层的网络状态。
* **网络状态提示:** 网页可能会根据网络连接状态显示不同的提示信息，例如在断网时显示“您已离线”的消息。
* **资源加载优化:**  JavaScript 可以根据网络类型（例如，通过 `navigator.connection.effectiveType` 获取）来选择加载不同质量的资源，或者采取不同的加载策略。
* **PWA 功能:**  对于 Progressive Web Apps (PWA)，网络状态的变化会影响 Service Worker 的行为，例如控制缓存策略或后台同步。

**举例说明 (JavaScript 侧):**

假设用户在浏览一个网页，该网页使用了以下 JavaScript 代码来检测网络状态变化：

```javascript
window.addEventListener('online', () => {
  console.log('网络已连接');
  // 执行网络恢复后的操作，例如重新尝试加载数据
});

window.addEventListener('offline', () => {
  console.log('网络已断开');
  // 显示离线提示，并可能缓存数据供稍后使用
});

console.log('当前网络状态:', navigator.onLine ? '在线' : '离线');
```

当用户的网络连接状态发生变化时，`NetworkChangeNotifierApple` 会检测到这个变化，并通知 Chromium 的相关组件。这些组件会将事件传递到渲染进程，触发 JavaScript 代码中的 `online` 或 `offline` 事件处理函数。`navigator.onLine` 属性的值也会相应地更新。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **初始状态:**  计算机连接到一个 Wi-Fi 网络，IP 地址为 `192.168.0.1` (IPv4)。
2. **操作:**  用户断开了 Wi-Fi 连接。

**输出 (由 `NetworkChangeNotifierApple` 触发的通知):**

* `OnIPAddressChanged()` 被调用： 因为网络接口的 IP 地址发生了变化 (不再有 IPv4 地址)。
* (更底层的实现细节) 可能会检测到网络接口状态的变化（例如，接口从 "已连接" 变为 "未连接"），但这在测试文件中通常通过模拟 `SCDynamicStore` 的变化来体现。

**假设输入 (针对 `ReduceIPAddressChangeNotification` 特性):**

1. **初始状态:** 计算机连接到一个网络，除了公共 IPv4 地址外，还有一个本地链路 IPv6 地址 (`fe80::...`) 分配给一个非主要的网络接口。
2. **操作:** 该非主要网络接口的本地链路 IPv6 地址发生变化。
3. **情况 1 (特性禁用):**  `OnIPAddressChanged()` 被调用。
4. **情况 2 (特性启用):**  `OnIPAddressChanged()` 可能不会被调用，因为该特性旨在减少对此类非关键 IP 地址变化的通知。

**用户或编程常见的使用错误 (涉及 `NetworkChangeNotifier` 的使用):**

1. **忘记添加观察者:**  开发者如果想接收网络状态变化的通知，需要实现 `NetworkChangeNotifier::Observer` 或其子类（如 `IPAddressObserver`），并通过 `NetworkChangeNotifier::AddObserver()` 添加到通知器中。忘记添加观察者会导致无法接收到通知。

   ```c++
   class MyNetworkObserver : public NetworkChangeNotifier::Observer {
    // ... 实现 OnConnectionTypeChanged 等方法
   };

   // 错误示例：忘记添加观察者
   // MyNetworkObserver observer;
   // NetworkChangeNotifier::AddObserver(&observer);

   // 正确示例
   MyNetworkObserver observer;
   NetworkChangeNotifier::AddObserver(&observer);
   ```

2. **在错误的线程访问 `NetworkChangeNotifier`:**  `NetworkChangeNotifier` 的某些操作可能需要在特定的线程上进行。例如，在主线程之外创建或销毁某些与平台相关的组件可能会导致问题。

3. **错误地假设通知的频率或顺序:**  网络状态变化可能很快发生多次，开发者不应假设每次变化都会立即产生一个单独的通知，或者通知的顺序总是与变化发生的顺序完全一致。

4. **没有正确处理观察者的生命周期:**  确保观察者的生命周期长于其需要接收通知的时间。如果观察者过早被销毁，`NetworkChangeNotifier` 尝试通知它时可能会导致崩溃。记得在不再需要时使用 `NetworkChangeNotifier::RemoveObserver()` 移除观察者。

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户遇到与网络连接相关的问题时，例如：

1. **网页加载失败:** 用户尝试访问网页，但由于网络问题无法加载。
2. **间歇性断网:** 用户在使用网络应用时，连接频繁中断。
3. **网络状态显示不正确:** 浏览器或操作系统显示已连接，但实际无法访问网络，反之亦然。
4. **VPN 连接问题:** 用户连接或断开 VPN 时出现异常行为。

作为调试线索，开发者可能会：

1. **检查浏览器网络组件的日志:** Chromium 提供了详细的网络日志，可以查看网络连接状态变化的记录。
2. **检查操作系统网络配置:**  使用 macOS 的“网络偏好设置”或命令行工具（如 `ifconfig`) 来查看当前的网络接口和 IP 地址。
3. **查看 `NetworkChangeNotifierApple` 的实现:**  如果怀疑是 Chromium 没有正确检测到 macOS 上的网络变化，开发者可能会查看 `NetworkChangeNotifierApple` 的代码，了解它是如何监听系统事件的。
4. **运行 `network_change_notifier_apple_unittest.cc` 中的测试:**  开发者可以通过运行这些单元测试来验证 `NetworkChangeNotifierApple` 的基本功能是否正常。如果某些测试失败，可能表明该组件存在 bug。
5. **在 `NetworkChangeNotifierApple` 的代码中添加日志:**  为了更深入地了解运行时行为，开发者可能会在 `NetworkChangeNotifierApple.cc` 中添加额外的日志输出，以便在实际运行时跟踪网络状态变化的检测过程。
6. **使用调试器:**  使用 Xcode 或 lldb 等调试器来单步执行 `NetworkChangeNotifierApple` 的代码，查看其如何响应系统事件，以及如何更新内部状态和发出通知。

总而言之，`network_change_notifier_apple_unittest.cc` 是确保 Chromium 在 macOS 上能够可靠地检测和响应网络状态变化的关键组成部分，这直接影响了浏览器中与网络相关的各种功能，包括 JavaScript 代码的网络感知能力。

### 提示词
```
这是目录为net/base/network_change_notifier_apple_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_change_notifier_apple.h"

#include <optional>
#include <string>

#include "base/apple/scoped_cftyperef.h"
#include "base/location.h"
#include "base/test/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/threading/thread.h"
#include "net/base/features.h"
#include "net/base/network_change_notifier.h"
#include "net/base/network_config_watcher_apple.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

static const char kIPv4PrivateAddrString1[] = "192.168.0.1";
static const char kIPv4PrivateAddrString2[] = "192.168.0.2";

static const char kIPv6PublicAddrString1[] =
    "2401:fa00:4:1000:be30:5b30:50e5:c0";
static const char kIPv6PublicAddrString2[] =
    "2401:fa00:4:1000:be30:5b30:50e5:c1";
static const char kIPv6LinkLocalAddrString1[] = "fe80::0:1:1:1";
static const char kIPv6LinkLocalAddrString2[] = "fe80::0:2:2:2";

class TestIPAddressObserver : public NetworkChangeNotifier::IPAddressObserver {
 public:
  TestIPAddressObserver() { NetworkChangeNotifier::AddIPAddressObserver(this); }

  TestIPAddressObserver(const TestIPAddressObserver&) = delete;
  TestIPAddressObserver& operator=(const TestIPAddressObserver&) = delete;

  ~TestIPAddressObserver() override {
    NetworkChangeNotifier::RemoveIPAddressObserver(this);
  }

  // Implements NetworkChangeNotifier::IPAddressObserver:
  void OnIPAddressChanged() override { ip_address_changed_ = true; }

  bool ip_address_changed() const { return ip_address_changed_; }

 private:
  bool ip_address_changed_ = false;
};

}  // namespace

class NetworkChangeNotifierAppleTest : public WithTaskEnvironment,
                                       public ::testing::TestWithParam<bool> {
 public:
  NetworkChangeNotifierAppleTest() {
    if (ReduceIPAddressChangeNotificationEnabled()) {
      feature_list_.InitWithFeatures(
          /*enabled_features=*/{features::kReduceIPAddressChangeNotification},
          /*disabled_features=*/{});
    } else {
      feature_list_.InitWithFeatures(
          /*enabled_features=*/{},
          /*disabled_features=*/{features::kReduceIPAddressChangeNotification});
    }
  }
  NetworkChangeNotifierAppleTest(const NetworkChangeNotifierAppleTest&) =
      delete;
  NetworkChangeNotifierAppleTest& operator=(
      const NetworkChangeNotifierAppleTest&) = delete;
  ~NetworkChangeNotifierAppleTest() override = default;

  void TearDown() override { RunUntilIdle(); }

 protected:
  bool ReduceIPAddressChangeNotificationEnabled() const { return GetParam(); }

  std::unique_ptr<NetworkChangeNotifierApple>
  CreateNetworkChangeNotifierApple() {
    auto notifier = std::make_unique<NetworkChangeNotifierApple>();
    base::RunLoop run_loop;
    notifier->SetCallbacksForTest(
        run_loop.QuitClosure(),
        base::BindRepeating(
            [](std::optional<NetworkInterfaceList>* network_interface_list,
               NetworkInterfaceList* list_out, int) {
              if (!network_interface_list->has_value()) {
                return false;
              }
              *list_out = **network_interface_list;
              return true;
            },
            &network_interface_list_),
        base::BindRepeating(
            [](std::string* ipv4_primary_interface_name, SCDynamicStoreRef)
                -> std::string { return *ipv4_primary_interface_name; },
            &ipv4_primary_interface_name_),
        base::BindRepeating(
            [](std::string* ipv6_primary_interface_name, SCDynamicStoreRef)
                -> std::string { return *ipv6_primary_interface_name; },
            &ipv6_primary_interface_name_));
    run_loop.Run();
    return notifier;
  }

  void SimulateDynamicStoreCallback(NetworkChangeNotifierApple& notifier,
                                    CFStringRef entity) {
    base::RunLoop run_loop;
    notifier.config_watcher_->GetNotifierThreadForTest()
        ->task_runner()
        ->PostTask(
            FROM_HERE, base::BindLambdaForTesting([&]() {
              base::apple::ScopedCFTypeRef<CFMutableArrayRef> array(
                  CFArrayCreateMutable(nullptr,
                                       /*capacity=*/0, &kCFTypeArrayCallBacks));
              base::apple::ScopedCFTypeRef<CFStringRef> entry_key(
                  SCDynamicStoreKeyCreateNetworkGlobalEntity(
                      nullptr, kSCDynamicStoreDomainState, entity));
              CFArrayAppendValue(array.get(), entry_key.get());
              notifier.OnNetworkConfigChange(array.get());
              run_loop.Quit();
            }));
    run_loop.Run();
  }

 protected:
  std::optional<NetworkInterfaceList> network_interface_list_ =
      NetworkInterfaceList();
  std::string ipv4_primary_interface_name_ = "en0";
  std::string ipv6_primary_interface_name_ = "en0";

 private:
  // Allows us to allocate our own NetworkChangeNotifier for unit testing.
  NetworkChangeNotifier::DisableForTest disable_for_test_;
  base::test::ScopedFeatureList feature_list_;
};

INSTANTIATE_TEST_SUITE_P(
    All,
    NetworkChangeNotifierAppleTest,
    ::testing::Values(true, false),
    [](const testing::TestParamInfo<bool>& info) {
      return info.param ? "ReduceIPAddressChangeNotificationEnabled"
                        : "ReduceIPAddressChangeNotificationDisabled";
    });

TEST_P(NetworkChangeNotifierAppleTest, NoInterfaceChange) {
  net::IPAddress ip_address;
  EXPECT_TRUE(ip_address.AssignFromIPLiteral(kIPv4PrivateAddrString1));
  network_interface_list_->push_back(net::NetworkInterface(
      "en0", "en0", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));

  std::unique_ptr<NetworkChangeNotifierApple> notifier =
      CreateNetworkChangeNotifierApple();

  // Simulate OnNetworkConfigChange callback without any change in
  // NetworkInterfaceList
  TestIPAddressObserver observer;
  SimulateDynamicStoreCallback(*notifier, kSCEntNetIPv4);
  RunUntilIdle();
  // When kReduceIPAddressChangeNotification feature is enabled, we ignores
  // the OnNetworkConfigChange callback without any network interface change.
  EXPECT_EQ(observer.ip_address_changed(),
            !ReduceIPAddressChangeNotificationEnabled());
}

TEST_P(NetworkChangeNotifierAppleTest, IPv4AddressChange) {
  net::IPAddress ip_address;
  EXPECT_TRUE(ip_address.AssignFromIPLiteral(kIPv4PrivateAddrString1));
  network_interface_list_->push_back(net::NetworkInterface(
      "en0", "en0", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));

  std::unique_ptr<NetworkChangeNotifierApple> notifier =
      CreateNetworkChangeNotifierApple();

  // Simulate OnNetworkConfigChange callback with IPv4 address change.
  EXPECT_TRUE((*network_interface_list_)[0].address.AssignFromIPLiteral(
      kIPv4PrivateAddrString2));
  TestIPAddressObserver observer;
  SimulateDynamicStoreCallback(*notifier, kSCEntNetIPv4);
  RunUntilIdle();
  EXPECT_TRUE(observer.ip_address_changed());
}

TEST_P(NetworkChangeNotifierAppleTest, PublicIPv6AddressChange) {
  net::IPAddress ip_address;
  EXPECT_TRUE(ip_address.AssignFromIPLiteral(kIPv6PublicAddrString1));
  network_interface_list_->push_back(net::NetworkInterface(
      "en0", "en0", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address, 64, net::IP_ADDRESS_ATTRIBUTE_NONE));

  std::unique_ptr<NetworkChangeNotifierApple> notifier =
      CreateNetworkChangeNotifierApple();

  // Simulate OnNetworkConfigChange callback with a public IPv6 address change.
  EXPECT_TRUE((*network_interface_list_)[0].address.AssignFromIPLiteral(
      kIPv6PublicAddrString2));
  TestIPAddressObserver observer;
  SimulateDynamicStoreCallback(*notifier, kSCEntNetIPv6);
  RunUntilIdle();
  EXPECT_TRUE(observer.ip_address_changed());
}

TEST_P(NetworkChangeNotifierAppleTest,
       LinkLocalIPv6AddressChangeOnPrimaryInterface) {
  net::IPAddress ip_address;
  EXPECT_TRUE(ip_address.AssignFromIPLiteral(kIPv6LinkLocalAddrString1));
  network_interface_list_->push_back(net::NetworkInterface(
      "en0", "en0", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address, 64, net::IP_ADDRESS_ATTRIBUTE_NONE));

  std::unique_ptr<NetworkChangeNotifierApple> notifier =
      CreateNetworkChangeNotifierApple();

  // Simulate OnNetworkConfigChange callback with a link local IPv6 address
  // change on the primary interface "en0".
  EXPECT_TRUE((*network_interface_list_)[0].address.AssignFromIPLiteral(
      kIPv6LinkLocalAddrString2));
  TestIPAddressObserver observer;
  SimulateDynamicStoreCallback(*notifier, kSCEntNetIPv4);
  RunUntilIdle();
  EXPECT_TRUE(observer.ip_address_changed());
}

TEST_P(NetworkChangeNotifierAppleTest,
       LinkLocalIPv6AddressChangeOnNonPrimaryInterface) {
  net::IPAddress ip_address1;
  EXPECT_TRUE(ip_address1.AssignFromIPLiteral(kIPv4PrivateAddrString1));
  network_interface_list_->push_back(net::NetworkInterface(
      "en0", "en0", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address1, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));

  net::IPAddress ip_address2;
  EXPECT_TRUE(ip_address2.AssignFromIPLiteral(kIPv6LinkLocalAddrString1));
  network_interface_list_->push_back(net::NetworkInterface(
      "en1", "en1", 2, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address2, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));

  std::unique_ptr<NetworkChangeNotifierApple> notifier =
      CreateNetworkChangeNotifierApple();

  // Simulate OnNetworkConfigChange callback with a link local IPv6 address
  // change on the non-primary interface "en1".
  EXPECT_TRUE((*network_interface_list_)[1].address.AssignFromIPLiteral(
      kIPv6LinkLocalAddrString2));
  TestIPAddressObserver observer;
  SimulateDynamicStoreCallback(*notifier, kSCEntNetIPv4);
  RunUntilIdle();
  // When kReduceIPAddressChangeNotification feature is enabled, we ignores
  // the link local IPv6 address change on the non-primary interface.
  EXPECT_EQ(observer.ip_address_changed(),
            !ReduceIPAddressChangeNotificationEnabled());
}

TEST_P(NetworkChangeNotifierAppleTest, NewInterfaceWithIpV4) {
  net::IPAddress ip_address;
  EXPECT_TRUE(ip_address.AssignFromIPLiteral(kIPv4PrivateAddrString1));
  network_interface_list_->push_back(net::NetworkInterface(
      "en0", "en0", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));

  std::unique_ptr<NetworkChangeNotifierApple> notifier =
      CreateNetworkChangeNotifierApple();

  // Simulate OnNetworkConfigChange callback with a new interface with a IPv4
  // address.
  net::IPAddress ip_address2;
  EXPECT_TRUE(ip_address2.AssignFromIPLiteral(kIPv4PrivateAddrString2));
  network_interface_list_->push_back(net::NetworkInterface(
      "en1", "en1", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address2, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));

  TestIPAddressObserver observer;
  SimulateDynamicStoreCallback(*notifier, kSCEntNetIPv4);
  RunUntilIdle();
  EXPECT_TRUE(observer.ip_address_changed());
}

TEST_P(NetworkChangeNotifierAppleTest, NewInterfaceWithLinkLocalIpV6) {
  net::IPAddress ip_address;
  EXPECT_TRUE(ip_address.AssignFromIPLiteral(kIPv4PrivateAddrString1));
  network_interface_list_->push_back(net::NetworkInterface(
      "en0", "en0", 2, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));

  std::unique_ptr<NetworkChangeNotifierApple> notifier =
      CreateNetworkChangeNotifierApple();

  // Simulate OnNetworkConfigChange callback with a new interface with a link
  // local IPv6 address.
  net::IPAddress ip_address2;
  EXPECT_TRUE(ip_address2.AssignFromIPLiteral(kIPv6LinkLocalAddrString1));
  EXPECT_FALSE(ip_address2.IsPubliclyRoutable());
  network_interface_list_->push_back(net::NetworkInterface(
      "en1", "en1", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address2, 64, net::IP_ADDRESS_ATTRIBUTE_NONE));

  TestIPAddressObserver observer;
  SimulateDynamicStoreCallback(*notifier, kSCEntNetIPv4);
  RunUntilIdle();
  // When kReduceIPAddressChangeNotification feature is enabled, we ignores
  // the new link local IPv6 interface.
  EXPECT_EQ(observer.ip_address_changed(),
            !ReduceIPAddressChangeNotificationEnabled());
}

TEST_P(NetworkChangeNotifierAppleTest, NewInterfaceWithPublicIpV6) {
  net::IPAddress ip_address;
  EXPECT_TRUE(ip_address.AssignFromIPLiteral(kIPv4PrivateAddrString1));
  network_interface_list_->push_back(net::NetworkInterface(
      "en0", "en0", 2, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));

  std::unique_ptr<NetworkChangeNotifierApple> notifier =
      CreateNetworkChangeNotifierApple();

  // Simulate OnNetworkConfigChange callback with a new interface with a
  // public IPv6 address.
  net::IPAddress ip_address2;
  EXPECT_TRUE(ip_address2.AssignFromIPLiteral(kIPv6PublicAddrString1));
  EXPECT_TRUE(ip_address2.IsPubliclyRoutable());
  network_interface_list_->push_back(net::NetworkInterface(
      "en1", "en1", 2, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address2, 64, net::IP_ADDRESS_ATTRIBUTE_NONE));

  TestIPAddressObserver observer;
  SimulateDynamicStoreCallback(*notifier, kSCEntNetIPv4);
  RunUntilIdle();
  EXPECT_TRUE(observer.ip_address_changed());
}

TEST_P(NetworkChangeNotifierAppleTest, IPv4PrimaryInterfaceChange) {
  net::IPAddress ip_address;
  EXPECT_TRUE(ip_address.AssignFromIPLiteral(kIPv4PrivateAddrString1));
  network_interface_list_->push_back(net::NetworkInterface(
      "en0", "en0", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));
  net::IPAddress ip_address2;
  EXPECT_TRUE(ip_address2.AssignFromIPLiteral(kIPv4PrivateAddrString2));
  network_interface_list_->push_back(net::NetworkInterface(
      "en1", "en1", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address2, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));

  std::unique_ptr<NetworkChangeNotifierApple> notifier =
      CreateNetworkChangeNotifierApple();

  // Simulate OnNetworkConfigChange callback for the IPv4 primary interface
  // change.
  TestIPAddressObserver observer;
  ipv4_primary_interface_name_ = "en1";
  SimulateDynamicStoreCallback(*notifier, kSCEntNetIPv4);
  RunUntilIdle();
  EXPECT_TRUE(observer.ip_address_changed());
}

TEST_P(NetworkChangeNotifierAppleTest, IPv6PrimaryInterfaceChange) {
  net::IPAddress ip_address;
  EXPECT_TRUE(ip_address.AssignFromIPLiteral(kIPv6PublicAddrString1));
  network_interface_list_->push_back(net::NetworkInterface(
      "en0", "en0", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));
  net::IPAddress ip_address2;
  EXPECT_TRUE(ip_address2.AssignFromIPLiteral(kIPv6PublicAddrString2));
  network_interface_list_->push_back(net::NetworkInterface(
      "en1", "en1", 1, net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
      ip_address2, 0, net::IP_ADDRESS_ATTRIBUTE_NONE));

  std::unique_ptr<NetworkChangeNotifierApple> notifier =
      CreateNetworkChangeNotifierApple();

  // Simulate OnNetworkConfigChange callback for the IPv6 primary interface
  // change.
  TestIPAddressObserver observer;
  ipv6_primary_interface_name_ = "en1";
  SimulateDynamicStoreCallback(*notifier, kSCEntNetIPv6);
  RunUntilIdle();
  EXPECT_TRUE(observer.ip_address_changed());
}

}  // namespace net
```