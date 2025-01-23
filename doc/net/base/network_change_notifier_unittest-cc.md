Response:
Let's break down the thought process for analyzing the given C++ unit test file.

1. **Understand the Goal:** The core goal is to analyze the provided C++ code and explain its purpose, its relationship to JavaScript (if any), illustrate its logic with examples, identify potential user/programming errors, and outline how a user might end up triggering this code (debugging context).

2. **Initial Scan and Key Components:**  Quickly read through the code to identify key classes, functions, and test names. Immediately, `NetworkChangeNotifier`, `NetworkInterface`, and test names like `NetMaxBandwidthRange`, `ConnectionTypeFromInterfaceList`, `IgnoreTeredoOnWindows`, etc., stand out. The `#include` statements confirm the involvement of networking and testing infrastructure within Chromium.

3. **Identify the Core Class Under Test:** The filename `network_change_notifier_unittest.cc` strongly suggests that the primary class being tested is `NetworkChangeNotifier`. The tests themselves further confirm this by directly calling methods of this class or using mock objects to interact with it.

4. **Determine the Purpose of `NetworkChangeNotifier`:** Based on the function names and test cases, we can infer that `NetworkChangeNotifier` is responsible for detecting and reporting changes in the network connection. This includes:
    * **Connection Type:** (e.g., Ethernet, Wi-Fi, Cellular)
    * **Maximum Bandwidth:**  An estimate of the network speed.
    * **Connection Cost:** (e.g., Metered, Unmetered)
    * **DNS Changes:** Detection of DNS server modifications.

5. **Analyze Individual Tests:**  Go through each test case and understand its specific objective.
    * `NetMaxBandwidthRange`: Checks if the reported maximum bandwidth falls within reasonable ranges for different connection types. This is essentially validating the accuracy of bandwidth estimation.
    * `ConnectionTypeFromInterfaceList`: Tests the logic for determining the overall connection type based on a list of network interfaces. It checks prioritization and handling of multiple interfaces.
    * `Ignore...` tests: These cases specifically verify that certain types of network interfaces (like Teredo tunnels, Airdrop, VM interfaces) are correctly ignored when determining the primary connection type. This is about filtering out irrelevant or virtual interfaces.
    * `GetConnectionSubtype`:  A simple smoke test to ensure this function doesn't crash.
    * `TriggerNonSystemDnsChange`: Tests the mechanism for manually triggering DNS change notifications, likely for internal purposes.
    * `TriggerConnectionCostChange`: Verifies the notification system for changes in connection cost.
    * `ConnectionCostDefaultsToCellular`: Checks the default connection cost behavior for different connection types.
    * `GetConnectionCost`:  Ensures the `GetConnectionCost` function returns a meaningful value.
    * `AddObserver`:  Confirms that adding an observer doesn't cause errors.

6. **Look for JavaScript Relevance:**  Think about how network information is used on the web. JavaScript running in a browser needs to know about the network connection for various reasons (e.g., adapting content for slow connections, informing the user about offline status, handling data usage). The `Network Information API` in browsers directly exposes this type of information to JavaScript. Therefore, `NetworkChangeNotifier` is *fundamentally* related to the underlying implementation that provides data for this JavaScript API.

7. **Develop Examples (Hypothetical Input/Output):** For key functions like `ConnectionTypeFromInterfaceList`, create simple examples demonstrating the logic. This clarifies how the function behaves with different inputs.

8. **Identify Potential Errors:** Consider common mistakes developers might make when *using* the `NetworkChangeNotifier` or related networking APIs. This includes:
    * Assuming a specific connection type is always available.
    * Not handling network changes gracefully.
    * Incorrectly interpreting connection cost information.

9. **Trace User Actions (Debugging Context):**  Think about the user actions that could lead to the `NetworkChangeNotifier` being invoked. This involves network operations within the browser, operating system network settings changes, and the browser reacting to these changes.

10. **Structure the Answer:** Organize the findings into logical sections as requested by the prompt: Functionality, JavaScript Relation, Logical Reasoning, Common Errors, and User Actions. Use clear and concise language.

11. **Review and Refine:**  Read through the explanation to ensure accuracy, clarity, and completeness. Make sure the examples are easy to understand and the connections to JavaScript are well-articulated. For example, initially, I might have just said "it's used by the browser."  Refining this to specifically mention the Network Information API makes the connection much clearer. Also, ensure the assumptions and limitations are mentioned, like the test's reliance on the host's network state.

This step-by-step process, starting with a broad understanding and progressively diving into details, allows for a comprehensive analysis of the given code snippet. The key is to connect the technical details of the C++ code to the higher-level concepts of network management and how this information is used in a web browser context.
这个C++源代码文件 `network_change_notifier_unittest.cc` 是 Chromium 项目中 `net/base` 目录下的一部分，专门用于测试 `NetworkChangeNotifier` 类的功能。 `NetworkChangeNotifier` 的核心职责是监听并报告网络连接状态的变化，例如连接类型的改变（Wi-Fi, Ethernet, Cellular 等）、DNS 服务器的变更以及连接成本的变化（是否按流量计费）。

下面详细列举该文件的功能：

**1. 测试 `NetworkChangeNotifier` 的基本功能:**

* **`NetMaxBandwidthRange` 测试:**
    * **功能:**  验证 `NetworkChangeNotifier::GetMaxBandwidthAndConnectionType` 函数返回的最大带宽和连接类型是否在合理的范围内。
    * **逻辑推理:** 它假设了不同连接类型对应的带宽范围。例如，以太网的带宽应该高于 2G，而 5G 的带宽（目前）被认为是无限的。
    * **假设输入与输出:**
        * **假设输入:**  当前系统连接类型为 Wi-Fi。
        * **预期输出:**  `max_bandwidth` 的值应该在 1.0 到 7000.0 之间，`connection_type` 应该为 `NetworkChangeNotifier::CONNECTION_WIFI`。
    * **局限性:** 这个测试依赖于运行测试的机器的实际网络连接状态，未来的网络标准可能超出当前定义的范围。

* **`ConnectionTypeFromInterfaceList` 测试:**
    * **功能:**  测试 `NetworkChangeNotifier::ConnectionTypeFromInterfaceList` 函数，该函数根据网络接口列表判断主要的连接类型。
    * **逻辑推理:**  它测试了空列表的情况，以及单个和多个接口的情况。当存在多个不同类型的接口时，它期望返回 `CONNECTION_UNKNOWN`，除非所有接口都是同一类型。
    * **假设输入与输出:**
        * **假设输入:**  一个包含两个接口的列表，一个是 Ethernet，另一个是 Wi-Fi。
        * **预期输出:** `NetworkChangeNotifier::CONNECTION_UNKNOWN`。
        * **假设输入:**  一个包含两个 Ethernet 接口的列表。
        * **预期输出:** `NetworkChangeNotifier::CONNECTION_ETHERNET`。

**2. 测试特定平台和场景下的网络接口处理:**

* **`IgnoreTeredoOnWindows` 测试:**
    * **功能:**  验证在 Windows 平台上是否正确忽略了 Teredo 隧道伪接口。Teredo 是一种 IPv6 过渡技术。
    * **逻辑推理:** 在 Windows 上，Teredo 接口不应被视为实际的网络连接类型。
    * **假设输入与输出:**
        * **假设输入:**  一个包含 Teredo 接口的网络接口列表。
        * **预期输出 (Windows):** `NetworkChangeNotifier::CONNECTION_NONE`。
        * **预期输出 (非 Windows):** `NetworkChangeNotifier::CONNECTION_ETHERNET`（因为 Teredo 被模拟为 Ethernet）。

* **`IgnoreAirdropOnMac` 测试:**
    * **功能:** 验证在 macOS 平台上是否正确忽略了 AirDrop 接口。
    * **逻辑推理:** AirDrop 是本地文件共享功能，其网络接口不应被视为主要的互联网连接。
    * **假设输入与输出:**
        * **假设输入:**  一个包含 AirDrop 接口的网络接口列表。
        * **预期输出 (macOS):** `NetworkChangeNotifier::CONNECTION_NONE`。
        * **预期输出 (非 macOS):** `NetworkChangeNotifier::CONNECTION_ETHERNET`。

* **`IgnoreTunnelsOnMac` 测试:**
    * **功能:** 验证在 macOS 平台上是否正确忽略了用户空间隧道接口 (utun)。
    * **逻辑推理:** 这些隧道接口通常用于 VPN 等，不代表物理网络连接类型。
    * **假设输入与输出:**
        * **假设输入:**  一个包含 utun 接口的网络接口列表。
        * **预期输出 (macOS):** `NetworkChangeNotifier::CONNECTION_NONE`。
        * **预期输出 (非 macOS):** `NetworkChangeNotifier::CONNECTION_ETHERNET`。

* **`IgnoreDisconnectedEthernetOnMac` 测试:**
    * **功能:** 验证在 macOS 平台上是否正确忽略了断开连接的以太网接口。
    * **逻辑推理:** 虽然接口类型是 Ethernet，但如果未连接，则不应被视为活动的网络连接。
    * **假设输入与输出:**
        * **假设输入:**  一个包含未连接的以太网接口的网络接口列表。
        * **预期输出 (macOS):** `NetworkChangeNotifier::CONNECTION_NONE`。
        * **预期输出 (非 macOS):** `NetworkChangeNotifier::CONNECTION_ETHERNET`。

* **`IgnoreVMInterfaces` 测试:**
    * **功能:** 验证是否正确忽略了虚拟机 (VM) 的网络接口。
    * **逻辑推理:** VM 的网络接口通常不代表主机的实际互联网连接。
    * **假设输入与输出:**
        * **假设输入:**  包含 `vmnet1` 或 "VMware Network Adapter VMnet1" 接口的列表。
        * **预期输出:** `NetworkChangeNotifier::CONNECTION_NONE`。

**3. 测试其他功能和通知机制:**

* **`GetConnectionSubtype` 测试:**
    * **功能:**  简单地调用 `NetworkChangeNotifier::GetConnectionSubtype()` 并确保不会崩溃。这通常是一个基本的健全性检查。

* **`TriggerNonSystemDnsChange` 测试:**
    * **功能:**  测试手动触发 DNS 变更通知的机制。
    * **逻辑推理:**  模拟非系统级别的 DNS 变更，例如应用程序内部的 DNS 设置变更。
    * **假设输入与输出:**
        * **假设操作:** 调用 `NetworkChangeNotifier::TriggerNonSystemDnsChange()`。
        * **预期输出:**  已注册的 `DNSObserver` 的 `OnDNSChanged()` 方法会被调用。

* **`TriggerConnectionCostChange` 测试:**
    * **功能:** 测试触发连接成本变更通知的机制。
    * **逻辑推理:**  模拟连接成本的变化，例如从 Wi-Fi 切换到移动数据。
    * **假设输入与输出:**
        * **假设操作:** 调用 `NetworkChangeNotifier::NotifyObserversOfConnectionCostChangeForTests` 并传入 `CONNECTION_COST_METERED`。
        * **预期输出:**  已注册的 `ConnectionCostObserver` 的 `OnConnectionCostChanged()` 方法会被调用，并收到 `CONNECTION_COST_METERED`。

* **`ConnectionCostDefaultsToCellular` 测试:**
    * **功能:**  测试在没有明确成本信息的情况下，连接成本是否正确默认为蜂窝网络（按流量计费）。
    * **逻辑推理:**  蜂窝网络通常被认为是按流量计费的。
    * **假设输入与输出:**
        * **假设输入:**  连接类型设置为 `CONNECTION_4G`。
        * **预期输出:** `NetworkChangeNotifier::GetConnectionCost()` 返回 `CONNECTION_COST_METERED`。
        * **假设输入:**  连接类型设置为 `CONNECTION_WIFI`。
        * **预期输出:** `NetworkChangeNotifier::GetConnectionCost()` 返回 `CONNECTION_COST_UNMETERED`。

* **`GetConnectionCost` 测试:**
    * **功能:**  确保 `NetworkChangeNotifier::GetConnectionCost()` 返回一个不是 `CONNECTION_COST_UNKNOWN` 的值。

* **`AddObserver` 测试:**
    * **功能:**  测试添加 `ConnectionCostObserver` 不会发生致命错误。

**与 JavaScript 功能的关系:**

`NetworkChangeNotifier` 在 Chromium 中扮演着至关重要的角色，它为浏览器中的 JavaScript 提供了关于网络连接状态的信息。JavaScript 可以通过 **Network Information API** 来访问这些信息。

**举例说明:**

1. **判断网络类型:** 网页上的 JavaScript 可以使用 `navigator.connection.effectiveType` 来获取当前的网络连接类型 (e.g., "4g", "wifi", "slow-2g")。 `NetworkChangeNotifier` 的状态变化会触发 Chromium 内部机制更新这个 API 的值。

2. **判断是否按流量计费:** JavaScript 可以使用 `navigator.connection.saveData` 来判断用户是否开启了省流模式，这通常与 `NetworkChangeNotifier` 报告的连接成本 (`CONNECTION_COST_METERED`) 相关联。

3. **网络状态变化事件:** JavaScript 可以监听 `online` 和 `offline` 事件，这些事件的触发也依赖于 `NetworkChangeNotifier` 检测到的网络连接变化。

**用户操作如何一步步到达这里 (作为调试线索):**

假设一个用户报告了网页在网络切换后行为异常的问题，例如图片加载失败或视频卡顿。作为开发人员，你可以采取以下步骤进行调试，最终可能会涉及到 `NetworkChangeNotifier`：

1. **用户报告问题:** 用户反馈在从 Wi-Fi 切换到移动数据后，网页加载变慢或者某些功能失效。

2. **开发者初步排查:**
   * **浏览器控制台检查:** 查看控制台是否有网络请求错误或 JavaScript 错误。
   * **Network 面板分析:** 使用浏览器的开发者工具 Network 面板，查看网络请求的时序、状态和大小，确认是否是因为网络切换导致请求失败或延迟。

3. **怀疑网络状态监听问题:**  如果问题与网络切换紧密相关，开发者可能会怀疑浏览器是否正确地监听和处理了网络状态的变化。

4. **查看 Chromium 网络栈代码:**  开发者可能会查看与网络状态相关的 Chromium 源代码，`net/base/network_change_notifier.h` 和 `net/base/network_change_notifier_unittest.cc` 就是关键的文件。

5. **断点调试 `NetworkChangeNotifier`:** 在 Chromium 源代码中设置断点，例如在 `NetworkChangeNotifier::NotifyObserversOfConnectionTypeChange` 或 `NetworkChangeNotifier::GetConnectionCost` 等方法中，以便跟踪网络状态变化时，这些方法是否被正确调用以及参数的值。

6. **模拟网络切换:** 使用操作系统的网络设置模拟 Wi-Fi 和移动数据之间的切换，观察断点是否被触发，以及 `NetworkChangeNotifier` 是否正确检测到了变化。

7. **检查 JavaScript Network Information API:**  在浏览器控制台中，手动检查 `navigator.connection` 对象的值，确认 JavaScript 获取到的网络信息是否与 `NetworkChangeNotifier` 的预期一致。

8. **查看平台相关的实现:** `NetworkChangeNotifier` 的具体实现依赖于操作系统。开发者可能需要查看 `net/base/network_change_notifier_*.cc` 等平台特定的文件，以了解底层是如何获取网络状态信息的。

**用户或编程常见的使用错误举例说明:**

1. **假设网络类型不变:** 开发者编写 JavaScript 代码时，可能会错误地假设用户的网络类型在整个会话期间保持不变，而没有充分处理网络切换的情况，导致 UI 状态或功能逻辑错误。

   ```javascript
   // 错误示例：假设一直是 Wi-Fi
   if (navigator.connection.type === 'wifi') {
       loadHighResolutionImages();
   } else {
       loadLowResolutionImages();
   }
   // 如果网络从 Wi-Fi 切换到 4G，可能不会重新加载低分辨率图片。
   ```

2. **未监听网络状态变化事件:**  开发者可能没有监听 `online` 和 `offline` 事件，导致应用程序在网络离线时无法给出合适的提示或进行离线缓存等处理。

   ```javascript
   window.addEventListener('offline', () => {
       console.log('网络已断开');
       showOfflineMessage();
   });
   ```

3. **过度依赖 Network Information API 的准确性:**  虽然 Network Information API 提供了有用的信息，但其准确性可能受到多种因素的影响，例如操作系统实现、驱动程序等。开发者应该考虑到这些不确定性，并进行适当的容错处理。

4. **在 Chromium 内部错误地使用 `NetworkChangeNotifier`:** 开发者在 Chromium 内部开发新功能时，可能会错误地注册或处理 `NetworkChangeNotifier` 的通知，导致网络状态的同步出现问题。例如，忘记移除不再需要的观察者，导致内存泄漏。

这个单元测试文件通过各种测试用例，确保 `NetworkChangeNotifier` 能够可靠地检测和报告网络状态的变化，这对于 Chromium 以及依赖其网络功能的 Web 应用的稳定运行至关重要。

### 提示词
```
这是目录为net/base/network_change_notifier_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_change_notifier.h"

#include "base/run_loop.h"
#include "build/build_config.h"
#include "net/base/mock_network_change_notifier.h"
#include "net/base/network_interfaces.h"
#include "net/test/test_connection_cost_observer.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

// Note: This test is subject to the host's OS and network connection. This test
// is not future-proof. New standards will come about necessitating the need to
// alter the ranges of these tests.
TEST(NetworkChangeNotifierTest, NetMaxBandwidthRange) {
  NetworkChangeNotifier::ConnectionType connection_type =
      NetworkChangeNotifier::CONNECTION_NONE;
  double max_bandwidth = 0.0;
  NetworkChangeNotifier::GetMaxBandwidthAndConnectionType(&max_bandwidth,
                                                          &connection_type);

  // Always accept infinity as it's the default value if the bandwidth is
  // unknown.
  if (max_bandwidth == std::numeric_limits<double>::infinity()) {
    EXPECT_NE(NetworkChangeNotifier::CONNECTION_NONE, connection_type);
    return;
  }

  switch (connection_type) {
    case NetworkChangeNotifier::CONNECTION_UNKNOWN:
      EXPECT_EQ(std::numeric_limits<double>::infinity(), max_bandwidth);
      break;
    case NetworkChangeNotifier::CONNECTION_ETHERNET:
      EXPECT_GE(10.0, max_bandwidth);
      EXPECT_LE(10000.0, max_bandwidth);
      break;
    case NetworkChangeNotifier::CONNECTION_WIFI:
      EXPECT_GE(1.0, max_bandwidth);
      EXPECT_LE(7000.0, max_bandwidth);
      break;
    case NetworkChangeNotifier::CONNECTION_2G:
      EXPECT_GE(0.01, max_bandwidth);
      EXPECT_LE(0.384, max_bandwidth);
      break;
    case NetworkChangeNotifier::CONNECTION_3G:
      EXPECT_GE(2.0, max_bandwidth);
      EXPECT_LE(42.0, max_bandwidth);
      break;
    case NetworkChangeNotifier::CONNECTION_4G:
      EXPECT_GE(100.0, max_bandwidth);
      EXPECT_LE(100.0, max_bandwidth);
      break;
    case NetworkChangeNotifier::CONNECTION_5G:
      // TODO(crbug.com/40148439): Expect proper bounds once we have introduced
      // subtypes for 5G connections.
      EXPECT_EQ(std::numeric_limits<double>::infinity(), max_bandwidth);
      break;
    case NetworkChangeNotifier::CONNECTION_NONE:
      EXPECT_EQ(0.0, max_bandwidth);
      break;
    case NetworkChangeNotifier::CONNECTION_BLUETOOTH:
      EXPECT_GE(1.0, max_bandwidth);
      EXPECT_LE(24.0, max_bandwidth);
      break;
  }
}

TEST(NetworkChangeNotifierTest, ConnectionTypeFromInterfaceList) {
  NetworkInterfaceList list;

  // Test empty list.
  EXPECT_EQ(NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list),
            NetworkChangeNotifier::CONNECTION_NONE);

  for (int i = NetworkChangeNotifier::CONNECTION_UNKNOWN;
       i <= NetworkChangeNotifier::CONNECTION_LAST; i++) {
    // Check individual types.
    NetworkInterface interface;
    interface.type = static_cast<NetworkChangeNotifier::ConnectionType>(i);
    list.clear();
    list.push_back(interface);
    EXPECT_EQ(NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list), i);
    // Check two types.
    for (int j = NetworkChangeNotifier::CONNECTION_UNKNOWN;
         j <= NetworkChangeNotifier::CONNECTION_LAST; j++) {
      list.clear();
      interface.type = static_cast<NetworkChangeNotifier::ConnectionType>(i);
      list.push_back(interface);
      interface.type = static_cast<NetworkChangeNotifier::ConnectionType>(j);
      list.push_back(interface);
      EXPECT_EQ(NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list),
                i == j ? i : NetworkChangeNotifier::CONNECTION_UNKNOWN);
    }
  }
}

TEST(NetworkChangeNotifierTest, IgnoreTeredoOnWindows) {
  NetworkInterfaceList list;
  NetworkInterface interface_teredo;
  interface_teredo.type = NetworkChangeNotifier::CONNECTION_ETHERNET;
  interface_teredo.friendly_name = "Teredo Tunneling Pseudo-Interface";
  list.push_back(interface_teredo);

#if BUILDFLAG(IS_WIN)
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_NONE,
            NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list));
#else
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_ETHERNET,
            NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list));
#endif
}

TEST(NetworkChangeNotifierTest, IgnoreAirdropOnMac) {
  NetworkInterfaceList list;
  NetworkInterface interface_airdrop;
  interface_airdrop.type = NetworkChangeNotifier::CONNECTION_ETHERNET;
  interface_airdrop.name = "awdl0";
  interface_airdrop.friendly_name = "awdl0";
  interface_airdrop.address =
      // Link-local IPv6 address
      IPAddress(0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4);
  list.push_back(interface_airdrop);

#if BUILDFLAG(IS_APPLE)
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_NONE,
            NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list));
#else
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_ETHERNET,
            NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list));
#endif
}

TEST(NetworkChangeNotifierTest, IgnoreTunnelsOnMac) {
  NetworkInterfaceList list;
  NetworkInterface interface_tunnel;
  interface_tunnel.type = NetworkChangeNotifier::CONNECTION_ETHERNET;
  interface_tunnel.name = "utun0";
  interface_tunnel.friendly_name = "utun0";
  interface_tunnel.address =
      // Link-local IPv6 address
      IPAddress(0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 3, 2, 1);
  list.push_back(interface_tunnel);

#if BUILDFLAG(IS_APPLE)
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_NONE,
            NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list));
#else
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_ETHERNET,
            NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list));
#endif
}

TEST(NetworkChangeNotifierTest, IgnoreDisconnectedEthernetOnMac) {
  NetworkInterfaceList list;
  NetworkInterface interface_ethernet;
  interface_ethernet.type = NetworkChangeNotifier::CONNECTION_ETHERNET;
  interface_ethernet.name = "en5";
  interface_ethernet.friendly_name = "en5";
  interface_ethernet.address =
      // Link-local IPv6 address
      IPAddress(0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 2, 3);
  list.push_back(interface_ethernet);

#if BUILDFLAG(IS_APPLE)
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_NONE,
            NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list));
#else
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_ETHERNET,
            NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list));
#endif
}

TEST(NetworkChangeNotifierTest, IgnoreVMInterfaces) {
  NetworkInterfaceList list;
  NetworkInterface interface_vmnet_linux;
  interface_vmnet_linux.type = NetworkChangeNotifier::CONNECTION_ETHERNET;
  interface_vmnet_linux.name = "vmnet1";
  interface_vmnet_linux.friendly_name = "vmnet1";
  list.push_back(interface_vmnet_linux);

  NetworkInterface interface_vmnet_win;
  interface_vmnet_win.type = NetworkChangeNotifier::CONNECTION_ETHERNET;
  interface_vmnet_win.name = "virtualdevice";
  interface_vmnet_win.friendly_name = "VMware Network Adapter VMnet1";
  list.push_back(interface_vmnet_win);

  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_NONE,
            NetworkChangeNotifier::ConnectionTypeFromInterfaceList(list));
}

TEST(NetworkChangeNotifierTest, GetConnectionSubtype) {
  // Call GetConnectionSubtype() and ensure that there is no crash.
  NetworkChangeNotifier::GetConnectionSubtype();
}

class NetworkChangeNotifierMockedTest : public TestWithTaskEnvironment {
 protected:
  test::ScopedMockNetworkChangeNotifier mock_notifier_;
};

class TestDnsObserver : public NetworkChangeNotifier::DNSObserver {
 public:
  void OnDNSChanged() override { ++dns_changed_calls_; }

  int dns_changed_calls() const { return dns_changed_calls_; }

 private:
  int dns_changed_calls_ = 0;
};

TEST_F(NetworkChangeNotifierMockedTest, TriggerNonSystemDnsChange) {
  TestDnsObserver observer;
  NetworkChangeNotifier::AddDNSObserver(&observer);

  ASSERT_EQ(0, observer.dns_changed_calls());

  NetworkChangeNotifier::TriggerNonSystemDnsChange();
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1, observer.dns_changed_calls());

  NetworkChangeNotifier::RemoveDNSObserver(&observer);
}

TEST_F(NetworkChangeNotifierMockedTest, TriggerConnectionCostChange) {
  TestConnectionCostObserver observer;
  NetworkChangeNotifier::AddConnectionCostObserver(&observer);

  ASSERT_EQ(0u, observer.cost_changed_calls());

  NetworkChangeNotifier::NotifyObserversOfConnectionCostChangeForTests(
      NetworkChangeNotifier::CONNECTION_COST_METERED);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, observer.cost_changed_calls());
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_COST_METERED,
            observer.cost_changed_inputs()[0]);

  NetworkChangeNotifier::RemoveConnectionCostObserver(&observer);
  NetworkChangeNotifier::NotifyObserversOfConnectionCostChangeForTests(
      NetworkChangeNotifier::CONNECTION_COST_UNMETERED);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(1u, observer.cost_changed_calls());
}

TEST_F(NetworkChangeNotifierMockedTest, ConnectionCostDefaultsToCellular) {
  mock_notifier_.mock_network_change_notifier()
      ->SetUseDefaultConnectionCostImplementation(true);

  mock_notifier_.mock_network_change_notifier()->SetConnectionType(
      NetworkChangeNotifier::CONNECTION_4G);
  EXPECT_TRUE(NetworkChangeNotifier::IsConnectionCellular(
      NetworkChangeNotifier::GetConnectionType()));
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_COST_METERED,
            NetworkChangeNotifier::GetConnectionCost());

  mock_notifier_.mock_network_change_notifier()->SetConnectionType(
      NetworkChangeNotifier::CONNECTION_WIFI);
  EXPECT_FALSE(NetworkChangeNotifier::IsConnectionCellular(
      NetworkChangeNotifier::GetConnectionType()));
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_COST_UNMETERED,
            NetworkChangeNotifier::GetConnectionCost());
}

class NetworkChangeNotifierConnectionCostTest : public TestWithTaskEnvironment {
 public:
  void SetUp() override {
    network_change_notifier_ = NetworkChangeNotifier::CreateIfNeeded();
  }

 private:
  // Allows creating a new NetworkChangeNotifier.  Must be created before
  // |network_change_notifier_| and destroyed after it to avoid DCHECK failures.
  NetworkChangeNotifier::DisableForTest disable_for_test_;
  std::unique_ptr<NetworkChangeNotifier> network_change_notifier_;
};

TEST_F(NetworkChangeNotifierConnectionCostTest, GetConnectionCost) {
  EXPECT_NE(NetworkChangeNotifier::ConnectionCost::CONNECTION_COST_UNKNOWN,
            NetworkChangeNotifier::GetConnectionCost());
}

TEST_F(NetworkChangeNotifierConnectionCostTest, AddObserver) {
  TestConnectionCostObserver observer;
  EXPECT_NO_FATAL_FAILURE(
      NetworkChangeNotifier::AddConnectionCostObserver(&observer));
  // RunUntilIdle because the secondary work resulting from adding an observer
  // may be posted to a task queue.
  base::RunLoop().RunUntilIdle();
}

}  // namespace net
```