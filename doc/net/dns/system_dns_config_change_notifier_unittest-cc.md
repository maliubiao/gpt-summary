Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ test file (`system_dns_config_change_notifier_unittest.cc`) and explain its functionality, its relation to JavaScript (if any), its logic, potential usage errors, and debugging context.

2. **Initial Scan for Keywords and Structure:**  Quickly scan the code for important keywords and structural elements. This helps establish the overall context. Keywords like `#include`, `namespace`, `class`, `TEST_F`, `EXPECT_THAT`, and the presence of a `TestObserver` class are strong indicators of a unit test file. The file name itself (`system_dns_config_change_notifier_unittest.cc`) strongly suggests it's testing a class named `SystemDnsConfigChangeNotifier`.

3. **Identify the Class Under Test:** The file name and the structure of the `TEST_F` macros clearly point to `SystemDnsConfigChangeNotifier` as the class being tested.

4. **Analyze the `SystemDnsConfigChangeNotifier` Class (Inferred):**  Although the implementation of `SystemDnsConfigChangeNotifier` isn't provided in *this* file, we can infer its purpose from how it's used in the tests. The presence of `AddObserver` and `RemoveObserver` methods, and the `OnSystemDnsConfigChanged` callback in the `TestObserver`, strongly indicate that `SystemDnsConfigChangeNotifier` implements an observer pattern for DNS configuration changes. It likely listens for system-level DNS changes and notifies registered observers.

5. **Understand the Test Setup (`SystemDnsConfigChangeNotifierTest`):**
    * **Inheritance:**  It inherits from `TestWithTaskEnvironment`, suggesting it's using a test framework that handles asynchronous tasks.
    * **Task Runner:**  The `notifier_task_runner_` and its initialization using `ThreadPool::CreateSequencedTaskRunner({base::MayBlock()})` indicates that the `SystemDnsConfigChangeNotifier` likely operates on a separate thread (or sequenced task runner) that can block. This is common for I/O-bound operations like network configuration.
    * **Mock DNS Service:** The `TestDnsConfigService` is crucial. It's a *mock* or *fake* implementation of a real DNS configuration service. This allows the tests to control the DNS configuration and simulate changes without actually modifying the system's DNS settings. The `OnConfigRead` and `InvalidateConfig` methods in `TestDnsConfigService` are used to simulate DNS configuration updates and removals.

6. **Analyze the `TestObserver` Class:**
    * **Observer Pattern:** It implements the `SystemDnsConfigChangeNotifier::Observer` interface, confirming the observer pattern.
    * **Notification Tracking:** The `configs_received_` vector stores the received DNS configurations.
    * **Synchronization:** The `WaitForNotification` and `WaitForNotifications` methods, using `base::RunLoop`, are used to synchronize the test execution with the asynchronous notifications. This is essential for testing asynchronous behavior.
    * **Sequence Checker:** The `SEQUENCE_CHECKER` macro suggests that the observer expects to receive notifications on a specific sequence (likely the main test thread).

7. **Analyze Individual Test Cases (`TEST_F` macros):**  Go through each test case and understand what aspect of `SystemDnsConfigChangeNotifier` it's testing:
    * `ReceiveNotification`: Basic test for receiving a single configuration change.
    * `ReceiveNotification_Multiple`: Tests receiving multiple configuration changes.
    * `ReceiveInitialNotification`: Checks if a newly added observer receives the currently loaded configuration.
    * `ReceiveInitialNotification_Multiple`:  Checks that a new observer only gets the *latest* configuration.
    * `NotificationsStopAfterRemoval`: Verifies that notifications stop after removing an observer.
    * `UnchangedConfigs`: Confirms that duplicate (unchanged) configurations don't trigger notifications.
    * `UnloadedConfig`: Tests the notification when the DNS configuration is invalidated (becomes unavailable).
    * `UnloadedConfig_Multiple`: Checks that multiple invalidations result in only one notification.
    * `InitialConfigInvalid`:  Verifies that no initial notification is sent if the initially loaded config is invalid.
    * `RefreshConfig`: Tests the `RefreshConfig` method, which likely forces a refresh of the DNS configuration.

8. **Look for JavaScript Connections:** Carefully review the code and the inferred functionality. There's no direct JavaScript code in this C++ file. The interaction with JavaScript would happen at a higher level in the Chromium browser, where JavaScript code might trigger actions that eventually lead to DNS configuration changes being observed by `SystemDnsConfigChangeNotifier`.

9. **Consider Logic and Scenarios:**  For each test case, think about the logical flow and what inputs and outputs are being tested. This helps formulate the "假设输入与输出" section.

10. **Identify Potential User/Programming Errors:** Based on the functionality, think about common mistakes developers might make when using `SystemDnsConfigChangeNotifier` or its related components. For example, forgetting to remove an observer can lead to memory leaks or unexpected behavior.

11. **Trace User Operations (Debugging Context):**  Think about how a user interaction in a browser could eventually lead to the execution of this code. This involves tracing the path from user action (e.g., navigating to a website) to DNS resolution and configuration management.

12. **Structure the Answer:** Organize the findings into logical sections as requested: 功能, 与 JavaScript 的关系, 逻辑推理, 使用错误, and 调试线索. Use clear and concise language.

13. **Refine and Review:**  Read through the entire analysis to ensure accuracy, clarity, and completeness. Double-check for any misunderstandings or missed points. For example, initially, I might focus too much on the *specifics* of the DNS configuration data. However, the tests are more about the *notification mechanism* itself. Refining involves recognizing this focus.

This detailed breakdown reflects the kind of systematic approach needed to understand and analyze even seemingly simple code files. It involves both code-level analysis and a broader understanding of the system's architecture and purpose.
这个文件 `net/dns/system_dns_config_change_notifier_unittest.cc` 是 Chromium 网络栈中的一个单元测试文件。它的主要功能是测试 `SystemDnsConfigChangeNotifier` 类的功能。

**功能:**

`SystemDnsConfigChangeNotifier` 的主要功能是监听系统级别的 DNS 配置变化，并在配置发生改变时通知其观察者 (observers)。这个测试文件通过模拟 DNS 配置的变化，并验证观察者是否正确接收到通知，来确保 `SystemDnsConfigChangeNotifier` 正常工作。

具体来说，测试文件覆盖了以下场景：

* **接收单个通知:** 当 DNS 配置发生变化时，观察者能否收到通知。
* **接收多个通知:** 当 DNS 配置连续发生多次变化时，观察者能否接收到所有通知。
* **接收初始通知:** 当观察者注册时，如果已经存在 DNS 配置，观察者能否立即收到一个包含当前配置的通知。
* **移除观察者后停止接收通知:** 当观察者被移除后，它不应该再接收到任何新的 DNS 配置变化通知。
* **忽略未变化的配置:** 当新的 DNS 配置与之前的配置相同时，观察者不应该收到通知。
* **接收配置被卸载的通知:** 当 DNS 配置被标记为无效时，观察者应该收到一个表示配置为空的通知。
* **处理初始配置无效的情况:** 如果在观察者注册前，DNS 配置已经被标记为无效，观察者不应立即收到通知，直到有新的有效配置出现。
* **刷新配置:** 测试 `RefreshConfig` 方法是否能触发配置的重新加载和通知。

**与 JavaScript 的关系:**

`SystemDnsConfigChangeNotifier` 本身是用 C++ 编写的，直接与 JavaScript 没有关系。然而，在 Chromium 浏览器中，JavaScript 代码（例如在浏览器扩展或网页脚本中）可能会触发需要进行 DNS 查询的操作。当系统的 DNS 配置发生变化时，`SystemDnsConfigChangeNotifier` 会通知 C++ 网络栈，进而影响到后续的 DNS 查询行为。

**举例说明:**

假设一个 JavaScript 应用程序尝试通过 `fetch` API 访问一个域名。

1. **初始状态:** 系统使用一组 DNS 服务器。`SystemDnsConfigChangeNotifier` 维护着当前的 DNS 配置。
2. **系统 DNS 配置变更:** 用户手动修改了操作系统的网络设置，更改了 DNS 服务器的地址。
3. **通知:** 操作系统会发出 DNS 配置变更的通知。`SystemDnsConfigChangeNotifier` 监听到了这个通知。
4. **JavaScript 的影响:** 当 JavaScript 代码再次尝试使用 `fetch` 访问域名时，Chromium 的网络栈会使用更新后的 DNS 配置进行查询。这可能会导致以下情况：
    * **成功解析:** 如果新的 DNS 配置是有效的，`fetch` 请求会成功解析域名并建立连接。
    * **解析失败:** 如果新的 DNS 配置不正确或无法访问，`fetch` 请求可能会失败并抛出网络错误。

**逻辑推理 (假设输入与输出):**

假设我们运行 `ReceiveNotification` 测试用例：

* **假设输入:**
    * 初始状态下，`SystemDnsConfigChangeNotifier` 正在运行，但可能没有加载任何 DNS 配置。
    * 创建一个 `TestObserver` 并注册到 `SystemDnsConfigChangeNotifier`。
    * 通过 `test_config_service_` 模拟 DNS 配置的读取，并提供 `kConfig` 作为新的 DNS 配置。
* **预期输出:**
    * `TestObserver` 的 `OnSystemDnsConfigChanged` 方法会被调用一次。
    * `observer.configs_received()` 向量会包含一个 `std::optional<DnsConfig>`，其值为 `kConfig`。

假设我们运行 `UnloadedConfig` 测试用例：

* **假设输入:**
    * `SystemDnsConfigChangeNotifier` 已经加载了 `kConfig`。
    * 创建一个 `TestObserver` 并注册。它会立即收到包含 `kConfig` 的通知。
    * 通过 `test_config_service_` 模拟 DNS 配置的失效 (`InvalidateConfig`)。
* **预期输出:**
    * `TestObserver` 的 `OnSystemDnsConfigChanged` 方法会被再次调用。
    * `observer.configs_received()` 向量会包含两个元素：第一个是 `kConfig`，第二个是 `std::nullopt` (表示配置为空)。

**用户或编程常见的使用错误:**

1. **忘记移除观察者:**  如果一个组件注册为 `SystemDnsConfigChangeNotifier` 的观察者，但在不再需要接收通知时忘记取消注册 (`RemoveObserver`)，可能会导致内存泄漏（如果观察者持有资源）或意外的行为（观察者在不应该响应时仍然响应）。
   ```c++
   class MyComponent : public SystemDnsConfigChangeNotifier::Observer {
    // ...
   };

   void someFunction(SystemDnsConfigChangeNotifier* notifier) {
     MyComponent* component = new MyComponent();
     notifier->AddObserver(component);
     // ... 使用 component 接收 DNS 配置变化 ...
     // 错误：忘记取消注册，导致 component 对象无法被正常释放
     // notifier->RemoveObserver(component);
     // delete component;
   }
   ```

2. **在错误的线程访问 `DnsConfig`:** `SystemDnsConfigChangeNotifier` 可能会在特定的线程上接收系统通知。观察者需要确保在正确的线程上处理接收到的 `DnsConfig`，避免线程安全问题。虽然测试代码使用了 `DCHECK_CALLED_ON_VALID_SEQUENCE` 来检查，但在实际应用中需要更加谨慎。

3. **假设通知会立即发生:**  DNS 配置的变更和通知是异步的。开发者不应该假设在系统 DNS 配置更改后，观察者会立即收到通知。依赖于立即通知可能会导致竞争条件和难以调试的问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个调试线索，以下用户操作可能会触发与 `SystemDnsConfigChangeNotifier` 相关的代码执行：

1. **用户修改操作系统 DNS 设置:**
   * **Windows:** 打开“控制面板” -> “网络和 Internet” -> “网络和共享中心” -> 点击当前的网络连接 -> 点击“属性” -> 选择 “Internet 协议版本 4 (TCP/IPv4)” 或 “Internet 协议版本 6 (TCP/IPv6)” -> 点击“属性” -> 修改“首选 DNS 服务器”或“备用 DNS 服务器”。
   * **macOS:** 打开“系统偏好设置” -> “网络” -> 选择当前的网络连接 -> 点击“高级…” -> 选择 “DNS” 标签页 -> 添加或删除 DNS 服务器。
   * **Linux:**  修改 `/etc/resolv.conf` 文件或使用网络管理工具（如 NetworkManager）。

   操作系统会检测到这些变化并发出相应的系统事件。Chromium 的网络栈中的代码（包括 `SystemDnsConfigChangeNotifier`）会监听这些事件。

2. **网络状态变化:** 连接或断开 Wi-Fi 网络，连接或断开 VPN 连接，切换网络接口等操作都可能导致 DNS 配置的变化。操作系统会更新 DNS 配置，并触发相应的通知。

3. **使用 Chromium 提供的网络配置工具:**  某些 Chromium 的实验性功能或内部设置可能允许用户修改与 DNS 相关的配置，这些操作也会触发配置变更。

**调试线索:**

当需要调试与 DNS 配置变更相关的问题时，可以关注以下几点：

* **确认操作系统是否正确发出 DNS 配置变更通知:** 可以使用操作系统提供的工具或 API 来监听系统事件，验证是否发出了预期的 DNS 配置变更通知。
* **检查 `SystemDnsConfigChangeNotifier` 是否正确接收到通知:**  可以在 `SystemDnsConfigChangeNotifier` 的代码中添加日志，查看是否捕获到了操作系统的通知，以及解析出的 DNS 配置是否正确。
* **验证观察者是否被正确通知:**  在观察者的 `OnSystemDnsConfigChanged` 方法中添加日志，确认该方法被调用，并检查接收到的 `DnsConfig` 是否与预期的变更一致。
* **检查线程上下文:** 确认 DNS 配置变更通知是在预期的线程上处理的，避免跨线程访问导致的问题。

总而言之，`net/dns/system_dns_config_change_notifier_unittest.cc` 是一个关键的测试文件，用于确保 Chromium 网络栈能够正确地响应系统级别的 DNS 配置变化，这对于保证浏览器的网络连接稳定性和安全性至关重要。

### 提示词
```
这是目录为net/dns/system_dns_config_change_notifier_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/dns/system_dns_config_change_notifier.h"

#include <optional>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/run_loop.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/dns/dns_hosts.h"
#include "net/dns/test_dns_config_service.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {
const std::vector<IPEndPoint> kNameservers = {
    IPEndPoint(IPAddress(1, 2, 3, 4), 95)};
const std::vector<IPEndPoint> kNameservers2 = {
    IPEndPoint(IPAddress(2, 3, 4, 5), 195)};
const DnsConfig kConfig(kNameservers);
const DnsConfig kConfig2(kNameservers2);
}  // namespace

class SystemDnsConfigChangeNotifierTest : public TestWithTaskEnvironment {
 public:
  // Set up a change notifier, owned on a dedicated blockable task runner, with
  // a faked underlying DnsConfigService.
  SystemDnsConfigChangeNotifierTest()
      : notifier_task_runner_(
            base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()})) {
    auto test_service = std::make_unique<TestDnsConfigService>();
    notifier_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&TestDnsConfigService::OnHostsRead,
                       base::Unretained(test_service.get()), DnsHosts()));
    test_config_service_ = test_service.get();

    notifier_ = std::make_unique<SystemDnsConfigChangeNotifier>(
        notifier_task_runner_, std::move(test_service));
  }

 protected:
  // Test observer implementation that records all notifications received in a
  // vector, and also validates that all notifications are received on the
  // expected sequence.
  class TestObserver : public SystemDnsConfigChangeNotifier::Observer {
   public:
    void OnSystemDnsConfigChanged(std::optional<DnsConfig> config) override {
      DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
      configs_received_.push_back(std::move(config));

      DCHECK_GT(notifications_remaining_, 0);
      if (--notifications_remaining_ == 0)
        run_loop_->Quit();
    }

    void WaitForNotification() { WaitForNotifications(1); }
    void WaitForNotifications(int num_notifications) {
      DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

      notifications_remaining_ = num_notifications;
      run_loop_->Run();
      run_loop_ = std::make_unique<base::RunLoop>();
    }

    void ExpectNoMoreNotifications() {
      DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
      configs_received_.clear();
      base::RunLoop().RunUntilIdle();
      EXPECT_TRUE(configs_received_.empty());
    }

    std::vector<std::optional<DnsConfig>>& configs_received() {
      return configs_received_;
    }

   private:
    int notifications_remaining_ = 0;
    std::unique_ptr<base::RunLoop> run_loop_ =
        std::make_unique<base::RunLoop>();
    std::vector<std::optional<DnsConfig>> configs_received_;
    SEQUENCE_CHECKER(sequence_checker_);
  };

  // Load a config and wait for it to be received by the notifier.
  void LoadConfig(const DnsConfig& config, bool already_loaded = false) {
    TestObserver observer;
    notifier_->AddObserver(&observer);

    // If |notifier_| already has a config loaded, |observer| will first get a
    // notification for that initial config.
    if (already_loaded)
      observer.WaitForNotification();

    notifier_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&TestDnsConfigService::OnConfigRead,
                       base::Unretained(test_config_service_), config));
    observer.WaitForNotification();

    notifier_->RemoveObserver(&observer);
  }

  scoped_refptr<base::SequencedTaskRunner> notifier_task_runner_;
  std::unique_ptr<SystemDnsConfigChangeNotifier> notifier_;
  // Owned by |notifier_|.
  raw_ptr<TestDnsConfigService> test_config_service_;
};

TEST_F(SystemDnsConfigChangeNotifierTest, ReceiveNotification) {
  TestObserver observer;

  notifier_->AddObserver(&observer);
  notifier_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&TestDnsConfigService::OnConfigRead,
                     base::Unretained(test_config_service_), kConfig));
  observer.WaitForNotification();

  EXPECT_THAT(observer.configs_received(),
              testing::ElementsAre(testing::Optional(kConfig)));
  observer.ExpectNoMoreNotifications();

  notifier_->RemoveObserver(&observer);
}

TEST_F(SystemDnsConfigChangeNotifierTest, ReceiveNotification_Multiple) {
  TestObserver observer;

  notifier_->AddObserver(&observer);
  notifier_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&TestDnsConfigService::OnConfigRead,
                     base::Unretained(test_config_service_), kConfig));
  notifier_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&TestDnsConfigService::OnConfigRead,
                     base::Unretained(test_config_service_), kConfig2));
  observer.WaitForNotifications(2);

  EXPECT_THAT(observer.configs_received(),
              testing::ElementsAre(testing::Optional(kConfig),
                                   testing::Optional(kConfig2)));
  observer.ExpectNoMoreNotifications();

  notifier_->RemoveObserver(&observer);
}

// If the notifier already has a config loaded, a new observer should receive an
// initial notification for that config.
TEST_F(SystemDnsConfigChangeNotifierTest, ReceiveInitialNotification) {
  LoadConfig(kConfig);

  TestObserver observer;
  notifier_->AddObserver(&observer);
  observer.WaitForNotification();

  EXPECT_THAT(observer.configs_received(),
              testing::ElementsAre(testing::Optional(kConfig)));
  observer.ExpectNoMoreNotifications();

  notifier_->RemoveObserver(&observer);
}

// If multiple configs have been read before adding an Observer, should notify
// it only of the most recent.
TEST_F(SystemDnsConfigChangeNotifierTest, ReceiveInitialNotification_Multiple) {
  LoadConfig(kConfig);
  LoadConfig(kConfig2, true /* already_loaded */);

  TestObserver observer;
  notifier_->AddObserver(&observer);
  observer.WaitForNotification();

  EXPECT_THAT(observer.configs_received(),
              testing::ElementsAre(testing::Optional(kConfig2)));
  observer.ExpectNoMoreNotifications();

  notifier_->RemoveObserver(&observer);
}

TEST_F(SystemDnsConfigChangeNotifierTest, NotificationsStopAfterRemoval) {
  TestObserver observer;
  notifier_->AddObserver(&observer);
  notifier_->RemoveObserver(&observer);

  LoadConfig(kConfig);
  LoadConfig(kConfig2, true /* already_loaded */);

  EXPECT_TRUE(observer.configs_received().empty());
  observer.ExpectNoMoreNotifications();
}

TEST_F(SystemDnsConfigChangeNotifierTest, UnchangedConfigs) {
  LoadConfig(kConfig);

  TestObserver observer;
  notifier_->AddObserver(&observer);
  observer.WaitForNotification();

  // Expect no notifications from duplicate configs.
  notifier_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&TestDnsConfigService::OnConfigRead,
                     base::Unretained(test_config_service_), kConfig));
  notifier_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&TestDnsConfigService::OnConfigRead,
                     base::Unretained(test_config_service_), kConfig));
  observer.ExpectNoMoreNotifications();

  // Notification on new config.
  notifier_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&TestDnsConfigService::OnConfigRead,
                     base::Unretained(test_config_service_), kConfig2));
  observer.WaitForNotification();
  EXPECT_THAT(observer.configs_received(),
              testing::ElementsAre(testing::Optional(kConfig2)));
  observer.ExpectNoMoreNotifications();

  notifier_->RemoveObserver(&observer);
}

TEST_F(SystemDnsConfigChangeNotifierTest, UnloadedConfig) {
  LoadConfig(kConfig);

  TestObserver observer;
  notifier_->AddObserver(&observer);
  // Initial config.
  observer.WaitForNotification();

  notifier_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&TestDnsConfigService::InvalidateConfig,
                                base::Unretained(test_config_service_)));
  observer.WaitForNotification();

  EXPECT_THAT(observer.configs_received(),
              testing::ElementsAre(testing::Optional(kConfig), std::nullopt));
  observer.ExpectNoMoreNotifications();

  notifier_->RemoveObserver(&observer);
}

// All invalid configs are considered the same for notifications, so only expect
// a single notification on multiple config invalidations.
TEST_F(SystemDnsConfigChangeNotifierTest, UnloadedConfig_Multiple) {
  LoadConfig(kConfig);

  TestObserver observer;
  notifier_->AddObserver(&observer);
  // Initial config.
  observer.WaitForNotification();

  notifier_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&TestDnsConfigService::InvalidateConfig,
                                base::Unretained(test_config_service_)));
  notifier_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&TestDnsConfigService::InvalidateConfig,
                                base::Unretained(test_config_service_)));
  observer.WaitForNotification();  // Only 1 notification expected.

  EXPECT_THAT(observer.configs_received(),
              testing::ElementsAre(testing::Optional(kConfig), std::nullopt));
  observer.ExpectNoMoreNotifications();

  notifier_->RemoveObserver(&observer);
}

TEST_F(SystemDnsConfigChangeNotifierTest, InitialConfigInvalid) {
  // Add and invalidate a config (using an extra observer to wait for
  // invalidation to complete).
  LoadConfig(kConfig);
  TestObserver setup_observer;
  notifier_->AddObserver(&setup_observer);
  setup_observer.WaitForNotification();
  notifier_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&TestDnsConfigService::InvalidateConfig,
                                base::Unretained(test_config_service_)));
  setup_observer.WaitForNotification();
  notifier_->RemoveObserver(&setup_observer);

  TestObserver observer;
  notifier_->AddObserver(&observer);

  // No notification expected until first valid config.
  observer.ExpectNoMoreNotifications();

  // Notification on new config.
  notifier_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&TestDnsConfigService::OnConfigRead,
                     base::Unretained(test_config_service_), kConfig));
  observer.WaitForNotification();
  EXPECT_THAT(observer.configs_received(),
              testing::ElementsAre(testing::Optional(kConfig)));
  observer.ExpectNoMoreNotifications();

  notifier_->RemoveObserver(&observer);
}

TEST_F(SystemDnsConfigChangeNotifierTest, RefreshConfig) {
  test_config_service_->SetConfigForRefresh(kConfig);

  TestObserver observer;
  notifier_->AddObserver(&observer);

  notifier_->RefreshConfig();
  observer.WaitForNotification();

  EXPECT_THAT(observer.configs_received(),
              testing::ElementsAre(testing::Optional(kConfig)));
  observer.ExpectNoMoreNotifications();

  notifier_->RemoveObserver(&observer);
}

}  // namespace net
```