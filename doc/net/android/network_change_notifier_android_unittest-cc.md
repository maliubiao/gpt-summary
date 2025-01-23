Response:
Let's break down the thought process for analyzing this C++ unittest file.

1. **Identify the Core Subject:** The filename `network_change_notifier_android_unittest.cc` immediately tells us this file is for testing the `network_change_notifier_android.h` component. The "unittest" suffix is a strong indicator of unit testing.

2. **Understand the Purpose of Unit Tests:** Unit tests aim to isolate and verify the behavior of individual units of code (classes, functions). This means the test file will likely create instances of the class being tested and interact with its methods to check if they work as expected.

3. **Scan for Key Classes and Methods:** Look for the main class being tested. In this case, it's clearly `NetworkChangeNotifierAndroid` and potentially its delegate `NetworkChangeNotifierDelegateAndroid`. Also, pay attention to helper classes defined within the test file itself (like the various `Observer` classes). These often simulate dependencies or allow for observation of the tested class's behavior.

4. **Analyze Helper Classes:**
    * `NetworkChangeNotifierDelegateAndroidObserver`: This class *observes* the `NetworkChangeNotifierDelegateAndroid`. The methods like `OnConnectionTypeChanged`, `OnConnectionCostChanged`, etc., tell us what kind of events the delegate can notify about. The counters within this class suggest it's used to verify that the correct number of notifications are sent.
    * `NetworkChangeNotifierObserver`: This is a simpler observer for `NetworkChangeNotifier`, specifically focusing on connection type changes. Again, it uses a counter to track notifications.
    * `NetworkChangeNotifierConnectionCostObserver` and `NetworkChangeNotifierMaxBandwidthObserver`: Similar to the above, but specifically for connection cost and maximum bandwidth changes.
    * `TestNetworkObserver`: This observer focuses on network-level events like connections, disconnections, and default network changes. The `ExpectChange` method is a strong hint that this observer is used to assert that specific events occur in a specific order with specific network handles. The `ChangeType` enum helps categorize these events.

5. **Examine Test Fixtures:** The `BaseNetworkChangeNotifierAndroidTest`, `NetworkChangeNotifierAndroidTest`, and `NetworkChangeNotifierDelegateAndroidTest` classes are test fixtures (using the `TEST_F` macro indicates this). They set up the environment for the tests.
    * `BaseNetworkChangeNotifierAndroidTest`:  Provides common setup and helper methods for simulating network changes (`SetOnline`, `SetOffline`, `FakeConnectionCostChange`, etc.). The `RunTest` method is a reusable test pattern for verifying connection type change notifications.
    * `NetworkChangeNotifierAndroidTest`:  Creates an instance of `NetworkChangeNotifierAndroid` and registers observers. This is where the primary tests for `NetworkChangeNotifierAndroid` reside.
    * `NetworkChangeNotifierDelegateAndroidTest`: Creates an instance of `NetworkChangeNotifierDelegateAndroid` and registers the `NetworkChangeNotifierDelegateAndroidObserver`. This fixture is used to test the delegate directly.

6. **Analyze Individual Tests (using `TEST_F`):**  Go through each test function and understand its purpose. The test names are often descriptive.
    * Tests like `DelegateObserverNotified`, `NotificationsSentToNetworkChangeNotifierAndroid`, and `NotificationsSentToClientsOfNetworkChangeNotifier` verify the notification mechanism.
    * Tests like `ConnectionCost`, `MaxBandwidth` check the retrieval of connection cost and bandwidth information.
    * The `NetworkCallbacks` test is comprehensive, verifying the handling of various network events (connect, disconnect, default network change).
    * Tests like `TypeChangeIsSynchronous` focus on specific implementation details (synchronicity of notifications).

7. **Look for Relationships with JavaScript:**  Consider how network status might be exposed to JavaScript in a browser. The `NetworkChangeNotifier` likely plays a role in providing this information. Think about browser APIs like `navigator.onLine` or APIs that provide more detailed network information. This is where the connection to JavaScript arises.

8. **Consider Logic and Assumptions:** For tests that simulate events, identify the assumptions made and the expected outputs. For example, in the `NetworkCallbacks` test, the sequence of `FakeNetworkChange` calls and the corresponding `ExpectChange` calls clearly show the assumed input and expected output.

9. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when using the `NetworkChangeNotifier`. For instance, forgetting to add or remove observers, or making assumptions about the timing of notifications. The tests themselves sometimes implicitly highlight these potential issues.

10. **Consider the Debugging Perspective:**  Imagine you are debugging a network-related issue. How would you reach this code?  What user actions or system events would trigger the network change notifications? This helps connect the code to a real-world scenario.

By following these steps, we can systematically dissect the C++ unittest file and understand its functionality, its relationship to other parts of the system (including potentially JavaScript), and identify potential issues and debugging paths. The key is to move from the general purpose of the file to the specific details of each test case, while keeping the broader context in mind.
这个文件 `net/android/network_change_notifier_android_unittest.cc` 是 Chromium 网络栈中用于测试 `net/android/network_change_notifier_android.h` 和相关功能的单元测试文件。 它的主要功能是验证在 Android 平台上网络状态变化时，`NetworkChangeNotifierAndroid` 类及其委托（`NetworkChangeNotifierDelegateAndroid`）的行为是否符合预期。

以下是该文件的具体功能分解：

**1. 提供测试基础设施:**

* **定义枚举 `ChangeType`:**  用于表示网络变化的类型，例如 `CONNECTED`（已连接）, `SOON_TO_DISCONNECT`（即将断开连接）, `DISCONNECTED`（已断开连接）, `MADE_DEFAULT`（成为默认网络）。
* **定义观察者类:**
    * `NetworkChangeNotifierDelegateAndroidObserver`:  用于观察 `NetworkChangeNotifierDelegateAndroid` 的状态变化，并记录接收到的通知数量，例如连接类型变化、连接成本变化、最大带宽变化等。
    * `NetworkChangeNotifierObserver`:  用于观察 `NetworkChangeNotifier` 的连接类型变化通知。
    * `NetworkChangeNotifierConnectionCostObserver`: 用于观察 `NetworkChangeNotifier` 的连接成本变化通知。
    * `NetworkChangeNotifierMaxBandwidthObserver`: 用于观察 `NetworkChangeNotifier` 的最大带宽变化通知。
    * `TestNetworkObserver`:  更细粒度的网络观察者，用于验证特定网络上的连接、断开连接和成为默认网络等事件是否按预期发生。
* **定义测试基类 `BaseNetworkChangeNotifierAndroidTest`:**  提供了测试所需的通用设置和辅助方法，例如模拟网络连接和断开 (`SetOnline`, `SetOffline`)，模拟连接成本和子类型变化 (`FakeConnectionCostChange`, `FakeConnectionSubtypeChange`)，以及模拟网络事件 (`FakeNetworkChange`)。
* **定义测试类:**
    * `NetworkChangeNotifierAndroidTest`:  主要的测试类，用于测试 `NetworkChangeNotifierAndroid` 类的行为，例如接收委托的通知、向外部观察者发送通知、获取连接成本和最大带宽等。
    * `NetworkChangeNotifierDelegateAndroidTest`:  用于直接测试 `NetworkChangeNotifierDelegateAndroid` 类的行为，例如通知其内部观察者。

**2. 测试 `NetworkChangeNotifierDelegateAndroid` 的功能:**

* **验证初始连接类型:** 测试 `NetworkChangeNotifierDelegateAndroid` 在创建时是否能正确获取当前的连接类型，而不是使用默认值。
* **验证观察者通知:** 测试 `NetworkChangeNotifierDelegateAndroid` 能否正确通知其注册的观察者（`NetworkChangeNotifierDelegateAndroidObserver`）网络状态的变化。

**3. 测试 `NetworkChangeNotifierAndroid` 的功能:**

* **验证从委托接收通知:** 测试 `NetworkChangeNotifierAndroid` 能否接收到来自 `NetworkChangeNotifierDelegateAndroid` 的网络状态变化通知。
* **验证向客户端发送通知:** 测试 `NetworkChangeNotifierAndroid` 能否将网络状态变化通知发送给其注册的客户端观察者 (`NetworkChangeNotifierObserver`, `NetworkChangeNotifierConnectionCostObserver`, `NetworkChangeNotifierMaxBandwidthObserver`)。
* **测试连接成本变化:** 模拟连接成本的变化，并验证 `NetworkChangeNotifierAndroid` 能否正确获取和通知连接成本的变化。
* **测试最大带宽变化:** 模拟网络子类型的变化，并验证 `NetworkChangeNotifierAndroid` 能否正确获取和通知最大带宽的变化。
* **测试网络连接和断开事件:** 模拟网络的连接、即将断开连接和断开连接事件，并验证 `NetworkChangeNotifierAndroid` 能否正确通知观察者这些事件，并维护正确的连接网络列表。
* **测试默认网络变化事件:** 模拟默认网络的变化，并验证 `NetworkChangeNotifierAndroid` 能否正确通知观察者，并记录当前的默认网络。
* **测试网络类型同步变化:** 验证网络类型变化通知是同步发生的。
* **测试默认网络活动状态通知:** 测试 `NetworkChangeNotifierAndroid` 在默认网络活动状态变化时能否正确通知观察者。

**与 JavaScript 功能的关系：**

`NetworkChangeNotifierAndroid` 的主要目的是向 Chromium 的其他部分（包括可能最终影响 JavaScript 的部分）通知底层的网络状态变化。

* **`navigator.onLine` API:**  JavaScript 中的 `navigator.onLine` 属性可以反映当前的在线状态。`NetworkChangeNotifierAndroid` 的状态变化可能会影响到这个 API 的值。当网络连接断开时，`navigator.onLine` 应该返回 `false`，连接上时应该返回 `true`。
* **网络请求 API (e.g., `fetch`, `XMLHttpRequest`):**  网络状态的变化会直接影响到 JavaScript 发起的网络请求。如果网络断开，这些请求可能会失败。`NetworkChangeNotifierAndroid` 可以帮助浏览器内部判断是否应该尝试发起请求或重试请求。
* **Service Workers:**  Service Workers 可以在后台运行并拦截网络请求。`NetworkChangeNotifierAndroid` 的状态可以影响 Service Workers 的行为，例如决定是否应该从缓存中提供内容，或者是否应该尝试从网络获取。

**举例说明:**

假设用户在 Android 设备上浏览网页，设备正在使用 Wi-Fi 连接。

1. **假设输入:**  Android 系统报告 Wi-Fi 连接断开。
2. **`NetworkChangeNotifierDelegateAndroid` 接收到系统通知:** Android 系统会通过某种机制通知 Chromium 的 `NetworkChangeNotifierDelegateAndroid` 网络状态已更改。
3. **`NetworkChangeNotifierDelegateAndroid` 发出通知:** `NetworkChangeNotifierDelegateAndroid` 会通知其观察者，包括 `NetworkChangeNotifierAndroid`。
4. **`NetworkChangeNotifierAndroid` 更新状态并通知客户端:** `NetworkChangeNotifierAndroid` 会更新其内部状态，并通知其注册的观察者（包括浏览器内核的其他部分）。
5. **输出到 JavaScript:**  浏览器内核接收到 `NetworkChangeNotifierAndroid` 的通知后，可能会更新 `navigator.onLine` 的值，并触发相应的事件。例如，如果一个网页监听了 `window.online` 和 `window.offline` 事件，断开连接会触发 `offline` 事件。

**假设输入与输出 (针对测试用例):**

* **假设输入 (针对 `NotificationsSentToClientsOfNetworkChangeNotifier` 测试):**
    * 初始状态：网络连接状态为 `CONNECTION_UNKNOWN`。
    * 模拟操作：调用 `SetOffline()` 将网络状态设置为离线。
    * 预期输出：`NetworkChangeNotifierObserver` 的 `notifications_count` 变为 1，`NetworkChangeNotifier::GetConnectionType()` 返回 `CONNECTION_NONE`。
    * 模拟操作：再次调用 `SetOffline()`。
    * 预期输出：`NetworkChangeNotifierObserver` 的 `notifications_count` 保持为 1，`NetworkChangeNotifier::GetConnectionType()` 仍然返回 `CONNECTION_NONE`。
    * 模拟操作：调用 `SetOnline()` 将网络状态设置为在线。
    * 预期输出：`NetworkChangeNotifierObserver` 的 `notifications_count` 变为 2，`NetworkChangeNotifier::GetConnectionType()` 返回 `CONNECTION_UNKNOWN`。

* **假设输入 (针对 `NetworkCallbacks` 测试):**
    * 模拟操作：调用 `FakeNetworkChange(CONNECTED, 100, NetworkChangeNotifier::CONNECTION_WIFI)`。
    * 预期输出：`TestNetworkObserver` 的 `OnNetworkConnected` 被调用，`last_change_type_` 为 `CONNECTED`，`last_network_changed_` 为 `100`。 `NetworkChangeNotifier::GetDefaultNetwork()` 返回 `handles::kInvalidNetworkHandle`。
    * 模拟操作：调用 `FakeNetworkChange(MADE_DEFAULT, 100, NetworkChangeNotifier::CONNECTION_WIFI)` (在连接之后)。
    * 预期输出：`TestNetworkObserver` 的 `OnNetworkMadeDefault` 被调用，`last_change_type_` 为 `MADE_DEFAULT`，`last_network_changed_` 为 `100`。 `NetworkChangeNotifier::GetDefaultNetwork()` 返回 `100`。

**用户或编程常见的使用错误:**

* **忘记添加或移除观察者:** 如果开发者忘记在不需要时移除对 `NetworkChangeNotifier` 的观察，可能会导致内存泄漏或在网络状态变化时执行不必要的代码。
    * **示例:**  一个组件添加了 `NetworkChangeNotifier::AddConnectionTypeObserver` 但在其生命周期结束时忘记调用 `NetworkChangeNotifier::RemoveConnectionTypeObserver`。
* **错误地假设通知的同步性:**  虽然某些通知可能是同步的（如 `TypeChangeIsSynchronous` 测试所验证），但并非所有通知都是如此。开发者不应该假设网络状态变化通知会立即到达，可能需要在适当的时候处理异步更新。
* **在错误的时机查询网络状态:**  在网络状态正在变化的过程中，查询网络状态可能会得到不一致的结果。开发者应该订阅网络状态变化通知，以便在状态稳定后进行操作。
* **没有正确处理网络句柄 (NetworkHandle):** 当使用网络句柄时，开发者需要确保正确处理 `kInvalidNetworkHandle` 的情况，以及理解不同网络句柄代表不同的网络接口。

**用户操作是如何一步步的到达这里，作为调试线索:**

当你在调试 Android 平台上 Chromium 的网络相关问题时，例如：

1. **用户报告网页加载失败，显示 "ERR_NETWORK_CHANGED" 或类似错误。** 这可能是因为网络连接在页面加载过程中发生了变化。
2. **开发者怀疑 `NetworkChangeNotifierAndroid` 没有正确检测到网络变化。**
3. **开发者可能会设置断点在 `NetworkChangeNotifierDelegateAndroid` 接收系统网络状态变化通知的代码中。** 这部分代码通常是平台相关的 JNI 调用。
4. **开发者可能会逐步跟踪 `NetworkChangeNotifierDelegateAndroid` 如何通知 `NetworkChangeNotifierAndroid`。**
5. **开发者可能会检查 `NetworkChangeNotifierAndroid` 的内部状态，例如当前连接类型和连接的网络列表。**
6. **开发者可能会查看 `NetworkChangeNotifier` 的观察者列表，以确保相关的组件（例如网络栈的其他部分）已正确注册。**
7. **如果问题涉及到 JavaScript，开发者可能会检查 `navigator.onLine` 的值以及相关的事件触发。** 他们会尝试将 JavaScript 的行为与 `NetworkChangeNotifierAndroid` 的状态变化关联起来。

**总而言之，`net/android/network_change_notifier_android_unittest.cc` 是一个至关重要的测试文件，用于确保 Chromium 在 Android 平台上能够可靠地检测和报告网络状态的变化，这对于提供良好的用户体验至关重要。它涵盖了从底层系统通知的接收到最终影响 JavaScript 行为的整个流程的关键环节。**

### 提示词
```
这是目录为net/android/network_change_notifier_android_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2012 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// See network_change_notifier_android.h for design explanations.

#include "net/android/network_change_notifier_android.h"

#include <memory>

#include "base/compiler_specific.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/run_loop.h"
#include "net/android/network_change_notifier_delegate_android.h"
#include "net/base/ip_address.h"
#include "net/base/network_change_notifier.h"
#include "net/test/test_with_task_environment.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

namespace {

// Types of network changes. See similarly named functions in
// NetworkChangeNotifier::NetworkObserver for descriptions.
enum ChangeType {
  NONE,
  CONNECTED,
  SOON_TO_DISCONNECT,
  DISCONNECTED,
  MADE_DEFAULT,
};

class NetworkChangeNotifierDelegateAndroidObserver
    : public NetworkChangeNotifierDelegateAndroid::Observer {
 public:
  typedef NetworkChangeNotifier::ConnectionCost ConnectionCost;
  typedef NetworkChangeNotifier::ConnectionType ConnectionType;
  typedef NetworkChangeNotifier::NetworkList NetworkList;

  NetworkChangeNotifierDelegateAndroidObserver() = default;

  // NetworkChangeNotifierDelegateAndroid::Observer:
  void OnConnectionTypeChanged() override { type_notifications_count_++; }

  void OnConnectionCostChanged() override { cost_notifications_count_++; }

  void OnMaxBandwidthChanged(
      double max_bandwidth_mbps,
      net::NetworkChangeNotifier::ConnectionType type) override {
    max_bandwidth_notifications_count_++;
  }

  void OnNetworkConnected(handles::NetworkHandle network) override {}

  void OnNetworkSoonToDisconnect(handles::NetworkHandle network) override {}

  void OnNetworkDisconnected(handles::NetworkHandle network) override {}

  void OnNetworkMadeDefault(handles::NetworkHandle network) override {}

  void OnDefaultNetworkActive() override {
    default_network_active_notifications_count_++;
  }

  int type_notifications_count() const { return type_notifications_count_; }
  int cost_notifications_count() const { return cost_notifications_count_; }
  int bandwidth_notifications_count() const {
    return max_bandwidth_notifications_count_;
  }
  int default_network_active_notifications_count() const {
    return default_network_active_notifications_count_;
  }

 private:
  int type_notifications_count_ = 0;
  int cost_notifications_count_ = 0;
  int max_bandwidth_notifications_count_ = 0;
  int default_network_active_notifications_count_ = 0;
};

class NetworkChangeNotifierObserver
    : public NetworkChangeNotifier::ConnectionTypeObserver {
 public:
  NetworkChangeNotifierObserver() = default;

  // NetworkChangeNotifier::ConnectionTypeObserver:
  void OnConnectionTypeChanged(
      NetworkChangeNotifier::ConnectionType connection_type) override {
    notifications_count_++;
  }

  int notifications_count() const {
    return notifications_count_;
  }

 private:
  int notifications_count_ = 0;
};

class NetworkChangeNotifierConnectionCostObserver
    : public NetworkChangeNotifier::ConnectionCostObserver {
 public:
  // NetworkChangeNotifier::ConnectionCostObserver:
  void OnConnectionCostChanged(
      NetworkChangeNotifier::ConnectionCost cost) override {
    notifications_count_++;
  }

  int notifications_count() const { return notifications_count_; }

 private:
  int notifications_count_ = 0;
};

class NetworkChangeNotifierMaxBandwidthObserver
    : public NetworkChangeNotifier::MaxBandwidthObserver {
 public:
  // NetworkChangeNotifier::MaxBandwidthObserver:
  void OnMaxBandwidthChanged(
      double max_bandwidth_mbps,
      NetworkChangeNotifier::ConnectionType type) override {
    notifications_count_++;
  }

  int notifications_count() const { return notifications_count_; }

 private:
  int notifications_count_ = 0;
};

// A NetworkObserver used for verifying correct notifications are sent.
class TestNetworkObserver : public NetworkChangeNotifier::NetworkObserver {
 public:
  TestNetworkObserver() { Clear(); }

  void ExpectChange(ChangeType change, handles::NetworkHandle network) {
    EXPECT_EQ(last_change_type_, change);
    EXPECT_EQ(last_network_changed_, network);
    Clear();
  }

 private:
  void Clear() {
    last_change_type_ = NONE;
    last_network_changed_ = handles::kInvalidNetworkHandle;
  }

  // NetworkChangeNotifier::NetworkObserver implementation:
  void OnNetworkConnected(handles::NetworkHandle network) override {
    ExpectChange(NONE, handles::kInvalidNetworkHandle);
    last_change_type_ = CONNECTED;
    last_network_changed_ = network;
  }
  void OnNetworkSoonToDisconnect(handles::NetworkHandle network) override {
    ExpectChange(NONE, handles::kInvalidNetworkHandle);
    last_change_type_ = SOON_TO_DISCONNECT;
    last_network_changed_ = network;
  }
  void OnNetworkDisconnected(handles::NetworkHandle network) override {
    ExpectChange(NONE, handles::kInvalidNetworkHandle);
    last_change_type_ = DISCONNECTED;
    last_network_changed_ = network;
  }
  void OnNetworkMadeDefault(handles::NetworkHandle network) override {
    // Cannot test for Clear()ed state as we receive CONNECTED immediately prior
    // to MADE_DEFAULT.
    last_change_type_ = MADE_DEFAULT;
    last_network_changed_ = network;
  }

  ChangeType last_change_type_;
  handles::NetworkHandle last_network_changed_;
};

}  // namespace

class BaseNetworkChangeNotifierAndroidTest : public TestWithTaskEnvironment {
 protected:
  typedef NetworkChangeNotifier::ConnectionType ConnectionType;
  typedef NetworkChangeNotifier::ConnectionCost ConnectionCost;
  typedef NetworkChangeNotifier::ConnectionSubtype ConnectionSubtype;

  ~BaseNetworkChangeNotifierAndroidTest() override = default;

  void RunTest(
      const base::RepeatingCallback<int(void)>& notifications_count_getter,
      const base::RepeatingCallback<ConnectionType(void)>&
          connection_type_getter) {
    EXPECT_EQ(0, notifications_count_getter.Run());
    EXPECT_EQ(NetworkChangeNotifier::CONNECTION_UNKNOWN,
              connection_type_getter.Run());

    // Changing from online to offline should trigger a notification.
    SetOffline();
    EXPECT_EQ(1, notifications_count_getter.Run());
    EXPECT_EQ(NetworkChangeNotifier::CONNECTION_NONE,
              connection_type_getter.Run());

    // No notification should be triggered when the offline state hasn't
    // changed.
    SetOffline();
    EXPECT_EQ(1, notifications_count_getter.Run());
    EXPECT_EQ(NetworkChangeNotifier::CONNECTION_NONE,
              connection_type_getter.Run());

    // Going from offline to online should trigger a notification.
    SetOnline();
    EXPECT_EQ(2, notifications_count_getter.Run());
    EXPECT_EQ(NetworkChangeNotifier::CONNECTION_UNKNOWN,
              connection_type_getter.Run());
  }

  void SetOnline(bool drain_run_loop = true) {
    delegate_.SetOnline();
    if (drain_run_loop) {
      // Note that this is needed because base::ObserverListThreadSafe uses
      // PostTask().
      base::RunLoop().RunUntilIdle();
    }
  }

  void SetOffline(bool drain_run_loop = true) {
    delegate_.SetOffline();
    if (drain_run_loop) {
      // See comment above.
      base::RunLoop().RunUntilIdle();
    }
  }

  void FakeConnectionCostChange(ConnectionCost cost) {
    delegate_.FakeConnectionCostChanged(cost);
    base::RunLoop().RunUntilIdle();
  }

  void FakeConnectionSubtypeChange(ConnectionSubtype subtype) {
    delegate_.FakeConnectionSubtypeChanged(subtype);
    base::RunLoop().RunUntilIdle();
  }

  void FakeNetworkChange(ChangeType change,
                         handles::NetworkHandle network,
                         ConnectionType type) {
    switch (change) {
      case CONNECTED:
        delegate_.FakeNetworkConnected(network, type);
        break;
      case SOON_TO_DISCONNECT:
        delegate_.FakeNetworkSoonToBeDisconnected(network);
        break;
      case DISCONNECTED:
        delegate_.FakeNetworkDisconnected(network);
        break;
      case MADE_DEFAULT:
        delegate_.FakeDefaultNetwork(network, type);
        break;
      case NONE:
        NOTREACHED();
    }
    // See comment above.
    base::RunLoop().RunUntilIdle();
  }

  void FakeDefaultNetworkActive() {
    delegate_.FakeDefaultNetworkActive();
    // See comment above.
    base::RunLoop().RunUntilIdle();
  }

  void FakePurgeActiveNetworkList(NetworkChangeNotifier::NetworkList networks) {
    delegate_.FakePurgeActiveNetworkList(networks);
    // See comment above.
    base::RunLoop().RunUntilIdle();
  }

  NetworkChangeNotifierDelegateAndroid delegate_;
};

// Tests that NetworkChangeNotifierDelegateAndroid is initialized with the
// actual connection type rather than a hardcoded one (e.g.
// CONNECTION_UNKNOWN). Initializing the connection type to CONNECTION_UNKNOWN
// and relying on the first network change notification to set it correctly can
// be problematic in case there is a long delay between the delegate's
// construction and the notification.
TEST_F(BaseNetworkChangeNotifierAndroidTest,
       DelegateIsInitializedWithCurrentConnectionType) {
  SetOffline();
  ASSERT_EQ(NetworkChangeNotifier::CONNECTION_NONE,
            delegate_.GetCurrentConnectionType());
  // Instantiate another delegate to validate that it uses the actual
  // connection type at construction.
  auto other_delegate =
      std::make_unique<NetworkChangeNotifierDelegateAndroid>();
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_NONE,
            other_delegate->GetCurrentConnectionType());

  // Toggle the global connectivity state and instantiate another delegate
  // again.
  SetOnline();
  ASSERT_EQ(NetworkChangeNotifier::CONNECTION_UNKNOWN,
            delegate_.GetCurrentConnectionType());
  other_delegate = std::make_unique<NetworkChangeNotifierDelegateAndroid>();
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_UNKNOWN,
            other_delegate->GetCurrentConnectionType());
}

class NetworkChangeNotifierAndroidTest
    : public BaseNetworkChangeNotifierAndroidTest {
 protected:
  NetworkChangeNotifierAndroidTest() : notifier_(&delegate_) {
    NetworkChangeNotifier::AddConnectionTypeObserver(
        &connection_type_observer_);
    NetworkChangeNotifier::AddConnectionTypeObserver(
        &other_connection_type_observer_);
    NetworkChangeNotifier::AddConnectionCostObserver(
        &connection_cost_observer_);
    NetworkChangeNotifier::AddMaxBandwidthObserver(&max_bandwidth_observer_);
  }

  void ForceNetworkHandlesSupportedForTesting() {
    notifier_.ForceNetworkHandlesSupportedForTesting();
  }

  NetworkChangeNotifierObserver connection_type_observer_;
  NetworkChangeNotifierConnectionCostObserver connection_cost_observer_;
  NetworkChangeNotifierMaxBandwidthObserver max_bandwidth_observer_;
  NetworkChangeNotifierObserver other_connection_type_observer_;
  NetworkChangeNotifier::DisableForTest disable_for_test_;
  NetworkChangeNotifierAndroid notifier_;
};

class NetworkChangeNotifierDelegateAndroidTest
    : public BaseNetworkChangeNotifierAndroidTest {
 protected:
  NetworkChangeNotifierDelegateAndroidTest() {
    delegate_.RegisterObserver(&delegate_observer_);
  }

  ~NetworkChangeNotifierDelegateAndroidTest() override {
    delegate_.UnregisterObserver(&delegate_observer_);
  }

  NetworkChangeNotifierDelegateAndroidObserver delegate_observer_;
};

// Tests that the NetworkChangeNotifierDelegateAndroid's observer is notified.
// A testing-only observer is used here for testing. In production the
// delegate's observers are instances of NetworkChangeNotifierAndroid.
TEST_F(NetworkChangeNotifierDelegateAndroidTest, DelegateObserverNotified) {
  RunTest(base::BindRepeating(&NetworkChangeNotifierDelegateAndroidObserver::
                                  type_notifications_count,
                              base::Unretained(&delegate_observer_)),
          base::BindRepeating(
              &NetworkChangeNotifierDelegateAndroid::GetCurrentConnectionType,
              base::Unretained(&delegate_)));
}

// When a NetworkChangeNotifierAndroid is observing a
// NetworkChangeNotifierDelegateAndroid for network state changes, and the
// NetworkChangeNotifierDelegateAndroid's connectivity state changes, the
// NetworkChangeNotifierAndroid should reflect that state.
TEST_F(NetworkChangeNotifierAndroidTest,
       NotificationsSentToNetworkChangeNotifierAndroid) {
  RunTest(
      base::BindRepeating(&NetworkChangeNotifierObserver::notifications_count,
                          base::Unretained(&connection_type_observer_)),
      base::BindRepeating(
          &NetworkChangeNotifierAndroid::GetCurrentConnectionType,
          base::Unretained(&notifier_)));
}

// When a NetworkChangeNotifierAndroid's connection state changes, it should
// notify all of its observers.
TEST_F(NetworkChangeNotifierAndroidTest,
       NotificationsSentToClientsOfNetworkChangeNotifier) {
  RunTest(
      base::BindRepeating(&NetworkChangeNotifierObserver::notifications_count,
                          base::Unretained(&connection_type_observer_)),
      base::BindRepeating(&NetworkChangeNotifier::GetConnectionType));
  // Check that *all* the observers are notified.
  EXPECT_EQ(connection_type_observer_.notifications_count(),
            other_connection_type_observer_.notifications_count());
}

TEST_F(NetworkChangeNotifierAndroidTest, ConnectionCost) {
  FakeConnectionCostChange(ConnectionCost::CONNECTION_COST_UNMETERED);
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_COST_UNMETERED,
            notifier_.GetConnectionCost());
  FakeConnectionCostChange(ConnectionCost::CONNECTION_COST_METERED);
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_COST_METERED,
            notifier_.GetConnectionCost());
}

TEST_F(NetworkChangeNotifierAndroidTest, ConnectionCostCallbackNotifier) {
  FakeConnectionCostChange(ConnectionCost::CONNECTION_COST_UNMETERED);
  EXPECT_EQ(1, connection_cost_observer_.notifications_count());

  FakeConnectionCostChange(ConnectionCost::CONNECTION_COST_METERED);
  EXPECT_EQ(2, connection_cost_observer_.notifications_count());
}

TEST_F(NetworkChangeNotifierDelegateAndroidTest,
       ConnectionCostCallbackNotifier) {
  EXPECT_EQ(0, delegate_observer_.cost_notifications_count());

  FakeConnectionCostChange(ConnectionCost::CONNECTION_COST_UNMETERED);
  EXPECT_EQ(1, delegate_observer_.cost_notifications_count());

  FakeConnectionCostChange(ConnectionCost::CONNECTION_COST_METERED);
  EXPECT_EQ(2, delegate_observer_.cost_notifications_count());
}

TEST_F(NetworkChangeNotifierAndroidTest, MaxBandwidth) {
  SetOnline();
  double max_bandwidth_mbps = 0.0;
  NetworkChangeNotifier::ConnectionType connection_type =
      NetworkChangeNotifier::CONNECTION_NONE;
  notifier_.GetMaxBandwidthAndConnectionType(&max_bandwidth_mbps,
                                             &connection_type);
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_UNKNOWN, connection_type);
  EXPECT_EQ(std::numeric_limits<double>::infinity(), max_bandwidth_mbps);
  SetOffline();
  notifier_.GetMaxBandwidthAndConnectionType(&max_bandwidth_mbps,
                                             &connection_type);
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_NONE, connection_type);
  EXPECT_EQ(0.0, max_bandwidth_mbps);
}

TEST_F(NetworkChangeNotifierAndroidTest, MaxBandwidthCallbackNotifier) {
  // The bandwidth notification should always be forwarded, even if the value
  // doesn't change (because the type might have changed).
  FakeConnectionSubtypeChange(ConnectionSubtype::SUBTYPE_CDMA);
  EXPECT_EQ(1, max_bandwidth_observer_.notifications_count());

  FakeConnectionSubtypeChange(ConnectionSubtype::SUBTYPE_CDMA);
  EXPECT_EQ(2, max_bandwidth_observer_.notifications_count());

  FakeConnectionSubtypeChange(ConnectionSubtype::SUBTYPE_LTE);
  EXPECT_EQ(3, max_bandwidth_observer_.notifications_count());
}

TEST_F(NetworkChangeNotifierDelegateAndroidTest,
       MaxBandwidthNotifiedOnConnectionChange) {
  EXPECT_EQ(0, delegate_observer_.bandwidth_notifications_count());
  SetOffline();
  EXPECT_EQ(1, delegate_observer_.bandwidth_notifications_count());
  SetOnline();
  EXPECT_EQ(2, delegate_observer_.bandwidth_notifications_count());
  SetOnline();
  EXPECT_EQ(2, delegate_observer_.bandwidth_notifications_count());
}

TEST_F(NetworkChangeNotifierAndroidTest, NetworkCallbacks) {
  ForceNetworkHandlesSupportedForTesting();

  TestNetworkObserver network_observer;
  NetworkChangeNotifier::AddNetworkObserver(&network_observer);

  // Test empty values
  EXPECT_EQ(handles::kInvalidNetworkHandle,
            NetworkChangeNotifier::GetDefaultNetwork());
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_UNKNOWN,
            NetworkChangeNotifier::GetNetworkConnectionType(100));
  NetworkChangeNotifier::NetworkList network_list;
  NetworkChangeNotifier::GetConnectedNetworks(&network_list);
  EXPECT_EQ(0u, network_list.size());
  // Test connecting network
  FakeNetworkChange(CONNECTED, 100, NetworkChangeNotifier::CONNECTION_WIFI);
  network_observer.ExpectChange(CONNECTED, 100);
  EXPECT_EQ(handles::kInvalidNetworkHandle,
            NetworkChangeNotifier::GetDefaultNetwork());
  // Test GetConnectedNetworks()
  NetworkChangeNotifier::GetConnectedNetworks(&network_list);
  EXPECT_EQ(1u, network_list.size());
  EXPECT_EQ(100, network_list[0]);
  // Test GetNetworkConnectionType()
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_WIFI,
            NetworkChangeNotifier::GetNetworkConnectionType(100));
  // Test deduplication of connecting signal
  FakeNetworkChange(CONNECTED, 100, NetworkChangeNotifier::CONNECTION_WIFI);
  network_observer.ExpectChange(NONE, handles::kInvalidNetworkHandle);
  // Test connecting another network
  FakeNetworkChange(CONNECTED, 101, NetworkChangeNotifier::CONNECTION_3G);
  network_observer.ExpectChange(CONNECTED, 101);
  NetworkChangeNotifier::GetConnectedNetworks(&network_list);
  EXPECT_EQ(2u, network_list.size());
  EXPECT_EQ(100, network_list[0]);
  EXPECT_EQ(101, network_list[1]);
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_WIFI,
            NetworkChangeNotifier::GetNetworkConnectionType(100));
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_3G,
            NetworkChangeNotifier::GetNetworkConnectionType(101));
  // Test lingering network
  FakeNetworkChange(SOON_TO_DISCONNECT, 100,
                    NetworkChangeNotifier::CONNECTION_WIFI);
  network_observer.ExpectChange(SOON_TO_DISCONNECT, 100);
  NetworkChangeNotifier::GetConnectedNetworks(&network_list);
  EXPECT_EQ(2u, network_list.size());
  EXPECT_EQ(100, network_list[0]);
  EXPECT_EQ(101, network_list[1]);
  // Test disconnecting network
  FakeNetworkChange(DISCONNECTED, 100, NetworkChangeNotifier::CONNECTION_WIFI);
  network_observer.ExpectChange(DISCONNECTED, 100);
  NetworkChangeNotifier::GetConnectedNetworks(&network_list);
  EXPECT_EQ(1u, network_list.size());
  EXPECT_EQ(101, network_list[0]);
  // Test deduplication of disconnecting signal
  FakeNetworkChange(DISCONNECTED, 100, NetworkChangeNotifier::CONNECTION_WIFI);
  network_observer.ExpectChange(NONE, handles::kInvalidNetworkHandle);
  // Test delay of default network signal until connect signal
  FakeNetworkChange(MADE_DEFAULT, 100, NetworkChangeNotifier::CONNECTION_WIFI);
  network_observer.ExpectChange(NONE, handles::kInvalidNetworkHandle);
  FakeNetworkChange(CONNECTED, 100, NetworkChangeNotifier::CONNECTION_WIFI);
  network_observer.ExpectChange(MADE_DEFAULT, 100);
  EXPECT_EQ(100, NetworkChangeNotifier::GetDefaultNetwork());
  // Test change of default
  FakeNetworkChange(MADE_DEFAULT, 101, NetworkChangeNotifier::CONNECTION_3G);
  network_observer.ExpectChange(MADE_DEFAULT, 101);
  EXPECT_EQ(101, NetworkChangeNotifier::GetDefaultNetwork());
  // Test deduplication default signal
  FakeNetworkChange(MADE_DEFAULT, 101, NetworkChangeNotifier::CONNECTION_3G);
  network_observer.ExpectChange(NONE, handles::kInvalidNetworkHandle);
  // Test that networks can change type
  FakeNetworkChange(CONNECTED, 101, NetworkChangeNotifier::CONNECTION_4G);
  network_observer.ExpectChange(NONE, handles::kInvalidNetworkHandle);
  EXPECT_EQ(NetworkChangeNotifier::CONNECTION_4G,
            NetworkChangeNotifier::GetNetworkConnectionType(101));
  // Test purging the network list
  NetworkChangeNotifier::GetConnectedNetworks(&network_list);
  EXPECT_EQ(2u, network_list.size());
  EXPECT_EQ(100, network_list[0]);
  EXPECT_EQ(101, network_list[1]);
  network_list.erase(network_list.begin() + 1);  // Remove network 101
  FakePurgeActiveNetworkList(network_list);
  network_observer.ExpectChange(DISCONNECTED, 101);
  NetworkChangeNotifier::GetConnectedNetworks(&network_list);
  EXPECT_EQ(1u, network_list.size());
  EXPECT_EQ(100, network_list[0]);
  EXPECT_EQ(handles::kInvalidNetworkHandle,
            NetworkChangeNotifier::GetDefaultNetwork());

  NetworkChangeNotifier::RemoveNetworkObserver(&network_observer);
}

// Tests that network type changes happen synchronously. Otherwise the type
// "change" at browser startup leaves tasks on the queue that will later
// invalidate any network requests that have been started.
TEST_F(NetworkChangeNotifierDelegateAndroidTest, TypeChangeIsSynchronous) {
  const int initial_value = delegate_observer_.type_notifications_count();
  SetOffline(/*drain_run_loop=*/false);
  // Note that there's no call to |base::RunLoop::RunUntilIdle| here. The
  // update must happen synchronously.
  EXPECT_EQ(initial_value + 1, delegate_observer_.type_notifications_count());
}

TEST_F(NetworkChangeNotifierDelegateAndroidTest, DefaultNetworkActive) {
  // No notifications should be received when there are no observers.
  EXPECT_EQ(0, delegate_observer_.default_network_active_notifications_count());
  FakeDefaultNetworkActive();
  EXPECT_EQ(0, delegate_observer_.default_network_active_notifications_count());

  // Simulate calls to NetworkChangeNotifier::AddDefaultNetworkObserver().
  // Notifications should be received now.
  delegate_.DefaultNetworkActiveObserverAdded();
  FakeDefaultNetworkActive();
  EXPECT_EQ(1, delegate_observer_.default_network_active_notifications_count());
  delegate_.DefaultNetworkActiveObserverAdded();
  FakeDefaultNetworkActive();
  EXPECT_EQ(2, delegate_observer_.default_network_active_notifications_count());

  // Simulate call to NetworkChangeNotifier::AddDefaultNetworkObserver().
  // Notifications should be received until the last observer has been
  // removed.
  delegate_.DefaultNetworkActiveObserverRemoved();
  FakeDefaultNetworkActive();
  EXPECT_EQ(3, delegate_observer_.default_network_active_notifications_count());
  delegate_.DefaultNetworkActiveObserverRemoved();
  FakeDefaultNetworkActive();
  EXPECT_EQ(3, delegate_observer_.default_network_active_notifications_count());

  // Double check that things keep working as expected after re-adding an
  // observer.
  delegate_.DefaultNetworkActiveObserverAdded();
  FakeDefaultNetworkActive();
  EXPECT_EQ(4, delegate_observer_.default_network_active_notifications_count());

  // Cleanup: delegate destructor DCHECKS that all observers have been
  // removed.
  delegate_.DefaultNetworkActiveObserverRemoved();
}

}  // namespace net
```