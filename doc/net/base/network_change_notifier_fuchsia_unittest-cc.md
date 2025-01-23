Response:
Let's break down the thought process for analyzing this C++ unittest file for Chromium's network stack.

1. **Identify the Core Subject:** The file name `network_change_notifier_fuchsia_unittest.cc` immediately tells us this is a unit test file for the `NetworkChangeNotifierFuchsia` class. This class is specifically designed for the Fuchsia operating system.

2. **Understand the Purpose of Unit Tests:** Unit tests aim to isolate and verify the functionality of a specific unit of code (in this case, the `NetworkChangeNotifierFuchsia` class). They do this by setting up various scenarios (inputs) and checking if the output or behavior matches expectations.

3. **Analyze the Includes:** The `#include` statements provide valuable context:
    * `<fuchsia/...>`: Indicates interaction with Fuchsia-specific APIs, particularly for network interfaces.
    * `<lib/fidl/...>`:  Suggests the use of FIDL (Fuchsia Interface Definition Language) for inter-process communication or defining interfaces.
    * Standard C++ includes (`<memory>`, `<string>`, etc.): Indicate general programming practices.
    * Chromium-specific includes (`"base/..."`, `"net/..."`, `"testing/..."`): Reveal dependencies on Chromium's base library, network stack, and testing framework (gtest/gmock). Specifically, the inclusion of `"net/base/network_change_notifier.h"` is crucial as it's the base class being tested.

4. **Examine the Namespaces:** The `namespace net { namespace { ... } }` structure is standard C++ for organizing code. The anonymous namespace `{}` is used for internal linkage within the file.

5. **Deconstruct Key Components:**

    * **Helper Functions:**  Notice the utility functions like `IpAddressFrom`, `SubnetFrom`, `InterfaceAddressFrom`, `MakeSingleItemVec`, `DefaultInterfaceProperties`, `SecondaryInterfaceProperties`, and `MakeChangeEvent`. These are used to create realistic or specific Fuchsia network interface data structures for testing. This hints at the kind of data the `NetworkChangeNotifierFuchsia` works with.

    * **FakeWatcher:** This is a *mock* or *stub* implementation of the `fuchsia::net::interfaces::Watcher` interface. Its purpose is to simulate the behavior of the real Fuchsia network interface watcher without needing to interact with the actual system. This is a common pattern in unit testing to isolate the component being tested. The `PushEvent` and `SetInitial` methods are key to injecting simulated network events. The asynchronous version `FakeWatcherAsync` indicates that the real watcher likely operates asynchronously.

    * **ResultReceiver and Fake Observers:** The `ResultReceiver` is a generic helper for collecting results from asynchronous operations. The `FakeConnectionTypeObserver`, `FakeNetworkChangeObserver`, and `FakeIPAddressObserver` are crucial. They implement the observer interfaces (`NetworkChangeNotifier::ConnectionTypeObserver`, etc.) that the `NetworkChangeNotifierFuchsia` uses to notify other parts of the system about network changes. These fake observers allow the tests to verify that the correct notifications are being sent at the right times.

    * **Test Fixture (`NetworkChangeNotifierFuchsiaTest`):**  This class sets up the testing environment. It creates a `FakeWatcherAsync`, and the `CreateNotifier` method is responsible for instantiating the `NetworkChangeNotifierFuchsia` being tested, injecting the fake watcher. The `TearDown` method ensures a clean state after each test. The `disable_for_test_` member is a common Chromium pattern to allow for custom instantiation of singleton-like classes in tests.

    * **Individual Tests (`TEST_F`):** Each `TEST_F` function focuses on testing a specific aspect or scenario of the `NetworkChangeNotifierFuchsia`. The names are generally descriptive (e.g., `InitialState`, `IpChange`, `InterfaceDown`, `FoundWiFi`).

6. **Identify Core Functionality:** Based on the test names and the types of events being simulated (IP changes, interface up/down, interface added/removed), we can deduce the core responsibilities of `NetworkChangeNotifierFuchsia`:

    * **Monitoring Network Interfaces:** It listens for events from the Fuchsia network interface watcher.
    * **Tracking Network Connectivity:** It determines the current network connectivity status (e.g., no connection, Ethernet, Wi-Fi).
    * **Notifying Observers:** It informs registered observers about changes in network connectivity and IP addresses.
    * **Handling Initial State:** It correctly processes the initial state of the network interfaces.
    * **Filtering Interfaces (Optional WLAN Requirement):** It can be configured to only consider WLAN interfaces.

7. **Consider Relationships with JavaScript (and Web Browsers in General):**  Think about how network connectivity information is used in web browsers. JavaScript code running in a browser needs to know if there's an internet connection and what type it is. The `NetworkChangeNotifier` (and its platform-specific implementations like `NetworkChangeNotifierFuchsia`) are the underlying mechanisms that provide this information to higher-level browser components. These components might then expose this information to JavaScript through browser APIs like `navigator.onLine` or through events related to network status.

8. **Look for Logic and Assumptions:** The tests make certain assumptions about how the `NetworkChangeNotifierFuchsia` should behave given specific input events. For example, when an interface goes down, the connection type should change to `CONNECTION_NONE`. When an interface with a WLAN class is added, the connection type should become `CONNECTION_WIFI`.

9. **Identify Potential Errors:** The tests implicitly highlight potential error scenarios: failure to connect to the watcher, incorrect handling of initial state, missing notifications, or incorrect connection type determination. The `EXPECT_EXIT` tests explicitly check for crash scenarios when the watcher connection fails.

10. **Trace User Actions (Debugging Context):** Imagine a user on a Fuchsia device experiencing network problems. Understanding how the system gets to the state being tested in these unit tests helps in debugging. User actions like connecting/disconnecting from Wi-Fi, plugging/unplugging Ethernet cables, or the system enabling/disabling network interfaces will generate the kinds of events that the `FakeWatcher` simulates. The logs and notifications triggered by `NetworkChangeNotifierFuchsia` would be part of the debugging process.

By systematically working through these steps, we can gain a comprehensive understanding of the functionality, purpose, and context of this C++ unit test file. The key is to connect the code to the broader purpose of a network change notifier and how it relates to the operating system and the applications running on it.
这个文件 `net/base/network_change_notifier_fuchsia_unittest.cc` 是 Chromium 项目中用于测试 `NetworkChangeNotifierFuchsia` 类的单元测试文件。`NetworkChangeNotifierFuchsia` 负责监听 Fuchsia 操作系统底层的网络状态变化，并将这些变化通知给 Chromium 的其他组件。

以下是该文件的功能分解：

**1. 测试 `NetworkChangeNotifierFuchsia` 的核心功能：**

    * **监听 Fuchsia 网络接口变化:**  该文件模拟 Fuchsia 系统发送的网络接口事件（例如，接口添加、删除、状态改变、IP 地址变化等），并验证 `NetworkChangeNotifierFuchsia` 是否正确地接收和解析这些事件。
    * **维护当前网络连接状态:** 测试 `NetworkChangeNotifierFuchsia` 是否能根据接收到的事件，正确地更新和维护当前的连接类型（例如，无连接、以太网、Wi-Fi）。
    * **通知观察者:** 测试 `NetworkChangeNotifierFuchsia` 是否在网络状态发生变化时，正确地通知已注册的观察者（例如，`NetworkChangeNotifier::ConnectionTypeObserver` 和 `NetworkChangeNotifier::IPAddressObserver`）。

**2. 模拟 Fuchsia 网络环境:**

    * **`FakeWatcher` 类:**  该类模拟了 Fuchsia 的 `fuchsia.net.interfaces/Watcher` 服务，该服务负责提供网络接口状态的更新。`FakeWatcher` 允许测试代码人为地推送各种网络事件，而无需实际与 Fuchsia 系统交互。
    * **预定义的网络接口属性:**  文件中定义了一些常量，例如 `kDefaultInterfaceId`, `kSecondaryInterfaceId`, `kDefaultIPv4Address` 等，用于创建模拟的网络接口属性，方便测试各种场景。

**3. 验证通知机制:**

    * **`FakeConnectionTypeObserver` 类:**  该类实现了 `NetworkChangeNotifier::ConnectionTypeObserver` 接口，用于接收连接类型变化的通知，并记录接收到的类型，方便测试验证是否收到了预期的通知。
    * **`FakeNetworkChangeObserver` 类:** 该类实现了 `NetworkChangeNotifier::NetworkChangeObserver` 接口，用于接收更通用的网络变化的通知，并记录接收到的类型。
    * **`FakeIPAddressObserver` 类:** 该类实现了 `NetworkChangeNotifier::IPAddressObserver` 接口，用于接收 IP 地址变化的通知，并记录接收到的通知次数，方便测试验证是否收到了预期的通知。

**与 JavaScript 功能的关系：**

`NetworkChangeNotifierFuchsia` 本身是 C++ 代码，不直接与 JavaScript 交互。但是，它提供的网络状态信息最终会被传递到 Chromium 的渲染进程，从而影响到运行在浏览器中的 JavaScript 代码。

**举例说明:**

* **`navigator.onLine` API:** JavaScript 可以使用 `navigator.onLine` API 来检查当前浏览器是否在线。当 `NetworkChangeNotifierFuchsia` 检测到网络连接状态发生变化时，它会通知 Chromium 的其他组件，这些组件会更新 `navigator.onLine` 的值，从而影响到 JavaScript 代码的判断。
    * **假设输入 (Fuchsia 端):**  `FakeWatcher` 模拟 Fuchsia 系统发送一个 "网络接口下线" 的事件。
    * **输出 (JavaScript 端):**  `navigator.onLine` 的值会从 `true` 变为 `false`。

* **`online` 和 `offline` 事件:**  浏览器会在网络连接状态发生变化时触发 `online` 和 `offline` 事件。`NetworkChangeNotifierFuchsia` 的通知会触发这些事件。
    * **假设输入 (Fuchsia 端):** `FakeWatcher` 模拟 Fuchsia 系统发送一个 "成功连接到 Wi-Fi" 的事件。
    * **输出 (JavaScript 端):** 浏览器会触发 `online` 事件，JavaScript 可以监听这个事件来执行相应的操作（例如，重新尝试发送请求）。

**逻辑推理 (假设输入与输出):**

* **假设输入:**
    1. `FakeWatcher` 初始化时模拟一个具有有效 IPv4 地址的以太网接口上线。
    2. `FakeWatcher` 随后模拟该接口的 IP 地址发生变化。
* **输出:**
    1. `NetworkChangeNotifierFuchsia` 初始化后，`GetCurrentConnectionType()` 应该返回 `CONNECTION_ETHERNET`。
    2. `FakeIPAddressObserver` 应该收到一次 `OnIPAddressChanged()` 的通知。

* **假设输入:**
    1. `FakeWatcher` 初始化时模拟一个离线的以太网接口。
    2. `FakeWatcher` 随后模拟该接口上线。
* **输出:**
    1. `NetworkChangeNotifierFuchsia` 初始化后，`GetCurrentConnectionType()` 应该返回 `CONNECTION_NONE`。
    2. `FakeConnectionTypeObserver` 应该收到一次 `OnConnectionTypeChanged(CONNECTION_ETHERNET)` 的通知。

**用户或编程常见的使用错误 (针对 `NetworkChangeNotifier` 的使用):**

* **忘记注册观察者:**  如果开发者忘记将自己的观察者（例如，实现了 `NetworkChangeNotifier::ConnectionTypeObserver` 的类）添加到 `NetworkChangeNotifier` 中，那么即使网络状态发生变化，他们的代码也不会收到通知。
    * **错误示例 (C++):**  创建了一个继承自 `NetworkChangeNotifier::ConnectionTypeObserver` 的类 `MyObserver`，但是没有调用 `NetworkChangeNotifier::AddConnectionTypeObserver(my_observer)`。

* **在不合适的时机移除观察者:** 如果过早地移除了观察者，可能会错过一些网络状态变化的通知。
    * **错误示例 (C++):**  在一个对象的构造函数中注册了观察者，但是在析构函数中忘记移除，导致程序退出时可能仍然有回调发生，引发错误。

**用户操作如何一步步到达这里 (作为调试线索):**

假设用户在使用 Chromium 浏览器时遇到了网络问题，开发者可能需要查看 `NetworkChangeNotifierFuchsia` 的日志或断点来定位问题。以下是一些可能的用户操作序列：

1. **用户连接到 Wi-Fi 网络:** Fuchsia 系统会检测到新的 Wi-Fi 连接，并通过 `fuchsia.net.interfaces/Watcher` 服务发送一个 "接口添加" 或 "接口属性改变" 的事件。`NetworkChangeNotifierFuchsia` 接收到这个事件，并更新内部状态。

2. **用户浏览网页:** 浏览器中的网络请求需要知道当前是否有网络连接。浏览器会查询 `NetworkChangeNotifier` 获取当前的连接状态。

3. **用户断开 Wi-Fi 连接:** Fuchsia 系统会检测到 Wi-Fi 断开，并通过 `fuchsia.net.interfaces/Watcher` 服务发送一个 "接口状态改变" 或 "接口删除" 的事件。`NetworkChangeNotifierFuchsia` 接收到这个事件，并更新内部状态，通知观察者。浏览器收到通知后，可能会显示一个 "无法连接到互联网" 的提示。

4. **用户尝试使用需要网络连接的功能:** JavaScript 代码可能会监听 `offline` 事件，当 `NetworkChangeNotifierFuchsia` 检测到网络断开并通知浏览器时，会触发该事件，JavaScript 代码可以执行相应的错误处理或提示。

**调试线索:**

* **查看 `FakeWatcher` 的 `PushEvent` 调用:**  在测试中，`FakeWatcher::PushEvent` 模拟了 Fuchsia 发送的网络事件。在调试实际问题时，可以查看 Fuchsia 系统日志中相关的网络事件，对比测试用例中的事件，看是否一致。
* **检查观察者的回调是否被触发:** 通过在 `FakeConnectionTypeObserver`、`FakeNetworkChangeObserver` 或 `FakeIPAddressObserver` 的回调函数中设置断点，可以验证 `NetworkChangeNotifierFuchsia` 是否正确地通知了观察者。
* **查看 `NetworkChangeNotifierFuchsia` 的内部状态:**  在测试或实际运行中，可以通过日志或断点查看 `NetworkChangeNotifierFuchsia` 内部维护的连接状态和接口信息，判断是否与预期一致。

总而言之，`net/base/network_change_notifier_fuchsia_unittest.cc` 是一个至关重要的测试文件，它确保了 Chromium 在 Fuchsia 平台上能够准确地感知和响应网络状态的变化，从而保证了浏览器网络功能的正常运行。

### 提示词
```
这是目录为net/base/network_change_notifier_fuchsia_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/network_change_notifier_fuchsia.h"

#include <fuchsia/net/interfaces/cpp/fidl_test_base.h>
#include <lib/fidl/cpp/binding.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/auto_reset.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/run_loop.h"
#include "base/test/task_environment.h"
#include "base/threading/sequence_bound.h"
#include "base/threading/thread.h"
#include "net/base/ip_address.h"
#include "net/base/network_change_notifier.h"
#include "net/dns/dns_config_service.h"
#include "net/dns/system_dns_config_change_notifier.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

enum : uint32_t { kDefaultInterfaceId = 1, kSecondaryInterfaceId = 2 };

using IPv4Octets = std::array<uint8_t, 4>;
using IPv6Octets = std::array<uint8_t, 16>;

constexpr IPv4Octets kDefaultIPv4Address = {192, 168, 0, 2};
constexpr uint8_t kDefaultIPv4Prefix = 16;
constexpr IPv4Octets kSecondaryIPv4Address = {10, 0, 0, 1};
constexpr uint8_t kSecondaryIPv4Prefix = 8;

constexpr IPv6Octets kDefaultIPv6Address = {0x20, 0x01, 0x01};
constexpr uint8_t kDefaultIPv6Prefix = 16;
constexpr IPv6Octets kSecondaryIPv6Address = {0x20, 0x01, 0x02};
constexpr uint8_t kSecondaryIPv6Prefix = 16;

constexpr const char kDefaultInterfaceName[] = "net1";
constexpr const char kSecondaryInterfaceName[] = "net2";

fuchsia::net::IpAddress IpAddressFrom(IPv4Octets octets) {
  fuchsia::net::IpAddress output;
  output.ipv4().addr = octets;
  return output;
}

fuchsia::net::IpAddress IpAddressFrom(IPv6Octets octets) {
  fuchsia::net::IpAddress output;
  output.ipv6().addr = octets;
  return output;
}

template <typename T>
fuchsia::net::Subnet SubnetFrom(T octets, uint8_t prefix) {
  fuchsia::net::Subnet output;
  output.addr = IpAddressFrom(octets);
  output.prefix_len = prefix;
  return output;
}

template <typename T>
fuchsia::net::interfaces::Address InterfaceAddressFrom(T octets,
                                                       uint8_t prefix) {
  fuchsia::net::interfaces::Address addr;
  addr.set_addr(SubnetFrom(octets, prefix));
  return addr;
}

template <typename T>
std::vector<T> MakeSingleItemVec(T item) {
  std::vector<T> vec;
  vec.push_back(std::move(item));
  return vec;
}

fuchsia::net::interfaces::Properties DefaultInterfaceProperties(
    fuchsia::hardware::network::PortClass device_class =
        fuchsia::hardware::network::PortClass::ETHERNET) {
  // For most tests a live interface with an IPv4 address and ethernet class is
  // sufficient.
  fuchsia::net::interfaces::Properties interface;
  interface.set_id(kDefaultInterfaceId);
  interface.set_name(kDefaultInterfaceName);
  interface.set_online(true);
  interface.set_has_default_ipv4_route(true);
  interface.set_has_default_ipv6_route(true);
  interface.set_port_class(fuchsia::net::interfaces::PortClass::WithDevice(
      std::move(device_class)));
  interface.set_addresses(MakeSingleItemVec(
      InterfaceAddressFrom(kDefaultIPv4Address, kDefaultIPv4Prefix)));
  return interface;
}

fuchsia::net::interfaces::Properties SecondaryInterfaceProperties() {
  // For most tests a live interface with an IPv4 address and ethernet class is
  // sufficient.
  fuchsia::net::interfaces::Properties interface;
  interface.set_id(kSecondaryInterfaceId);
  interface.set_name(kSecondaryInterfaceName);
  interface.set_online(true);
  interface.set_has_default_ipv4_route(false);
  interface.set_has_default_ipv6_route(false);
  interface.set_port_class(fuchsia::net::interfaces::PortClass::WithDevice(
      []() { return fuchsia::hardware::network::PortClass::ETHERNET; } ()));
  interface.set_addresses(MakeSingleItemVec(
      InterfaceAddressFrom(kSecondaryIPv4Address, kSecondaryIPv4Prefix)));
  return interface;
}

template <typename F>
fuchsia::net::interfaces::Event MakeChangeEvent(uint64_t interface_id, F fn) {
  fuchsia::net::interfaces::Properties props;
  props.set_id(interface_id);
  fn(&props);
  return fuchsia::net::interfaces::Event::WithChanged(std::move(props));
}

// Partial fake implementation of a fuchsia.net.interfaces/Watcher.
class FakeWatcher : public fuchsia::net::interfaces::testing::Watcher_TestBase {
 public:
  FakeWatcher() : binding_(this) {
    // Always create the watcher with an empty set of interfaces.
    // Callers can override the initial set of events with SetInitial.
    pending_.push(fuchsia::net::interfaces::Event::WithIdle(
        fuchsia::net::interfaces::Empty{}));
  }
  FakeWatcher(const FakeWatcher&) = delete;
  FakeWatcher& operator=(const FakeWatcher&) = delete;
  ~FakeWatcher() override = default;

  void Bind(fidl::InterfaceRequest<fuchsia::net::interfaces::Watcher> request) {
    CHECK_EQ(ZX_OK, binding_.Bind(std::move(request)));
  }

  void Unbind() { binding_.Unbind(); }

  void PushEvent(fuchsia::net::interfaces::Event event) {
    if (pending_callback_) {
      pending_callback_(std::move(event));
      pending_callback_ = nullptr;
    } else {
      pending_.push(std::move(event));
    }
  }

  void SetInitial(std::vector<fuchsia::net::interfaces::Properties> props) {
    // Discard any pending events.
    pending_ = std::queue<fuchsia::net::interfaces::Event>();
    for (auto& prop : props) {
      pending_.push(
          fuchsia::net::interfaces::Event::WithExisting(std::move(prop)));
    }
    pending_.push(fuchsia::net::interfaces::Event::WithIdle(
        fuchsia::net::interfaces::Empty{}));
    // We should not have a pending callback already when setting initial state.
    CHECK(!pending_callback_);
  }

 private:
  void Watch(WatchCallback callback) override {
    ASSERT_FALSE(pending_callback_);
    if (pending_.empty()) {
      pending_callback_ = std::move(callback);
    } else {
      callback(std::move(pending_.front()));
      pending_.pop();
    }
  }

  void NotImplemented_(const std::string& name) override {
    LOG(FATAL) << "Unimplemented function called: " << name;
  }

  std::queue<fuchsia::net::interfaces::Event> pending_;
  fidl::Binding<fuchsia::net::interfaces::Watcher> binding_;
  WatchCallback pending_callback_ = nullptr;
};

class FakeWatcherAsync {
 public:
  FakeWatcherAsync() {
    base::Thread::Options options(base::MessagePumpType::IO, 0);
    CHECK(thread_.StartWithOptions(std::move(options)));
    watcher_ = base::SequenceBound<FakeWatcher>(thread_.task_runner());
  }
  FakeWatcherAsync(const FakeWatcherAsync&) = delete;
  FakeWatcherAsync& operator=(const FakeWatcherAsync&) = delete;
  ~FakeWatcherAsync() = default;

  void Bind(fidl::InterfaceRequest<fuchsia::net::interfaces::Watcher> request) {
    watcher_.AsyncCall(&FakeWatcher::Bind).WithArgs(std::move(request));
  }

  void Unbind() { watcher_.AsyncCall(&FakeWatcher::Unbind); }

  // Asynchronously push an event to the watcher.
  void PushEvent(fuchsia::net::interfaces::Event event) {
    watcher_.AsyncCall(&FakeWatcher::PushEvent).WithArgs(std::move(event));
  }

  // Asynchronously push an initial set of interfaces to the watcher.
  void SetInitial(std::vector<fuchsia::net::interfaces::Properties> props) {
    watcher_.AsyncCall(&FakeWatcher::SetInitial).WithArgs(std::move(props));
  }

  // Asynchronously push an initial single intface to the watcher.
  void SetInitial(fuchsia::net::interfaces::Properties prop) {
    SetInitial(MakeSingleItemVec(std::move(prop)));
  }

  // Ensures that any PushEvent() or SetInitial() calls have
  // been processed.
  void FlushThread() { thread_.FlushForTesting(); }

 private:
  base::Thread thread_{"Watcher Thread"};
  base::SequenceBound<FakeWatcher> watcher_;
};

template <class T>
class ResultReceiver {
 public:
  ~ResultReceiver() { EXPECT_EQ(entries_.size(), 0u); }
  bool RunAndExpectEntries(std::vector<T> expected_entries) {
    if (entries_.size() < expected_entries.size()) {
      base::RunLoop loop;
      base::AutoReset<size_t> size(&expected_count_, expected_entries.size());
      base::AutoReset<base::OnceClosure> quit(&quit_loop_, loop.QuitClosure());
      loop.Run();
    }
    return expected_entries == std::exchange(entries_, {});
  }
  void AddEntry(T entry) {
    entries_.push_back(entry);
    if (quit_loop_ && entries_.size() >= expected_count_)
      std::move(quit_loop_).Run();
  }

 protected:
  size_t expected_count_ = 0u;
  std::vector<T> entries_;
  base::OnceClosure quit_loop_;
};

// Accumulates the list of ConnectionTypes notified via OnConnectionTypeChanged.
class FakeConnectionTypeObserver final
    : public NetworkChangeNotifier::ConnectionTypeObserver {
 public:
  FakeConnectionTypeObserver() {
    NetworkChangeNotifier::AddConnectionTypeObserver(this);
  }
  ~FakeConnectionTypeObserver() override {
    NetworkChangeNotifier::RemoveConnectionTypeObserver(this);
  }

  bool RunAndExpectConnectionTypes(
      std::vector<NetworkChangeNotifier::ConnectionType> sequence) {
    return receiver_.RunAndExpectEntries(sequence);
  }

  // ConnectionTypeObserver implementation.
  void OnConnectionTypeChanged(
      NetworkChangeNotifier::ConnectionType type) override {
    receiver_.AddEntry(type);
  }

 protected:
  ResultReceiver<NetworkChangeNotifier::ConnectionType> receiver_;
};

// Accumulates the list of ConnectionTypes notified via OnConnectionTypeChanged.
class FakeNetworkChangeObserver final
    : public NetworkChangeNotifier::NetworkChangeObserver {
 public:
  FakeNetworkChangeObserver() {
    NetworkChangeNotifier::AddNetworkChangeObserver(this);
  }
  ~FakeNetworkChangeObserver() override {
    NetworkChangeNotifier::RemoveNetworkChangeObserver(this);
  }

  bool RunAndExpectNetworkChanges(
      std::vector<NetworkChangeNotifier::ConnectionType> sequence) {
    return receiver_.RunAndExpectEntries(sequence);
  }

  // NetworkChangeObserver implementation.
  void OnNetworkChanged(NetworkChangeNotifier::ConnectionType type) override {
    receiver_.AddEntry(type);
  }

 protected:
  ResultReceiver<NetworkChangeNotifier::ConnectionType> receiver_;
};

// Accumulates the list of ConnectionTypes notified via OnConnectionTypeChanged.
class FakeIPAddressObserver final
    : public NetworkChangeNotifier::IPAddressObserver {
 public:
  FakeIPAddressObserver() { NetworkChangeNotifier::AddIPAddressObserver(this); }
  ~FakeIPAddressObserver() override {
    NetworkChangeNotifier::RemoveIPAddressObserver(this);
    EXPECT_EQ(ip_change_count_, 0u);
  }

  size_t ip_change_count() const { return ip_change_count_; }

  bool RunAndExpectCallCount(size_t expected_count) {
    if (ip_change_count_ < expected_count) {
      base::RunLoop loop;
      base::AutoReset<size_t> expectation(&expected_count_, expected_count);
      base::AutoReset<base::OnceClosure> quit(&quit_loop_, loop.QuitClosure());
      loop.Run();
    }
    return std::exchange(ip_change_count_, 0u) == expected_count;
  }

  // IPAddressObserver implementation.
  void OnIPAddressChanged() override {
    ip_change_count_++;
    if (quit_loop_ && ip_change_count_ >= expected_count_)
      std::move(quit_loop_).Run();
  }

 protected:
  size_t expected_count_ = 0u;
  size_t ip_change_count_ = 0u;
  base::OnceClosure quit_loop_;
};

}  // namespace

class NetworkChangeNotifierFuchsiaTest : public testing::Test {
 public:
  NetworkChangeNotifierFuchsiaTest() = default;
  NetworkChangeNotifierFuchsiaTest(const NetworkChangeNotifierFuchsiaTest&) =
      delete;
  NetworkChangeNotifierFuchsiaTest& operator=(
      const NetworkChangeNotifierFuchsiaTest&) = delete;
  ~NetworkChangeNotifierFuchsiaTest() override = default;

  // Creates a NetworkChangeNotifier that binds to |watcher_|.
  // |observer_| is registered last, so that tests need only express
  // expectations on changes they make themselves.
  void CreateNotifier(bool require_wlan = false,
                      bool disconnect_watcher = false) {
    // Ensure that internal state is up-to-date before the
    // notifier queries it.
    watcher_.FlushThread();

    fidl::InterfaceHandle<fuchsia::net::interfaces::Watcher> watcher;
    fidl::InterfaceRequest<fuchsia::net::interfaces::Watcher> watcher_request =
        watcher.NewRequest();
    if (disconnect_watcher) {
      // Reset the InterfaceRequest to close the `watcher` channel.
      watcher_request = {};
    } else {
      watcher_.Bind(std::move(watcher_request));
    }

    // Use a noop DNS notifier.
    dns_config_notifier_ = std::make_unique<SystemDnsConfigChangeNotifier>(
        nullptr /* task_runner */, nullptr /* dns_config_service */);
    notifier_ = base::WrapUnique(new NetworkChangeNotifierFuchsia(
        std::move(watcher), require_wlan, dns_config_notifier_.get()));

    type_observer_ = std::make_unique<FakeConnectionTypeObserver>();
    ip_observer_ = std::make_unique<FakeIPAddressObserver>();
  }

  void TearDown() override {
    // Spin the loops to catch any unintended notifications.
    watcher_.FlushThread();
    base::RunLoop().RunUntilIdle();
  }

 protected:
  base::test::SingleThreadTaskEnvironment task_environment_{
      base::test::SingleThreadTaskEnvironment::MainThreadType::IO};

  FakeWatcherAsync watcher_;

  // Allows us to allocate our own NetworkChangeNotifier for unit testing.
  NetworkChangeNotifier::DisableForTest disable_for_test_;
  std::unique_ptr<SystemDnsConfigChangeNotifier> dns_config_notifier_;
  std::unique_ptr<NetworkChangeNotifierFuchsia> notifier_;

  std::unique_ptr<FakeConnectionTypeObserver> type_observer_;
  std::unique_ptr<FakeIPAddressObserver> ip_observer_;
};

TEST_F(NetworkChangeNotifierFuchsiaTest, ConnectFail_BeforeGetWatcher) {
  // CreateNotifier will pass an already-disconnected Watcher handle to the
  // new NetworkChangeNotifier, which will cause the process to exit during
  // construction.
  EXPECT_EXIT(
      CreateNotifier(/*require_wlan=*/false, /*disconnect_watcher=*/true),
      testing::ExitedWithCode(1), "");
}

TEST_F(NetworkChangeNotifierFuchsiaTest, ConnectFail_AfterGetWatcher) {
  CreateNotifier();

  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_NONE,
            notifier_->GetCurrentConnectionType());

  // Disconnect the Watcher protocol in-use by the NetworkChangeNotifier.
  watcher_.Unbind();
  watcher_.FlushThread();

  // Spin the loop to process the disconnection, which should terminate the
  // test process.
  EXPECT_EXIT(base::RunLoop().RunUntilIdle(), testing::ExitedWithCode(1), "");

  // Teardown the notifier here to ensure it doesn't observe further events.
  notifier_ = nullptr;
}

TEST_F(NetworkChangeNotifierFuchsiaTest, InitialState) {
  CreateNotifier();
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_NONE,
            notifier_->GetCurrentConnectionType());
}

TEST_F(NetworkChangeNotifierFuchsiaTest, InterfacesChangeDuringConstruction) {
  // Set a live interface with an IP address.
  watcher_.SetInitial(DefaultInterfaceProperties(
      fuchsia::hardware::network::PortClass::WLAN_CLIENT));

  // Inject an interfaces change event so that the notifier will receive it
  // immediately after the initial state.
  watcher_.PushEvent(MakeChangeEvent(
      kDefaultInterfaceId, [](fuchsia::net::interfaces::Properties* props) {
        props->set_addresses(MakeSingleItemVec(
            InterfaceAddressFrom(kSecondaryIPv4Address, kSecondaryIPv4Prefix)));
      }));

  // Create the Notifier, which should process the initial network state before
  // returning, but not the change event, yet.
  CreateNotifier();
  EXPECT_EQ(ip_observer_->ip_change_count(), 0u);

  // Now spin the loop to allow the change event to be processed, triggering a
  // call to the |ip_observer_|.
  EXPECT_TRUE(ip_observer_->RunAndExpectCallCount(1));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, NotifyNetworkChangeOnInitialIPChange) {
  // Set a live interface with an IP address and create the notifier.
  watcher_.SetInitial(DefaultInterfaceProperties(
      fuchsia::hardware::network::PortClass::WLAN_CLIENT));
  CreateNotifier();

  // Add the NetworkChangeNotifier, and change the IP address. This should
  // trigger a network change notification.
  FakeNetworkChangeObserver network_change_observer;

  watcher_.PushEvent(MakeChangeEvent(
      kDefaultInterfaceId, [](fuchsia::net::interfaces::Properties* props) {
        props->set_addresses(MakeSingleItemVec(
            InterfaceAddressFrom(kSecondaryIPv4Address, kSecondaryIPv4Prefix)));
      }));

  EXPECT_TRUE(network_change_observer.RunAndExpectNetworkChanges(
      {NetworkChangeNotifier::CONNECTION_NONE,
       NetworkChangeNotifier::CONNECTION_WIFI}));
  EXPECT_TRUE(ip_observer_->RunAndExpectCallCount(1));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, NoChange) {
  // Set a live interface with an IP address and create the notifier.
  watcher_.SetInitial(DefaultInterfaceProperties());
  CreateNotifier();
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_ETHERNET,
            notifier_->GetCurrentConnectionType());
  // Push an event with no side-effects.
  watcher_.PushEvent(MakeChangeEvent(kDefaultInterfaceId, [](auto*) {}));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, NoChangeV6) {
  auto initial = DefaultInterfaceProperties();
  initial.set_addresses(MakeSingleItemVec(
      InterfaceAddressFrom(kDefaultIPv6Address, kDefaultIPv6Prefix)));
  watcher_.SetInitial(std::move(initial));
  CreateNotifier();
  // Push an event with no side-effects.
  watcher_.PushEvent(MakeChangeEvent(kDefaultInterfaceId, [](auto*) {}));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, MultiInterfaceNoChange) {
  std::vector<fuchsia::net::interfaces::Properties> props;
  props.push_back(DefaultInterfaceProperties());
  props.push_back(SecondaryInterfaceProperties());
  watcher_.SetInitial(std::move(props));
  CreateNotifier();
  // Push an event with no side-effects.
  watcher_.PushEvent(MakeChangeEvent(kDefaultInterfaceId, [](auto*) {}));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, MultiV6IPNoChange) {
  auto props = DefaultInterfaceProperties();
  props.mutable_addresses()->push_back(
      InterfaceAddressFrom(kDefaultIPv6Address, kDefaultIPv6Prefix));
  props.mutable_addresses()->push_back(
      InterfaceAddressFrom(kSecondaryIPv6Address, kSecondaryIPv6Prefix));

  watcher_.SetInitial(std::move(props));
  CreateNotifier();

  // Push an event with no side-effects.
  watcher_.PushEvent(MakeChangeEvent(kDefaultInterfaceId, [](auto*) {}));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, IpChange) {
  watcher_.SetInitial(DefaultInterfaceProperties());
  CreateNotifier();
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_ETHERNET,
            notifier_->GetCurrentConnectionType());

  watcher_.PushEvent(MakeChangeEvent(
      kDefaultInterfaceId, [](fuchsia::net::interfaces::Properties* props) {
        props->set_addresses(MakeSingleItemVec(
            InterfaceAddressFrom(kSecondaryIPv4Address, kSecondaryIPv4Prefix)));
      }));

  // Expect a single OnIPAddressChanged() notification.
  EXPECT_TRUE(ip_observer_->RunAndExpectCallCount(1));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, IpChangeV6) {
  auto props = DefaultInterfaceProperties();
  props.set_addresses(MakeSingleItemVec(
      InterfaceAddressFrom(kDefaultIPv6Address, kDefaultIPv6Prefix)));
  watcher_.SetInitial(std::move(props));
  CreateNotifier();
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_ETHERNET,
            notifier_->GetCurrentConnectionType());

  watcher_.PushEvent(MakeChangeEvent(
      kDefaultInterfaceId, [](fuchsia::net::interfaces::Properties* props) {
        props->set_addresses(MakeSingleItemVec(
            InterfaceAddressFrom(kSecondaryIPv6Address, kSecondaryIPv6Prefix)));
      }));

  // Expect a single OnIPAddressChanged() notification.
  EXPECT_TRUE(ip_observer_->RunAndExpectCallCount(1));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, MultiV6IPChanged) {
  auto props = DefaultInterfaceProperties();
  props.mutable_addresses()->push_back(
      InterfaceAddressFrom(kDefaultIPv6Address, kDefaultIPv6Prefix));

  watcher_.SetInitial(std::move(props));
  CreateNotifier();
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_ETHERNET,
            notifier_->GetCurrentConnectionType());

  watcher_.PushEvent(MakeChangeEvent(
      kDefaultInterfaceId, [](fuchsia::net::interfaces::Properties* props) {
        std::vector<fuchsia::net::interfaces::Address> addrs;
        addrs.push_back(
            InterfaceAddressFrom(kSecondaryIPv4Address, kSecondaryIPv4Prefix));
        addrs.push_back(
            InterfaceAddressFrom(kSecondaryIPv6Address, kSecondaryIPv6Prefix));
        props->set_addresses(std::move(addrs));
      }));

  // Expect a single OnIPAddressChanged() notification.
  EXPECT_TRUE(ip_observer_->RunAndExpectCallCount(1));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, Ipv6AdditionalIpChange) {
  watcher_.SetInitial(DefaultInterfaceProperties());
  CreateNotifier();
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_ETHERNET,
            notifier_->GetCurrentConnectionType());

  watcher_.PushEvent(MakeChangeEvent(
      kDefaultInterfaceId, [](fuchsia::net::interfaces::Properties* props) {
        // Add the initial default address + a new IPv6 one. Address changes are
        // always sent as the entire new list of addresses.
        props->mutable_addresses()->push_back(
            InterfaceAddressFrom(kDefaultIPv4Address, kDefaultIPv4Prefix));
        props->mutable_addresses()->push_back(
            InterfaceAddressFrom(kDefaultIPv6Address, kDefaultIPv6Prefix));
      }));

  // Expect a single OnIPAddressChanged() notification.
  EXPECT_TRUE(ip_observer_->RunAndExpectCallCount(1));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, InterfaceDown) {
  watcher_.SetInitial(DefaultInterfaceProperties());
  CreateNotifier();
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_ETHERNET,
            notifier_->GetCurrentConnectionType());

  watcher_.PushEvent(MakeChangeEvent(
      kDefaultInterfaceId, [](fuchsia::net::interfaces::Properties* props) {
        props->set_online(false);
      }));

  EXPECT_TRUE(type_observer_->RunAndExpectConnectionTypes(
      {NetworkChangeNotifier::ConnectionType::CONNECTION_NONE}));
  EXPECT_TRUE(ip_observer_->RunAndExpectCallCount(1));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, InterfaceUp) {
  auto props = DefaultInterfaceProperties();
  props.set_online(false);
  watcher_.SetInitial(std::move(props));
  CreateNotifier();
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_NONE,
            notifier_->GetCurrentConnectionType());

  watcher_.PushEvent(MakeChangeEvent(
      kDefaultInterfaceId, [](fuchsia::net::interfaces::Properties* props) {
        props->set_online(true);
      }));

  EXPECT_TRUE(type_observer_->RunAndExpectConnectionTypes(
      {NetworkChangeNotifier::ConnectionType::CONNECTION_ETHERNET}));
  EXPECT_TRUE(ip_observer_->RunAndExpectCallCount(1));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, InterfaceDeleted) {
  watcher_.SetInitial(DefaultInterfaceProperties());
  CreateNotifier();
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_ETHERNET,
            notifier_->GetCurrentConnectionType());

  watcher_.PushEvent(
      fuchsia::net::interfaces::Event::WithRemoved(kDefaultInterfaceId));

  EXPECT_TRUE(type_observer_->RunAndExpectConnectionTypes(
      {NetworkChangeNotifier::ConnectionType::CONNECTION_NONE}));
  EXPECT_TRUE(ip_observer_->RunAndExpectCallCount(1));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, InterfaceAdded) {
  // Initial interface list is intentionally left empty.
  CreateNotifier();
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_NONE,
            notifier_->GetCurrentConnectionType());

  watcher_.PushEvent(
      fuchsia::net::interfaces::Event::WithAdded(DefaultInterfaceProperties(
          fuchsia::hardware::network::PortClass::WLAN_CLIENT)));

  EXPECT_TRUE(type_observer_->RunAndExpectConnectionTypes(
      {NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI}));
  EXPECT_TRUE(ip_observer_->RunAndExpectCallCount(1));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, SecondaryInterfaceAddedNoop) {
  watcher_.SetInitial(DefaultInterfaceProperties());
  CreateNotifier();

  watcher_.PushEvent(fuchsia::net::interfaces::Event::WithAdded(
      SecondaryInterfaceProperties()));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, SecondaryInterfaceDeletedNoop) {
  std::vector<fuchsia::net::interfaces::Properties> interfaces;
  interfaces.push_back(DefaultInterfaceProperties());
  interfaces.push_back(SecondaryInterfaceProperties());

  watcher_.SetInitial(std::move(interfaces));
  CreateNotifier();

  watcher_.PushEvent(
      fuchsia::net::interfaces::Event::WithRemoved(kSecondaryInterfaceId));
}

TEST_F(NetworkChangeNotifierFuchsiaTest, FoundWiFi) {
  watcher_.SetInitial(DefaultInterfaceProperties(
      fuchsia::hardware::network::PortClass::WLAN_CLIENT));
  CreateNotifier();
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI,
            notifier_->GetCurrentConnectionType());
}

TEST_F(NetworkChangeNotifierFuchsiaTest, FindsInterfaceWithRequiredWlan) {
  watcher_.SetInitial(DefaultInterfaceProperties(
      fuchsia::hardware::network::PortClass::WLAN_CLIENT));
  CreateNotifier(/*require_wlan=*/true);
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI,
            notifier_->GetCurrentConnectionType());
}

TEST_F(NetworkChangeNotifierFuchsiaTest, IgnoresNonWlanInterface) {
  watcher_.SetInitial(DefaultInterfaceProperties());
  CreateNotifier(/*require_wlan=*/true);
  EXPECT_EQ(NetworkChangeNotifier::ConnectionType::CONNECTION_NONE,
            notifier_->GetCurrentConnectionType());
}

}  // namespace net
```