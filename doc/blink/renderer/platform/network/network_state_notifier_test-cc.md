Response:
Let's break down the thought process for analyzing the given C++ test file and fulfilling the prompt's requirements.

**1. Understanding the Goal:**

The core task is to understand the functionality of the `network_state_notifier_test.cc` file. Since it's a test file, the primary goal is to determine what aspect of the Chromium Blink engine it's testing. The prompt specifically asks about its functions, relationships to web technologies (JavaScript, HTML, CSS), logic with input/output examples, potential user errors, and a summary of its functionality.

**2. Initial Code Scan - Identifying Key Components:**

I started by quickly scanning the code for recognizable keywords and patterns:

* **Includes:**  `network_state_notifier.h`, `testing/gtest/include/gtest/gtest.h`, and `third_party/blink/public/platform/...` immediately signal this is a test file for the `NetworkStateNotifier` class within the Blink engine. The `gtest` include confirms it's using Google Test for unit testing.
* **Namespaces:**  The `blink` namespace confirms the context.
* **Test Fixture:** The `class NetworkStateNotifierTest : public testing::Test` defines the test environment.
* **Test Cases:**  `TEST_F(NetworkStateNotifierTest, ...)` clearly marks individual test scenarios.
* **`StateObserver` Class:** This class implements the `NetworkStateNotifier::NetworkStateObserver` interface, suggesting it's used to observe changes in network state. The member variables within this class (like `observed_type_`, `observed_max_bandwidth_mbps_`, etc.) indicate the specific network properties being monitored.
* **`NetworkStateNotifier` Instance:** The `notifier_` member in `NetworkStateNotifierTest` is the class under test.
* **`SetConnection` and `SetOnLine` methods:** These methods within the test fixture seem to be used to simulate changes in network conditions.
* **`VerifyObservations` method:**  This method is used to assert that the `StateObserver` has received the expected network state updates.
* **Constants:**  Constants like `kNoneMaxBandwidthMbps`, `kBluetoothMaxBandwidthMbps`, etc., represent different network connection types and their properties.

**3. Inferring Functionality - The Core Logic:**

Based on the identified components, the core functionality of the `NetworkStateNotifier` and the purpose of the test file become apparent:

* **`NetworkStateNotifier`:** This class is responsible for managing and notifying about the current network state (connection type, bandwidth, effective connection type, round-trip times, online/offline status, data saving preference). It likely acts as a central point for components within the Blink engine to access this information.
* **`NetworkStateObserver`:** This is an interface that other classes can implement to receive notifications when the network state changes.
* **Test File (`network_state_notifier_test.cc`):** This file tests the `NetworkStateNotifier` class by:
    * Creating instances of `NetworkStateNotifier`.
    * Creating mock observers (`StateObserver`).
    * Adding and removing observers.
    * Simulating different network state changes using methods like `SetWebConnection`, `SetNetworkQuality`, and `SetOnLine`.
    * Verifying that the observers are correctly notified of these changes using assertions in `VerifyObservations`.
    * Testing scenarios involving adding and removing observers during notification.
    * Testing overriding network connection information.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This requires understanding *why* Blink needs to track network state.

* **JavaScript:** JavaScript code running in a web page can access network information through browser APIs like `navigator.connection`. The `NetworkStateNotifier` likely provides the underlying data for these APIs. For example, a website might adapt its behavior based on the connection type (e.g., serving lower-resolution images on a slow connection).
* **HTML:**  HTML itself doesn't directly interact with network state. However, the resources referenced in HTML (images, scripts, stylesheets) are loaded over the network, and the network state affects loading performance.
* **CSS:**  Similar to HTML, CSS files are fetched over the network. CSS Media Queries can be used to apply different styles based on network conditions (though this is less common than JavaScript-driven adaptations).

**5. Logic and Examples (Input/Output):**

This involves looking at the test cases and inferring the expected behavior. The `SetConnection` method is the key input, and the `VerifyObservations` method checks the output received by the observers. I analyzed specific test cases like `AddObserver`, `RemoveObserver`, and the override tests to understand the flow.

* **Example:** If `SetConnection` is called with `kWebConnectionTypeBluetooth`, the registered observers should eventually receive a `ConnectionChange` callback with `observed_type_` set to `kWebConnectionTypeBluetooth`.

**6. User/Programming Errors:**

I considered common mistakes someone might make when *using* the `NetworkStateNotifier` or its observer mechanism.

* **Forgetting to Add Observer:** If a component needs to react to network changes but doesn't register as an observer, it won't receive updates.
* **Memory Management Issues:**  If the observer object is destroyed prematurely while still registered, this could lead to crashes or undefined behavior when the notifier tries to call a method on a dangling pointer. The use of `std::unique_ptr` for handles helps mitigate this.
* **Incorrect Task Runner:** Adding and removing observers on different threads than the notifier runs on can lead to race conditions or missed notifications.

**7. Summarizing Functionality:**

Finally, I synthesized the information gathered into a concise summary, focusing on the core purpose of the test file: verifying the `NetworkStateNotifier`'s ability to manage and propagate network state changes to its observers.

**Self-Correction/Refinement:**

During this process, I might have initially focused too much on the details of individual test cases. I then stepped back to understand the bigger picture: the role of `NetworkStateNotifier` in the Blink engine. I also refined the examples and explanations to be clearer and more specific to web technologies. For instance, initially, I might have just said "JavaScript can use network info," but then refined it to mention the `navigator.connection` API.
好的，让我们来分析一下 `blink/renderer/platform/network/network_state_notifier_test.cc` 这个文件的功能。

**功能概览**

`network_state_notifier_test.cc` 是 Chromium Blink 引擎中用于测试 `NetworkStateNotifier` 类的单元测试文件。它的主要功能是验证 `NetworkStateNotifier` 类是否能够正确地管理和通知网络状态的变化。

具体来说，它测试了以下方面：

1. **添加和移除观察者 (Observers):** 测试 `NetworkStateNotifier` 是否允许其他对象（观察者）注册以接收网络状态变化的通知，并且在不需要时能够正确地取消注册。这包括在通知过程中添加和移除观察者的场景。
2. **网络状态变化的通知:** 测试当网络连接类型、最大带宽、有效连接类型（例如 3G、4G）、往返时延 (RTT)、下行吞吐量、是否开启省流模式以及在线状态发生变化时，`NetworkStateNotifier` 是否能够正确地通知所有已注册的观察者。
3. **跨线程通知:** 测试在不同的线程上添加观察者时，`NetworkStateNotifier` 是否能够正确地进行通知。
4. **覆盖 (Override) 网络状态:** 测试 `NetworkStateNotifier` 是否支持设置临时的网络状态覆盖，这在某些测试或特殊场景下很有用。并且验证覆盖状态下，原始的网络状态变化是否被正确地忽略，以及取消覆盖后是否恢复正常通知。
5. **获取当前网络状态:** 测试 `NetworkStateNotifier` 是否提供了方法来获取当前的各种网络状态信息。

**与 JavaScript, HTML, CSS 的关系**

`NetworkStateNotifier` 位于 Blink 引擎的底层网络平台层，它本身不直接操作 JavaScript, HTML 或 CSS。但是，它提供的网络状态信息会被 Blink 引擎的其他组件使用，最终影响到 Web 页面的行为和渲染。

**举例说明:**

* **JavaScript:**  Web 页面中的 JavaScript 代码可以使用 `navigator.connection` API 来获取网络连接信息，例如连接类型 (`type`) 和下行链路速度 (`downlinkMax`). `NetworkStateNotifier` 负责收集和维护这些底层网络信息，并将其传递给上层的 JavaScript API。

   **假设输入与输出 (JavaScript 角度):**
   * **假设输入 (C++ 层面):** `NetworkStateNotifier` 接收到操作系统通知，网络连接从 `kWebConnectionTypeWifi` 变为 `kWebConnectionTypeCellular`.
   * **逻辑推理:** `NetworkStateNotifier` 更新其内部状态，并通知所有观察者。
   * **假设输出 (JavaScript 层面):**  在 Web 页面中注册了 `navigator.connection.onchange` 事件的 JavaScript 代码会收到通知，`navigator.connection.type` 的值会从 `"wifi"` 更新为 `"cellular"`。

* **HTML 和 CSS:** 虽然 HTML 和 CSS 本身不直接与 `NetworkStateNotifier` 交互，但网络状态会影响资源的加载。例如，在弱网络环境下，浏览器可能会采取不同的策略来加载图片或执行脚本，以提高页面加载速度。`NetworkStateNotifier` 提供的网络质量信息可以帮助浏览器做出这些决策。

   **假设输入与输出 (HTML/CSS 加载角度):**
   * **假设输入 (C++ 层面):** `NetworkStateNotifier` 监测到网络 RTT 较高，有效连接类型为 `kTypeSlow2G`。
   * **逻辑推理:** Blink 引擎中的资源加载器可能会接收到 `NetworkStateNotifier` 发出的网络质量信号。
   * **假设输出 (HTML/CSS 加载角度):** 浏览器可能会延迟加载某些非关键的图片或者使用较低分辨率的图片，以减少加载时间，提升用户体验。这可能涉及到对 `<img>` 标签的 `loading="lazy"` 属性的更积极应用，或者 CSS 中使用媒体查询根据网络速度应用不同的样式。

**逻辑推理举例**

* **假设输入:**
    1. 创建一个 `NetworkStateNotifier` 实例。
    2. 创建两个 `StateObserver` 实例 (observer1 和 observer2)。
    3. 将 observer1 注册到 `NetworkStateNotifier`。
    4. 调用 `notifier_.SetWebConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps)`。
* **逻辑推理:**
    1. `NetworkStateNotifier` 检测到网络连接类型和带宽发生了变化。
    2. `NetworkStateNotifier` 遍历已注册的观察者列表。
    3. `NetworkStateNotifier` 调用 observer1 的 `ConnectionChange` 方法，并传递新的网络连接类型和带宽信息。
* **假设输出:**
    1. observer1 的 `ObservedType()` 返回 `kWebConnectionTypeBluetooth`。
    2. observer1 的 `ObservedMaxBandwidth()` 返回 `kBluetoothMaxBandwidthMbps`。
    3. observer2 由于没有注册，其状态不会发生改变。

**用户或编程常见的使用错误**

1. **忘记注册观察者:**  一个组件需要监听网络状态变化，但是忘记调用 `notifier_.AddConnectionObserver()` 进行注册，导致无法接收到通知。
   ```c++
   // 错误示例：忘记注册观察者
   class MyComponent : public NetworkStateNotifier::NetworkStateObserver {
   public:
       void ConnectionChange(WebConnectionType type,
                             double max_bandwidth_mbps,
                             WebEffectiveConnectionType effective_type,
                             const std::optional<base::TimeDelta>& http_rtt,
                             const std::optional<base::TimeDelta>& transport_rtt,
                             const std::optional<double>& downlink_throughput_mbps,
                             bool save_data) override {
           // ... 对网络状态变化做出响应
       }
       // ...
   };

   void SomeFunction() {
       MyComponent my_component;
       // 注意：这里忘记了将 my_component 注册到 NetworkStateNotifier
       NetworkStateNotifier::GetInstance().SetWebConnection(kWebConnectionTypeWifi, 10.0);
       // my_component 的 ConnectionChange 不会被调用
   }
   ```

2. **在错误的线程上操作:**  如果在一个线程上注册了观察者，然后在另一个线程上修改网络状态，可能会导致线程安全问题或通知不及时。`NetworkStateNotifier` 通常会指定在哪个线程上进行观察者回调。
   ```c++
   // 假设在线程 A 上创建并注册了观察者
   auto task_runner_a = base::ThreadTaskRunnerHandle::Get();
   StateObserver observer;
   NetworkStateNotifier::GetInstance().AddConnectionObserver(&observer, task_runner_a);

   // 然后在线程 B 上修改网络状态
   std::thread thread_b([]() {
       NetworkStateNotifier::GetInstance().SetWebConnection(kWebConnectionTypeCellular, 5.0);
   });
   thread_b.join();

   // 可能会出现通知延迟或线程安全问题，具体取决于 NetworkStateNotifier 的实现
   ```

3. **内存管理错误:**  如果观察者对象在被 `NetworkStateNotifier` 通知之前被销毁，可能会导致程序崩溃。通常，需要确保观察者的生命周期长于其注册的时间，或者使用智能指针来管理观察者的生命周期。

**归纳功能 (第 1 部分)**

总的来说，`blink/renderer/platform/network/network_state_notifier_test.cc` 文件的主要功能是**全面地测试 `NetworkStateNotifier` 类的核心能力，包括管理观察者、正确地通知各种网络状态变化（连接类型、带宽、有效连接类型、RTT、吞吐量、省流模式、在线状态）、处理跨线程场景以及验证网络状态覆盖机制的正确性。**  这个测试文件确保了 `NetworkStateNotifier` 作为 Blink 引擎中重要的网络状态信息提供者，能够稳定可靠地工作，为上层模块（包括最终影响 JavaScript API 和资源加载策略）提供准确的网络信息。

Prompt: 
```
这是目录为blink/renderer/platform/network/network_state_notifier_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (c) 2014, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/network/network_state_notifier.h"

#include <optional>

#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_connection_type.h"
#include "third_party/blink/public/platform/web_effective_connection_type.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

using scheduler::FakeTaskRunner;

namespace {
const double kNoneMaxBandwidthMbps = 0.0;
const double kBluetoothMaxBandwidthMbps = 1.0;
const double kEthernetMaxBandwidthMbps = 2.0;
const std::optional<base::TimeDelta> kEthernetHttpRtt(base::Milliseconds(50));
const std::optional<base::TimeDelta> kEthernetTransportRtt(
    base::Milliseconds(25));
const std::optional<double> kEthernetThroughputMbps(75.0);
const std::optional<base::TimeDelta> kUnknownRtt;
const std::optional<double> kUnknownThroughputMbps;

enum class SaveData {
  kOff = 0,
  kOn = 1,
};

}  // namespace

class StateObserver final : public NetworkStateNotifier::NetworkStateObserver {
 public:
  StateObserver()
      : observed_type_(kWebConnectionTypeNone),
        observed_max_bandwidth_mbps_(0.0),
        observed_effective_type_(WebEffectiveConnectionType::kTypeUnknown),
        observed_http_rtt_(kUnknownRtt),
        observed_transport_rtt_(kUnknownRtt),
        observed_downlink_throughput_mbps_(kUnknownThroughputMbps),
        observed_on_line_state_(false),
        observed_save_data_(SaveData::kOff),
        callback_count_(0) {}
  ~StateObserver() = default;

  void ConnectionChange(WebConnectionType type,
                        double max_bandwidth_mbps,
                        WebEffectiveConnectionType effective_type,
                        const std::optional<base::TimeDelta>& http_rtt,
                        const std::optional<base::TimeDelta>& transport_rtt,
                        const std::optional<double>& downlink_throughput_mbps,
                        bool save_data) override {
    observed_type_ = type;
    observed_max_bandwidth_mbps_ = max_bandwidth_mbps;
    observed_effective_type_ = effective_type;
    observed_http_rtt_ = http_rtt;
    observed_transport_rtt_ = transport_rtt;
    observed_downlink_throughput_mbps_ = downlink_throughput_mbps;
    observed_save_data_ = save_data ? SaveData::kOn : SaveData::kOff;
    callback_count_ += 1;

    if (closure_)
      std::move(closure_).Run();
  }

  void OnLineStateChange(bool on_line) override {
    observed_on_line_state_ = on_line;
    callback_count_ += 1;

    if (closure_)
      std::move(closure_).Run();
  }

  WebConnectionType ObservedType() const { return observed_type_; }
  double ObservedMaxBandwidth() const { return observed_max_bandwidth_mbps_; }
  WebEffectiveConnectionType ObservedEffectiveType() const {
    return observed_effective_type_;
  }
  std::optional<base::TimeDelta> ObservedHttpRtt() const {
    return observed_http_rtt_;
  }
  std::optional<base::TimeDelta> ObservedTransportRtt() const {
    return observed_transport_rtt_;
  }
  std::optional<double> ObservedDownlinkThroughputMbps() const {
    return observed_downlink_throughput_mbps_;
  }
  bool ObservedOnLineState() const { return observed_on_line_state_; }
  SaveData ObservedSaveData() const { return observed_save_data_; }
  int CallbackCount() const { return callback_count_; }

  void AddObserverOnNotification(
      NetworkStateNotifier* notifier,
      StateObserver* observer_to_add,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    closure_ = base::BindOnce(
        [](StateObserver* observer, NetworkStateNotifier* notifier,
           StateObserver* observer_to_add,
           scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
          observer->added_handle_ =
              notifier->AddConnectionObserver(observer_to_add, task_runner);
        },
        base::Unretained(this), base::Unretained(notifier),
        base::Unretained(observer_to_add), task_runner);
  }

  void RemoveObserverOnNotification(
      std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle>
          handle) {
    closure_ = base::BindOnce(
        [](std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle>
               handle) {},
        std::move(handle));
  }

 private:
  base::OnceClosure closure_;
  WebConnectionType observed_type_;
  double observed_max_bandwidth_mbps_;
  WebEffectiveConnectionType observed_effective_type_;
  std::optional<base::TimeDelta> observed_http_rtt_;
  std::optional<base::TimeDelta> observed_transport_rtt_;
  std::optional<double> observed_downlink_throughput_mbps_;
  bool observed_on_line_state_;
  SaveData observed_save_data_;
  int callback_count_;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle>
      added_handle_;
};

class NetworkStateNotifierTest : public testing::Test {
 public:
  NetworkStateNotifierTest()
      : task_runner_(base::MakeRefCounted<FakeTaskRunner>()),
        task_runner2_(base::MakeRefCounted<FakeTaskRunner>()) {
    // Initialize connection, so that future calls to setWebConnection issue
    // notifications.
    notifier_.SetWebConnection(kWebConnectionTypeUnknown, 0.0);
    notifier_.SetOnLine(false);
  }

  base::SingleThreadTaskRunner* GetTaskRunner() { return task_runner_.get(); }
  base::SingleThreadTaskRunner* GetTaskRunner2() { return task_runner2_.get(); }

  void TearDown() override {
    // NetworkStateNotifier class is a singleton, so clear the override to avoid
    // indeterminate state across the test harness.
    notifier_.ClearOverride();
    RunPendingTasks();
    task_runner_ = nullptr;
    task_runner2_ = nullptr;
  }

 protected:
  void RunPendingTasks() {
    task_runner_->RunUntilIdle();
    task_runner2_->RunUntilIdle();
  }

  void SetConnection(WebConnectionType type,
                     double max_bandwidth_mbps,
                     WebEffectiveConnectionType effective_type,
                     const std::optional<base::TimeDelta>& http_rtt,
                     const std::optional<base::TimeDelta>& transport_rtt,
                     const std::optional<double>& downlink_throughput_mbps,
                     SaveData save_data) {
    notifier_.SetWebConnection(type, max_bandwidth_mbps);
    notifier_.SetNetworkQuality(
        effective_type,
        http_rtt.has_value() ? http_rtt.value() : base::Milliseconds(-1),
        transport_rtt.has_value() ? transport_rtt.value()
                                  : base::Milliseconds(-1),
        downlink_throughput_mbps.has_value()
            ? downlink_throughput_mbps.value() * 1000
            : -1);
    notifier_.SetSaveDataEnabled(save_data == SaveData::kOn);
    RunPendingTasks();
  }
  void SetOnLine(bool on_line) {
    notifier_.SetOnLine(on_line);
    RunPendingTasks();
  }

  void VerifyInitialMetricsWithWebHoldbackState(
      WebConnectionType expected_type,
      double expected_max_bandwidth_mbps,
      WebEffectiveConnectionType expected_effective_type,
      const std::optional<base::TimeDelta>& expected_http_rtt,
      const std::optional<double>& expected_downlink_throughput_mbps,
      SaveData expected_save_data) const {
    WebConnectionType initial_type;
    double initial_downlink_max_mbps;
    WebEffectiveConnectionType initial_effective_type;
    std::optional<base::TimeDelta> initial_http_rtt;
    std::optional<double> initial_downlink_mbps;
    bool initial_save_data;

    notifier_.GetMetricsWithWebHoldback(
        &initial_type, &initial_downlink_max_mbps, &initial_effective_type,
        &initial_http_rtt, &initial_downlink_mbps, &initial_save_data);

    EXPECT_EQ(expected_type, initial_type);
    EXPECT_EQ(expected_max_bandwidth_mbps, initial_downlink_max_mbps);
    EXPECT_EQ(expected_effective_type, initial_effective_type);
    EXPECT_EQ(expected_http_rtt, initial_http_rtt);
    EXPECT_EQ(expected_downlink_throughput_mbps, initial_downlink_mbps);
    EXPECT_EQ(expected_save_data == SaveData::kOn, initial_save_data);
  }

  bool VerifyObservations(const StateObserver& observer,
                          WebConnectionType type,
                          double max_bandwidth_mbps,
                          WebEffectiveConnectionType effective_type,
                          const std::optional<base::TimeDelta>& http_rtt,
                          const std::optional<base::TimeDelta>& transport_rtt,
                          const std::optional<double>& downlink_throughput_mbps,
                          SaveData save_data) const {
    EXPECT_EQ(type, observer.ObservedType());
    EXPECT_EQ(max_bandwidth_mbps, observer.ObservedMaxBandwidth());
    EXPECT_EQ(effective_type, observer.ObservedEffectiveType());
    EXPECT_EQ(http_rtt, observer.ObservedHttpRtt());
    EXPECT_EQ(transport_rtt, observer.ObservedTransportRtt());
    EXPECT_EQ(downlink_throughput_mbps,
              observer.ObservedDownlinkThroughputMbps());
    EXPECT_EQ(save_data, observer.ObservedSaveData());

    return observer.ObservedType() == type &&
           observer.ObservedMaxBandwidth() == max_bandwidth_mbps &&
           observer.ObservedEffectiveType() == effective_type &&
           observer.ObservedHttpRtt() == http_rtt &&
           observer.ObservedTransportRtt() == transport_rtt &&
           observer.ObservedDownlinkThroughputMbps() ==
               downlink_throughput_mbps &&
           observer.ObservedSaveData() == save_data;
  }

  scoped_refptr<FakeTaskRunner> task_runner_;
  scoped_refptr<FakeTaskRunner> task_runner2_;
  NetworkStateNotifier notifier_;
};

TEST_F(NetworkStateNotifierTest, AddObserver) {
  StateObserver observer;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddConnectionObserver(&observer, GetTaskRunner());
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeNone, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));

  VerifyInitialMetricsWithWebHoldbackState(
      kWebConnectionTypeUnknown, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff);

  // Change max. bandwidth and the network quality estimates.
  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff));
  EXPECT_EQ(observer.CallbackCount(), 2);

  VerifyInitialMetricsWithWebHoldbackState(
      kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetThroughputMbps, SaveData::kOff);

  // Only change the connection type.
  SetConnection(kWebConnectionTypeEthernet, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeEthernet, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff));
  EXPECT_EQ(observer.CallbackCount(), 3);

  // Only change the max. bandwidth.
  SetConnection(kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff));
  EXPECT_EQ(observer.CallbackCount(), 4);

  // Only change the transport RTT.
  SetConnection(kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt.value() * 2, kEthernetThroughputMbps,
                SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt.value() * 2, kEthernetThroughputMbps,
      SaveData::kOff));
  EXPECT_EQ(observer.CallbackCount(), 5);

  // Only change the effective connection type.
  SetConnection(kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
                WebEffectiveConnectionType::kType4G, kEthernetHttpRtt,
                kEthernetTransportRtt.value() * 2, kEthernetThroughputMbps,
                SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kType4G, kEthernetHttpRtt,
      kEthernetTransportRtt.value() * 2, kEthernetThroughputMbps,
      SaveData::kOff));
  EXPECT_EQ(observer.CallbackCount(), 6);

  // Only change the save data.
  SetConnection(kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
                WebEffectiveConnectionType::kType4G, kEthernetHttpRtt,
                kEthernetTransportRtt.value() * 2, kEthernetThroughputMbps,
                SaveData::kOn);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kType4G, kEthernetHttpRtt,
      kEthernetTransportRtt.value() * 2, kEthernetThroughputMbps,
      SaveData::kOn));
  EXPECT_EQ(observer.CallbackCount(), 7);
}

TEST_F(NetworkStateNotifierTest, RemoveObserver) {
  StateObserver observer1, observer2;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle1 =
      notifier_.AddConnectionObserver(&observer1, GetTaskRunner());
  handle1 = nullptr;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle2 =
      notifier_.AddConnectionObserver(&observer2, GetTaskRunner());

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);

  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeNone, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(VerifyObservations(
      observer2, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff));
}

TEST_F(NetworkStateNotifierTest, RemoveSoleObserver) {
  StateObserver observer1;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddConnectionObserver(&observer1, GetTaskRunner());
  handle = nullptr;

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeNone, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
}

TEST_F(NetworkStateNotifierTest, AddObserverWhileNotifying) {
  StateObserver observer1, observer2;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddConnectionObserver(&observer1, GetTaskRunner());
  observer1.AddObserverOnNotification(&notifier_, &observer2, GetTaskRunner());

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  RunPendingTasks();
  EXPECT_EQ(0, observer2.CallbackCount());
}

TEST_F(NetworkStateNotifierTest, RemoveSoleObserverWhileNotifying) {
  StateObserver observer1;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddConnectionObserver(&observer1, GetTaskRunner());
  observer1.RemoveObserverOnNotification(std::move(handle));

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));

  SetConnection(kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
}

TEST_F(NetworkStateNotifierTest, RemoveCurrentObserverWhileNotifying) {
  StateObserver observer1, observer2;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle1 =
      notifier_.AddConnectionObserver(&observer1, GetTaskRunner());
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle2 =
      notifier_.AddConnectionObserver(&observer2, GetTaskRunner());
  observer1.RemoveObserverOnNotification(std::move(handle1));

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(VerifyObservations(
      observer2, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));

  SetConnection(kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(VerifyObservations(
      observer2, kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
}

// It should be safe to remove multiple observers in one iteration.
TEST_F(NetworkStateNotifierTest, RemoveMultipleObserversWhileNotifying) {
  StateObserver observer1, observer2, observer3;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle1 =
      notifier_.AddConnectionObserver(&observer1, GetTaskRunner());
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle2 =
      notifier_.AddConnectionObserver(&observer2, GetTaskRunner());
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle3 =
      notifier_.AddConnectionObserver(&observer3, GetTaskRunner());
  observer1.RemoveObserverOnNotification(std::move(handle1));
  observer3.RemoveObserverOnNotification(std::move(handle3));

  // Running the first time should delete observers 1 and 3.
  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(VerifyObservations(
      observer2, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(VerifyObservations(
      observer3, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));

  // Run again and only observer 2 should have been updated.
  SetConnection(kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(VerifyObservations(
      observer2, kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(VerifyObservations(
      observer3, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
}

TEST_F(NetworkStateNotifierTest, MultipleContextsAddObserver) {
  StateObserver observer1, observer2;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle1 =
      notifier_.AddConnectionObserver(&observer1, GetTaskRunner());
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle2 =
      notifier_.AddConnectionObserver(&observer2, GetTaskRunner2());

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(VerifyObservations(
      observer2, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff));
}

TEST_F(NetworkStateNotifierTest, RemoveContext) {
  StateObserver observer1, observer2;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle1 =
      notifier_.AddConnectionObserver(&observer1, GetTaskRunner());
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle2 =
      notifier_.AddConnectionObserver(&observer2, GetTaskRunner2());
  handle2 = nullptr;

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
      kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(VerifyObservations(
      observer2, kWebConnectionTypeNone, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
}

TEST_F(NetworkStateNotifierTest, RemoveAllContexts) {
  StateObserver observer1, observer2;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle1 =
      notifier_.AddConnectionObserver(&observer1, GetTaskRunner());
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle2 =
      notifier_.AddConnectionObserver(&observer2, GetTaskRunner2());
  handle1 = nullptr;
  handle2 = nullptr;

  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kType3G, kEthernetHttpRtt,
                kEthernetTransportRtt, kEthernetThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer1, kWebConnectionTypeNone, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(VerifyObservations(
      observer2, kWebConnectionTypeNone, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
}

TEST_F(NetworkStateNotifierTest, SetNetworkConnectionInfoOverride) {
  StateObserver observer;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddConnectionObserver(&observer, GetTaskRunner());

  notifier_.SetOnLine(true);
  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeBluetooth, notifier_.ConnectionType());
  EXPECT_EQ(kBluetoothMaxBandwidthMbps, notifier_.MaxBandwidth());
  VerifyInitialMetricsWithWebHoldbackState(
      kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff);

  notifier_.SetNetworkConnectionInfoOverride(
      true, kWebConnectionTypeEthernet, WebEffectiveConnectionType::kType4G,
      kEthernetHttpRtt.value().InMilliseconds(), kEthernetMaxBandwidthMbps);
  RunPendingTasks();
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kType4G, kEthernetHttpRtt, kUnknownRtt,
      kEthernetMaxBandwidthMbps, SaveData::kOff));
  EXPECT_TRUE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeEthernet, notifier_.ConnectionType());
  EXPECT_EQ(kEthernetMaxBandwidthMbps, notifier_.MaxBandwidth());
  VerifyInitialMetricsWithWebHoldbackState(
      kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kType4G, kEthernetHttpRtt,
      kEthernetMaxBandwidthMbps, SaveData::kOff);

  // When override is active, calls to setOnLine and setConnection are temporary
  // ignored.
  notifier_.SetOnLine(false);
  SetConnection(kWebConnectionTypeNone, kNoneMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  RunPendingTasks();
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kType4G, kEthernetHttpRtt, kUnknownRtt,
      kEthernetMaxBandwidthMbps, SaveData::kOff));
  EXPECT_TRUE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeEthernet, notifier_.ConnectionType());
  EXPECT_EQ(kEthernetMaxBandwidthMbps, notifier_.MaxBandwidth());
  VerifyInitialMetricsWithWebHoldbackState(
      kWebConnectionTypeEthernet, kEthernetMaxBandwidthMbps,
      WebEffectiveConnectionType::kType4G, kEthernetHttpRtt,
      kEthernetMaxBandwidthMbps, SaveData::kOff);

  notifier_.ClearOverride();
  RunPendingTasks();
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeNone, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_FALSE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeNone, notifier_.ConnectionType());
  EXPECT_EQ(kNoneMaxBandwidthMbps, notifier_.MaxBandwidth());
  VerifyInitialMetricsWithWebHoldbackState(
      kWebConnectionTypeNone, kNoneMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff);
}

TEST_F(NetworkStateNotifierTest, SetNetworkQualityInfoOverride) {
  StateObserver observer;
  std::unique_ptr<NetworkStateNotifier::NetworkStateObserverHandle> handle =
      notifier_.AddConnectionObserver(&observer, GetTaskRunner());

  notifier_.SetOnLine(true);
  SetConnection(kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
                WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
                kUnknownRtt, kUnknownThroughputMbps, SaveData::kOff);
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeBluetooth, notifier_.ConnectionType());
  EXPECT_EQ(kBluetoothMaxBandwidthMbps, notifier_.MaxBandwidth());
  VerifyInitialMetricsWithWebHoldbackState(
      kWebConnectionTypeBluetooth, kBluetoothMaxBandwidthMbps,
      WebEffectiveConnectionType::kTypeUnknown, kUnknownRtt,
      kUnknownThroughputMbps, SaveData::kOff);

  notifier_.SetNetworkConnectionInfoOverride(
      true, kWebConnectionTypeOther, WebEffectiveConnectionType::kType3G,
      kEthernetHttpRtt.value().InMilliseconds(),
      kEthernetThroughputMbps.value());
  RunPendingTasks();
  EXPECT_TRUE(VerifyObservations(
      observer, kWebConnectionTypeOther, kEthernetThroughputMbps.value(),
      WebEffectiveConnectionType::kType3G, kEthernetHttpRtt, kUnknownRtt,
      kEthernetThroughputMbps, SaveData::kOff));
  EXPECT_TRUE(notifier_.OnLine());
  EXPECT_EQ(kWebConnectionTypeOther, notifier_.ConnectionType());
  EXPECT_EQ(kEthernetThroughputMbps, notifier_.MaxBandwidth());
  EXPECT_EQ(WebEffectiveConnectionType::kTy
"""


```