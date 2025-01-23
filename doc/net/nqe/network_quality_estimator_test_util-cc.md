Response:
Let's break down the thought process for analyzing this C++ test utility file.

**1. Initial Skim and Keyword Recognition:**

The first step is to quickly scan the code and identify key terms and patterns. I see:

* `TestNetworkQualityEstimator`: This immediately suggests this is a testing class, likely for the `NetworkQualityEstimator`.
* `#include ...`:  Lots of standard Chromium networking headers (`net/...`). This confirms it's part of the network stack.
* `embedded_test_server`:  This indicates the class sets up a local HTTP server for testing.
* `RunOneRequest`, `SimulateNetworkChange`: These are methods that clearly simulate network events for testing purposes.
* `GetEffectiveConnectionType`, `GetRecentRTT`, `GetRecentDownlinkThroughputKbps`: These are methods related to retrieving network quality metrics.
* `NetLog`:  Indicates interaction with the Chromium Network Logging system.
* `NotifyObservers...`: Suggests the class interacts with an observer pattern, likely to notify other components of changes in network quality.
* `Set...`: Methods that allow setting specific values for testing, overriding the real network conditions.

**2. Deeper Dive into Class Structure and Purpose:**

Now, let's analyze the `TestNetworkQualityEstimator` class itself.

* **Constructors:**  Multiple constructors allow for different initialization scenarios, particularly for setting variation parameters. The parameters likely influence the behavior of the network quality estimation logic.
* **Private Members:** The `embedded_test_server_`, `current_network_type_`, `current_network_id_`, and the various `std::optional` members (like `effective_connection_type_`, `recent_http_rtt_`, etc.) are used to control the testing environment and simulate different network conditions. The `net_log_observer_` is crucial for verifying log output.
* **Public Methods:** These are the methods that the test code will interact with. They provide the core functionality for setting up test scenarios and retrieving results.

**3. Function-by-Function Analysis (Mental or Written Notes):**

Go through each public method and understand its purpose:

* `RunOneRequest()`: Sends a single request to the embedded server. Essential for testing the basic functionality.
* `SimulateNetworkChange()`:  Directly manipulates the simulated network connection type and ID. Key for testing how the estimator reacts to network changes.
* `GetEchoURL()`, `GetRedirectURL()`: Convenience methods for getting URLs from the test server.
* `GetEffectiveConnectionType()`:  Retrieves the currently estimated effective connection type. The `std::optional` return type suggests it might not always have a value. The override logic with `effective_connection_type_` is important for testing.
* `GetRecentEffectiveConnectionTypeUsingMetrics()`:  Similar to the above but also retrieves the underlying metrics used for the calculation. The override logic with `recent_effective_connection_type_` is important.
* `GetRecentRTT()`, `GetRecentDownlinkThroughputKbps()`:  Methods to retrieve specific recent network metrics. The logic with `start_time.is_null()` and the use of the `std::optional` members indicate the ability to provide specific test values.
* `GetRTTEstimateInternal()`:  Retrieves an internal RTT estimate. Likely for more granular testing.
* `GetEntriesCount()`, `GetNetLogLastStringValue()`, `GetNetLogLastIntegerValue()`:  Methods for inspecting the NetLog. Crucial for verifying the internal workings of the estimator and its logging behavior.
* `NotifyObserversOf...()` and `SetAndNotifyObserversOf...()`: Methods for interacting with observers. Important for testing how the estimator communicates changes to other components.
* `GetOverrideECT()`:  Allows retrieving the overridden effective connection type, useful for verification.
* `RecordSpdyPingLatency()`:  Simulates receiving a SPDY ping.
* `params()`: Returns the configuration parameters.
* `GetCurrentNetworkID()`:  Gets the simulated network ID.
* `LocalHttpTestServer`: A nested class to manage the embedded HTTP server.
* `NotifyObserversOfRTTOrThroughputComputed()`, `NotifyRTTAndThroughputEstimatesObserverIfPresent()`:  Methods to trigger observer notifications, with logic to suppress notifications during testing.
* `SetStartTimeNullHttpRtt()`, `SetStartTimeNullTransportRtt()`: Methods to set specific RTT values, forcing a recalculation of the effective connection type. This is very useful for targeted testing of the ECT logic.

**4. Identifying JavaScript Relevance:**

Now, think about how this C++ code relates to JavaScript in a browser context.

* **`EffectiveConnectionType` API:**  JavaScript in a browser has access to the `navigator.connection.effectiveType` API. This C++ code is *implementing* the logic behind that API. Therefore, manipulating the `TestNetworkQualityEstimator` directly affects what the JavaScript API would report in a real browser environment.
* **Network Performance Measurement:**  JavaScript performance APIs and tools often rely on underlying network metrics. The data collected and estimated by this C++ code forms the basis for some of those measurements.
* **Resource Loading Optimization:**  Browsers use network quality information to make decisions about resource loading, such as choosing lower-quality images or delaying non-critical requests. The logic tested here directly influences those optimizations.

**5. Crafting Examples and Explanations:**

Based on the analysis, construct concrete examples:

* **JavaScript API Relationship:** Demonstrate how setting a specific ECT in the C++ test affects the JavaScript API.
* **Logic Reasoning:** Provide a simple scenario with inputs (simulated RTT) and expected outputs (ECT).
* **Common Usage Errors:** Think about how a developer using this test utility might misuse it. For instance, forgetting to start the embedded server.
* **Debugging Scenario:**  Trace a user action that could lead to this code being involved, emphasizing the role of network quality estimation.

**6. Refinement and Organization:**

Finally, structure the information clearly and concisely. Use headings, bullet points, and code formatting to enhance readability. Ensure that all the requested aspects of the prompt are addressed. Double-check for accuracy and clarity.

This iterative process of skimming, deep diving, analyzing individual components, connecting to higher-level concepts (like JavaScript APIs), and crafting examples allows for a comprehensive understanding of the provided code and its role within the larger Chromium project.
这个文件 `net/nqe/network_quality_estimator_test_util.cc` 是 Chromium 网络栈中用于测试 `NetworkQualityEstimator` 组件的工具类。它提供了一系列方法来模拟和控制网络环境，以便更方便地测试网络质量估计器的功能。

以下是它的主要功能：

**1. 提供一个可控的 `NetworkQualityEstimator` 实例 (`TestNetworkQualityEstimator`)：**

   - 该类继承自 `NetworkQualityEstimator`，允许在测试环境中创建一个可操控的网络质量估计器实例。
   - 构造函数允许指定不同的变体参数 (`variation_params`)，模拟不同的实验配置。
   - 可以控制是否允许本地主机请求和更小的响应体，方便测试不同场景。
   - 可以抑制通知，避免测试过程中不必要的副作用。

**2. 模拟网络请求：**

   - `RunOneRequest()` 方法可以发送一个简单的 HTTP 请求到内嵌的测试服务器，用于触发网络质量估计器的相关逻辑。
   - 使用 `embedded_test_server_` 提供一个本地 HTTP 服务器，避免依赖外部网络环境。

**3. 模拟网络连接变化：**

   - `SimulateNetworkChange()` 方法可以模拟网络连接类型的变化 (例如从 WiFi 切换到 Cellular)，以及网络 ID 的变化，用于测试网络质量估计器对网络状态变化的响应。

**4. 提供测试用的 URLs：**

   - `GetEchoURL()` 和 `GetRedirectURL()` 方法返回内嵌测试服务器提供的特定 URLs，方便进行请求测试。

**5. 重写和控制网络质量估计器的行为和返回值：**

   - 可以通过 `effective_connection_type_`、`recent_http_rtt_`、`recent_transport_rtt_`、`recent_downlink_throughput_kbps_` 等成员变量来设置特定的网络质量指标，从而模拟特定的网络状况。
   - 重写了 `GetEffectiveConnectionType()`, `GetRecentEffectiveConnectionTypeUsingMetrics()`, `GetRecentRTT()`, `GetRecentDownlinkThroughputKbps()`, `GetRTTEstimateInternal()` 等方法，使其在测试时可以返回预设的值，而不是实时的网络测量值。
   - `SetStartTimeNullHttpRtt()` 和 `SetStartTimeNullTransportRtt()` 可以设置特定时间点的 RTT 值，强制重新计算有效连接类型。

**6. 检查网络日志 (NetLog)：**

   - 提供了 `GetEntriesCount()`, `GetNetLogLastStringValue()`, `GetNetLogLastIntegerValue()` 等方法来检查 `NetworkQualityEstimator` 在运行过程中产生的 NetLog 事件，用于验证其内部行为。

**7. 通知观察者：**

   - 提供了 `NotifyObserversOfRTTOrThroughputEstimatesComputed()` 和 `SetAndNotifyObserversOfEffectiveConnectionType()` 等方法，允许测试代码手动触发观察者的通知，或者设置并通知有效连接类型的变化。

**8. 模拟 P2P 连接数变化：**

   - `SetAndNotifyObserversOfP2PActiveConnectionsCountChange()` 方法可以模拟 P2P 连接数的改变，用于测试 `NetworkQualityEstimator` 对 P2P 流量的考虑。

**9. 记录 SPDY Ping 延迟：**

   - `RecordSpdyPingLatency()` 方法用于模拟接收到 SPDY Ping 消息，用于测试 RTT 估计的逻辑。

**与 JavaScript 功能的关系：**

这个 C++ 文件直接关系到浏览器中 JavaScript 可以访问的网络性能相关的 API。具体来说：

* **`navigator.connection.effectiveType` API:**  这个 JavaScript API 允许网页获取当前网络的有效连接类型 (Effective Connection Type, ECT)，例如 "slow-2g", "2g", "3g", "4g", "5g", "offline"。`TestNetworkQualityEstimator` 可以用来测试 Chromium 如何计算和更新这个值。通过 `SetAndNotifyObserversOfEffectiveConnectionType()` 方法，可以模拟 ECT 的变化，这会直接影响到 JavaScript 中 `navigator.connection.effectiveType` 的值。

   **举例说明：**

   假设我们有一个 JavaScript 代码：

   ```javascript
   if (navigator.connection) {
     navigator.connection.addEventListener('change', () => {
       console.log('Effective Connection Type changed to:', navigator.connection.effectiveType);
     });
     console.log('Initial Effective Connection Type:', navigator.connection.effectiveType);
   }
   ```

   在 C++ 测试中，我们可以使用 `TestNetworkQualityEstimator` 来模拟 ECT 的变化：

   ```c++
   TestNetworkQualityEstimator estimator;
   estimator.SetAndNotifyObserversOfEffectiveConnectionType(EFFECTIVE_CONNECTION_TYPE_4G);
   // ... 稍后 ...
   estimator.SetAndNotifyObserversOfEffectiveConnectionType(EFFECTIVE_CONNECTION_TYPE_3G);
   ```

   这将导致 JavaScript 代码中的 `change` 事件被触发，并在控制台中打印出 ECT 的变化。

* **网络性能测量 API (Performance APIs):**  JavaScript 的 Performance APIs (例如 `PerformanceNavigationTiming`, `PerformanceResourceTiming`) 可以提供关于网络请求的详细信息，包括连接时间、TTFB (Time To First Byte) 等。`TestNetworkQualityEstimator` 通过模拟网络请求和控制 RTT 等指标，可以用来测试这些 API 提供的数据的准确性，以及浏览器如何利用这些数据进行性能优化。

**逻辑推理的假设输入与输出：**

假设我们使用 `TestNetworkQualityEstimator` 来测试 ECT 的计算逻辑。

**假设输入：**

1. **设置 HTTP RTT：** 使用 `SetStartTimeNullHttpRtt(base::TimeDelta::FromMilliseconds(100));`  设置 HTTP RTT 为 100 毫秒。
2. **设置传输层 RTT：** 使用 `SetStartTimeNullTransportRtt(base::TimeDelta::FromMilliseconds(50));` 设置传输层 RTT 为 50 毫秒。

**假设输出：**

调用 `GetEffectiveConnectionType()` 应该返回一个与这些 RTT 值对应的 ECT。根据 Chromium 的 ECT 计算逻辑，较低的 RTT 通常会对应更好的连接类型。例如，如果阈值设定合理，可能返回 `EFFECTIVE_CONNECTION_TYPE_4G` 或 `EFFECTIVE_CONNECTION_TYPE_3G`。具体的值取决于 Chromium 内部的阈值设置。

**涉及用户或编程常见的使用错误：**

1. **忘记启动内嵌测试服务器：**  在调用 `RunOneRequest()` 之前，如果忘记启动 `embedded_test_server_`，测试将会失败。虽然代码中做了检查，但手动管理服务器状态仍然容易出错。
2. **假设特定的 ECT 值而不考虑阈值：**  在测试 ECT 相关功能时，如果直接假设某个 RTT 值会对应特定的 ECT，而没有考虑 Chromium 内部的阈值配置，可能会导致断言失败。需要仔细查看 Chromium 中 ECT 的阈值定义。
3. **没有正确模拟网络变化的时序：**  在测试网络切换场景时，如果模拟 `SimulateNetworkChange()` 的时序不正确，可能会导致网络质量估计器没有按照预期更新状态。
4. **过度依赖模拟值而忽略实际网络行为：** 虽然 `TestNetworkQualityEstimator` 提供了方便的模拟功能，但过度依赖模拟值可能会忽略在真实网络环境下可能出现的问题。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在浏览器中遇到了网页加载缓慢的问题，或者某些依赖网络质量的功能表现异常，开发者可能会进行以下调试步骤，最终涉及到这个测试工具文件：

1. **复现问题：**  开发者首先需要在本地或者测试环境中复现用户遇到的问题。
2. **开启 NetLog 记录：**  为了分析网络请求的详细信息，开发者会开启 Chromium 的 NetLog 功能 (通过 `chrome://net-export/`) 来记录网络事件。
3. **分析 NetLog：**  查看 NetLog 中关于连接建立、请求发送、响应接收等各个阶段的时间，可能会发现 RTT 过高、吞吐量过低等异常情况。
4. **怀疑网络质量估计器的问题：**  如果 NetLog 显示网络连接本身没有明显问题，但浏览器行为仍然不符合预期（例如，仍然加载低质量的图片），开发者可能会怀疑是网络质量估计器给出了错误的评估。
5. **查看网络质量估计器的内部状态：**  开发者可能会尝试查看 Chromium 内部的网络质量估计器的状态，但这通常需要修改 Chromium 源码或者使用内部调试工具。
6. **运行相关的单元测试：**  为了验证网络质量估计器的逻辑是否正确，开发者会查看和运行与 `NetworkQualityEstimator` 相关的单元测试，其中就包括 `network_quality_estimator_test_util.cc` 中定义的测试。
7. **使用 `TestNetworkQualityEstimator` 进行特定场景的测试：**  开发者可能会编写新的测试用例，使用 `TestNetworkQualityEstimator` 来模拟用户遇到的特定网络环境（例如，高延迟、低带宽），并检查 `NetworkQualityEstimator` 的行为是否符合预期，以及其输出的 ECT 等指标是否正确。
8. **调试 `NetworkQualityEstimator` 的源码：**  如果单元测试失败或者仍然怀疑 `NetworkQualityEstimator` 的实现有问题，开发者可能会深入到 `net/nqe/network_quality_estimator.cc` 等源文件中进行代码级别的调试，而 `network_quality_estimator_test_util.cc` 提供的工具可以帮助他们创建各种测试场景来验证修复。

总而言之，`network_quality_estimator_test_util.cc` 提供了一种受控的环境来测试 Chromium 网络栈中负责估计网络质量的关键组件，对于保证网络相关功能的正确性和性能至关重要。它与 JavaScript 的网络性能 API 有着直接的联系，因为它的测试目标就是为这些 API 提供底层数据支持。

### 提示词
```
这是目录为net/nqe/network_quality_estimator_test_util.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/nqe/network_quality_estimator_test_util.h"

#include "base/files/file_path.h"
#include "base/run_loop.h"
#include "net/base/load_flags.h"
#include "net/log/net_log.h"
#include "net/log/net_log_with_source.h"
#include "net/log/test_net_log_util.h"
#include "net/nqe/network_quality_estimator_params.h"
#include "net/test/embedded_test_server/http_response.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"

namespace {

const base::FilePath::CharType kTestFilePath[] =
    FILE_PATH_LITERAL("net/data/url_request_unittest");

}  // namespace

namespace net {

TestNetworkQualityEstimator::TestNetworkQualityEstimator()
    : TestNetworkQualityEstimator(std::map<std::string, std::string>()) {}

TestNetworkQualityEstimator::TestNetworkQualityEstimator(
    const std::map<std::string, std::string>& variation_params)
    : TestNetworkQualityEstimator(variation_params, true, true) {}

TestNetworkQualityEstimator::TestNetworkQualityEstimator(
    const std::map<std::string, std::string>& variation_params,
    bool allow_local_host_requests_for_tests,
    bool allow_smaller_responses_for_tests)
    : TestNetworkQualityEstimator(variation_params,
                                  allow_local_host_requests_for_tests,
                                  allow_smaller_responses_for_tests,
                                  false) {}

TestNetworkQualityEstimator::TestNetworkQualityEstimator(
    const std::map<std::string, std::string>& variation_params,
    bool allow_local_host_requests_for_tests,
    bool allow_smaller_responses_for_tests,
    bool suppress_notifications_for_testing)
    : NetworkQualityEstimator(
          std::make_unique<NetworkQualityEstimatorParams>(variation_params),
          NetLog::Get()),
      suppress_notifications_for_testing_(suppress_notifications_for_testing),
      embedded_test_server_(base::FilePath(kTestFilePath)) {
  SetUseLocalHostRequestsForTesting(allow_local_host_requests_for_tests);
  SetUseSmallResponsesForTesting(allow_smaller_responses_for_tests);
}

TestNetworkQualityEstimator::TestNetworkQualityEstimator(
    std::unique_ptr<NetworkQualityEstimatorParams> params)
    : NetworkQualityEstimator(std::move(params), NetLog::Get()),
      suppress_notifications_for_testing_(false),
      embedded_test_server_(base::FilePath(kTestFilePath)) {}

TestNetworkQualityEstimator::~TestNetworkQualityEstimator() = default;

void TestNetworkQualityEstimator::RunOneRequest() {
  // Set up the embedded test server.
  if (!embedded_test_server_.Started()) {
    EXPECT_TRUE(embedded_test_server_.Start());
  }

  TestDelegate test_delegate;
  auto builder = CreateTestURLRequestContextBuilder();
  builder->set_network_quality_estimator(this);
  auto context = builder->Build();
  std::unique_ptr<URLRequest> request(
      context->CreateRequest(GetEchoURL(), DEFAULT_PRIORITY, &test_delegate,
                             TRAFFIC_ANNOTATION_FOR_TESTS));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request->Start();
  test_delegate.RunUntilComplete();
}

void TestNetworkQualityEstimator::SimulateNetworkChange(
    NetworkChangeNotifier::ConnectionType new_connection_type,
    const std::string& network_id) {
  current_network_type_ = new_connection_type;
  current_network_id_ = network_id;
  OnConnectionTypeChanged(new_connection_type);
}

const GURL TestNetworkQualityEstimator::GetEchoURL() {
  // Set up the embedded test server.
  if (!embedded_test_server_.Started()) {
    EXPECT_TRUE(embedded_test_server_.Start());
  }
  return embedded_test_server_.GetURL("/simple.html");
}

const GURL TestNetworkQualityEstimator::GetRedirectURL() {
  // Set up the embedded test server.
  if (!embedded_test_server_.Started()) {
    EXPECT_TRUE(embedded_test_server_.Start());
  }
  return embedded_test_server_.GetURL("/redirect302-to-https");
}

EffectiveConnectionType
TestNetworkQualityEstimator::GetEffectiveConnectionType() const {
  if (effective_connection_type_)
    return effective_connection_type_.value();
  return NetworkQualityEstimator::GetEffectiveConnectionType();
}

EffectiveConnectionType
TestNetworkQualityEstimator::GetRecentEffectiveConnectionTypeUsingMetrics(
    base::TimeDelta* http_rtt,
    base::TimeDelta* transport_rtt,
    base::TimeDelta* end_to_end_rtt,
    int32_t* downstream_throughput_kbps,
    size_t* observations_count,
    size_t* end_to_end_rtt_observation_count) const {
  if (recent_effective_connection_type_) {
    GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP, base::TimeTicks(),
                 http_rtt, nullptr);
    GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                 base::TimeTicks(), transport_rtt, observations_count);
    GetRecentDownlinkThroughputKbps(base::TimeTicks(),
                                    downstream_throughput_kbps);
    return recent_effective_connection_type_.value();
  }
  return NetworkQualityEstimator::GetRecentEffectiveConnectionTypeUsingMetrics(
      http_rtt, transport_rtt, end_to_end_rtt, downstream_throughput_kbps,
      observations_count, end_to_end_rtt_observation_count);
}

bool TestNetworkQualityEstimator::GetRecentRTT(
    nqe::internal::ObservationCategory observation_category,
    const base::TimeTicks& start_time,
    base::TimeDelta* rtt,
    size_t* observations_count) const {
  switch (observation_category) {
    case nqe::internal::OBSERVATION_CATEGORY_HTTP:

      if (start_time.is_null()) {
        if (start_time_null_http_rtt_) {
          *rtt = start_time_null_http_rtt_.value();
          return true;
        }
        return NetworkQualityEstimator::GetRecentRTT(
            observation_category, start_time, rtt, observations_count);
      }
      if (recent_http_rtt_) {
        *rtt = recent_http_rtt_.value();
        return true;
      }
      break;

    case nqe::internal::OBSERVATION_CATEGORY_TRANSPORT:
      if (start_time.is_null()) {
        if (start_time_null_transport_rtt_) {
          *rtt = start_time_null_transport_rtt_.value();
          if (transport_rtt_observation_count_last_ect_computation_) {
            *observations_count =
                transport_rtt_observation_count_last_ect_computation_.value();
          }
          return true;
        }
        return NetworkQualityEstimator::GetRecentRTT(
            observation_category, start_time, rtt, observations_count);
      }

      if (recent_transport_rtt_) {
        *rtt = recent_transport_rtt_.value();
        return true;
      }
      break;
    case nqe::internal::OBSERVATION_CATEGORY_END_TO_END:
      if (start_time_null_end_to_end_rtt_) {
        *rtt = start_time_null_end_to_end_rtt_.value();
        return true;
      }
      break;
    case nqe::internal::OBSERVATION_CATEGORY_COUNT:
      NOTREACHED();
  }

  return NetworkQualityEstimator::GetRecentRTT(observation_category, start_time,
                                               rtt, observations_count);
}

std::optional<base::TimeDelta> TestNetworkQualityEstimator::GetTransportRTT()
    const {
  if (start_time_null_transport_rtt_)
    return start_time_null_transport_rtt_;
  return NetworkQualityEstimator::GetTransportRTT();
}

bool TestNetworkQualityEstimator::GetRecentDownlinkThroughputKbps(
    const base::TimeTicks& start_time,
    int32_t* kbps) const {
  if (start_time.is_null()) {
    if (start_time_null_downlink_throughput_kbps_) {
      *kbps = start_time_null_downlink_throughput_kbps_.value();
      return true;
    }
    return NetworkQualityEstimator::GetRecentDownlinkThroughputKbps(start_time,
                                                                    kbps);
  }

  if (recent_downlink_throughput_kbps_) {
    *kbps = recent_downlink_throughput_kbps_.value();
    return true;
  }
  return NetworkQualityEstimator::GetRecentDownlinkThroughputKbps(start_time,
                                                                  kbps);
}

base::TimeDelta TestNetworkQualityEstimator::GetRTTEstimateInternal(
    base::TimeTicks start_time,
    nqe::internal::ObservationCategory observation_category,
    int percentile,
    size_t* observations_count) const {
  if (rtt_estimate_internal_)
    return rtt_estimate_internal_.value();

  return NetworkQualityEstimator::GetRTTEstimateInternal(
      start_time, observation_category, percentile, observations_count);
}

int TestNetworkQualityEstimator::GetEntriesCount(NetLogEventType type) const {
  return net_log_observer_.GetEntriesWithType(type).size();
}

std::string TestNetworkQualityEstimator::GetNetLogLastStringValue(
    NetLogEventType type,
    const std::string& key) const {
  auto entries = net_log_observer_.GetEntries();

  for (int i = entries.size() - 1; i >= 0; --i) {
    if (entries[i].type == type) {
      auto value = GetOptionalStringValueFromParams(entries[i], key);
      if (value)
        return *value;
    }
  }
  return std::string();
}

int TestNetworkQualityEstimator::GetNetLogLastIntegerValue(
    NetLogEventType type,
    const std::string& key) const {
  auto entries = net_log_observer_.GetEntries();

  for (int i = entries.size() - 1; i >= 0; --i) {
    if (entries[i].type == type) {
      auto value = GetOptionalIntegerValueFromParams(entries[i], key);
      if (value)
        return *value;
    }
  }
  return 0;
}

void TestNetworkQualityEstimator::
    NotifyObserversOfRTTOrThroughputEstimatesComputed(
        const net::nqe::internal::NetworkQuality& network_quality) {
  for (auto& observer : rtt_and_throughput_estimates_observer_list_) {
    observer.OnRTTOrThroughputEstimatesComputed(
        network_quality.http_rtt(), network_quality.transport_rtt(),
        network_quality.downstream_throughput_kbps());
  }
}

void TestNetworkQualityEstimator::
    SetAndNotifyObserversOfEffectiveConnectionType(
        EffectiveConnectionType type) {
  set_effective_connection_type(type);
  for (auto& observer : effective_connection_type_observer_list_)
    observer.OnEffectiveConnectionTypeChanged(type);
}

std::optional<net::EffectiveConnectionType>
TestNetworkQualityEstimator::GetOverrideECT() const {
  return effective_connection_type_;
}

void TestNetworkQualityEstimator::
    SetAndNotifyObserversOfP2PActiveConnectionsCountChange(uint32_t count) {
  p2p_connections_count_ = count;
  for (auto& observer : peer_to_peer_type_observer_list_)
    observer.OnPeerToPeerConnectionsCountChange(count);
}

void TestNetworkQualityEstimator::RecordSpdyPingLatency(
    const HostPortPair& host_port_pair,
    base::TimeDelta rtt) {
  ++ping_rtt_received_count_;
  NetworkQualityEstimator::RecordSpdyPingLatency(host_port_pair, rtt);
}

const NetworkQualityEstimatorParams* TestNetworkQualityEstimator::params()
    const {
  return params_.get();
}

nqe::internal::NetworkID TestNetworkQualityEstimator::GetCurrentNetworkID()
    const {
  return nqe::internal::NetworkID(current_network_type_, current_network_id_,
                                  INT32_MIN);
}

TestNetworkQualityEstimator::LocalHttpTestServer::LocalHttpTestServer(
    const base::FilePath& document_root) {
  AddDefaultHandlers(document_root);
}

void TestNetworkQualityEstimator::NotifyObserversOfRTTOrThroughputComputed()
    const {
  if (suppress_notifications_for_testing_)
    return;

  NetworkQualityEstimator::NotifyObserversOfRTTOrThroughputComputed();
}

void TestNetworkQualityEstimator::
    NotifyRTTAndThroughputEstimatesObserverIfPresent(
        RTTAndThroughputEstimatesObserver* observer) const {
  if (suppress_notifications_for_testing_)
    return;

  NetworkQualityEstimator::NotifyRTTAndThroughputEstimatesObserverIfPresent(
      observer);
}

void TestNetworkQualityEstimator::SetStartTimeNullHttpRtt(
    const base::TimeDelta http_rtt) {
  start_time_null_http_rtt_ = http_rtt;
  // Force compute effective connection type so that the new RTT value is
  // immediately picked up. This ensures that the next call to
  // GetEffectiveConnectionType() returns the effective connnection type
  // that was computed based on |http_rtt|.
  ComputeEffectiveConnectionType();
}

void TestNetworkQualityEstimator::SetStartTimeNullTransportRtt(
    const base::TimeDelta transport_rtt) {
  start_time_null_transport_rtt_ = transport_rtt;
  // Force compute effective connection type so that the new RTT value is
  // immediately picked up. This ensures that the next call to
  // GetEffectiveConnectionType() returns the effective connnection type
  // that was computed based on |transport_rtt|.
  ComputeEffectiveConnectionType();
}

}  // namespace net
```