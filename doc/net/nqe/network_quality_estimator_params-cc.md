Response:
Let's break down the thought process for analyzing this C++ code and answering the user's request.

**1. Understanding the Request:**

The user wants to understand the functionality of the `network_quality_estimator_params.cc` file within the Chromium networking stack. They are specifically interested in:

* **Functionality:** What does this code *do*?
* **JavaScript Relation:** Is there any interaction with JavaScript?
* **Logical Inference:** Are there parameter-based logic flows where I can provide hypothetical inputs and outputs?
* **Usage Errors:** What are common mistakes when using or configuring this?
* **Debugging:** How does a user's interaction lead to this code being executed?

**2. Initial Code Scan - Identifying Key Areas:**

I start by quickly reading through the code, looking for recognizable patterns and keywords:

* **Headers:**  `#include` directives indicate dependencies. `base/strings/string_number_conversions.h`, `base/time/time.h`, and `net/base/features.h` suggest string/number parsing, time management, and feature flags.
* **Namespaces:** The code is within the `net` namespace, further narrowing its scope.
* **Constants:**  `kForceEffectiveConnectionType`, `kEffectiveConnectionTypeSlow2GOnCellular`, `kHttpRttEffectiveConnectionTypeThresholds` are important configuration strings and data structures.
* **Helper Functions:**  Functions like `GetValueForVariationParam`, `GetDoubleValueForVariationParamWithDefaultValue`, `GetStringValueForVariationParamWithDefaultValue` strongly suggest this file is about managing configuration parameters.
* **"Default" and "Typical" Values:** The code has sections for `ObtainDefaultObservations` and `ObtainTypicalNetworkQualities`. This hints at setting baseline values for network quality under different conditions.
* **Effective Connection Type (ECT):**  The repeated mentions of `EffectiveConnectionType` and related functions (`DeprecatedGetNameForEffectiveConnectionType`, `GetEffectiveConnectionTypeForName`) are central to the file's purpose.
* **`NetworkQualityEstimatorParams` Class:** This is the core class, and its constructor takes a `std::map<std::string, std::string>& params`, further reinforcing the idea of parameter-driven configuration.
* **Feature Flags:** The use of `features::kCountNewObservationsReceivedComputeEct.Get()` and `features::kObservationBufferSize.Get()` indicates integration with Chromium's feature flag system.

**3. Deeper Dive - Understanding the Functionality:**

Now, I focus on understanding *what* these different parts do and how they relate:

* **Configuration Management:** The core function is to manage parameters that influence how the network quality is estimated. These parameters come from various sources (like variations/feature flags).
* **Effective Connection Type (ECT) Logic:** A significant portion deals with determining the ECT (Slow 2G, 2G, 3G, 4G, etc.). This involves thresholds (like `kHttpRttEffectiveConnectionTypeThresholds`) and mechanisms to force or influence the ECT.
* **Default and Typical Values:**  The `ObtainDefaultObservations` function sets initial network quality estimates based on connection type (WiFi, Cellular, etc.). `ObtainTypicalNetworkQualities` does something similar, but for *effective* connection types, which are more abstract categories of network quality.
* **Time-Weighted Calculations:** The `GetWeightMultiplierPerSecond` function suggests that historical data is weighted, giving more importance to recent measurements.
* **Debugging/Testing Support:** The `SetForcedEffectiveConnectionTypeForTesting` and `use_small_responses` functions clearly indicate support for testing and debugging scenarios.

**4. Connecting to JavaScript (and Why It's Indirect):**

I consider where this code fits in the larger Chromium picture. This C++ code runs in the browser's network process. JavaScript in web pages doesn't directly interact with this C++ code. The connection is *indirect*:

* **Network API Usage:**  JavaScript uses browser APIs (like `navigator.connection.effectiveType`) to *get* network information.
* **Underlying C++ Implementation:** The C++ networking stack, including this `network_quality_estimator_params.cc` file, *powers* those APIs. The logic in this file influences the values returned by those JavaScript APIs.
* **Configuration via Finch/Variations:** Chromium's Finch system (for A/B testing and feature rollout) can set these parameters, affecting the network quality estimation and, consequently, what JavaScript sees.

**5. Logical Inference (Hypothetical Inputs and Outputs):**

With the understanding of parameters, I can start creating hypothetical scenarios:

* **Scenario: Forcing ECT:** If the `kForceEffectiveConnectionType` parameter is set to "2G", the code will enforce that ECT, regardless of actual network conditions (useful for testing).
* **Scenario: Adjusting Thresholds:** If the `WiFi.DefaultMedianRTTMsec` parameter is changed, the default RTT for WiFi connections will be altered. This would impact the initial network quality estimate for WiFi.

**6. Identifying Usage Errors:**

I think about common mistakes a *developer* or someone configuring Chromium might make:

* **Incorrect Parameter Names:** Typographical errors in parameter names in Finch configurations would lead to the default values being used.
* **Invalid Parameter Values:**  Setting non-numeric values for parameters expecting numbers could cause parsing errors or the use of default values.
* **Conflicting Parameters:**  Setting parameters that contradict each other might lead to unexpected behavior (though the code tries to provide defaults).

**7. Tracing User Actions (Debugging Clues):**

I consider how a user's actions might lead to this code being executed:

* **Page Load:**  When a user loads a webpage, the browser needs to estimate network quality to make decisions about resource loading, etc.
* **Network Changes:** When the network connection changes (e.g., switching from WiFi to cellular), this code is likely involved in re-evaluating the network quality.
* **Feature Flag Configurations:** If a user is part of a Finch experiment that modifies network quality estimation parameters, those settings would be loaded and used by this code.

**8. Structuring the Answer:**

Finally, I organize the information into a clear and structured format, addressing each part of the user's request with explanations, examples, and code references. I use headings and bullet points for readability. I pay attention to being precise about the indirect relationship with JavaScript.

This step-by-step process, combining code reading, pattern recognition, understanding the broader context, and logical deduction, helps in thoroughly analyzing the provided C++ source file and answering the user's questions effectively.
这个文件 `net/nqe/network_quality_estimator_params.cc` 是 Chromium 网络栈中 **网络质量评估器 (Network Quality Estimator, NQE)** 的参数配置文件。它定义了 NQE 使用的各种参数，这些参数控制着网络质量的评估方式和行为。

以下是它的主要功能：

**1. 定义和管理 NQE 的配置参数：**

* **默认值：**  为各种 NQE 相关的参数设置默认值。这些默认值在没有通过其他方式（例如实验配置、命令行标志）覆盖时使用。
* **实验配置：**  允许通过实验框架（如 Finch）配置 NQE 的行为。代码中使用了 `std::map<std::string, std::string>& params` 来接收这些配置参数。
* **不同网络类型的参数：**  针对不同的网络连接类型（例如，WiFi、2G、3G、4G）定义特定的参数，例如默认的 RTT (Round-Trip Time) 和吞吐量。
* **有效连接类型 (Effective Connection Type, ECT) 的阈值和典型值：**  定义了不同 ECT 等级的阈值（例如，HTTP RTT 阈值）和典型网络质量（例如，典型 RTT 和吞吐量）。

**2. 提供访问 NQE 参数的接口：**

*  `NetworkQualityEstimatorParams` 类是参数的容器，提供了获取各种参数值的成员函数。例如，`throughput_min_requests_in_flight()` 返回计算吞吐量所需的最小并发请求数。
*  提供静态方法来获取某些默认值，例如 `GetDefaultTypicalHttpRtt()` 和 `GetDefaultTypicalDownlinkKbps()`。

**3. 支持测试和调试：**

*  `SetForcedEffectiveConnectionTypeForTesting()` 允许在测试环境中强制设置特定的有效连接类型，以便进行可控的测试。
*  `use_small_responses_` 和 `SetUseSmallResponsesForTesting()` 看起来是为特定类型的测试设计的，可能用于模拟小响应场景。

**与 JavaScript 的关系（间接）：**

该 C++ 文件本身不包含任何 JavaScript 代码，因此没有直接的 JavaScript 功能。但是，它通过影响 Chromium 的网络行为，间接地与 JavaScript 功能相关联。

**举例说明：**

* **`navigator.connection.effectiveType` API:**  JavaScript 可以通过 `navigator.connection.effectiveType` API 获取浏览器估计的当前网络连接质量（例如 "slow-2g", "2g", "3g", "4g"）。`NetworkQualityEstimatorParams` 中定义的阈值（例如 `kHttpRttEffectiveConnectionTypeThresholds`）直接影响 NQE 如何判断当前的有效连接类型，从而影响 `navigator.connection.effectiveType` 返回的值。

   **例子：** 假设 `kHttpRttEffectiveConnectionTypeThresholds[EFFECTIVE_CONNECTION_TYPE_3G]` 被设置为 272 毫秒。当 NQE 观察到 HTTP RTT 接近或超过这个值时，它可能会将有效连接类型降级为 3G。这将导致 JavaScript 中的 `navigator.connection.effectiveType` 返回 "3g"。

* **资源加载策略：**  浏览器可能会根据估计的网络质量调整资源加载策略。例如，在较慢的网络上，浏览器可能会延迟加载非关键资源或加载低分辨率的图像。`NetworkQualityEstimatorParams` 中的参数决定了 NQE 对网络质量的评估，从而间接影响了这些加载策略。

**逻辑推理和假设输入/输出：**

`NetworkQualityEstimatorParams` 的主要逻辑是通过读取和解析配置参数来设置内部状态。

**假设输入：**

假设通过 Finch 实验配置了以下参数：

```
params = {
  "WiFi.DefaultMedianRTTMsec": "80",
  "throughput_min_requests_in_flight": "3",
  "force_effective_connection_type": "3G"
}
```

**逻辑推理和输出：**

1. **`WiFi.DefaultMedianRTTMsec`:** `ObtainDefaultObservations` 函数会解析这个参数，并将 WiFi 连接的默认中位 RTT 设置为 80 毫秒。
2. **`throughput_min_requests_in_flight`:** `NetworkQualityEstimatorParams` 的构造函数会解析这个参数，并将 `throughput_min_requests_in_flight_` 成员变量设置为 3。这意味着 NQE 至少需要观察到 3 个并发请求才能进行吞吐量估计。
3. **`force_effective_connection_type`:** `GetInitForcedEffectiveConnectionType` 函数会解析这个参数，并将 `forced_effective_connection_type_` 设置为 `EFFECTIVE_CONNECTION_TYPE_3G`。这意味着无论实际的网络状况如何，NQE 都会报告有效连接类型为 3G（除非有专门针对蜂窝网络的覆盖）。

**假设输出：**

* 调用 `params.DefaultObservation(NetworkChangeNotifier::CONNECTION_WIFI).http_rtt()` 将返回 `base::Milliseconds(80)`。
* 调用 `params.throughput_min_requests_in_flight()` 将返回 `3`。
* 调用 `params.GetForcedEffectiveConnectionType(NetworkChangeNotifier::CONNECTION_WIFI)` 将返回 `EFFECTIVE_CONNECTION_TYPE_3G`。

**用户或编程常见的使用错误：**

1. **拼写错误的参数名称：** 在 Finch 配置或其他方式传递参数时，如果参数名称拼写错误（例如，将 "WiFi.DefaultMedianRTTMsec" 拼写成 "Wifi.DefaultMedianRTTMsec"），则该参数将被忽略，NQE 将使用默认值。

   **例子：** 用户在 Finch 中配置了 "Wifi.DefaultMedianRTTMsec": "70"，但由于 "Wifi" 拼写错误，NQE 仍然使用默认的 WiFi RTT 值。

2. **提供无效的参数值：**  例如，为期望整数的参数提供了字符串值，或者提供了超出有效范围的值。

   **例子：** 用户将 "throughput_min_requests_in_flight" 设置为 "-1"。由于代码中没有显式的最小值检查（或者检查不严格），这可能会导致 NQE 的行为异常。

3. **不理解参数之间的相互作用：** 某些参数可能会相互影响。不理解这些关系可能会导致配置出与预期不符的行为。

   **例子：**  用户同时设置了较低的 RTT 阈值和较高的吞吐量阈值，但实际网络条件无法同时满足这两个条件，导致有效连接类型频繁波动。

**用户操作如何一步步到达这里作为调试线索：**

以下是一些用户操作可能最终导致与 `network_quality_estimator_params.cc` 相关的代码被执行的情况：

1. **用户加载网页：**
   * 用户在浏览器中输入 URL 或点击链接。
   * 浏览器发起网络请求。
   * Chromium 的网络栈开始工作，包括网络质量评估。
   * NQE 初始化，`NetworkQualityEstimatorParams` 对象被创建，并加载配置参数（可能来自默认值、Finch 配置等）。
   * NQE 使用这些参数来评估网络质量，这会影响后续的网络行为，例如 TCP 连接参数调整、HTTP 缓存策略、资源加载优先级等。

2. **用户网络连接发生变化：**
   * 用户从 WiFi 连接到移动数据，或者反过来。
   * 操作系统通知 Chromium 网络连接状态的变化。
   * Chromium 的网络变化监听器 (NetworkChangeNotifier) 触发 NQE 重新评估网络质量。
   * NQE 可能会根据新的网络类型使用不同的默认参数（在 `NetworkQualityEstimatorParams` 中定义）。

3. **用户参与了 A/B 测试（Finch 实验）：**
   * Chromium 的 Finch 服务可能会为用户分配不同的实验分组。
   * 如果某个实验涉及到 NQE 的参数调整，Finch 会将相应的参数值传递给 `NetworkQualityEstimatorParams`。
   * 当用户进行网络操作时，NQE 会使用这些实验配置的参数进行网络质量评估.

**调试线索：**

当需要调试与网络质量评估相关的问题时，`network_quality_estimator_params.cc` 文件中的参数是重要的检查点。以下是一些调试步骤：

1. **确认当前的 NQE 参数配置：**  可以通过 Chromium 的内部页面（例如 `chrome://net-internals/#network-quality`）查看当前生效的 NQE 参数。这可以帮助确定哪些参数被实验配置覆盖，哪些使用了默认值。
2. **检查 Finch 实验状态：**  如果怀疑问题与 A/B 测试有关，可以查看 `chrome://version` 页面，查找与网络质量相关的 Finch 实验信息。
3. **使用命令行标志进行覆盖：**  可以使用 Chromium 的命令行标志来临时覆盖某些 NQE 参数，以便进行本地测试和调试。例如，可以使用 `--force-effective-connection-type=<type>` 来强制设置有效连接类型。
4. **日志记录：**  在 `network_quality_estimator_params.cc` 文件中添加日志记录，可以帮助了解参数是如何被加载和使用的。例如，可以在 `GetValueForVariationParam` 等函数中添加日志，输出读取到的参数值。
5. **代码断点：**  在调试构建中，可以在 `NetworkQualityEstimatorParams` 的构造函数和相关参数获取函数中设置断点，以便查看参数的加载过程和值。

总而言之，`network_quality_estimator_params.cc` 是 Chromium 网络栈中一个关键的配置文件，它控制着网络质量评估器的行为，并间接地影响着浏览器的网络性能和用户体验。理解其功能和配置方式对于诊断和优化网络相关问题至关重要。

### 提示词
```
这是目录为net/nqe/network_quality_estimator_params.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/nqe/network_quality_estimator_params.h"

#include <stdint.h>

#include "base/strings/string_number_conversions.h"
#include "base/time/time.h"
#include "net/base/features.h"

namespace net {

const char kForceEffectiveConnectionType[] = "force_effective_connection_type";
const char kEffectiveConnectionTypeSlow2GOnCellular[] = "Slow-2G-On-Cellular";
const base::TimeDelta
    kHttpRttEffectiveConnectionTypeThresholds[EFFECTIVE_CONNECTION_TYPE_LAST] =
        {base::Milliseconds(0),    base::Milliseconds(0),
         base::Milliseconds(2010), base::Milliseconds(1420),
         base::Milliseconds(272),  base::Milliseconds(0)};

namespace {

// Minimum valid value of the variation parameter that holds RTT (in
// milliseconds) values.
static const int kMinimumRTTVariationParameterMsec = 1;

// Minimum valid value of the variation parameter that holds throughput (in
// kilobits per second) values.
static const int kMinimumThroughputVariationParameterKbps = 1;

// Returns the value of |parameter_name| read from |params|. If the
// value is unavailable from |params|, then |default_value| is returned.
int64_t GetValueForVariationParam(
    const std::map<std::string, std::string>& params,
    const std::string& parameter_name,
    int64_t default_value) {
  const auto it = params.find(parameter_name);
  int64_t variations_value = default_value;
  if (it != params.end() &&
      base::StringToInt64(it->second, &variations_value)) {
    return variations_value;
  }
  return default_value;
}

// Returns the variation value for |parameter_name|. If the value is
// unavailable, |default_value| is returned.
double GetDoubleValueForVariationParamWithDefaultValue(
    const std::map<std::string, std::string>& params,
    const std::string& parameter_name,
    double default_value) {
  const auto it = params.find(parameter_name);
  if (it == params.end())
    return default_value;

  double variations_value = default_value;
  if (!base::StringToDouble(it->second, &variations_value))
    return default_value;
  return variations_value;
}

// Returns the variation value for |parameter_name|. If the value is
// unavailable, |default_value| is returned.
std::string GetStringValueForVariationParamWithDefaultValue(
    const std::map<std::string, std::string>& params,
    const std::string& parameter_name,
    const std::string& default_value) {
  const auto it = params.find(parameter_name);
  if (it == params.end())
    return default_value;
  return it->second;
}

double GetWeightMultiplierPerSecond(
    const std::map<std::string, std::string>& params) {
  // Default value of the half life (in seconds) for computing time weighted
  // percentiles. Every half life, the weight of all observations reduces by
  // half. Lowering the half life would reduce the weight of older values
  // faster.
  int half_life_seconds = 60;
  int32_t variations_value = 0;
  auto it = params.find("HalfLifeSeconds");
  if (it != params.end() && base::StringToInt(it->second, &variations_value) &&
      variations_value >= 1) {
    half_life_seconds = variations_value;
  }
  DCHECK_GT(half_life_seconds, 0);
  return pow(0.5, 1.0 / half_life_seconds);
}

bool GetPersistentCacheReadingEnabled(
    const std::map<std::string, std::string>& params) {
  if (GetStringValueForVariationParamWithDefaultValue(
          params, "persistent_cache_reading_enabled", "true") != "true") {
    return false;
  }
  return true;
}

base::TimeDelta GetMinSocketWatcherNotificationInterval(
    const std::map<std::string, std::string>& params) {
  // Use 1000 milliseconds as the default value.
  return base::Milliseconds(GetValueForVariationParam(
      params, "min_socket_watcher_notification_interval_msec", 1000));
}

// static
const char* GetNameForConnectionTypeInternal(
    NetworkChangeNotifier::ConnectionType connection_type) {
  switch (connection_type) {
    case NetworkChangeNotifier::CONNECTION_UNKNOWN:
      return "Unknown";
    case NetworkChangeNotifier::CONNECTION_ETHERNET:
      return "Ethernet";
    case NetworkChangeNotifier::CONNECTION_WIFI:
      return "WiFi";
    case NetworkChangeNotifier::CONNECTION_2G:
      return "2G";
    case NetworkChangeNotifier::CONNECTION_3G:
      return "3G";
    case NetworkChangeNotifier::CONNECTION_4G:
      return "4G";
    case NetworkChangeNotifier::CONNECTION_5G:
      return "5G";
    case NetworkChangeNotifier::CONNECTION_NONE:
      return "None";
    case NetworkChangeNotifier::CONNECTION_BLUETOOTH:
      return "Bluetooth";
  }
  return "";
}

// Sets the default observation for different connection types in
// |default_observations|. The default observations are different for
// different connection types (e.g., 2G, 3G, 4G, WiFi). The default
// observations may be used to determine the network quality in absence of any
// other information.
void ObtainDefaultObservations(
    const std::map<std::string, std::string>& params,
    nqe::internal::NetworkQuality default_observations[]) {
  for (size_t i = 0; i < NetworkChangeNotifier::CONNECTION_LAST; ++i) {
    DCHECK_EQ(nqe::internal::InvalidRTT(), default_observations[i].http_rtt());
    DCHECK_EQ(nqe::internal::InvalidRTT(),
              default_observations[i].transport_rtt());
    DCHECK_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
              default_observations[i].downstream_throughput_kbps());
  }

  // Default observations for HTTP RTT, transport RTT, and downstream throughput
  // Kbps for the various connection types. These may be overridden by
  // variations params. The default observation for a connection type
  // corresponds to typical network quality for that connection type.
  default_observations[NetworkChangeNotifier::CONNECTION_UNKNOWN] =
      nqe::internal::NetworkQuality(base::Milliseconds(115),
                                    base::Milliseconds(55), 1961);

  default_observations[NetworkChangeNotifier::CONNECTION_ETHERNET] =
      nqe::internal::NetworkQuality(base::Milliseconds(90),
                                    base::Milliseconds(33), 1456);

  default_observations[NetworkChangeNotifier::CONNECTION_WIFI] =
      nqe::internal::NetworkQuality(base::Milliseconds(116),
                                    base::Milliseconds(66), 2658);

  default_observations[NetworkChangeNotifier::CONNECTION_2G] =
      nqe::internal::NetworkQuality(base::Milliseconds(1726),
                                    base::Milliseconds(1531), 74);

  default_observations[NetworkChangeNotifier::CONNECTION_3G] =
      nqe::internal::NetworkQuality(base::Milliseconds(273),
                                    base::Milliseconds(209), 749);

  default_observations[NetworkChangeNotifier::CONNECTION_4G] =
      nqe::internal::NetworkQuality(base::Milliseconds(137),
                                    base::Milliseconds(80), 1708);

  default_observations[NetworkChangeNotifier::CONNECTION_NONE] =
      nqe::internal::NetworkQuality(base::Milliseconds(163),
                                    base::Milliseconds(83), 575);

  default_observations[NetworkChangeNotifier::CONNECTION_BLUETOOTH] =
      nqe::internal::NetworkQuality(base::Milliseconds(385),
                                    base::Milliseconds(318), 476);

  // Override using the values provided via variation params.
  for (size_t i = 0; i <= NetworkChangeNotifier::CONNECTION_LAST; ++i) {
    NetworkChangeNotifier::ConnectionType type =
        static_cast<NetworkChangeNotifier::ConnectionType>(i);

    int32_t variations_value = kMinimumRTTVariationParameterMsec - 1;
    std::string parameter_name =
        std::string(GetNameForConnectionTypeInternal(type))
            .append(".DefaultMedianRTTMsec");
    auto it = params.find(parameter_name);
    if (it != params.end() &&
        base::StringToInt(it->second, &variations_value) &&
        variations_value >= kMinimumRTTVariationParameterMsec) {
      default_observations[i] = nqe::internal::NetworkQuality(
          base::Milliseconds(variations_value),
          default_observations[i].transport_rtt(),
          default_observations[i].downstream_throughput_kbps());
    }

    variations_value = kMinimumRTTVariationParameterMsec - 1;
    parameter_name = std::string(GetNameForConnectionTypeInternal(type))
                         .append(".DefaultMedianTransportRTTMsec");
    it = params.find(parameter_name);
    if (it != params.end() &&
        base::StringToInt(it->second, &variations_value) &&
        variations_value >= kMinimumRTTVariationParameterMsec) {
      default_observations[i] = nqe::internal::NetworkQuality(
          default_observations[i].http_rtt(),
          base::Milliseconds(variations_value),
          default_observations[i].downstream_throughput_kbps());
    }

    variations_value = kMinimumThroughputVariationParameterKbps - 1;
    parameter_name = std::string(GetNameForConnectionTypeInternal(type))
                         .append(".DefaultMedianKbps");
    it = params.find(parameter_name);

    if (it != params.end() &&
        base::StringToInt(it->second, &variations_value) &&
        variations_value >= kMinimumThroughputVariationParameterKbps) {
      default_observations[i] = nqe::internal::NetworkQuality(
          default_observations[i].http_rtt(),
          default_observations[i].transport_rtt(), variations_value);
    }
  }
}

// Typical HTTP RTT value corresponding to a given WebEffectiveConnectionType
// value. Taken from
// https://cs.chromium.org/chromium/src/net/nqe/network_quality_estimator_params.cc.
const base::TimeDelta kTypicalHttpRttEffectiveConnectionType
    [net::EFFECTIVE_CONNECTION_TYPE_LAST] = {
        base::Milliseconds(0),    base::Milliseconds(0),
        base::Milliseconds(3600), base::Milliseconds(1800),
        base::Milliseconds(450),  base::Milliseconds(175)};

// Typical downlink throughput (in Mbps) value corresponding to a given
// WebEffectiveConnectionType value. Taken from
// https://cs.chromium.org/chromium/src/net/nqe/network_quality_estimator_params.cc.
const int32_t kTypicalDownlinkKbpsEffectiveConnectionType
    [net::EFFECTIVE_CONNECTION_TYPE_LAST] = {0, 0, 40, 75, 400, 1600};

// Sets |typical_network_quality| to typical network quality for different
// effective connection types.
void ObtainTypicalNetworkQualities(
    const std::map<std::string, std::string>& params,
    nqe::internal::NetworkQuality typical_network_quality[]) {
  for (size_t i = 0; i < EFFECTIVE_CONNECTION_TYPE_LAST; ++i) {
    DCHECK_EQ(nqe::internal::InvalidRTT(),
              typical_network_quality[i].http_rtt());
    DCHECK_EQ(nqe::internal::InvalidRTT(),
              typical_network_quality[i].transport_rtt());
    DCHECK_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
              typical_network_quality[i].downstream_throughput_kbps());
  }

  typical_network_quality[EFFECTIVE_CONNECTION_TYPE_SLOW_2G] =
      nqe::internal::NetworkQuality(
          // Set to the 77.5th percentile of 2G RTT observations on Android.
          // This corresponds to the median RTT observation when effective
          // connection type is Slow 2G.
          kTypicalHttpRttEffectiveConnectionType
              [EFFECTIVE_CONNECTION_TYPE_SLOW_2G],
          base::Milliseconds(3000),
          kTypicalDownlinkKbpsEffectiveConnectionType
              [EFFECTIVE_CONNECTION_TYPE_SLOW_2G]);

  typical_network_quality[EFFECTIVE_CONNECTION_TYPE_2G] =
      nqe::internal::NetworkQuality(
          // Set to the 58th percentile of 2G RTT observations on Android. This
          // corresponds to the median RTT observation when effective connection
          // type is 2G.
          kTypicalHttpRttEffectiveConnectionType[EFFECTIVE_CONNECTION_TYPE_2G],
          base::Milliseconds(1500),
          kTypicalDownlinkKbpsEffectiveConnectionType
              [EFFECTIVE_CONNECTION_TYPE_2G]);

  typical_network_quality[EFFECTIVE_CONNECTION_TYPE_3G] =
      nqe::internal::NetworkQuality(
          // Set to the 75th percentile of 3G RTT observations on Android. This
          // corresponds to the median RTT observation when effective connection
          // type is 3G.
          kTypicalHttpRttEffectiveConnectionType[EFFECTIVE_CONNECTION_TYPE_3G],
          base::Milliseconds(400),
          kTypicalDownlinkKbpsEffectiveConnectionType
              [EFFECTIVE_CONNECTION_TYPE_3G]);

  // Set to the 25th percentile of 3G RTT observations on Android.
  typical_network_quality[EFFECTIVE_CONNECTION_TYPE_4G] =
      nqe::internal::NetworkQuality(
          kTypicalHttpRttEffectiveConnectionType[EFFECTIVE_CONNECTION_TYPE_4G],
          base::Milliseconds(125),
          kTypicalDownlinkKbpsEffectiveConnectionType
              [EFFECTIVE_CONNECTION_TYPE_4G]);

  static_assert(
      EFFECTIVE_CONNECTION_TYPE_4G + 1 == EFFECTIVE_CONNECTION_TYPE_LAST,
      "Missing effective connection type");
}

// Sets the thresholds for different effective connection types in
// |connection_thresholds|.
void ObtainConnectionThresholds(
    const std::map<std::string, std::string>& params,
    nqe::internal::NetworkQuality connection_thresholds[]) {
  // First set the default thresholds.
  nqe::internal::NetworkQuality default_effective_connection_type_thresholds
      [EffectiveConnectionType::EFFECTIVE_CONNECTION_TYPE_LAST];

  DCHECK_LT(base::TimeDelta(), kHttpRttEffectiveConnectionTypeThresholds
                                   [EFFECTIVE_CONNECTION_TYPE_SLOW_2G]);
  default_effective_connection_type_thresholds
      [EFFECTIVE_CONNECTION_TYPE_SLOW_2G] = nqe::internal::NetworkQuality(
          // Set to the 66th percentile of 2G RTT observations on Android.
          kHttpRttEffectiveConnectionTypeThresholds
              [EFFECTIVE_CONNECTION_TYPE_SLOW_2G],
          nqe::internal::InvalidRTT(), nqe::internal::INVALID_RTT_THROUGHPUT);

  DCHECK_LT(
      base::TimeDelta(),
      kHttpRttEffectiveConnectionTypeThresholds[EFFECTIVE_CONNECTION_TYPE_2G]);
  default_effective_connection_type_thresholds[EFFECTIVE_CONNECTION_TYPE_2G] =
      nqe::internal::NetworkQuality(
          // Set to the 50th percentile of RTT observations on Android.
          kHttpRttEffectiveConnectionTypeThresholds
              [EFFECTIVE_CONNECTION_TYPE_2G],
          nqe::internal::InvalidRTT(), nqe::internal::INVALID_RTT_THROUGHPUT);

  DCHECK_LT(
      base::TimeDelta(),
      kHttpRttEffectiveConnectionTypeThresholds[EFFECTIVE_CONNECTION_TYPE_3G]);
  default_effective_connection_type_thresholds[EFFECTIVE_CONNECTION_TYPE_3G] =
      nqe::internal::NetworkQuality(
          // Set to the 50th percentile of 3G RTT observations on Android.
          kHttpRttEffectiveConnectionTypeThresholds
              [EFFECTIVE_CONNECTION_TYPE_3G],
          nqe::internal::InvalidRTT(), nqe::internal::INVALID_RTT_THROUGHPUT);

  // Connection threshold should not be set for 4G effective connection type
  // since it is the fastest.
  static_assert(
      EFFECTIVE_CONNECTION_TYPE_3G + 1 == EFFECTIVE_CONNECTION_TYPE_4G,
      "Missing effective connection type");
  static_assert(
      EFFECTIVE_CONNECTION_TYPE_4G + 1 == EFFECTIVE_CONNECTION_TYPE_LAST,
      "Missing effective connection type");
  for (size_t i = 0; i <= EFFECTIVE_CONNECTION_TYPE_3G; ++i) {
    EffectiveConnectionType effective_connection_type =
        static_cast<EffectiveConnectionType>(i);
    DCHECK_EQ(nqe::internal::InvalidRTT(), connection_thresholds[i].http_rtt());
    DCHECK_EQ(nqe::internal::InvalidRTT(),
              connection_thresholds[i].transport_rtt());
    DCHECK_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
              connection_thresholds[i].downstream_throughput_kbps());
    if (effective_connection_type == EFFECTIVE_CONNECTION_TYPE_UNKNOWN)
      continue;

    std::string connection_type_name = std::string(
        DeprecatedGetNameForEffectiveConnectionType(effective_connection_type));

    connection_thresholds[i].set_http_rtt(
        base::Milliseconds(GetValueForVariationParam(
            params, connection_type_name + ".ThresholdMedianHttpRTTMsec",
            default_effective_connection_type_thresholds[i]
                .http_rtt()
                .InMilliseconds())));

    DCHECK_EQ(nqe::internal::InvalidRTT(),
              default_effective_connection_type_thresholds[i].transport_rtt());
    DCHECK_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
              default_effective_connection_type_thresholds[i]
                  .downstream_throughput_kbps());
    DCHECK(i == 0 ||
           connection_thresholds[i].IsFaster(connection_thresholds[i - 1]));
  }
}

std::string GetForcedEffectiveConnectionTypeString(
    const std::map<std::string, std::string>& params) {
  return GetStringValueForVariationParamWithDefaultValue(
      params, kForceEffectiveConnectionType, "");
}

bool GetForcedEffectiveConnectionTypeOnCellularOnly(
    const std::map<std::string, std::string>& params) {
  return GetForcedEffectiveConnectionTypeString(params) ==
         kEffectiveConnectionTypeSlow2GOnCellular;
}

std::optional<EffectiveConnectionType> GetInitForcedEffectiveConnectionType(
    const std::map<std::string, std::string>& params) {
  if (GetForcedEffectiveConnectionTypeOnCellularOnly(params)) {
    return std::nullopt;
  }
  std::string forced_value = GetForcedEffectiveConnectionTypeString(params);
  std::optional<EffectiveConnectionType> ect =
      GetEffectiveConnectionTypeForName(forced_value);
  DCHECK(forced_value.empty() || ect);
  return ect;
}

}  // namespace

NetworkQualityEstimatorParams::NetworkQualityEstimatorParams(
    const std::map<std::string, std::string>& params)
    : params_(params),
      throughput_min_requests_in_flight_(
          GetValueForVariationParam(params_,
                                    "throughput_min_requests_in_flight",
                                    5)),
      throughput_min_transfer_size_kilobytes_(
          GetValueForVariationParam(params_,
                                    "throughput_min_transfer_size_kilobytes",
                                    32)),
      throughput_hanging_requests_cwnd_size_multiplier_(
          GetDoubleValueForVariationParamWithDefaultValue(
              params_,
              "throughput_hanging_requests_cwnd_size_multiplier",
              1)),
      weight_multiplier_per_second_(GetWeightMultiplierPerSecond(params_)),
      forced_effective_connection_type_(
          GetInitForcedEffectiveConnectionType(params_)),
      forced_effective_connection_type_on_cellular_only_(
          GetForcedEffectiveConnectionTypeOnCellularOnly(params_)),
      persistent_cache_reading_enabled_(
          GetPersistentCacheReadingEnabled(params_)),
      min_socket_watcher_notification_interval_(
          GetMinSocketWatcherNotificationInterval(params_)),
      upper_bound_http_rtt_endtoend_rtt_multiplier_(
          GetDoubleValueForVariationParamWithDefaultValue(
              params_,
              "upper_bound_http_rtt_endtoend_rtt_multiplier",
              3.0)),
      hanging_request_http_rtt_upper_bound_transport_rtt_multiplier_(
          GetValueForVariationParam(
              params_,
              "hanging_request_http_rtt_upper_bound_transport_rtt_multiplier",
              8)),
      hanging_request_http_rtt_upper_bound_http_rtt_multiplier_(
          GetValueForVariationParam(
              params_,
              "hanging_request_http_rtt_upper_bound_http_rtt_multiplier",
              6)),
      http_rtt_transport_rtt_min_count_(
          GetValueForVariationParam(params_,
                                    "http_rtt_transport_rtt_min_count",
                                    5)),
      increase_in_transport_rtt_logging_interval_(
          base::Milliseconds(GetDoubleValueForVariationParamWithDefaultValue(
              params_,
              "increase_in_transport_rtt_logging_interval",
              10000))),
      recent_time_threshold_(
          base::Milliseconds(GetDoubleValueForVariationParamWithDefaultValue(
              params_,
              "recent_time_threshold",
              5000))),
      historical_time_threshold_(
          base::Milliseconds(GetDoubleValueForVariationParamWithDefaultValue(
              params_,
              "historical_time_threshold",
              60000))),
      hanging_request_duration_http_rtt_multiplier_(GetValueForVariationParam(
          params_,
          "hanging_request_duration_http_rtt_multiplier",
          5)),
      add_default_platform_observations_(
          GetStringValueForVariationParamWithDefaultValue(
              params_,
              "add_default_platform_observations",
              "true") == "true"),
      count_new_observations_received_compute_ect_(
          features::kCountNewObservationsReceivedComputeEct.Get()),
      observation_buffer_size_(features::kObservationBufferSize.Get()),
      socket_watchers_min_notification_interval_(
          base::Milliseconds(GetValueForVariationParam(
              params_,
              "socket_watchers_min_notification_interval_msec",
              200))),
      upper_bound_typical_kbps_multiplier_(
          GetDoubleValueForVariationParamWithDefaultValue(
              params_,
              "upper_bound_typical_kbps_multiplier",
              3.5)),
      adjust_rtt_based_on_rtt_counts_(
          GetStringValueForVariationParamWithDefaultValue(
              params_,
              "adjust_rtt_based_on_rtt_counts",
              "false") == "true") {
  DCHECK(hanging_request_http_rtt_upper_bound_transport_rtt_multiplier_ == -1 ||
         hanging_request_http_rtt_upper_bound_transport_rtt_multiplier_ > 0);
  DCHECK(hanging_request_http_rtt_upper_bound_http_rtt_multiplier_ == -1 ||
         hanging_request_http_rtt_upper_bound_http_rtt_multiplier_ > 0);
  DCHECK(hanging_request_http_rtt_upper_bound_transport_rtt_multiplier_ == -1 ||
         hanging_request_http_rtt_upper_bound_http_rtt_multiplier_ == -1 ||
         hanging_request_http_rtt_upper_bound_transport_rtt_multiplier_ >=
             hanging_request_http_rtt_upper_bound_http_rtt_multiplier_);

  DCHECK_LT(0, hanging_request_duration_http_rtt_multiplier());
  DCHECK_LT(0, hanging_request_http_rtt_upper_bound_http_rtt_multiplier());
  DCHECK_LT(0, hanging_request_http_rtt_upper_bound_transport_rtt_multiplier());

  ObtainDefaultObservations(params_, default_observations_);
  ObtainTypicalNetworkQualities(params_, typical_network_quality_);
  ObtainConnectionThresholds(params_, connection_thresholds_);
}

NetworkQualityEstimatorParams::~NetworkQualityEstimatorParams() = default;

void NetworkQualityEstimatorParams::SetUseSmallResponsesForTesting(
    bool use_small_responses) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  use_small_responses_ = use_small_responses;
}

bool NetworkQualityEstimatorParams::use_small_responses() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return use_small_responses_;
}

// static
base::TimeDelta NetworkQualityEstimatorParams::GetDefaultTypicalHttpRtt(
    EffectiveConnectionType effective_connection_type) {
  return kTypicalHttpRttEffectiveConnectionType[effective_connection_type];
}

// static
int32_t NetworkQualityEstimatorParams::GetDefaultTypicalDownlinkKbps(
    EffectiveConnectionType effective_connection_type) {
  return kTypicalDownlinkKbpsEffectiveConnectionType[effective_connection_type];
}

void NetworkQualityEstimatorParams::SetForcedEffectiveConnectionTypeForTesting(
    EffectiveConnectionType type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!forced_effective_connection_type_on_cellular_only_);
  forced_effective_connection_type_ = type;
}

std::optional<EffectiveConnectionType>
NetworkQualityEstimatorParams::GetForcedEffectiveConnectionType(
    NetworkChangeNotifier::ConnectionType connection_type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (forced_effective_connection_type_) {
    return forced_effective_connection_type_;
  }

  if (forced_effective_connection_type_on_cellular_only_ &&
      net::NetworkChangeNotifier::IsConnectionCellular(connection_type)) {
    return EFFECTIVE_CONNECTION_TYPE_SLOW_2G;
  }
  return std::nullopt;
}

size_t NetworkQualityEstimatorParams::throughput_min_requests_in_flight()
    const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // If |use_small_responses_| is set to true for testing, then consider one
  // request as sufficient for taking throughput sample.
  return use_small_responses_ ? 1 : throughput_min_requests_in_flight_;
}

int64_t NetworkQualityEstimatorParams::GetThroughputMinTransferSizeBits()
    const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return static_cast<int64_t>(throughput_min_transfer_size_kilobytes_) * 8 *
         1000;
}

const nqe::internal::NetworkQuality&
NetworkQualityEstimatorParams::DefaultObservation(
    NetworkChangeNotifier::ConnectionType type) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return default_observations_[type];
}

const nqe::internal::NetworkQuality&
NetworkQualityEstimatorParams::TypicalNetworkQuality(
    EffectiveConnectionType type) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return typical_network_quality_[type];
}

const nqe::internal::NetworkQuality&
NetworkQualityEstimatorParams::ConnectionThreshold(
    EffectiveConnectionType type) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return connection_thresholds_[type];
}

}  // namespace net
```