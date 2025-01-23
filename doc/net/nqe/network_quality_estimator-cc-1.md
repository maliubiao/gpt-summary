Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's network stack. This is the second part of a two-part request, so the goal is to summarize the overall function. The decomposed instructions ask for:

1. **Functionality:**  Describe what the code does.
2. **JavaScript Relation:** Explain any connection to JavaScript functionality with examples.
3. **Logical Inference:** Provide examples of input and output based on the code's logic.
4. **User/Programming Errors:**  Illustrate common mistakes that might occur.
5. **User Navigation:** Explain how a user's actions could lead to this code being executed.
6. **Summary:**  Provide a concise overview of the file's purpose.

Let's go through each point based on the provided code:

**1. Functionality:**

The code primarily deals with:

* **Effective Connection Type (ECT) Estimation:**  It calculates the perceived network connection quality (e.g., 2G, 3G, 4G, Slow 2G) based on observed Round Trip Time (RTT) and download throughput.
* **RTT and Throughput Measurement:**  It collects and manages historical RTT and throughput data from various sources (HTTP, TCP sockets, QUIC, SPDY pings).
* **Observer Pattern:** It implements an observer pattern to notify other parts of the system when the estimated network quality changes or new RTT/throughput measurements are available.
* **Caching:** It interacts with a cache to store and retrieve network quality estimates for different networks to improve the speed of initial estimates.
* **Configuration:** It uses `NetworkQualityEstimatorParams` to define thresholds and other parameters for the estimation process.
* **Peer-to-Peer Connection Tracking:** It tracks the number of active peer-to-peer connections.

**2. JavaScript Relation:**

The most direct relationship to JavaScript is through the Network Information API. This API, exposed in web browsers, allows JavaScript to query the estimated effective connection type. The `NetworkQualityEstimator` is the underlying component in Chromium that provides this information.

**3. Logical Inference (Hypothetical Input/Output):**

Consider the `GetEffectiveConnectionType()` function.

* **Input (Hypothetical):**
    * `http_rtt`: 200ms
    * `transport_rtt`: 150ms
    * `end_to_end_rtt`: 250ms
    * `downstream_throughput_kbps`: 500 kbps
    * `params_->ConnectionThreshold(EffectiveConnectionType::EFFECTIVE_CONNECTION_TYPE_3G).http_rtt()`: 150ms
    * `params_->ConnectionThreshold(EffectiveConnectionType::EFFECTIVE_CONNECTION_TYPE_4G).http_rtt()`: 100ms

* **Output:** `EFFECTIVE_CONNECTION_TYPE_3G`

**Explanation:** The code iterates through the connection types. The HTTP RTT (200ms) is greater than or equal to the threshold for 3G (150ms), so it returns 3G.

* **Input (Hypothetical - Fallback Scenario):**  No recent transport or end-to-end RTT measurements are available.

* **Output:** The function will attempt to retrieve any transport/end-to-end RTT, and if still not found, will use `nqe::internal::InvalidRTT()`. It will then proceed with the HTTP RTT to determine the effective connection type.

**4. User/Programming Errors:**

* **Incorrect Observer Management:** Forgetting to call `RemoveEffectiveConnectionTypeObserver` when an observer is no longer needed can lead to memory leaks or unexpected behavior. The code uses `DCHECK_CALLED_ON_VALID_SEQUENCE` to help catch errors related to threading.
* **Incorrectly Interpreting ECT:**  Assuming ECT is an exact measure of network speed rather than an estimation of *perceived* quality.
* **Misconfiguring Thresholds:** Setting overly aggressive or conservative thresholds in `NetworkQualityEstimatorParams` can lead to inaccurate ECT estimations.

**5. User Navigation (Debugging Clues):**

A user action that could trigger this code includes:

1. **Opening a webpage:** The browser needs to estimate the network quality to optimize resource loading and provide a better user experience.
2. **Starting a video call:** The browser might use the estimated network quality to select appropriate video and audio codecs.
3. **Downloading a large file:** The browser can use the throughput estimate to show a more accurate progress bar.
4. **Using a web application that relies on real-time data:** The application might adapt its behavior based on the estimated network quality.

As a debugging clue, if a user reports that a website is loading slowly, developers might investigate the effective connection type reported by the browser and then trace back through the `NetworkQualityEstimator` to see which metrics are being used and if there are any unusual patterns in the RTT or throughput data. They could also examine the cached network quality information.

**6. Summary of Functionality (Part 2):**

This part of the `NetworkQualityEstimator` code focuses on:

* **Refining and utilizing the collected network quality metrics (RTT and throughput) to determine the Effective Connection Type (ECT).** It iterates through different connection type thresholds to find the best match.
* **Implementing the observer pattern for ECT and RTT/throughput updates, allowing other components to react to changes in network quality.**
* **Providing methods to add and remove these observers.**
* **Offering functions to directly query recent RTT and throughput estimates.**
* **Managing a persistent cache of network quality estimates to speed up initial assessments.**
* **Handling cached estimates and ensuring new observations override or refine them.**
* **Defining the logic for when to recompute the ECT based on time intervals, significant changes in observations, or connection changes.**
* **Exposing methods for testing and simulating network conditions.**
* **Tracking peer-to-peer connection counts.**

Essentially, this section builds upon the data collection mechanisms (presumably in the first part of the file) and uses that data to make informed decisions about the user's network experience and communicate those decisions to other parts of the browser. It also includes mechanisms for persistence and observation.
这是对 Chromium 网络栈中 `net/nqe/network_quality_estimator.cc` 文件部分代码的分析和功能归纳。这部分代码主要负责以下功能：

**核心功能：根据收集到的网络指标（RTT和吞吐量）来计算和更新设备的有效连接类型 (EffectiveConnectionType)。**

**具体功能点：**

1. **获取并处理最近的 RTT 和吞吐量数据：**
   - `GetEffectiveConnectionType()` 函数会尝试获取最近的 HTTP、传输层 (TCP/QUIC) 和端到端的 RTT 值，以及下行吞吐量。
   - 如果最近的数据不可用，它会尝试回退到更早的数据，并记录回退是否成功。
   - 如果所有 RTT 数据都不可用，则认为有效连接类型未知。

2. **使用 RTT 和吞吐量来确定有效连接类型：**
   - `GetEffectiveConnectionType()` 遍历不同的 `EffectiveConnectionType` (从最慢到最快)。
   - 对于每种连接类型，它会比较估计的 HTTP RTT 是否高于该连接类型的阈值 (`params_->ConnectionThreshold(type).http_rtt()`)。
   - 如果估计的 HTTP RTT 高于某个连接类型的阈值，则认为当前的有效连接类型是该类型。
   - 如果所有连接类型的阈值都低于估计的 HTTP RTT，则认为当前连接类型是最快的。

3. **实现观察者模式以通知有效连接类型的变化：**
   - `AddEffectiveConnectionTypeObserver()` 和 `RemoveEffectiveConnectionTypeObserver()` 用于添加和移除 `EffectiveConnectionTypeObserver`。
   - 当有效连接类型发生变化时，会通过 `effective_connection_type_observer_list_` 通知所有注册的观察者。

4. **实现观察者模式以通知对等连接数量的变化：**
   - `AddPeerToPeerConnectionsCountObserver()` 和 `RemovePeerToPeerConnectionsCountObserver()` 用于添加和移除 `PeerToPeerConnectionsCountObserver`。
   - 当对等连接数量发生变化时，会通过 `peer_to_peer_type_observer_list_` 通知所有注册的观察者。

5. **实现观察者模式以通知 RTT 和吞吐量估计值的变化：**
   - `AddRTTAndThroughputEstimatesObserver()` 和 `RemoveRTTAndThroughputEstimatesObserver()` 用于添加和移除 `RTTAndThroughputEstimatesObserver`。
   - 当 RTT 或吞吐量估计值更新时，会通过 `rtt_and_throughput_estimates_observer_list_` 通知所有注册的观察者。

6. **提供获取最近 RTT 和吞吐量估计值的方法：**
   - `GetRecentRTT()` 和 `GetRecentDownlinkThroughputKbps()` 用于获取指定时间段内的 RTT 和吞吐量估计值。

7. **内部方法用于获取 RTT 和吞吐量的百分位数估计：**
   - `GetRTTEstimateInternal()` 和 `GetDownlinkThroughputKbpsEstimateInternal()` 用于根据指定的百分位数获取 RTT 和吞吐量的估计值。

8. **从缓存中读取网络质量估计值：**
   - `ReadCachedNetworkQualityEstimate()` 尝试从持久化存储中读取当前网络的缓存质量估计值。
   - 如果找到缓存的估计值，它会用这些值来初始化观察缓冲区并计算有效连接类型。
   - 如果缓存的估计值缺少 RTT 或吞吐量信息，它会使用典型值进行填充并更新缓存。

9. **处理新的 RTT 和吞吐量观测值：**
   - `OnUpdatedTransportRTTAvailable()` 处理来自传输层的新的 RTT 观测值。
   - `AddAndNotifyObserversOfRTT()` 添加新的 RTT 观测值到缓冲区并通知观察者。
   - `AddAndNotifyObserversOfThroughput()` 添加新的吞吐量观测值到缓冲区并通知观察者。
   - `OnNewThroughputObservationAvailable()` 处理来自 HTTP 层的新的吞吐量观测值。

10. **决定何时重新计算有效连接类型：**
    - `ShouldComputeEffectiveConnectionType()` 判断是否应该重新计算有效连接类型，基于上次计算的时间、连接状态是否改变、以及是否有足够多的新的 RTT 或吞吐量观测值。
    - `MaybeComputeEffectiveConnectionType()` 在条件满足时触发有效连接类型的重新计算。

11. **通知观察者有效连接类型的变化：**
    - `NotifyObserversOfEffectiveConnectionTypeChanged()` 通知所有注册的 `EffectiveConnectionTypeObserver` 有效连接类型的变化。

12. **通知观察者 RTT 或吞吐量估计值的变化：**
    - `NotifyObserversOfRTTOrThroughputComputed()` 通知所有注册的 `RTTAndThroughputEstimatesObserver` RTT 或吞吐量估计值的变化。

13. **处理从偏好设置中读取的缓存网络质量数据：**
    - `OnPrefsRead()` 处理从偏好设置中读取的缓存网络质量数据，用于初始化网络质量估计器。

14. **提供获取当前 RTT 和吞吐量估计值的方法：**
    - `GetHttpRTT()`, `GetTransportRTT()`, `GetDownstreamThroughputKbps()` 提供获取当前 HTTP RTT、传输层 RTT 和下行吞吐量估计值的方法。

15. **处理缓存估计值的应用和后续观测值的添加：**
    - `MaybeUpdateCachedEstimateApplied()` 标记缓存估计值已被应用，并清理可能与之冲突的早期观测值。
    - `ShouldAddObservation()` 判断是否应该添加新的观测值，避免在应用缓存估计值后添加某些类型的旧观测值。

16. **控制 Socket Watcher 的 RTT 通知频率：**
    - `ShouldSocketWatcherNotifyRTT()` 用于判断 Socket Watcher 是否应该发送新的 RTT 通知，以避免过于频繁的通知。

17. **提供测试和模拟网络质量变化的功能：**
    - `SimulateNetworkQualityChangeForTesting()` 用于在测试环境下模拟网络质量的变化。
    - `ForceReportWifiAsSlow2GForTesting()` 用于在测试环境下强制将 Wi-Fi 报告为慢速 2G。

18. **记录 SPDY Ping 延迟：**
    - `RecordSpdyPingLatency()` 用于记录 SPDY Ping 的延迟，作为 RTT 的一种观测值。

19. **处理对等连接数量的变化：**
    - `OnPeerToPeerConnectionsCountChange()` 记录对等连接数量的变化并通知观察者。
    - `GetPeerToPeerConnectionsCountChange()` 获取当前的对等连接数量。

**与 JavaScript 功能的关系：**

这段 C++ 代码是 Chromium 浏览器内部实现网络质量估计的核心部分。它与 JavaScript 的功能通过以下方式关联：

- **Network Information API：** 浏览器将此代码估计出的 `EffectiveConnectionType` 通过 Network Information API 暴露给网页的 JavaScript 代码。网页可以使用 `navigator.connection.effectiveType` 来获取当前的有效连接类型，并根据网络状况优化资源加载、媒体播放等行为。

**举例说明：**

假设 JavaScript 代码使用 Network Information API 获取到 `effectiveType` 为 "3g"。这表明 `NetworkQualityEstimator` 内部经过上述的逻辑判断，认为当前网络状况符合 3G 网络的特征（根据其 RTT 和吞吐量与预设的 3G 阈值比较）。网页的 JavaScript 代码可能会因此选择加载低分辨率的图片或者禁用某些动画效果，以节省流量并提高加载速度。

**逻辑推理的假设输入与输出：**

假设：
- 最近的 HTTP RTT 为 180 毫秒。
- 最近的传输层 RTT 为 150 毫秒。
- 最近的端到端 RTT 为 200 毫秒。
- 最近的下行吞吐量为 400 Kbps。
- `params_->ConnectionThreshold(EFFECTIVE_CONNECTION_TYPE_3G).http_rtt()` 为 150 毫秒。
- `params_->ConnectionThreshold(EFFECTIVE_CONNECTION_TYPE_4G).http_rtt()` 为 100 毫秒。

输出：
- `GetEffectiveConnectionType()` 将会遍历连接类型。当评估到 `EFFECTIVE_CONNECTION_TYPE_3G` 时，由于 180ms >= 150ms，函数将返回 `EFFECTIVE_CONNECTION_TYPE_3G`。

**涉及用户或编程常见的使用错误：**

1. **没有正确注册或注销观察者：**
   - **错误：**  开发者添加了 `EffectiveConnectionTypeObserver` 但在不需要时忘记移除。
   - **后果：**  当有效连接类型变化时，不再需要的观察者仍然会被通知，可能导致内存泄漏或意外行为。

2. **误解有效连接类型的含义：**
   - **错误：**  开发者将 `EffectiveConnectionType` 视为精确的网络速度指标，而不是基于历史数据和阈值的估计值。
   - **后果：**  可能基于不完全准确的信息做出决策，例如过早地认为网络很差而采取激进的优化措施。

3. **配置错误的阈值：**
   - **错误：**  管理员或开发者配置了不合理的 `NetworkQualityEstimatorParams`，例如将 4G 的 RTT 阈值设置得非常高。
   - **后果：**  即使在 4G 网络下，系统也可能错误地估计为 3G 甚至更慢的连接类型。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个网页：** 浏览器开始加载网页资源。
2. **浏览器发起网络请求：**  在发起 HTTP 请求或建立 TCP/QUIC 连接的过程中，会收集 RTT 等网络指标。
3. **网络质量估计器接收观测值：**  例如，TCP 连接握手完成时，可以获取 TCP RTT；HTTP 响应到达时，可以计算 HTTP RTT 和吞吐量。
4. **`AddAndNotifyObserversOfRTT()` 或 `AddAndNotifyObserversOfThroughput()` 被调用：**  新的观测值被添加到相应的观察缓冲区。
5. **`MaybeComputeEffectiveConnectionType()` 被调用：**  根据设定的规则，可能会触发有效连接类型的重新计算。
6. **`GetEffectiveConnectionType()` 被调用：**  根据当前的 RTT 和吞吐量以及配置的阈值，计算出当前的有效连接类型。
7. **`NotifyObserversOfEffectiveConnectionTypeChanged()` 被调用：**  通知所有注册的观察者（包括渲染进程），有效连接类型已发生变化。
8. **渲染进程将有效连接类型暴露给 JavaScript：**  网页的 JavaScript 代码可以通过 `navigator.connection.effectiveType` 获取到最新的有效连接类型。

**调试线索：** 如果用户报告网页加载缓慢，开发者可以检查 `navigator.connection.effectiveType` 的值。如果该值与用户的预期不符（例如用户在高速 Wi-Fi 下看到 "slow-2g"），则可以深入 `NetworkQualityEstimator` 的日志或断点，查看收集到的 RTT 和吞吐量数据是否异常，以及当前的有效连接类型是如何计算出来的。也可以检查 `NetworkQualityEstimatorParams` 的配置是否正确。

**功能归纳（第2部分）：**

总而言之，这部分 `NetworkQualityEstimator` 代码的核心职责是**利用收集到的网络性能数据 (RTT 和吞吐量) 来动态评估设备的网络连接质量，并将其抽象为不同的有效连接类型 (如 2G, 3G, 4G 等)，同时提供机制将这些评估结果通知给浏览器的其他组件和网页的 JavaScript 代码，以便进行相应的优化和调整。**  它还负责管理网络质量数据的缓存，并提供了用于测试和模拟网络环境的功能。

### 提示词
```
这是目录为net/nqe/network_quality_estimator.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
ernal::InvalidRTT();
      fallback_success = false;
    }
    RecordFallbackSuccess("Transport", fallback_success);
  }

  if (!GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_END_TO_END,
                    GetEndToEndStartTime(), end_to_end_rtt,
                    end_to_end_rtt_observation_count)) {
    bool fallback_success = true;
    if (!GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_END_TO_END,
                      base::TimeTicks(), end_to_end_rtt,
                      end_to_end_rtt_observation_count)) {
      *end_to_end_rtt = nqe::internal::InvalidRTT();
      fallback_success = false;
    }
    RecordFallbackSuccess("EndToEnd", fallback_success);
  }

  UpdateHttpRttUsingAllRttValues(http_rtt, *transport_rtt, *end_to_end_rtt);

  if (!GetRecentDownlinkThroughputKbps(base::TimeTicks(),
                                       downstream_throughput_kbps)) {
    *downstream_throughput_kbps = nqe::internal::INVALID_RTT_THROUGHPUT;
  }

  if (*http_rtt == nqe::internal::InvalidRTT()) {
    return EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  }

  if (*http_rtt == nqe::internal::InvalidRTT() &&
      *transport_rtt == nqe::internal::InvalidRTT() &&
      *downstream_throughput_kbps == nqe::internal::INVALID_RTT_THROUGHPUT) {
    // None of the metrics are available.
    return EFFECTIVE_CONNECTION_TYPE_UNKNOWN;
  }

  // Search from the slowest connection type to the fastest to find the
  // EffectiveConnectionType that best matches the current connection's
  // performance. The match is done by comparing RTT and throughput.
  for (size_t i = 0; i < EFFECTIVE_CONNECTION_TYPE_LAST; ++i) {
    EffectiveConnectionType type = static_cast<EffectiveConnectionType>(i);
    if (i == EFFECTIVE_CONNECTION_TYPE_UNKNOWN)
      continue;

    const bool estimated_http_rtt_is_higher_than_threshold =
        *http_rtt != nqe::internal::InvalidRTT() &&
        params_->ConnectionThreshold(type).http_rtt() !=
            nqe::internal::InvalidRTT() &&
        *http_rtt >= params_->ConnectionThreshold(type).http_rtt();

    if (estimated_http_rtt_is_higher_than_threshold)
      return type;
  }
  // Return the fastest connection type.
  return static_cast<EffectiveConnectionType>(EFFECTIVE_CONNECTION_TYPE_LAST -
                                              1);
}

void NetworkQualityEstimator::AddEffectiveConnectionTypeObserver(
    EffectiveConnectionTypeObserver* observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(observer);
  effective_connection_type_observer_list_.AddObserver(observer);

  // Notify the |observer| on the next message pump since |observer| may not
  // be completely set up for receiving the callbacks.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&NetworkQualityEstimator::
                         NotifyEffectiveConnectionTypeObserverIfPresent,
                     weak_ptr_factory_.GetWeakPtr(),
                     // This is safe as `handle` is checked against a map to
                     // verify it hasn't been removed before dereferencing.
                     base::UnsafeDangling(observer)));
}

void NetworkQualityEstimator::RemoveEffectiveConnectionTypeObserver(
    EffectiveConnectionTypeObserver* observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  effective_connection_type_observer_list_.RemoveObserver(observer);
}

void NetworkQualityEstimator::AddPeerToPeerConnectionsCountObserver(
    PeerToPeerConnectionsCountObserver* observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(observer);
  peer_to_peer_type_observer_list_.AddObserver(observer);

  // Notify the |observer| on the next message pump since |observer| may not
  // be completely set up for receiving the callbacks.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&NetworkQualityEstimator::
                         NotifyPeerToPeerConnectionsCountObserverIfPresent,
                     weak_ptr_factory_.GetWeakPtr(),
                     // This is safe as `handle` is checked against a map to
                     // verify it hasn't been removed before dereferencing.
                     base::UnsafeDangling(observer)));
}

void NetworkQualityEstimator::RemovePeerToPeerConnectionsCountObserver(
    PeerToPeerConnectionsCountObserver* observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  peer_to_peer_type_observer_list_.RemoveObserver(observer);
}

void NetworkQualityEstimator::AddRTTAndThroughputEstimatesObserver(
    RTTAndThroughputEstimatesObserver* observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(observer);
  rtt_and_throughput_estimates_observer_list_.AddObserver(observer);

  // Notify the |observer| on the next message pump since |observer| may not
  // be completely set up for receiving the callbacks.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE,
      base::BindOnce(&NetworkQualityEstimator::
                         NotifyRTTAndThroughputEstimatesObserverIfPresent,
                     weak_ptr_factory_.GetWeakPtr(), observer));
}

void NetworkQualityEstimator::RemoveRTTAndThroughputEstimatesObserver(
    RTTAndThroughputEstimatesObserver* observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  rtt_and_throughput_estimates_observer_list_.RemoveObserver(observer);
}

bool NetworkQualityEstimator::GetRecentRTT(
    nqe::internal::ObservationCategory observation_category,
    const base::TimeTicks& start_time,
    base::TimeDelta* rtt,
    size_t* observations_count) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  *rtt = GetRTTEstimateInternal(start_time, observation_category, 50,
                                observations_count);
  return (*rtt != nqe::internal::InvalidRTT());
}

bool NetworkQualityEstimator::GetRecentDownlinkThroughputKbps(
    const base::TimeTicks& start_time,
    int32_t* kbps) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  *kbps = GetDownlinkThroughputKbpsEstimateInternal(start_time, 50);
  return (*kbps != nqe::internal::INVALID_RTT_THROUGHPUT);
}

base::TimeDelta NetworkQualityEstimator::GetRTTEstimateInternal(
    base::TimeTicks start_time,
    nqe::internal::ObservationCategory observation_category,
    int percentile,
    size_t* observations_count) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(nqe::internal::OBSERVATION_CATEGORY_COUNT,
            std::size(rtt_ms_observations_));

  // RTT observations are sorted by duration from shortest to longest, thus
  // a higher percentile RTT will have a longer RTT than a lower percentile.
  switch (observation_category) {
    case nqe::internal::OBSERVATION_CATEGORY_HTTP:
    case nqe::internal::OBSERVATION_CATEGORY_TRANSPORT:
    case nqe::internal::OBSERVATION_CATEGORY_END_TO_END:
      return base::Milliseconds(
          rtt_ms_observations_[observation_category]
              .GetPercentile(start_time, current_network_id_.signal_strength,
                             percentile, observations_count)
              .value_or(nqe::internal::INVALID_RTT_THROUGHPUT));
    case nqe::internal::OBSERVATION_CATEGORY_COUNT:
      NOTREACHED();
  }
}

int32_t NetworkQualityEstimator::GetDownlinkThroughputKbpsEstimateInternal(
    const base::TimeTicks& start_time,
    int percentile) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // Throughput observations are sorted by kbps from slowest to fastest,
  // thus a higher percentile throughput will be faster than a lower one.
  return http_downstream_throughput_kbps_observations_
      .GetPercentile(start_time, current_network_id_.signal_strength,
                     100 - percentile, nullptr)
      .value_or(nqe::internal::INVALID_RTT_THROUGHPUT);
}

nqe::internal::NetworkID NetworkQualityEstimator::GetCurrentNetworkID() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // TODO(tbansal): crbug.com/498068 Add NetworkQualityEstimatorAndroid class
  // that overrides this method on the Android platform.

  return DoGetCurrentNetworkID(params_.get());
}

bool NetworkQualityEstimator::ReadCachedNetworkQualityEstimate() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!params_->persistent_cache_reading_enabled())
    return false;

  nqe::internal::CachedNetworkQuality cached_network_quality;

  const bool cached_estimate_available = network_quality_store_->GetById(
      current_network_id_, &cached_network_quality);

  if (!cached_estimate_available) {
    return false;
  }

  EffectiveConnectionType effective_connection_type =
      cached_network_quality.effective_connection_type();

  if (effective_connection_type == EFFECTIVE_CONNECTION_TYPE_UNKNOWN ||
      effective_connection_type == EFFECTIVE_CONNECTION_TYPE_OFFLINE ||
      effective_connection_type == EFFECTIVE_CONNECTION_TYPE_LAST) {
    return false;
  }

  nqe::internal::NetworkQuality network_quality =
      cached_network_quality.network_quality();

  bool update_network_quality_store = false;

  // Populate |network_quality| with synthetic RTT and throughput observations
  // if they are missing.
  if (network_quality.http_rtt().InMilliseconds() ==
      nqe::internal::INVALID_RTT_THROUGHPUT) {
    network_quality.set_http_rtt(
        params_->TypicalNetworkQuality(effective_connection_type).http_rtt());
    update_network_quality_store = true;
  }

  if (network_quality.transport_rtt().InMilliseconds() ==
      nqe::internal::INVALID_RTT_THROUGHPUT) {
    network_quality.set_transport_rtt(
        params_->TypicalNetworkQuality(effective_connection_type)
            .transport_rtt());
    update_network_quality_store = true;
  }

  if (network_quality.downstream_throughput_kbps() ==
      nqe::internal::INVALID_RTT_THROUGHPUT) {
    network_quality.set_downstream_throughput_kbps(
        params_->TypicalNetworkQuality(effective_connection_type)
            .downstream_throughput_kbps());
    update_network_quality_store = true;
  }

  if (update_network_quality_store) {
    network_quality_store_->Add(current_network_id_,
                                nqe::internal::CachedNetworkQuality(
                                    tick_clock_->NowTicks(), network_quality,
                                    effective_connection_type));
  }

  Observation http_rtt_observation(
      network_quality.http_rtt().InMilliseconds(), tick_clock_->NowTicks(),
      INT32_MIN, NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE);
  AddAndNotifyObserversOfRTT(http_rtt_observation);

  Observation transport_rtt_observation(
      network_quality.transport_rtt().InMilliseconds(), tick_clock_->NowTicks(),
      INT32_MIN, NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE);
  AddAndNotifyObserversOfRTT(transport_rtt_observation);

  Observation througphput_observation(
      network_quality.downstream_throughput_kbps(), tick_clock_->NowTicks(),
      INT32_MIN, NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE);
  AddAndNotifyObserversOfThroughput(througphput_observation);

  ComputeEffectiveConnectionType();
  return true;
}

void NetworkQualityEstimator::SetTickClockForTesting(
    const base::TickClock* tick_clock) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  tick_clock_ = tick_clock;
  for (auto& rtt_ms_observation : rtt_ms_observations_)
    rtt_ms_observation.SetTickClockForTesting(tick_clock_);  // IN-TEST
  http_downstream_throughput_kbps_observations_.SetTickClockForTesting(
      tick_clock_);
  throughput_analyzer_->SetTickClockForTesting(tick_clock_);
  watcher_factory_->SetTickClockForTesting(tick_clock_);
}

void NetworkQualityEstimator::OnUpdatedTransportRTTAvailable(
    SocketPerformanceWatcherFactory::Protocol protocol,
    const base::TimeDelta& rtt,
    const std::optional<nqe::internal::IPHash>& host) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_LT(nqe::internal::INVALID_RTT_THROUGHPUT, rtt.InMilliseconds());
  Observation observation(rtt.InMilliseconds(), tick_clock_->NowTicks(),
                          current_network_id_.signal_strength,
                          ProtocolSourceToObservationSource(protocol), host);
  AddAndNotifyObserversOfRTT(observation);
}

void NetworkQualityEstimator::AddAndNotifyObserversOfRTT(
    const Observation& observation) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_NE(nqe::internal::InvalidRTT(),
            base::Milliseconds(observation.value()));
  DCHECK_GT(NETWORK_QUALITY_OBSERVATION_SOURCE_MAX, observation.source());

  if (!ShouldAddObservation(observation))
    return;

  MaybeUpdateCachedEstimateApplied(
      observation,
      &rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_HTTP]);
  MaybeUpdateCachedEstimateApplied(
      observation,
      &rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_TRANSPORT]);
  ++new_rtt_observations_since_last_ect_computation_;

  std::vector<nqe::internal::ObservationCategory> observation_categories =
      observation.GetObservationCategories();
  for (nqe::internal::ObservationCategory observation_category :
       observation_categories) {
    auto evicted =
        rtt_ms_observations_[observation_category].AddObservation(observation);
    if (evicted) {
      auto delta = base::TimeTicks::Now() - evicted->timestamp();
      base::UmaHistogramLongTimes100(
          base::StrCat({"NQE.RTT.ObservationBufferLifeTime2.",
                        CategoryToString(observation_category)}),
          delta);
      base::UmaHistogramLongTimes100("NQE.RTT.ObservationBufferLifeTime2.All",
                                     delta);
    }
  }

  if (observation.source() == NETWORK_QUALITY_OBSERVATION_SOURCE_TCP ||
      observation.source() == NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC) {
    last_socket_watcher_rtt_notification_ = tick_clock_->NowTicks();
  }

  UMA_HISTOGRAM_ENUMERATION("NQE.RTT.ObservationSource", observation.source(),
                            NETWORK_QUALITY_OBSERVATION_SOURCE_MAX);

  // Maybe recompute the effective connection type since a new RTT observation
  // is available.
  if (observation.source() !=
          NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE &&
      observation.source() !=
          NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE) {
    MaybeComputeEffectiveConnectionType();
  }
  for (auto& observer : rtt_observer_list_) {
    observer.OnRTTObservation(observation.value(), observation.timestamp(),
                              observation.source());
  }
}

void NetworkQualityEstimator::AddAndNotifyObserversOfThroughput(
    const Observation& observation) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_NE(nqe::internal::INVALID_RTT_THROUGHPUT, observation.value());
  DCHECK_GT(NETWORK_QUALITY_OBSERVATION_SOURCE_MAX, observation.source());
  DCHECK_EQ(1u, observation.GetObservationCategories().size());
  DCHECK_EQ(nqe::internal::OBSERVATION_CATEGORY_HTTP,
            observation.GetObservationCategories().front());

  if (!ShouldAddObservation(observation))
    return;

  MaybeUpdateCachedEstimateApplied(
      observation, &http_downstream_throughput_kbps_observations_);
  ++new_throughput_observations_since_last_ect_computation_;
  http_downstream_throughput_kbps_observations_.AddObservation(observation);

  // Maybe recompute the effective connection type since a new throughput
  // observation is available.
  if (observation.source() !=
          NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE &&
      observation.source() !=
          NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE) {
    MaybeComputeEffectiveConnectionType();
  }
  for (auto& observer : throughput_observer_list_) {
    observer.OnThroughputObservation(
        observation.value(), observation.timestamp(), observation.source());
  }
}

void NetworkQualityEstimator::OnNewThroughputObservationAvailable(
    int32_t downstream_kbps) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (downstream_kbps <= 0)
    return;

  DCHECK_NE(nqe::internal::INVALID_RTT_THROUGHPUT, downstream_kbps);

  Observation throughput_observation(downstream_kbps, tick_clock_->NowTicks(),
                                     current_network_id_.signal_strength,
                                     NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP);
  AddAndNotifyObserversOfThroughput(throughput_observation);
}

bool NetworkQualityEstimator::ShouldComputeEffectiveConnectionType() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(nqe::internal::OBSERVATION_CATEGORY_COUNT,
            std::size(rtt_ms_observations_));

  const base::TimeTicks now = tick_clock_->NowTicks();
  // Recompute effective connection type only if
  // |effective_connection_type_recomputation_interval_| has passed since it was
  // last computed or a connection change event was observed since the last
  // computation. Strict inequalities are used to ensure that effective
  // connection type is recomputed on connection change events even if the clock
  // has not updated.
  if (now - last_effective_connection_type_computation_ >=
      effective_connection_type_recomputation_interval_) {
    return true;
  }

  if (last_connection_change_ >= last_effective_connection_type_computation_) {
    return true;
  }

  // Recompute the effective connection type if the previously computed
  // effective connection type was unknown.
  if (effective_connection_type_ == EFFECTIVE_CONNECTION_TYPE_UNKNOWN) {
    return true;
  }

  // Recompute the effective connection type if the number of samples
  // available now are 50% more than the number of samples that were
  // available when the effective connection type was last computed.
  if (rtt_observations_size_at_last_ect_computation_ * 1.5 <
      (rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_HTTP].Size() +
       rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_TRANSPORT]
           .Size())) {
    return true;
  }

  if (throughput_observations_size_at_last_ect_computation_ * 1.5 <
      http_downstream_throughput_kbps_observations_.Size()) {
    return true;
  }

  if ((new_rtt_observations_since_last_ect_computation_ +
       new_throughput_observations_since_last_ect_computation_) >=
      params_->count_new_observations_received_compute_ect()) {
    return true;
  }
  return false;
}

void NetworkQualityEstimator::MaybeComputeEffectiveConnectionType() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!ShouldComputeEffectiveConnectionType())
    return;
  ComputeEffectiveConnectionType();
}

void NetworkQualityEstimator::
    NotifyObserversOfEffectiveConnectionTypeChanged() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_NE(EFFECTIVE_CONNECTION_TYPE_LAST, effective_connection_type_);

  std::optional<net::EffectiveConnectionType> override_ect = GetOverrideECT();

  // TODO(tbansal): Add hysteresis in the notification.
  for (auto& observer : effective_connection_type_observer_list_)
    observer.OnEffectiveConnectionTypeChanged(
        override_ect ? override_ect.value() : effective_connection_type_);
  // Add the estimates of the current network to the cache store.
  network_quality_store_->Add(current_network_id_,
                              nqe::internal::CachedNetworkQuality(
                                  tick_clock_->NowTicks(), network_quality_,
                                  effective_connection_type_));
}

void NetworkQualityEstimator::NotifyObserversOfRTTOrThroughputComputed() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  // TODO(tbansal): Add hysteresis in the notification.
  for (auto& observer : rtt_and_throughput_estimates_observer_list_) {
    observer.OnRTTOrThroughputEstimatesComputed(
        network_quality_.http_rtt(), network_quality_.transport_rtt(),
        network_quality_.downstream_throughput_kbps());
  }
}

void NetworkQualityEstimator::NotifyEffectiveConnectionTypeObserverIfPresent(
    MayBeDangling<EffectiveConnectionTypeObserver> observer) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!effective_connection_type_observer_list_.HasObserver(observer))
    return;

  std::optional<net::EffectiveConnectionType> override_ect = GetOverrideECT();
  if (override_ect) {
    observer->OnEffectiveConnectionTypeChanged(override_ect.value());
    return;
  }
  if (effective_connection_type_ == EFFECTIVE_CONNECTION_TYPE_UNKNOWN)
    return;
  observer->OnEffectiveConnectionTypeChanged(effective_connection_type_);
}

void NetworkQualityEstimator::NotifyPeerToPeerConnectionsCountObserverIfPresent(
    MayBeDangling<PeerToPeerConnectionsCountObserver> observer) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!peer_to_peer_type_observer_list_.HasObserver(observer))
    return;
  observer->OnPeerToPeerConnectionsCountChange(p2p_connections_count_);
}

void NetworkQualityEstimator::NotifyRTTAndThroughputEstimatesObserverIfPresent(
    RTTAndThroughputEstimatesObserver* observer) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!rtt_and_throughput_estimates_observer_list_.HasObserver(observer))
    return;
  observer->OnRTTOrThroughputEstimatesComputed(
      network_quality_.http_rtt(), network_quality_.transport_rtt(),
      network_quality_.downstream_throughput_kbps());
}

void NetworkQualityEstimator::AddNetworkQualitiesCacheObserver(
    nqe::internal::NetworkQualityStore::NetworkQualitiesCacheObserver*
        observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  network_quality_store_->AddNetworkQualitiesCacheObserver(observer);
}

void NetworkQualityEstimator::RemoveNetworkQualitiesCacheObserver(
    nqe::internal::NetworkQualityStore::NetworkQualitiesCacheObserver*
        observer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  network_quality_store_->RemoveNetworkQualitiesCacheObserver(observer);
}

void NetworkQualityEstimator::OnPrefsRead(
    const std::map<nqe::internal::NetworkID,
                   nqe::internal::CachedNetworkQuality> read_prefs) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  for (auto& it : read_prefs) {
    EffectiveConnectionType effective_connection_type =
        it.second.effective_connection_type();
    if (effective_connection_type == EFFECTIVE_CONNECTION_TYPE_UNKNOWN ||
        effective_connection_type == EFFECTIVE_CONNECTION_TYPE_OFFLINE) {
      continue;
    }

    // RTT and throughput values are not set in the prefs.
    DCHECK_EQ(nqe::internal::InvalidRTT(),
              it.second.network_quality().http_rtt());
    DCHECK_EQ(nqe::internal::InvalidRTT(),
              it.second.network_quality().transport_rtt());
    DCHECK_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
              it.second.network_quality().downstream_throughput_kbps());

    nqe::internal::CachedNetworkQuality cached_network_quality(
        tick_clock_->NowTicks(),
        params_->TypicalNetworkQuality(effective_connection_type),
        effective_connection_type);

    network_quality_store_->Add(it.first, cached_network_quality);
  }
  ReadCachedNetworkQualityEstimate();
}

#if BUILDFLAG(IS_CHROMEOS_ASH)
void NetworkQualityEstimator::EnableGetNetworkIdAsynchronously() {
  get_network_id_asynchronously_ = true;
}
#endif  // BUILDFLAG(IS_CHROMEOS_ASH)

std::optional<base::TimeDelta> NetworkQualityEstimator::GetHttpRTT() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (network_quality_.http_rtt() == nqe::internal::InvalidRTT())
    return std::optional<base::TimeDelta>();
  return network_quality_.http_rtt();
}

std::optional<base::TimeDelta> NetworkQualityEstimator::GetTransportRTT()
    const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (network_quality_.transport_rtt() == nqe::internal::InvalidRTT())
    return std::optional<base::TimeDelta>();
  return network_quality_.transport_rtt();
}

std::optional<int32_t> NetworkQualityEstimator::GetDownstreamThroughputKbps()
    const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (network_quality_.downstream_throughput_kbps() ==
      nqe::internal::INVALID_RTT_THROUGHPUT) {
    return std::optional<int32_t>();
  }
  return network_quality_.downstream_throughput_kbps();
}

void NetworkQualityEstimator::MaybeUpdateCachedEstimateApplied(
    const Observation& observation,
    ObservationBuffer* buffer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (observation.source() !=
          NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE &&
      observation.source() !=
          NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE) {
    return;
  }

  cached_estimate_applied_ = true;
  bool deleted_observation_sources[NETWORK_QUALITY_OBSERVATION_SOURCE_MAX] = {
      false};
  deleted_observation_sources
      [NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_HTTP_FROM_PLATFORM] = true;
  deleted_observation_sources
      [NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_TRANSPORT_FROM_PLATFORM] =
          true;

  buffer->RemoveObservationsWithSource(deleted_observation_sources);
}

bool NetworkQualityEstimator::ShouldAddObservation(
    const Observation& observation) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (cached_estimate_applied_ &&
      (observation.source() ==
           NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_HTTP_FROM_PLATFORM ||
       observation.source() ==
           NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_TRANSPORT_FROM_PLATFORM)) {
    return false;
  }
  return true;
}

bool NetworkQualityEstimator::ShouldSocketWatcherNotifyRTT(
    base::TimeTicks now) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return (now - last_socket_watcher_rtt_notification_ >=
          params_->socket_watchers_min_notification_interval());
}

void NetworkQualityEstimator::SimulateNetworkQualityChangeForTesting(
    net::EffectiveConnectionType type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  params_->SetForcedEffectiveConnectionTypeForTesting(type);
  ComputeEffectiveConnectionType();
}

void NetworkQualityEstimator::ForceReportWifiAsSlow2GForTesting() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  force_report_wifi_as_slow_2g_for_testing_ = true;
}

void NetworkQualityEstimator::RecordSpdyPingLatency(
    const HostPortPair& host_port_pair,
    base::TimeDelta rtt) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_LT(nqe::internal::INVALID_RTT_THROUGHPUT, rtt.InMilliseconds());

  Observation observation(rtt.InMilliseconds(), tick_clock_->NowTicks(),
                          current_network_id_.signal_strength,
                          NETWORK_QUALITY_OBSERVATION_SOURCE_H2_PINGS);
  AddAndNotifyObserversOfRTT(observation);
}

void NetworkQualityEstimator::OnPeerToPeerConnectionsCountChange(
    uint32_t count) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (p2p_connections_count_ == count)
    return;

  p2p_connections_count_ = count;

  for (auto& observer : peer_to_peer_type_observer_list_) {
    observer.OnPeerToPeerConnectionsCountChange(p2p_connections_count_);
  }
}

uint32_t NetworkQualityEstimator::GetPeerToPeerConnectionsCountChange() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return p2p_connections_count_;
}

}  // namespace net
```