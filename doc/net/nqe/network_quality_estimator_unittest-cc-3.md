Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of a unit test file for the Chromium network stack. The file is `network_quality_estimator_unittest.cc`.

Here's a breakdown of the user's requests:

1. **List the functionalities:** I need to identify what aspects of the `NetworkQualityEstimator` the code is testing.
2. **Relation to JavaScript:** I need to determine if any of the tested functionalities have a direct counterpart or impact on JavaScript functionality in a web browser.
3. **Logical Reasoning (Input/Output):**  Where the tests involve specific inputs and expected outputs, I should illustrate this.
4. **Common Usage Errors:**  I should identify potential misuses of the `NetworkQualityEstimator` API, either by developers or in the user's environment.
5. **User Operation to Reach Here (Debugging):**  I need to describe how a user's actions in a browser could lead to the execution of this code (although this is a unit test, so it's more about developer workflow).
6. **Summary of Functionality (Part 4 of 4):** This is the final part of a larger context, so I should provide a comprehensive overview of the functionalities demonstrated in *this specific* snippet.

Let's analyze the code snippet to identify these points:

- **Observer Registration:** The code registers different types of observers (`TestRTTObserver`, `TestThroughputObserver`, `TestRTTAndThroughputEstimatesObserver`, `TestEffectiveConnectionTypeObserver`) to the `NetworkQualityEstimator`. This suggests the code is testing the observer pattern and how the estimator notifies observers of network quality changes.
- **Simulating Network Changes:**  The `estimator.SimulateNetworkChange()` method is used, indicating tests around how the estimator reacts to different network connection types and names.
- **Reading Preferences (`OnPrefsRead`):** The code simulates reading network quality preferences and checks if cached values are correctly loaded and used. This includes scenarios where reading preferences is disabled.
- **Discarding Observations:**  The code tests the logic for discarding network quality observations when cached estimates are available.
- **Computing Effective Connection Type (ECT):** The code includes tests for triggering ECT computation based on the number of received RTT samples.
- **Detecting Hanging Requests:**  There are tests for identifying "hanging requests" based on HTTP RTT and potentially end-to-end RTT.
- **Peer-to-Peer Connection Count:** The code tests an observer for changes in the number of peer-to-peer connections.
- **Adjusting HTTP RTT:** A test verifies if HTTP RTT is adjusted based on the count of transport RTT samples.

Now, let's consider the other requirements:

- **JavaScript Relationship:** The Network Quality Estimator directly impacts web page performance and how browsers adapt to varying network conditions. JavaScript can access this information through browser APIs like `navigator.connection.effectiveType`.
- **Logical Reasoning:** The `EXPECT_EQ` and `EXPECT_LE` statements demonstrate the expected outputs based on simulated inputs.
- **Common Usage Errors:**  Misconfiguration of the estimator's parameters or incorrect handling of observer notifications could be common issues.
- **User Operation:** While a user doesn't directly trigger this unit test, their actions (like browsing on different network conditions) lead to the underlying code being executed in a real browser.

Finally, the request emphasizes that this is Part 4 of 4. This suggests the previous parts covered other aspects of the `NetworkQualityEstimator`. I should focus on summarizing the functionalities *within this specific snippet* while acknowledging it's part of a larger testing suite.
这是对 Chromium 网络栈中 `net/nqe/network_quality_estimator_unittest.cc` 文件代码片段的功能归纳，侧重于提供的代码片段本身。

**功能归纳 (基于提供的代码片段):**

这段代码片段主要测试了 `NetworkQualityEstimator` 类在处理网络质量信息缓存（来自 preferences）和根据观察数据进行估计的功能。具体来说，它测试了以下几个方面：

1. **从 Preferences 读取缓存的网络质量信息:**
   - 测试当启用读取缓存时，`NetworkQualityEstimator` 能否正确地从 preferences 中读取并应用之前保存的网络质量信息（RTT 和吞吐量）。
   - 测试当禁用读取缓存时，`NetworkQualityEstimator` 是否不会使用 preferences 中的缓存信息，即使这些信息存在。
   - 测试即使禁用读取缓存，网络质量信息仍然会被写入到内部存储中。

2. **当缓存信息可用时，是否会忽略新的观察数据:**
   - 测试当从 preferences 中加载了有效的缓存网络质量信息后，来自平台或其他外部来源的新的 RTT 和吞吐量观察数据是否会被 `NetworkQualityEstimator` 忽略。这确保了在启动时优先使用缓存的稳定信息。

3. **基于观察样本数量计算有效连接类型 (ECT):**
   - 测试当接收到足够数量的 RTT 样本后，`NetworkQualityEstimator` 是否会触发有效连接类型的重新计算。

4. **检测“挂起”请求 (Hanging Request):**
   - 测试 `NetworkQualityEstimator` 如何基于 HTTP RTT 来判断一个请求是否是“挂起”请求。
   - 测试在使用端到端 RTT 的情况下，如何判断请求是否是“挂起”请求。这涉及到比较 HTTP RTT 和端到端 RTT。
   - 测试在同时有传输层 RTT (Transport RTT) 和 HTTP RTT 的情况下，如何使用传输层 RTT 来辅助判断“挂起”请求。

5. **观察 Peer-to-Peer 连接数量变化:**
   - 测试 `NetworkQualityEstimator` 是否能够通知已注册的观察者关于 Peer-to-Peer 连接数量的变化。

6. **基于 RTT 样本数量调整 HTTP RTT 估计值:**
   - 测试在传输层 RTT 样本数量较少的情况下，是否可以根据配置调整 HTTP RTT 的估计值。

**与 JavaScript 功能的关系:**

`NetworkQualityEstimator` 的核心功能是为 Chromium 提供网络质量的评估，这些评估结果会直接影响浏览器行为，并且可以通过 JavaScript API 暴露给网页开发者。

**举例说明:**

* **有效连接类型 (ECT):**  JavaScript 可以通过 `navigator.connection.effectiveType` 属性获取当前网络的估计连接类型（如 "slow-2g", "2g", "3g", "4g" 等）。这段代码测试了 `NetworkQualityEstimator` 如何计算和更新这个值。例如，当测试代码模拟接收到一定数量的 RTT 样本后，`NetworkQualityEstimator` 内部会重新评估 ECT，而这个新的 ECT 值最终可能会反映到 JavaScript 的 `navigator.connection.effectiveType` 中。
* **资源加载优先级:**  浏览器可以使用 `NetworkQualityEstimator` 提供的网络质量信息来调整资源的加载优先级。例如，在低速网络下，浏览器可能会延迟加载非关键资源。JavaScript 开发者虽然不能直接控制这个过程，但网络质量的评估结果会直接影响他们网页的加载性能。

**逻辑推理的假设输入与输出:**

**场景 1: 从 Preferences 读取缓存，启用读取**

* **假设输入:**
    * `read_prefs` 中包含特定网络 (Wi-Fi, 名称 "test_ect_2g") 的缓存 RTT 和吞吐量信息。
    * 首次模拟连接到该网络。
* **预期输出:**
    * `rtt_observer` 和 `throughput_observer` 的 `observations()` 会包含从缓存中读取的 RTT 和吞吐量值。
    * `effective_connection_type_observer` 会收到从缓存中读取的 ECT 值。
    * `rtt_throughput_observer` 会收到包含缓存 RTT 和吞吐量信息的通知。

**场景 2: 检测挂起请求**

* **假设输入:**
    * `hanging_request_upper_bound_min_http_rtt_msec` 参数设置为 500ms。
    * 观察到的 HTTP RTT 为 600ms。
* **预期输出:**
    * `estimator.IsHangingRequest(base::Milliseconds(600))` 返回 `true`。

**用户或编程常见的使用错误:**

1. **未注册观察者:** 如果开发者忘记将观察者（例如，用于监控 RTT 或吞吐量的类）注册到 `NetworkQualityEstimator`，那么观察者将不会收到任何网络质量更新通知。代码片段中通过 `estimator.AddRTTObserver(&rtt_observer);` 等操作来演示正确的注册方式。
2. **配置参数错误:**  `NetworkQualityEstimator` 的行为受多个配置参数影响。如果开发者配置了错误的参数（例如，错误的挂起请求阈值），可能会导致不符合预期的行为。测试代码通过 `variation_params` 来模拟不同的配置场景。
3. **假设缓存总是存在:**  开发者可能会错误地假设网络质量信息总是能从缓存中读取到。测试代码中包含了禁用缓存读取的场景，提醒开发者需要考虑缓存不存在的情况。

**用户操作如何一步步到达这里 (调试线索):**

尽管这是一个单元测试，用户本身不会直接 "到达" 这里。但是，理解背后的原理有助于调试实际问题：

1. **用户连接到新的 Wi-Fi 网络:**  操作系统会检测到网络变化，Chromium 浏览器会接收到这个通知。
2. **Chromium 查询是否有该网络的缓存质量信息:**  `NetworkQualityEstimator` 可能会尝试从 preferences 中加载该 Wi-Fi 网络的历史 RTT 和吞吐量信息。这段测试代码模拟了这个过程 (`estimator.OnPrefsRead(read_prefs);`)。
3. **用户发起网络请求:**  浏览器会测量请求的 RTT 和吞吐量。
4. **`NetworkQualityEstimator` 接收到新的观察数据:** 这些数据会被用来更新网络质量的估计值，并可能触发 ECT 的重新计算。测试代码模拟了这个过程 (`estimator.AddAndNotifyObserversOfRTT(...)`).
5. **用户遇到加载缓慢或“挂起”的请求:**  `NetworkQualityEstimator` 可能会判断该请求为挂起请求。测试代码模拟了判断挂起请求的逻辑 (`estimator.IsHangingRequest(...)`).
6. **开发者调试网络性能问题:** 开发者可能会查看浏览器的内部状态，例如 `chrome://net-internals/#network-quality`，来了解 `NetworkQualityEstimator` 的评估结果，并可能需要深入到 `network_quality_estimator_unittest.cc` 这样的测试文件中来理解其工作原理。

**总结 (基于提供的代码片段):**

这段代码片段专注于测试 `NetworkQualityEstimator` 如何处理和利用缓存的网络质量信息，以及如何根据实际的网络观察数据（RTT 和吞吐量）进行估计和决策，例如计算有效连接类型和检测挂起请求。它还测试了观察者模式的正确实现，以及在不同配置下 `NetworkQualityEstimator` 的行为。总的来说，这段代码保证了 `NetworkQualityEstimator` 在网络质量评估的核心功能上的正确性和鲁棒性。

### 提示词
```
这是目录为net/nqe/network_quality_estimator_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ughputEstimatesObserver rtt_throughput_observer;
  TestEffectiveConnectionTypeObserver effective_connection_type_observer;
  estimator.AddRTTObserver(&rtt_observer);
  estimator.AddThroughputObserver(&throughput_observer);
  estimator.AddRTTAndThroughputEstimatesObserver(&rtt_throughput_observer);
  estimator.AddEffectiveConnectionTypeObserver(
      &effective_connection_type_observer);

  std::string network_name("test_ect_2g");

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, network_name);
  EXPECT_EQ(0u, rtt_observer.observations().size());
  EXPECT_EQ(0u, throughput_observer.observations().size());
  EXPECT_LE(0, rtt_throughput_observer.notifications_received());

  // Simulate reading of prefs.
  estimator.OnPrefsRead(read_prefs);

  // Taken from network_quality_estimator_params.cc.
  EXPECT_EQ(base::Milliseconds(1800),
            rtt_observer.last_rtt(
                NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE));
  EXPECT_EQ(base::Milliseconds(1500),
            rtt_observer.last_rtt(
                NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE));
  EXPECT_EQ(1u, throughput_observer.observations().size());
  EXPECT_EQ(base::Milliseconds(1800), rtt_throughput_observer.http_rtt());
  EXPECT_EQ(base::Milliseconds(1500), rtt_throughput_observer.transport_rtt());
  EXPECT_EQ(75, rtt_throughput_observer.downstream_throughput_kbps());
  EXPECT_LE(
      1u,
      effective_connection_type_observer.effective_connection_types().size());
  // Compare the ECT stored in prefs with the observer's last entry.
  EXPECT_EQ(
      read_prefs[nqe::internal::NetworkID(
                     NetworkChangeNotifier::CONNECTION_WIFI, network_name,
                     INT32_MIN)]
          .effective_connection_type(),
      effective_connection_type_observer.effective_connection_types().back());

  // Change to a different connection type.
  network_name = "test_ect_slow_2g";
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, network_name);

  EXPECT_EQ(base::Milliseconds(3600),
            rtt_observer.last_rtt(
                NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE));
  EXPECT_EQ(base::Milliseconds(3000),
            rtt_observer.last_rtt(
                NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE));
  EXPECT_EQ(2U, throughput_observer.observations().size());
  EXPECT_EQ(base::Milliseconds(3600), rtt_throughput_observer.http_rtt());
  EXPECT_EQ(base::Milliseconds(3000), rtt_throughput_observer.transport_rtt());
  EXPECT_EQ(40, rtt_throughput_observer.downstream_throughput_kbps());
  EXPECT_LE(
      2u,
      effective_connection_type_observer.effective_connection_types().size());
  // Compare with the last entry.
  EXPECT_EQ(
      read_prefs[nqe::internal::NetworkID(
                     NetworkChangeNotifier::CONNECTION_WIFI, network_name,
                     INT32_MIN)]
          .effective_connection_type(),
      effective_connection_type_observer.effective_connection_types().back());

  // Cleanup.
  estimator.RemoveRTTObserver(&rtt_observer);
  estimator.RemoveThroughputObserver(&throughput_observer);
  estimator.RemoveRTTAndThroughputEstimatesObserver(&rtt_throughput_observer);
  estimator.RemoveEffectiveConnectionTypeObserver(
      &effective_connection_type_observer);
}

// Verify that the cached network qualities from the prefs are not used if the
// reading of the network quality prefs is not enabled..
TEST_F(NetworkQualityEstimatorTest, OnPrefsReadWithReadingDisabled) {

  // Construct the read prefs.
  std::map<nqe::internal::NetworkID, nqe::internal::CachedNetworkQuality>
      read_prefs;
  read_prefs[nqe::internal::NetworkID(NetworkChangeNotifier::CONNECTION_WIFI,
                                      "test_ect_2g", INT32_MIN)] =
      nqe::internal::CachedNetworkQuality(EFFECTIVE_CONNECTION_TYPE_2G);
  read_prefs[nqe::internal::NetworkID(NetworkChangeNotifier::CONNECTION_WIFI,
                                      "test_ect_slow_2g", INT32_MIN)] =
      nqe::internal::CachedNetworkQuality(EFFECTIVE_CONNECTION_TYPE_SLOW_2G);
  read_prefs[nqe::internal::NetworkID(NetworkChangeNotifier::CONNECTION_4G,
                                      "test_ect_4g", INT32_MIN)] =
      nqe::internal::CachedNetworkQuality(EFFECTIVE_CONNECTION_TYPE_4G);

  std::map<std::string, std::string> variation_params;
  variation_params["persistent_cache_reading_enabled"] = "false";
  variation_params["add_default_platform_observations"] = "false";

  // Disable default platform values so that the effect of cached estimates
  // at the time of startup can be studied in isolation.
  TestNetworkQualityEstimator estimator(variation_params, true, true);

  // Add observers.
  TestRTTObserver rtt_observer;
  TestThroughputObserver throughput_observer;
  TestRTTAndThroughputEstimatesObserver rtt_throughput_observer;
  TestEffectiveConnectionTypeObserver effective_connection_type_observer;
  estimator.AddRTTObserver(&rtt_observer);
  estimator.AddThroughputObserver(&throughput_observer);
  estimator.AddRTTAndThroughputEstimatesObserver(&rtt_throughput_observer);
  estimator.AddEffectiveConnectionTypeObserver(
      &effective_connection_type_observer);

  std::string network_name("test_ect_2g");

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, network_name);
  EXPECT_EQ(0u, rtt_observer.observations().size());
  EXPECT_EQ(0u, throughput_observer.observations().size());
  EXPECT_LE(0, rtt_throughput_observer.notifications_received());

  // Simulate reading of prefs.
  estimator.OnPrefsRead(read_prefs);

  // Force read the network quality store from the store to verify that store
  // gets populated even if reading of prefs is not enabled.
  nqe::internal::CachedNetworkQuality cached_network_quality;
  EXPECT_TRUE(estimator.network_quality_store_->GetById(
      nqe::internal::NetworkID(NetworkChangeNotifier::CONNECTION_WIFI,
                               "test_ect_2g", INT32_MIN),
      &cached_network_quality));
  EXPECT_EQ(EFFECTIVE_CONNECTION_TYPE_2G,
            cached_network_quality.effective_connection_type());

  // Taken from network_quality_estimator_params.cc.
  EXPECT_EQ(nqe::internal::InvalidRTT(),
            rtt_observer.last_rtt(
                NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE));
  EXPECT_EQ(nqe::internal::InvalidRTT(),
            rtt_observer.last_rtt(
                NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE));
  EXPECT_EQ(0u, throughput_observer.observations().size());

  EXPECT_EQ(
      0u,
      effective_connection_type_observer.effective_connection_types().size());

  // Change to a different connection type.
  network_name = "test_ect_slow_2g";
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, network_name);

  EXPECT_EQ(nqe::internal::InvalidRTT(),
            rtt_observer.last_rtt(
                NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE));
  EXPECT_EQ(nqe::internal::InvalidRTT(),
            rtt_observer.last_rtt(
                NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE));
  EXPECT_EQ(0U, throughput_observer.observations().size());

  // Cleanup.
  estimator.RemoveRTTObserver(&rtt_observer);
  estimator.RemoveThroughputObserver(&throughput_observer);
  estimator.RemoveRTTAndThroughputEstimatesObserver(&rtt_throughput_observer);
  estimator.RemoveEffectiveConnectionTypeObserver(
      &effective_connection_type_observer);
}

// Verifies that when the cached network qualities from the prefs are available,
// then estimates from the platform or the external estimate provider are not
// used.
TEST_F(NetworkQualityEstimatorTest,
       ObservationDiscardedIfCachedEstimateAvailable) {

  // Construct the read prefs.
  std::map<nqe::internal::NetworkID, nqe::internal::CachedNetworkQuality>
      read_prefs;
  read_prefs[nqe::internal::NetworkID(NetworkChangeNotifier::CONNECTION_WIFI,
                                      "test_2g", INT32_MIN)] =
      nqe::internal::CachedNetworkQuality(EFFECTIVE_CONNECTION_TYPE_2G);

  std::map<std::string, std::string> variation_params;
  variation_params["persistent_cache_reading_enabled"] = "true";
  variation_params["add_default_platform_observations"] = "false";
  // Disable default platform values so that the effect of cached estimates
  // at the time of startup can be studied in isolation.
  TestNetworkQualityEstimator estimator(variation_params, true, true);

  // Add observers.
  TestRTTObserver rtt_observer;
  TestThroughputObserver throughput_observer;
  estimator.AddRTTObserver(&rtt_observer);
  estimator.AddThroughputObserver(&throughput_observer);

  std::string network_name("test_2g");

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, network_name);
  EXPECT_EQ(0u, rtt_observer.observations().size());
  EXPECT_EQ(0u, throughput_observer.observations().size());
  EXPECT_EQ(
      0u,
      estimator
          .rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_TRANSPORT]
          .Size());
  EXPECT_EQ(0u, estimator.http_downstream_throughput_kbps_observations_.Size());

  // Simulate reading of prefs.
  estimator.OnPrefsRead(read_prefs);

  // Taken from network_quality_estimator_params.cc.
  EXPECT_EQ(base::Milliseconds(1800),
            rtt_observer.last_rtt(
                NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE));
  EXPECT_EQ(base::Milliseconds(1500),
            rtt_observer.last_rtt(
                NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE));
  EXPECT_EQ(2u, rtt_observer.observations().size());

  // RTT observation with source
  // DEPRECATED_NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_EXTERNAL_ESTIMATE should
  // be removed from |estimator.rtt_ms_observations_| when a cached estimate is
  // received.
  EXPECT_EQ(
      1u,
      estimator.rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_HTTP]
          .Size());
  EXPECT_EQ(
      1u,
      estimator
          .rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_TRANSPORT]
          .Size());

  // When a cached estimate is available, RTT observations from the external
  // estimate provider and platform must be discarded.
  estimator.AddAndNotifyObserversOfRTT(nqe::internal::Observation(
      1, base::TimeTicks::Now(), INT32_MIN,
      DEPRECATED_NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_EXTERNAL_ESTIMATE));
  estimator.AddAndNotifyObserversOfRTT(nqe::internal::Observation(
      1, base::TimeTicks::Now(), INT32_MIN,
      NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_HTTP_FROM_PLATFORM));
  EXPECT_EQ(3u, rtt_observer.observations().size());
  EXPECT_EQ(
      2u,
      estimator.rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_HTTP]
          .Size());
  EXPECT_EQ(
      1u,
      estimator
          .rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_TRANSPORT]
          .Size());
  estimator.AddAndNotifyObserversOfRTT(
      nqe::internal::Observation(1, base::TimeTicks::Now(), INT32_MIN,
                                 NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  EXPECT_EQ(4u, rtt_observer.observations().size());
  EXPECT_EQ(
      3u,
      estimator.rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_HTTP]
          .Size());
  EXPECT_EQ(
      1u,
      estimator
          .rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_TRANSPORT]
          .Size());

  // When a cached estimate is available, throughput observations from the
  // external estimate provider and platform must be discarded.
  EXPECT_EQ(1u, throughput_observer.observations().size());
  // Throughput observation with source
  // DEPRECATED_NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_EXTERNAL_ESTIMATE should
  // be removed from |estimator.downstream_throughput_kbps_observations_| when a
  // cached estimate is received.
  EXPECT_EQ(1u, estimator.http_downstream_throughput_kbps_observations_.Size());
  estimator.AddAndNotifyObserversOfThroughput(nqe::internal::Observation(
      1, base::TimeTicks::Now(), INT32_MIN,
      DEPRECATED_NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_EXTERNAL_ESTIMATE));
  estimator.AddAndNotifyObserversOfThroughput(nqe::internal::Observation(
      1, base::TimeTicks::Now(), INT32_MIN,
      NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_HTTP_FROM_PLATFORM));
  EXPECT_EQ(2u, throughput_observer.observations().size());
  EXPECT_EQ(2u, estimator.http_downstream_throughput_kbps_observations_.Size());
  estimator.AddAndNotifyObserversOfThroughput(
      nqe::internal::Observation(1, base::TimeTicks::Now(), INT32_MIN,
                                 NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  EXPECT_EQ(3u, throughput_observer.observations().size());
  EXPECT_EQ(3u, estimator.http_downstream_throughput_kbps_observations_.Size());

  base::RunLoop().RunUntilIdle();
}

// Tests that the ECT is computed when more than N RTT samples have been
// received.
TEST_F(NetworkQualityEstimatorTest, MaybeComputeECTAfterNSamples) {
  base::SimpleTestTickClock tick_clock;
  tick_clock.Advance(base::Minutes(1));

  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.DisableOfflineCheckForTesting(true);
  base::RunLoop().RunUntilIdle();
  estimator.SetTickClockForTesting(&tick_clock);
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");
  tick_clock.Advance(base::Minutes(1));

  const base::TimeDelta rtt = base::Seconds(1);
  uint64_t host = 1u;

  // Fill the observation buffer so that ECT computations are not triggered due
  // to observation buffer's size increasing to 1.5x.
  for (size_t i = 0; i < estimator.params()->observation_buffer_size(); ++i) {
    estimator.AddAndNotifyObserversOfRTT(NetworkQualityEstimator::Observation(
        rtt.InMilliseconds(), tick_clock.NowTicks(), INT32_MIN,
        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP, host));
  }
  EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
  tick_clock.Advance(base::Minutes(60));

  const base::TimeDelta rtt_new = base::Seconds(3);
  for (size_t i = 0;
       i < estimator.params()->count_new_observations_received_compute_ect();
       ++i) {
    estimator.AddAndNotifyObserversOfRTT(NetworkQualityEstimator::Observation(
        rtt_new.InMilliseconds(), tick_clock.NowTicks(), INT32_MIN,
        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP, host));
  }
  EXPECT_EQ(rtt_new, estimator.GetHttpRTT().value());
}

// Tests that the hanging request is correctly detected.
TEST_F(NetworkQualityEstimatorTest, HangingRequestUsingHttpOnly) {
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  variation_params["hanging_request_http_rtt_upper_bound_http_rtt_multiplier"] =
      "6";
  variation_params["hanging_request_upper_bound_min_http_rtt_msec"] = "500";

  TestNetworkQualityEstimator estimator(variation_params);

  // 500 msec.
  const int32_t hanging_request_threshold =
      estimator.params()
          ->hanging_request_upper_bound_min_http_rtt()
          .InMilliseconds();

  estimator.SetStartTimeNullHttpRtt(base::Milliseconds(5));
  base::RunLoop().RunUntilIdle();
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");

  const struct {
    base::TimeDelta observed_http_rtt;
  } tests[] = {
      {base::Milliseconds(10)},
      {base::Milliseconds(100)},
      {base::Milliseconds(hanging_request_threshold - 1)},
      {base::Milliseconds(hanging_request_threshold + 1)},
      {base::Milliseconds(1000)},
  };

  for (const auto& test : tests) {
    EXPECT_EQ(
        test.observed_http_rtt.InMilliseconds() >= hanging_request_threshold,
        estimator.IsHangingRequest(test.observed_http_rtt));
  }
}

// Tests that the hanging request is correctly detected using end-to-end RTT.
TEST_F(NetworkQualityEstimatorTest, HangingRequestEndToEndUsingHttpOnly) {
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  variation_params["hanging_request_http_rtt_upper_bound_http_rtt_multiplier"] =
      "6";
  variation_params["hanging_request_upper_bound_min_http_rtt_msec"] = "500";
  variation_params["use_end_to_end_rtt"] = "true";

  int end_to_end_rtt_milliseconds = 1000;
  int hanging_request_http_rtt_upper_bound_transport_rtt_multiplier = 8;

  TestNetworkQualityEstimator estimator(variation_params);
  estimator.SetStartTimeNullHttpRtt(base::Milliseconds(10));

  base::RunLoop().RunUntilIdle();
  estimator.set_start_time_null_end_to_end_rtt(
      base::Milliseconds(end_to_end_rtt_milliseconds));
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");

  const struct {
    base::TimeDelta observed_http_rtt;
    bool is_end_to_end_rtt_sample_count_enough;
    bool expect_hanging_request;
  } tests[] = {
      {base::Milliseconds(10), true, false},
      {base::Milliseconds(10), false, false},
      {base::Milliseconds(100), true, false},
      // |observed_http_rtt| is not large enough. Request is expected to be
      // classified as not hanging.
      {base::Milliseconds(
           (end_to_end_rtt_milliseconds *
            hanging_request_http_rtt_upper_bound_transport_rtt_multiplier) -
           1),
       true, false},
      // |observed_http_rtt| is large. Request is expected to be classified as
      // hanging.
      {base::Milliseconds(
           (end_to_end_rtt_milliseconds *
            hanging_request_http_rtt_upper_bound_transport_rtt_multiplier) +
           1),
       true, true},
      // Not enough end-to-end RTT samples. Request is expected to be classified
      // as hanging.
      {base::Milliseconds(
           end_to_end_rtt_milliseconds *
               hanging_request_http_rtt_upper_bound_transport_rtt_multiplier -
           1),
       false, true},
  };

  for (const auto& test : tests) {
    if (test.is_end_to_end_rtt_sample_count_enough) {
      estimator.set_start_time_null_end_to_end_rtt_observation_count(
          estimator.params()->http_rtt_transport_rtt_min_count());
    } else {
      estimator.set_start_time_null_end_to_end_rtt_observation_count(
          estimator.params()->http_rtt_transport_rtt_min_count() - 1);
    }
    EXPECT_EQ(test.expect_hanging_request,
              estimator.IsHangingRequest(test.observed_http_rtt));
  }
}

TEST_F(NetworkQualityEstimatorTest, HangingRequestUsingTransportAndHttpOnly) {
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  variation_params
      ["hanging_request_http_rtt_upper_bound_transport_rtt_multiplier"] = "8";
  variation_params["hanging_request_http_rtt_upper_bound_http_rtt_multiplier"] =
      "6";
  variation_params["hanging_request_upper_bound_min_http_rtt_msec"] = "500";

  const base::TimeDelta transport_rtt = base::Milliseconds(100);

  TestNetworkQualityEstimator estimator(variation_params);

  // 800 msec.
  const int32_t hanging_request_threshold =
      transport_rtt.InMilliseconds() *
      estimator.params()
          ->hanging_request_http_rtt_upper_bound_transport_rtt_multiplier();

  estimator.DisableOfflineCheckForTesting(true);
  estimator.SetStartTimeNullHttpRtt(base::Milliseconds(5));

  for (size_t i = 0; i < 100; ++i) {
    // Throw enough transport RTT samples so that transport RTT estimate is
    // recomputed.
    estimator.AddAndNotifyObserversOfRTT(NetworkQualityEstimator::Observation(
        transport_rtt.InMilliseconds(), base::TimeTicks::Now(), INT32_MIN,
        NETWORK_QUALITY_OBSERVATION_SOURCE_TCP, 0));
  }

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(transport_rtt, estimator.GetTransportRTT());

  const struct {
    base::TimeDelta observed_http_rtt;
  } tests[] = {
      {base::Milliseconds(100)},
      {base::Milliseconds(500)},
      {base::Milliseconds(hanging_request_threshold - 1)},
      {base::Milliseconds(hanging_request_threshold + 1)},
      {base::Milliseconds(1000)},
  };

  for (const auto& test : tests) {
    EXPECT_EQ(
        test.observed_http_rtt.InMilliseconds() >= hanging_request_threshold,
        estimator.IsHangingRequest(test.observed_http_rtt));
  }
}

TEST_F(NetworkQualityEstimatorTest, TestPeerToPeerConnectionsCountObserver) {
  TestPeerToPeerConnectionsCountObserver observer;
  TestNetworkQualityEstimator estimator;

  EXPECT_EQ(0u, observer.count());
  estimator.OnPeerToPeerConnectionsCountChange(5u);
  base::RunLoop().RunUntilIdle();
  // |observer| has not yet registered with |estimator|.
  EXPECT_EQ(0u, observer.count());

  // |observer| should be notified of the current count on registration.
  estimator.AddPeerToPeerConnectionsCountObserver(&observer);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(5u, observer.count());

  estimator.OnPeerToPeerConnectionsCountChange(3u);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3u, observer.count());
}

// Tests that the HTTP RTT and ECT are adjusted when the count of transport RTTs
// is low. The test adds only HTTP RTT observations and does not add any
// transport RTT observations. Absence of transport RTT observations should
// trigger adjusting of HTTP RTT if param |add_default_platform_observations| is
// set to true.
TEST_F(NetworkQualityEstimatorTest, AdjustHttpRttBasedOnRttCounts) {
  for (const bool adjust_rtt_based_on_rtt_counts : {false, true}) {
    base::SimpleTestTickClock tick_clock;
    tick_clock.Advance(base::Minutes(1));

    std::map<std::string, std::string> variation_params;
    variation_params["add_default_platform_observations"] = "false";

    if (adjust_rtt_based_on_rtt_counts) {
      variation_params["adjust_rtt_based_on_rtt_counts"] = "true";
    }

    TestNetworkQualityEstimator estimator(variation_params);
    estimator.DisableOfflineCheckForTesting(true);
    base::RunLoop().RunUntilIdle();

    base::TimeDelta typical_http_rtt_4g =
        estimator.params()
            ->TypicalNetworkQuality(EFFECTIVE_CONNECTION_TYPE_4G)
            .http_rtt();

    estimator.SetTickClockForTesting(&tick_clock);
    estimator.SimulateNetworkChange(
        NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");
    tick_clock.Advance(base::Minutes(1));

    const base::TimeDelta rtt = base::Seconds(1);
    uint64_t host = 1u;

    // Fill the observation buffer so that ECT computations are not triggered
    // due to observation buffer's size increasing to 1.5x.
    for (size_t i = 0; i < estimator.params()->observation_buffer_size(); ++i) {
      estimator.AddAndNotifyObserversOfRTT(NetworkQualityEstimator::Observation(
          rtt.InMilliseconds(), tick_clock.NowTicks(), INT32_MIN,
          NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP, host));
    }
    // If |adjust_rtt_based_on_rtt_counts| is set, then the HTTP RTT should be
    // that of a typical 4G connection. Otherwise, the RTT estimate should be
    // based only on the RTT of the observations added to the buffer.
    EXPECT_EQ(adjust_rtt_based_on_rtt_counts ? typical_http_rtt_4g : rtt,
              estimator.GetHttpRTT().value());
    tick_clock.Advance(base::Minutes(60));

    const base::TimeDelta rtt_new = base::Seconds(3);
    for (size_t i = 0;
         i < estimator.params()->count_new_observations_received_compute_ect();
         ++i) {
      estimator.AddAndNotifyObserversOfRTT(NetworkQualityEstimator::Observation(
          rtt_new.InMilliseconds(), tick_clock.NowTicks(), INT32_MIN,
          NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP, host));
    }
    EXPECT_EQ(adjust_rtt_based_on_rtt_counts ? typical_http_rtt_4g : rtt_new,
              estimator.GetHttpRTT().value());
  }
}

}  // namespace net
```