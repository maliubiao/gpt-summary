Response:
The user wants a summary of the functionality of the provided C++ code snippet from `network_quality_estimator_unittest.cc`.

Here's a breakdown of the code's purpose and how to structure the answer:

1. **Overall Goal:** The code tests the `NetworkQualityEstimator` class.
2. **Key Functionality Areas:**  Identify the specific aspects of the `NetworkQualityEstimator` being tested in this snippet.
3. **Specific Tests:**  Summarize what each `TEST_F` function verifies.
4. **Relationship to JavaScript:** Analyze if any of the tested functionalities have a direct counterpart or influence on web browser behavior observable in JavaScript.
5. **Logic and Assumptions:**  For tests involving calculations or conditional behavior, identify the inputs and expected outputs.
6. **Potential User/Programming Errors:**  Consider scenarios where incorrect usage or configuration could lead to unexpected results.
7. **User Journey (Debugging Clues):**  Outline how a user's action might trigger the code being tested.
8. **Summary:** Provide a concise overview of the section's purpose.

**Mental Walkthrough of the Code:**

* **`DefaultObservationsOverridden`:** Tests that default network quality values are correctly applied and can be overridden by field trial parameters.
* **`Offline`:**  Verifies that the estimator correctly identifies when the device is offline.
* **`ObtainThresholdsOnlyRTT`:** Checks how effective connection type is determined using only RTT thresholds.
* **`ClampKbpsBasedOnEct`:**  Tests the mechanism for limiting throughput based on the effective connection type.
* **`DefaultHttpRTTBasedThresholds`:**  Verifies that default HTTP RTT thresholds for different connection types are set correctly.
* **`ObtainThresholdsHttpRTTandThroughput`:** Checks how effective connection type is determined using both RTT and throughput thresholds.
* **`TestGetMetricsSince`:**  Tests the ability to retrieve network quality metrics from a specific point in time.
* **`TestThroughputNoRequestOverlap`:**  Examines throughput calculation when requests don't overlap.
* **`TestEffectiveConnectionTypeObserver`:** Tests the notification mechanism for changes in effective connection type.
* **`TestTransportRttUsedForHttpRttComputation`:**  Verifies that transport RTT can influence HTTP RTT estimation.
* **`TestEndToEndRttUsedForHttpRttComputation`:**  Tests how end-to-end RTT is used to bound HTTP RTT.
* **`TestRTTAndThroughputEstimatesObserver`:** Tests the notification mechanism for changes in RTT and throughput estimates.

**Relationship to JavaScript:**  The effective connection type is exposed to JavaScript via the Network Information API (`navigator.connection.effectiveType`). This is a key point to highlight.

**Logic and Assumptions:**  Many tests involve setting specific RTT and throughput values and asserting the resulting effective connection type. Document these input-output relationships.

**User/Programming Errors:** Misconfiguring field trial parameters or relying on outdated network quality information are potential errors.

**User Journey:**  A user browsing the web generates network requests, which provide data for the `NetworkQualityEstimator`. Changes in network conditions or connectivity status will trigger updates and potentially the execution of the tested code.
This部分代码主要集中在对 `NetworkQualityEstimator` 类的功能进行单元测试，特别是关注以下几个方面：

**1. 默认观测值和配置:**

* **功能:** 测试了 `NetworkQualityEstimator` 如何处理默认的网络质量观测值，并且验证了可以通过 Field Trial 参数来覆盖这些默认值。
* **逻辑推理:**
    * **假设输入:** 通过 Field Trial 参数设置了不同网络类型 (Unknown, WiFi, 2G) 的默认中位数 RTT 和吞吐量。
    * **预期输出:**  当模拟网络切换时，`NetworkQualityEstimator` 应该返回在 Field Trial 中配置的对应网络的默认 RTT 和吞吐量。对于没有在 Field Trial 中配置的值，则使用代码中的默认值。
* **用户/编程常见错误:**
    * **错误配置 Field Trial 参数:** 用户可能会错误地配置 Field Trial 参数，例如设置了负的 RTT 值，测试代码验证了这种情况下的处理方式（负值不会被使用）。
    * **期望与实际不符:**  开发者可能期望通过 Field Trial 完全控制所有默认值，但如果某些类型没有配置，则会回退到代码默认值，这可能导致混淆。

**2. 网络离线状态的处理:**

* **功能:** 测试了当设备处于离线状态 (`CONNECTION_NONE`) 时，`NetworkQualityEstimator` 的 `GetEffectiveConnectionType` 方法是否返回 `EFFECTIVE_CONNECTION_TYPE_OFFLINE`。
* **逻辑推理:**
    * **假设输入:**  模拟网络连接状态为 `CONNECTION_NONE`。
    * **预期输出:** `GetEffectiveConnectionType()` 应该返回 `EFFECTIVE_CONNECTION_TYPE_OFFLINE`。

**3. 基于 RTT 阈值判断有效连接类型 (ECT):**

* **功能:** 测试了当只配置了 RTT 阈值时，`NetworkQualityEstimator` 如何根据当前的 RTT 值判断有效的连接类型 (EffectiveConnectionType)。
* **逻辑推理:**
    * **假设输入:**  配置了不同 ECT 等级的 RTT 阈值 (例如，Slow 2G 的 RTT 阈值是 2000ms)。模拟不同的 RTT 值。
    * **预期输出:**  `GetEffectiveConnectionType()` 应该根据当前的 RTT 值落入哪个阈值范围来返回对应的 ECT。
* **用户/编程常见错误:**
    * **阈值配置错误:**  用户可能错误地配置了 RTT 阈值，导致 ECT 判断不准确。
    * **对阈值理解偏差:**  用户可能不清楚阈值的具体含义 (例如，是小于等于还是小于)。

**4. 基于 ECT 限制吞吐量:**

* **功能:** 测试了 `NetworkQualityEstimator` 是否可以根据当前的有效连接类型 (ECT) 来限制最大吞吐量。这通常用于在网络状况较差时避免过高的吞吐量预估。
* **逻辑推理:**
    * **假设输入:**  配置了不同的 ECT 的典型吞吐量上限倍数 (可以通过 Field Trial 参数 `upper_bound_typical_kbps_multiplier` 配置)。设置不同的 RTT 和吞吐量值。
    * **预期输出:**  当实际吞吐量超过基于当前 ECT 和配置倍数计算出的上限时，`GetDownstreamThroughputKbps()` 应该返回上限值。如果配置倍数为 -1，则禁用此限制。
* **用户/编程常见错误:**
    * **对限制逻辑不理解:** 用户可能不明白吞吐量限制的机制，导致对最终吞吐量预估感到困惑。
    * **错误配置上限倍数:** 用户可能会设置不合理的上限倍数，导致吞吐量被过度限制或根本没有限制。

**5. 默认 HTTP RTT 阈值:**

* **功能:** 测试了 `NetworkQualityEstimator` 中不同有效连接类型的默认 HTTP RTT 阈值是否被正确设置。同时测试了如何通过 Field Trial 参数覆盖这些默认值。
* **逻辑推理:**  与第3点类似，测试的是默认阈值和通过 Field Trial 覆盖后的阈值是否生效。

**6. 同时使用 RTT 和吞吐量阈值判断 ECT:**

* **功能:** 测试了当同时配置了 RTT 和吞吐量阈值时，`NetworkQualityEstimator` 如何综合这两个指标来判断有效的连接类型。
* **逻辑推理:**
    * **假设输入:**  配置了 RTT 和吞吐量的阈值。模拟不同的 RTT 和吞吐量组合。
    * **预期输出:** `GetEffectiveConnectionType()` 应该根据 RTT 和吞吐量分别对应的 ECT，并选择其中较差的那个作为最终的 ECT。

**7. 获取指定时间后的网络质量指标:**

* **功能:** 测试了 `GetRecentRTT` 和 `GetRecentDownlinkThroughputKbps` 方法，验证它们能够获取指定时间点之后的最近的网络质量指标。
* **逻辑推理:**
    * **假设输入:**  添加了多个不同时间点的 RTT 和吞吐量观测值。指定一个起始时间。
    * **预期输出:**  方法应该返回起始时间之后最近的观测值。如果起始时间晚于所有观测值的时间，则应该返回表示没有可用数据的状态。

**8. 非重叠请求的吞吐量计算:**

* **功能:** 测试了当本地请求和网络请求不重叠时，`NetworkQualityEstimator` 是否能正确计算吞吐量。
* **与 JavaScript 的关系:**  虽然这个测试是 C++ 层的，但它影响着浏览器如何评估网络性能，最终会影响到 JavaScript 中通过 Network Information API 获取到的网络信息。例如，如果吞吐量计算不准确，`navigator.connection.downlink` 的值可能会不准确，从而影响到基于网络状态的 JavaScript 应用逻辑。
* **逻辑推理:**
    * **假设输入:**  发起一个网络请求，确保在请求期间没有其他请求干扰。
    * **预期输出:**  `NetworkQualityEstimator` 应该能够基于这个独立的请求计算出准确的吞吐量。
* **用户操作如何到达这里:** 用户在浏览器中访问一个网页，该网页发起了一个或多个网络请求来加载资源。这些请求的完成时间会被记录下来，用于计算吞吐量。

**9. 有效连接类型观察者 (Observer):**

* **功能:** 测试了 `NetworkQualityEstimator` 的有效连接类型观察者机制。验证了当有效连接类型发生变化时，注册的观察者能够收到通知。
* **与 JavaScript 的关系:**  `NetworkQualityEstimator` 计算出的有效连接类型最终会通过 Network Information API (特别是 `navigator.connection.effectiveType` 属性) 暴露给 JavaScript。这个测试验证了底层 C++ 代码的有效连接类型变化能够正确地传递到上层。
* **用户操作如何到达这里:** 用户的网络状况发生变化 (例如，从 Wi-Fi 切换到 4G)，或者根据 `NetworkQualityEstimator` 的内部逻辑判断有效连接类型发生了变化。

**10. 使用传输层 RTT 计算 HTTP RTT:**

* **功能:** 测试了 `NetworkQualityEstimator` 在计算 HTTP RTT 时，会考虑传输层 RTT (例如 TCP RTT)。如果传输层 RTT 比 HTTP RTT 大，则会使用传输层 RTT 作为 HTTP RTT 的估计值。
* **逻辑推理:**
    * **假设输入:**  设置不同的 HTTP RTT 和传输层 RTT 值。
    * **预期输出:**  最终的 HTTP RTT 估计值应该取 HTTP RTT 和传输层 RTT 中的较大值。
* **用户操作如何到达这里:** 用户建立 TCP 连接并进行 HTTP 通信。TCP 连接的握手和数据传输会产生传输层 RTT 的观测值，HTTP 请求的完成时间会产生 HTTP RTT 的观测值。

**11. 使用端到端 RTT 计算 HTTP RTT:**

* **功能:** 测试了 `NetworkQualityEstimator` 在计算 HTTP RTT 时，会考虑端到端 RTT。端到端 RTT 可以作为 HTTP RTT 的下限。
* **逻辑推理:**
    * **假设输入:** 设置不同的 HTTP RTT 和端到端 RTT 值，并控制端到端 RTT 样本的数量。
    * **预期输出:** 如果端到端 RTT 样本足够多，且端到端 RTT 大于 HTTP RTT，则最终的 HTTP RTT 估计值会被设置为端到端 RTT。
* **用户操作如何到达这里:**  类似于传输层 RTT，用户的网络请求会产生端到端 RTT 的观测值。

**12. RTT 和吞吐量估计观察者:**

* **功能:** 测试了 `NetworkQualityEstimator` 的 RTT 和吞吐量估计观察者机制，验证了当 RTT 和吞吐量估计值发生变化时，注册的观察者能够收到通知。
* **与 JavaScript 的关系:**  虽然 JavaScript 无法直接订阅 C++ 层的观察者，但 `NetworkQualityEstimator` 的 RTT 和吞吐量估计会影响到 Network Information API 提供的数据。
* **用户操作如何到达这里:**  当 `NetworkQualityEstimator` 接收到新的网络质量观测数据，并更新其内部的 RTT 和吞吐量估计值时，观察者会被通知。

**归纳一下这部分的功能:**

这部分代码主要负责测试 `NetworkQualityEstimator` 类的以下核心功能：

* **初始化和配置:** 测试了如何使用默认值和 Field Trial 参数配置网络质量估计器。
* **基本网络状态判断:** 测试了识别设备是否离线的能力。
* **有效连接类型 (ECT) 推断:**  详细测试了基于 RTT 和吞吐量阈值推断 ECT 的各种情况，包括只使用 RTT 阈值，同时使用 RTT 和吞吐量阈值，以及基于 ECT 限制吞吐量。
* **历史数据处理:** 测试了获取指定时间点后的网络质量指标的能力。
* **异步和独立请求处理:** 测试了在非重叠请求场景下吞吐量计算的正确性。
* **通知机制:** 测试了有效连接类型和网络质量指标变化时的观察者通知机制。
* **RTT 计算逻辑:** 测试了如何使用传输层 RTT 和端到端 RTT 来辅助计算 HTTP RTT。

总的来说，这部分测试用例覆盖了 `NetworkQualityEstimator` 类中关于网络状态判断、有效连接类型推断和基本网络质量指标计算的核心逻辑。

Prompt: 
```
这是目录为net/nqe/network_quality_estimator_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
).at(0).throughput_kbps);
  EXPECT_EQ(NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_HTTP_FROM_PLATFORM,
            throughput_observer.observations().at(0).source);
}

// Verifies that the default observations are added to the set of observations.
// If default observations are overridden using field trial parameters, verify
// that the overriding values are used.
TEST_F(NetworkQualityEstimatorTest, DefaultObservationsOverridden) {
  std::map<std::string, std::string> variation_params;
  variation_params["Unknown.DefaultMedianKbps"] = "100";
  variation_params["WiFi.DefaultMedianKbps"] = "200";
  variation_params["2G.DefaultMedianKbps"] = "250";

  variation_params["Unknown.DefaultMedianRTTMsec"] = "1000";
  variation_params["WiFi.DefaultMedianRTTMsec"] = "2000";
  // Negative variation value should not be used.
  variation_params["2G.DefaultMedianRTTMsec"] = "-5";

  variation_params["Unknown.DefaultMedianTransportRTTMsec"] = "500";
  variation_params["WiFi.DefaultMedianTransportRTTMsec"] = "1000";
  // Negative variation value should not be used.
  variation_params["2G.DefaultMedianTransportRTTMsec"] = "-5";

  TestNetworkQualityEstimator estimator(variation_params, false, false);
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "unknown-1");

  base::TimeDelta rtt;
  int32_t kbps;

  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(base::Milliseconds(1000), rtt);
  EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(base::Milliseconds(500), rtt);
  EXPECT_EQ(rtt, estimator.GetTransportRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  EXPECT_EQ(100, kbps);
  EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());

  // Simulate network change to Wi-Fi.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(base::Milliseconds(2000), rtt);
  EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(base::Milliseconds(1000), rtt);
  EXPECT_EQ(rtt, estimator.GetTransportRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  EXPECT_EQ(200, kbps);
  EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());

  // Simulate network change to 2G. Only the Kbps default estimate should be
  // available.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test-2");
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));
  // Taken from network_quality_estimator_params.cc.
  EXPECT_EQ(base::Milliseconds(1726), rtt);
  EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(base::Milliseconds(1531), rtt);
  EXPECT_EQ(rtt, estimator.GetTransportRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  EXPECT_EQ(250, kbps);
  EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());

  // Simulate network change to 3G. Default estimates should be available.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_3G, "test-3");
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(base::Milliseconds(273), rtt);
  EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(base::Milliseconds(209), rtt);
  EXPECT_EQ(rtt, estimator.GetTransportRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  EXPECT_EQ(749, kbps);
  EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());
}

// Tests that |GetEffectiveConnectionType| returns
// EFFECTIVE_CONNECTION_TYPE_OFFLINE when the device is currently offline.
TEST_F(NetworkQualityEstimatorTest, Offline) {
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);

  const struct {
    NetworkChangeNotifier::ConnectionType connection_type;
    EffectiveConnectionType expected_connection_type;
  } tests[] = {
      {NetworkChangeNotifier::CONNECTION_2G, EFFECTIVE_CONNECTION_TYPE_UNKNOWN},
      {NetworkChangeNotifier::CONNECTION_NONE,
       EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {NetworkChangeNotifier::CONNECTION_3G, EFFECTIVE_CONNECTION_TYPE_UNKNOWN},
  };

  for (const auto& test : tests) {
    estimator.SimulateNetworkChange(test.connection_type, "test");
    EXPECT_EQ(test.expected_connection_type,
              estimator.GetEffectiveConnectionType());
  }
}

// Tests that |GetEffectiveConnectionType| returns correct connection type when
// only RTT thresholds are specified in the variation params.
TEST_F(NetworkQualityEstimatorTest, ObtainThresholdsOnlyRTT) {
  std::map<std::string, std::string> variation_params;

  variation_params["Offline.ThresholdMedianHttpRTTMsec"] = "4000";
  variation_params["Slow2G.ThresholdMedianHttpRTTMsec"] = "2000";
  variation_params["2G.ThresholdMedianHttpRTTMsec"] = "1000";
  variation_params["3G.ThresholdMedianHttpRTTMsec"] = "500";

  TestNetworkQualityEstimator estimator(variation_params);

  // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
  // does not return Offline if the device is offline.
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");

  const struct {
    int32_t rtt_msec;
    EffectiveConnectionType expected_ect;
  } tests[] = {
      {5000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {4000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {3000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {2000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {1500, EFFECTIVE_CONNECTION_TYPE_2G},
      {1000, EFFECTIVE_CONNECTION_TYPE_2G},
      {700, EFFECTIVE_CONNECTION_TYPE_3G},
      {500, EFFECTIVE_CONNECTION_TYPE_3G},
      {400, EFFECTIVE_CONNECTION_TYPE_4G},
      {300, EFFECTIVE_CONNECTION_TYPE_4G},
      {200, EFFECTIVE_CONNECTION_TYPE_4G},
      {100, EFFECTIVE_CONNECTION_TYPE_4G},
      {20, EFFECTIVE_CONNECTION_TYPE_4G},
  };

  for (const auto& test : tests) {
    estimator.set_recent_http_rtt(base::Milliseconds(test.rtt_msec));
    estimator.set_start_time_null_downlink_throughput_kbps(INT32_MAX);
    estimator.set_recent_downlink_throughput_kbps(INT32_MAX);
    estimator.SetStartTimeNullHttpRtt(base::Milliseconds(test.rtt_msec));
    EXPECT_EQ(test.expected_ect, estimator.GetEffectiveConnectionType());
  }
}

TEST_F(NetworkQualityEstimatorTest, ClampKbpsBasedOnEct) {
  const int32_t kTypicalDownlinkKbpsEffectiveConnectionType
      [net::EFFECTIVE_CONNECTION_TYPE_LAST] = {0, 0, 40, 75, 400, 1600};

  const struct {
    std::string upper_bound_typical_kbps_multiplier;
    int32_t set_rtt_msec;
    int32_t set_downstream_kbps;
    EffectiveConnectionType expected_ect;
    int32_t expected_downstream_throughput;
  } tests[] = {
      // Clamping multiplier set to 3.5 by default.
      {"", 3000, INT32_MAX, EFFECTIVE_CONNECTION_TYPE_SLOW_2G,
       base::ClampFloor(kTypicalDownlinkKbpsEffectiveConnectionType
                            [EFFECTIVE_CONNECTION_TYPE_SLOW_2G] *
                        3.5)},
      // Clamping disabled.
      {"-1", 3000, INT32_MAX, EFFECTIVE_CONNECTION_TYPE_SLOW_2G, INT32_MAX},
      // Clamping multiplier overridden to 1000.
      {"1000.0", 3000, INT32_MAX, EFFECTIVE_CONNECTION_TYPE_SLOW_2G,
       kTypicalDownlinkKbpsEffectiveConnectionType
               [EFFECTIVE_CONNECTION_TYPE_SLOW_2G] *
           1000},
      // Clamping multiplier overridden to 1000.
      {"1000.0", 1500, INT32_MAX, EFFECTIVE_CONNECTION_TYPE_2G,
       kTypicalDownlinkKbpsEffectiveConnectionType
               [EFFECTIVE_CONNECTION_TYPE_2G] *
           1000},
      // Clamping multiplier overridden to 1000.
      {"1000.0", 700, INT32_MAX, EFFECTIVE_CONNECTION_TYPE_3G,
       kTypicalDownlinkKbpsEffectiveConnectionType
               [EFFECTIVE_CONNECTION_TYPE_3G] *
           1000},
      // Clamping multiplier set to 3.5 by default.
      {"", 500, INT32_MAX, EFFECTIVE_CONNECTION_TYPE_3G,
       base::ClampFloor(kTypicalDownlinkKbpsEffectiveConnectionType
                            [EFFECTIVE_CONNECTION_TYPE_3G] *
                        3.5)},
      // Clamping ineffective when the observed throughput is lower than the
      // clamped throughput.
      {"", 500, 100, EFFECTIVE_CONNECTION_TYPE_3G, 100},
      // Clamping disabled on 4G ECT.
      {"1.0", 40, INT32_MAX, EFFECTIVE_CONNECTION_TYPE_4G, INT32_MAX},
      // Clamping disabled on 4G ECT.
      {"1.0", 40, 100, EFFECTIVE_CONNECTION_TYPE_4G, 100},
  };

  for (const auto& test : tests) {
    std::map<std::string, std::string> variation_params;
    variation_params["upper_bound_typical_kbps_multiplier"] =
        test.upper_bound_typical_kbps_multiplier;
    TestNetworkQualityEstimator estimator(variation_params);

    // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
    // does not return Offline if the device is offline.
    estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                    "test");

    estimator.set_recent_http_rtt(base::Milliseconds(test.set_rtt_msec));
    estimator.set_start_time_null_downlink_throughput_kbps(INT32_MAX);
    estimator.set_recent_downlink_throughput_kbps(test.set_downstream_kbps);
    estimator.set_start_time_null_downlink_throughput_kbps(
        test.set_downstream_kbps);
    estimator.SetStartTimeNullHttpRtt(base::Milliseconds(test.set_rtt_msec));
    EXPECT_EQ(test.expected_ect, estimator.GetEffectiveConnectionType());
    EXPECT_EQ(test.expected_downstream_throughput,
              estimator.GetDownstreamThroughputKbps().value());
  }
}

// Tests that default HTTP RTT thresholds for different effective
// connection types are correctly set.
TEST_F(NetworkQualityEstimatorTest, DefaultHttpRTTBasedThresholds) {
  const struct {
    bool override_defaults_using_variation_params;
    int32_t http_rtt_msec;
    EffectiveConnectionType expected_ect;
  } tests[] = {
      // When the variation params do not override connection thresholds,
      // default values should be used.
      {false, 5000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {false, 4000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {false, 3000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {false, 2000, EFFECTIVE_CONNECTION_TYPE_2G},
      {false, 1500, EFFECTIVE_CONNECTION_TYPE_2G},
      {false, 1000, EFFECTIVE_CONNECTION_TYPE_3G},
      {false, 100, EFFECTIVE_CONNECTION_TYPE_4G},
      {false, 20, EFFECTIVE_CONNECTION_TYPE_4G},
      // Override default thresholds using variation params.
      {true, 5000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {true, 4000, EFFECTIVE_CONNECTION_TYPE_OFFLINE},
      {true, 3000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {true, 2000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {true, 1500, EFFECTIVE_CONNECTION_TYPE_2G},
      {true, 1000, EFFECTIVE_CONNECTION_TYPE_2G},
      {true, 20, EFFECTIVE_CONNECTION_TYPE_4G},
  };

  for (const auto& test : tests) {
    std::map<std::string, std::string> variation_params;
    if (test.override_defaults_using_variation_params) {
      variation_params["Offline.ThresholdMedianHttpRTTMsec"] = "4000";
      variation_params["Slow2G.ThresholdMedianHttpRTTMsec"] = "2000";
      variation_params["2G.ThresholdMedianHttpRTTMsec"] = "1000";
    }

    TestNetworkQualityEstimator estimator(variation_params);

    // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
    // does not return Offline if the device is offline.
    estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                    "test");

    estimator.SetStartTimeNullHttpRtt(base::Milliseconds(test.http_rtt_msec));
    estimator.set_recent_http_rtt(base::Milliseconds(test.http_rtt_msec));
    estimator.set_start_time_null_downlink_throughput_kbps(INT32_MAX);
    estimator.set_recent_downlink_throughput_kbps(INT32_MAX);
    EXPECT_EQ(test.expected_ect, estimator.GetEffectiveConnectionType());
  }
}

// Tests that |GetEffectiveConnectionType| returns correct connection type when
// both HTTP RTT and throughput thresholds are specified in the variation
// params.
TEST_F(NetworkQualityEstimatorTest, ObtainThresholdsHttpRTTandThroughput) {
  std::map<std::string, std::string> variation_params;

  variation_params["Offline.ThresholdMedianHttpRTTMsec"] = "4000";
  variation_params["Slow2G.ThresholdMedianHttpRTTMsec"] = "2000";
  variation_params["2G.ThresholdMedianHttpRTTMsec"] = "1000";
  variation_params["3G.ThresholdMedianHttpRTTMsec"] = "500";

  TestNetworkQualityEstimator estimator(variation_params);

  // Simulate the connection type as Wi-Fi so that GetEffectiveConnectionType
  // does not return Offline if the device is offline.
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");

  const struct {
    int32_t rtt_msec;
    int32_t downlink_throughput_kbps;
    EffectiveConnectionType expected_ect;
  } tests[] = {
      // Set both RTT and throughput. RTT is the bottleneck.
      {3000, 25000, EFFECTIVE_CONNECTION_TYPE_SLOW_2G},
      {700, 25000, EFFECTIVE_CONNECTION_TYPE_3G},
  };

  for (const auto& test : tests) {
    estimator.SetStartTimeNullHttpRtt(base::Milliseconds(test.rtt_msec));
    estimator.set_recent_http_rtt(base::Milliseconds(test.rtt_msec));
    estimator.set_start_time_null_downlink_throughput_kbps(
        test.downlink_throughput_kbps);
    estimator.set_recent_downlink_throughput_kbps(
        test.downlink_throughput_kbps);
    // Run one main frame request to force recomputation of effective connection
    // type.
    estimator.RunOneRequest();
    EXPECT_EQ(test.expected_ect, estimator.GetEffectiveConnectionType());
  }
}

TEST_F(NetworkQualityEstimatorTest, TestGetMetricsSince) {
  std::map<std::string, std::string> variation_params;

  const base::TimeDelta rtt_threshold_3g = base::Milliseconds(30);
  const base::TimeDelta rtt_threshold_4g = base::Milliseconds(1);

  variation_params["3G.ThresholdMedianHttpRTTMsec"] =
      base::NumberToString(rtt_threshold_3g.InMilliseconds());
  variation_params["HalfLifeSeconds"] = "300000";
  variation_params["add_default_platform_observations"] = "false";

  TestNetworkQualityEstimator estimator(variation_params);
  base::TimeTicks now = base::TimeTicks::Now();
  base::TimeTicks old = now - base::Milliseconds(1);
  ASSERT_NE(old, now);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test");

  const int32_t old_downlink_kbps = 1;
  const base::TimeDelta old_url_rtt = base::Milliseconds(1);
  const base::TimeDelta old_tcp_rtt = base::Milliseconds(10);

  DCHECK_LT(old_url_rtt, rtt_threshold_3g);
  DCHECK_LT(old_tcp_rtt, rtt_threshold_3g);

  // First sample has very old timestamp.
  for (size_t i = 0; i < 2; ++i) {
    estimator.http_downstream_throughput_kbps_observations_.AddObservation(
        NetworkQualityEstimator::Observation(
            old_downlink_kbps, old, INT32_MIN,
            NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
    estimator.rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_HTTP]
        .AddObservation(NetworkQualityEstimator::Observation(
            old_url_rtt.InMilliseconds(), old, INT32_MIN,
            NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
    estimator
        .rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_TRANSPORT]
        .AddObservation(NetworkQualityEstimator::Observation(
            old_tcp_rtt.InMilliseconds(), old, INT32_MIN,
            NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));
  }

  const int32_t new_downlink_kbps = 100;
  const base::TimeDelta new_url_rtt = base::Milliseconds(100);
  const base::TimeDelta new_tcp_rtt = base::Milliseconds(1000);

  DCHECK_NE(old_downlink_kbps, new_downlink_kbps);
  DCHECK_NE(old_url_rtt, new_url_rtt);
  DCHECK_NE(old_tcp_rtt, new_tcp_rtt);
  DCHECK_GT(new_url_rtt, rtt_threshold_3g);
  DCHECK_GT(new_tcp_rtt, rtt_threshold_3g);
  DCHECK_GT(new_url_rtt, rtt_threshold_4g);
  DCHECK_GT(new_tcp_rtt, rtt_threshold_4g);

  estimator.http_downstream_throughput_kbps_observations_.AddObservation(
      NetworkQualityEstimator::Observation(
          new_downlink_kbps, now, INT32_MIN,
          NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  estimator.rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_HTTP]
      .AddObservation(NetworkQualityEstimator::Observation(
          new_url_rtt.InMilliseconds(), now, INT32_MIN,
          NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  estimator.rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_TRANSPORT]
      .AddObservation(NetworkQualityEstimator::Observation(
          new_tcp_rtt.InMilliseconds(), now, INT32_MIN,
          NETWORK_QUALITY_OBSERVATION_SOURCE_TCP));

  const struct {
    base::TimeTicks start_timestamp;
    bool expect_network_quality_available;
    base::TimeDelta expected_http_rtt;
    base::TimeDelta expected_transport_rtt;
    int32_t expected_downstream_throughput;
    EffectiveConnectionType expected_effective_connection_type;
  } tests[] = {
      {now + base::Seconds(10), false, base::Milliseconds(0),
       base::Milliseconds(0), 0, EFFECTIVE_CONNECTION_TYPE_4G},
      {now, true, new_url_rtt, new_tcp_rtt, new_downlink_kbps,
       EFFECTIVE_CONNECTION_TYPE_3G},
      {old - base::Microseconds(500), true, old_url_rtt, old_tcp_rtt,
       old_downlink_kbps, EFFECTIVE_CONNECTION_TYPE_4G},

  };
  for (const auto& test : tests) {
    base::TimeDelta http_rtt;
    base::TimeDelta transport_rtt;
    int32_t downstream_throughput_kbps;
    EXPECT_EQ(test.expect_network_quality_available,
              estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     test.start_timestamp, &http_rtt, nullptr));
    EXPECT_EQ(
        test.expect_network_quality_available,
        estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                               test.start_timestamp, &transport_rtt, nullptr));
    EXPECT_EQ(test.expect_network_quality_available,
              estimator.GetRecentDownlinkThroughputKbps(
                  test.start_timestamp, &downstream_throughput_kbps));

    if (test.expect_network_quality_available) {
      EXPECT_EQ(test.expected_http_rtt, http_rtt);
      EXPECT_EQ(test.expected_transport_rtt, transport_rtt);
      EXPECT_EQ(test.expected_downstream_throughput,
                downstream_throughput_kbps);
    }
  }
}

#if BUILDFLAG(IS_IOS)
// Flaky on iOS: crbug.com/672917.
#define MAYBE_TestThroughputNoRequestOverlap \
  DISABLED_TestThroughputNoRequestOverlap
#else
#define MAYBE_TestThroughputNoRequestOverlap TestThroughputNoRequestOverlap
#endif
// Tests if the throughput observation is taken correctly when local and network
// requests do not overlap.
TEST_F(NetworkQualityEstimatorTest, MAYBE_TestThroughputNoRequestOverlap) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;
  variation_params["throughput_min_requests_in_flight"] = "1";
  variation_params["add_default_platform_observations"] = "false";

  static const struct {
    bool allow_small_localhost_requests;
  } tests[] = {
      {
          false,
      },
      {
          true,
      },
  };

  for (const auto& test : tests) {
    TestNetworkQualityEstimator estimator(variation_params,
                                          test.allow_small_localhost_requests,
                                          test.allow_small_localhost_requests);

    base::TimeDelta rtt;
    EXPECT_FALSE(
        estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                               base::TimeTicks(), &rtt, nullptr));
    int32_t kbps;
    EXPECT_FALSE(
        estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

    TestDelegate test_delegate;
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_network_quality_estimator(&estimator);
    auto context = context_builder->Build();

    std::unique_ptr<URLRequest> request(
        context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                               &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
    request->Start();
    test_delegate.RunUntilComplete();

    // Pump message loop to allow estimator tasks to be processed.
    base::RunLoop().RunUntilIdle();

    EXPECT_EQ(test.allow_small_localhost_requests,
              estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));
    EXPECT_EQ(
        test.allow_small_localhost_requests,
        estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  }
}

#if BUILDFLAG(IS_IOS)
// Flaky on iOS: crbug.com/672917.
#define MAYBE_TestEffectiveConnectionTypeObserver \
  DISABLED_TestEffectiveConnectionTypeObserver
#else
#define MAYBE_TestEffectiveConnectionTypeObserver \
  TestEffectiveConnectionTypeObserver
#endif

// Tests that the effective connection type is computed at the specified
// interval, and that the observers are notified of any change.
TEST_F(NetworkQualityEstimatorTest, MAYBE_TestEffectiveConnectionTypeObserver) {
  base::HistogramTester histogram_tester;
  base::SimpleTestTickClock tick_clock;

  TestEffectiveConnectionTypeObserver observer;
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.AddEffectiveConnectionTypeObserver(&observer);
  // |observer| may be notified as soon as it is added. Run the loop to so that
  // the notification to |observer| is finished.
  base::RunLoop().RunUntilIdle();
  estimator.SetTickClockForTesting(&tick_clock);

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  context_builder->SuppressSettingSocketPerformanceWatcherFactoryForTesting();
  auto context = context_builder->Build();

  EXPECT_EQ(0U, observer.effective_connection_types().size());

  estimator.SetStartTimeNullHttpRtt(base::Milliseconds(1500));
  estimator.set_start_time_null_downlink_throughput_kbps(164);

  tick_clock.Advance(base::Minutes(60));

  std::unique_ptr<URLRequest> request(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request->Start();
  test_delegate.RunUntilComplete();
  EXPECT_EQ(1U, observer.effective_connection_types().size());
  EXPECT_LE(
      1, estimator.GetEntriesCount(NetLogEventType::NETWORK_QUALITY_CHANGED));

  // Verify the contents of the net log.
  EXPECT_EQ(GetNameForEffectiveConnectionType(EFFECTIVE_CONNECTION_TYPE_2G),
            estimator.GetNetLogLastStringValue(
                NetLogEventType::NETWORK_QUALITY_CHANGED,
                "effective_connection_type"));
  EXPECT_EQ(1500, estimator.GetNetLogLastIntegerValue(
                      NetLogEventType::NETWORK_QUALITY_CHANGED, "http_rtt_ms"));
  EXPECT_EQ(-1,
            estimator.GetNetLogLastIntegerValue(
                NetLogEventType::NETWORK_QUALITY_CHANGED, "transport_rtt_ms"));
  EXPECT_EQ(164, estimator.GetNetLogLastIntegerValue(
                     NetLogEventType::NETWORK_QUALITY_CHANGED,
                     "downstream_throughput_kbps"));

  // Next request should not trigger recomputation of effective connection type
  // since there has been no change in the clock.
  std::unique_ptr<URLRequest> request2(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request2->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request2->Start();
  test_delegate.RunUntilComplete();
  EXPECT_EQ(1U, observer.effective_connection_types().size());

  // Change in connection type should send out notification to the observers.
  estimator.SetStartTimeNullHttpRtt(base::Milliseconds(500));
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");
  EXPECT_EQ(3U, observer.effective_connection_types().size());

  // A change in effective connection type does not trigger notification to the
  // observers, since it is not accompanied by any new observation or a network
  // change event.
  estimator.SetStartTimeNullHttpRtt(base::Milliseconds(100));
  EXPECT_EQ(4U, observer.effective_connection_types().size());

  TestEffectiveConnectionTypeObserver observer_2;
  estimator.AddEffectiveConnectionTypeObserver(&observer_2);
  EXPECT_EQ(0U, observer_2.effective_connection_types().size());
  base::RunLoop().RunUntilIdle();
  // |observer_2| must be notified as soon as it is added.
  EXPECT_EQ(1U, observer_2.effective_connection_types().size());

  // |observer_3| should not be notified since it unregisters before the
  // message loop is run.
  TestEffectiveConnectionTypeObserver observer_3;
  estimator.AddEffectiveConnectionTypeObserver(&observer_3);
  EXPECT_EQ(0U, observer_3.effective_connection_types().size());
  estimator.RemoveEffectiveConnectionTypeObserver(&observer_3);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0U, observer_3.effective_connection_types().size());
}

// Tests that the transport RTT is used for computing the HTTP RTT.
TEST_F(NetworkQualityEstimatorTest, TestTransportRttUsedForHttpRttComputation) {
  const struct {
    base::TimeDelta http_rtt;
    base::TimeDelta transport_rtt;
    base::TimeDelta expected_http_rtt;
    EffectiveConnectionType expected_type;
  } tests[] = {
      {
          base::Milliseconds(200),
          base::Milliseconds(100),
          base::Milliseconds(200),
          EFFECTIVE_CONNECTION_TYPE_4G,
      },
      {
          base::Milliseconds(100),
          base::Milliseconds(200),
          base::Milliseconds(200),
          EFFECTIVE_CONNECTION_TYPE_4G,
      },
      {
          base::Milliseconds(100),
          base::Milliseconds(4000),
          base::Milliseconds(4000),
          EFFECTIVE_CONNECTION_TYPE_SLOW_2G,
      },
  };

  for (const auto& test : tests) {
    std::map<std::string, std::string> variation_params;
    variation_params["add_default_platform_observations"] = "false";

    base::SimpleTestTickClock tick_clock;
    tick_clock.Advance(base::Seconds(1));

    TestNetworkQualityEstimator estimator(variation_params);
    estimator.SetTickClockForTesting(&tick_clock);
    estimator.SetStartTimeNullHttpRtt(test.http_rtt);
    estimator.SetStartTimeNullTransportRtt(test.transport_rtt);

    // Minimum number of transport RTT samples that should be present before
    // transport RTT estimate can be used to clamp the HTTP RTT.
    estimator.SetTransportRTTAtastECTSampleCount(
        estimator.params()->http_rtt_transport_rtt_min_count());

    // Add one observation to ensure ECT is not computed for each request.
    estimator.AddAndNotifyObserversOfRTT(NetworkQualityEstimator::Observation(
        test.http_rtt.InMilliseconds(), tick_clock.NowTicks(), INT32_MIN,
        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));

    EXPECT_EQ(test.expected_http_rtt, estimator.GetHttpRTT());
    EXPECT_EQ(test.transport_rtt, estimator.GetTransportRTT());
    EXPECT_EQ(test.expected_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests that the end to end RTT is used for computing the lower bound for HTTP
// RTT.
TEST_F(NetworkQualityEstimatorTest, TestEndToEndRttUsedForHttpRttComputation) {
  const struct {
    base::TimeDelta http_rtt;
    base::TimeDelta end_to_end_rtt;
    bool is_end_to_end_rtt_sample_count_enough;
    base::TimeDelta expected_http_rtt;
    EffectiveConnectionType expected_type;
  } tests[] = {
      {
          base::Milliseconds(200),
          base::Milliseconds(100),
          true,
          base::Milliseconds(200),
          EFFECTIVE_CONNECTION_TYPE_4G,
      },
      {
          // |http_rtt| is lower than |end_to_end_rtt|. The HTTP RTT estimate
          // should be set to |end_to_end_rtt|.
          base::Milliseconds(100),
          base::Milliseconds(200),
          true,
          base::Milliseconds(200),
          EFFECTIVE_CONNECTION_TYPE_4G,
      },
      {
          // Not enough samples. End to End RTT should not be used.
          base::Milliseconds(100),
          base::Milliseconds(200),
          false,
          base::Milliseconds(100),
          EFFECTIVE_CONNECTION_TYPE_4G,
      },
      {
          base::Milliseconds(100),
          base::Milliseconds(4000),
          true,
          base::Milliseconds(4000),
          EFFECTIVE_CONNECTION_TYPE_SLOW_2G,
      },
      {
          // Verify end to end RTT places an upper bound on HTTP RTT when enough
          // samples are present.
          base::Milliseconds(3000),
          base::Milliseconds(100),
          true,
          base::Milliseconds(300),
          EFFECTIVE_CONNECTION_TYPE_3G,
      },
      {
          // Verify end to end RTT does not place an upper bound on HTTP RTT
          // when enough samples are not present.
          base::Milliseconds(3000),
          base::Milliseconds(100),
          false,
          base::Milliseconds(3000),
          EFFECTIVE_CONNECTION_TYPE_SLOW_2G,
      },
  };

  for (const auto& test : tests) {
    std::map<std::string, std::string> variation_params;
    variation_params["add_default_platform_observations"] = "false";
    variation_params["use_end_to_end_rtt"] = "true";

    base::SimpleTestTickClock tick_clock;  // Must outlive `estimator`.
    tick_clock.Advance(base::Seconds(1));

    TestNetworkQualityEstimator estimator(variation_params);
    estimator.SetTickClockForTesting(&tick_clock);
    estimator.SetStartTimeNullHttpRtt(test.http_rtt);
    estimator.set_start_time_null_end_to_end_rtt(test.end_to_end_rtt);

    // Minimum number of end to end RTT samples that should be present before
    // transport RTT estimate can be used to clamp the HTTP RTT.
    if (test.is_end_to_end_rtt_sample_count_enough) {
      estimator.set_start_time_null_end_to_end_rtt_observation_count(
          estimator.params()->http_rtt_transport_rtt_min_count());
    } else {
      estimator.set_start_time_null_end_to_end_rtt_observation_count(
          estimator.params()->http_rtt_transport_rtt_min_count() - 1);
    }

    // Ensure ECT is recomputed.
    estimator.RunOneRequest();

    EXPECT_EQ(test.expected_http_rtt, estimator.GetHttpRTT().value());
    EXPECT_EQ(test.expected_type, estimator.GetEffectiveConnectionType());
  }
}

// Tests that the network quality is computed at the specified interval, and
// that the network quality observers are notified of any change.
TEST_F(NetworkQualityEstimatorTest, TestRTTAndThroughputEstimatesObserver) {
  base::HistogramTester histogram_tester;
  base::SimpleTestTickClock tick_clock;

  TestRTTAndThroughputEstimatesObserver observer;
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.AddRTTAndThroughputEstimatesObserver(&observer);
  estimator.SetTickClockForTesting(&tick_clock);

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  auto context = context_builde
"""


```