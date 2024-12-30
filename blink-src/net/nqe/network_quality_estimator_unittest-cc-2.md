Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Goal:** The primary goal is to analyze a specific part of a C++ unit test file (`network_quality_estimator_unittest.cc`) within the Chromium project. The request asks for its functionality, relationship to JavaScript (if any), logic inference with inputs and outputs, common usage errors, debugging clues, and a summary of its function within the larger context of the file.

2. **Initial Scan and Keyword Identification:** Quickly read through the code snippet, looking for keywords that provide clues about its purpose. Words like `EXPECT_EQ`, `EXPECT_LE`, `SetStartTimeNullHttpRtt`, `SimulateNetworkChange`, `AddRTTAndThroughputEstimatesObserver`, `URLRequest`, etc., immediately jump out. These suggest testing of the `NetworkQualityEstimator` class and its interaction with observers and network conditions.

3. **Identify the Test Case:** The code is part of the `NetworkQualityEstimatorTest` fixture. Within this fixture, there's a specific test function being examined, although the exact function name isn't explicitly stated in the provided snippet. However, the structure (setup with `Build()`, assertions, actions like `SimulateNetworkChange`) indicates a self-contained test case.

4. **Analyze the First Block of Code:**

   * **Setup:** `TestRTTAndThroughputEstimatesObserver observer;` and `estimator_builder.Build();` suggest setting up an observer to track RTT and throughput and building the `NetworkQualityEstimator`.
   * **Initial Assertions:** The `EXPECT_EQ` statements check initial values of `http_rtt`, `transport_rtt`, and `downstream_throughput_kbps` in the observer. This confirms the initial state of the estimator.
   * **Setting Initial Values:** `estimator.SetStartTimeNullHttpRtt(...)`, `estimator.SetStartTimeNullTransportRtt(...)`, and `estimator.set_start_time_null_downlink_throughput_kbps(...)` indicate that the test is setting initial values for these network quality metrics.
   * **Simulating a Request:** The code creates and starts a `URLRequest`. This is a key action that likely triggers the estimator to perform calculations and update its state.
   * **Assertions After Request:** The subsequent `EXPECT_EQ` statements verify that the observer now holds the values previously set on the estimator. This confirms that the estimator propagates the initial values correctly after a network request.
   * **Second Request:** Another `URLRequest` is made. The assertion `EXPECT_LE(1, observer.notifications_received() - notifications_received);` suggests that even without a clock change, the observer should still receive a notification. This likely tests for some background processing or internal state updates.
   * **Network Change Simulation:** `estimator.SimulateNetworkChange(...)` simulates a change in the network connection type. The subsequent assertions verify that the observer still holds the previous values (as a network change *itself* doesn't immediately change RTT/throughput without new observations).
   * **Effective Connection Type Change (Without Notification):**  The lines `estimator.SetStartTimeNullHttpRtt(base::Milliseconds(10000));` and `estimator.SetStartTimeNullHttpRtt(base::Milliseconds(1));` changing the start time HTTP RTT, but the assertion `EXPECT_EQ(2, observer.notifications_received() - notifications_received);` implies these specific actions don't trigger a full notification to the *original* observer. This likely tests internal state updates or thresholds for notification.

5. **Analyze the Second Block of Code (Observer 2 & 3):**

   * **Adding a Second Observer:** `TestRTTAndThroughputEstimatesObserver observer_2;` and `estimator.AddRTTAndThroughputEstimatesObserver(&observer_2);` introduce a new observer. The subsequent assertions and `base::RunLoop().RunUntilIdle();` suggest that newly added observers *do* get the current estimates.
   * **Adding and Removing a Third Observer:** `TestRTTAndThroughputEstimatesObserver observer_3;`, `estimator.AddRTTAndThroughputEstimatesObserver(&observer_3);`, and `estimator.RemoveRTTAndThroughputEstimatesObserver(&observer_3);` test adding and immediately removing an observer. The assertions confirm that this observer *doesn't* receive notifications after being removed, even after the message loop runs.

6. **Identify JavaScript Relevance (or Lack Thereof):**  The code uses C++ constructs (`std::unique_ptr`, `base::TimeDelta`, `EXPECT_EQ`, etc.) and interacts with Chromium's networking stack (`URLRequest`, `NetworkChangeNotifier`). There's no direct indication of JavaScript involvement in this specific test case. The network quality information might *eventually* be exposed to JavaScript for web pages, but this code is focused on the C++ implementation.

7. **Infer Logic and Examples:**

   * **Assumptions:**  The core assumption is that the `NetworkQualityEstimator` class is responsible for tracking and estimating network quality metrics.
   * **Input/Output:**  The example input/output focuses on the initial state, actions (setting values, simulating requests/network changes), and the observed changes in the observer's state.

8. **Identify Common Errors:**  Think about how a developer might misuse the API being tested. Forgetting to add an observer, removing it prematurely, or misinterpreting when notifications are sent are potential errors.

9. **Trace User Actions:** Consider how a user's actions in a browser might lead to this code being executed. Opening a web page, experiencing network changes (Wi-Fi to cellular), and the browser needing to estimate network quality for optimal performance are relevant scenarios.

10. **Synthesize the Summary:** Combine the findings from the analysis into a concise summary of the code's purpose. Focus on the key actions and assertions.

11. **Review and Refine:** Read through the analysis to ensure clarity, accuracy, and completeness. Check if all parts of the request have been addressed. For example, ensure that the "Part 3 of 4" instruction is reflected in the summary's framing.

By following these steps, we can systematically analyze the code snippet and provide a comprehensive response to the user's request. The process involves both careful reading of the code and a deeper understanding of the underlying concepts and the Chromium networking architecture.
这是 `net/nqe/network_quality_estimator_unittest.cc` 文件中 `NetworkQualityEstimatorTest` 测试套件的一部分，主要测试了 `NetworkQualityEstimator` 类在以下方面的功能：

**功能归纳 (基于提供的代码片段):**

* **观察者模式 (RTT和吞吐量):**  测试了如何添加和移除 `RTTAndThroughputEstimatesObserver`，以及当 `NetworkQualityEstimator` 的状态发生变化时，这些观察者是否能正确收到通知。这包括初始状态、网络请求后的更新、网络类型变化后的通知行为。
* **初始空值的设置:** 测试了如何设置初始的 HTTP RTT、传输层 RTT 和下行吞吐量，以及这些初始值如何在第一次网络请求后被观察者获取。
* **重复请求的处理:** 验证了在没有时间推移的情况下，后续的请求是否会触发 RTT 和吞吐量的重新计算。
* **网络变化通知:** 测试了模拟网络连接类型变化 (`SimulateNetworkChange`) 是否会通知观察者。
* **有效连接类型变化的影响:**  验证了单独改变有效连接类型 (没有伴随新的观察或网络变化事件) 是否会触发观察者的通知。
* **观察者的生命周期:**  测试了在消息循环运行前注销的观察者是否不会收到通知。

**与 Javascript 功能的关系：**

虽然这段 C++ 代码本身不直接涉及 Javascript，但 `NetworkQualityEstimator` 的目标是为 Chromium 浏览器提供网络质量的评估信息。这些信息最终可能会被暴露给浏览器的 Javascript 环境，以允许网页开发者根据网络质量优化用户体验。

**举例说明:**

假设网页开发者想根据网络连接速度来动态加载不同质量的图片：

1. **C++ (NetworkQualityEstimator):**  `NetworkQualityEstimator` 通过网络请求、TCP 连接信息等收集数据，计算出当前的 RTT 和吞吐量。
2. **C++ (暴露给渲染进程):** Chromium 会将 `NetworkQualityEstimator` 计算出的网络质量信息（例如，有效连接类型 EffectiveConnectionType）传递给渲染进程。
3. **Javascript (网页):** 网页的 Javascript 代码可以通过 Chromium 提供的 API (可能通过 `navigator.connection` 或其他接口) 获取到这些网络质量信息。
4. **Javascript (逻辑):**  Javascript 代码基于获取到的 `EffectiveConnectionType` 值（例如 "slow-2g", "3g", "4g"），决定加载低分辨率、中等分辨率还是高分辨率的图片。

**逻辑推理与假设输入输出:**

**场景:** 首次启动浏览器，网络连接为 Wi-Fi。

**假设输入:**

* 初始状态下，`NetworkQualityEstimator` 的 RTT 和吞吐量为无效值。
* 设置初始空值的 HTTP RTT 为 100ms，传输层 RTT 为 200ms，下行吞吐量为 300kbps。
* 经过 60 分钟。
* 发起一个网络请求。

**预期输出:**

* 首次请求完成后，观察者 `observer` 的 `http_rtt()` 将变为 100ms。
* 观察者 `observer` 的 `transport_rtt()` 将变为 200ms。
* 观察者 `observer` 的 `downstream_throughput_kbps()` 将变为 300。
* 观察者 `observer` 收到的通知数量至少为 1。

**用户或编程常见的使用错误:**

* **忘记添加观察者:** 用户可能创建了 `NetworkQualityEstimator` 对象，并期望获取网络质量信息，但忘记添加 `RTTAndThroughputEstimatesObserver`，导致无法接收到任何更新通知。
* **过早移除观察者:** 用户可能在需要接收通知的时间段内，错误地移除了观察者，导致部分更新信息丢失。例如，在发起多个请求后立即移除观察者，可能错过后续请求完成时的更新通知。
* **误解通知时机:**  用户可能认为每次调用 `SetStartTimeNullHttpRtt` 等方法会立即通知所有观察者，但实际上，通知可能发生在网络事件发生或满足特定条件时。例如，在代码中看到，单独改变 `StartTimeNullHttpRtt` 两次，第二次才会触发额外的通知。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开浏览器:**  浏览器启动时，网络栈的相关组件会被初始化，包括 `NetworkQualityEstimator`。
2. **用户建立网络连接:**  操作系统和浏览器的网络组件检测到网络连接（例如，连接到 Wi-Fi 网络）。
3. **用户访问网页 (发起网络请求):** 当用户在地址栏输入网址或点击链接时，浏览器会发起 HTTP 请求。
4. **`NetworkQualityEstimator` 收集数据:** 在网络请求过程中，`NetworkQualityEstimator` 会收集 RTT、吞吐量等信息。例如，通过监听 TCP 连接的 ACK 包来估算 RTT。
5. **`NetworkQualityEstimator` 更新状态:**  根据收集到的数据，`NetworkQualityEstimator` 会更新其内部状态，例如更新当前的 RTT 和吞吐量估计值。
6. **通知观察者:** 当 `NetworkQualityEstimator` 的状态发生显著变化时，它会通知已注册的 `RTTAndThroughputEstimatesObserver`。
7. **测试代码模拟上述步骤:** 这段测试代码通过 `CreateTestURLRequestContextBuilder` 创建测试环境，模拟发起网络请求 (`request->Start()`) 和网络状态变化 (`estimator.SimulateNetworkChange`)，并使用 `TestRTTAndThroughputEstimatesObserver` 来验证 `NetworkQualityEstimator` 的行为是否符合预期。

**第 3 部分功能归纳:**

这段代码片段（第 3 部分）主要关注 `NetworkQualityEstimator` 的 **观察者模式** 和 **初始状态设置**。它详细测试了如何添加和移除 `RTTAndThroughputEstimatesObserver`，以及在不同的场景下（首次请求、重复请求、网络变化、有效连接类型变化）观察者是否能正确地接收到 `NetworkQualityEstimator` 发出的通知，并获取到相应的 RTT 和吞吐量信息。 此外，它还测试了初始空值的设置以及重复请求的处理逻辑。

Prompt: 
```
这是目录为net/nqe/network_quality_estimator_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
r->Build();

  EXPECT_EQ(nqe::internal::InvalidRTT(), observer.http_rtt());
  EXPECT_EQ(nqe::internal::InvalidRTT(), observer.transport_rtt());
  EXPECT_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
            observer.downstream_throughput_kbps());
  int notifications_received = observer.notifications_received();
  EXPECT_EQ(0, notifications_received);

  base::TimeDelta http_rtt(base::Milliseconds(100));
  base::TimeDelta transport_rtt(base::Milliseconds(200));
  int32_t downstream_throughput_kbps(300);
  estimator.SetStartTimeNullHttpRtt(http_rtt);
  estimator.SetStartTimeNullTransportRtt(transport_rtt);
  estimator.set_start_time_null_downlink_throughput_kbps(
      downstream_throughput_kbps);
  tick_clock.Advance(base::Minutes(60));

  std::unique_ptr<URLRequest> request(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->Start();
  test_delegate.RunUntilComplete();
  EXPECT_EQ(http_rtt, observer.http_rtt());
  EXPECT_EQ(transport_rtt, observer.transport_rtt());
  EXPECT_EQ(downstream_throughput_kbps, observer.downstream_throughput_kbps());
  EXPECT_LE(1, observer.notifications_received() - notifications_received);
  notifications_received = observer.notifications_received();

  // The next request should not trigger recomputation of RTT or throughput
  // since there has been no change in the clock.
  std::unique_ptr<URLRequest> request2(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request2->Start();
  test_delegate.RunUntilComplete();
  EXPECT_LE(1, observer.notifications_received() - notifications_received);
  notifications_received = observer.notifications_received();

  // A change in the connection type should send out notification to the
  // observers.
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");
  EXPECT_EQ(http_rtt, observer.http_rtt());
  EXPECT_EQ(transport_rtt, observer.transport_rtt());
  EXPECT_EQ(downstream_throughput_kbps, observer.downstream_throughput_kbps());
  EXPECT_LE(1, observer.notifications_received() - notifications_received);
  notifications_received = observer.notifications_received();

  // A change in effective connection type does not trigger notification to the
  // observers, since it is not accompanied by any new observation or a network
  // change event.
  estimator.SetStartTimeNullHttpRtt(base::Milliseconds(10000));
  estimator.SetStartTimeNullHttpRtt(base::Milliseconds(1));
  EXPECT_EQ(2, observer.notifications_received() - notifications_received);

  TestRTTAndThroughputEstimatesObserver observer_2;
  estimator.AddRTTAndThroughputEstimatesObserver(&observer_2);
  EXPECT_EQ(nqe::internal::InvalidRTT(), observer_2.http_rtt());
  EXPECT_EQ(nqe::internal::InvalidRTT(), observer_2.transport_rtt());
  EXPECT_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
            observer_2.downstream_throughput_kbps());
  base::RunLoop().RunUntilIdle();
  EXPECT_NE(nqe::internal::InvalidRTT(), observer_2.http_rtt());
  EXPECT_NE(nqe::internal::InvalidRTT(), observer_2.transport_rtt());
  EXPECT_NE(nqe::internal::INVALID_RTT_THROUGHPUT,
            observer_2.downstream_throughput_kbps());

  // |observer_3| should not be notified because it is unregisters before the
  // message loop is run.
  TestRTTAndThroughputEstimatesObserver observer_3;
  estimator.AddRTTAndThroughputEstimatesObserver(&observer_3);
  EXPECT_EQ(nqe::internal::InvalidRTT(), observer_3.http_rtt());
  EXPECT_EQ(nqe::internal::InvalidRTT(), observer_3.transport_rtt());
  EXPECT_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
            observer_3.downstream_throughput_kbps());
  estimator.RemoveRTTAndThroughputEstimatesObserver(&observer_3);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(nqe::internal::InvalidRTT(), observer_3.http_rtt());
  EXPECT_EQ(nqe::internal::InvalidRTT(), observer_3.transport_rtt());
  EXPECT_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
            observer_3.downstream_throughput_kbps());
}

// Tests that the effective connection type is computed on every RTT
// observation if the last computed effective connection type was unknown.
TEST_F(NetworkQualityEstimatorTest, UnknownEffectiveConnectionType) {
  base::SimpleTestTickClock tick_clock;

  TestEffectiveConnectionTypeObserver observer;
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.SetTickClockForTesting(&tick_clock);
  estimator.AddEffectiveConnectionTypeObserver(&observer);
  tick_clock.Advance(base::Minutes(60));

  size_t expected_effective_connection_type_notifications = 0;
  estimator.set_recent_effective_connection_type(
      EFFECTIVE_CONNECTION_TYPE_UNKNOWN);
  // Run one main frame request to force recomputation of effective connection
  // type.
  estimator.RunOneRequest();
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");

  NetworkQualityEstimator::Observation rtt_observation(
      5000, tick_clock.NowTicks(), INT32_MIN,
      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP);

  for (size_t i = 0; i < 10; ++i) {
    estimator.AddAndNotifyObserversOfRTT(rtt_observation);
    EXPECT_EQ(expected_effective_connection_type_notifications,
              observer.effective_connection_types().size());
  }
  estimator.set_recent_effective_connection_type(
      EFFECTIVE_CONNECTION_TYPE_SLOW_2G);
  // Even though there are 10 RTT samples already available, the addition of one
  // more RTT sample should trigger recomputation of the effective connection
  // type since the last computed effective connection type was unknown.
  estimator.AddAndNotifyObserversOfRTT(NetworkQualityEstimator::Observation(
      5000, tick_clock.NowTicks(), INT32_MIN,
      NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));
  ++expected_effective_connection_type_notifications;
  EXPECT_EQ(expected_effective_connection_type_notifications,
            observer.effective_connection_types().size());
}

// Tests that the effective connection type is computed regularly depending
// on the number of RTT and bandwidth samples.
TEST_F(NetworkQualityEstimatorTest,
       AdaptiveRecomputationEffectiveConnectionType) {
  base::HistogramTester histogram_tester;
  base::SimpleTestTickClock tick_clock;

  TestEffectiveConnectionTypeObserver observer;
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.SetTickClockForTesting(&tick_clock);
  estimator.SimulateNetworkChange(NetworkChangeNotifier::CONNECTION_WIFI,
                                  "test");
  estimator.AddEffectiveConnectionTypeObserver(&observer);
  // |observer| may be notified as soon as it is added. Run the loop to so that
  // the notification to |observer| is finished.
  base::RunLoop().RunUntilIdle();

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  context_builder->SuppressSettingSocketPerformanceWatcherFactoryForTesting();
  auto context = context_builder->Build();

  EXPECT_EQ(0U, observer.effective_connection_types().size());

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_2G);
  tick_clock.Advance(base::Minutes(60));

  std::unique_ptr<URLRequest> request(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request->Start();
  test_delegate.RunUntilComplete();
  EXPECT_EQ(1U, observer.effective_connection_types().size());

  size_t expected_effective_connection_type_notifications = 1;
  EXPECT_EQ(expected_effective_connection_type_notifications,
            observer.effective_connection_types().size());

  EXPECT_EQ(
      expected_effective_connection_type_notifications,
      (estimator.rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_HTTP]
           .Size() +
       estimator
           .rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_TRANSPORT]
           .Size()));

  // Increase the number of RTT observations. Every time the number of RTT
  // observations is more than doubled, effective connection type must be
  // recomputed and notified to observers.
  for (size_t repetition = 0; repetition < 2; ++repetition) {
    // Change the effective connection type so that the observers are
    // notified when the effective connection type is recomputed.
    if (repetition % 2 == 0) {
      estimator.set_recent_effective_connection_type(
          EFFECTIVE_CONNECTION_TYPE_SLOW_2G);
    } else {
      estimator.set_recent_effective_connection_type(
          EFFECTIVE_CONNECTION_TYPE_3G);
    }
    size_t rtt_observations_count =
        (estimator
             .rtt_ms_observations_[nqe::internal::OBSERVATION_CATEGORY_HTTP]
             .Size() +
         estimator
             .rtt_ms_observations_
                 [nqe::internal::OBSERVATION_CATEGORY_TRANSPORT]
             .Size()) *
        0.5;
    // Increase the number of RTT observations to more than twice the number
    // of current observations. This should trigger recomputation of
    // effective connection type.
    for (size_t i = 0; i < rtt_observations_count + 1; ++i) {
      estimator.AddAndNotifyObserversOfRTT(NetworkQualityEstimator::Observation(
          5000, tick_clock.NowTicks(), INT32_MIN,
          NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP));

      if (i == rtt_observations_count) {
        // Effective connection type must be recomputed since the number of RTT
        // samples are now more than twice the number of RTT samples that were
        // available when effective connection type was last computed.
        ++expected_effective_connection_type_notifications;
      }
      EXPECT_EQ(expected_effective_connection_type_notifications,
                observer.effective_connection_types().size());
    }
  }
}

TEST_F(NetworkQualityEstimatorTest, TestRttThroughputObservers) {
  base::HistogramTester histogram_tester;
  TestRTTObserver rtt_observer;
  TestThroughputObserver throughput_observer;

  std::map<std::string, std::string> variation_params;
  variation_params["throughput_min_requests_in_flight"] = "1";
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);

  estimator.AddRTTObserver(&rtt_observer);
  estimator.AddThroughputObserver(&throughput_observer);

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  context_builder->SuppressSettingSocketPerformanceWatcherFactoryForTesting();
  auto context = context_builder->Build();

  EXPECT_EQ(0U, rtt_observer.observations().size());
  EXPECT_EQ(0U, throughput_observer.observations().size());
  base::TimeTicks then = base::TimeTicks::Now();

  std::unique_ptr<URLRequest> request(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request->Start();
  test_delegate.RunUntilComplete();

  std::unique_ptr<URLRequest> request2(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request2->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request2->Start();
  test_delegate.RunUntilComplete();

  // Pump message loop to allow estimator tasks to be processed.
  base::RunLoop().RunUntilIdle();

  // Both RTT and downstream throughput should be updated.
  base::TimeDelta rtt;
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));

  int32_t throughput;
  EXPECT_TRUE(estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(),
                                                        &throughput));

  EXPECT_EQ(2U, rtt_observer.observations().size());
  EXPECT_EQ(2U, throughput_observer.observations().size());
  for (const auto& observation : rtt_observer.observations()) {
    EXPECT_LE(0, observation.rtt_ms);
    EXPECT_LE(0, (observation.timestamp - then).InMilliseconds());
    EXPECT_EQ(NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP, observation.source);
  }
  for (const auto& observation : throughput_observer.observations()) {
    EXPECT_LE(0, observation.throughput_kbps);
    EXPECT_LE(0, (observation.timestamp - then).InMilliseconds());
    EXPECT_EQ(NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP, observation.source);
  }

  EXPECT_FALSE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));

  // Verify that observations from TCP and QUIC are passed on to the observers.
  base::TimeDelta tcp_rtt(base::Milliseconds(1));
  base::TimeDelta quic_rtt(base::Milliseconds(2));

  // Use a public IP address so that the socket watcher runs the RTT callback.
  IPAddress ip_address;
  ASSERT_TRUE(ip_address.AssignFromIPLiteral("157.0.0.1"));

  std::unique_ptr<SocketPerformanceWatcher> tcp_watcher =
      estimator.GetSocketPerformanceWatcherFactory()
          ->CreateSocketPerformanceWatcher(
              SocketPerformanceWatcherFactory::PROTOCOL_TCP, ip_address);

  std::unique_ptr<SocketPerformanceWatcher> quic_watcher =
      estimator.GetSocketPerformanceWatcherFactory()
          ->CreateSocketPerformanceWatcher(
              SocketPerformanceWatcherFactory::PROTOCOL_QUIC, ip_address);

  tcp_watcher->OnUpdatedRTTAvailable(tcp_rtt);
  // First RTT sample from QUIC connections is dropped, but the second RTT
  // notification should not be dropped.
  quic_watcher->OnUpdatedRTTAvailable(quic_rtt);
  quic_watcher->OnUpdatedRTTAvailable(quic_rtt);

  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(4U, rtt_observer.observations().size());
  EXPECT_EQ(2U, throughput_observer.observations().size());

  EXPECT_EQ(tcp_rtt.InMilliseconds(), rtt_observer.observations().at(2).rtt_ms);
  EXPECT_EQ(quic_rtt.InMilliseconds(),
            rtt_observer.observations().at(3).rtt_ms);

  EXPECT_TRUE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));

  EXPECT_EQ(quic_rtt, estimator.end_to_end_rtt_.value());
  EXPECT_LT(
      0u, estimator.end_to_end_rtt_observation_count_at_last_ect_computation_);
}

TEST_F(NetworkQualityEstimatorTest, TestGlobalSocketWatcherThrottle) {
  base::SimpleTestTickClock tick_clock;
  tick_clock.Advance(base::Seconds(1));

  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.SetTickClockForTesting(&tick_clock);

  TestRTTObserver rtt_observer;
  estimator.AddRTTObserver(&rtt_observer);

  const base::TimeDelta tcp_rtt(base::Milliseconds(1));

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  context_builder->SuppressSettingSocketPerformanceWatcherFactoryForTesting();
  auto context = context_builder->Build();

  // Use a public IP address so that the socket watcher runs the RTT callback.
  IPAddress ip_address;
  ASSERT_TRUE(ip_address.AssignFromIPLiteral("157.0.0.1"));
  std::unique_ptr<SocketPerformanceWatcher> tcp_watcher =
      estimator.GetSocketPerformanceWatcherFactory()
          ->CreateSocketPerformanceWatcher(
              SocketPerformanceWatcherFactory::PROTOCOL_TCP, ip_address);

  EXPECT_EQ(0U, rtt_observer.observations().size());
  EXPECT_TRUE(tcp_watcher->ShouldNotifyUpdatedRTT());
  std::unique_ptr<URLRequest> request(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request->Start();
  test_delegate.RunUntilComplete();
  EXPECT_EQ(1U, rtt_observer.observations().size());
  EXPECT_TRUE(tcp_watcher->ShouldNotifyUpdatedRTT());

  tcp_watcher->OnUpdatedRTTAvailable(tcp_rtt);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(tcp_watcher->ShouldNotifyUpdatedRTT());
  EXPECT_EQ(2U, rtt_observer.observations().size());
  // Advancing the clock should make it possible to notify new RTT
  // notifications.
  tick_clock.Advance(
      estimator.params()->socket_watchers_min_notification_interval());
  EXPECT_TRUE(tcp_watcher->ShouldNotifyUpdatedRTT());

  EXPECT_EQ(tcp_rtt.InMilliseconds(), rtt_observer.observations().at(1).rtt_ms);
  base::TimeDelta rtt;
  EXPECT_TRUE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));
}

// TestTCPSocketRTT requires kernel support for tcp_info struct, and so it is
// enabled only on certain platforms.
// ChromeOS is disabled due to crbug.com/986904
// TODO(crbug.com/40118868): Revisit once build flag switch of lacros-chrome is
// complete.
#if (defined(TCP_INFO) ||                                      \
     (BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS_LACROS)) || \
     BUILDFLAG(IS_ANDROID)) &&                                 \
    !BUILDFLAG(IS_CHROMEOS)
#define MAYBE_TestTCPSocketRTT TestTCPSocketRTT
#else
#define MAYBE_TestTCPSocketRTT DISABLED_TestTCPSocketRTT
#endif
// Tests that the TCP socket notifies the Network Quality Estimator of TCP RTTs,
// which in turn notifies registered RTT observers.
TEST_F(NetworkQualityEstimatorTest, MAYBE_TestTCPSocketRTT) {
  base::SimpleTestTickClock tick_clock;
  tick_clock.Advance(base::Seconds(1));

  base::HistogramTester histogram_tester;
  TestRTTObserver rtt_observer;

  std::map<std::string, std::string> variation_params;
  variation_params["persistent_cache_reading_enabled"] = "true";
  variation_params["throughput_min_requests_in_flight"] = "1";
  TestNetworkQualityEstimator estimator(variation_params, true, true);
  estimator.SetTickClockForTesting(&tick_clock);
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test");

  estimator.AddRTTObserver(&rtt_observer);
  // |observer| may be notified as soon as it is added. Run the loop to so that
  // the notification to |observer| is finished.
  base::RunLoop().RunUntilIdle();

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  auto context = context_builder->Build();

  EXPECT_EQ(0U, rtt_observer.observations().size());
  base::TimeDelta rtt;
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(rtt, estimator.GetTransportRTT().value());

  // Send two requests. Verify that the completion of each request generates at
  // least one TCP RTT observation.
  const size_t num_requests = 2;
  for (size_t i = 0; i < num_requests; ++i) {
    size_t before_count_tcp_rtt_observations = 0;
    for (const auto& observation : rtt_observer.observations()) {
      if (observation.source == NETWORK_QUALITY_OBSERVATION_SOURCE_TCP)
        ++before_count_tcp_rtt_observations;
    }

    std::unique_ptr<URLRequest> request(
        context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                               &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
    request->Start();
    tick_clock.Advance(
        estimator.params()->socket_watchers_min_notification_interval());

    test_delegate.RunUntilComplete();

    size_t after_count_tcp_rtt_observations = 0;
    for (const auto& observation : rtt_observer.observations()) {
      if (observation.source == NETWORK_QUALITY_OBSERVATION_SOURCE_TCP)
        ++after_count_tcp_rtt_observations;
    }
    // At least one notification should be received per socket performance
    // watcher.
    EXPECT_LE(1U, after_count_tcp_rtt_observations -
                      before_count_tcp_rtt_observations)
        << i;
  }
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));
  EXPECT_NE(nqe::internal::InvalidRTT(), estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(rtt, estimator.GetTransportRTT().value());

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");

  ExpectBucketCountAtLeast(&histogram_tester, "NQE.RTT.ObservationSource",
                           NETWORK_QUALITY_OBSERVATION_SOURCE_TCP, 1);
  EXPECT_LE(1u,
            histogram_tester.GetAllSamples("NQE.RTT.OnECTComputation").size());

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test");
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource",
      NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE, 1);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource",
      NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE, 2);
}

class TestNetworkQualitiesCacheObserver
    : public nqe::internal::NetworkQualityStore::NetworkQualitiesCacheObserver {
 public:
  TestNetworkQualitiesCacheObserver()
      : network_id_(net::NetworkChangeNotifier::CONNECTION_UNKNOWN,
                    std::string(),
                    INT32_MIN) {}

  TestNetworkQualitiesCacheObserver(const TestNetworkQualitiesCacheObserver&) =
      delete;
  TestNetworkQualitiesCacheObserver& operator=(
      const TestNetworkQualitiesCacheObserver&) = delete;

  ~TestNetworkQualitiesCacheObserver() override = default;

  void OnChangeInCachedNetworkQuality(
      const nqe::internal::NetworkID& network_id,
      const nqe::internal::CachedNetworkQuality& cached_network_quality)
      override {
    network_id_ = network_id;
    notification_received_++;
  }

  size_t get_notification_received_and_reset() {
    size_t notification_received = notification_received_;
    notification_received_ = 0;
    return notification_received;
  }

  nqe::internal::NetworkID network_id() const { return network_id_; }

 private:
  nqe::internal::NetworkID network_id_;
  size_t notification_received_ = 0;
};

TEST_F(NetworkQualityEstimatorTest, CacheObserver) {
  TestNetworkQualitiesCacheObserver observer;
  TestNetworkQualityEstimator estimator;

  // Add |observer| as a persistent caching observer.
  estimator.AddNetworkQualitiesCacheObserver(&observer);

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_3G);
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test3g");
  estimator.RunOneRequest();
  EXPECT_EQ(4u, observer.get_notification_received_and_reset());
  EXPECT_EQ("test3g", observer.network_id().id);

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_2G);
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test2g");
  // One notification should be received for the previous network
  // ("test3g") right before the connection change event. The second
  // notification should be received for the second network ("test2g").
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2u, observer.get_notification_received_and_reset());
  estimator.RunOneRequest();
  EXPECT_EQ("test2g", observer.network_id().id);

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_4G);
  // Start multiple requests, but there should be only one notification
  // received, since the effective connection type does not change.
  estimator.RunOneRequest();
  estimator.RunOneRequest();
  estimator.RunOneRequest();
  EXPECT_EQ(1u, observer.get_notification_received_and_reset());

  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_2G);
  estimator.RunOneRequest();
  EXPECT_EQ(1u, observer.get_notification_received_and_reset());

  // Remove |observer|, and it should not receive any notifications.
  estimator.RemoveNetworkQualitiesCacheObserver(&observer);
  estimator.set_recent_effective_connection_type(EFFECTIVE_CONNECTION_TYPE_3G);
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test2g");
  EXPECT_EQ(0u, observer.get_notification_received_and_reset());
  estimator.RunOneRequest();
  EXPECT_EQ(0u, observer.get_notification_received_and_reset());
}

// Tests that the value of the effective connection type can be forced through
// field trial parameters.
TEST_F(NetworkQualityEstimatorTest,
       ForceEffectiveConnectionTypeThroughFieldTrial) {
  for (int i = 0; i < EFFECTIVE_CONNECTION_TYPE_LAST; ++i) {
    EffectiveConnectionType ect_type = static_cast<EffectiveConnectionType>(i);
    std::map<std::string, std::string> variation_params;
    variation_params[kForceEffectiveConnectionType] =
        GetNameForEffectiveConnectionType(
            static_cast<EffectiveConnectionType>(i));
    TestNetworkQualityEstimator estimator(variation_params);

    TestEffectiveConnectionTypeObserver ect_observer;
    estimator.AddEffectiveConnectionTypeObserver(&ect_observer);
    TestRTTAndThroughputEstimatesObserver rtt_throughput_observer;
    estimator.AddRTTAndThroughputEstimatesObserver(&rtt_throughput_observer);
    // |observer| may be notified as soon as it is added. Run the loop to so
    // that the notification to |observer| is finished.
    base::RunLoop().RunUntilIdle();

    TestDelegate test_delegate;
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_network_quality_estimator(&estimator);
    auto context = context_builder->Build();

    if (ect_type == EFFECTIVE_CONNECTION_TYPE_UNKNOWN) {
      EXPECT_EQ(0U, ect_observer.effective_connection_types().size());
    } else {
      EXPECT_EQ(1U, ect_observer.effective_connection_types().size());
    }

    std::unique_ptr<URLRequest> request(
        context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                               &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
    request->Start();
    test_delegate.RunUntilComplete();

    // Pump message loop to allow estimator tasks to be processed.
    base::RunLoop().RunUntilIdle();

    EXPECT_EQ(i, estimator.GetEffectiveConnectionType());

    size_t expected_count =
        ect_type == EFFECTIVE_CONNECTION_TYPE_UNKNOWN ? 0 : 1;
    ASSERT_EQ(expected_count, ect_observer.effective_connection_types().size());
    if (expected_count == 1) {
      EffectiveConnectionType last_notified_type =
          ect_observer.effective_connection_types().at(
              ect_observer.effective_connection_types().size() - 1);
      EXPECT_EQ(i, last_notified_type);

      if (ect_type == EFFECTIVE_CONNECTION_TYPE_UNKNOWN ||
          ect_type == EFFECTIVE_CONNECTION_TYPE_OFFLINE) {
        EXPECT_EQ(nqe::internal::InvalidRTT(),
                  rtt_throughput_observer.http_rtt());
        EXPECT_EQ(nqe::internal::InvalidRTT(),
                  rtt_throughput_observer.transport_rtt());
        EXPECT_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
                  rtt_throughput_observer.downstream_throughput_kbps());
      } else {
        EXPECT_EQ(estimator.params_->TypicalNetworkQuality(ect_type).http_rtt(),
                  rtt_throughput_observer.http_rtt());
        EXPECT_EQ(
            estimator.params_->TypicalNetworkQuality(ect_type).transport_rtt(),
            rtt_throughput_observer.transport_rtt());
        EXPECT_EQ(estimator.params_->TypicalNetworkQuality(ect_type)
                      .downstream_throughput_kbps(),
                  rtt_throughput_observer.downstream_throughput_kbps());
      }
    }
  }
}

// Tests that the value of the effective connection type can be forced after
// network quality estimator has been initialized.
TEST_F(NetworkQualityEstimatorTest, SimulateNetworkQualityChangeForTesting) {
  for (int i = 0; i < EFFECTIVE_CONNECTION_TYPE_LAST; ++i) {
    EffectiveConnectionType ect_type = static_cast<EffectiveConnectionType>(i);
    TestNetworkQualityEstimator estimator;

    TestEffectiveConnectionTypeObserver ect_observer;
    estimator.AddEffectiveConnectionTypeObserver(&ect_observer);

    // |observer| may be notified as soon as it is added. Run the loop to so
    // that the notification to |observer| is finished.
    base::RunLoop().RunUntilIdle();

    TestDelegate test_delegate;
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_network_quality_estimator(&estimator);
    auto context = context_builder->Build();
    estimator.SimulateNetworkQualityChangeForTesting(ect_type);
    base::RunLoop().RunUntilIdle();

    EXPECT_EQ(ect_type, ect_observer.effective_connection_types().back());
  }
}

// Test that the typical network qualities are set correctly.
TEST_F(NetworkQualityEstimatorTest, TypicalNetworkQualities) {
  TestNetworkQualityEstimator estimator;
  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  auto context = context_builder->Build();

  for (size_t effective_connection_type = EFFECTIVE_CONNECTION_TYPE_SLOW_2G;
       effective_connection_type <= EFFECTIVE_CONNECTION_TYPE_4G;
       ++effective_connection_type) {
    // Set the RTT and throughput values to the typical values for
    // |effective_connection_type|. The effective connection type should be
    // computed as |effective_connection_type|.
    estimator.SetStartTimeNullHttpRtt(
        estimator.params_
            ->TypicalNetworkQuality(
                static_cast<EffectiveConnectionType>(effective_connection_type))
            .http_rtt());
    estimator.set_start_time_null_downlink_throughput_kbps(INT32_MAX);
    estimator.SetStartTimeNullTransportRtt(
        estimator.params_
            ->TypicalNetworkQuality(
                static_cast<EffectiveConnectionType>(effective_connection_type))
            .transport_rtt());

    EXPECT_EQ(effective_connection_type,
              static_cast<size_t>(estimator.GetEffectiveConnectionType()));
  }
}

// Verify that the cached network qualities from the prefs are correctly used.
TEST_F(NetworkQualityEstimatorTest, OnPrefsRead) {

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
  variation_params["persistent_cache_reading_enabled"] = "true";
  variation_params["add_default_platform_observations"] = "false";
  // Disable default platform values so that the effect of cached estimates
  // at the time of startup can be studied in isolation.
  TestNetworkQualityEstimator estimator(variation_params, true, true);

  // Add observers.
  TestRTTObserver rtt_observer;
  TestThroughputObserver throughput_observer;
  TestRTTAndThro
"""


```