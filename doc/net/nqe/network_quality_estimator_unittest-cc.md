Response:
The user wants a summary of the functionality of the C++ source code file `net/nqe/network_quality_estimator_unittest.cc`.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file name `network_quality_estimator_unittest.cc` strongly suggests it's a unit test file for the `NetworkQualityEstimator` class.

2. **Scan the includes:** The included headers provide clues about the functionalities being tested. Look for key classes and concepts like:
    - `network_quality_estimator.h`: The class being tested.
    - `effective_connection_type.h`, `effective_connection_type_observer.h`: Testing the observation and handling of effective connection type.
    - `rtt_throughput_estimates_observer.h`: Testing the observation of RTT and throughput estimates.
    - `socket_performance_watcher.h`, `socket_performance_watcher_factory.h`:  Relates to observing socket performance for network quality.
    - `url_request/`:  Indicates testing interactions with network requests.
    - `base/test/`: Includes testing utilities.
    - `testing/gtest/include/gtest/gtest.h`:  Confirms it's using Google Test framework.

3. **Analyze the test cases (TEST_F blocks):** Each `TEST_F` function focuses on testing a specific aspect of the `NetworkQualityEstimator`. Summarize the purpose of each test case.

4. **Look for custom test classes:** Classes like `TestEffectiveConnectionTypeObserver`, `TestPeerToPeerConnectionsCountObserver`, `TestRTTAndThroughputEstimatesObserver`, `TestRTTObserver`, and `TestThroughputObserver` are mock or stub implementations used for verifying the behavior of the `NetworkQualityEstimator`. Note their roles.

5. **Identify key actions being tested:**  Look for calls to methods of the `NetworkQualityEstimator` and assertions (`EXPECT_*`). This will reveal what functionality is being exercised. Common actions include:
    - Adding/removing observers.
    - Simulating network changes.
    - Making network requests.
    - Receiving RTT and throughput updates.
    - Checking cached data.
    - Verifying histogram updates (using `base::HistogramTester`).

6. **Address specific requirements in the prompt:**
    - **Javascript relation:** Consider if any tested functionality directly relates to how network quality information might be exposed to Javascript (e.g., through APIs).
    - **Logical reasoning:** Identify test cases that set up specific conditions and verify expected outcomes based on the estimator's logic.
    - **User/programming errors:** Think about common mistakes a user or developer might make when interacting with or configuring network quality estimation, and if any tests implicitly cover these.
    - **User operation to reach here:** Consider the browser's internal workings and how user actions might trigger the network quality estimation logic.

7. **Synthesize a summary:** Combine the findings into a concise description of the file's overall function.

**Self-Correction/Refinement during thought process:**

- Initially, I might focus too much on individual test details. The prompt asks for a summary of *functionality*, so I need to abstract the purpose of each test.
- If a test case seems overly complex, I should try to identify the core functionality it's verifying.
- For the Javascript relation, I should focus on *potential* connections rather than needing direct Javascript code within the unit test. Think about the information the estimator provides and how that could be used by web pages.
- When considering user errors, think broadly about configuration mistakes, incorrect usage of APIs related to network quality, etc.

By following these steps, I can generate a comprehensive and accurate summary of the `network_quality_estimator_unittest.cc` file, addressing all the user's requests.
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/nqe/network_quality_estimator.h"

#include <stddef.h>
#include <stdint.h>

#include <cmath>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/check_op.h"
#include "base/containers/adapters.h"
#include "base/metrics/histogram_samples.h"
#include "base/numerics/safe_conversions.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "net/base/load_flags.h"
#include "net/base/network_change_notifier.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_status_code.h"
#include "net/log/test_net_log.h"
#include "net/nqe/effective_connection_type.h"
#include "net/nqe/effective_connection_type_observer.h"
#include "net/nqe/network_quality_estimator_test_util.h"
#include "net/nqe/network_quality_observation.h"
#include "net/nqe/network_quality_observation_source.h"
#include "net/nqe/observation_buffer.h"
#include "net/nqe/rtt_throughput_estimates_observer.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace {

// Verifies that the number of samples in the bucket with minimum value
// |bucket_min| in |histogram| are at least |expected_min_count_samples|.
void ExpectBucketCountAtLeast(base::HistogramTester* histogram_tester,
                              const std::string& histogram,
                              int32_t bucket_min,
                              int32_t expected_min_count_samples) {
  std::vector<base::Bucket> buckets =
      histogram_tester->GetAllSamples(histogram);
  int actual_count_samples = 0;
  for (const auto& bucket : buckets) {
    if (bucket.min == bucket_min)
      actual_count_samples += bucket.count;
  }
  EXPECT_LE(expected_min_count_samples, actual_count_samples)
      << " histogram=" << histogram << " bucket_min=" << bucket_min
      << " expected_min_count_samples=" << expected_min_count_samples;
}

}  // namespace

namespace net {

namespace {

class TestEffectiveConnectionTypeObserver
    : public EffectiveConnectionTypeObserver {
 public:
  std::vector<EffectiveConnectionType>& effective_connection_types() {
    return effective_connection_types_;
  }

  // EffectiveConnectionTypeObserver implementation:
  void OnEffectiveConnectionTypeChanged(EffectiveConnectionType type) override {
    effective_connection_types_.push_back(type);
  }

 private:
  std::vector<EffectiveConnectionType> effective_connection_types_;
};

class TestPeerToPeerConnectionsCountObserver
    : public PeerToPeerConnectionsCountObserver {
 public:
  uint32_t count() { return count_; }

 private:
  // PeerToPeerConnectionsCountObserver:
  void OnPeerToPeerConnectionsCountChange(uint32_t count) override {
    count_ = count;
  }

  uint32_t count_ = 0u;
};

class TestRTTAndThroughputEstimatesObserver
    : public RTTAndThroughputEstimatesObserver {
 public:
  TestRTTAndThroughputEstimatesObserver()
      : http_rtt_(nqe::internal::InvalidRTT()),
        transport_rtt_(nqe::internal::InvalidRTT()) {}

  // RTTAndThroughputEstimatesObserver implementation:
  void OnRTTOrThroughputEstimatesComputed(
      base::TimeDelta http_rtt,
      base::TimeDelta transport_rtt,
      int32_t downstream_throughput_kbps) override {
    http_rtt_ = http_rtt;
    transport_rtt_ = transport_rtt;
    downstream_throughput_kbps_ = downstream_throughput_kbps;
    notifications_received_++;
  }

  int notifications_received() const { return notifications_received_; }

  base::TimeDelta http_rtt() const { return http_rtt_; }
  base::TimeDelta transport_rtt() const { return transport_rtt_; }
  int32_t downstream_throughput_kbps() const {
    return downstream_throughput_kbps_;
  }

 private:
  base::TimeDelta http_rtt_;
  base::TimeDelta transport_rtt_;
  int32_t downstream_throughput_kbps_ = nqe::internal::INVALID_RTT_THROUGHPUT;
  int notifications_received_ = 0;
};

class TestRTTObserver : public NetworkQualityEstimator::RTTObserver {
 public:
  struct Observation {
    Observation(int32_t ms,
                const base::TimeTicks& ts,
                NetworkQualityObservationSource src)
        : rtt_ms(ms), timestamp(ts), source(src) {}
    int32_t rtt_ms;
    base::TimeTicks timestamp;
    NetworkQualityObservationSource source;
  };

  std::vector<Observation>& observations() { return observations_; }

  // RttObserver implementation:
  void OnRTTObservation(int32_t rtt_ms,
                        const base::TimeTicks& timestamp,
                        NetworkQualityObservationSource source) override {
    observations_.emplace_back(rtt_ms, timestamp, source);
  }

  // Returns the last received RTT observation that has source set to |source|.
  base::TimeDelta last_rtt(NetworkQualityObservationSource source) {
    for (const auto& observation : base::Reversed(observations_)) {
      if (observation.source == source)
        return base::Milliseconds(observation.rtt_ms);
    }
    return nqe::internal::InvalidRTT();
  }

 private:
  std::vector<Observation> observations_;
};

class TestThroughputObserver
    : public NetworkQualityEstimator::ThroughputObserver {
 public:
  struct Observation {
    Observation(int32_t kbps,
                const base::TimeTicks& ts,
                NetworkQualityObservationSource src)
        : throughput_kbps(kbps), timestamp(ts), source(src) {}
    int32_t throughput_kbps;
    base::TimeTicks timestamp;
    NetworkQualityObservationSource source;
  };

  std::vector<Observation>& observations() { return observations_; }

  // ThroughputObserver implementation:
  void OnThroughputObservation(
      int32_t throughput_kbps,
      const base::TimeTicks& timestamp,
      NetworkQualityObservationSource source) override {
    observations_.emplace_back(throughput_kbps, timestamp, source);
  }

 private:
  std::vector<Observation> observations_;
};

}  // namespace

using NetworkQualityEstimatorTest = TestWithTaskEnvironment;

TEST_F(NetworkQualityEstimatorTest, TestKbpsRTTUpdates) {
  base::HistogramTester histogram_tester;
  // Enable requests to local host to be used for network quality estimation.
  std::map<std::string, std::string> variation_params;
  variation_params["throughput_min_requests_in_flight"] = "1";
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  context_builder->SuppressSettingSocketPerformanceWatcherFactoryForTesting();
  auto context = context_builder->Build();

  std::unique_ptr<URLRequest> request(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request->Start();
  test_delegate.RunUntilComplete();

  // Pump message loop to allow estimator tasks to be processed.
  base::RunLoop().RunUntilIdle();

  // Both RTT and downstream throughput should be updated.
  base::TimeDelta http_rtt;
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &http_rtt, nullptr));
  EXPECT_EQ(http_rtt, estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());
  base::TimeDelta transport_rtt;
  EXPECT_FALSE(estimator.GetTransportRTT());
  EXPECT_FALSE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &transport_rtt, nullptr));

  // Verify the contents of the net log.
  EXPECT_LE(
      2, estimator.GetEntriesCount(NetLogEventType::NETWORK_QUALITY_CHANGED));
  EXPECT_EQ(http_rtt.InMilliseconds(),
            estimator.GetNetLogLastIntegerValue(
                NetLogEventType::NETWORK_QUALITY_CHANGED, "http_rtt_ms"));
  EXPECT_EQ(-1,
            estimator.GetNetLogLastIntegerValue(
                NetLogEventType::NETWORK_QUALITY_CHANGED, "transport_rtt_ms"));
  EXPECT_EQ(kbps, estimator.GetNetLogLastIntegerValue(
                      NetLogEventType::NETWORK_QUALITY_CHANGED,
                      "downstream_throughput_kbps"));

  // Check UMA histograms.
  EXPECT_LE(1u,
            histogram_tester.GetAllSamples("NQE.RTT.OnECTComputation").size());

  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource", NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP, 1);

  std::unique_ptr<URLRequest> request2(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request2->SetLoadFlags(request2->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request2->Start();
  test_delegate.RunUntilComplete();

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  histogram_tester.ExpectTotalCount("NQE.RatioMedianRTT.WiFi", 0);

  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, std::string());

  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

  std::unique_ptr<URLRequest> request3(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request3->SetLoadFlags(request2->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request3->Start();
  test_delegate.RunUntilComplete();

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");
}

// Tests that the network quality estimator writes and reads network quality
// from the cache store correctly.
TEST_F(NetworkQualityEstimatorTest, Caching) {
  for (NetworkChangeNotifier::ConnectionType connection_type :
       {NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI,
        NetworkChangeNotifier::ConnectionType::CONNECTION_ETHERNET}) {
    base::HistogramTester histogram_tester;
    std::map<std::string, std::string> variation_params;
    variation_params["throughput_min_requests_in_flight"] = "1";
    variation_params["add_default_platform_observations"] = "false";
    TestNetworkQualityEstimator estimator(variation_params);

    const std::string connection_id =
        connection_type ==
                NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI
            ? "test"
            : "";

    estimator.SimulateNetworkChange(connection_type, connection_id);

    base::TimeDelta rtt;
    int32_t kbps;
    EXPECT_FALSE(
        estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                               base::TimeTicks(), &rtt, nullptr));
    EXPECT_FALSE(
        estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

    TestDelegate test_delegate;
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_network_quality_estimator(&estimator);
    context_builder->SuppressSettingSocketPerformanceWatcherFactoryForTesting();
    auto context = context_builder->Build();

    // Start two requests so that the network quality is added to cache store at
    // the beginning of the second request from the network traffic observed
    // from the first request.
    for (size_t i = 0; i < 2; ++i) {
      std::unique_ptr<URLRequest> request(
          context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                                 &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
      request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
      request->Start();
      test_delegate.RunUntilComplete();
    }
    histogram_tester.ExpectUniqueSample("NQE.RTT.ObservationSource",
                                        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP,
                                        2);

    base::RunLoop().RunUntilIdle();

    // Both RTT and downstream throughput should be updated.
    EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                       base::TimeTicks(), &rtt, nullptr));
    EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
    EXPECT_TRUE(
        estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
    EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());
    EXPECT_NE(EFFECTIVE_CONNECTION_TYPE_UNKNOWN,
              estimator.GetEffectiveConnectionType());
    EXPECT_FALSE(
        estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                               base::TimeTicks(), &rtt, nullptr));
    EXPECT_FALSE(estimator.GetTransportRTT());

    // Add the observers before changing the network type.
    TestEffectiveConnectionTypeObserver observer;
    estimator.AddEffectiveConnectionTypeObserver(&observer);
    TestRTTObserver rtt_observer;
    estimator.AddRTTObserver(&rtt_observer);
    TestThroughputObserver throughput_observer;
    estimator.AddThroughputObserver(&throughput_observer);

    // |observer| should be notified as soon as it is added.
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(1U, observer.effective_connection_types().size());

    int num_net_log_entries =
        estimator.GetEntriesCount(NetLogEventType::NETWORK_QUALITY_CHANGED);
    EXPECT_LE(2, num_net_log_entries);

    estimator.SimulateNetworkChange(connection_type, connection_id);
    histogram_tester.ExpectBucketCount(
        "NQE.RTT.ObservationSource",
        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE, 1);
    histogram_tester.ExpectBucketCount(
        "NQE.RTT.ObservationSource",
        NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE, 1);
    histogram_tester.ExpectTotalCount("NQE.RTT.ObservationSource", 4);

    // Verify the contents of the net log.
    EXPECT_LE(
        1, estimator.GetEntriesCount(NetLogEventType::NETWORK_QUALITY_CHANGED) -
               num_net_log_entries);
    EXPECT_NE(-1, estimator.GetNetLogLastIntegerValue(
                      NetLogEventType::NETWORK_QUALITY_CHANGED, "http_rtt_ms"));
    EXPECT_NE(
        -1, estimator.GetNetLogLastIntegerValue(
                NetLogEventType::NETWORK_QUALITY_CHANGED, "transport_rtt_ms"));
    EXPECT_NE(-1, estimator.GetNetLogLastIntegerValue(
                      NetLogEventType::NETWORK_QUALITY_CHANGED,
                      "downstream_throughput_kbps"));
    EXPECT_EQ(GetNameForEffectiveConnectionType(
                  estimator.GetEffectiveConnectionType()),
              estimator.GetNetLogLastStringValue(
                  NetLogEventType::NETWORK_QUALITY_CHANGED,
                  "effective_connection_type"));

    base::RunLoop().RunUntilIdle();

    // Verify that the cached network quality was read, and observers were
    // notified. |observer| must be notified once right after it was added, and
    // once again after the cached network quality was read.
    EXPECT_LE(2U, observer.effective_connection_types().size());
    EXPECT_EQ(estimator.GetEffectiveConnectionType(),
              observer.effective_connection_types().back());
    EXPECT_EQ(2U, rtt_observer.observations().size());
    EXPECT_EQ(1U, throughput_observer.observations().size());
  }
}

// Tests that the network quality estimator does not read the network quality
// from the cache store when caching is not enabled.
TEST_F(NetworkQualityEstimatorTest, CachingDisabled) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;
  // Do not set |persistent_cache_reading_enabled| variation param.
  variation_params["persistent_cache_reading_enabled"] = "false";
  variation_params["throughput_min_requests_in_flight"] = "1";
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test");

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  context_builder->SuppressSettingSocketPerformanceWatcherFactoryForTesting();
  auto context = context_builder->Build();

  // Start two requests so that the network quality is added to cache store at
  // the beginning of the second request from the network traffic observed from
  // the first request.
  for (size_t i = 0; i < 2; ++i) {
    std::unique_ptr<URLRequest> request(
        context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                               &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
    request->Start();
    test_delegate.RunUntilComplete();
  }

  base::RunLoop().RunUntilIdle();

  // Both RTT and downstream throughput should be updated.
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());
  EXPECT_NE(EFFECTIVE_CONNECTION_TYPE_UNKNOWN,
            estimator.GetEffectiveConnectionType());
  EXPECT_FALSE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(estimator.GetTransportRTT());

  // Add the observers before changing the network type.
  TestRTTObserver rtt_observer;
  estimator.AddRTTObserver(&rtt_observer);
  TestThroughputObserver throughput_observer;
  estimator.AddThroughputObserver(&throughput_observer);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test");

  base::RunLoop().RunUntilIdle();

  // Verify that the cached network quality was read, and observers were
  // notified. |observer| must be notified once right after it was added, and
  // once again after the cached network quality was read.
  EXPECT_EQ(0U, rtt_observer.observations().size());
  EXPECT_EQ(0U, throughput_observer.observations().size());
}

TEST_F(NetworkQualityEstimatorTest, QuicObservations) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.OnUpdatedTransportRTTAvailable(
      SocketPerformanceWatcherFactory::PROTOCOL_TCP, base::Milliseconds(10),
      std::nullopt);
  estimator.OnUpdatedTransportRTTAvailable(
      SocketPerformanceWatcherFactory::PROTOCOL_QUIC, base::Milliseconds(10),
      std::nullopt);
  histogram_tester.ExpectBucketCount("NQE.RTT.ObservationSource",
                                     NETWORK_QUALITY_OBSERVATION_SOURCE_TCP, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource", NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC, 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.ObservationSource", 2);

  // Verify that the QUIC RTT samples are used when computing transport RTT
  // estimate.
  EXPECT_EQ(base::Milliseconds(10), estimator.GetTransportRTT());
  EXPECT_FALSE(estimator.GetHttpRTT().has_value());
}

// Verifies that the QUIC RTT samples are used when computing transport RTT
// estimate.
TEST_F(NetworkQualityEstimatorTest,
       QuicObservationsUsedForTransportRTTComputation) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.OnUpdatedTransportRTTAvailable(
      SocketPerformanceWatcherFactory::PROTOCOL_QUIC, base::Milliseconds(10),
      std::nullopt);
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource", NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC, 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.ObservationSource", 1);

  EXPECT_EQ(base::Milliseconds(10), estimator.GetTransportRTT());
  EXPECT_FALSE(estimator.GetHttpRTT().has_value());
}

// Verifies that the H2 RTT samples are used when computing transport RTT
// estimate.
TEST_F(NetworkQualityEstimatorTest,
       H2ObservationsUsedForTransportRTTComputation) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.RecordSpdyPingLatency(
      net::HostPortPair::FromString("www.test.com:443"),
      base::Milliseconds(10));
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource", NETWORK_QUALITY_OBSERVATION_SOURCE_H2_PINGS,
      1);
  histogram_tester.ExpectTotalCount("NQE.RTT.ObservationSource", 1);

  EXPECT_EQ(base::Milliseconds(10), estimator.GetTransportRTT());
  EXPECT_FALSE(estimator.GetHttpRTT().has_value());
}

TEST_F(NetworkQualityEstimatorTest, StoreObservations) {
  std::map<std::string, std::string> variation_params;
  variation_params["throughput_min_requests_in_flight"] = "1";
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  auto context = context_builder->Build();

  const size_t kMaxObservations = 10;
  for (size_t i = 0; i < kMaxObservations; ++i) {
    std::unique_ptr<URLRequest> request(
        context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                               &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    request->Start();
    test_delegate.RunUntilComplete();

    // Pump the message loop to process estimator tasks.
    base::RunLoop().RunUntilIdle();

    EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                       base::TimeTicks(), &rtt, nullptr));
    EXPECT_TRUE(
        estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  }

  // Verify that the stored observations are cleared on network change.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-2");
  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
}

// This test notifies NetworkQualityEstimator of received data. Next,
// throughput and RTT percentiles are checked for correctness by doing simple
// verifications.
TEST_F(NetworkQualityEstimatorTest, ComputedPercentiles) {
  std::map<std::string, std::string> variation_params;
  variation_params["throughput_min_requests_in_flight"] = "1";
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);

  EXPECT_EQ(nqe::internal::InvalidRTT(),
            estimator.GetRTTEstimateInternal(
                base::TimeTicks(), nqe::internal::OBSERVATION_CATEGORY_HTTP,
                100, nullptr));
  EXPECT_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
            estimator.GetDownlinkThroughputKbpsEstimateInternal(
                base::TimeTicks(), 100));

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  auto context = context_builder->Build();

  for (size_t i = 0; i < 10U; ++i) {
    std::unique_ptr<URLRequest> request(
        context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                               &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    request->Start();
    test_delegate.RunUntilComplete();
  }

  // Verify the percentiles through simple tests.
  for (int i = 0; i <= 100; ++i) {
    EXPECT_GT(estimator.GetDownlinkThroughputKbpsEstimateInternal(
                  base::TimeTicks(), i),
              0);
    EXPECT_LT(estimator.GetRTTEstimateInternal(
                  base::TimeTicks(), nqe::internal::OBSERVATION_CATEGORY_HTTP,
                  i, nullptr),
              base::TimeDelta::Max());

    if (i != 0)
### 提示词
```
这是目录为net/nqe/network_quality_estimator_unittest.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/40284755): Remove this and spanify to fix the errors.
#pragma allow_unsafe_buffers
#endif

#include "net/nqe/network_quality_estimator.h"

#include <stddef.h>
#include <stdint.h>

#include <cmath>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "base/check_op.h"
#include "base/containers/adapters.h"
#include "base/metrics/histogram_samples.h"
#include "base/numerics/safe_conversions.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "net/base/load_flags.h"
#include "net/base/network_change_notifier.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_status_code.h"
#include "net/log/test_net_log.h"
#include "net/nqe/effective_connection_type.h"
#include "net/nqe/effective_connection_type_observer.h"
#include "net/nqe/network_quality_estimator_test_util.h"
#include "net/nqe/network_quality_observation.h"
#include "net/nqe/network_quality_observation_source.h"
#include "net/nqe/observation_buffer.h"
#include "net/nqe/rtt_throughput_estimates_observer.h"
#include "net/socket/socket_performance_watcher.h"
#include "net/socket/socket_performance_watcher_factory.h"
#include "net/test/test_with_task_environment.h"
#include "net/traffic_annotation/network_traffic_annotation_test_helper.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "net/url_request/url_request_test_util.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

namespace {

// Verifies that the number of samples in the bucket with minimum value
// |bucket_min| in |histogram| are at least |expected_min_count_samples|.
void ExpectBucketCountAtLeast(base::HistogramTester* histogram_tester,
                              const std::string& histogram,
                              int32_t bucket_min,
                              int32_t expected_min_count_samples) {
  std::vector<base::Bucket> buckets =
      histogram_tester->GetAllSamples(histogram);
  int actual_count_samples = 0;
  for (const auto& bucket : buckets) {
    if (bucket.min == bucket_min)
      actual_count_samples += bucket.count;
  }
  EXPECT_LE(expected_min_count_samples, actual_count_samples)
      << " histogram=" << histogram << " bucket_min=" << bucket_min
      << " expected_min_count_samples=" << expected_min_count_samples;
}

}  // namespace

namespace net {

namespace {

class TestEffectiveConnectionTypeObserver
    : public EffectiveConnectionTypeObserver {
 public:
  std::vector<EffectiveConnectionType>& effective_connection_types() {
    return effective_connection_types_;
  }

  // EffectiveConnectionTypeObserver implementation:
  void OnEffectiveConnectionTypeChanged(EffectiveConnectionType type) override {
    effective_connection_types_.push_back(type);
  }

 private:
  std::vector<EffectiveConnectionType> effective_connection_types_;
};

class TestPeerToPeerConnectionsCountObserver
    : public PeerToPeerConnectionsCountObserver {
 public:
  uint32_t count() { return count_; }

 private:
  // PeerToPeerConnectionsCountObserver:
  void OnPeerToPeerConnectionsCountChange(uint32_t count) override {
    count_ = count;
  }

  uint32_t count_ = 0u;
};

class TestRTTAndThroughputEstimatesObserver
    : public RTTAndThroughputEstimatesObserver {
 public:
  TestRTTAndThroughputEstimatesObserver()
      : http_rtt_(nqe::internal::InvalidRTT()),
        transport_rtt_(nqe::internal::InvalidRTT()) {}

  // RTTAndThroughputEstimatesObserver implementation:
  void OnRTTOrThroughputEstimatesComputed(
      base::TimeDelta http_rtt,
      base::TimeDelta transport_rtt,
      int32_t downstream_throughput_kbps) override {
    http_rtt_ = http_rtt;
    transport_rtt_ = transport_rtt;
    downstream_throughput_kbps_ = downstream_throughput_kbps;
    notifications_received_++;
  }

  int notifications_received() const { return notifications_received_; }

  base::TimeDelta http_rtt() const { return http_rtt_; }
  base::TimeDelta transport_rtt() const { return transport_rtt_; }
  int32_t downstream_throughput_kbps() const {
    return downstream_throughput_kbps_;
  }

 private:
  base::TimeDelta http_rtt_;
  base::TimeDelta transport_rtt_;
  int32_t downstream_throughput_kbps_ = nqe::internal::INVALID_RTT_THROUGHPUT;
  int notifications_received_ = 0;
};

class TestRTTObserver : public NetworkQualityEstimator::RTTObserver {
 public:
  struct Observation {
    Observation(int32_t ms,
                const base::TimeTicks& ts,
                NetworkQualityObservationSource src)
        : rtt_ms(ms), timestamp(ts), source(src) {}
    int32_t rtt_ms;
    base::TimeTicks timestamp;
    NetworkQualityObservationSource source;
  };

  std::vector<Observation>& observations() { return observations_; }

  // RttObserver implementation:
  void OnRTTObservation(int32_t rtt_ms,
                        const base::TimeTicks& timestamp,
                        NetworkQualityObservationSource source) override {
    observations_.emplace_back(rtt_ms, timestamp, source);
  }

  // Returns the last received RTT observation that has source set to |source|.
  base::TimeDelta last_rtt(NetworkQualityObservationSource source) {
    for (const auto& observation : base::Reversed(observations_)) {
      if (observation.source == source)
        return base::Milliseconds(observation.rtt_ms);
    }
    return nqe::internal::InvalidRTT();
  }

 private:
  std::vector<Observation> observations_;
};

class TestThroughputObserver
    : public NetworkQualityEstimator::ThroughputObserver {
 public:
  struct Observation {
    Observation(int32_t kbps,
                const base::TimeTicks& ts,
                NetworkQualityObservationSource src)
        : throughput_kbps(kbps), timestamp(ts), source(src) {}
    int32_t throughput_kbps;
    base::TimeTicks timestamp;
    NetworkQualityObservationSource source;
  };

  std::vector<Observation>& observations() { return observations_; }

  // ThroughputObserver implementation:
  void OnThroughputObservation(
      int32_t throughput_kbps,
      const base::TimeTicks& timestamp,
      NetworkQualityObservationSource source) override {
    observations_.emplace_back(throughput_kbps, timestamp, source);
  }

 private:
  std::vector<Observation> observations_;
};

}  // namespace

using NetworkQualityEstimatorTest = TestWithTaskEnvironment;

TEST_F(NetworkQualityEstimatorTest, TestKbpsRTTUpdates) {
  base::HistogramTester histogram_tester;
  // Enable requests to local host to be used for network quality estimation.
  std::map<std::string, std::string> variation_params;
  variation_params["throughput_min_requests_in_flight"] = "1";
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  context_builder->SuppressSettingSocketPerformanceWatcherFactoryForTesting();
  auto context = context_builder->Build();

  std::unique_ptr<URLRequest> request(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request->Start();
  test_delegate.RunUntilComplete();

  // Pump message loop to allow estimator tasks to be processed.
  base::RunLoop().RunUntilIdle();

  // Both RTT and downstream throughput should be updated.
  base::TimeDelta http_rtt;
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &http_rtt, nullptr));
  EXPECT_EQ(http_rtt, estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());
  base::TimeDelta transport_rtt;
  EXPECT_FALSE(estimator.GetTransportRTT());
  EXPECT_FALSE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &transport_rtt, nullptr));

  // Verify the contents of the net log.
  EXPECT_LE(
      2, estimator.GetEntriesCount(NetLogEventType::NETWORK_QUALITY_CHANGED));
  EXPECT_EQ(http_rtt.InMilliseconds(),
            estimator.GetNetLogLastIntegerValue(
                NetLogEventType::NETWORK_QUALITY_CHANGED, "http_rtt_ms"));
  EXPECT_EQ(-1,
            estimator.GetNetLogLastIntegerValue(
                NetLogEventType::NETWORK_QUALITY_CHANGED, "transport_rtt_ms"));
  EXPECT_EQ(kbps, estimator.GetNetLogLastIntegerValue(
                      NetLogEventType::NETWORK_QUALITY_CHANGED,
                      "downstream_throughput_kbps"));

  // Check UMA histograms.
  EXPECT_LE(1u,
            histogram_tester.GetAllSamples("NQE.RTT.OnECTComputation").size());

  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource", NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP, 1);

  std::unique_ptr<URLRequest> request2(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request2->SetLoadFlags(request2->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request2->Start();
  test_delegate.RunUntilComplete();

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-1");
  histogram_tester.ExpectTotalCount("NQE.RatioMedianRTT.WiFi", 0);

  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, std::string());

  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

  std::unique_ptr<URLRequest> request3(
      context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                             &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
  request3->SetLoadFlags(request2->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
  request3->Start();
  test_delegate.RunUntilComplete();

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "test");
}

// Tests that the network quality estimator writes and reads network quality
// from the cache store correctly.
TEST_F(NetworkQualityEstimatorTest, Caching) {
  for (NetworkChangeNotifier::ConnectionType connection_type :
       {NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI,
        NetworkChangeNotifier::ConnectionType::CONNECTION_ETHERNET}) {
    base::HistogramTester histogram_tester;
    std::map<std::string, std::string> variation_params;
    variation_params["throughput_min_requests_in_flight"] = "1";
    variation_params["add_default_platform_observations"] = "false";
    TestNetworkQualityEstimator estimator(variation_params);

    const std::string connection_id =
        connection_type ==
                NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI
            ? "test"
            : "";

    estimator.SimulateNetworkChange(connection_type, connection_id);

    base::TimeDelta rtt;
    int32_t kbps;
    EXPECT_FALSE(
        estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                               base::TimeTicks(), &rtt, nullptr));
    EXPECT_FALSE(
        estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

    TestDelegate test_delegate;
    auto context_builder = CreateTestURLRequestContextBuilder();
    context_builder->set_network_quality_estimator(&estimator);
    context_builder->SuppressSettingSocketPerformanceWatcherFactoryForTesting();
    auto context = context_builder->Build();

    // Start two requests so that the network quality is added to cache store at
    // the beginning of the second request from the network traffic observed
    // from the first request.
    for (size_t i = 0; i < 2; ++i) {
      std::unique_ptr<URLRequest> request(
          context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                                 &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
      request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
      request->Start();
      test_delegate.RunUntilComplete();
    }
    histogram_tester.ExpectUniqueSample("NQE.RTT.ObservationSource",
                                        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP,
                                        2);

    base::RunLoop().RunUntilIdle();

    // Both RTT and downstream throughput should be updated.
    EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                       base::TimeTicks(), &rtt, nullptr));
    EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
    EXPECT_TRUE(
        estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
    EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());
    EXPECT_NE(EFFECTIVE_CONNECTION_TYPE_UNKNOWN,
              estimator.GetEffectiveConnectionType());
    EXPECT_FALSE(
        estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                               base::TimeTicks(), &rtt, nullptr));
    EXPECT_FALSE(estimator.GetTransportRTT());

    // Add the observers before changing the network type.
    TestEffectiveConnectionTypeObserver observer;
    estimator.AddEffectiveConnectionTypeObserver(&observer);
    TestRTTObserver rtt_observer;
    estimator.AddRTTObserver(&rtt_observer);
    TestThroughputObserver throughput_observer;
    estimator.AddThroughputObserver(&throughput_observer);

    // |observer| should be notified as soon as it is added.
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(1U, observer.effective_connection_types().size());

    int num_net_log_entries =
        estimator.GetEntriesCount(NetLogEventType::NETWORK_QUALITY_CHANGED);
    EXPECT_LE(2, num_net_log_entries);

    estimator.SimulateNetworkChange(connection_type, connection_id);
    histogram_tester.ExpectBucketCount(
        "NQE.RTT.ObservationSource",
        NETWORK_QUALITY_OBSERVATION_SOURCE_HTTP_CACHED_ESTIMATE, 1);
    histogram_tester.ExpectBucketCount(
        "NQE.RTT.ObservationSource",
        NETWORK_QUALITY_OBSERVATION_SOURCE_TRANSPORT_CACHED_ESTIMATE, 1);
    histogram_tester.ExpectTotalCount("NQE.RTT.ObservationSource", 4);

    // Verify the contents of the net log.
    EXPECT_LE(
        1, estimator.GetEntriesCount(NetLogEventType::NETWORK_QUALITY_CHANGED) -
               num_net_log_entries);
    EXPECT_NE(-1, estimator.GetNetLogLastIntegerValue(
                      NetLogEventType::NETWORK_QUALITY_CHANGED, "http_rtt_ms"));
    EXPECT_NE(
        -1, estimator.GetNetLogLastIntegerValue(
                NetLogEventType::NETWORK_QUALITY_CHANGED, "transport_rtt_ms"));
    EXPECT_NE(-1, estimator.GetNetLogLastIntegerValue(
                      NetLogEventType::NETWORK_QUALITY_CHANGED,
                      "downstream_throughput_kbps"));
    EXPECT_EQ(GetNameForEffectiveConnectionType(
                  estimator.GetEffectiveConnectionType()),
              estimator.GetNetLogLastStringValue(
                  NetLogEventType::NETWORK_QUALITY_CHANGED,
                  "effective_connection_type"));

    base::RunLoop().RunUntilIdle();

    // Verify that the cached network quality was read, and observers were
    // notified. |observer| must be notified once right after it was added, and
    // once again after the cached network quality was read.
    EXPECT_LE(2U, observer.effective_connection_types().size());
    EXPECT_EQ(estimator.GetEffectiveConnectionType(),
              observer.effective_connection_types().back());
    EXPECT_EQ(2U, rtt_observer.observations().size());
    EXPECT_EQ(1U, throughput_observer.observations().size());
  }
}

// Tests that the network quality estimator does not read the network quality
// from the cache store when caching is not enabled.
TEST_F(NetworkQualityEstimatorTest, CachingDisabled) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;
  // Do not set |persistent_cache_reading_enabled| variation param.
  variation_params["persistent_cache_reading_enabled"] = "false";
  variation_params["throughput_min_requests_in_flight"] = "1";
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test");

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  context_builder->SuppressSettingSocketPerformanceWatcherFactoryForTesting();
  auto context = context_builder->Build();

  // Start two requests so that the network quality is added to cache store at
  // the beginning of the second request from the network traffic observed from
  // the first request.
  for (size_t i = 0; i < 2; ++i) {
    std::unique_ptr<URLRequest> request(
        context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                               &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    request->SetLoadFlags(request->load_flags() | LOAD_MAIN_FRAME_DEPRECATED);
    request->Start();
    test_delegate.RunUntilComplete();
  }

  base::RunLoop().RunUntilIdle();

  // Both RTT and downstream throughput should be updated.
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());
  EXPECT_NE(EFFECTIVE_CONNECTION_TYPE_UNKNOWN,
            estimator.GetEffectiveConnectionType());
  EXPECT_FALSE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(estimator.GetTransportRTT());

  // Add the observers before changing the network type.
  TestRTTObserver rtt_observer;
  estimator.AddRTTObserver(&rtt_observer);
  TestThroughputObserver throughput_observer;
  estimator.AddThroughputObserver(&throughput_observer);

  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_2G, "test");

  base::RunLoop().RunUntilIdle();

  // Verify that the cached network quality was read, and observers were
  // notified. |observer| must be notified once right after it was added, and
  // once again after the cached network quality was read.
  EXPECT_EQ(0U, rtt_observer.observations().size());
  EXPECT_EQ(0U, throughput_observer.observations().size());
}

TEST_F(NetworkQualityEstimatorTest, QuicObservations) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.OnUpdatedTransportRTTAvailable(
      SocketPerformanceWatcherFactory::PROTOCOL_TCP, base::Milliseconds(10),
      std::nullopt);
  estimator.OnUpdatedTransportRTTAvailable(
      SocketPerformanceWatcherFactory::PROTOCOL_QUIC, base::Milliseconds(10),
      std::nullopt);
  histogram_tester.ExpectBucketCount("NQE.RTT.ObservationSource",
                                     NETWORK_QUALITY_OBSERVATION_SOURCE_TCP, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource", NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC, 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.ObservationSource", 2);

  // Verify that the QUIC RTT samples are used when computing transport RTT
  // estimate.
  EXPECT_EQ(base::Milliseconds(10), estimator.GetTransportRTT());
  EXPECT_FALSE(estimator.GetHttpRTT().has_value());
}

// Verifies that the QUIC RTT samples are used when computing transport RTT
// estimate.
TEST_F(NetworkQualityEstimatorTest,
       QuicObservationsUsedForTransportRTTComputation) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.OnUpdatedTransportRTTAvailable(
      SocketPerformanceWatcherFactory::PROTOCOL_QUIC, base::Milliseconds(10),
      std::nullopt);
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource", NETWORK_QUALITY_OBSERVATION_SOURCE_QUIC, 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.ObservationSource", 1);

  EXPECT_EQ(base::Milliseconds(10), estimator.GetTransportRTT());
  EXPECT_FALSE(estimator.GetHttpRTT().has_value());
}

// Verifies that the H2 RTT samples are used when computing transport RTT
// estimate.
TEST_F(NetworkQualityEstimatorTest,
       H2ObservationsUsedForTransportRTTComputation) {
  base::HistogramTester histogram_tester;
  std::map<std::string, std::string> variation_params;
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);
  estimator.RecordSpdyPingLatency(
      net::HostPortPair::FromString("www.test.com:443"),
      base::Milliseconds(10));
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource", NETWORK_QUALITY_OBSERVATION_SOURCE_H2_PINGS,
      1);
  histogram_tester.ExpectTotalCount("NQE.RTT.ObservationSource", 1);

  EXPECT_EQ(base::Milliseconds(10), estimator.GetTransportRTT());
  EXPECT_FALSE(estimator.GetHttpRTT().has_value());
}

TEST_F(NetworkQualityEstimatorTest, StoreObservations) {
  std::map<std::string, std::string> variation_params;
  variation_params["throughput_min_requests_in_flight"] = "1";
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);

  base::TimeDelta rtt;
  int32_t kbps;
  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  auto context = context_builder->Build();

  const size_t kMaxObservations = 10;
  for (size_t i = 0; i < kMaxObservations; ++i) {
    std::unique_ptr<URLRequest> request(
        context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                               &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    request->Start();
    test_delegate.RunUntilComplete();

    // Pump the message loop to process estimator tasks.
    base::RunLoop().RunUntilIdle();

    EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                       base::TimeTicks(), &rtt, nullptr));
    EXPECT_TRUE(
        estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  }

  // Verify that the stored observations are cleared on network change.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_WIFI, "test-2");
  EXPECT_FALSE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                      base::TimeTicks(), &rtt, nullptr));
  EXPECT_FALSE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
}

// This test notifies NetworkQualityEstimator of received data. Next,
// throughput and RTT percentiles are checked for correctness by doing simple
// verifications.
TEST_F(NetworkQualityEstimatorTest, ComputedPercentiles) {
  std::map<std::string, std::string> variation_params;
  variation_params["throughput_min_requests_in_flight"] = "1";
  variation_params["add_default_platform_observations"] = "false";
  TestNetworkQualityEstimator estimator(variation_params);

  EXPECT_EQ(nqe::internal::InvalidRTT(),
            estimator.GetRTTEstimateInternal(
                base::TimeTicks(), nqe::internal::OBSERVATION_CATEGORY_HTTP,
                100, nullptr));
  EXPECT_EQ(nqe::internal::INVALID_RTT_THROUGHPUT,
            estimator.GetDownlinkThroughputKbpsEstimateInternal(
                base::TimeTicks(), 100));

  TestDelegate test_delegate;
  auto context_builder = CreateTestURLRequestContextBuilder();
  context_builder->set_network_quality_estimator(&estimator);
  auto context = context_builder->Build();

  for (size_t i = 0; i < 10U; ++i) {
    std::unique_ptr<URLRequest> request(
        context->CreateRequest(estimator.GetEchoURL(), DEFAULT_PRIORITY,
                               &test_delegate, TRAFFIC_ANNOTATION_FOR_TESTS));
    request->Start();
    test_delegate.RunUntilComplete();
  }

  // Verify the percentiles through simple tests.
  for (int i = 0; i <= 100; ++i) {
    EXPECT_GT(estimator.GetDownlinkThroughputKbpsEstimateInternal(
                  base::TimeTicks(), i),
              0);
    EXPECT_LT(estimator.GetRTTEstimateInternal(
                  base::TimeTicks(), nqe::internal::OBSERVATION_CATEGORY_HTTP,
                  i, nullptr),
              base::TimeDelta::Max());

    if (i != 0) {
      // Throughput percentiles are in decreasing order.
      EXPECT_LE(estimator.GetDownlinkThroughputKbpsEstimateInternal(
                    base::TimeTicks(), i),
                estimator.GetDownlinkThroughputKbpsEstimateInternal(
                    base::TimeTicks(), i - 1));

      // RTT percentiles are in increasing order.
      EXPECT_GE(estimator.GetRTTEstimateInternal(
                    base::TimeTicks(), nqe::internal::OBSERVATION_CATEGORY_HTTP,
                    i, nullptr),
                estimator.GetRTTEstimateInternal(
                    base::TimeTicks(), nqe::internal::OBSERVATION_CATEGORY_HTTP,
                    i - 1, nullptr));
    }
  }
}

// Verifies that the observers receive the notifications when default estimates
// are added to the observations.
TEST_F(NetworkQualityEstimatorTest, DefaultObservations) {
  base::HistogramTester histogram_tester;

  TestEffectiveConnectionTypeObserver effective_connection_type_observer;
  TestRTTAndThroughputEstimatesObserver rtt_throughput_estimates_observer;
  TestRTTObserver rtt_observer;
  TestThroughputObserver throughput_observer;
  std::map<std::string, std::string> variation_params;
  TestNetworkQualityEstimator estimator(variation_params, false, false);

  // Default observations should be added when constructing the |estimator|.
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource",
      NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_HTTP_FROM_PLATFORM, 1);
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource",
      NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_TRANSPORT_FROM_PLATFORM, 1);
  histogram_tester.ExpectTotalCount("NQE.RTT.ObservationSource", 2);

  // Default observations should be added on connection change.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_UNKNOWN, "unknown-1");
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource",
      NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_HTTP_FROM_PLATFORM, 2);
  histogram_tester.ExpectBucketCount(
      "NQE.RTT.ObservationSource",
      NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_TRANSPORT_FROM_PLATFORM, 2);
  histogram_tester.ExpectTotalCount("NQE.RTT.ObservationSource", 4);

  base::TimeDelta rtt;
  int32_t kbps;

  // Default estimates should be available.
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(base::Milliseconds(115), rtt);
  EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(base::Milliseconds(55), rtt);
  EXPECT_EQ(rtt, estimator.GetTransportRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  EXPECT_EQ(1961, kbps);
  EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());

  estimator.AddEffectiveConnectionTypeObserver(
      &effective_connection_type_observer);
  estimator.AddRTTAndThroughputEstimatesObserver(
      &rtt_throughput_estimates_observer);
  estimator.AddRTTObserver(&rtt_observer);
  estimator.AddThroughputObserver(&throughput_observer);

  // Simulate network change to 3G. Default estimates should be available.
  estimator.SimulateNetworkChange(
      NetworkChangeNotifier::ConnectionType::CONNECTION_3G, "test-3");
  EXPECT_TRUE(estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_HTTP,
                                     base::TimeTicks(), &rtt, nullptr));
  // Taken from network_quality_estimator_params.cc.
  EXPECT_EQ(base::Milliseconds(273), rtt);
  EXPECT_EQ(rtt, estimator.GetHttpRTT().value());
  EXPECT_TRUE(
      estimator.GetRecentRTT(nqe::internal::OBSERVATION_CATEGORY_TRANSPORT,
                             base::TimeTicks(), &rtt, nullptr));
  EXPECT_EQ(base::Milliseconds(209), rtt);
  EXPECT_EQ(rtt, estimator.GetTransportRTT());
  EXPECT_TRUE(
      estimator.GetRecentDownlinkThroughputKbps(base::TimeTicks(), &kbps));
  EXPECT_EQ(749, kbps);
  EXPECT_EQ(kbps, estimator.GetDownstreamThroughputKbps().value());

  EXPECT_NE(EFFECTIVE_CONNECTION_TYPE_UNKNOWN,
            estimator.GetEffectiveConnectionType());
  EXPECT_EQ(
      1U,
      effective_connection_type_observer.effective_connection_types().size());
  EXPECT_NE(
      EFFECTIVE_CONNECTION_TYPE_UNKNOWN,
      effective_connection_type_observer.effective_connection_types().front());

  // Verify the contents of the net log.
  EXPECT_LE(
      3, estimator.GetEntriesCount(NetLogEventType::NETWORK_QUALITY_CHANGED));
  EXPECT_NE(
      GetNameForEffectiveConnectionType(EFFECTIVE_CONNECTION_TYPE_UNKNOWN),
      estimator.GetNetLogLastStringValue(
          NetLogEventType::NETWORK_QUALITY_CHANGED,
          "effective_connection_type"));

  EXPECT_EQ(4, rtt_throughput_estimates_observer.notifications_received());
  EXPECT_EQ(base::Milliseconds(273),
            rtt_throughput_estimates_observer.http_rtt());
  EXPECT_EQ(base::Milliseconds(209),
            rtt_throughput_estimates_observer.transport_rtt());
  EXPECT_EQ(749,
            rtt_throughput_estimates_observer.downstream_throughput_kbps());

  EXPECT_EQ(2U, rtt_observer.observations().size());
  EXPECT_EQ(273, rtt_observer.observations().at(0).rtt_ms);
  EXPECT_EQ(NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_HTTP_FROM_PLATFORM,
            rtt_observer.observations().at(0).source);
  EXPECT_EQ(209, rtt_observer.observations().at(1).rtt_ms);
  EXPECT_EQ(NETWORK_QUALITY_OBSERVATION_SOURCE_DEFAULT_TRANSPORT_FROM_PLATFORM,
            rtt_observer.observations().at(1).source);

  EXPECT_EQ(1U, throughput_observer.observations().size());
  EXPECT_EQ(749, throughput_observer.observations(
```