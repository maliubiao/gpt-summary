Response:
The user wants a summary of the functionalities of the provided C++ code snippet.
The code is a test file for the BBRv2 congestion control algorithm in Chromium's QUIC implementation.

Here's a breakdown of the functionalities present in the code:

1. **Setting up a simulated network environment:**  It defines classes and structures to model network elements like links, switches, traffic policers, and endpoints (sender and receiver).
2. **Configuring network parameters:** It allows setting parameters like bandwidth, latency, and queue capacity for the simulated network.
3. **Implementing the BBRv2 sender:** It instantiates and configures the `Bbr2Sender` class, which implements the BBRv2 congestion control logic.
4. **Simulating data transfer:** It provides methods to simulate sending data between endpoints and track the transfer progress.
5. **Verifying BBRv2 behavior:** It includes various test cases that check the behavior of BBRv2 under different network conditions and configurations. This involves asserting on metrics like bandwidth estimation, congestion window, pacing rate, and packet loss.
6. **Regression testing:** It supports recording and comparing test results for regression testing purposes.
7. **Integration with the QUIC framework:** It utilizes QUIC core components like `QuicConnection`, `QuicSentPacketManager`, and `RttStats`.
8. **Command-line flag for regression mode:** It uses a command-line flag to switch between recording, regressing, and normal testing modes.
This C++ code snippet is a **test file** for the BBRv2 congestion control algorithm within the Chromium network stack's QUIC implementation. Specifically, it's designed for **simulating network conditions** and **verifying the behavior** of the `Bbr2Sender` class.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Simulates a Network Topology:** It sets up a basic network environment with a sender, receiver, and a network switch acting as a bottleneck. This allows testing BBRv2's behavior under controlled conditions.
2. **Configures Network Link Parameters:** It defines structures (`LinkParams`) to specify the bandwidth and delay of network links. This allows simulating different network speeds and latencies.
3. **Simulates Traffic Policing (Optional):** It includes an option to introduce a traffic policer at the sender, which can limit the rate at which data is sent.
4. **Instantiates and Configures BBRv2 Sender:** It creates instances of the `Bbr2Sender` class (the core of the BBRv2 algorithm) and integrates it with a simulated QUIC connection.
5. **Simulates Data Transfer:** It provides methods (`DoSimpleTransfer`, `SendBursts`, `SendUntilOrTimeout`) to simulate the transfer of data between the sender and receiver endpoints.
6. **Verifies BBRv2 Behavior:** The core purpose is to write tests that assert specific behaviors of the BBRv2 algorithm under different scenarios. This includes checking:
    *   **Startup Behavior:** How BBRv2 enters and exits the startup phase.
    *   **Bandwidth Estimation:** Whether BBRv2 correctly estimates the available bandwidth.
    *   **Congestion Window Control:** How BBRv2 adjusts its congestion window.
    *   **Pacing Rate:**  The rate at which BBRv2 sends packets.
    *   **Reaction to Network Changes:** How BBRv2 responds to changes in bandwidth and latency.
    *   **Packet Loss:** The amount of packet loss experienced during the transfer.
    *   **Interaction with Connection Options:** How BBRv2 behaves with different QUIC connection options (identified by `QuicTag`).
7. **Supports Regression Testing:** It includes functionality to record the results of tests and then compare subsequent test runs against these recorded results. This helps detect unintended changes in behavior.
8. **Provides Debugging Information:** It exposes internal state variables of the `Bbr2Sender` (using `ExportDebugState`) to allow detailed inspection of the algorithm's state during testing.

**Relationship to JavaScript Functionality:**

This C++ code directly relates to the underlying network performance and congestion control mechanisms that affect web browsers and other applications using the QUIC protocol. While JavaScript itself doesn't directly interact with this specific C++ file, the behavior tested here has a direct impact on the user experience in web browsers.

*   **Faster Page Loads:** BBRv2 aims to improve network throughput and reduce latency, leading to faster loading of web pages and web applications accessed through a browser.
*   **Smoother Video Streaming:** Effective congestion control helps in delivering a more stable and less buffered video streaming experience.
*   **Improved Performance in Lossy Networks:** BBRv2 is designed to be more robust in networks with packet loss, providing a better experience in less-than-ideal network conditions.

**Example:** Imagine a user in a web browser starts downloading a large file. The browser's QUIC implementation would use a congestion control algorithm like BBRv2 (whose behavior is tested in this file). If the network conditions change (e.g., congestion increases), BBRv2, based on its internal logic (tested here), would reduce the sending rate to avoid overwhelming the network, preventing excessive packet loss and ensuring a more stable download.

**Logical Reasoning with Hypothetical Input and Output:**

Let's consider the `NormalStartup` test case:

*   **Hypothetical Input:**
    *   `DefaultTopologyParams`:  A network with a defined bandwidth and delay.
    *   `sender_endpoint_.AddBytesToTransfer(12 * 1024 * 1024)`: The sender needs to send 12MB of data.
*   **Logical Reasoning:** The test expects BBRv2 to enter the `STARTUP` phase, gradually increase its sending rate until it reaches the bottleneck bandwidth, and then transition to the `DRAIN` phase. It also checks the number of round trips taken to reach full bandwidth.
*   **Expected Output:**
    *   `sender_->ExportDebugState().startup.full_bandwidth_reached` is `true`.
    *   `sender_->ExportDebugState().mode` is `Bbr2Mode::DRAIN`.
    *   `sender_->ExportDebugState().round_trip_count - max_bw_round` is `3u` (indicating the number of rounds after reaching maximum bandwidth before exiting startup).
    *   `sender_connection_stats().packets_lost` is `0u` (no packet loss during startup).
    *   `sender_->ExportDebugState().bandwidth_hi` is approximately equal to the bottleneck bandwidth.

**User or Programming Common Usage Errors:**

While this is a test file and not directly used by users, common errors in *implementing* or *configuring* congestion control algorithms (which this file helps to prevent) could include:

*   **Incorrectly setting initial congestion window:** Setting it too high can lead to overwhelming the network and causing packet loss.
*   **Flawed bandwidth estimation logic:** Incorrectly estimating bandwidth can lead to either underutilization of the network or aggressive sending that causes congestion.
*   **Not properly handling packet loss:**  A congestion control algorithm needs to react appropriately to packet loss signals. Ignoring them can worsen network congestion.
*   **Incorrect pacing rate calculation:** Setting the pacing rate too high can also lead to network congestion.

**User Operation to Reach This Code (Debugging Context):**

Imagine a web developer or a network engineer is investigating performance issues with a web application that uses QUIC. Here's how they might end up looking at this test file:

1. **User reports slow loading times or connection instability.**
2. **The developer suspects a problem with the QUIC congestion control algorithm.**
3. **They decide to debug the QUIC implementation in Chromium.**
4. **They might search the Chromium source code for files related to "BBRv2" or "congestion control".**
5. **This leads them to the directory `net/third_party/quiche/src/quiche/quic/core/congestion_control/`.**
6. **They might look at the `bbr2_sender.cc` (the actual implementation) and, to understand how it's tested, they'd open `bbr2_simulator_test.cc`.**
7. **They might then run specific test cases within this file to reproduce the issue or to understand the algorithm's behavior under certain network conditions.**
8. **By examining the test setup and assertions, they can gain insights into how BBRv2 is expected to behave and identify potential bugs in the implementation.**

**Summary of Functionality (Part 1):**

This first part of the `bbr2_simulator_test.cc` file focuses on **setting up the basic testing framework and defining the fundamental network simulation environment for BBRv2**. It includes:

*   **Includes necessary headers:** Bringing in required libraries for testing, QUIC core components, and the BBRv2 implementation.
*   **Defines command-line flag for regression testing.**
*   **Sets up default network parameters and a default network topology.**
*   **Creates base test classes (`Bbr2SimulatorTest` and `Bbr2DefaultTopologyTest`)** which provide the infrastructure for running simulations and interacting with the BBRv2 sender.
*   **Includes the first few basic test cases, such as `NormalStartup` and `SimpleTransfer`, which verify core BBRv2 functionality in a standard network environment.**

In essence, this section lays the groundwork for more complex and specific BBRv2 testing that will likely appear in the subsequent parts of the file.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_simulator_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "quiche/quic/core/congestion_control/bbr2_misc.h"
#include "quiche/quic/core/congestion_control/bbr2_sender.h"
#include "quiche/quic/core/congestion_control/bbr_sender.h"
#include "quiche/quic/core/congestion_control/tcp_cubic_sender_bytes.h"
#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/send_algorithm_test_result.pb.h"
#include "quiche/quic/test_tools/send_algorithm_test_utils.h"
#include "quiche/quic/test_tools/simulator/link.h"
#include "quiche/quic/test_tools/simulator/quic_endpoint.h"
#include "quiche/quic/test_tools/simulator/simulator.h"
#include "quiche/quic/test_tools/simulator/switch.h"
#include "quiche/quic/test_tools/simulator/traffic_policer.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"

using testing::AllOf;
using testing::Ge;
using testing::Le;

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, quic_bbr2_test_regression_mode, "",
    "One of a) 'record' to record test result (one file per test), or "
    "b) 'regress' to regress against recorded results, or "
    "c) <anything else> for non-regression mode.");

namespace quic {

using CyclePhase = Bbr2ProbeBwMode::CyclePhase;

namespace test {

// Use the initial CWND of 10, as 32 is too much for the test network.
const uint32_t kDefaultInitialCwndPackets = 10;
const uint32_t kDefaultInitialCwndBytes =
    kDefaultInitialCwndPackets * kDefaultTCPMSS;

struct LinkParams {
  LinkParams(int64_t kilo_bits_per_sec, int64_t delay_us)
      : bandwidth(QuicBandwidth::FromKBitsPerSecond(kilo_bits_per_sec)),
        delay(QuicTime::Delta::FromMicroseconds(delay_us)) {}
  QuicBandwidth bandwidth;
  QuicTime::Delta delay;
};

struct TrafficPolicerParams {
  std::string name = "policer";
  QuicByteCount initial_burst_size;
  QuicByteCount max_bucket_size;
  QuicBandwidth target_bandwidth = QuicBandwidth::Zero();
};

// All Bbr2DefaultTopologyTests uses the default network topology:
//
//            Sender
//               |
//               |  <-- local_link
//               |
//        Network switch
//               *  <-- the bottleneck queue in the direction
//               |          of the receiver
//               |
//               |  <-- test_link
//               |
//               |
//           Receiver
class DefaultTopologyParams {
 public:
  LinkParams local_link = {10000, 2000};
  LinkParams test_link = {4000, 30000};

  const simulator::SwitchPortNumber switch_port_count = 2;
  // Network switch queue capacity, in number of BDPs.
  float switch_queue_capacity_in_bdp = 2;

  std::optional<TrafficPolicerParams> sender_policer_params;

  QuicBandwidth BottleneckBandwidth() const {
    return std::min(local_link.bandwidth, test_link.bandwidth);
  }

  // Round trip time of a single full size packet.
  QuicTime::Delta RTT() const {
    return 2 * (local_link.delay + test_link.delay +
                local_link.bandwidth.TransferTime(kMaxOutgoingPacketSize) +
                test_link.bandwidth.TransferTime(kMaxOutgoingPacketSize));
  }

  QuicByteCount BDP() const { return BottleneckBandwidth() * RTT(); }

  QuicByteCount SwitchQueueCapacity() const {
    return switch_queue_capacity_in_bdp * BDP();
  }

  std::string ToString() const {
    std::ostringstream os;
    os << "{ BottleneckBandwidth: " << BottleneckBandwidth()
       << " RTT: " << RTT() << " BDP: " << BDP()
       << " BottleneckQueueSize: " << SwitchQueueCapacity() << "}";
    return os.str();
  }
};

class Bbr2SimulatorTest : public QuicTest {
 protected:
  Bbr2SimulatorTest() : simulator_(&random_) {
    // Prevent the server(receiver), which only sends acks, from closing
    // connection due to too many outstanding packets.
    SetQuicFlag(quic_max_tracked_packet_count, 1000000);
  }

  void SetUp() override {
    if (quiche::GetQuicheCommandLineFlag(
            FLAGS_quic_bbr2_test_regression_mode) == "regress") {
      SendAlgorithmTestResult expected;
      ASSERT_TRUE(LoadSendAlgorithmTestResult(&expected));
      random_seed_ = expected.random_seed();
    } else {
      random_seed_ = QuicRandom::GetInstance()->RandUint64();
    }
    random_.set_seed(random_seed_);
    QUIC_LOG(INFO) << "Using random seed: " << random_seed_;
  }

  ~Bbr2SimulatorTest() override {
    const std::string regression_mode =
        quiche::GetQuicheCommandLineFlag(FLAGS_quic_bbr2_test_regression_mode);
    const QuicTime::Delta simulated_duration =
        SimulatedNow() - QuicTime::Zero();
    if (regression_mode == "record") {
      RecordSendAlgorithmTestResult(random_seed_,
                                    simulated_duration.ToMicroseconds());
    } else if (regression_mode == "regress") {
      CompareSendAlgorithmTestResult(simulated_duration.ToMicroseconds());
    }
  }

  QuicTime SimulatedNow() const { return simulator_.GetClock()->Now(); }

  uint64_t random_seed_;
  SimpleRandom random_;
  simulator::Simulator simulator_;
};

class Bbr2DefaultTopologyTest : public Bbr2SimulatorTest {
 protected:
  Bbr2DefaultTopologyTest()
      : sender_endpoint_(&simulator_, "Sender", "Receiver",
                         Perspective::IS_CLIENT, TestConnectionId(42)),
        receiver_endpoint_(&simulator_, "Receiver", "Sender",
                           Perspective::IS_SERVER, TestConnectionId(42)) {
    sender_ = SetupBbr2Sender(&sender_endpoint_, /*old_sender=*/nullptr);
  }

  ~Bbr2DefaultTopologyTest() {
    const auto* test_info =
        ::testing::UnitTest::GetInstance()->current_test_info();
    const Bbr2Sender::DebugState& debug_state = sender_->ExportDebugState();
    QUIC_LOG(INFO) << "Bbr2DefaultTopologyTest." << test_info->name()
                   << " completed at simulated time: "
                   << SimulatedNow().ToDebuggingValue() / 1e6
                   << " sec. packet loss:"
                   << sender_loss_rate_in_packets() * 100
                   << "%, bw_hi:" << debug_state.bandwidth_hi;
  }

  QuicUnackedPacketMap* GetUnackedMap(QuicConnection* connection) {
    return QuicSentPacketManagerPeer::GetUnackedPacketMap(
        QuicConnectionPeer::GetSentPacketManager(connection));
  }

  Bbr2Sender* SetupBbr2Sender(simulator::QuicEndpoint* endpoint,
                              BbrSender* old_sender) {
    // Ownership of the sender will be overtaken by the endpoint.
    Bbr2Sender* sender = new Bbr2Sender(
        endpoint->connection()->clock()->Now(),
        endpoint->connection()->sent_packet_manager().GetRttStats(),
        GetUnackedMap(endpoint->connection()), kDefaultInitialCwndPackets,
        GetQuicFlag(quic_max_congestion_window), &random_,
        QuicConnectionPeer::GetStats(endpoint->connection()), old_sender);
    QuicConnectionPeer::SetSendAlgorithm(endpoint->connection(), sender);
    const int kTestMaxPacketSize = 1350;
    endpoint->connection()->SetMaxPacketLength(kTestMaxPacketSize);
    endpoint->RecordTrace();
    return sender;
  }

  void CreateNetwork(const DefaultTopologyParams& params) {
    QUIC_LOG(INFO) << "CreateNetwork with parameters: " << params.ToString();
    switch_ = std::make_unique<simulator::Switch>(&simulator_, "Switch",
                                                  params.switch_port_count,
                                                  params.SwitchQueueCapacity());

    // WARNING: The order to add links to network_links_ matters, because some
    // tests adjusts the link bandwidth on the fly.

    // Local link connects sender and port 1.
    network_links_.push_back(std::make_unique<simulator::SymmetricLink>(
        &sender_endpoint_, switch_->port(1), params.local_link.bandwidth,
        params.local_link.delay));

    // Test link connects receiver and port 2.
    if (params.sender_policer_params.has_value()) {
      const TrafficPolicerParams& policer_params =
          params.sender_policer_params.value();
      sender_policer_ = std::make_unique<simulator::TrafficPolicer>(
          &simulator_, policer_params.name, policer_params.initial_burst_size,
          policer_params.max_bucket_size, policer_params.target_bandwidth,
          switch_->port(2));
      network_links_.push_back(std::make_unique<simulator::SymmetricLink>(
          &receiver_endpoint_, sender_policer_.get(),
          params.test_link.bandwidth, params.test_link.delay));
    } else {
      network_links_.push_back(std::make_unique<simulator::SymmetricLink>(
          &receiver_endpoint_, switch_->port(2), params.test_link.bandwidth,
          params.test_link.delay));
    }
  }

  simulator::SymmetricLink* TestLink() { return network_links_[1].get(); }

  void DoSimpleTransfer(QuicByteCount transfer_size, QuicTime::Delta timeout) {
    sender_endpoint_.AddBytesToTransfer(transfer_size);
    // TODO(wub): consider rewriting this to run until the receiver actually
    // receives the intended amount of bytes.
    bool simulator_result = simulator_.RunUntilOrTimeout(
        [this]() { return sender_endpoint_.bytes_to_transfer() == 0; },
        timeout);
    EXPECT_TRUE(simulator_result)
        << "Simple transfer failed.  Bytes remaining: "
        << sender_endpoint_.bytes_to_transfer();
    QUIC_LOG(INFO) << "Simple transfer state: " << sender_->ExportDebugState();
  }

  // Drive the simulator by sending enough data to enter PROBE_BW.
  void DriveOutOfStartup(const DefaultTopologyParams& params) {
    ASSERT_FALSE(sender_->ExportDebugState().startup.full_bandwidth_reached);
    DoSimpleTransfer(1024 * 1024, QuicTime::Delta::FromSeconds(15));
    EXPECT_EQ(Bbr2Mode::PROBE_BW, sender_->ExportDebugState().mode);
    EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                     sender_->ExportDebugState().bandwidth_hi, 0.02f);
  }

  // Send |bytes|-sized bursts of data |number_of_bursts| times, waiting for
  // |wait_time| between each burst.
  void SendBursts(const DefaultTopologyParams& params, size_t number_of_bursts,
                  QuicByteCount bytes, QuicTime::Delta wait_time) {
    ASSERT_EQ(0u, sender_endpoint_.bytes_to_transfer());
    for (size_t i = 0; i < number_of_bursts; i++) {
      sender_endpoint_.AddBytesToTransfer(bytes);

      // Transfer data and wait for three seconds between each transfer.
      simulator_.RunFor(wait_time);

      // Ensure the connection did not time out.
      ASSERT_TRUE(sender_endpoint_.connection()->connected());
      ASSERT_TRUE(receiver_endpoint_.connection()->connected());
    }

    simulator_.RunFor(wait_time + params.RTT());
    ASSERT_EQ(0u, sender_endpoint_.bytes_to_transfer());
  }

  template <class TerminationPredicate>
  bool SendUntilOrTimeout(TerminationPredicate termination_predicate,
                          QuicTime::Delta timeout) {
    EXPECT_EQ(0u, sender_endpoint_.bytes_to_transfer());
    const QuicTime deadline = SimulatedNow() + timeout;
    do {
      sender_endpoint_.AddBytesToTransfer(4 * kDefaultTCPMSS);
      if (simulator_.RunUntilOrTimeout(
              [this]() { return sender_endpoint_.bytes_to_transfer() == 0; },
              deadline - SimulatedNow()) &&
          termination_predicate()) {
        return true;
      }
    } while (SimulatedNow() < deadline);
    return false;
  }

  void EnableAggregation(QuicByteCount aggregation_bytes,
                         QuicTime::Delta aggregation_timeout) {
    switch_->port_queue(1)->EnableAggregation(aggregation_bytes,
                                              aggregation_timeout);
  }

  void SetConnectionOption(QuicTag option) {
    SetConnectionOption(std::move(option), sender_);
  }

  void SetConnectionOption(QuicTag option, Bbr2Sender* sender) {
    QuicConfig config;
    QuicTagVector options;
    options.push_back(option);
    QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
    sender->SetFromConfig(config, Perspective::IS_SERVER);
  }

  bool Bbr2ModeIsOneOf(const std::vector<Bbr2Mode>& expected_modes) const {
    const Bbr2Mode mode = sender_->ExportDebugState().mode;
    for (Bbr2Mode expected_mode : expected_modes) {
      if (mode == expected_mode) {
        return true;
      }
    }
    return false;
  }

  const RttStats* rtt_stats() {
    return sender_endpoint_.connection()->sent_packet_manager().GetRttStats();
  }

  QuicConnection* sender_connection() { return sender_endpoint_.connection(); }

  Bbr2Sender::DebugState sender_debug_state() const {
    return sender_->ExportDebugState();
  }

  const QuicConnectionStats& sender_connection_stats() {
    return sender_connection()->GetStats();
  }

  QuicUnackedPacketMap* sender_unacked_map() {
    return GetUnackedMap(sender_connection());
  }

  float sender_loss_rate_in_packets() {
    return static_cast<float>(sender_connection_stats().packets_lost) /
           sender_connection_stats().packets_sent;
  }

  simulator::QuicEndpoint sender_endpoint_;
  simulator::QuicEndpoint receiver_endpoint_;
  Bbr2Sender* sender_;

  std::unique_ptr<simulator::Switch> switch_;
  std::unique_ptr<simulator::TrafficPolicer> sender_policer_;
  std::vector<std::unique_ptr<simulator::SymmetricLink>> network_links_;
};

TEST_F(Bbr2DefaultTopologyTest, NormalStartup) {
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Run until the full bandwidth is reached and check how many rounds it was.
  sender_endpoint_.AddBytesToTransfer(12 * 1024 * 1024);
  QuicRoundTripCount max_bw_round = 0;
  QuicBandwidth max_bw(QuicBandwidth::Zero());
  bool simulator_result = simulator_.RunUntilOrTimeout(
      [this, &max_bw, &max_bw_round]() {
        if (max_bw * 1.001 < sender_->ExportDebugState().bandwidth_hi) {
          max_bw = sender_->ExportDebugState().bandwidth_hi;
          max_bw_round = sender_->ExportDebugState().round_trip_count;
        }
        return sender_->ExportDebugState().startup.full_bandwidth_reached;
      },
      QuicTime::Delta::FromSeconds(5));
  ASSERT_TRUE(simulator_result);
  EXPECT_EQ(Bbr2Mode::DRAIN, sender_->ExportDebugState().mode);
  EXPECT_EQ(3u, sender_->ExportDebugState().round_trip_count - max_bw_round);
  EXPECT_EQ(
      3u,
      sender_->ExportDebugState().startup.round_trips_without_bandwidth_growth);
  EXPECT_EQ(0u, sender_connection_stats().packets_lost);
  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);
}

TEST_F(Bbr2DefaultTopologyTest, NormalStartupB207) {
  SetConnectionOption(kB207);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Run until the full bandwidth is reached and check how many rounds it was.
  sender_endpoint_.AddBytesToTransfer(12 * 1024 * 1024);
  QuicRoundTripCount max_bw_round = 0;
  QuicBandwidth max_bw(QuicBandwidth::Zero());
  bool simulator_result = simulator_.RunUntilOrTimeout(
      [this, &max_bw, &max_bw_round]() {
        if (max_bw < sender_->ExportDebugState().bandwidth_hi) {
          max_bw = sender_->ExportDebugState().bandwidth_hi;
          max_bw_round = sender_->ExportDebugState().round_trip_count;
        }
        return sender_->ExportDebugState().startup.full_bandwidth_reached;
      },
      QuicTime::Delta::FromSeconds(5));
  ASSERT_TRUE(simulator_result);
  EXPECT_EQ(Bbr2Mode::DRAIN, sender_->ExportDebugState().mode);
  EXPECT_EQ(1u, sender_->ExportDebugState().round_trip_count - max_bw_round);
  EXPECT_EQ(
      1u,
      sender_->ExportDebugState().startup.round_trips_without_bandwidth_growth);
  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);
  EXPECT_EQ(0u, sender_connection_stats().packets_lost);
}

// Add extra_acked to CWND in STARTUP and exit STARTUP on a persistent queue.
TEST_F(Bbr2DefaultTopologyTest, NormalStartupB207andB205) {
  SetConnectionOption(kB205);
  SetConnectionOption(kB207);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Run until the full bandwidth is reached and check how many rounds it was.
  sender_endpoint_.AddBytesToTransfer(12 * 1024 * 1024);
  QuicRoundTripCount max_bw_round = 0;
  QuicBandwidth max_bw(QuicBandwidth::Zero());
  bool simulator_result = simulator_.RunUntilOrTimeout(
      [this, &max_bw, &max_bw_round]() {
        if (max_bw < sender_->ExportDebugState().bandwidth_hi) {
          max_bw = sender_->ExportDebugState().bandwidth_hi;
          max_bw_round = sender_->ExportDebugState().round_trip_count;
        }
        return sender_->ExportDebugState().startup.full_bandwidth_reached;
      },
      QuicTime::Delta::FromSeconds(5));
  ASSERT_TRUE(simulator_result);
  EXPECT_EQ(Bbr2Mode::DRAIN, sender_->ExportDebugState().mode);
  EXPECT_EQ(1u, sender_->ExportDebugState().round_trip_count - max_bw_round);
  EXPECT_EQ(
      2u,
      sender_->ExportDebugState().startup.round_trips_without_bandwidth_growth);
  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);
  EXPECT_EQ(0u, sender_connection_stats().packets_lost);
}

// Add extra_acked to CWND in STARTUP and exit STARTUP on a persistent queue.
TEST_F(Bbr2DefaultTopologyTest, NormalStartupBB2S) {
  SetQuicReloadableFlag(quic_bbr2_probe_two_rounds, true);
  SetConnectionOption(kBB2S);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Run until the full bandwidth is reached and check how many rounds it was.
  sender_endpoint_.AddBytesToTransfer(12 * 1024 * 1024);
  QuicRoundTripCount max_bw_round = 0;
  QuicBandwidth max_bw(QuicBandwidth::Zero());
  bool simulator_result = simulator_.RunUntilOrTimeout(
      [this, &max_bw, &max_bw_round]() {
        if (max_bw * 1.001 < sender_->ExportDebugState().bandwidth_hi) {
          max_bw = sender_->ExportDebugState().bandwidth_hi;
          max_bw_round = sender_->ExportDebugState().round_trip_count;
        }
        return sender_->ExportDebugState().startup.full_bandwidth_reached;
      },
      QuicTime::Delta::FromSeconds(5));
  ASSERT_TRUE(simulator_result);
  EXPECT_EQ(Bbr2Mode::DRAIN, sender_->ExportDebugState().mode);
  // BB2S reduces 3 rounds without bandwidth growth to 2.
  EXPECT_EQ(2u, sender_->ExportDebugState().round_trip_count - max_bw_round);
  EXPECT_EQ(
      2u,
      sender_->ExportDebugState().startup.round_trips_without_bandwidth_growth);
  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);
  EXPECT_EQ(0u, sender_connection_stats().packets_lost);
}

// Test a simple long data transfer in the default setup.
TEST_F(Bbr2DefaultTopologyTest, SimpleTransfer) {
  DefaultTopologyParams params;
  CreateNetwork(params);

  // At startup make sure we are at the default.
  EXPECT_EQ(kDefaultInitialCwndBytes, sender_->GetCongestionWindow());
  // At startup make sure we can send.
  EXPECT_TRUE(sender_->CanSend(0));
  // And that window is un-affected.
  EXPECT_EQ(kDefaultInitialCwndBytes, sender_->GetCongestionWindow());

  // Verify that Sender is in slow start.
  EXPECT_TRUE(sender_->InSlowStart());

  // Verify that pacing rate is based on the initial RTT.
  QuicBandwidth expected_pacing_rate = QuicBandwidth::FromBytesAndTimeDelta(
      2.885 * kDefaultInitialCwndBytes, rtt_stats()->initial_rtt());
  EXPECT_APPROX_EQ(expected_pacing_rate.ToBitsPerSecond(),
                   sender_->PacingRate(0).ToBitsPerSecond(), 0.01f);

  ASSERT_GE(params.BDP(), kDefaultInitialCwndBytes + kDefaultTCPMSS);

  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(30));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));
  EXPECT_EQ(0u, sender_connection_stats().packets_lost);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);

  // The margin here is quite high, since there exists a possibility that the
  // connection just exited high gain cycle.
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->smoothed_rtt(), 1.0f);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransferB2RC) {
  SetConnectionOption(kB2RC);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));

  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);

  EXPECT_LE(sender_loss_rate_in_packets(), 0.05);
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(params.RTT() * 4, rtt_stats()->smoothed_rtt());
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->min_rtt(), 0.2f);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransferB201) {
  SetConnectionOption(kB201);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));

  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);

  EXPECT_LE(sender_loss_rate_in_packets(), 0.05);
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(params.RTT() * 4, rtt_stats()->smoothed_rtt());
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->min_rtt(), 0.2f);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransferB206) {
  SetConnectionOption(kB206);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));

  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);

  EXPECT_LE(sender_loss_rate_in_packets(), 0.05);
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(params.RTT() * 4, rtt_stats()->smoothed_rtt());
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->min_rtt(), 0.2f);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransferB207) {
  SetConnectionOption(kB207);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));

  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);

  EXPECT_LE(sender_loss_rate_in_packets(), 0.05);
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(params.RTT() * 4, rtt_stats()->smoothed_rtt());
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->min_rtt(), 0.2f);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransferBBRB) {
  SetConnectionOption(kBBRB);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));

  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);

  EXPECT_LE(sender_loss_rate_in_packets(), 0.05);
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(params.RTT() * 4, rtt_stats()->smoothed_rtt());
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->min_rtt(), 0.2f);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransferBBR4) {
  SetQuicReloadableFlag(quic_bbr2_extra_acked_window, true);
  SetConnectionOption(kBBR4);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));

  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);

  EXPECT_LE(sender_loss_rate_in_packets(), 0.05);
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(params.RTT() * 4, rtt_stats()->smoothed_rtt());
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->min_rtt(), 0.2f);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransferBBR5) {
  SetQuicReloadableFlag(quic_bbr2_extra_acked_window, true);
  SetConnectionOption(kBBR5);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));

  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);

  EXPECT_LE(sender_loss_rate_in_packets(), 0.05);
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(params.RTT() * 4, rtt_stats()->smoothed_rtt());
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->min_rtt(), 0.2f);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransferBBQ1) {
  SetConnectionOption(kBBQ1);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));

  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);

  EXPECT_LE(sender_loss_rate_in_packets(), 0.05);
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(params.RTT() * 4, rtt_stats()->smoothed_rtt());
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->min_rtt(), 0.2f);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransferSmallBuffer) {
  DefaultTopologyParams params;
  params.switch_queue_capacity_in_bdp = 0.5;
  CreateNetwork(params);

  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(30));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));
  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.02f);
  EXPECT_GE(sender_connection_stats().packets_lost, 0u);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransferSmallBufferB2H2) {
  SetConnectionOption(kB2H2);
  DefaultTopologyParams params;
  params.switch_queue_capacity_in_bdp = 0.5;
  CreateNetwork(params);

  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(30));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));
  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.02f);
  EXPECT_GE(sender_connection_stats().packets_lost, 0u);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransfer2RTTAggregationBytes) {
  SetConnectionOption(kBSAO);
  DefaultTopologyParams params;
  CreateNetwork(params);
  // 2 RTTs of aggregation, with a max of 10kb.
  EnableAggregation(10 * 1024, 2 * params.RTT());

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));

  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);

  EXPECT_EQ(sender_loss_rate_in_packets(), 0);
  // The margin here is high, because both link level aggregation and ack
  // decimation can greatly increase smoothed rtt.
  EXPECT_GE(params.RTT() * 5, rtt_stats()->smoothed_rtt());
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->min_rtt(), 0.2f);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransfer2RTTAggregationBytesB201) {
  SetConnectionOption(kB201);
  DefaultTopologyParams params;
  CreateNetwork(params);
  // 2 RTTs of aggregation, with a max of 10kb.
  EnableAggregation(10 * 1024, 2 * params.RTT());

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));

  // TODO(wub): Tighten the error bound once BSAO is default enabled.
  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.5f);

  EXPECT_LE(sender_loss_rate_in_packets(), 0.01);
  // The margin here is high, because both link level aggregation and ack
  // decimation can greatly increase smoothed rtt.
  EXPECT_GE(params.RTT() * 5, rtt_stats()->smoothed_rtt());
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->min_rtt(), 0.2f);
}

TEST_F(Bbr2DefaultTopologyTest, SimpleTransferAckDecimation) {
  SetConnectionOption(kBSAO);
  DefaultTopologyParams params;
  CreateNetwork(params);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));

  EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                   sender_->ExportDebugState().bandwidth_hi, 0.01f);

  EXPECT_LE(sender_loss_rate_in_packets(), 0.001);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(params.RTT() * 3, rtt_stats()->smoothed_rtt());
  EXPECT_APPROX_EQ(params.RTT(), rtt_stats()->min_rtt(), 0.1f);
}

// Test Bbr2's reaction to a 100x bandwidth decrease during a transfer.
TEST_F(Bbr2DefaultTopologyTest, QUIC_SLOW_TEST(BandwidthDecrease)) {
  DefaultTopologyParams params;
  params.local_link.bandwidth = QuicBandwidth::FromKBitsPerSecond(15000);
  params.test_link.bandwidth = QuicBandwidth::FromKBitsPerSecond(10000);
  CreateNetwork(params);

  sender_endpoint_.AddBytesToTransfer(20 * 1024 * 1024);

  // We can transfer ~12MB in the first 10 seconds. The rest ~8MB needs about
  // 640 seconds.
  simulator_.RunFor(QuicTime::Delta::FromSeconds(10));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));
  QUIC_LOG(INFO) << "Bandwidth decreasing at time " << SimulatedNow();

  EXPECT_APPROX_EQ(params.test_link.bandwidth,
                   sender_->ExportDebugState().bandwidth_est, 0.1f);
  EXPECT_EQ(0u, sender_connection_stats().packets_lost);

  // Now decrease the bottleneck bandwidth from 10Mbps to 100Kbps.
  params.test_link.bandwidth = QuicBandwidth::FromKBitsPerSecond(100);
  TestLink()->set_bandwidth(params.test_link.bandwidth);

  bool simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return sender_endpoint_.bytes_to_transfer() == 0; },
      QuicTime::Delta::FromSeconds(800));
  EXPECT_TRUE(simulator_result);
}

// Test Bbr2's reaction to a 100x bandwidth increase during a transfer with B203
TEST_F(Bbr2DefaultTopologyTest, QUIC_SLOW_TEST(BandwidthIncreaseB203)) {
  SetConnectionOption(kB203);
  DefaultTopologyParams params;
  params.local_link.bandwidth = QuicBandwidth::FromKBitsPerSecond(15000);
  params.test_link.bandwidth = QuicBandwidth::FromKBitsPerSecond(100);
  CreateNetwork(params);

  sender_endpoint_.AddBytesToTransfer(20 * 1024 * 1024);

  simulator_.RunFor(QuicTime::Delta::FromSeconds(15));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));
  QUIC_LOG(INFO) << "Bandwidth increasing at time " << SimulatedNow();

  EXPECT_APPROX_EQ(params.test_link.bandwidth,
                   sender_->ExportDebugState().bandwidth_est, 0.1f);
  EXPECT_LE(sender_loss_rate_in_packets(), 0.30);

  // Now increase the bottleneck bandwidth from 100Kbps to 10Mbps.
  params.test_link.bandwidth = QuicBandwidth::FromKBitsPerSecond(10000);
  TestLink()->set_bandwidth(params.test_link.bandwidth);

  bool simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return sender_endpoint_.bytes_to_transfer() == 0; },
      QuicTime::Delta::FromSeconds(50));
  EXPECT_TRUE(simulator_result);
  // Ensure the full bandwidth is discovered.
  EXPECT_APPROX_EQ(params.test_link.bandwidth,
                   sender_->ExportDebugState().bandwidth_hi, 0.02f);
}

// Test Bbr2's reaction to a 100x bandwidth
```