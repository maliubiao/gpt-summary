Response:
My thinking process to analyze the provided C++ code and generate the summary involved the following steps:

1. **Initial Skim and Keyword Identification:** I quickly scanned the code, looking for keywords and structural elements that indicate its purpose. I noticed:
    * `#include ...`:  Standard C++ headers and QUIC-specific headers like `bbr_sender.h`, `rtt_stats.h`, `quic_bandwidth.h`, `quic_packets.h`, etc. This immediately suggests it's related to the BBR congestion control algorithm within the QUIC protocol.
    * `namespace quic { namespace test { ... } }`: This confirms it's part of the QUIC library's testing framework.
    * `class BbrSenderTest : public QuicTest`: This is the core of the file – a test fixture specifically for testing the `BbrSender` class.
    * `TEST_F(BbrSenderTest, ...)`:  Multiple test cases are defined, each focusing on a specific aspect of `BbrSender` behavior.
    * `simulator::Simulator`, `simulator::QuicEndpoint`, `simulator::Switch`, `simulator::SymmetricLink`: These indicate the use of a network simulator for testing.
    * `BbrSender* sender_;`: A pointer to the `BbrSender` object being tested.
    * `CreateDefaultSetup()`, `CreateSmallBufferSetup()`, `CreateCompetitionSetup()`:  Functions that set up different network topologies for testing.
    * `DoSimpleTransfer()`, `DriveOutOfStartup()`, `SendBursts()`: Helper functions to simulate common data transfer scenarios.
    * `ExportDebugState()`:  A method likely used to inspect the internal state of the `BbrSender` during testing.
    * `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_APPROX_EQ`, `ASSERT_TRUE`: Google Test framework assertions to verify expected behavior.

2. **Understanding the Core Functionality:** Based on the keywords and structure, I concluded that this file contains **unit tests for the BBR congestion control algorithm implementation in Chromium's QUIC stack.**  It uses a network simulator to create controlled environments and verify that the `BbrSender` behaves as expected under various conditions.

3. **Analyzing Individual Test Cases:** I examined the names of the test cases to understand their specific focus:
    * `SetInitialCongestionWindow`: Tests the ability to set the initial congestion window.
    * `SimpleTransfer`: Tests a basic data transfer scenario.
    * `SimpleTransferBBRB`: Likely tests a variation of BBR.
    * `SimpleTransferSmallBuffer`: Tests behavior with limited network buffer.
    * `RemoveBytesLostInRecovery`: Tests how the algorithm handles packet loss during recovery.
    * `SimpleTransfer2RTTAggregationBytes`, `SimpleTransferAckDecimation`: Tests with specific QUIC options related to aggregation and acknowledgment decimation.
    * `PacketLossOnSmallBufferStartup`: Focuses on loss during the startup phase.
    * `RecoveryStates`: Verifies transitions between recovery states.
    * `ApplicationLimitedBursts`: Tests behavior when the application limits data sending.
    * `Drain`: Checks the DRAIN phase of BBR.
    * `ProbeRtt`: Tests the PROBE_RTT phase.

4. **Identifying Relationships with JavaScript:** I considered how congestion control in general, and BBR specifically, relates to JavaScript in a web browser context. The key link is that **the browser's network stack (implemented in C++) uses BBR to manage the rate of data transmission for web requests initiated by JavaScript code.**  JavaScript itself doesn't directly implement or control BBR, but it indirectly benefits from its performance characteristics.

5. **Formulating Examples for JavaScript Interaction:** To illustrate the relationship with JavaScript, I focused on scenarios where network performance is visible to the user and is influenced by congestion control:
    * **Downloading a large file:** JavaScript initiates the download, and BBR controls the download speed.
    * **Streaming video:**  BBR helps maintain a stable streaming rate by adapting to network conditions.
    * **Real-time applications (WebRTC):** BBR plays a role in managing the bandwidth used by real-time communication.

6. **Identifying Logic and Assumptions:** I looked for specific logic within the tests and inferred the underlying assumptions:
    * **Network Topology:** The tests make assumptions about the network setup (bottleneck, link speeds, delays).
    * **Packet Loss:** Some tests intentionally introduce packet loss to observe BBR's recovery mechanisms.
    * **Timeouts:** The tests use timeouts to prevent indefinite runs if something goes wrong.
    * **Metrics:** The tests rely on specific metrics like congestion window, pacing rate, RTT, and packet loss to verify BBR's behavior.

7. **Identifying Potential User/Programming Errors:** I considered common mistakes related to network configuration or QUIC usage that could surface in these tests:
    * **Incorrect network parameters:**  Setting up the simulator with unrealistic bandwidth or delay values.
    * **Misunderstanding QUIC options:**  Enabling or disabling QUIC features without understanding their impact on BBR.
    * **Not handling packet loss:**  Assuming a perfect network and not accounting for potential losses.

8. **Tracing User Actions to the Code:** I outlined a simplified sequence of user actions that would eventually lead to this BBR code being executed:
    * User opens a website -> Browser initiates a QUIC connection -> BBR is selected as the congestion control algorithm -> Data transfer occurs, and these tests verify the correctness of BBR's implementation.

9. **Summarizing the Functionality:**  Finally, I synthesized the information gathered in the previous steps into a concise summary of the file's purpose, emphasizing its role in testing the BBR congestion control algorithm. I also highlighted its use of simulation, the focus on various network conditions, and the connection to the broader QUIC implementation.

Throughout this process, I paid attention to the specific requests in the prompt, ensuring I addressed the points about JavaScript, logical reasoning, common errors, and user actions. The iterative nature of examining the code, understanding its purpose, and then generating the specific examples and explanations was key to producing a comprehensive and accurate response.
好的，我们来分析一下 `net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr_sender_test.cc` 这个文件。

**文件功能归纳 (第1部分)**

这个C++源代码文件 (`bbr_sender_test.cc`) 的主要功能是：

**作为 Chromium 网络栈中 QUIC 协议的 BBR 拥塞控制算法 (`BbrSender`) 的单元测试。**

具体来说，它做了以下事情：

* **定义了一系列测试用例 (using Google Test framework):**  这些测试用例模拟各种网络条件和数据传输场景，用来验证 `BbrSender` 类的行为是否符合预期。
* **使用了网络模拟器 (`simulator::Simulator`)**:  为了创建可控的、可重复的网络环境，例如设置带宽、延迟、丢包率等。
* **创建了不同的网络拓扑:**  例如，默认设置、小缓冲区设置、竞争网络设置等，以测试 BBR 在不同网络条件下的表现。
* **模拟数据传输过程:**  通过 `AddBytesToTransfer` 等方法让发送端发送数据。
* **断言 (`EXPECT_...`, `ASSERT_...`) 检查结果:**  在模拟过程中和结束后，断言会检查 `BbrSender` 的内部状态（如拥塞窗口、发送速率、BBR 的状态机）、发送端的统计信息（如丢包数、发送包数）以及接收端的状态，以验证 BBR 的正确性。
* **支持回归测试:**  通过命令行标志 (`--quic_bbr_test_regression_mode`)，可以记录测试结果并与之前的记录进行比较，以防止代码修改引入回归错误。
* **测试了 BBR 的各种特性和状态:** 例如，慢启动、Drain 阶段、Probe RTT 阶段、拥塞恢复、应用受限场景等。
* **可以启用不同的 BBR 变种 (通过 `SetConnectionOption`)**: 例如 `kBBRB`, `kBSAO` 等，测试不同配置下的 BBR 行为。

**它与 Javascript 功能的关系**

虽然这个文件是 C++ 代码，直接在浏览器的网络栈底层运行，但它测试的 BBR 拥塞控制算法对 Javascript 的网络请求性能有直接影响。

**举例说明:**

假设一个 Javascript 应用需要下载一个大文件：

1. **Javascript 发起请求:**  Javascript 代码通过 `fetch()` API 或 `XMLHttpRequest` 发起对服务器的 HTTP/3 (QUIC) 请求。
2. **QUIC 连接建立:** 浏览器底层会建立一个 QUIC 连接。
3. **BBR 控制发送速率:**  在数据传输过程中，QUIC 连接的发送端会使用 BBR 算法来控制发送数据的速率，以避免网络拥塞，并尽可能高效地利用可用带宽。
4. **测试验证 BBR 行为:**  `bbr_sender_test.cc` 中的测试用例，例如 `SimpleTransfer`，就是在模拟这个过程，确保 BBR 算法能够平稳地增加发送速率，最终达到网络容量，并且在网络拥塞时能够正确地降低速率。
5. **Javascript 感知性能:**  最终，Javascript 应用会感受到下载速度的变化。如果 BBR 工作良好，下载速度会比较快且稳定。如果 BBR 存在 bug，可能会导致下载速度过慢、不稳定甚至中断。

**逻辑推理 (假设输入与输出)**

**假设输入 (以 `SimpleTransfer` 测试用例为例):**

* **网络拓扑:** 默认设置，包含发送端、接收端、交换机，并定义了链路带宽和延迟。
* **传输数据量:**  12MB。
* **初始状态:** BBR 发送端处于慢启动阶段。

**逻辑推理过程:**

* **慢启动:**  BBR 在开始时会以较小的拥塞窗口发送数据，并根据收到的 ACK 逐渐增加拥塞窗口。
* **带宽探测:**  随着拥塞窗口的增大，BBR 会探测网络的可用带宽。
* **状态转移:**  最终，BBR 应该会脱离慢启动阶段，进入其他状态（例如 PROBE_BW）。
* **性能指标:**  发送速率应该逐渐接近瓶颈链路的带宽，丢包率应该较低。

**预期输出:**

* **BBR 状态:**  最终进入 `PROBE_BW` 状态。
* **丢包数:**  接近于 0。
* **平滑 RTT:** 接近于测试网络的 RTT (kTestRtt)。
* **最大带宽估计:** 接近于瓶颈链路带宽 (kTestLinkBandwidth)。

**用户或编程常见的使用错误**

由于这是一个测试文件，用户直接操作到这里的可能性很小。但开发人员在修改 BBR 算法或相关代码时，可能会遇到以下错误，而这些测试用例可以帮助捕获这些错误：

1. **修改 BBR 算法后引入回归错误:**  例如，错误地更新了拥塞窗口的计算方式，导致 BBR 在某些网络条件下表现异常（过激或保守）。回归测试可以检测到这类问题。
    * **举例:**  修改了 BBR 在丢包时的降速逻辑，导致丢包后拥塞窗口下降过多，传输效率降低。
2. **网络参数配置错误:**  在模拟网络环境时，错误地配置了带宽、延迟等参数，导致测试结果不准确。
    * **举例:**  将本地链路带宽设置得过低，掩盖了 BBR 在瓶颈链路上的表现。
3. **状态机转换错误:**  BBR 算法有多个状态，错误的状态转换逻辑会导致 BBR 行为异常。
    * **举例:**  在应该进入 `PROBE_RTT` 阶段时，没有正确触发状态转移。
4. **资源管理错误:**  例如，内存泄漏或资源未正确释放，虽然测试文件可能不会直接暴露这类问题，但长时间运行大量的测试可以帮助发现。

**用户操作如何一步步的到达这里 (作为调试线索)**

虽然用户不会直接“到达”这个测试文件，但以下是一个简化的流程，说明了用户操作如何触发 BBR 代码的执行，从而使这个测试文件变得重要：

1. **用户在 Chrome 浏览器中访问一个使用 HTTP/3 的网站。**
2. **Chrome 浏览器尝试与服务器建立 QUIC 连接。**
3. **连接建立后，用户执行某些操作，例如浏览网页、下载文件、观看视频等，导致浏览器需要发送或接收数据。**
4. **Chrome 浏览器的网络栈 (C++ 代码) 中的 QUIC 实现开始发送数据包。**
5. **QUIC 的拥塞控制模块被激活，`BbrSender` 负责根据网络状况调整发送速率。**
6. **如果 `BbrSender` 的代码存在缺陷，用户可能会遇到网络连接问题，例如加载缓慢、视频卡顿等。**
7. **为了调试这些问题，Chromium 的开发人员可能会需要查看 `BbrSender` 的代码，并运行 `bbr_sender_test.cc` 中的测试用例，以复现和修复 bug。**  测试用例可以帮助开发人员隔离问题，验证修复是否有效。

**总结 (第1部分功能)**

总而言之，`net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr_sender_test.cc` 的第一部分主要功能是**构建了一个全面的测试框架，用于验证 Chromium QUIC 协议中 BBR 拥塞控制算法的核心功能和在各种网络条件下的正确性**。它使用了模拟、断言和回归测试机制，确保 BBR 算法的稳定性和性能，从而间接地提升了用户在 Chrome 浏览器中使用 HTTP/3 的网络体验。

请等待下一部分的分析。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr_sender_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/bbr_sender.h"

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <utility>

#include "quiche/quic/core/congestion_control/rtt_stats.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/send_algorithm_test_result.pb.h"
#include "quiche/quic/test_tools/send_algorithm_test_utils.h"
#include "quiche/quic/test_tools/simulator/quic_endpoint.h"
#include "quiche/quic/test_tools/simulator/simulator.h"
#include "quiche/quic/test_tools/simulator/switch.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"

using testing::AllOf;
using testing::Ge;
using testing::Le;

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, quic_bbr_test_regression_mode, "",
    "One of a) 'record' to record test result (one file per test), or "
    "b) 'regress' to regress against recorded results, or "
    "c) <anything else> for non-regression mode.");

namespace quic {
namespace test {

// Use the initial CWND of 10, as 32 is too much for the test network.
const uint32_t kInitialCongestionWindowPackets = 10;
const uint32_t kDefaultWindowTCP =
    kInitialCongestionWindowPackets * kDefaultTCPMSS;

// Test network parameters.  Here, the topology of the network is:
//
//          BBR sender
//               |
//               |  <-- local link (10 Mbps, 2 ms delay)
//               |
//        Network switch
//               *  <-- the bottleneck queue in the direction
//               |          of the receiver
//               |
//               |  <-- test link (4 Mbps, 30 ms delay)
//               |
//               |
//           Receiver
//
// The reason the bandwidths chosen are relatively low is the fact that the
// connection simulator uses QuicTime for its internal clock, and as such has
// the granularity of 1us, meaning that at bandwidth higher than 20 Mbps the
// packets can start to land on the same timestamp.
const QuicBandwidth kTestLinkBandwidth =
    QuicBandwidth::FromKBitsPerSecond(4000);
const QuicBandwidth kLocalLinkBandwidth =
    QuicBandwidth::FromKBitsPerSecond(10000);
const QuicTime::Delta kTestPropagationDelay =
    QuicTime::Delta::FromMilliseconds(30);
const QuicTime::Delta kLocalPropagationDelay =
    QuicTime::Delta::FromMilliseconds(2);
const QuicTime::Delta kTestTransferTime =
    kTestLinkBandwidth.TransferTime(kMaxOutgoingPacketSize) +
    kLocalLinkBandwidth.TransferTime(kMaxOutgoingPacketSize);
const QuicTime::Delta kTestRtt =
    (kTestPropagationDelay + kLocalPropagationDelay + kTestTransferTime) * 2;
const QuicByteCount kTestBdp = kTestRtt * kTestLinkBandwidth;

class BbrSenderTest : public QuicTest {
 protected:
  BbrSenderTest()
      : simulator_(&random_),
        bbr_sender_(&simulator_, "BBR sender", "Receiver",
                    Perspective::IS_CLIENT,
                    /*connection_id=*/TestConnectionId(42)),
        competing_sender_(&simulator_, "Competing sender", "Competing receiver",
                          Perspective::IS_CLIENT,
                          /*connection_id=*/TestConnectionId(43)),
        receiver_(&simulator_, "Receiver", "BBR sender", Perspective::IS_SERVER,
                  /*connection_id=*/TestConnectionId(42)),
        competing_receiver_(&simulator_, "Competing receiver",
                            "Competing sender", Perspective::IS_SERVER,
                            /*connection_id=*/TestConnectionId(43)),
        receiver_multiplexer_("Receiver multiplexer",
                              {&receiver_, &competing_receiver_}) {
    rtt_stats_ = bbr_sender_.connection()->sent_packet_manager().GetRttStats();
    const int kTestMaxPacketSize = 1350;
    bbr_sender_.connection()->SetMaxPacketLength(kTestMaxPacketSize);
    sender_ = SetupBbrSender(&bbr_sender_);
    SetConnectionOption(kBBRA);
    clock_ = simulator_.GetClock();
  }

  void SetUp() override {
    if (quiche::GetQuicheCommandLineFlag(FLAGS_quic_bbr_test_regression_mode) ==
        "regress") {
      SendAlgorithmTestResult expected;
      ASSERT_TRUE(LoadSendAlgorithmTestResult(&expected));
      random_seed_ = expected.random_seed();
    } else {
      random_seed_ = QuicRandom::GetInstance()->RandUint64();
    }
    random_.set_seed(random_seed_);
    QUIC_LOG(INFO) << "BbrSenderTest simulator set up.  Seed: " << random_seed_;
  }

  ~BbrSenderTest() {
    const std::string regression_mode =
        quiche::GetQuicheCommandLineFlag(FLAGS_quic_bbr_test_regression_mode);
    const QuicTime::Delta simulated_duration = clock_->Now() - QuicTime::Zero();
    if (regression_mode == "record") {
      RecordSendAlgorithmTestResult(random_seed_,
                                    simulated_duration.ToMicroseconds());
    } else if (regression_mode == "regress") {
      CompareSendAlgorithmTestResult(simulated_duration.ToMicroseconds());
    }
  }

  uint64_t random_seed_;
  SimpleRandom random_;
  simulator::Simulator simulator_;
  simulator::QuicEndpoint bbr_sender_;
  simulator::QuicEndpoint competing_sender_;
  simulator::QuicEndpoint receiver_;
  simulator::QuicEndpoint competing_receiver_;
  simulator::QuicEndpointMultiplexer receiver_multiplexer_;
  std::unique_ptr<simulator::Switch> switch_;
  std::unique_ptr<simulator::SymmetricLink> bbr_sender_link_;
  std::unique_ptr<simulator::SymmetricLink> competing_sender_link_;
  std::unique_ptr<simulator::SymmetricLink> receiver_link_;

  // Owned by different components of the connection.
  const QuicClock* clock_;
  const RttStats* rtt_stats_;
  BbrSender* sender_;

  // Enables BBR on |endpoint| and returns the associated BBR congestion
  // controller.
  BbrSender* SetupBbrSender(simulator::QuicEndpoint* endpoint) {
    const RttStats* rtt_stats =
        endpoint->connection()->sent_packet_manager().GetRttStats();
    // Ownership of the sender will be overtaken by the endpoint.
    BbrSender* sender = new BbrSender(
        endpoint->connection()->clock()->Now(), rtt_stats,
        QuicSentPacketManagerPeer::GetUnackedPacketMap(
            QuicConnectionPeer::GetSentPacketManager(endpoint->connection())),
        kInitialCongestionWindowPackets,
        GetQuicFlag(quic_max_congestion_window), &random_,
        QuicConnectionPeer::GetStats(endpoint->connection()));
    QuicConnectionPeer::SetSendAlgorithm(endpoint->connection(), sender);
    endpoint->RecordTrace();
    return sender;
  }

  // Creates a default setup, which is a network with a bottleneck between the
  // receiver and the switch.  The switch has the buffers four times larger than
  // the bottleneck BDP, which should guarantee a lack of losses.
  void CreateDefaultSetup() {
    switch_ = std::make_unique<simulator::Switch>(&simulator_, "Switch", 8,
                                                  2 * kTestBdp);
    bbr_sender_link_ = std::make_unique<simulator::SymmetricLink>(
        &bbr_sender_, switch_->port(1), kLocalLinkBandwidth,
        kLocalPropagationDelay);
    receiver_link_ = std::make_unique<simulator::SymmetricLink>(
        &receiver_, switch_->port(2), kTestLinkBandwidth,
        kTestPropagationDelay);
  }

  // Same as the default setup, except the buffer now is half of the BDP.
  void CreateSmallBufferSetup() {
    switch_ = std::make_unique<simulator::Switch>(&simulator_, "Switch", 8,
                                                  0.5 * kTestBdp);
    bbr_sender_link_ = std::make_unique<simulator::SymmetricLink>(
        &bbr_sender_, switch_->port(1), kLocalLinkBandwidth,
        kLocalPropagationDelay);
    receiver_link_ = std::make_unique<simulator::SymmetricLink>(
        &receiver_, switch_->port(2), kTestLinkBandwidth,
        kTestPropagationDelay);
  }

  // Creates the variation of the default setup in which there is another sender
  // that competes for the same bottleneck link.
  void CreateCompetitionSetup() {
    switch_ = std::make_unique<simulator::Switch>(&simulator_, "Switch", 8,
                                                  2 * kTestBdp);

    // Add a small offset to the competing link in order to avoid
    // synchronization effects.
    const QuicTime::Delta small_offset = QuicTime::Delta::FromMicroseconds(3);
    bbr_sender_link_ = std::make_unique<simulator::SymmetricLink>(
        &bbr_sender_, switch_->port(1), kLocalLinkBandwidth,
        kLocalPropagationDelay);
    competing_sender_link_ = std::make_unique<simulator::SymmetricLink>(
        &competing_sender_, switch_->port(3), kLocalLinkBandwidth,
        kLocalPropagationDelay + small_offset);
    receiver_link_ = std::make_unique<simulator::SymmetricLink>(
        &receiver_multiplexer_, switch_->port(2), kTestLinkBandwidth,
        kTestPropagationDelay);
  }

  // Creates a BBR vs BBR competition setup.
  void CreateBbrVsBbrSetup() {
    SetupBbrSender(&competing_sender_);
    CreateCompetitionSetup();
  }

  void EnableAggregation(QuicByteCount aggregation_bytes,
                         QuicTime::Delta aggregation_timeout) {
    // Enable aggregation on the path from the receiver to the sender.
    switch_->port_queue(1)->EnableAggregation(aggregation_bytes,
                                              aggregation_timeout);
  }

  void DoSimpleTransfer(QuicByteCount transfer_size, QuicTime::Delta deadline) {
    bbr_sender_.AddBytesToTransfer(transfer_size);
    // TODO(vasilvv): consider rewriting this to run until the receiver actually
    // receives the intended amount of bytes.
    bool simulator_result = simulator_.RunUntilOrTimeout(
        [this]() { return bbr_sender_.bytes_to_transfer() == 0; }, deadline);
    EXPECT_TRUE(simulator_result)
        << "Simple transfer failed.  Bytes remaining: "
        << bbr_sender_.bytes_to_transfer();
    QUIC_LOG(INFO) << "Simple transfer state: " << sender_->ExportDebugState();
  }

  // Drive the simulator by sending enough data to enter PROBE_BW.
  void DriveOutOfStartup() {
    ASSERT_FALSE(sender_->ExportDebugState().is_at_full_bandwidth);
    DoSimpleTransfer(1024 * 1024, QuicTime::Delta::FromSeconds(15));
    EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
    EXPECT_APPROX_EQ(kTestLinkBandwidth,
                     sender_->ExportDebugState().max_bandwidth, 0.02f);
  }

  // Send |bytes|-sized bursts of data |number_of_bursts| times, waiting for
  // |wait_time| between each burst.
  void SendBursts(size_t number_of_bursts, QuicByteCount bytes,
                  QuicTime::Delta wait_time) {
    ASSERT_EQ(0u, bbr_sender_.bytes_to_transfer());
    for (size_t i = 0; i < number_of_bursts; i++) {
      bbr_sender_.AddBytesToTransfer(bytes);

      // Transfer data and wait for three seconds between each transfer.
      simulator_.RunFor(wait_time);

      // Ensure the connection did not time out.
      ASSERT_TRUE(bbr_sender_.connection()->connected());
      ASSERT_TRUE(receiver_.connection()->connected());
    }

    simulator_.RunFor(wait_time + kTestRtt);
    ASSERT_EQ(0u, bbr_sender_.bytes_to_transfer());
  }

  void SetConnectionOption(QuicTag option) {
    QuicConfig config;
    QuicTagVector options;
    options.push_back(option);
    QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
    sender_->SetFromConfig(config, Perspective::IS_SERVER);
  }
};

TEST_F(BbrSenderTest, SetInitialCongestionWindow) {
  EXPECT_NE(3u * kDefaultTCPMSS, sender_->GetCongestionWindow());
  sender_->SetInitialCongestionWindowInPackets(3);
  EXPECT_EQ(3u * kDefaultTCPMSS, sender_->GetCongestionWindow());
}

// Test a simple long data transfer in the default setup.
TEST_F(BbrSenderTest, SimpleTransfer) {
  CreateDefaultSetup();

  // At startup make sure we are at the default.
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
  // At startup make sure we can send.
  EXPECT_TRUE(sender_->CanSend(0));
  // And that window is un-affected.
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());

  // Verify that Sender is in slow start.
  EXPECT_TRUE(sender_->InSlowStart());

  // Verify that pacing rate is based on the initial RTT.
  QuicBandwidth expected_pacing_rate = QuicBandwidth::FromBytesAndTimeDelta(
      2.885 * kDefaultWindowTCP, rtt_stats_->initial_rtt());
  EXPECT_APPROX_EQ(expected_pacing_rate.ToBitsPerSecond(),
                   sender_->PacingRate(0).ToBitsPerSecond(), 0.01f);

  ASSERT_GE(kTestBdp, kDefaultWindowTCP + kDefaultTCPMSS);

  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(30));
  EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
  EXPECT_EQ(0u, bbr_sender_.connection()->GetStats().packets_lost);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);

  // The margin here is quite high, since there exists a possibility that the
  // connection just exited high gain cycle.
  EXPECT_APPROX_EQ(kTestRtt, rtt_stats_->smoothed_rtt(), 0.2f);
}

TEST_F(BbrSenderTest, SimpleTransferBBRB) {
  SetConnectionOption(kBBRB);
  CreateDefaultSetup();

  // At startup make sure we are at the default.
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
  // At startup make sure we can send.
  EXPECT_TRUE(sender_->CanSend(0));
  // And that window is un-affected.
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());

  // Verify that Sender is in slow start.
  EXPECT_TRUE(sender_->InSlowStart());

  // Verify that pacing rate is based on the initial RTT.
  QuicBandwidth expected_pacing_rate = QuicBandwidth::FromBytesAndTimeDelta(
      2.885 * kDefaultWindowTCP, rtt_stats_->initial_rtt());
  EXPECT_APPROX_EQ(expected_pacing_rate.ToBitsPerSecond(),
                   sender_->PacingRate(0).ToBitsPerSecond(), 0.01f);

  ASSERT_GE(kTestBdp, kDefaultWindowTCP + kDefaultTCPMSS);

  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(30));
  EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
  EXPECT_EQ(0u, bbr_sender_.connection()->GetStats().packets_lost);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);

  // The margin here is quite high, since there exists a possibility that the
  // connection just exited high gain cycle.
  EXPECT_APPROX_EQ(kTestRtt, rtt_stats_->smoothed_rtt(), 0.2f);
}

// Test a simple transfer in a situation when the buffer is less than BDP.
TEST_F(BbrSenderTest, SimpleTransferSmallBuffer) {
  CreateSmallBufferSetup();

  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(30));
  EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
  EXPECT_APPROX_EQ(kTestLinkBandwidth,
                   sender_->ExportDebugState().max_bandwidth, 0.01f);
  EXPECT_GE(bbr_sender_.connection()->GetStats().packets_lost, 0u);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);

  // The margin here is quite high, since there exists a possibility that the
  // connection just exited high gain cycle.
  EXPECT_APPROX_EQ(kTestRtt, sender_->GetMinRtt(), 0.2f);
}

TEST_F(BbrSenderTest, RemoveBytesLostInRecovery) {
  CreateDefaultSetup();

  DriveOutOfStartup();

  // Drop a packet to enter recovery.
  receiver_.DropNextIncomingPacket();
  ASSERT_TRUE(
      simulator_.RunUntilOrTimeout([this]() { return sender_->InRecovery(); },
                                   QuicTime::Delta::FromSeconds(30)));

  QuicUnackedPacketMap* unacked_packets =
      QuicSentPacketManagerPeer::GetUnackedPacketMap(
          QuicConnectionPeer::GetSentPacketManager(bbr_sender_.connection()));
  QuicPacketNumber largest_sent =
      bbr_sender_.connection()->sent_packet_manager().GetLargestSentPacket();
  // least_inflight is the smallest inflight packet.
  QuicPacketNumber least_inflight =
      bbr_sender_.connection()->sent_packet_manager().GetLeastUnacked();
  while (!unacked_packets->GetTransmissionInfo(least_inflight).in_flight) {
    ASSERT_LE(least_inflight, largest_sent);
    least_inflight++;
  }
  QuicPacketLength least_inflight_packet_size =
      unacked_packets->GetTransmissionInfo(least_inflight).bytes_sent;
  QuicByteCount prior_recovery_window =
      sender_->ExportDebugState().recovery_window;
  QuicByteCount prior_inflight = unacked_packets->bytes_in_flight();
  QUIC_LOG(INFO) << "Recovery window:" << prior_recovery_window
                 << ", least_inflight_packet_size:"
                 << least_inflight_packet_size
                 << ", bytes_in_flight:" << prior_inflight;
  ASSERT_GT(prior_recovery_window, least_inflight_packet_size);

  // Lose the least inflight packet and expect the recovery window to drop.
  unacked_packets->RemoveFromInFlight(least_inflight);
  LostPacketVector lost_packets;
  lost_packets.emplace_back(least_inflight, least_inflight_packet_size);
  sender_->OnCongestionEvent(false, prior_inflight, clock_->Now(), {},
                             lost_packets, 0, 0);
  EXPECT_EQ(sender_->ExportDebugState().recovery_window,
            prior_inflight - least_inflight_packet_size);
  EXPECT_LT(sender_->ExportDebugState().recovery_window, prior_recovery_window);
}

// Test a simple long data transfer with 2 rtts of aggregation.
TEST_F(BbrSenderTest, SimpleTransfer2RTTAggregationBytes) {
  SetConnectionOption(kBSAO);
  CreateDefaultSetup();
  // 2 RTTs of aggregation, with a max of 10kb.
  EnableAggregation(10 * 1024, 2 * kTestRtt);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(sender_->ExportDebugState().mode == BbrSender::PROBE_BW ||
              sender_->ExportDebugState().mode == BbrSender::PROBE_RTT);

  EXPECT_APPROX_EQ(kTestLinkBandwidth,
                   sender_->ExportDebugState().max_bandwidth, 0.01f);

  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(kTestRtt * 4, rtt_stats_->smoothed_rtt());
  EXPECT_APPROX_EQ(kTestRtt, rtt_stats_->min_rtt(), 0.5f);
}

// Test a simple long data transfer with 2 rtts of aggregation.
TEST_F(BbrSenderTest, SimpleTransferAckDecimation) {
  SetConnectionOption(kBSAO);
  // Decrease the CWND gain so extra CWND is required with stretch acks.
  SetQuicFlag(quic_bbr_cwnd_gain, 1.0);
  sender_ = new BbrSender(
      bbr_sender_.connection()->clock()->Now(), rtt_stats_,
      QuicSentPacketManagerPeer::GetUnackedPacketMap(
          QuicConnectionPeer::GetSentPacketManager(bbr_sender_.connection())),
      kInitialCongestionWindowPackets, GetQuicFlag(quic_max_congestion_window),
      &random_, QuicConnectionPeer::GetStats(bbr_sender_.connection()));
  QuicConnectionPeer::SetSendAlgorithm(bbr_sender_.connection(), sender_);
  CreateDefaultSetup();

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);

  EXPECT_APPROX_EQ(kTestLinkBandwidth,
                   sender_->ExportDebugState().max_bandwidth, 0.01f);

  // TODO(ianswett): Expect 0 packets are lost once BBR no longer measures
  // bandwidth higher than the link rate.
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(kTestRtt * 2, rtt_stats_->smoothed_rtt());
  EXPECT_APPROX_EQ(kTestRtt, rtt_stats_->min_rtt(), 0.1f);
}

// Test a simple long data transfer with 2 rtts of aggregation.
// TODO(b/172302465) Re-enable this test.
TEST_F(BbrSenderTest, QUIC_TEST_DISABLED_IN_CHROME(
                          SimpleTransfer2RTTAggregationBytes20RTTWindow)) {
  SetConnectionOption(kBSAO);
  CreateDefaultSetup();
  SetConnectionOption(kBBR4);
  // 2 RTTs of aggregation, with a max of 10kb.
  EnableAggregation(10 * 1024, 2 * kTestRtt);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(sender_->ExportDebugState().mode == BbrSender::PROBE_BW ||
              sender_->ExportDebugState().mode == BbrSender::PROBE_RTT);

  EXPECT_APPROX_EQ(kTestLinkBandwidth,
                   sender_->ExportDebugState().max_bandwidth, 0.01f);

  // TODO(ianswett): Expect 0 packets are lost once BBR no longer measures
  // bandwidth higher than the link rate.
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(kTestRtt * 4, rtt_stats_->smoothed_rtt());
  EXPECT_APPROX_EQ(kTestRtt, rtt_stats_->min_rtt(), 0.25f);
}

// Test a simple long data transfer with 2 rtts of aggregation.
TEST_F(BbrSenderTest, SimpleTransfer2RTTAggregationBytes40RTTWindow) {
  SetConnectionOption(kBSAO);
  CreateDefaultSetup();
  SetConnectionOption(kBBR5);
  // 2 RTTs of aggregation, with a max of 10kb.
  EnableAggregation(10 * 1024, 2 * kTestRtt);

  // Transfer 12MB.
  DoSimpleTransfer(12 * 1024 * 1024, QuicTime::Delta::FromSeconds(35));
  EXPECT_TRUE(sender_->ExportDebugState().mode == BbrSender::PROBE_BW ||
              sender_->ExportDebugState().mode == BbrSender::PROBE_RTT);

  EXPECT_APPROX_EQ(kTestLinkBandwidth,
                   sender_->ExportDebugState().max_bandwidth, 0.01f);

  // TODO(ianswett): Expect 0 packets are lost once BBR no longer measures
  // bandwidth higher than the link rate.
  // The margin here is high, because the aggregation greatly increases
  // smoothed rtt.
  EXPECT_GE(kTestRtt * 4, rtt_stats_->smoothed_rtt());
  EXPECT_APPROX_EQ(kTestRtt, rtt_stats_->min_rtt(), 0.25f);
}

// Test the number of losses incurred by the startup phase in a situation when
// the buffer is less than BDP.
TEST_F(BbrSenderTest, PacketLossOnSmallBufferStartup) {
  CreateSmallBufferSetup();

  DriveOutOfStartup();
  float loss_rate =
      static_cast<float>(bbr_sender_.connection()->GetStats().packets_lost) /
      bbr_sender_.connection()->GetStats().packets_sent;
  EXPECT_LE(loss_rate, 0.31);
}

// Test the number of losses incurred by the startup phase in a situation when
// the buffer is less than BDP, with a STARTUP CWND gain of 2.
TEST_F(BbrSenderTest, PacketLossOnSmallBufferStartupDerivedCWNDGain) {
  CreateSmallBufferSetup();

  SetConnectionOption(kBBQ2);
  DriveOutOfStartup();
  float loss_rate =
      static_cast<float>(bbr_sender_.connection()->GetStats().packets_lost) /
      bbr_sender_.connection()->GetStats().packets_sent;
  EXPECT_LE(loss_rate, 0.1);
}

// Ensures the code transitions loss recovery states correctly (NOT_IN_RECOVERY
// -> CONSERVATION -> GROWTH -> NOT_IN_RECOVERY).
TEST_F(BbrSenderTest, RecoveryStates) {
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(10);
  bool simulator_result;
  CreateSmallBufferSetup();

  bbr_sender_.AddBytesToTransfer(100 * 1024 * 1024);
  ASSERT_EQ(BbrSender::NOT_IN_RECOVERY,
            sender_->ExportDebugState().recovery_state);

  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().recovery_state !=
               BbrSender::NOT_IN_RECOVERY;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::CONSERVATION,
            sender_->ExportDebugState().recovery_state);

  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().recovery_state !=
               BbrSender::CONSERVATION;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::GROWTH, sender_->ExportDebugState().recovery_state);

  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().recovery_state != BbrSender::GROWTH;
      },
      timeout);

  ASSERT_EQ(BbrSender::NOT_IN_RECOVERY,
            sender_->ExportDebugState().recovery_state);
  ASSERT_TRUE(simulator_result);
}

// Verify the behavior of the algorithm in the case when the connection sends
// small bursts of data after sending continuously for a while.
TEST_F(BbrSenderTest, ApplicationLimitedBursts) {
  CreateDefaultSetup();
  EXPECT_FALSE(sender_->HasGoodBandwidthEstimateForResumption());

  DriveOutOfStartup();
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);
  EXPECT_TRUE(sender_->HasGoodBandwidthEstimateForResumption());

  SendBursts(20, 512, QuicTime::Delta::FromSeconds(3));
  EXPECT_TRUE(sender_->ExportDebugState().last_sample_is_app_limited);
  EXPECT_TRUE(sender_->HasGoodBandwidthEstimateForResumption());
  EXPECT_APPROX_EQ(kTestLinkBandwidth,
                   sender_->ExportDebugState().max_bandwidth, 0.01f);
}

// Verify the behavior of the algorithm in the case when the connection sends
// small bursts of data and then starts sending continuously.
TEST_F(BbrSenderTest, ApplicationLimitedBurstsWithoutPrior) {
  CreateDefaultSetup();

  SendBursts(40, 512, QuicTime::Delta::FromSeconds(3));
  EXPECT_TRUE(sender_->ExportDebugState().last_sample_is_app_limited);

  DriveOutOfStartup();
  EXPECT_APPROX_EQ(kTestLinkBandwidth,
                   sender_->ExportDebugState().max_bandwidth, 0.01f);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);
}

// Verify that the DRAIN phase works correctly.
TEST_F(BbrSenderTest, Drain) {
  CreateDefaultSetup();
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(10);
  // Get the queue at the bottleneck, which is the outgoing queue at the port to
  // which the receiver is connected.
  const simulator::Queue* queue = switch_->port_queue(2);
  bool simulator_result;

  // We have no intention of ever finishing this transfer.
  bbr_sender_.AddBytesToTransfer(100 * 1024 * 1024);

  // Run the startup, and verify that it fills up the queue.
  ASSERT_EQ(BbrSender::STARTUP, sender_->ExportDebugState().mode);
  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().mode != BbrSender::STARTUP;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::DRAIN, sender_->ExportDebugState().mode);
  EXPECT_APPROX_EQ(sender_->BandwidthEstimate() * (1 / 2.885f),
                   sender_->PacingRate(0), 0.01f);

  // BBR uses CWND gain of 2 during STARTUP, hence it will fill the buffer
  // with approximately 1 BDP.  Here, we use 0.8 to give some margin for
  // error.
  EXPECT_GE(queue->bytes_queued(), 0.8 * kTestBdp);

  // Observe increased RTT due to bufferbloat.
  const QuicTime::Delta queueing_delay =
      kTestLinkBandwidth.TransferTime(queue->bytes_queued());
  EXPECT_APPROX_EQ(kTestRtt + queueing_delay, rtt_stats_->latest_rtt(), 0.1f);

  // Transition to the drain phase and verify that it makes the queue
  // have at most a BDP worth of packets.
  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return sender_->ExportDebugState().mode != BbrSender::DRAIN; },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
  EXPECT_LE(queue->bytes_queued(), kTestBdp);

  // Wait for a few round trips and ensure we're in appropriate phase of gain
  // cycling before taking an RTT measurement.
  const QuicRoundTripCount start_round_trip =
      sender_->ExportDebugState().round_trip_count;
  simulator_result = simulator_.RunUntilOrTimeout(
      [this, start_round_trip]() {
        QuicRoundTripCount rounds_passed =
            sender_->ExportDebugState().round_trip_count - start_round_trip;
        return rounds_passed >= 4 &&
               sender_->ExportDebugState().gain_cycle_index == 7;
      },
      timeout);
  ASSERT_TRUE(simulator_result);

  // Observe the bufferbloat go away.
  EXPECT_APPROX_EQ(kTestRtt, rtt_stats_->smoothed_rtt(), 0.1f);
}

// TODO(wub): Re-enable this test once default drain_gain changed to 0.75.
// Verify that the DRAIN phase works correctly.
TEST_F(BbrSenderTest, DISABLED_ShallowDrain) {
  CreateDefaultSetup();
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(10);
  // Get the queue at the bottleneck, which is the outgoing queue at the port to
  // which the receiver is connected.
  const simulator::Queue* queue = switch_->port_queue(2);
  bool simulator_result;

  // We have no intention of ever finishing this transfer.
  bbr_sender_.AddBytesToTransfer(100 * 1024 * 1024);

  // Run the startup, and verify that it fills up the queue.
  ASSERT_EQ(BbrSender::STARTUP, sender_->ExportDebugState().mode);
  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().mode != BbrSender::STARTUP;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::DRAIN, sender_->ExportDebugState().mode);
  EXPECT_EQ(0.75 * sender_->BandwidthEstimate(), sender_->PacingRate(0));
  // BBR uses CWND gain of 2.88 during STARTUP, hence it will fill the buffer
  // with approximately 1.88 BDPs.  Here, we use 1.5 to give some margin for
  // error.
  EXPECT_GE(queue->bytes_queued(), 1.5 * kTestBdp);

  // Observe increased RTT due to bufferbloat.
  const QuicTime::Delta queueing_delay =
      kTestLinkBandwidth.TransferTime(queue->bytes_queued());
  EXPECT_APPROX_EQ(kTestRtt + queueing_delay, rtt_stats_->latest_rtt(), 0.1f);

  // Transition to the drain phase and verify that it makes the queue
  // have at most a BDP worth of packets.
  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return sender_->ExportDebugState().mode != BbrSender::DRAIN; },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
  EXPECT_LE(queue->bytes_queued(), kTestBdp);

  // Wait for a few round trips and ensure we're in appropriate phase of gain
  // cycling before taking an RTT measurement.
  const QuicRoundTripCount start_round_trip =
      sender_->ExportDebugState().round_trip_count;
  simulator_result = simulator_.RunUntilOrTimeout(
      [this, start_round_trip]() {
        QuicRoundTripCount rounds_passed =
            sender_->ExportDebugState().round_trip_count - start_round_trip;
        return rounds_passed >= 4 &&
               sender_->ExportDebugState().gain_cycle_index == 7;
      },
      timeout);
  ASSERT_TRUE(simulator_result);

  // Observe the bufferbloat go away.
  EXPECT_APPROX_EQ(kTestRtt, rtt_stats_->smoothed_rtt(), 0.1f);
}

// Verify that the connection enters and exits PROBE_RTT correctly.
TEST_F(BbrSenderTest, ProbeRtt) {
  CreateDefaultSetup();
  DriveOutOfStartup();

  // We have no intention of ever finishing this transfer.
  bbr_sender_.AddBytesToTransfer(100 * 1024 * 1024);

  // Wait until the connection enters PROBE_RTT.
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(12);
  bool simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().mode == BbrSender::PROBE_RTT;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  ASSERT_EQ(BbrSender::PROBE_RTT, sender_->ExportDebugState().mode);

  // Exit PROBE_RTT.
  const QuicTime probe_rtt_start = clock_->Now();
  const QuicTime::Delta time_to_exit_probe_rtt =
      kTestRtt + QuicTime::Delta::FromMilliseconds(200);
  simulator_.RunFor(1.5 * time_to_exit_probe_rtt);
  EXPECT_EQ(BbrSender::PROBE_BW, sender_->ExportDebugState().mode);
  EXPECT_GE(sender_->ExportDebugState().min_rtt_timestamp, probe_rtt_start);
}

// Ensure that a connection that is app-limited and is at sufficiently low
// bandwidth will not exit high gain phase, and similarly ensure that the
// connection will exit low gain early if the number of bytes in flight is low.
// TODO(crbug.com/1145095): Re-enable this test.
TEST_F(BbrSenderTest, QUIC_TEST_DISABLED_IN_CHROME(InFlightAwareGainCycling)) {
  CreateDefaultSetup();
  DriveOutOfStartup();

  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(5);
  while (!(sender_->ExportDebugState().gain_cycle_index >= 4 &&
           bbr_sender_.bytes_to_transfer() == 0)) {
    bbr_sender_.AddBytesToTransfer(kTestLinkBandwidth.ToBytesPerSecond());
    ASSERT_TRUE(simulator_.RunUntilOrTimeout(
        [this]() { return bbr_sender_.bytes_to_transfer() == 0; }, timeout));
  }

  // Send at 10% of available rate.  Run for 3 seconds, checking in the middle
  // and at the end.  The pacing gain should be high throughout.
  QuicBandwidth target_bandwidth = 0.1f * kTestLinkBandwidth;
  QuicTime::Delta burst_
```