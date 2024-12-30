Response:
The user wants a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_simulator_test.cc`. Specifically, they are asking for the functionality of the *third* part of this file.

Here's a breakdown of how to approach this:

1. **Identify the boundaries of the third part:** Since this is part 3 of 4, I need to look for clear divisions in the code, likely based on test case groupings or comments.

2. **Analyze the test cases within the third part:** For each test case, determine its purpose and what aspects of BBR2's congestion control logic it's exercising.

3. **Look for patterns and common themes:**  Are there specific modes, transitions, or edge cases being tested in this section?

4. **Address the specific requests:**
    * **Functionality:** Summarize the observed behavior and the BBR2 features being tested.
    * **Relation to JavaScript:**  Consider if any of the tested concepts (like congestion control, pacing, loss recovery) have analogues or interactions with JavaScript (e.g., in a browser context).
    * **Logical Reasoning (Input/Output):** For select test cases, identify the setup (input) and the expected state or behavior being verified (output).
    * **User/Programming Errors:** Think about how the scenarios in the tests could reflect common mistakes in configuration or usage of BBR2 or the network stack.
    * **User Steps to Reach Here:**  Consider the user's journey leading to the execution of these tests.
    * **Overall Functionality of Part 3:** Provide a concise summary of what this section of the test file achieves.

**Mental Walkthrough of the Code Snippet (Part 3):**

* **`SenderPoliced` test:** Focuses on how BBR2 behaves when there's a sender-side policer limiting the outgoing traffic.
* **`StartupStats` test:** Checks the collection and correctness of statistics related to the STARTUP congestion control phase.
* **`ProbeUpAdaptInflightHiGradually` test:** Verifies the gradual increase of the `inflight_hi` variable during the PROBE_UP phase.
* **`LossOnlyCongestionEvent` test:**  Confirms that BBR2 doesn't adjust bandwidth estimates solely based on loss events.
* **`SpuriousLossEvent` test:** Simulates and tests BBR2's handling of cases where a packet is initially considered lost but is later acknowledged.
* **`ProbeRttAfterQuiescenceImmediatelyExits` test:**  Examines the transition from PROBE_RTT to PROBE_BW after a period of inactivity.
* **`ProbeBwAfterQuiescencePostponeMinRttTimestamp` test:** Checks if the minimum RTT timestamp is updated correctly after a period of quiescence.
* **`SwitchToBbr2MidConnection` test:**  Covers the scenario of switching from a different congestion control algorithm (likely CUBIC, given the setup in earlier parts of the file) to BBR2 during an active connection.
* **`AdjustNetworkParameters` test:** Tests the functionality of externally adjusting network parameters like bandwidth and RTT.
* **Tests related to initial congestion window (`200InitialCongestionWindowWithNetworkParameterAdjusted`, `100InitialCongestionWindowFromNetworkParameter`, `100InitialCongestionWindowWithNetworkParameterAdjusted`):**  These verify the behavior of BBR2 when the initial congestion window is constrained by network parameters or connection options.
* **Start of `MultiSenderTopologyParams` and `Bbr2MultiSenderTest`:** This signals the beginning of a new set of tests focusing on scenarios with multiple senders.

Based on this, I can now structure the response to address each of the user's points.
这是`net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_simulator_test.cc`文件的第三部分，主要集中在以下BBR2拥塞控制算法的特性和场景的测试：

**功能归纳 (第三部分):**

* **在存在发送端策略器 (Sender Policer) 的情况下测试 BBR2 的行为:** 验证当发送端受到速率限制时，BBR2 是否能正常工作，并观察其带宽估计和丢包率。
* **测试 BBR2 的启动阶段 (STARTUP) 的统计信息收集:** 验证 BBR2 是否正确记录了启动阶段的次数和持续时间。
* **测试 BBR2 在探测带宽模式 (PROBE_BW) 的上升阶段 (PROBE_UP) 如何逐步调整 `inflight_hi` (目标 Inflight 大小):** 验证 BBR2 在此阶段是否会根据网络状况逐步增加允许的最大 Inflight 数据量。
* **测试仅发生丢包事件时 BBR2 的行为:** 验证当只收到丢包反馈而没有 ACK 时，BBR2 的带宽估计是否保持不变。
* **测试 BBR2 如何处理虚假丢包事件 (Spurious Loss):**  模拟一个数据包被认为丢失但随后又被确认的情况，验证 BBR2 是否能正确处理此类事件。
* **测试 BBR2 在空闲期 (Quiescence) 结束后立即退出探测 RTT 模式 (PROBE_RTT):** 验证在连接空闲一段时间后，一旦开始发送数据，BBR2 能否快速回到探测带宽模式。
* **测试 BBR2 在空闲期后延迟更新最小 RTT 时间戳的行为:** 验证在空闲期结束后，BBR2 是否会等待一段时间再更新最小 RTT 时间戳。
* **测试在连接过程中从其他拥塞控制算法切换到 BBR2 的情况:** 模拟从 `BbrSender` 切换到 `Bbr2Sender`，验证切换过程的平滑性和 BBR2 的正常工作。
* **测试 BBR2 响应网络参数调整的能力:**  验证可以通过 `AdjustNetworkParameters` 接口动态调整 BBR2 的带宽、RTT 和拥塞窗口等参数。
* **测试在网络参数调整后，BBR2 的初始拥塞窗口 (Initial Congestion Window, ICWND) 的限制:**  验证当通过网络参数设置较大的初始带宽时，BBR2 的拥塞窗口是否会受到最大值的限制 (例如 200 个 MSS)。
* **测试通过网络参数设置或连接选项设置初始拥塞窗口为 100 个 MSS 的情况:** 验证 BBR2 是否能正确响应这种初始拥塞窗口的限制。
* **引入多发送方场景 (Bbr2MultiSenderTest):**  开始定义用于测试多个发送方共享同一个瓶颈链路的拓扑结构和测试类。

**与 JavaScript 功能的关系:**

直接来说，这个 C++ 文件是 Chromium 网络栈的底层实现，与用户直接操作的 JavaScript 没有直接关联。然而，BBR2 算法的目标是提高网络传输效率，这最终会影响到基于浏览器的 JavaScript 应用的性能。

**举例说明:**

* **场景：** 用户在浏览器中加载一个大型网页，网页需要下载大量的图片、CSS 和 JavaScript 文件。
* **BBR2 的作用：** 如果浏览器使用 QUIC 协议，并且连接采用了 BBR2 拥塞控制算法，BBR2 会更有效地利用网络带宽，减少丢包和延迟，从而加快网页资源的加载速度。
* **JavaScript 的体现：**  网页加载速度的提升最终会体现在 JavaScript 代码的执行效率上，例如，资源加载更快，JavaScript 代码可以更早地执行，用户与网页的交互也会更加流畅。

**逻辑推理 (假设输入与输出):**

以 `TEST_F(Bbr2DefaultTopologyTest, ProbeUpAdaptInflightHiGradually)` 为例：

* **假设输入:**
    * BBR2 处于探测带宽模式的上升阶段 (PROBE_UP)。
    * 网络存在一定的时延和带宽。
    * 发送端发送了两个数据包，其中第一个数据包丢失。
* **逻辑推理:**
    * 在 PROBE_UP 阶段，BBR2 会尝试逐步增加 `inflight_hi`。
    * 发生丢包事件可能会导致 BBR2 降低 `inflight_hi` 以避免拥塞。
* **预期输出:**
    * 观察到 `inflight_hi` 的值在丢包后会低于发送这两个数据包前的期望值，但仍然大于丢失数据包之前的值。  具体而言，会小于 `2 * kDefaultMaxPacketSize` (因为丢了一个包)，但仍然比丢失前的 `inflight_hi` 大。

**用户或编程常见的使用错误:**

* **错误配置发送端策略器:**  用户或管理员可能错误地配置了发送端策略器，导致策略器的限制过于严格，反而降低了网络吞吐量，BBR2 的自适应能力在这种情况下可能受到影响。例如，将策略器的目标带宽设置得远低于实际可用带宽。
* **不理解 BBR2 的工作原理，盲目调整网络参数:**  用户或管理员可能不理解 BBR2 的自适应特性，尝试手动调整网络参数 (例如，拥塞窗口)，可能适得其反，干扰 BBR2 的正常工作。例如，在 BBR2 已经稳定工作的情况下，人为地减小拥塞窗口。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设开发人员在调试 Chromium 网络栈中与 BBR2 拥塞控制相关的问题，他们可能会进行以下步骤：

1. **遇到网络性能问题:** 用户反馈或者自动化测试发现使用了 QUIC 协议的连接性能不佳，例如下载速度慢，延迟高等。
2. **怀疑是拥塞控制算法的问题:** 开发人员可能会怀疑是 BBR2 算法在特定网络条件下工作不正常。
3. **查看 BBR2 的相关日志和指标:**  开发人员会查看 Chromium 的内部日志和性能指标，例如 BBR2 的状态、带宽估计、RTT 等，以获取初步的诊断信息。
4. **复现问题场景:** 开发人员尝试在测试环境中复现用户遇到的问题，例如模拟特定的网络拓扑和流量模式。
5. **运行 BBR2 的单元测试:**  为了更深入地了解 BBR2 的行为，开发人员可能会运行 `bbr2_simulator_test.cc` 中的单元测试，特别是与他们怀疑的场景相关的测试。例如，如果怀疑是发送端策略器的问题，他们可能会运行 `SenderPoliced` 测试。
6. **单步调试和分析代码:** 如果单元测试失败或者需要更深入的分析，开发人员可能会使用调试器单步执行 `bbr2_simulator_test.cc` 中的代码，结合 BBR2 的算法实现，来理解问题的根源。他们可能会关注 `OnCongestionEvent` 等关键函数的执行流程和状态变化。
7. **修改代码并验证:**  根据分析结果，开发人员可能会修改 BBR2 的实现，并重新运行单元测试来验证修复效果。

**总结 (第三部分功能):**

这部分测试用例主要关注 BBR2 算法在各种复杂场景下的行为，包括存在发送端策略器、连接空闲、从其他算法切换、以及响应外部网络参数调整等情况。 目标是验证 BBR2 在这些场景下的正确性、稳定性和自适应性。 此外，它开始引入多发送方共享瓶颈链路的测试场景，为后续部分更复杂的测试奠定基础。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/bbr2_simulator_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
/ connection will exit low gain early if the number of bytes in flight is low.
TEST_F(Bbr2DefaultTopologyTest, InFlightAwareGainCycling) {
  DefaultTopologyParams params;
  CreateNetwork(params);
  DriveOutOfStartup(params);

  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(5);
  bool simulator_result;

  // Start a few cycles prior to the high gain one.
  simulator_result = SendUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().probe_bw.phase ==
               CyclePhase::PROBE_REFILL;
      },
      timeout);
  ASSERT_TRUE(simulator_result);

  // Send at 10% of available rate.  Run for 3 seconds, checking in the middle
  // and at the end.  The pacing gain should be high throughout.
  QuicBandwidth target_bandwidth = 0.1f * params.BottleneckBandwidth();
  QuicTime::Delta burst_interval = QuicTime::Delta::FromMilliseconds(300);
  for (int i = 0; i < 2; i++) {
    SendBursts(params, 5, target_bandwidth * burst_interval, burst_interval);
    EXPECT_EQ(Bbr2Mode::PROBE_BW, sender_->ExportDebugState().mode);
    EXPECT_EQ(CyclePhase::PROBE_UP, sender_->ExportDebugState().probe_bw.phase);
    EXPECT_APPROX_EQ(params.BottleneckBandwidth(),
                     sender_->ExportDebugState().bandwidth_hi, 0.02f);
  }

  if (GetQuicReloadableFlag(quic_pacing_remove_non_initial_burst)) {
    QuicSentPacketManagerPeer::GetPacingSender(
        &sender_connection()->sent_packet_manager())
        ->SetBurstTokens(10);
  }

  // Now that in-flight is almost zero and the pacing gain is still above 1,
  // send approximately 1.4 BDPs worth of data. This should cause the PROBE_BW
  // mode to enter low gain cycle(PROBE_DOWN), and exit it earlier than one
  // min_rtt due to running out of data to send.
  sender_endpoint_.AddBytesToTransfer(1.4 * params.BDP());
  simulator_result = simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().probe_bw.phase ==
               CyclePhase::PROBE_DOWN;
      },
      timeout);
  ASSERT_TRUE(simulator_result);
  simulator_.RunFor(0.75 * sender_->ExportDebugState().min_rtt);
  EXPECT_EQ(Bbr2Mode::PROBE_BW, sender_->ExportDebugState().mode);
  EXPECT_EQ(CyclePhase::PROBE_CRUISE,
            sender_->ExportDebugState().probe_bw.phase);
}

// Test exiting STARTUP earlier upon loss due to loss.
TEST_F(Bbr2DefaultTopologyTest, ExitStartupDueToLoss) {
  DefaultTopologyParams params;
  params.switch_queue_capacity_in_bdp = 0.5;
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
  EXPECT_GE(2u, sender_->ExportDebugState().round_trip_count - max_bw_round);
  EXPECT_EQ(
      1u,
      sender_->ExportDebugState().startup.round_trips_without_bandwidth_growth);
  EXPECT_NE(0u, sender_connection_stats().packets_lost);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);

  EXPECT_GT(sender_->ExportDebugState().inflight_hi, 1.2f * params.BDP());
}

// Test exiting STARTUP earlier upon loss due to loss when connection option
// B2SL is used.
TEST_F(Bbr2DefaultTopologyTest, ExitStartupDueToLossB2SL) {
  SetConnectionOption(kB2SL);
  DefaultTopologyParams params;
  params.switch_queue_capacity_in_bdp = 0.5;
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
  EXPECT_GE(2u, sender_->ExportDebugState().round_trip_count - max_bw_round);
  EXPECT_EQ(
      1u,
      sender_->ExportDebugState().startup.round_trips_without_bandwidth_growth);
  EXPECT_NE(0u, sender_connection_stats().packets_lost);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);

  EXPECT_APPROX_EQ(sender_->ExportDebugState().inflight_hi, params.BDP(), 0.1f);
}

// Verifies that in STARTUP, if we exceed loss threshold in a round, we exit
// STARTUP at the end of the round even if there's enough bandwidth growth.
TEST_F(Bbr2DefaultTopologyTest, ExitStartupDueToLossB2NE) {
  // Set up flags such that any loss will be considered "too high".
  SetQuicFlag(quic_bbr2_default_startup_full_loss_count, 0);
  SetQuicFlag(quic_bbr2_default_loss_threshold, 0.0);

  sender_ = SetupBbr2Sender(&sender_endpoint_, /*old_sender=*/nullptr);

  SetConnectionOption(kB2NE);
  DefaultTopologyParams params;
  params.switch_queue_capacity_in_bdp = 0.5;
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
  EXPECT_EQ(sender_->ExportDebugState().round_trip_count, max_bw_round);
  EXPECT_EQ(
      0u,
      sender_->ExportDebugState().startup.round_trips_without_bandwidth_growth);
  EXPECT_NE(0u, sender_connection_stats().packets_lost);
}

TEST_F(Bbr2DefaultTopologyTest, SenderPoliced) {
  DefaultTopologyParams params;
  params.sender_policer_params = TrafficPolicerParams();
  params.sender_policer_params->initial_burst_size = 1000 * 10;
  params.sender_policer_params->max_bucket_size = 1000 * 100;
  params.sender_policer_params->target_bandwidth =
      params.BottleneckBandwidth() * 0.25;

  CreateNetwork(params);

  ASSERT_GE(params.BDP(), kDefaultInitialCwndBytes + kDefaultTCPMSS);

  DoSimpleTransfer(3 * 1024 * 1024, QuicTime::Delta::FromSeconds(30));
  EXPECT_TRUE(Bbr2ModeIsOneOf({Bbr2Mode::PROBE_BW, Bbr2Mode::PROBE_RTT}));
  // TODO(wub): Fix (long-term) bandwidth overestimation in policer mode, then
  // reduce the loss rate upper bound.
  EXPECT_LE(sender_loss_rate_in_packets(), 0.30);
}

// TODO(wub): Add other slowstart stats to BBRv2.
TEST_F(Bbr2DefaultTopologyTest, StartupStats) {
  DefaultTopologyParams params;
  CreateNetwork(params);

  DriveOutOfStartup(params);
  ASSERT_FALSE(sender_->InSlowStart());

  const QuicConnectionStats& stats = sender_connection_stats();
  // The test explicitly replaces the default-created send algorithm with the
  // one created by the test. slowstart_count increaments every time a BBR
  // sender is created.
  EXPECT_GE(stats.slowstart_count, 1u);
  EXPECT_FALSE(stats.slowstart_duration.IsRunning());
  EXPECT_THAT(stats.slowstart_duration.GetTotalElapsedTime(),
              AllOf(Ge(QuicTime::Delta::FromMilliseconds(500)),
                    Le(QuicTime::Delta::FromMilliseconds(1500))));
  EXPECT_EQ(stats.slowstart_duration.GetTotalElapsedTime(),
            QuicConnectionPeer::GetSentPacketManager(sender_connection())
                ->GetSlowStartDuration());
}

TEST_F(Bbr2DefaultTopologyTest, ProbeUpAdaptInflightHiGradually) {
  DefaultTopologyParams params;
  CreateNetwork(params);

  DriveOutOfStartup(params);

  AckedPacketVector acked_packets;
  QuicPacketNumber acked_packet_number =
      sender_unacked_map()->GetLeastUnacked();
  for (auto& info : *sender_unacked_map()) {
    acked_packets.emplace_back(acked_packet_number++, info.bytes_sent,
                               SimulatedNow());
  }

  // Advance time significantly so the OnCongestionEvent enters PROBE_REFILL.
  QuicTime now = SimulatedNow() + QuicTime::Delta::FromSeconds(5);
  auto next_packet_number = sender_unacked_map()->largest_sent_packet() + 1;
  sender_->OnCongestionEvent(
      /*rtt_updated=*/true, sender_unacked_map()->bytes_in_flight(), now,
      acked_packets, {}, 0, 0);
  ASSERT_EQ(CyclePhase::PROBE_REFILL,
            sender_->ExportDebugState().probe_bw.phase);

  // Send and Ack one packet to exit app limited and enter PROBE_UP.
  sender_->OnPacketSent(now, /*bytes_in_flight=*/0, next_packet_number++,
                        kDefaultMaxPacketSize, HAS_RETRANSMITTABLE_DATA);
  now = now + params.RTT();
  sender_->OnCongestionEvent(
      /*rtt_updated=*/true, kDefaultMaxPacketSize, now,
      {AckedPacket(next_packet_number - 1, kDefaultMaxPacketSize, now)}, {}, 0,
      0);
  ASSERT_EQ(CyclePhase::PROBE_UP, sender_->ExportDebugState().probe_bw.phase);

  // Send 2 packets and lose the first one(50% loss) to exit PROBE_UP.
  for (uint64_t i = 0; i < 2; ++i) {
    sender_->OnPacketSent(now, /*bytes_in_flight=*/i * kDefaultMaxPacketSize,
                          next_packet_number++, kDefaultMaxPacketSize,
                          HAS_RETRANSMITTABLE_DATA);
  }
  now = now + params.RTT();
  sender_->OnCongestionEvent(
      /*rtt_updated=*/true, 2 * kDefaultMaxPacketSize, now,
      {AckedPacket(next_packet_number - 1, kDefaultMaxPacketSize, now)},
      {LostPacket(next_packet_number - 2, kDefaultMaxPacketSize)}, 0, 0);

  QuicByteCount inflight_hi = sender_->ExportDebugState().inflight_hi;
  EXPECT_LT(2 * kDefaultMaxPacketSize, inflight_hi);
}

// Ensures bandwidth estimate does not change after a loss only event.
TEST_F(Bbr2DefaultTopologyTest, LossOnlyCongestionEvent) {
  DefaultTopologyParams params;
  CreateNetwork(params);

  DriveOutOfStartup(params);
  EXPECT_FALSE(sender_->ExportDebugState().last_sample_is_app_limited);

  // Send some bursts, each burst increments round count by 1, since it only
  // generates small, app-limited samples, the max_bandwidth_filter_ will not be
  // updated.
  SendBursts(params, 20, 512, QuicTime::Delta::FromSeconds(3));

  // Run until we have something in flight.
  sender_endpoint_.AddBytesToTransfer(50 * 1024 * 1024);
  bool simulator_result = simulator_.RunUntilOrTimeout(
      [&]() { return sender_unacked_map()->bytes_in_flight() > 0; },
      QuicTime::Delta::FromSeconds(5));
  ASSERT_TRUE(simulator_result);

  const QuicBandwidth prior_bandwidth_estimate = sender_->BandwidthEstimate();
  EXPECT_APPROX_EQ(params.BottleneckBandwidth(), prior_bandwidth_estimate,
                   0.01f);

  // Lose the least unacked packet.
  LostPacketVector lost_packets;
  lost_packets.emplace_back(
      sender_connection()->sent_packet_manager().GetLeastUnacked(),
      kDefaultMaxPacketSize);

  QuicTime now = simulator_.GetClock()->Now() + params.RTT() * 0.25;
  sender_->OnCongestionEvent(false, sender_unacked_map()->bytes_in_flight(),
                             now, {}, lost_packets, 0, 0);

  // Bandwidth estimate should not change for the loss only event.
  EXPECT_EQ(prior_bandwidth_estimate, sender_->BandwidthEstimate());
}

// Simulate the case where a packet is considered lost but then acked.
TEST_F(Bbr2DefaultTopologyTest, SpuriousLossEvent) {
  DefaultTopologyParams params;
  CreateNetwork(params);

  DriveOutOfStartup(params);

  // Make sure we have something in flight.
  if (sender_unacked_map()->bytes_in_flight() == 0) {
    sender_endpoint_.AddBytesToTransfer(50 * 1024 * 1024);
    bool simulator_result = simulator_.RunUntilOrTimeout(
        [&]() { return sender_unacked_map()->bytes_in_flight() > 0; },
        QuicTime::Delta::FromSeconds(5));
    ASSERT_TRUE(simulator_result);
  }

  // Lose all in flight packets.
  QuicTime now = simulator_.GetClock()->Now() + params.RTT() * 0.25;
  const QuicByteCount prior_inflight = sender_unacked_map()->bytes_in_flight();
  LostPacketVector lost_packets;
  for (QuicPacketNumber packet_number = sender_unacked_map()->GetLeastUnacked();
       sender_unacked_map()->HasInFlightPackets(); packet_number++) {
    const auto& info = sender_unacked_map()->GetTransmissionInfo(packet_number);
    if (!info.in_flight) {
      continue;
    }
    lost_packets.emplace_back(packet_number, info.bytes_sent);
    sender_unacked_map()->RemoveFromInFlight(packet_number);
  }
  ASSERT_FALSE(lost_packets.empty());
  sender_->OnCongestionEvent(false, prior_inflight, now, {}, lost_packets, 0,
                             0);

  // Pretend the first lost packet number is acked.
  now = now + params.RTT() * 0.5;
  AckedPacketVector acked_packets;
  acked_packets.emplace_back(lost_packets[0].packet_number, 0, now);
  acked_packets.back().spurious_loss = true;
  EXPECT_EQ(sender_unacked_map()->bytes_in_flight(), 0);
  sender_->OnCongestionEvent(false, sender_unacked_map()->bytes_in_flight(),
                             now, acked_packets, {}, 0, 0);

  EXPECT_EQ(sender_->GetNetworkModel().total_bytes_sent(),
            sender_->GetNetworkModel().total_bytes_acked() +
                sender_->GetNetworkModel().total_bytes_lost());
}

// After quiescence, if the sender is in PROBE_RTT, it should transition to
// PROBE_BW immediately on the first sent packet after quiescence.
TEST_F(Bbr2DefaultTopologyTest, ProbeRttAfterQuiescenceImmediatelyExits) {
  DefaultTopologyParams params;
  CreateNetwork(params);

  DriveOutOfStartup(params);

  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(15);
  bool simulator_result;

  // Keep sending until reach PROBE_RTT.
  simulator_result = SendUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().mode == Bbr2Mode::PROBE_RTT;
      },
      timeout);
  ASSERT_TRUE(simulator_result);

  // Wait for entering a quiescence of 5 seconds.
  ASSERT_TRUE(simulator_.RunUntilOrTimeout(
      [this]() {
        return sender_unacked_map()->bytes_in_flight() == 0 &&
               sender_->ExportDebugState().mode == Bbr2Mode::PROBE_RTT;
      },
      timeout));

  simulator_.RunFor(QuicTime::Delta::FromSeconds(5));

  // Send one packet to exit quiescence.
  EXPECT_EQ(sender_->ExportDebugState().mode, Bbr2Mode::PROBE_RTT);
  sender_->OnPacketSent(SimulatedNow(), /*bytes_in_flight=*/0,
                        sender_unacked_map()->largest_sent_packet() + 1,
                        kDefaultMaxPacketSize, HAS_RETRANSMITTABLE_DATA);

  EXPECT_EQ(sender_->ExportDebugState().mode, Bbr2Mode::PROBE_BW);
}

TEST_F(Bbr2DefaultTopologyTest, ProbeBwAfterQuiescencePostponeMinRttTimestamp) {
  DefaultTopologyParams params;
  CreateNetwork(params);

  DriveOutOfStartup(params);

  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(5);
  bool simulator_result;

  // Keep sending until reach PROBE_REFILL.
  simulator_result = SendUntilOrTimeout(
      [this]() {
        return sender_->ExportDebugState().probe_bw.phase ==
               CyclePhase::PROBE_REFILL;
      },
      timeout);
  ASSERT_TRUE(simulator_result);

  const QuicTime min_rtt_timestamp_before_idle =
      sender_->ExportDebugState().min_rtt_timestamp;

  // Wait for entering a quiescence of 15 seconds.
  ASSERT_TRUE(simulator_.RunUntilOrTimeout(
      [this]() { return sender_unacked_map()->bytes_in_flight() == 0; },
      params.RTT() + timeout));

  simulator_.RunFor(QuicTime::Delta::FromSeconds(15));

  // Send some data to exit quiescence.
  SendBursts(params, 1, kDefaultTCPMSS, QuicTime::Delta::Zero());
  const QuicTime min_rtt_timestamp_after_idle =
      sender_->ExportDebugState().min_rtt_timestamp;

  EXPECT_LT(min_rtt_timestamp_before_idle + QuicTime::Delta::FromSeconds(14),
            min_rtt_timestamp_after_idle);
}

TEST_F(Bbr2DefaultTopologyTest, SwitchToBbr2MidConnection) {
  QuicTime now = QuicTime::Zero();
  BbrSender old_sender(sender_connection()->clock()->Now(),
                       sender_connection()->sent_packet_manager().GetRttStats(),
                       GetUnackedMap(sender_connection()),
                       kDefaultInitialCwndPackets + 1,
                       GetQuicFlag(quic_max_congestion_window), &random_,
                       QuicConnectionPeer::GetStats(sender_connection()));

  QuicPacketNumber next_packet_number(1);

  // Send packets 1-4.
  while (next_packet_number < QuicPacketNumber(5)) {
    now = now + QuicTime::Delta::FromMilliseconds(10);

    old_sender.OnPacketSent(now, /*bytes_in_flight=*/0, next_packet_number++,
                            /*bytes=*/1350, HAS_RETRANSMITTABLE_DATA);
  }

  // Switch from |old_sender| to |sender_|.
  const QuicByteCount old_sender_cwnd = old_sender.GetCongestionWindow();
  sender_ = SetupBbr2Sender(&sender_endpoint_, &old_sender);
  EXPECT_EQ(old_sender_cwnd, sender_->GetCongestionWindow());

  // Send packets 5-7.
  now = now + QuicTime::Delta::FromMilliseconds(10);
  sender_->OnPacketSent(now, /*bytes_in_flight=*/1350, next_packet_number++,
                        /*bytes=*/23, NO_RETRANSMITTABLE_DATA);

  now = now + QuicTime::Delta::FromMilliseconds(10);
  sender_->OnPacketSent(now, /*bytes_in_flight=*/1350, next_packet_number++,
                        /*bytes=*/767, HAS_RETRANSMITTABLE_DATA);

  QuicByteCount bytes_in_flight = 767;
  while (next_packet_number < QuicPacketNumber(30)) {
    now = now + QuicTime::Delta::FromMilliseconds(10);
    bytes_in_flight += 1350;
    sender_->OnPacketSent(now, bytes_in_flight, next_packet_number++,
                          /*bytes=*/1350, HAS_RETRANSMITTABLE_DATA);
  }

  // Ack 1 & 2.
  AckedPacketVector acked = {
      AckedPacket(QuicPacketNumber(1), /*bytes_acked=*/0, QuicTime::Zero()),
      AckedPacket(QuicPacketNumber(2), /*bytes_acked=*/0, QuicTime::Zero()),
  };
  now = now + QuicTime::Delta::FromMilliseconds(2000);
  sender_->OnCongestionEvent(true, bytes_in_flight, now, acked, {}, 0, 0);

  // Send 30-41.
  while (next_packet_number < QuicPacketNumber(42)) {
    now = now + QuicTime::Delta::FromMilliseconds(10);
    bytes_in_flight += 1350;
    sender_->OnPacketSent(now, bytes_in_flight, next_packet_number++,
                          /*bytes=*/1350, HAS_RETRANSMITTABLE_DATA);
  }

  // Ack 3.
  acked = {
      AckedPacket(QuicPacketNumber(3), /*bytes_acked=*/0, QuicTime::Zero()),
  };
  now = now + QuicTime::Delta::FromMilliseconds(2000);
  sender_->OnCongestionEvent(true, bytes_in_flight, now, acked, {}, 0, 0);

  // Send 42.
  now = now + QuicTime::Delta::FromMilliseconds(10);
  bytes_in_flight += 1350;
  sender_->OnPacketSent(now, bytes_in_flight, next_packet_number++,
                        /*bytes=*/1350, HAS_RETRANSMITTABLE_DATA);

  // Ack 4-7.
  acked = {
      AckedPacket(QuicPacketNumber(4), /*bytes_acked=*/0, QuicTime::Zero()),
      AckedPacket(QuicPacketNumber(5), /*bytes_acked=*/0, QuicTime::Zero()),
      AckedPacket(QuicPacketNumber(6), /*bytes_acked=*/767, QuicTime::Zero()),
      AckedPacket(QuicPacketNumber(7), /*bytes_acked=*/1350, QuicTime::Zero()),
  };
  now = now + QuicTime::Delta::FromMilliseconds(2000);
  sender_->OnCongestionEvent(true, bytes_in_flight, now, acked, {}, 0, 0);
  EXPECT_FALSE(sender_->BandwidthEstimate().IsZero());
}

TEST_F(Bbr2DefaultTopologyTest, AdjustNetworkParameters) {
  DefaultTopologyParams params;
  CreateNetwork(params);

  QUIC_LOG(INFO) << "Initial cwnd: " << sender_debug_state().congestion_window
                 << "\nInitial pacing rate: " << sender_->PacingRate(0)
                 << "\nInitial bandwidth estimate: "
                 << sender_->BandwidthEstimate()
                 << "\nInitial rtt: " << sender_debug_state().min_rtt;

  sender_connection()->AdjustNetworkParameters(
      SendAlgorithmInterface::NetworkParams(params.BottleneckBandwidth(),
                                            params.RTT(),
                                            /*allow_cwnd_to_decrease=*/false));

  EXPECT_EQ(params.BDP(), sender_->ExportDebugState().congestion_window);

  EXPECT_EQ(params.BottleneckBandwidth(),
            sender_->PacingRate(/*bytes_in_flight=*/0));
  EXPECT_NE(params.BottleneckBandwidth(), sender_->BandwidthEstimate());

  EXPECT_APPROX_EQ(params.RTT(), sender_->ExportDebugState().min_rtt, 0.01f);

  DriveOutOfStartup(params);
}

TEST_F(Bbr2DefaultTopologyTest,
       200InitialCongestionWindowWithNetworkParameterAdjusted) {
  DefaultTopologyParams params;
  CreateNetwork(params);

  sender_endpoint_.AddBytesToTransfer(1 * 1024 * 1024);

  // Wait until an ACK comes back.
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(5);
  bool simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return !sender_->ExportDebugState().min_rtt.IsZero(); },
      timeout);
  ASSERT_TRUE(simulator_result);

  // Bootstrap cwnd by a overly large bandwidth sample.
  sender_connection()->AdjustNetworkParameters(
      SendAlgorithmInterface::NetworkParams(1024 * params.BottleneckBandwidth(),
                                            QuicTime::Delta::Zero(), false));

  // Verify cwnd is capped at 200.
  EXPECT_EQ(200 * kDefaultTCPMSS,
            sender_->ExportDebugState().congestion_window);
  EXPECT_GT(1024 * params.BottleneckBandwidth(), sender_->PacingRate(0));
}

TEST_F(Bbr2DefaultTopologyTest,
       100InitialCongestionWindowFromNetworkParameter) {
  DefaultTopologyParams params;
  CreateNetwork(params);

  sender_endpoint_.AddBytesToTransfer(1 * 1024 * 1024);
  // Wait until an ACK comes back.
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(5);
  bool simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return !sender_->ExportDebugState().min_rtt.IsZero(); },
      timeout);
  ASSERT_TRUE(simulator_result);

  // Bootstrap cwnd by a overly large bandwidth sample.
  SendAlgorithmInterface::NetworkParams network_params(
      1024 * params.BottleneckBandwidth(), QuicTime::Delta::Zero(), false);
  network_params.max_initial_congestion_window = 100;
  sender_connection()->AdjustNetworkParameters(network_params);

  // Verify cwnd is capped at 100.
  EXPECT_EQ(100 * kDefaultTCPMSS,
            sender_->ExportDebugState().congestion_window);
  EXPECT_GT(1024 * params.BottleneckBandwidth(), sender_->PacingRate(0));
}

TEST_F(Bbr2DefaultTopologyTest,
       100InitialCongestionWindowWithNetworkParameterAdjusted) {
  SetConnectionOption(kICW1);
  DefaultTopologyParams params;
  CreateNetwork(params);

  sender_endpoint_.AddBytesToTransfer(1 * 1024 * 1024);
  // Wait until an ACK comes back.
  const QuicTime::Delta timeout = QuicTime::Delta::FromSeconds(5);
  bool simulator_result = simulator_.RunUntilOrTimeout(
      [this]() { return !sender_->ExportDebugState().min_rtt.IsZero(); },
      timeout);
  ASSERT_TRUE(simulator_result);

  // Bootstrap cwnd by a overly large bandwidth sample.
  sender_connection()->AdjustNetworkParameters(
      SendAlgorithmInterface::NetworkParams(1024 * params.BottleneckBandwidth(),
                                            QuicTime::Delta::Zero(), false));

  // Verify cwnd is capped at 100.
  EXPECT_EQ(100 * kDefaultTCPMSS,
            sender_->ExportDebugState().congestion_window);
  EXPECT_GT(1024 * params.BottleneckBandwidth(), sender_->PacingRate(0));
}

// All Bbr2MultiSenderTests uses the following network topology:
//
//   Sender 0  (A Bbr2Sender)
//       |
//       | <-- local_links[0]
//       |
//       |  Sender N (1 <= N < kNumLocalLinks) (May or may not be a Bbr2Sender)
//       |      |
//       |      | <-- local_links[N]
//       |      |
//    Network switch
//           *  <-- the bottleneck queue in the direction
//           |          of the receiver
//           |
//           |  <-- test_link
//           |
//           |
//       Receiver
class MultiSenderTopologyParams {
 public:
  static constexpr size_t kNumLocalLinks = 8;
  std::array<LinkParams, kNumLocalLinks> local_links = {
      LinkParams(10000, 1987), LinkParams(10000, 1993), LinkParams(10000, 1997),
      LinkParams(10000, 1999), LinkParams(10000, 2003), LinkParams(10000, 2011),
      LinkParams(10000, 2017), LinkParams(10000, 2027),
  };

  LinkParams test_link = LinkParams(4000, 30000);

  const simulator::SwitchPortNumber switch_port_count = kNumLocalLinks + 1;

  // Network switch queue capacity, in number of BDPs.
  float switch_queue_capacity_in_bdp = 2;

  QuicBandwidth BottleneckBandwidth() const {
    // Make sure all local links have a higher bandwidth than the test link.
    for (size_t i = 0; i < local_links.size(); ++i) {
      QUICHE_CHECK_GT(local_links[i].bandwidth, test_link.bandwidth);
    }
    return test_link.bandwidth;
  }

  // Sender n's round trip time of a single full size packet.
  QuicTime::Delta Rtt(size_t n) const {
    return 2 * (local_links[n].delay + test_link.delay +
                local_links[n].bandwidth.TransferTime(kMaxOutgoingPacketSize) +
                test_link.bandwidth.TransferTime(kMaxOutgoingPacketSize));
  }

  QuicByteCount Bdp(size_t n) const { return BottleneckBandwidth() * Rtt(n); }

  QuicByteCount SwitchQueueCapacity() const {
    return switch_queue_capacity_in_bdp * Bdp(1);
  }

  std::string ToString() const {
    std::ostringstream os;
    os << "{ BottleneckBandwidth: " << BottleneckBandwidth();
    for (size_t i = 0; i < local_links.size(); ++i) {
      os << " RTT_" << i << ": " << Rtt(i) << " BDP_" << i << ": " << Bdp(i);
    }
    os << " BottleneckQueueSize: " << SwitchQueueCapacity() << "}";
    return os.str();
  }
};

class Bbr2MultiSenderTest : public Bbr2SimulatorTest {
 protected:
  Bbr2MultiSenderTest() {
    uint64_t first_connection_id = 42;
    std::vector<simulator::QuicEndpointBase*> receiver_endpoint_pointers;
    for (size_t i = 0; i < MultiSenderTopologyParams::kNumLocalLinks; ++i) {
      std::string sender_name = absl::StrCat("Sender", i + 1);
      std::string receiver_name = absl::StrCat("Receiver", i + 1);
      sender_endpoints_.push_back(std::make_unique<simulator::QuicEndpoint>(
          &simulator_, sender_name, receiver_name, Perspective::IS_CLIENT,
          TestConnectionId(first_connection_id + i)));
      receiver_endpoints_.push_back(std::make_unique<simulator::QuicEndpoint>(
          &simulator_, receiver_name, sender_name, Perspective::IS_SERVER,
          TestConnectionId(first_connection_id + i)));
      receiver_endpoint_pointers.push_back(receiver_endpoints_.back().get());
    }
    receiver_multiplexer_ =
        std::make_unique<simulator::QuicEndpointMultiplexer>(
            "Receiver multiplexer", receiver_endpoint_pointers);
    sender_0_ = SetupBbr2Sender(sender_endpoints_[0].get());
  }

  ~Bbr2MultiSenderTest() {
    const auto* test_info =
        ::testing::UnitTest::GetInstance()->current_test_info();
    QUIC_LOG(INFO) << "Bbr2MultiSenderTest." << test_info->name()
                   << " completed at simulated time: "
                   << SimulatedNow().ToDebuggingValue() / 1e6
                   << " sec. Per sender stats:";
    for (size_t i = 0; i < sender_endpoints_.size(); ++i) {
      QUIC_LOG(INFO) << "sender[" << i << "]: "
                     << sender_connection(i)
                            ->sent_packet_manager()
                            .GetSendAlgorithm()
                            ->GetCongestionControlType()
                     << ", packet_loss:"
                     << 100.0 * sender_loss_rate_in_packets(i) << "%";
    }
  }

  Bbr2Sender* SetupBbr2Sender(simulator::QuicEndpoint* endpoint) {
    // Ownership of the sender will be overtaken by the endpoint.
    Bbr2Sender* sender = new Bbr2Sender(
        endpoint->connection()->clock()->Now(),
        endpoint->connection()->sent_packet_manager().GetRttStats(),
        QuicSentPacketManagerPeer::GetUnackedPacketMap(
            QuicConnectionPeer::GetSentPacketManager(endpoint->connection())),
        kDefaultInitialCwndPackets, GetQuicFlag(quic_max_congestion_window),
        &random_, QuicConnectionPeer::GetStats(endpoint->connection()),
        nullptr);
    // TODO(ianswett): Add dedicated tests for this option until it becomes
    // the default behavior.
    SetConnectionOption(sender, kBBRA);

    QuicConnectionPeer::SetSendAlgorithm(endpoint->connection(), sender);
    endpoint->RecordTrace();
    return sender;
  }

  BbrSender* SetupBbrSender(simulator::QuicEndpoint* endpoint) {
    // Ownership of the sender will be overtaken by the endpoint.
    BbrSender* sender = new BbrSender(
        endpoint->connection()->clock()->Now(),
        endpoint->connection()->sent_packet_manager().GetRttStats(),
        QuicSentPacketManagerPeer::GetUnackedPacketMap(
            QuicConnectionPeer::GetSentPacketManager(endpoint->connection())),
        kDefaultInitialCwndPackets, GetQuicFlag(quic_max_congestion_window),
        &random_, QuicConnectionPeer::GetStats(endpoint->connection()));
    QuicConnectionPeer::SetSendAlgorithm(endpoint->connection(), sender);
    endpoint->RecordTrace();
    return sender;
  }

  // reno => Reno. !reno => Cubic.
  TcpCubicSenderBytes* SetupTcpSender(simulator::QuicEndpoint* endpoint,
                                      bool reno) {
    // Ownership of the sender will be overtaken by the endpoint.
    TcpCubicSenderBytes* sender = new TcpCubicSenderBytes(
        endpoint->connection()->clock(),
        endpoint->connection()->sent_packet_manager().GetRttStats(), reno,
        kDefaultInitialCwndPackets, GetQuicFlag(quic_max_congestion_window),
        QuicConnectionPeer::GetStats(endpoint->connection()));
    QuicConnectionPeer::SetSendAlgorithm(endpoint->connection(), sender);
    endpoint->RecordTrace();
    return sender;
  }

  void SetConnectionOption(SendAlgorithmInterface* sender, QuicTag option) {
    QuicConfig config;
    QuicTagVector options;
    options.push_back(option);
    QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
    sender->SetFromConfig(config, Perspective::IS_SERVER);
  }

  void CreateNetwork(const MultiSenderTopologyParams& params) {
    QUIC_LOG(INFO) << "CreateNetwork with parameters: " << params.ToString();
    switch_ = std::make_unique<simulator::Switch>(&simulator_, "Switch",
                                                  params.switch_port_count,
                                                  params.SwitchQueueCapacity());

    network_links_.push_back(std::make_unique<simulator::SymmetricLink>(
        receiver_multiplexer_.get(), switch_->port(1),
        params.test_link.bandwidth, params.test_link.delay));
    for (size_t i = 0; i < MultiSenderTopologyParams::kNumLocalLinks; ++i) {
      simulator::SwitchPortNumber port_number = i + 2;
      network_links_.push_back(std::make_unique<simulator::SymmetricLink>(
          sender_endpoints_[i].get(), switch_->port(port_number),
          params.local_links[i].bandwidth, params.local_links[i].delay));
    }
  }

  QuicConnection* sender_connection(size_t which) {
    return sender_endpoints_[which]->connection();
  }

  const QuicConnectionStats& sender_connection_stats(size_t which) {
    return sender_connection(which)->GetStats();
  }

  float sender_loss_rate_in_packets(size_t which) {
    return static_cast<float>(sender_connection_stats(which).packets_lost) /
           sender_connection_stats(which).packets_sent;
  }

  std::vector<std::unique_ptr<simulator::QuicEndpoint>> sender_endpoints_;
  std::vector<std::unique_ptr<simulator::QuicEndpoint>> receiver_endpoints_;
  std::unique_ptr<simulator::QuicEndpointMultiplexer> receiver_multiplexer_;
  Bbr2Sender* sender_0_;

  std::unique_ptr<simulator::Switch> switch_;
  std::vector<std::unique_ptr<simulator::SymmetricLink>> network_links_;
};

TEST_F(Bbr2MultiSenderTest, Bbr2VsBbr2) {
  SetupBbr2Sender(sender_endpoints_[1].get());

  MultiSenderTopologyParams params;
  CreateNetwork(params);

  const QuicByteCount transfer_size = 10 * 1024 * 1024;
  const QuicTime::Delta transfer_time =
      params.BottleneckBandwidth().TransferTime(transfer_size);
  QUIC_LOG(INFO) << "Single flow trans
"""


```