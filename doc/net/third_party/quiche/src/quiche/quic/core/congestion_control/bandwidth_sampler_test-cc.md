Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding of the Goal:**

The core request is to understand the functionality of `bandwidth_sampler_test.cc`. The decomposition includes:

* **Core Functionality:** What does the code *do*?
* **Relationship to JavaScript:**  Are there any connections, even if indirect?
* **Logical Reasoning (Input/Output):** How do specific actions lead to predictable results?
* **Common User Errors:** What mistakes might developers make when using or interacting with this code (or related concepts)?
* **User Path to This Code:** How would a user's actions lead to this code being relevant (primarily from a debugging perspective)?
* **Overall Summary:** A concise description of the file's purpose.

**2. Scanning the Code for Clues:**

The first step is to quickly scan the code for keywords and patterns that give hints about its purpose. Key observations:

* **`// Copyright 2016 The Chromium Authors...`**:  Confirms this is part of the Chromium project.
* **`#include "quiche/quic/core/congestion_control/bandwidth_sampler.h"`**:  This is the most important line. It tells us this file is testing the `BandwidthSampler` class.
* **`#include "quiche/quic/platform/api/quic_test.h"`**: Indicates this is a unit test file using the QUIC testing framework.
* **`namespace quic { namespace test {`**:  Standard C++ practice for organizing test code.
* **Class names like `BandwidthSamplerTest`, `MaxAckHeightTrackerTest`**:  Clearly identify the classes being tested.
* **Method names like `SendPacket`, `AckPacket`, `LosePacket`, `OnCongestionEvent`**:  Suggest the scenarios being tested involve sending, acknowledging, and losing network packets.
* **Assertions (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_LT`, `ASSERT_GE`):** Confirm this is test code verifying expected behavior.
* **Constants like `kRegularPacketSize`**: Provide context about the simulated network environment.
* **Parameters (`TestParameters`, `overestimate_avoidance`):** Indicate different test configurations.

**3. Deconstructing the `BandwidthSamplerTest` Class:**

This is the main focus. Analyze the member variables and methods:

* **`MockClock clock_`**:  Crucial for controlling the simulated time, essential for testing time-dependent network behavior.
* **`BandwidthSampler sampler_`**: The object under test.
* **`bytes_in_flight_`, `max_bandwidth_`, `est_bandwidth_upper_bound_`, `round_trip_count_`**:  Variables that represent the internal state of the congestion control mechanism.
* **`SendPacketInner`, `SendPacket`**: Simulate sending packets, updating the `BandwidthSampler`'s state.
* **`AckPacketInner`, `AckPacket`, `MakeAckedPacket`**: Simulate receiving acknowledgments, triggering updates in the `BandwidthSampler`. The `AckPacketInner` returns the important `BandwidthSample`.
* **`LosePacket`, `MakeLostPacket`**: Simulate packet loss.
* **`OnCongestionEvent`**:  The central method where the `BandwidthSampler` processes acknowledgments and losses to update its internal state and generate bandwidth samples.
* **`Send40PacketsAndAckFirst20`**: A helper function for setting up common test scenarios.

**4. Analyzing Individual Test Cases (`TEST_P` and `TEST_F`):**

Read the names of the test cases and their logic:

* **`SendAndWait`**: Tests basic send/ack scenarios.
* **`SendTimeState`**: Examines the `SendTimeState` structure.
* **`SendPaced`**: Tests with a fixed congestion window.
* **`SendWithLosses`**: Simulates packet loss.
* **`NotCongestionControlled`**: Tests how the sampler handles non-congestion-controlled packets.
* **`CompressedAck`**: Simulates bursty acknowledgments.
* **`ReorderedAck`**: Tests handling of out-of-order acknowledgments.
* **`AppLimited`**:  Focuses on the app-limited state and its impact on bandwidth estimation.
* **`FirstRoundTrip`**:  Tests bandwidth estimation during the initial round trip.
* **`RemoveObsoletePackets`**:  Verifies the functionality of removing tracked packet data.
* **`NeuterPacket`**:  Tests the handling of neutered (effectively canceled) packets.
* **`CongestionEventSampleDefaultValues`**: Checks the initial values of the `CongestionEventSample` struct.
* **`TwoAckedPacketsPerEvent`**:  Tests scenarios with multiple acknowledgments in a single event.
* **`LoseEveryOtherPacket`**:  Simulates consistent packet loss.
* **`AckHeightRespectBandwidthEstimateUpperBound`**: Tests how the sampler respects bandwidth limits.

**5. Deconstructing the `MaxAckHeightTrackerTest` Class:**

* **`MaxAckHeightTracker tracker_`**:  Another component related to congestion control, specifically tracking acknowledgment aggregation.
* **`AggregationEpisode`**:  A function that simulates periods of aggregated acknowledgments followed by quiet periods. This helps test the logic for identifying and handling ACK bursts.

**6. Connecting to the Request's Specific Points:**

* **Functionality:**  The tests clearly show the `BandwidthSampler` is responsible for estimating network bandwidth based on sent packets, received acknowledgments, and packet losses. It tracks packet information to calculate bandwidth samples and handles scenarios like app-limited states and reordered acknowledgments. The `MaxAckHeightTracker` aims to identify ACK aggregation.

* **JavaScript Relationship:** This is the trickiest part. The core QUIC implementation in Chromium is in C++. JavaScript in the browser interacts with the network stack through lower-level APIs. There's no direct JavaScript code in this file. The connection is *indirect*: JavaScript initiates network requests, which eventually trigger the QUIC protocol and its congestion control mechanisms (including the `BandwidthSampler`).

* **Logical Reasoning (Input/Output):**  The tests provide numerous examples. For instance, sending packets at a constant rate and acknowledging them results in a bandwidth sample matching that rate. Introducing packet loss reduces the estimated bandwidth. The tests explicitly set up these scenarios and verify the expected outcomes.

* **Common User Errors:** From a *developer* perspective (those working on the QUIC implementation), common errors might involve:
    * Incorrectly updating the `BandwidthSampler`'s state after sending, receiving, or losing packets.
    * Miscalculating the time differences between events.
    * Not handling edge cases like the initial round trip or app-limited scenarios correctly.

* **User Operation to This Code (Debugging):**  If a user experiences slow network performance or connection issues in a Chromium-based browser, and developers are investigating QUIC, they might look at the `BandwidthSampler`'s behavior. They might:
    1. Enable QUIC logging.
    2. Examine logs related to congestion control and bandwidth estimation.
    3. Step through the `BandwidthSampler`'s code (potentially including these test cases) in a debugger to understand how the bandwidth is being calculated.

* **Summary of Functionality (Part 1):** The first part of the file defines test fixtures and several test cases for the `BandwidthSampler` class. These tests cover basic send/ack scenarios, handling of packet loss, non-congestion-controlled packets, reordered acknowledgments, and the app-limited state. The tests use a mock clock to simulate time and verify the `BandwidthSampler`'s bandwidth estimation logic.

**7. Refinement and Organization:**

After the initial analysis, organize the information into a clear and structured format, using headings and bullet points as in the provided good answer. Ensure the explanation is concise and easy to understand. For the JavaScript connection, emphasize the indirect nature of the relationship. For the logical reasoning, pick a few representative examples from the tests. For user errors and debugging, think from the perspective of developers working on the QUIC stack.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/congestion_control/bandwidth_sampler_test.cc` 文件的第一部分，它是一个单元测试文件，专门用于测试 `BandwidthSampler` 类的功能。`BandwidthSampler` 类是 QUIC 协议中拥塞控制机制的一部分，用于估算网络带宽。

**功能归纳 (第一部分):**

这个文件的主要功能是提供了一系列的单元测试，以验证 `BandwidthSampler` 类的各种场景下的行为是否符合预期。  它通过模拟发送数据包、接收 ACK 包、丢包等网络事件，并使用断言 (如 `EXPECT_EQ`, `EXPECT_LT`) 来检查 `BandwidthSampler` 的状态和输出结果。

**具体功能点包括：**

* **基础的发送和等待测试 (`SendAndWait`):** 测试在简单的停等模式下，`BandwidthSampler` 是否能正确估算带宽。
* **`SendTimeState` 测试:** 验证 `BandwidthSampler` 记录的发送时间状态 (如已发送字节数、已确认字节数、已丢失字节数等) 的准确性。
* **窗口发送测试 (`SendPaced`):** 测试在固定拥塞窗口下，`BandwidthSampler` 的带宽估算能力。
* **丢包场景测试 (`SendWithLosses`):** 模拟网络丢包情况，检验 `BandwidthSampler` 如何调整带宽估算。
* **非拥塞控制数据包测试 (`NotCongestionControlled`):**  测试 `BandwidthSampler` 如何处理不参与拥塞控制的数据包 (例如，仅有头部的数据包)。
* **乱序 ACK 测试 (`ReorderedAck`):** 模拟接收到乱序的 ACK 包，测试 `BandwidthSampler` 的处理能力。
* **压缩 ACK 测试 (`CompressedAck`):**  模拟 ACK 包突发到达的情况，测试 `BandwidthSampler` 的反应。
* **应用层限制 (App-Limited) 测试 (`AppLimited`):** 测试在发送速率受应用层限制时，`BandwidthSampler` 的行为，以及如何从应用层限制状态恢复。
* **首个往返时延 (First Round Trip) 测试 (`FirstRoundTrip`):** 验证在连接建立初期，数据较少的情况下，`BandwidthSampler` 的带宽估算。
* **移除过时数据包测试 (`RemoveObsoletePackets`):**  测试 `BandwidthSampler` 清理不再需要的内部数据的功能。
* **`NeuterPacket` 测试:**  测试当一个数据包被 "neuter" (例如，因为重传而不再有效) 时，`BandwidthSampler` 的行为。
* **`CongestionEventSampleDefaultValues` 测试:** 检查 `CongestionEventSample` 结构体的默认值。
* **每次事件确认两个数据包测试 (`TwoAckedPacketsPerEvent`):** 测试在一次拥塞事件中收到多个 ACK 包时的处理。
* **丢失间隔数据包测试 (`LoseEveryOtherPacket`):** 模拟规律性丢包的情况。
* **ACK 高度与带宽上限关系测试 (`AckHeightRespectBandwidthEstimateUpperBound`):** 测试 ACK 包的数量如何影响带宽估算，并考虑带宽上限。

**与 JavaScript 功能的关系：**

`BandwidthSampler` 本身是用 C++ 实现的，直接与 JavaScript 代码没有关系。然而，JavaScript 在浏览器中发起网络请求时，底层的网络栈 (包括 QUIC 协议及其拥塞控制机制) 会被调用。

**举例说明：**

1. **用户在浏览器中访问一个网页：**
   - JavaScript 发起 HTTP/3 请求 (如果支持)。
   - 底层的 QUIC 协议开始连接协商。
   - 在数据传输阶段，`BandwidthSampler` 会根据发送和接收的包来估算网络带宽。
   - 如果 `BandwidthSampler` 估算到带宽较低，QUIC 的拥塞控制机制可能会降低发送速率，这最终会影响到 JavaScript 中看到的数据加载速度。

2. **JavaScript 进行 WebSocket 连接：**
   - WebSocket 连接也可能使用 QUIC 作为底层传输协议。
   - `BandwidthSampler` 会参与到 WebSocket 数据传输的拥塞控制中，影响实时数据的传输速率。

**逻辑推理 (假设输入与输出)：**

**假设输入：**

* **场景 1:** 以恒定速率发送一系列数据包，并且这些数据包都被及时确认。
* **场景 2:** 发送数据包，但部分数据包丢失，并且有延迟的确认。

**输出：**

* **场景 1:** `BandwidthSampler` 应该估算出一个接近实际发送速率的带宽值。测试用例 `SendAndWait` 和 `SendPaced` 验证了这一点。例如，在 `SendAndWait` 中，代码发送数据包并立即确认，期望 `current_sample` 与 `expected_bandwidth` 相等。
* **场景 2:** `BandwidthSampler` 估算的带宽值应该会降低，反映了网络拥塞或丢包。测试用例 `SendWithLosses` 模拟了这种情况，并期望 `last_bandwidth` 会是一个基于丢包率调整后的值。

**用户或编程常见的使用错误：**

虽然用户不会直接使用 `BandwidthSampler`，但开发者在实现或调试 QUIC 拥塞控制相关功能时可能会犯以下错误：

1. **未正确调用 `OnPacketSent` 和 `OnCongestionEvent`:**  这是 `BandwidthSampler` 工作的关键。如果在发送数据包或接收到 ACK 时没有通知 `BandwidthSampler`，它就无法进行准确的带宽估算。
   ```c++
   // 错误示例：发送数据包，但忘记调用 OnPacketSent
   void SendData(QuicPacketNumber packet_number, QuicByteCount bytes) {
     // ... 发送数据包的代码 ...
     // 缺少 sampler_.OnPacketSent(...) 的调用
   }

   // 错误示例：收到 ACK，但未触发拥塞事件更新
   void OnAckReceived(const AckFrame& ack_frame) {
     // ... 处理 ACK 的代码 ...
     // 缺少 sampler_.OnCongestionEvent(...) 的调用
   }
   ```

2. **时间戳不一致：** `BandwidthSampler` 依赖于准确的时间信息来计算速率。如果提供给 `OnPacketSent` 和 `OnCongestionEvent` 的时间戳不一致或不准确，会导致错误的带宽估算。
   ```c++
   MockClock clock_;
   BandwidthSampler sampler_;

   void SendPacketWithError(uint64_t packet_number, QuicByteCount bytes) {
     sampler_.OnPacketSent(clock_.Now(), QuicPacketNumber(packet_number), bytes, 0, HAS_RETRANSMITTABLE_DATA);
     // ...
   }

   void AckPacketWithError(uint64_t packet_number) {
     // 使用过时的时间戳
     sampler_.OnCongestionEvent(clock_.Now() - QuicTime::Delta::FromSeconds(10), 
                                {MakeAckedPacket(packet_number)}, {}, max_bandwidth_, est_bandwidth_upper_bound_, round_trip_count_);
   }
   ```

3. **状态管理错误：** `BandwidthSampler` 内部维护着连接状态。如果状态更新不正确 (例如，`bytes_in_flight_` 的维护)，会导致错误的带宽计算。

**用户操作是如何一步步的到达这里，作为调试线索：**

当用户遇到网络问题，例如网页加载缓慢、视频卡顿等，并且怀疑是 QUIC 协议的拥塞控制机制出现了问题时，开发人员可能会进行以下调试：

1. **用户报告网络问题：** 用户反馈在使用 Chrome 浏览器访问特定网站或进行特定操作时网络速度异常缓慢。
2. **开发者排查：** 开发者开始排查问题，可能怀疑是 QUIC 连接的拥塞控制算法出现了异常行为。
3. **启用 QUIC 内部日志：** 开发者可能会启用 Chrome 的内部日志 (例如使用 `chrome://net-export/`)，以查看 QUIC 连接的详细信息，包括拥塞控制相关的事件。
4. **分析日志：** 在日志中查找与 `BandwidthSampler` 相关的指标和事件，例如带宽估算值、发送速率调整等。
5. **代码审查和调试：** 如果日志显示 `BandwidthSampler` 的行为异常，开发者可能会查看 `bandwidth_sampler.cc` 和 `bandwidth_sampler_test.cc` 的代码，理解其实现逻辑，并尝试重现问题。
6. **运行单元测试：** 开发者可能会运行 `bandwidth_sampler_test.cc` 中的相关测试用例，以验证 `BandwidthSampler` 在特定场景下的行为是否符合预期。如果某个测试用例失败，则表明 `BandwidthSampler` 的实现可能存在 bug。
7. **单步调试：** 开发者可以使用调试器 (如 gdb) 单步执行 `BandwidthSampler` 的代码，观察其内部状态变化，以便更精确地定位问题。他们可能会设置断点在 `OnPacketSent` 或 `OnCongestionEvent` 等关键函数中，查看参数和内部变量的值。

总而言之，`bandwidth_sampler_test.cc` 是 QUIC 拥塞控制机制质量保证的关键部分，它通过大量的测试用例来确保 `BandwidthSampler` 能够在各种网络条件下准确地估算带宽，从而帮助 QUIC 协议实现高效可靠的数据传输。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/bandwidth_sampler_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
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

#include "quiche/quic/core/congestion_control/bandwidth_sampler.h"

#include <algorithm>
#include <cstdint>
#include <set>
#include <string>

#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_clock.h"

namespace quic {
namespace test {

class BandwidthSamplerPeer {
 public:
  static size_t GetNumberOfTrackedPackets(const BandwidthSampler& sampler) {
    return sampler.connection_state_map_.number_of_present_entries();
  }

  static QuicByteCount GetPacketSize(const BandwidthSampler& sampler,
                                     QuicPacketNumber packet_number) {
    return sampler.connection_state_map_.GetEntry(packet_number)->size();
  }
};

const QuicByteCount kRegularPacketSize = 1280;
// Enforce divisibility for some of the tests.
static_assert((kRegularPacketSize & 31) == 0,
              "kRegularPacketSize has to be five times divisible by 2");

struct TestParameters {
  bool overestimate_avoidance;
};

// Used by ::testing::PrintToStringParamName().
std::string PrintToString(const TestParameters& p) {
  return p.overestimate_avoidance ? "enable_overestimate_avoidance"
                                  : "no_enable_overestimate_avoidance";
}

// A test fixture with utility methods for BandwidthSampler tests.
class BandwidthSamplerTest : public QuicTestWithParam<TestParameters> {
 protected:
  BandwidthSamplerTest()
      : sampler_(nullptr, /*max_height_tracker_window_length=*/0),
        sampler_app_limited_at_start_(sampler_.is_app_limited()),
        bytes_in_flight_(0),
        max_bandwidth_(QuicBandwidth::Zero()),
        est_bandwidth_upper_bound_(QuicBandwidth::Infinite()),
        round_trip_count_(0) {
    // Ensure that the clock does not start at zero.
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
    if (GetParam().overestimate_avoidance) {
      sampler_.EnableOverestimateAvoidance();
    }
  }

  MockClock clock_;
  BandwidthSampler sampler_;
  bool sampler_app_limited_at_start_;
  QuicByteCount bytes_in_flight_;
  QuicBandwidth max_bandwidth_;  // Max observed bandwidth from acks.
  QuicBandwidth est_bandwidth_upper_bound_;
  QuicRoundTripCount round_trip_count_;  // Needed to calculate extra_acked.

  QuicByteCount PacketsToBytes(QuicPacketCount packet_count) {
    return packet_count * kRegularPacketSize;
  }

  void SendPacketInner(uint64_t packet_number, QuicByteCount bytes,
                       HasRetransmittableData has_retransmittable_data) {
    sampler_.OnPacketSent(clock_.Now(), QuicPacketNumber(packet_number), bytes,
                          bytes_in_flight_, has_retransmittable_data);
    if (has_retransmittable_data == HAS_RETRANSMITTABLE_DATA) {
      bytes_in_flight_ += bytes;
    }
  }

  void SendPacket(uint64_t packet_number) {
    SendPacketInner(packet_number, kRegularPacketSize,
                    HAS_RETRANSMITTABLE_DATA);
  }

  BandwidthSample AckPacketInner(uint64_t packet_number) {
    QuicByteCount size = BandwidthSamplerPeer::GetPacketSize(
        sampler_, QuicPacketNumber(packet_number));
    bytes_in_flight_ -= size;
    BandwidthSampler::CongestionEventSample sample = sampler_.OnCongestionEvent(
        clock_.Now(), {MakeAckedPacket(packet_number)}, {}, max_bandwidth_,
        est_bandwidth_upper_bound_, round_trip_count_);
    max_bandwidth_ = std::max(max_bandwidth_, sample.sample_max_bandwidth);
    BandwidthSample bandwidth_sample;
    bandwidth_sample.bandwidth = sample.sample_max_bandwidth;
    bandwidth_sample.rtt = sample.sample_rtt;
    bandwidth_sample.state_at_send = sample.last_packet_send_state;
    EXPECT_TRUE(bandwidth_sample.state_at_send.is_valid);
    return bandwidth_sample;
  }

  AckedPacket MakeAckedPacket(uint64_t packet_number) const {
    QuicByteCount size = BandwidthSamplerPeer::GetPacketSize(
        sampler_, QuicPacketNumber(packet_number));
    return AckedPacket(QuicPacketNumber(packet_number), size, clock_.Now());
  }

  LostPacket MakeLostPacket(uint64_t packet_number) const {
    return LostPacket(QuicPacketNumber(packet_number),
                      BandwidthSamplerPeer::GetPacketSize(
                          sampler_, QuicPacketNumber(packet_number)));
  }

  // Acknowledge receipt of a packet and expect it to be not app-limited.
  QuicBandwidth AckPacket(uint64_t packet_number) {
    BandwidthSample sample = AckPacketInner(packet_number);
    return sample.bandwidth;
  }

  BandwidthSampler::CongestionEventSample OnCongestionEvent(
      std::set<uint64_t> acked_packet_numbers,
      std::set<uint64_t> lost_packet_numbers) {
    AckedPacketVector acked_packets;
    for (auto it = acked_packet_numbers.begin();
         it != acked_packet_numbers.end(); ++it) {
      acked_packets.push_back(MakeAckedPacket(*it));
      bytes_in_flight_ -= acked_packets.back().bytes_acked;
    }

    LostPacketVector lost_packets;
    for (auto it = lost_packet_numbers.begin(); it != lost_packet_numbers.end();
         ++it) {
      lost_packets.push_back(MakeLostPacket(*it));
      bytes_in_flight_ -= lost_packets.back().bytes_lost;
    }

    BandwidthSampler::CongestionEventSample sample = sampler_.OnCongestionEvent(
        clock_.Now(), acked_packets, lost_packets, max_bandwidth_,
        est_bandwidth_upper_bound_, round_trip_count_);
    max_bandwidth_ = std::max(max_bandwidth_, sample.sample_max_bandwidth);
    return sample;
  }

  SendTimeState LosePacket(uint64_t packet_number) {
    QuicByteCount size = BandwidthSamplerPeer::GetPacketSize(
        sampler_, QuicPacketNumber(packet_number));
    bytes_in_flight_ -= size;
    LostPacket lost_packet(QuicPacketNumber(packet_number), size);
    BandwidthSampler::CongestionEventSample sample = sampler_.OnCongestionEvent(
        clock_.Now(), {}, {lost_packet}, max_bandwidth_,
        est_bandwidth_upper_bound_, round_trip_count_);
    EXPECT_TRUE(sample.last_packet_send_state.is_valid);
    EXPECT_EQ(sample.sample_max_bandwidth, QuicBandwidth::Zero());
    EXPECT_EQ(sample.sample_rtt, QuicTime::Delta::Infinite());
    return sample.last_packet_send_state;
  }

  // Sends one packet and acks it.  Then, send 20 packets.  Finally, send
  // another 20 packets while acknowledging previous 20.
  void Send40PacketsAndAckFirst20(QuicTime::Delta time_between_packets) {
    // Send 20 packets at a constant inter-packet time.
    for (int i = 1; i <= 20; i++) {
      SendPacket(i);
      clock_.AdvanceTime(time_between_packets);
    }

    // Ack packets 1 to 20, while sending new packets at the same rate as
    // before.
    for (int i = 1; i <= 20; i++) {
      AckPacket(i);
      SendPacket(i + 20);
      clock_.AdvanceTime(time_between_packets);
    }
  }
};

INSTANTIATE_TEST_SUITE_P(
    BandwidthSamplerTests, BandwidthSamplerTest,
    testing::Values(TestParameters{/*overestimate_avoidance=*/false},
                    TestParameters{/*overestimate_avoidance=*/true}),
    testing::PrintToStringParamName());

// Test the sampler in a simple stop-and-wait sender setting.
TEST_P(BandwidthSamplerTest, SendAndWait) {
  QuicTime::Delta time_between_packets = QuicTime::Delta::FromMilliseconds(10);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromBytesPerSecond(kRegularPacketSize * 100);

  // Send packets at the constant bandwidth.
  for (int i = 1; i < 20; i++) {
    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
    QuicBandwidth current_sample = AckPacket(i);
    EXPECT_EQ(expected_bandwidth, current_sample);
  }

  // Send packets at the exponentially decreasing bandwidth.
  for (int i = 20; i < 25; i++) {
    time_between_packets = time_between_packets * 2;
    expected_bandwidth = expected_bandwidth * 0.5;

    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
    QuicBandwidth current_sample = AckPacket(i);
    EXPECT_EQ(expected_bandwidth, current_sample);
  }
  sampler_.RemoveObsoletePackets(QuicPacketNumber(25));

  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

TEST_P(BandwidthSamplerTest, SendTimeState) {
  QuicTime::Delta time_between_packets = QuicTime::Delta::FromMilliseconds(10);

  // Send packets 1-5.
  for (int i = 1; i <= 5; i++) {
    SendPacket(i);
    EXPECT_EQ(PacketsToBytes(i), sampler_.total_bytes_sent());
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack packet 1.
  SendTimeState send_time_state = AckPacketInner(1).state_at_send;
  EXPECT_EQ(PacketsToBytes(1), send_time_state.total_bytes_sent);
  EXPECT_EQ(0u, send_time_state.total_bytes_acked);
  EXPECT_EQ(0u, send_time_state.total_bytes_lost);
  EXPECT_EQ(PacketsToBytes(1), sampler_.total_bytes_acked());

  // Lose packet 2.
  send_time_state = LosePacket(2);
  EXPECT_EQ(PacketsToBytes(2), send_time_state.total_bytes_sent);
  EXPECT_EQ(0u, send_time_state.total_bytes_acked);
  EXPECT_EQ(0u, send_time_state.total_bytes_lost);
  EXPECT_EQ(PacketsToBytes(1), sampler_.total_bytes_lost());

  // Lose packet 3.
  send_time_state = LosePacket(3);
  EXPECT_EQ(PacketsToBytes(3), send_time_state.total_bytes_sent);
  EXPECT_EQ(0u, send_time_state.total_bytes_acked);
  EXPECT_EQ(0u, send_time_state.total_bytes_lost);
  EXPECT_EQ(PacketsToBytes(2), sampler_.total_bytes_lost());

  // Send packets 6-10.
  for (int i = 6; i <= 10; i++) {
    SendPacket(i);
    EXPECT_EQ(PacketsToBytes(i), sampler_.total_bytes_sent());
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack all inflight packets.
  QuicPacketCount acked_packet_count = 1;
  EXPECT_EQ(PacketsToBytes(acked_packet_count), sampler_.total_bytes_acked());
  for (int i = 4; i <= 10; i++) {
    send_time_state = AckPacketInner(i).state_at_send;
    ++acked_packet_count;
    EXPECT_EQ(PacketsToBytes(acked_packet_count), sampler_.total_bytes_acked());
    EXPECT_EQ(PacketsToBytes(i), send_time_state.total_bytes_sent);
    if (i <= 5) {
      EXPECT_EQ(0u, send_time_state.total_bytes_acked);
      EXPECT_EQ(0u, send_time_state.total_bytes_lost);
    } else {
      EXPECT_EQ(PacketsToBytes(1), send_time_state.total_bytes_acked);
      EXPECT_EQ(PacketsToBytes(2), send_time_state.total_bytes_lost);
    }

    // This equation works because there is no neutered bytes.
    EXPECT_EQ(send_time_state.total_bytes_sent -
                  send_time_state.total_bytes_acked -
                  send_time_state.total_bytes_lost,
              send_time_state.bytes_in_flight);

    clock_.AdvanceTime(time_between_packets);
  }
}

// Test the sampler during regular windowed sender scenario with fixed
// CWND of 20.
TEST_P(BandwidthSamplerTest, SendPaced) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize);

  Send40PacketsAndAckFirst20(time_between_packets);

  // Ack the packets 21 to 40, arriving at the correct bandwidth.
  QuicBandwidth last_bandwidth = QuicBandwidth::Zero();
  for (int i = 21; i <= 40; i++) {
    last_bandwidth = AckPacket(i);
    EXPECT_EQ(expected_bandwidth, last_bandwidth) << "i is " << i;
    clock_.AdvanceTime(time_between_packets);
  }
  sampler_.RemoveObsoletePackets(QuicPacketNumber(41));

  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Test the sampler in a scenario where 50% of packets is consistently lost.
TEST_P(BandwidthSamplerTest, SendWithLosses) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize) * 0.5;

  // Send 20 packets, each 1 ms apart.
  for (int i = 1; i <= 20; i++) {
    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack packets 1 to 20, losing every even-numbered packet, while sending new
  // packets at the same rate as before.
  for (int i = 1; i <= 20; i++) {
    if (i % 2 == 0) {
      AckPacket(i);
    } else {
      LosePacket(i);
    }
    SendPacket(i + 20);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack the packets 21 to 40 with the same loss pattern.
  QuicBandwidth last_bandwidth = QuicBandwidth::Zero();
  for (int i = 21; i <= 40; i++) {
    if (i % 2 == 0) {
      last_bandwidth = AckPacket(i);
      EXPECT_EQ(expected_bandwidth, last_bandwidth);
    } else {
      LosePacket(i);
    }
    clock_.AdvanceTime(time_between_packets);
  }
  sampler_.RemoveObsoletePackets(QuicPacketNumber(41));

  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Test the sampler in a scenario where the 50% of packets are not
// congestion controlled (specifically, non-retransmittable data is not
// congestion controlled).  Should be functionally consistent in behavior with
// the SendWithLosses test.
TEST_P(BandwidthSamplerTest, NotCongestionControlled) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize) * 0.5;

  // Send 20 packets, each 1 ms apart. Every even packet is not congestion
  // controlled.
  for (int i = 1; i <= 20; i++) {
    SendPacketInner(
        i, kRegularPacketSize,
        i % 2 == 0 ? HAS_RETRANSMITTABLE_DATA : NO_RETRANSMITTABLE_DATA);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ensure only congestion controlled packets are tracked.
  EXPECT_EQ(10u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));

  // Ack packets 2 to 21, ignoring every even-numbered packet, while sending new
  // packets at the same rate as before.
  for (int i = 1; i <= 20; i++) {
    if (i % 2 == 0) {
      AckPacket(i);
    }
    SendPacketInner(
        i + 20, kRegularPacketSize,
        i % 2 == 0 ? HAS_RETRANSMITTABLE_DATA : NO_RETRANSMITTABLE_DATA);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack the packets 22 to 41 with the same congestion controlled pattern.
  QuicBandwidth last_bandwidth = QuicBandwidth::Zero();
  for (int i = 21; i <= 40; i++) {
    if (i % 2 == 0) {
      last_bandwidth = AckPacket(i);
      EXPECT_EQ(expected_bandwidth, last_bandwidth);
    }
    clock_.AdvanceTime(time_between_packets);
  }
  sampler_.RemoveObsoletePackets(QuicPacketNumber(41));

  // Since only congestion controlled packets are entered into the map, it has
  // to be empty at this point.
  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Simulate a situation where ACKs arrive in burst and earlier than usual, thus
// producing an ACK rate which is higher than the original send rate.
TEST_P(BandwidthSamplerTest, CompressedAck) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize);

  Send40PacketsAndAckFirst20(time_between_packets);

  // Simulate an RTT somewhat lower than the one for 1-to-21 transmission.
  clock_.AdvanceTime(time_between_packets * 15);

  // Ack the packets 21 to 40 almost immediately at once.
  QuicBandwidth last_bandwidth = QuicBandwidth::Zero();
  QuicTime::Delta ridiculously_small_time_delta =
      QuicTime::Delta::FromMicroseconds(20);
  for (int i = 21; i <= 40; i++) {
    last_bandwidth = AckPacket(i);
    clock_.AdvanceTime(ridiculously_small_time_delta);
  }
  EXPECT_EQ(expected_bandwidth, last_bandwidth);

  sampler_.RemoveObsoletePackets(QuicPacketNumber(41));

  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Tests receiving ACK packets in the reverse order.
TEST_P(BandwidthSamplerTest, ReorderedAck) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize);

  Send40PacketsAndAckFirst20(time_between_packets);

  // Ack the packets 21 to 40 in the reverse order, while sending packets 41 to
  // 60.
  QuicBandwidth last_bandwidth = QuicBandwidth::Zero();
  for (int i = 0; i < 20; i++) {
    last_bandwidth = AckPacket(40 - i);
    EXPECT_EQ(expected_bandwidth, last_bandwidth);
    SendPacket(41 + i);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack the packets 41 to 60, now in the regular order.
  for (int i = 41; i <= 60; i++) {
    last_bandwidth = AckPacket(i);
    EXPECT_EQ(expected_bandwidth, last_bandwidth);
    clock_.AdvanceTime(time_between_packets);
  }
  sampler_.RemoveObsoletePackets(QuicPacketNumber(61));

  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Test the app-limited logic.
TEST_P(BandwidthSamplerTest, AppLimited) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  QuicBandwidth expected_bandwidth =
      QuicBandwidth::FromKBytesPerSecond(kRegularPacketSize);

  // Send 20 packets at a constant inter-packet time.
  for (int i = 1; i <= 20; i++) {
    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack packets 1 to 20, while sending new packets at the same rate as
  // before.
  for (int i = 1; i <= 20; i++) {
    BandwidthSample sample = AckPacketInner(i);
    EXPECT_EQ(sample.state_at_send.is_app_limited,
              sampler_app_limited_at_start_);
    SendPacket(i + 20);
    clock_.AdvanceTime(time_between_packets);
  }

  // We are now app-limited. Ack 21 to 40 as usual, but do not send anything for
  // now.
  sampler_.OnAppLimited();
  for (int i = 21; i <= 40; i++) {
    BandwidthSample sample = AckPacketInner(i);
    EXPECT_FALSE(sample.state_at_send.is_app_limited);
    EXPECT_EQ(expected_bandwidth, sample.bandwidth);
    clock_.AdvanceTime(time_between_packets);
  }

  // Enter quiescence.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));

  // Send packets 41 to 60, all of which would be marked as app-limited.
  for (int i = 41; i <= 60; i++) {
    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
  }

  // Ack packets 41 to 60, while sending packets 61 to 80.  41 to 60 should be
  // app-limited and underestimate the bandwidth due to that.
  for (int i = 41; i <= 60; i++) {
    BandwidthSample sample = AckPacketInner(i);
    EXPECT_TRUE(sample.state_at_send.is_app_limited);
    EXPECT_LT(sample.bandwidth, 0.7f * expected_bandwidth);

    SendPacket(i + 20);
    clock_.AdvanceTime(time_between_packets);
  }

  // Run out of packets, and then ack packet 61 to 80, all of which should have
  // correct non-app-limited samples.
  for (int i = 61; i <= 80; i++) {
    BandwidthSample sample = AckPacketInner(i);
    EXPECT_FALSE(sample.state_at_send.is_app_limited);
    EXPECT_EQ(sample.bandwidth, expected_bandwidth);
    clock_.AdvanceTime(time_between_packets);
  }
  sampler_.RemoveObsoletePackets(QuicPacketNumber(81));

  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  EXPECT_EQ(0u, bytes_in_flight_);
}

// Test the samples taken at the first flight of packets sent.
TEST_P(BandwidthSamplerTest, FirstRoundTrip) {
  const QuicTime::Delta time_between_packets =
      QuicTime::Delta::FromMilliseconds(1);
  const QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(800);
  const int num_packets = 10;
  const QuicByteCount num_bytes = kRegularPacketSize * num_packets;
  const QuicBandwidth real_bandwidth =
      QuicBandwidth::FromBytesAndTimeDelta(num_bytes, rtt);

  for (int i = 1; i <= 10; i++) {
    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
  }

  clock_.AdvanceTime(rtt - num_packets * time_between_packets);

  QuicBandwidth last_sample = QuicBandwidth::Zero();
  for (int i = 1; i <= 10; i++) {
    QuicBandwidth sample = AckPacket(i);
    EXPECT_GT(sample, last_sample);
    last_sample = sample;
    clock_.AdvanceTime(time_between_packets);
  }

  // The final measured sample for the first flight of sample is expected to be
  // smaller than the real bandwidth, yet it should not lose more than 10%. The
  // specific value of the error depends on the difference between the RTT and
  // the time it takes to exhaust the congestion window (i.e. in the limit when
  // all packets are sent simultaneously, last sample would indicate the real
  // bandwidth).
  EXPECT_LT(last_sample, real_bandwidth);
  EXPECT_GT(last_sample, 0.9f * real_bandwidth);
}

// Test sampler's ability to remove obsolete packets.
TEST_P(BandwidthSamplerTest, RemoveObsoletePackets) {
  SendPacket(1);
  SendPacket(2);
  SendPacket(3);
  SendPacket(4);
  SendPacket(5);

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(100));

  EXPECT_EQ(5u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  sampler_.RemoveObsoletePackets(QuicPacketNumber(4));
  EXPECT_EQ(2u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  LosePacket(4);
  sampler_.RemoveObsoletePackets(QuicPacketNumber(5));

  EXPECT_EQ(1u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
  AckPacket(5);

  sampler_.RemoveObsoletePackets(QuicPacketNumber(6));

  EXPECT_EQ(0u, BandwidthSamplerPeer::GetNumberOfTrackedPackets(sampler_));
}

TEST_P(BandwidthSamplerTest, NeuterPacket) {
  SendPacket(1);
  EXPECT_EQ(0u, sampler_.total_bytes_neutered());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  sampler_.OnPacketNeutered(QuicPacketNumber(1));
  EXPECT_LT(0u, sampler_.total_bytes_neutered());
  EXPECT_EQ(0u, sampler_.total_bytes_acked());

  // If packet 1 is acked it should not produce a bandwidth sample.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(10));
  BandwidthSampler::CongestionEventSample sample = sampler_.OnCongestionEvent(
      clock_.Now(),
      {AckedPacket(QuicPacketNumber(1), kRegularPacketSize, clock_.Now())}, {},
      max_bandwidth_, est_bandwidth_upper_bound_, round_trip_count_);
  EXPECT_EQ(0u, sampler_.total_bytes_acked());
  EXPECT_EQ(QuicBandwidth::Zero(), sample.sample_max_bandwidth);
  EXPECT_FALSE(sample.sample_is_app_limited);
  EXPECT_EQ(QuicTime::Delta::Infinite(), sample.sample_rtt);
  EXPECT_EQ(0u, sample.sample_max_inflight);
  EXPECT_EQ(0u, sample.extra_acked);
}

TEST_P(BandwidthSamplerTest, CongestionEventSampleDefaultValues) {
  // Make sure a default constructed CongestionEventSample has the correct
  // initial values for BandwidthSampler::OnCongestionEvent() to work.
  BandwidthSampler::CongestionEventSample sample;

  EXPECT_EQ(QuicBandwidth::Zero(), sample.sample_max_bandwidth);
  EXPECT_FALSE(sample.sample_is_app_limited);
  EXPECT_EQ(QuicTime::Delta::Infinite(), sample.sample_rtt);
  EXPECT_EQ(0u, sample.sample_max_inflight);
  EXPECT_EQ(0u, sample.extra_acked);
}

// 1) Send 2 packets, 2) Ack both in 1 event, 3) Repeat.
TEST_P(BandwidthSamplerTest, TwoAckedPacketsPerEvent) {
  QuicTime::Delta time_between_packets = QuicTime::Delta::FromMilliseconds(10);
  QuicBandwidth sending_rate = QuicBandwidth::FromBytesAndTimeDelta(
      kRegularPacketSize, time_between_packets);

  for (uint64_t i = 1; i < 21; i++) {
    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
    if (i % 2 != 0) {
      continue;
    }

    BandwidthSampler::CongestionEventSample sample =
        OnCongestionEvent({i - 1, i}, {});
    EXPECT_EQ(sending_rate, sample.sample_max_bandwidth);
    EXPECT_EQ(time_between_packets, sample.sample_rtt);
    EXPECT_EQ(2 * kRegularPacketSize, sample.sample_max_inflight);
    EXPECT_TRUE(sample.last_packet_send_state.is_valid);
    EXPECT_EQ(2 * kRegularPacketSize,
              sample.last_packet_send_state.bytes_in_flight);
    EXPECT_EQ(i * kRegularPacketSize,
              sample.last_packet_send_state.total_bytes_sent);
    EXPECT_EQ((i - 2) * kRegularPacketSize,
              sample.last_packet_send_state.total_bytes_acked);
    EXPECT_EQ(0u, sample.last_packet_send_state.total_bytes_lost);
    sampler_.RemoveObsoletePackets(QuicPacketNumber(i - 2));
  }
}

TEST_P(BandwidthSamplerTest, LoseEveryOtherPacket) {
  QuicTime::Delta time_between_packets = QuicTime::Delta::FromMilliseconds(10);
  QuicBandwidth sending_rate = QuicBandwidth::FromBytesAndTimeDelta(
      kRegularPacketSize, time_between_packets);

  for (uint64_t i = 1; i < 21; i++) {
    SendPacket(i);
    clock_.AdvanceTime(time_between_packets);
    if (i % 2 != 0) {
      continue;
    }

    // Ack packet i and lose i-1.
    BandwidthSampler::CongestionEventSample sample =
        OnCongestionEvent({i}, {i - 1});
    // Losing 50% packets means sending rate is twice the bandwidth.
    EXPECT_EQ(sending_rate, sample.sample_max_bandwidth * 2);
    EXPECT_EQ(time_between_packets, sample.sample_rtt);
    EXPECT_EQ(kRegularPacketSize, sample.sample_max_inflight);
    EXPECT_TRUE(sample.last_packet_send_state.is_valid);
    EXPECT_EQ(2 * kRegularPacketSize,
              sample.last_packet_send_state.bytes_in_flight);
    EXPECT_EQ(i * kRegularPacketSize,
              sample.last_packet_send_state.total_bytes_sent);
    EXPECT_EQ((i - 2) * kRegularPacketSize / 2,
              sample.last_packet_send_state.total_bytes_acked);
    EXPECT_EQ((i - 2) * kRegularPacketSize / 2,
              sample.last_packet_send_state.total_bytes_lost);
    sampler_.RemoveObsoletePackets(QuicPacketNumber(i - 2));
  }
}

TEST_P(BandwidthSamplerTest, AckHeightRespectBandwidthEstimateUpperBound) {
  QuicTime::Delta time_between_packets = QuicTime::Delta::FromMilliseconds(10);
  QuicBandwidth first_packet_sending_rate =
      QuicBandwidth::FromBytesAndTimeDelta(kRegularPacketSize,
                                           time_between_packets);

  // Send packets 1 to 4 and ack packet 1.
  SendPacket(1);
  clock_.AdvanceTime(time_between_packets);
  SendPacket(2);
  SendPacket(3);
  SendPacket(4);
  BandwidthSampler::CongestionEventSample sample = OnCongestionEvent({1}, {});
  EXPECT_EQ(first_packet_sending_rate, sample.sample_max_bandwidth);
  EXPECT_EQ(first_packet_sending_rate, max_bandwidth_);

  // Ack packet 2, 3 and 4, all of which uses S(1) to calculate ack rate since
  // there were no acks at the time they were sent.
  round_trip_count_++;
  est_bandwidth_upper_bound_ = first_packet_sending_rate * 0.3;
  clock_.AdvanceTime(time_between_packets);
  sample = OnCongestionEvent({2, 3, 4}, {});
  EXPECT_EQ(first_packet_sending_rate * 2, sample.sample_max_bandwidth);
  EXPECT_EQ(max_bandwidth_, sample.sample_max_bandwidth);

  EXPECT_LT(2 * kRegularPacketSize, sample.extra_acked);
}

class MaxAckHeightTrackerTest : public QuicTest {
 protected:
  MaxAckHeightTrackerTest() : tracker_(/*initial_filter_window=*/10) {
    tracker_.SetAckAggregationBandwidthThreshold(1.8);
    tracker_.SetStartNewAggregationEpochAfterFullRound(true);
  }

  // Run a full aggregation episode, which is one or more aggregated acks,
  // followed by a quiet period in which no ack happens.
  // After this function returns, the time is set to the earliest point at which
  // any ack event will cause tracker_.Update() to start a new aggregation.
  void AggregationEpisode(QuicBandwidth aggregation_bandwidth,
                          QuicTime::Delta aggregation_duration,
                          QuicByteCount bytes_per_ack,
                          bool expect_new_aggregation_epoch) {
    ASSERT_GE(aggregation_bandwidth, bandwidth_);
    const QuicTime start_time = now_;

    const QuicByteCount aggregation_bytes =
        aggregation_bandwidth * aggregation_duration;

    const int num_acks = aggregation_bytes / bytes_per_ack;
    ASSERT_EQ(aggregation_bytes, num_acks * bytes_per_ack)
        << "aggregation_bytes: " << aggregation_bytes << " ["
        << aggregation_bandwidth << " in " << aggregation_duration
        << "], bytes_per_ack: " << bytes_per_ack;

    const QuicTime::Delta time_between_acks = QuicTime::Delta::FromMicroseconds(
        aggregation_duration.ToMicroseconds() / num_acks);
    ASSERT_EQ(aggregation_duration, num_acks * time_between_acks)
        << "aggregation_bytes: " << aggregation_bytes
        << ", num_acks: " << num_acks
        << ", time_between_acks: " << time_between_acks;

    // The total duration of aggregation time and quiet period.
    const QuicTime::Delta total_duration = QuicTime::Delta::FromMicroseconds(
        aggregation_bytes * 8 * 1000000 / bandwidth_.ToBitsPerSecond());
    ASSERT_EQ(aggregation_bytes, total_duration * bandwidth_)
        << "total_duration: " << total_duration
        << ", bandwidth_: " << bandwidth_;

    QuicByteCount last_extra_acked = 0;
    for (QuicByteCount bytes = 0; bytes < aggregation_bytes;
         bytes += bytes_per_ack) {
      QuicByteCount extra_acked = tracker_.Update(
          bandwidth_, true, RoundTripCount(), last_sent_packet_number_,
          last_acked_packet_number_, now_, bytes_per_ack);
      QUIC_VLOG(1) << "T" << now_ << ": Update after " << bytes_per_ack
                   << " bytes acked, " << extra_acked << " extra bytes acked";
      // |extra_acked| should be 0 if either
      // [1] We are at the beginning of a aggregation epoch(bytes==0) and the
      //     the current tracker implementation can identify it, or
      // [2] We are not really aggregating acks.
      if ((bytes == 0 && expect_new_aggregation_epoch) ||  // [1]
          (aggregation_bandwidth == bandwidth_)) {         // [2]
        EXPECT_EQ(0u, extra_acked);
      } else {
        EXPECT_LT(last_extra_acked, extra_acked);
      }
      now_ = now_ + time_between_acks;
      last_extra_acked = extra_acked;
    }

    // Advance past the quiet period.
    const QuicTime time_after_aggregation = now_;
    now_ = start_time + total_duration;
    QUIC_VLOG(1) << "Advanced time from " << time_after_aggregation << " to "
                 << now_ << ". Aggregation time["
                 << (time_after_aggregation - start_time) << "], Quiet time["
                 << (now_ - time_after_aggregation) << "].";
  }

  QuicRoundTripCount RoundTripCount() const {
    return (now_ - QuicTime::Zero()).ToMicroseconds() / rtt_.ToMicroseconds();
  }

  MaxAckHeightTracker tracker_;
  QuicBandwidth bandwidth_ = QuicBandwidth::FromBytesPerSecond(10 * 1000);
  QuicTime now_ = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(1);
  QuicTime::Delta rtt_ = QuicTime::Delta::FromMilliseconds(60);
  QuicPacketNumber last_sent_packet_number_;
  QuicPacketNumber last_acked_packet_number_;
};

TEST_F(MaxAckHeightTrackerTest, VeryAggregatedLargeAck) {
  AggregationEpisode(bandwidth_ * 20, QuicTime::Delta::FromMilliseconds(6),
                     1200, true);
  AggregationEpisode(bandwidth_ * 20, QuicTime::Delta::FromMilliseconds(6),
                     1200, true);
  now_ = now_ - QuicTime::Delta::FromMilliseconds(1);

  if (tracker_.ack_aggregation_bandwidth_threshold() > 1.1) {
    AggregationEpisode(bandwidth_ * 20, QuicTime::Delta::FromMilliseconds(6),
                       1200, true);
    EXPECT_EQ(3u, tracker_.num_ack_aggregation_epochs());
  } else {
    AggregationEpisode(bandwidth_ * 20, QuicTime::Delta::FromMilliseconds(6),
                       1200, false);
    EXPECT_EQ(2u, tracker_.num_ack_aggregation_epochs());
  }
}

TEST_F(MaxAckHeightTrackerTest, VeryAggregatedSmallAcks) {
  AggregationEpisode(bandwidth_ * 20, QuicTime::Delta::FromMilliseconds(6), 300,
                     true);
  AggregationEpisode(bandwidth_ * 20, QuicTime::Delta::FromMilliseconds(6), 300,
                     true);
  now_ = now_ - QuicTime::Delta::FromMilliseconds(1);

  if (tracker_.ack_aggregation_bandwidth_threshold() > 1.1) {
    AggregationEpisode(bandwidth_ * 20, QuicTime::Delta::FromMilliseconds(6),
                       300, true);
    EXPECT_EQ(3u, tracker_.num_ack_aggregation_epochs());
  } else {
    AggregationEpisode(bandwidth_ * 20, QuicTime::Delta::FromMilliseconds(6),
                       300, false);
    EXPECT_EQ(2u, tracker_.num_ack_aggregation_epochs());
  }
}

TEST_F(MaxAckHeightTrackerTest, SomewhatAggregatedLargeAck) {
  AggregationEpisode(bandwidth_ * 2, QuicTime::Delta::FromMilliseconds(50),
                     1000, true);
  AggregationEpisode(bandwidth_ * 2, QuicTime::Delta::FromMilliseconds(50),
                     1000, true);
  now_ = now_ - QuicTime::Delta::FromMilliseconds(1);

  if (tracker_.ack_aggregation_bandwidth_threshold() > 1.1) {
    AggregationEpisode(bandwidth_ * 2, QuicTime::Delta::FromMilliseconds(50),
```