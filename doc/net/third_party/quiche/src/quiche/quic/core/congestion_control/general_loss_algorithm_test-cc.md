Response:
The user is asking for an analysis of the provided C++ source code file. I need to identify its purpose, explore any connections to JavaScript, demonstrate its logic with examples, highlight common user errors, and explain how a user might reach this code during debugging.

**Plan:**

1. **Identify the core functionality:** Analyze the class `GeneralLossAlgorithmTest` and its methods to understand the purpose of the code. It's clearly a unit test file.
2. **Check for JavaScript relevance:** Examine the code for any direct or indirect relationships with JavaScript. Networking code in Chromium might have interactions with JavaScript through browser APIs.
3. **Demonstrate logic with examples:**  Go through the test cases and extract the input (sent packets, acks) and expected output (losses). Explain the reasoning behind the loss detection.
4. **Identify common user errors:** Think about mistakes developers might make when using or configuring congestion control algorithms that these tests are verifying.
5. **Explain the debugging scenario:** Describe a realistic user action that could lead to this code being relevant during debugging.
这个C++源代码文件 `general_loss_algorithm_test.cc` 是 Chromium QUIC 协议栈中用于测试 `GeneralLossAlgorithm` 类的单元测试文件。它的主要功能是：

**功能列举:**

1. **测试 `GeneralLossAlgorithm` 类的各种丢包检测逻辑:**  该文件包含了多个以 `TEST_F` 开头的测试用例，每个测试用例都针对 `GeneralLossAlgorithm` 类的不同场景和逻辑进行测试，例如：
    * 基于 NACK (Negative Acknowledgement) 的丢包重传检测。
    * 基于时间超时的早期重传检测。
    * 处理乱序到达的 ACK 包。
    * 针对虚假丢包的适应性调整。
    * 实现了 IETF 标准的丢包检测算法。
    * 针对小数据包的特殊处理。

2. **模拟网络行为:** 测试用例中通过 `SendDataPacket` 和 `SendAckPacket` 函数模拟发送数据包和 ACK 包的行为，并使用 `MockClock` 来控制时间流逝，模拟不同的网络延迟和丢包情况。

3. **验证丢包检测结果:** 每个测试用例都会设定预期的丢包情况，并通过 `VerifyLosses` 函数来验证 `GeneralLossAlgorithm` 是否正确地检测出了这些丢包。

4. **测试超时机制:** 某些测试用例还会验证 `GeneralLossAlgorithm` 计算的丢包超时时间 (`GetLossTimeout`) 是否符合预期。

**与 JavaScript 的关系:**

这个 C++ 文件本身与 JavaScript 没有直接的功能关联。然而，Chromium 的网络栈是用 C++ 实现的，而网页和 Web 应用通常使用 JavaScript 来发起网络请求。  当用户在浏览器中进行网络操作时，例如访问一个网站，JavaScript 会调用浏览器提供的 API (例如 `fetch` 或 `XMLHttpRequest`) 来发起 HTTP/3 (QUIC) 连接。  底层的 QUIC 协议栈（包括这个 `GeneralLossAlgorithm` 类）会在 C++ 层处理连接的建立、数据传输、拥塞控制和丢包恢复等操作。

**举例说明 JavaScript 的间接关系:**

假设一个 JavaScript 应用程序通过 `fetch` API 发送数据到服务器。在网络传输过程中，由于网络拥塞或其他原因，某些数据包可能会丢失。底层的 QUIC 协议栈中的 `GeneralLossAlgorithm` 会负责检测这些丢包，并触发必要的重传机制。虽然 JavaScript 代码本身不直接调用 `GeneralLossAlgorithm`，但它的行为会受到其影响，例如，如果丢包检测和恢复机制运行良好，JavaScript 应用会更快、更可靠地接收到服务器的响应。

**逻辑推理 (假设输入与输出):**

**测试用例: `NackRetransmit1Packet`**

* **假设输入:**
    1. 发送了 5 个数据包 (packet number 1 到 5)。
    2. 收到 ACK 包确认了 packet 2。
    3. 收到 ACK 包确认了 packet 3。
    4. 收到 ACK 包确认了 packet 4。
* **逻辑推理:**  `GeneralLossAlgorithm` 的 NACK 检测逻辑会基于收到的 ACK 包和已发送但未被确认的包来判断是否存在丢包。当收到 ACK 4 时，由于 packet 1 没有被确认，且连续收到了多个更高序号的 ACK，算法会推断 packet 1 丢失。
* **预期输出:** `VerifyLosses` 函数会断言检测到的丢包是 packet 1。

**测试用例: `EarlyRetransmit1Packet`**

* **假设输入:**
    1. 发送了 2 个数据包 (packet number 1 和 2)。
    2. 收到 ACK 包确认了 packet 2。
    3. 经过了一段时间 (接近但不超过一个 RTT)。
* **逻辑推理:**  早期重传机制会监控未被确认的最早的包（packet 1）的发送时间。当收到后续包的 ACK (packet 2) 且距离最早包的发送时间超过一定阈值时，会触发早期重传。
* **预期输出:**  在第一个 `VerifyLosses` 调用中，由于时间未完全到达阈值，不会立即检测到丢包。但在第二个 `VerifyLosses` 调用中，当时间超过阈值后，会检测到 packet 1 丢失。

**用户或编程常见的使用错误:**

虽然用户通常不会直接与 `GeneralLossAlgorithm` 交互，但编程错误或配置不当可能会导致其行为异常，而这些测试用例旨在防止或发现这些错误：

1. **不正确的 RTT 估算:**  `GeneralLossAlgorithm` 依赖于准确的 RTT (Round-Trip Time) 估算。如果 RTT 估算不准确（例如，初始值设置不当），可能导致过早或过晚地触发丢包重传，影响性能。测试用例中通过 `rtt_stats_` 模拟 RTT 信息，可以验证算法在不同 RTT 情况下的表现。

2. **丢包检测参数配置错误:**  例如，`reordering_shift` 参数控制着丢包检测对包乱序的容忍度。如果配置不当，可能导致将乱序的包误判为丢失。测试用例如 `DefaultIetfLossDetection` 和 `IetfLossDetectionWithOneFourthRttDelay` 就是测试不同参数配置下的丢包检测行为。

3. **对拥塞控制算法理解不足:**  开发者可能错误地认为可以完全控制丢包检测行为，而忽略了拥塞控制算法的自适应性。测试用例展示了算法如何根据网络状况调整其行为，例如虚假丢包检测后调整阈值。

**用户操作到达此代码的调试线索:**

以下是一些用户操作可能最终导致开发者需要查看或调试 `general_loss_algorithm_test.cc` 的场景：

1. **用户报告网页加载缓慢或连接不稳定:**  如果用户遇到网络连接问题，例如网页加载时间过长、视频卡顿等，开发者可能会怀疑是底层网络协议栈的拥塞控制或丢包恢复机制出现了问题。

2. **开发者修改了 QUIC 协议栈代码:**  如果开发者正在开发或修改 Chromium 的 QUIC 相关代码，特别是涉及到拥塞控制或丢包检测的部分，他们会运行这些单元测试来验证修改是否引入了错误或影响了现有功能的正确性。

3. **网络性能测试和优化:**  进行网络性能测试时，如果发现某些场景下丢包率过高或重传效率低下，开发者可能会深入研究丢包检测算法的实现，并可能需要查看相关的单元测试来理解其工作原理和测试覆盖范围。

**逐步到达这里的过程 (以用户报告网页加载缓慢为例):**

1. **用户报告问题:** 用户反馈访问特定网站时加载速度很慢。
2. **初步排查:** 开发者可能会先检查 DNS 解析、服务器响应时间等，排除这些因素。
3. **怀疑网络拥塞:** 如果初步排查没有发现问题，开发者可能会怀疑是网络拥塞导致了丢包和重传，从而影响了加载速度。
4. **查看 QUIC 连接信息:** 如果连接使用的是 QUIC 协议，开发者可能会查看浏览器提供的 QUIC 连接信息，例如丢包率、重传次数等。
5. **分析 QUIC 拥塞控制和丢包检测:**  如果怀疑是 QUIC 的拥塞控制或丢包检测算法有问题，开发者可能会开始研究相关的代码。
6. **查看 `GeneralLossAlgorithm` 代码:**  开发者可能会查看 `GeneralLossAlgorithm.cc` 的实现代码，了解其具体的丢包检测逻辑。
7. **运行或分析单元测试:**  为了更深入地理解 `GeneralLossAlgorithm` 的行为，或者验证某些假设，开发者可能会查看 `general_loss_algorithm_test.cc` 中的单元测试用例，分析不同的测试场景和预期结果，甚至可能修改或添加新的测试用例来复现或调试问题。

总而言之，`general_loss_algorithm_test.cc` 是 Chromium QUIC 协议栈中至关重要的测试文件，它确保了丢包检测算法的正确性和健壮性，间接保障了基于 QUIC 协议的网络连接的稳定性和性能。虽然普通用户不会直接接触这个文件，但它的作用对于提供良好的网络体验至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/general_loss_algorithm_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/general_loss_algorithm.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

#include "quiche/quic/core/congestion_control/rtt_stats.h"
#include "quiche/quic/core/quic_unacked_packet_map.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_clock.h"

namespace quic {
namespace test {
namespace {

// Default packet length.
const uint32_t kDefaultLength = 1000;

class GeneralLossAlgorithmTest : public QuicTest {
 protected:
  GeneralLossAlgorithmTest() : unacked_packets_(Perspective::IS_CLIENT) {
    rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(100),
                         QuicTime::Delta::Zero(), clock_.Now());
    EXPECT_LT(0, rtt_stats_.smoothed_rtt().ToMicroseconds());
    loss_algorithm_.Initialize(HANDSHAKE_DATA, nullptr);
  }

  ~GeneralLossAlgorithmTest() override {}

  void SendDataPacket(uint64_t packet_number,
                      QuicPacketLength encrypted_length) {
    QuicStreamFrame frame;
    frame.stream_id = QuicUtils::GetFirstBidirectionalStreamId(
        CurrentSupportedVersions()[0].transport_version,
        Perspective::IS_CLIENT);
    SerializedPacket packet(QuicPacketNumber(packet_number),
                            PACKET_1BYTE_PACKET_NUMBER, nullptr,
                            encrypted_length, false, false);
    packet.retransmittable_frames.push_back(QuicFrame(frame));
    unacked_packets_.AddSentPacket(&packet, NOT_RETRANSMISSION, clock_.Now(),
                                   true, true, ECN_NOT_ECT);
  }

  void SendDataPacket(uint64_t packet_number) {
    SendDataPacket(packet_number, kDefaultLength);
  }

  void SendAckPacket(uint64_t packet_number) {
    SerializedPacket packet(QuicPacketNumber(packet_number),
                            PACKET_1BYTE_PACKET_NUMBER, nullptr, kDefaultLength,
                            true, false);
    unacked_packets_.AddSentPacket(&packet, NOT_RETRANSMISSION, clock_.Now(),
                                   false, true, ECN_NOT_ECT);
  }

  void VerifyLosses(uint64_t largest_newly_acked,
                    const AckedPacketVector& packets_acked,
                    const std::vector<uint64_t>& losses_expected) {
    return VerifyLosses(largest_newly_acked, packets_acked, losses_expected,
                        std::nullopt, std::nullopt);
  }

  void VerifyLosses(
      uint64_t largest_newly_acked, const AckedPacketVector& packets_acked,
      const std::vector<uint64_t>& losses_expected,
      std::optional<QuicPacketCount> max_sequence_reordering_expected,
      std::optional<QuicPacketCount> num_borderline_time_reorderings_expected) {
    unacked_packets_.MaybeUpdateLargestAckedOfPacketNumberSpace(
        APPLICATION_DATA, QuicPacketNumber(largest_newly_acked));
    LostPacketVector lost_packets;
    LossDetectionInterface::DetectionStats stats = loss_algorithm_.DetectLosses(
        unacked_packets_, clock_.Now(), rtt_stats_,
        QuicPacketNumber(largest_newly_acked), packets_acked, &lost_packets);
    if (max_sequence_reordering_expected.has_value()) {
      EXPECT_EQ(stats.sent_packets_max_sequence_reordering,
                max_sequence_reordering_expected.value());
    }
    if (num_borderline_time_reorderings_expected.has_value()) {
      EXPECT_EQ(stats.sent_packets_num_borderline_time_reorderings,
                num_borderline_time_reorderings_expected.value());
    }
    ASSERT_EQ(losses_expected.size(), lost_packets.size());
    for (size_t i = 0; i < losses_expected.size(); ++i) {
      EXPECT_EQ(lost_packets[i].packet_number,
                QuicPacketNumber(losses_expected[i]));
    }
  }

  QuicUnackedPacketMap unacked_packets_;
  GeneralLossAlgorithm loss_algorithm_;
  RttStats rtt_stats_;
  MockClock clock_;
};

TEST_F(GeneralLossAlgorithmTest, NackRetransmit1Packet) {
  const size_t kNumSentPackets = 5;
  // Transmit 5 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  AckedPacketVector packets_acked;
  // No loss on one ack.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(2), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(2, packets_acked, std::vector<uint64_t>{}, 1, 0);
  packets_acked.clear();
  // No loss on two acks.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(3));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(3), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(3, packets_acked, std::vector<uint64_t>{}, 2, 0);
  packets_acked.clear();
  // Loss on three acks.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(4));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(4), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(4, packets_acked, {1}, 3, 0);
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

// A stretch ack is an ack that covers more than 1 packet of previously
// unacknowledged data.
TEST_F(GeneralLossAlgorithmTest, NackRetransmit1PacketWith1StretchAck) {
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  AckedPacketVector packets_acked;
  // Nack the first packet 3 times in a single StretchAck.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(2), kMaxOutgoingPacketSize, QuicTime::Zero()));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(3));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(3), kMaxOutgoingPacketSize, QuicTime::Zero()));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(4));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(4), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(4, packets_acked, {1});
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

// Ack a packet 3 packets ahead, causing a retransmit.
TEST_F(GeneralLossAlgorithmTest, NackRetransmit1PacketSingleAck) {
  const size_t kNumSentPackets = 10;
  // Transmit 10 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  AckedPacketVector packets_acked;
  // Nack the first packet 3 times in an AckFrame with three missing packets.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(4));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(4), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(4, packets_acked, {1});
  EXPECT_EQ(clock_.Now() + 1.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, EarlyRetransmit1Packet) {
  const size_t kNumSentPackets = 2;
  // Transmit 2 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  AckedPacketVector packets_acked;
  // Early retransmit when the final packet gets acked and the first is nacked.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(2), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(2, packets_acked, std::vector<uint64_t>{});
  packets_acked.clear();
  EXPECT_EQ(clock_.Now() + 1.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout());

  clock_.AdvanceTime(1.13 * rtt_stats_.latest_rtt());
  // If reordering_shift increases by one we should have detected a loss.
  VerifyLosses(2, packets_acked, {}, /*max_sequence_reordering_expected=*/1,
               /*num_borderline_time_reorderings_expected=*/1);

  clock_.AdvanceTime(0.13 * rtt_stats_.latest_rtt());
  VerifyLosses(2, packets_acked, {1});
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, EarlyRetransmitAllPackets) {
  const size_t kNumSentPackets = 5;
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
    // Advance the time 1/4 RTT between 3 and 4.
    if (i == 3) {
      clock_.AdvanceTime(0.25 * rtt_stats_.smoothed_rtt());
    }
  }
  AckedPacketVector packets_acked;
  // Early retransmit when the final packet gets acked and 1.25 RTTs have
  // elapsed since the packets were sent.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(kNumSentPackets));
  packets_acked.push_back(AckedPacket(QuicPacketNumber(kNumSentPackets),
                                      kMaxOutgoingPacketSize,
                                      QuicTime::Zero()));
  // This simulates a single ack following multiple missing packets with FACK.
  VerifyLosses(kNumSentPackets, packets_acked, {1, 2});
  packets_acked.clear();
  // The time has already advanced 1/4 an RTT, so ensure the timeout is set
  // 1.25 RTTs after the earliest pending packet(3), not the last(4).
  EXPECT_EQ(clock_.Now() + rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout());

  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());
  VerifyLosses(kNumSentPackets, packets_acked, {3});
  EXPECT_EQ(clock_.Now() + 0.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout());
  clock_.AdvanceTime(0.25 * rtt_stats_.smoothed_rtt());
  VerifyLosses(kNumSentPackets, packets_acked, {4});
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, DontEarlyRetransmitNeuteredPacket) {
  const size_t kNumSentPackets = 2;
  // Transmit 2 packets.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
  }
  AckedPacketVector packets_acked;
  // Neuter packet 1.
  unacked_packets_.RemoveRetransmittability(QuicPacketNumber(1));
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());

  // Early retransmit when the final packet gets acked and the first is nacked.
  unacked_packets_.MaybeUpdateLargestAckedOfPacketNumberSpace(
      APPLICATION_DATA, QuicPacketNumber(2));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(2), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(2, packets_acked, std::vector<uint64_t>{});
  EXPECT_EQ(clock_.Now() + 0.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, EarlyRetransmitWithLargerUnackablePackets) {
  // Transmit 2 data packets and one ack.
  SendDataPacket(1);
  SendDataPacket(2);
  SendAckPacket(3);
  AckedPacketVector packets_acked;
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());

  // Early retransmit when the final packet gets acked and the first is nacked.
  unacked_packets_.MaybeUpdateLargestAckedOfPacketNumberSpace(
      APPLICATION_DATA, QuicPacketNumber(2));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(2), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(2, packets_acked, std::vector<uint64_t>{});
  packets_acked.clear();
  EXPECT_EQ(clock_.Now() + 0.25 * rtt_stats_.smoothed_rtt(),
            loss_algorithm_.GetLossTimeout());

  // The packet should be lost once the loss timeout is reached.
  clock_.AdvanceTime(0.25 * rtt_stats_.latest_rtt());
  VerifyLosses(2, packets_acked, {1});
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, AlwaysLosePacketSent1RTTEarlier) {
  // Transmit 1 packet and then wait an rtt plus 1ms.
  SendDataPacket(1);
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt() +
                     QuicTime::Delta::FromMilliseconds(1));

  // Transmit 2 packets.
  SendDataPacket(2);
  SendDataPacket(3);
  AckedPacketVector packets_acked;
  // Wait another RTT and ack 2.
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt());
  unacked_packets_.MaybeUpdateLargestAckedOfPacketNumberSpace(
      APPLICATION_DATA, QuicPacketNumber(2));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(2), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(2, packets_acked, {1});
}

TEST_F(GeneralLossAlgorithmTest, IncreaseTimeThresholdUponSpuriousLoss) {
  loss_algorithm_.enable_adaptive_time_threshold();
  loss_algorithm_.set_reordering_shift(kDefaultLossDelayShift);
  EXPECT_EQ(kDefaultLossDelayShift, loss_algorithm_.reordering_shift());
  EXPECT_TRUE(loss_algorithm_.use_adaptive_time_threshold());
  const size_t kNumSentPackets = 10;
  // Transmit 2 packets at 1/10th an RTT interval.
  for (size_t i = 1; i <= kNumSentPackets; ++i) {
    SendDataPacket(i);
    clock_.AdvanceTime(0.1 * rtt_stats_.smoothed_rtt());
  }
  EXPECT_EQ(QuicTime::Zero() + rtt_stats_.smoothed_rtt(), clock_.Now());
  AckedPacketVector packets_acked;
  // Expect the timer to not be set.
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // Packet 1 should not be lost until 1/4 RTTs pass.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(2), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(2, packets_acked, std::vector<uint64_t>{});
  packets_acked.clear();
  // Expect the timer to be set to 1/4 RTT's in the future.
  EXPECT_EQ(rtt_stats_.smoothed_rtt() * (1.0f / 4),
            loss_algorithm_.GetLossTimeout() - clock_.Now());
  VerifyLosses(2, packets_acked, std::vector<uint64_t>{});
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt() * (1.0f / 4));
  VerifyLosses(2, packets_acked, {1});
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  // Retransmit packet 1 as 11 and 2 as 12.
  SendDataPacket(11);
  SendDataPacket(12);

  // Advance the time 1/4 RTT and indicate the loss was spurious.
  // The new threshold should be 1/2 RTT.
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt() * (1.0f / 4));
  loss_algorithm_.SpuriousLossDetected(unacked_packets_, rtt_stats_,
                                       clock_.Now(), QuicPacketNumber(1),
                                       QuicPacketNumber(2));
  EXPECT_EQ(1, loss_algorithm_.reordering_shift());
}

TEST_F(GeneralLossAlgorithmTest, IncreaseReorderingThresholdUponSpuriousLoss) {
  loss_algorithm_.set_use_adaptive_reordering_threshold(true);
  for (size_t i = 1; i <= 4; ++i) {
    SendDataPacket(i);
  }
  // Acking 4 causes 1 detected lost.
  AckedPacketVector packets_acked;
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(4));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(4), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(4, packets_acked, std::vector<uint64_t>{1});
  packets_acked.clear();

  // Retransmit 1 as 5.
  SendDataPacket(5);

  // Acking 1 such that it was detected lost spuriously.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(1));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(1), kMaxOutgoingPacketSize, QuicTime::Zero()));
  loss_algorithm_.SpuriousLossDetected(unacked_packets_, rtt_stats_,
                                       clock_.Now(), QuicPacketNumber(1),
                                       QuicPacketNumber(4));
  VerifyLosses(4, packets_acked, std::vector<uint64_t>{});
  packets_acked.clear();

  // Verify acking 5 does not cause 2 detected lost.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(5));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(5), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(5, packets_acked, std::vector<uint64_t>{});
  packets_acked.clear();

  SendDataPacket(6);

  // Acking 6 will causes 2 detected lost.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(6));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(6), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(6, packets_acked, std::vector<uint64_t>{2});
  packets_acked.clear();

  // Retransmit 2 as 7.
  SendDataPacket(7);

  // Acking 2 such that it was detected lost spuriously.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(2), kMaxOutgoingPacketSize, QuicTime::Zero()));
  loss_algorithm_.SpuriousLossDetected(unacked_packets_, rtt_stats_,
                                       clock_.Now(), QuicPacketNumber(2),
                                       QuicPacketNumber(6));
  VerifyLosses(6, packets_acked, std::vector<uint64_t>{});
  packets_acked.clear();

  // Acking 7 will not cause 3 as detected lost.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(7));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(7), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(7, packets_acked, std::vector<uint64_t>{});
  packets_acked.clear();
}

TEST_F(GeneralLossAlgorithmTest, DefaultIetfLossDetection) {
  loss_algorithm_.set_reordering_shift(kDefaultIetfLossDelayShift);
  for (size_t i = 1; i <= 6; ++i) {
    SendDataPacket(i);
  }
  // Packet threshold loss detection.
  AckedPacketVector packets_acked;
  // No loss on one ack.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(2), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(2, packets_acked, std::vector<uint64_t>{});
  packets_acked.clear();
  // No loss on two acks.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(3));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(3), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(3, packets_acked, std::vector<uint64_t>{});
  packets_acked.clear();
  // Loss on three acks.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(4));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(4), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(4, packets_acked, {1});
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
  packets_acked.clear();

  SendDataPacket(7);

  // Time threshold loss detection.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(6));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(6), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(6, packets_acked, std::vector<uint64_t>{});
  packets_acked.clear();
  EXPECT_EQ(clock_.Now() + rtt_stats_.smoothed_rtt() +
                (rtt_stats_.smoothed_rtt() >> 3),
            loss_algorithm_.GetLossTimeout());
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt() +
                     (rtt_stats_.smoothed_rtt() >> 3));
  VerifyLosses(6, packets_acked, {5});
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, IetfLossDetectionWithOneFourthRttDelay) {
  loss_algorithm_.set_reordering_shift(2);
  SendDataPacket(1);
  SendDataPacket(2);

  AckedPacketVector packets_acked;
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(2), kMaxOutgoingPacketSize, QuicTime::Zero()));
  VerifyLosses(2, packets_acked, std::vector<uint64_t>{});
  packets_acked.clear();
  EXPECT_EQ(clock_.Now() + rtt_stats_.smoothed_rtt() +
                (rtt_stats_.smoothed_rtt() >> 2),
            loss_algorithm_.GetLossTimeout());
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt() +
                     (rtt_stats_.smoothed_rtt() >> 2));
  VerifyLosses(2, packets_acked, {1});
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

TEST_F(GeneralLossAlgorithmTest, NoPacketThresholdForRuntPackets) {
  loss_algorithm_.disable_packet_threshold_for_runt_packets();
  for (size_t i = 1; i <= 6; ++i) {
    SendDataPacket(i);
  }
  // Send a small packet.
  SendDataPacket(7, /*encrypted_length=*/kDefaultLength / 2);
  // No packet threshold for runt packet.
  AckedPacketVector packets_acked;
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(7));
  packets_acked.push_back(AckedPacket(
      QuicPacketNumber(7), kMaxOutgoingPacketSize, QuicTime::Zero()));
  // Verify no packet is detected lost because packet 7 is a runt.
  VerifyLosses(7, packets_acked, std::vector<uint64_t>{});
  EXPECT_EQ(clock_.Now() + rtt_stats_.smoothed_rtt() +
                (rtt_stats_.smoothed_rtt() >> 2),
            loss_algorithm_.GetLossTimeout());
  clock_.AdvanceTime(rtt_stats_.smoothed_rtt() +
                     (rtt_stats_.smoothed_rtt() >> 2));
  // Verify packets are declared lost because time threshold has passed.
  VerifyLosses(7, packets_acked, {1, 2, 3, 4, 5, 6});
  EXPECT_EQ(QuicTime::Zero(), loss_algorithm_.GetLossTimeout());
}

}  // namespace
}  // namespace test
}  // namespace quic

"""

```