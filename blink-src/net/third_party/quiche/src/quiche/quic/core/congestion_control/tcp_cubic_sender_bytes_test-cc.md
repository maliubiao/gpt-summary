Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Purpose:** The filename `tcp_cubic_sender_bytes_test.cc` immediately suggests this file contains tests for a class related to TCP Cubic congestion control, specifically one dealing with byte-based calculations.

2. **Scan the Includes:**  The `#include` directives provide crucial context:
    * Standard Library (`<algorithm>`, `<cstdint>`, etc.): Indicates basic utilities and data types are used.
    * `quiche/quic/core/...`:  Points to the specific QUIC implementation being tested. Keywords like `congestion_control`, `rtt_stats`, `send_algorithm_interface`, `quic_packets` are very informative.
    * `quiche/quic/platform/api/...`:  Suggests platform-independent testing infrastructure.
    * `quiche/quic/test_tools/...`:  Highlights the use of mock objects (`mock_clock`) and testing helpers (`quic_config_peer`).

3. **Examine the Namespaces:** `namespace quic { namespace test { ... } }` confirms this is part of the QUIC testing framework.

4. **Look for Key Class Definitions:** The code defines `TcpCubicSenderBytesPeer` and `TcpCubicSenderBytesTest`. The `Peer` suffix often indicates a class designed to access private members for testing purposes. `*_Test` is a standard naming convention for test fixture classes.

5. **Analyze `TcpCubicSenderBytesPeer`:**
    * It inherits from `TcpCubicSenderBytes`. This is the class being tested.
    * It exposes `hybrid_slow_start_`, `GetRenoBeta()`, `rtt_stats_`, and `stats_`. This tells us which internal components are relevant to the tests.

6. **Analyze `TcpCubicSenderBytesTest`:**
    * **Member Variables:** `one_ms_`, `clock_`, `sender_`, `packet_number_`, `acked_packet_number_`, `bytes_in_flight_` are used for setting up and managing the test environment. The mock clock is especially important for controlling time.
    * **Helper Functions:** These are the core of the test setup. Functions like `SendAvailableSendWindow`, `AckNPackets`, `LoseNPackets`, and `LosePacket` abstract away the details of interacting with the `TcpCubicSenderBytes` class, making the tests more readable. Pay attention to what these functions *do* (send packets, simulate ACKs, simulate losses).

7. **Study the Test Cases (Functions starting with `TEST_F`):** Each `TEST_F` function focuses on a specific aspect of the `TcpCubicSenderBytes` class's behavior. Read the test names carefully (e.g., `SimpleSender`, `ApplicationLimitedSlowStart`, `SlowStartPacketLoss`, `RTOCongestionWindow`). These names often describe the scenario being tested.

8. **Connect Test Cases to Functionality:**  As you read each test case, try to understand *what* behavior is being verified and *how*. For example, `SimpleSender` checks basic initialization, `ApplicationLimitedSlowStart` checks the behavior when the application limits sending, and `SlowStartPacketLoss` verifies how the congestion control reacts to packet loss during slow start.

9. **Look for Specific Values and Assertions:**  Pay attention to `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_GT`, `EXPECT_LT`, `EXPECT_NEAR`. These assertions verify the expected outcomes of the tested operations. The specific numerical values in these assertions are the result of the calculations within the congestion control algorithm and often require careful analysis to understand.

10. **Consider JavaScript Relevance:**  Think about how congestion control affects web browsing and network performance in general. JavaScript running in a browser relies on the underlying network stack, so while this C++ code isn't directly *used* in JavaScript, the *concepts* it tests are critical to how web applications function.

11. **Identify Potential User/Programming Errors:** Look for test cases that simulate error conditions (like packet loss or retransmission timeouts). Consider how a misconfiguration or network issue might lead to these scenarios.

12. **Trace User Actions (Debugging Clues):**  Think about how a user action (like opening a webpage) translates into network requests. Consider the sequence of events that might lead to congestion and trigger the congestion control mechanisms being tested. This involves understanding the basics of TCP/IP and how QUIC builds upon it.

13. **Refine and Organize:**  Once you have a general understanding, organize your findings into logical categories (functionality, JavaScript relevance, assumptions, errors, debugging). Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:**  You might initially misinterpret a test case's purpose. By carefully reading the code and the assertions, you can correct your understanding.
* **Missing Links:** You might not immediately see the connection to JavaScript. Thinking about the broader context of web performance and network communication can help bridge this gap.
* **Technical Details:**  You might not understand the specifics of TCP Cubic. While a deep dive into the algorithm isn't always necessary for a high-level analysis, having some basic knowledge of congestion control principles is helpful. You can note areas where further investigation might be beneficial.
* **Assumptions:** Be explicit about any assumptions you're making about the QUIC protocol or TCP Cubic. For example, assuming a standard TCP MSS (Maximum Segment Size) when the code uses `kDefaultTCPMSS`.

By following this kind of systematic approach, you can effectively analyze complex C++ test files and extract the relevant information, even without being an expert in every detail of the codebase.
这个C++源代码文件 `tcp_cubic_sender_bytes_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `TcpCubicSenderBytes` 类的功能。 `TcpCubicSenderBytes` 类实现了基于字节的 TCP Cubic 拥塞控制算法。

以下是该文件的主要功能：

**1. 单元测试 `TcpCubicSenderBytes` 类的各种行为：**

   * **慢启动 (Slow Start):**
      * 测试初始拥塞窗口 (CWND) 的设置和增长。
      * 测试在应用受限 (Application Limited) 的情况下慢启动的行为。
      * 测试在慢启动期间发生丢包时的行为，包括退出慢启动、降低拥塞窗口、进入恢复阶段 (Recovery)。
      * 测试使用 PRR (Proportional Rate Reduction) 算法在慢启动丢包后的行为。
   * **拥塞避免 (Congestion Avoidance):**
      * 测试在恢复阶段结束后，拥塞窗口的增长方式。
      * 测试在多个连接模拟下的拥塞避免行为。
   * **快速恢复 (Fast Recovery):**  虽然没有显式命名为快速恢复的测试，但通过测试丢包后的拥塞窗口降低和恢复阶段的行为，间接测试了快速恢复的逻辑。
   * **重传超时 (RTO, Retransmission Timeout):**
      * 测试发生 RTO 时的拥塞窗口降低行为。
      * 测试没有数据需要重传时的 RTO 行为。
      * 测试 RTO 如何重置慢启动状态。
   * **连接空闲 (Quiescence):** 测试连接空闲一段时间后，Cubic 算法的 epoch 是否会被重置，避免拥塞窗口增长过快。
   * **多次丢包 (Multiple Losses):** 测试在一个拥塞窗口内发生多次丢包时的拥塞窗口调整行为。
   * **配置选项 (Configuration Options):** 测试各种配置选项如何影响拥塞窗口的初始值和最小值，例如 `kIW10` 和 `kMIN4`。
   * **带宽恢复 (Bandwidth Resumption):** 测试在连接迁移后，如何根据缓存的网络参数调整初始拥塞窗口。
   * **禁用 PRR (No PRR):** 测试禁用 PRR 时的发送行为。
   * **连接迁移 (Connection Migration):** 测试连接迁移时如何重置拥塞控制状态。
   * **最大拥塞窗口限制 (Default Max Cwnd):** 测试默认最大拥塞窗口的限制。
   * **拥塞避免期间限制 CWND 增长 (Limit Cwnd Increase):** 测试在拥塞避免阶段，拥塞窗口的增长速度是否受到限制。

**2. 使用 Mock 对象和测试工具进行隔离测试：**

   * 使用 `MockClock` 模拟时间流逝，以便精确控制测试场景中的时间。
   * 使用 `QuicConfigPeer` 修改连接配置，模拟不同的网络环境和协议选项。
   * 定义 `TcpCubicSenderBytesPeer` 类作为友元类，以便访问 `TcpCubicSenderBytes` 的私有成员进行断言。

**与 JavaScript 功能的关系：**

虽然这段 C++ 代码本身不在 JavaScript 环境中运行，但它直接影响着基于 QUIC 协议的 Web 应用的性能，而这些 Web 应用通常使用 JavaScript 开发。

* **网络性能优化:** QUIC 协议旨在提供比传统 TCP 更快的、更可靠的网络连接。 `TcpCubicSenderBytes` 作为 QUIC 的拥塞控制机制，直接决定了数据发送的速度和对网络拥塞的响应，从而影响网页加载速度、实时通信质量等用户体验。JavaScript 应用的性能会因此受益。
* **API 的间接影响:** 浏览器会提供一些与网络连接相关的 JavaScript API (例如 `fetch`, `WebSocket`)。QUIC 协议的底层实现（包括这里的拥塞控制）会影响这些 API 的性能表现。
* **开发者工具:** 开发者可以使用浏览器提供的开发者工具来观察网络请求的 timing 信息。理解拥塞控制的工作原理有助于开发者分析网络瓶颈。

**举例说明：**

假设一个基于 JavaScript 的在线游戏，使用 QUIC 进行实时数据传输。

* **慢启动测试:**  `TEST_F(TcpCubicSenderBytesTest, ExponentialSlowStart)` 确保了在连接建立初期，数据发送速率会逐渐增加，避免一下子占用过多带宽导致网络拥塞，从而保证了游戏连接的平稳建立。
* **丢包处理测试:** `TEST_F(TcpCubicSenderBytesTest, SlowStartPacketLossPRR)` 测试了在网络出现丢包时，拥塞控制如何降低发送速率并进入恢复阶段，这直接影响到游戏过程中数据传输的稳定性和流畅性，避免卡顿。
* **带宽恢复测试:** `TEST_F(TcpCubicSenderBytesTest, BandwidthResumption)` 测试了在网络切换后，如何快速恢复到之前的带宽利用率，这对于移动端用户在 Wi-Fi 和移动网络之间切换时保持游戏连接的稳定非常重要。

**逻辑推理的假设输入与输出：**

以 `TEST_F(TcpCubicSenderBytesTest, SlowStartPacketLoss)` 为例：

* **假设输入:**
    * 初始拥塞窗口为 10 个数据包 (`kInitialCongestionWindowPackets`).
    * 连续发送并确认了若干个数据包，使得拥塞窗口增长到一定程度。
    * 模拟发生一个丢包事件 (`LoseNPackets(1)`).
* **逻辑推理:**
    * 根据 TCP Cubic 的慢启动和快速恢复机制，发生丢包后，拥塞窗口应该减小到当前窗口的一半乘以一个回退因子 (RenoBeta)。
    * 进入恢复阶段，发送速率会受到限制。
    * 只有当确认了恢复窗口内的所有数据包后，拥塞窗口才会开始缓慢增长。
* **预期输出:**
    * 在丢包后，`sender_->GetCongestionWindow()` 的值会等于预期降低后的拥塞窗口大小。
    * 在恢复阶段，即使有可发送的数据，发送器的 `CanSend()` 方法在某些时候会返回 `false`，限制发送速率。
    * 确认恢复窗口内的所有数据包后，拥塞窗口会开始缓慢增长。

**用户或编程常见的使用错误：**

* **配置不当的初始拥塞窗口:** 如果服务器或客户端配置了一个过大的初始拥塞窗口，可能会导致连接建立初期就占用过多带宽，影响其他网络应用。测试用例 `TEST_F(TcpCubicSenderBytesTest, ConfigureMaxInitialWindow)` 确保了配置选项能够正确限制初始拥塞窗口。
* **错误地理解拥塞控制算法:** 开发者如果对拥塞控制算法理解不足，可能会在应用层做出一些与拥塞控制机制冲突的操作，例如在网络已经拥塞的情况下仍然尝试发送大量数据，导致性能下降。
* **网络环境模拟不充分:** 在测试网络应用时，如果没有充分考虑到各种网络条件（例如高丢包率、高延迟），可能会导致应用在真实网络环境中表现不佳。 这些测试用例覆盖了各种网络场景，有助于确保拥塞控制算法在不同情况下都能正常工作。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户发起网络请求:** 用户在浏览器中输入网址、点击链接或执行 JavaScript 代码发起一个网络请求。
2. **浏览器解析请求:** 浏览器解析请求，确定目标服务器和协议（例如 HTTPS over QUIC）。
3. **建立 QUIC 连接:** 如果是首次连接，浏览器会与服务器进行握手，建立 QUIC 连接。这包括协商连接参数，例如使用的拥塞控制算法。
4. **数据传输:** 连接建立后，浏览器开始发送 HTTP 请求数据。`TcpCubicSenderBytes` 类在此阶段开始发挥作用，根据网络状况控制发送速率。
5. **网络拥塞或丢包:**  在数据传输过程中，如果网络出现拥塞或者数据包丢失，QUIC 协议的丢包检测机制会发现这些问题。
6. **触发拥塞控制事件:** 丢包事件会触发 `TcpCubicSenderBytes` 类的 `OnCongestionEvent` 方法，该方法会根据 TCP Cubic 算法调整拥塞窗口和慢启动阈值。
7. **发送速率调整:** 调整后的拥塞窗口会影响后续的数据发送速率。`CanSend` 方法会根据当前的拥塞窗口和已发送但未确认的数据量来决定是否可以发送新的数据包。
8. **测试用例模拟场景:** `tcp_cubic_sender_bytes_test.cc` 中的测试用例正是模拟了这些步骤中的各种场景，例如发送数据、模拟丢包、模拟确认等，以验证 `TcpCubicSenderBytes` 类的行为是否符合预期。

**调试线索:**

* 如果在基于 QUIC 的应用中发现网络性能问题（例如连接建立慢、传输速度不稳定、频繁卡顿），可以考虑以下调试步骤：
    * **检查 QUIC 连接状态:** 使用浏览器开发者工具或其他网络抓包工具查看 QUIC 连接的详细信息，例如拥塞窗口大小、丢包率、RTT 等。
    * **分析拥塞控制事件:** 如果可能，查看 QUIC 协议栈的日志，了解拥塞控制算法是如何响应网络事件的。
    * **对比测试结果:**  将实际的网络行为与 `tcp_cubic_sender_bytes_test.cc` 中的测试用例进行对比，看是否符合预期。如果不符合，可能说明拥塞控制算法的实现存在 bug 或者网络环境存在异常。
    * **排查配置问题:** 检查 QUIC 连接的配置参数，例如初始拥塞窗口大小、是否启用了 PRR 等。

总而言之，`tcp_cubic_sender_bytes_test.cc` 文件是 QUIC 协议栈中非常重要的一个测试文件，它确保了 TCP Cubic 拥塞控制算法的正确性和鲁棒性，从而保障了基于 QUIC 协议的网络应用的性能和稳定性。虽然与 JavaScript 没有直接的代码关联，但它对使用 JavaScript 开发的 Web 应用的网络体验有着重要的幕后影响。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/tcp_cubic_sender_bytes_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/tcp_cubic_sender_bytes.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <utility>

#include "quiche/quic/core/congestion_control/rtt_stats.h"
#include "quiche/quic/core/congestion_control/send_algorithm_interface.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_config_peer.h"

namespace quic {
namespace test {

// TODO(ianswett): A number of theses tests were written with the assumption of
// an initial CWND of 10. They have carefully calculated values which should be
// updated to be based on kInitialCongestionWindow.
const uint32_t kInitialCongestionWindowPackets = 10;
const uint32_t kMaxCongestionWindowPackets = 200;
const uint32_t kDefaultWindowTCP =
    kInitialCongestionWindowPackets * kDefaultTCPMSS;
const float kRenoBeta = 0.7f;  // Reno backoff factor.

class TcpCubicSenderBytesPeer : public TcpCubicSenderBytes {
 public:
  TcpCubicSenderBytesPeer(const QuicClock* clock, bool reno)
      : TcpCubicSenderBytes(clock, &rtt_stats_, reno,
                            kInitialCongestionWindowPackets,
                            kMaxCongestionWindowPackets, &stats_) {}

  const HybridSlowStart& hybrid_slow_start() const {
    return hybrid_slow_start_;
  }

  float GetRenoBeta() const { return RenoBeta(); }

  RttStats rtt_stats_;
  QuicConnectionStats stats_;
};

class TcpCubicSenderBytesTest : public QuicTest {
 protected:
  TcpCubicSenderBytesTest()
      : one_ms_(QuicTime::Delta::FromMilliseconds(1)),
        sender_(new TcpCubicSenderBytesPeer(&clock_, true)),
        packet_number_(1),
        acked_packet_number_(0),
        bytes_in_flight_(0) {}

  int SendAvailableSendWindow() {
    return SendAvailableSendWindow(kDefaultTCPMSS);
  }

  int SendAvailableSendWindow(QuicPacketLength /*packet_length*/) {
    // Send as long as TimeUntilSend returns Zero.
    int packets_sent = 0;
    bool can_send = sender_->CanSend(bytes_in_flight_);
    while (can_send) {
      sender_->OnPacketSent(clock_.Now(), bytes_in_flight_,
                            QuicPacketNumber(packet_number_++), kDefaultTCPMSS,
                            HAS_RETRANSMITTABLE_DATA);
      ++packets_sent;
      bytes_in_flight_ += kDefaultTCPMSS;
      can_send = sender_->CanSend(bytes_in_flight_);
    }
    return packets_sent;
  }

  // Normal is that TCP acks every other segment.
  void AckNPackets(int n) {
    sender_->rtt_stats_.UpdateRtt(QuicTime::Delta::FromMilliseconds(60),
                                  QuicTime::Delta::Zero(), clock_.Now());
    AckedPacketVector acked_packets;
    LostPacketVector lost_packets;
    for (int i = 0; i < n; ++i) {
      ++acked_packet_number_;
      acked_packets.push_back(
          AckedPacket(QuicPacketNumber(acked_packet_number_), kDefaultTCPMSS,
                      QuicTime::Zero()));
    }
    sender_->OnCongestionEvent(true, bytes_in_flight_, clock_.Now(),
                               acked_packets, lost_packets, 0, 0);
    bytes_in_flight_ -= n * kDefaultTCPMSS;
    clock_.AdvanceTime(one_ms_);
  }

  void LoseNPackets(int n) { LoseNPackets(n, kDefaultTCPMSS); }

  void LoseNPackets(int n, QuicPacketLength packet_length) {
    AckedPacketVector acked_packets;
    LostPacketVector lost_packets;
    for (int i = 0; i < n; ++i) {
      ++acked_packet_number_;
      lost_packets.push_back(
          LostPacket(QuicPacketNumber(acked_packet_number_), packet_length));
    }
    sender_->OnCongestionEvent(false, bytes_in_flight_, clock_.Now(),
                               acked_packets, lost_packets, 0, 0);
    bytes_in_flight_ -= n * packet_length;
  }

  // Does not increment acked_packet_number_.
  void LosePacket(uint64_t packet_number) {
    AckedPacketVector acked_packets;
    LostPacketVector lost_packets;
    lost_packets.push_back(
        LostPacket(QuicPacketNumber(packet_number), kDefaultTCPMSS));
    sender_->OnCongestionEvent(false, bytes_in_flight_, clock_.Now(),
                               acked_packets, lost_packets, 0, 0);
    bytes_in_flight_ -= kDefaultTCPMSS;
  }

  const QuicTime::Delta one_ms_;
  MockClock clock_;
  std::unique_ptr<TcpCubicSenderBytesPeer> sender_;
  uint64_t packet_number_;
  uint64_t acked_packet_number_;
  QuicByteCount bytes_in_flight_;
};

TEST_F(TcpCubicSenderBytesTest, SimpleSender) {
  // At startup make sure we are at the default.
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
  // At startup make sure we can send.
  EXPECT_TRUE(sender_->CanSend(0));
  // Make sure we can send.
  EXPECT_TRUE(sender_->CanSend(0));
  // And that window is un-affected.
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());

  // Fill the send window with data, then verify that we can't send.
  SendAvailableSendWindow();
  EXPECT_FALSE(sender_->CanSend(sender_->GetCongestionWindow()));
}

TEST_F(TcpCubicSenderBytesTest, ApplicationLimitedSlowStart) {
  // Send exactly 10 packets and ensure the CWND ends at 14 packets.
  const int kNumberOfAcks = 5;
  // At startup make sure we can send.
  EXPECT_TRUE(sender_->CanSend(0));
  // Make sure we can send.
  EXPECT_TRUE(sender_->CanSend(0));

  SendAvailableSendWindow();
  for (int i = 0; i < kNumberOfAcks; ++i) {
    AckNPackets(2);
  }
  QuicByteCount bytes_to_send = sender_->GetCongestionWindow();
  // It's expected 2 acks will arrive when the bytes_in_flight are greater than
  // half the CWND.
  EXPECT_EQ(kDefaultWindowTCP + kDefaultTCPMSS * 2 * 2, bytes_to_send);
}

TEST_F(TcpCubicSenderBytesTest, ExponentialSlowStart) {
  const int kNumberOfAcks = 20;
  // At startup make sure we can send.
  EXPECT_TRUE(sender_->CanSend(0));
  EXPECT_EQ(QuicBandwidth::Zero(), sender_->BandwidthEstimate());
  // Make sure we can send.
  EXPECT_TRUE(sender_->CanSend(0));

  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  const QuicByteCount cwnd = sender_->GetCongestionWindow();
  EXPECT_EQ(kDefaultWindowTCP + kDefaultTCPMSS * 2 * kNumberOfAcks, cwnd);
  EXPECT_EQ(QuicBandwidth::FromBytesAndTimeDelta(
                cwnd, sender_->rtt_stats_.smoothed_rtt()),
            sender_->BandwidthEstimate());
}

TEST_F(TcpCubicSenderBytesTest, SlowStartPacketLoss) {
  sender_->SetNumEmulatedConnections(1);
  const int kNumberOfAcks = 10;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose a packet to exit slow start.
  LoseNPackets(1);
  size_t packets_in_recovery_window = expected_send_window / kDefaultTCPMSS;

  // We should now have fallen out of slow start with a reduced window.
  expected_send_window *= kRenoBeta;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Recovery phase. We need to ack every packet in the recovery window before
  // we exit recovery.
  size_t number_of_packets_in_window = expected_send_window / kDefaultTCPMSS;
  QUIC_DLOG(INFO) << "number_packets: " << number_of_packets_in_window;
  AckNPackets(packets_in_recovery_window);
  SendAvailableSendWindow();
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // We need to ack an entire window before we increase CWND by 1.
  AckNPackets(number_of_packets_in_window - 2);
  SendAvailableSendWindow();
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Next ack should increase cwnd by 1.
  AckNPackets(1);
  expected_send_window += kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Now RTO and ensure slow start gets reset.
  EXPECT_TRUE(sender_->hybrid_slow_start().started());
  sender_->OnRetransmissionTimeout(true);
  EXPECT_FALSE(sender_->hybrid_slow_start().started());
}

TEST_F(TcpCubicSenderBytesTest, SlowStartPacketLossWithLargeReduction) {
  QuicConfig config;
  QuicTagVector options;
  options.push_back(kSSLR);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);

  sender_->SetNumEmulatedConnections(1);
  const int kNumberOfAcks = (kDefaultWindowTCP / (2 * kDefaultTCPMSS)) - 1;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose a packet to exit slow start. We should now have fallen out of
  // slow start with a window reduced by 1.
  LoseNPackets(1);
  expected_send_window -= kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose 5 packets in recovery and verify that congestion window is reduced
  // further.
  LoseNPackets(5);
  expected_send_window -= 5 * kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  // Lose another 10 packets and ensure it reduces below half the peak CWND,
  // because we never acked the full IW.
  LoseNPackets(10);
  expected_send_window -= 10 * kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  size_t packets_in_recovery_window = expected_send_window / kDefaultTCPMSS;

  // Recovery phase. We need to ack every packet in the recovery window before
  // we exit recovery.
  size_t number_of_packets_in_window = expected_send_window / kDefaultTCPMSS;
  QUIC_DLOG(INFO) << "number_packets: " << number_of_packets_in_window;
  AckNPackets(packets_in_recovery_window);
  SendAvailableSendWindow();
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // We need to ack an entire window before we increase CWND by 1.
  AckNPackets(number_of_packets_in_window - 1);
  SendAvailableSendWindow();
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Next ack should increase cwnd by 1.
  AckNPackets(1);
  expected_send_window += kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Now RTO and ensure slow start gets reset.
  EXPECT_TRUE(sender_->hybrid_slow_start().started());
  sender_->OnRetransmissionTimeout(true);
  EXPECT_FALSE(sender_->hybrid_slow_start().started());
}

TEST_F(TcpCubicSenderBytesTest, SlowStartHalfPacketLossWithLargeReduction) {
  QuicConfig config;
  QuicTagVector options;
  options.push_back(kSSLR);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);

  sender_->SetNumEmulatedConnections(1);
  const int kNumberOfAcks = 10;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window in half sized packets.
    SendAvailableSendWindow(kDefaultTCPMSS / 2);
    AckNPackets(2);
  }
  SendAvailableSendWindow(kDefaultTCPMSS / 2);
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose a packet to exit slow start. We should now have fallen out of
  // slow start with a window reduced by 1.
  LoseNPackets(1);
  expected_send_window -= kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose 10 packets in recovery and verify that congestion window is reduced
  // by 5 packets.
  LoseNPackets(10, kDefaultTCPMSS / 2);
  expected_send_window -= 5 * kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderBytesTest, SlowStartPacketLossWithMaxHalfReduction) {
  QuicConfig config;
  QuicTagVector options;
  options.push_back(kSSLR);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);

  sender_->SetNumEmulatedConnections(1);
  const int kNumberOfAcks = kInitialCongestionWindowPackets / 2;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose a packet to exit slow start. We should now have fallen out of
  // slow start with a window reduced by 1.
  LoseNPackets(1);
  expected_send_window -= kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose half the outstanding packets in recovery and verify the congestion
  // window is only reduced by a max of half.
  LoseNPackets(kNumberOfAcks * 2);
  expected_send_window -= (kNumberOfAcks * 2 - 1) * kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  LoseNPackets(5);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderBytesTest, NoPRRWhenLessThanOnePacketInFlight) {
  SendAvailableSendWindow();
  LoseNPackets(kInitialCongestionWindowPackets - 1);
  AckNPackets(1);
  // PRR will allow 2 packets for every ack during recovery.
  EXPECT_EQ(2, SendAvailableSendWindow());
  // Simulate abandoning all packets by supplying a bytes_in_flight of 0.
  // PRR should now allow a packet to be sent, even though prr's state variables
  // believe it has sent enough packets.
  EXPECT_TRUE(sender_->CanSend(0));
}

TEST_F(TcpCubicSenderBytesTest, SlowStartPacketLossPRR) {
  sender_->SetNumEmulatedConnections(1);
  // Test based on the first example in RFC6937.
  // Ack 10 packets in 5 acks to raise the CWND to 20, as in the example.
  const int kNumberOfAcks = 5;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  LoseNPackets(1);

  // We should now have fallen out of slow start with a reduced window.
  size_t send_window_before_loss = expected_send_window;
  expected_send_window *= kRenoBeta;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Testing TCP proportional rate reduction.
  // We should send packets paced over the received acks for the remaining
  // outstanding packets. The number of packets before we exit recovery is the
  // original CWND minus the packet that has been lost and the one which
  // triggered the loss.
  size_t remaining_packets_in_recovery =
      send_window_before_loss / kDefaultTCPMSS - 2;

  for (size_t i = 0; i < remaining_packets_in_recovery; ++i) {
    AckNPackets(1);
    SendAvailableSendWindow();
    EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  }

  // We need to ack another window before we increase CWND by 1.
  size_t number_of_packets_in_window = expected_send_window / kDefaultTCPMSS;
  for (size_t i = 0; i < number_of_packets_in_window; ++i) {
    AckNPackets(1);
    EXPECT_EQ(1, SendAvailableSendWindow());
    EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  }

  AckNPackets(1);
  expected_send_window += kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderBytesTest, SlowStartBurstPacketLossPRR) {
  sender_->SetNumEmulatedConnections(1);
  // Test based on the second example in RFC6937, though we also implement
  // forward acknowledgements, so the first two incoming acks will trigger
  // PRR immediately.
  // Ack 20 packets in 10 acks to raise the CWND to 30.
  const int kNumberOfAcks = 10;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Lose one more than the congestion window reduction, so that after loss,
  // bytes_in_flight is lesser than the congestion window.
  size_t send_window_after_loss = kRenoBeta * expected_send_window;
  size_t num_packets_to_lose =
      (expected_send_window - send_window_after_loss) / kDefaultTCPMSS + 1;
  LoseNPackets(num_packets_to_lose);
  // Immediately after the loss, ensure at least one packet can be sent.
  // Losses without subsequent acks can occur with timer based loss detection.
  EXPECT_TRUE(sender_->CanSend(bytes_in_flight_));
  AckNPackets(1);

  // We should now have fallen out of slow start with a reduced window.
  expected_send_window *= kRenoBeta;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Only 2 packets should be allowed to be sent, per PRR-SSRB.
  EXPECT_EQ(2, SendAvailableSendWindow());

  // Ack the next packet, which triggers another loss.
  LoseNPackets(1);
  AckNPackets(1);

  // Send 2 packets to simulate PRR-SSRB.
  EXPECT_EQ(2, SendAvailableSendWindow());

  // Ack the next packet, which triggers another loss.
  LoseNPackets(1);
  AckNPackets(1);

  // Send 2 packets to simulate PRR-SSRB.
  EXPECT_EQ(2, SendAvailableSendWindow());

  // Exit recovery and return to sending at the new rate.
  for (int i = 0; i < kNumberOfAcks; ++i) {
    AckNPackets(1);
    EXPECT_EQ(1, SendAvailableSendWindow());
  }
}

TEST_F(TcpCubicSenderBytesTest, RTOCongestionWindow) {
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
  // Expect the window to decrease to the minimum once the RTO fires and slow
  // start threshold to be set to 1/2 of the CWND.
  sender_->OnRetransmissionTimeout(true);
  EXPECT_EQ(2 * kDefaultTCPMSS, sender_->GetCongestionWindow());
  EXPECT_EQ(5u * kDefaultTCPMSS, sender_->GetSlowStartThreshold());
}

TEST_F(TcpCubicSenderBytesTest, RTOCongestionWindowNoRetransmission) {
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());

  // Expect the window to remain unchanged if the RTO fires but no packets are
  // retransmitted.
  sender_->OnRetransmissionTimeout(false);
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderBytesTest, TcpCubicResetEpochOnQuiescence) {
  const int kMaxCongestionWindow = 50;
  const QuicByteCount kMaxCongestionWindowBytes =
      kMaxCongestionWindow * kDefaultTCPMSS;
  int num_sent = SendAvailableSendWindow();

  // Make sure we fall out of slow start.
  QuicByteCount saved_cwnd = sender_->GetCongestionWindow();
  LoseNPackets(1);
  EXPECT_GT(saved_cwnd, sender_->GetCongestionWindow());

  // Ack the rest of the outstanding packets to get out of recovery.
  for (int i = 1; i < num_sent; ++i) {
    AckNPackets(1);
  }
  EXPECT_EQ(0u, bytes_in_flight_);

  // Send a new window of data and ack all; cubic growth should occur.
  saved_cwnd = sender_->GetCongestionWindow();
  num_sent = SendAvailableSendWindow();
  for (int i = 0; i < num_sent; ++i) {
    AckNPackets(1);
  }
  EXPECT_LT(saved_cwnd, sender_->GetCongestionWindow());
  EXPECT_GT(kMaxCongestionWindowBytes, sender_->GetCongestionWindow());
  EXPECT_EQ(0u, bytes_in_flight_);

  // Quiescent time of 100 seconds
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(100000));

  // Send new window of data and ack one packet. Cubic epoch should have
  // been reset; ensure cwnd increase is not dramatic.
  saved_cwnd = sender_->GetCongestionWindow();
  SendAvailableSendWindow();
  AckNPackets(1);
  EXPECT_NEAR(saved_cwnd, sender_->GetCongestionWindow(), kDefaultTCPMSS);
  EXPECT_GT(kMaxCongestionWindowBytes, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderBytesTest, MultipleLossesInOneWindow) {
  SendAvailableSendWindow();
  const QuicByteCount initial_window = sender_->GetCongestionWindow();
  LosePacket(acked_packet_number_ + 1);
  const QuicByteCount post_loss_window = sender_->GetCongestionWindow();
  EXPECT_GT(initial_window, post_loss_window);
  LosePacket(acked_packet_number_ + 3);
  EXPECT_EQ(post_loss_window, sender_->GetCongestionWindow());
  LosePacket(packet_number_ - 1);
  EXPECT_EQ(post_loss_window, sender_->GetCongestionWindow());

  // Lose a later packet and ensure the window decreases.
  LosePacket(packet_number_);
  EXPECT_GT(post_loss_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderBytesTest, ConfigureMaxInitialWindow) {
  QuicConfig config;

  // Verify that kCOPT: kIW10 forces the congestion window to the default of 10.
  QuicTagVector options;
  options.push_back(kIW10);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);
  EXPECT_EQ(10u * kDefaultTCPMSS, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderBytesTest, SetInitialCongestionWindow) {
  EXPECT_NE(3u * kDefaultTCPMSS, sender_->GetCongestionWindow());
  sender_->SetInitialCongestionWindowInPackets(3);
  EXPECT_EQ(3u * kDefaultTCPMSS, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderBytesTest, 2ConnectionCongestionAvoidanceAtEndOfRecovery) {
  sender_->SetNumEmulatedConnections(2);
  // Ack 10 packets in 5 acks to raise the CWND to 20.
  const int kNumberOfAcks = 5;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  LoseNPackets(1);

  // We should now have fallen out of slow start with a reduced window.
  expected_send_window = expected_send_window * sender_->GetRenoBeta();
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // No congestion window growth should occur in recovery phase, i.e., until the
  // currently outstanding 20 packets are acked.
  for (int i = 0; i < 10; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    EXPECT_TRUE(sender_->InRecovery());
    AckNPackets(2);
    EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  }
  EXPECT_FALSE(sender_->InRecovery());

  // Out of recovery now. Congestion window should not grow for half an RTT.
  size_t packets_in_send_window = expected_send_window / kDefaultTCPMSS;
  SendAvailableSendWindow();
  AckNPackets(packets_in_send_window / 2 - 2);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Next ack should increase congestion window by 1MSS.
  SendAvailableSendWindow();
  AckNPackets(2);
  expected_send_window += kDefaultTCPMSS;
  packets_in_send_window += 1;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Congestion window should remain steady again for half an RTT.
  SendAvailableSendWindow();
  AckNPackets(packets_in_send_window / 2 - 1);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Next ack should cause congestion window to grow by 1MSS.
  SendAvailableSendWindow();
  AckNPackets(2);
  expected_send_window += kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderBytesTest, 1ConnectionCongestionAvoidanceAtEndOfRecovery) {
  sender_->SetNumEmulatedConnections(1);
  // Ack 10 packets in 5 acks to raise the CWND to 20.
  const int kNumberOfAcks = 5;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  LoseNPackets(1);

  // We should now have fallen out of slow start with a reduced window.
  expected_send_window *= kRenoBeta;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // No congestion window growth should occur in recovery phase, i.e., until the
  // currently outstanding 20 packets are acked.
  for (int i = 0; i < 10; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    EXPECT_TRUE(sender_->InRecovery());
    AckNPackets(2);
    EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  }
  EXPECT_FALSE(sender_->InRecovery());

  // Out of recovery now. Congestion window should not grow during RTT.
  for (uint64_t i = 0; i < expected_send_window / kDefaultTCPMSS - 2; i += 2) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
    EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  }

  // Next ack should cause congestion window to grow by 1MSS.
  SendAvailableSendWindow();
  AckNPackets(2);
  expected_send_window += kDefaultTCPMSS;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderBytesTest, BandwidthResumption) {
  // Test that when provided with CachedNetworkParameters and opted in to the
  // bandwidth resumption experiment, that the TcpCubicSenderPackets sets
  // initial CWND appropriately.

  // Set some common values.
  const QuicPacketCount kNumberOfPackets = 123;
  const QuicBandwidth kBandwidthEstimate =
      QuicBandwidth::FromBytesPerSecond(kNumberOfPackets * kDefaultTCPMSS);
  const QuicTime::Delta kRttEstimate = QuicTime::Delta::FromSeconds(1);

  SendAlgorithmInterface::NetworkParams network_param;
  network_param.bandwidth = kBandwidthEstimate;
  network_param.rtt = kRttEstimate;
  sender_->AdjustNetworkParameters(network_param);
  EXPECT_EQ(kNumberOfPackets * kDefaultTCPMSS, sender_->GetCongestionWindow());

  // Resume with an illegal value of 0 and verify the server ignores it.
  SendAlgorithmInterface::NetworkParams network_param_no_bandwidth;
  network_param_no_bandwidth.bandwidth = QuicBandwidth::Zero();
  network_param_no_bandwidth.rtt = kRttEstimate;
  sender_->AdjustNetworkParameters(network_param_no_bandwidth);
  EXPECT_EQ(kNumberOfPackets * kDefaultTCPMSS, sender_->GetCongestionWindow());

  // Resumed CWND is limited to be in a sensible range.
  const QuicBandwidth kUnreasonableBandwidth =
      QuicBandwidth::FromBytesPerSecond((kMaxResumptionCongestionWindow + 1) *
                                        kDefaultTCPMSS);
  SendAlgorithmInterface::NetworkParams network_param_large_bandwidth;
  network_param_large_bandwidth.bandwidth = kUnreasonableBandwidth;
  network_param_large_bandwidth.rtt = QuicTime::Delta::FromSeconds(1);
  sender_->AdjustNetworkParameters(network_param_large_bandwidth);
  EXPECT_EQ(kMaxResumptionCongestionWindow * kDefaultTCPMSS,
            sender_->GetCongestionWindow());
}

TEST_F(TcpCubicSenderBytesTest, PaceBelowCWND) {
  QuicConfig config;

  // Verify that kCOPT: kMIN4 forces the min CWND to 1 packet, but allows up
  // to 4 to be sent.
  QuicTagVector options;
  options.push_back(kMIN4);
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);
  sender_->OnRetransmissionTimeout(true);
  EXPECT_EQ(kDefaultTCPMSS, sender_->GetCongestionWindow());
  EXPECT_TRUE(sender_->CanSend(kDefaultTCPMSS));
  EXPECT_TRUE(sender_->CanSend(2 * kDefaultTCPMSS));
  EXPECT_TRUE(sender_->CanSend(3 * kDefaultTCPMSS));
  EXPECT_FALSE(sender_->CanSend(4 * kDefaultTCPMSS));
}

TEST_F(TcpCubicSenderBytesTest, NoPRR) {
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(100);
  sender_->rtt_stats_.UpdateRtt(rtt, QuicTime::Delta::Zero(), QuicTime::Zero());

  sender_->SetNumEmulatedConnections(1);
  // Verify that kCOPT: kNPRR allows all packets to be sent, even if only one
  // ack has been received.
  QuicTagVector options;
  options.push_back(kNPRR);
  QuicConfig config;
  QuicConfigPeer::SetReceivedConnectionOptions(&config, options);
  sender_->SetFromConfig(config, Perspective::IS_SERVER);
  SendAvailableSendWindow();
  LoseNPackets(9);
  AckNPackets(1);

  // We should now have fallen out of slow start with a reduced window.
  EXPECT_EQ(kRenoBeta * kDefaultWindowTCP, sender_->GetCongestionWindow());
  const QuicPacketCount window_in_packets =
      kRenoBeta * kDefaultWindowTCP / kDefaultTCPMSS;
  const QuicBandwidth expected_pacing_rate =
      QuicBandwidth::FromBytesAndTimeDelta(kRenoBeta * kDefaultWindowTCP,
                                           sender_->rtt_stats_.smoothed_rtt());
  EXPECT_EQ(expected_pacing_rate, sender_->PacingRate(0));
  EXPECT_EQ(window_in_packets,
            static_cast<uint64_t>(SendAvailableSendWindow()));
  EXPECT_EQ(expected_pacing_rate,
            sender_->PacingRate(kRenoBeta * kDefaultWindowTCP));
}

TEST_F(TcpCubicSenderBytesTest, ResetAfterConnectionMigration) {
  // Starts from slow start.
  sender_->SetNumEmulatedConnections(1);
  const int kNumberOfAcks = 10;
  for (int i = 0; i < kNumberOfAcks; ++i) {
    // Send our full send window.
    SendAvailableSendWindow();
    AckNPackets(2);
  }
  SendAvailableSendWindow();
  QuicByteCount expected_send_window =
      kDefaultWindowTCP + (kDefaultTCPMSS * 2 * kNumberOfAcks);
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());

  // Loses a packet to exit slow start.
  LoseNPackets(1);

  // We should now have fallen out of slow start with a reduced window. Slow
  // start threshold is also updated.
  expected_send_window *= kRenoBeta;
  EXPECT_EQ(expected_send_window, sender_->GetCongestionWindow());
  EXPECT_EQ(expected_send_window, sender_->GetSlowStartThreshold());

  // Resets cwnd and slow start threshold on connection migrations.
  sender_->OnConnectionMigration();
  EXPECT_EQ(kDefaultWindowTCP, sender_->GetCongestionWindow());
  EXPECT_EQ(kMaxCongestionWindowPackets * kDefaultTCPMSS,
            sender_->GetSlowStartThreshold());
  EXPECT_FALSE(sender_->hybrid_slow_start().started());
}

TEST_F(TcpCubicSenderBytesTest, DefaultMaxCwnd) {
  RttStats rtt_stats;
  QuicConnectionStats stats;
  std::unique_ptr<SendAlgorithmInterface> sender(SendAlgorithmInterface::Create(
      &clock_, &rtt_stats, /*unacked_packets=*/nullptr, kCubicBytes,
      QuicRandom::GetInstance(), &stats, kInitialCongestionWindow, nullptr));

  AckedPacketVector acked_packets;
  LostPacketVector missing_packets;
  QuicPacketCount max_congestion_window =
      GetQuicFlag(quic_max_congestion_window);
  for (uint64_t i = 1; i < max_congestion_window; ++i) {
    acked_packets.clear();
    acked_packets.push_back(
        AckedPacket(QuicPacketNumber(i), 1350, QuicTime::Zero()));
    sender->OnCongestionEvent(true, sender->GetCongestionWindow(), clock_.Now(),
                              acked_packets, missing_packets, 0, 0);
  }
  EXPECT_EQ(max_congestion_window,
            sender->GetCongestionWindow() / kDefaultTCPMSS);
}

TEST_F(TcpCubicSenderBytesTest, LimitCwndIncreaseInCongestionAvoidance) {
  // Enable Cubic.
  sender_ = std::make_unique<TcpCubicSenderBytesPeer>(&clock_, false);

  int num_sent = SendAvailableSendWindow();

  // Make sure we fall out of slow start.
  QuicByteCount saved_cwnd = sender_->GetCongestionWindow();
  LoseNPackets(1);
  EXPECT_GT(saved_cwnd, sender_->GetCongestionWindow());

  // Ack the rest of the outstanding packets to get out of recovery.
  for (int i = 1; i < num_sent; ++i) {
    AckNPackets(1);
  }
  EXPECT_EQ(0u, bytes_in_flight_);
  // Send a new window of data and ack all; cubic growth should occur.
  saved_cwnd = sender_->GetCongestionWindow();
  num_sent = SendAvailableSendWindow();

  // Ack packets until the CWND increases.
  while (sender_->GetCongestionWindow() == saved_cwnd) {
    AckNPackets(1);
    SendAvailableSendWindow();
  }
  // Bytes in flight may be larger than the CWND if the CWND isn't an exact
  // multiple of the packet sizes being sent.
  EXPECT_GE(bytes_in_flight_, sender_->GetCongestionWindow());
  saved_cwnd = sender_->GetCongestionWindow();

  // Advance time 2 seconds waiting for an ack.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(2000));

  // Ack two packets.  The CWND should increase by only one packet.
  AckNPackets(2);
  EXPECT_EQ(saved_cwnd + kDefaultTCPMSS, sender_->GetCongestionWindow());
}

}  // namespace test
}  // namespace quic

"""

```