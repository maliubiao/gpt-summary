Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Identify the Core Subject:** The file name `pacing_sender_test.cc` immediately tells us this is a test file for something called `PacingSender`. The directory `net/third_party/quiche/src/quiche/quic/core/congestion_control/` reinforces this, placing `PacingSender` within the QUIC protocol's congestion control mechanism.

2. **Understand the Purpose of a Test File:** Test files are designed to verify the correct behavior of a specific piece of code. They do this by setting up different scenarios, executing the code under test, and then asserting that the output or state matches the expected behavior.

3. **Scan for Key Classes and Methods:** Looking at the code, we see:
    * `TestPacingSender`:  Inherits from `PacingSender`, suggesting it's a modified version for testing purposes (likely to expose internal state).
    * `PacingSenderTest`:  The main test fixture, inheriting from `QuicTest`. This class sets up and runs the individual test cases.
    * Test functions like `NoSend`, `SendNow`, `VariousSending`, etc. These are the individual test cases.
    * Mocking using `StrictMock<MockSendAlgorithm>`: This indicates that `PacingSender` interacts with another component (`SendAlgorithm`), and these interactions are being controlled and verified in the tests.

4. **Analyze Individual Test Cases:**  Let's pick a few examples and analyze how they work:

    * **`NoSend`:**  This test checks the scenario where the underlying `MockSendAlgorithm` says it `CanSend()` is false. The assertion `EXPECT_EQ(infinite_time_, ...)` verifies that the `PacingSender` correctly reports that it cannot send (by returning an infinite delay).

    * **`SendNow`:** This is the opposite of `NoSend`. It checks that when `MockSendAlgorithm` allows sending (`CanSend()` returns true), the `PacingSender` also indicates immediate sending (zero delay).

    * **`VariousSending`:** This test is more complex. It involves:
        * Initializing the pacing rate.
        * Updating the RTT (Round-Trip Time).
        * Calling `CheckPacketIsSentImmediately()` and `CheckPacketIsDelayed()`. These helper functions encapsulate the logic for verifying immediate or delayed sending based on the pacing algorithm. The advancing of `clock_` simulates the passage of time.

5. **Infer the Functionality of `PacingSender`:** Based on the test cases, we can infer the following about `PacingSender`:
    * **Pacing:** It controls the rate at which packets are sent, preventing the network from being overwhelmed. This is evident in tests like `VariousSending` and the delays being checked.
    * **Initial Burst:** It allows a burst of packets at the beginning of a connection before pacing kicks in. This is tested in `InitialBurst`.
    * **Interaction with `SendAlgorithm`:** It relies on another component (`SendAlgorithm`) for decisions about congestion and bandwidth. The mocking confirms this dependency.
    * **Response to RTT:** It adjusts its pacing based on the measured Round-Trip Time.
    * **Handling Application Limits:** It can handle situations where the application isn't sending data as fast as the network allows.
    * **Lumpy Pacing (Optional Feature):**  The tests with `quic_lumpy_pacing_size` and `quic_lumpy_pacing_cwnd_fraction` flags suggest an optional feature where packets are sent in groups ("lumps").

6. **Look for Connections to JavaScript:**  A careful read reveals no direct interaction with JavaScript. The code is entirely C++. However, it's important to consider *where* this code fits in the Chromium architecture. Chromium uses a multi-process model. Network operations often happen in a separate network process. JavaScript running in a web page's renderer process would communicate with this network process via inter-process communication (IPC). So, while *this specific C++ file* doesn't have JavaScript, the *functionality it provides* (pacing of network traffic) directly impacts the performance of web pages and JavaScript applications.

7. **Consider Potential Errors and Debugging:** The test file itself provides clues about potential errors. For instance, the `CwndLimited` test highlights issues that can arise when the congestion window limits the sending rate. The structure of the test cases, with clear setup and assertions, provides a template for debugging. If a pacing-related issue arises, developers would likely look at these tests to understand how the `PacingSender` *should* behave and then use debugging tools to see where the actual behavior diverges.

8. **Address Specific Requirements (Hypothetical Inputs/Outputs, User Errors, Debugging Steps):**  Based on the understanding gained so far, these become easier to address. Hypothetical inputs involve different bandwidths, RTTs, and congestion scenarios. User errors would be less direct (users don't interact with this C++ code directly), but more about the *consequences* of pacing behavior (e.g., slow page loads if pacing is misconfigured). The debugging steps involve tracing the execution flow, inspecting the state of `PacingSender`, and comparing it against the expected behavior defined in the tests.

9. **Iterative Refinement:**  The initial analysis might not be perfect. Reading the code carefully again, especially the helper functions like `CheckPacketIsSentImmediately` and `CheckPacketIsDelayed`, provides more details about how the tests are structured and what specific conditions are being verified. Understanding the role of the `MockSendAlgorithm` is crucial.

By following this structured approach, we can effectively analyze the C++ test file, understand its purpose, infer the functionality of the code under test, and connect it to the broader context of the Chromium network stack.
这个C++源代码文件 `pacing_sender_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的一部分，专门用于测试 `PacingSender` 类的功能。 `PacingSender` 的作用是控制数据包的发送速率，防止网络拥塞，即**流量整形**或**速率限制**。

以下是该文件的详细功能列表：

**主要功能：**

1. **单元测试 `PacingSender` 类:** 该文件包含了多个独立的测试用例（以 `TEST_F` 宏定义），用于验证 `PacingSender` 类的各种行为和功能是否符合预期。

2. **模拟网络环境:** 测试用例使用 `MockClock` 来模拟时间流逝，并使用 `StrictMock<MockSendAlgorithm>` 来模拟底层发送算法的行为，例如判断是否可以发送数据包 (`CanSend`)，获取当前的发送速率 (`PacingRate`) 和带宽估计 (`BandwidthEstimate`)，以及处理拥塞事件 (`OnCongestionEvent`) 和数据包发送事件 (`OnPacketSent`)。

3. **验证发送时机:**  测试用例的核心是验证 `PacingSender` 在不同的网络条件下，如何决定何时发送下一个数据包。这主要通过调用 `pacing_sender_->TimeUntilSend()` 方法来判断在给定时间和已发送字节数的情况下，还需要等待多久才能发送下一个数据包。

4. **验证初始突发:**  QUIC 协议允许在连接建立初期发送一定数量的数据包而不受速率限制，称为初始突发。测试用例会验证 `PacingSender` 是否正确实现了初始突发机制。

5. **验证速率限制:** 测试用例会设置不同的发送速率，并验证 `PacingSender` 是否能够按照设定的速率发送数据包，防止发送速度过快导致网络拥塞。

6. **验证 RTT (往返时延) 影响:**  测试用例会模拟 RTT 的变化，并验证 `PacingSender` 是否能够根据 RTT 调整发送速率。

7. **验证拥塞事件处理:** 测试用例会模拟发生丢包等拥塞事件，并验证 `PacingSender` 是否能够正确响应拥塞事件，例如降低发送速率。

8. **验证应用层限制:** 测试用例会模拟应用层数据发送受限的情况，并验证 `PacingSender` 是否能够处理这种情况。

9. **验证分块发送 (Lumpy Pacing，实验性特性):** 文件中包含一些针对 "lumpy pacing" 的测试用例，这是一种将多个数据包组合在一起发送的策略，旨在提高带宽利用率。这些测试用例验证了在启用分块发送时 `PacingSender` 的行为。

**与 JavaScript 的关系：**

`pacing_sender_test.cc` 本身是 C++ 代码，与 JavaScript 没有直接的代码级别的关系。但是，它测试的网络流量控制功能**直接影响**基于 JavaScript 的 Web 应用的性能和用户体验。

* **用户感知速度:**  如果 `PacingSender` 工作不正常，可能导致网页加载缓慢、视频卡顿等问题，最终影响 JavaScript 应用的响应速度。
* **网络资源利用:**  `PacingSender` 的目标是合理利用网络带宽，避免拥塞。良好的流量控制可以提升整体网络效率，让 JavaScript 应用更流畅地传输数据。
* **QUIC 协议支持:**  现代浏览器越来越多地采用 QUIC 协议，而 `PacingSender` 是 QUIC 协议实现的关键组成部分。因此，它的正确性直接影响浏览器对 QUIC 协议的支持，进而影响使用 QUIC 的 JavaScript 应用。

**举例说明:**

假设一个使用 JavaScript 的在线视频播放器：

* **功能异常（`PacingSender` Bug）：** 如果 `PacingSender` 的初始突发逻辑有误，可能导致视频播放开始时加载速度过慢，用户需要等待很久才能看到画面。
* **功能优化（`PacingSender` 优化）：** 如果 `PacingSender` 能够更智能地根据网络状况调整发送速率，就能减少视频播放过程中的缓冲和卡顿，提升用户的观看体验。

**逻辑推理：**

**假设输入：**

1. **初始带宽估计:** 1 Mbps
2. **RTT:** 100ms
3. **最大数据包大小:** 1400 字节
4. **发送数据:** 10 个数据包

**预期输出（基于理想的 `PacingSender` 行为）：**

1. **初始突发:**  `PacingSender` 可能会允许发送少量数据包（例如，根据初始拥塞窗口大小），而无需立即等待。
2. **后续发送间隔:**  `PacingSender` 会根据带宽估计和 RTT 计算出理想的发送间隔。 大致的计算公式是： `发送间隔 = 数据包大小 / (带宽 / 8)`。 在这个例子中，`发送间隔 = 1400 字节 / (1000000 bit/s / 8) = 0.0112 秒 = 11.2 毫秒`。  考虑到 RTT， pacing 策略可能还会考虑避免发送速度过快导致网络拥塞。
3. **总发送时间:**  由于有初始突发和后续的速率限制，总发送时间会比理想情况稍长。

**实际输出（需要通过测试验证）：**

测试用例会模拟这些输入条件，然后断言 `pacing_sender_->TimeUntilSend()` 的返回值以及实际的数据包发送时机是否符合预期的 pacing 行为。例如，会检查在发送初始突发后的数据包时，`TimeUntilSend()` 返回的值是否接近计算出的发送间隔。

**用户或编程常见的使用错误：**

虽然用户不直接与 `PacingSender` 交互，但编程错误可能导致其行为异常：

1. **错误的带宽估计:**  如果底层的 `SendAlgorithm` 提供了错误的带宽估计，`PacingSender` 可能无法做出正确的发送决策，导致发送过快或过慢。
2. **错误的 RTT 计算:**  同样，错误的 RTT 计算也会影响 `PacingSender` 的判断。
3. **配置错误:**  如果 QUIC 的相关配置参数（例如初始拥塞窗口大小）设置不当，可能会影响 `PacingSender` 的初始行为。
4. **状态管理错误:**  `PacingSender` 需要维护一些内部状态（例如，剩余的 burst tokens）。如果状态管理出现错误，可能导致 pacing 失效。
5. **与底层发送算法的集成问题:**  `PacingSender` 依赖于 `SendAlgorithm` 提供信息和执行发送操作。如果两者之间的接口或逻辑存在问题，会导致 pacing 行为异常。

**用户操作如何一步步到达这里（作为调试线索）：**

假设用户在使用 Chrome 浏览器浏览一个视频网站，发现视频播放非常卡顿：

1. **用户操作：** 用户点击播放按钮开始观看视频。
2. **浏览器行为：** 浏览器向视频服务器发起 HTTP/3 (QUIC) 请求获取视频数据。
3. **网络栈处理：** Chrome 的网络栈接收到视频数据，并使用 QUIC 协议进行传输。
4. **`PacingSender` 介入：** 在 QUIC 连接中，`PacingSender` 负责控制视频数据包的发送速率，确保不会因为发送过快而导致网络拥塞。
5. **可能的问题点：** 如果 `PacingSender` 的逻辑存在 Bug，或者底层的带宽估计不准确，可能导致发送速率过慢，从而造成视频卡顿。

**调试线索：**

* **抓包分析:**  使用网络抓包工具 (例如 Wireshark) 可以查看实际的网络数据包发送情况，例如数据包的发送时间间隔，可以判断是否符合 pacing 策略。
* **Chrome Net-Internals:**  Chrome 浏览器内置了 `chrome://net-internals/#quic` 页面，可以查看当前 QUIC 连接的详细信息，包括 pacing 相关的参数和统计数据。
* **日志输出:**  开发者可能会在 `PacingSender` 的代码中添加日志输出，记录其决策过程和状态变化，以便在调试时分析问题。
* **单元测试:**  如果怀疑是 `PacingSender` 的问题，可以运行 `pacing_sender_test.cc` 中的单元测试，验证其基本功能是否正常。如果单元测试失败，则说明 `PacingSender` 的代码存在 Bug。

总而言之，`pacing_sender_test.cc` 文件是保证 Chromium QUIC 协议实现质量的关键部分，它通过各种测试用例来验证流量控制机制的正确性，最终影响用户的网络体验。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/congestion_control/pacing_sender_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/congestion_control/pacing_sender.h"

#include <memory>
#include <utility>

#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

using testing::_;
using testing::AtMost;
using testing::Return;
using testing::StrictMock;

namespace quic {
namespace test {

const QuicByteCount kBytesInFlight = 1024;
const int kInitialBurstPackets = 10;

class TestPacingSender : public PacingSender {
 public:
  using PacingSender::lumpy_tokens;
  using PacingSender::PacingSender;

  QuicTime ideal_next_packet_send_time() const {
    return GetNextReleaseTime().release_time;
  }
};

class PacingSenderTest : public QuicTest {
 protected:
  PacingSenderTest()
      : zero_time_(QuicTime::Delta::Zero()),
        infinite_time_(QuicTime::Delta::Infinite()),
        packet_number_(1),
        mock_sender_(new StrictMock<MockSendAlgorithm>()),
        pacing_sender_(new TestPacingSender) {
    pacing_sender_->set_sender(mock_sender_.get());
    // Pick arbitrary time.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(9));
  }

  ~PacingSenderTest() override {}

  void InitPacingRate(QuicPacketCount burst_size, QuicBandwidth bandwidth) {
    mock_sender_ = std::make_unique<StrictMock<MockSendAlgorithm>>();
    pacing_sender_ = std::make_unique<TestPacingSender>();
    pacing_sender_->set_sender(mock_sender_.get());
    EXPECT_CALL(*mock_sender_, PacingRate(_)).WillRepeatedly(Return(bandwidth));
    EXPECT_CALL(*mock_sender_, BandwidthEstimate())
        .WillRepeatedly(Return(bandwidth));
    if (burst_size == 0) {
      EXPECT_CALL(*mock_sender_, OnCongestionEvent(_, _, _, _, _, _, _));
      LostPacketVector lost_packets;
      lost_packets.push_back(
          LostPacket(QuicPacketNumber(1), kMaxOutgoingPacketSize));
      AckedPacketVector empty;
      pacing_sender_->OnCongestionEvent(true, 1234, clock_.Now(), empty,
                                        lost_packets, 0, 0);
    } else if (burst_size != kInitialBurstPackets) {
      QUIC_LOG(FATAL) << "Unsupported burst_size " << burst_size
                      << " specificied, only 0 and " << kInitialBurstPackets
                      << " are supported.";
    }
  }

  void CheckPacketIsSentImmediately(HasRetransmittableData retransmittable_data,
                                    QuicByteCount prior_in_flight,
                                    bool in_recovery, QuicPacketCount cwnd) {
    // In order for the packet to be sendable, the underlying sender must
    // permit it to be sent immediately.
    for (int i = 0; i < 2; ++i) {
      EXPECT_CALL(*mock_sender_, CanSend(prior_in_flight))
          .WillOnce(Return(true));
      // Verify that the packet can be sent immediately.
      EXPECT_EQ(zero_time_,
                pacing_sender_->TimeUntilSend(clock_.Now(), prior_in_flight))
          << "Next packet to send is " << packet_number_;
    }

    // Actually send the packet.
    if (prior_in_flight == 0 &&
        !GetQuicReloadableFlag(quic_pacing_remove_non_initial_burst)) {
      EXPECT_CALL(*mock_sender_, InRecovery()).WillOnce(Return(in_recovery));
    }
    EXPECT_CALL(*mock_sender_,
                OnPacketSent(clock_.Now(), prior_in_flight, packet_number_,
                             kMaxOutgoingPacketSize, retransmittable_data));
    EXPECT_CALL(*mock_sender_, GetCongestionWindow())
        .WillRepeatedly(Return(cwnd * kDefaultTCPMSS));
    EXPECT_CALL(*mock_sender_,
                CanSend(prior_in_flight + kMaxOutgoingPacketSize))
        .Times(AtMost(1))
        .WillRepeatedly(Return((prior_in_flight + kMaxOutgoingPacketSize) <
                               (cwnd * kDefaultTCPMSS)));
    pacing_sender_->OnPacketSent(clock_.Now(), prior_in_flight,
                                 packet_number_++, kMaxOutgoingPacketSize,
                                 retransmittable_data);
  }

  void CheckPacketIsSentImmediately() {
    CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA, kBytesInFlight,
                                 false, 10);
  }

  void CheckPacketIsDelayed(QuicTime::Delta delay) {
    // In order for the packet to be sendable, the underlying sender must
    // permit it to be sent immediately.
    for (int i = 0; i < 2; ++i) {
      EXPECT_CALL(*mock_sender_, CanSend(kBytesInFlight))
          .WillOnce(Return(true));
      // Verify that the packet is delayed.
      EXPECT_EQ(delay.ToMicroseconds(),
                pacing_sender_->TimeUntilSend(clock_.Now(), kBytesInFlight)
                    .ToMicroseconds());
    }
  }

  void UpdateRtt() {
    EXPECT_CALL(*mock_sender_,
                OnCongestionEvent(true, kBytesInFlight, _, _, _, _, _));
    AckedPacketVector empty_acked;
    LostPacketVector empty_lost;
    pacing_sender_->OnCongestionEvent(true, kBytesInFlight, clock_.Now(),
                                      empty_acked, empty_lost, 0, 0);
  }

  void OnApplicationLimited() { pacing_sender_->OnApplicationLimited(); }

  const QuicTime::Delta zero_time_;
  const QuicTime::Delta infinite_time_;
  MockClock clock_;
  QuicPacketNumber packet_number_;
  std::unique_ptr<StrictMock<MockSendAlgorithm>> mock_sender_;
  std::unique_ptr<TestPacingSender> pacing_sender_;
};

TEST_F(PacingSenderTest, NoSend) {
  for (int i = 0; i < 2; ++i) {
    EXPECT_CALL(*mock_sender_, CanSend(kBytesInFlight)).WillOnce(Return(false));
    EXPECT_EQ(infinite_time_,
              pacing_sender_->TimeUntilSend(clock_.Now(), kBytesInFlight));
  }
}

TEST_F(PacingSenderTest, SendNow) {
  for (int i = 0; i < 2; ++i) {
    EXPECT_CALL(*mock_sender_, CanSend(kBytesInFlight)).WillOnce(Return(true));
    EXPECT_EQ(zero_time_,
              pacing_sender_->TimeUntilSend(clock_.Now(), kBytesInFlight));
  }
}

TEST_F(PacingSenderTest, VariousSending) {
  // Configure pacing rate of 1 packet per 1 ms, no initial burst.
  InitPacingRate(
      0, QuicBandwidth::FromBytesAndTimeDelta(
             kMaxOutgoingPacketSize, QuicTime::Delta::FromMilliseconds(1)));

  // Now update the RTT and verify that packets are actually paced.
  UpdateRtt();

  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 2.
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  // Wake up on time.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(2));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  // Wake up late.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(4));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  // Wake up really late.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(8));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  // Wake up really late again, but application pause partway through.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(8));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  OnApplicationLimited();
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(100));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
  // Wake up early, but after enough time has passed to permit a send.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  CheckPacketIsSentImmediately();
}

TEST_F(PacingSenderTest, InitialBurst) {
  // Configure pacing rate of 1 packet per 1 ms.
  InitPacingRate(
      10, QuicBandwidth::FromBytesAndTimeDelta(
              kMaxOutgoingPacketSize, QuicTime::Delta::FromMilliseconds(1)));

  // Update the RTT and verify that the first 10 packets aren't paced.
  UpdateRtt();

  // Send 10 packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 2ms.
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));

  if (GetQuicReloadableFlag(quic_pacing_remove_non_initial_burst)) {
    // Can send some packets immediately to make up for 5ms of lost time.
    for (int i = 0; i < 6; ++i) {
      CheckPacketIsSentImmediately();
    }
    CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(3));
    return;
  }

  CheckPacketIsSentImmediately();
  // Next time TimeUntilSend is called with no bytes in flight, pacing should
  // allow a packet to be sent, and when it's sent, the tokens are refilled.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA, 0, false, 10);
  for (int i = 0; i < kInitialBurstPackets - 1; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 2ms.
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
}

TEST_F(PacingSenderTest, InitialBurstNoRttMeasurement) {
  // Configure pacing rate of 1 packet per 1 ms.
  InitPacingRate(
      10, QuicBandwidth::FromBytesAndTimeDelta(
              kMaxOutgoingPacketSize, QuicTime::Delta::FromMilliseconds(1)));

  // Send 10 packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 2ms.
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));

  if (GetQuicReloadableFlag(quic_pacing_remove_non_initial_burst)) {
    // Can send some packets immediately to make up for 5ms of lost time.
    for (int i = 0; i < 6; ++i) {
      CheckPacketIsSentImmediately();
    }
    CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(3));
    return;
  }

  CheckPacketIsSentImmediately();

  // Next time TimeUntilSend is called with no bytes in flight, the tokens
  // should be refilled and there should be no delay.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA, 0, false, 10);
  // Send 10 packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets - 1; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 2ms.
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
}

TEST_F(PacingSenderTest, FastSending) {
  // Ensure the pacing sender paces, even when the inter-packet spacing(0.5ms)
  // is less than the pacing granularity(1ms).
  InitPacingRate(10, QuicBandwidth::FromBytesAndTimeDelta(
                         2 * kMaxOutgoingPacketSize,
                         QuicTime::Delta::FromMilliseconds(1)));
  // Update the RTT and verify that the first 10 packets aren't paced.
  UpdateRtt();

  // Send 10 packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets; ++i) {
    CheckPacketIsSentImmediately();
  }

  CheckPacketIsSentImmediately();  // Make up
  CheckPacketIsSentImmediately();  // Lumpy token
  CheckPacketIsSentImmediately();  // "In the future" but within granularity.
  CheckPacketIsSentImmediately();  // Lumpy token
  CheckPacketIsDelayed(QuicTime::Delta::FromMicroseconds(2000));

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));

  if (GetQuicReloadableFlag(quic_pacing_remove_non_initial_burst)) {
    // Can send some packets immediately to make up for 5ms of lost time.
    for (int i = 0; i < 10; ++i) {
      CheckPacketIsSentImmediately();
    }
    CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
    return;
  }

  CheckPacketIsSentImmediately();

  // Next time TimeUntilSend is called with no bytes in flight, the tokens
  // should be refilled and there should be no delay.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA, 0, false, 10);
  for (int i = 0; i < kInitialBurstPackets - 1; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet was a "make up", then we sent two packets "into the
  // future", so the delay should be 1.5ms.
  CheckPacketIsSentImmediately();  // Make up
  CheckPacketIsSentImmediately();  // Lumpy token
  CheckPacketIsSentImmediately();  // "In the future" but within granularity.
  CheckPacketIsSentImmediately();  // Lumpy token
  CheckPacketIsDelayed(QuicTime::Delta::FromMicroseconds(2000));
}

TEST_F(PacingSenderTest, NoBurstEnteringRecovery) {
  // Configure pacing rate of 1 packet per 1 ms with no burst tokens.
  InitPacingRate(
      0, QuicBandwidth::FromBytesAndTimeDelta(
             kMaxOutgoingPacketSize, QuicTime::Delta::FromMilliseconds(1)));
  // Sending a packet will set burst tokens.
  CheckPacketIsSentImmediately();

  // Losing a packet will set clear burst tokens.
  LostPacketVector lost_packets;
  lost_packets.push_back(
      LostPacket(QuicPacketNumber(1), kMaxOutgoingPacketSize));
  AckedPacketVector empty_acked;
  EXPECT_CALL(*mock_sender_, OnCongestionEvent(true, kMaxOutgoingPacketSize, _,
                                               testing::IsEmpty(), _, _, _));
  pacing_sender_->OnCongestionEvent(true, kMaxOutgoingPacketSize, clock_.Now(),
                                    empty_acked, lost_packets, 0, 0);
  // One packet is sent immediately, because of 1ms pacing granularity.
  CheckPacketIsSentImmediately();
  // Ensure packets are immediately paced.
  EXPECT_CALL(*mock_sender_, CanSend(kMaxOutgoingPacketSize))
      .WillOnce(Return(true));
  // Verify the next packet is paced and delayed 2ms due to granularity.
  EXPECT_EQ(
      QuicTime::Delta::FromMilliseconds(2),
      pacing_sender_->TimeUntilSend(clock_.Now(), kMaxOutgoingPacketSize));
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
}

TEST_F(PacingSenderTest, NoBurstInRecovery) {
  // Configure pacing rate of 1 packet per 1 ms with no burst tokens.
  InitPacingRate(
      0, QuicBandwidth::FromBytesAndTimeDelta(
             kMaxOutgoingPacketSize, QuicTime::Delta::FromMilliseconds(1)));

  UpdateRtt();

  // Ensure only one packet is sent immediately and the rest are paced.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA, 0, true, 10);
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
}

TEST_F(PacingSenderTest, CwndLimited) {
  // Configure pacing rate of 1 packet per 1 ms, no initial burst.
  InitPacingRate(
      0, QuicBandwidth::FromBytesAndTimeDelta(
             kMaxOutgoingPacketSize, QuicTime::Delta::FromMilliseconds(1)));

  UpdateRtt();

  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  // Packet 3 will be delayed 2ms.
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));

  // Wake up on time.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(2));
  // After sending packet 3, cwnd is limited.
  // This test is slightly odd because bytes_in_flight is calculated using
  // kMaxOutgoingPacketSize and CWND is calculated using kDefaultTCPMSS,
  // which is 8 bytes larger, so 3 packets can be sent for a CWND of 2.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA,
                               2 * kMaxOutgoingPacketSize, false, 2);

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(100));
  // Verify pacing sender stops making up for lost time after sending packet 3.
  // Packet 6 will be delayed 2ms.
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
}

TEST_F(PacingSenderTest, LumpyPacingWithInitialBurstToken) {
  // Set lumpy size to be 3, and cwnd faction to 0.5
  SetQuicFlag(quic_lumpy_pacing_size, 3);
  SetQuicFlag(quic_lumpy_pacing_cwnd_fraction, 0.5f);
  // Configure pacing rate of 1 packet per 1 ms.
  InitPacingRate(
      10, QuicBandwidth::FromBytesAndTimeDelta(
              kMaxOutgoingPacketSize, QuicTime::Delta::FromMilliseconds(1)));
  UpdateRtt();

  // Send 10 packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets; ++i) {
    CheckPacketIsSentImmediately();
  }

  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  // Packet 14 will be delayed 3ms.
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(3));

  // Wake up on time.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  // Packet 17 will be delayed 3ms.
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(3));

  // Application throttles sending.
  OnApplicationLimited();
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(100));
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  CheckPacketIsSentImmediately();
  // Packet 20 will be delayed 3ms.
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(3));

  // Wake up on time.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(3));
  CheckPacketIsSentImmediately();
  // After sending packet 21, cwnd is limited.
  // This test is slightly odd because bytes_in_flight is calculated using
  // kMaxOutgoingPacketSize and CWND is calculated using kDefaultTCPMSS,
  // which is 8 bytes larger, so 21 packets can be sent for a CWND of 20.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA,
                               20 * kMaxOutgoingPacketSize, false, 20);

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(100));
  // Suppose cwnd size is 5, so that lumpy size becomes 2.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA, kBytesInFlight, false,
                               5);
  CheckPacketIsSentImmediately();
  // Packet 24 will be delayed 2ms.
  CheckPacketIsDelayed(QuicTime::Delta::FromMilliseconds(2));
}

TEST_F(PacingSenderTest, NoLumpyPacingForLowBandwidthFlows) {
  // Set lumpy size to be 3, and cwnd fraction to 0.5
  SetQuicFlag(quic_lumpy_pacing_size, 3);
  SetQuicFlag(quic_lumpy_pacing_cwnd_fraction, 0.5f);

  // Configure pacing rate of 1 packet per 100 ms.
  QuicTime::Delta inter_packet_delay = QuicTime::Delta::FromMilliseconds(100);
  InitPacingRate(kInitialBurstPackets,
                 QuicBandwidth::FromBytesAndTimeDelta(kMaxOutgoingPacketSize,
                                                      inter_packet_delay));
  UpdateRtt();

  // Send kInitialBurstPackets packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets; ++i) {
    CheckPacketIsSentImmediately();
  }

  // The first packet after burst token exhausted is also sent immediately,
  // because ideal_next_packet_send_time has not been set yet.
  CheckPacketIsSentImmediately();

  for (int i = 0; i < 200; ++i) {
    CheckPacketIsDelayed(inter_packet_delay);
  }
}

// Regression test for b/184471302 to ensure that ACKs received back-to-back
// don't cause bursts in sending.
TEST_F(PacingSenderTest, NoBurstsForLumpyPacingWithAckAggregation) {
  // Configure pacing rate of 1 packet per millisecond.
  QuicTime::Delta inter_packet_delay = QuicTime::Delta::FromMilliseconds(1);
  InitPacingRate(kInitialBurstPackets,
                 QuicBandwidth::FromBytesAndTimeDelta(kMaxOutgoingPacketSize,
                                                      inter_packet_delay));
  UpdateRtt();

  // Send kInitialBurstPackets packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets; ++i) {
    CheckPacketIsSentImmediately();
  }
  // The last packet of the burst causes the sender to be CWND limited.
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA,
                               10 * kMaxOutgoingPacketSize, false, 10);

  // The last sent packet made the connection CWND limited, so no lumpy tokens
  // should be available.
  EXPECT_EQ(0u, pacing_sender_->lumpy_tokens());
  CheckPacketIsSentImmediately(HAS_RETRANSMITTABLE_DATA,
                               10 * kMaxOutgoingPacketSize, false, 10);
  EXPECT_EQ(0u, pacing_sender_->lumpy_tokens());
  CheckPacketIsDelayed(2 * inter_packet_delay);
}

TEST_F(PacingSenderTest, IdealNextPacketSendTimeWithLumpyPacing) {
  // Set lumpy size to be 3, and cwnd faction to 0.5
  SetQuicFlag(quic_lumpy_pacing_size, 3);
  SetQuicFlag(quic_lumpy_pacing_cwnd_fraction, 0.5f);

  // Configure pacing rate of 1 packet per millisecond.
  QuicTime::Delta inter_packet_delay = QuicTime::Delta::FromMilliseconds(1);
  InitPacingRate(kInitialBurstPackets,
                 QuicBandwidth::FromBytesAndTimeDelta(kMaxOutgoingPacketSize,
                                                      inter_packet_delay));

  // Send kInitialBurstPackets packets, and verify that they are not paced.
  for (int i = 0; i < kInitialBurstPackets; ++i) {
    CheckPacketIsSentImmediately();
  }

  CheckPacketIsSentImmediately();
  EXPECT_EQ(pacing_sender_->ideal_next_packet_send_time(),
            clock_.Now() + inter_packet_delay);
  EXPECT_EQ(pacing_sender_->lumpy_tokens(), 2u);

  CheckPacketIsSentImmediately();
  EXPECT_EQ(pacing_sender_->ideal_next_packet_send_time(),
            clock_.Now() + 2 * inter_packet_delay);
  EXPECT_EQ(pacing_sender_->lumpy_tokens(), 1u);

  CheckPacketIsSentImmediately();
  EXPECT_EQ(pacing_sender_->ideal_next_packet_send_time(),
            clock_.Now() + 3 * inter_packet_delay);
  EXPECT_EQ(pacing_sender_->lumpy_tokens(), 0u);

  CheckPacketIsDelayed(3 * inter_packet_delay);

  // Wake up on time.
  clock_.AdvanceTime(3 * inter_packet_delay);
  CheckPacketIsSentImmediately();
  EXPECT_EQ(pacing_sender_->ideal_next_packet_send_time(),
            clock_.Now() + inter_packet_delay);
  EXPECT_EQ(pacing_sender_->lumpy_tokens(), 2u);

  CheckPacketIsSentImmediately();
  EXPECT_EQ(pacing_sender_->ideal_next_packet_send_time(),
            clock_.Now() + 2 * inter_packet_delay);
  EXPECT_EQ(pacing_sender_->lumpy_tokens(), 1u);

  CheckPacketIsSentImmediately();
  EXPECT_EQ(pacing_sender_->ideal_next_packet_send_time(),
            clock_.Now() + 3 * inter_packet_delay);
  EXPECT_EQ(pacing_sender_->lumpy_tokens(), 0u);

  CheckPacketIsDelayed(3 * inter_packet_delay);

  // Wake up late.
  clock_.AdvanceTime(4.5 * inter_packet_delay);
  CheckPacketIsSentImmediately();
  EXPECT_EQ(pacing_sender_->ideal_next_packet_send_time(),
            clock_.Now() - 0.5 * inter_packet_delay);
  EXPECT_EQ(pacing_sender_->lumpy_tokens(), 2u);

  CheckPacketIsSentImmediately();
  EXPECT_EQ(pacing_sender_->ideal_next_packet_send_time(),
            clock_.Now() + 0.5 * inter_packet_delay);
  EXPECT_EQ(pacing_sender_->lumpy_tokens(), 1u);

  CheckPacketIsSentImmediately();
  EXPECT_EQ(pacing_sender_->ideal_next_packet_send_time(),
            clock_.Now() + 1.5 * inter_packet_delay);
  EXPECT_EQ(pacing_sender_->lumpy_tokens(), 0u);

  CheckPacketIsDelayed(1.5 * inter_packet_delay);
}

}  // namespace test
}  // namespace quic

"""

```