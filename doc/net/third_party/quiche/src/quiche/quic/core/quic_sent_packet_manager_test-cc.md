Response:
My goal is to analyze the provided C++ code snippet and extract its functionality, relate it to JavaScript if possible, discuss logical reasoning with examples, point out common user errors, and describe how a user might reach this code during debugging. Since this is part 1 of 5, I also need to summarize the core functionality revealed in this part.

Here's a breakdown of the thinking process:

1. **Identify the Core Class:** The code clearly revolves around `QuicSentPacketManagerTest`. The name suggests it's a unit test suite for the `QuicSentPacketManager` class.

2. **Analyze Includes:** The included headers provide valuable clues:
    * `quiche/quic/core/quic_sent_packet_manager.h`:  This confirms the main class being tested.
    * Various `<algorithm>`, `<memory>`, etc.: Standard C++ library components.
    * `quiche/quic/core/frames/...`: Indicates interaction with different QUIC frame types (ACK, ACK Frequency).
    * `quiche/quic/core/...`:  Points to core QUIC concepts like packet numbers, time, types.
    * `quiche/quic/platform/api/...`:  Testing and platform-specific abstractions.
    * `quiche/quic/test_tools/...`:  Helper classes for testing `QuicSentPacketManager`.
    * `quiche/common/platform/api/...`: Common utilities.

3. **Examine the Test Fixture (`QuicSentPacketManagerTest`):**
    * **Member Variables:**
        * `manager_`:  The instance of `QuicSentPacketManager` being tested.
        * `clock_`: A mock clock for controlling time in tests.
        * `stats_`:  Connection statistics.
        * `send_algorithm_`: A mock of the congestion control algorithm. This is crucial – the test needs to isolate `QuicSentPacketManager`'s logic.
        * `network_change_visitor_`: A mock for handling network changes.
        * `notifier_`: A mock session notifier, likely responsible for callbacks to the QUIC session.
    * **Helper Methods:**  These are key to understanding the test setup and actions:
        * `RetransmitCryptoPacket`, `RetransmitDataPacket`: Simulate retransmitting packets. Notice the `EXPECT_CALL` which sets up expectations for mock object interactions.
        * `BytesInFlight`: Accessor for bytes in flight.
        * `VerifyUnackedPackets`, `VerifyRetransmittablePackets`:  Assertions to check the state of unacknowledged and retransmittable packets.
        * `ExpectAck`, `ExpectUpdatedRtt`, `ExpectAckAndLoss`, `ExpectAcksAndLosses`:  Set expectations for congestion control algorithm calls based on acknowledgments and losses.
        * `RetransmitAndSendPacket`: Simulates a retransmission and sending of a new packet.
        * `CreateDataPacket`, `CreatePacket`, `CreatePingPacket`: Create different types of test packets.
        * `SendDataPacket`, `SendPingPacket`, `SendCryptoPacket`, `SendAckPacket`: Simulate sending various packet types, including setting up mock expectations.

4. **Analyze Individual Tests:**  While the prompt only asks for the functionality of the *file* (specifically part 1), looking at the initial tests provides concrete examples of what aspects are being tested:
    * `IsUnacked`: Checks if a sent packet is considered unacknowledged.
    * `IsUnAckedRetransmit`: Checks the state of retransmitted packets.
    * `RetransmitThenAck`: Tests the scenario where a retransmitted packet is acknowledged.
    * `RetransmitThenAckBeforeSend`: Tests acknowledgement before a retransmitted packet is sent.
    * `RetransmitThenStopRetransmittingBeforeSend`: Tests stopping a retransmission before sending.
    * `RetransmitThenAckPrevious`: Tests acknowledging the original transmission after a retransmission.
    * `RetransmitThenAckPreviousThenNackRetransmit`: A more complex scenario with acknowledgements and negative acknowledgements (implicitly).
    * The names of the tests provide strong hints about the functionality being verified.

5. **Relate to JavaScript:** Consider how the concepts being tested map to JavaScript in a networking context. While JavaScript doesn't directly handle the low-level details of QUIC, the *concepts* are relevant:
    * **Reliable Delivery:**  Ensuring data reaches the recipient. This is what `QuicSentPacketManager` helps with. In JS, you might use WebSockets or Fetch API, which handle reliability at a higher level, but the underlying principles are similar.
    * **Congestion Control:** Avoiding overwhelming the network. JavaScript developers don't typically implement congestion control directly, but they might be aware of its effects (e.g., slower network speeds during congestion).
    * **Packet Loss and Retransmission:**  Dealing with lost data. JavaScript libraries handle this automatically.
    * **Acknowledgements:** Confirming data receipt. Implicit in reliable protocols used by JavaScript.

6. **Logical Reasoning Examples:** Choose a test case and illustrate the input, the actions taken by the test, and the expected output based on the code and mock expectations. For example, the `RetransmitThenAck` test clearly shows a send, a retransmit, and then an acknowledgement of the retransmitted packet.

7. **Common User Errors:** Think about what mistakes a developer using the `QuicSentPacketManager` (or a similar networking component) might make. Examples include improper handling of acknowledgements, incorrect retransmission logic, or misunderstanding the impact of packet loss.

8. **Debugging Scenario:**  Imagine a situation where a network connection is unreliable. Describe how a developer might step through the code in `quic_sent_packet_manager_test.cc` or the actual `quic_sent_packet_manager.cc` to understand the packet sending and acknowledgement process.

9. **Summarize Part 1 Functionality:** Based on the analyzed code and the focus of the initial tests, synthesize a concise description of what this part of the test file covers. The emphasis should be on basic packet sending, acknowledgement, and retransmission scenarios.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus too much on individual lines of code.
* **Correction:** Shift focus to the higher-level purpose of the test fixture and the individual tests. The test names are very informative.
* **Initial thought:** Overcomplicate the JavaScript relationship.
* **Correction:** Keep the JavaScript analogies high-level, focusing on the underlying networking concepts rather than trying to find direct code equivalents.
* **Initial thought:**  Only describe what the code *does*.
* **Correction:** Include the *why* – why are these tests being written? What aspects of `QuicSentPacketManager`'s behavior are being validated?

By following these steps and incorporating self-correction, I can arrive at a comprehensive and accurate analysis of the provided code snippet, fulfilling all the requirements of the prompt.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager_test.cc` 文件的第一部分。这个文件包含了对 `QuicSentPacketManager` 类的单元测试。`QuicSentPacketManager` 是 QUIC 协议核心组件之一，负责管理已发送的数据包，包括跟踪哪些包已被确认，哪些包需要重传，以及执行拥塞控制等。

**它的主要功能可以归纳为测试 `QuicSentPacketManager` 的以下方面：**

1. **跟踪未确认的数据包 (Unacked Packets):**  测试 `QuicSentPacketManager` 是否能正确记录和查询哪些数据包尚未被对端确认接收。
2. **管理可重传的数据包 (Retransmittable Packets):** 测试 `QuicSentPacketManager` 是否能正确标记包含需要可靠传输的数据（例如流数据、控制帧）的数据包，并在需要时进行重传。
3. **处理确认帧 (ACK Frames):** 测试当收到对端发来的 ACK 帧时，`QuicSentPacketManager` 是否能正确更新已确认的数据包状态，并触发相应的拥塞控制事件。
4. **处理重传 (Retransmission):** 测试 `QuicSentPacketManager` 在各种情况下（例如超时、收到 NACK）是否能正确发起数据包重传，并更新相关状态。
5. **处理乱序确认和丢失检测 (Out-of-order ACK and Loss Detection):** 虽然这部分可能在后续部分更深入，但本部分已经开始涉及处理重传后收到对原始包的确认的情况，以及通过 NACK 等机制进行简单的丢失检测。
6. **与拥塞控制算法的交互 (Interaction with Congestion Control Algorithm):** 测试 `QuicSentPacketManager` 在发送数据包、接收 ACK 以及检测到丢包时，是否能正确调用 `SendAlgorithm` 接口，通知拥塞控制算法进行相应的调整。
7. **与会话通知器的交互 (Interaction with Session Notifier):** 测试 `QuicSentPacketManager` 是否能通知会话层关于帧的重传和丢失事件。
8. **统计信息收集 (Statistics Collection):** 测试 `QuicSentPacketManager` 是否能收集和更新诸如重传次数、丢包次数等统计信息。
9. **处理 Early Retransmission:** 测试在某些情况下，过早的重传被识别为虚假重传的情况。
10. **获取最小未确认的包 (Get Least Unacked):** 测试获取当前最小的未被确认的数据包编号。
11. **更新 RTT (Round Trip Time):** 测试根据收到的 ACK 帧中的延迟信息来更新 RTT 估算。

**与 JavaScript 的功能关系：**

QUIC 协议最终服务于应用层的数据传输，而 JavaScript 作为客户端（例如浏览器）和服务端（例如 Node.js）的常见编程语言，会通过各种 API 与底层的网络协议栈交互。

* **高层抽象:** JavaScript 本身并不直接操作 QUIC 数据包的管理和重传逻辑。它通常使用更高级别的 API，如 Fetch API 或 WebSockets，这些 API 底层可能会使用 QUIC（在支持的浏览器和环境下）。
* **功能映射 (概念上):**
    * **可靠性 (Reliability):** JavaScript 应用期望数据可靠传输。`QuicSentPacketManager` 保证了 QUIC 连接的可靠性，这使得 JavaScript 应用无需关心底层的丢包和重传。例如，当你在 JavaScript 中使用 `fetch()` 下载一个大文件时，即使网络出现短暂的丢包，QUIC 也能在底层处理重传，保证 JavaScript 接收到完整的数据。
    * **性能 (Performance):** `QuicSentPacketManager` 的拥塞控制和重传机制直接影响 QUIC 连接的性能。更高效的拥塞控制和更智能的重传策略可以减少延迟，提高 JavaScript 应用的网络体验。例如，快速重传机制可以避免因超时而导致的长时间等待，从而提升 JavaScript 应用的响应速度。
    * **加密 (Encryption):** QUIC 协议强制加密，`QuicSentPacketManager` 参与管理加密上下文。这保证了 JavaScript 应用通过 QUIC 发送的数据的安全性。

**举例说明 (假设场景):**

假设一个 JavaScript 应用使用 Fetch API 通过 HTTPS (底层使用 QUIC) 向服务器请求数据：

1. **用户操作:** 用户在浏览器中点击一个按钮，触发 JavaScript 代码使用 `fetch('/data')` 发起网络请求。
2. **到达 `QuicSentPacketManager` 的路径:**
   * JavaScript 的 `fetch()` 调用会经过浏览器网络栈的 HTTP/3 实现。
   * HTTP/3 会将请求数据封装成 QUIC 数据包。
   * 这些数据包会交给 `QuicSentPacketManager` 进行管理。
3. **`QuicSentPacketManager` 的操作:**
   * **假设输入:**  `QuicSentPacketManager` 接收到一个包含 HTTP 请求数据的 `SerializedPacket`，包编号为 1，包含需要可靠传输的数据。
   * **逻辑推理:** `QuicSentPacketManager` 会将包 1 标记为已发送且需要确认。它会调用 `send_algorithm_->OnPacketSent(...)` 通知拥塞控制算法。
   * **假设输出:** 包 1 被发送出去，`manager_.unacked_packets()` 中会记录包 1 的信息。
4. **后续情况:**
   * **假设输入:** 一段时间后，`QuicSentPacketManager` 收到一个 ACK 帧，确认接收到包 1。
   * **逻辑推理:** `QuicSentPacketManager` 会更新包 1 的状态为已确认，并调用 `send_algorithm_->OnCongestionEvent(...)` 通知拥塞控制算法。
   * **假设输出:** 包 1 从 `manager_.unacked_packets()` 中移除。
   * **假设输入:**  如果一段时间后没有收到 ACK，且超过了重传超时时间。
   * **逻辑推理:** `QuicSentPacketManager` 会将包 1 标记为需要重传，并调用相应的重传机制。
   * **假设输出:**  包 1 的数据会被重新发送。

**用户或编程常见的使用错误 (虽然用户不直接操作 `QuicSentPacketManager`):**

* **网络配置错误:**  用户的网络环境可能存在问题，例如防火墙阻止 QUIC 连接，导致数据包无法正常发送或接收，从而触发 `QuicSentPacketManager` 的重传机制。
* **服务端问题:**  服务端可能没有正确响应或发送 ACK，导致客户端的 `QuicSentPacketManager` 一直等待确认，最终可能触发超时重传甚至连接断开。
* **QUIC 实现错误 (开发者角度):**  如果 `QuicSentPacketManager` 的实现存在 bug，例如在特定情况下未能正确处理 ACK 或重传，会导致数据传输失败或性能下降。这个测试文件就是为了防止这类错误。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户遇到网络问题:** 用户在使用基于 Chromium 的浏览器访问某个网站时，发现网页加载缓慢或部分内容加载不出来。
2. **开发者介入:**  开发者开始排查问题，怀疑是底层的网络连接出现了问题。
3. **抓包分析:** 开发者可能会使用 Wireshark 等工具抓取网络包，分析 QUIC 连接的交互过程，例如查看是否有大量的重传，ACK 是否及时等。
4. **查看 Chromium 内部日志:** Chromium 浏览器和内核会记录详细的 QUIC 连接日志。开发者可以查看这些日志，了解 `QuicSentPacketManager` 的状态，例如哪些包被发送、哪些被确认、哪些被重传。
5. **源码调试 (高级):**  如果开发者需要深入了解问题，可能会下载 Chromium 源码，并在调试模式下运行浏览器，设置断点在 `QuicSentPacketManager` 的相关代码中，例如 `OnPacketSent`、`OnAckFrameEnd` 等函数，来跟踪数据包的管理和确认流程。这个测试文件中的测试用例可以帮助开发者理解这些函数的行为和逻辑。

**归纳一下它的功能 (第 1 部分):**

这部分测试文件主要关注 `QuicSentPacketManager` 的基础功能，包括：

* **数据包的发送和跟踪:** 验证了 `QuicSentPacketManager` 能否正确记录已发送但未确认的数据包。
* **基本的确认处理:** 测试了收到 ACK 帧后，`QuicSentPacketManager` 能否正确更新数据包状态并通知拥塞控制算法。
* **简单的重传场景:**  验证了在一些基本情况下，例如发送后等待确认超时，`QuicSentPacketManager` 能否触发重传。
* **与拥塞控制和会话通知器的初步交互:**  测试了 `QuicSentPacketManager` 在发送和接收确认时，与 `SendAlgorithm` 和 `SessionNotifier` 的基本交互。

总而言之，这部分测试是构建一个可靠的 `QuicSentPacketManager` 的基础，确保了其核心的数据包管理和确认机制的正确性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_sent_packet_manager_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_sent_packet_manager.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/frames/quic_ack_frame.h"
#include "quiche/quic/core/frames/quic_ack_frequency_frame.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_sent_packet_manager_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"

using testing::_;
using testing::AnyNumber;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::IsEmpty;
using testing::Not;
using testing::Pointwise;
using testing::Return;
using testing::StrictMock;
using testing::WithArgs;

namespace quic {
namespace test {
namespace {
// Default packet length.
const uint32_t kDefaultLength = 1000;

// Stream ID for data sent in CreatePacket().
const QuicStreamId kStreamId = 7;

// The compiler won't allow std::nullopt as an argument.
const std::optional<QuicEcnCounts> kEmptyCounts = std::nullopt;

// Matcher to check that the packet number matches the second argument.
MATCHER(PacketNumberEq, "") {
  return std::get<0>(arg).packet_number == QuicPacketNumber(std::get<1>(arg));
}

class MockDebugDelegate : public QuicSentPacketManager::DebugDelegate {
 public:
  MOCK_METHOD(void, OnSpuriousPacketRetransmission,
              (TransmissionType transmission_type, QuicByteCount byte_size),
              (override));
  MOCK_METHOD(void, OnPacketLoss,
              (QuicPacketNumber lost_packet_number,
               EncryptionLevel encryption_level,
               TransmissionType transmission_type, QuicTime detection_time),
              (override));
  MOCK_METHOD(void, OnIncomingAck,
              (QuicPacketNumber ack_packet_number,
               EncryptionLevel ack_decrypted_level,
               const QuicAckFrame& ack_frame, QuicTime ack_receive_time,
               QuicPacketNumber largest_observed, bool rtt_updated,
               QuicPacketNumber least_unacked_sent_packet),
              (override));
};

class QuicSentPacketManagerTest : public QuicTest {
 public:
  bool RetransmitCryptoPacket(uint64_t packet_number) {
    EXPECT_CALL(
        *send_algorithm_,
        OnPacketSent(_, BytesInFlight(), QuicPacketNumber(packet_number),
                     kDefaultLength, HAS_RETRANSMITTABLE_DATA));
    SerializedPacket packet(CreatePacket(packet_number, false));
    packet.retransmittable_frames.push_back(
        QuicFrame(QuicStreamFrame(1, false, 0, absl::string_view())));
    packet.has_crypto_handshake = IS_HANDSHAKE;
    manager_.OnPacketSent(&packet, clock_.Now(), HANDSHAKE_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA, true, ECN_NOT_ECT);
    return true;
  }

  bool RetransmitDataPacket(uint64_t packet_number, TransmissionType type,
                            EncryptionLevel level) {
    EXPECT_CALL(
        *send_algorithm_,
        OnPacketSent(_, BytesInFlight(), QuicPacketNumber(packet_number),
                     kDefaultLength, HAS_RETRANSMITTABLE_DATA));
    SerializedPacket packet(CreatePacket(packet_number, true));
    packet.encryption_level = level;
    manager_.OnPacketSent(&packet, clock_.Now(), type, HAS_RETRANSMITTABLE_DATA,
                          true, ECN_NOT_ECT);
    return true;
  }

  bool RetransmitDataPacket(uint64_t packet_number, TransmissionType type) {
    return RetransmitDataPacket(packet_number, type, ENCRYPTION_INITIAL);
  }

 protected:
  const CongestionControlType kInitialCongestionControlType = kCubicBytes;
  QuicSentPacketManagerTest()
      : manager_(Perspective::IS_SERVER, &clock_, QuicRandom::GetInstance(),
                 &stats_, kInitialCongestionControlType),
        send_algorithm_(new StrictMock<MockSendAlgorithm>),
        network_change_visitor_(new StrictMock<MockNetworkChangeVisitor>) {
    QuicSentPacketManagerPeer::SetSendAlgorithm(&manager_, send_algorithm_);
    // Advance the time 1s so the send times are never QuicTime::Zero.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1000));
    manager_.SetNetworkChangeVisitor(network_change_visitor_.get());
    manager_.SetSessionNotifier(&notifier_);

    EXPECT_CALL(*send_algorithm_, GetCongestionControlType())
        .WillRepeatedly(Return(kInitialCongestionControlType));
    EXPECT_CALL(*send_algorithm_, BandwidthEstimate())
        .Times(AnyNumber())
        .WillRepeatedly(Return(QuicBandwidth::Zero()));
    EXPECT_CALL(*send_algorithm_, InSlowStart()).Times(AnyNumber());
    EXPECT_CALL(*send_algorithm_, InRecovery()).Times(AnyNumber());
    EXPECT_CALL(*send_algorithm_, OnPacketNeutered(_)).Times(AnyNumber());
    EXPECT_CALL(*network_change_visitor_, OnPathMtuIncreased(1000))
        .Times(AnyNumber());
    EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(notifier_, HasUnackedCryptoData())
        .WillRepeatedly(Return(false));
    EXPECT_CALL(notifier_, OnStreamFrameRetransmitted(_)).Times(AnyNumber());
    EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).WillRepeatedly(Return(true));
  }

  ~QuicSentPacketManagerTest() override {}

  QuicByteCount BytesInFlight() { return manager_.GetBytesInFlight(); }
  void VerifyUnackedPackets(uint64_t* packets, size_t num_packets) {
    if (num_packets == 0) {
      EXPECT_TRUE(manager_.unacked_packets().empty());
      EXPECT_EQ(0u, QuicSentPacketManagerPeer::GetNumRetransmittablePackets(
                        &manager_));
      return;
    }

    EXPECT_FALSE(manager_.unacked_packets().empty());
    EXPECT_EQ(QuicPacketNumber(packets[0]), manager_.GetLeastUnacked());
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(
          manager_.unacked_packets().IsUnacked(QuicPacketNumber(packets[i])))
          << packets[i];
    }
  }

  void VerifyRetransmittablePackets(uint64_t* packets, size_t num_packets) {
    EXPECT_EQ(
        num_packets,
        QuicSentPacketManagerPeer::GetNumRetransmittablePackets(&manager_));
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(QuicSentPacketManagerPeer::HasRetransmittableFrames(
          &manager_, packets[i]))
          << " packets[" << i << "]:" << packets[i];
    }
  }

  void ExpectAck(uint64_t largest_observed) {
    EXPECT_CALL(
        *send_algorithm_,
        // Ensure the AckedPacketVector argument contains largest_observed.
        OnCongestionEvent(true, _, _,
                          Pointwise(PacketNumberEq(), {largest_observed}),
                          IsEmpty(), _, _));
    EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  }

  void ExpectUpdatedRtt(uint64_t /*largest_observed*/) {
    EXPECT_CALL(*send_algorithm_,
                OnCongestionEvent(true, _, _, IsEmpty(), IsEmpty(), _, _));
    EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  }

  void ExpectAckAndLoss(bool rtt_updated, uint64_t largest_observed,
                        uint64_t lost_packet) {
    EXPECT_CALL(
        *send_algorithm_,
        OnCongestionEvent(rtt_updated, _, _,
                          Pointwise(PacketNumberEq(), {largest_observed}),
                          Pointwise(PacketNumberEq(), {lost_packet}), _, _));
    EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  }

  // |packets_acked| and |packets_lost| should be in packet number order.
  void ExpectAcksAndLosses(bool rtt_updated, uint64_t* packets_acked,
                           size_t num_packets_acked, uint64_t* packets_lost,
                           size_t num_packets_lost) {
    std::vector<QuicPacketNumber> ack_vector;
    for (size_t i = 0; i < num_packets_acked; ++i) {
      ack_vector.push_back(QuicPacketNumber(packets_acked[i]));
    }
    std::vector<QuicPacketNumber> lost_vector;
    for (size_t i = 0; i < num_packets_lost; ++i) {
      lost_vector.push_back(QuicPacketNumber(packets_lost[i]));
    }
    EXPECT_CALL(*send_algorithm_,
                OnCongestionEvent(
                    rtt_updated, _, _, Pointwise(PacketNumberEq(), ack_vector),
                    Pointwise(PacketNumberEq(), lost_vector), _, _));
    EXPECT_CALL(*network_change_visitor_, OnCongestionChange())
        .Times(AnyNumber());
  }

  void RetransmitAndSendPacket(uint64_t old_packet_number,
                               uint64_t new_packet_number) {
    RetransmitAndSendPacket(old_packet_number, new_packet_number,
                            PTO_RETRANSMISSION);
  }

  void RetransmitAndSendPacket(uint64_t old_packet_number,
                               uint64_t new_packet_number,
                               TransmissionType transmission_type) {
    bool is_lost = false;
    if (transmission_type == HANDSHAKE_RETRANSMISSION ||
        transmission_type == PTO_RETRANSMISSION) {
      EXPECT_CALL(notifier_, RetransmitFrames(_, _))
          .WillOnce(WithArgs<1>(
              Invoke([this, new_packet_number](TransmissionType type) {
                return RetransmitDataPacket(new_packet_number, type);
              })));
    } else {
      EXPECT_CALL(notifier_, OnFrameLost(_)).Times(1);
      is_lost = true;
    }
    QuicSentPacketManagerPeer::MarkForRetransmission(
        &manager_, old_packet_number, transmission_type);
    if (!is_lost) {
      return;
    }
    EXPECT_CALL(
        *send_algorithm_,
        OnPacketSent(_, BytesInFlight(), QuicPacketNumber(new_packet_number),
                     kDefaultLength, HAS_RETRANSMITTABLE_DATA));
    SerializedPacket packet(CreatePacket(new_packet_number, true));
    manager_.OnPacketSent(&packet, clock_.Now(), transmission_type,
                          HAS_RETRANSMITTABLE_DATA, true, ECN_NOT_ECT);
  }

  SerializedPacket CreateDataPacket(uint64_t packet_number) {
    return CreatePacket(packet_number, true);
  }

  SerializedPacket CreatePacket(uint64_t packet_number, bool retransmittable) {
    SerializedPacket packet(QuicPacketNumber(packet_number),
                            PACKET_4BYTE_PACKET_NUMBER, nullptr, kDefaultLength,
                            false, false);
    if (retransmittable) {
      packet.retransmittable_frames.push_back(
          QuicFrame(QuicStreamFrame(kStreamId, false, 0, absl::string_view())));
    }
    return packet;
  }

  SerializedPacket CreatePingPacket(uint64_t packet_number) {
    SerializedPacket packet(QuicPacketNumber(packet_number),
                            PACKET_4BYTE_PACKET_NUMBER, nullptr, kDefaultLength,
                            false, false);
    packet.retransmittable_frames.push_back(QuicFrame(QuicPingFrame()));
    return packet;
  }

  void SendDataPacket(uint64_t packet_number) {
    SendDataPacket(packet_number, ENCRYPTION_INITIAL, ECN_NOT_ECT);
  }

  void SendDataPacket(uint64_t packet_number,
                      EncryptionLevel encryption_level) {
    SendDataPacket(packet_number, encryption_level, ECN_NOT_ECT);
  }

  void SendDataPacket(uint64_t packet_number, EncryptionLevel encryption_level,
                      QuicEcnCodepoint ecn_codepoint) {
    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, BytesInFlight(),
                             QuicPacketNumber(packet_number), _, _));
    SerializedPacket packet(CreateDataPacket(packet_number));
    packet.encryption_level = encryption_level;
    manager_.OnPacketSent(&packet, clock_.Now(), NOT_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA, true, ecn_codepoint);
  }

  void SendPingPacket(uint64_t packet_number,
                      EncryptionLevel encryption_level) {
    EXPECT_CALL(*send_algorithm_,
                OnPacketSent(_, BytesInFlight(),
                             QuicPacketNumber(packet_number), _, _));
    SerializedPacket packet(CreatePingPacket(packet_number));
    packet.encryption_level = encryption_level;
    manager_.OnPacketSent(&packet, clock_.Now(), NOT_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA, true, ECN_NOT_ECT);
  }

  void SendCryptoPacket(uint64_t packet_number) {
    EXPECT_CALL(
        *send_algorithm_,
        OnPacketSent(_, BytesInFlight(), QuicPacketNumber(packet_number),
                     kDefaultLength, HAS_RETRANSMITTABLE_DATA));
    SerializedPacket packet(CreatePacket(packet_number, false));
    packet.retransmittable_frames.push_back(
        QuicFrame(QuicStreamFrame(1, false, 0, absl::string_view())));
    packet.has_crypto_handshake = IS_HANDSHAKE;
    manager_.OnPacketSent(&packet, clock_.Now(), NOT_RETRANSMISSION,
                          HAS_RETRANSMITTABLE_DATA, true, ECN_NOT_ECT);
    EXPECT_CALL(notifier_, HasUnackedCryptoData()).WillRepeatedly(Return(true));
  }

  void SendAckPacket(uint64_t packet_number, uint64_t largest_acked) {
    SendAckPacket(packet_number, largest_acked, ENCRYPTION_INITIAL);
  }

  void SendAckPacket(uint64_t packet_number, uint64_t largest_acked,
                     EncryptionLevel level) {
    EXPECT_CALL(
        *send_algorithm_,
        OnPacketSent(_, BytesInFlight(), QuicPacketNumber(packet_number),
                     kDefaultLength, NO_RETRANSMITTABLE_DATA));
    SerializedPacket packet(CreatePacket(packet_number, false));
    packet.largest_acked = QuicPacketNumber(largest_acked);
    packet.encryption_level = level;
    manager_.OnPacketSent(&packet, clock_.Now(), NOT_RETRANSMISSION,
                          NO_RETRANSMITTABLE_DATA, true, ECN_NOT_ECT);
  }

  quiche::SimpleBufferAllocator allocator_;
  QuicSentPacketManager manager_;
  MockClock clock_;
  QuicConnectionStats stats_;
  MockSendAlgorithm* send_algorithm_;
  std::unique_ptr<MockNetworkChangeVisitor> network_change_visitor_;
  StrictMock<MockSessionNotifier> notifier_;
};

TEST_F(QuicSentPacketManagerTest, IsUnacked) {
  VerifyUnackedPackets(nullptr, 0);
  SendDataPacket(1);

  uint64_t unacked[] = {1};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  uint64_t retransmittable[] = {1};
  VerifyRetransmittablePackets(retransmittable,
                               ABSL_ARRAYSIZE(retransmittable));
}

TEST_F(QuicSentPacketManagerTest, IsUnAckedRetransmit) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);

  EXPECT_TRUE(QuicSentPacketManagerPeer::IsRetransmission(&manager_, 2));
  uint64_t unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  std::vector<uint64_t> retransmittable = {1, 2};
  VerifyRetransmittablePackets(&retransmittable[0], retransmittable.size());
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAck) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);

  // Ack 2 but not 1.
  ExpectAck(2);
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(2), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  // Packet 1 is unacked, pending, but not retransmittable.
  uint64_t unacked[] = {1};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  EXPECT_TRUE(manager_.HasInFlightPackets());
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAckBeforeSend) {
  SendDataPacket(1);
  EXPECT_CALL(notifier_, RetransmitFrames(_, _))
      .WillOnce(WithArgs<1>(Invoke([this](TransmissionType type) {
        return RetransmitDataPacket(2, type);
      })));
  QuicSentPacketManagerPeer::MarkForRetransmission(&manager_, 1,
                                                   PTO_RETRANSMISSION);
  // Ack 1.
  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  uint64_t unacked[] = {2};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  // We do not know packet 2 is a spurious retransmission until it gets acked.
  VerifyRetransmittablePackets(nullptr, 0);
  EXPECT_EQ(0u, stats_.packets_spuriously_retransmitted);
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenStopRetransmittingBeforeSend) {
  SendDataPacket(1);
  EXPECT_CALL(notifier_, RetransmitFrames(_, _)).WillRepeatedly(Return(true));
  QuicSentPacketManagerPeer::MarkForRetransmission(&manager_, 1,
                                                   PTO_RETRANSMISSION);

  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));

  uint64_t unacked[] = {1};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);
  EXPECT_EQ(0u, stats_.packets_spuriously_retransmitted);
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAckPrevious) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(15);
  clock_.AdvanceTime(rtt);

  // Ack 1 but not 2.
  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  // 2 remains unacked, but no packets have retransmittable data.
  uint64_t unacked[] = {2};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  EXPECT_TRUE(manager_.HasInFlightPackets());
  VerifyRetransmittablePackets(nullptr, 0);
  // Ack 2 causes 2 be considered as spurious retransmission.
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).WillOnce(Return(false));
  ExpectAck(2);
  manager_.OnAckFrameStart(QuicPacketNumber(2), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  EXPECT_EQ(1u, stats_.packets_spuriously_retransmitted);
}

TEST_F(QuicSentPacketManagerTest, RetransmitThenAckPreviousThenNackRetransmit) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(15);
  clock_.AdvanceTime(rtt);

  // First, ACK packet 1 which makes packet 2 non-retransmittable.
  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  SendDataPacket(3);
  SendDataPacket(4);
  SendDataPacket(5);
  clock_.AdvanceTime(rtt);

  // Next, NACK packet 2 three times.
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  EXPECT_CALL(notifier_, OnFrameLost(_)).Times(1);
  ExpectAckAndLoss(true, 3, 2);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(4));
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  ExpectAck(4);
  manager_.OnAckFrameStart(QuicPacketNumber(4), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(5));
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(3),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  ExpectAck(5);
  manager_.OnAckFrameStart(QuicPacketNumber(5), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(6));
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(4),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  uint64_t unacked[] = {2};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  EXPECT_FALSE(manager_.HasInFlightPackets());
  VerifyRetransmittablePackets(nullptr, 0);

  // Verify that the retransmission alarm would not fire,
  // since there is no retransmittable data outstanding.
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest,
       DISABLED_RetransmitTwiceThenAckPreviousBeforeSend) {
  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);

  // Fire the RTO, which will mark 2 for retransmission (but will not send it).
  EXPECT_CALL(*send_algorithm_, OnRetransmissionTimeout(true));
  EXPECT_CALL(*network_change_visitor_, OnCongestionChange());
  manager_.OnRetransmissionTimeout();

  // Ack 1 but not 2, before 2 is able to be sent.
  // Since 1 has been retransmitted, it has already been lost, and so the
  // send algorithm is not informed that it has been ACK'd.
  ExpectUpdatedRtt(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  // Since 2 was marked for retransmit, when 1 is acked, 2 is kept for RTT.
  uint64_t unacked[] = {2};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  EXPECT_FALSE(manager_.HasInFlightPackets());
  VerifyRetransmittablePackets(nullptr, 0);

  // Verify that the retransmission alarm would not fire,
  // since there is no retransmittable data outstanding.
  EXPECT_EQ(QuicTime::Zero(), manager_.GetRetransmissionTime());
}

TEST_F(QuicSentPacketManagerTest, RetransmitTwiceThenAckFirst) {
  StrictMock<MockDebugDelegate> debug_delegate;
  EXPECT_CALL(debug_delegate, OnSpuriousPacketRetransmission(PTO_RETRANSMISSION,
                                                             kDefaultLength))
      .Times(1);
  manager_.SetDebugDelegate(&debug_delegate);

  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);
  RetransmitAndSendPacket(2, 3);
  QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(15);
  clock_.AdvanceTime(rtt);

  // Ack 1 but not 2 or 3.
  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_CALL(debug_delegate, OnIncomingAck(_, _, _, _, _, _, _)).Times(1);
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  // Frames in packets 2 and 3 are acked.
  EXPECT_CALL(notifier_, IsFrameOutstanding(_))
      .Times(2)
      .WillRepeatedly(Return(false));

  // 2 and 3 remain unacked, but no packets have retransmittable data.
  uint64_t unacked[] = {2, 3};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  EXPECT_TRUE(manager_.HasInFlightPackets());
  VerifyRetransmittablePackets(nullptr, 0);

  // Ensure packet 2 is lost when 4 is sent and 3 and 4 are acked.
  SendDataPacket(4);
  // No new data gets acked in packet 3.
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _))
      .WillOnce(Return(false))
      .WillRepeatedly(Return(true));
  uint64_t acked[] = {3, 4};
  ExpectAcksAndLosses(true, acked, ABSL_ARRAYSIZE(acked), nullptr, 0);
  manager_.OnAckFrameStart(QuicPacketNumber(4), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(5));
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_CALL(debug_delegate, OnIncomingAck(_, _, _, _, _, _, _)).Times(1);
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  uint64_t unacked2[] = {2};
  VerifyUnackedPackets(unacked2, ABSL_ARRAYSIZE(unacked2));
  EXPECT_TRUE(manager_.HasInFlightPackets());

  SendDataPacket(5);
  ExpectAckAndLoss(true, 5, 2);
  EXPECT_CALL(debug_delegate,
              OnPacketLoss(QuicPacketNumber(2), _, LOSS_RETRANSMISSION, _));
  // Frames in all packets are acked.
  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  // Notify session that stream frame in packet 2 gets lost although it is
  // not outstanding.
  EXPECT_CALL(notifier_, OnFrameLost(_)).Times(1);
  manager_.OnAckFrameStart(QuicPacketNumber(5), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(6));
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_CALL(debug_delegate, OnIncomingAck(_, _, _, _, _, _, _)).Times(1);
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(3),
                                   ENCRYPTION_INITIAL, kEmptyCounts));

  uint64_t unacked3[] = {2};
  VerifyUnackedPackets(unacked3, ABSL_ARRAYSIZE(unacked3));
  EXPECT_FALSE(manager_.HasInFlightPackets());
  // Spurious retransmission is detected when packet 3 gets acked. We cannot
  // know packet 2 is a spurious until it gets acked.
  EXPECT_EQ(1u, stats_.packets_spuriously_retransmitted);
  EXPECT_EQ(1u, stats_.packets_lost);
  EXPECT_LT(0.0, stats_.total_loss_detection_response_time);
  EXPECT_LE(1u, stats_.sent_packets_max_sequence_reordering);
}

TEST_F(QuicSentPacketManagerTest, AckOriginalTransmission) {
  auto loss_algorithm = std::make_unique<MockLossAlgorithm>();
  QuicSentPacketManagerPeer::SetLossAlgorithm(&manager_, loss_algorithm.get());

  SendDataPacket(1);
  RetransmitAndSendPacket(1, 2);

  // Ack original transmission, but that wasn't lost via fast retransmit,
  // so no call on OnSpuriousRetransmission is expected.
  {
    ExpectAck(1);
    EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _));
    manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                             clock_.Now());
    manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
    EXPECT_EQ(PACKETS_NEWLY_ACKED,
              manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                     ENCRYPTION_INITIAL, kEmptyCounts));
  }

  SendDataPacket(3);
  SendDataPacket(4);
  // Ack 4, which causes 3 to be retransmitted.
  {
    ExpectAck(4);
    EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _));
    manager_.OnAckFrameStart(QuicPacketNumber(4), QuicTime::Delta::Infinite(),
                             clock_.Now());
    manager_.OnAckRange(QuicPacketNumber(4), QuicPacketNumber(5));
    manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
    EXPECT_EQ(PACKETS_NEWLY_ACKED,
              manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                     ENCRYPTION_INITIAL, kEmptyCounts));
    RetransmitAndSendPacket(3, 5, LOSS_RETRANSMISSION);
  }

  // Ack 3, which causes SpuriousRetransmitDetected to be called.
  {
    uint64_t acked[] = {3};
    ExpectAcksAndLosses(false, acked, ABSL_ARRAYSIZE(acked), nullptr, 0);
    EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _));
    EXPECT_CALL(*loss_algorithm,
                SpuriousLossDetected(_, _, _, QuicPacketNumber(3),
                                     QuicPacketNumber(4)));
    manager_.OnAckFrameStart(QuicPacketNumber(4), QuicTime::Delta::Infinite(),
                             clock_.Now());
    manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(5));
    manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
    EXPECT_EQ(0u, stats_.packet_spuriously_detected_lost);
    EXPECT_EQ(PACKETS_NEWLY_ACKED,
              manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(3),
                                     ENCRYPTION_INITIAL, kEmptyCounts));
    EXPECT_EQ(1u, stats_.packet_spuriously_detected_lost);
    // Ack 3 will not cause 5 be considered as a spurious retransmission. Ack
    // 5 will cause 5 be considered as a spurious retransmission as no new
    // data gets acked.
    ExpectAck(5);
    EXPECT_CALL(*loss_algorithm, DetectLosses(_, _, _, _, _, _));
    EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).WillOnce(Return(false));
    manager_.OnAckFrameStart(QuicPacketNumber(5), QuicTime::Delta::Infinite(),
                             clock_.Now());
    manager_.OnAckRange(QuicPacketNumber(3), QuicPacketNumber(6));
    manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
    EXPECT_EQ(PACKETS_NEWLY_ACKED,
              manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(4),
                                     ENCRYPTION_INITIAL, kEmptyCounts));
  }
}

TEST_F(QuicSentPacketManagerTest, GetLeastUnacked) {
  EXPECT_EQ(QuicPacketNumber(1u), manager_.GetLeastUnacked());
}

TEST_F(QuicSentPacketManagerTest, GetLeastUnackedUnacked) {
  SendDataPacket(1);
  EXPECT_EQ(QuicPacketNumber(1u), manager_.GetLeastUnacked());
}

TEST_F(QuicSentPacketManagerTest, AckAckAndUpdateRtt) {
  EXPECT_FALSE(manager_.largest_packet_peer_knows_is_acked().IsInitialized());
  SendDataPacket(1);
  SendAckPacket(2, 1);

  // Now ack the ack and expect an RTT update.
  uint64_t acked[] = {1, 2};
  ExpectAcksAndLosses(true, acked, ABSL_ARRAYSIZE(acked), nullptr, 0);
  manager_.OnAckFrameStart(QuicPacketNumber(2),
                           QuicTime::Delta::FromMilliseconds(5), clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(3));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(QuicPacketNumber(1), manager_.largest_packet_peer_knows_is_acked());

  SendAckPacket(3, 3);

  // Now ack the ack and expect only an RTT update.
  uint64_t acked2[] = {3};
  ExpectAcksAndLosses(true, acked2, ABSL_ARRAYSIZE(acked2), nullptr, 0);
  manager_.OnAckFrameStart(QuicPacketNumber(3), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(4));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(2),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(QuicPacketNumber(3u),
            manager_.largest_packet_peer_knows_is_acked());
}

TEST_F(QuicSentPacketManagerTest, Rtt) {
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(20);
  SendDataPacket(1);
  clock_.AdvanceTime(expected_rtt);

  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1), QuicTime::Delta::Infinite(),
                           clock_.Now());
  manager_.OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2));
  EXPECT_EQ(PACKETS_NEWLY_ACKED,
            manager_.OnAckFrameEnd(clock_.Now(), QuicPacketNumber(1),
                                   ENCRYPTION_INITIAL, kEmptyCounts));
  EXPECT_EQ(expected_rtt, manager_.GetRttStats()->latest_rtt());
}

TEST_F(QuicSentPacketManagerTest, RttWithInvalidDelta) {
  // Expect that the RTT is equal to the local time elapsed, since the
  // ack_delay_time is larger than the local time elapsed
  // and is hence invalid.
  QuicTime::Delta expected_rtt = QuicTime::Delta::FromMilliseconds(10);
  SendDataPacket(1);
  clock_.AdvanceTime(expected_rtt);

  ExpectAck(1);
  manager_.OnAckFrameStart(QuicPacketNumber(1),
                           QuicTime
```