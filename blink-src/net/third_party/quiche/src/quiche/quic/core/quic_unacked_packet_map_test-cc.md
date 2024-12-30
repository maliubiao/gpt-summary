Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Understanding of the Goal:**

The request is to understand the functionality of `quic_unacked_packet_map_test.cc`, its relationship to JavaScript (if any), logical inferences, potential user errors, and debugging context.

**2. Deconstructing the Request (Keywords & Concepts):**

* **"目录为 net/third_party/quiche/src/quiche/quic/core/quic_unacked_packet_map_test.cc 的 chromium 网络栈的源代码文件"**:  This tells us the location and project context. It's a C++ test file within the QUIC implementation of Chromium's network stack.
* **"请列举一下它的功能"**: The primary task is to describe what this file *does*.
* **"如果它与 javascript 的功能有关系，请做出对应的举例说明"**:  This requires examining the code for any interactions or analogies with JavaScript concepts.
* **"如果做了逻辑推理，请给出假设输入与输出"**: This prompts us to identify test cases and predict their behavior based on the code.
* **"如果涉及用户或者编程常见的使用错误，请举例说明"**: We need to think about how someone might misuse the functionality being tested.
* **"说明用户操作是如何一步步的到达这里，作为调试线索"**: This asks about the context in which this code might be relevant during debugging.

**3. Analyzing the Code (Top-Down and Keyword-Driven):**

* **Includes:** The `#include` statements are a good starting point. They reveal the dependencies:
    * `"quiche/quic/core/quic_unacked_packet_map.h"`:  This is the core subject of the test – the `QuicUnackedPacketMap` class. This class is likely responsible for tracking packets that haven't been acknowledged yet.
    * Other QUIC core headers (`quic_stream_frame.h`, `quic_packet_number.h`, etc.):  These indicate the data structures and concepts involved in managing unacknowledged packets (stream frames, packet numbers, transmission info).
    * Test-related headers (`quiche/quic/platform/api/quic_test.h`, `quiche/quic/test_tools/...`): This confirms it's a testing file.
    * Standard C++ headers (`<cstddef>`, `<limits>`, `<vector>`).
* **Namespaces:** `quic::test::{anonymous}`:  This indicates the code is within the QUIC testing framework.
* **Test Fixture:** The `QuicUnackedPacketMapTest` class inheriting from `QuicTestWithParam<Perspective>` is a standard Google Test pattern for parameterized tests. The `Perspective` parameter likely represents client or server perspective.
* **Helper Functions:** The `CreateRetransmittablePacket`, `CreateNonRetransmittablePacket`, `VerifyInFlightPackets`, `VerifyUnackedPackets`, etc., functions are crucial. They encapsulate common setup and verification steps for testing different scenarios. *This is where the core logic of the tests lies.*
* **Individual Tests:** The `TEST_P` macros define the actual test cases (e.g., `RttOnly`, `RetransmittableInflightAndRtt`, `StopRetransmission`). Each test focuses on a specific aspect of the `QuicUnackedPacketMap`'s behavior.
* **Mocking:** The use of `StrictMock<MockSessionNotifier>` and `EXPECT_CALL` indicates that the tests are verifying interactions with a related component (the `SessionNotifier`). This helps isolate the `QuicUnackedPacketMap` for testing.
* **Key Methods Being Tested (Inferring from Test Names and Logic):**
    * `AddSentPacket`:  Adding a packet to the map.
    * `RemoveRetransmittability`:  Marking a packet as no longer needing retransmission.
    * `IncreaseLargestAcked`:  Processing acknowledgments.
    * `RemoveFromInFlight`:  Removing a packet from the "in-flight" tracking.
    * `HasInFlightPackets`, `HasMultipleInFlightPackets`, `IsUnacked`, `HasRetransmittableFrames`: Querying the state of the map.
    * `GetTransmissionInfo`:  Retrieving details about a sent packet.
    * `RetransmitAndSendPacket`: Simulating retransmissions.
    * `MaybeAggregateAckedStreamFrame`: Testing aggregation of ACKed stream frames.
    * `GetLargestSentRetransmittableOfPacketNumberSpace`:  Handling multiple packet number spaces.
    * `DebugString`: For debugging purposes.

**4. Connecting to JavaScript (or Lack Thereof):**

The analysis reveals this is low-level network stack code in C++. There's no direct interaction with JavaScript. However, we can draw analogies:

* **Analogy of Tracking and Acknowledgement:**  JavaScript Promises can be seen as a high-level analogy. A Promise is "sent" (initiated), and we await its "acknowledgment" (resolution or rejection). Just like the `QuicUnackedPacketMap` tracks sent packets awaiting ACKs.
* **Analogy of Retransmission (Error Handling):**  If a JavaScript network request fails, you might implement retry logic, which is analogous to the retransmission mechanisms tested here.

**5. Logical Inferences (Test Cases):**

By examining the test functions, we can infer the intended behavior and create example input/output scenarios. Each test function essentially *is* a logical inference with a setup (input) and verification (output).

**6. User/Programming Errors:**

Consider how a developer using the `QuicUnackedPacketMap` might make mistakes:

* Incorrectly calling methods in the wrong order.
* Not handling acknowledgments properly.
* Misunderstanding the concept of "in-flight" vs. "unacked."

**7. Debugging Context:**

Think about when you'd need to look at this code during debugging:

* Network performance issues (packet loss, retransmissions).
* Issues with reliability and data delivery.
* Investigating why packets aren't being acknowledged.

**8. Structuring the Answer:**

Finally, organize the findings into a clear and structured response, addressing each part of the original request. Use headings and bullet points for readability. Provide concrete examples where possible. For the JavaScript connection, focus on analogies rather than direct relationships.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe there's some interaction with JavaScript through WebAssembly or a similar mechanism. *Correction:* After examining the includes and core functionality, it's clear this is purely C++ within the network stack. The connection to JavaScript is only at an abstract, conceptual level.
* **Focus on the "why":** Don't just list the functions. Explain *why* these tests are important and what aspects of the `QuicUnackedPacketMap` they verify.
* **Make the error examples concrete:** Instead of just saying "incorrect usage," provide a specific scenario.

By following this detailed analysis and thought process, we can generate a comprehensive and accurate answer to the request.
这个文件 `net/third_party/quiche/src/quiche/quic/core/quic_unacked_packet_map_test.cc` 是 Chromium QUIC 库中用于测试 `QuicUnackedPacketMap` 类的单元测试文件。`QuicUnackedPacketMap` 的主要功能是**跟踪已发送但尚未收到确认（ACK）的 QUIC 数据包**。

以下是 `quic_unacked_packet_map_test.cc` 的主要功能及其测试的各个方面：

**主要功能：**

1. **添加已发送的数据包:**  测试 `QuicUnackedPacketMap::AddSentPacket()` 功能，确保当数据包发送时，它能正确地添加到未确认数据包的跟踪记录中。
2. **跟踪数据包状态:** 测试数据包是否被标记为 "in-flight" (正在网络中传输，计入拥塞控制窗口) 以及是否包含可重传的帧。
3. **处理确认 (ACK):** 测试 `QuicUnackedPacketMap::IncreaseLargestAcked()` 功能，模拟收到 ACK 包，并验证已确认的数据包是否从未确认列表中移除。
4. **处理数据包丢失和重传:** 测试与数据包重传相关的逻辑，例如标记需要重传的数据包，以及在重传后更新数据包的状态。  包括丢包重传 (`LOSS_RETRANSMISSION`) 和 PTO 重传 (`PTO_RETRANSMISSION`)。
5. **管理可重传帧:** 测试对包含可重传帧（如 `STREAM_FRAME`）的数据包的处理，以及在收到 ACK 或发生重传时如何管理这些帧。
6. **优化重传 (Stopping Retransmission):** 测试在收到包含特定 `STREAM_FRAME` 的 ACK 时，如何停止对该 `STREAM_FRAME` 的重传，即使原始的包含该帧的数据包尚未被确认。
7. **聚合确认的 Stream 帧:** 测试 `QuicUnackedPacketMap::MaybeAggregateAckedStreamFrame()` 功能，验证是否可以将连续的、确认的 `STREAM_FRAME` 聚合为一个逻辑上的已确认帧，以减少通知次数。
8. **处理不同 Packet Number Space:** (当启用时) 测试对 Initial, Handshake, Application 等不同加密级别的数据包的跟踪和管理。
9. **管理 In-Flight 数据包:** 测试跟踪当前网络中 "in-flight" 的数据包，这对于拥塞控制和流量控制至关重要。
10. **调试信息:** 测试 `QuicUnackedPacketMap::DebugString()` 功能，用于生成可读的调试信息。
11. **存储 ECN 信息:** 测试是否能正确存储和检索每个数据包的 ECN (Explicit Congestion Notification) 信息。

**与 JavaScript 的关系：**

`quic_unacked_packet_map_test.cc` 是一个 C++ 文件，直接与 JavaScript 没有关系。JavaScript 运行在浏览器或其他环境中，通过 Web API (如 Fetch API) 与网络交互。QUIC 协议的实现 (包括 `QuicUnackedPacketMap`) 是在浏览器或服务器的底层网络栈中进行的，对 JavaScript 来说是透明的。

**举例说明 (类比):**

虽然没有直接关系，我们可以用一个类比来理解：

* **`QuicUnackedPacketMap` (C++) 类似于一个任务跟踪器，记录着已发送的网络请求（数据包），等待服务器的响应（ACK）。**
* **JavaScript (前端) 发起网络请求，就像向 `QuicUnackedPacketMap` "发送" 一个数据包。**
* **服务器的响应（ACK）就像任务完成的通知，`QuicUnackedPacketMap` 会移除对应的任务。**
* **如果一段时间没有收到响应，`QuicUnackedPacketMap` 可能会触发重传，就像前端的重试机制。**

**逻辑推理 (假设输入与输出):**

**假设输入 1:**

* 发送一个包含可重传 `STREAM_FRAME` 的数据包，packet_number = 1。
* 调用 `AddSentPacket(packet1, ...)`。

**预期输出 1:**

* `unacked_packets_.IsUnacked(QuicPacketNumber(1))` 返回 `true`。
* `unacked_packets_.HasRetransmittableFrames(QuicPacketNumber(1))` 返回 `true`。
* `unacked_packets_.HasInFlightPackets()` 返回 `true`。

**假设输入 2:**

* 收到对 packet_number = 1 的 ACK。
* 调用 `IncreaseLargestAcked(QuicPacketNumber(1))`。

**预期输出 2:**

* `unacked_packets_.IsUnacked(QuicPacketNumber(1))` 返回 `false`。
* `unacked_packets_.HasRetransmittableFrames(QuicPacketNumber(1))` 返回 `false`。
* 如果这是唯一 "in-flight" 的数据包，`unacked_packets_.HasInFlightPackets()` 返回 `false`。

**用户或编程常见的使用错误：**

1. **过早地释放与数据包关联的内存:** 如果在数据包被确认之前，或者在需要重传时，过早地释放了数据包的缓冲区，会导致崩溃或数据损坏。
   * **例子:** 在调用 `AddSentPacket` 后，立即删除作为参数传递的 `SerializedPacket` 对象，而不是让 `QuicUnackedPacketMap` 管理其生命周期。
2. **不正确地处理 ACK:** 如果没有正确调用 `IncreaseLargestAcked` 来更新已确认的数据包，`QuicUnackedPacketMap` 会认为这些数据包仍然未确认，可能导致不必要的重传。
   * **例子:**  收到 ACK 包后，没有解析出正确的被确认的最大包序号并更新 `QuicUnackedPacketMap`。
3. **对同一个数据包进行多次重传而不更新状态:** 如果一个数据包被多次重传，但 `QuicUnackedPacketMap` 的状态没有正确更新，可能会导致混乱的重传逻辑和性能问题。
   * **例子:**  在重传一个数据包后，没有调用 `RetransmitAndSendPacket` 来更新旧数据包的状态，导致它仍然被认为是初始发送的数据包。
4. **在多包号空间中混淆包号:** 当使用多个包号空间（Initial, Handshake, Application）时，错误地使用或比较不同空间中的包号会导致逻辑错误。
   * **例子:**  尝试用 Application 空间的包号去查找 Initial 空间的数据包。

**用户操作如何一步步到达这里 (调试线索):**

假设用户报告了一个网络连接问题，例如：

1. **用户在浏览器中访问一个网站，但加载速度很慢或失败。**
2. **开发人员开始使用 Chromium 的网络调试工具 (如 `chrome://net-internals`) 分析网络连接。**
3. **在 QUIC 会话的详细信息中，开发人员可能会看到大量的丢包或重传。**
4. **为了进一步调查，开发人员可能会查看 QUIC 协议栈的日志，发现与 `QuicUnackedPacketMap` 相关的警告或错误。**
5. **为了理解这些错误，开发人员可能会查看 `quic_unacked_packet_map.cc` 和 `quic_unacked_packet_map_test.cc` 的源代码，以了解 `QuicUnackedPacketMap` 的工作原理以及可能的故障点。**
6. **如果怀疑是某个特定的重传场景导致的错误，开发人员可能会在 `quic_unacked_packet_map_test.cc` 中找到相关的测试用例，并尝试在本地环境中复现该问题。**
7. **开发人员还可以修改或添加新的测试用例，以更精确地模拟用户遇到的场景，并验证修复方案的有效性。**

总而言之，`quic_unacked_packet_map_test.cc` 是确保 `QuicUnackedPacketMap` 类功能正确性和稳定性的关键组成部分，它覆盖了数据包生命周期中从发送到确认的各种场景，包括重传和优化。虽然与 JavaScript 没有直接联系，但它是实现可靠 QUIC 连接的基础，而 QUIC 连接又为基于 Web 的应用提供了更快的网络体验。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_unacked_packet_map_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_unacked_packet_map.h"

#include <cstddef>
#include <limits>
#include <vector>

#include "absl/base/macros.h"
#include "quiche/quic/core/frames/quic_stream_frame.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_transmission_info.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/quic_unacked_packet_map_peer.h"

using testing::_;
using testing::Return;
using testing::StrictMock;

namespace quic {
namespace test {
namespace {

// Default packet length.
const uint32_t kDefaultLength = 1000;

class QuicUnackedPacketMapTest : public QuicTestWithParam<Perspective> {
 protected:
  QuicUnackedPacketMapTest()
      : unacked_packets_(GetParam()),
        now_(QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(1000)) {
    unacked_packets_.SetSessionNotifier(&notifier_);
    EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(notifier_, OnStreamFrameRetransmitted(_))
        .Times(testing::AnyNumber());
  }

  ~QuicUnackedPacketMapTest() override {}

  SerializedPacket CreateRetransmittablePacket(uint64_t packet_number) {
    return CreateRetransmittablePacketForStream(
        packet_number, QuicUtils::GetFirstBidirectionalStreamId(
                           CurrentSupportedVersions()[0].transport_version,
                           Perspective::IS_CLIENT));
  }

  SerializedPacket CreateRetransmittablePacketForStream(
      uint64_t packet_number, QuicStreamId stream_id) {
    SerializedPacket packet(QuicPacketNumber(packet_number),
                            PACKET_1BYTE_PACKET_NUMBER, nullptr, kDefaultLength,
                            false, false);
    QuicStreamFrame frame;
    frame.stream_id = stream_id;
    packet.retransmittable_frames.push_back(QuicFrame(frame));
    return packet;
  }

  SerializedPacket CreateNonRetransmittablePacket(uint64_t packet_number) {
    return SerializedPacket(QuicPacketNumber(packet_number),
                            PACKET_1BYTE_PACKET_NUMBER, nullptr, kDefaultLength,
                            false, false);
  }

  void VerifyInFlightPackets(uint64_t* packets, size_t num_packets) {
    unacked_packets_.RemoveObsoletePackets();
    if (num_packets == 0) {
      EXPECT_FALSE(unacked_packets_.HasInFlightPackets());
      EXPECT_FALSE(unacked_packets_.HasMultipleInFlightPackets());
      return;
    }
    if (num_packets == 1) {
      EXPECT_TRUE(unacked_packets_.HasInFlightPackets());
      EXPECT_FALSE(unacked_packets_.HasMultipleInFlightPackets());
      ASSERT_TRUE(unacked_packets_.IsUnacked(QuicPacketNumber(packets[0])));
      EXPECT_TRUE(
          unacked_packets_.GetTransmissionInfo(QuicPacketNumber(packets[0]))
              .in_flight);
    }
    for (size_t i = 0; i < num_packets; ++i) {
      ASSERT_TRUE(unacked_packets_.IsUnacked(QuicPacketNumber(packets[i])));
      EXPECT_TRUE(
          unacked_packets_.GetTransmissionInfo(QuicPacketNumber(packets[i]))
              .in_flight);
    }
    size_t in_flight_count = 0;
    for (auto it = unacked_packets_.begin(); it != unacked_packets_.end();
         ++it) {
      if (it->in_flight) {
        ++in_flight_count;
      }
    }
    EXPECT_EQ(num_packets, in_flight_count);
  }

  void VerifyUnackedPackets(uint64_t* packets, size_t num_packets) {
    unacked_packets_.RemoveObsoletePackets();
    if (num_packets == 0) {
      EXPECT_TRUE(unacked_packets_.empty());
      EXPECT_FALSE(unacked_packets_.HasUnackedRetransmittableFrames());
      return;
    }
    EXPECT_FALSE(unacked_packets_.empty());
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(unacked_packets_.IsUnacked(QuicPacketNumber(packets[i])))
          << packets[i];
    }
    EXPECT_EQ(num_packets, unacked_packets_.GetNumUnackedPacketsDebugOnly());
  }

  void VerifyRetransmittablePackets(uint64_t* packets, size_t num_packets) {
    unacked_packets_.RemoveObsoletePackets();
    size_t num_retransmittable_packets = 0;
    for (auto it = unacked_packets_.begin(); it != unacked_packets_.end();
         ++it) {
      if (unacked_packets_.HasRetransmittableFrames(*it)) {
        ++num_retransmittable_packets;
      }
    }
    EXPECT_EQ(num_packets, num_retransmittable_packets);
    for (size_t i = 0; i < num_packets; ++i) {
      EXPECT_TRUE(unacked_packets_.HasRetransmittableFrames(
          QuicPacketNumber(packets[i])))
          << " packets[" << i << "]:" << packets[i];
    }
  }

  void UpdatePacketState(uint64_t packet_number, SentPacketState state) {
    unacked_packets_
        .GetMutableTransmissionInfo(QuicPacketNumber(packet_number))
        ->state = state;
  }

  void RetransmitAndSendPacket(uint64_t old_packet_number,
                               uint64_t new_packet_number,
                               TransmissionType transmission_type) {
    QUICHE_DCHECK(unacked_packets_.HasRetransmittableFrames(
        QuicPacketNumber(old_packet_number)));
    QuicTransmissionInfo* info = unacked_packets_.GetMutableTransmissionInfo(
        QuicPacketNumber(old_packet_number));
    QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
        CurrentSupportedVersions()[0].transport_version,
        Perspective::IS_CLIENT);
    for (const auto& frame : info->retransmittable_frames) {
      if (frame.type == STREAM_FRAME) {
        stream_id = frame.stream_frame.stream_id;
        break;
      }
    }
    UpdatePacketState(
        old_packet_number,
        QuicUtils::RetransmissionTypeToPacketState(transmission_type));
    info->first_sent_after_loss = QuicPacketNumber(new_packet_number);
    SerializedPacket packet(
        CreateRetransmittablePacketForStream(new_packet_number, stream_id));
    unacked_packets_.AddSentPacket(&packet, transmission_type, now_, true, true,
                                   ECN_NOT_ECT);
  }
  QuicUnackedPacketMap unacked_packets_;
  QuicTime now_;
  StrictMock<MockSessionNotifier> notifier_;
};

INSTANTIATE_TEST_SUITE_P(Tests, QuicUnackedPacketMapTest,
                         ::testing::ValuesIn({Perspective::IS_CLIENT,
                                              Perspective::IS_SERVER}),
                         ::testing::PrintToStringParamName());

TEST_P(QuicUnackedPacketMapTest, RttOnly) {
  // Acks are only tracked for RTT measurement purposes.
  SerializedPacket packet(CreateNonRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet, NOT_RETRANSMISSION, now_, false, true,
                                 ECN_NOT_ECT);

  uint64_t unacked[] = {1};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.IncreaseLargestAcked(QuicPacketNumber(1));
  VerifyUnackedPackets(nullptr, 0);
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_P(QuicUnackedPacketMapTest, RetransmittableInflightAndRtt) {
  // Simulate a retransmittable packet being sent and acked.
  SerializedPacket packet(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);

  uint64_t unacked[] = {1};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(unacked, ABSL_ARRAYSIZE(unacked));

  unacked_packets_.RemoveRetransmittability(QuicPacketNumber(1));
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.IncreaseLargestAcked(QuicPacketNumber(1));
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(1));
  VerifyUnackedPackets(nullptr, 0);
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_P(QuicUnackedPacketMapTest, StopRetransmission) {
  const QuicStreamId stream_id = 2;
  SerializedPacket packet(CreateRetransmittablePacketForStream(1, stream_id));
  unacked_packets_.AddSentPacket(&packet, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);

  uint64_t unacked[] = {1};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  uint64_t retransmittable[] = {1};
  VerifyRetransmittablePackets(retransmittable,
                               ABSL_ARRAYSIZE(retransmittable));

  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_P(QuicUnackedPacketMapTest, StopRetransmissionOnOtherStream) {
  const QuicStreamId stream_id = 2;
  SerializedPacket packet(CreateRetransmittablePacketForStream(1, stream_id));
  unacked_packets_.AddSentPacket(&packet, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);

  uint64_t unacked[] = {1};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  uint64_t retransmittable[] = {1};
  VerifyRetransmittablePackets(retransmittable,
                               ABSL_ARRAYSIZE(retransmittable));

  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(retransmittable,
                               ABSL_ARRAYSIZE(retransmittable));
}

TEST_P(QuicUnackedPacketMapTest, StopRetransmissionAfterRetransmission) {
  const QuicStreamId stream_id = 2;
  SerializedPacket packet1(CreateRetransmittablePacketForStream(1, stream_id));
  unacked_packets_.AddSentPacket(&packet1, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  RetransmitAndSendPacket(1, 2, LOSS_RETRANSMISSION);

  uint64_t unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  std::vector<uint64_t> retransmittable = {1, 2};
  VerifyRetransmittablePackets(&retransmittable[0], retransmittable.size());

  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_P(QuicUnackedPacketMapTest, RetransmittedPacket) {
  // Simulate a retransmittable packet being sent, retransmitted, and the first
  // transmission being acked.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  RetransmitAndSendPacket(1, 2, LOSS_RETRANSMISSION);

  uint64_t unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  std::vector<uint64_t> retransmittable = {1, 2};
  VerifyRetransmittablePackets(&retransmittable[0], retransmittable.size());

  EXPECT_CALL(notifier_, IsFrameOutstanding(_)).WillRepeatedly(Return(false));
  unacked_packets_.RemoveRetransmittability(QuicPacketNumber(1));
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.IncreaseLargestAcked(QuicPacketNumber(2));
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  uint64_t unacked2[] = {1};
  VerifyUnackedPackets(unacked2, ABSL_ARRAYSIZE(unacked2));
  VerifyInFlightPackets(unacked2, ABSL_ARRAYSIZE(unacked2));
  VerifyRetransmittablePackets(nullptr, 0);

  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(1));
  VerifyUnackedPackets(nullptr, 0);
  VerifyInFlightPackets(nullptr, 0);
  VerifyRetransmittablePackets(nullptr, 0);
}

TEST_P(QuicUnackedPacketMapTest, RetransmitThreeTimes) {
  // Simulate a retransmittable packet being sent and retransmitted twice.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  SerializedPacket packet2(CreateRetransmittablePacket(2));
  unacked_packets_.AddSentPacket(&packet2, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);

  uint64_t unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  uint64_t retransmittable[] = {1, 2};
  VerifyRetransmittablePackets(retransmittable,
                               ABSL_ARRAYSIZE(retransmittable));

  // Early retransmit 1 as 3 and send new data as 4.
  unacked_packets_.IncreaseLargestAcked(QuicPacketNumber(2));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  unacked_packets_.RemoveRetransmittability(QuicPacketNumber(2));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(1));
  RetransmitAndSendPacket(1, 3, LOSS_RETRANSMISSION);
  SerializedPacket packet4(CreateRetransmittablePacket(4));
  unacked_packets_.AddSentPacket(&packet4, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);

  uint64_t unacked2[] = {1, 3, 4};
  VerifyUnackedPackets(unacked2, ABSL_ARRAYSIZE(unacked2));
  uint64_t pending2[] = {3, 4};
  VerifyInFlightPackets(pending2, ABSL_ARRAYSIZE(pending2));
  std::vector<uint64_t> retransmittable2 = {1, 3, 4};
  VerifyRetransmittablePackets(&retransmittable2[0], retransmittable2.size());

  // Early retransmit 3 (formerly 1) as 5, and remove 1 from unacked.
  unacked_packets_.IncreaseLargestAcked(QuicPacketNumber(4));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(4));
  unacked_packets_.RemoveRetransmittability(QuicPacketNumber(4));
  RetransmitAndSendPacket(3, 5, LOSS_RETRANSMISSION);
  SerializedPacket packet6(CreateRetransmittablePacket(6));
  unacked_packets_.AddSentPacket(&packet6, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);

  std::vector<uint64_t> unacked3 = {3, 5, 6};
  std::vector<uint64_t> retransmittable3 = {3, 5, 6};
  VerifyUnackedPackets(&unacked3[0], unacked3.size());
  VerifyRetransmittablePackets(&retransmittable3[0], retransmittable3.size());
  uint64_t pending3[] = {3, 5, 6};
  VerifyInFlightPackets(pending3, ABSL_ARRAYSIZE(pending3));

  // Early retransmit 5 as 7 and ensure in flight packet 3 is not removed.
  unacked_packets_.IncreaseLargestAcked(QuicPacketNumber(6));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(6));
  unacked_packets_.RemoveRetransmittability(QuicPacketNumber(6));
  RetransmitAndSendPacket(5, 7, LOSS_RETRANSMISSION);

  std::vector<uint64_t> unacked4 = {3, 5, 7};
  std::vector<uint64_t> retransmittable4 = {3, 5, 7};
  VerifyUnackedPackets(&unacked4[0], unacked4.size());
  VerifyRetransmittablePackets(&retransmittable4[0], retransmittable4.size());
  uint64_t pending4[] = {3, 5, 7};
  VerifyInFlightPackets(pending4, ABSL_ARRAYSIZE(pending4));

  // Remove the older two transmissions from in flight.
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(3));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(5));
  uint64_t pending5[] = {7};
  VerifyInFlightPackets(pending5, ABSL_ARRAYSIZE(pending5));
}

TEST_P(QuicUnackedPacketMapTest, RetransmitFourTimes) {
  // Simulate a retransmittable packet being sent and retransmitted twice.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  SerializedPacket packet2(CreateRetransmittablePacket(2));
  unacked_packets_.AddSentPacket(&packet2, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);

  uint64_t unacked[] = {1, 2};
  VerifyUnackedPackets(unacked, ABSL_ARRAYSIZE(unacked));
  VerifyInFlightPackets(unacked, ABSL_ARRAYSIZE(unacked));
  uint64_t retransmittable[] = {1, 2};
  VerifyRetransmittablePackets(retransmittable,
                               ABSL_ARRAYSIZE(retransmittable));

  // Early retransmit 1 as 3.
  unacked_packets_.IncreaseLargestAcked(QuicPacketNumber(2));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(2));
  unacked_packets_.RemoveRetransmittability(QuicPacketNumber(2));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(1));
  RetransmitAndSendPacket(1, 3, LOSS_RETRANSMISSION);

  uint64_t unacked2[] = {1, 3};
  VerifyUnackedPackets(unacked2, ABSL_ARRAYSIZE(unacked2));
  uint64_t pending2[] = {3};
  VerifyInFlightPackets(pending2, ABSL_ARRAYSIZE(pending2));
  std::vector<uint64_t> retransmittable2 = {1, 3};
  VerifyRetransmittablePackets(&retransmittable2[0], retransmittable2.size());

  // PTO 3 (formerly 1) as 4, and don't remove 1 from unacked.
  RetransmitAndSendPacket(3, 4, PTO_RETRANSMISSION);
  SerializedPacket packet5(CreateRetransmittablePacket(5));
  unacked_packets_.AddSentPacket(&packet5, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);

  uint64_t unacked3[] = {1, 3, 4, 5};
  VerifyUnackedPackets(unacked3, ABSL_ARRAYSIZE(unacked3));
  uint64_t pending3[] = {3, 4, 5};
  VerifyInFlightPackets(pending3, ABSL_ARRAYSIZE(pending3));
  std::vector<uint64_t> retransmittable3 = {1, 3, 4, 5};
  VerifyRetransmittablePackets(&retransmittable3[0], retransmittable3.size());

  // Early retransmit 4 as 6 and ensure in flight packet 3 is removed.
  unacked_packets_.IncreaseLargestAcked(QuicPacketNumber(5));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(5));
  unacked_packets_.RemoveRetransmittability(QuicPacketNumber(5));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(3));
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(4));
  RetransmitAndSendPacket(4, 6, LOSS_RETRANSMISSION);

  std::vector<uint64_t> unacked4 = {4, 6};
  VerifyUnackedPackets(&unacked4[0], unacked4.size());
  uint64_t pending4[] = {6};
  VerifyInFlightPackets(pending4, ABSL_ARRAYSIZE(pending4));
  std::vector<uint64_t> retransmittable4 = {4, 6};
  VerifyRetransmittablePackets(&retransmittable4[0], retransmittable4.size());
}

TEST_P(QuicUnackedPacketMapTest, SendWithGap) {
  // Simulate a retransmittable packet being sent, retransmitted, and the first
  // transmission being acked.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  SerializedPacket packet3(CreateRetransmittablePacket(3));
  unacked_packets_.AddSentPacket(&packet3, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  RetransmitAndSendPacket(3, 5, LOSS_RETRANSMISSION);

  EXPECT_EQ(QuicPacketNumber(1u), unacked_packets_.GetLeastUnacked());
  EXPECT_TRUE(unacked_packets_.IsUnacked(QuicPacketNumber(1)));
  EXPECT_FALSE(unacked_packets_.IsUnacked(QuicPacketNumber(2)));
  EXPECT_TRUE(unacked_packets_.IsUnacked(QuicPacketNumber(3)));
  EXPECT_FALSE(unacked_packets_.IsUnacked(QuicPacketNumber(4)));
  EXPECT_TRUE(unacked_packets_.IsUnacked(QuicPacketNumber(5)));
  EXPECT_EQ(QuicPacketNumber(5u), unacked_packets_.largest_sent_packet());
}

TEST_P(QuicUnackedPacketMapTest, AggregateContiguousAckedStreamFrames) {
  testing::InSequence s;
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).Times(0);
  unacked_packets_.NotifyAggregatedStreamFrameAcked(QuicTime::Delta::Zero());

  QuicTransmissionInfo info1;
  QuicStreamFrame stream_frame1(3, false, 0, 100);
  info1.retransmittable_frames.push_back(QuicFrame(stream_frame1));

  QuicTransmissionInfo info2;
  QuicStreamFrame stream_frame2(3, false, 100, 100);
  info2.retransmittable_frames.push_back(QuicFrame(stream_frame2));

  QuicTransmissionInfo info3;
  QuicStreamFrame stream_frame3(3, false, 200, 100);
  info3.retransmittable_frames.push_back(QuicFrame(stream_frame3));

  QuicTransmissionInfo info4;
  QuicStreamFrame stream_frame4(3, true, 300, 0);
  info4.retransmittable_frames.push_back(QuicFrame(stream_frame4));

  // Verify stream frames are aggregated.
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).Times(0);
  unacked_packets_.MaybeAggregateAckedStreamFrame(
      info1, QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).Times(0);
  unacked_packets_.MaybeAggregateAckedStreamFrame(
      info2, QuicTime::Delta::Zero(), QuicTime::Zero());
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).Times(0);
  unacked_packets_.MaybeAggregateAckedStreamFrame(
      info3, QuicTime::Delta::Zero(), QuicTime::Zero());

  // Verify aggregated stream frame gets acked since fin is acked.
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).Times(1);
  unacked_packets_.MaybeAggregateAckedStreamFrame(
      info4, QuicTime::Delta::Zero(), QuicTime::Zero());
}

// Regression test for b/112930090.
TEST_P(QuicUnackedPacketMapTest, CannotAggregateIfDataLengthOverflow) {
  QuicByteCount kMaxAggregatedDataLength =
      std::numeric_limits<decltype(QuicStreamFrame().data_length)>::max();
  QuicStreamId stream_id = 2;

  // acked_stream_length=512 covers the case where a frame will cause the
  // aggregated frame length to be exactly 64K.
  // acked_stream_length=1300 covers the case where a frame will cause the
  // aggregated frame length to exceed 64K.
  for (const QuicPacketLength acked_stream_length : {512, 1300}) {
    ++stream_id;
    QuicStreamOffset offset = 0;
    // Expected length of the aggregated stream frame.
    QuicByteCount aggregated_data_length = 0;

    while (offset < 1e6) {
      QuicTransmissionInfo info;
      QuicStreamFrame stream_frame(stream_id, false, offset,
                                   acked_stream_length);
      info.retransmittable_frames.push_back(QuicFrame(stream_frame));

      const QuicStreamFrame& aggregated_stream_frame =
          QuicUnackedPacketMapPeer::GetAggregatedStreamFrame(unacked_packets_);
      if (aggregated_stream_frame.data_length + acked_stream_length <=
          kMaxAggregatedDataLength) {
        // Verify the acked stream frame can be aggregated.
        EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).Times(0);
        unacked_packets_.MaybeAggregateAckedStreamFrame(
            info, QuicTime::Delta::Zero(), QuicTime::Zero());
        aggregated_data_length += acked_stream_length;
        testing::Mock::VerifyAndClearExpectations(&notifier_);
      } else {
        // Verify the acked stream frame cannot be aggregated because
        // data_length is overflow.
        EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).Times(1);
        unacked_packets_.MaybeAggregateAckedStreamFrame(
            info, QuicTime::Delta::Zero(), QuicTime::Zero());
        aggregated_data_length = acked_stream_length;
        testing::Mock::VerifyAndClearExpectations(&notifier_);
      }

      EXPECT_EQ(aggregated_data_length, aggregated_stream_frame.data_length);
      offset += acked_stream_length;
    }

    // Ack the last frame of the stream.
    QuicTransmissionInfo info;
    QuicStreamFrame stream_frame(stream_id, true, offset, acked_stream_length);
    info.retransmittable_frames.push_back(QuicFrame(stream_frame));
    EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).Times(1);
    unacked_packets_.MaybeAggregateAckedStreamFrame(
        info, QuicTime::Delta::Zero(), QuicTime::Zero());
    testing::Mock::VerifyAndClearExpectations(&notifier_);
  }
}

TEST_P(QuicUnackedPacketMapTest, CannotAggregateAckedControlFrames) {
  testing::InSequence s;
  QuicWindowUpdateFrame window_update(1, 5, 100);
  QuicStreamFrame stream_frame1(3, false, 0, 100);
  QuicStreamFrame stream_frame2(3, false, 100, 100);
  QuicBlockedFrame blocked(2, 5, 0);
  QuicGoAwayFrame go_away(3, QUIC_PEER_GOING_AWAY, 5, "Going away.");

  QuicTransmissionInfo info1;
  info1.retransmittable_frames.push_back(QuicFrame(window_update));
  info1.retransmittable_frames.push_back(QuicFrame(stream_frame1));
  info1.retransmittable_frames.push_back(QuicFrame(stream_frame2));

  QuicTransmissionInfo info2;
  info2.retransmittable_frames.push_back(QuicFrame(blocked));
  info2.retransmittable_frames.push_back(QuicFrame(&go_away));

  // Verify 2 contiguous stream frames are aggregated.
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).Times(1);
  unacked_packets_.MaybeAggregateAckedStreamFrame(
      info1, QuicTime::Delta::Zero(), QuicTime::Zero());
  // Verify aggregated stream frame gets acked.
  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).Times(3);
  unacked_packets_.MaybeAggregateAckedStreamFrame(
      info2, QuicTime::Delta::Zero(), QuicTime::Zero());

  EXPECT_CALL(notifier_, OnFrameAcked(_, _, _)).Times(0);
  unacked_packets_.NotifyAggregatedStreamFrameAcked(QuicTime::Delta::Zero());
}

TEST_P(QuicUnackedPacketMapTest, LargestSentPacketMultiplePacketNumberSpaces) {
  unacked_packets_.EnableMultiplePacketNumberSpacesSupport();
  EXPECT_FALSE(
      unacked_packets_
          .GetLargestSentRetransmittableOfPacketNumberSpace(INITIAL_DATA)
          .IsInitialized());
  // Send packet 1.
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  packet1.encryption_level = ENCRYPTION_INITIAL;
  unacked_packets_.AddSentPacket(&packet1, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  EXPECT_EQ(QuicPacketNumber(1u), unacked_packets_.largest_sent_packet());
  EXPECT_EQ(QuicPacketNumber(1),
            unacked_packets_.GetLargestSentRetransmittableOfPacketNumberSpace(
                INITIAL_DATA));
  EXPECT_FALSE(
      unacked_packets_
          .GetLargestSentRetransmittableOfPacketNumberSpace(HANDSHAKE_DATA)
          .IsInitialized());
  // Send packet 2.
  SerializedPacket packet2(CreateRetransmittablePacket(2));
  packet2.encryption_level = ENCRYPTION_HANDSHAKE;
  unacked_packets_.AddSentPacket(&packet2, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  EXPECT_EQ(QuicPacketNumber(2u), unacked_packets_.largest_sent_packet());
  EXPECT_EQ(QuicPacketNumber(1),
            unacked_packets_.GetLargestSentRetransmittableOfPacketNumberSpace(
                INITIAL_DATA));
  EXPECT_EQ(QuicPacketNumber(2),
            unacked_packets_.GetLargestSentRetransmittableOfPacketNumberSpace(
                HANDSHAKE_DATA));
  EXPECT_FALSE(
      unacked_packets_
          .GetLargestSentRetransmittableOfPacketNumberSpace(APPLICATION_DATA)
          .IsInitialized());
  // Send packet 3.
  SerializedPacket packet3(CreateRetransmittablePacket(3));
  packet3.encryption_level = ENCRYPTION_ZERO_RTT;
  unacked_packets_.AddSentPacket(&packet3, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  EXPECT_EQ(QuicPacketNumber(3u), unacked_packets_.largest_sent_packet());
  EXPECT_EQ(QuicPacketNumber(1),
            unacked_packets_.GetLargestSentRetransmittableOfPacketNumberSpace(
                INITIAL_DATA));
  EXPECT_EQ(QuicPacketNumber(2),
            unacked_packets_.GetLargestSentRetransmittableOfPacketNumberSpace(
                HANDSHAKE_DATA));
  EXPECT_EQ(QuicPacketNumber(3),
            unacked_packets_.GetLargestSentRetransmittableOfPacketNumberSpace(
                APPLICATION_DATA));
  // Verify forward secure belongs to the same packet number space as encryption
  // zero rtt.
  EXPECT_EQ(QuicPacketNumber(3),
            unacked_packets_.GetLargestSentRetransmittableOfPacketNumberSpace(
                APPLICATION_DATA));

  // Send packet 4.
  SerializedPacket packet4(CreateRetransmittablePacket(4));
  packet4.encryption_level = ENCRYPTION_FORWARD_SECURE;
  unacked_packets_.AddSentPacket(&packet4, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  EXPECT_EQ(QuicPacketNumber(4u), unacked_packets_.largest_sent_packet());
  EXPECT_EQ(QuicPacketNumber(1),
            unacked_packets_.GetLargestSentRetransmittableOfPacketNumberSpace(
                INITIAL_DATA));
  EXPECT_EQ(QuicPacketNumber(2),
            unacked_packets_.GetLargestSentRetransmittableOfPacketNumberSpace(
                HANDSHAKE_DATA));
  EXPECT_EQ(QuicPacketNumber(4),
            unacked_packets_.GetLargestSentRetransmittableOfPacketNumberSpace(
                APPLICATION_DATA));
  // Verify forward secure belongs to the same packet number space as encryption
  // zero rtt.
  EXPECT_EQ(QuicPacketNumber(4),
            unacked_packets_.GetLargestSentRetransmittableOfPacketNumberSpace(
                APPLICATION_DATA));
  EXPECT_TRUE(unacked_packets_.GetLastPacketContent() & (1 << STREAM_FRAME));
  EXPECT_FALSE(unacked_packets_.GetLastPacketContent() & (1 << ACK_FRAME));
}

TEST_P(QuicUnackedPacketMapTest, ReserveInitialCapacityTest) {
  QuicUnackedPacketMap unacked_packets(GetParam());
  ASSERT_EQ(QuicUnackedPacketMapPeer::GetCapacity(unacked_packets), 0u);
  unacked_packets.ReserveInitialCapacity(16);
  QuicStreamId stream_id(1);
  SerializedPacket packet(CreateRetransmittablePacketForStream(1, stream_id));
  unacked_packets.AddSentPacket(&packet, TransmissionType::NOT_RETRANSMISSION,
                                now_, true, true, ECN_NOT_ECT);
  ASSERT_EQ(QuicUnackedPacketMapPeer::GetCapacity(unacked_packets), 16u);
}

TEST_P(QuicUnackedPacketMapTest, DebugString) {
  EXPECT_EQ(unacked_packets_.DebugString(),
            "{size: 0, least_unacked: 1, largest_sent_packet: uninitialized, "
            "largest_acked: uninitialized, bytes_in_flight: 0, "
            "packets_in_flight: 0}");

  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  EXPECT_EQ(
      unacked_packets_.DebugString(),
      "{size: 1, least_unacked: 1, largest_sent_packet: 1, largest_acked: "
      "uninitialized, bytes_in_flight: 1000, packets_in_flight: 1}");

  SerializedPacket packet2(CreateRetransmittablePacket(2));
  unacked_packets_.AddSentPacket(&packet2, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  unacked_packets_.RemoveFromInFlight(QuicPacketNumber(1));
  unacked_packets_.IncreaseLargestAcked(QuicPacketNumber(1));
  unacked_packets_.RemoveObsoletePackets();
  EXPECT_EQ(
      unacked_packets_.DebugString(),
      "{size: 1, least_unacked: 2, largest_sent_packet: 2, largest_acked: 1, "
      "bytes_in_flight: 1000, packets_in_flight: 1}");
}

TEST_P(QuicUnackedPacketMapTest, EcnInfoStored) {
  SerializedPacket packet1(CreateRetransmittablePacket(1));
  unacked_packets_.AddSentPacket(&packet1, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_NOT_ECT);
  SerializedPacket packet2(CreateRetransmittablePacket(2));
  unacked_packets_.AddSentPacket(&packet2, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_ECT0);
  SerializedPacket packet3(CreateRetransmittablePacket(3));
  unacked_packets_.AddSentPacket(&packet3, NOT_RETRANSMISSION, now_, true, true,
                                 ECN_ECT1);
  EXPECT_EQ(
      unacked_packets_.GetTransmissionInfo(QuicPacketNumber(1)).ecn_codepoint,
      ECN_NOT_ECT);
  EXPECT_EQ(
      unacked_packets_.GetTransmissionInfo(QuicPacketNumber(2)).ecn_codepoint,
      ECN_ECT0);
  EXPECT_EQ(
      unacked_packets_.GetTransmissionInfo(QuicPacketNumber(3)).ecn_codepoint,
      ECN_ECT1);
}

}  // namespace
}  // namespace test
}  // namespace quic

"""

```