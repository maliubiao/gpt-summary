Response:
The user wants to understand the functionality of the C++ source code file `quic_frames_test.cc`.
This file is part of the Chromium network stack, specifically within the QUIC implementation.
It's a test file, so its primary function is to verify the correctness of the QUIC frame classes.

Here's a breakdown of the requested information:
1. **Functionality of the file:** This involves identifying the main purpose of the tests.
2. **Relationship with JavaScript:**  Explore if and how these QUIC frame tests might relate to JavaScript functionality in a browser context.
3. **Logical reasoning (input/output):** For specific test cases, describe the expected input and output.
4. **Common usage errors:** Identify potential mistakes developers might make when working with QUIC frames.
5. **User operation to reach this code:** Explain how a user's actions in a browser could indirectly lead to the execution of this test code.
6. **Summary of functionality (for part 1):**  Condense the overall purpose of the code in this first part.

**Plan:**
1. Analyze the `#include` directives to understand which QUIC frame classes are being tested.
2. Examine the `TEST_F` macros to identify individual test cases and their objectives.
3. Determine how the tests interact with the QUIC frame classes.
4. Connect the functionality to potential JavaScript interactions, focusing on browser networking.
5. Select a few test cases for input/output examples.
6. Brainstorm common errors when dealing with network frames or testing in general.
7. Describe a typical browser scenario involving QUIC to trace the path to this test file.
8. Summarize the file's functionality based on the analysis.
这是chromium网络栈中QUIC协议框架（frames）的单元测试文件。

**功能归纳:**

这个文件的主要功能是测试QUIC协议中各种帧（frame）类的正确性。它包含了针对不同类型的QUIC帧的单元测试，例如：

* **ACK 帧 (ACK Frame):** 测试 ACK 帧的字符串表示，包括单个和多个不连续的确认包序列。
* **Padding 帧 (Padding Frame):** 测试填充帧的字符串表示。
* **RST_STREAM 帧 (Rst Stream Frame):** 测试重置流帧的字符串表示和控制帧 ID 的设置。
* **STOP_SENDING 帧 (Stop Sending Frame):** 测试停止发送帧的字符串表示和控制帧 ID 的设置。
* **NEW_CONNECTION_ID 帧 (New Connection ID Frame):** 测试新连接ID帧的字符串表示、控制帧 ID 的设置以及可重传控制帧的复制。
* **RETIRE_CONNECTION_ID 帧 (Retire Connection ID Frame):** 测试退役连接ID帧的字符串表示、控制帧 ID 的设置以及可重传控制帧的复制。
* **STREAMS_BLOCKED 帧 (Streams Blocked Frame):** 测试流阻塞帧的字符串表示和控制帧 ID 的设置。
* **MAX_STREAMS 帧 (Max Streams Frame):** 测试最大流数帧的字符串表示和控制帧 ID 的设置。
* **CONNECTION_CLOSE 帧 (Connection Close Frame):** 测试连接关闭帧的不同类型的字符串表示 (Google QUIC 和 IETF QUIC Transport)。
* **GOAWAY 帧 (GoAway Frame):** 测试 GOAWAY 帧的字符串表示和控制帧 ID 的设置。
* **WINDOW_UPDATE 帧 (Window Update Frame):** 测试窗口更新帧的字符串表示和控制帧 ID 的设置。
* **BLOCKED 帧 (Blocked Frame):** 测试阻塞帧的字符串表示和控制帧 ID 的设置。
* **PING 帧 (Ping Frame):** 测试 PING 帧的字符串表示和控制帧 ID 的设置。
* **HANDSHAKE_DONE 帧 (Handshake Done Frame):** 测试握手完成帧的字符串表示和控制帧 ID 的设置。
* **ACK_FREQUENCY 帧 (Ack Frequency Frame):** 测试 ACK 频率帧的字符串表示和控制帧 ID 的设置。
* **STREAM 帧 (Stream Frame):** 测试流帧的字符串表示。
* **STOP_WAITING 帧 (Stop Waiting Frame):** 测试停止等待帧的字符串表示。

此外，该文件还测试了与 ACK 帧相关的辅助功能，例如：

* **IsAwaitingPacket:** 判断 ACK 帧是否在等待某个数据包的确认。
* **AddPacket:** 向 ACK 帧的确认包列表中添加单个数据包，并测试添加后的区间合并逻辑。
* **AddRange:** 向 ACK 帧的确认包列表中添加一个数据包区间，并测试添加后的区间合并逻辑。
* **RemoveSmallestInterval:** 移除 ACK 帧确认包列表中最小的区间。
* **CopyQuicFrames:** 测试复制 QUIC 帧列表的功能，包括不同类型帧的深拷贝。

最后，该文件还测试了一个名为 `PacketNumberQueue` 的数据结构，它用于存储和管理数据包编号：

* **AddRange:** 向队列中添加一个数据包编号范围。
* **Contains:** 检查队列是否包含特定的数据包编号。
* **Removal (RemoveUpTo):** 从队列中移除指定数据包编号之前的所有数据包。
* **Empty:** 检查队列是否为空。
* **Iterators 和 ReversedIterators:** 测试队列的正向和反向迭代器。

**与 Javascript 的关系：**

虽然这个 C++ 文件本身不包含 JavaScript 代码，但它测试的 QUIC 协议帧是现代网络通信的基础，直接影响着浏览器与服务器之间的数据传输效率和可靠性。JavaScript 代码在浏览器中发起网络请求时，底层可能会使用 QUIC 协议（如果服务器支持且浏览器启用了 QUIC）。

**举例说明：**

假设一个 JavaScript 应用程序通过 `fetch` API 向支持 QUIC 的服务器请求一个资源。浏览器在建立 QUIC 连接后，数据传输会使用各种 QUIC 帧。

* **ACK 帧：**  当服务器发送数据包给浏览器后，浏览器会生成 ACK 帧来确认收到的数据包。这个 C++ 文件中的 `TEST_F(QuicFramesTest, AckFrameToString)` 等测试用例确保了 ACK 帧的结构和信息的正确性，这对于服务器正确理解浏览器的确认至关重要。
* **STREAM 帧：** 服务器会将请求的资源数据分割成多个数据块，并通过 STREAM 帧发送给浏览器。 `TEST_F(QuicFramesTest, StreamFrameToString)` 验证了 STREAM 帧的结构，确保浏览器能够正确解析收到的数据。
* **CONNECTION_CLOSE 帧：** 如果连接出现错误，服务器或浏览器会发送 CONNECTION_CLOSE 帧来关闭连接。 `TEST_F(QuicFramesTest, ConnectionCloseFrameToString)` 测试了不同类型的连接关闭帧的表示，有助于调试连接问题。

**逻辑推理 (假设输入与输出):**

**例子 1: `TEST_F(QuicFramesTest, AckFrameToString)`**

* **假设输入 (frame 内容):**
    * `largest_acked`: 5
    * `ack_delay_time`: 3 微秒
    * `packets`: 确认了数据包 4 和 5
    * `received_packet_times`:  数据包 6 的接收时间戳为 7 微秒
* **预期输出 (stream.str()):**
    ```
    "{ largest_acked: 5, ack_delay_time: 3, packets: [ 4...5  ], received_packets: [ 6 at 7  ], ecn_counters_populated: 0 }\n"
    ```

**例子 2: `TEST_F(PacketNumberQueueTest, AddRange)`**

* **假设输入 (queue 操作):**
    1. 创建一个空的 `PacketNumberQueue`。
    2. 调用 `AddRange(QuicPacketNumber(1), QuicPacketNumber(51))`。
    3. 调用 `Add(QuicPacketNumber(53))`。
* **预期输出 (queue 状态):**
    * `Contains(QuicPacketNumber(1))` 到 `Contains(QuicPacketNumber(50))` 返回 `true`。
    * `Contains(QuicPacketNumber(51))` 和 `Contains(QuicPacketNumber(52))` 返回 `false`。
    * `Contains(QuicPacketNumber(53))` 返回 `true`。
    * `NumPacketsSlow()` 返回 `51`。
    * `Min()` 返回 `QuicPacketNumber(1)`。
    * `Max()` 返回 `QuicPacketNumber(53)`。

**用户或编程常见的使用错误 (举例说明):**

1. **错误地构造 ACK 帧的确认包列表:**  开发者可能手动添加确认的数据包，而没有考虑区间的合并，导致 ACK 帧的大小不必要地增大。例如，分别添加数据包 1, 2, 3 而不是添加一个区间 1...3。  `QuicFramesTest` 中的 `AddPacket` 和 `AddRange` 测试就验证了区间合并的正确性。

2. **错误地设置控制帧 ID:** 对于需要重传的控制帧，开发者可能忘记设置唯一的控制帧 ID。这会导致接收方无法正确处理重复的控制帧。`QuicFramesTest` 中很多测试用例都涉及到 `SetControlFrameId` 和 `GetControlFrameId`，确保了这些操作的正确性。

3. **在处理连接关闭帧时，忽略了 `close_type`:**  开发者可能只检查了 `quic_error_code`，而忽略了 `close_type`，导致无法区分是 Google QUIC 的连接关闭还是 IETF QUIC Transport 的连接关闭，从而可能采取错误的恢复措施。 `QuicFramesTest` 中的 `ConnectionCloseFrameToString` 和 `TransportConnectionCloseFrameToString` 测试了不同类型的连接关闭帧。

**用户操作是如何一步步的到达这里 (作为调试线索):**

1. **用户在浏览器中访问一个 HTTPS 网站 (该网站支持 QUIC 协议):**
2. **浏览器与服务器进行协商，决定使用 QUIC 协议进行通信。**
3. **浏览器发起对网页资源的请求。**
4. **浏览器将请求数据封装成 QUIC 数据包，其中包含 STREAM 帧等。**
5. **服务器收到请求，处理后将响应数据封装成 QUIC 数据包，其中包含 STREAM 帧和 ACK 帧等。**
6. **在数据传输过程中，如果发生丢包或者网络延迟，浏览器和服务器会使用 ACK 帧来确认收到的数据包，并可能发送重传请求。**
7. **如果连接出现错误（例如，网络超时），浏览器或服务器会发送 CONNECTION_CLOSE 帧。**

当开发者在调试 QUIC 连接问题时，可能会需要查看网络抓包，分析 QUIC 数据包中的帧内容。`quic_frames_test.cc` 中的测试用例，尤其是那些涉及帧的字符串表示的测试用例，可以帮助开发者理解和验证抓包中看到的帧结构和信息是否符合预期。如果发现了与预期不符的情况，开发者可以查看 `quic_frames_test.cc` 中的相关测试用例，或者编写新的测试用例来验证 QUIC 帧的编解码逻辑是否存在问题。

这就是第一部分的功能归纳和相关说明。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/frames/quic_frames_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sstream>
#include <vector>

#include "quiche/quic/core/frames/quic_ack_frame.h"
#include "quiche/quic/core/frames/quic_blocked_frame.h"
#include "quiche/quic/core/frames/quic_connection_close_frame.h"
#include "quiche/quic/core/frames/quic_frame.h"
#include "quiche/quic/core/frames/quic_goaway_frame.h"
#include "quiche/quic/core/frames/quic_mtu_discovery_frame.h"
#include "quiche/quic/core/frames/quic_new_connection_id_frame.h"
#include "quiche/quic/core/frames/quic_padding_frame.h"
#include "quiche/quic/core/frames/quic_ping_frame.h"
#include "quiche/quic/core/frames/quic_rst_stream_frame.h"
#include "quiche/quic/core/frames/quic_stop_waiting_frame.h"
#include "quiche/quic/core/frames/quic_stream_frame.h"
#include "quiche/quic/core/frames/quic_window_update_frame.h"
#include "quiche/quic/core/quic_interval.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {
namespace test {
namespace {

class QuicFramesTest : public QuicTest {};

TEST_F(QuicFramesTest, AckFrameToString) {
  QuicAckFrame frame;
  frame.largest_acked = QuicPacketNumber(5);
  frame.ack_delay_time = QuicTime::Delta::FromMicroseconds(3);
  frame.packets.Add(QuicPacketNumber(4));
  frame.packets.Add(QuicPacketNumber(5));
  frame.received_packet_times = {
      {QuicPacketNumber(6),
       QuicTime::Zero() + QuicTime::Delta::FromMicroseconds(7)}};
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ(
      "{ largest_acked: 5, ack_delay_time: 3, packets: [ 4...5  ], "
      "received_packets: [ 6 at 7  ], ecn_counters_populated: 0 }\n",
      stream.str());
  QuicFrame quic_frame(&frame);
  EXPECT_FALSE(IsControlFrame(quic_frame.type));
}

TEST_F(QuicFramesTest, AckFrameToStringMultipleIntervals) {
  QuicAckFrame frame;
  frame.largest_acked = QuicPacketNumber(6);
  frame.ack_delay_time = QuicTime::Delta::FromMicroseconds(3);
  frame.packets.Add(QuicPacketNumber(1));
  frame.packets.Add(QuicPacketNumber(2));
  frame.packets.Add(QuicPacketNumber(3));
  frame.packets.Add(QuicPacketNumber(5));
  frame.packets.Add(QuicPacketNumber(6));
  frame.received_packet_times = {
      {QuicPacketNumber(7),
       QuicTime::Zero() + QuicTime::Delta::FromMicroseconds(7)}};
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ(
      "{ largest_acked: 6, ack_delay_time: 3, packets: [ 1...3 5...6  ], "
      "received_packets: [ 7 at 7  ], ecn_counters_populated: 0 }\n",
      stream.str());
  QuicFrame quic_frame(&frame);
  EXPECT_FALSE(IsControlFrame(quic_frame.type));
}

TEST_F(QuicFramesTest, AckFrameToStringMultipleIntervalsSinglePacketRange) {
  QuicAckFrame frame;
  frame.largest_acked = QuicPacketNumber(6);
  frame.ack_delay_time = QuicTime::Delta::FromMicroseconds(3);
  frame.packets.Add(QuicPacketNumber(1));
  frame.packets.Add(QuicPacketNumber(5));
  frame.packets.Add(QuicPacketNumber(6));
  frame.received_packet_times = {
      {QuicPacketNumber(7),
       QuicTime::Zero() + QuicTime::Delta::FromMicroseconds(7)}};
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ(
      "{ largest_acked: 6, ack_delay_time: 3, packets: [ 1 5...6  ], "
      "received_packets: [ 7 at 7  ], ecn_counters_populated: 0 }\n",
      stream.str());
  QuicFrame quic_frame(&frame);
  EXPECT_FALSE(IsControlFrame(quic_frame.type));
}

TEST_F(QuicFramesTest, BigAckFrameToString) {
  QuicAckFrame frame;
  frame.largest_acked = QuicPacketNumber(500);
  frame.ack_delay_time = QuicTime::Delta::FromMicroseconds(3);
  frame.packets.AddRange(QuicPacketNumber(4), QuicPacketNumber(501));
  frame.received_packet_times = {
      {QuicPacketNumber(500),
       QuicTime::Zero() + QuicTime::Delta::FromMicroseconds(7)}};
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ(
      "{ largest_acked: 500, ack_delay_time: 3, packets: [ 4...500  ], "
      "received_packets: [ 500 at 7  ], ecn_counters_populated: 0 }\n",
      stream.str());
  QuicFrame quic_frame(&frame);
  EXPECT_FALSE(IsControlFrame(quic_frame.type));
}

TEST_F(QuicFramesTest, PaddingFrameToString) {
  QuicPaddingFrame frame;
  frame.num_padding_bytes = 1;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ num_padding_bytes: 1 }\n", stream.str());
  QuicFrame quic_frame(frame);
  EXPECT_FALSE(IsControlFrame(quic_frame.type));
}

TEST_F(QuicFramesTest, RstStreamFrameToString) {
  QuicRstStreamFrame rst_stream;
  QuicFrame frame(&rst_stream);
  SetControlFrameId(1, &frame);
  EXPECT_EQ(1u, GetControlFrameId(frame));
  rst_stream.stream_id = 1;
  rst_stream.byte_offset = 3;
  rst_stream.error_code = QUIC_STREAM_CANCELLED;
  std::ostringstream stream;
  stream << rst_stream;
  EXPECT_EQ(
      "{ control_frame_id: 1, stream_id: 1, byte_offset: 3, error_code: 6, "
      "ietf_error_code: 0 }\n",
      stream.str());
  EXPECT_TRUE(IsControlFrame(frame.type));
}

TEST_F(QuicFramesTest, StopSendingFrameToString) {
  QuicFrame frame((QuicStopSendingFrame()));
  SetControlFrameId(1, &frame);
  EXPECT_EQ(1u, GetControlFrameId(frame));
  frame.stop_sending_frame.stream_id = 321;
  frame.stop_sending_frame.error_code = QUIC_STREAM_CANCELLED;
  frame.stop_sending_frame.ietf_error_code =
      static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_CANCELLED);
  std::ostringstream stream;
  stream << frame.stop_sending_frame;
  EXPECT_EQ(
      "{ control_frame_id: 1, stream_id: 321, error_code: 6, ietf_error_code: "
      "268 }\n",
      stream.str());
}

TEST_F(QuicFramesTest, NewConnectionIdFrameToString) {
  QuicNewConnectionIdFrame new_connection_id_frame;
  QuicFrame frame(&new_connection_id_frame);
  SetControlFrameId(1, &frame);
  QuicFrame frame_copy = CopyRetransmittableControlFrame(frame);
  EXPECT_EQ(1u, GetControlFrameId(frame_copy));
  new_connection_id_frame.connection_id = TestConnectionId(2);
  new_connection_id_frame.sequence_number = 2u;
  new_connection_id_frame.retire_prior_to = 1u;
  new_connection_id_frame.stateless_reset_token =
      StatelessResetToken{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  std::ostringstream stream;
  stream << new_connection_id_frame;
  EXPECT_EQ(
      "{ control_frame_id: 1, connection_id: 0000000000000002, "
      "sequence_number: 2, retire_prior_to: 1 }\n",
      stream.str());
  EXPECT_TRUE(IsControlFrame(frame_copy.type));
  DeleteFrame(&frame_copy);
}

TEST_F(QuicFramesTest, RetireConnectionIdFrameToString) {
  QuicRetireConnectionIdFrame retire_connection_id_frame;
  QuicFrame frame(&retire_connection_id_frame);
  SetControlFrameId(1, &frame);
  QuicFrame frame_copy = CopyRetransmittableControlFrame(frame);
  EXPECT_EQ(1u, GetControlFrameId(frame_copy));
  retire_connection_id_frame.sequence_number = 1u;
  std::ostringstream stream;
  stream << retire_connection_id_frame;
  EXPECT_EQ("{ control_frame_id: 1, sequence_number: 1 }\n", stream.str());
  EXPECT_TRUE(IsControlFrame(frame_copy.type));
  DeleteFrame(&frame_copy);
}

TEST_F(QuicFramesTest, StreamsBlockedFrameToString) {
  QuicStreamsBlockedFrame streams_blocked;
  QuicFrame frame(streams_blocked);
  SetControlFrameId(1, &frame);
  EXPECT_EQ(1u, GetControlFrameId(frame));
  // QuicStreamsBlocked is copied into a QuicFrame (as opposed to putting a
  // pointer to it into QuicFrame) so need to work with the copy in |frame| and
  // not the original one, streams_blocked.
  frame.streams_blocked_frame.stream_count = 321;
  frame.streams_blocked_frame.unidirectional = false;
  std::ostringstream stream;
  stream << frame.streams_blocked_frame;
  EXPECT_EQ("{ control_frame_id: 1, stream count: 321, bidirectional }\n",
            stream.str());
  EXPECT_TRUE(IsControlFrame(frame.type));
}

TEST_F(QuicFramesTest, MaxStreamsFrameToString) {
  QuicMaxStreamsFrame max_streams;
  QuicFrame frame(max_streams);
  SetControlFrameId(1, &frame);
  EXPECT_EQ(1u, GetControlFrameId(frame));
  // QuicMaxStreams is copied into a QuicFrame (as opposed to putting a
  // pointer to it into QuicFrame) so need to work with the copy in |frame| and
  // not the original one, max_streams.
  frame.max_streams_frame.stream_count = 321;
  frame.max_streams_frame.unidirectional = true;
  std::ostringstream stream;
  stream << frame.max_streams_frame;
  EXPECT_EQ("{ control_frame_id: 1, stream_count: 321, unidirectional }\n",
            stream.str());
  EXPECT_TRUE(IsControlFrame(frame.type));
}

TEST_F(QuicFramesTest, ConnectionCloseFrameToString) {
  QuicConnectionCloseFrame frame;
  frame.quic_error_code = QUIC_NETWORK_IDLE_TIMEOUT;
  frame.error_details = "No recent network activity.";
  std::ostringstream stream;
  stream << frame;
  // Note that "extracted_error_code: 122" is QUIC_IETF_GQUIC_ERROR_MISSING,
  // indicating that, in fact, no extended error code was available from the
  // underlying frame.
  EXPECT_EQ(
      "{ Close type: GOOGLE_QUIC_CONNECTION_CLOSE, "
      "quic_error_code: QUIC_NETWORK_IDLE_TIMEOUT, "
      "error_details: 'No recent network activity.'}\n",
      stream.str());
  QuicFrame quic_frame(&frame);
  EXPECT_FALSE(IsControlFrame(quic_frame.type));
}

TEST_F(QuicFramesTest, TransportConnectionCloseFrameToString) {
  QuicConnectionCloseFrame frame;
  frame.close_type = IETF_QUIC_TRANSPORT_CONNECTION_CLOSE;
  frame.wire_error_code = FINAL_SIZE_ERROR;
  frame.quic_error_code = QUIC_NETWORK_IDLE_TIMEOUT;
  frame.error_details = "No recent network activity.";
  frame.transport_close_frame_type = IETF_STREAM;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ(
      "{ Close type: IETF_QUIC_TRANSPORT_CONNECTION_CLOSE, "
      "wire_error_code: FINAL_SIZE_ERROR, "
      "quic_error_code: QUIC_NETWORK_IDLE_TIMEOUT, "
      "error_details: 'No recent "
      "network activity.', "
      "frame_type: IETF_STREAM"
      "}\n",
      stream.str());
  QuicFrame quic_frame(&frame);
  EXPECT_FALSE(IsControlFrame(quic_frame.type));
}

TEST_F(QuicFramesTest, GoAwayFrameToString) {
  QuicGoAwayFrame goaway_frame;
  QuicFrame frame(&goaway_frame);
  SetControlFrameId(2, &frame);
  EXPECT_EQ(2u, GetControlFrameId(frame));
  goaway_frame.error_code = QUIC_NETWORK_IDLE_TIMEOUT;
  goaway_frame.last_good_stream_id = 2;
  goaway_frame.reason_phrase = "Reason";
  std::ostringstream stream;
  stream << goaway_frame;
  EXPECT_EQ(
      "{ control_frame_id: 2, error_code: 25, last_good_stream_id: 2, "
      "reason_phrase: "
      "'Reason' }\n",
      stream.str());
  EXPECT_TRUE(IsControlFrame(frame.type));
}

TEST_F(QuicFramesTest, WindowUpdateFrameToString) {
  QuicFrame frame((QuicWindowUpdateFrame()));
  SetControlFrameId(3, &frame);
  EXPECT_EQ(3u, GetControlFrameId(frame));
  std::ostringstream stream;
  frame.window_update_frame.stream_id = 1;
  frame.window_update_frame.max_data = 2;
  stream << frame.window_update_frame;
  EXPECT_EQ("{ control_frame_id: 3, stream_id: 1, max_data: 2 }\n",
            stream.str());
  EXPECT_TRUE(IsControlFrame(frame.type));
}

TEST_F(QuicFramesTest, BlockedFrameToString) {
  QuicFrame frame((QuicBlockedFrame()));
  SetControlFrameId(4, &frame);
  EXPECT_EQ(4u, GetControlFrameId(frame));
  frame.blocked_frame.stream_id = 1;
  frame.blocked_frame.offset = 2;
  std::ostringstream stream;
  stream << frame.blocked_frame;
  EXPECT_EQ("{ control_frame_id: 4, stream_id: 1, offset: 2 }\n", stream.str());
  EXPECT_TRUE(IsControlFrame(frame.type));
}

TEST_F(QuicFramesTest, PingFrameToString) {
  QuicPingFrame ping;
  QuicFrame frame(ping);
  SetControlFrameId(5, &frame);
  EXPECT_EQ(5u, GetControlFrameId(frame));
  std::ostringstream stream;
  stream << frame.ping_frame;
  EXPECT_EQ("{ control_frame_id: 5 }\n", stream.str());
  EXPECT_TRUE(IsControlFrame(frame.type));
}

TEST_F(QuicFramesTest, HandshakeDoneFrameToString) {
  QuicHandshakeDoneFrame handshake_done;
  QuicFrame frame(handshake_done);
  SetControlFrameId(6, &frame);
  EXPECT_EQ(6u, GetControlFrameId(frame));
  std::ostringstream stream;
  stream << frame.handshake_done_frame;
  EXPECT_EQ("{ control_frame_id: 6 }\n", stream.str());
  EXPECT_TRUE(IsControlFrame(frame.type));
}

TEST_F(QuicFramesTest, QuicAckFreuqncyFrameToString) {
  QuicAckFrequencyFrame ack_frequency_frame;
  ack_frequency_frame.sequence_number = 1;
  ack_frequency_frame.packet_tolerance = 2;
  ack_frequency_frame.max_ack_delay = QuicTime::Delta::FromMilliseconds(25);
  ack_frequency_frame.ignore_order = false;
  QuicFrame frame(&ack_frequency_frame);
  ASSERT_EQ(ACK_FREQUENCY_FRAME, frame.type);
  SetControlFrameId(6, &frame);
  EXPECT_EQ(6u, GetControlFrameId(frame));
  std::ostringstream stream;
  stream << *frame.ack_frequency_frame;
  EXPECT_EQ(
      "{ control_frame_id: 6, sequence_number: 1, packet_tolerance: 2, "
      "max_ack_delay_ms: 25, ignore_order: 0 }\n",
      stream.str());
  EXPECT_TRUE(IsControlFrame(frame.type));
}

TEST_F(QuicFramesTest, StreamFrameToString) {
  QuicStreamFrame frame;
  frame.stream_id = 1;
  frame.fin = false;
  frame.offset = 2;
  frame.data_length = 3;
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ stream_id: 1, fin: 0, offset: 2, length: 3 }\n", stream.str());
  EXPECT_FALSE(IsControlFrame(frame.type));
}

TEST_F(QuicFramesTest, StopWaitingFrameToString) {
  QuicStopWaitingFrame frame;
  frame.least_unacked = QuicPacketNumber(2);
  std::ostringstream stream;
  stream << frame;
  EXPECT_EQ("{ least_unacked: 2 }\n", stream.str());
  QuicFrame quic_frame(frame);
  EXPECT_FALSE(IsControlFrame(quic_frame.type));
}

TEST_F(QuicFramesTest, IsAwaitingPacket) {
  QuicAckFrame ack_frame1;
  ack_frame1.largest_acked = QuicPacketNumber(10u);
  ack_frame1.packets.AddRange(QuicPacketNumber(1), QuicPacketNumber(11));
  EXPECT_TRUE(
      IsAwaitingPacket(ack_frame1, QuicPacketNumber(11u), QuicPacketNumber()));
  EXPECT_FALSE(
      IsAwaitingPacket(ack_frame1, QuicPacketNumber(1u), QuicPacketNumber()));

  ack_frame1.packets.Add(QuicPacketNumber(12));
  EXPECT_TRUE(
      IsAwaitingPacket(ack_frame1, QuicPacketNumber(11u), QuicPacketNumber()));

  QuicAckFrame ack_frame2;
  ack_frame2.largest_acked = QuicPacketNumber(100u);
  ack_frame2.packets.AddRange(QuicPacketNumber(21), QuicPacketNumber(100));
  EXPECT_FALSE(IsAwaitingPacket(ack_frame2, QuicPacketNumber(11u),
                                QuicPacketNumber(20u)));
  EXPECT_FALSE(IsAwaitingPacket(ack_frame2, QuicPacketNumber(80u),
                                QuicPacketNumber(20u)));
  EXPECT_TRUE(IsAwaitingPacket(ack_frame2, QuicPacketNumber(101u),
                               QuicPacketNumber(20u)));

  ack_frame2.packets.AddRange(QuicPacketNumber(102), QuicPacketNumber(200));
  EXPECT_TRUE(IsAwaitingPacket(ack_frame2, QuicPacketNumber(101u),
                               QuicPacketNumber(20u)));
}

TEST_F(QuicFramesTest, AddPacket) {
  QuicAckFrame ack_frame1;
  ack_frame1.packets.Add(QuicPacketNumber(1));
  ack_frame1.packets.Add(QuicPacketNumber(99));

  EXPECT_EQ(2u, ack_frame1.packets.NumIntervals());
  EXPECT_EQ(QuicPacketNumber(1u), ack_frame1.packets.Min());
  EXPECT_EQ(QuicPacketNumber(99u), ack_frame1.packets.Max());

  std::vector<QuicInterval<QuicPacketNumber>> expected_intervals;
  expected_intervals.emplace_back(
      QuicInterval<QuicPacketNumber>(QuicPacketNumber(1), QuicPacketNumber(2)));
  expected_intervals.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(99), QuicPacketNumber(100)));

  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals(
      ack_frame1.packets.begin(), ack_frame1.packets.end());

  EXPECT_EQ(expected_intervals, actual_intervals);

  ack_frame1.packets.Add(QuicPacketNumber(20));
  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals2(
      ack_frame1.packets.begin(), ack_frame1.packets.end());

  std::vector<QuicInterval<QuicPacketNumber>> expected_intervals2;
  expected_intervals2.emplace_back(
      QuicInterval<QuicPacketNumber>(QuicPacketNumber(1), QuicPacketNumber(2)));
  expected_intervals2.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(20), QuicPacketNumber(21)));
  expected_intervals2.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(99), QuicPacketNumber(100)));

  EXPECT_EQ(3u, ack_frame1.packets.NumIntervals());
  EXPECT_EQ(expected_intervals2, actual_intervals2);

  ack_frame1.packets.Add(QuicPacketNumber(19));
  ack_frame1.packets.Add(QuicPacketNumber(21));

  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals3(
      ack_frame1.packets.begin(), ack_frame1.packets.end());

  std::vector<QuicInterval<QuicPacketNumber>> expected_intervals3;
  expected_intervals3.emplace_back(
      QuicInterval<QuicPacketNumber>(QuicPacketNumber(1), QuicPacketNumber(2)));
  expected_intervals3.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(19), QuicPacketNumber(22)));
  expected_intervals3.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(99), QuicPacketNumber(100)));

  EXPECT_EQ(expected_intervals3, actual_intervals3);

  ack_frame1.packets.Add(QuicPacketNumber(20));

  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals4(
      ack_frame1.packets.begin(), ack_frame1.packets.end());

  EXPECT_EQ(expected_intervals3, actual_intervals4);

  QuicAckFrame ack_frame2;
  ack_frame2.packets.Add(QuicPacketNumber(20));
  ack_frame2.packets.Add(QuicPacketNumber(40));
  ack_frame2.packets.Add(QuicPacketNumber(60));
  ack_frame2.packets.Add(QuicPacketNumber(10));
  ack_frame2.packets.Add(QuicPacketNumber(80));

  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals5(
      ack_frame2.packets.begin(), ack_frame2.packets.end());

  std::vector<QuicInterval<QuicPacketNumber>> expected_intervals5;
  expected_intervals5.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(10), QuicPacketNumber(11)));
  expected_intervals5.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(20), QuicPacketNumber(21)));
  expected_intervals5.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(40), QuicPacketNumber(41)));
  expected_intervals5.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(60), QuicPacketNumber(61)));
  expected_intervals5.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(80), QuicPacketNumber(81)));

  EXPECT_EQ(expected_intervals5, actual_intervals5);
}

TEST_F(QuicFramesTest, AddInterval) {
  QuicAckFrame ack_frame1;
  ack_frame1.packets.AddRange(QuicPacketNumber(1), QuicPacketNumber(10));
  ack_frame1.packets.AddRange(QuicPacketNumber(50), QuicPacketNumber(100));

  EXPECT_EQ(2u, ack_frame1.packets.NumIntervals());
  EXPECT_EQ(QuicPacketNumber(1u), ack_frame1.packets.Min());
  EXPECT_EQ(QuicPacketNumber(99u), ack_frame1.packets.Max());

  std::vector<QuicInterval<QuicPacketNumber>> expected_intervals{
      {QuicPacketNumber(1), QuicPacketNumber(10)},
      {QuicPacketNumber(50), QuicPacketNumber(100)},
  };

  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals(
      ack_frame1.packets.begin(), ack_frame1.packets.end());

  EXPECT_EQ(expected_intervals, actual_intervals);

  // Add a range in the middle.
  ack_frame1.packets.AddRange(QuicPacketNumber(20), QuicPacketNumber(30));

  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals2(
      ack_frame1.packets.begin(), ack_frame1.packets.end());

  std::vector<QuicInterval<QuicPacketNumber>> expected_intervals2{
      {QuicPacketNumber(1), QuicPacketNumber(10)},
      {QuicPacketNumber(20), QuicPacketNumber(30)},
      {QuicPacketNumber(50), QuicPacketNumber(100)},
  };

  EXPECT_EQ(expected_intervals2.size(), ack_frame1.packets.NumIntervals());
  EXPECT_EQ(expected_intervals2, actual_intervals2);

  // Add ranges at both ends.
  QuicAckFrame ack_frame2;
  ack_frame2.packets.AddRange(QuicPacketNumber(20), QuicPacketNumber(25));
  ack_frame2.packets.AddRange(QuicPacketNumber(40), QuicPacketNumber(45));
  ack_frame2.packets.AddRange(QuicPacketNumber(60), QuicPacketNumber(65));
  ack_frame2.packets.AddRange(QuicPacketNumber(10), QuicPacketNumber(15));
  ack_frame2.packets.AddRange(QuicPacketNumber(80), QuicPacketNumber(85));

  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals8(
      ack_frame2.packets.begin(), ack_frame2.packets.end());

  std::vector<QuicInterval<QuicPacketNumber>> expected_intervals8{
      {QuicPacketNumber(10), QuicPacketNumber(15)},
      {QuicPacketNumber(20), QuicPacketNumber(25)},
      {QuicPacketNumber(40), QuicPacketNumber(45)},
      {QuicPacketNumber(60), QuicPacketNumber(65)},
      {QuicPacketNumber(80), QuicPacketNumber(85)},
  };

  EXPECT_EQ(expected_intervals8, actual_intervals8);
}

TEST_F(QuicFramesTest, AddAdjacentForward) {
  QuicAckFrame ack_frame1;
  ack_frame1.packets.Add(QuicPacketNumber(49));
  ack_frame1.packets.AddRange(QuicPacketNumber(50), QuicPacketNumber(60));
  ack_frame1.packets.AddRange(QuicPacketNumber(60), QuicPacketNumber(70));
  ack_frame1.packets.AddRange(QuicPacketNumber(70), QuicPacketNumber(100));

  std::vector<QuicInterval<QuicPacketNumber>> expected_intervals;
  expected_intervals.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(49), QuicPacketNumber(100)));

  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals(
      ack_frame1.packets.begin(), ack_frame1.packets.end());

  EXPECT_EQ(expected_intervals, actual_intervals);
}

TEST_F(QuicFramesTest, AddAdjacentReverse) {
  QuicAckFrame ack_frame1;
  ack_frame1.packets.AddRange(QuicPacketNumber(70), QuicPacketNumber(100));
  ack_frame1.packets.AddRange(QuicPacketNumber(60), QuicPacketNumber(70));
  ack_frame1.packets.AddRange(QuicPacketNumber(50), QuicPacketNumber(60));
  ack_frame1.packets.Add(QuicPacketNumber(49));

  std::vector<QuicInterval<QuicPacketNumber>> expected_intervals;
  expected_intervals.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(49), QuicPacketNumber(100)));

  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals(
      ack_frame1.packets.begin(), ack_frame1.packets.end());

  EXPECT_EQ(expected_intervals, actual_intervals);
}

TEST_F(QuicFramesTest, RemoveSmallestInterval) {
  QuicAckFrame ack_frame1;
  ack_frame1.largest_acked = QuicPacketNumber(100u);
  ack_frame1.packets.AddRange(QuicPacketNumber(51), QuicPacketNumber(60));
  ack_frame1.packets.AddRange(QuicPacketNumber(71), QuicPacketNumber(80));
  ack_frame1.packets.AddRange(QuicPacketNumber(91), QuicPacketNumber(100));
  ack_frame1.packets.RemoveSmallestInterval();
  EXPECT_EQ(2u, ack_frame1.packets.NumIntervals());
  EXPECT_EQ(QuicPacketNumber(71u), ack_frame1.packets.Min());
  EXPECT_EQ(QuicPacketNumber(99u), ack_frame1.packets.Max());

  ack_frame1.packets.RemoveSmallestInterval();
  EXPECT_EQ(1u, ack_frame1.packets.NumIntervals());
  EXPECT_EQ(QuicPacketNumber(91u), ack_frame1.packets.Min());
  EXPECT_EQ(QuicPacketNumber(99u), ack_frame1.packets.Max());
}

TEST_F(QuicFramesTest, CopyQuicFrames) {
  QuicFrames frames;
  QuicMessageFrame* message_frame =
      new QuicMessageFrame(1, MemSliceFromString("message"));
  // Construct a frame list.
  for (uint8_t i = 0; i < NUM_FRAME_TYPES; ++i) {
    switch (i) {
      case PADDING_FRAME:
        frames.push_back(QuicFrame(QuicPaddingFrame(-1)));
        break;
      case RST_STREAM_FRAME:
        frames.push_back(QuicFrame(new QuicRstStreamFrame()));
        break;
      case CONNECTION_CLOSE_FRAME:
        frames.push_back(QuicFrame(new QuicConnectionCloseFrame()));
        break;
      case GOAWAY_FRAME:
        frames.push_back(QuicFrame(new QuicGoAwayFrame()));
        break;
      case WINDOW_UPDATE_FRAME:
        frames.push_back(QuicFrame(QuicWindowUpdateFrame()));
        break;
      case BLOCKED_FRAME:
        frames.push_back(QuicFrame(QuicBlockedFrame()));
        break;
      case STOP_WAITING_FRAME:
        frames.push_back(QuicFrame(QuicStopWaitingFrame()));
        break;
      case PING_FRAME:
        frames.push_back(QuicFrame(QuicPingFrame()));
        break;
      case CRYPTO_FRAME:
        frames.push_back(QuicFrame(new QuicCryptoFrame()));
        break;
      case STREAM_FRAME:
        frames.push_back(QuicFrame(QuicStreamFrame()));
        break;
      case ACK_FRAME:
        frames.push_back(QuicFrame(new QuicAckFrame()));
        break;
      case MTU_DISCOVERY_FRAME:
        frames.push_back(QuicFrame(QuicMtuDiscoveryFrame()));
        break;
      case NEW_CONNECTION_ID_FRAME:
        frames.push_back(QuicFrame(new QuicNewConnectionIdFrame()));
        break;
      case MAX_STREAMS_FRAME:
        frames.push_back(QuicFrame(QuicMaxStreamsFrame()));
        break;
      case STREAMS_BLOCKED_FRAME:
        frames.push_back(QuicFrame(QuicStreamsBlockedFrame()));
        break;
      case PATH_RESPONSE_FRAME:
        frames.push_back(QuicFrame(QuicPathResponseFrame()));
        break;
      case PATH_CHALLENGE_FRAME:
        frames.push_back(QuicFrame(QuicPathChallengeFrame()));
        break;
      case STOP_SENDING_FRAME:
        frames.push_back(QuicFrame(QuicStopSendingFrame()));
        break;
      case MESSAGE_FRAME:
        frames.push_back(QuicFrame(message_frame));
        break;
      case NEW_TOKEN_FRAME:
        frames.push_back(QuicFrame(new QuicNewTokenFrame()));
        break;
      case RETIRE_CONNECTION_ID_FRAME:
        frames.push_back(QuicFrame(new QuicRetireConnectionIdFrame()));
        break;
      case HANDSHAKE_DONE_FRAME:
        frames.push_back(QuicFrame(QuicHandshakeDoneFrame()));
        break;
      case ACK_FREQUENCY_FRAME:
        frames.push_back(QuicFrame(new QuicAckFrequencyFrame()));
        break;
      case RESET_STREAM_AT_FRAME:
        frames.push_back(QuicFrame(new QuicResetStreamAtFrame()));
        break;
      default:
        ASSERT_TRUE(false)
            << "Please fix CopyQuicFrames if a new frame type is added.";
        break;
    }
  }

  QuicFrames copy =
      CopyQuicFrames(quiche::SimpleBufferAllocator::Get(), frames);
  ASSERT_EQ(NUM_FRAME_TYPES, copy.size());
  for (uint8_t i = 0; i < NUM_FRAME_TYPES; ++i) {
    EXPECT_EQ(i, copy[i].type);
    if (i == MESSAGE_FRAME) {
      // Verify message frame is correctly copied.
      EXPECT_EQ(1u, copy[i].message_frame->message_id);
      EXPECT_EQ(nullptr, copy[i].message_frame->data);
      EXPECT_EQ(7u, copy[i].message_frame->message_length);
      ASSERT_EQ(1u, copy[i].message_frame->message_data.size());
      EXPECT_EQ(0, memcmp(copy[i].message_frame->message_data[0].data(),
                          frames[i].message_frame->message_data[0].data(), 7));
    } else if (i == PATH_CHALLENGE_FRAME) {
      EXPECT_EQ(copy[i].path_challenge_frame.control_frame_id,
                frames[i].path_challenge_frame.control_frame_id);
      EXPECT_EQ(memcmp(&copy[i].path_challenge_frame.data_buffer,
                       &frames[i].path_challenge_frame.data_buffer,
                       copy[i].path_challenge_frame.data_buffer.size()),
                0);
    } else if (i == PATH_RESPONSE_FRAME) {
      EXPECT_EQ(copy[i].path_response_frame.control_frame_id,
                frames[i].path_response_frame.control_frame_id);
      EXPECT_EQ(memcmp(&copy[i].path_response_frame.data_buffer,
                       &frames[i].path_response_frame.data_buffer,
                       copy[i].path_response_frame.data_buffer.size()),
                0);
    }
  }
  DeleteFrames(&frames);
  DeleteFrames(&copy);
}

class PacketNumberQueueTest : public QuicTest {};

// Tests that a queue contains the expected data after calls to Add().
TEST_F(PacketNumberQueueTest, AddRange) {
  PacketNumberQueue queue;
  queue.AddRange(QuicPacketNumber(1), QuicPacketNumber(51));
  queue.Add(QuicPacketNumber(53));

  EXPECT_FALSE(queue.Contains(QuicPacketNumber()));
  for (int i = 1; i < 51; ++i) {
    EXPECT_TRUE(queue.Contains(QuicPacketNumber(i)));
  }
  EXPECT_FALSE(queue.Contains(QuicPacketNumber(51)));
  EXPECT_FALSE(queue.Contains(QuicPacketNumber(52)));
  EXPECT_TRUE(queue.Contains(QuicPacketNumber(53)));
  EXPECT_FALSE(queue.Contains(QuicPacketNumber(54)));
  EXPECT_EQ(51u, queue.NumPacketsSlow());
  EXPECT_EQ(QuicPacketNumber(1u), queue.Min());
  EXPECT_EQ(QuicPacketNumber(53u), queue.Max());

  queue.Add(QuicPacketNumber(70));
  EXPECT_EQ(QuicPacketNumber(70u), queue.Max());
}

// Tests Contains function
TEST_F(PacketNumberQueueTest, Contains) {
  PacketNumberQueue queue;
  EXPECT_FALSE(queue.Contains(QuicPacketNumber()));
  queue.AddRange(QuicPacketNumber(5), QuicPacketNumber(10));
  queue.Add(QuicPacketNumber(20));

  for (int i = 1; i < 5; ++i) {
    EXPECT_FALSE(queue.Contains(QuicPacketNumber(i)));
  }

  for (int i = 5; i < 10; ++i) {
    EXPECT_TRUE(queue.Contains(QuicPacketNumber(i)));
  }
  for (int i = 10; i < 20; ++i) {
    EXPECT_FALSE(queue.Contains(QuicPacketNumber(i)));
  }
  EXPECT_TRUE(queue.Contains(QuicPacketNumber(20)));
  EXPECT_FALSE(queue.Contains(QuicPacketNumber(21)));

  PacketNumberQueue queue2;
  EXPECT_FALSE(queue2.Contains(QuicPacketNumber(1)));
  for (int i = 1; i < 51; ++i) {
    queue2.Add(QuicPacketNumber(2 * i));
  }
  EXPECT_FALSE(queue2.Contains(QuicPacketNumber()));
  for (int i = 1; i < 51; ++i) {
    if (i % 2 == 0) {
      EXPECT_TRUE(queue2.Contains(QuicPacketNumber(i)));
    } else {
      EXPECT_FALSE(queue2.Contains(QuicPacketNumber(i)));
    }
  }
  EXPECT_FALSE(queue2.Contains(QuicPacketNumber(101)));
}

// Tests that a queue contains the expected data after calls to RemoveUpTo().
TEST_F(PacketNumberQueueTest, Removal) {
  PacketNumberQueue queue;
  EXPECT_FALSE(queue.Contains(QuicPacketNumber(51)));
  queue.AddRange(QuicPacketNumber(1), QuicPacketNumber(100));

  EXPECT_TRUE(queue.RemoveUpTo(QuicPacketNumber(51)));
  EXPECT_FALSE(queue.RemoveUpTo(QuicPacketNumber(51)));

  EXPECT_FALSE(queue.Contains(QuicPacketNumber()));
  for (int i = 1; i < 51; ++i) {
    EXPECT_FALSE(queue.Contains(QuicPacketNumber(i)));
  }
  for (int i = 51; i < 100; ++i) {
    EXPECT_TRUE(queue.Contains(QuicPacketNumber(i)));
  }
  EXPECT_EQ(49u, queue.NumPacketsSlow());
  EXPECT_EQ(QuicPacketNumber(51u), queue.Min());
  EXPECT_EQ(QuicPacketNumber(99u), queue.Max());

  PacketNumberQueue queue2;
  queue2.AddRange(QuicPacketNumber(1), QuicPacketNumber(5));
  EXPECT_TRUE(queue2.RemoveUpTo(QuicPacketNumber(3)));
  EXPECT_TRUE(queue2.RemoveUpTo(QuicPacketNumber(50)));
  EXPECT_TRUE(queue2.Empty());
}

// Tests that a queue is empty when all of its elements are removed.
TEST_F(PacketNumberQueueTest, Empty) {
  PacketNumberQueue queue;
  EXPECT_TRUE(queue.Empty());
  EXPECT_EQ(0u, queue.NumPacketsSlow());

  queue.AddRange(QuicPacketNumber(1), QuicPacketNumber(100));
  EXPECT_TRUE(queue.RemoveUpTo(QuicPacketNumber(100)));
  EXPECT_TRUE(queue.Empty());
  EXPECT_EQ(0u, queue.NumPacketsSlow());
}

// Tests that logging the state of a PacketNumberQueue does not crash.
TEST_F(PacketNumberQueueTest, LogDoesNotCrash) {
  std::ostringstream oss;
  PacketNumberQueue queue;
  oss << queue;

  queue.Add(QuicPacketNumber(1));
  queue.AddRange(QuicPacketNumber(50), QuicPacketNumber(100));
  oss << queue;
}

// Tests that the iterators returned from a packet queue iterate over the queue.
TEST_F(PacketNumberQueueTest, Iterators) {
  PacketNumberQueue queue;
  queue.AddRange(QuicPacketNumber(1), QuicPacketNumber(100));

  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals(
      queue.begin(), queue.end());

  PacketNumberQueue queue2;
  for (int i = 1; i < 100; i++) {
    queue2.AddRange(QuicPacketNumber(i), QuicPacketNumber(i + 1));
  }

  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals2(
      queue2.begin(), queue2.end());

  std::vector<QuicInterval<QuicPacketNumber>> expected_intervals;
  expected_intervals.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(1), QuicPacketNumber(100)));
  EXPECT_EQ(expected_intervals, actual_intervals);
  EXPECT_EQ(expected_intervals, actual_intervals2);
  EXPECT_EQ(actual_intervals, actual_intervals2);
}

TEST_F(PacketNumberQueueTest, ReversedIterators) {
  PacketNumberQueue queue;
  queue.AddRange(QuicPacketNumber(1), QuicPacketNumber(100));
  PacketNumberQueue queue2;
  for (int i = 1; i < 100; i++) {
    queue2.AddRange(QuicPacketNumber(i), QuicPacketNumber(i + 1));
  }
  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals(
      queue.rbegin(), queue.rend());
  const std::vector<QuicInterval<QuicPacketNumber>> actual_intervals2(
      queue2.rbegin(), queue2.rend());

  std::vector<QuicInterval<QuicPacketNumber>> expected_intervals;
  expected_intervals.emplace_back(QuicInterval<QuicPacketNumber>(
      QuicPacketNumber(1), QuicPacketNumber(100
"""


```