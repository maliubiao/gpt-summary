Response:
The user is asking for a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc`. This file appears to be a unit test suite for the `QuicConnection` class in the Chromium QUIC implementation.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Purpose:** The filename ends with `_test.cc`, strongly suggesting this is a unit test file. The path components (`quiche/quic/core`) further indicate that it's testing core QUIC functionality. Specifically, it tests the `QuicConnection` class.

2. **Analyze Test Case Names:**  The provided code snippets contain various `TEST_P` macros. The names of these test cases are very descriptive and provide strong clues about the functionality being tested. Look for common themes or prefixes. In this case, there are many tests related to MTU discovery (`MtuDiscovery...`) and timeouts (`Timeout...`).

3. **Infer Functionality from Test Case Logic:** Even without knowing the exact implementation details of `QuicConnection`, the code within the test cases reveals how it's expected to behave. For instance:
    * **MTU Discovery Tests:**  They involve sending packets of varying sizes, simulating write errors (packet too large, write blocked), and verifying how the connection adjusts its maximum packet size.
    * **Timeout Tests:** These tests manipulate the clock, send and receive data, and check if the connection closes correctly after a certain idle period.

4. **Look for Setup and Teardown:**  While not explicitly shown in the snippet, unit tests often have setup and teardown methods (like the `MtuDiscoveryTestInit()` call). These give context to the test scenarios.

5. **Consider the Role of Mock Objects:**  The presence of `EXPECT_CALL` and `visitor_` suggests the use of mocking frameworks (like Google Mock). This implies the tests are isolating the `QuicConnection` and controlling the behavior of its dependencies (like the visitor interface).

6. **Identify Key Concepts:** Based on the test cases, several key QUIC concepts are being tested:
    * Connection lifecycle (opening, closing, error handling)
    * Path MTU Discovery (probing, handling acknowledgements, handling failures)
    * Idle timeouts
    * Packet sending and queuing
    * Congestion control (implied by interactions with `send_algorithm_`)

7. **Relate to JavaScript (If Applicable):**  Think about where QUIC is used in web browsers. JavaScript interacts with the network stack indirectly through browser APIs (like `fetch`). Consider scenarios where the tested functionalities would have observable effects from a JavaScript perspective. For instance, if MTU discovery fails, it might lead to slower data transfer, which could be indirectly observed by JavaScript applications. However, the direct low-level details of MTU discovery are usually abstracted away.

8. **Consider User Errors:** Think about common mistakes developers might make when using a QUIC library or when network conditions are unusual. For example, unexpected write errors or network delays could trigger the MTU discovery or timeout mechanisms being tested.

9. **Construct Example Scenarios:**  For logic推理,  create simplified scenarios with specific inputs and expected outputs. This helps illustrate the behavior being tested.

10. **Relate to Debugging:**  Think about how a developer might end up inspecting this code during debugging. What user actions or network events could lead to the execution of these code paths?

11. **Address the "Part X of Y" Instruction:** Acknowledge the context that this is part of a larger set of files and try to summarize the specific focus of this part.

**Self-Correction/Refinement:**

* **Initial thought:**  Focus heavily on the individual test cases.
* **Refinement:**  Elevate to a higher level and summarize the *categories* of functionality being tested. Individual test cases are examples, not the core summary.
* **Initial thought:**  Overemphasize the direct link to JavaScript.
* **Refinement:**  Acknowledge the relationship is indirect and focus on the user-observable effects rather than low-level API interaction.
* **Initial thought:**  Focus only on the code snippets provided.
* **Refinement:**  Infer broader context based on standard unit testing practices and common QUIC concepts.
这个C++源代码文件 `net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的单元测试文件，专门用于测试 `QuicConnection` 类的各项功能。作为第 8 部分（共 24 部分），它主要关注 `QuicConnection` 中与 **路径最大传输单元发现 (MTU Discovery)** 和 **连接超时管理** 相关的测试。

以下是该文件主要功能的详细列表：

**1. 路径 MTU 发现 (MTU Discovery) 测试:**

* **启动和成功 MTU 探测:** 测试连接如何启动 MTU 探测，发送探测包，并根据收到的 ACK 确认探测成功，从而增加连接的最大包大小。
* **处理写入错误:** 测试在 MTU 探测过程中遇到写入错误（例如，探测包过大）时连接的行为，包括忽略首次写入错误和在连续写入错误后关闭连接。
* **处理写入阻塞:** 模拟在发送 MTU 探测包时遇到写入阻塞的情况，以及后续如何处理 `MSG_TOO_BIG` 错误。
* **MTU 发现失败:** 测试在 MTU 探测包没有被确认的情况下，连接如何退回到默认的最大包大小，并进行多次探测尝试。
* **部分成功的 MTU 探测:** 测试 MTU 探测过程中，部分探测成功（增加 MTU），然后失败，然后再成功的情况，验证连接如何调整 MTU 值。
* **受限的写入器:** 模拟写入器对最大包大小有限制的情况，测试 MTU 发现如何在这种限制下工作。
* **写入器返回错误:** 测试即使声明了更大的包长度，但写入器实际返回错误时，MTU 发现的行为。
* **连接关闭后不进行 MTU 发现:** 确保在连接关闭后不会再触发 MTU 发现。

**2. 连接超时管理测试:**

* **握手期间超时:** 测试在连接握手过程中，发送数据后连接如何设置和触发超时，以及超时后的行为。
* **握手完成后超时:** 测试在连接握手完成后，发送数据后连接如何设置和触发超时，以及默认的静默关闭行为（不发送连接关闭包）。
* **有打开的流时的静默关闭超时:**  测试在握手完成后，即使有打开的流，连接在超时后仍然可以执行静默关闭（可以通过配置发送连接关闭帧）。
* **接收数据后超时:** 测试接收到数据后，连接如何更新超时时间，以及在超时后关闭连接的行为。
* **接收数据后超时，但未发送数据:** 测试接收到数据后，即使有未确认的发送数据，连接仍然会触发超时并关闭。

**3. 其他功能测试:**

* **发送调度器:** 测试发送没有延迟的数据包时，它不会被放入队列。
* **发送第一个数据包失败:** 测试在发送第一个数据包失败时，连接是否能正常处理，避免崩溃。

**与 JavaScript 的关系：**

这个 C++ 文件直接测试的是 Chromium 浏览器内核中 QUIC 协议的底层实现，与 JavaScript 没有直接的代码层面上的关系。然而，这些底层功能的正确性直接影响到基于浏览器的 JavaScript 应用的网络性能和稳定性。

例如：

* **MTU Discovery 的成功与否会影响 JavaScript 应用的加载速度。** 如果 MTU 发现成功，可以使用更大的数据包传输数据，减少网络往返次数，从而加速页面加载和资源下载。反之，如果 MTU 发现失败，则会使用较小的默认包大小，传输效率降低。
* **连接超时管理影响用户体验。** 如果连接超时设置不合理，可能导致 JavaScript 应用在网络短暂中断后无法恢复，需要重新建立连接，影响用户体验。

**逻辑推理、假设输入与输出：**

**示例：MTU 发现成功测试**

* **假设输入:**
    * 连接初始最大包大小为 1200 字节。
    * 连接配置启用了 MTU 发现。
    * 网络路径支持更大的包大小。
    * 接收到对 MTU 探测包的 ACK。
* **预期输出:**
    * 连接的最大包大小会增加到探测包的大小（例如，1400 字节）。
    * `connection_.max_packet_length()` 返回新的最大包大小。

**示例：握手期间超时测试**

* **假设输入:**
    * 连接处于握手阶段。
    * 设置了初始空闲超时时间。
    * 发送了一些数据包。
    * 在超时时间内没有收到任何数据。
* **预期输出:**
    * 超时定时器触发。
    * 连接状态变为关闭。
    * `visitor_.OnConnectionClosed()` 被调用，错误码为 `QUIC_NETWORK_IDLE_TIMEOUT`。

**用户或编程常见的使用错误：**

* **配置不当的超时时间:**  如果开发者或系统管理员配置了过短的超时时间，可能会导致连接在网络波动或延迟较高的情况下意外关闭。
* **网络环境问题:** 用户所处的网络环境如果不支持 MTU 发现，或者存在会丢弃大包的中间设备，可能导致 MTU 发现一直失败，影响性能。
* **忽略写入错误:** 在进行底层网络编程时，如果忽略了写入错误，可能会导致数据丢失或连接异常，尤其是在 MTU 探测过程中。

**用户操作如何一步步到达这里（作为调试线索）：**

1. **用户在浏览器中访问一个使用 QUIC 协议的网站。**
2. **浏览器尝试与服务器建立 QUIC 连接。** 这涉及到 `QuicConnection` 对象的创建和初始化。
3. **如果启用了 MTU 发现，`QuicConnection` 会尝试发送大于当前最大包大小的探测包。**
4. **如果网络路径支持更大的包，对端会发送 ACK。** 相关的代码逻辑会在 `QuicConnection::ProcessUdpPacket()` 中处理接收到的 ACK，并调用相应的 MTU 发现处理函数。
5. **如果网络路径不支持更大的包，或者中间设备丢弃了大包，探测包可能不会被确认。**  `QuicConnection` 会启动超时定时器，如果超时，会触发相应的关闭逻辑。
6. **如果发生网络写入错误（例如，探测包太大），`QuicConnection::SendPacket()` 或 `QuicConnection::FlushPackets()` 中会处理这些错误。**
7. **在调试过程中，开发者可能会设置断点在这个测试文件中的特定测试用例中，例如 `MtuDiscoveryFailed()`，来观察 MTU 发现失败时的连接状态和行为。**

**功能归纳（作为第 8 部分）：**

作为整个 `QuicConnectionTest` 文件的一部分，这第 8 部分主要集中在测试 `QuicConnection` 类在 **网络路径特性变化**（通过 MTU 发现）和 **连接生命周期管理**（通过超时机制）方面的健壮性和正确性。它验证了连接在不同网络条件下如何调整自身以优化性能，以及如何在长时间空闲或遇到错误时进行恰当的处理。 这部分测试确保了 QUIC 连接在各种实际网络环境中能够稳定可靠地工作。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
onnected());
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(QUIC_PACKET_WRITE_ERROR));
}

// After a successful MTU probe, one and only one write error should be ignored
// if it happened in QuicConnection::FlushPacket.
TEST_P(QuicConnectionTest,
       MtuDiscoveryIgnoreOneWriteErrorInFlushAfterSuccessfulProbes) {
  MtuDiscoveryTestInit();
  writer_->SetBatchMode(true);

  const QuicPacketCount packets_between_probes_base = 5;
  set_packets_between_probes_base(packets_between_probes_base);

  connection_.EnablePathMtuDiscovery(send_algorithm_);

  const QuicByteCount original_max_packet_length =
      connection_.max_packet_length();
  // Send enough packets so that the next one triggers path MTU discovery.
  for (QuicPacketCount i = 0; i < packets_between_probes_base - 1; i++) {
    SendStreamDataToPeer(3, ".", i, NO_FIN, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  // Trigger the probe.
  SendStreamDataToPeer(3, "!", packets_between_probes_base - 1, NO_FIN,
                       nullptr);
  ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  QuicByteCount probe_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(SaveArg<3>(&probe_size));
  connection_.GetMtuDiscoveryAlarm()->Fire();

  EXPECT_THAT(probe_size, InRange(connection_.max_packet_length(),
                                  kMtuDiscoveryTargetPacketSizeHigh));

  const QuicPacketNumber probe_packet_number =
      FirstSendingPacketNumber() + packets_between_probes_base;
  ASSERT_EQ(probe_packet_number, creator_->packet_number());

  // Acknowledge all packets sent so far.
  {
    QuicAckFrame probe_ack = InitAckFrame(probe_packet_number);
    EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _))
        .Times(AnyNumber());
    ProcessAckPacket(&probe_ack);
    EXPECT_EQ(probe_size, connection_.max_packet_length());
    EXPECT_EQ(0u, connection_.GetBytesInFlight());
  }

  EXPECT_EQ(1u, connection_.mtu_probe_count());

  writer_->SetShouldWriteFail();

  // Ignore PACKET_WRITE_ERROR once.
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    // flusher's destructor will call connection_.FlushPackets, which should
    // get a WRITE_STATUS_ERROR from the writer and ignore it.
  }
  EXPECT_EQ(original_max_packet_length, connection_.max_packet_length());
  EXPECT_TRUE(connection_.connected());

  // Close connection on another PACKET_WRITE_ERROR.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, _))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    // flusher's destructor will call connection_.FlushPackets, which should
    // get a WRITE_STATUS_ERROR from the writer and ignore it.
  }
  EXPECT_EQ(original_max_packet_length, connection_.max_packet_length());
  EXPECT_FALSE(connection_.connected());
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(QUIC_PACKET_WRITE_ERROR));
}

// Simulate the case where the first attempt to send a probe is write blocked,
// and after unblock, the second attempt returns a MSG_TOO_BIG error.
TEST_P(QuicConnectionTest, MtuDiscoveryWriteBlocked) {
  MtuDiscoveryTestInit();

  const QuicPacketCount packets_between_probes_base = 5;
  set_packets_between_probes_base(packets_between_probes_base);

  connection_.EnablePathMtuDiscovery(send_algorithm_);

  // Send enough packets so that the next one triggers path MTU discovery.
  for (QuicPacketCount i = 0; i < packets_between_probes_base - 1; i++) {
    SendStreamDataToPeer(3, ".", i, NO_FIN, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  QuicByteCount original_max_packet_length = connection_.max_packet_length();

  // Trigger the probe.
  SendStreamDataToPeer(3, "!", packets_between_probes_base - 1, NO_FIN,
                       nullptr);
  ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  BlockOnNextWrite();
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  connection_.GetMtuDiscoveryAlarm()->Fire();
  EXPECT_EQ(1u, connection_.mtu_probe_count());
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
  ASSERT_TRUE(connection_.connected());

  writer_->SetWritable();
  SimulateNextPacketTooLarge();
  connection_.OnCanWrite();
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_EQ(original_max_packet_length, connection_.max_packet_length());
  EXPECT_TRUE(connection_.connected());
}

// Tests whether MTU discovery works correctly when the probes never get
// acknowledged.
TEST_P(QuicConnectionTest, MtuDiscoveryFailed) {
  MtuDiscoveryTestInit();

  // Lower the number of probes between packets in order to make the test go
  // much faster.
  const QuicPacketCount packets_between_probes_base = 5;
  set_packets_between_probes_base(packets_between_probes_base);

  connection_.EnablePathMtuDiscovery(send_algorithm_);

  const QuicTime::Delta rtt = QuicTime::Delta::FromMilliseconds(100);

  EXPECT_EQ(packets_between_probes_base,
            QuicConnectionPeer::GetPacketsBetweenMtuProbes(&connection_));

  // This tests sends more packets than strictly necessary to make sure that if
  // the connection was to send more discovery packets than needed, those would
  // get caught as well.
  const QuicPacketCount number_of_packets =
      packets_between_probes_base * (1 << (kMtuDiscoveryAttempts + 1));
  std::vector<QuicPacketNumber> mtu_discovery_packets;
  // Called on many acks.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _))
      .Times(AnyNumber());
  for (QuicPacketCount i = 0; i < number_of_packets; i++) {
    SendStreamDataToPeer(3, "!", i, NO_FIN, nullptr);
    clock_.AdvanceTime(rtt);

    // Receive an ACK, which marks all data packets as received, and all MTU
    // discovery packets as missing.

    QuicAckFrame ack;

    if (!mtu_discovery_packets.empty()) {
      QuicPacketNumber min_packet = *min_element(mtu_discovery_packets.begin(),
                                                 mtu_discovery_packets.end());
      QuicPacketNumber max_packet = *max_element(mtu_discovery_packets.begin(),
                                                 mtu_discovery_packets.end());
      ack.packets.AddRange(QuicPacketNumber(1), min_packet);
      ack.packets.AddRange(QuicPacketNumber(max_packet + 1),
                           creator_->packet_number() + 1);
      ack.largest_acked = creator_->packet_number();

    } else {
      ack.packets.AddRange(QuicPacketNumber(1), creator_->packet_number() + 1);
      ack.largest_acked = creator_->packet_number();
    }

    ProcessAckPacket(&ack);

    // Trigger MTU probe if it would be scheduled now.
    if (!connection_.GetMtuDiscoveryAlarm()->IsSet()) {
      continue;
    }

    // Fire the alarm.  The alarm should cause a packet to be sent.
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
    connection_.GetMtuDiscoveryAlarm()->Fire();
    // Record the packet number of the MTU discovery packet in order to
    // mark it as NACK'd.
    mtu_discovery_packets.push_back(creator_->packet_number());
  }

  // Ensure the number of packets between probes grows exponentially by checking
  // it against the closed-form expression for the packet number.
  ASSERT_EQ(kMtuDiscoveryAttempts, mtu_discovery_packets.size());
  for (uint64_t i = 0; i < kMtuDiscoveryAttempts; i++) {
    // 2^0 + 2^1 + 2^2 + ... + 2^n = 2^(n + 1) - 1
    const QuicPacketCount packets_between_probes =
        packets_between_probes_base * ((1 << (i + 1)) - 1);
    EXPECT_EQ(QuicPacketNumber(packets_between_probes + (i + 1)),
              mtu_discovery_packets[i]);
  }

  EXPECT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  EXPECT_EQ(kDefaultMaxPacketSize, connection_.max_packet_length());
  EXPECT_EQ(kMtuDiscoveryAttempts, connection_.mtu_probe_count());
}

// Probe 3 times, the first one succeeds, then fails, then succeeds again.
TEST_P(QuicConnectionTest, MtuDiscoverySecondProbeFailed) {
  MtuDiscoveryTestInit();

  const QuicPacketCount packets_between_probes_base = 5;
  set_packets_between_probes_base(packets_between_probes_base);

  connection_.EnablePathMtuDiscovery(send_algorithm_);

  // Send enough packets so that the next one triggers path MTU discovery.
  QuicStreamOffset stream_offset = 0;
  for (QuicPacketCount i = 0; i < packets_between_probes_base - 1; i++) {
    SendStreamDataToPeer(3, ".", stream_offset++, NO_FIN, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  // Trigger the probe.
  SendStreamDataToPeer(3, "!", packets_between_probes_base - 1, NO_FIN,
                       nullptr);
  ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  QuicByteCount probe_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(SaveArg<3>(&probe_size));
  connection_.GetMtuDiscoveryAlarm()->Fire();
  EXPECT_THAT(probe_size, InRange(connection_.max_packet_length(),
                                  kMtuDiscoveryTargetPacketSizeHigh));

  const QuicPacketNumber probe_packet_number =
      FirstSendingPacketNumber() + packets_between_probes_base;
  ASSERT_EQ(probe_packet_number, creator_->packet_number());

  // Acknowledge all packets sent so far.
  QuicAckFrame first_ack = InitAckFrame(probe_packet_number);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _))
      .Times(AnyNumber());
  ProcessAckPacket(&first_ack);
  EXPECT_EQ(probe_size, connection_.max_packet_length());
  EXPECT_EQ(0u, connection_.GetBytesInFlight());

  EXPECT_EQ(1u, connection_.mtu_probe_count());

  // Send just enough packets without triggering the second probe.
  for (QuicPacketCount i = 0; i < (packets_between_probes_base << 1) - 1; ++i) {
    SendStreamDataToPeer(3, ".", stream_offset++, NO_FIN, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  // Trigger the second probe.
  SendStreamDataToPeer(3, "!", stream_offset++, NO_FIN, nullptr);
  ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  QuicByteCount second_probe_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(SaveArg<3>(&second_probe_size));
  connection_.GetMtuDiscoveryAlarm()->Fire();
  EXPECT_THAT(second_probe_size,
              InRange(probe_size, kMtuDiscoveryTargetPacketSizeHigh));
  EXPECT_EQ(2u, connection_.mtu_probe_count());

  // Acknowledge all packets sent so far, except the second probe.
  QuicPacketNumber second_probe_packet_number = creator_->packet_number();
  QuicAckFrame second_ack = InitAckFrame(second_probe_packet_number - 1);
  ProcessAckPacket(&first_ack);
  EXPECT_EQ(probe_size, connection_.max_packet_length());

  // Send just enough packets without triggering the third probe.
  for (QuicPacketCount i = 0; i < (packets_between_probes_base << 2) - 1; ++i) {
    SendStreamDataToPeer(3, "@", stream_offset++, NO_FIN, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  // Trigger the third probe.
  SendStreamDataToPeer(3, "#", stream_offset++, NO_FIN, nullptr);
  ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  QuicByteCount third_probe_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(SaveArg<3>(&third_probe_size));
  connection_.GetMtuDiscoveryAlarm()->Fire();
  EXPECT_THAT(third_probe_size, InRange(probe_size, second_probe_size));
  EXPECT_EQ(3u, connection_.mtu_probe_count());

  // Acknowledge all packets sent so far, except the second probe.
  QuicAckFrame third_ack =
      ConstructAckFrame(creator_->packet_number(), second_probe_packet_number);
  ProcessAckPacket(&third_ack);
  EXPECT_EQ(third_probe_size, connection_.max_packet_length());

  SendStreamDataToPeer(3, "$", stream_offset++, NO_FIN, nullptr);
  EXPECT_TRUE(connection_.PathMtuReductionDetectionInProgress());

  if (connection_.PathDegradingDetectionInProgress() &&
      QuicConnectionPeer::GetPathDegradingDeadline(&connection_) <
          QuicConnectionPeer::GetPathMtuReductionDetectionDeadline(
              &connection_)) {
    // Fire path degrading alarm first.
    connection_.PathDegradingTimeout();
  }

  // Verify the max packet size has not reduced.
  EXPECT_EQ(third_probe_size, connection_.max_packet_length());

  // Fire alarm to get path mtu reduction callback called.
  EXPECT_TRUE(connection_.PathMtuReductionDetectionInProgress());
  connection_.GetBlackholeDetectorAlarm()->Fire();

  // Verify the max packet size has reduced to the previous value.
  EXPECT_EQ(probe_size, connection_.max_packet_length());
}

// Tests whether MTU discovery works when the writer has a limit on how large a
// packet can be.
TEST_P(QuicConnectionTest, MtuDiscoveryWriterLimited) {
  MtuDiscoveryTestInit();

  const QuicByteCount mtu_limit = kMtuDiscoveryTargetPacketSizeHigh - 1;
  writer_->set_max_packet_size(mtu_limit);

  const QuicPacketCount packets_between_probes_base = 5;
  set_packets_between_probes_base(packets_between_probes_base);

  connection_.EnablePathMtuDiscovery(send_algorithm_);

  // Send enough packets so that the next one triggers path MTU discovery.
  for (QuicPacketCount i = 0; i < packets_between_probes_base - 1; i++) {
    SendStreamDataToPeer(3, ".", i, NO_FIN, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  // Trigger the probe.
  SendStreamDataToPeer(3, "!", packets_between_probes_base - 1, NO_FIN,
                       nullptr);
  ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  QuicByteCount probe_size;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
      .WillOnce(SaveArg<3>(&probe_size));
  connection_.GetMtuDiscoveryAlarm()->Fire();

  EXPECT_THAT(probe_size, InRange(connection_.max_packet_length(), mtu_limit));

  const QuicPacketNumber probe_sequence_number =
      FirstSendingPacketNumber() + packets_between_probes_base;
  ASSERT_EQ(probe_sequence_number, creator_->packet_number());

  // Acknowledge all packets sent so far.
  {
    QuicAckFrame probe_ack = InitAckFrame(probe_sequence_number);
    EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _))
        .Times(AnyNumber());
    ProcessAckPacket(&probe_ack);
    EXPECT_EQ(probe_size, connection_.max_packet_length());
    EXPECT_EQ(0u, connection_.GetBytesInFlight());
  }

  EXPECT_EQ(1u, connection_.mtu_probe_count());

  QuicStreamOffset stream_offset = packets_between_probes_base;
  for (size_t num_probes = 1; num_probes < kMtuDiscoveryAttempts;
       ++num_probes) {
    // Send just enough packets without triggering the next probe.
    for (QuicPacketCount i = 0;
         i < (packets_between_probes_base << num_probes) - 1; ++i) {
      SendStreamDataToPeer(3, ".", stream_offset++, NO_FIN, nullptr);
      ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
    }

    // Trigger the next probe.
    SendStreamDataToPeer(3, "!", stream_offset++, NO_FIN, nullptr);
    ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
    QuicByteCount new_probe_size;
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .WillOnce(SaveArg<3>(&new_probe_size));
    connection_.GetMtuDiscoveryAlarm()->Fire();
    EXPECT_THAT(new_probe_size, InRange(probe_size, mtu_limit));
    EXPECT_EQ(num_probes + 1, connection_.mtu_probe_count());

    // Acknowledge all packets sent so far.
    QuicAckFrame probe_ack = InitAckFrame(creator_->packet_number());
    ProcessAckPacket(&probe_ack);
    EXPECT_EQ(new_probe_size, connection_.max_packet_length());
    EXPECT_EQ(0u, connection_.GetBytesInFlight());

    probe_size = new_probe_size;
  }

  // The last probe size should be equal to the target.
  EXPECT_EQ(probe_size, mtu_limit);
}

// Tests whether MTU discovery works when the writer returns an error despite
// advertising higher packet length.
TEST_P(QuicConnectionTest, MtuDiscoveryWriterFailed) {
  MtuDiscoveryTestInit();

  const QuicByteCount mtu_limit = kMtuDiscoveryTargetPacketSizeHigh - 1;
  const QuicByteCount initial_mtu = connection_.max_packet_length();
  EXPECT_LT(initial_mtu, mtu_limit);
  writer_->set_max_packet_size(mtu_limit);

  const QuicPacketCount packets_between_probes_base = 5;
  set_packets_between_probes_base(packets_between_probes_base);

  connection_.EnablePathMtuDiscovery(send_algorithm_);

  // Send enough packets so that the next one triggers path MTU discovery.
  for (QuicPacketCount i = 0; i < packets_between_probes_base - 1; i++) {
    SendStreamDataToPeer(3, ".", i, NO_FIN, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  // Trigger the probe.
  SendStreamDataToPeer(3, "!", packets_between_probes_base - 1, NO_FIN,
                       nullptr);
  ASSERT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  writer_->SimulateNextPacketTooLarge();
  connection_.GetMtuDiscoveryAlarm()->Fire();
  ASSERT_TRUE(connection_.connected());

  // Send more data.
  QuicPacketNumber probe_number = creator_->packet_number();
  QuicPacketCount extra_packets = packets_between_probes_base * 3;
  for (QuicPacketCount i = 0; i < extra_packets; i++) {
    connection_.EnsureWritableAndSendStreamData5();
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  // Acknowledge all packets sent so far, except for the lost probe.
  QuicAckFrame probe_ack =
      ConstructAckFrame(creator_->packet_number(), probe_number);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  ProcessAckPacket(&probe_ack);
  EXPECT_EQ(initial_mtu, connection_.max_packet_length());

  // Send more packets, and ensure that none of them sets the alarm.
  for (QuicPacketCount i = 0; i < 4 * packets_between_probes_base; i++) {
    connection_.EnsureWritableAndSendStreamData5();
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  EXPECT_EQ(initial_mtu, connection_.max_packet_length());
  EXPECT_EQ(1u, connection_.mtu_probe_count());
}

TEST_P(QuicConnectionTest, NoMtuDiscoveryAfterConnectionClosed) {
  MtuDiscoveryTestInit();

  const QuicPacketCount packets_between_probes_base = 10;
  set_packets_between_probes_base(packets_between_probes_base);

  connection_.EnablePathMtuDiscovery(send_algorithm_);

  // Send enough packets so that the next one triggers path MTU discovery.
  for (QuicPacketCount i = 0; i < packets_between_probes_base - 1; i++) {
    SendStreamDataToPeer(3, ".", i, NO_FIN, nullptr);
    ASSERT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
  }

  SendStreamDataToPeer(3, "!", packets_between_probes_base - 1, NO_FIN,
                       nullptr);
  EXPECT_TRUE(connection_.GetMtuDiscoveryAlarm()->IsSet());

  EXPECT_CALL(visitor_, OnConnectionClosed(_, _));
  connection_.CloseConnection(QUIC_PEER_GOING_AWAY, "no reason",
                              ConnectionCloseBehavior::SILENT_CLOSE);
  EXPECT_FALSE(connection_.GetMtuDiscoveryAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, TimeoutAfterSendDuringHandshake) {
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);

  const QuicTime::Delta initial_idle_timeout =
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1);
  const QuicTime::Delta five_ms = QuicTime::Delta::FromMilliseconds(5);
  QuicTime default_timeout = clock_.ApproximateNow() + initial_idle_timeout;

  // When we send a packet, the timeout will change to 5ms +
  // kInitialIdleTimeoutSecs.
  clock_.AdvanceTime(five_ms);
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, FIN, nullptr);
  EXPECT_EQ(default_timeout + five_ms,
            connection_.GetTimeoutAlarm()->deadline());

  // Now send more data. This will not move the timeout because
  // no data has been received since the previous write.
  clock_.AdvanceTime(five_ms);
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      3, FIN, nullptr);
  EXPECT_EQ(default_timeout + five_ms,
            connection_.GetTimeoutAlarm()->deadline());

  // The original alarm will fire.  We should not time out because we had a
  // network event at t=5ms.  The alarm will reregister.
  clock_.AdvanceTime(initial_idle_timeout - five_ms - five_ms);
  EXPECT_EQ(default_timeout, clock_.ApproximateNow());
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_TRUE(connection_.connected());
  EXPECT_EQ(default_timeout + five_ms,
            connection_.GetTimeoutAlarm()->deadline());

  // This time, we should time out.
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1));
  clock_.AdvanceTime(five_ms);
  EXPECT_EQ(default_timeout + five_ms, clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(QUIC_NETWORK_IDLE_TIMEOUT);
}

TEST_P(QuicConnectionTest, TimeoutAfterSendAfterHandshake) {
  // When the idle timeout fires, verify that by default we do not send any
  // connection close packets.
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;

  // Create a handshake message that also enables silent close.
  CryptoHandshakeMessage msg;
  std::string error_details;
  QuicConfig client_config;
  client_config.SetInitialStreamFlowControlWindowToSend(
      kInitialStreamFlowControlWindowForTest);
  client_config.SetInitialSessionFlowControlWindowToSend(
      kInitialSessionFlowControlWindowForTest);
  client_config.SetIdleNetworkTimeout(
      QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs));
  client_config.ToHandshakeMessage(&msg, connection_.transport_version());
  const QuicErrorCode error =
      config.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_THAT(error, IsQuicNoError());

  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(
        &config, connection_.connection_id());
  }
  connection_.SetFromConfig(config);

  const QuicTime::Delta default_idle_timeout =
      QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs - 1);
  const QuicTime::Delta five_ms = QuicTime::Delta::FromMilliseconds(5);
  QuicTime default_timeout = clock_.ApproximateNow() + default_idle_timeout;

  // When we send a packet, the timeout will change to 5ms +
  // kInitialIdleTimeoutSecs.
  clock_.AdvanceTime(five_ms);
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, FIN, nullptr);
  EXPECT_EQ(default_timeout + five_ms,
            connection_.GetTimeoutAlarm()->deadline());

  // Now send more data. This will not move the timeout because
  // no data has been received since the previous write.
  clock_.AdvanceTime(five_ms);
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      3, FIN, nullptr);
  EXPECT_EQ(default_timeout + five_ms,
            connection_.GetTimeoutAlarm()->deadline());

  // The original alarm will fire.  We should not time out because we had a
  // network event at t=5ms.  The alarm will reregister.
  clock_.AdvanceTime(default_idle_timeout - five_ms - five_ms);
  EXPECT_EQ(default_timeout, clock_.ApproximateNow());
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_TRUE(connection_.connected());
  EXPECT_EQ(default_timeout + five_ms,
            connection_.GetTimeoutAlarm()->deadline());

  // This time, we should time out.
  // This results in a SILENT_CLOSE, so the writer will not be invoked
  // and will not save the frame. Grab the frame from OnConnectionClosed
  // directly.
  EXPECT_CALL(visitor_, OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
      .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));

  clock_.AdvanceTime(five_ms);
  EXPECT_EQ(default_timeout + five_ms, clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());
  EXPECT_EQ(1, connection_close_frame_count_);
  EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
              IsError(QUIC_NETWORK_IDLE_TIMEOUT));
}

TEST_P(QuicConnectionTest, TimeoutAfterSendSilentCloseWithOpenStreams) {
  // Same test as above, but having open streams causes a connection close
  // to be sent.
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;

  // Create a handshake message that also enables silent close.
  CryptoHandshakeMessage msg;
  std::string error_details;
  QuicConfig client_config;
  client_config.SetInitialStreamFlowControlWindowToSend(
      kInitialStreamFlowControlWindowForTest);
  client_config.SetInitialSessionFlowControlWindowToSend(
      kInitialSessionFlowControlWindowForTest);
  client_config.SetIdleNetworkTimeout(
      QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs));
  client_config.ToHandshakeMessage(&msg, connection_.transport_version());
  const QuicErrorCode error =
      config.ProcessPeerHello(msg, CLIENT, &error_details);
  EXPECT_THAT(error, IsQuicNoError());

  if (connection_.version().UsesTls()) {
    QuicConfigPeer::SetReceivedOriginalConnectionId(
        &config, connection_.connection_id());
    QuicConfigPeer::SetReceivedInitialSourceConnectionId(
        &config, connection_.connection_id());
  }
  connection_.SetFromConfig(config);

  const QuicTime::Delta default_idle_timeout =
      QuicTime::Delta::FromSeconds(kMaximumIdleTimeoutSecs - 1);
  const QuicTime::Delta five_ms = QuicTime::Delta::FromMilliseconds(5);
  QuicTime default_timeout = clock_.ApproximateNow() + default_idle_timeout;

  // When we send a packet, the timeout will change to 5ms +
  // kInitialIdleTimeoutSecs.
  clock_.AdvanceTime(five_ms);
  SendStreamDataToPeer(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, FIN, nullptr);
  EXPECT_EQ(default_timeout + five_ms,
            connection_.GetTimeoutAlarm()->deadline());

  // Indicate streams are still open.
  EXPECT_CALL(visitor_, ShouldKeepConnectionAlive())
      .WillRepeatedly(Return(true));
  if (GetQuicReloadableFlag(quic_add_stream_info_to_idle_close_detail)) {
    EXPECT_CALL(visitor_, GetStreamsInfoForLogging()).WillOnce(Return(""));
  }

  // This time, we should time out and send a connection close due to the TLP.
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1));
  clock_.AdvanceTime(connection_.GetTimeoutAlarm()->deadline() -
                     clock_.ApproximateNow() + five_ms);
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(QUIC_NETWORK_IDLE_TIMEOUT);
}

TEST_P(QuicConnectionTest, TimeoutAfterReceive) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);

  const QuicTime::Delta initial_idle_timeout =
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1);
  const QuicTime::Delta five_ms = QuicTime::Delta::FromMilliseconds(5);
  QuicTime default_timeout = clock_.ApproximateNow() + initial_idle_timeout;

  connection_.SendStreamDataWithString(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, NO_FIN);
  connection_.SendStreamDataWithString(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      3, NO_FIN);

  EXPECT_EQ(default_timeout, connection_.GetTimeoutAlarm()->deadline());
  clock_.AdvanceTime(five_ms);

  // When we receive a packet, the timeout will change to 5ms +
  // kInitialIdleTimeoutSecs.
  QuicAckFrame ack = InitAckFrame(2);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  ProcessAckPacket(&ack);

  // The original alarm will fire.  We should not time out because we had a
  // network event at t=5ms.  The alarm will reregister.
  clock_.AdvanceTime(initial_idle_timeout - five_ms);
  EXPECT_EQ(default_timeout, clock_.ApproximateNow());
  EXPECT_TRUE(connection_.connected());
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_EQ(default_timeout + five_ms,
            connection_.GetTimeoutAlarm()->deadline());

  // This time, we should time out.
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1));
  clock_.AdvanceTime(five_ms);
  EXPECT_EQ(default_timeout + five_ms, clock_.ApproximateNow());
  connection_.GetTimeoutAlarm()->Fire();
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_FALSE(connection_.connected());
  TestConnectionCloseQuicErrorCode(QUIC_NETWORK_IDLE_TIMEOUT);
}

TEST_P(QuicConnectionTest, TimeoutAfterReceiveNotSendWhenUnacked) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
  QuicConfig config;
  connection_.SetFromConfig(config);

  const QuicTime::Delta initial_idle_timeout =
      QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs - 1);
  connection_.SetNetworkTimeouts(
      QuicTime::Delta::Infinite(),
      initial_idle_timeout + QuicTime::Delta::FromSeconds(1));
  const QuicTime::Delta five_ms = QuicTime::Delta::FromMilliseconds(5);
  QuicTime default_timeout = clock_.ApproximateNow() + initial_idle_timeout;

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  connection_.SendStreamDataWithString(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      0, NO_FIN);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  connection_.SendStreamDataWithString(
      GetNthClientInitiatedStreamId(1, connection_.transport_version()), "foo",
      3, NO_FIN);

  EXPECT_EQ(default_timeout, connection_.GetTimeoutAlarm()->deadline());

  clock_.AdvanceTime(five_ms);

  // When we receive a packet, the timeout will change to 5ms +
  // kInitialIdleTimeoutSecs.
  QuicAckFrame ack = InitAckFrame(2);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  ProcessAckPacket(&ack);

  // The original alarm will fire.  We should not time out because we had a
  // network event at t=5ms.  The alarm will reregister.
  clock_.AdvanceTime(initial_idle_timeout - five_ms);
  EXPECT_EQ(default_timeout, clock_.ApproximateNow());
  EXPECT_TRUE(connection_.connected());
  EXPECT_TRUE(connection_.GetTimeoutAlarm()->IsSet());
  EXPECT_EQ(default_timeout + five_ms,
            connection_.GetTimeoutAlarm()->deadline());

  // Now, send packets while advancing the time and verify that the connection
  // eventually times out.
  EXPECT_CALL(visitor_,
              OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AnyNumber());
  for (int i = 0; i < 100 && connection_.connected(); ++i) {
    QUIC_LOG(INFO) << "sending data packet";
    connection_.SendStreamDataWithString(
        GetNthClientInitiatedStreamId(1, connection_.transport_version()),
        "foo", 0, NO_FIN);
    connection_.GetTimeoutAlarm()->Fire();
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  }
  EXPECT_FALSE(connection_.connected());
  EXPECT_FALSE(connection_.GetTimeoutAlarm()->IsSet());
  TestConnectionCloseQuicErrorCode(QUIC_NETWORK_IDLE_TIMEOUT);
}

TEST_P(QuicConnectionTest, SendScheduler) {
  // Test that if we send a packet without delay, it is not queued.
  QuicFramerPeer::SetPerspective(&peer_framer_, Perspective::IS_CLIENT);
  std::unique_ptr<QuicPacket> packet =
      ConstructDataPacket(1, !kHasStopWaiting, ENCRYPTION_INITIAL);
  QuicPacketCreatorPeer::SetPacketNumber(creator_, 1);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  connection_.SendPacket(ENCRYPTION_INITIAL, 1, std::move(packet),
                         HAS_RETRANSMITTABLE_DATA, false, false);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_P(QuicConnectionTest, FailToSendFirstPacket) {
  // Test that the connection does not crash when it fails to send the first
  // packet at which point self_address_ mig
```