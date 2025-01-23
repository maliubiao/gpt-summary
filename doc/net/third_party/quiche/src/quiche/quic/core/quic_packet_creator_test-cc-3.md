Response:
The user is asking for a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_packet_creator_test.cc`. The request specifies several aspects to cover: general function, relationship to Javascript (if any), logical reasoning with inputs/outputs, common user errors, debugging hints, and a concise summary of its purpose within the context of a larger, multi-part set of files.

**Plan:**

1. **Identify the core purpose:** Based on the file name (`quic_packet_creator_test.cc`), it's clearly a unit test file for the `QuicPacketCreator` class.
2. **Analyze the test cases:**  Scan the provided code snippets for `TEST_P` and `TEST_F` macros to understand the specific scenarios being tested. These test names will reveal the functionalities of `QuicPacketCreator` under scrutiny.
3. **Summarize the tested functionalities:**  Group the identified test scenarios into broader functional areas.
4. **Javascript relationship:** Determine if any tested functionality has a direct or indirect link to Javascript within a web browser context.
5. **Logical reasoning (input/output):**  For some test cases, identify the setup (input/configuration) and the expected outcome (assertions).
6. **Common user errors:**  Infer potential misuses of `QuicPacketCreator` based on the tests, particularly negative tests or those that check error conditions.
7. **Debugging hints:**  The test file itself provides debugging clues by illustrating how different configurations and actions affect the `QuicPacketCreator`.
8. **Overall function (Part 4 of 6):**  Synthesize the findings into a concise description of the file's role within the broader project.

**Mental Walkthrough and Refinement:**

* **Core purpose is clear.**
* **Test case analysis:** I will look for verbs like `Set`, `Add`, `Consume`, `Flush`, `Check`, etc., in test names. The parameters of these functions within the tests will be important to understand the inputs. Assertions (e.g., `EXPECT_EQ`, `ASSERT_TRUE`) will show the expected outputs.
* **Javascript relationship:**  Consider if packet creation aspects like size limits, framing, or encryption have relevance to Javascript's interaction with network requests. Since QUIC is a transport protocol used by web browsers, there might be indirect connections related to how the browser initiates and manages network communication.
* **Logical reasoning:** Focus on tests where explicit values are set up and then an assertion is made. For instance, setting a maximum packet length and then checking if the creator respects it.
* **User errors:** Look for tests that prevent incorrect usage, like trying to send data at the wrong encryption level or without proper permissions.
* **Debugging hints:** The tests themselves act as examples of correct usage. The assertions point out the expected behavior under various conditions.
* **Overall function:**  Emphasize the testing aspect and how this file helps ensure the `QuicPacketCreator` works correctly.

**Constraint Checklist & Confidence:**

1. 列举一下它的功能: Yes
2. 如果它与javascript的功能有关系，请做出对应的举例说明: Yes
3. 如果做了逻辑推理，请给出假设输入与输出: Yes
4. 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
5. 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
6. 这是第4部分，共6部分，请归纳一下它的功能: Yes

Confidence Level: 5/5

Strategizing complete. I will now proceed with generating the response by extracting and synthesizing information from the provided code snippets based on the steps outlined above.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_packet_creator_test.cc` 文件的第四部分，它主要包含以下功能：

**核心功能：测试 `QuicPacketCreator` 类的各种功能**

这个文件是一个单元测试文件，专门用于测试 `QuicPacketCreator` 类的各种方法和行为。`QuicPacketCreator` 的主要职责是根据需要创建和序列化 QUIC 数据包。

**具体测试的功能点（基于提供的代码片段）：**

* **设置和调整最大数据包长度 (`SetSoftMaxPacketLength`)：**
    * 测试了当设置的软最大数据包长度小于实际开销时，是否会被拒绝。
    * 验证了设置成功的软最大数据包长度会被正确应用。
    * 确认了设置软最大长度后，`QuicPacketCreator` 仍然有空间容纳 StreamFrame 和 MessageFrame。
    * 测试了在设置软最大长度后，是否可以成功消耗 Crypto 数据。
    * 验证了设置软最大长度后，是否可以成功添加 ACK 帧。
* **加密级别变化对软最大数据包长度的影响 (`ChangingEncryptionLevelRemovesSoftMaxPacketLength`)：**
    * 测试了当加密级别改变时，之前设置的软最大数据包长度是否会被移除，恢复到之前的最大长度。这通常发生在加密级别提升，头部开销增加时。
* **最小有效载荷长度 (`MinPayloadLength`)：**
    * 测试了在不同的包序号长度下，最小的有效载荷长度的计算是否正确。
* **数据包填充到最大长度 (`PadWhenAlmostMaxLength`)：**
    * 测试了当添加 StreamFrame 使得数据包接近最大长度时，是否会进行填充以达到最大长度。
* **待处理填充大于可用空间 (`MorePendingPaddingThanBytesFree`)：**
    * 测试了当有待处理的填充数据，并且大于当前可用空间时，是否能够正确处理，保证数据包最终达到最大长度。
* **使用 `MockDelegate` 进行模拟测试：**
    * 定义了一个 `MockDelegate` 类，用于模拟 `QuicPacketCreator` 的委托对象，方便进行隔离测试，例如模拟是否允许发送数据包等情况。
* **测试在多种场景下添加和消耗不同类型的帧：**
    *  使用了 `MultiplePacketsTestPacketCreator` 类，继承自 `QuicPacketCreator`，用于更方便地控制和测试创建多个数据包的情况。
    *  测试了当 `ShouldGeneratePacket` 返回 false 时，添加控制帧是否会被拒绝。
    *  测试了在错误的加密级别下尝试快速路径发送流数据是否会触发错误。
    *  测试了当只允许发送非重传帧时，添加控制帧是否会被拒绝。
    *  测试了添加控制帧后，是否会正确设置 `HasPendingFrames` 和 `HasPendingRetransmittableFrames` 标志。
    *  测试了添加控制帧后，如果允许发送，是否会刷新数据包并触发 `OnSerializedPacket` 回调。
    *  测试了 `ConsumeCryptoData` 方法，包括成功消耗和 `ShouldGeneratePacket` 返回 false 的情况。
    *  测试了 `ConsumeData` 方法，包括各种场景，例如不可写、可写但不应立即刷新、可写且应立即刷新。
    *  特别测试了 `ConsumeData` 处理握手数据流的情况，确保数据包会被立即发送并填充。
    *  测试了 `ConsumeData` 处理空数据的情况，预期会触发断言。
    *  测试了多次调用 `ConsumeData` 的情况，包括不立即刷新和批量操作的情况。
    *  测试了在之前已经排队帧的情况下，`ConsumeData` 的行为。

**与 Javascript 的功能关系：**

虽然这个 C++ 文件本身不包含 Javascript 代码，但它测试的网络协议 QUIC 最终是为了支持 Web 浏览器的网络通信，而 Javascript 是 Web 浏览器中常用的脚本语言。

* **数据包大小限制：** Javascript 发起的网络请求最终会被浏览器底层处理，包括 QUIC 协议的数据包创建。这里测试的最大数据包长度限制会直接影响浏览器能发送的最大数据量，从而间接影响 Javascript 发起的请求。例如，如果 Javascript 需要上传大量数据，QUIC 的分包机制和最大包大小的设置就至关重要。
* **加密级别：**  Javascript 发起的 HTTPS 请求依赖于底层的加密协议。这里测试的加密级别变化与数据包创建的关系，确保了在不同加密阶段数据包能够正确创建，从而保证 Javascript 请求的安全性。
* **数据包填充：** 为了防止流量分析，QUIC 可能会填充数据包。虽然 Javascript 本身不直接控制填充，但填充策略会影响网络性能，从而间接影响 Javascript 应用的性能。

**举例说明：**

假设一个 Javascript 应用需要通过 `fetch` API 上传一个较大的文件。浏览器底层会使用 QUIC 协议进行传输。`QuicPacketCreator` 负责将文件数据分片并封装到 QUIC 数据包中。这个文件中的测试确保了：

* **最大数据包长度 (`SetSoftMaxPacketLength`):** 测试保证了 `QuicPacketCreator` 能够正确处理配置的最大数据包长度，不会创建过大的数据包导致网络传输问题。
* **加密级别 (`ChangingEncryptionLevelRemovesSoftMaxPacketLength`):**  测试保证了在 TLS 握手过程中，随着加密级别的提升，数据包的创建能够适应新的头部大小，确保连接建立的顺利进行。
* **数据包填充 (`PadWhenAlmostMaxLength`):**  测试保证了在某些情况下，即使数据量略小于最大值，也会进行填充，这对于安全性至关重要，但也可能对 Javascript 应用的上传速度产生一定的影响。

**逻辑推理（假设输入与输出）：**

**示例 1:**

* **假设输入:** 调用 `creator_.SetSoftMaxPacketLength(overhead - 1)`，其中 `overhead` 是当前数据包头部的开销。
* **预期输出:**  由于设置的软最大长度小于头部开销，该设置会被拒绝，`creator_.max_packet_length()` 的值保持不变。

**示例 2:**

* **假设输入:** 调用 `creator_.ConsumeData(stream_id, "long_data", 0, FIN)`，并且当前 `delegate_` 模拟为 `SetCanWriteAnything()`，允许发送数据。
* **预期输出:** 数据会被添加到当前数据包中，`creator_.HasPendingFrames()` 返回 `true`，`creator_.HasPendingRetransmittableFrames()` 返回 `true`，并且 `consumed.bytes_consumed` 等于 `"long_data"` 的长度，`consumed.fin_consumed` 为 `true`。

**用户或编程常见的使用错误：**

* **在错误的加密级别发送数据：**  测试 `WrongEncryptionLevelForStreamDataFastPath` 就模拟了这种情况。如果开发者尝试在握手阶段就使用应用数据流的加密级别发送数据，会导致错误。
* **没有检查是否允许发送数据就尝试添加帧：**  测试 `AddControlFrame_NotWritable` 和 `AddControlFrame_OnlyAckWritable` 模拟了这种情况。开发者需要通过 `delegate_->ShouldGeneratePacket()` 检查是否允许发送特定类型的帧，否则添加操作可能会失败或导致未预期的行为。
* **假设可以无限发送数据而不考虑流量控制：** 虽然测试中设置了 `GetFlowControlSendWindowSize` 返回最大值，但在实际应用中，开发者需要考虑接收端的流量控制窗口，避免发送过多数据导致阻塞或丢包。

**用户操作如何一步步到达这里（作为调试线索）：**

假设一个用户在使用 Chrome 浏览器访问一个使用 QUIC 协议的网站时遇到网络问题，例如上传文件失败或连接不稳定。作为 Chrome 浏览器的开发者，在调试 QUIC 相关问题时，可能会需要查看 `QuicPacketCreator` 的行为：

1. **用户报告问题:** 用户反馈在使用特定网站或进行特定操作时出现网络问题。
2. **网络抓包分析:** 开发者可能会使用网络抓包工具（如 Wireshark）捕获网络数据包，观察 QUIC 连接的建立和数据传输过程。
3. **定位到 QUIC 层:** 通过抓包分析，发现问题可能出在 QUIC 协议层。
4. **查看 `QuicPacketCreator` 的日志或状态:** 开发者可能会在 Chrome 的 QUIC 代码中添加日志，记录 `QuicPacketCreator` 何时创建数据包，数据包的大小，包含哪些帧等信息。
5. **运行单元测试:** 为了验证 `QuicPacketCreator` 的行为是否符合预期，开发者会运行相关的单元测试，例如这个 `quic_packet_creator_test.cc` 文件中的测试用例。
6. **特定测试用例触发:**  如果怀疑问题与数据包大小限制或加密级别有关，开发者可能会重点关注 `SetSoftMaxPacketLength` 或 `ChangingEncryptionLevelRemovesSoftMaxPacketLength` 相关的测试用例。
7. **代码断点调试:** 如果单元测试无法完全复现问题，开发者可能会在 `QuicPacketCreator` 的代码中设置断点，例如在 `ConsumeData` 或 `FlushCurrentPacket` 等方法中，逐步执行代码，观察变量的值和执行流程。
8. **分析测试结果:** 通过单元测试的结果和代码调试的信息，开发者可以判断 `QuicPacketCreator` 是否按预期工作，从而缩小问题范围。

**归纳其功能（作为第4部分，共6部分）：**

作为系列测试文件的第 4 部分，这个文件专注于 **详细测试 `QuicPacketCreator` 类在各种场景下的数据包创建和管理能力**。它涵盖了数据包大小的控制、加密级别变化的影响、不同类型帧的添加和消耗、以及在各种网络状态下的行为。这部分测试旨在确保 `QuicPacketCreator` 能够可靠且正确地生成符合 QUIC 协议规范的数据包，是保证 QUIC 连接稳定性和性能的关键组成部分。

总而言之，这个文件通过大量的单元测试用例，细致地检验了 `QuicPacketCreator` 类的功能，确保其在各种边界条件和正常情况下都能正确工作，为 QUIC 协议的实现提供了重要的质量保障。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_packet_creator_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
th) gets rejected.
  creator_.SetSoftMaxPacketLength(overhead - 1);
  EXPECT_EQ(previous_max_packet_length, creator_.max_packet_length());

  creator_.SetSoftMaxPacketLength(overhead);
  EXPECT_EQ(overhead, creator_.max_packet_length());

  // Verify creator has room for stream frame because max_packet_length_ gets
  // restored.
  ASSERT_TRUE(creator_.HasRoomForStreamFrame(
      GetNthClientInitiatedStreamId(1), kMaxIetfVarInt,
      std::numeric_limits<uint32_t>::max()));
  EXPECT_EQ(previous_max_packet_length, creator_.max_packet_length());

  // Same for message frame.
  creator_.SetSoftMaxPacketLength(overhead);
  if (client_framer_.version().UsesTls()) {
    creator_.SetMaxDatagramFrameSize(kMaxAcceptedDatagramFrameSize);
  }
  // Verify GetCurrentLargestMessagePayload is based on the actual
  // max_packet_length.
  EXPECT_LT(1u, creator_.GetCurrentLargestMessagePayload());
  EXPECT_EQ(overhead, creator_.max_packet_length());
  ASSERT_TRUE(creator_.HasRoomForMessageFrame(
      creator_.GetCurrentLargestMessagePayload()));
  EXPECT_EQ(previous_max_packet_length, creator_.max_packet_length());

  // Verify creator can consume crypto data because max_packet_length_ gets
  // restored.
  creator_.SetSoftMaxPacketLength(overhead);
  EXPECT_EQ(overhead, creator_.max_packet_length());
  const std::string data = "crypto data";
  QuicFrame frame;
  if (!QuicVersionUsesCryptoFrames(client_framer_.transport_version())) {
    ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
        QuicUtils::GetCryptoStreamId(client_framer_.transport_version()), data,
        kOffset, false, true, NOT_RETRANSMISSION, &frame));
    size_t bytes_consumed = frame.stream_frame.data_length;
    EXPECT_LT(0u, bytes_consumed);
  } else {
    producer_.SaveCryptoData(ENCRYPTION_INITIAL, kOffset, data);
    ASSERT_TRUE(creator_.ConsumeCryptoDataToFillCurrentPacket(
        ENCRYPTION_INITIAL, data.length(), kOffset,
        /*needs_full_padding=*/true, NOT_RETRANSMISSION, &frame));
    size_t bytes_consumed = frame.crypto_frame->data_length;
    EXPECT_LT(0u, bytes_consumed);
  }
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.FlushCurrentPacket();

  // Verify ACK frame can be consumed.
  creator_.SetSoftMaxPacketLength(overhead);
  EXPECT_EQ(overhead, creator_.max_packet_length());
  QuicAckFrame ack_frame(InitAckFrame(10u));
  EXPECT_TRUE(creator_.AddFrame(QuicFrame(&ack_frame), NOT_RETRANSMISSION));
  EXPECT_TRUE(creator_.HasPendingFrames());
}

TEST_P(QuicPacketCreatorTest,
       ChangingEncryptionLevelRemovesSoftMaxPacketLength) {
  if (!client_framer_.version().CanSendCoalescedPackets()) {
    return;
  }
  // First set encryption level to forward secure which has the shortest header.
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  const QuicByteCount previous_max_packet_length = creator_.max_packet_length();
  const size_t min_acceptable_packet_size =
      GetPacketHeaderOverhead(client_framer_.transport_version()) +
      QuicPacketCreator::MinPlaintextPacketSize(
          client_framer_.version(),
          QuicPacketCreatorPeer::GetPacketNumberLength(&creator_)) +
      GetEncryptionOverhead();
  // Then set the soft max packet length to the lowest allowed value.
  creator_.SetSoftMaxPacketLength(min_acceptable_packet_size);
  // Make sure that the low value was accepted.
  EXPECT_EQ(creator_.max_packet_length(), min_acceptable_packet_size);
  // Now set the encryption level to handshake which increases the header size.
  creator_.set_encryption_level(ENCRYPTION_HANDSHAKE);
  // Make sure that adding a frame removes the the soft max packet length.
  QuicAckFrame ack_frame(InitAckFrame(1));
  frames_.push_back(QuicFrame(&ack_frame));
  SerializedPacket serialized = SerializeAllFrames(frames_);
  EXPECT_EQ(serialized.encryption_level, ENCRYPTION_HANDSHAKE);
  EXPECT_EQ(creator_.max_packet_length(), previous_max_packet_length);
}

TEST_P(QuicPacketCreatorTest, MinPayloadLength) {
  ParsedQuicVersion version = client_framer_.version();
  for (QuicPacketNumberLength pn_length :
       {PACKET_1BYTE_PACKET_NUMBER, PACKET_2BYTE_PACKET_NUMBER,
        PACKET_3BYTE_PACKET_NUMBER, PACKET_4BYTE_PACKET_NUMBER}) {
    if (!version.HasHeaderProtection()) {
      EXPECT_EQ(creator_.MinPlaintextPacketSize(version, pn_length), 0);
    } else {
      EXPECT_EQ(creator_.MinPlaintextPacketSize(version, pn_length),
                (version.UsesTls() ? 4 : 8) - pn_length);
    }
  }
}

// A variant of StreamFrameConsumption that tests when expansion of the stream
// frame puts it at or over the max length, but the packet is supposed to be
// padded to max length.
TEST_P(QuicPacketCreatorTest, PadWhenAlmostMaxLength) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  // Compute the total overhead for a single frame in packet.
  const size_t overhead =
      GetPacketHeaderOverhead(client_framer_.transport_version()) +
      GetEncryptionOverhead() +
      GetStreamFrameOverhead(client_framer_.transport_version());
  size_t capacity = kDefaultMaxPacketSize - overhead;
  for (size_t bytes_free = 1; bytes_free <= 2; bytes_free++) {
    std::string data(capacity - bytes_free, 'A');

    QuicFrame frame;
    ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
        GetNthClientInitiatedStreamId(1), data, kOffset, false,
        /*needs_full_padding=*/true, NOT_RETRANSMISSION, &frame));

    // BytesFree() returns bytes available for the next frame, which will
    // be two bytes smaller since the stream frame would need to be grown.
    EXPECT_EQ(2u, creator_.ExpansionOnNewFrame());
    EXPECT_EQ(0u, creator_.BytesFree());
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
    creator_.FlushCurrentPacket();
    EXPECT_EQ(serialized_packet_->encrypted_length, kDefaultMaxPacketSize);
    DeleteSerializedPacket();
  }
}

TEST_P(QuicPacketCreatorTest, MorePendingPaddingThanBytesFree) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  // Compute the total overhead for a single frame in packet.
  const size_t overhead =
      GetPacketHeaderOverhead(client_framer_.transport_version()) +
      GetEncryptionOverhead() +
      GetStreamFrameOverhead(client_framer_.transport_version());
  size_t capacity = kDefaultMaxPacketSize - overhead;
  const size_t pending_padding = 10;
  std::string data(capacity - pending_padding, 'A');
  QuicFrame frame;
  // The stream frame means that BytesFree() will be less than the
  // available space, because of the frame length field.
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      GetNthClientInitiatedStreamId(1), data, kOffset, false,
      /*needs_full_padding=*/false, NOT_RETRANSMISSION, &frame));
  creator_.AddPendingPadding(pending_padding);
  EXPECT_EQ(2u, creator_.ExpansionOnNewFrame());
  // BytesFree() does not know about pending_padding because that's added
  // when flushed.
  EXPECT_EQ(pending_padding - 2u, creator_.BytesFree());
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.FlushCurrentPacket();
  /* Without the fix, the packet is not full-length. */
  EXPECT_EQ(serialized_packet_->encrypted_length, kDefaultMaxPacketSize);
  DeleteSerializedPacket();
}

class MockDelegate : public QuicPacketCreator::DelegateInterface {
 public:
  MockDelegate() {}
  MockDelegate(const MockDelegate&) = delete;
  MockDelegate& operator=(const MockDelegate&) = delete;
  ~MockDelegate() override {}

  MOCK_METHOD(bool, ShouldGeneratePacket,
              (HasRetransmittableData retransmittable, IsHandshake handshake),
              (override));
  MOCK_METHOD(void, MaybeBundleOpportunistically,
              (TransmissionType transmission_type), (override));
  MOCK_METHOD(QuicByteCount, GetFlowControlSendWindowSize, (QuicStreamId),
              (override));
  MOCK_METHOD(QuicPacketBuffer, GetPacketBuffer, (), (override));
  MOCK_METHOD(void, OnSerializedPacket, (SerializedPacket), (override));
  MOCK_METHOD(void, OnUnrecoverableError, (QuicErrorCode, const std::string&),
              (override));
  MOCK_METHOD(SerializedPacketFate, GetSerializedPacketFate,
              (bool, EncryptionLevel), (override));

  void SetCanWriteAnything() {
    EXPECT_CALL(*this, ShouldGeneratePacket(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*this, ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA, _))
        .WillRepeatedly(Return(true));
  }

  void SetCanNotWrite() {
    EXPECT_CALL(*this, ShouldGeneratePacket(_, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*this, ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA, _))
        .WillRepeatedly(Return(false));
  }

  // Use this when only ack frames should be allowed to be written.
  void SetCanWriteOnlyNonRetransmittable() {
    EXPECT_CALL(*this, ShouldGeneratePacket(_, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*this, ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA, _))
        .WillRepeatedly(Return(true));
  }
};

// Simple struct for describing the contents of a packet.
// Useful in conjunction with a SimpleQuicFrame for validating that a packet
// contains the expected frames.
struct PacketContents {
  PacketContents()
      : num_ack_frames(0),
        num_connection_close_frames(0),
        num_goaway_frames(0),
        num_rst_stream_frames(0),
        num_stop_waiting_frames(0),
        num_stream_frames(0),
        num_crypto_frames(0),
        num_ping_frames(0),
        num_mtu_discovery_frames(0),
        num_padding_frames(0) {}

  size_t num_ack_frames;
  size_t num_connection_close_frames;
  size_t num_goaway_frames;
  size_t num_rst_stream_frames;
  size_t num_stop_waiting_frames;
  size_t num_stream_frames;
  size_t num_crypto_frames;
  size_t num_ping_frames;
  size_t num_mtu_discovery_frames;
  size_t num_padding_frames;
};

class MultiplePacketsTestPacketCreator : public QuicPacketCreator {
 public:
  MultiplePacketsTestPacketCreator(
      QuicConnectionId connection_id, QuicFramer* framer,
      QuicRandom* random_generator,
      QuicPacketCreator::DelegateInterface* delegate,
      SimpleDataProducer* producer)
      : QuicPacketCreator(connection_id, framer, random_generator, delegate),
        ack_frame_(InitAckFrame(1)),
        delegate_(static_cast<MockDelegate*>(delegate)),
        producer_(producer) {}

  bool ConsumeRetransmittableControlFrame(const QuicFrame& frame,
                                          bool bundle_ack) {
    QuicFrames frames;
    if (bundle_ack) {
      frames.push_back(QuicFrame(&ack_frame_));
    }
    EXPECT_CALL(*delegate_, MaybeBundleOpportunistically(_))
        .WillOnce(Invoke([this, frames = std::move(frames)] {
          FlushAckFrame(frames);
          return QuicFrames();
        }));
    return QuicPacketCreator::ConsumeRetransmittableControlFrame(frame);
  }

  QuicConsumedData ConsumeDataFastPath(QuicStreamId id,
                                       absl::string_view data) {
    // Save data before data is consumed.
    if (!data.empty()) {
      producer_->SaveStreamData(id, data);
    }
    return QuicPacketCreator::ConsumeDataFastPath(id, data.length(),
                                                  /* offset = */ 0,
                                                  /* fin = */ true, 0);
  }

  QuicConsumedData ConsumeData(QuicStreamId id, absl::string_view data,
                               QuicStreamOffset offset,
                               StreamSendingState state) {
    // Save data before data is consumed.
    if (!data.empty()) {
      producer_->SaveStreamData(id, data);
    }
    EXPECT_CALL(*delegate_, MaybeBundleOpportunistically(_)).Times(1);
    return QuicPacketCreator::ConsumeData(id, data.length(), offset, state);
  }

  MessageStatus AddMessageFrame(QuicMessageId message_id,
                                quiche::QuicheMemSlice message) {
    if (!has_ack() && delegate_->ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA,
                                                      NOT_HANDSHAKE)) {
      EXPECT_CALL(*delegate_, MaybeBundleOpportunistically(_)).Times(1);
    }
    return QuicPacketCreator::AddMessageFrame(message_id,
                                              absl::MakeSpan(&message, 1));
  }

  size_t ConsumeCryptoData(EncryptionLevel level, absl::string_view data,
                           QuicStreamOffset offset) {
    producer_->SaveCryptoData(level, offset, data);
    EXPECT_CALL(*delegate_, MaybeBundleOpportunistically(_)).Times(1);
    return QuicPacketCreator::ConsumeCryptoData(level, data.length(), offset);
  }

  QuicAckFrame ack_frame_;
  MockDelegate* delegate_;
  SimpleDataProducer* producer_;
};

class QuicPacketCreatorMultiplePacketsTest : public QuicTest {
 public:
  QuicPacketCreatorMultiplePacketsTest()
      : framer_(AllSupportedVersions(), QuicTime::Zero(),
                Perspective::IS_CLIENT, kQuicDefaultConnectionIdLength),
        creator_(TestConnectionId(), &framer_, &random_creator_, &delegate_,
                 &producer_),
        ack_frame_(InitAckFrame(1)) {
    EXPECT_CALL(delegate_, GetPacketBuffer())
        .WillRepeatedly(Return(QuicPacketBuffer()));
    EXPECT_CALL(delegate_, GetSerializedPacketFate(_, _))
        .WillRepeatedly(Return(SEND_TO_WRITER));
    EXPECT_CALL(delegate_, GetFlowControlSendWindowSize(_))
        .WillRepeatedly(Return(std::numeric_limits<QuicByteCount>::max()));
    creator_.SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
    creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
    framer_.set_data_producer(&producer_);
    if (simple_framer_.framer()->version().KnowsWhichDecrypterToUse()) {
      simple_framer_.framer()->InstallDecrypter(
          ENCRYPTION_FORWARD_SECURE, std::make_unique<TaggingDecrypter>());
    }
    creator_.AttachPacketFlusher();
  }

  ~QuicPacketCreatorMultiplePacketsTest() override {}

  void SavePacket(SerializedPacket packet) {
    QUICHE_DCHECK(packet.release_encrypted_buffer == nullptr);
    packet.encrypted_buffer = CopyBuffer(packet);
    packet.release_encrypted_buffer = [](const char* p) { delete[] p; };
    packets_.push_back(std::move(packet));
  }

 protected:
  QuicRstStreamFrame* CreateRstStreamFrame() {
    return new QuicRstStreamFrame(1, 1, QUIC_STREAM_NO_ERROR, 0);
  }

  QuicGoAwayFrame* CreateGoAwayFrame() {
    return new QuicGoAwayFrame(2, QUIC_NO_ERROR, 1, std::string());
  }

  void CheckPacketContains(const PacketContents& contents,
                           size_t packet_index) {
    ASSERT_GT(packets_.size(), packet_index);
    const SerializedPacket& packet = packets_[packet_index];
    size_t num_retransmittable_frames =
        contents.num_connection_close_frames + contents.num_goaway_frames +
        contents.num_rst_stream_frames + contents.num_stream_frames +
        contents.num_crypto_frames + contents.num_ping_frames;
    size_t num_frames =
        contents.num_ack_frames + contents.num_stop_waiting_frames +
        contents.num_mtu_discovery_frames + contents.num_padding_frames +
        num_retransmittable_frames;

    if (num_retransmittable_frames == 0) {
      ASSERT_TRUE(packet.retransmittable_frames.empty());
    } else {
      EXPECT_EQ(num_retransmittable_frames,
                packet.retransmittable_frames.size());
    }

    ASSERT_TRUE(packet.encrypted_buffer != nullptr);
    ASSERT_TRUE(simple_framer_.ProcessPacket(
        QuicEncryptedPacket(packet.encrypted_buffer, packet.encrypted_length)));
    size_t num_padding_frames = 0;
    if (contents.num_padding_frames == 0) {
      num_padding_frames = simple_framer_.padding_frames().size();
    }
    EXPECT_EQ(num_frames + num_padding_frames, simple_framer_.num_frames());
    EXPECT_EQ(contents.num_ack_frames, simple_framer_.ack_frames().size());
    EXPECT_EQ(contents.num_connection_close_frames,
              simple_framer_.connection_close_frames().size());
    EXPECT_EQ(contents.num_goaway_frames,
              simple_framer_.goaway_frames().size());
    EXPECT_EQ(contents.num_rst_stream_frames,
              simple_framer_.rst_stream_frames().size());
    EXPECT_EQ(contents.num_stream_frames,
              simple_framer_.stream_frames().size());
    EXPECT_EQ(contents.num_crypto_frames,
              simple_framer_.crypto_frames().size());
    EXPECT_EQ(contents.num_stop_waiting_frames,
              simple_framer_.stop_waiting_frames().size());
    if (contents.num_padding_frames != 0) {
      EXPECT_EQ(contents.num_padding_frames,
                simple_framer_.padding_frames().size());
    }

    // From the receiver's perspective, MTU discovery frames are ping frames.
    EXPECT_EQ(contents.num_ping_frames + contents.num_mtu_discovery_frames,
              simple_framer_.ping_frames().size());
  }

  void CheckPacketHasSingleStreamFrame(size_t packet_index) {
    ASSERT_GT(packets_.size(), packet_index);
    const SerializedPacket& packet = packets_[packet_index];
    ASSERT_FALSE(packet.retransmittable_frames.empty());
    EXPECT_EQ(1u, packet.retransmittable_frames.size());
    ASSERT_TRUE(packet.encrypted_buffer != nullptr);
    ASSERT_TRUE(simple_framer_.ProcessPacket(
        QuicEncryptedPacket(packet.encrypted_buffer, packet.encrypted_length)));
    EXPECT_EQ(1u, simple_framer_.num_frames());
    EXPECT_EQ(1u, simple_framer_.stream_frames().size());
  }

  void CheckAllPacketsHaveSingleStreamFrame() {
    for (size_t i = 0; i < packets_.size(); i++) {
      CheckPacketHasSingleStreamFrame(i);
    }
  }

  QuicFramer framer_;
  MockRandom random_creator_;
  StrictMock<MockDelegate> delegate_;
  MultiplePacketsTestPacketCreator creator_;
  SimpleQuicFramer simple_framer_;
  std::vector<SerializedPacket> packets_;
  QuicAckFrame ack_frame_;
  struct iovec iov_;
  quiche::SimpleBufferAllocator allocator_;

 private:
  std::unique_ptr<char[]> data_array_;
  SimpleDataProducer producer_;
};

TEST_F(QuicPacketCreatorMultiplePacketsTest, AddControlFrame_NotWritable) {
  delegate_.SetCanNotWrite();

  QuicRstStreamFrame* rst_frame = CreateRstStreamFrame();
  const bool consumed =
      creator_.ConsumeRetransmittableControlFrame(QuicFrame(rst_frame),
                                                  /*bundle_ack=*/false);
  EXPECT_FALSE(consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());
  delete rst_frame;
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       WrongEncryptionLevelForStreamDataFastPath) {
  creator_.set_encryption_level(ENCRYPTION_HANDSHAKE);
  delegate_.SetCanWriteAnything();
  const std::string data(10000, '?');
  EXPECT_CALL(delegate_, OnSerializedPacket(_)).Times(0);
  EXPECT_QUIC_BUG(
      {
        EXPECT_CALL(delegate_, OnUnrecoverableError(_, _));
        creator_.ConsumeDataFastPath(
            QuicUtils::GetFirstBidirectionalStreamId(
                framer_.transport_version(), Perspective::IS_CLIENT),
            data);
      },
      "");
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, AddControlFrame_OnlyAckWritable) {
  delegate_.SetCanWriteOnlyNonRetransmittable();

  QuicRstStreamFrame* rst_frame = CreateRstStreamFrame();
  const bool consumed =
      creator_.ConsumeRetransmittableControlFrame(QuicFrame(rst_frame),
                                                  /*bundle_ack=*/false);
  EXPECT_FALSE(consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());
  delete rst_frame;
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       AddControlFrame_WritableAndShouldNotFlush) {
  delegate_.SetCanWriteAnything();

  creator_.ConsumeRetransmittableControlFrame(QuicFrame(CreateRstStreamFrame()),
                                              /*bundle_ack=*/false);
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingRetransmittableFrames());
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       AddControlFrame_NotWritableBatchThenFlush) {
  delegate_.SetCanNotWrite();

  QuicRstStreamFrame* rst_frame = CreateRstStreamFrame();
  const bool consumed =
      creator_.ConsumeRetransmittableControlFrame(QuicFrame(rst_frame),
                                                  /*bundle_ack=*/false);
  EXPECT_FALSE(consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());
  delete rst_frame;
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       AddControlFrame_WritableAndShouldFlush) {
  delegate_.SetCanWriteAnything();

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));

  creator_.ConsumeRetransmittableControlFrame(QuicFrame(CreateRstStreamFrame()),
                                              /*bundle_ack=*/false);
  creator_.Flush();
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  PacketContents contents;
  contents.num_rst_stream_frames = 1;
  CheckPacketContains(contents, 0);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, ConsumeCryptoData) {
  delegate_.SetCanWriteAnything();

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  std::string data = "crypto data";
  size_t consumed_bytes =
      creator_.ConsumeCryptoData(ENCRYPTION_INITIAL, data, 0);
  creator_.Flush();
  EXPECT_EQ(data.length(), consumed_bytes);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  PacketContents contents;
  contents.num_crypto_frames = 1;
  contents.num_padding_frames = 1;
  CheckPacketContains(contents, 0);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       ConsumeCryptoDataCheckShouldGeneratePacket) {
  delegate_.SetCanNotWrite();

  EXPECT_CALL(delegate_, OnSerializedPacket(_)).Times(0);
  std::string data = "crypto data";
  size_t consumed_bytes =
      creator_.ConsumeCryptoData(ENCRYPTION_INITIAL, data, 0);
  creator_.Flush();
  EXPECT_EQ(0u, consumed_bytes);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());
}

// Tests the case that after bundling data, send window reduced to be shorter
// than data.
TEST_F(QuicPacketCreatorMultiplePacketsTest,
       ConsumeDataAdjustWriteLengthAfterBundledData) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  creator_.SetTransmissionType(NOT_RETRANSMISSION);
  delegate_.SetCanWriteAnything();

  const std::string data(1000, 'D');
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      framer_.transport_version(), Perspective::IS_CLIENT);

  EXPECT_CALL(delegate_, GetFlowControlSendWindowSize(stream_id))
      .WillOnce(Return(data.length() - 1));

  QuicConsumedData consumed = creator_.ConsumeData(stream_id, data, 0u, FIN);

  EXPECT_EQ(consumed.bytes_consumed, data.length() - 1);
  EXPECT_FALSE(consumed.fin_consumed);
}

// Tests the case that after bundling data, send window is exactly as big as
// data length.
TEST_F(QuicPacketCreatorMultiplePacketsTest,
       ConsumeDataDoesNotAdjustWriteLengthAfterBundledData) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  creator_.SetTransmissionType(NOT_RETRANSMISSION);
  delegate_.SetCanWriteAnything();

  const std::string data(1000, 'D');
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      framer_.transport_version(), Perspective::IS_CLIENT);

  EXPECT_CALL(delegate_, GetFlowControlSendWindowSize(stream_id))
      .WillOnce(Return(data.length()));

  QuicConsumedData consumed = creator_.ConsumeData(stream_id, data, 0u, FIN);

  EXPECT_EQ(consumed.bytes_consumed, data.length());
  EXPECT_TRUE(consumed.fin_consumed);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, ConsumeData_NotWritable) {
  delegate_.SetCanNotWrite();

  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      "foo", 0, FIN);
  EXPECT_EQ(0u, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       ConsumeData_WritableAndShouldNotFlush) {
  delegate_.SetCanWriteAnything();

  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      "foo", 0, FIN);
  EXPECT_EQ(3u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingRetransmittableFrames());
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       ConsumeData_WritableAndShouldFlush) {
  delegate_.SetCanWriteAnything();

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      "foo", 0, FIN);
  creator_.Flush();
  EXPECT_EQ(3u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  PacketContents contents;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);
}

// Test the behavior of ConsumeData when the data consumed is for the crypto
// handshake stream.  Ensure that the packet is always sent and padded even if
// the creator operates in batch mode.
TEST_F(QuicPacketCreatorMultiplePacketsTest, ConsumeData_Handshake) {
  delegate_.SetCanWriteAnything();

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  const std::string data = "foo bar";
  size_t consumed_bytes = 0;
  if (QuicVersionUsesCryptoFrames(framer_.transport_version())) {
    consumed_bytes = creator_.ConsumeCryptoData(ENCRYPTION_INITIAL, data, 0);
  } else {
    consumed_bytes =
        creator_
            .ConsumeData(
                QuicUtils::GetCryptoStreamId(framer_.transport_version()), data,
                0, NO_FIN)
            .bytes_consumed;
  }
  EXPECT_EQ(7u, consumed_bytes);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  PacketContents contents;
  if (QuicVersionUsesCryptoFrames(framer_.transport_version())) {
    contents.num_crypto_frames = 1;
  } else {
    contents.num_stream_frames = 1;
  }
  contents.num_padding_frames = 1;
  CheckPacketContains(contents, 0);

  ASSERT_EQ(1u, packets_.size());
  ASSERT_EQ(kDefaultMaxPacketSize, creator_.max_packet_length());
  EXPECT_EQ(kDefaultMaxPacketSize, packets_[0].encrypted_length);
}

// Test the behavior of ConsumeData when the data is for the crypto handshake
// stream, but padding is disabled.
TEST_F(QuicPacketCreatorMultiplePacketsTest,
       ConsumeData_Handshake_PaddingDisabled) {
  creator_.set_fully_pad_crypto_handshake_packets(false);

  delegate_.SetCanWriteAnything();

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  const std::string data = "foo";
  size_t bytes_consumed = 0;
  if (QuicVersionUsesCryptoFrames(framer_.transport_version())) {
    bytes_consumed = creator_.ConsumeCryptoData(ENCRYPTION_INITIAL, data, 0);
  } else {
    bytes_consumed =
        creator_
            .ConsumeData(
                QuicUtils::GetCryptoStreamId(framer_.transport_version()), data,
                0, NO_FIN)
            .bytes_consumed;
  }
  EXPECT_EQ(3u, bytes_consumed);
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  PacketContents contents;
  if (QuicVersionUsesCryptoFrames(framer_.transport_version())) {
    contents.num_crypto_frames = 1;
  } else {
    contents.num_stream_frames = 1;
  }
  contents.num_padding_frames = 0;
  CheckPacketContains(contents, 0);

  ASSERT_EQ(1u, packets_.size());

  // Packet is not fully padded, but we want to future packets to be larger.
  ASSERT_EQ(kDefaultMaxPacketSize, creator_.max_packet_length());
  size_t expected_packet_length = 31;
  if (QuicVersionUsesCryptoFrames(framer_.transport_version())) {
    // The framing of CRYPTO frames is slightly different than that of stream
    // frames, so the expected packet length differs slightly.
    expected_packet_length = 32;
  }
  EXPECT_EQ(expected_packet_length, packets_[0].encrypted_length);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, ConsumeData_EmptyData) {
  delegate_.SetCanWriteAnything();

  EXPECT_QUIC_BUG(creator_.ConsumeData(
                      QuicUtils::QuicUtils::GetFirstBidirectionalStreamId(
                          framer_.transport_version(), Perspective::IS_CLIENT),
                      {}, 0, NO_FIN),
                  "Attempt to consume empty data without FIN.");
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       ConsumeDataMultipleTimes_WritableAndShouldNotFlush) {
  delegate_.SetCanWriteAnything();

  creator_.ConsumeData(QuicUtils::GetFirstBidirectionalStreamId(
                           framer_.transport_version(), Perspective::IS_CLIENT),
                       "foo", 0, FIN);
  QuicConsumedData consumed = creator_.ConsumeData(3, "quux", 3, NO_FIN);
  EXPECT_EQ(4u, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingRetransmittableFrames());
}

TEST_F(QuicPacketCreatorMultiplePacketsTest, ConsumeData_BatchOperations) {
  delegate_.SetCanWriteAnything();

  creator_.ConsumeData(QuicUtils::GetFirstBidirectionalStreamId(
                           framer_.transport_version(), Perspective::IS_CLIENT),
                       "foo", 0, NO_FIN);
  QuicConsumedData consumed = creator_.ConsumeData(
      QuicUtils::GetFirstBidirectionalStreamId(framer_.transport_version(),
                                               Perspective::IS_CLIENT),
      "quux", 3, FIN);
  EXPECT_EQ(4u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingRetransmittableFrames());

  // Now both frames will be flushed out.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(
          Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  creator_.Flush();
  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingRetransmittableFrames());

  PacketContents contents;
  contents.num_stream_frames = 1;
  CheckPacketContains(contents, 0);
}

TEST_F(QuicPacketCreatorMultiplePacketsTest,
       ConsumeData_FramesPreviouslyQueued) {
  // Set the packet size be enough for two stream frames with 0 stream offset,
  // but not enough for a stream frame of 0 offset and one with non-zero offset.
  size_t length =
      TaggingEncrypter(0x00).GetCiphertextSize(0) +
      GetPacketHeaderSize(
          framer_.transport_version(),
          creator_.GetDestinationConnectionIdLength(),
          creator_.GetSourceConnectionIdLength(),
          QuicPacketCreatorPeer::SendVersionInPacket(&creator_),
          !kIncludeDiversificationNonce,
          QuicPacketCreatorPeer::GetPacketNumberLength(&creator_),
          QuicPacketCreatorPeer::GetRetryTokenLengthLength(&creator_), 0,
          QuicPacketCreatorPeer::GetLengthLength(&creator_)) +
      // Add an extra 3 bytes for the payload and 1 byte so
      // BytesFree is larger than the GetMinStreamFrameSize.
      QuicFramer::GetMinStreamFrameSize(framer_.transport_version(), 1, 0,
                                        false, 3) +
      3 +
      QuicFramer::GetMinStreamFrameSize(framer_.transport_version(), 1, 0, true,
                                        1) +
      1;
  creator_.SetMaxPacketLength(length);
  delegate_.SetCanWriteAnything();
  {
    InSequence dummy;
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(
            Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
    EXPECT_CALL(delegate_, OnSerializedPacket(_))
        .WillOnce(
            Invoke(this, &QuicPacketCreatorMultiplePacketsTest::SavePacket));
  }
  // Queue enough d
```