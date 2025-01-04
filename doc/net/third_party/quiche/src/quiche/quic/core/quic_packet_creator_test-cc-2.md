Response:
The user wants a summary of the functionality of the C++ code in `net/third_party/quiche/src/quiche/quic/core/quic_packet_creator_test.cc`.
I need to analyze the test cases to understand what aspects of the `QuicPacketCreator` class are being tested.

The test cases cover various aspects, including:
- Adding different types of frames (stream, ACK, padding, message).
- Handling encryption levels.
- Managing packet size limits.
- Coalescing packets.
- Retransmission logic.
- Handling errors.
- Setting and getting connection IDs and retry tokens.

I should structure the summary based on these areas.

Regarding the relationship with JavaScript, I need to consider that this is a low-level networking component. While it doesn't directly interact with JavaScript, the QUIC protocol it implements is used in web browsers, which execute JavaScript. Therefore, I can explain the connection by describing how this component facilitates communication for web applications.

For logical reasoning, I can look at test cases that involve conditional behavior or specific input/output scenarios, like the padding tests.

For common user/programming errors, I should focus on test cases that explicitly check for error conditions or potential misuses of the `QuicPacketCreator`.

To describe how a user reaches this code, I'll need to provide a high-level overview of the networking stack and how packet creation fits into it.
```cpp
        creator_.AddFrame(QuicFrame(stream_frame), NOT_RETRANSMISSION);
      },
      "Cannot send stream data with level: ENCRYPTION_INITIAL");
}

TEST_P(QuicPacketCreatorTest, SendStreamDataWithEncryptionHandshake) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration()) {
    return;
  }

  creator_.set_encryption_level(ENCRYPTION_HANDSHAKE);
  QuicStreamFrame stream_frame(GetNthClientInitiatedStreamId(0),
                               /*fin=*/false, 0u, absl::string_view());
  EXPECT_QUIC_BUG(
      {
        EXPECT_CALL(delegate_, OnUnrecoverableError(_, _));
        creator_.AddFrame(QuicFrame(stream_frame), NOT_RETRANSMISSION);
      },
      "Cannot send stream data with level: ENCRYPTION_HANDSHAKE");
}

TEST_P(QuicPacketCreatorTest, ChloTooLarge) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration()) {
    return;
  }

  // This test only matters when the crypto handshake is sent in stream frames.
  // TODO(b/128596274): Re-enable when this check is supported for CRYPTO
  // frames.
  if (QuicVersionUsesCryptoFrames(client_framer_.transport_version())) {
    return;
  }

  CryptoHandshakeMessage message;
  message.set_tag(kCHLO);
  message.set_minimum_size(kMaxOutgoingPacketSize);
  CryptoFramer framer;
  std::unique_ptr<QuicData> message_data;
  message_data = framer.ConstructHandshakeMessage(message);

  QuicFrame frame;
  EXPECT_CALL(delegate_, OnUnrecoverableError(QUIC_CRYPTO_CHLO_TOO_LARGE, _));
  EXPECT_QUIC_BUG(
      creator_.ConsumeDataToFillCurrentPacket(
          QuicUtils::GetCryptoStreamId(client_framer_.transport_version()),
          absl::string_view(message_data->data(), message_data->length()), 0u,
          false, false, NOT_RETRANSMISSION, &frame),
      "Client hello won't fit in a single packet.");
}

TEST_P(QuicPacketCreatorTest, PendingPadding) {
  EXPECT_EQ(0u, creator_.pending_padding_bytes());
  creator_.AddPendingPadding(kMaxNumRandomPaddingBytes * 10);
  EXPECT_EQ(kMaxNumRandomPaddingBytes * 10, creator_.pending_padding_bytes());

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  // Flush all paddings.
  while (creator_.pending_padding_bytes() > 0) {
    creator_.FlushCurrentPacket();
    {
      InSequence s;
      EXPECT_CALL(framer_visitor_, OnPacket());
      EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
      EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
      EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
      EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
      EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
      EXPECT_CALL(framer_visitor_, OnPacketComplete());
    }
    // Packet only contains padding.
    ProcessPacket(*serialized_packet_);
  }
  EXPECT_EQ(0u, creator_.pending_padding_bytes());
}

TEST_P(QuicPacketCreatorTest, FullPaddingDoesNotConsumePendingPadding) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  creator_.AddPendingPadding(kMaxNumRandomPaddingBytes);
  QuicFrame frame;
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  const std::string data("test");
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false,
      /*needs_full_padding=*/true, NOT_RETRANSMISSION, &frame));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.FlushCurrentPacket();
  EXPECT_EQ(kMaxNumRandomPaddingBytes, creator_.pending_padding_bytes());
}

TEST_P(QuicPacketCreatorTest, ConsumeDataAndRandomPadding) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  const QuicByteCount kStreamFramePayloadSize = 100u;
  // Set the packet size be enough for one stream frame with 0 stream offset +
  // 1.
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  size_t length =
      GetPacketHeaderOverhead(client_framer_.transport_version()) +
      GetEncryptionOverhead() +
      QuicFramer::GetMinStreamFrameSize(
          client_framer_.transport_version(), stream_id, 0,
          /*last_frame_in_packet=*/true, kStreamFramePayloadSize + 1) +
      kStreamFramePayloadSize + 1;
  creator_.SetMaxPacketLength(length);
  creator_.AddPendingPadding(kMaxNumRandomPaddingBytes);
  QuicByteCount pending_padding_bytes = creator_.pending_padding_bytes();
  QuicFrame frame;
  char buf[kStreamFramePayloadSize + 1] = {};
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  // Send stream frame of size kStreamFramePayloadSize.
  creator_.ConsumeDataToFillCurrentPacket(
      stream_id, absl::string_view(buf, kStreamFramePayloadSize), 0u, false,
      false, NOT_RETRANSMISSION, &frame);
  creator_.FlushCurrentPacket();
  // 1 byte padding is sent.
  EXPECT_EQ(pending_padding_bytes - 1, creator_.pending_padding_bytes());
  // Send stream frame of size kStreamFramePayloadSize + 1.
  creator_.ConsumeDataToFillCurrentPacket(
      stream_id, absl::string_view(buf, kStreamFramePayloadSize + 1),
      kStreamFramePayloadSize, false, false, NOT_RETRANSMISSION, &frame);
  // No padding is sent.
  creator_.FlushCurrentPacket();
  EXPECT_EQ(pending_padding_bytes - 1, creator_.pending_padding_bytes());
  // Flush all paddings.
  while (creator_.pending_padding_bytes() > 0) {
    creator_.FlushCurrentPacket();
  }
  EXPECT_EQ(0u, creator_.pending_padding_bytes());
}

TEST_P(QuicPacketCreatorTest, FlushWithExternalBuffer) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  char* buffer = new char[kMaxOutgoingPacketSize];
  QuicPacketBuffer external_buffer = {buffer,
                                      [](const char* p) { delete[] p; }};
  EXPECT_CALL(delegate_, GetPacketBuffer()).WillOnce(Return(external_buffer));

  QuicFrame frame;
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  const std::string data("test");
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false,
      /*needs_full_padding=*/true, NOT_RETRANSMISSION, &frame));

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke([&external_buffer](SerializedPacket serialized_packet) {
        EXPECT_EQ(external_buffer.buffer, serialized_packet.encrypted_buffer);
      }));
  creator_.FlushCurrentPacket();
}

// Test for error found in
// https://bugs.chromium.org/p/chromium/issues/detail?id=859949 where a gap
// length that crosses an IETF VarInt length boundary would cause a
// failure. While this test is not applicable to versions other than version 99,
// it should still work. Hence, it is not made version-specific.
TEST_P(QuicPacketCreatorTest, IetfAckGapErrorRegression) {
  QuicAckFrame ack_frame =
      InitAckFrame({{QuicPacketNumber(60), QuicPacketNumber(61)},
                    {QuicPacketNumber(125), QuicPacketNumber(126)}});
  frames_.push_back(QuicFrame(&ack_frame));
  SerializeAllFrames(frames_);
}

TEST_P(QuicPacketCreatorTest, AddMessageFrame) {
  if (client_framer_.version().UsesTls()) {
    creator_.SetMaxDatagramFrameSize(kMaxAcceptedDatagramFrameSize);
  }
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .Times(3)
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorTest::ClearSerializedPacketForTests));
  // Verify that there is enough room for the largest message payload.
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(
      creator_.GetCurrentLargestMessagePayload()));
  std::string large_message(creator_.GetCurrentLargestMessagePayload(), 'a');
  QuicMessageFrame* message_frame =
      new QuicMessageFrame(1, MemSliceFromString(large_message));
  EXPECT_TRUE(creator_.AddFrame(QuicFrame(message_frame), NOT_RETRANSMISSION));
  EXPECT_TRUE(creator_.HasPendingFrames());
  creator_.FlushCurrentPacket();

  QuicMessageFrame* frame2 =
      new QuicMessageFrame(2, MemSliceFromString("message"));
  EXPECT_TRUE(creator_.AddFrame(QuicFrame(frame2), NOT_RETRANSMISSION));
  EXPECT_TRUE(creator_.HasPendingFrames());
  // Verify if a new frame is added, 1 byte message length will be added.
  EXPECT_EQ(1u, creator_.ExpansionOnNewFrame());
  QuicMessageFrame* frame3 =
      new QuicMessageFrame(3, MemSliceFromString("message2"));
  EXPECT_TRUE(creator_.AddFrame(QuicFrame(frame3), NOT_RETRANSMISSION));
  EXPECT_EQ(1u, creator_.ExpansionOnNewFrame());
  creator_.FlushCurrentPacket();

  QuicFrame frame;
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  const std::string data("test");
  EXPECT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false, false, NOT_RETRANSMISSION, &frame));
  QuicMessageFrame* frame4 =
      new QuicMessageFrame(4, MemSliceFromString("message"));
  EXPECT_TRUE(creator_.AddFrame(QuicFrame(frame4), NOT_RETRANSMISSION));
  EXPECT_TRUE(creator_.HasPendingFrames());
  // Verify there is not enough room for largest payload.
  EXPECT_FALSE(creator_.HasRoomForMessageFrame(
      creator_.GetCurrentLargestMessagePayload()));
  // Add largest message will causes the flush of the stream frame.
  QuicMessageFrame frame5(5, MemSliceFromString(large_message));
  EXPECT_FALSE(creator_.AddFrame(QuicFrame(&frame5), NOT_RETRANSMISSION));
  EXPECT_FALSE(creator_.HasPendingFrames());
}

TEST_P(QuicPacketCreatorTest, MessageFrameConsumption) {
  if (client_framer_.version().UsesTls()) {
    creator_.SetMaxDatagramFrameSize(kMaxAcceptedDatagramFrameSize);
  }
  std::string message_data(kDefaultMaxPacketSize, 'a');
  // Test all possible encryption levels of message frames.
  for (EncryptionLevel level :
       {ENCRYPTION_ZERO_RTT, ENCRYPTION_FORWARD_SECURE}) {
    creator_.set_encryption_level(level);
    // Test all possible sizes of message frames.
    for (size_t message_size = 0;
         message_size <= creator_.GetCurrentLargestMessagePayload();
         ++message_size) {
      QuicMessageFrame* frame =
          new QuicMessageFrame(0, MemSliceFromString(absl::string_view(
                                      message_data.data(), message_size)));
      EXPECT_TRUE(creator_.AddFrame(QuicFrame(frame), NOT_RETRANSMISSION));
      EXPECT_TRUE(creator_.HasPendingFrames());

      size_t expansion_bytes = message_size >= 64 ? 2 : 1;
      EXPECT_EQ(expansion_bytes, creator_.ExpansionOnNewFrame());
      // Verify BytesFree returns bytes available for the next frame, which
      // should subtract the message length.
      size_t expected_bytes_free =
          creator_.GetCurrentLargestMessagePayload() - message_size <
                  expansion_bytes
              ? 0
              : creator_.GetCurrentLargestMessagePayload() - expansion_bytes -
                    message_size;
      EXPECT_EQ(expected_bytes_free, creator_.BytesFree());
      EXPECT_LE(creator_.GetGuaranteedLargestMessagePayload(),
                creator_.GetCurrentLargestMessagePayload());
      EXPECT_CALL(delegate_, OnSerializedPacket(_))
          .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
      creator_.FlushCurrentPacket();
      ASSERT_TRUE(serialized_packet_->encrypted_buffer);
      DeleteSerializedPacket();
    }
  }
}

TEST_P(QuicPacketCreatorTest, GetGuaranteedLargestMessagePayload) {
  ParsedQuicVersion version = GetParam().version;
  if (version.UsesTls()) {
    creator_.SetMaxDatagramFrameSize(kMaxAcceptedDatagramFrameSize);
  }
  QuicPacketLength expected_largest_payload = 1215;
  if (version.HasLongHeaderLengths()) {
    expected_largest_payload -= 2;
  }
  if (version.HasLengthPrefixedConnectionIds()) {
    expected_largest_payload -= 1;
  }
  EXPECT_EQ(expected_largest_payload,
            creator_.GetGuaranteedLargestMessagePayload());
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(
      creator_.GetGuaranteedLargestMessagePayload()));

  // Now test whether SetMaxDatagramFrameSize works.
  creator_.SetMaxDatagramFrameSize(expected_largest_payload + 1 +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload,
            creator_.GetGuaranteedLargestMessagePayload());
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(
      creator_.GetGuaranteedLargestMessagePayload()));

  creator_.SetMaxDatagramFrameSize(expected_largest_payload +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload,
            creator_.GetGuaranteedLargestMessagePayload());
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(
      creator_.GetGuaranteedLargestMessagePayload()));

  creator_.SetMaxDatagramFrameSize(expected_largest_payload - 1 +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload - 1,
            creator_.GetGuaranteedLargestMessagePayload());
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(
      creator_.GetGuaranteedLargestMessagePayload()));

  constexpr QuicPacketLength kFrameSizeLimit = 1000;
  constexpr QuicPacketLength kPayloadSizeLimit =
      kFrameSizeLimit - kQuicFrameTypeSize;
  creator_.SetMaxDatagramFrameSize(kFrameSizeLimit);
  EXPECT_EQ(creator_.GetGuaranteedLargestMessagePayload(), kPayloadSizeLimit);
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(kPayloadSizeLimit));
  EXPECT_FALSE(creator_.HasRoomForMessageFrame(kPayloadSizeLimit + 1));
}

TEST_P(QuicPacketCreatorTest, GetCurrentLargestMessagePayload) {
  ParsedQuicVersion version = GetParam().version;
  if (version.UsesTls()) {
    creator_.SetMaxDatagramFrameSize(kMaxAcceptedDatagramFrameSize);
  }
  QuicPacketLength expected_largest_payload = 1215;
  if (version.SendsVariableLengthPacketNumberInLongHeader()) {
    expected_largest_payload += 3;
  }
  if (version.HasLongHeaderLengths()) {
    expected_largest_payload -= 2;
  }
  if (version.HasLengthPrefixedConnectionIds()) {
    expected_largest_payload -= 1;
  }
  EXPECT_EQ(expected_largest_payload,
            creator_.GetCurrentLargestMessagePayload());

  // Now test whether SetMaxDatagramFrameSize works.
  creator_.SetMaxDatagramFrameSize(expected_largest_payload + 1 +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload,
            creator_.GetCurrentLargestMessagePayload());

  creator_.SetMaxDatagramFrameSize(expected_largest_payload +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload,
            creator_.GetCurrentLargestMessagePayload());

  creator_.SetMaxDatagramFrameSize(expected_largest_payload - 1 +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload - 1,
            creator_.GetCurrentLargestMessagePayload());
}

TEST_P(QuicPacketCreatorTest, PacketTransmissionType) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  QuicAckFrame temp_ack_frame = InitAckFrame(1);
  QuicFrame ack_frame(&temp_ack_frame);
  ASSERT_FALSE(QuicUtils::IsRetransmittableFrame(ack_frame.type));

  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  QuicFrame stream_frame(QuicStreamFrame(stream_id,
                                         /*fin=*/false, 0u,
                                         absl::string_view()));
  ASSERT_TRUE(QuicUtils::IsRetransmittableFrame(stream_frame.type));

  QuicFrame stream_frame_2(QuicStreamFrame(stream_id,
                                           /*fin=*/false, 1u,
                                           absl::string_view()));

  QuicFrame padding_frame{QuicPaddingFrame()};
  ASSERT_FALSE(QuicUtils::IsRetransmittableFrame(padding_frame.type));

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));

  EXPECT_TRUE(creator_.AddFrame(ack_frame, LOSS_RETRANSMISSION));
  ASSERT_EQ(serialized_packet_, nullptr);

  EXPECT_TRUE(creator_.AddFrame(stream_frame, PTO_RETRANSMISSION));
  ASSERT_EQ(serialized_packet_, nullptr);

  EXPECT_TRUE(creator_.AddFrame(stream_frame_2, PATH_RETRANSMISSION));
  ASSERT_EQ(serialized_packet_, nullptr);

  EXPECT_TRUE(creator_.AddFrame(padding_frame, PTO_RETRANSMISSION));
  creator_.FlushCurrentPacket();
  ASSERT_TRUE(serialized_packet_->encrypted_buffer);

  // The last retransmittable frame on packet is a stream frame, the packet's
  // transmission type should be the same as the stream frame's.
  EXPECT_EQ(serialized_packet_->transmission_type, PATH_RETRANSMISSION);
  DeleteSerializedPacket();
}

TEST_P(QuicPacketCreatorTest,
       PacketBytesRetransmitted_AddFrame_Retransmission) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  QuicAckFrame temp_ack_frame = InitAckFrame(1);
  QuicFrame ack_frame(&temp_ack_frame);
  EXPECT_TRUE(creator_.AddFrame(ack_frame, LOSS_RETRANSMISSION));

  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);

  QuicFrame stream_frame;
  const std::string data("data");
  // ConsumeDataToFillCurrentPacket calls AddFrame
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false, false, PTO_RETRANSMISSION, &stream_frame));
  EXPECT_EQ(4u, stream_frame.stream_frame.data_length);

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));

  creator_.FlushCurrentPacket();
  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_FALSE(serialized_packet_->bytes_not_retransmitted.has_value());

  DeleteSerializedPacket();
}

TEST_P(QuicPacketCreatorTest,
       PacketBytesRetransmitted_AddFrame_NotRetransmission) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  QuicAckFrame temp_ack_frame = InitAckFrame(1);
  QuicFrame ack_frame(&temp_ack_frame);
  EXPECT_TRUE(creator_.AddFrame(ack_frame, NOT_RETRANSMISSION));

  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);

  QuicFrame stream_frame;
  const std::string data("data");
  // ConsumeDataToFillCurrentPacket calls AddFrame
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false, false, NOT_RETRANSMISSION, &stream_frame));
  EXPECT_EQ(4u, stream_frame.stream_frame.data_length);

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));

  creator_.FlushCurrentPacket();
  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_FALSE(serialized_packet_->bytes_not_retransmitted.has_value());

  DeleteSerializedPacket();
}

TEST_P(QuicPacketCreatorTest, PacketBytesRetransmitted_AddFrame_MixedFrames) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  QuicAckFrame temp_ack_frame = InitAckFrame(1);
  QuicFrame ack_frame(&temp_ack_frame);
  EXPECT_TRUE(creator_.AddFrame(ack_frame, NOT_RETRANSMISSION));

  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);

  QuicFrame stream_frame;
  const std::string data("data");
  // ConsumeDataToFillCurrentPacket calls AddFrame
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false, false, NOT_RETRANSMISSION, &stream_frame));
  EXPECT_EQ(4u, stream_frame.stream_frame.data_length);

  QuicFrame stream_frame2;
  // ConsumeDataToFillCurrentPacket calls AddFrame
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false, false, LOSS_RETRANSMISSION, &stream_frame2));
  EXPECT_EQ(4u, stream_frame2.stream_frame.data_length);

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));

  creator_.FlushCurrentPacket();
  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_TRUE(serialized_packet_->bytes_not_retransmitted.has_value());
  ASSERT_GE(serialized_packet_->bytes_not_retransmitted.value(), 4u);

  DeleteSerializedPacket();
}

TEST_P(QuicPacketCreatorTest,
       PacketBytesRetransmitted_CreateAndSerializeStreamFrame_Retransmission) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  const std::string data("test");
  producer_.SaveStreamData(GetNthClientInitiatedStreamId(0), data);
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  size_t num_bytes_consumed;
  // Retransmission frame adds to packet's bytes_retransmitted
  creator_.CreateAndSerializeStreamFrame(
      GetNthClientInitiatedStreamId(0), data.length(), 0, 0, true,
      LOSS_RETRANSMISSION, &num_bytes_consumed);
  EXPECT_EQ(4u, num_bytes_consumed);

  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_FALSE(serialized_packet_->bytes_not_retransmitted.has_value());
  DeleteSerializedPacket();

  EXPECT_FALSE(creator_.HasPendingFrames());
}

TEST_P(
    QuicPacketCreatorTest,
    PacketBytesRetransmitted_CreateAndSerializeStreamFrame_NotRetransmission) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  const std::string data("test");
  producer_.SaveStreamData(GetNthClientInitiatedStreamId(0), data);
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  size_t num_bytes_consumed;
  // Non-retransmission frame does not add to packet's bytes_retransmitted
  creator_.CreateAndSerializeStreamFrame(
      GetNthClientInitiatedStreamId(0), data.length(), 0, 0, true,
      NOT_RETRANSMISSION, &num_bytes_consumed);
  EXPECT_EQ(4u, num_bytes_consumed);

  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_FALSE(serialized_packet_->bytes_not_retransmitted.has_value());
  DeleteSerializedPacket();

  EXPECT_FALSE(creator_.HasPendingFrames());
}

TEST_P(QuicPacketCreatorTest, RetryToken) {
  if (!GetParam().version_serialization ||
      !QuicVersionHasLongHeaderLengths(client_framer_.transport_version())) {
    return;
  }

  char retry_token_bytes[] = {1, 2,  3,  4,  5,  6,  7,  8,
                              9, 10, 11, 12, 13, 14, 15, 16};

  creator_.SetRetryToken(
      std::string(retry_token_bytes, sizeof(retry_token_bytes)));

  frames_.push_back(QuicFrame(QuicPingFrame()));
  SerializedPacket serialized = SerializeAllFrames(frames_);

  QuicPacketHeader header;
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_))
        .WillOnce(DoAll(SaveArg<0>(&header), Return(true)));
    if (client_framer_.version().HasHeaderProtection()) {
      EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    }
    EXPECT_CALL(framer_visitor_, OnPingFrame(_));
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  ProcessPacket(serialized);
  ASSERT_TRUE(header.version_flag);
  ASSERT_EQ(header.long_packet_type, INITIAL);
  ASSERT_EQ(header.retry_token.length(), sizeof(retry_token_bytes));
  quiche::test::CompareCharArraysWithHexError(
      "retry token", header.retry_token.data(), header.retry_token.length(),
      retry_token_bytes, sizeof(retry_token_bytes));
}

TEST_P(QuicPacketCreatorTest, GetConnectionId) {
  EXPECT_EQ(TestConnectionId(2), creator_.GetDestinationConnectionId());
  EXPECT_EQ(EmptyQuicConnectionId(), creator_.GetSourceConnectionId());
}

TEST_P(QuicPacketCreatorTest, ClientConnectionId) {
  if (!client_framer_.version().SupportsClientConnectionIds()) {
    return;
  }
  EXPECT_EQ(TestConnectionId(2), creator_.GetDestinationConnectionId());
  EXPECT_EQ(EmptyQuicConnectionId(), creator_.GetSourceConnectionId());
  creator_.SetClientConnectionId(TestConnectionId(0x33));
  EXPECT_EQ(TestConnectionId(2), creator_.GetDestinationConnectionId());
  EXPECT_EQ(TestConnectionId(0x33), creator_.GetSourceConnectionId());
}

TEST_P(QuicPacketCreatorTest, CoalesceStreamFrames) {
  InSequence s;
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  const size_t max_plaintext_size =
      client_framer_.GetMaxPlaintextSize(creator_.max_packet_length());
  EXPECT_FALSE(creator_.HasPendingFrames());
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  QuicStreamId stream_id1 = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  QuicStreamId stream_id2 = GetNthClientInitiatedStreamId(1);
  EXPECT_FALSE(creator_.HasPendingStreamFramesOfStream(stream_id1));
  EXPECT_EQ(max_plaintext_size -
                GetPacketHeaderSize(
                    client_framer_.transport_version(),
                    creator_.GetDestinationConnectionIdLength(),
                    creator_.GetSourceConnectionIdLength(),
                    QuicPacketCreatorPeer::SendVersionInPacket(&creator_),
                    !kIncludeDiversificationNonce,
                    QuicPacketCreatorPeer::GetPacketNumberLength(&creator_),
                    QuicPacketCreatorPeer::GetRetryTokenLengthLength(&creator_),
                    0, QuicPacketCreatorPeer::GetLengthLength(&creator_)),
            creator_.BytesFree());
  StrictMock<MockDebugDelegate> debug;
  creator_.set_debug_delegate(&debug);

  QuicFrame frame;
  const std::string data1("test");
  EXPECT_CALL(debug, OnFrameAddedToPacket(_));
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id1, data1, 0u, false, false, NOT_RETRANSMISSION, &frame));
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingStreamFramesOfStream(stream_id1));

  const std::string data2("coalesce");
  // frame will be coalesced with the first frame.
  const auto previous_size = creator_.PacketSize();
  QuicStreamFrame target(stream_id1, true, 0, data1.length() + data2.length());
  EXPECT_CALL(debug, OnStreamFrameCoalesced(target));
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id1, data2, 4u, true, false, NOT_RETRANSMISSION, &frame));
  EXPECT_EQ(frame.stream_frame.data_length,
            creator_.PacketSize() - previous_size);

  // frame is for another stream, so it won't be coalesced.
  const auto length = creator_.BytesFree() - 10u;
  const std::string data3(length, 'x');
  EXPECT_CALL(debug, OnFrameAddedToPacket(_));
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id2, data3, 0u, false, false, NOT_RETRANSMISSION, &frame));
  EXPECT_TRUE(creator_.HasPendingStreamFramesOfStream(stream_id2));

  // The packet doesn't have enough free bytes for all data, but will still be
  // able to consume and coalesce part of them.
  EXPECT_CALL(debug, OnStreamFrameCoalesced(_));
  const std::string data4("somerandomdata");
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id2, data4, length, false, false, NOT_RETRANSMISSION,
Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_packet_creator_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""

        creator_.AddFrame(QuicFrame(stream_frame), NOT_RETRANSMISSION);
      },
      "Cannot send stream data with level: ENCRYPTION_INITIAL");
}

TEST_P(QuicPacketCreatorTest, SendStreamDataWithEncryptionHandshake) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration()) {
    return;
  }

  creator_.set_encryption_level(ENCRYPTION_HANDSHAKE);
  QuicStreamFrame stream_frame(GetNthClientInitiatedStreamId(0),
                               /*fin=*/false, 0u, absl::string_view());
  EXPECT_QUIC_BUG(
      {
        EXPECT_CALL(delegate_, OnUnrecoverableError(_, _));
        creator_.AddFrame(QuicFrame(stream_frame), NOT_RETRANSMISSION);
      },
      "Cannot send stream data with level: ENCRYPTION_HANDSHAKE");
}

TEST_P(QuicPacketCreatorTest, ChloTooLarge) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration()) {
    return;
  }

  // This test only matters when the crypto handshake is sent in stream frames.
  // TODO(b/128596274): Re-enable when this check is supported for CRYPTO
  // frames.
  if (QuicVersionUsesCryptoFrames(client_framer_.transport_version())) {
    return;
  }

  CryptoHandshakeMessage message;
  message.set_tag(kCHLO);
  message.set_minimum_size(kMaxOutgoingPacketSize);
  CryptoFramer framer;
  std::unique_ptr<QuicData> message_data;
  message_data = framer.ConstructHandshakeMessage(message);

  QuicFrame frame;
  EXPECT_CALL(delegate_, OnUnrecoverableError(QUIC_CRYPTO_CHLO_TOO_LARGE, _));
  EXPECT_QUIC_BUG(
      creator_.ConsumeDataToFillCurrentPacket(
          QuicUtils::GetCryptoStreamId(client_framer_.transport_version()),
          absl::string_view(message_data->data(), message_data->length()), 0u,
          false, false, NOT_RETRANSMISSION, &frame),
      "Client hello won't fit in a single packet.");
}

TEST_P(QuicPacketCreatorTest, PendingPadding) {
  EXPECT_EQ(0u, creator_.pending_padding_bytes());
  creator_.AddPendingPadding(kMaxNumRandomPaddingBytes * 10);
  EXPECT_EQ(kMaxNumRandomPaddingBytes * 10, creator_.pending_padding_bytes());

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  // Flush all paddings.
  while (creator_.pending_padding_bytes() > 0) {
    creator_.FlushCurrentPacket();
    {
      InSequence s;
      EXPECT_CALL(framer_visitor_, OnPacket());
      EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
      EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
      EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
      EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
      EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
      EXPECT_CALL(framer_visitor_, OnPacketComplete());
    }
    // Packet only contains padding.
    ProcessPacket(*serialized_packet_);
  }
  EXPECT_EQ(0u, creator_.pending_padding_bytes());
}

TEST_P(QuicPacketCreatorTest, FullPaddingDoesNotConsumePendingPadding) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  creator_.AddPendingPadding(kMaxNumRandomPaddingBytes);
  QuicFrame frame;
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  const std::string data("test");
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false,
      /*needs_full_padding=*/true, NOT_RETRANSMISSION, &frame));
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.FlushCurrentPacket();
  EXPECT_EQ(kMaxNumRandomPaddingBytes, creator_.pending_padding_bytes());
}

TEST_P(QuicPacketCreatorTest, ConsumeDataAndRandomPadding) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  const QuicByteCount kStreamFramePayloadSize = 100u;
  // Set the packet size be enough for one stream frame with 0 stream offset +
  // 1.
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  size_t length =
      GetPacketHeaderOverhead(client_framer_.transport_version()) +
      GetEncryptionOverhead() +
      QuicFramer::GetMinStreamFrameSize(
          client_framer_.transport_version(), stream_id, 0,
          /*last_frame_in_packet=*/true, kStreamFramePayloadSize + 1) +
      kStreamFramePayloadSize + 1;
  creator_.SetMaxPacketLength(length);
  creator_.AddPendingPadding(kMaxNumRandomPaddingBytes);
  QuicByteCount pending_padding_bytes = creator_.pending_padding_bytes();
  QuicFrame frame;
  char buf[kStreamFramePayloadSize + 1] = {};
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  // Send stream frame of size kStreamFramePayloadSize.
  creator_.ConsumeDataToFillCurrentPacket(
      stream_id, absl::string_view(buf, kStreamFramePayloadSize), 0u, false,
      false, NOT_RETRANSMISSION, &frame);
  creator_.FlushCurrentPacket();
  // 1 byte padding is sent.
  EXPECT_EQ(pending_padding_bytes - 1, creator_.pending_padding_bytes());
  // Send stream frame of size kStreamFramePayloadSize + 1.
  creator_.ConsumeDataToFillCurrentPacket(
      stream_id, absl::string_view(buf, kStreamFramePayloadSize + 1),
      kStreamFramePayloadSize, false, false, NOT_RETRANSMISSION, &frame);
  // No padding is sent.
  creator_.FlushCurrentPacket();
  EXPECT_EQ(pending_padding_bytes - 1, creator_.pending_padding_bytes());
  // Flush all paddings.
  while (creator_.pending_padding_bytes() > 0) {
    creator_.FlushCurrentPacket();
  }
  EXPECT_EQ(0u, creator_.pending_padding_bytes());
}

TEST_P(QuicPacketCreatorTest, FlushWithExternalBuffer) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  char* buffer = new char[kMaxOutgoingPacketSize];
  QuicPacketBuffer external_buffer = {buffer,
                                      [](const char* p) { delete[] p; }};
  EXPECT_CALL(delegate_, GetPacketBuffer()).WillOnce(Return(external_buffer));

  QuicFrame frame;
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  const std::string data("test");
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false,
      /*needs_full_padding=*/true, NOT_RETRANSMISSION, &frame));

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke([&external_buffer](SerializedPacket serialized_packet) {
        EXPECT_EQ(external_buffer.buffer, serialized_packet.encrypted_buffer);
      }));
  creator_.FlushCurrentPacket();
}

// Test for error found in
// https://bugs.chromium.org/p/chromium/issues/detail?id=859949 where a gap
// length that crosses an IETF VarInt length boundary would cause a
// failure. While this test is not applicable to versions other than version 99,
// it should still work. Hence, it is not made version-specific.
TEST_P(QuicPacketCreatorTest, IetfAckGapErrorRegression) {
  QuicAckFrame ack_frame =
      InitAckFrame({{QuicPacketNumber(60), QuicPacketNumber(61)},
                    {QuicPacketNumber(125), QuicPacketNumber(126)}});
  frames_.push_back(QuicFrame(&ack_frame));
  SerializeAllFrames(frames_);
}

TEST_P(QuicPacketCreatorTest, AddMessageFrame) {
  if (client_framer_.version().UsesTls()) {
    creator_.SetMaxDatagramFrameSize(kMaxAcceptedDatagramFrameSize);
  }
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .Times(3)
      .WillRepeatedly(
          Invoke(this, &QuicPacketCreatorTest::ClearSerializedPacketForTests));
  // Verify that there is enough room for the largest message payload.
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(
      creator_.GetCurrentLargestMessagePayload()));
  std::string large_message(creator_.GetCurrentLargestMessagePayload(), 'a');
  QuicMessageFrame* message_frame =
      new QuicMessageFrame(1, MemSliceFromString(large_message));
  EXPECT_TRUE(creator_.AddFrame(QuicFrame(message_frame), NOT_RETRANSMISSION));
  EXPECT_TRUE(creator_.HasPendingFrames());
  creator_.FlushCurrentPacket();

  QuicMessageFrame* frame2 =
      new QuicMessageFrame(2, MemSliceFromString("message"));
  EXPECT_TRUE(creator_.AddFrame(QuicFrame(frame2), NOT_RETRANSMISSION));
  EXPECT_TRUE(creator_.HasPendingFrames());
  // Verify if a new frame is added, 1 byte message length will be added.
  EXPECT_EQ(1u, creator_.ExpansionOnNewFrame());
  QuicMessageFrame* frame3 =
      new QuicMessageFrame(3, MemSliceFromString("message2"));
  EXPECT_TRUE(creator_.AddFrame(QuicFrame(frame3), NOT_RETRANSMISSION));
  EXPECT_EQ(1u, creator_.ExpansionOnNewFrame());
  creator_.FlushCurrentPacket();

  QuicFrame frame;
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  const std::string data("test");
  EXPECT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false, false, NOT_RETRANSMISSION, &frame));
  QuicMessageFrame* frame4 =
      new QuicMessageFrame(4, MemSliceFromString("message"));
  EXPECT_TRUE(creator_.AddFrame(QuicFrame(frame4), NOT_RETRANSMISSION));
  EXPECT_TRUE(creator_.HasPendingFrames());
  // Verify there is not enough room for largest payload.
  EXPECT_FALSE(creator_.HasRoomForMessageFrame(
      creator_.GetCurrentLargestMessagePayload()));
  // Add largest message will causes the flush of the stream frame.
  QuicMessageFrame frame5(5, MemSliceFromString(large_message));
  EXPECT_FALSE(creator_.AddFrame(QuicFrame(&frame5), NOT_RETRANSMISSION));
  EXPECT_FALSE(creator_.HasPendingFrames());
}

TEST_P(QuicPacketCreatorTest, MessageFrameConsumption) {
  if (client_framer_.version().UsesTls()) {
    creator_.SetMaxDatagramFrameSize(kMaxAcceptedDatagramFrameSize);
  }
  std::string message_data(kDefaultMaxPacketSize, 'a');
  // Test all possible encryption levels of message frames.
  for (EncryptionLevel level :
       {ENCRYPTION_ZERO_RTT, ENCRYPTION_FORWARD_SECURE}) {
    creator_.set_encryption_level(level);
    // Test all possible sizes of message frames.
    for (size_t message_size = 0;
         message_size <= creator_.GetCurrentLargestMessagePayload();
         ++message_size) {
      QuicMessageFrame* frame =
          new QuicMessageFrame(0, MemSliceFromString(absl::string_view(
                                      message_data.data(), message_size)));
      EXPECT_TRUE(creator_.AddFrame(QuicFrame(frame), NOT_RETRANSMISSION));
      EXPECT_TRUE(creator_.HasPendingFrames());

      size_t expansion_bytes = message_size >= 64 ? 2 : 1;
      EXPECT_EQ(expansion_bytes, creator_.ExpansionOnNewFrame());
      // Verify BytesFree returns bytes available for the next frame, which
      // should subtract the message length.
      size_t expected_bytes_free =
          creator_.GetCurrentLargestMessagePayload() - message_size <
                  expansion_bytes
              ? 0
              : creator_.GetCurrentLargestMessagePayload() - expansion_bytes -
                    message_size;
      EXPECT_EQ(expected_bytes_free, creator_.BytesFree());
      EXPECT_LE(creator_.GetGuaranteedLargestMessagePayload(),
                creator_.GetCurrentLargestMessagePayload());
      EXPECT_CALL(delegate_, OnSerializedPacket(_))
          .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
      creator_.FlushCurrentPacket();
      ASSERT_TRUE(serialized_packet_->encrypted_buffer);
      DeleteSerializedPacket();
    }
  }
}

TEST_P(QuicPacketCreatorTest, GetGuaranteedLargestMessagePayload) {
  ParsedQuicVersion version = GetParam().version;
  if (version.UsesTls()) {
    creator_.SetMaxDatagramFrameSize(kMaxAcceptedDatagramFrameSize);
  }
  QuicPacketLength expected_largest_payload = 1215;
  if (version.HasLongHeaderLengths()) {
    expected_largest_payload -= 2;
  }
  if (version.HasLengthPrefixedConnectionIds()) {
    expected_largest_payload -= 1;
  }
  EXPECT_EQ(expected_largest_payload,
            creator_.GetGuaranteedLargestMessagePayload());
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(
      creator_.GetGuaranteedLargestMessagePayload()));

  // Now test whether SetMaxDatagramFrameSize works.
  creator_.SetMaxDatagramFrameSize(expected_largest_payload + 1 +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload,
            creator_.GetGuaranteedLargestMessagePayload());
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(
      creator_.GetGuaranteedLargestMessagePayload()));

  creator_.SetMaxDatagramFrameSize(expected_largest_payload +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload,
            creator_.GetGuaranteedLargestMessagePayload());
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(
      creator_.GetGuaranteedLargestMessagePayload()));

  creator_.SetMaxDatagramFrameSize(expected_largest_payload - 1 +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload - 1,
            creator_.GetGuaranteedLargestMessagePayload());
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(
      creator_.GetGuaranteedLargestMessagePayload()));

  constexpr QuicPacketLength kFrameSizeLimit = 1000;
  constexpr QuicPacketLength kPayloadSizeLimit =
      kFrameSizeLimit - kQuicFrameTypeSize;
  creator_.SetMaxDatagramFrameSize(kFrameSizeLimit);
  EXPECT_EQ(creator_.GetGuaranteedLargestMessagePayload(), kPayloadSizeLimit);
  EXPECT_TRUE(creator_.HasRoomForMessageFrame(kPayloadSizeLimit));
  EXPECT_FALSE(creator_.HasRoomForMessageFrame(kPayloadSizeLimit + 1));
}

TEST_P(QuicPacketCreatorTest, GetCurrentLargestMessagePayload) {
  ParsedQuicVersion version = GetParam().version;
  if (version.UsesTls()) {
    creator_.SetMaxDatagramFrameSize(kMaxAcceptedDatagramFrameSize);
  }
  QuicPacketLength expected_largest_payload = 1215;
  if (version.SendsVariableLengthPacketNumberInLongHeader()) {
    expected_largest_payload += 3;
  }
  if (version.HasLongHeaderLengths()) {
    expected_largest_payload -= 2;
  }
  if (version.HasLengthPrefixedConnectionIds()) {
    expected_largest_payload -= 1;
  }
  EXPECT_EQ(expected_largest_payload,
            creator_.GetCurrentLargestMessagePayload());

  // Now test whether SetMaxDatagramFrameSize works.
  creator_.SetMaxDatagramFrameSize(expected_largest_payload + 1 +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload,
            creator_.GetCurrentLargestMessagePayload());

  creator_.SetMaxDatagramFrameSize(expected_largest_payload +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload,
            creator_.GetCurrentLargestMessagePayload());

  creator_.SetMaxDatagramFrameSize(expected_largest_payload - 1 +
                                   kQuicFrameTypeSize);
  EXPECT_EQ(expected_largest_payload - 1,
            creator_.GetCurrentLargestMessagePayload());
}

TEST_P(QuicPacketCreatorTest, PacketTransmissionType) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  QuicAckFrame temp_ack_frame = InitAckFrame(1);
  QuicFrame ack_frame(&temp_ack_frame);
  ASSERT_FALSE(QuicUtils::IsRetransmittableFrame(ack_frame.type));

  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  QuicFrame stream_frame(QuicStreamFrame(stream_id,
                                         /*fin=*/false, 0u,
                                         absl::string_view()));
  ASSERT_TRUE(QuicUtils::IsRetransmittableFrame(stream_frame.type));

  QuicFrame stream_frame_2(QuicStreamFrame(stream_id,
                                           /*fin=*/false, 1u,
                                           absl::string_view()));

  QuicFrame padding_frame{QuicPaddingFrame()};
  ASSERT_FALSE(QuicUtils::IsRetransmittableFrame(padding_frame.type));

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));

  EXPECT_TRUE(creator_.AddFrame(ack_frame, LOSS_RETRANSMISSION));
  ASSERT_EQ(serialized_packet_, nullptr);

  EXPECT_TRUE(creator_.AddFrame(stream_frame, PTO_RETRANSMISSION));
  ASSERT_EQ(serialized_packet_, nullptr);

  EXPECT_TRUE(creator_.AddFrame(stream_frame_2, PATH_RETRANSMISSION));
  ASSERT_EQ(serialized_packet_, nullptr);

  EXPECT_TRUE(creator_.AddFrame(padding_frame, PTO_RETRANSMISSION));
  creator_.FlushCurrentPacket();
  ASSERT_TRUE(serialized_packet_->encrypted_buffer);

  // The last retransmittable frame on packet is a stream frame, the packet's
  // transmission type should be the same as the stream frame's.
  EXPECT_EQ(serialized_packet_->transmission_type, PATH_RETRANSMISSION);
  DeleteSerializedPacket();
}

TEST_P(QuicPacketCreatorTest,
       PacketBytesRetransmitted_AddFrame_Retransmission) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  QuicAckFrame temp_ack_frame = InitAckFrame(1);
  QuicFrame ack_frame(&temp_ack_frame);
  EXPECT_TRUE(creator_.AddFrame(ack_frame, LOSS_RETRANSMISSION));

  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);

  QuicFrame stream_frame;
  const std::string data("data");
  // ConsumeDataToFillCurrentPacket calls AddFrame
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false, false, PTO_RETRANSMISSION, &stream_frame));
  EXPECT_EQ(4u, stream_frame.stream_frame.data_length);

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));

  creator_.FlushCurrentPacket();
  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_FALSE(serialized_packet_->bytes_not_retransmitted.has_value());

  DeleteSerializedPacket();
}

TEST_P(QuicPacketCreatorTest,
       PacketBytesRetransmitted_AddFrame_NotRetransmission) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  QuicAckFrame temp_ack_frame = InitAckFrame(1);
  QuicFrame ack_frame(&temp_ack_frame);
  EXPECT_TRUE(creator_.AddFrame(ack_frame, NOT_RETRANSMISSION));

  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);

  QuicFrame stream_frame;
  const std::string data("data");
  // ConsumeDataToFillCurrentPacket calls AddFrame
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false, false, NOT_RETRANSMISSION, &stream_frame));
  EXPECT_EQ(4u, stream_frame.stream_frame.data_length);

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));

  creator_.FlushCurrentPacket();
  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_FALSE(serialized_packet_->bytes_not_retransmitted.has_value());

  DeleteSerializedPacket();
}

TEST_P(QuicPacketCreatorTest, PacketBytesRetransmitted_AddFrame_MixedFrames) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  QuicAckFrame temp_ack_frame = InitAckFrame(1);
  QuicFrame ack_frame(&temp_ack_frame);
  EXPECT_TRUE(creator_.AddFrame(ack_frame, NOT_RETRANSMISSION));

  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);

  QuicFrame stream_frame;
  const std::string data("data");
  // ConsumeDataToFillCurrentPacket calls AddFrame
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false, false, NOT_RETRANSMISSION, &stream_frame));
  EXPECT_EQ(4u, stream_frame.stream_frame.data_length);

  QuicFrame stream_frame2;
  // ConsumeDataToFillCurrentPacket calls AddFrame
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false, false, LOSS_RETRANSMISSION, &stream_frame2));
  EXPECT_EQ(4u, stream_frame2.stream_frame.data_length);

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));

  creator_.FlushCurrentPacket();
  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_TRUE(serialized_packet_->bytes_not_retransmitted.has_value());
  ASSERT_GE(serialized_packet_->bytes_not_retransmitted.value(), 4u);

  DeleteSerializedPacket();
}

TEST_P(QuicPacketCreatorTest,
       PacketBytesRetransmitted_CreateAndSerializeStreamFrame_Retransmission) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  const std::string data("test");
  producer_.SaveStreamData(GetNthClientInitiatedStreamId(0), data);
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  size_t num_bytes_consumed;
  // Retransmission frame adds to packet's bytes_retransmitted
  creator_.CreateAndSerializeStreamFrame(
      GetNthClientInitiatedStreamId(0), data.length(), 0, 0, true,
      LOSS_RETRANSMISSION, &num_bytes_consumed);
  EXPECT_EQ(4u, num_bytes_consumed);

  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_FALSE(serialized_packet_->bytes_not_retransmitted.has_value());
  DeleteSerializedPacket();

  EXPECT_FALSE(creator_.HasPendingFrames());
}

TEST_P(
    QuicPacketCreatorTest,
    PacketBytesRetransmitted_CreateAndSerializeStreamFrame_NotRetransmission) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  const std::string data("test");
  producer_.SaveStreamData(GetNthClientInitiatedStreamId(0), data);
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  size_t num_bytes_consumed;
  // Non-retransmission frame does not add to packet's bytes_retransmitted
  creator_.CreateAndSerializeStreamFrame(
      GetNthClientInitiatedStreamId(0), data.length(), 0, 0, true,
      NOT_RETRANSMISSION, &num_bytes_consumed);
  EXPECT_EQ(4u, num_bytes_consumed);

  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_FALSE(serialized_packet_->bytes_not_retransmitted.has_value());
  DeleteSerializedPacket();

  EXPECT_FALSE(creator_.HasPendingFrames());
}

TEST_P(QuicPacketCreatorTest, RetryToken) {
  if (!GetParam().version_serialization ||
      !QuicVersionHasLongHeaderLengths(client_framer_.transport_version())) {
    return;
  }

  char retry_token_bytes[] = {1, 2,  3,  4,  5,  6,  7,  8,
                              9, 10, 11, 12, 13, 14, 15, 16};

  creator_.SetRetryToken(
      std::string(retry_token_bytes, sizeof(retry_token_bytes)));

  frames_.push_back(QuicFrame(QuicPingFrame()));
  SerializedPacket serialized = SerializeAllFrames(frames_);

  QuicPacketHeader header;
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_))
        .WillOnce(DoAll(SaveArg<0>(&header), Return(true)));
    if (client_framer_.version().HasHeaderProtection()) {
      EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    }
    EXPECT_CALL(framer_visitor_, OnPingFrame(_));
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  ProcessPacket(serialized);
  ASSERT_TRUE(header.version_flag);
  ASSERT_EQ(header.long_packet_type, INITIAL);
  ASSERT_EQ(header.retry_token.length(), sizeof(retry_token_bytes));
  quiche::test::CompareCharArraysWithHexError(
      "retry token", header.retry_token.data(), header.retry_token.length(),
      retry_token_bytes, sizeof(retry_token_bytes));
}

TEST_P(QuicPacketCreatorTest, GetConnectionId) {
  EXPECT_EQ(TestConnectionId(2), creator_.GetDestinationConnectionId());
  EXPECT_EQ(EmptyQuicConnectionId(), creator_.GetSourceConnectionId());
}

TEST_P(QuicPacketCreatorTest, ClientConnectionId) {
  if (!client_framer_.version().SupportsClientConnectionIds()) {
    return;
  }
  EXPECT_EQ(TestConnectionId(2), creator_.GetDestinationConnectionId());
  EXPECT_EQ(EmptyQuicConnectionId(), creator_.GetSourceConnectionId());
  creator_.SetClientConnectionId(TestConnectionId(0x33));
  EXPECT_EQ(TestConnectionId(2), creator_.GetDestinationConnectionId());
  EXPECT_EQ(TestConnectionId(0x33), creator_.GetSourceConnectionId());
}

TEST_P(QuicPacketCreatorTest, CoalesceStreamFrames) {
  InSequence s;
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  const size_t max_plaintext_size =
      client_framer_.GetMaxPlaintextSize(creator_.max_packet_length());
  EXPECT_FALSE(creator_.HasPendingFrames());
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  QuicStreamId stream_id1 = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  QuicStreamId stream_id2 = GetNthClientInitiatedStreamId(1);
  EXPECT_FALSE(creator_.HasPendingStreamFramesOfStream(stream_id1));
  EXPECT_EQ(max_plaintext_size -
                GetPacketHeaderSize(
                    client_framer_.transport_version(),
                    creator_.GetDestinationConnectionIdLength(),
                    creator_.GetSourceConnectionIdLength(),
                    QuicPacketCreatorPeer::SendVersionInPacket(&creator_),
                    !kIncludeDiversificationNonce,
                    QuicPacketCreatorPeer::GetPacketNumberLength(&creator_),
                    QuicPacketCreatorPeer::GetRetryTokenLengthLength(&creator_),
                    0, QuicPacketCreatorPeer::GetLengthLength(&creator_)),
            creator_.BytesFree());
  StrictMock<MockDebugDelegate> debug;
  creator_.set_debug_delegate(&debug);

  QuicFrame frame;
  const std::string data1("test");
  EXPECT_CALL(debug, OnFrameAddedToPacket(_));
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id1, data1, 0u, false, false, NOT_RETRANSMISSION, &frame));
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingStreamFramesOfStream(stream_id1));

  const std::string data2("coalesce");
  // frame will be coalesced with the first frame.
  const auto previous_size = creator_.PacketSize();
  QuicStreamFrame target(stream_id1, true, 0, data1.length() + data2.length());
  EXPECT_CALL(debug, OnStreamFrameCoalesced(target));
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id1, data2, 4u, true, false, NOT_RETRANSMISSION, &frame));
  EXPECT_EQ(frame.stream_frame.data_length,
            creator_.PacketSize() - previous_size);

  // frame is for another stream, so it won't be coalesced.
  const auto length = creator_.BytesFree() - 10u;
  const std::string data3(length, 'x');
  EXPECT_CALL(debug, OnFrameAddedToPacket(_));
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id2, data3, 0u, false, false, NOT_RETRANSMISSION, &frame));
  EXPECT_TRUE(creator_.HasPendingStreamFramesOfStream(stream_id2));

  // The packet doesn't have enough free bytes for all data, but will still be
  // able to consume and coalesce part of them.
  EXPECT_CALL(debug, OnStreamFrameCoalesced(_));
  const std::string data4("somerandomdata");
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id2, data4, length, false, false, NOT_RETRANSMISSION, &frame));

  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  creator_.FlushCurrentPacket();
  EXPECT_CALL(framer_visitor_, OnPacket());
  EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
  EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
  EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
  EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
  // The packet should only have 2 stream frames.
  EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
  EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
  EXPECT_CALL(framer_visitor_, OnPacketComplete());
  ProcessPacket(*serialized_packet_);
}

TEST_P(QuicPacketCreatorTest, SaveNonRetransmittableFrames) {
  QuicAckFrame ack_frame(InitAckFrame(1));
  frames_.push_back(QuicFrame(&ack_frame));
  frames_.push_back(QuicFrame(QuicPaddingFrame(-1)));
  SerializedPacket serialized = SerializeAllFrames(frames_);
  ASSERT_EQ(2u, serialized.nonretransmittable_frames.size());
  EXPECT_EQ(ACK_FRAME, serialized.nonretransmittable_frames[0].type);
  EXPECT_EQ(PADDING_FRAME, serialized.nonretransmittable_frames[1].type);
  // Verify full padding frame is translated to a padding frame with actual
  // bytes of padding.
  EXPECT_LT(
      0,
      serialized.nonretransmittable_frames[1].padding_frame.num_padding_bytes);
  frames_.clear();

  // Serialize another packet with the same frames.
  SerializedPacket packet = QuicPacketCreatorPeer::SerializeAllFrames(
      &creator_, serialized.nonretransmittable_frames, buffer_,
      kMaxOutgoingPacketSize);
  // Verify the packet length of both packets are equal.
  EXPECT_EQ(serialized.encrypted_length, packet.encrypted_length);
}

TEST_P(QuicPacketCreatorTest, SerializeCoalescedPacket) {
  QuicCoalescedPacket coalesced;
  quiche::SimpleBufferAllocator allocator;
  QuicSocketAddress self_address(QuicIpAddress::Loopback4(), 1);
  QuicSocketAddress peer_address(QuicIpAddress::Loopback4(), 2);
  for (size_t i = ENCRYPTION_INITIAL; i < NUM_ENCRYPTION_LEVELS; ++i) {
    EncryptionLevel level = static_cast<EncryptionLevel>(i);
    creator_.set_encryption_level(level);
    QuicAckFrame ack_frame(InitAckFrame(1));
    if (level != ENCRYPTION_ZERO_RTT) {
      frames_.push_back(QuicFrame(&ack_frame));
    }
    if (level != ENCRYPTION_INITIAL && level != ENCRYPTION_HANDSHAKE) {
      frames_.push_back(
          QuicFrame(QuicStreamFrame(1, false, 0u, absl::string_view())));
    }
    SerializedPacket serialized = SerializeAllFrames(frames_);
    EXPECT_EQ(level, serialized.encryption_level);
    frames_.clear();
    ASSERT_TRUE(coalesced.MaybeCoalescePacket(
        serialized, self_address, peer_address, &allocator,
        creator_.max_packet_length(), ECN_NOT_ECT, 0));
  }
  char buffer[kMaxOutgoingPacketSize];
  size_t coalesced_length = creator_.SerializeCoalescedPacket(
      coalesced, buffer, kMaxOutgoingPacketSize);
  // Verify packet is padded to full.
  ASSERT_EQ(coalesced.max_packet_length(), coalesced_length);
  if (!QuicVersionHasLongHeaderLengths(server_framer_.transport_version())) {
    return;
  }
  // Verify packet process.
  std::unique_ptr<QuicEncryptedPacket> packets[NUM_ENCRYPTION_LEVELS];
  packets[ENCRYPTION_INITIAL] =
      std::make_unique<QuicEncryptedPacket>(buffer, coalesced_length);
  for (size_t i = ENCRYPTION_INITIAL; i < NUM_ENCRYPTION_LEVELS; ++i) {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    if (i < ENCRYPTION_FORWARD_SECURE) {
      // Save coalesced packet.
      EXPECT_CALL(framer_visitor_, OnCoalescedPacket(_))
          .WillOnce(Invoke([i, &packets](const QuicEncryptedPacket& packet) {
            packets[i + 1] = packet.Clone();
          }));
    }
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    if (i != ENCRYPTION_ZERO_RTT) {
      if (i != ENCRYPTION_INITIAL) {
        EXPECT_CALL(framer_visitor_, OnPaddingFrame(_))
            .Times(testing::AtMost(1));
      }
      EXPECT_CALL(framer_visitor_, OnAckFrameStart(_, _))
          .WillOnce(Return(true));
      EXPECT_CALL(framer_visitor_,
                  OnAckRange(QuicPacketNumber(1), QuicPacketNumber(2)))
          .WillOnce(Return(true));
      EXPECT_CALL(framer_visitor_, OnAckFrameEnd(_, _)).WillOnce(Return(true));
    }
    if (i == ENCRYPTION_INITIAL) {
      // Verify padding is added.
      EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    }
    if (i == ENCRYPTION_ZERO_RTT) {
      EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    }
    if (i != ENCRYPTION_INITIAL && i != ENCRYPTION_HANDSHAKE) {
      EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
    }
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
    server_framer_.ProcessPacket(*packets[i]);
  }
}

TEST_P(QuicPacketCreatorTest, SoftMaxPacketLength) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  QuicByteCount previous_max_packet_length = creator_.max_packet_length();
  const size_t overhead =
      GetPacketHeaderOverhead(client_framer_.transport_version()) +
      QuicPacketCreator::MinPlaintextPacketSize(
          client_framer_.version(),
          QuicPacketCreatorPeer::GetPacketNumberLength(&creator_)) +
      GetEncryptionOverhead();
  // Make sure a length which cannot accommodate header (includes header
  // protection minimal leng
"""


```