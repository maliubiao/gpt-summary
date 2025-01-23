Response:
The user wants a summary of the functionality of the provided C++ code snippet from `quic_connection_test.cc`. The snippet focuses on simulating the reception of various QUIC packets at different encryption levels.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the core purpose:** The code defines a class `QuicConnectionTest` with helper functions to simulate receiving packets. The names of these functions (`ProcessFramePacket`, `ProcessDataPacket`, `ProcessClosePacket`, `ProcessCoalescedPacket`, etc.) clearly indicate this.

2. **Group related functions:** Notice patterns in the function names. Many functions start with `Process...Packet` and have variations like `AtLevel` or `WithEcn`. This suggests different ways to simulate receiving the same type of packet.

3. **Analyze individual function functionalities:**
    * `ForceProcessFramePacket`: Bypasses normal packet creation, allowing the processing of frames that wouldn't normally be created.
    * `ProcessFramePacketAtLevel` and its variants: Process a packet containing a specific frame at a given encryption level, optionally with an ECN codepoint.
    * `ProcessFramesPacketAtLevel` and its variant:  Similar to the above, but handles multiple frames in a single packet.
    * `ProcessCoalescedPacket`: Simulates receiving multiple QUIC packets bundled together.
    * `ProcessDataPacketAtLevel`:  Simulates receiving a data packet at a specific encryption level, potentially with STOP_WAITING information.
    * `ProcessCryptoPacketAtLevel`: Simulates receiving a crypto handshake packet.
    * `ProcessClosePacket`: Simulates receiving a connection close packet.
    * `ProcessAckPacket`: Simulates receiving an ACK frame.
    * `ProcessStopWaitingPacketAtLevel`: Simulates receiving a STOP_WAITING frame.
    * `ProcessGoAwayPacket`: Simulates receiving a GO_AWAY frame.

4. **Identify key concepts:**  Terms like "encryption level", "frames", "packet number", "ECN", "coalesced packets" are repeated, indicating important QUIC concepts being tested.

5. **Consider relationships to JavaScript:**  QUIC is a transport protocol. JavaScript, being a client-side scripting language, interacts with network protocols through browser APIs. While JavaScript doesn't directly handle the low-level packet processing shown here, understanding QUIC helps in debugging network issues and understanding browser behavior related to network connections. Examples could include observing network traffic in browser developer tools or understanding the impact of network conditions on web application performance.

6. **Look for logical reasoning and input/output:** The functions simulate packet processing. The input is the packet data (represented by frames and headers) and the encryption level. The output is the effect on the internal state of the `connection_` object. For example, processing an ACK updates the connection's acknowledgment state.

7. **Consider common usage errors:**  These test functions are designed to catch errors. Common errors in QUIC implementation might involve incorrect encryption/decryption, wrong packet ordering, or invalid frame structures. The `ForceProcessFramePacket` function highlights the possibility of creating invalid packets.

8. **Trace user actions to reach this code:** This code is part of the Chromium networking stack. A user's web request triggers a series of actions that eventually lead to the browser sending and receiving QUIC packets. This test code simulates the receiving end of that process.

9. **Summarize the overall functionality:**  Combine the observations to create a concise summary focusing on the core purpose and the various ways it's achieved.

10. **Address the "Part 2 of 24" instruction:**  Acknowledge that this is a part of a larger test suite and the current snippet focuses on packet reception simulation.

This systematic approach allows for a comprehensive understanding of the code's functionality and its role within the larger context of QUIC testing.
```cpp
rm()->Fire();
    }
  }

  // Bypassing the packet creator is unrealistic, but allows us to process
  // packets the QuicPacketCreator won't allow us to create.
  void ForceProcessFramePacket(QuicFrame frame) {
    QuicFrames frames;
    frames.push_back(QuicFrame(frame));
    bool send_version = connection_.perspective() == Perspective::IS_SERVER;
    if (connection_.version().KnowsWhichDecrypterToUse()) {
      send_version = true;
    }
    QuicPacketCreatorPeer::SetSendVersionInPacket(&peer_creator_, send_version);
    QuicPacketHeader header;
    QuicPacketCreatorPeer::FillPacketHeader(&peer_creator_, &header);
    char encrypted_buffer[kMaxOutgoingPacketSize];
    size_t length = peer_framer_.BuildDataPacket(
        header, frames, encrypted_buffer, kMaxOutgoingPacketSize,
        ENCRYPTION_INITIAL);
    QUICHE_DCHECK_GT(length, 0u);

    const size_t encrypted_length = peer_framer_.EncryptInPlace(
        ENCRYPTION_INITIAL, header.packet_number,
        GetStartOfEncryptedData(peer_framer_.version().transport_version,
                                header),
        length, kMaxOutgoingPacketSize, encrypted_buffer);
    QUICHE_DCHECK_GT(encrypted_length, 0u);

    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(encrypted_buffer, encrypted_length, clock_.Now()));
  }

  size_t ProcessFramePacketAtLevel(uint64_t number, QuicFrame frame,
                                   EncryptionLevel level) {
    return ProcessFramePacketAtLevelWithEcn(number, frame, level, ECN_NOT_ECT);
  }

  size_t ProcessFramePacketAtLevelWithEcn(uint64_t number, QuicFrame frame,
                                          EncryptionLevel level,
                                          QuicEcnCodepoint ecn_codepoint) {
    QuicFrames frames;
    frames.push_back(frame);
    return ProcessFramesPacketAtLevelWithEcn(number, frames, level,
                                             ecn_codepoint);
  }

  size_t ProcessFramesPacketAtLevel(uint64_t number, QuicFrames frames,
                                    EncryptionLevel level) {
    return ProcessFramesPacketAtLevelWithEcn(number, frames, level,
                                             ECN_NOT_ECT);
  }

  size_t ProcessFramesPacketAtLevelWithEcn(uint64_t number,
                                           const QuicFrames& frames,
                                           EncryptionLevel level,
                                           QuicEcnCodepoint ecn_codepoint) {
    QuicPacketHeader header = ConstructPacketHeader(number, level);
    // Set the correct encryption level and encrypter on peer_creator and
    // peer_framer, respectively.
    peer_creator_.set_encryption_level(level);
    if (level > ENCRYPTION_INITIAL) {
      peer_framer_.SetEncrypter(level,
                                std::make_unique<TaggingEncrypter>(level));
      // Set the corresponding decrypter.
      if (connection_.version().KnowsWhichDecrypterToUse()) {
        connection_.InstallDecrypter(
            level, std::make_unique<StrictTaggingDecrypter>(level));
      } else {
        connection_.SetAlternativeDecrypter(
            level, std::make_unique<StrictTaggingDecrypter>(level), false);
      }
    }
    std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));

    char buffer[kMaxOutgoingPacketSize];
    size_t encrypted_length =
        peer_framer_.EncryptPayload(level, QuicPacketNumber(number), *packet,
                                    buffer, kMaxOutgoingPacketSize);
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(buffer, encrypted_length, clock_.Now(), false, 0,
                           true, nullptr, 0, false, ecn_codepoint));
    if (connection_.GetSendAlarm()->IsSet()) {
      connection_.GetSendAlarm()->Fire();
    }
    return encrypted_length;
  }

  struct PacketInfo {
    PacketInfo(uint64_t packet_number, QuicFrames frames, EncryptionLevel level)
        : packet_number(packet_number), frames(frames), level(level) {}

    uint64_t packet_number;
    QuicFrames frames;
    EncryptionLevel level;
  };

  size_t ProcessCoalescedPacket(std::vector<PacketInfo> packets) {
    return ProcessCoalescedPacket(packets, ECN_NOT_ECT);
  }

  size_t ProcessCoalescedPacket(std::vector<PacketInfo> packets,
                                QuicEcnCodepoint ecn_codepoint) {
    char coalesced_buffer[kMaxOutgoingPacketSize];
    size_t coalesced_size = 0;
    bool contains_initial = false;
    for (const auto& packet : packets) {
      QuicPacketHeader header =
          ConstructPacketHeader(packet.packet_number, packet.level);
      // Set the correct encryption level and encrypter on peer_creator and
      // peer_framer, respectively.
      peer_creator_.set_encryption_level(packet.level);
      if (packet.level == ENCRYPTION_INITIAL) {
        contains_initial = true;
      }
      EncryptionLevel level =
          QuicPacketCreatorPeer::GetEncryptionLevel(&peer_creator_);
      if (level > ENCRYPTION_INITIAL) {
        peer_framer_.SetEncrypter(level,
                                  std::make_unique<TaggingEncrypter>(level));
        // Set the corresponding decrypter.
        if (connection_.version().KnowsWhichDecrypterToUse()) {
          connection_.InstallDecrypter(
              level, std::make_unique<StrictTaggingDecrypter>(level));
        } else {
          connection_.SetDecrypter(
              level, std::make_unique<StrictTaggingDecrypter>(level));
        }
      }
      std::unique_ptr<QuicPacket> constructed_packet(
          ConstructPacket(header, packet.frames));

      char buffer[kMaxOutgoingPacketSize];
      size_t encrypted_length = peer_framer_.EncryptPayload(
          packet.level, QuicPacketNumber(packet.packet_number),
          *constructed_packet, buffer, kMaxOutgoingPacketSize);
      QUICHE_DCHECK_LE(coalesced_size + encrypted_length,
                       kMaxOutgoingPacketSize);
      memcpy(coalesced_buffer + coalesced_size, buffer, encrypted_length);
      coalesced_size += encrypted_length;
    }
    if (contains_initial) {
      // Padded coalesced packet to full if it contains initial packet.
      memset(coalesced_buffer + coalesced_size, '0',
             kMaxOutgoingPacketSize - coalesced_size);
    }
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(coalesced_buffer, coalesced_size, clock_.Now(),
                           false, 0, true, nullptr, 0, false, ecn_codepoint));
    if (connection_.GetSendAlarm()->IsSet()) {
      connection_.GetSendAlarm()->Fire();
    }
    return coalesced_size;
  }

  size_t ProcessDataPacket(uint64_t number) {
    return ProcessDataPacketAtLevel(number, false, ENCRYPTION_FORWARD_SECURE);
  }

  size_t ProcessDataPacket(QuicPacketNumber packet_number) {
    return ProcessDataPacketAtLevel(packet_number, false,
                                    ENCRYPTION_FORWARD_SECURE);
  }

  size_t ProcessDataPacketAtLevel(QuicPacketNumber packet_number,
                                  bool has_stop_waiting,
                                  EncryptionLevel level) {
    return ProcessDataPacketAtLevel(packet_number.ToUint64(), has_stop_waiting,
                                    level);
  }

  size_t ProcessDataPacketAtLevel(uint64_t number, bool has_stop_waiting,
                                  EncryptionLevel level) {
    return ProcessDataPacketAtLevel(number, has_stop_waiting, level, 0);
  }

  size_t ProcessCryptoPacketAtLevel(uint64_t number, EncryptionLevel level) {
    QuicPacketHeader header = ConstructPacketHeader(number, level);
    QuicFrames frames;
    if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
      frames.push_back(QuicFrame(&crypto_frame_));
    } else {
      frames.push_back(QuicFrame(frame1_));
    }
    if (level == ENCRYPTION_INITIAL) {
      frames.push_back(QuicFrame(QuicPaddingFrame(-1)));
    }
    std::unique_ptr<QuicPacket> packet = ConstructPacket(header, frames);
    char buffer[kMaxOutgoingPacketSize];
    peer_creator_.set_encryption_level(level);
    size_t encrypted_length =
        peer_framer_.EncryptPayload(level, QuicPacketNumber(number), *packet,
                                    buffer, kMaxOutgoingPacketSize);
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(buffer, encrypted_length, clock_.Now(), false));
    if (connection_.GetSendAlarm()->IsSet()) {
      connection_.GetSendAlarm()->Fire();
    }
    return encrypted_length;
  }

  size_t ProcessDataPacketAtLevel(uint64_t number, bool has_stop_waiting,
                                  EncryptionLevel level, uint32_t flow_label) {
    std::unique_ptr<QuicPacket> packet(
        ConstructDataPacket(number, has_stop_waiting, level));
    char buffer[kMaxOutgoingPacketSize];
    peer_creator_.set_encryption_level(level);
    size_t encrypted_length =
        peer_framer_.EncryptPayload(level, QuicPacketNumber(number), *packet,
                                    buffer, kMaxOutgoingPacketSize);
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(buffer, encrypted_length, clock_.Now(), false,
                           0 /* ttl */, true /* ttl_valid */,
                           nullptr /* packet_headers */, 0 /* headers_length */,
                           false /* owns_header_buffer */, ECN_NOT_ECT,
                           flow_label));

    if (connection_.GetSendAlarm()->IsSet()) {
      connection_.GetSendAlarm()->Fire();
    }
    return encrypted_length;
  }

  void ProcessClosePacket(uint64_t number) {
    std::unique_ptr<QuicPacket> packet(ConstructClosePacket(number));
    char buffer[kMaxOutgoingPacketSize];
    size_t encrypted_length = peer_framer_.EncryptPayload(
        ENCRYPTION_FORWARD_SECURE, QuicPacketNumber(number), *packet, buffer,
        kMaxOutgoingPacketSize);
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));
  }

  QuicByteCount SendStreamDataToPeer(QuicStreamId id, absl::string_view data,
                                     QuicStreamOffset offset,
                                     StreamSendingState state,
                                     QuicPacketNumber* last_packet) {
    QuicByteCount packet_size = 0;
    // Save the last packet's size.
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(SaveArg<3>(&packet_size));
    connection_.SendStreamDataWithString(id, data, offset, state);
    if (last_packet != nullptr) {
      *last_packet = creator_->packet_number();
    }
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AnyNumber());
    return packet_size;
  }

  void SendAckPacketToPeer() {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
    {
      QuicConnection::ScopedPacketFlusher flusher(&connection_);
      connection_.SendAck();
    }
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AnyNumber());
  }

  void SendRstStream(QuicStreamId id, QuicRstStreamErrorCode error,
                     QuicStreamOffset bytes_written) {
    notifier_.WriteOrBufferRstStream(id, error, bytes_written);
    connection_.OnStreamReset(id, error);
  }

  void SendPing() { notifier_.WriteOrBufferPing(); }

  MessageStatus SendMessage(absl::string_view message) {
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    quiche::QuicheMemSlice slice(quiche::QuicheBuffer::Copy(
        connection_.helper()->GetStreamSendBufferAllocator(), message));
    return connection_.SendMessage(1, absl::MakeSpan(&slice, 1), false);
  }

  void ProcessAckPacket(uint64_t packet_number, QuicAckFrame* frame) {
    if (packet_number > 1) {
      QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, packet_number - 1);
    } else {
      QuicPacketCreatorPeer::ClearPacketNumber(&peer_creator_);
    }
    ProcessFramePacket(QuicFrame(frame));
  }

  void ProcessAckPacket(QuicAckFrame* frame) {
    ProcessFramePacket(QuicFrame(frame));
  }

  void ProcessStopWaitingPacket(QuicStopWaitingFrame frame) {
    ProcessFramePacket(QuicFrame(frame));
  }

  size_t ProcessStopWaitingPacketAtLevel(uint64_t number,
                                         QuicStopWaitingFrame frame,
                                         EncryptionLevel /*level*/) {
    return ProcessFramePacketAtLevel(number, QuicFrame(frame),
                                     ENCRYPTION_ZERO_RTT);
  }

  void ProcessGoAwayPacket(QuicGoAwayFrame* frame) {
    ProcessFramePacket(QuicFrame(frame));
  }

  bool IsMissing(uint64_t number) {
    return IsAwaitingPacket(connection_.ack_frame(), QuicPacketNumber(number),
                            QuicPacketNumber());
  }

  std::unique_ptr<QuicPacket> ConstructPacket(const QuicPacketHeader& header,
                                              const QuicFrames& frames) {
    auto packet = BuildUnsizedDataPacket(&peer_framer_, header, frames);
    EXPECT_NE(nullptr, packet.get());
    return packet;
  }

  QuicPacketHeader ConstructPacketHeader(uint64_t number,
                                         EncryptionLevel level) {
    QuicPacketHeader header;
    if (level < ENCRYPTION_FORWARD_SECURE) {
      // Set long header type accordingly.
      header.version_flag = true;
      header.form = IETF_QUIC_LONG_HEADER_PACKET;
      header.long_packet_type = EncryptionlevelToLongHeaderType(level);
      if (QuicVersionHasLongHeaderLengths(
              peer_framer_.version().transport_version)) {
        header.length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
        if (header.long_packet_type == INITIAL) {
          header.retry_token_length_length =
              quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1;
        }
      }
    }
    // Set connection_id to peer's in memory representation as this data packet
    // is created by peer_framer.
    if (peer_framer_.perspective() == Perspective::IS_SERVER) {
      header.source_connection_id = connection_id_;
      header.source_connection_id_included = connection_id_included_;
      header.destination_connection_id_included = CONNECTION_ID_ABSENT;
    } else {
      header.destination_connection_id = connection_id_;
      header.destination_connection_id_included = connection_id_included_;
    }
    if (peer_framer_.perspective() == Perspective::IS_SERVER) {
      if (!connection_.client_connection_id().IsEmpty()) {
        header.destination_connection_id = connection_.client_connection_id();
        header.destination_connection_id_included = CONNECTION_ID_PRESENT;
      } else {
        header.destination_connection_id_included = CONNECTION_ID_ABSENT;
      }
      if (header.version_flag) {
        header.source_connection_id = connection_id_;
        header.source_connection_id_included = CONNECTION_ID_PRESENT;
        if (GetParam().version.handshake_protocol == PROTOCOL_QUIC_CRYPTO &&
            header.long_packet_type == ZERO_RTT_PROTECTED) {
          header.nonce = &kTestDiversificationNonce;
        }
      }
    }
    header.packet_number_length = packet_number_length_;
    header.packet_number = QuicPacketNumber(number);
    return header;
  }

  std::unique_ptr<QuicPacket> ConstructDataPacket(uint64_t number,
                                                  bool has_stop_waiting,
                                                  EncryptionLevel level) {
    QuicPacketHeader header = ConstructPacketHeader(number, level);
    QuicFrames frames;
    if (VersionHasIetfQuicFrames(version().transport_version) &&
        (level == ENCRYPTION_INITIAL || level == ENCRYPTION_HANDSHAKE)) {
      frames.push_back(QuicFrame(QuicPingFrame()));
      frames.push_back(QuicFrame(QuicPaddingFrame(100)));
    } else {
      frames.push_back(QuicFrame(frame1_));
      if (has_stop_waiting) {
        frames.push_back(QuicFrame(stop_waiting_));
      }
    }
    return ConstructPacket(header, frames);
  }

  std::unique_ptr<SerializedPacket> ConstructProbingPacket() {
    peer_creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
    if (VersionHasIetfQuicFrames(version().transport_version)) {
      QuicPathFrameBuffer payload = {
          {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xfe}};
      return QuicPacketCreatorPeer::
          SerializePathChallengeConnectivityProbingPacket(&peer_creator_,
                                                          payload);
    }
    QUICHE_DCHECK(!GetQuicReloadableFlag(quic_ignore_gquic_probing));
    return QuicPacketCreatorPeer::SerializeConnectivityProbingPacket(
        &peer_creator_);
  }

  std::unique_ptr<QuicPacket> ConstructClosePacket(uint64_t number) {
    peer_creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
    QuicPacketHeader header;
    // Set connection_id to peer's in memory representation as this connection
    // close packet is created by peer_framer.
    if (peer_framer_.perspective() == Perspective::IS_SERVER) {
      header.source_connection_id = connection_id_;
      header.destination_connection_id_included = CONNECTION_ID_ABSENT;
    } else {
      header.destination_connection_id = connection_id_;
      header.destination_connection_id_included = CONNECTION_ID_ABSENT;
    }

    header.packet_number = QuicPacketNumber(number);

    QuicErrorCode kQuicErrorCode = QUIC_PEER_GOING_AWAY;
    QuicConnectionCloseFrame qccf(peer_framer_.transport_version(),
                                  kQuicErrorCode, NO_IETF_QUIC_ERROR, "",
                                  /*transport_close_frame_type=*/0);
    QuicFrames frames;
    frames.push_back(QuicFrame(&qccf));
    return ConstructPacket(header, frames);
  }

  QuicTime::Delta DefaultRetransmissionTime() {
    return QuicTime::Delta::FromMilliseconds(kDefaultRetransmissionTimeMs);
  }

  QuicTime::Delta DefaultDelayedAckTime() {
    return QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());
  }

  const QuicStopWaitingFrame InitStopWaitingFrame(uint64_t least_unacked) {
    QuicStopWaitingFrame frame;
    frame.least_unacked = QuicPacketNumber(least_unacked);
    return frame;
  }

  // Construct a ack_frame that acks all packet numbers between 1 and
  // |largest_acked|, except |missing|.
  // REQUIRES: 1 <= |missing| < |largest_acked|
  QuicAckFrame ConstructAckFrame(uint64_t largest_acked, uint64_t missing) {
    return ConstructAckFrame(QuicPacketNumber(largest_acked),
                             QuicPacketNumber(missing));
  }

  QuicAckFrame ConstructAckFrame(QuicPacketNumber largest_acked,
                                 QuicPacketNumber missing) {
    if (missing == QuicPacketNumber(1)) {
      return InitAckFrame({{missing + 1, largest_acked + 1}});
    }
    return InitAckFrame(
        {{QuicPacketNumber(1), missing}, {missing + 1, largest_acked + 1}});
  }

  // Undo nacking a packet within the frame.
  void AckPacket(QuicPacketNumber arrived, QuicAckFrame* frame) {
    EXPECT_FALSE(frame->packets.Contains(arrived));
    frame->packets.Add(arrived);
  }

  void TriggerConnectionClose() {
    // Send an erroneous packet to close the connection.
    EXPECT_CALL(visitor_,
                OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
        .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));

    EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
    // Triggers a connection by receiving ACK of unsent packet.
    QuicAckFrame frame = InitAckFrame(10000);
    ProcessAckPacket(1, &frame);
    EXPECT_FALSE(QuicConnectionPeer::GetConnectionClosePacket(&connection_) ==
                 nullptr);
    EXPECT_EQ(1, connection_close_frame_count_);
    EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
                IsError(QUIC_INVALID_ACK_DATA));
  }

  void BlockOnNextWrite() {
    writer_->BlockOnNextWrite();
    EXPECT_CALL(visitor_, OnWriteBlocked()).Times(AtLeast(1));
  }

  void SimulateNextPacketTooLarge() { writer_->SimulateNextPacketTooLarge(); }

  void ExpectNextPacketUnprocessable() {
    writer_->ExpectNextPacketUnprocessable();
  }

  void AlwaysGetPacketTooLarge() { writer_->AlwaysGetPacketTooLarge(); }

  void SetWritePauseTimeDelta(QuicTime::Delta delta) {
    writer_->SetWritePauseTimeDelta(delta);
  }

  void CongestionBlockWrites() {
    EXPECT_CALL(*send_algorithm_, CanSend(_))
        .WillRepeatedly(testing::Return(false));
  }

  void CongestionUnblockWrites() {
    EXPECT_CALL(*send_algorithm_, CanSend(_))
        .WillRepeatedly(testing::Return(true));
  }

  void set_perspective(Perspective perspective) {
    connection_.set_perspective(perspective);
    if (perspective == Perspective::IS_SERVER) {
      connection_.set_can_truncate_connection_ids(true);
      QuicConnectionPeer::SetNegotiatedVersion(&connection_);
      connection_.OnSuccessfulVersionNegotiation();
    }
    QuicFramerPeer::SetPerspective(&peer_framer_,
                                   QuicUtils::InvertPerspective(perspective));
    peer_framer_.SetInitialObfuscators(TestConnectionId());
    for (EncryptionLevel level : {ENCRYPTION_ZERO_RTT, ENCRYPTION_HANDSHAKE,
                                  ENCRYPTION_FORWARD_SECURE}) {
      if (peer_framer_.HasEncrypterOfEncryptionLevel(level)) {
        peer_creator_.SetEncrypter(level,
                                   std::make_unique<TaggingEncrypter>(level));
      }
    }
  }

  void set_packets_between_probes_base(
      const QuicPacketCount packets_between_probes_base) {
    QuicConnectionPeer::ReInitializeMtuDiscoverer(
        &connection_, packets_between_probes_base,
        QuicPacketNumber(packets_between_probes_base));
  }

  bool IsDefaultTestConfiguration() {
    TestParams p = GetParam();
    return p.ack_response == AckResponse::kImmediate &&
           p.version == AllSupportedVersions()[0];
  }

  void TestConnectionCloseQuicErrorCode(QuicErrorCode expected_code) {
    // Not strictly needed for this test, but is commonly done.
    EXPECT_FALSE(QuicConnectionPeer::GetConnectionClosePacket(&connection_) ==
                 nullptr);
    const std::vector<QuicConnectionCloseFrame>& connection_close_frames =
        writer_->connection_close_frames();
    ASSERT_EQ(1u, connection_close_frames.size());

    EXPECT_THAT(connection_close_frames[0].quic_error_code,
                IsError(expected_code));

    if (!VersionHasIetfQuicFrames(version().transport_version)) {
      EXPECT_THAT(connection_close_frames[0].wire_error_code,
                  IsError(expected_code));
      EXPECT_EQ(GOOGLE_QUIC_CONNECTION_CLOSE,
                connection_close_frames[0].close_type);
      return;
    }

    QuicErrorCodeToIetfMapping mapping =
        QuicErrorCodeToTransportErrorCode(expected_code);

    if (mapping.is_transport_close) {
      // This Google QUIC Error Code maps to a transport close,
      EXPECT_EQ(IETF_QUIC_TRANSPORT_CONNECTION_CLOSE,
                connection_close_frames[0].close_type);
    } else {
      // This maps to an application close.
      EXPECT_EQ(IETF_QUIC_APPLICATION_CONNECTION_CLOSE,
                connection_close_frames[0].close_type);
    }
    EXPECT_EQ(mapping.error_code, connection_close_frames[0].wire_error_code);
  }

  void MtuDiscoveryTestInit() {
    set_perspective(Perspective::IS_SERVER);
    QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
    if (version().SupportsAntiAmplificationLimit()) {
      QuicConnectionPeer::SetAddressValidated(&connection_);
    }
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    peer_creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
    // Prevent packets from being coalesced.
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
    EXPECT_TRUE(connection_.connected());
  }

  void PathProbeTestInit(Perspective perspective,
                         bool receive_new_server_connection_id = true) {
    set_perspective(perspective);
    connection_.CreateConnectionIdManager();
    EXPECT_EQ(connection_.perspective(), perspective);
    if (perspective == Perspective::IS_SERVER) {
      QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
    }
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    peer_creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
    // Discard INITIAL key.
    connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
    connection_.NeuterUnencryptedPackets();
    // Prevent packets from being coalesced.
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
    if (version().SupportsAntiAmplificationLimit() &&
        perspective == Perspective::IS_SERVER) {
      QuicConnectionPeer::SetAddressValidated(&connection_);
    }
    // Clear direct_peer_address.
    QuicConnectionPeer::SetDirectPeerAddress(&connection_, QuicSocketAddress());
    // Clear effective_peer_address, it is the same as direct_peer_address for
    // this test.
    QuicConnectionPeer::SetEffectivePeerAddress(&connection_,
                                                QuicSocketAddress());
    EXPECT_FALSE(connection_.effective_peer_address().IsInitialized());

    if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
      EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
    } else {
      EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
    }
    QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 2);
    ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress,
                                    kPeerAddress, ENCRYPTION_FORWARD_SECURE);
    EXPECT_EQ(kPeerAddress, connection_.peer_address());
    EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
    if (perspective == Perspective::IS_CLIENT &&
        receive_new_server_connection_id && version().HasIetfQuicFrames()) {
      QuicNewConnectionIdFrame frame;
      frame.connection_id = TestConnectionId(1234);
      ASSERT_NE(frame.connection_id, connection_.connection_id());
      frame.stateless_reset_token =
          QuicUtils::GenerateStatelessResetToken(frame.connection_id);
      frame.retire_prior_to = 0u;
      frame.sequence_number = 1u;
      connection_.OnNewConnectionIdFrame(frame);
    }
  }

  void ServerHandlePreferredAddressInit() {
    ASSERT_TRUE(GetParam().version.HasIetfQuicFrames());
    set_perspective(Perspective::IS_SERVER);
    connection_.CreateConnectionIdManager();
    QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
    SetQuicReloadableFlag(quic_use_received_client_addresses_cache, true);
    EXPECT_CALL(visitor_, AllowSelfAddressChange())
        .WillRepeatedly(Return(true));

    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    peer_creator_.set_encryption_level(ENCRY
### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
rm()->Fire();
    }
  }

  // Bypassing the packet creator is unrealistic, but allows us to process
  // packets the QuicPacketCreator won't allow us to create.
  void ForceProcessFramePacket(QuicFrame frame) {
    QuicFrames frames;
    frames.push_back(QuicFrame(frame));
    bool send_version = connection_.perspective() == Perspective::IS_SERVER;
    if (connection_.version().KnowsWhichDecrypterToUse()) {
      send_version = true;
    }
    QuicPacketCreatorPeer::SetSendVersionInPacket(&peer_creator_, send_version);
    QuicPacketHeader header;
    QuicPacketCreatorPeer::FillPacketHeader(&peer_creator_, &header);
    char encrypted_buffer[kMaxOutgoingPacketSize];
    size_t length = peer_framer_.BuildDataPacket(
        header, frames, encrypted_buffer, kMaxOutgoingPacketSize,
        ENCRYPTION_INITIAL);
    QUICHE_DCHECK_GT(length, 0u);

    const size_t encrypted_length = peer_framer_.EncryptInPlace(
        ENCRYPTION_INITIAL, header.packet_number,
        GetStartOfEncryptedData(peer_framer_.version().transport_version,
                                header),
        length, kMaxOutgoingPacketSize, encrypted_buffer);
    QUICHE_DCHECK_GT(encrypted_length, 0u);

    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(encrypted_buffer, encrypted_length, clock_.Now()));
  }

  size_t ProcessFramePacketAtLevel(uint64_t number, QuicFrame frame,
                                   EncryptionLevel level) {
    return ProcessFramePacketAtLevelWithEcn(number, frame, level, ECN_NOT_ECT);
  }

  size_t ProcessFramePacketAtLevelWithEcn(uint64_t number, QuicFrame frame,
                                          EncryptionLevel level,
                                          QuicEcnCodepoint ecn_codepoint) {
    QuicFrames frames;
    frames.push_back(frame);
    return ProcessFramesPacketAtLevelWithEcn(number, frames, level,
                                             ecn_codepoint);
  }

  size_t ProcessFramesPacketAtLevel(uint64_t number, QuicFrames frames,
                                    EncryptionLevel level) {
    return ProcessFramesPacketAtLevelWithEcn(number, frames, level,
                                             ECN_NOT_ECT);
  }

  size_t ProcessFramesPacketAtLevelWithEcn(uint64_t number,
                                           const QuicFrames& frames,
                                           EncryptionLevel level,
                                           QuicEcnCodepoint ecn_codepoint) {
    QuicPacketHeader header = ConstructPacketHeader(number, level);
    // Set the correct encryption level and encrypter on peer_creator and
    // peer_framer, respectively.
    peer_creator_.set_encryption_level(level);
    if (level > ENCRYPTION_INITIAL) {
      peer_framer_.SetEncrypter(level,
                                std::make_unique<TaggingEncrypter>(level));
      // Set the corresponding decrypter.
      if (connection_.version().KnowsWhichDecrypterToUse()) {
        connection_.InstallDecrypter(
            level, std::make_unique<StrictTaggingDecrypter>(level));
      } else {
        connection_.SetAlternativeDecrypter(
            level, std::make_unique<StrictTaggingDecrypter>(level), false);
      }
    }
    std::unique_ptr<QuicPacket> packet(ConstructPacket(header, frames));

    char buffer[kMaxOutgoingPacketSize];
    size_t encrypted_length =
        peer_framer_.EncryptPayload(level, QuicPacketNumber(number), *packet,
                                    buffer, kMaxOutgoingPacketSize);
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(buffer, encrypted_length, clock_.Now(), false, 0,
                           true, nullptr, 0, false, ecn_codepoint));
    if (connection_.GetSendAlarm()->IsSet()) {
      connection_.GetSendAlarm()->Fire();
    }
    return encrypted_length;
  }

  struct PacketInfo {
    PacketInfo(uint64_t packet_number, QuicFrames frames, EncryptionLevel level)
        : packet_number(packet_number), frames(frames), level(level) {}

    uint64_t packet_number;
    QuicFrames frames;
    EncryptionLevel level;
  };

  size_t ProcessCoalescedPacket(std::vector<PacketInfo> packets) {
    return ProcessCoalescedPacket(packets, ECN_NOT_ECT);
  }

  size_t ProcessCoalescedPacket(std::vector<PacketInfo> packets,
                                QuicEcnCodepoint ecn_codepoint) {
    char coalesced_buffer[kMaxOutgoingPacketSize];
    size_t coalesced_size = 0;
    bool contains_initial = false;
    for (const auto& packet : packets) {
      QuicPacketHeader header =
          ConstructPacketHeader(packet.packet_number, packet.level);
      // Set the correct encryption level and encrypter on peer_creator and
      // peer_framer, respectively.
      peer_creator_.set_encryption_level(packet.level);
      if (packet.level == ENCRYPTION_INITIAL) {
        contains_initial = true;
      }
      EncryptionLevel level =
          QuicPacketCreatorPeer::GetEncryptionLevel(&peer_creator_);
      if (level > ENCRYPTION_INITIAL) {
        peer_framer_.SetEncrypter(level,
                                  std::make_unique<TaggingEncrypter>(level));
        // Set the corresponding decrypter.
        if (connection_.version().KnowsWhichDecrypterToUse()) {
          connection_.InstallDecrypter(
              level, std::make_unique<StrictTaggingDecrypter>(level));
        } else {
          connection_.SetDecrypter(
              level, std::make_unique<StrictTaggingDecrypter>(level));
        }
      }
      std::unique_ptr<QuicPacket> constructed_packet(
          ConstructPacket(header, packet.frames));

      char buffer[kMaxOutgoingPacketSize];
      size_t encrypted_length = peer_framer_.EncryptPayload(
          packet.level, QuicPacketNumber(packet.packet_number),
          *constructed_packet, buffer, kMaxOutgoingPacketSize);
      QUICHE_DCHECK_LE(coalesced_size + encrypted_length,
                       kMaxOutgoingPacketSize);
      memcpy(coalesced_buffer + coalesced_size, buffer, encrypted_length);
      coalesced_size += encrypted_length;
    }
    if (contains_initial) {
      // Padded coalesced packet to full if it contains initial packet.
      memset(coalesced_buffer + coalesced_size, '0',
             kMaxOutgoingPacketSize - coalesced_size);
    }
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(coalesced_buffer, coalesced_size, clock_.Now(),
                           false, 0, true, nullptr, 0, false, ecn_codepoint));
    if (connection_.GetSendAlarm()->IsSet()) {
      connection_.GetSendAlarm()->Fire();
    }
    return coalesced_size;
  }

  size_t ProcessDataPacket(uint64_t number) {
    return ProcessDataPacketAtLevel(number, false, ENCRYPTION_FORWARD_SECURE);
  }

  size_t ProcessDataPacket(QuicPacketNumber packet_number) {
    return ProcessDataPacketAtLevel(packet_number, false,
                                    ENCRYPTION_FORWARD_SECURE);
  }

  size_t ProcessDataPacketAtLevel(QuicPacketNumber packet_number,
                                  bool has_stop_waiting,
                                  EncryptionLevel level) {
    return ProcessDataPacketAtLevel(packet_number.ToUint64(), has_stop_waiting,
                                    level);
  }

  size_t ProcessDataPacketAtLevel(uint64_t number, bool has_stop_waiting,
                                  EncryptionLevel level) {
    return ProcessDataPacketAtLevel(number, has_stop_waiting, level, 0);
  }

  size_t ProcessCryptoPacketAtLevel(uint64_t number, EncryptionLevel level) {
    QuicPacketHeader header = ConstructPacketHeader(number, level);
    QuicFrames frames;
    if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
      frames.push_back(QuicFrame(&crypto_frame_));
    } else {
      frames.push_back(QuicFrame(frame1_));
    }
    if (level == ENCRYPTION_INITIAL) {
      frames.push_back(QuicFrame(QuicPaddingFrame(-1)));
    }
    std::unique_ptr<QuicPacket> packet = ConstructPacket(header, frames);
    char buffer[kMaxOutgoingPacketSize];
    peer_creator_.set_encryption_level(level);
    size_t encrypted_length =
        peer_framer_.EncryptPayload(level, QuicPacketNumber(number), *packet,
                                    buffer, kMaxOutgoingPacketSize);
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(buffer, encrypted_length, clock_.Now(), false));
    if (connection_.GetSendAlarm()->IsSet()) {
      connection_.GetSendAlarm()->Fire();
    }
    return encrypted_length;
  }

  size_t ProcessDataPacketAtLevel(uint64_t number, bool has_stop_waiting,
                                  EncryptionLevel level, uint32_t flow_label) {
    std::unique_ptr<QuicPacket> packet(
        ConstructDataPacket(number, has_stop_waiting, level));
    char buffer[kMaxOutgoingPacketSize];
    peer_creator_.set_encryption_level(level);
    size_t encrypted_length =
        peer_framer_.EncryptPayload(level, QuicPacketNumber(number), *packet,
                                    buffer, kMaxOutgoingPacketSize);
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(buffer, encrypted_length, clock_.Now(), false,
                           0 /* ttl */, true /* ttl_valid */,
                           nullptr /* packet_headers */, 0 /* headers_length */,
                           false /* owns_header_buffer */, ECN_NOT_ECT,
                           flow_label));

    if (connection_.GetSendAlarm()->IsSet()) {
      connection_.GetSendAlarm()->Fire();
    }
    return encrypted_length;
  }

  void ProcessClosePacket(uint64_t number) {
    std::unique_ptr<QuicPacket> packet(ConstructClosePacket(number));
    char buffer[kMaxOutgoingPacketSize];
    size_t encrypted_length = peer_framer_.EncryptPayload(
        ENCRYPTION_FORWARD_SECURE, QuicPacketNumber(number), *packet, buffer,
        kMaxOutgoingPacketSize);
    connection_.ProcessUdpPacket(
        kSelfAddress, kPeerAddress,
        QuicReceivedPacket(buffer, encrypted_length, QuicTime::Zero(), false));
  }

  QuicByteCount SendStreamDataToPeer(QuicStreamId id, absl::string_view data,
                                     QuicStreamOffset offset,
                                     StreamSendingState state,
                                     QuicPacketNumber* last_packet) {
    QuicByteCount packet_size = 0;
    // Save the last packet's size.
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AnyNumber())
        .WillRepeatedly(SaveArg<3>(&packet_size));
    connection_.SendStreamDataWithString(id, data, offset, state);
    if (last_packet != nullptr) {
      *last_packet = creator_->packet_number();
    }
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AnyNumber());
    return packet_size;
  }

  void SendAckPacketToPeer() {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
    {
      QuicConnection::ScopedPacketFlusher flusher(&connection_);
      connection_.SendAck();
    }
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _))
        .Times(AnyNumber());
  }

  void SendRstStream(QuicStreamId id, QuicRstStreamErrorCode error,
                     QuicStreamOffset bytes_written) {
    notifier_.WriteOrBufferRstStream(id, error, bytes_written);
    connection_.OnStreamReset(id, error);
  }

  void SendPing() { notifier_.WriteOrBufferPing(); }

  MessageStatus SendMessage(absl::string_view message) {
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    quiche::QuicheMemSlice slice(quiche::QuicheBuffer::Copy(
        connection_.helper()->GetStreamSendBufferAllocator(), message));
    return connection_.SendMessage(1, absl::MakeSpan(&slice, 1), false);
  }

  void ProcessAckPacket(uint64_t packet_number, QuicAckFrame* frame) {
    if (packet_number > 1) {
      QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, packet_number - 1);
    } else {
      QuicPacketCreatorPeer::ClearPacketNumber(&peer_creator_);
    }
    ProcessFramePacket(QuicFrame(frame));
  }

  void ProcessAckPacket(QuicAckFrame* frame) {
    ProcessFramePacket(QuicFrame(frame));
  }

  void ProcessStopWaitingPacket(QuicStopWaitingFrame frame) {
    ProcessFramePacket(QuicFrame(frame));
  }

  size_t ProcessStopWaitingPacketAtLevel(uint64_t number,
                                         QuicStopWaitingFrame frame,
                                         EncryptionLevel /*level*/) {
    return ProcessFramePacketAtLevel(number, QuicFrame(frame),
                                     ENCRYPTION_ZERO_RTT);
  }

  void ProcessGoAwayPacket(QuicGoAwayFrame* frame) {
    ProcessFramePacket(QuicFrame(frame));
  }

  bool IsMissing(uint64_t number) {
    return IsAwaitingPacket(connection_.ack_frame(), QuicPacketNumber(number),
                            QuicPacketNumber());
  }

  std::unique_ptr<QuicPacket> ConstructPacket(const QuicPacketHeader& header,
                                              const QuicFrames& frames) {
    auto packet = BuildUnsizedDataPacket(&peer_framer_, header, frames);
    EXPECT_NE(nullptr, packet.get());
    return packet;
  }

  QuicPacketHeader ConstructPacketHeader(uint64_t number,
                                         EncryptionLevel level) {
    QuicPacketHeader header;
    if (level < ENCRYPTION_FORWARD_SECURE) {
      // Set long header type accordingly.
      header.version_flag = true;
      header.form = IETF_QUIC_LONG_HEADER_PACKET;
      header.long_packet_type = EncryptionlevelToLongHeaderType(level);
      if (QuicVersionHasLongHeaderLengths(
              peer_framer_.version().transport_version)) {
        header.length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
        if (header.long_packet_type == INITIAL) {
          header.retry_token_length_length =
              quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1;
        }
      }
    }
    // Set connection_id to peer's in memory representation as this data packet
    // is created by peer_framer.
    if (peer_framer_.perspective() == Perspective::IS_SERVER) {
      header.source_connection_id = connection_id_;
      header.source_connection_id_included = connection_id_included_;
      header.destination_connection_id_included = CONNECTION_ID_ABSENT;
    } else {
      header.destination_connection_id = connection_id_;
      header.destination_connection_id_included = connection_id_included_;
    }
    if (peer_framer_.perspective() == Perspective::IS_SERVER) {
      if (!connection_.client_connection_id().IsEmpty()) {
        header.destination_connection_id = connection_.client_connection_id();
        header.destination_connection_id_included = CONNECTION_ID_PRESENT;
      } else {
        header.destination_connection_id_included = CONNECTION_ID_ABSENT;
      }
      if (header.version_flag) {
        header.source_connection_id = connection_id_;
        header.source_connection_id_included = CONNECTION_ID_PRESENT;
        if (GetParam().version.handshake_protocol == PROTOCOL_QUIC_CRYPTO &&
            header.long_packet_type == ZERO_RTT_PROTECTED) {
          header.nonce = &kTestDiversificationNonce;
        }
      }
    }
    header.packet_number_length = packet_number_length_;
    header.packet_number = QuicPacketNumber(number);
    return header;
  }

  std::unique_ptr<QuicPacket> ConstructDataPacket(uint64_t number,
                                                  bool has_stop_waiting,
                                                  EncryptionLevel level) {
    QuicPacketHeader header = ConstructPacketHeader(number, level);
    QuicFrames frames;
    if (VersionHasIetfQuicFrames(version().transport_version) &&
        (level == ENCRYPTION_INITIAL || level == ENCRYPTION_HANDSHAKE)) {
      frames.push_back(QuicFrame(QuicPingFrame()));
      frames.push_back(QuicFrame(QuicPaddingFrame(100)));
    } else {
      frames.push_back(QuicFrame(frame1_));
      if (has_stop_waiting) {
        frames.push_back(QuicFrame(stop_waiting_));
      }
    }
    return ConstructPacket(header, frames);
  }

  std::unique_ptr<SerializedPacket> ConstructProbingPacket() {
    peer_creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
    if (VersionHasIetfQuicFrames(version().transport_version)) {
      QuicPathFrameBuffer payload = {
          {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xfe}};
      return QuicPacketCreatorPeer::
          SerializePathChallengeConnectivityProbingPacket(&peer_creator_,
                                                          payload);
    }
    QUICHE_DCHECK(!GetQuicReloadableFlag(quic_ignore_gquic_probing));
    return QuicPacketCreatorPeer::SerializeConnectivityProbingPacket(
        &peer_creator_);
  }

  std::unique_ptr<QuicPacket> ConstructClosePacket(uint64_t number) {
    peer_creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
    QuicPacketHeader header;
    // Set connection_id to peer's in memory representation as this connection
    // close packet is created by peer_framer.
    if (peer_framer_.perspective() == Perspective::IS_SERVER) {
      header.source_connection_id = connection_id_;
      header.destination_connection_id_included = CONNECTION_ID_ABSENT;
    } else {
      header.destination_connection_id = connection_id_;
      header.destination_connection_id_included = CONNECTION_ID_ABSENT;
    }

    header.packet_number = QuicPacketNumber(number);

    QuicErrorCode kQuicErrorCode = QUIC_PEER_GOING_AWAY;
    QuicConnectionCloseFrame qccf(peer_framer_.transport_version(),
                                  kQuicErrorCode, NO_IETF_QUIC_ERROR, "",
                                  /*transport_close_frame_type=*/0);
    QuicFrames frames;
    frames.push_back(QuicFrame(&qccf));
    return ConstructPacket(header, frames);
  }

  QuicTime::Delta DefaultRetransmissionTime() {
    return QuicTime::Delta::FromMilliseconds(kDefaultRetransmissionTimeMs);
  }

  QuicTime::Delta DefaultDelayedAckTime() {
    return QuicTime::Delta::FromMilliseconds(GetDefaultDelayedAckTimeMs());
  }

  const QuicStopWaitingFrame InitStopWaitingFrame(uint64_t least_unacked) {
    QuicStopWaitingFrame frame;
    frame.least_unacked = QuicPacketNumber(least_unacked);
    return frame;
  }

  // Construct a ack_frame that acks all packet numbers between 1 and
  // |largest_acked|, except |missing|.
  // REQUIRES: 1 <= |missing| < |largest_acked|
  QuicAckFrame ConstructAckFrame(uint64_t largest_acked, uint64_t missing) {
    return ConstructAckFrame(QuicPacketNumber(largest_acked),
                             QuicPacketNumber(missing));
  }

  QuicAckFrame ConstructAckFrame(QuicPacketNumber largest_acked,
                                 QuicPacketNumber missing) {
    if (missing == QuicPacketNumber(1)) {
      return InitAckFrame({{missing + 1, largest_acked + 1}});
    }
    return InitAckFrame(
        {{QuicPacketNumber(1), missing}, {missing + 1, largest_acked + 1}});
  }

  // Undo nacking a packet within the frame.
  void AckPacket(QuicPacketNumber arrived, QuicAckFrame* frame) {
    EXPECT_FALSE(frame->packets.Contains(arrived));
    frame->packets.Add(arrived);
  }

  void TriggerConnectionClose() {
    // Send an erroneous packet to close the connection.
    EXPECT_CALL(visitor_,
                OnConnectionClosed(_, ConnectionCloseSource::FROM_SELF))
        .WillOnce(Invoke(this, &QuicConnectionTest::SaveConnectionCloseFrame));

    EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
    // Triggers a connection by receiving ACK of unsent packet.
    QuicAckFrame frame = InitAckFrame(10000);
    ProcessAckPacket(1, &frame);
    EXPECT_FALSE(QuicConnectionPeer::GetConnectionClosePacket(&connection_) ==
                 nullptr);
    EXPECT_EQ(1, connection_close_frame_count_);
    EXPECT_THAT(saved_connection_close_frame_.quic_error_code,
                IsError(QUIC_INVALID_ACK_DATA));
  }

  void BlockOnNextWrite() {
    writer_->BlockOnNextWrite();
    EXPECT_CALL(visitor_, OnWriteBlocked()).Times(AtLeast(1));
  }

  void SimulateNextPacketTooLarge() { writer_->SimulateNextPacketTooLarge(); }

  void ExpectNextPacketUnprocessable() {
    writer_->ExpectNextPacketUnprocessable();
  }

  void AlwaysGetPacketTooLarge() { writer_->AlwaysGetPacketTooLarge(); }

  void SetWritePauseTimeDelta(QuicTime::Delta delta) {
    writer_->SetWritePauseTimeDelta(delta);
  }

  void CongestionBlockWrites() {
    EXPECT_CALL(*send_algorithm_, CanSend(_))
        .WillRepeatedly(testing::Return(false));
  }

  void CongestionUnblockWrites() {
    EXPECT_CALL(*send_algorithm_, CanSend(_))
        .WillRepeatedly(testing::Return(true));
  }

  void set_perspective(Perspective perspective) {
    connection_.set_perspective(perspective);
    if (perspective == Perspective::IS_SERVER) {
      connection_.set_can_truncate_connection_ids(true);
      QuicConnectionPeer::SetNegotiatedVersion(&connection_);
      connection_.OnSuccessfulVersionNegotiation();
    }
    QuicFramerPeer::SetPerspective(&peer_framer_,
                                   QuicUtils::InvertPerspective(perspective));
    peer_framer_.SetInitialObfuscators(TestConnectionId());
    for (EncryptionLevel level : {ENCRYPTION_ZERO_RTT, ENCRYPTION_HANDSHAKE,
                                  ENCRYPTION_FORWARD_SECURE}) {
      if (peer_framer_.HasEncrypterOfEncryptionLevel(level)) {
        peer_creator_.SetEncrypter(level,
                                   std::make_unique<TaggingEncrypter>(level));
      }
    }
  }

  void set_packets_between_probes_base(
      const QuicPacketCount packets_between_probes_base) {
    QuicConnectionPeer::ReInitializeMtuDiscoverer(
        &connection_, packets_between_probes_base,
        QuicPacketNumber(packets_between_probes_base));
  }

  bool IsDefaultTestConfiguration() {
    TestParams p = GetParam();
    return p.ack_response == AckResponse::kImmediate &&
           p.version == AllSupportedVersions()[0];
  }

  void TestConnectionCloseQuicErrorCode(QuicErrorCode expected_code) {
    // Not strictly needed for this test, but is commonly done.
    EXPECT_FALSE(QuicConnectionPeer::GetConnectionClosePacket(&connection_) ==
                 nullptr);
    const std::vector<QuicConnectionCloseFrame>& connection_close_frames =
        writer_->connection_close_frames();
    ASSERT_EQ(1u, connection_close_frames.size());

    EXPECT_THAT(connection_close_frames[0].quic_error_code,
                IsError(expected_code));

    if (!VersionHasIetfQuicFrames(version().transport_version)) {
      EXPECT_THAT(connection_close_frames[0].wire_error_code,
                  IsError(expected_code));
      EXPECT_EQ(GOOGLE_QUIC_CONNECTION_CLOSE,
                connection_close_frames[0].close_type);
      return;
    }

    QuicErrorCodeToIetfMapping mapping =
        QuicErrorCodeToTransportErrorCode(expected_code);

    if (mapping.is_transport_close) {
      // This Google QUIC Error Code maps to a transport close,
      EXPECT_EQ(IETF_QUIC_TRANSPORT_CONNECTION_CLOSE,
                connection_close_frames[0].close_type);
    } else {
      // This maps to an application close.
      EXPECT_EQ(IETF_QUIC_APPLICATION_CONNECTION_CLOSE,
                connection_close_frames[0].close_type);
    }
    EXPECT_EQ(mapping.error_code, connection_close_frames[0].wire_error_code);
  }

  void MtuDiscoveryTestInit() {
    set_perspective(Perspective::IS_SERVER);
    QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
    if (version().SupportsAntiAmplificationLimit()) {
      QuicConnectionPeer::SetAddressValidated(&connection_);
    }
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    peer_creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
    // Prevent packets from being coalesced.
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
    EXPECT_TRUE(connection_.connected());
  }

  void PathProbeTestInit(Perspective perspective,
                         bool receive_new_server_connection_id = true) {
    set_perspective(perspective);
    connection_.CreateConnectionIdManager();
    EXPECT_EQ(connection_.perspective(), perspective);
    if (perspective == Perspective::IS_SERVER) {
      QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
    }
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    peer_creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
    // Discard INITIAL key.
    connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
    connection_.NeuterUnencryptedPackets();
    // Prevent packets from being coalesced.
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
    if (version().SupportsAntiAmplificationLimit() &&
        perspective == Perspective::IS_SERVER) {
      QuicConnectionPeer::SetAddressValidated(&connection_);
    }
    // Clear direct_peer_address.
    QuicConnectionPeer::SetDirectPeerAddress(&connection_, QuicSocketAddress());
    // Clear effective_peer_address, it is the same as direct_peer_address for
    // this test.
    QuicConnectionPeer::SetEffectivePeerAddress(&connection_,
                                                QuicSocketAddress());
    EXPECT_FALSE(connection_.effective_peer_address().IsInitialized());

    if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
      EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
    } else {
      EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
    }
    QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 2);
    ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress,
                                    kPeerAddress, ENCRYPTION_FORWARD_SECURE);
    EXPECT_EQ(kPeerAddress, connection_.peer_address());
    EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
    if (perspective == Perspective::IS_CLIENT &&
        receive_new_server_connection_id && version().HasIetfQuicFrames()) {
      QuicNewConnectionIdFrame frame;
      frame.connection_id = TestConnectionId(1234);
      ASSERT_NE(frame.connection_id, connection_.connection_id());
      frame.stateless_reset_token =
          QuicUtils::GenerateStatelessResetToken(frame.connection_id);
      frame.retire_prior_to = 0u;
      frame.sequence_number = 1u;
      connection_.OnNewConnectionIdFrame(frame);
    }
  }

  void ServerHandlePreferredAddressInit() {
    ASSERT_TRUE(GetParam().version.HasIetfQuicFrames());
    set_perspective(Perspective::IS_SERVER);
    connection_.CreateConnectionIdManager();
    QuicPacketCreatorPeer::SetSendVersionInPacket(creator_, false);
    SetQuicReloadableFlag(quic_use_received_client_addresses_cache, true);
    EXPECT_CALL(visitor_, AllowSelfAddressChange())
        .WillRepeatedly(Return(true));

    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    peer_creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
    // Discard INITIAL key.
    connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
    connection_.NeuterUnencryptedPackets();
    // Prevent packets from being coalesced.
    EXPECT_CALL(visitor_, GetHandshakeState())
        .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
    if (version().SupportsAntiAmplificationLimit()) {
      QuicConnectionPeer::SetAddressValidated(&connection_);
    }
    // Clear direct_peer_address.
    QuicConnectionPeer::SetDirectPeerAddress(&connection_, QuicSocketAddress());
    // Clear effective_peer_address, it is the same as direct_peer_address for
    // this test.
    QuicConnectionPeer::SetEffectivePeerAddress(&connection_,
                                                QuicSocketAddress());
    EXPECT_FALSE(connection_.effective_peer_address().IsInitialized());

    if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
      EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(AnyNumber());
    } else {
      EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(AnyNumber());
    }
    QuicPacketCreatorPeer::SetPacketNumber(&peer_creator_, 2);
    ProcessFramePacketWithAddresses(MakeCryptoFrame(), kSelfAddress,
                                    kPeerAddress, ENCRYPTION_FORWARD_SECURE);
    EXPECT_EQ(kPeerAddress, connection_.peer_address());
    EXPECT_EQ(kPeerAddress, connection_.effective_peer_address());
    QuicConfig config;
    EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
    connection_.SetFromConfig(config);
    connection_.set_expected_server_preferred_address(kServerPreferredAddress);
  }

  // Receive server preferred address.
  void ServerPreferredAddressInit(QuicConfig& config) {
    ASSERT_EQ(Perspective::IS_CLIENT, connection_.perspective());
    ASSERT_TRUE(version().HasIetfQuicFrames());
    ASSERT_TRUE(connection_.self_address().host().IsIPv6());
    const QuicConnectionId connection_id = TestConnectionId(17);
    const StatelessResetToken reset_token =
        QuicUtils::GenerateStatelessResetToken(connection_id);

    connection_.CreateConnectionIdManager();

    connection_.SendCryptoStreamData();
    EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
    EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
    QuicAckFrame frame = InitAckFrame(1);
    // Received ACK for packet 1.
    ProcessFramePacketAtLevel(1, QuicFrame(&frame), ENCRYPTION_INITIAL);
    // Discard INITIAL key.
    connection_.RemoveEncrypter(ENCRYPTION_INITIAL);
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

    QuicConfigPeer::SetReceivedStatelessResetToken(&config,
                                                   kTestStatelessResetToken);
    QuicConfigPeer::SetReceivedAlternateServerAddress(&config,
                                                      kServerPreferredAddress);
    QuicConfigPeer::SetPreferredAddressConnectionIdAndToken(
        &config, connection_id, reset_token);
    EXPECT_CALL(*send_algorithm_, SetFromConfig(_, _));
    connection_.SetFromConfig(config);

    ASSERT_TRUE(
        QuicConnectionPeer::GetReceivedServerPreferredAddress(&connection_)
            .IsInitialized());
    EXPECT_EQ(
        kServerPreferredAddress,
        QuicConnectionPeer::GetReceivedServerPreferredAddress(&connection_));
  }

  // If defer sending is enabled, tell |visitor_| to return true on the next
  // call to WillingAndAbleToWrite().
  // This function can be used before a call to ProcessXxxPacket, to allow the
  // process function to schedule and fire the send alarm at the end.
  void ForceWillingAndAbleToWriteOnceForDeferSending() {
    if (GetParam().ack_response == AckResponse::kDefer) {
      EXPECT_CALL(visitor_, WillingAndAbleToWrite())
          .WillOnce(Return(true))
          .RetiresOnSaturation();
    }
  }

  void TestClientRetryHandling(bool invalid_retry_tag,
                               bool missing_original_id_in_config,
                               bool wrong_original_id_in_config,
                               bool missing_retry_id_in_config,
                               bool wrong_retry_id_in_config);

  void TestReplaceConnectionIdFromInitial();

  QuicConnectionId connection_id_;
  QuicFramer framer_;

  MockSendAlgorithm* send_algorithm_;
  std::unique_ptr<MockLossAlgorithm> loss_algorithm_;
  MockClock clock_;
  MockRandom random_generator_;
  quiche::SimpleBufferAllocator buffer_allocator_;
  std::unique_ptr<TestConnectionHelper> helper_;
  std::unique_ptr<TestAlarmFactory> alarm_factory_;
  QuicFramer peer_framer_;
  QuicPacketCreator peer_creator_;
  std::unique_ptr<TestPacketWriter> writer_;
  TestConnection connection_;
  QuicPacketCreator* creator_;
  QuicSentPacketManager* manager_;
  StrictMock<MockQuicConnectionVisitor> visitor_;

  QuicStreamFrame frame1_;
  QuicStreamFrame frame2_;
  QuicCryptoFrame crypto_frame_;
  QuicAckFrame ack_;
  QuicStopWaitingFrame stop_waiting_;
  QuicPacketNumberLength packet_number_length_;
  QuicConnectionIdIncluded connection_id_included_;

  SimpleSessionNotifier notifier_;

  QuicConnectionCloseFrame saved_connection_close_frame_;
  int connection_close_frame_count_;
  MockConnectionIdGenerator connection_id_generator_;
};

// Run all end to end tests with all supported versions.
INSTANTIATE_TEST_SUITE_P(QuicConnectionTests, QuicConnectionTest,
                         ::testing::ValuesIn(GetTestParams()),
                         ::testing::PrintToStringParamName());

// Regression test for b/372756997.
TEST_P(QuicConnectionTest, NoNestedCloseConnection) {
  if (!GetQuicReloadableFlag(quic_avoid_nested_close_connection)) {
    // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
    if (!IsDefaultTestConfiguration()) {
      return;
    }
  }
  EXPECT_TRUE(connection_.connected());
  EXPECT_CALL(visitor_, OnConnectionCl
```