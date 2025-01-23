Response:
The user is asking for a summary of the functionality of the `QuicPacketCreator` class in Chromium's QUIC implementation, based on the provided source code. The request is the third part of a three-part request. The previous parts likely covered the beginning and middle portions of the file. Therefore, this part of the summary should focus on the latter half of the class's responsibilities.

Here's a breakdown of the key functionalities visible in this part of the code:

1. **Flushing and Sending Packets:** The code includes functions like `Flush()`, `SendRemainingPendingPadding()`, and `FlushCurrentPacket()`, indicating the class manages when and how packets are finalized and sent. The `AttachPacketFlusher()` suggests a mechanism to initiate this process.

2. **Padding Management:** Functions like `AddRandomPadding()`, `AddPendingPadding()`, and `MaybeAddPadding()` demonstrate the class's responsibility for adding padding to packets, potentially for various reasons like minimizing information leakage or meeting minimum packet size requirements.

3. **Message Handling:** `AddMessageFrame()` handles the addition of message frames to packets, checking for size constraints and potentially flushing the current packet if there's not enough space.

4. **Packet Header Construction:** `FillPacketHeader()` is responsible for populating the header fields of a QUIC packet.

5. **Frame Serialization and Addition:**  `GetSerializedFrameLength()` calculates the serialized size of a frame, and `AddFrame()` adds frames to the current packet, managing retransmittable and non-retransmittable frames separately. The code includes logic for coalescing stream frames.

6. **Maximum Packet Size Management:** The code deals with `max_packet_length_` and related variables, suggesting it enforces or respects limitations on packet sizes. The `RemoveSoftMaxPacketLength()` function indicates a mechanism to temporarily reduce and then restore the maximum packet length.

7. **Encryption Level Management:**  The class keeps track of and sets the encryption level of the current packet.

8. **Path Validation Frames:** Functions like `AddPathChallengeFrame()` and `AddPathResponseFrame()` indicate support for sending frames related to path validation.

9. **Error Handling and Debugging:**  The presence of `QUIC_BUG` macros and a `debug_delegate_` suggests mechanisms for internal error detection and debugging.

10. **Connection ID Management:** Functions like `SetServerConnectionIdLength()`, `SetServerConnectionIdIncluded()`, `SetServerConnectionId()`, and `SetClientConnectionId()` show the class manages connection IDs in the packet header.

11. **Transmission Type Tracking:**  `SetTransmissionType()` and logic within `AddFrame()` manage the type of transmission for the packet.

12. **Peer Address Context:** The `ScopedPeerAddressContext` class suggests a mechanism to temporarily change the destination address for packets.

13. **Serialization Failure Handling:** The `ScopedSerializationFailureHandler` class is designed to handle errors during packet serialization.

Considering this is the final part of the request, the summary should encompass the overall responsibilities of the class, drawing on the functionality evident in this and the likely preceding parts of the code.
Based on the provided code snippet, here's a summary of the functionality of `QuicPacketCreator` focusing on this section:

**Core Functionalities in this Section:**

* **Packet Flushing and Sending:**
    * **`Flush()`:** This is the primary function for finalizing and triggering the sending of the currently assembled packet. It also handles sending any remaining pending padding.
    * **`SendRemainingPendingPadding()`:**  Specifically sends padding bytes if there are no other frames to add and the delegate allows sending a packet.
    * **`AttachPacketFlusher()`:** Marks that a packet creation process has begun, potentially associating it with a write operation and tracking the starting packet number for statistics.

* **Message Frame Handling:**
    * **`AddMessageFrame()`:** Adds a complete message as a frame to the current packet. It checks if the message fits within the current packet's available space and flushes the packet if needed.

* **Packet Header Population:**
    * **`FillPacketHeader()`:** Populates the fields of a `QuicPacketHeader` object based on the current state of the `QuicPacketCreator`. This includes connection IDs, packet number, and flags.

* **Frame Serialization and Management:**
    * **`GetSerializedFrameLength()`:** Calculates the serialized size of a given `QuicFrame`, considering available space, packet number length, and header protection requirements.
    * **`AddFrame()`:** Adds a `QuicFrame` to the currently being built packet. It distinguishes between retransmittable and non-retransmittable frames, manages crypto handshake flags, and handles ACK and STOP_WAITING frames. It also includes logic for coalescing stream frames.
    * **`MaybeCoalesceStreamFrame()`:** Attempts to merge a new stream frame with the last stream frame in the packet if they are for the same stream and contiguous.

* **Padding Implementation:**
    * **`MaybeAddPadding()`:** Adds padding to the packet before serialization, either to fill the packet to the maximum size or to satisfy minimum plaintext size requirements for header protection.
    * **`AddPendingPadding()`:**  Increments a counter of bytes that need to be added as padding in a future packet.

* **Maximum Packet Length Control:**
    * **`RemoveSoftMaxPacketLength()`:**  Reverts the maximum packet length to its original "hard" maximum if a temporary smaller limit was applied.

* **Connection ID Management:**
    * **`SetServerConnectionIdLength()`:** Sets whether the server connection ID is included based on the provided length.
    * **`SetServerConnectionIdIncluded()`:** Explicitly sets whether the server connection ID is included.
    * **`SetServerConnectionId()`:** Sets the actual server connection ID.
    * **`SetClientConnectionId()`:** Sets the client connection ID.

* **Transmission Type Handling:**
    * **`SetTransmissionType()`:** Sets the intended transmission type for the next frames added to the packet.

* **Path Validation Frame Handling:**
    * **`AddPathChallengeFrame()`:** Adds a `PATH_CHALLENGE` frame to a packet, potentially padding it.
    * **`AddPathResponseFrame()`:** Adds a `PATH_RESPONSE` frame to a packet, potentially padding it.
    * **`AddPaddedFrameWithRetry()`:** A helper function to add a frame and flush the packet if necessary, retrying if the initial attempt fails.

* **Helper Functions and State Management:**
    * **`IncludeNonceInPublicHeader()`:** Determines if a nonce should be included in the public header.
    * **`IncludeVersionInHeader()`:** Determines if the version should be included in the header.
    * **`StreamFrameIsClientHello()`:** Checks if a stream frame contains the ClientHello message.
    * **`GetCurrentLargestMessagePayload()`:** Calculates the maximum size of a message that can be placed in a single packet.
    * **`GetGuaranteedLargestMessagePayload()`:** Calculates a guaranteed minimum size for a message payload.
    * **`AttemptingToSendUnencryptedStreamData()`:** Checks if an attempt is being made to send unencrypted stream data when it's not allowed.
    * **`HasIetfLongHeader()`:** Determines if the current packet should use the IETF long header format.
    * **`MinPlaintextPacketSize()`:** (Static method) Calculates the minimum plaintext size required for header protection.
    * **`NextSendingPacketNumber()`:**  Determines the next packet number to use.
    * **`PacketFlusherAttached()`:** Checks if a packet flusher is currently attached.
    * **`HasSoftMaxPacketLength()`:** Checks if a temporary reduced maximum packet length is in effect.
    * **`SetDefaultPeerAddress()`:** Sets the default peer address for the current packet, flushing the packet if the address changes.

* **Scoped Contexts for Specific Operations:**
    * **`ScopedPeerAddressContext`:** Allows temporarily changing the peer address, client connection ID, and server connection ID for a specific packet or set of packets.
    * **`ScopedSerializationFailureHandler`:** Provides a way to handle errors that occur during packet serialization, ensuring resources are cleaned up and errors are reported.

**Relationship with JavaScript:**

This C++ code directly implements the QUIC protocol within the Chromium network stack. JavaScript running in a web browser would interact with this code indirectly through higher-level network APIs.

**Example of Indirect Relationship:**

1. **User Action:** A user initiates an HTTPS request in a Chrome browser (e.g., by typing a URL in the address bar or clicking a link).
2. **JavaScript Interaction:** The browser's rendering engine (Blink), which includes JavaScript execution, might make calls to network APIs to fetch resources.
3. **Network Stack Involvement:** The network stack, including this `QuicPacketCreator` class, is responsible for constructing and sending the QUIC packets necessary to fulfill that request.
4. **`QuicPacketCreator` Role:**  When sending data (like the initial HTTP request or later data for the connection), the `QuicPacketCreator` will be used to create the QUIC packets. It will take the data to be sent, potentially break it into frames (like stream frames for HTTP data), add necessary control frames, manage packet numbers, apply encryption, and add padding as required.

**Hypothetical Input and Output (Illustrative for `AddMessageFrame`):**

**Assumption:** The current packet has enough space for a message frame.

* **Input:**
    * `message_id`: A `QuicMessageId` (e.g., 123).
    * `message`: A `absl::Span<quiche::QuicheMemSlice>` containing the message data (e.g., "Hello, world!").
* **Output:**
    * The function returns `MESSAGE_STATUS_SUCCESS`.
    * A `QuicMessageFrame` containing the `message_id` and the message data is added to the `packet_.retransmittable_frames` and `queued_frames_`.
    * The `packet_size_` is increased by the size of the message frame.
    * `packet_.has_message` is set to `true`.

**Hypothetical Input and Output (Illustrative for `Flush`):**

**Assumption:**  A packet has been partially constructed with some frames.

* **Input:**  The `QuicPacketCreator` object with pending frames and potentially some pending padding.
* **Output:**
    * The currently assembled packet is serialized and sent via the `delegate_`.
    * Any remaining pending padding is added to new packets and sent.
    * `flusher_attached_` is set to `false`.
    * If `quic_export_write_path_stats_at_server` is enabled, a histogram is updated with the number of packets sent during this flush.
    * `write_start_packet_number_` is cleared.

**Common User/Programming Errors and Debugging:**

* **Forgetting to Attach the Packet Flusher:**  Many functions, like `AddMessageFrame` and `AddPathChallengeFrame`, check if `flusher_attached_` is true. If a programmer attempts to add frames or messages without attaching the flusher, it will lead to a `QUIC_BUG`. This can happen if the higher-level logic managing packet creation doesn't properly initiate the process.

    * **Debugging Step:**  When encountering such a bug, trace back the call stack to see where the packet creation process should have been started. Look for calls to functions that are supposed to initiate packet sending or buffer data for sending.

* **Adding Frames that Exceed the Maximum Packet Size:** If a programmer attempts to add frames (especially large stream frames or messages) that would cause the packet to exceed the configured maximum size, the `AddFrame` or `AddMessageFrame` function might return `false` or `MESSAGE_STATUS_TOO_LARGE`.

    * **Debugging Step:** Check the configured maximum packet size and the size of the frames being added. Ensure that the higher-level logic is correctly segmenting data or handling potential overflows. Look for logic that calculates available space before adding frames.

* **Sending Data at the Wrong Encryption Level:** The code includes checks to prevent sending certain frame types at incorrect encryption levels (e.g., sending `GOAWAY_FRAME` before handshake completion). Violating these checks will trigger a `QUIC_BUG`.

    * **Debugging Step:** Inspect the encryption level of the connection at the time the frame is being added. Verify that the logic responsible for sending different types of control frames is respecting the current connection state.

**User Operation to Reach Here (as a Debugging线索):**

1. **User Opens a Website or Application using QUIC:** The user interacts with a web page or application that communicates using the QUIC protocol (e.g., a website served over HTTPS with QUIC enabled).
2. **Data Needs to Be Sent:**  The browser needs to send data to the server. This could be the initial HTTP request, subsequent data for the page, or data for a web application.
3. **Network Stack Initiates Packet Creation:** The higher layers of the Chromium network stack determine that data needs to be sent over the QUIC connection.
4. **`QuicConnection` or Similar Calls `QuicPacketCreator`:**  A component managing the QUIC connection (likely a `QuicConnection` object or a related class) will interact with the `QuicPacketCreator`.
5. **Attach Flusher:**  A call to `AttachPacketFlusher()` might be made to indicate the start of a packet creation process.
6. **Add Frames:**  Various data and control information are added as frames using functions like `AddStreamFrame`, `AddAckFrame`, `AddMessageFrame`, etc.
7. **Padding (Optional):** `MaybeAddPadding()` might be called to add padding.
8. **Flush:**  Finally, `Flush()` is called to finalize the packet and send it.

By tracing the execution flow from a user action down through the network stack, developers can pinpoint how the `QuicPacketCreator` is invoked and the sequence of operations leading to a particular state or potential error. This is crucial for debugging network issues at the QUIC protocol level.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_packet_creator.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
rame causing another control frame to be sent.
  QUIC_BUG_IF(quic_bug_12398_18, !frames.empty() && has_ack())
      << ENDPOINT << "Trying to flush " << quiche::PrintElements(frames)
      << " when there is ACK queued";
  for (const auto& frame : frames) {
    QUICHE_DCHECK(frame.type == ACK_FRAME || frame.type == STOP_WAITING_FRAME)
        << ENDPOINT;
    if (HasPendingFrames()) {
      if (AddFrame(frame, next_transmission_type_)) {
        // There is pending frames and current frame fits.
        continue;
      }
    }
    QUICHE_DCHECK(!HasPendingFrames()) << ENDPOINT;
    // There is no pending frames, consult the delegate whether a packet can be
    // generated.
    if (!delegate_->ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA,
                                         NOT_HANDSHAKE)) {
      return false;
    }
    const bool success = AddFrame(frame, next_transmission_type_);
    QUIC_BUG_IF(quic_bug_10752_31, !success)
        << ENDPOINT << "Failed to flush " << frame;
  }
  return true;
}

void QuicPacketCreator::AddRandomPadding() {
  AddPendingPadding(random_->RandUint64() % kMaxNumRandomPaddingBytes + 1);
}

void QuicPacketCreator::AttachPacketFlusher() {
  flusher_attached_ = true;
  if (!write_start_packet_number_.IsInitialized()) {
    write_start_packet_number_ = NextSendingPacketNumber();
  }
}

void QuicPacketCreator::Flush() {
  FlushCurrentPacket();
  SendRemainingPendingPadding();
  flusher_attached_ = false;
  if (GetQuicFlag(quic_export_write_path_stats_at_server)) {
    if (!write_start_packet_number_.IsInitialized()) {
      QUIC_BUG(quic_bug_10752_32)
          << ENDPOINT << "write_start_packet_number is not initialized";
      return;
    }
    QUIC_SERVER_HISTOGRAM_COUNTS(
        "quic_server_num_written_packets_per_write",
        NextSendingPacketNumber() - write_start_packet_number_, 1, 200, 50,
        "Number of QUIC packets written per write operation");
  }
  write_start_packet_number_.Clear();
}

void QuicPacketCreator::SendRemainingPendingPadding() {
  while (
      pending_padding_bytes() > 0 && !HasPendingFrames() &&
      delegate_->ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA, NOT_HANDSHAKE)) {
    FlushCurrentPacket();
  }
}

void QuicPacketCreator::SetServerConnectionIdLength(uint32_t length) {
  if (length == 0) {
    SetServerConnectionIdIncluded(CONNECTION_ID_ABSENT);
  } else {
    SetServerConnectionIdIncluded(CONNECTION_ID_PRESENT);
  }
}

void QuicPacketCreator::SetTransmissionType(TransmissionType type) {
  next_transmission_type_ = type;
}

MessageStatus QuicPacketCreator::AddMessageFrame(
    QuicMessageId message_id, absl::Span<quiche::QuicheMemSlice> message) {
  QUIC_BUG_IF(quic_bug_10752_33, !flusher_attached_)
      << ENDPOINT
      << "Packet flusher is not attached when "
         "generator tries to add message frame.";
  MaybeBundleOpportunistically();
  const QuicByteCount message_length = MemSliceSpanTotalSize(message);
  if (message_length > GetCurrentLargestMessagePayload()) {
    return MESSAGE_STATUS_TOO_LARGE;
  }
  if (!HasRoomForMessageFrame(message_length)) {
    FlushCurrentPacket();
  }
  QuicMessageFrame* frame = new QuicMessageFrame(message_id, message);
  const bool success = AddFrame(QuicFrame(frame), next_transmission_type_);
  if (!success) {
    QUIC_BUG(quic_bug_10752_34)
        << ENDPOINT << "Failed to send message " << message_id;
    delete frame;
    return MESSAGE_STATUS_INTERNAL_ERROR;
  }
  QUICHE_DCHECK_EQ(MemSliceSpanTotalSize(message),
                   0u);  // Ensure the old slices are empty.
  return MESSAGE_STATUS_SUCCESS;
}

quiche::QuicheVariableLengthIntegerLength QuicPacketCreator::GetLengthLength()
    const {
  if (QuicVersionHasLongHeaderLengths(framer_->transport_version()) &&
      HasIetfLongHeader()) {
    QuicLongHeaderType long_header_type =
        EncryptionlevelToLongHeaderType(packet_.encryption_level);
    if (long_header_type == INITIAL || long_header_type == ZERO_RTT_PROTECTED ||
        long_header_type == HANDSHAKE) {
      return quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
    }
  }
  return quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0;
}

void QuicPacketCreator::FillPacketHeader(QuicPacketHeader* header) {
  header->destination_connection_id = GetDestinationConnectionId();
  header->destination_connection_id_included =
      GetDestinationConnectionIdIncluded();
  header->source_connection_id = GetSourceConnectionId();
  header->source_connection_id_included = GetSourceConnectionIdIncluded();
  header->reset_flag = false;
  header->version_flag = IncludeVersionInHeader();
  if (IncludeNonceInPublicHeader()) {
    QUICHE_DCHECK_EQ(Perspective::IS_SERVER, framer_->perspective())
        << ENDPOINT;
    header->nonce = &diversification_nonce_;
  } else {
    header->nonce = nullptr;
  }
  packet_.packet_number = NextSendingPacketNumber();
  header->packet_number = packet_.packet_number;
  header->packet_number_length = GetPacketNumberLength();
  header->retry_token_length_length = GetRetryTokenLengthLength();
  header->retry_token = GetRetryToken();
  header->length_length = GetLengthLength();
  header->remaining_packet_length = 0;
  if (!HasIetfLongHeader()) {
    return;
  }
  header->long_packet_type =
      EncryptionlevelToLongHeaderType(packet_.encryption_level);
}

size_t QuicPacketCreator::GetSerializedFrameLength(const QuicFrame& frame) {
  size_t serialized_frame_length = framer_->GetSerializedFrameLength(
      frame, BytesFree(), queued_frames_.empty(),
      /* last_frame_in_packet= */ true, GetPacketNumberLength());
  if (!framer_->version().HasHeaderProtection() ||
      serialized_frame_length == 0) {
    return serialized_frame_length;
  }
  // Calculate frame bytes and bytes free with this frame added.
  const size_t frame_bytes = PacketSize() - PacketHeaderSize() +
                             ExpansionOnNewFrame() + serialized_frame_length;
  if (frame_bytes >=
      MinPlaintextPacketSize(framer_->version(), GetPacketNumberLength())) {
    // No extra bytes is needed.
    return serialized_frame_length;
  }
  if (BytesFree() < serialized_frame_length) {
    QUIC_BUG(quic_bug_10752_35) << ENDPOINT << "Frame does not fit: " << frame;
    return 0;
  }
  // Please note bytes_free does not take |frame|'s expansion into account.
  size_t bytes_free = BytesFree() - serialized_frame_length;
  // Extra bytes needed (this is NOT padding needed) should be at least 1
  // padding + expansion.
  const size_t extra_bytes_needed = std::max(
      1 + ExpansionOnNewFrameWithLastFrame(frame, framer_->transport_version()),
      MinPlaintextPacketSize(framer_->version(), GetPacketNumberLength()) -
          frame_bytes);
  if (bytes_free < extra_bytes_needed) {
    // This frame does not fit.
    return 0;
  }
  return serialized_frame_length;
}

bool QuicPacketCreator::AddFrame(const QuicFrame& frame,
                                 TransmissionType transmission_type) {
  QUIC_DVLOG(1) << ENDPOINT << "Adding frame with transmission type "
                << transmission_type << ": " << frame;
  if (frame.type == STREAM_FRAME &&
      !QuicUtils::IsCryptoStreamId(framer_->transport_version(),
                                   frame.stream_frame.stream_id) &&
      AttemptingToSendUnencryptedStreamData()) {
    return false;
  }

  // Sanity check to ensure we don't send frames at the wrong encryption level.
  QUICHE_DCHECK(
      packet_.encryption_level == ENCRYPTION_ZERO_RTT ||
      packet_.encryption_level == ENCRYPTION_FORWARD_SECURE ||
      (frame.type != GOAWAY_FRAME && frame.type != WINDOW_UPDATE_FRAME &&
       frame.type != HANDSHAKE_DONE_FRAME &&
       frame.type != NEW_CONNECTION_ID_FRAME &&
       frame.type != MAX_STREAMS_FRAME && frame.type != STREAMS_BLOCKED_FRAME &&
       frame.type != PATH_RESPONSE_FRAME &&
       frame.type != PATH_CHALLENGE_FRAME && frame.type != STOP_SENDING_FRAME &&
       frame.type != MESSAGE_FRAME && frame.type != NEW_TOKEN_FRAME &&
       frame.type != RETIRE_CONNECTION_ID_FRAME &&
       frame.type != ACK_FREQUENCY_FRAME))
      << ENDPOINT << frame.type << " not allowed at "
      << packet_.encryption_level;

  if (frame.type == STREAM_FRAME) {
    if (MaybeCoalesceStreamFrame(frame.stream_frame)) {
      LogCoalesceStreamFrameStatus(true);
      return true;
    } else {
      LogCoalesceStreamFrameStatus(false);
    }
  }

  // If this is an ACK frame, validate that it is non-empty and that
  // largest_acked matches the max packet number.
  QUICHE_DCHECK(frame.type != ACK_FRAME || (!frame.ack_frame->packets.Empty() &&
                                            frame.ack_frame->packets.Max() ==
                                                frame.ack_frame->largest_acked))
      << ENDPOINT << "Invalid ACK frame: " << frame;

  size_t frame_len = GetSerializedFrameLength(frame);
  if (frame_len == 0 && RemoveSoftMaxPacketLength()) {
    // Remove soft max_packet_length and retry.
    frame_len = GetSerializedFrameLength(frame);
  }
  if (frame_len == 0) {
    QUIC_DVLOG(1) << ENDPOINT
                  << "Flushing because current open packet is full when adding "
                  << frame;
    FlushCurrentPacket();
    return false;
  }
  if (queued_frames_.empty()) {
    packet_size_ = PacketHeaderSize();
  }
  QUICHE_DCHECK_LT(0u, packet_size_) << ENDPOINT;

  packet_size_ += ExpansionOnNewFrame() + frame_len;

  if (QuicUtils::IsRetransmittableFrame(frame.type)) {
    packet_.retransmittable_frames.push_back(frame);
    queued_frames_.push_back(frame);
    if (QuicUtils::IsHandshakeFrame(frame, framer_->transport_version())) {
      packet_.has_crypto_handshake = IS_HANDSHAKE;
    }
  } else {
    if (frame.type == PADDING_FRAME &&
        frame.padding_frame.num_padding_bytes == -1) {
      // Populate the actual length of full padding frame, such that one can
      // know how much padding is actually added.
      packet_.nonretransmittable_frames.push_back(
          QuicFrame(QuicPaddingFrame(frame_len)));
    } else {
      packet_.nonretransmittable_frames.push_back(frame);
    }
    queued_frames_.push_back(frame);
  }

  if (frame.type == ACK_FRAME) {
    packet_.has_ack = true;
    packet_.largest_acked = LargestAcked(*frame.ack_frame);
    if (frame.ack_frame->ecn_counters.has_value()) {
      packet_.has_ack_ecn = true;
    }
  } else if (frame.type == STOP_WAITING_FRAME) {
    packet_.has_stop_waiting = true;
  } else if (frame.type == ACK_FREQUENCY_FRAME) {
    packet_.has_ack_frequency = true;
  } else if (frame.type == MESSAGE_FRAME) {
    packet_.has_message = true;
  }
  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnFrameAddedToPacket(frame);
  }

  if (transmission_type == NOT_RETRANSMISSION) {
    packet_.bytes_not_retransmitted.emplace(
        packet_.bytes_not_retransmitted.value_or(0) + frame_len);
  } else if (QuicUtils::IsRetransmittableFrame(frame.type)) {
    // Packet transmission type is determined by the last added retransmittable
    // frame of a retransmission type. If a packet has no retransmittable
    // retransmission frames, it has type NOT_RETRANSMISSION.
    packet_.transmission_type = transmission_type;
  }
  return true;
}

void QuicPacketCreator::MaybeAddExtraPaddingForHeaderProtection() {
  if (!framer_->version().HasHeaderProtection() || needs_full_padding_) {
    return;
  }
  const size_t frame_bytes = PacketSize() - PacketHeaderSize();
  if (frame_bytes >=
      MinPlaintextPacketSize(framer_->version(), GetPacketNumberLength())) {
    return;
  }
  QuicByteCount min_header_protection_padding =
      MinPlaintextPacketSize(framer_->version(), GetPacketNumberLength()) -
      frame_bytes;
  // Update pending_padding_bytes_.
  pending_padding_bytes_ =
      std::max(pending_padding_bytes_, min_header_protection_padding);
}

bool QuicPacketCreator::MaybeCoalesceStreamFrame(const QuicStreamFrame& frame) {
  if (queued_frames_.empty() || queued_frames_.back().type != STREAM_FRAME) {
    return false;
  }
  QuicStreamFrame* candidate = &queued_frames_.back().stream_frame;
  if (candidate->stream_id != frame.stream_id ||
      candidate->offset + candidate->data_length != frame.offset ||
      frame.data_length > BytesFree()) {
    return false;
  }
  candidate->data_length += frame.data_length;
  candidate->fin = frame.fin;

  // The back of retransmittable frames must be the same as the original
  // queued frames' back.
  QUICHE_DCHECK_EQ(packet_.retransmittable_frames.back().type, STREAM_FRAME)
      << ENDPOINT;
  QuicStreamFrame* retransmittable =
      &packet_.retransmittable_frames.back().stream_frame;
  QUICHE_DCHECK_EQ(retransmittable->stream_id, frame.stream_id) << ENDPOINT;
  QUICHE_DCHECK_EQ(retransmittable->offset + retransmittable->data_length,
                   frame.offset)
      << ENDPOINT;
  retransmittable->data_length = candidate->data_length;
  retransmittable->fin = candidate->fin;
  packet_size_ += frame.data_length;
  if (debug_delegate_ != nullptr) {
    debug_delegate_->OnStreamFrameCoalesced(*candidate);
  }
  return true;
}

bool QuicPacketCreator::RemoveSoftMaxPacketLength() {
  if (latched_hard_max_packet_length_ == 0) {
    return false;
  }
  if (!CanSetMaxPacketLength()) {
    return false;
  }
  QUIC_DVLOG(1) << ENDPOINT << "Restoring max packet length to: "
                << latched_hard_max_packet_length_;
  SetMaxPacketLength(latched_hard_max_packet_length_);
  // Reset latched_max_packet_length_.
  latched_hard_max_packet_length_ = 0;
  return true;
}

void QuicPacketCreator::MaybeAddPadding() {
  // The current packet should have no padding bytes because padding is only
  // added when this method is called just before the packet is serialized.
  if (BytesFreeForPadding() == 0) {
    // Don't pad full packets.
    return;
  }

  if (packet_.fate == COALESCE) {
    // Do not add full padding if the packet is going to be coalesced.
    needs_full_padding_ = false;
  }

  // Header protection requires a minimum plaintext packet size.
  MaybeAddExtraPaddingForHeaderProtection();

  QUIC_DVLOG(3) << "MaybeAddPadding for " << packet_.packet_number
                << ": transmission_type:" << packet_.transmission_type
                << ", fate:" << packet_.fate
                << ", needs_full_padding_:" << needs_full_padding_
                << ", pending_padding_bytes_:" << pending_padding_bytes_
                << ", BytesFree:" << BytesFree();

  if (!needs_full_padding_ && pending_padding_bytes_ == 0) {
    // Do not need padding.
    return;
  }

  int padding_bytes = -1;
  if (!needs_full_padding_) {
    padding_bytes =
        std::min<int16_t>(pending_padding_bytes_, BytesFreeForPadding());
    pending_padding_bytes_ -= padding_bytes;
  }

  if (!queued_frames_.empty()) {
    // Insert PADDING before the other frames to avoid adding a length field
    // to any trailing STREAM frame.
    if (needs_full_padding_) {
      padding_bytes = BytesFreeForPadding();
    }
    // AddFrame cannot be used here because it adds the frame to the end of the
    // packet.
    QuicFrame frame{QuicPaddingFrame(padding_bytes)};
    queued_frames_.insert(queued_frames_.begin(), frame);
    packet_size_ += padding_bytes;
    packet_.nonretransmittable_frames.push_back(frame);
    if (packet_.transmission_type == NOT_RETRANSMISSION) {
      packet_.bytes_not_retransmitted.emplace(
          packet_.bytes_not_retransmitted.value_or(0) + padding_bytes);
    }
  } else {
    bool success = AddFrame(QuicFrame(QuicPaddingFrame(padding_bytes)),
                            packet_.transmission_type);
    QUIC_BUG_IF(quic_bug_10752_36, !success)
        << ENDPOINT << "Failed to add padding_bytes: " << padding_bytes
        << " transmission_type: " << packet_.transmission_type;
  }
}

bool QuicPacketCreator::IncludeNonceInPublicHeader() const {
  return have_diversification_nonce_ &&
         packet_.encryption_level == ENCRYPTION_ZERO_RTT;
}

bool QuicPacketCreator::IncludeVersionInHeader() const {
  return packet_.encryption_level < ENCRYPTION_FORWARD_SECURE;
}

void QuicPacketCreator::AddPendingPadding(QuicByteCount size) {
  pending_padding_bytes_ += size;
  QUIC_DVLOG(3) << "After AddPendingPadding(" << size
                << "), pending_padding_bytes_:" << pending_padding_bytes_;
}

bool QuicPacketCreator::StreamFrameIsClientHello(
    const QuicStreamFrame& frame) const {
  if (framer_->perspective() == Perspective::IS_SERVER ||
      !QuicUtils::IsCryptoStreamId(framer_->transport_version(),
                                   frame.stream_id)) {
    return false;
  }
  // The ClientHello is always sent with INITIAL encryption.
  return packet_.encryption_level == ENCRYPTION_INITIAL;
}

void QuicPacketCreator::SetServerConnectionIdIncluded(
    QuicConnectionIdIncluded server_connection_id_included) {
  QUICHE_DCHECK(server_connection_id_included == CONNECTION_ID_PRESENT ||
                server_connection_id_included == CONNECTION_ID_ABSENT)
      << ENDPOINT;
  QUICHE_DCHECK(framer_->perspective() == Perspective::IS_SERVER ||
                server_connection_id_included != CONNECTION_ID_ABSENT)
      << ENDPOINT;
  server_connection_id_included_ = server_connection_id_included;
}

void QuicPacketCreator::SetServerConnectionId(
    QuicConnectionId server_connection_id) {
  server_connection_id_ = server_connection_id;
}

void QuicPacketCreator::SetClientConnectionId(
    QuicConnectionId client_connection_id) {
  QUICHE_DCHECK(client_connection_id.IsEmpty() ||
                framer_->version().SupportsClientConnectionIds())
      << ENDPOINT;
  client_connection_id_ = client_connection_id;
}

QuicPacketLength QuicPacketCreator::GetCurrentLargestMessagePayload() const {
  const size_t packet_header_size = GetPacketHeaderSize(
      framer_->transport_version(), GetDestinationConnectionIdLength(),
      GetSourceConnectionIdLength(), IncludeVersionInHeader(),
      IncludeNonceInPublicHeader(), GetPacketNumberLength(),
      // No Retry token on packets containing application data.
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0, GetLengthLength());
  // This is the largest possible message payload when the length field is
  // omitted.
  size_t max_plaintext_size =
      latched_hard_max_packet_length_ == 0
          ? max_plaintext_size_
          : framer_->GetMaxPlaintextSize(latched_hard_max_packet_length_);
  size_t largest_frame =
      max_plaintext_size - std::min(max_plaintext_size, packet_header_size);
  if (static_cast<QuicByteCount>(largest_frame) > max_datagram_frame_size_) {
    largest_frame = static_cast<size_t>(max_datagram_frame_size_);
  }
  return largest_frame - std::min(largest_frame, kQuicFrameTypeSize);
}

QuicPacketLength QuicPacketCreator::GetGuaranteedLargestMessagePayload() const {
  // QUIC Crypto server packets may include a diversification nonce.
  const bool may_include_nonce =
      framer_->version().handshake_protocol == PROTOCOL_QUIC_CRYPTO &&
      framer_->perspective() == Perspective::IS_SERVER;
  // IETF QUIC long headers include a length on client 0RTT packets.
  quiche::QuicheVariableLengthIntegerLength length_length =
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0;
  if (framer_->perspective() == Perspective::IS_CLIENT) {
    length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
  }
  if (!QuicVersionHasLongHeaderLengths(framer_->transport_version())) {
    length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0;
  }
  const size_t packet_header_size = GetPacketHeaderSize(
      framer_->transport_version(), GetDestinationConnectionIdLength(),
      // Assume CID lengths don't change, but version may be present.
      GetSourceConnectionIdLength(), kIncludeVersion, may_include_nonce,
      PACKET_4BYTE_PACKET_NUMBER,
      // No Retry token on packets containing application data.
      quiche::VARIABLE_LENGTH_INTEGER_LENGTH_0, 0, length_length);
  // This is the largest possible message payload when the length field is
  // omitted.
  size_t max_plaintext_size =
      latched_hard_max_packet_length_ == 0
          ? max_plaintext_size_
          : framer_->GetMaxPlaintextSize(latched_hard_max_packet_length_);
  size_t largest_frame =
      max_plaintext_size - std::min(max_plaintext_size, packet_header_size);
  if (static_cast<QuicByteCount>(largest_frame) > max_datagram_frame_size_) {
    largest_frame = static_cast<size_t>(max_datagram_frame_size_);
  }
  const QuicPacketLength largest_payload =
      largest_frame - std::min(largest_frame, kQuicFrameTypeSize);
  // This must always be less than or equal to GetCurrentLargestMessagePayload.
  QUICHE_DCHECK_LE(largest_payload, GetCurrentLargestMessagePayload())
      << ENDPOINT;
  return largest_payload;
}

bool QuicPacketCreator::AttemptingToSendUnencryptedStreamData() {
  if (packet_.encryption_level == ENCRYPTION_ZERO_RTT ||
      packet_.encryption_level == ENCRYPTION_FORWARD_SECURE) {
    return false;
  }
  const std::string error_details =
      absl::StrCat("Cannot send stream data with level: ",
                   EncryptionLevelToString(packet_.encryption_level));
  QUIC_BUG(quic_bug_10752_37) << ENDPOINT << error_details;
  delegate_->OnUnrecoverableError(QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA,
                                  error_details);
  return true;
}

bool QuicPacketCreator::HasIetfLongHeader() const {
  return packet_.encryption_level < ENCRYPTION_FORWARD_SECURE;
}

// static
size_t QuicPacketCreator::MinPlaintextPacketSize(
    const ParsedQuicVersion& version,
    QuicPacketNumberLength packet_number_length) {
  if (!version.HasHeaderProtection()) {
    return 0;
  }
  // Header protection samples 16 bytes of ciphertext starting 4 bytes after the
  // packet number. In IETF QUIC, all AEAD algorithms have a 16-byte auth tag
  // (i.e. the ciphertext is 16 bytes larger than the plaintext). Since packet
  // numbers could be as small as 1 byte, but the sample starts 4 bytes after
  // the packet number, at least 3 bytes of plaintext are needed to make sure
  // that there is enough ciphertext to sample.
  //
  // Google QUIC crypto uses different AEAD algorithms - in particular the auth
  // tags are only 12 bytes instead of 16 bytes. Since the auth tag is 4 bytes
  // shorter, 4 more bytes of plaintext are needed to guarantee there is enough
  // ciphertext to sample.
  //
  // This method could check for PROTOCOL_TLS1_3 vs PROTOCOL_QUIC_CRYPTO and
  // return 3 when TLS 1.3 is in use (the use of IETF vs Google QUIC crypters is
  // determined based on the handshake protocol used). However, even when TLS
  // 1.3 is used, unittests still use NullEncrypter/NullDecrypter (and other
  // test crypters) which also only use 12 byte tags.
  //
  return (version.UsesTls() ? 4 : 8) - packet_number_length;
}

QuicPacketNumber QuicPacketCreator::NextSendingPacketNumber() const {
  if (!packet_number().IsInitialized()) {
    return framer_->first_sending_packet_number();
  }
  return packet_number() + 1;
}

bool QuicPacketCreator::PacketFlusherAttached() const {
  return flusher_attached_;
}

bool QuicPacketCreator::HasSoftMaxPacketLength() const {
  return latched_hard_max_packet_length_ != 0;
}

void QuicPacketCreator::SetDefaultPeerAddress(QuicSocketAddress address) {
  if (!packet_.peer_address.IsInitialized()) {
    packet_.peer_address = address;
    return;
  }
  if (packet_.peer_address != address) {
    FlushCurrentPacket();
    packet_.peer_address = address;
  }
}

#define ENDPOINT2                                                          \
  (creator_->framer_->perspective() == Perspective::IS_SERVER ? "Server: " \
                                                              : "Client: ")

QuicPacketCreator::ScopedPeerAddressContext::ScopedPeerAddressContext(
    QuicPacketCreator* creator, QuicSocketAddress address,
    const QuicConnectionId& client_connection_id,
    const QuicConnectionId& server_connection_id)
    : creator_(creator),
      old_peer_address_(creator_->packet_.peer_address),
      old_client_connection_id_(creator_->GetClientConnectionId()),
      old_server_connection_id_(creator_->GetServerConnectionId()) {
  QUIC_BUG_IF(quic_bug_12398_19, !old_peer_address_.IsInitialized())
      << ENDPOINT2
      << "Context is used before serialized packet's peer address is "
         "initialized.";
  creator_->SetDefaultPeerAddress(address);
  if (creator_->version().HasIetfQuicFrames()) {
    // Flush current packet if connection ID length changes.
    if (address == old_peer_address_ &&
        ((client_connection_id.length() !=
          old_client_connection_id_.length()) ||
         (server_connection_id.length() !=
          old_server_connection_id_.length()))) {
      creator_->FlushCurrentPacket();
    }
    creator_->SetClientConnectionId(client_connection_id);
    creator_->SetServerConnectionId(server_connection_id);
  }
}

QuicPacketCreator::ScopedPeerAddressContext::~ScopedPeerAddressContext() {
  creator_->SetDefaultPeerAddress(old_peer_address_);
  if (creator_->version().HasIetfQuicFrames()) {
    creator_->SetClientConnectionId(old_client_connection_id_);
    creator_->SetServerConnectionId(old_server_connection_id_);
  }
}

QuicPacketCreator::ScopedSerializationFailureHandler::
    ScopedSerializationFailureHandler(QuicPacketCreator* creator)
    : creator_(creator) {}

QuicPacketCreator::ScopedSerializationFailureHandler::
    ~ScopedSerializationFailureHandler() {
  if (creator_ == nullptr) {
    return;
  }
  // Always clear queued_frames_.
  creator_->queued_frames_.clear();

  if (creator_->packet_.encrypted_buffer == nullptr) {
    const std::string error_details = "Failed to SerializePacket.";
    QUIC_BUG(quic_bug_10752_38) << ENDPOINT2 << error_details;
    creator_->delegate_->OnUnrecoverableError(QUIC_FAILED_TO_SERIALIZE_PACKET,
                                              error_details);
  }
}

#undef ENDPOINT2

void QuicPacketCreator::set_encryption_level(EncryptionLevel level) {
  QUICHE_DCHECK(level == packet_.encryption_level || !HasPendingFrames())
      << ENDPOINT << "Cannot update encryption level from "
      << packet_.encryption_level << " to " << level
      << " when we already have pending frames: "
      << QuicFramesToString(queued_frames_);
  packet_.encryption_level = level;
}

void QuicPacketCreator::AddPathChallengeFrame(
    const QuicPathFrameBuffer& payload) {
  // TODO(danzh) Unify similar checks at several entry points into one in
  // AddFrame(). Sort out test helper functions and peer class that don't
  // enforce this check.
  QUIC_BUG_IF(quic_bug_10752_39, !flusher_attached_)
      << ENDPOINT
      << "Packet flusher is not attached when "
         "generator tries to write stream data.";
  // Write a PATH_CHALLENGE frame, which has a random 8-byte payload.
  QuicFrame frame(QuicPathChallengeFrame(0, payload));
  if (AddPaddedFrameWithRetry(frame)) {
    return;
  }
  // Fail silently if the probing packet cannot be written, path validation
  // initiator will retry sending automatically.
  // TODO(danzh) This will consume retry budget, if it causes performance
  // regression, consider to notify the caller about the sending failure and let
  // the caller to decide if it worth retrying.
  QUIC_DVLOG(1) << ENDPOINT << "Can't send PATH_CHALLENGE now";
}

bool QuicPacketCreator::AddPathResponseFrame(
    const QuicPathFrameBuffer& data_buffer) {
  QuicFrame frame(QuicPathResponseFrame(kInvalidControlFrameId, data_buffer));
  if (AddPaddedFrameWithRetry(frame)) {
    return true;
  }

  QUIC_DVLOG(1) << ENDPOINT << "Can't send PATH_RESPONSE now";
  return false;
}

bool QuicPacketCreator::AddPaddedFrameWithRetry(const QuicFrame& frame) {
  if (HasPendingFrames()) {
    if (AddPaddedSavedFrame(frame, NOT_RETRANSMISSION)) {
      // Frame is queued.
      return true;
    }
  }
  // Frame was not queued but queued frames were flushed.
  QUICHE_DCHECK(!HasPendingFrames()) << ENDPOINT;
  if (!delegate_->ShouldGeneratePacket(NO_RETRANSMITTABLE_DATA,
                                       NOT_HANDSHAKE)) {
    return false;
  }
  bool success = AddPaddedSavedFrame(frame, NOT_RETRANSMISSION);
  QUIC_BUG_IF(quic_bug_12398_20, !success) << ENDPOINT;
  return true;
}

bool QuicPacketCreator::HasRetryToken() const { return !retry_token_.empty(); }

#undef ENDPOINT  // undef for jumbo builds
}  // namespace quic
```