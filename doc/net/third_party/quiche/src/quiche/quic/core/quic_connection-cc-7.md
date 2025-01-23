Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's QUIC implementation. I need to analyze the code and identify its key responsibilities.

Here's a breakdown of the code's functionality:

1. **Peer Migration Handling:**  It checks for changes in the peer's address and initiates peer migration if supported.
2. **Post-ACK Processing:** It updates the retransmission alarm, handles forward progress, and manages blackhole detection after receiving an ACK.
3. **Setting Dependencies:** It allows setting the session notifier and data producer.
4. **Transmission Type Control:** It allows setting the transmission type for packets.
5. **Release Time Management:** It updates the maximum allowed delay for packet release.
6. **ACK State Reset:** It resets the states related to acknowledgments.
7. **Message Sending:** It handles sending messages, including size checks and blocking conditions.
8. **Largest Message Payload:** It provides methods to get the current and guaranteed largest message payload sizes.
9. **Cipher ID Retrieval:** It retrieves the cipher ID used for encryption.
10. **Connection Close Encryption Level:** It determines the encryption level to use when closing the connection.
11. **Bundling Crypto Data with ACKs:** It attempts to bundle CRYPTO data with ACK frames for efficiency.
12. **Sending All Pending ACKs:** It iterates through pending ACKs for different packet number spaces and sends them.
13. **Coalescing Packets:** It tries to combine packets of different encryption levels into a single physical packet.
14. **Flushing Coalesced Packets:** It serializes and sends the coalesced packet.
15. **Multiple Packet Number Space Support:** It enables and checks for support for multiple packet number spaces.
16. **Tracking Largest Received Packet with ACK:** It keeps track of the largest received packet that acknowledged new data.
17. **Forward Progress Handling:** It performs actions when forward progress is made, including restarting blackhole detection.
18. **Getting Largest Packet Numbers:** It provides methods to retrieve the largest received and acknowledged packet numbers.
19. **Anti-Amplification Limit Enforcement:** It checks if sending is limited by the anti-amplification factor.
20. **Timeout Behavior Control:** It determines if timeout adjustments should be applied.
21. **Packet Fate Determination:** It decides whether a packet should be discarded, coalesced, buffered, or sent immediately.
22. **Handshake Status:** It provides methods to check the handshake completion status.
23. **ACK Decimation Control:** It manages parameters related to delaying ACKs.
24. **Accessing ACK Frame:** It provides access to the ACK frame.
25. **Setting Client Connection ID:** It sets the client connection ID and initializes related managers.
26. **Path Degradation Handling:** It responds to path degradation detection.
27. **Multi-Port Path Migration:** It initiates migration to a multi-port path.
28. **Blackhole Detection Handling:** It reacts to the detection of a network blackhole.
29. **Path MTU Reduction Handling:** It responds to the detection of path MTU reduction.
30. **Timeout Handling:** It handles handshake, idle network, and keep-alive timeouts.
31. **Retransmittable On-Wire Timeout:** It responds to timeouts where retransmittable data is expected to be in transit.
32. **Peer-Issued Connection ID Retirement:** It handles the retirement of connection IDs issued by the peer.

Now, I need to address the specific requirements of the prompt:

*   **Relationship with Javascript:** This code is part of the network stack and directly manages the QUIC protocol. Javascript in a browser would interact with this functionality through higher-level APIs (like `fetch` or WebSockets) which internally utilize this QUIC implementation.
*   **Logical Reasoning (Hypothetical Input/Output):** Consider the `PostProcessAfterAckFrame` function.
    *   **Input:** `acked_new_packet = true`
    *   **Output:** The retransmission alarm is reset, and `OnForwardProgressMade()` is called, potentially restarting blackhole detection if there are in-flight packets.
    *   **Input:** `acked_new_packet = false`, `sent_packet_manager_.HasInFlightPackets() = false`, `blackhole_detector_.IsDetectionInProgress() = true`
    *   **Output:** Blackhole detection is stopped.
*   **User/Programming Errors:** The `SendMessage` function checks for message size. A common programming error would be trying to send a message larger than `GetCurrentLargestMessagePayload()`, resulting in `MESSAGE_STATUS_TOO_LARGE`.
*   **User Operation to Reach Here (Debugging):**  A user browsing a website that uses QUIC could trigger this code. When a QUIC connection is established and data is exchanged, ACKs will be received, leading to the execution of functions like `PostProcessAfterAckFrame`. During debugging, one might set breakpoints in these functions to inspect the connection state.
*   **Summary of Functionality (Part 8 of 10):** This section of the code primarily deals with the lifecycle of a QUIC connection after packets have been exchanged, focusing on ACK processing, managing packet transmission and retransmission, handling various timeout scenarios, and adapting to network conditions like path changes and blackholes. It also manages connection IDs and supports features like packet coalescing and multiple packet number spaces.
This section of the `quic_connection.cc` file focuses on several key aspects of managing a QUIC connection after it has been established and is actively exchanging data. Here's a breakdown of its functionalities:

**Core Connection Management and State Updates:**

*   **Peer Migration Handling:**  It checks if the peer's IP address has changed and initiates or updates the peer migration process if supported. This ensures the connection remains alive if the peer's network path changes.
*   **Post-Acknowledgement Processing:**  After receiving an acknowledgement (ACK) frame, this code performs crucial actions:
    *   Updates the retransmission alarm to reflect the latest round-trip time (RTT) estimate.
    *   Potentially tells the received packet manager to stop waiting for packets older than the newly acknowledged ones.
    *   Calls `OnForwardProgressMade()` if the ACK acknowledged new data, signaling progress.
    *   Manages the blackhole detector, stopping it if no new packets are acknowledged and there are no packets in flight.
*   **Setting External Interfaces:** It provides functions to set external dependencies like `SessionNotifierInterface` (for reporting connection events) and `QuicStreamFrameDataProducer` (for providing data to be sent).
*   **Transmission Type Control:** Allows setting the type of transmission for subsequent packets (e.g., retransmission, probing).
*   **Release Time Management:** Updates the maximum allowed delay for sending packets based on the smoothed RTT, influencing pacing and congestion control.
*   **Acknowledgement State Reset:**  Cancels the ACK alarm and resets the internal state of the received packet manager related to acknowledgements.

**Data Sending and Framing:**

*   **Message Sending:** The `SendMessage` function attempts to send a message. It checks if the message size exceeds the current limit and if the connection is ready to write data. It then uses the `packet_creator_` to add the message to a frame.
*   **Retrieving Message Payload Limits:** Provides functions to get the current and guaranteed maximum payload sizes for messages.

**Security and Encryption:**

*   **Cipher ID Retrieval:**  Returns the identifier of the cipher currently being used for encryption.
*   **Determining Connection Close Encryption Level:**  Specifies the encryption level that should be used when sending a connection close frame.

**Acknowledgement Handling and Optimization:**

*   **Bundling Crypto Data with ACKs:**  Attempts to include cryptographic handshake data within acknowledgement packets to reduce the number of packets sent during the handshake process, especially on the server side.
*   **Sending All Pending ACKs:** Iterates through the different packet number spaces and sends any pending acknowledgement frames. It also handles cases where sending ACKs might be blocked due to network conditions.
*   **Coalescing Packets:**  The `MaybeCoalescePacketOfHigherSpace` function tries to combine packets destined for different encryption levels into a single larger packet to improve efficiency. This is particularly relevant during the handshake.
*   **Flushing Coalesced Packets:**  Actually serializes and sends the combined (coalesced) packet. It handles potential write blocking and amplification limits.

**Multiple Packet Number Space Support (QUICv3):**

*   **Enabling Support:**  Provides a function to enable support for multiple packet number spaces, a key feature of newer QUIC versions.
*   **Checking for Support:**  Allows querying if multiple packet number spaces are currently enabled.
*   **Tracking Largest Received Packet with ACK:**  Keeps track of the largest packet number acknowledged for each packet number space.

**Network Condition Monitoring and Adaptation:**

*   **Forward Progress Detection:** The `OnForwardProgressMade` function is called when new data is successfully acknowledged. It handles actions like:
    *   Notifying the visitor about forward progress after path degradation or flow label changes.
    *   Restarting blackhole and path MTU reduction detection mechanisms.
*   **Retrieving Largest Packet Numbers:** Provides functions to get the largest received and acknowledged packet numbers, which are important for various QUIC mechanisms.
*   **Anti-Amplification Limit Enforcement:** Checks if the connection is currently limited by the anti-amplification mechanism (especially relevant for servers before client address validation).
*   **Timeout Behavior Adjustment:** Determines if connection timeouts should be adjusted based on received connection options.

**Packet Handling and Fate Determination:**

*   **Determining Packet Fate:** The `GetSerializedPacketFate` function decides what to do with a packet before sending it: discard it, coalesce it with other packets, buffer it, or send it immediately to the writer.

**Handshake Status:**

*   **Checking Handshake Completion:** Provides functions to check if the QUIC handshake is complete or confirmed.

**Acknowledgement Decimation:**

*   **Controlling ACK Frequency:** Allows setting and getting the minimum number of received packets before an ACK needs to be sent.

**Accessing Acknowledgement Information:**

*   **Retrieving ACK Frame:** Provides access to the most recent acknowledgement frame.

**Connection ID Management:**

*   **Setting Client Connection ID:** Sets the client connection ID and initializes the peer-issued connection ID manager (for servers) or self-issued connection ID manager (for clients).

**Path Management and Network Issues:**

*   **Path Degradation Detection:**  Handles the detection of a degrading network path and potentially triggers migration to a multi-port path.
*   **Multi-Port Path Migration:** Initiates the process of switching the connection to an alternative network path (multi-port).
*   **Blackhole Detection Handling:**  Reacts when a network blackhole is detected, typically by closing the connection.
*   **Path MTU Reduction Handling:**  Responds to the detection of a reduced Maximum Transmission Unit (MTU) on the path, potentially by reverting to a smaller MTU.

**Timeout Handling:**

*   **Handshake Timeout:** Handles the scenario where the handshake takes too long to complete.
*   **Idle Network Timeout:**  Handles the case where there has been no network activity for a prolonged period.
*   **Keep-Alive Timeout:** Sends a PING frame to keep the connection alive if it's been idle.
*   **Retransmittable On-Wire Timeout:**  Addresses a specific scenario where retransmittable data is expected to be in transit but there's a timeout. It can trigger sending a buffered packet or a PING.
*   **Peer-Issued Connection ID Retirement:**  Handles the peer indicating that a connection ID is no longer in use.

**Relationship with Javascript:**

This C++ code is part of the underlying network stack in Chromium. Javascript running in a web browser doesn't directly interact with this code. Instead, when a website uses HTTPS over QUIC, the browser's network stack (which includes this `quic_connection.cc` file) handles the QUIC protocol details transparently. Javascript interacts with network resources using higher-level APIs like `fetch` or WebSockets. These APIs then internally utilize the QUIC implementation when appropriate.

**Example:**

Imagine a Javascript application uses `fetch` to request data from a server over HTTPS/QUIC.

1. The Javascript code calls `fetch()`.
2. The browser's network stack determines that the connection to the server can use QUIC.
3. If an ACK is received from the server for a data packet, the code in `PostProcessAfterAckFrame` would be executed within the Chromium network stack. This would update the RTT estimate, potentially trigger congestion control adjustments, and inform the system that forward progress is being made.
4. The Javascript application remains unaware of these low-level QUIC details. It simply receives the response from the `fetch()` call when the data is available.

**Logical Reasoning (Hypothetical Input and Output):**

**Scenario: Handling Peer Address Change**

*   **Hypothetical Input:**  The `last_received_packet_info_.source_address` has changed compared to the previously known peer address, and `current_effective_peer_migration_type_` is not `NO_CHANGE`.
*   **Assumptions:** Peer migration is supported.
*   **Output:** `StartEffectivePeerMigration(current_effective_peer_migration_type_)` is called. This initiates the process of formally migrating the connection to the new peer address.

**Scenario: Processing an ACK for a New Packet**

*   **Hypothetical Input:** `acked_new_packet` is `true`.
*   **Output:** `SetRetransmissionAlarm()` is called to adjust the retransmission timer based on the new RTT estimate. `OnForwardProgressMade()` is also called, potentially restarting blackhole detection if there are packets in flight.

**User or Programming Common Usage Errors:**

*   **Sending Oversized Messages:**  A common programming error would be attempting to send a message using `SendMessage` that is larger than the maximum allowed payload (returned by `GetCurrentLargestMessagePayload()`). This would result in `MESSAGE_STATUS_TOO_LARGE`, and the message would not be sent. The developer would need to either fragment the message or wait for the connection to negotiate a larger payload limit.

**User Operation to Reach Here (Debugging Scenario):**

1. **User Browses a Website:** A user opens a website in Chrome that supports HTTPS over QUIC.
2. **QUIC Connection Establishment:** The browser attempts to establish a QUIC connection with the server.
3. **Data Exchange:** Once the connection is established, the browser starts sending requests (e.g., for web page resources) and receiving responses from the server.
4. **Packet Reception and Acknowledgement:** As the browser receives data packets from the server, it sends acknowledgement (ACK) packets back.
5. **Triggering `PostProcessAfterAckFrame`:** When an ACK packet from the server is processed by the browser's QUIC implementation, the `QuicConnection::OnAckFrame` function (not shown in this snippet) would be called. This function would then call `PostProcessAfterAckFrame`.
6. **Debugging Breakpoint:** A developer debugging the Chromium network stack could set a breakpoint in `PostProcessAfterAckFrame` to inspect the connection state when an ACK is received. They could examine variables like `acked_new_packet`, the current RTT estimate, and the state of the blackhole detector.

**Summary of Functionality (Part 8 of 10):**

This specific section of `quic_connection.cc` is heavily involved in the **ongoing management and maintenance of an active QUIC connection**. It handles critical tasks such as processing acknowledgements, managing retransmission timers, handling peer address changes, optimizing packet transmission through coalescing, and reacting to changing network conditions like path degradation and potential blackholes. It also lays the groundwork for more advanced QUIC features like multi-path connections and manages connection identifiers. Essentially, it ensures the reliability, efficiency, and responsiveness of the QUIC connection after the initial handshake.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
supported, only
      // start peer migration for the application data.
      StartEffectivePeerMigration(current_effective_peer_migration_type_);
    } else {
      UpdatePeerAddress(last_received_packet_info_.source_address);
    }
  }
  current_effective_peer_migration_type_ = NO_CHANGE;
}

void QuicConnection::PostProcessAfterAckFrame(bool acked_new_packet) {
  if (!packet_creator_.has_ack()) {
    uber_received_packet_manager_.DontWaitForPacketsBefore(
        last_received_packet_info_.decrypted_level,
        SupportsMultiplePacketNumberSpaces()
            ? sent_packet_manager_.GetLargestPacketPeerKnowsIsAcked(
                  last_received_packet_info_.decrypted_level)
            : sent_packet_manager_.largest_packet_peer_knows_is_acked());
  }
  // Always reset the retransmission alarm when an ack comes in, since we now
  // have a better estimate of the current rtt than when it was set.
  SetRetransmissionAlarm();
  if (acked_new_packet) {
    OnForwardProgressMade();
  } else if (default_enable_5rto_blackhole_detection_ &&
             !sent_packet_manager_.HasInFlightPackets() &&
             blackhole_detector_.IsDetectionInProgress()) {
    // In case no new packets get acknowledged, it is possible packets are
    // detected lost because of time based loss detection. Cancel blackhole
    // detection if there is no packets in flight.
    blackhole_detector_.StopDetection(/*permanent=*/false);
  }
}

void QuicConnection::SetSessionNotifier(
    SessionNotifierInterface* session_notifier) {
  sent_packet_manager_.SetSessionNotifier(session_notifier);
}

void QuicConnection::SetDataProducer(
    QuicStreamFrameDataProducer* data_producer) {
  framer_.set_data_producer(data_producer);
}

void QuicConnection::SetTransmissionType(TransmissionType type) {
  packet_creator_.SetTransmissionType(type);
}

void QuicConnection::UpdateReleaseTimeIntoFuture() {
  QUICHE_DCHECK(supports_release_time_);

  const QuicTime::Delta prior_max_release_time = release_time_into_future_;
  release_time_into_future_ = std::max(
      QuicTime::Delta::FromMilliseconds(kMinReleaseTimeIntoFutureMs),
      std::min(QuicTime::Delta::FromMilliseconds(
                   GetQuicFlag(quic_max_pace_time_into_future_ms)),
               sent_packet_manager_.GetRttStats()->SmoothedOrInitialRtt() *
                   GetQuicFlag(quic_pace_time_into_future_srtt_fraction)));
  QUIC_DVLOG(3) << "Updated max release time delay from "
                << prior_max_release_time << " to "
                << release_time_into_future_;
}

void QuicConnection::ResetAckStates() {
  ack_alarm().Cancel();
  uber_received_packet_manager_.ResetAckStates(encryption_level_);
}

MessageStatus QuicConnection::SendMessage(
    QuicMessageId message_id, absl::Span<quiche::QuicheMemSlice> message,
    bool flush) {
  if (MemSliceSpanTotalSize(message) > GetCurrentLargestMessagePayload()) {
    return MESSAGE_STATUS_TOO_LARGE;
  }
  if (!connected_ || (!flush && !CanWrite(HAS_RETRANSMITTABLE_DATA))) {
    return MESSAGE_STATUS_BLOCKED;
  }
  ScopedPacketFlusher flusher(this);
  return packet_creator_.AddMessageFrame(message_id, message);
}

QuicPacketLength QuicConnection::GetCurrentLargestMessagePayload() const {
  return packet_creator_.GetCurrentLargestMessagePayload();
}

QuicPacketLength QuicConnection::GetGuaranteedLargestMessagePayload() const {
  return packet_creator_.GetGuaranteedLargestMessagePayload();
}

uint32_t QuicConnection::cipher_id() const {
  if (version().KnowsWhichDecrypterToUse()) {
    if (quic_limit_new_streams_per_loop_2_) {
      QUIC_RELOADABLE_FLAG_COUNT_N(quic_limit_new_streams_per_loop_2, 4, 4);
      for (auto decryption_level :
           {ENCRYPTION_FORWARD_SECURE, ENCRYPTION_HANDSHAKE,
            ENCRYPTION_ZERO_RTT, ENCRYPTION_INITIAL}) {
        const QuicDecrypter* decrypter = framer_.GetDecrypter(decryption_level);
        if (decrypter != nullptr) {
          return decrypter->cipher_id();
        }
      }
      QUICHE_BUG(no_decrypter_found)
          << ENDPOINT << "No decrypter found at all encryption levels";
      return 0;
    } else {
      return framer_.GetDecrypter(last_received_packet_info_.decrypted_level)
          ->cipher_id();
    }
  }
  return framer_.decrypter()->cipher_id();
}

EncryptionLevel QuicConnection::GetConnectionCloseEncryptionLevel() const {
  if (perspective_ == Perspective::IS_CLIENT) {
    return encryption_level_;
  }
  if (IsHandshakeComplete()) {
    // A forward secure packet has been received.
    QUIC_BUG_IF(quic_bug_12714_31,
                encryption_level_ != ENCRYPTION_FORWARD_SECURE)
        << ENDPOINT << "Unexpected connection close encryption level "
        << encryption_level_;
    return ENCRYPTION_FORWARD_SECURE;
  }
  if (framer_.HasEncrypterOfEncryptionLevel(ENCRYPTION_ZERO_RTT)) {
    if (encryption_level_ != ENCRYPTION_ZERO_RTT) {
      QUIC_CODE_COUNT(quic_wrong_encryption_level_connection_close_ietf);
    }
    return ENCRYPTION_ZERO_RTT;
  }
  return ENCRYPTION_INITIAL;
}

void QuicConnection::MaybeBundleCryptoDataWithAcks() {
  QUICHE_DCHECK(SupportsMultiplePacketNumberSpaces());
  if (IsHandshakeConfirmed()) {
    return;
  }
  PacketNumberSpace space = HANDSHAKE_DATA;
  if (perspective() == Perspective::IS_SERVER &&
      framer_.HasEncrypterOfEncryptionLevel(ENCRYPTION_INITIAL)) {
    // On the server side, sends INITIAL data with INITIAL ACK if initial key is
    // available.
    space = INITIAL_DATA;
  }
  const QuicTime ack_timeout =
      uber_received_packet_manager_.GetAckTimeout(space);
  if (!ack_timeout.IsInitialized() ||
      (ack_timeout > clock_->ApproximateNow() &&
       ack_timeout > uber_received_packet_manager_.GetEarliestAckTimeout())) {
    // No pending ACK of space.
    return;
  }
  if (coalesced_packet_.length() > 0) {
    // Do not bundle CRYPTO data if the ACK could be coalesced with other
    // packets.
    return;
  }

  if (!framer_.HasAnEncrypterForSpace(space)) {
    QUIC_BUG(quic_bug_10511_39)
        << ENDPOINT
        << "Try to bundle crypto with ACK with missing key of space "
        << PacketNumberSpaceToString(space);
    return;
  }

  sent_packet_manager_.RetransmitDataOfSpaceIfAny(space);
}

void QuicConnection::SendAllPendingAcks() {
  QUICHE_DCHECK(SupportsMultiplePacketNumberSpaces());
  QUIC_DVLOG(1) << ENDPOINT << "Trying to send all pending ACKs";
  ack_alarm().Cancel();
  QuicTime earliest_ack_timeout =
      uber_received_packet_manager_.GetEarliestAckTimeout();
  QUIC_BUG_IF(quic_bug_12714_32, !earliest_ack_timeout.IsInitialized());
  MaybeBundleCryptoDataWithAcks();
  visitor_->MaybeBundleOpportunistically();
  earliest_ack_timeout = uber_received_packet_manager_.GetEarliestAckTimeout();
  if (!earliest_ack_timeout.IsInitialized()) {
    return;
  }
  for (int8_t i = INITIAL_DATA; i <= APPLICATION_DATA; ++i) {
    const QuicTime ack_timeout = uber_received_packet_manager_.GetAckTimeout(
        static_cast<PacketNumberSpace>(i));
    if (!ack_timeout.IsInitialized()) {
      continue;
    }
    if (!framer_.HasAnEncrypterForSpace(static_cast<PacketNumberSpace>(i))) {
      // The key has been dropped.
      continue;
    }
    if (ack_timeout > clock_->ApproximateNow() &&
        ack_timeout > earliest_ack_timeout) {
      // Always send the earliest ACK to make forward progress in case alarm
      // fires early.
      continue;
    }
    QUIC_DVLOG(1) << ENDPOINT << "Sending ACK of packet number space "
                  << PacketNumberSpaceToString(
                         static_cast<PacketNumberSpace>(i));
    ScopedEncryptionLevelContext context(
        this, QuicUtils::GetEncryptionLevelToSendAckofSpace(
                  static_cast<PacketNumberSpace>(i)));
    QuicFrames frames;
    frames.push_back(uber_received_packet_manager_.GetUpdatedAckFrame(
        static_cast<PacketNumberSpace>(i), clock_->ApproximateNow()));
    const bool flushed = packet_creator_.FlushAckFrame(frames);
    // Consider reset ack states even when flush is not successful.
    if (!flushed) {
      // Connection is write blocked.
      QUIC_BUG_IF(quic_bug_12714_33,
                  connected_ && !writer_->IsWriteBlocked() &&
                      !LimitedByAmplificationFactor(
                          packet_creator_.max_packet_length()) &&
                      !IsMissingDestinationConnectionID())
          << "Writer not blocked and not throttled by amplification factor, "
             "but ACK not flushed for packet space:"
          << PacketNumberSpaceToString(static_cast<PacketNumberSpace>(i))
          << ", fill_coalesced_packet: " << fill_coalesced_packet_
          << ", blocked_by_no_connection_id: "
          << (peer_issued_cid_manager_ != nullptr &&
              packet_creator_.GetDestinationConnectionId().IsEmpty())
          << ", has_soft_max_packet_length: "
          << packet_creator_.HasSoftMaxPacketLength()
          << ", max_packet_length: " << packet_creator_.max_packet_length()
          << ", pending frames: " << packet_creator_.GetPendingFramesInfo();
      break;
    }
    ResetAckStates();
  }

  const QuicTime timeout =
      uber_received_packet_manager_.GetEarliestAckTimeout();
  if (timeout.IsInitialized()) {
    // If there are ACKs pending, re-arm ack alarm.
    ack_alarm().Update(timeout, kAlarmGranularity);
  }
  // Only try to bundle retransmittable data with ACK frame if default
  // encryption level is forward secure.
  if (encryption_level_ != ENCRYPTION_FORWARD_SECURE ||
      !ShouldBundleRetransmittableFrameWithAck()) {
    return;
  }
  consecutive_num_packets_with_no_retransmittable_frames_ = 0;
  if (packet_creator_.HasPendingRetransmittableFrames() ||
      visitor_->WillingAndAbleToWrite()) {
    // There are pending retransmittable frames.
    return;
  }

  visitor_->OnAckNeedsRetransmittableFrame();
}

bool QuicConnection::ShouldBundleRetransmittableFrameWithAck() const {
  if (consecutive_num_packets_with_no_retransmittable_frames_ >=
      max_consecutive_num_packets_with_no_retransmittable_frames_) {
    return true;
  }
  if (bundle_retransmittable_with_pto_ack_ &&
      sent_packet_manager_.GetConsecutivePtoCount() > 0) {
    // Bundle a retransmittable frame with an ACK if PTO has fired in order to
    // recover more quickly in cases of temporary network outage.
    return true;
  }
  return false;
}

void QuicConnection::MaybeCoalescePacketOfHigherSpace() {
  if (!connected() || !packet_creator_.HasSoftMaxPacketLength()) {
    return;
  }
  if (fill_coalesced_packet_) {
    // Make sure MaybeCoalescePacketOfHigherSpace is not re-entrant.
    QUIC_BUG(quic_coalesce_packet_reentrant);
    return;
  }
  for (EncryptionLevel retransmission_level :
       {ENCRYPTION_INITIAL, ENCRYPTION_HANDSHAKE}) {
    // Coalesce HANDSHAKE with INITIAL retransmission, and coalesce 1-RTT with
    // HANDSHAKE retransmission.
    const EncryptionLevel coalesced_level =
        retransmission_level == ENCRYPTION_INITIAL ? ENCRYPTION_HANDSHAKE
                                                   : ENCRYPTION_FORWARD_SECURE;
    if (coalesced_packet_.ContainsPacketOfEncryptionLevel(
            retransmission_level) &&
        coalesced_packet_.TransmissionTypeOfPacket(retransmission_level) !=
            NOT_RETRANSMISSION &&
        framer_.HasEncrypterOfEncryptionLevel(coalesced_level) &&
        !coalesced_packet_.ContainsPacketOfEncryptionLevel(coalesced_level)) {
      QUIC_DVLOG(1) << ENDPOINT
                    << "Trying to coalesce packet of encryption level: "
                    << EncryptionLevelToString(coalesced_level);
      fill_coalesced_packet_ = true;
      sent_packet_manager_.RetransmitDataOfSpaceIfAny(
          QuicUtils::GetPacketNumberSpace(coalesced_level));
      fill_coalesced_packet_ = false;
    }
  }
}

bool QuicConnection::FlushCoalescedPacket() {
  ScopedCoalescedPacketClearer clearer(&coalesced_packet_);
  if (!connected_) {
    return false;
  }
  if (!version().CanSendCoalescedPackets()) {
    QUIC_BUG_IF(quic_bug_12714_34, coalesced_packet_.length() > 0);
    return true;
  }
  if (coalesced_packet_.ContainsPacketOfEncryptionLevel(ENCRYPTION_INITIAL) &&
      !framer_.HasEncrypterOfEncryptionLevel(ENCRYPTION_INITIAL)) {
    // Initial packet will be re-serialized. Neuter it in case initial key has
    // been dropped.
    QUIC_BUG(quic_bug_10511_40)
        << ENDPOINT
        << "Coalescer contains initial packet while initial key has "
           "been dropped.";
    coalesced_packet_.NeuterInitialPacket();
  }
  if (coalesced_packet_.length() == 0) {
    return true;
  }

  char buffer[kMaxOutgoingPacketSize];
  const size_t length = packet_creator_.SerializeCoalescedPacket(
      coalesced_packet_, buffer, coalesced_packet_.max_packet_length());
  if (length == 0) {
    if (connected_) {
      CloseConnection(QUIC_FAILED_TO_SERIALIZE_PACKET,
                      "Failed to serialize coalesced packet.",
                      ConnectionCloseBehavior::SILENT_CLOSE);
    }
    return false;
  }
  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnCoalescedPacketSent(coalesced_packet_, length);
  }
  QUIC_DVLOG(1) << ENDPOINT << "Sending coalesced packet "
                << coalesced_packet_.ToString(length);
  const size_t padding_size =
      length - std::min<size_t>(length, coalesced_packet_.length());
  // Buffer coalesced packet if padding + bytes_sent exceeds amplifcation limit.
  if (!buffered_packets_.empty() || HandleWriteBlocked() ||
      (enforce_strict_amplification_factor_ &&
       LimitedByAmplificationFactor(padding_size))) {
    QUIC_DVLOG(1) << ENDPOINT
                  << "Buffering coalesced packet of len: " << length;
    buffered_packets_.emplace_back(
        buffer, static_cast<QuicPacketLength>(length),
        coalesced_packet_.self_address(), coalesced_packet_.peer_address(),
        coalesced_packet_.ecn_codepoint(), coalesced_packet_.flow_label());
  } else {
    WriteResult result = SendPacketToWriter(
        buffer, length, coalesced_packet_.self_address().host(),
        coalesced_packet_.peer_address(), writer_,
        coalesced_packet_.ecn_codepoint(), coalesced_packet_.flow_label());
    if (IsWriteError(result.status)) {
      OnWriteError(result.error_code);
      return false;
    }
    if (IsWriteBlockedStatus(result.status)) {
      visitor_->OnWriteBlocked();
      if (result.status != WRITE_STATUS_BLOCKED_DATA_BUFFERED) {
        QUIC_DVLOG(1) << ENDPOINT
                      << "Buffering coalesced packet of len: " << length;
        buffered_packets_.emplace_back(
            buffer, static_cast<QuicPacketLength>(length),
            coalesced_packet_.self_address(), coalesced_packet_.peer_address(),
            coalesced_packet_.ecn_codepoint(), coalesced_packet_.flow_label());
      }
    }
  }
  if (accelerated_server_preferred_address_ &&
      stats_.num_duplicated_packets_sent_to_server_preferred_address <
          kMaxDuplicatedPacketsSentToServerPreferredAddress) {
    // Send coalesced packets to both addresses while the server preferred
    // address validation is pending.
    QUICHE_DCHECK(received_server_preferred_address_.IsInitialized());
    path_validator_.MaybeWritePacketToAddress(
        buffer, length, received_server_preferred_address_);
    ++stats_.num_duplicated_packets_sent_to_server_preferred_address;
  }
  // Account for added padding.
  if (length > coalesced_packet_.length()) {
    if (IsDefaultPath(coalesced_packet_.self_address(),
                      coalesced_packet_.peer_address())) {
      if (EnforceAntiAmplificationLimit()) {
        // Include bytes sent even if they are not in flight.
        default_path_.bytes_sent_before_address_validation += padding_size;
      }
    } else {
      MaybeUpdateBytesSentToAlternativeAddress(coalesced_packet_.peer_address(),
                                               padding_size);
    }
    stats_.bytes_sent += padding_size;
    if (coalesced_packet_.initial_packet() != nullptr &&
        coalesced_packet_.initial_packet()->transmission_type !=
            NOT_RETRANSMISSION) {
      stats_.bytes_retransmitted += padding_size;
    }
  }
  return true;
}

void QuicConnection::MaybeEnableMultiplePacketNumberSpacesSupport() {
  if (version().handshake_protocol != PROTOCOL_TLS1_3) {
    return;
  }
  QUIC_DVLOG(1) << ENDPOINT << "connection " << connection_id()
                << " supports multiple packet number spaces";
  framer_.EnableMultiplePacketNumberSpacesSupport();
  sent_packet_manager_.EnableMultiplePacketNumberSpacesSupport();
  uber_received_packet_manager_.EnableMultiplePacketNumberSpacesSupport(
      perspective_);
}

bool QuicConnection::SupportsMultiplePacketNumberSpaces() const {
  return sent_packet_manager_.supports_multiple_packet_number_spaces();
}

void QuicConnection::SetLargestReceivedPacketWithAck(
    QuicPacketNumber new_value) {
  if (SupportsMultiplePacketNumberSpaces()) {
    largest_seen_packets_with_ack_[QuicUtils::GetPacketNumberSpace(
        last_received_packet_info_.decrypted_level)] = new_value;
  } else {
    largest_seen_packet_with_ack_ = new_value;
  }
}

void QuicConnection::OnForwardProgressMade() {
  if (!connected_) {
    return;
  }
  if (is_path_degrading_) {
    visitor_->OnForwardProgressMadeAfterPathDegrading();
    stats_.num_forward_progress_after_path_degrading++;
    is_path_degrading_ = false;
  }
  if (flow_label_has_changed_) {
    visitor_->OnForwardProgressMadeAfterFlowLabelChange();
    stats_.num_forward_progress_after_flow_label_change++;
    flow_label_has_changed_ = false;
  }
  if (sent_packet_manager_.HasInFlightPackets()) {
    // Restart detections if forward progress has been made.
    blackhole_detector_.RestartDetection(GetPathDegradingDeadline(),
                                         GetNetworkBlackholeDeadline(),
                                         GetPathMtuReductionDeadline());
  } else {
    // Stop detections in quiecense.
    blackhole_detector_.StopDetection(/*permanent=*/false);
  }
  QUIC_BUG_IF(quic_bug_12714_35,
              perspective_ == Perspective::IS_SERVER &&
                  default_enable_5rto_blackhole_detection_ &&
                  blackhole_detector_.IsDetectionInProgress() &&
                  !sent_packet_manager_.HasInFlightPackets())
      << ENDPOINT
      << "Trying to start blackhole detection without no bytes in flight";
}

QuicPacketNumber QuicConnection::GetLargestReceivedPacketWithAck() const {
  if (SupportsMultiplePacketNumberSpaces()) {
    return largest_seen_packets_with_ack_[QuicUtils::GetPacketNumberSpace(
        last_received_packet_info_.decrypted_level)];
  }
  return largest_seen_packet_with_ack_;
}

QuicPacketNumber QuicConnection::GetLargestAckedPacket() const {
  if (SupportsMultiplePacketNumberSpaces()) {
    return sent_packet_manager_.GetLargestAckedPacket(
        last_received_packet_info_.decrypted_level);
  }
  return sent_packet_manager_.GetLargestObserved();
}

QuicPacketNumber QuicConnection::GetLargestReceivedPacket() const {
  return uber_received_packet_manager_.GetLargestObserved(
      last_received_packet_info_.decrypted_level);
}

bool QuicConnection::EnforceAntiAmplificationLimit() const {
  return version().SupportsAntiAmplificationLimit() &&
         perspective_ == Perspective::IS_SERVER && !default_path_.validated;
}

bool QuicConnection::ShouldFixTimeouts(const QuicConfig& config) const {
  return quic_fix_timeouts_ && version().UsesTls() &&
         config.HasClientSentConnectionOption(kFTOE, perspective_);
}

// TODO(danzh) Pass in path object or its reference of some sort to use this
// method to check anti-amplification limit on non-default path.
bool QuicConnection::LimitedByAmplificationFactor(QuicByteCount bytes) const {
  return EnforceAntiAmplificationLimit() &&
         (default_path_.bytes_sent_before_address_validation +
          (enforce_strict_amplification_factor_ ? bytes : 0)) >=
             anti_amplification_factor_ *
                 default_path_.bytes_received_before_address_validation;
}

SerializedPacketFate QuicConnection::GetSerializedPacketFate(
    bool is_mtu_discovery, EncryptionLevel encryption_level) {
  if (ShouldDiscardPacket(encryption_level)) {
    return DISCARD;
  }
  if (version().CanSendCoalescedPackets() && !coalescing_done_ &&
      !is_mtu_discovery) {
    if (!IsHandshakeConfirmed()) {
      // Before receiving ACK for any 1-RTT packets, always try to coalesce
      // packet (except MTU discovery packet).
      return COALESCE;
    }
    if (coalesced_packet_.length() > 0) {
      // If the coalescer is not empty, let this packet go through coalescer
      // to avoid potential out of order sending.
      return COALESCE;
    }
  }
  if (!buffered_packets_.empty() || HandleWriteBlocked()) {
    return BUFFER;
  }
  return SEND_TO_WRITER;
}

bool QuicConnection::IsHandshakeComplete() const {
  return visitor_->GetHandshakeState() >= HANDSHAKE_COMPLETE;
}

bool QuicConnection::IsHandshakeConfirmed() const {
  QUICHE_DCHECK_EQ(PROTOCOL_TLS1_3, version().handshake_protocol);
  return visitor_->GetHandshakeState() == HANDSHAKE_CONFIRMED;
}

size_t QuicConnection::min_received_before_ack_decimation() const {
  return uber_received_packet_manager_.min_received_before_ack_decimation();
}

void QuicConnection::set_min_received_before_ack_decimation(size_t new_value) {
  uber_received_packet_manager_.set_min_received_before_ack_decimation(
      new_value);
}

const QuicAckFrame& QuicConnection::ack_frame() const {
  if (SupportsMultiplePacketNumberSpaces()) {
    return uber_received_packet_manager_.GetAckFrame(
        QuicUtils::GetPacketNumberSpace(
            last_received_packet_info_.decrypted_level));
  }
  return uber_received_packet_manager_.ack_frame();
}

void QuicConnection::set_client_connection_id(
    QuicConnectionId client_connection_id) {
  if (!version().SupportsClientConnectionIds()) {
    QUIC_BUG_IF(quic_bug_12714_36, !client_connection_id.IsEmpty())
        << ENDPOINT << "Attempted to use client connection ID "
        << client_connection_id << " with unsupported version " << version();
    return;
  }
  default_path_.client_connection_id = client_connection_id;

  client_connection_id_is_set_ = true;
  if (version().HasIetfQuicFrames() && !client_connection_id.IsEmpty()) {
    if (perspective_ == Perspective::IS_SERVER) {
      QUICHE_DCHECK(peer_issued_cid_manager_ == nullptr);
      peer_issued_cid_manager_ =
          std::make_unique<QuicPeerIssuedConnectionIdManager>(
              kMinNumOfActiveConnectionIds, client_connection_id, clock_,
              alarm_factory_, this, context());
    } else {
      bool create_client_self_issued_cid_manager = true;
      quiche::AdjustTestValue(
          "quic::QuicConnection::create_cid_manager_when_set_client_cid",
          &create_client_self_issued_cid_manager);
      // Note in Chromium client, set_client_connection_id is not called and
      // thus self_issued_cid_manager_ should be null.
      if (create_client_self_issued_cid_manager) {
        self_issued_cid_manager_ = MakeSelfIssuedConnectionIdManager();
      }
    }
  }
  QUIC_DLOG(INFO) << ENDPOINT << "setting client connection ID to "
                  << default_path_.client_connection_id
                  << " for connection with server connection ID "
                  << default_path_.server_connection_id;
  packet_creator_.SetClientConnectionId(default_path_.client_connection_id);
  framer_.SetExpectedClientConnectionIdLength(
      default_path_.client_connection_id.length());
}

void QuicConnection::OnPathDegradingDetected() {
  is_path_degrading_ = true;
  visitor_->OnPathDegrading();
  stats_.num_path_degrading++;
  if (multi_port_stats_ && multi_port_migration_enabled_) {
    MaybeMigrateToMultiPortPath();
  }
}

void QuicConnection::MaybeMigrateToMultiPortPath() {
  if (!alternative_path_.validated) {
    QUIC_CLIENT_HISTOGRAM_ENUM(
        "QuicConnection.MultiPortPathStatusWhenMigrating",
        MultiPortStatusOnMigration::kNotValidated,
        MultiPortStatusOnMigration::kMaxValue,
        "Status of the multi port path upon migration");
    return;
  }
  std::unique_ptr<QuicPathValidationContext> context;
  const bool has_pending_validation =
      path_validator_.HasPendingPathValidation();
  if (!has_pending_validation) {
    // The multi-port path should have just finished the recent probe and
    // waiting for the next one.
    context = std::move(multi_port_path_context_);
    multi_port_probing_alarm().Cancel();
    QUIC_CLIENT_HISTOGRAM_ENUM(
        "QuicConnection.MultiPortPathStatusWhenMigrating",
        MultiPortStatusOnMigration::kWaitingForRefreshValidation,
        MultiPortStatusOnMigration::kMaxValue,
        "Status of the multi port path upon migration");
  } else {
    // The multi-port path is currently under probing.
    context = path_validator_.ReleaseContext();
    QUIC_CLIENT_HISTOGRAM_ENUM(
        "QuicConnection.MultiPortPathStatusWhenMigrating",
        MultiPortStatusOnMigration::kPendingRefreshValidation,
        MultiPortStatusOnMigration::kMaxValue,
        "Status of the multi port path upon migration");
  }
  if (context == nullptr) {
    QUICHE_BUG(quic_bug_12714_90) << "No multi-port context to migrate to";
    return;
  }
  visitor_->MigrateToMultiPortPath(std::move(context));
}

void QuicConnection::OnBlackholeDetected() {
  if (default_enable_5rto_blackhole_detection_ &&
      !sent_packet_manager_.HasInFlightPackets()) {
    QUIC_BUG(quic_bug_10511_41)
        << ENDPOINT
        << "Blackhole detected, but there is no bytes in flight, version: "
        << version();
    // Do not close connection if there is no bytes in flight.
    return;
  }
  CloseConnection(QUIC_TOO_MANY_RTOS, "Network blackhole detected",
                  ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

void QuicConnection::OnPathMtuReductionDetected() {
  MaybeRevertToPreviousMtu();
}

void QuicConnection::OnHandshakeTimeout() {
  const QuicTime::Delta duration =
      clock_->ApproximateNow() - stats_.connection_creation_time;
  std::string error_details = absl::StrCat(
      "Handshake timeout expired after ", duration.ToDebuggingValue(),
      ". Timeout:",
      idle_network_detector_.handshake_timeout().ToDebuggingValue());
  if (perspective() == Perspective::IS_CLIENT && version().UsesTls()) {
    absl::StrAppend(&error_details, " ", UndecryptablePacketsInfo());
  }
  QUIC_DVLOG(1) << ENDPOINT << error_details;
  CloseConnection(QUIC_HANDSHAKE_TIMEOUT, error_details,
                  ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

void QuicConnection::OnIdleNetworkDetected() {
  const QuicTime::Delta duration =
      clock_->ApproximateNow() -
      idle_network_detector_.last_network_activity_time();
  std::string error_details = absl::StrCat(
      "No recent network activity after ", duration.ToDebuggingValue(),
      ". Timeout:",
      idle_network_detector_.idle_network_timeout().ToDebuggingValue());
  if (perspective() == Perspective::IS_CLIENT && version().UsesTls() &&
      !IsHandshakeComplete()) {
    absl::StrAppend(&error_details, " ", UndecryptablePacketsInfo());
  }
  QUIC_DVLOG(1) << ENDPOINT << error_details;
  const bool has_consecutive_pto =
      sent_packet_manager_.GetConsecutivePtoCount() > 0;
  if (has_consecutive_pto || visitor_->ShouldKeepConnectionAlive()) {
    if (GetQuicReloadableFlag(quic_add_stream_info_to_idle_close_detail) &&
        !has_consecutive_pto) {
      // Include stream information in error detail if there are open streams.
      QUIC_RELOADABLE_FLAG_COUNT(quic_add_stream_info_to_idle_close_detail);
      absl::StrAppend(&error_details, ", ",
                      visitor_->GetStreamsInfoForLogging());
    }
    CloseConnection(QUIC_NETWORK_IDLE_TIMEOUT, error_details,
                    ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  QuicErrorCode error_code = QUIC_NETWORK_IDLE_TIMEOUT;
  if (idle_timeout_connection_close_behavior_ ==
      ConnectionCloseBehavior::
          SILENT_CLOSE_WITH_CONNECTION_CLOSE_PACKET_SERIALIZED) {
    error_code = QUIC_SILENT_IDLE_TIMEOUT;
  }
  CloseConnection(error_code, error_details,
                  idle_timeout_connection_close_behavior_);
}

void QuicConnection::OnKeepAliveTimeout() {
  if (retransmission_alarm().IsSet() ||
      !visitor_->ShouldKeepConnectionAlive()) {
    return;
  }
  SendPingAtLevel(framer().GetEncryptionLevelToSendApplicationData());
}

void QuicConnection::OnRetransmittableOnWireTimeout() {
  if (retransmission_alarm().IsSet() ||
      !visitor_->ShouldKeepConnectionAlive()) {
    return;
  }
  bool packet_buffered = false;
  switch (retransmittable_on_wire_behavior_) {
    case DEFAULT:
      break;
    case SEND_FIRST_FORWARD_SECURE_PACKET:
      if (first_serialized_one_rtt_packet_ != nullptr) {
        buffered_packets_.emplace_back(
            first_serialized_one_rtt_packet_->data.get(),
            first_serialized_one_rtt_packet_->length, self_address(),
            peer_address(), first_serialized_one_rtt_packet_->ecn_codepoint,
            first_serialized_one_rtt_packet_->flow_label);
        packet_buffered = true;
      }
      break;
    case SEND_RANDOM_BYTES:
      const QuicPacketLength random_bytes_length = std::max<QuicPacketLength>(
          QuicFramer::GetMinStatelessResetPacketLength() + 1,
          random_generator_->RandUint64() %
              packet_creator_.max_packet_length());
      buffered_packets_.emplace_back(*random_generator_, random_bytes_length,
                                     self_address(), peer_address());
      packet_buffered = true;
      break;
  }
  if (packet_buffered) {
    if (!writer_->IsWriteBlocked()) {
      WriteQueuedPackets();
    }
    if (connected_) {
      // Always reset PING alarm with has_in_flight_packets=true. This is used
      // to avoid re-arming the alarm in retransmittable-on-wire mode.
      ping_manager_.SetAlarm(clock_->ApproximateNow(),
                             visitor_->ShouldKeepConnectionAlive(),
                             /*has_in_flight_packets=*/true);
    }
    return;
  }
  SendPingAtLevel(framer().GetEncryptionLevelToSendApplicationData());
}

void QuicConnection::OnPeerIssuedConnectionIdRetired() {
  QUICHE_DCHECK(peer_issued_cid_manager_ != nullptr);
  QuicConnectionId* default_path_cid =
      perspective_ == Perspective::IS_CLIENT
          ? &default_path_.server_connection_id
          : &default_path_.client_connection_id;
  QuicConnectionId* alternative_path_cid =
      perspective_ == Perspective::IS_CLIENT
          ? &alternative_path_.server_connection_id
          : &alternative_path_.client_connection_id;
  bool default_path_and_alternative_path_use_the_same_peer_connection_id =
      *default_path_cid == *alternative_path_cid;
  if (!default_path_cid->IsEmpty() &&
      !peer_issued_cid_manager_->IsConnectionIdActive(*default_path_cid)) {
    *default_path_cid = QuicConnectionId();
  }
  // TODO(haoyuewang) Handle the change for default_path_ & alternatvie_path_
  // via the same helper function.
  if (default_path_cid->IsEmpty()) {
    // Try setting a new connection ID now such that subsequent
    // RetireConnectionId frames can be sent on the default path.
    const QuicConnectionIdData* unused_connection_id_data =
        peer_issued_cid_manager_->ConsumeOneUnusedConnectionId();
    if (unused_connection_id_data != nullptr) {
      *default_path_cid = unused_connection_id_data->connection_id;
      default_path_.stateless_reset_token =
          unused_connection_id_data->stateless_reset_token;
      if (perspective_ == Perspective::IS_CLIENT) {
        packet_creator_.SetServerConnectionId(
            unused_connection_id_data->connection_id);
      } else {
        packet_creator_.SetClientConnectionId(
            unused_connection_id_data->connection_id);
      }
    }
  }
  if (default_path_and_alternative_path_use_the_same_peer_connection_id) {
    *alternative_path_cid = *default_path_cid;
    alternative_path_.stateless_reset_token =
        default_path_.stateless_reset_token;
  } else if (!alternative_path_cid->IsEmpty() &&
             !peer_issued_cid_manager_->IsConnectionIdActive(
                 *alternative_path_cid)) {
    *alternative_path_cid = EmptyQuicConnectionId();
    const QuicConnectionIdData* unused_connection_id_data =
        peer_issued_cid_manager_->ConsumeOneUnusedConnectionId();
    if (unused_connection_id_data != nullptr) {
      *alternative_path_cid = unused_connection_id_data->connection_id;
      alternative_path_.stateless_reset_token =
          unused_connection_id_data->stateless_reset_token;
    }
  }

  std::vector<uint64_t> reti
```