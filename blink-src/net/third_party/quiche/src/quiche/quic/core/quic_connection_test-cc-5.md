Response:
My thinking process to arrive at the summary and analysis goes like this:

1. **Understand the Core Request:** The user wants a functional summary of the provided C++ code snippet, specifically within the context of Chromium's network stack (QUIC). They also want to know about its relationship to JavaScript, any logical inferences, common errors, debugging steps, and a concise summary of this specific chunk (part 6 of 24).

2. **Initial Code Scan (Keywords and Structure):**  I quickly scanned the code looking for keywords like `TEST_P`, `EXPECT_EQ`, `EXPECT_CALL`, `connection_`, `writer_`, `visitor_`, `SendStreamData`, `ProcessPacket`, `AckFrame`, `RstStream`, etc. The presence of `TEST_P` strongly suggests this is a unit test file. The repeated `EXPECT_CALL` indicates mocking or stubbing of dependencies. The `connection_` object is clearly the core subject of these tests.

3. **Identify Key Functionality Areas:** Based on the test names and the operations performed within them, I started to group related functionalities:
    * **Retransmission Stats:** Tests involving `ConnectionStatsRetransmission` clearly deal with tracking retransmission metrics.
    * **Frame Packing:** Tests like `FramePacking`, `FramePackingNonCryptoThenCrypto`, etc., are focused on how the QUIC connection bundles multiple frames into single packets.
    * **Sending Data (various scenarios):**  Tests involving `SendStreamData`, `SendingZeroBytes`, `LargeSendWithPendingAck`, `FramePackingSendv` demonstrate different ways data is sent and handled.
    * **`OnCanWrite` Handling:** The `OnCanWrite` test checks how the connection reacts to being able to write.
    * **Retransmission Logic (NACK, RTO, PTO):** Tests involving `RetransmitOnNack`, `DoNotRetransmitForResetStreamOnNack`, etc., explore different retransmission triggers and their effects, particularly in combination with stream resets.
    * **Write Blocking:** Tests like `WriteBlockedBufferedThenSent`, `WriteBlockedThenSent`, `AlarmsWhenWriteBlocked` are specifically about handling situations where the underlying socket is not immediately writable.
    * **Interaction with ACKs:** Tests with `AckResponse`, `RetransmitAckedPacket`, and others show how acknowledgments influence packet sending and retransmission.

4. **Deep Dive into Each Test:** I then went through each test case more carefully, understanding:
    * **Setup:** What preconditions are established (e.g., encryption level, blocking writes).
    * **Action:** What method is being called on the `connection_` object or a mock (`visitor_`, `send_algorithm_`).
    * **Assertions:** What `EXPECT_EQ`, `EXPECT_TRUE`, `ASSERT_EQ`, etc., are verifying about the state of the connection, writer, or statistics.
    * **Underlying Logic:**  Based on the actions and assertions, I inferred the purpose of the test. For instance, a test calling `SaveAndSendStreamData` followed by checking `writer_->frame_count()` is testing frame packing. A test involving `ProcessAckPacket` and checking retransmission stats is testing retransmission handling.

5. **Address Specific User Questions:**

    * **Functionality Listing:** I compiled the grouped functionalities into a bulleted list.
    * **JavaScript Relationship:** I considered if any of the tested behaviors directly map to browser-level JavaScript APIs. While QUIC enables faster and more reliable data transfer, the *specific* logic in this test file is low-level connection management and doesn't have a direct 1:1 mapping to JavaScript functions. I explained this indirect relationship.
    * **Logical Inference (Hypothetical Input/Output):**  I selected a test case (`ConnectionStatsRetransmission_WithMixedFrames`) and created a plausible scenario with clear input (sending specific data with retransmission flags) and output (expected frame counts and retransmission stats).
    * **Common Errors:** I thought about what could go wrong in using or interacting with this type of connection logic. For example, incorrect handling of stream IDs, forgetting to flush queued packets, or misunderstanding retransmission triggers are common pitfalls.
    * **Debugging Steps:** I outlined a typical debugging flow, starting from a user action in the browser and tracing it down to the connection layer.
    * **Part 6 Summary:**  I synthesized the main themes covered in this specific snippet, emphasizing retransmission stats and frame packing, as those are heavily represented.

6. **Refine and Organize:** I organized the information logically, starting with the main functionality and then addressing the specific user questions. I used clear and concise language.

7. **Self-Correction/Double-Checking:** I reread the code and my analysis to ensure accuracy and completeness. I made sure the examples were relevant and easy to understand. For instance, I initially might have focused too much on the specific C++ syntax, but I shifted the focus to the *behavior* being tested, which is more relevant to a broader understanding.This C++ code snippet is a part of a unit test file (`quic_connection_test.cc`) for the `QuicConnection` class in Chromium's QUIC implementation. It focuses on testing various aspects of how a QUIC connection manages outgoing data, including:

**Core Functionality Demonstrated in this Snippet (Part 6 of 24):**

* **Tracking Retransmission Statistics:**  The tests verify that the connection correctly counts retransmitted packets and bytes, differentiating between full packet retransmissions and scenarios where only part of a packet needs retransmission.
* **Frame Packing:** The tests demonstrate how the `QuicConnection` efficiently packs multiple smaller data frames (like stream frames for different streams) into a single QUIC packet to minimize overhead. It also tests how crypto frames are handled in conjunction with regular stream frames.
* **Bundling Acknowledgements (ACKs):** The code confirms that the connection bundles pending ACK frames along with outgoing data frames in the same packet.
* **Handling `sendv` (Scatter-Gather I/O):** Tests verify that the connection can efficiently send data using `sendv`, combining multiple data buffers into a single outgoing stream frame.
* **Sending Zero-Byte Data:** The code tests the scenario of sending an empty data write (often used with a FIN flag to close a stream).
* **Large Sends with Pending ACKs:** It checks that the connection can handle sending large amounts of data while also including pending ACKs in the outgoing packets.
* **`OnCanWrite` Logic:**  The tests illustrate how the `OnCanWrite` callback (signaling that the socket is ready for writing) triggers the connection to send queued data.
* **Retransmission Mechanisms (NACKs):** The tests cover how the connection reacts to receiving Negative Acknowledgements (NACKs), triggering retransmissions of lost packets.
* **Interaction with Stream Resets (RST_STREAM):**  A significant portion of this snippet focuses on how the connection behaves when a stream is reset (using `RST_STREAM` frames). It tests:
    * Whether queued data for a reset stream is discarded or sent.
    * Whether packets belonging to a reset stream are retransmitted upon NACK or Retransmission Timeout (RTO).
    * How pending retransmissions are handled when a stream is reset.
* **Retransmission of Acked Packets:**  The tests cover scenarios where a packet is initially lost and retransmitted, but the original transmission is then acknowledged.
* **Retransmission of the Largest Observed Packet:** It checks the behavior of retransmitting the most recently received packet when a loss is detected.
* **Handling Write Blocking:** The tests demonstrate how the connection handles situations where the underlying socket is temporarily unable to send data (write-blocked). It verifies that data is buffered and sent later when the socket becomes writable. It also checks how alarms are affected by write blocking.
* **Send Alarm Logic:**  The tests examine how the send alarm is set and fired, particularly in relation to processing incoming packets and handling write-blocked states.

**Relationship to JavaScript Functionality:**

While this C++ code is low-level network stack implementation, it underpins the functionality of web browsers and Node.js that use QUIC. Here's how it indirectly relates to JavaScript:

* **`fetch` API and WebSockets over HTTP/3:**  When a JavaScript application uses the `fetch` API to make requests to a server over HTTP/3 (which uses QUIC), or establishes a WebSocket connection over HTTP/3, the underlying QUIC connection logic tested here is responsible for the reliable and efficient transport of data.
* **Real-time Communication:** Applications using WebRTC might leverage QUIC for its data channels. The reliability and congestion control mechanisms tested here are crucial for delivering real-time media and data.
* **Service Workers:** Service workers can intercept network requests and potentially use QUIC connections to fetch resources. The logic for managing these connections is tested in this code.

**Example of Indirect Relationship:**

Imagine a JavaScript application using `fetch` to download a large image from a server over HTTP/3.

1. **JavaScript (Input):**
   ```javascript
   fetch('https://example.com/large_image.jpg')
     .then(response => response.blob())
     .then(imageBlob => { /* ... display image ... */ });
   ```

2. **Underlying QUIC Connection (Where this code comes into play):**  The `fetch` API will trigger the browser's network stack to establish a QUIC connection (if one doesn't exist). As the server sends the image data in QUIC packets:
   * **Frame Packing:** The server might pack multiple chunks of the image data into single QUIC packets. The tests here ensure this packing is done correctly.
   * **Retransmission:** If some of the QUIC packets carrying the image data are lost due to network issues, the retransmission logic tested here (triggered by NACKs or RTOs) will ensure those lost packets are re-sent, guaranteeing reliable delivery to the JavaScript application.
   * **Flow Control/Congestion Control:** While not explicitly shown in this snippet, related parts of the `QuicConnection` manage flow control and congestion to avoid overwhelming the network.

3. **JavaScript (Output):** The `fetch` promise resolves with the complete image blob, even if there were packet losses and retransmissions happening behind the scenes thanks to the robust QUIC implementation.

**Logical Inference (Hypothetical Input and Output):**

Let's consider the `ConnectionStatsRetransmission_WithMixedFrames` test:

**Hypothetical Input:**

* The connection is in the `ENCRYPTION_FORWARD_SECURE` state.
* Two stream frames are queued for sending in the same packet:
    * Stream 1: "helloworld", offset 0, marked as a PTO retransmission (`PTO_RETRANSMISSION`).
    * Stream 2: "helloworld", offset 0, *not* marked as a retransmission (`NOT_RETRANSMISSION`).

**Hypothetical Output:**

* One QUIC packet is sent.
* The packet contains two stream frames, each with 10 bytes of data.
* The connection statistics will show:
    * `packets_retransmitted` = 1 (because the packet as a whole was a PTO retransmission, even if one frame wasn't individually marked as such).
    * `bytes_retransmitted` >= 10 (at least the data from the retransmitted frame is counted).

**User or Programming Common Usage Errors:**

* **Incorrect Stream ID Management:**  A common error in higher-level code (not directly in this low-level test) could be using the wrong stream ID when sending data, leading to data being sent to the wrong recipient or being dropped. The tests here ensure the underlying connection correctly handles data for different stream IDs.
* **Forgetting to Flush Queued Packets:** If a programmer uses the `ScopedPacketFlusher` incorrectly or forgets to trigger a send, packets might remain queued and not be sent. The tests implicitly verify that the flushing mechanism works.
* **Misunderstanding Retransmission Semantics:**  Developers might have incorrect assumptions about when and how QUIC retransmits data. These tests help ensure the implementation aligns with the expected behavior.
* **Not Handling Stream Closure Correctly:** Errors in managing stream closure (e.g., not sending or handling FIN flags properly) can lead to data loss or connection errors. The tests involving sending zero-byte data with FIN are relevant here.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User Action:** A user performs an action in a web browser that involves network communication, such as:
   * Loading a webpage over HTTPS (which might use HTTP/3).
   * Downloading a file.
   * Streaming video.
   * Interacting with a web application that uses WebSockets over HTTP/3.

2. **Browser Network Request:** The browser initiates a network request. If HTTP/3 is negotiated, a QUIC connection is established.

3. **Data Transmission:**  Data needs to be sent or received over the QUIC connection.

4. **Potential Packet Loss/Congestion:** During data transmission, network conditions might lead to packet loss or congestion.

5. **QUIC Connection Logic:** The `QuicConnection` class (and the code being tested) comes into play to handle these situations:
   * **Packet Loss Detection:** The connection detects lost packets (through mechanisms not directly in this snippet).
   * **Retransmission Trigger:**  Upon detecting loss (e.g., via a NACK), the connection decides which packets need to be retransmitted. This is where tests like `RetransmitOnNack` become relevant.
   * **Frame Packing for Retransmission:** The connection might pack the retransmitted data along with other pending data.
   * **Write Blocking:** If the network is congested, the underlying socket might become write-blocked, triggering the logic tested in `WriteBlockedThenSent`.

6. **Debugging Scenario:** A developer investigating a network issue (e.g., slow loading times, incomplete downloads, dropped WebSocket messages) might need to examine the QUIC connection's behavior. They might set breakpoints in the `QuicConnection::SaveAndSendStreamData`, `QuicConnection::OnCanWrite`, or packet processing methods to understand how data is being sent and retransmitted. The unit tests in `quic_connection_test.cc` provide insights into the expected behavior of these core components.

**Summary of Part 6:**

This specific part of the `quic_connection_test.cc` file primarily focuses on verifying the correct implementation of **retransmission statistics tracking** and **efficient frame packing** within the `QuicConnection` class. It also extensively tests the connection's behavior when dealing with **stream resets** in various scenarios (queued data, NACKs, RTOs, pending retransmissions). Furthermore, it covers how the connection handles **write blocking** and the interaction of the **send alarm** with packet processing.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_connection_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共24部分，请归纳一下它的功能

"""
PECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  }

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  EXPECT_EQ(2u, writer_->frame_count());
  for (auto& frame : writer_->stream_frames()) {
    EXPECT_EQ(frame->data_length, 10u);
  }

  ASSERT_EQ(connection_.GetStats().packets_retransmitted, 1u);
  ASSERT_GE(connection_.GetStats().bytes_retransmitted, 20u);
}

TEST_P(QuicConnectionTest, ConnectionStatsRetransmission_WithMixedFrames) {
  // Send two stream frames in 1 packet by queueing them.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    // First frame is retransmission. Second is NOT_RETRANSMISSION but the
    // packet retains the PTO_RETRANSMISSION type.
    connection_.SaveAndSendStreamData(
        GetNthClientInitiatedStreamId(1, connection_.transport_version()),
        "helloworld", 0, NO_FIN, PTO_RETRANSMISSION);
    connection_.SaveAndSendStreamData(
        GetNthClientInitiatedStreamId(2, connection_.transport_version()),
        "helloworld", 0, NO_FIN, NOT_RETRANSMISSION);
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  }

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  EXPECT_EQ(2u, writer_->frame_count());
  for (auto& frame : writer_->stream_frames()) {
    EXPECT_EQ(frame->data_length, 10u);
  }

  ASSERT_EQ(connection_.GetStats().packets_retransmitted, 1u);
  ASSERT_GE(connection_.GetStats().bytes_retransmitted, 10u);
}

TEST_P(QuicConnectionTest, ConnectionStatsRetransmission_NoRetransmission) {
  // Send two stream frames in 1 packet by queueing them.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);

  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    // Both frames are NOT_RETRANSMISSION
    connection_.SaveAndSendStreamData(
        GetNthClientInitiatedStreamId(1, connection_.transport_version()),
        "helloworld", 0, NO_FIN, NOT_RETRANSMISSION);
    connection_.SaveAndSendStreamData(
        GetNthClientInitiatedStreamId(2, connection_.transport_version()),
        "helloworld", 0, NO_FIN, NOT_RETRANSMISSION);
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  }

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  EXPECT_EQ(2u, writer_->frame_count());
  ASSERT_EQ(connection_.GetStats().packets_retransmitted, 0u);
  ASSERT_EQ(connection_.GetStats().bytes_retransmitted, 0u);
}

TEST_P(QuicConnectionTest, FramePacking) {
  // Send two stream frames in 1 packet by queueing them.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  {
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    connection_.SendStreamData3();
    connection_.SendStreamData5();
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  }
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure it's an ack and two stream frames from
  // two different streams.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_TRUE(writer_->stop_waiting_frames().empty());

  EXPECT_TRUE(writer_->ack_frames().empty());

  ASSERT_EQ(2u, writer_->stream_frames().size());
  EXPECT_EQ(GetNthClientInitiatedStreamId(1, connection_.transport_version()),
            writer_->stream_frames()[0]->stream_id);
  EXPECT_EQ(GetNthClientInitiatedStreamId(2, connection_.transport_version()),
            writer_->stream_frames()[1]->stream_id);
}

TEST_P(QuicConnectionTest, FramePackingNonCryptoThenCrypto) {
  // Send two stream frames (one non-crypto, then one crypto) in 2 packets by
  // queueing them.
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  {
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    connection_.SendStreamData3();
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_INITIAL);
    // Set the crypters for INITIAL packets in the TestPacketWriter.
    if (!connection_.version().KnowsWhichDecrypterToUse()) {
      writer_->framer()->framer()->SetAlternativeDecrypter(
          ENCRYPTION_INITIAL,
          std::make_unique<NullDecrypter>(Perspective::IS_SERVER), false);
    }
    connection_.SendCryptoStreamData();
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  }
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure it contains a crypto stream frame.
  EXPECT_LE(2u, writer_->frame_count());
  ASSERT_LE(1u, writer_->padding_frames().size());
  if (!QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    ASSERT_EQ(1u, writer_->stream_frames().size());
    EXPECT_EQ(QuicUtils::GetCryptoStreamId(connection_.transport_version()),
              writer_->stream_frames()[0]->stream_id);
  } else {
    EXPECT_LE(1u, writer_->crypto_frames().size());
  }
}

TEST_P(QuicConnectionTest, FramePackingCryptoThenNonCrypto) {
  // Send two stream frames (one crypto, then one non-crypto) in 2 packets by
  // queueing them.
  {
    connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(2);
    QuicConnection::ScopedPacketFlusher flusher(&connection_);
    connection_.SendCryptoStreamData();
    connection_.SendStreamData3();
  }
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure it's the stream frame from stream 3.
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  ASSERT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(GetNthClientInitiatedStreamId(1, connection_.transport_version()),
            writer_->stream_frames()[0]->stream_id);
}

TEST_P(QuicConnectionTest, FramePackingAckResponse) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  // Process a data packet to queue up a pending ack.
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    EXPECT_CALL(visitor_, OnCryptoFrame(_)).Times(1);
  } else {
    EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  }
  ProcessCryptoPacketAtLevel(1, ENCRYPTION_INITIAL);

  QuicPacketNumber last_packet;
  if (QuicVersionUsesCryptoFrames(connection_.transport_version())) {
    connection_.SendCryptoDataWithString("foo", 0);
  } else {
    SendStreamDataToPeer(
        QuicUtils::GetCryptoStreamId(connection_.transport_version()), "foo", 0,
        NO_FIN, &last_packet);
  }
  // Verify ack is bundled with outging packet.
  EXPECT_FALSE(writer_->ack_frames().empty());

  EXPECT_CALL(visitor_, OnCanWrite())
      .WillOnce(DoAll(IgnoreResult(InvokeWithoutArgs(
                          &connection_, &TestConnection::SendStreamData3)),
                      IgnoreResult(InvokeWithoutArgs(
                          &connection_, &TestConnection::SendStreamData5))));

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);

  // Process a data packet to cause the visitor's OnCanWrite to be invoked.
  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  peer_framer_.SetEncrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
  SetDecrypter(
      ENCRYPTION_FORWARD_SECURE,
      std::make_unique<StrictTaggingDecrypter>(ENCRYPTION_FORWARD_SECURE));
  ForceWillingAndAbleToWriteOnceForDeferSending();
  ProcessDataPacket(2);

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure it's an ack and two stream frames from
  // two different streams.
  EXPECT_EQ(3u, writer_->frame_count());
  EXPECT_TRUE(writer_->stop_waiting_frames().empty());
  EXPECT_FALSE(writer_->ack_frames().empty());
  ASSERT_EQ(2u, writer_->stream_frames().size());
  EXPECT_EQ(GetNthClientInitiatedStreamId(1, connection_.transport_version()),
            writer_->stream_frames()[0]->stream_id);
  EXPECT_EQ(GetNthClientInitiatedStreamId(2, connection_.transport_version()),
            writer_->stream_frames()[1]->stream_id);
}

TEST_P(QuicConnectionTest, FramePackingSendv) {
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));

  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      connection_.transport_version(), Perspective::IS_CLIENT);
  connection_.SaveAndSendStreamData(stream_id, "ABCDEF", 0, NO_FIN);

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure multiple iovector blocks have
  // been packed into a single stream frame from one stream.
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(0u, writer_->padding_frames().size());
  QuicStreamFrame* frame = writer_->stream_frames()[0].get();
  EXPECT_EQ(stream_id, frame->stream_id);
  EXPECT_EQ("ABCDEF",
            absl::string_view(frame->data_buffer, frame->data_length));
}

TEST_P(QuicConnectionTest, FramePackingSendvQueued) {
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));

  BlockOnNextWrite();
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      connection_.transport_version(), Perspective::IS_CLIENT);
  connection_.SaveAndSendStreamData(stream_id, "ABCDEF", 0, NO_FIN);

  EXPECT_EQ(1u, connection_.NumQueuedPackets());
  EXPECT_TRUE(connection_.HasQueuedData());

  // Unblock the writes and actually send.
  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_EQ(0u, connection_.NumQueuedPackets());

  // Parse the last packet and ensure it's one stream frame from one stream.
  EXPECT_EQ(1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(0u, writer_->padding_frames().size());
  QuicStreamFrame* frame = writer_->stream_frames()[0].get();
  EXPECT_EQ(stream_id, frame->stream_id);
  EXPECT_EQ("ABCDEF",
            absl::string_view(frame->data_buffer, frame->data_length));
}

TEST_P(QuicConnectionTest, SendingZeroBytes) {
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  // Send a zero byte write with a fin using writev.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _));
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      connection_.transport_version(), Perspective::IS_CLIENT);
  connection_.SaveAndSendStreamData(stream_id, {}, 0, FIN);

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Padding frames are added by v99 to ensure a minimum packet size.
  size_t extra_padding_frames = 0;
  if (GetParam().version.HasHeaderProtection()) {
    extra_padding_frames = 1;
  }

  // Parse the last packet and ensure it's one stream frame from one stream.
  EXPECT_EQ(1u + extra_padding_frames, writer_->frame_count());
  EXPECT_EQ(extra_padding_frames, writer_->padding_frames().size());
  ASSERT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(stream_id, writer_->stream_frames()[0]->stream_id);
  EXPECT_TRUE(writer_->stream_frames()[0]->fin);
}

TEST_P(QuicConnectionTest, LargeSendWithPendingAck) {
  connection_.SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
  EXPECT_CALL(visitor_, GetHandshakeState())
      .WillRepeatedly(Return(HANDSHAKE_CONFIRMED));
  // Set the ack alarm by processing a ping frame.
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Processs a PING frame.
  ProcessFramePacket(QuicFrame(QuicPingFrame()));
  // Ensure that this has caused the ACK alarm to be set.
  EXPECT_TRUE(connection_.HasPendingAcks());

  // Send data and ensure the ack is bundled.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(9);
  const std::string data(10000, '?');
  QuicConsumedData consumed = connection_.SaveAndSendStreamData(
      GetNthClientInitiatedStreamId(0, connection_.transport_version()), data,
      0, FIN);
  EXPECT_EQ(data.length(), consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.HasQueuedData());

  // Parse the last packet and ensure it's one stream frame with a fin.
  EXPECT_EQ(1u, writer_->frame_count());
  ASSERT_EQ(1u, writer_->stream_frames().size());
  EXPECT_EQ(GetNthClientInitiatedStreamId(0, connection_.transport_version()),
            writer_->stream_frames()[0]->stream_id);
  EXPECT_TRUE(writer_->stream_frames()[0]->fin);
  // Ensure the ack alarm was cancelled when the ack was sent.
  EXPECT_FALSE(connection_.HasPendingAcks());
}

TEST_P(QuicConnectionTest, OnCanWrite) {
  // Visitor's OnCanWrite will send data, but will have more pending writes.
  EXPECT_CALL(visitor_, OnCanWrite())
      .WillOnce(DoAll(IgnoreResult(InvokeWithoutArgs(
                          &connection_, &TestConnection::SendStreamData3)),
                      IgnoreResult(InvokeWithoutArgs(
                          &connection_, &TestConnection::SendStreamData5))));
  {
    InSequence seq;
    EXPECT_CALL(visitor_, WillingAndAbleToWrite()).WillOnce(Return(true));
    EXPECT_CALL(visitor_, WillingAndAbleToWrite())
        .WillRepeatedly(Return(false));
  }

  EXPECT_CALL(*send_algorithm_, CanSend(_))
      .WillRepeatedly(testing::Return(true));

  connection_.OnCanWrite();

  // Parse the last packet and ensure it's the two stream frames from
  // two different streams.
  EXPECT_EQ(2u, writer_->frame_count());
  EXPECT_EQ(2u, writer_->stream_frames().size());
  EXPECT_EQ(GetNthClientInitiatedStreamId(1, connection_.transport_version()),
            writer_->stream_frames()[0]->stream_id);
  EXPECT_EQ(GetNthClientInitiatedStreamId(2, connection_.transport_version()),
            writer_->stream_frames()[1]->stream_id);
}

TEST_P(QuicConnectionTest, RetransmitOnNack) {
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(3, "foo", 0, NO_FIN, &last_packet);
  SendStreamDataToPeer(3, "foos", 3, NO_FIN, &last_packet);
  SendStreamDataToPeer(3, "fooos", 7, NO_FIN, &last_packet);

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Don't lose a packet on an ack, and nothing is retransmitted.
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  QuicAckFrame ack_one = InitAckFrame(1);
  ProcessAckPacket(&ack_one);

  // Lose a packet and ensure it triggers retransmission.
  QuicAckFrame nack_two = ConstructAckFrame(3, 2);
  LostPacketVector lost_packets;
  lost_packets.push_back(
      LostPacket(QuicPacketNumber(2), kMaxOutgoingPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(lost_packets),
                      Return(LossDetectionInterface::DetectionStats())));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  EXPECT_FALSE(QuicPacketCreatorPeer::SendVersionInPacket(creator_));
  ProcessAckPacket(&nack_two);
}

TEST_P(QuicConnectionTest, DoNotSendQueuedPacketForResetStream) {
  // Block the connection to queue the packet.
  BlockOnNextWrite();

  QuicStreamId stream_id = 2;
  connection_.SendStreamDataWithString(stream_id, "foo", 0, NO_FIN);

  // Now that there is a queued packet, reset the stream.
  SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 3);

  // Unblock the connection and verify that only the RST_STREAM is sent.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  writer_->SetWritable();
  connection_.OnCanWrite();
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->rst_stream_frames().size());
}

TEST_P(QuicConnectionTest, SendQueuedPacketForQuicRstStreamNoError) {
  // Block the connection to queue the packet.
  BlockOnNextWrite();

  QuicStreamId stream_id = 2;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(stream_id, "foo", 0, NO_FIN);

  // Now that there is a queued packet, reset the stream.
  SendRstStream(stream_id, QUIC_STREAM_NO_ERROR, 3);

  // Unblock the connection and verify that the RST_STREAM is sent and the data
  // packet is sent.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1));
  writer_->SetWritable();
  connection_.OnCanWrite();
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->rst_stream_frames().size());
}

TEST_P(QuicConnectionTest, DoNotRetransmitForResetStreamOnNack) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, NO_FIN, &last_packet);
  SendStreamDataToPeer(stream_id, "foos", 3, NO_FIN, &last_packet);
  SendStreamDataToPeer(stream_id, "fooos", 7, NO_FIN, &last_packet);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 12);

  // Lose a packet and ensure it does not trigger retransmission.
  QuicAckFrame nack_two = ConstructAckFrame(last_packet, last_packet - 1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessAckPacket(&nack_two);
}

TEST_P(QuicConnectionTest, RetransmitForQuicRstStreamNoErrorOnNack) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, NO_FIN, &last_packet);
  SendStreamDataToPeer(stream_id, "foos", 3, NO_FIN, &last_packet);
  SendStreamDataToPeer(stream_id, "fooos", 7, NO_FIN, &last_packet);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  SendRstStream(stream_id, QUIC_STREAM_NO_ERROR, 12);

  // Lose a packet, ensure it triggers retransmission.
  QuicAckFrame nack_two = ConstructAckFrame(last_packet, last_packet - 1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  LostPacketVector lost_packets;
  lost_packets.push_back(LostPacket(last_packet - 1, kMaxOutgoingPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(lost_packets),
                      Return(LossDetectionInterface::DetectionStats())));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1));
  ProcessAckPacket(&nack_two);
}

TEST_P(QuicConnectionTest, DoNotRetransmitForResetStreamOnRTO) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, NO_FIN, &last_packet);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 3);

  // Fire the RTO and verify that the RST_STREAM is resent, not stream data.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  clock_.AdvanceTime(DefaultRetransmissionTime());
  connection_.GetRetransmissionAlarm()->Fire();
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->rst_stream_frames().size());
  EXPECT_EQ(stream_id, writer_->rst_stream_frames().front().stream_id);
}

// Ensure that if the only data in flight is non-retransmittable, the
// retransmission alarm is not set.
TEST_P(QuicConnectionTest, CancelRetransmissionAlarmAfterResetStream) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_data_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, NO_FIN, &last_data_packet);

  // Cancel the stream.
  const QuicPacketNumber rst_packet = last_data_packet + 1;
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, rst_packet, _, _)).Times(1);
  SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 3);

  // Ack the RST_STREAM frame (since it's retransmittable), but not the data
  // packet, which is no longer retransmittable since the stream was cancelled.
  QuicAckFrame nack_stream_data =
      ConstructAckFrame(rst_packet, last_data_packet);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessAckPacket(&nack_stream_data);

  // Ensure that the data is still in flight, but the retransmission alarm is no
  // longer set.
  EXPECT_GT(manager_->GetBytesInFlight(), 0u);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, RetransmitForQuicRstStreamNoErrorOnPTO) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, NO_FIN, &last_packet);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  SendRstStream(stream_id, QUIC_STREAM_NO_ERROR, 3);

  // Fire the RTO and verify that the RST_STREAM is resent, the stream data
  // is sent.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(1));
  clock_.AdvanceTime(DefaultRetransmissionTime());
  connection_.GetRetransmissionAlarm()->Fire();
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
}

TEST_P(QuicConnectionTest, DoNotSendPendingRetransmissionForResetStream) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, NO_FIN, &last_packet);
  SendStreamDataToPeer(stream_id, "foos", 3, NO_FIN, &last_packet);
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(stream_id, "fooos", 7, NO_FIN);

  // Lose a packet which will trigger a pending retransmission.
  QuicAckFrame ack = ConstructAckFrame(last_packet, last_packet - 1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessAckPacket(&ack);

  SendRstStream(stream_id, QUIC_ERROR_PROCESSING_STREAM, 12);

  // Unblock the connection and verify that the RST_STREAM is sent but not the
  // second data packet nor a retransmit.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  writer_->SetWritable();
  connection_.OnCanWrite();
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  ASSERT_EQ(1u, writer_->rst_stream_frames().size());
  EXPECT_EQ(stream_id, writer_->rst_stream_frames().front().stream_id);
}

TEST_P(QuicConnectionTest, SendPendingRetransmissionForQuicRstStreamNoError) {
  QuicStreamId stream_id = 2;
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(stream_id, "foo", 0, NO_FIN, &last_packet);
  SendStreamDataToPeer(stream_id, "foos", 3, NO_FIN, &last_packet);
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(stream_id, "fooos", 7, NO_FIN);

  // Lose a packet which will trigger a pending retransmission.
  QuicAckFrame ack = ConstructAckFrame(last_packet, last_packet - 1);
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  LostPacketVector lost_packets;
  lost_packets.push_back(LostPacket(last_packet - 1, kMaxOutgoingPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(lost_packets),
                      Return(LossDetectionInterface::DetectionStats())));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  ProcessAckPacket(&ack);

  SendRstStream(stream_id, QUIC_STREAM_NO_ERROR, 12);

  // Unblock the connection and verify that the RST_STREAM is sent and the
  // second data packet or a retransmit is sent.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(AtLeast(2));
  writer_->SetWritable();
  connection_.OnCanWrite();
  // The RST_STREAM_FRAME is sent after queued packets and pending
  // retransmission.
  connection_.SendControlFrame(QuicFrame(
      new QuicRstStreamFrame(1, stream_id, QUIC_STREAM_NO_ERROR, 14)));
  size_t padding_frame_count = writer_->padding_frames().size();
  EXPECT_EQ(padding_frame_count + 1u, writer_->frame_count());
  EXPECT_EQ(1u, writer_->rst_stream_frames().size());
}

TEST_P(QuicConnectionTest, RetransmitAckedPacket) {
  QuicPacketNumber last_packet;
  SendStreamDataToPeer(1, "foo", 0, NO_FIN, &last_packet);    // Packet 1
  SendStreamDataToPeer(1, "foos", 3, NO_FIN, &last_packet);   // Packet 2
  SendStreamDataToPeer(1, "fooos", 7, NO_FIN, &last_packet);  // Packet 3

  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Instigate a loss with an ack.
  QuicAckFrame nack_two = ConstructAckFrame(3, 2);
  // The first nack should trigger a fast retransmission, but we'll be
  // write blocked, so the packet will be queued.
  BlockOnNextWrite();

  LostPacketVector lost_packets;
  lost_packets.push_back(
      LostPacket(QuicPacketNumber(2), kMaxOutgoingPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(lost_packets),
                      Return(LossDetectionInterface::DetectionStats())));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(4), _, _))
      .Times(1);
  ProcessAckPacket(&nack_two);
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // Now, ack the previous transmission.
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(false, _, _, _, _, _, _));
  QuicAckFrame ack_all = InitAckFrame(3);
  ProcessAckPacket(&ack_all);

  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, QuicPacketNumber(4), _, _))
      .Times(0);

  writer_->SetWritable();
  connection_.OnCanWrite();

  EXPECT_EQ(0u, connection_.NumQueuedPackets());
  // We do not store retransmittable frames of this retransmission.
  EXPECT_FALSE(QuicConnectionPeer::HasRetransmittableFrames(&connection_, 4));
}

TEST_P(QuicConnectionTest, RetransmitNackedLargestObserved) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  QuicPacketNumber original, second;

  QuicByteCount packet_size =
      SendStreamDataToPeer(3, "foo", 0, NO_FIN, &original);  // 1st packet.
  SendStreamDataToPeer(3, "bar", 3, NO_FIN, &second);        // 2nd packet.

  QuicAckFrame frame = InitAckFrame({{second, second + 1}});
  // The first nack should retransmit the largest observed packet.
  LostPacketVector lost_packets;
  lost_packets.push_back(LostPacket(original, kMaxOutgoingPacketSize));
  EXPECT_CALL(*loss_algorithm_, DetectLosses(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(lost_packets),
                      Return(LossDetectionInterface::DetectionStats())));
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  // Packet 1 is short header for IETF QUIC because the encryption level
  // switched to ENCRYPTION_FORWARD_SECURE in SendStreamDataToPeer.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, packet_size, _));
  ProcessAckPacket(&frame);
}

TEST_P(QuicConnectionTest, WriteBlockedBufferedThenSent) {
  BlockOnNextWrite();
  writer_->set_is_write_blocked_data_buffered(true);
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(1, "foo", 0, NO_FIN);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, WriteBlockedThenSent) {
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  BlockOnNextWrite();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(1, "foo", 0, NO_FIN);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_EQ(1u, connection_.NumQueuedPackets());

  // The second packet should also be queued, in order to ensure packets are
  // never sent out of order.
  writer_->SetWritable();
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(1);
  connection_.SendStreamDataWithString(1, "foo", 0, NO_FIN);
  EXPECT_EQ(2u, connection_.NumQueuedPackets());

  // Now both are sent in order when we unblock.
  EXPECT_CALL(*send_algorithm_, OnPacketSent(_, _, _, _, _)).Times(0);
  connection_.OnCanWrite();
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_EQ(0u, connection_.NumQueuedPackets());
}

TEST_P(QuicConnectionTest, RetransmitWriteBlockedAckedOriginalThenSent) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());

  BlockOnNextWrite();
  writer_->set_is_write_blocked_data_buffered(true);
  // Simulate the retransmission alarm firing.
  clock_.AdvanceTime(DefaultRetransmissionTime());
  connection_.GetRetransmissionAlarm()->Fire();

  // Ack the sent packet before the callback returns, which happens in
  // rare circumstances with write blocked sockets.
  QuicAckFrame ack = InitAckFrame(1);
  EXPECT_CALL(*send_algorithm_, OnCongestionEvent(true, _, _, _, _, _, _));
  ProcessAckPacket(&ack);

  writer_->SetWritable();
  connection_.OnCanWrite();
  EXPECT_TRUE(connection_.GetRetransmissionAlarm()->IsSet());
  EXPECT_FALSE(QuicConnectionPeer::HasRetransmittableFrames(&connection_, 3));
}

TEST_P(QuicConnectionTest, AlarmsWhenWriteBlocked) {
  // Block the connection.
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  EXPECT_EQ(1u, writer_->packets_write_attempts());
  EXPECT_TRUE(writer_->IsWriteBlocked());

  // Set the send alarm. Fire the alarm and ensure it doesn't attempt to write.
  connection_.GetSendAlarm()->Set(clock_.ApproximateNow());
  connection_.GetSendAlarm()->Fire();
  EXPECT_TRUE(writer_->IsWriteBlocked());
  EXPECT_EQ(1u, writer_->packets_write_attempts());
}

TEST_P(QuicConnectionTest, NoSendAlarmAfterProcessPacketWhenWriteBlocked) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));

  // Block the connection.
  BlockOnNextWrite();
  connection_.SendStreamDataWithString(3, "foo", 0, NO_FIN);
  EXPECT_TRUE(writer_->IsWriteBlocked());
  EXPECT_EQ(1u, connection_.NumQueuedPackets());
  EXPECT_FALSE(connection_.GetSendAlarm()->IsSet());

  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  // Process packet number 1. Can not call ProcessPacket or ProcessDataPacket
  // here, because they will fire the alarm after QuicConnection::ProcessPacket
  // is returned.
  const uint64_t received_packet_num = 1;
  const bool has_stop_waiting = false;
  const EncryptionLevel level = ENCRYPTION_FORWARD_SECURE;
  std::unique_ptr<QuicPacket> packet(
      ConstructDataPacket(received_packet_num, has_stop_waiting, level));
  char buffer[kMaxOutgoingPacketSize];
  size_t encrypted_length =
      peer_framer_.EncryptPayload(level, QuicPacketNumber(received_packet_num),
                                  *packet, buffer, kMaxOutgoingPacketSize);
  connection_.ProcessUdpPacket(
      kSelfAddress, kPeerAddress,
      QuicReceivedPacket(buffer, encrypted_length, clock_.Now(), false));

  EXPECT_TRUE(writer_->IsWriteBlocked());
  EXPECT_FALSE(connection_.GetSendAlarm()->IsSet());
}

TEST_P(QuicConnectionTest, SendAlarmNonZeroDelay) {
  EXPECT_CALL(visitor_, OnSuccessfulVersionNegotiation(_));
  // Set a 10 ms send alarm delay. The send alarm after processing the packet
  // should fire after waiting 10ms, not immediately.
  connection_.set_defer_send_in_response_to_packets(true);
  connection_.sent_packet_manager().SetDeferredSendAlarmDelay(
      QuicTime::Delta::FromMilliseconds(10));
  EXPECT_FALSE(connection_.GetSendAlarm()->IsSet());

  EXPECT_CALL(visitor_, OnStreamFrame(_)).Times(1);
  // Process packet number 1. Can not call ProcessPacket or ProcessDataPacket
  // here, because they will fire the alarm after QuicConnection::ProcessPacket
  // is returned.
  const uint64_t received_packet_num = 1;
  const bool has_stop_waiting = false;
  const EncryptionLevel level = ENCRYPTIO
"""


```