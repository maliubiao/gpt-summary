Response:
My thinking process for analyzing the provided C++ code snippet goes like this:

1. **Identify the core functionality:** The filename `quic_packet_creator_test.cc` immediately suggests this file contains unit tests for a class related to creating QUIC packets. The code itself contains `TEST_P` macros, which are a strong indicator of parameterized tests in Google Test. The various test names like `BuildPathResponsePacket`, `SerializeConnectivityProbingPacket`, and `SerializePathChallengeProbePacket` further reinforce this idea.

2. **Break down the individual tests:**  I examine each `TEST_P` block separately to understand what it's testing. Key observations within each test include:
    * **Setting up the test environment:**  Creating a `QuicPacketCreator` instance (`creator_`), potentially setting encryption levels (`creator_.set_encryption_level`), and defining packet headers (`QuicPacketHeader`).
    * **Defining expected output:**  Creating a byte array (`unsigned char packet[]`) representing the expected binary representation of the QUIC packet. This is a crucial part of the test.
    * **Performing the action under test:** Calling a method of the `QuicPacketCreator` (e.g., `BuildPathResponsePacket`, `SerializePathChallengeConnectivityProbingPacket`).
    * **Verifying the output:**  Using `EXPECT_EQ` to compare the generated packet length with the expected length and `quiche::test::CompareCharArraysWithHexError` to perform a byte-by-byte comparison of the generated and expected packet content.
    * **Using mock objects (framer_visitor_):**  The presence of `EXPECT_CALL` on `framer_visitor_` indicates that the tests also verify the sequence of frame processing events that should occur when the generated packet is parsed. This adds another layer of verification beyond just the raw packet bytes.

3. **Look for common patterns and themes:** I notice several recurring patterns:
    * **Testing different scenarios for `BuildPathResponsePacket`:** With varying numbers of payloads and with/without padding.
    * **Testing different types of probe packets:** `PathChallenge` and `PathResponse`.
    * **Testing serialization of connectivity probing packets.**
    * **Testing serialization of connection close packets.**
    * **Testing the logic for updating packet sequence number lengths.**
    * **Testing the serialization of general frames (crypto and stream frames).**
    * **Testing the "chaos protection" mechanism.**
    * **Testing the ability to consume and add data to packets.**

4. **Infer the functionality of `QuicPacketCreator`:** Based on the tests, I can infer the core responsibilities of the `QuicPacketCreator` class:
    * **Building specific types of QUIC packets:**  Specifically, path response packets, connectivity probing packets, and connection close packets.
    * **Serializing frames into packets:**  Taking individual QUIC frames (like `PATH_RESPONSE`, `PING`, `PADDING`, `CRYPTO`, `STREAM`) and assembling them into the correct packet format.
    * **Handling packet headers:** Setting connection IDs, packet numbers, and other header flags.
    * **Managing packet padding.**
    * **Dealing with different QUIC versions:** The use of `VersionHasIetfQuicFrames` suggests version-specific logic.
    * **Interacting with a `QuicFramer`:** The interaction with `framer_visitor_` implies that the `QuicPacketCreator` produces packets that a `QuicFramer` can parse.

5. **Consider the JavaScript connection (as requested):** I think about how these low-level packet creation mechanisms relate to JavaScript. While JavaScript itself doesn't directly manipulate raw network packets in typical web development scenarios, the underlying network stack that a browser uses (including implementations of protocols like QUIC) is often written in languages like C++. Therefore, the functionality tested in this file is crucial for the browser's ability to establish and maintain QUIC connections, which in turn enables the loading of web pages and the operation of web applications written in JavaScript. I look for specific examples like the `PATH_RESPONSE` which is part of the QUIC handshake, a process essential for establishing a secure connection before any JavaScript code is executed over that connection.

6. **Address the other specific points in the prompt:**
    * **Logic and assumptions:** I analyze the tests with specific input values and their expected output. For instance, the `BuildPathResponsePacket` tests clearly show how different payloads are assembled into the packet.
    * **User/programming errors:** I consider scenarios where incorrect usage of the `QuicPacketCreator` might lead to errors. For example, trying to add too much data to a packet, or using the class in a way that violates the QUIC specification.
    * **User operations leading to this code:** I trace back from high-level user actions (like opening a web page) down to the network stack and how QUIC packet creation fits into that process.
    * **Debugging clues:** I note how the tests themselves provide debugging information (e.g., the hex dumps of expected packets).

7. **Synthesize the summary:** Based on all the above points, I formulate a concise summary of the file's functionality, focusing on the key responsibilities of the code under test. Since this is part 2 of a 6-part series, I acknowledge that the provided snippet likely focuses on a subset of the overall functionality, specifically the creation of path response and probing packets, and the serialization of frames.

By following this structured approach, I can systematically analyze the code, understand its purpose, and address the specific requirements of the prompt.
This is the **second part** of the `quic_packet_creator_test.cc` file. Building upon the functionalities described in the previous part (which we don't have access to here, but can infer general packet creation capabilities), this section focuses specifically on testing the creation and serialization of **Path Response packets** and **Connectivity Probing packets**.

Here's a breakdown of the functionalities demonstrated in this part:

**1. Building Path Response Packets:**

* **`BuildPathResponsePacket1ResponseUnpadded` and `BuildPathResponsePacket1ResponsePadded`:**  These tests verify the creation of a Path Response packet containing a single PATH_RESPONSE frame. They check both unpadded and padded versions of the packet.
* **`BuildPathResponsePacket3ResponsesUnpadded` and `BuildPathResponsePacket3ResponsesPadded`:** These tests extend the previous ones by verifying the creation of Path Response packets with multiple (three in this case) PATH_RESPONSE frames. They also test both unpadded and padded scenarios.
* **Functionality:** The `BuildPathResponsePacket` method of the `QuicPacketCreator` class is responsible for constructing QUIC packets specifically for responding to Path Challenge frames. These packets contain one or more PATH_RESPONSE frames, each carrying data received in a corresponding PATH_CHALLENGE. The tests ensure the correct formatting of the packet header, the inclusion of the PATH_RESPONSE frames, and the application of padding when requested.

**2. Serializing Connectivity Probing Packets:**

* **`SerializeConnectivityProbingPacket`:** This test checks the serialization of a general connectivity probing packet. For older QUIC versions, this involves sending a PING frame. For newer (IETF QUIC) versions, it sends a PATH_CHALLENGE frame. The test verifies the resulting serialized packet by parsing it using a `QuicFramer` and checking the expected frame type.
* **`SerializePathChallengeProbePacket`:** This test specifically focuses on serializing a connectivity probing packet containing a PATH_CHALLENGE frame (for IETF QUIC).
* **`SerializePathResponseProbePacket1PayloadPadded` to `SerializePathResponseProbePacket3PayloadsUnpadded`:** These tests cover various scenarios for serializing Path Response probe packets. They test with one, two, and three PATH_RESPONSE payloads, and for each case, they verify both padded and unpadded versions.
* **Functionality:** The `Serialize...ConnectivityProbingPacket` methods of the `QuicPacketCreator` are used to create and serialize packets specifically designed for probing network path connectivity. These packets help determine if a network path is still active and can be used for path validation. The tests ensure the correct frame type (PING or PATH_CHALLENGE/PATH_RESPONSE) is included and that the packet is serialized correctly for transmission.

**3. Serializing Large Packet Number Connection Close Packets:**

* **`SerializeLargePacketNumberConnectionClosePacket`:** This test verifies the serialization of a CONNECTION_CLOSE packet when using large packet numbers.
* **Functionality:** The `SerializeLargePacketNumberConnectionClosePacket` method is responsible for creating and serializing a packet that signals the termination of a QUIC connection. The test confirms that the CONNECTION_CLOSE frame is correctly included in the serialized packet.

**4. Updating Packet Sequence Number Length:**

* **`UpdatePacketSequenceNumberLengthLeastAwaiting` and `UpdatePacketSequenceNumberLengthCwnd`:** These tests check the logic for dynamically adjusting the length of the packet sequence number based on the least awaiting packet number and the congestion window (cwnd).
* **`SkipNPacketNumbers`:** This test verifies the ability to skip a certain number of packet numbers.
* **Functionality:**  QUIC can use variable-length packet numbers to optimize packet size. The `QuicPacketCreator` needs to dynamically adjust the length of the packet number field based on the current state of the connection (e.g., how many packets are in flight). These tests ensure that this logic works correctly.

**5. Serializing General Frames (Crypto and Stream):**

* **`SerializeFrame` and `SerializeFrameShortData`:** These tests verify the basic serialization of frames. They test both long and short data scenarios and check if the version flag is set correctly.
* **Functionality:** The `SerializeAllFrames` method (inferred from the code, not explicitly shown here) takes a list of `QuicFrame` objects and serializes them into a QUIC packet. The tests check that the header and the frame data are correctly formatted.

**6. Chaos Protection (Optional Feature):**

* **`ChaosProtectionEnabled` and `ChaosProtectionDisabled`:** These tests check an optional "chaos protection" mechanism which, when enabled, adds extra padding and potentially PING frames to the packet.
* **Functionality:** This feature seems designed to add randomness and potentially obfuscate the actual data being sent, possibly for security or testing purposes.

**7. Consuming Data and Adding Frames:**

* **`ConsumeDataLargerThanOneStreamFrame`:** This test checks how the `QuicPacketCreator` handles consuming data that is larger than what can fit in a single STREAM frame.
* **`AddFrameAndFlush`:** This test verifies the process of adding various frame types to a packet and then flushing the packet (serializing and sending it).
* **Functionality:** These tests explore how the `QuicPacketCreator` manages the process of adding data and different types of control frames to a packet, ensuring that the packet doesn't exceed the maximum size and that all the added frames are included.

**8. Serializing and Sending Stream Frames:**

* **`SerializeAndSendStreamFrame` and `SerializeStreamFrameWithPadding`:** These tests specifically focus on creating and serializing STREAM frames, including cases where padding is necessary.
* **Functionality:** The `CreateAndSerializeStreamFrame` method is used to create packets containing data for a specific QUIC stream. The tests verify the correct formatting of the STREAM frame and the application of padding.

**Relationship to JavaScript:**

This C++ code directly implements the low-level mechanisms for creating and sending QUIC packets. While JavaScript running in a web browser doesn't directly manipulate these raw packets, it relies on the underlying browser's network stack, which is often implemented in C++ (like Chromium's network stack).

Here's how it relates:

* **Establishing a QUIC Connection:** When a user navigates to a website using HTTPS (and the server supports QUIC), the browser needs to perform a QUIC handshake. The `PathResponsePacket` functionality is directly involved in this handshake process, as the client needs to respond to the server's path challenges.
    * **Example:** A user types `https://example.com` in the address bar. The browser, as part of the QUIC handshake, might receive a `PATH_CHALLENGE` from the server. The `QuicPacketCreator` (tested here) would be used to build a `PATH_RESPONSE` packet containing the data from the challenge, which is then sent back to the server.
* **Maintaining Connection Liveness:** The connectivity probing packets (`SerializeConnectivityProbingPacket`, `SerializePathChallengeProbePacket`, `SerializePathResponseProbePacket`) are used to ensure the network path between the client and server remains active.
    * **Example:** After a period of inactivity, the browser might send a probing packet to confirm the connection is still viable before attempting to send more data (perhaps initiated by JavaScript making an AJAX request).
* **Closing Connections:** The `SerializeLargePacketNumberConnectionClosePacket` functionality is used when the browser or server needs to gracefully terminate the QUIC connection.
    * **Example:** If a user closes a browser tab or navigates away from a website, the browser might initiate a connection close, and this code would be involved in creating the necessary packet.
* **Sending and Receiving Data:** While not the primary focus of this snippet, the ability to serialize general frames (including STREAM frames) is fundamental to how the browser sends and receives data for web pages and applications. JavaScript code uses APIs like `fetch()` or WebSockets, which under the hood, rely on the browser's network stack to send data as QUIC packets.

**Logic and Assumptions (with examples):**

* **Assumption:** The tests assume a specific structure and content for the expected packets. These assumptions are based on the QUIC specification and the implementation details of the `QuicPacketCreator`.
* **Input (for `BuildPathResponsePacket1ResponseUnpadded`):**
    * `header`: A `QuicPacketHeader` object containing basic packet information (destination connection ID, packet number, etc.).
    * `payloads`: A `quiche::QuicheCircularDeque` containing a single `QuicPathFrameBuffer` with 8 bytes of data (0x01 to 0x08).
    * `is_padded`: `false` (no padding).
    * `encryption_level`: `ENCRYPTION_INITIAL`.
* **Output:** A QUIC packet (represented by the `packet` array) with the following structure:
    * Short Header (0x43)
    * Destination Connection ID (0xFEDCBA9876543210)
    * Packet Number (0x12345678)
    * PATH_RESPONSE frame (type 0x1b) with the 8-byte payload.

**User or Programming Common Usage Errors:**

* **Incorrect Payload Size for Path Response:** If the payload provided to `BuildPathResponsePacket` is not exactly 8 bytes, the resulting packet will be invalid according to the QUIC specification.
* **Attempting to Add Too Many Frames:**  If a programmer tries to add frames to a packet that would exceed the maximum packet size, the `QuicPacketCreator` might not be able to add the frame, potentially leading to unexpected behavior or errors. The `AddFrameAndFlush` test demonstrates how the creator handles a full packet.
* **Incorrect Encryption Level:** Using the wrong encryption level when building or serializing packets can lead to decryption failures on the receiving end. For example, trying to send application data before the handshake is complete and the encryption level is high enough.
* **Mismatched Versions:** If the client and server are using incompatible QUIC versions, certain frame types or packet formats might not be understood, leading to connection errors. The tests with `VersionHasIetfQuicFrames` highlight the importance of version-specific logic.

**User Operations Leading to This Code (Debugging Clues):**

Imagine a user is experiencing issues connecting to a website using QUIC. Here's how debugging might lead to this code:

1. **User reports "website not loading" or "slow connection".**
2. **Network engineers or developers investigate the network traffic.** They might use tools like Wireshark to capture and analyze the QUIC packets being exchanged.
3. **They observe issues with the QUIC handshake.** Perhaps the client is sending `PATH_RESPONSE` packets that the server is not acknowledging.
4. **To understand why the `PATH_RESPONSE` packets are not being processed correctly, developers might need to examine the code responsible for creating these packets.** This leads them to `net/third_party/quiche/src/quiche/quic/core/quic_packet_creator.cc` and specifically the tests in `quic_packet_creator_test.cc` that verify the `BuildPathResponsePacket` functionality.
5. **The tests provide concrete examples of how these packets are supposed to be formed, allowing developers to compare the actual packets being sent with the expected format.**  The hex dumps in the tests are invaluable for this.
6. **By stepping through the code in `QuicPacketCreator::BuildPathResponsePacket` and comparing it to the test cases, developers can identify potential bugs or incorrect assumptions in the packet creation logic.**

**Summary of Part 2's Functionality:**

This second part of `quic_packet_creator_test.cc` focuses on testing the `QuicPacketCreator`'s ability to:

* **Construct and serialize Path Response packets**, which are crucial for the QUIC handshake and path validation.
* **Create and serialize various types of connectivity probing packets**, used to check the liveness of the network path.
* **Serialize connection close packets.**
* **Dynamically adjust packet sequence number length.**
* **Serialize general QUIC frames (crypto and stream).**
* **Optionally add "chaos protection" to packets.**
* **Manage the process of adding data and frames to packets.**

These functionalities are essential for establishing, maintaining, and closing QUIC connections, and they directly underpin the network communication for web browsers and applications that utilize the QUIC protocol.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_packet_creator_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
quiche::QuicheCircularDeque<QuicPathFrameBuffer> payloads;
  payloads.push_back(payload0);
  size_t length = creator_.BuildPathResponsePacket(
      header, buffer.get(), ABSL_ARRAYSIZE(packet), payloads,
      /*is_padded=*/true, ENCRYPTION_INITIAL);
  EXPECT_EQ(length, ABSL_ARRAYSIZE(packet));
  QuicPacket data(creator_.transport_version(), buffer.release(), length, true,
                  header);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data.data(), data.length(),
      reinterpret_cast<char*>(packet), ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicPacketCreatorTest, BuildPathResponsePacket3ResponsesUnpadded) {
  if (!VersionHasIetfQuicFrames(creator_.transport_version())) {
    // This frame is only for IETF QUIC.
    return;
  }

  QuicPacketHeader header;
  header.destination_connection_id = CreateTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;
  QuicPathFrameBuffer payload0 = {
      {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}};
  QuicPathFrameBuffer payload1 = {
      {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}};
  QuicPathFrameBuffer payload2 = {
      {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}};

  // Build one packet with 3 PATH RESPONSES, no padding
  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // 3 path response frames (IETF_PATH_RESPONSE type byte and payload)
    0x1b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x1b, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x1b, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
  };
  // clang-format on

  std::unique_ptr<char[]> buffer(new char[kMaxOutgoingPacketSize]);
  quiche::QuicheCircularDeque<QuicPathFrameBuffer> payloads;
  payloads.push_back(payload0);
  payloads.push_back(payload1);
  payloads.push_back(payload2);
  size_t length = creator_.BuildPathResponsePacket(
      header, buffer.get(), ABSL_ARRAYSIZE(packet), payloads,
      /*is_padded=*/false, ENCRYPTION_INITIAL);
  EXPECT_EQ(length, ABSL_ARRAYSIZE(packet));
  QuicPacket data(creator_.transport_version(), buffer.release(), length, true,
                  header);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data.data(), data.length(),
      reinterpret_cast<char*>(packet), ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicPacketCreatorTest, BuildPathResponsePacket3ResponsesPadded) {
  if (!VersionHasIetfQuicFrames(creator_.transport_version())) {
    // This frame is only for IETF QUIC.
    return;
  }

  QuicPacketHeader header;
  header.destination_connection_id = CreateTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;
  QuicPathFrameBuffer payload0 = {
      {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}};
  QuicPathFrameBuffer payload1 = {
      {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}};
  QuicPathFrameBuffer payload2 = {
      {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}};

  // Build one packet with 3 PATH RESPONSES, with padding
  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // 3 path response frames (IETF_PATH_RESPONSE byte and payload)
    0x1b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x1b, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x1b, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    // Padding
    0x00, 0x00, 0x00, 0x00, 0x00
  };
  // clang-format on

  std::unique_ptr<char[]> buffer(new char[kMaxOutgoingPacketSize]);
  quiche::QuicheCircularDeque<QuicPathFrameBuffer> payloads;
  payloads.push_back(payload0);
  payloads.push_back(payload1);
  payloads.push_back(payload2);
  size_t length = creator_.BuildPathResponsePacket(
      header, buffer.get(), ABSL_ARRAYSIZE(packet), payloads,
      /*is_padded=*/true, ENCRYPTION_INITIAL);
  EXPECT_EQ(length, ABSL_ARRAYSIZE(packet));
  QuicPacket data(creator_.transport_version(), buffer.release(), length, true,
                  header);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data.data(), data.length(),
      reinterpret_cast<char*>(packet), ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicPacketCreatorTest, SerializeConnectivityProbingPacket) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  std::unique_ptr<SerializedPacket> encrypted;
  if (VersionHasIetfQuicFrames(creator_.transport_version())) {
    QuicPathFrameBuffer payload = {
        {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xfe}};
    encrypted =
        creator_.SerializePathChallengeConnectivityProbingPacket(payload);
  } else {
    encrypted = creator_.SerializeConnectivityProbingPacket();
  }
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    if (VersionHasIetfQuicFrames(creator_.transport_version())) {
      EXPECT_CALL(framer_visitor_, OnPathChallengeFrame(_));
      EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    } else {
      EXPECT_CALL(framer_visitor_, OnPingFrame(_));
      EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    }
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  // QuicFramerPeer::SetPerspective(&client_framer_, Perspective::IS_SERVER);
  server_framer_.ProcessPacket(QuicEncryptedPacket(
      encrypted->encrypted_buffer, encrypted->encrypted_length));
}

TEST_P(QuicPacketCreatorTest, SerializePathChallengeProbePacket) {
  if (!VersionHasIetfQuicFrames(creator_.transport_version())) {
    return;
  }
  QuicPathFrameBuffer payload = {
      {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee}};

  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  std::unique_ptr<SerializedPacket> encrypted(
      creator_.SerializePathChallengeConnectivityProbingPacket(payload));
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    EXPECT_CALL(framer_visitor_, OnPathChallengeFrame(_));
    EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  // QuicFramerPeer::SetPerspective(&client_framer_, Perspective::IS_SERVER);
  server_framer_.ProcessPacket(QuicEncryptedPacket(
      encrypted->encrypted_buffer, encrypted->encrypted_length));
}

TEST_P(QuicPacketCreatorTest, SerializePathResponseProbePacket1PayloadPadded) {
  if (!VersionHasIetfQuicFrames(creator_.transport_version())) {
    return;
  }
  QuicPathFrameBuffer payload0 = {
      {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee}};

  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  quiche::QuicheCircularDeque<QuicPathFrameBuffer> payloads;
  payloads.push_back(payload0);

  std::unique_ptr<SerializedPacket> encrypted(
      creator_.SerializePathResponseConnectivityProbingPacket(payloads, true));
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    EXPECT_CALL(framer_visitor_, OnPathResponseFrame(_));
    EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  server_framer_.ProcessPacket(QuicEncryptedPacket(
      encrypted->encrypted_buffer, encrypted->encrypted_length));
}

TEST_P(QuicPacketCreatorTest,
       SerializePathResponseProbePacket1PayloadUnPadded) {
  if (!VersionHasIetfQuicFrames(creator_.transport_version())) {
    return;
  }
  QuicPathFrameBuffer payload0 = {
      {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee}};

  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  quiche::QuicheCircularDeque<QuicPathFrameBuffer> payloads;
  payloads.push_back(payload0);

  std::unique_ptr<SerializedPacket> encrypted(
      creator_.SerializePathResponseConnectivityProbingPacket(payloads, false));
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    EXPECT_CALL(framer_visitor_, OnPathResponseFrame(_));
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  server_framer_.ProcessPacket(QuicEncryptedPacket(
      encrypted->encrypted_buffer, encrypted->encrypted_length));
}

TEST_P(QuicPacketCreatorTest, SerializePathResponseProbePacket2PayloadsPadded) {
  if (!VersionHasIetfQuicFrames(creator_.transport_version())) {
    return;
  }
  QuicPathFrameBuffer payload0 = {
      {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee}};
  QuicPathFrameBuffer payload1 = {
      {0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee, 0xde}};

  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  quiche::QuicheCircularDeque<QuicPathFrameBuffer> payloads;
  payloads.push_back(payload0);
  payloads.push_back(payload1);

  std::unique_ptr<SerializedPacket> encrypted(
      creator_.SerializePathResponseConnectivityProbingPacket(payloads, true));
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    EXPECT_CALL(framer_visitor_, OnPathResponseFrame(_)).Times(2);
    EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  server_framer_.ProcessPacket(QuicEncryptedPacket(
      encrypted->encrypted_buffer, encrypted->encrypted_length));
}

TEST_P(QuicPacketCreatorTest,
       SerializePathResponseProbePacket2PayloadsUnPadded) {
  if (!VersionHasIetfQuicFrames(creator_.transport_version())) {
    return;
  }
  QuicPathFrameBuffer payload0 = {
      {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee}};
  QuicPathFrameBuffer payload1 = {
      {0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee, 0xde}};

  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  quiche::QuicheCircularDeque<QuicPathFrameBuffer> payloads;
  payloads.push_back(payload0);
  payloads.push_back(payload1);

  std::unique_ptr<SerializedPacket> encrypted(
      creator_.SerializePathResponseConnectivityProbingPacket(payloads, false));
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    EXPECT_CALL(framer_visitor_, OnPathResponseFrame(_)).Times(2);
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  server_framer_.ProcessPacket(QuicEncryptedPacket(
      encrypted->encrypted_buffer, encrypted->encrypted_length));
}

TEST_P(QuicPacketCreatorTest, SerializePathResponseProbePacket3PayloadsPadded) {
  if (!VersionHasIetfQuicFrames(creator_.transport_version())) {
    return;
  }
  QuicPathFrameBuffer payload0 = {
      {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee}};
  QuicPathFrameBuffer payload1 = {
      {0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee, 0xde}};
  QuicPathFrameBuffer payload2 = {
      {0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee, 0xde, 0xad}};

  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  quiche::QuicheCircularDeque<QuicPathFrameBuffer> payloads;
  payloads.push_back(payload0);
  payloads.push_back(payload1);
  payloads.push_back(payload2);

  std::unique_ptr<SerializedPacket> encrypted(
      creator_.SerializePathResponseConnectivityProbingPacket(payloads, true));
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    EXPECT_CALL(framer_visitor_, OnPathResponseFrame(_)).Times(3);
    EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  server_framer_.ProcessPacket(QuicEncryptedPacket(
      encrypted->encrypted_buffer, encrypted->encrypted_length));
}

TEST_P(QuicPacketCreatorTest,
       SerializePathResponseProbePacket3PayloadsUnpadded) {
  if (!VersionHasIetfQuicFrames(creator_.transport_version())) {
    return;
  }
  QuicPathFrameBuffer payload0 = {
      {0xde, 0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee}};
  QuicPathFrameBuffer payload1 = {
      {0xad, 0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee, 0xde}};
  QuicPathFrameBuffer payload2 = {
      {0xbe, 0xef, 0xba, 0xdc, 0x0f, 0xee, 0xde, 0xad}};

  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);

  quiche::QuicheCircularDeque<QuicPathFrameBuffer> payloads;
  payloads.push_back(payload0);
  payloads.push_back(payload1);
  payloads.push_back(payload2);

  std::unique_ptr<SerializedPacket> encrypted(
      creator_.SerializePathResponseConnectivityProbingPacket(payloads, false));
  InSequence s;
  EXPECT_CALL(framer_visitor_, OnPacket());
  EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
  EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
  EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
  EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
  EXPECT_CALL(framer_visitor_, OnPathResponseFrame(_)).Times(3);
  EXPECT_CALL(framer_visitor_, OnPacketComplete());

  server_framer_.ProcessPacket(QuicEncryptedPacket(
      encrypted->encrypted_buffer, encrypted->encrypted_length));
}

TEST_P(QuicPacketCreatorTest, SerializeLargePacketNumberConnectionClosePacket) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  std::unique_ptr<SerializedPacket> encrypted(
      creator_.SerializeLargePacketNumberConnectionClosePacket(
          QuicPacketNumber(1), QUIC_CLIENT_LOST_NETWORK_ACCESS,
          "QuicPacketCreatorTest"));

  InSequence s;
  EXPECT_CALL(framer_visitor_, OnPacket());
  EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
  EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
  EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
  EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
  EXPECT_CALL(framer_visitor_, OnConnectionCloseFrame(_));
  EXPECT_CALL(framer_visitor_, OnPacketComplete());

  server_framer_.ProcessPacket(QuicEncryptedPacket(
      encrypted->encrypted_buffer, encrypted->encrypted_length));
}

TEST_P(QuicPacketCreatorTest, UpdatePacketSequenceNumberLengthLeastAwaiting) {
  if (!GetParam().version.SendsVariableLengthPacketNumberInLongHeader()) {
    EXPECT_EQ(PACKET_4BYTE_PACKET_NUMBER,
              QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
    creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  } else {
    EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
              QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
  }

  QuicPacketCreatorPeer::SetPacketNumber(&creator_, 64);
  creator_.UpdatePacketNumberLength(QuicPacketNumber(2),
                                    10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  QuicPacketCreatorPeer::SetPacketNumber(&creator_, 64 * 256);
  creator_.UpdatePacketNumberLength(QuicPacketNumber(2),
                                    10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_2BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  QuicPacketCreatorPeer::SetPacketNumber(&creator_, 64 * 256 * 256);
  creator_.UpdatePacketNumberLength(QuicPacketNumber(2),
                                    10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_4BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  QuicPacketCreatorPeer::SetPacketNumber(&creator_,
                                         UINT64_C(64) * 256 * 256 * 256 * 256);
  creator_.UpdatePacketNumberLength(QuicPacketNumber(2),
                                    10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_6BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
}

TEST_P(QuicPacketCreatorTest, UpdatePacketSequenceNumberLengthCwnd) {
  QuicPacketCreatorPeer::SetPacketNumber(&creator_, 1);
  if (!GetParam().version.SendsVariableLengthPacketNumberInLongHeader()) {
    EXPECT_EQ(PACKET_4BYTE_PACKET_NUMBER,
              QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
    creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  } else {
    EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
              QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
  }

  creator_.UpdatePacketNumberLength(QuicPacketNumber(1),
                                    10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  creator_.UpdatePacketNumberLength(QuicPacketNumber(1),
                                    10000 * 256 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_2BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  creator_.UpdatePacketNumberLength(QuicPacketNumber(1),
                                    10000 * 256 * 256 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_4BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  creator_.UpdatePacketNumberLength(
      QuicPacketNumber(1),
      UINT64_C(1000) * 256 * 256 * 256 * 256 / kDefaultMaxPacketSize);
  EXPECT_EQ(PACKET_6BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
}

TEST_P(QuicPacketCreatorTest, SkipNPacketNumbers) {
  QuicPacketCreatorPeer::SetPacketNumber(&creator_, 1);
  if (!GetParam().version.SendsVariableLengthPacketNumberInLongHeader()) {
    EXPECT_EQ(PACKET_4BYTE_PACKET_NUMBER,
              QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
    creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  } else {
    EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
              QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
  }
  creator_.SkipNPacketNumbers(63, QuicPacketNumber(2),
                              10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(QuicPacketNumber(64), creator_.packet_number());
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  creator_.SkipNPacketNumbers(64 * 255, QuicPacketNumber(2),
                              10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(QuicPacketNumber(64 * 256), creator_.packet_number());
  EXPECT_EQ(PACKET_2BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));

  creator_.SkipNPacketNumbers(64 * 256 * 255, QuicPacketNumber(2),
                              10000 / kDefaultMaxPacketSize);
  EXPECT_EQ(QuicPacketNumber(64 * 256 * 256), creator_.packet_number());
  EXPECT_EQ(PACKET_4BYTE_PACKET_NUMBER,
            QuicPacketCreatorPeer::GetPacketNumberLength(&creator_));
}

TEST_P(QuicPacketCreatorTest, SerializeFrame) {
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  std::string data("test data");
  if (!QuicVersionUsesCryptoFrames(client_framer_.transport_version())) {
    QuicStreamFrame stream_frame(
        QuicUtils::GetCryptoStreamId(client_framer_.transport_version()),
        /*fin=*/false, 0u, absl::string_view());
    frames_.push_back(QuicFrame(stream_frame));
  } else {
    producer_.SaveCryptoData(ENCRYPTION_INITIAL, 0, data);
    frames_.push_back(
        QuicFrame(new QuicCryptoFrame(ENCRYPTION_INITIAL, 0, data.length())));
  }
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
    if (QuicVersionUsesCryptoFrames(client_framer_.transport_version())) {
      EXPECT_CALL(framer_visitor_, OnCryptoFrame(_));
    } else {
      EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
    }
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  ProcessPacket(serialized);
  EXPECT_EQ(GetParam().version_serialization, header.version_flag);
}

TEST_P(QuicPacketCreatorTest, SerializeFrameShortData) {
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  std::string data("Hello World!");
  if (!QuicVersionUsesCryptoFrames(client_framer_.transport_version())) {
    QuicStreamFrame stream_frame(
        QuicUtils::GetCryptoStreamId(client_framer_.transport_version()),
        /*fin=*/false, 0u, absl::string_view());
    frames_.push_back(QuicFrame(stream_frame));
  } else {
    producer_.SaveCryptoData(ENCRYPTION_INITIAL, 0, data);
    frames_.push_back(
        QuicFrame(new QuicCryptoFrame(ENCRYPTION_INITIAL, 0, data.length())));
  }
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
    if (QuicVersionUsesCryptoFrames(client_framer_.transport_version())) {
      EXPECT_CALL(framer_visitor_, OnCryptoFrame(_));
    } else {
      EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
    }
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  ProcessPacket(serialized);
  EXPECT_EQ(GetParam().version_serialization, header.version_flag);
}

void QuicPacketCreatorTest::TestChaosProtection(bool enabled) {
  if (!GetParam().version.UsesCryptoFrames()) {
    return;
  }
  MockRandom mock_random(2);
  QuicPacketCreatorPeer::SetRandom(&creator_, &mock_random);
  std::string data("ChAoS_ThEoRy!");
  producer_.SaveCryptoData(ENCRYPTION_INITIAL, 0, data);
  frames_.push_back(
      QuicFrame(new QuicCryptoFrame(ENCRYPTION_INITIAL, 0, data.length())));
  frames_.push_back(QuicFrame(QuicPaddingFrame(33)));
  SerializedPacket serialized = SerializeAllFrames(frames_);
  EXPECT_CALL(framer_visitor_, OnPacket());
  EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
  EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
  EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
  EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
  if (enabled) {
    EXPECT_CALL(framer_visitor_, OnCryptoFrame(_)).Times(AtLeast(2));
    EXPECT_CALL(framer_visitor_, OnPaddingFrame(_)).Times(AtLeast(2));
    EXPECT_CALL(framer_visitor_, OnPingFrame(_)).Times(AtLeast(1));
  } else {
    EXPECT_CALL(framer_visitor_, OnCryptoFrame(_)).Times(1);
    EXPECT_CALL(framer_visitor_, OnPaddingFrame(_)).Times(1);
    EXPECT_CALL(framer_visitor_, OnPingFrame(_)).Times(0);
  }
  EXPECT_CALL(framer_visitor_, OnPacketComplete());
  ProcessPacket(serialized);
}

TEST_P(QuicPacketCreatorTest, ChaosProtectionEnabled) {
  TestChaosProtection(true);
}

TEST_P(QuicPacketCreatorTest, ChaosProtectionDisabled) {
  SetQuicFlag(quic_enable_chaos_protection, false);
  TestChaosProtection(false);
}

TEST_P(QuicPacketCreatorTest, ConsumeDataLargerThanOneStreamFrame) {
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  // A string larger than fits into a frame.
  QuicFrame frame;
  size_t payload_length = creator_.max_packet_length();
  const std::string too_long_payload(payload_length, 'a');
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, too_long_payload, 0u, true, false, NOT_RETRANSMISSION,
      &frame));
  size_t consumed = frame.stream_frame.data_length;
  // The entire payload could not be consumed.
  EXPECT_GT(payload_length, consumed);
  creator_.FlushCurrentPacket();
  DeleteSerializedPacket();
}

TEST_P(QuicPacketCreatorTest, AddFrameAndFlush) {
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  const size_t max_plaintext_size =
      client_framer_.GetMaxPlaintextSize(creator_.max_packet_length());
  EXPECT_FALSE(creator_.HasPendingFrames());
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  QuicStreamId stream_id = QuicUtils::GetFirstBidirectionalStreamId(
      client_framer_.transport_version(), Perspective::IS_CLIENT);
  if (!QuicVersionUsesCryptoFrames(client_framer_.transport_version())) {
    stream_id =
        QuicUtils::GetCryptoStreamId(client_framer_.transport_version());
  }
  EXPECT_FALSE(creator_.HasPendingStreamFramesOfStream(stream_id));
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

  // Add a variety of frame types and then a padding frame.
  QuicAckFrame ack_frame(InitAckFrame(10u));
  EXPECT_CALL(debug, OnFrameAddedToPacket(_));
  EXPECT_TRUE(creator_.AddFrame(QuicFrame(&ack_frame), NOT_RETRANSMISSION));
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingStreamFramesOfStream(stream_id));

  QuicFrame frame;
  const std::string data("test");
  EXPECT_CALL(debug, OnFrameAddedToPacket(_));
  ASSERT_TRUE(creator_.ConsumeDataToFillCurrentPacket(
      stream_id, data, 0u, false, false, NOT_RETRANSMISSION, &frame));
  size_t consumed = frame.stream_frame.data_length;
  EXPECT_EQ(4u, consumed);
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_TRUE(creator_.HasPendingStreamFramesOfStream(stream_id));

  QuicPaddingFrame padding_frame;
  EXPECT_CALL(debug, OnFrameAddedToPacket(_));
  EXPECT_TRUE(creator_.AddFrame(QuicFrame(padding_frame), NOT_RETRANSMISSION));
  EXPECT_TRUE(creator_.HasPendingFrames());
  EXPECT_EQ(0u, creator_.BytesFree());

  // Packet is full. Creator will flush.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  EXPECT_FALSE(creator_.AddFrame(QuicFrame(&ack_frame), NOT_RETRANSMISSION));

  // Ensure the packet is successfully created.
  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_FALSE(serialized_packet_->retransmittable_frames.empty());
  const QuicFrames& retransmittable =
      serialized_packet_->retransmittable_frames;
  ASSERT_EQ(1u, retransmittable.size());
  EXPECT_EQ(STREAM_FRAME, retransmittable[0].type);
  EXPECT_TRUE(serialized_packet_->has_ack);
  EXPECT_EQ(QuicPacketNumber(10u), serialized_packet_->largest_acked);
  DeleteSerializedPacket();

  EXPECT_FALSE(creator_.HasPendingFrames());
  EXPECT_FALSE(creator_.HasPendingStreamFramesOfStream(stream_id));
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
}

TEST_P(QuicPacketCreatorTest, SerializeAndSendStreamFrame) {
  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  EXPECT_FALSE(creator_.HasPendingFrames());

  const std::string data("test");
  producer_.SaveStreamData(GetNthClientInitiatedStreamId(0), data);
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  size_t num_bytes_consumed;
  StrictMock<MockDebugDelegate> debug;
  creator_.set_debug_delegate(&debug);
  EXPECT_CALL(debug, OnFrameAddedToPacket(_));
  creator_.CreateAndSerializeStreamFrame(
      GetNthClientInitiatedStreamId(0), data.length(), 0, 0, true,
      NOT_RETRANSMISSION, &num_bytes_consumed);
  EXPECT_EQ(4u, num_bytes_consumed);

  // Ensure the packet is successfully created.
  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_FALSE(serialized_packet_->retransmittable_frames.empty());
  const QuicFrames& retransmittable =
      serialized_packet_->retransmittable_frames;
  ASSERT_EQ(1u, retransmittable.size());
  EXPECT_EQ(STREAM_FRAME, retransmittable[0].type);
  DeleteSerializedPacket();

  EXPECT_FALSE(creator_.HasPendingFrames());
}

TEST_P(QuicPacketCreatorTest, SerializeStreamFrameWithPadding) {
  // Regression test to check that CreateAndSerializeStreamFrame uses a
  // correctly formatted stream frame header when appending padding.

  creator_.set_encryption_level(ENCRYPTION_FORWARD_SECURE);
  if (!GetParam().version_serialization) {
    creator_.StopSendingVersion();
  }
  EXPECT_FALSE(creator_.HasPendingFrames());

  // Send zero bytes of stream data. This requires padding.
  EXPECT_CALL(delegate_, OnSerializedPacket(_))
      .WillOnce(Invoke(this, &QuicPacketCreatorTest::SaveSerializedPacket));
  size_t num_bytes_consumed;
  creator_.CreateAndSerializeStreamFrame(GetNthClientInitiatedStreamId(0), 0, 0,
                                         0, true, NOT_RETRANSMISSION,
                                         &num_bytes_consumed);
  EXPECT_EQ(0u, num_bytes_consumed);

  // Check that a packet is created.
  ASSERT_TRUE(serialized_packet_->encrypted_buffer);
  ASSERT_FALSE(serialized_packet_->retransmittable_frames.empty());
  ASSERT_EQ(serialized_packet_->packet_number_length,
            PACKET_1BYTE_PACKET_NUMBER);
  {
    InSequence s;
    EXPECT_CALL(framer_visitor_, OnPacket());
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedPublicHeader(_));
    EXPECT_CALL(framer_visitor_, OnUnauthenticatedHeader(_));
    EXPECT_CALL(framer_visitor_, OnDecryptedPacket(_, _));
    EXPECT_CALL(framer_visitor_, OnPacketHeader(_));
    if (client_framer_.version().HasHeaderProtection()) {
      EXPECT_CALL(framer_visitor_, OnPaddingFrame(_));
      EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
    } else {
      EXPECT_CALL(framer_visitor_, OnStreamFrame(_));
    }
    EXPECT_CALL(framer_visitor_, OnPacketComplete());
  }
  ProcessPacket(*serialized_packet_);
}

TEST_P(QuicPacketCreatorTest, AddUnencryptedStreamDataClosesConnection) {
  // EXPECT_QUIC_BUG tests are expensive so only run one instance of them.
  if (!IsDefaultTestConfiguration()) {
    return;
  }

  creator_.set_encryption_level(ENCRYPTION_INITIAL);
  QuicStreamFrame stream_frame(GetNthClientInitiatedStreamId(0),
                               /*fin=*/false, 0u, absl::string_view());
  EXPECT_QUIC_BUG(
      {
        EXPECT_CALL(delegate_, OnUnrecoverableError(_, _));
```