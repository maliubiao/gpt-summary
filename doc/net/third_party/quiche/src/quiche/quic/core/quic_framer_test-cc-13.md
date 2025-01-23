Response:
The user wants to understand the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc`.

I need to:
1. **Summarize the file's purpose:**  Based on the filename and content, it's a test file for the `QuicFramer` class.
2. **Identify connections to JavaScript:**  QUIC is a transport protocol, and its core functionality is implemented in C++. JavaScript interacts with it at a higher level, usually via browser APIs. I need to explain this indirect relationship.
3. **Provide examples of logical reasoning:** The test cases themselves are examples of logical reasoning with specific inputs and expected outputs. I will pick a couple of representative test cases.
4. **Illustrate common usage errors:**  As a testing file, it doesn't directly expose user-facing errors. The errors it tests are related to malformed packets or protocol violations. I need to frame these as potential issues a developer implementing QUIC might encounter.
5. **Explain how a user might reach this code (debugging context):**  Users won't directly interact with this C++ test file. The path involves network communication, browser interactions, and potentially low-level debugging.
6. **Summarize the functionality based on its position in the sequence (part 14 of 16):**  Given that it's a test file and near the end of the sequence, it likely covers a wide range of functionalities of the `QuicFramer`, possibly including more complex or edge cases.

**Plan:**

* Start by stating the primary function: testing the `QuicFramer`.
* Explain the indirect relationship with JavaScript through browser APIs for network requests.
* Select two test cases to demonstrate logical reasoning with input and output.
* Describe common developer errors related to incorrect packet formatting or protocol violations, using examples from the test cases.
* Outline the steps involved for a user action to trigger this code during network communication and debugging.
* Based on the content of the provided snippet, which heavily features packet processing and error handling, summarize the file's role in verifying the correctness of the `QuicFramer`.
This source code file, `net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc`, is a **unit test file** for the `QuicFramer` class in the Chromium QUIC implementation. Its primary function is to **thoroughly test the functionality of the `QuicFramer`**, which is responsible for:

* **Parsing incoming QUIC packets:**  Taking raw byte sequences and interpreting them into structured data like headers, frames, and packet numbers.
* **Serializing outgoing QUIC packets:**  Taking structured data and converting it into the raw byte format for transmission.
* **Handling different QUIC versions:** Ensuring compatibility and correct parsing/serialization across various versions of the QUIC protocol.
* **Managing encryption and decryption:**  Working with crypters to secure and process packet payloads.
* **Detecting and handling errors:** Identifying malformed packets or protocol violations.
* **Supporting various QUIC features:**  Testing functionalities like coalesced packets, packet number spaces, and version negotiation.

**Relationship with JavaScript Functionality:**

While this C++ code doesn't directly execute JavaScript, it is **fundamentally related to how network requests made by JavaScript in a browser are handled when using the QUIC protocol.**

* **JavaScript initiates network requests:** When a web page (JavaScript) makes an HTTP/3 request (which uses QUIC), the browser's networking stack comes into play.
* **The `QuicFramer` processes the underlying QUIC packets:**  The C++ QUIC implementation, including the `QuicFramer`, is responsible for the low-level details of sending and receiving QUIC packets that carry the HTTP/3 data.
* **Indirect Interaction:**  JavaScript doesn't directly call functions in `quic_framer_test.cc`. Instead, the browser's QUIC implementation uses the `QuicFramer` (whose correctness is ensured by this test file) to handle the QUIC protocol details behind the scenes when fulfilling JavaScript's network requests.

**Example:**

Imagine a JavaScript `fetch()` call that retrieves data from a server using HTTP/3.

1. **JavaScript:** `fetch('https://example.com/data')`
2. **Browser Networking (C++):** The browser's networking code determines that HTTP/3 will be used.
3. **QUIC Implementation (C++):** The browser's QUIC implementation uses the `QuicFramer` to:
    * **Serialize outgoing packets:**  When sending the request to the server, the `QuicFramer` takes the request data and formats it into QUIC packets.
    * **Parse incoming packets:** When the server responds, the `QuicFramer` parses the received QUIC packets to extract the response data.
4. **JavaScript:** The `fetch()` promise resolves with the received data.

**Logical Reasoning Examples (with assumed inputs and outputs from the provided snippet):**

**Test Case: `TEST_P(QuicFramerTest, ProcessSingleStreamPacket)`**

* **Assumed Input:** A raw byte array representing a valid QUIC packet containing a single stream frame with the "HELLO_WORLD?" message and the FIN flag set.
* **Processing:** The `framer_.ProcessPacket()` function is called with this byte array. The `QuicFramer` parses the packet header and the stream frame.
* **Expected Output:** The `visitor_` (a mock object used for testing) should record:
    * A valid header.
    * One `stream_frame_` with:
        * `stream_id`:  Equal to `kStreamId` (masked to the correct length).
        * `fin`: True.
        * `offset`: Equal to `kStreamOffset`.
        * Data: "HELLO_WORLD?".

**Test Case: `TEST_P(QuicFramerTest, MismatchedCoalescedPacket)`**

* **Assumed Input:** A raw byte array containing two coalesced QUIC packets. The key mismatch is that the *destination connection IDs* of the two packets are different.
* **Processing:** `framer_.ProcessPacket()` is called. The `QuicFramer` attempts to parse the coalesced packets.
* **Expected Output:** The `QuicFramer` will successfully process the *first* coalesced packet. The `visitor_` will record the details of this first packet's header and stream frame. Crucially, `visitor_.coalesced_packets_.size()` will be `0u` after processing, indicating that the mismatched second packet was not processed as a separate coalesced packet. The error status of the framer should be `IsQuicNoError()`.

**User or Programming Common Usage Errors (and how this test helps):**

This test file helps prevent common programming errors in the `QuicFramer` implementation itself. However, it also indirectly helps prevent issues for developers using the QUIC API:

* **Incorrect packet formatting:**  If the `QuicFramer` has bugs in serialization, developers might inadvertently create malformed packets that are rejected by peers. Test cases like the ones with specific byte arrays ensure the serialization logic is correct.
    * **Example:**  If the length field for a stream frame is calculated incorrectly during serialization, a receiving `QuicFramer` might fail to parse it. Tests with various frame structures help catch these errors.
* **Protocol violations:**  The QUIC specification has strict rules. Bugs in the `QuicFramer` could lead to generating or misinterpreting packets that violate these rules.
    * **Example:** Sending data on a stream before it's opened, or sending a packet with an invalid packet number. The tests for different packet types and frame combinations ensure adherence to the protocol.
* **Version incompatibility:**  QUIC has different versions, and the `QuicFramer` needs to handle them correctly. Tests like `ClientReceivesWrongVersion` ensure proper handling of version negotiation and rejection of incompatible packets.

**User Operation Steps to Reach This Code (Debugging Context):**

A typical user wouldn't directly interact with this C++ test code. However, if a developer is debugging a network issue involving QUIC in Chromium, they might step through this code as part of their investigation:

1. **User Action:** A user visits a website or uses a web application that communicates over HTTP/3 (QUIC).
2. **Network Issue:**  The user experiences a network problem, such as slow loading, connection errors, or data corruption.
3. **Developer Intervention:** A developer investigates the issue using browser debugging tools (like Chrome DevTools).
4. **Network Log Analysis:** The developer might examine the network logs, which show the QUIC connection and packets being exchanged.
5. **Source Code Debugging:** If the issue seems to be within the QUIC implementation, a Chromium developer might:
    * **Set breakpoints:** Place breakpoints in the `QuicFramer::ProcessPacket()` function or other relevant parts of the QUIC code.
    * **Step through the code:**  Reproduce the user's action and step through the C++ code, including the `QuicFramer`, to see how packets are being processed.
    * **Examine variables:** Inspect the values of packet headers, frame data, and internal state within the `QuicFramer` to identify the source of the problem.
    * **Potentially look at the tests:** If a bug is found, the developer might look at the corresponding test cases in `quic_framer_test.cc` to understand how the functionality is supposed to work or to create a new test case that reproduces the bug.

**Summary of Functionality (Part 14 of 16):**

As part 14 of 16, this section of `quic_framer_test.cc` continues to **verify the robustness and correctness of the `QuicFramer` in handling various scenarios related to packet processing, especially focusing on more complex cases:**

* **Coalesced Packets:** It tests the ability of the `QuicFramer` to correctly process multiple QUIC packets bundled together. It covers scenarios with both matching and mismatched connection IDs, as well as invalid coalesced packets.
* **Handling of Zeroes/Padding:** It checks how the framer deals with packets that have trailing zeroes, which can occur in certain QUIC implementations.
* **Version Negotiation:** It includes tests related to how the `QuicFramer` handles packets with incorrect or negotiation versions.
* **Variable Length Connection IDs:**  It tests support for connection IDs of varying lengths, a feature in some QUIC versions.
* **Multiple Packet Number Spaces:**  It verifies the functionality for managing different packet number sequences for different phases of the QUIC handshake.
* **Rejection of Retry Packets (in specific versions):** It tests that the `QuicFramer` correctly rejects retry packets in QUIC versions where they are not supported or when multiple packet number spaces are enabled.
* **Client Version Negotiation Probe Packets:**  It includes tests for generating and parsing special packets used during version negotiation.
* **Dispatcher Functionality:** It tests the `ParsePublicHeaderDispatcher` function, which is responsible for initially parsing the packet header to determine its type and version.

In summary, this section of the test file delves into more intricate aspects of QUIC packet processing, ensuring the `QuicFramer` can handle a wide range of valid and potentially invalid packet structures and scenarios.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第14部分，共16部分，请归纳一下它的功能
```

### 源代码
```cpp
cket is parsed correctly.
  ASSERT_EQ(visitor_.coalesced_packets_.size(), 1u);
  EXPECT_TRUE(framer_.ProcessPacket(*visitor_.coalesced_packets_[0].get()));

  ASSERT_TRUE(visitor_.header_.get());

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());

  // Stream ID should be the last 3 bytes of kStreamId.
  EXPECT_EQ(0x00FFFFFF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("HELLO_WORLD?", visitor_.stream_frames_[0].get());
}

TEST_P(QuicFramerTest, MismatchedCoalescedPacket) {
  if (!QuicVersionHasLongHeaderLengths(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  // clang-format off
  unsigned char packet[] = {
    // first coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (stream frame with fin)
      0xFE,
      // stream id
      0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data length
      0x00, 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // second coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x79,
      // frame type (stream frame with fin)
      0xFE,
      // stream id
      0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data length
      0x00, 0x0c,
      // data
      'H',  'E',  'L',  'L',
      'O',  '_',  'W',  'O',
      'R',  'L',  'D',  '?',
  };
  unsigned char packet_ietf[] = {
    // first coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
      0x32, 0x10, 0x76, 0x54,
      // data length
      kVarInt62OneByte + 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // second coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x11,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x79,
      // frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
      0x32, 0x10, 0x76, 0x54,
      // data length
      kVarInt62OneByte + 0x0c,
      // data
      'H',  'E',  'L',  'L',
      'O',  '_',  'W',  'O',
      'R',  'L',  'D',  '?',
  };
  // clang-format on
  const size_t length_of_first_coalesced_packet = 46;
  // If the first packet changes, the attempt to fix the first byte of the
  // second packet will fail.
  EXPECT_EQ(packet_ietf[length_of_first_coalesced_packet], 0xD3);

  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasIetfQuicFrames()) {
    ReviseFirstByteByVersion(packet_ietf);
    ReviseFirstByteByVersion(&packet_ietf[length_of_first_coalesced_packet]);
    p = packet_ietf;
    p_length = ABSL_ARRAYSIZE(packet_ietf);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_length, false);

  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());

  // Stream ID should be the last 3 bytes of kStreamId.
  EXPECT_EQ(0x00FFFFFF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  ASSERT_EQ(visitor_.coalesced_packets_.size(), 0u);
}

TEST_P(QuicFramerTest, InvalidCoalescedPacket) {
  if (!QuicVersionHasLongHeaderLengths(framer_.transport_version())) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_ZERO_RTT);
  // clang-format off
  unsigned char packet[] = {
    // first coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (stream frame with fin)
      0xFE,
      // stream id
      0x02, 0x03, 0x04,
      // offset
      0x3A, 0x98, 0xFE, 0xDC, 0x32, 0x10, 0x76, 0x54,
      // data length
      0x00, 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // second coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version would be here but we cut off the invalid coalesced header.
  };
  unsigned char packet_ietf[] = {
    // first coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version
      QUIC_VERSION_BYTES,
      // destination connection ID length
      0x08,
      // destination connection ID
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
      // source connection ID length
      0x00,
      // long header packet length
      0x1E,
      // packet number
      0x12, 0x34, 0x56, 0x78,
      // frame type (IETF_STREAM frame with FIN, LEN, and OFFSET bits set)
      0x08 | 0x01 | 0x02 | 0x04,
      // stream id
      kVarInt62FourBytes + 0x00, 0x02, 0x03, 0x04,
      // offset
      kVarInt62EightBytes + 0x3A, 0x98, 0xFE, 0xDC,
      0x32, 0x10, 0x76, 0x54,
      // data length
      kVarInt62OneByte + 0x0c,
      // data
      'h',  'e',  'l',  'l',
      'o',  ' ',  'w',  'o',
      'r',  'l',  'd',  '!',
    // second coalesced packet
      // public flags (long header with packet type ZERO_RTT_PROTECTED and
      // 4-byte packet number)
      0xD3,
      // version would be here but we cut off the invalid coalesced header.
  };
  // clang-format on
  const size_t length_of_first_coalesced_packet = 46;
  // If the first packet changes, the attempt to fix the first byte of the
  // second packet will fail.
  EXPECT_EQ(packet_ietf[length_of_first_coalesced_packet], 0xD3);

  unsigned char* p = packet;
  size_t p_length = ABSL_ARRAYSIZE(packet);
  if (framer_.version().HasIetfQuicFrames()) {
    ReviseFirstByteByVersion(packet_ietf);
    ReviseFirstByteByVersion(&packet_ietf[length_of_first_coalesced_packet]);
    p = packet_ietf;
    p_length = ABSL_ARRAYSIZE(packet_ietf);
  }

  QuicEncryptedPacket encrypted(AsChars(p), p_length, false);

  EXPECT_TRUE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());

  ASSERT_EQ(1u, visitor_.stream_frames_.size());
  EXPECT_EQ(0u, visitor_.ack_frames_.size());

  // Stream ID should be the last 3 bytes of kStreamId.
  EXPECT_EQ(0x00FFFFFF & kStreamId, visitor_.stream_frames_[0]->stream_id);
  EXPECT_TRUE(visitor_.stream_frames_[0]->fin);
  EXPECT_EQ(kStreamOffset, visitor_.stream_frames_[0]->offset);
  CheckStreamFrameData("hello world!", visitor_.stream_frames_[0].get());

  ASSERT_EQ(visitor_.coalesced_packets_.size(), 0u);
}

// Some IETF implementations send an initial followed by zeroes instead of
// padding inside the initial. We need to make sure that we still process
// the initial correctly and ignore the zeroes.
TEST_P(QuicFramerTest, CoalescedPacketWithZeroesRoundTrip) {
  if (!QuicVersionHasLongHeaderLengths(framer_.transport_version()) ||
      !framer_.version().UsesInitialObfuscators()) {
    return;
  }
  ASSERT_TRUE(framer_.version().KnowsWhichDecrypterToUse());
  QuicConnectionId connection_id = FramerTestConnectionId();
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);

  CrypterPair client_crypters;
  CryptoUtils::CreateInitialObfuscators(Perspective::IS_CLIENT,
                                        framer_.version(), connection_id,
                                        &client_crypters);
  framer_.SetEncrypter(ENCRYPTION_INITIAL,
                       std::move(client_crypters.encrypter));

  QuicPacketHeader header;
  header.destination_connection_id = connection_id;
  header.version_flag = true;
  header.packet_number = kPacketNumber;
  header.packet_number_length = PACKET_4BYTE_PACKET_NUMBER;
  header.long_packet_type = INITIAL;
  header.length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_2;
  header.retry_token_length_length = quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1;
  QuicFrames frames = {QuicFrame(QuicPingFrame()),
                       QuicFrame(QuicPaddingFrame(3))};

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_NE(nullptr, data);

  // Add zeroes after the valid initial packet.
  unsigned char packet[kMaxOutgoingPacketSize] = {};
  size_t encrypted_length =
      framer_.EncryptPayload(ENCRYPTION_INITIAL, header.packet_number, *data,
                             AsChars(packet), ABSL_ARRAYSIZE(packet));
  ASSERT_NE(0u, encrypted_length);

  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_SERVER);
  CrypterPair server_crypters;
  CryptoUtils::CreateInitialObfuscators(Perspective::IS_SERVER,
                                        framer_.version(), connection_id,
                                        &server_crypters);
  framer_.InstallDecrypter(ENCRYPTION_INITIAL,
                           std::move(server_crypters.decrypter));

  // Make sure the first long header initial packet parses correctly.
  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);

  // Make sure we discard the subsequent zeroes.
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  EXPECT_TRUE(visitor_.coalesced_packets_.empty());
}

TEST_P(QuicFramerTest, ClientReceivesWrongVersion) {
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);

  // clang-format off
  unsigned char packet[] = {
       // public flags (long header with packet type INITIAL)
       0xC3,
       // version that is different from the framer's version
       'Q', '0', '4', '3',
       // connection ID lengths
       0x05,
       // source connection ID
       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
       // packet number
       0x01,
       // padding frame
       0x00,
  };
  // clang-format on

  QuicEncryptedPacket encrypted(AsChars(packet), ABSL_ARRAYSIZE(packet), false);
  EXPECT_FALSE(framer_.ProcessPacket(encrypted));

  EXPECT_THAT(framer_.error(), IsError(QUIC_PACKET_WRONG_VERSION));
  EXPECT_EQ("Client received unexpected version.", framer_.detailed_error());
}

TEST_P(QuicFramerTest, PacketHeaderWithVariableLengthConnectionId) {
  if (!framer_.version().AllowsVariableLengthConnectionIds()) {
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  uint8_t connection_id_bytes[9] = {0xFE, 0xDC, 0xBA, 0x98, 0x76,
                                    0x54, 0x32, 0x10, 0x42};
  QuicConnectionId connection_id(reinterpret_cast<char*>(connection_id_bytes),
                                 sizeof(connection_id_bytes));
  QuicFramerPeer::SetLargestPacketNumber(&framer_, kPacketNumber - 2);
  QuicFramerPeer::SetExpectedServerConnectionIDLength(&framer_,
                                                      connection_id.length());

  // clang-format off
  PacketFragments packet = {
      // type (8 byte connection_id and 1 byte packet number)
      {"Unable to read first byte.",
       {0x40}},
      // connection_id
      {"Unable to read destination connection ID.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x42}},
      // packet number
      {"Unable to read packet number.",
       {0x78}},
  };

  PacketFragments packet_with_padding = {
      // type (8 byte connection_id and 1 byte packet number)
      {"Unable to read first byte.",
       {0x40}},
      // connection_id
      {"Unable to read destination connection ID.",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x42}},
      // packet number
      {"",
       {0x78}},
      // padding
      {"", {0x00, 0x00, 0x00}},
  };
  // clang-format on

  PacketFragments& fragments =
      framer_.version().HasHeaderProtection() ? packet_with_padding : packet;
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(fragments));
  if (framer_.version().HasHeaderProtection()) {
    EXPECT_TRUE(framer_.ProcessPacket(*encrypted));
    EXPECT_THAT(framer_.error(), IsQuicNoError());
  } else {
    EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
    EXPECT_THAT(framer_.error(), IsError(QUIC_MISSING_PAYLOAD));
  }
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_EQ(connection_id, visitor_.header_->destination_connection_id);
  EXPECT_FALSE(visitor_.header_->reset_flag);
  EXPECT_FALSE(visitor_.header_->version_flag);
  EXPECT_EQ(PACKET_1BYTE_PACKET_NUMBER, visitor_.header_->packet_number_length);
  EXPECT_EQ(kPacketNumber, visitor_.header_->packet_number);

  CheckFramingBoundaries(fragments, QUIC_INVALID_PACKET_HEADER);
}

TEST_P(QuicFramerTest, MultiplePacketNumberSpaces) {
  framer_.EnableMultiplePacketNumberSpacesSupport();

  // clang-format off
  unsigned char long_header_packet[] = {
       // public flags (long header with packet type ZERO_RTT_PROTECTED and
       // 4-byte packet number)
       0xD3,
       // version
       QUIC_VERSION_BYTES,
       // destination connection ID length
       0x50,
       // destination connection ID
       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
       // packet number
       0x12, 0x34, 0x56, 0x78,
       // padding frame
       0x00,
   };
  unsigned char long_header_packet_ietf[] = {
       // public flags (long header with packet type ZERO_RTT_PROTECTED and
       // 4-byte packet number)
       0xD3,
       // version
       QUIC_VERSION_BYTES,
       // destination connection ID length
       0x08,
       // destination connection ID
       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
       // source connection ID length
       0x00,
       // long header packet length
       0x05,
       // packet number
       0x12, 0x34, 0x56, 0x78,
       // padding frame
       0x00,
  };
  // clang-format on

  if (framer_.version().KnowsWhichDecrypterToUse()) {
    framer_.InstallDecrypter(ENCRYPTION_ZERO_RTT,
                             std::make_unique<TestDecrypter>());
    framer_.RemoveDecrypter(ENCRYPTION_INITIAL);
  } else {
    framer_.SetDecrypter(ENCRYPTION_ZERO_RTT,
                         std::make_unique<TestDecrypter>());
  }
  if (!QuicVersionHasLongHeaderLengths(framer_.transport_version())) {
    EXPECT_TRUE(framer_.ProcessPacket(
        QuicEncryptedPacket(AsChars(long_header_packet),
                            ABSL_ARRAYSIZE(long_header_packet), false)));
  } else {
    ReviseFirstByteByVersion(long_header_packet_ietf);
    EXPECT_TRUE(framer_.ProcessPacket(
        QuicEncryptedPacket(AsChars(long_header_packet_ietf),
                            ABSL_ARRAYSIZE(long_header_packet_ietf), false)));
  }

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  EXPECT_FALSE(
      QuicFramerPeer::GetLargestDecryptedPacketNumber(&framer_, INITIAL_DATA)
          .IsInitialized());
  EXPECT_FALSE(
      QuicFramerPeer::GetLargestDecryptedPacketNumber(&framer_, HANDSHAKE_DATA)
          .IsInitialized());
  EXPECT_EQ(kPacketNumber, QuicFramerPeer::GetLargestDecryptedPacketNumber(
                               &framer_, APPLICATION_DATA));

  // clang-format off
  unsigned char short_header_packet[] = {
     // type (short header, 1 byte packet number)
     0x40,
     // connection_id
     0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
     // packet number
     0x79,
     // padding frame
     0x00, 0x00, 0x00,
  };
  // clang-format on

  QuicEncryptedPacket short_header_encrypted(
      AsChars(short_header_packet), ABSL_ARRAYSIZE(short_header_packet), false);
  if (framer_.version().KnowsWhichDecrypterToUse()) {
    framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE,
                             std::make_unique<TestDecrypter>());
    framer_.RemoveDecrypter(ENCRYPTION_ZERO_RTT);
  } else {
    framer_.SetDecrypter(ENCRYPTION_FORWARD_SECURE,
                         std::make_unique<TestDecrypter>());
  }
  EXPECT_TRUE(framer_.ProcessPacket(short_header_encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  EXPECT_FALSE(
      QuicFramerPeer::GetLargestDecryptedPacketNumber(&framer_, INITIAL_DATA)
          .IsInitialized());
  EXPECT_FALSE(
      QuicFramerPeer::GetLargestDecryptedPacketNumber(&framer_, HANDSHAKE_DATA)
          .IsInitialized());
  EXPECT_EQ(kPacketNumber + 1, QuicFramerPeer::GetLargestDecryptedPacketNumber(
                                   &framer_, APPLICATION_DATA));
}

TEST_P(QuicFramerTest, IetfRetryPacketRejected) {
  if (!framer_.version().KnowsWhichDecrypterToUse() ||
      framer_.version().SupportsRetry()) {
    return;
  }

  // clang-format off
  PacketFragments packet = {
    // public flags (IETF Retry packet, 0-length original destination CID)
    {"Unable to read first byte.",
     {0xf0}},
    // version tag
    {"Unable to read protocol version.",
     {QUIC_VERSION_BYTES}},
    // connection_id length
    {"RETRY not supported in this version.",
     {0x00}},
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));

  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_PACKET_HEADER));
  CheckFramingBoundaries(packet, QUIC_INVALID_PACKET_HEADER);
}

TEST_P(QuicFramerTest, RetryPacketRejectedWithMultiplePacketNumberSpaces) {
  if (framer_.version().SupportsRetry()) {
    return;
  }
  framer_.EnableMultiplePacketNumberSpacesSupport();

  // clang-format off
  PacketFragments packet = {
    // public flags (IETF Retry packet, 0-length original destination CID)
    {"Unable to read first byte.",
     {0xf0}},
    // version tag
    {"Unable to read protocol version.",
     {QUIC_VERSION_BYTES}},
    // connection_id length
    {"RETRY not supported in this version.",
     {0x00}},
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));

  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));
  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_PACKET_HEADER));
  CheckFramingBoundaries(packet, QUIC_INVALID_PACKET_HEADER);
}

TEST_P(QuicFramerTest, WriteClientVersionNegotiationProbePacket) {
  // clang-format off
  static const uint8_t expected_packet[1200] = {
    // IETF long header with fixed bit set, type initial, all-0 encrypted bits.
    0xc0,
    // Version, part of the IETF space reserved for negotiation.
    0xca, 0xba, 0xda, 0xda,
    // Destination connection ID length 8.
    0x08,
    // 8-byte destination connection ID.
    0x56, 0x4e, 0x20, 0x70, 0x6c, 0x7a, 0x20, 0x21,
    // Source connection ID length 0.
    0x00,
    // 8 bytes of zeroes followed by 8 bytes of ones to ensure that this does
    // not parse with any known version.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // zeroes to pad to 16 byte boundary.
    0x00,
    // A polite greeting in case a human sees this in tcpdump.
    0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x61, 0x63,
    0x6b, 0x65, 0x74, 0x20, 0x6f, 0x6e, 0x6c, 0x79,
    0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x73, 0x20,
    0x74, 0x6f, 0x20, 0x74, 0x72, 0x69, 0x67, 0x67,
    0x65, 0x72, 0x20, 0x49, 0x45, 0x54, 0x46, 0x20,
    0x51, 0x55, 0x49, 0x43, 0x20, 0x76, 0x65, 0x72,
    0x73, 0x69, 0x6f, 0x6e, 0x20, 0x6e, 0x65, 0x67,
    0x6f, 0x74, 0x69, 0x61, 0x74, 0x69, 0x6f, 0x6e,
    0x2e, 0x20, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65,
    0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64,
    0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x61, 0x20,
    0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20,
    0x4e, 0x65, 0x67, 0x6f, 0x74, 0x69, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x20, 0x70, 0x61, 0x63, 0x6b,
    0x65, 0x74, 0x20, 0x69, 0x6e, 0x64, 0x69, 0x63,
    0x61, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x77, 0x68,
    0x61, 0x74, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69,
    0x6f, 0x6e, 0x73, 0x20, 0x79, 0x6f, 0x75, 0x20,
    0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x2e,
    0x20, 0x54, 0x68, 0x61, 0x6e, 0x6b, 0x20, 0x79,
    0x6f, 0x75, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x68,
    0x61, 0x76, 0x65, 0x20, 0x61, 0x20, 0x6e, 0x69,
    0x63, 0x65, 0x20, 0x64, 0x61, 0x79, 0x2e, 0x00,
  };
  // clang-format on
  char packet[1200];
  char destination_connection_id_bytes[] = {0x56, 0x4e, 0x20, 0x70,
                                            0x6c, 0x7a, 0x20, 0x21};
  EXPECT_TRUE(QuicFramer::WriteClientVersionNegotiationProbePacket(
      packet, sizeof(packet), destination_connection_id_bytes,
      sizeof(destination_connection_id_bytes)));
  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", packet, sizeof(packet),
      reinterpret_cast<const char*>(expected_packet), sizeof(expected_packet));
  QuicEncryptedPacket encrypted(reinterpret_cast<const char*>(packet),
                                sizeof(packet), false);
  if (!framer_.version().HasLengthPrefixedConnectionIds()) {
    // We can only parse the connection ID with a parser expecting
    // length-prefixed connection IDs.
    EXPECT_FALSE(framer_.ProcessPacket(encrypted));
    return;
  }
  EXPECT_TRUE(framer_.ProcessPacket(encrypted));
  ASSERT_TRUE(visitor_.header_.get());
  QuicConnectionId probe_payload_connection_id(
      reinterpret_cast<const char*>(destination_connection_id_bytes),
      sizeof(destination_connection_id_bytes));
  EXPECT_EQ(probe_payload_connection_id,
            visitor_.header_.get()->destination_connection_id);
}

TEST_P(QuicFramerTest, DispatcherParseOldClientVersionNegotiationProbePacket) {
  // clang-format off
  static const uint8_t packet[1200] = {
    // IETF long header with fixed bit set, type initial, all-0 encrypted bits.
    0xc0,
    // Version, part of the IETF space reserved for negotiation.
    0xca, 0xba, 0xda, 0xba,
    // Destination connection ID length 8, source connection ID length 0.
    0x50,
    // 8-byte destination connection ID.
    0x56, 0x4e, 0x20, 0x70, 0x6c, 0x7a, 0x20, 0x21,
    // 8 bytes of zeroes followed by 8 bytes of ones to ensure that this does
    // not parse with any known version.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // 2 bytes of zeroes to pad to 16 byte boundary.
    0x00, 0x00,
    // A polite greeting in case a human sees this in tcpdump.
    0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x61, 0x63,
    0x6b, 0x65, 0x74, 0x20, 0x6f, 0x6e, 0x6c, 0x79,
    0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x73, 0x20,
    0x74, 0x6f, 0x20, 0x74, 0x72, 0x69, 0x67, 0x67,
    0x65, 0x72, 0x20, 0x49, 0x45, 0x54, 0x46, 0x20,
    0x51, 0x55, 0x49, 0x43, 0x20, 0x76, 0x65, 0x72,
    0x73, 0x69, 0x6f, 0x6e, 0x20, 0x6e, 0x65, 0x67,
    0x6f, 0x74, 0x69, 0x61, 0x74, 0x69, 0x6f, 0x6e,
    0x2e, 0x20, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65,
    0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64,
    0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x61, 0x20,
    0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20,
    0x4e, 0x65, 0x67, 0x6f, 0x74, 0x69, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x20, 0x70, 0x61, 0x63, 0x6b,
    0x65, 0x74, 0x20, 0x69, 0x6e, 0x64, 0x69, 0x63,
    0x61, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x77, 0x68,
    0x61, 0x74, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69,
    0x6f, 0x6e, 0x73, 0x20, 0x79, 0x6f, 0x75, 0x20,
    0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x2e,
    0x20, 0x54, 0x68, 0x61, 0x6e, 0x6b, 0x20, 0x79,
    0x6f, 0x75, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x68,
    0x61, 0x76, 0x65, 0x20, 0x61, 0x20, 0x6e, 0x69,
    0x63, 0x65, 0x20, 0x64, 0x61, 0x79, 0x2e, 0x00,
  };
  // clang-format on
  char expected_destination_connection_id_bytes[] = {0x56, 0x4e, 0x20, 0x70,
                                                     0x6c, 0x7a, 0x20, 0x21};
  QuicConnectionId expected_destination_connection_id(
      reinterpret_cast<const char*>(expected_destination_connection_id_bytes),
      sizeof(expected_destination_connection_id_bytes));

  QuicEncryptedPacket encrypted(reinterpret_cast<const char*>(packet),
                                sizeof(packet));
  PacketHeaderFormat format = GOOGLE_QUIC_PACKET;
  QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
  bool version_present = false, has_length_prefix = true;
  QuicVersionLabel version_label = 33;
  ParsedQuicVersion parsed_version = UnsupportedQuicVersion();
  QuicConnectionId destination_connection_id = TestConnectionId(1);
  QuicConnectionId source_connection_id = TestConnectionId(2);
  std::optional<absl::string_view> retry_token;
  std::string detailed_error = "foobar";
  QuicErrorCode header_parse_result = QuicFramer::ParsePublicHeaderDispatcher(
      encrypted, kQuicDefaultConnectionIdLength, &format, &long_packet_type,
      &version_present, &has_length_prefix, &version_label, &parsed_version,
      &destination_connection_id, &source_connection_id, &retry_token,
      &detailed_error);
  EXPECT_THAT(header_parse_result, IsQuicNoError());
  EXPECT_EQ(IETF_QUIC_LONG_HEADER_PACKET, format);
  EXPECT_TRUE(version_present);
  EXPECT_FALSE(has_length_prefix);
  EXPECT_EQ(0xcabadaba, version_label);
  EXPECT_EQ(expected_destination_connection_id, destination_connection_id);
  EXPECT_EQ(EmptyQuicConnectionId(), source_connection_id);
  EXPECT_FALSE(retry_token.has_value());
  EXPECT_EQ("", detailed_error);
}

TEST_P(QuicFramerTest, DispatcherParseClientVersionNegotiationProbePacket) {
  // clang-format off
  static const uint8_t packet[1200] = {
    // IETF long header with fixed bit set, type initial, all-0 encrypted bits.
    0xc0,
    // Version, part of the IETF space reserved for negotiation.
    0xca, 0xba, 0xda, 0xba,
    // Destination connection ID length 8.
    0x08,
    // 8-byte destination connection ID.
    0x56, 0x4e, 0x20, 0x70, 0x6c, 0x7a, 0x20, 0x21,
    // Source connection ID length 0.
    0x00,
    // 8 bytes of zeroes followed by 8 bytes of ones to ensure that this does
    // not parse with any known version.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // 1 byte of zeroes to pad to 16 byte boundary.
    0x00,
    // A polite greeting in case a human sees this in tcpdump.
    0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x61, 0x63,
    0x6b, 0x65, 0x74, 0x20, 0x6f, 0x6e, 0x6c, 0x79,
    0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x73, 0x20,
    0x74, 0x6f, 0x20, 0x74, 0x72, 0x69, 0x67, 0x67,
    0x65, 0x72, 0x20, 0x49, 0x45, 0x54, 0x46, 0x20,
    0x51, 0x55, 0x49, 0x43, 0x20, 0x76, 0x65, 0x72,
    0x73, 0x69, 0x6f, 0x6e, 0x20, 0x6e, 0x65, 0x67,
    0x6f, 0x74, 0x69, 0x61, 0x74, 0x69, 0x6f, 0x6e,
    0x2e, 0x20, 0x50, 0x6c, 0x65, 0x61, 0x73, 0x65,
    0x20, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64,
    0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x61, 0x20,
    0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x20,
    0x4e, 0x65, 0x67, 0x6f, 0x74, 0x69, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x20, 0x70, 0x61, 0x63, 0x6b,
    0x65, 0x74, 0x20, 0x69, 0x6e, 0x64, 0x69, 0x63,
    0x61, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x77, 0x68,
    0x61, 0x74, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69,
    0x6f, 0x6e, 0x73, 0x20, 0x79, 0x6f, 0x75, 0x20,
    0x73, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x2e,
    0x20, 0x54, 0x68, 0x61, 0x6e, 0x6b, 0x20, 0x79,
    0x6f, 0x75, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x68,
    0x61, 0x76, 0x65, 0x20, 0x61, 0x20, 0x6e, 0x69,
    0x63, 0x65, 0x20, 0x64, 0x61, 0x79, 0x2e, 0x00,
  };
  // clang-format on
  char expected_destination_connection_id_bytes[] = {0x56, 0x4e, 0x20, 0x70,
                                                     0x6c, 0x7a, 0x20, 0x21};
  QuicConnectionId expected_destination_connection_id(
      reinterpret_cast<const char*>(expected_destination_connection_id_bytes),
      sizeof(expected_destination_connection_id_bytes));

  QuicEncryptedPacket encrypted(reinterpret_cast<const char*>(packet),
                                sizeof(packet));
  PacketHeaderFormat format = GOOGLE_QUIC_PACKET;
  QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
  bool version_present = false, has_length_prefix = false;
  QuicVersionLabel version_label = 33;
  ParsedQuicVersion parsed_version = UnsupportedQuicVersion();
  QuicConnectionId destination_connection_id = TestConnectionId(1);
  QuicConnectionId source_connection_id = TestConnectionId(2);
  std::optional<absl::string_view> retry_token;
  std::string detailed_error = "foobar";
  QuicErrorCode header_parse_result = QuicFramer::ParsePublicHeaderDispatcher(
      encrypted, kQuicDefaultConnectionIdLength, &format, &long_packet_type,
      &version_present, &has_length_prefix, &version_label, &parsed_version,
      &destination_connection_id, &source_connection_id, &retry_token,
      &detailed_error);
  EXPECT_THAT(header_parse_result, IsQuicNoError());
  EXPECT_EQ(IETF_QUIC_LONG_HEADER_PACKET, format);
  EXPECT_TRUE(version_present);
  EXPECT_TRUE(has_length_prefix);
  EXPECT_EQ(0xcabadaba, version_label);
  EXPECT_EQ(expected_destination_connection_id, destination_connection_id);
  EXPECT_EQ(EmptyQuicConnectionId(), source_connection_id);
  EXPECT_EQ("", detailed_error);
}

TEST_P(QuicFramerTest, DispatcherParseClientInitialPacketNumber) {
  // clang-format off
  PacketFragments packet = {
      // Type (Long header, INITIAL, 2B packet number)
      {"Unable to read first byte.",
       {0xC1}},
      // Version
      {"Unable to read protocol version.",
       {QUIC_VERSION_BYTES}},
      // Length-prefixed Destination connection_id
      {"Unable to read destination connection ID.",
       {0x08, 0x56, 0x4e, 0x20, 0x70, 0x6c, 0x7a, 0x20, 0x21}},
      // Length-prefixed Source connection_id
      {"Unable to read source connection ID.",
       {0x00}},
      // Retry token
      {"",
       {0x00}},
      // Length
      {"",
       {kVarInt62TwoBytes + 0x03, 0x04}},
      // Packet number
      {"Unable to read packet number.",
       {0x00, 0x02}},
      // Packet payload (padding)
      {"",
       std::vector<uint8_t>(static_cast<size_t>(kDefaultMaxPacketSize - 20), 0)}
  };
  // clang-format on

  SetDecrypterLevel(ENCRYPTION_INITIAL);
  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));
  ASSERT_EQ(encrypted->length(), kDefaultMaxPacketSize);
  PacketHeaderFormat format;
  QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
  bool version_flag;
  bool use_length_prefix;
  QuicVersionLabel version_label;
  std::optional<absl::string_view> retry_token;
  ParsedQuicVersion parsed_version = UnsupportedQuicVersion();
  QuicConnectionId destination_connection_id, source_connection_id;
  std::string detailed_error;
  MockConnec
```