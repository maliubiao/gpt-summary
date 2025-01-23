Response:
The user is asking for an analysis of a C++ source code file related to the QUIC protocol. The file `quic_framer_test.cc` is a test file for the `QuicFramer` class in Chromium's network stack.

Here's a breakdown of the thought process to generate the response:

1. **Identify the core functionality:** The filename `quic_framer_test.cc` strongly suggests this file contains unit tests for the `QuicFramer` class. The `QuicFramer` is responsible for parsing and serializing QUIC packets and frames.

2. **Analyze the code structure:** The code consists of multiple test cases (`TEST_P`) within a test fixture (`QuicFramerTest`). Each test case focuses on a specific aspect of the `QuicFramer`'s functionality. The tests generally follow a pattern:
    * Set up test data (packet fragments or complete packets).
    * Process the packet using `framer_.ProcessPacket()`.
    * Assertions (`EXPECT_TRUE`, `EXPECT_EQ`, `EXPECT_THAT`) to verify the expected behavior, such as error codes, parsed frame data, or the ability to build packets.

3. **Categorize the test cases:** Group the test cases based on the QUIC frame types they cover. This helps in understanding the overall scope of the file. The provided snippet includes tests for:
    * `NEW_TOKEN` frame
    * `STOP_SENDING` frame
    * `PATH_CHALLENGE` frame
    * `PATH_RESPONSE` frame
    * Frame type encoding errors (for IETF QUIC)
    * `RETIRE_CONNECTION_ID` frame (at the end of the snippet)

4. **Address specific instructions:**

    * **List the file's functions:** Based on the identified test categories, the file's main function is testing the parsing and serialization of various QUIC frame types by the `QuicFramer`.

    * **Relationship with JavaScript:**  QUIC is a transport protocol, and JavaScript running in a browser interacts with it indirectly through browser APIs. The connection isn't direct manipulation of QUIC frames. Examples include `fetch()` API using HTTP/3 (which uses QUIC) or WebTransport API which is built on top of QUIC. Emphasize that the JavaScript interaction is *indirect*.

    * **Logical Reasoning (Input/Output):** For parsing tests, the input is a byte sequence (simulating an incoming packet), and the output is the parsed frame data (stored in the `visitor_` object). For building tests, the input is a frame object, and the output is a constructed byte sequence representing the packet. Provide concrete examples using data from the test cases.

    * **User/Programming Errors:** Focus on common mistakes related to QUIC, such as incorrect frame formatting, using features not supported in a specific QUIC version, or issues with encryption levels. Relate these back to the tests, e.g., tests for invalid frame data demonstrate error handling.

    * **User Operation to Reach Here (Debugging):** Explain the journey from a user action in the browser (e.g., accessing a website) down to the QUIC layer and how a developer might use this test file during debugging (verifying frame parsing).

    * **File's Function (Part 12/16):**  Given it's part 12 of 16, and previous parts likely covered other core QUIC functionality,  this part focuses on testing the handling of specific control frames and error conditions, particularly those introduced with the IETF QUIC standard.

5. **Refine the language:** Use clear and concise language, avoiding overly technical jargon where possible. Explain QUIC concepts briefly where needed. Use examples from the code to illustrate points.

6. **Review and organize:** Ensure the answer addresses all parts of the prompt and is well-organized for readability. Use headings and bullet points to break down the information.
This source code file, `quic_framer_test.cc`, located in the Chromium network stack, serves as a **unit test suite for the `QuicFramer` class**. The `QuicFramer` class is responsible for **parsing and serializing QUIC packets and frames**.

Here's a breakdown of its functionality:

* **Testing Packet Processing:** The file contains numerous test cases that simulate receiving various types of QUIC packets with different frame combinations. It checks if the `QuicFramer` correctly parses these packets and extracts the individual frames.
* **Testing Frame Building:**  It also tests the ability of the `QuicFramer` to construct QUIC packets containing specific frames. This verifies the serialization logic.
* **Verification using a Visitor:** The tests typically use a `MockQuicFramerVisitor` (or a similar visitor pattern implementation) to observe the parsed frames. Assertions are then made against the visitor's state to confirm the expected frame data was extracted.
* **Error Handling Tests:**  Several tests are designed to verify how the `QuicFramer` handles malformed or invalid packets and frames, ensuring it correctly identifies errors and reports them.
* **Version and Feature Specific Tests:**  The code includes conditional logic (`if (!VersionHasIetfQuicFrames(framer_.transport_version()))`) to test features that are specific to certain QUIC versions (especially the IETF QUIC standard).
* **Testing Specific Frame Types:** The provided snippet focuses on testing the processing and building of the following IETF QUIC frame types:
    * **`NEW_TOKEN` Frame:** Used by the server to provide a token to the client for future connection establishment.
    * **`STOP_SENDING` Frame:** Used to signal to the peer that the sender will no longer send data on a specific stream.
    * **`PATH_CHALLENGE` Frame:** Sent to verify reachability of the peer at a given network path.
    * **`PATH_RESPONSE` Frame:** Sent in response to a `PATH_CHALLENGE` frame.
    * **Frame Type Encoding Errors:** Tests that the framer correctly identifies and handles invalid or non-minimally encoded frame types, which is a requirement in IETF QUIC.
    * **`RETIRE_CONNECTION_ID` Frame:** Used to indicate that a previously advertised connection ID is no longer in use.
* **Testing Frame Size Calculation:** The `GetRetransmittableControlFrameSize` test verifies the calculation of the serialized size for various control frames.

**Relationship with JavaScript Functionality:**

While this C++ code directly deals with the low-level details of the QUIC protocol, it indirectly relates to JavaScript functionality in a web browser. Here's how:

* **`fetch()` API and HTTP/3:** When a JavaScript application uses the `fetch()` API to make a network request to a server that supports HTTP/3, the underlying transport protocol is QUIC. The browser's network stack (including code like this) handles the QUIC connection establishment, packet framing, and data transfer. The JavaScript code doesn't directly interact with `QuicFramer`, but its network requests rely on it.

    **Example:**
    ```javascript
    // In a web page's JavaScript:
    fetch('https://example.com/data')
      .then(response => response.json())
      .then(data => console.log(data));
    ```
    Behind the scenes, if `example.com` supports HTTP/3, the browser will use QUIC. The `QuicFramer` in the browser's network stack will be involved in parsing the QUIC packets received from the server, which might contain `NEW_TOKEN` frames, `STOP_SENDING` frames (if the server wants to signal an issue with a stream), or other relevant frames.

* **WebTransport API:** The WebTransport API in browsers allows for bidirectional, multiplexed connections over HTTP/3 (and thus QUIC). JavaScript code using WebTransport relies heavily on the correct implementation of the QUIC protocol, including frame parsing and serialization handled by `QuicFramer`.

    **Example:**
    ```javascript
    // In a web page's JavaScript using WebTransport:
    const transport = new WebTransport('https://example.com/webtransport');

    transport.ready.then(() => {
      const stream = transport.createUnidirectionalStream();
      const writer = stream.writable.getWriter();
      writer.write(new TextEncoder().encode('Hello from JavaScript!'));
      writer.close();
    });
    ```
    When this JavaScript code sends data, the browser's QUIC implementation uses `QuicFramer` to construct the appropriate QUIC packets containing stream data frames. Similarly, when the server sends a `STOP_SENDING` frame (handled by the tests in the provided snippet), the `QuicFramer` will parse it, and the WebTransport implementation in the browser will notify the JavaScript application about the stream closure.

**Logical Reasoning (Hypothesized Input and Output):**

Let's take the `TEST_P(QuicFramerTest, IetfNewTokenFrame)` test as an example:

* **Hypothesized Input:** A raw byte sequence representing a QUIC packet containing a `NEW_TOKEN` frame. This is represented by the `packet` array in the test.
    ```
    0x43, // Short header with 4-byte packet number
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, // Destination Connection ID
    0x12, 0x34, 0x56, 0x78, // Packet Number
    0x07, // NEW_TOKEN frame type
    0x08, // Length of the token (1 byte encoding)
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07  // The new token value
    ```
* **Expected Output:** After processing this packet with `framer_.ProcessPacket(*encrypted)`, the `visitor_` object should contain the parsed `NEW_TOKEN` frame data. Specifically:
    * `visitor_.new_token_.token.length()` should be 8.
    * `memcmp(expected_token_value, visitor_.new_token_.token.data(), sizeof(expected_token_value))` should return 0 (meaning the token values are identical).
    * `framer_.error()` should be `IsQuicNoError()`.

Similarly, for the `BuildNewTokenFramePacket` test:

* **Hypothesized Input:** A `QuicNewTokenFrame` object constructed with a specific token value.
* **Expected Output:** The `BuildDataPacket` function should produce a raw byte sequence (the `data` packet) that matches the `packet` array defined in the test.

**User or Programming Common Usage Errors (and how these tests help):**

* **Incorrect Frame Formatting:** A common error is constructing a QUIC packet with frames that don't adhere to the specified format (e.g., incorrect length encoding, missing fields). The parsing tests in this file help catch these errors. If a server or client implementation generates a malformed `NEW_TOKEN` frame, the corresponding parsing test would likely fail, indicating a bug.
* **Using Features Not Supported in a Specific QUIC Version:** If code attempts to use an IETF QUIC frame type with an older QUIC version, the `QuicFramer` should ideally reject it. The conditional checks in the tests (`if (!VersionHasIetfQuicFrames(...))`) ensure that version-specific behavior is correctly implemented.
* **Misinterpreting Frame Semantics:** Incorrectly understanding the meaning or usage of a particular frame can lead to errors. While these unit tests don't directly test the high-level logic, they ensure that the basic parsing of the frame is correct, which is a foundation for higher-level logic.
* **Encryption Issues:** Although not explicitly shown in this snippet, other parts of the `QuicFramer` and its tests would cover decryption. A common error is using the wrong decryption keys or levels, leading to parsing failures. The `SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE)` calls in some tests indicate the importance of testing with different encryption states.

**User Operation to Reach Here (Debugging 线索):**

Imagine a user is experiencing issues connecting to a website that uses HTTP/3. Here's how the code in this file could be relevant as a debugging step:

1. **User Action:** The user types a URL into their browser and hits Enter. The browser attempts to establish a QUIC connection with the server.
2. **QUIC Connection Establishment:** The browser sends initial QUIC packets to the server. The server might respond with a `NEW_TOKEN` frame.
3. **Parsing `NEW_TOKEN`:** The browser's network stack receives the server's response. The `QuicFramer::ProcessPacket()` function (being tested here) is called to parse the incoming packet.
4. **Debugging Scenario:** If the browser fails to establish the connection, a developer might suspect an issue with parsing the server's `NEW_TOKEN`. They might:
    * **Examine Network Logs:** Check the raw bytes of the received QUIC packets to see the exact format of the `NEW_TOKEN` frame.
    * **Run Unit Tests:**  The developer might run the `IetfNewTokenFrame` test (or create a similar test with the specific byte sequence from the network logs) to see if the `QuicFramer` correctly parses the token. If the test fails, it pinpoints an issue in the `QuicFramer`'s parsing logic.
    * **Step Through the Code:** Using a debugger, the developer can step through the `QuicFramer::ProcessPacket()` function while processing the problematic packet to understand exactly where the parsing fails.

Similarly, if a website using WebTransport has issues with stream management, the `BuildIetfStopSendingPacket` and `IetfStopSendingFrame` tests become relevant. If the browser isn't correctly handling `STOP_SENDING` frames from the server, these tests can help isolate the parsing logic errors.

**歸納一下它的功能 (Summary of its Functionality - Part 12/16):**

As part 12 of 16, this specific section of `quic_framer_test.cc` primarily focuses on **testing the `QuicFramer`'s ability to correctly parse and serialize specific IETF QUIC control frames**, namely `NEW_TOKEN`, `STOP_SENDING`, `PATH_CHALLENGE`, `PATH_RESPONSE`, and `RETIRE_CONNECTION_ID`. It also includes crucial tests for **verifying the correct handling of frame type encoding**, ensuring adherence to the IETF QUIC specification regarding minimal encoding and rejection of unknown frame types. Given its position in the sequence, it's likely that earlier parts covered more fundamental frame types (like stream data frames) and core packet parsing, while later parts might delve into more complex scenarios or other QUIC features. This section plays a vital role in ensuring the robust and correct implementation of the IETF QUIC extensions within Chromium's network stack.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_framer_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第12部分，共16部分，请归纳一下它的功能
```

### 源代码
```cpp
0x03,
                                    0x04, 0x05, 0x06, 0x07};

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(0u, visitor_.stream_frames_.size());

  EXPECT_EQ(sizeof(expected_token_value), visitor_.new_token_.token.length());
  EXPECT_EQ(0, memcmp(expected_token_value, visitor_.new_token_.token.data(),
                      sizeof(expected_token_value)));

  CheckFramingBoundaries(packet, QUIC_INVALID_NEW_TOKEN);
}

TEST_P(QuicFramerTest, BuildNewTokenFramePacket) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for IETF QUIC only.
    return;
  }
  QuicFramerPeer::SetPerspective(&framer_, Perspective::IS_CLIENT);
  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  uint8_t expected_token_value[] = {0x00, 0x01, 0x02, 0x03,
                                    0x04, 0x05, 0x06, 0x07};

  QuicNewTokenFrame frame(0,
                          absl::string_view((const char*)(expected_token_value),
                                            sizeof(expected_token_value)));

  QuicFrames frames = {QuicFrame(&frame)};

  // clang-format off
  unsigned char packet[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_NEW_TOKEN frame)
    0x07,
    // Length and token
    kVarInt62OneByte + 0x08,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet),
      ABSL_ARRAYSIZE(packet));
}

TEST_P(QuicFramerTest, IetfStopSendingFrame) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Stop sending frame is IETF QUIC only.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (IETF_STOP_SENDING frame)
      {"",
       {0x05}},
      // stream id
      {"Unable to read IETF_STOP_SENDING frame stream id/count.",
       {kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04}},
      {"Unable to read stop sending application error code.",
       {kVarInt62FourBytes + 0x00, 0x00, 0x76, 0x54}},
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(kStreamId, visitor_.stop_sending_frame_.stream_id);
  EXPECT_EQ(QUIC_STREAM_UNKNOWN_APPLICATION_ERROR_CODE,
            visitor_.stop_sending_frame_.error_code);
  EXPECT_EQ(static_cast<uint64_t>(0x7654),
            visitor_.stop_sending_frame_.ietf_error_code);

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_STOP_SENDING_FRAME_DATA);
}

TEST_P(QuicFramerTest, BuildIetfStopSendingPacket) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Stop sending frame is IETF QUIC only.
    return;
  }

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicStopSendingFrame frame;
  frame.stream_id = kStreamId;
  frame.error_code = QUIC_STREAM_ENCODER_STREAM_ERROR;
  frame.ietf_error_code =
      static_cast<uint64_t>(QuicHttpQpackErrorCode::ENCODER_STREAM_ERROR);
  QuicFrames frames = {QuicFrame(frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_STOP_SENDING frame)
    0x05,
    // Stream ID
    kVarInt62FourBytes + 0x01, 0x02, 0x03, 0x04,
    // Application error code
    kVarInt62TwoBytes + 0x02, 0x01,
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, IetfPathChallengeFrame) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Path Challenge frame is IETF QUIC only.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (IETF_PATH_CHALLENGE)
      {"",
       {0x1a}},
      // data
      {"Can not read path challenge data.",
       {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(QuicPathFrameBuffer({{0, 1, 2, 3, 4, 5, 6, 7}}),
            visitor_.path_challenge_frame_.data_buffer);

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_PATH_CHALLENGE_DATA);
}

TEST_P(QuicFramerTest, BuildIetfPathChallengePacket) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Path Challenge frame is IETF QUIC only.
    return;
  }

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicPathChallengeFrame frame;
  frame.data_buffer = QuicPathFrameBuffer({{0, 1, 2, 3, 4, 5, 6, 7}});
  QuicFrames frames = {QuicFrame(frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_PATH_CHALLENGE)
    0x1a,
    // Data
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, IetfPathResponseFrame) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Path response frame is IETF QUIC only.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (IETF_PATH_RESPONSE)
      {"",
       {0x1b}},
      // data
      {"Can not read path response data.",
       {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsQuicNoError());
  ASSERT_TRUE(visitor_.header_.get());
  EXPECT_TRUE(CheckDecryption(
      *encrypted, !kIncludeVersion, !kIncludeDiversificationNonce,
      kPacket8ByteConnectionId, kPacket0ByteConnectionId));

  EXPECT_EQ(QuicPathFrameBuffer({{0, 1, 2, 3, 4, 5, 6, 7}}),
            visitor_.path_response_frame_.data_buffer);

  CheckFramingBoundaries(packet_ietf, QUIC_INVALID_PATH_RESPONSE_DATA);
}

TEST_P(QuicFramerTest, BuildIetfPathResponsePacket) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Path response frame is IETF QUIC only
    return;
  }

  QuicPacketHeader header;
  header.destination_connection_id = FramerTestConnectionId();
  header.reset_flag = false;
  header.version_flag = false;
  header.packet_number = kPacketNumber;

  QuicPathResponseFrame frame;
  frame.data_buffer = QuicPathFrameBuffer({{0, 1, 2, 3, 4, 5, 6, 7}});
  QuicFrames frames = {QuicFrame(frame)};

  // clang-format off
  unsigned char packet_ietf[] = {
    // type (short header, 4 byte packet number)
    0x43,
    // connection_id
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    // packet number
    0x12, 0x34, 0x56, 0x78,

    // frame type (IETF_PATH_RESPONSE)
    0x1b,
    // Data
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
  };
  // clang-format on

  std::unique_ptr<QuicPacket> data(BuildDataPacket(header, frames));
  ASSERT_TRUE(data != nullptr);

  quiche::test::CompareCharArraysWithHexError(
      "constructed packet", data->data(), data->length(), AsChars(packet_ietf),
      ABSL_ARRAYSIZE(packet_ietf));
}

TEST_P(QuicFramerTest, GetRetransmittableControlFrameSize) {
  QuicRstStreamFrame rst_stream(1, 3, QUIC_STREAM_CANCELLED, 1024);
  EXPECT_EQ(QuicFramer::GetRstStreamFrameSize(framer_.transport_version(),
                                              rst_stream),
            QuicFramer::GetRetransmittableControlFrameSize(
                framer_.transport_version(), QuicFrame(&rst_stream)));

  std::string error_detail(2048, 'e');
  QuicConnectionCloseFrame connection_close(framer_.transport_version(),
                                            QUIC_NETWORK_IDLE_TIMEOUT,
                                            NO_IETF_QUIC_ERROR, error_detail,
                                            /*transport_close_frame_type=*/0);

  EXPECT_EQ(QuicFramer::GetConnectionCloseFrameSize(framer_.transport_version(),
                                                    connection_close),
            QuicFramer::GetRetransmittableControlFrameSize(
                framer_.transport_version(), QuicFrame(&connection_close)));

  QuicGoAwayFrame goaway(2, QUIC_PEER_GOING_AWAY, 3, error_detail);
  EXPECT_EQ(QuicFramer::GetMinGoAwayFrameSize() + 256,
            QuicFramer::GetRetransmittableControlFrameSize(
                framer_.transport_version(), QuicFrame(&goaway)));

  QuicWindowUpdateFrame window_update(3, 3, 1024);
  EXPECT_EQ(QuicFramer::GetWindowUpdateFrameSize(framer_.transport_version(),
                                                 window_update),
            QuicFramer::GetRetransmittableControlFrameSize(
                framer_.transport_version(), QuicFrame(window_update)));

  QuicBlockedFrame blocked(4, 3, 1024);
  EXPECT_EQ(
      QuicFramer::GetBlockedFrameSize(framer_.transport_version(), blocked),
      QuicFramer::GetRetransmittableControlFrameSize(
          framer_.transport_version(), QuicFrame(blocked)));

  // Following frames are IETF QUIC frames only.
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    return;
  }

  QuicNewConnectionIdFrame new_connection_id(5, TestConnectionId(), 1,
                                             kTestStatelessResetToken, 1);
  EXPECT_EQ(QuicFramer::GetNewConnectionIdFrameSize(new_connection_id),
            QuicFramer::GetRetransmittableControlFrameSize(
                framer_.transport_version(), QuicFrame(&new_connection_id)));

  QuicMaxStreamsFrame max_streams(6, 3, /*unidirectional=*/false);
  EXPECT_EQ(QuicFramer::GetMaxStreamsFrameSize(framer_.transport_version(),
                                               max_streams),
            QuicFramer::GetRetransmittableControlFrameSize(
                framer_.transport_version(), QuicFrame(max_streams)));

  QuicStreamsBlockedFrame streams_blocked(7, 3, /*unidirectional=*/false);
  EXPECT_EQ(QuicFramer::GetStreamsBlockedFrameSize(framer_.transport_version(),
                                                   streams_blocked),
            QuicFramer::GetRetransmittableControlFrameSize(
                framer_.transport_version(), QuicFrame(streams_blocked)));

  QuicPathFrameBuffer buffer = {
      {0x80, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe5, 0xf7}};
  QuicPathResponseFrame path_response_frame(8, buffer);
  EXPECT_EQ(QuicFramer::GetPathResponseFrameSize(path_response_frame),
            QuicFramer::GetRetransmittableControlFrameSize(
                framer_.transport_version(), QuicFrame(path_response_frame)));

  QuicPathChallengeFrame path_challenge_frame(9, buffer);
  EXPECT_EQ(QuicFramer::GetPathChallengeFrameSize(path_challenge_frame),
            QuicFramer::GetRetransmittableControlFrameSize(
                framer_.transport_version(), QuicFrame(path_challenge_frame)));

  QuicStopSendingFrame stop_sending_frame(10, 3, QUIC_STREAM_CANCELLED);
  EXPECT_EQ(QuicFramer::GetStopSendingFrameSize(stop_sending_frame),
            QuicFramer::GetRetransmittableControlFrameSize(
                framer_.transport_version(), QuicFrame(stop_sending_frame)));
}

// A set of tests to ensure that bad frame-type encodings
// are properly detected and handled.
// First, four tests to see that unknown frame types generate
// a QUIC_INVALID_FRAME_DATA error with detailed information
// "Illegal frame type." This regardless of the encoding of the type
// (1/2/4/8 bytes).
// This only for version 99.
TEST_P(QuicFramerTest, IetfFrameTypeEncodingErrorUnknown1Byte) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Only IETF QUIC encodes frame types such that this test is relevant.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (unknown value, single-byte encoding)
      {"",
       {0x38}}
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));

  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_FRAME_DATA));
  EXPECT_EQ("Illegal frame type.", framer_.detailed_error());
}

TEST_P(QuicFramerTest, IetfFrameTypeEncodingErrorUnknown2Bytes) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Only IETF QUIC encodes frame types such that this test is relevant.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (unknown value, two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x01, 0x38}}
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));

  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_FRAME_DATA));
  EXPECT_EQ("Illegal frame type.", framer_.detailed_error());
}

TEST_P(QuicFramerTest, IetfFrameTypeEncodingErrorUnknown4Bytes) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Only IETF QUIC encodes frame types such that this test is relevant.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (unknown value, four-byte encoding)
      {"",
       {kVarInt62FourBytes + 0x01, 0x00, 0x00, 0x38}}
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));

  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_FRAME_DATA));
  EXPECT_EQ("Illegal frame type.", framer_.detailed_error());
}

TEST_P(QuicFramerTest, IetfFrameTypeEncodingErrorUnknown8Bytes) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Only IETF QUIC encodes frame types such that this test is relevant.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (unknown value, eight-byte encoding)
      {"",
       {kVarInt62EightBytes + 0x01, 0x00, 0x00, 0x01, 0x02, 0x34, 0x56, 0x38}}
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));

  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsError(QUIC_INVALID_FRAME_DATA));
  EXPECT_EQ("Illegal frame type.", framer_.detailed_error());
}

// Three tests to check that known frame types that are not minimally
// encoded generate IETF_QUIC_PROTOCOL_VIOLATION errors with detailed
// information "Frame type not minimally encoded."
// Look at the frame-type encoded in 2, 4, and 8 bytes.
TEST_P(QuicFramerTest, IetfFrameTypeEncodingErrorKnown2Bytes) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Only IETF QUIC encodes frame types such that this test is relevant.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (Blocked, two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x08}}
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));

  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsError(IETF_QUIC_PROTOCOL_VIOLATION));
  EXPECT_EQ("Frame type not minimally encoded.", framer_.detailed_error());
}

TEST_P(QuicFramerTest, IetfFrameTypeEncodingErrorKnown4Bytes) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Only IETF QUIC encodes frame types such that this test is relevant.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (Blocked, four-byte encoding)
      {"",
       {kVarInt62FourBytes + 0x00, 0x00, 0x00, 0x08}}
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));

  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsError(IETF_QUIC_PROTOCOL_VIOLATION));
  EXPECT_EQ("Frame type not minimally encoded.", framer_.detailed_error());
}

TEST_P(QuicFramerTest, IetfFrameTypeEncodingErrorKnown8Bytes) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Only IETF QUIC encodes frame types such that this test is relevant.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (Blocked, eight-byte encoding)
      {"",
       {kVarInt62EightBytes + 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08}}
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet));

  EXPECT_FALSE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), IsError(IETF_QUIC_PROTOCOL_VIOLATION));
  EXPECT_EQ("Frame type not minimally encoded.", framer_.detailed_error());
}

// Tests to check that all known IETF frame types that are not minimally
// encoded generate IETF_QUIC_PROTOCOL_VIOLATION errors with detailed
// information "Frame type not minimally encoded."
// Just look at 2-byte encoding.
TEST_P(QuicFramerTest, IetfFrameTypeEncodingErrorKnown2BytesAllTypes) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // Only IETF QUIC encodes frame types such that this test is relevant.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);

  // clang-format off
  PacketFragments packets[] = {
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x00}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x01}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x02}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x03}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x04}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x05}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x06}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x07}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x08}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x09}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x0a}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x0b}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x0c}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x0d}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x0e}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x0f}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x10}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x11}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x12}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x13}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x14}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x15}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x16}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x17}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x18}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x20}}
    },
    {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x9A, 0xBC}},
      // frame type (two-byte encoding)
      {"",
       {kVarInt62TwoBytes + 0x00, 0x21}}
    },
  };
  // clang-format on

  for (PacketFragments& packet : packets) {
    std::unique_ptr<QuicEncryptedPacket> encrypted(
        AssemblePacketFromFragments(packet));

    EXPECT_FALSE(framer_.ProcessPacket(*encrypted));

    EXPECT_THAT(framer_.error(), IsError(IETF_QUIC_PROTOCOL_VIOLATION));
    EXPECT_EQ("Frame type not minimally encoded.", framer_.detailed_error());
  }
}

TEST_P(QuicFramerTest, RetireConnectionIdFrame) {
  if (!VersionHasIetfQuicFrames(framer_.transport_version())) {
    // This frame is only for version 99.
    return;
  }
  SetDecrypterLevel(ENCRYPTION_FORWARD_SECURE);
  // clang-format off
  PacketFragments packet_ietf = {
      // type (short header, 4 byte packet number)
      {"",
       {0x43}},
      // connection_id
      {"",
       {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}},
      // packet number
      {"",
       {0x12, 0x34, 0x56, 0x78}},
      // frame type (IETF_RETIRE_CONNECTION_ID frame)
      {"",
       {0x19}},
      // Sequence number
      {"Unable to read retire connection ID frame sequence number.",
       {kVarInt62TwoBytes + 0x11, 0x22}}
  };
  // clang-format on

  std::unique_ptr<QuicEncryptedPacket> encrypted(
      AssemblePacketFromFragments(packet_ietf));
  EXPECT_TRUE(framer_.ProcessPacket(*encrypted));

  EXPECT_THAT(framer_.error(), Is
```