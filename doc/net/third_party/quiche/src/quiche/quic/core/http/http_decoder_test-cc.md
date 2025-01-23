Response:
The user wants me to analyze the provided C++ code, which is a unit test file for an HTTP decoder in Chromium's QUIC implementation.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The file `http_decoder_test.cc` tests the `HttpDecoder` class. The primary function of the `HttpDecoder` is to take raw byte streams and parse them into HTTP/3 frames, notifying a visitor interface (`MockHttpDecoderVisitor`) about the detected frames and their contents.

2. **Analyze the Test Structure:**  The tests are structured using Google Test (`TEST_F`). Each test method focuses on a specific aspect of the `HttpDecoder`'s behavior, like handling different frame types, error conditions, and partial input.

3. **List Key Features/Functionality Covered:** Based on the test names and the code within each test, I can identify the functionalities being tested:
    * Basic initialization (`InitialState`).
    * Handling unknown frame types (`UnknownFrame`).
    * Handling specific frame types: `CANCEL_PUSH`, `PUSH_PROMISE` (although it tests for an error, indicating the decoder doesn't *handle* it but *detects* it), `MAX_PUSH_ID`, `SETTINGS`, `DATA`, `GOAWAY`, `HEADERS`, `METADATA`.
    * Handling partial frame delivery and processing character by character.
    * Handling oversized frames.
    * Handling malformed or corrupt frames.
    * Handling duplicate settings in a `SETTINGS` frame.
    * Detecting HTTP/2 frames.
    * Testing scenarios where the visitor pauses processing.

4. **Determine Relationship to JavaScript:**  HTTP/3 is the underlying protocol for many web interactions. While this C++ code is not directly JavaScript, it's crucial for the networking layer that enables JavaScript applications to communicate with servers. Specifically, this decoder processes the incoming data that a browser (where JavaScript runs) receives from a server.

5. **Provide JavaScript Examples:**  I need to illustrate how the functionality of this C++ code manifests in JavaScript. Examples could involve:
    * Fetch API: How a `fetch()` call triggers HTTP/3 communication, and this decoder parses the server's response.
    * WebSockets: How initial handshake and subsequent data transfer over HTTP/3 are handled.
    * Server-Sent Events (SSE): How the server pushes updates, which are received and decoded by this component.

6. **Address Logical Reasoning (Assumptions and Outputs):**  Many tests implicitly or explicitly demonstrate logical reasoning. I need to pick a few examples and clarify the assumed input and expected output. For instance, the `UnknownFrame` test assumes a specific byte sequence representing an unknown frame and verifies that the visitor receives the correct frame type and payload.

7. **Identify Common Usage Errors:** These are related to how a *programmer* interacting with the `HttpDecoder` (or related components) might make mistakes. Examples include:
    * Not handling errors reported by the decoder.
    * Providing incomplete data to the decoder.
    * Incorrectly implementing the visitor interface.

8. **Trace User Operations to This Point (Debugging Context):**  How does a user's action in a browser eventually lead to this code being executed? I need to provide a step-by-step explanation, starting with a user action like clicking a link or typing a URL, and tracing the flow through DNS lookup, connection establishment, and finally, the processing of HTTP/3 data using this decoder.

9. **Summarize Functionality for Part 1:** Based on the analysis, I need to concisely summarize the primary purpose of the `http_decoder_test.cc` file and the `HttpDecoder` class it tests.

**Self-Correction/Refinement:**

* Initially, I might have focused too much on the low-level details of each test. I need to abstract to the higher-level functionality being tested.
* When explaining the JavaScript relationship, I should avoid getting bogged down in the intricacies of the underlying network stack and focus on the observable effects in JavaScript.
* For the logical reasoning examples, I need to be precise about the assumed input and the verifiable output (the visitor method calls).
* When discussing usage errors, I should target errors that are relevant to someone using or integrating with this networking component, not just hypothetical compiler errors.
* The debugging trace should be a plausible sequence of events, even if simplified.

By following this thought process, I can systematically analyze the code and address all aspects of the user's request.
This is the first part of a unit test file (`http_decoder_test.cc`) for the `HttpDecoder` class in Chromium's QUIC implementation. Here's a breakdown of its functionality:

**Core Functionality:**

This test file verifies the correct behavior of the `HttpDecoder` class. The `HttpDecoder` is responsible for taking a raw byte stream (representing an incoming HTTP/3 message) and parsing it into individual HTTP/3 frames. It then notifies a "visitor" (an interface with methods for handling each frame type) about the discovered frames.

**Key functionalities being tested in this part:**

* **Initialization:** Tests the initial state of the `HttpDecoder` (no errors).
* **Unknown Frames:**  Verifies that the decoder can correctly identify and process unknown frame types, extracting the frame type, header length, and payload.
* **Error Handling for Specific Frames:** Tests how the decoder reacts to receiving frames that are unexpected or invalid in the current context (e.g., `CANCEL_PUSH`, `PUSH_PROMISE`). These tests often expect the decoder to report an error.
* **`MAX_PUSH_ID` Frame:**  Tests the decoding of `MAX_PUSH_ID` frames, including scenarios where the visitor pauses processing.
* **`SETTINGS` Frame:** Tests the decoding of `SETTINGS` frames, including handling multiple settings, partial delivery of the frame, and detecting corrupt or malformed settings. It also tests for duplicate settings identifiers.
* **`DATA` Frame:** Tests the decoding of `DATA` frames, including handling partial delivery of the frame header and payload, and processing empty data frames.
* **Partial Frame Delivery:**  Includes tests that simulate receiving frame data in chunks, ensuring the decoder can handle incomplete frames.
* **Large Frame Types:** Tests the decoding of frame types that require more than one byte to represent.
* **`GOAWAY` Frame:** Tests the decoding of `GOAWAY` frames, including handling visitor pauses.
* **`HEADERS` Frame:** Tests the decoding of `HEADERS` frames, including handling partial delivery and empty header frames.
* **`METADATA` Frame:** Tests the decoding of `METADATA` frames, similar to the `HEADERS` frame tests.
* **Oversized Payloads:** Tests how the decoder handles frames with excessively large declared payload lengths, ensuring it doesn't allocate unbounded memory and reports errors correctly.
* **Malformed Frames:** Tests scenarios with various kinds of malformed frame data, verifying that the decoder detects the errors and provides informative error messages.
* **HTTP/2 Frame Detection:** Tests that the decoder correctly identifies and rejects HTTP/2 frames, which are not valid in an HTTP/3 connection.
* **Interleaving Frames:** Tests a scenario where a `HEADERS` frame is partially processed and then a `DATA` frame is encountered.
* **Corrupt Specific Frames:** Contains more detailed tests for specific corruptions within frames like `MAX_PUSH_ID`, `GOAWAY`, and `ACCEPT_CH`.
* **Empty `SETTINGS` Frame:** Specifically tests the handling of a `SETTINGS` frame with no settings.

**Relationship to Javascript Functionality:**

While this is C++ code, it directly relates to the functionality that enables Javascript in a browser to communicate with web servers using the HTTP/3 protocol. Here's how:

* **Fetching Resources (Fetch API):** When Javascript code uses the `fetch()` API to request a resource from a server that supports HTTP/3, the browser's networking stack uses code like this `HttpDecoder` to process the incoming HTTP/3 response data. The `HttpDecoder` parses the response headers (within `HEADERS` frames) and the response body (within `DATA` frames), making this information available to the Javascript `fetch()` promise.

    **Example:**
    ```javascript
    fetch('https://example.com/data')
      .then(response => response.json())
      .then(data => console.log(data));
    ```
    Behind the scenes, if the connection uses HTTP/3, the server's response, structured as HTTP/3 frames, will be processed by the `HttpDecoder`. The `HEADERS` frame will contain the `Content-Type: application/json` header, which informs the browser how to interpret the `DATA` frame containing the JSON payload.

* **WebSockets over HTTP/3:** If a WebSocket connection is established over HTTP/3, the data frames exchanged after the initial handshake will be parsed by the `HttpDecoder`.

    **Example:**
    ```javascript
    const websocket = new WebSocket('wss://example.com');
    websocket.onmessage = (event) => {
      console.log('Message received:', event.data);
    };
    ```
    The `event.data` in the Javascript code corresponds to the payload of a `DATA` frame that was decoded by the `HttpDecoder`.

* **Server-Sent Events (SSE):** When a Javascript application subscribes to server-sent events, the server pushes updates in a specific format over an HTTP connection. With HTTP/3, these updates arrive as `DATA` frames, which are processed by the `HttpDecoder`.

    **Example:**
    ```javascript
    const eventSource = new EventSource('/events');
    eventSource.onmessage = (event) => {
      console.log('Event received:', event.data);
    };
    ```
    Each `event.data` received by the Javascript code represents the payload of a `DATA` frame decoded by the `HttpDecoder`.

**Logical Reasoning (Assumption and Output Examples):**

* **Test Case: `UnknownFrame`**
    * **Assumption (Input):**  A byte sequence representing an unknown frame type (e.g., `0x21`) with a specific payload length (e.g., 14 bytes).
    * **Expected Output:** The `MockHttpDecoderVisitor`'s `OnUnknownFrameStart` method will be called with the correct frame type, header length, and payload length. If the payload length is greater than zero, `OnUnknownFramePayload` will be called with the payload data, and finally, `OnUnknownFrameEnd` will be called.

* **Test Case: `SettingsFrame`**
    * **Assumption (Input):** A byte sequence representing a `SETTINGS` frame with specific settings (identifier-value pairs).
    * **Expected Output:** The `MockHttpDecoderVisitor`'s `OnSettingsFrameStart` will be called with the number of settings. Then, `OnSettingsFrame` will be called with a `SettingsFrame` object containing the parsed identifier-value pairs.

**User or Programming Common Usage Errors:**

* **Not Handling Decoder Errors:** A common programming error would be to use the `HttpDecoder` and not check for errors using the `decoder_.error()` method. If the input data is malformed, the decoder will set an error state, and the program needs to handle this to avoid unexpected behavior or crashes.

    **Example of potential error:**  Receiving a corrupted HTTP/3 response and the Javascript application proceeding as if the data was valid, leading to incorrect rendering or application logic.

* **Providing Incomplete Data:** If the program provides only a partial HTTP/3 message to the `HttpDecoder`, it might not be able to fully process the frames. The `ProcessInput` method returns the number of bytes processed. Not accounting for this and not providing the remaining data can lead to incomplete decoding.

    **Example Scenario:** A network interruption occurs mid-response. The browser receives a partial response, and the `HttpDecoder` might not be able to fully parse a frame. The Javascript application might be left waiting for more data or receive an incomplete resource.

* **Incorrectly Implementing the Visitor Interface:** If a custom visitor is used, incorrectly implementing its methods (e.g., returning `false` prematurely from a "start" method) can disrupt the decoding process and lead to unexpected results. The tests in this file demonstrate how the visitor's return values can control the decoding flow.

**User Operation Leading to This Code (Debugging线索):**

Imagine a user browsing the web using Chrome:

1. **User Enters a URL or Clicks a Link:** The user initiates a navigation to a website (e.g., `https://example.com`).
2. **DNS Lookup:** The browser performs a DNS lookup to resolve the hostname to an IP address.
3. **Establishing a Connection:**  If the server supports HTTP/3, the browser will attempt to establish a QUIC connection (the underlying transport protocol for HTTP/3) with the server. This involves a handshake process.
4. **Sending the HTTP Request:** Once the QUIC connection is established, the browser sends an HTTP/3 request to the server. This request is formatted as HTTP/3 frames.
5. **Receiving the HTTP Response:** The server sends back the HTTP response, also formatted as HTTP/3 frames.
6. **Data Arrives in Chunks:** The response data doesn't necessarily arrive all at once. The operating system's network stack delivers the data to the browser in packets or chunks.
7. **`HttpDecoder::ProcessInput` is Called:**  As these chunks of data arrive, the browser's QUIC implementation calls the `HttpDecoder::ProcessInput()` method, providing the received bytes.
8. **Frame Parsing and Visitor Notification:** The `HttpDecoder` parses the byte stream, identifies the HTTP/3 frames (like `HEADERS` containing response headers, `DATA` containing the response body, `SETTINGS` if the server updates settings, etc.), and calls the corresponding methods on its visitor (in a real browser, this visitor would be part of the higher-level HTTP processing logic).
9. **Data Delivered to Javascript:**  The parsed information (headers, data) is then made available to the Javascript code running on the webpage through APIs like the Fetch API's `response` object or WebSocket's `onmessage` event.

Therefore, if a developer is debugging an issue where a webpage isn't loading correctly or a WebSocket connection is failing, and they suspect a problem with the received HTTP/3 data, they might look at the code related to the `HttpDecoder` to understand how the incoming data is being processed. They might use network inspection tools in the browser to examine the raw HTTP/3 frames being exchanged and then try to reproduce the issue with targeted test cases like the ones in this `http_decoder_test.cc` file.

**Summary of Part 1 Functionality:**

This first part of the `http_decoder_test.cc` file comprehensively tests the fundamental ability of the `HttpDecoder` class to correctly parse various valid and invalid HTTP/3 frames from a byte stream. It covers handling different frame types, partial delivery scenarios, error conditions, and interactions with a visitor interface. The tests ensure that the decoder correctly identifies frame boundaries, extracts frame headers and payloads, and reports errors when encountering malformed data or unexpected frame types.

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/http_decoder_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/http_decoder.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/http/http_encoder.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::InSequence;
using ::testing::Return;

namespace quic {
namespace test {

class HttpDecoderPeer {
 public:
  static uint64_t current_frame_type(HttpDecoder* decoder) {
    return decoder->current_frame_type_;
  }
};

namespace {

class HttpDecoderTest : public QuicTest {
 public:
  HttpDecoderTest() : decoder_(&visitor_) {
    ON_CALL(visitor_, OnMaxPushIdFrame()).WillByDefault(Return(true));
    ON_CALL(visitor_, OnGoAwayFrame(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnSettingsFrameStart(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnSettingsFrame(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnDataFrameStart(_, _)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnDataFramePayload(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnDataFrameEnd()).WillByDefault(Return(true));
    ON_CALL(visitor_, OnHeadersFrameStart(_, _)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnHeadersFramePayload(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnHeadersFrameEnd()).WillByDefault(Return(true));
    ON_CALL(visitor_, OnPriorityUpdateFrameStart(_))
        .WillByDefault(Return(true));
    ON_CALL(visitor_, OnPriorityUpdateFrame(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnAcceptChFrameStart(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnAcceptChFrame(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnOriginFrameStart(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnOriginFrame(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnMetadataFrameStart(_, _)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnMetadataFramePayload(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnMetadataFrameEnd()).WillByDefault(Return(true));
    ON_CALL(visitor_, OnUnknownFrameStart(_, _, _)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnUnknownFramePayload(_)).WillByDefault(Return(true));
    ON_CALL(visitor_, OnUnknownFrameEnd()).WillByDefault(Return(true));
  }
  ~HttpDecoderTest() override = default;

  uint64_t current_frame_type() {
    return HttpDecoderPeer::current_frame_type(&decoder_);
  }

  // Process |input| in a single call to HttpDecoder::ProcessInput().
  QuicByteCount ProcessInput(absl::string_view input) {
    return decoder_.ProcessInput(input.data(), input.size());
  }

  // Feed |input| to |decoder_| one character at a time,
  // verifying that each character gets processed.
  void ProcessInputCharByChar(absl::string_view input) {
    for (char c : input) {
      EXPECT_EQ(1u, decoder_.ProcessInput(&c, 1));
    }
  }

  // Append garbage to |input|, then process it in a single call to
  // HttpDecoder::ProcessInput().  Verify that garbage is not read.
  QuicByteCount ProcessInputWithGarbageAppended(absl::string_view input) {
    std::string input_with_garbage_appended = absl::StrCat(input, "blahblah");
    QuicByteCount processed_bytes = ProcessInput(input_with_garbage_appended);

    // Guaranteed by HttpDecoder::ProcessInput() contract.
    QUICHE_DCHECK_LE(processed_bytes, input_with_garbage_appended.size());

    // Caller should set up visitor to pause decoding
    // before HttpDecoder would read garbage.
    EXPECT_LE(processed_bytes, input.size());

    return processed_bytes;
  }

  testing::StrictMock<MockHttpDecoderVisitor> visitor_;
  HttpDecoder decoder_;
};

TEST_F(HttpDecoderTest, InitialState) {
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, UnknownFrame) {
  std::unique_ptr<char[]> input;

  const QuicByteCount payload_lengths[] = {0, 14, 100};
  const uint64_t frame_types[] = {
      0x21, 0x40, 0x5f, 0x7e, 0x9d,  // some reserved frame types
      0x6f, 0x14                     // some unknown, not reserved frame types
  };

  for (auto payload_length : payload_lengths) {
    std::string data(payload_length, 'a');

    for (auto frame_type : frame_types) {
      const QuicByteCount total_length =
          QuicDataWriter::GetVarInt62Len(frame_type) +
          QuicDataWriter::GetVarInt62Len(payload_length) + payload_length;
      input = std::make_unique<char[]>(total_length);

      QuicDataWriter writer(total_length, input.get());
      writer.WriteVarInt62(frame_type);
      writer.WriteVarInt62(payload_length);
      const QuicByteCount header_length = writer.length();
      if (payload_length > 0) {
        writer.WriteStringPiece(data);
      }

      EXPECT_CALL(visitor_, OnUnknownFrameStart(frame_type, header_length,
                                                payload_length));
      if (payload_length > 0) {
        EXPECT_CALL(visitor_, OnUnknownFramePayload(Eq(data)));
      }
      EXPECT_CALL(visitor_, OnUnknownFrameEnd());

      EXPECT_EQ(total_length, decoder_.ProcessInput(input.get(), total_length));

      EXPECT_THAT(decoder_.error(), IsQuicNoError());
      ASSERT_EQ("", decoder_.error_detail());
      EXPECT_EQ(frame_type, current_frame_type());
    }
  }
}

TEST_F(HttpDecoderTest, CancelPush) {
  InSequence s;
  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("03"   // type (CANCEL_PUSH)
                             "01"   // length
                             "01",  // Push Id
                             &input));

  EXPECT_CALL(visitor_, OnError(&decoder_));
  EXPECT_EQ(1u, ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsError(QUIC_HTTP_FRAME_ERROR));
  EXPECT_EQ("CANCEL_PUSH frame received.", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, PushPromiseFrame) {
  InSequence s;
  std::string push_promise_bytes;
  ASSERT_TRUE(
      absl::HexStringToBytes("05"   // type (PUSH PROMISE)
                             "08"   // length
                             "1f",  // push id 31
                             &push_promise_bytes));
  std::string input = absl::StrCat(push_promise_bytes,
                                   "Headers");  // headers

  EXPECT_CALL(visitor_, OnError(&decoder_));
  EXPECT_EQ(1u, ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsError(QUIC_HTTP_FRAME_ERROR));
  EXPECT_EQ("PUSH_PROMISE frame received.", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, MaxPushId) {
  InSequence s;
  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("0D"   // type (MAX_PUSH_ID)
                             "01"   // length
                             "01",  // Push Id
                             &input));

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnMaxPushIdFrame()).WillOnce(Return(false));
  EXPECT_EQ(input.size(), ProcessInputWithGarbageAppended(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnMaxPushIdFrame());
  EXPECT_EQ(input.size(), ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnMaxPushIdFrame());
  ProcessInputCharByChar(input);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, SettingsFrame) {
  InSequence s;
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "04"    // type (SETTINGS)
      "07"    // length
      "01"    // identifier (SETTINGS_QPACK_MAX_TABLE_CAPACITY)
      "02"    // content
      "06"    // identifier (SETTINGS_MAX_HEADER_LIST_SIZE)
      "05"    // content
      "4100"  // identifier, encoded on 2 bytes (0x40), value is 256 (0x100)
      "04",   // content
      &input));

  SettingsFrame frame;
  frame.values[1] = 2;
  frame.values[6] = 5;
  frame.values[256] = 4;

  // Visitor pauses processing.
  absl::string_view remaining_input(input);
  EXPECT_CALL(visitor_, OnSettingsFrameStart(2)).WillOnce(Return(false));
  QuicByteCount processed_bytes =
      ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(2u, processed_bytes);
  remaining_input = remaining_input.substr(processed_bytes);

  EXPECT_CALL(visitor_, OnSettingsFrame(frame)).WillOnce(Return(false));
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(remaining_input.size(), processed_bytes);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
  EXPECT_THAT(decoder_.decoded_frame_types(), ElementsAre(4));

  // Process the full frame.
  EXPECT_CALL(visitor_, OnSettingsFrameStart(2));
  EXPECT_CALL(visitor_, OnSettingsFrame(frame));
  EXPECT_EQ(input.size(), ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
  EXPECT_THAT(decoder_.decoded_frame_types(), ElementsAre(4, 4));

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnSettingsFrameStart(2));
  EXPECT_CALL(visitor_, OnSettingsFrame(frame));
  ProcessInputCharByChar(input);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
  EXPECT_THAT(decoder_.decoded_frame_types(), ElementsAre(4, 4, 4));
}

TEST_F(HttpDecoderTest, CorruptSettingsFrame) {
  const char* const kPayload =
      "\x42\x11"                           // two-byte id
      "\x80\x22\x33\x44"                   // four-byte value
      "\x58\x39"                           // two-byte id
      "\xf0\x22\x33\x44\x55\x66\x77\x88";  // eight-byte value
  struct {
    size_t payload_length;
    const char* const error_message;
  } kTestData[] = {
      {1, "Unable to read setting identifier."},
      {5, "Unable to read setting value."},
      {7, "Unable to read setting identifier."},
      {12, "Unable to read setting value."},
  };

  for (const auto& test_data : kTestData) {
    std::string input;
    input.push_back(4u);  // type SETTINGS
    input.push_back(test_data.payload_length);
    const size_t header_length = input.size();
    input.append(kPayload, test_data.payload_length);

    HttpDecoder decoder(&visitor_);
    EXPECT_CALL(visitor_, OnSettingsFrameStart(header_length));
    EXPECT_CALL(visitor_, OnError(&decoder));

    QuicByteCount processed_bytes =
        decoder.ProcessInput(input.data(), input.size());
    EXPECT_EQ(input.size(), processed_bytes);
    EXPECT_THAT(decoder.error(), IsError(QUIC_HTTP_FRAME_ERROR));
    EXPECT_EQ(test_data.error_message, decoder.error_detail());
  }
}

TEST_F(HttpDecoderTest, DuplicateSettingsIdentifier) {
  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("04"   // type (SETTINGS)
                             "04"   // length
                             "01"   // identifier
                             "01"   // content
                             "01"   // identifier
                             "02",  // content
                             &input));

  EXPECT_CALL(visitor_, OnSettingsFrameStart(2));
  EXPECT_CALL(visitor_, OnError(&decoder_));

  EXPECT_EQ(input.size(), ProcessInput(input));

  EXPECT_THAT(decoder_.error(),
              IsError(QUIC_HTTP_DUPLICATE_SETTING_IDENTIFIER));
  EXPECT_EQ("Duplicate setting identifier.", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, DataFrame) {
  InSequence s;
  std::string type_and_length_bytes;
  ASSERT_TRUE(
      absl::HexStringToBytes("00"   // type (DATA)
                             "05",  // length
                             &type_and_length_bytes));
  std::string input = absl::StrCat(type_and_length_bytes,
                                   "Data!");  // data

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnDataFrameStart(2, 5)).WillOnce(Return(false));
  absl::string_view remaining_input(input);
  QuicByteCount processed_bytes =
      ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(2u, processed_bytes);
  remaining_input = remaining_input.substr(processed_bytes);

  EXPECT_CALL(visitor_, OnDataFramePayload(absl::string_view("Data!")))
      .WillOnce(Return(false));
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(remaining_input.size(), processed_bytes);

  EXPECT_CALL(visitor_, OnDataFrameEnd()).WillOnce(Return(false));
  EXPECT_EQ(0u, ProcessInputWithGarbageAppended(""));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnDataFrameStart(2, 5));
  EXPECT_CALL(visitor_, OnDataFramePayload(absl::string_view("Data!")));
  EXPECT_CALL(visitor_, OnDataFrameEnd());
  EXPECT_EQ(input.size(), ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnDataFrameStart(2, 5));
  EXPECT_CALL(visitor_, OnDataFramePayload(absl::string_view("D")));
  EXPECT_CALL(visitor_, OnDataFramePayload(absl::string_view("a")));
  EXPECT_CALL(visitor_, OnDataFramePayload(absl::string_view("t")));
  EXPECT_CALL(visitor_, OnDataFramePayload(absl::string_view("a")));
  EXPECT_CALL(visitor_, OnDataFramePayload(absl::string_view("!")));
  EXPECT_CALL(visitor_, OnDataFrameEnd());
  ProcessInputCharByChar(input);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, FrameHeaderPartialDelivery) {
  InSequence s;
  // A large input that will occupy more than 1 byte in the length field.
  std::string input(2048, 'x');
  quiche::QuicheBuffer header = HttpEncoder::SerializeDataFrameHeader(
      input.length(), quiche::SimpleBufferAllocator::Get());
  // Partially send only 1 byte of the header to process.
  EXPECT_EQ(1u, decoder_.ProcessInput(header.data(), 1));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Send the rest of the header.
  EXPECT_CALL(visitor_, OnDataFrameStart(3, input.length()));
  EXPECT_EQ(header.size() - 1,
            decoder_.ProcessInput(header.data() + 1, header.size() - 1));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Send data.
  EXPECT_CALL(visitor_, OnDataFramePayload(absl::string_view(input)));
  EXPECT_CALL(visitor_, OnDataFrameEnd());
  EXPECT_EQ(2048u, decoder_.ProcessInput(input.data(), 2048));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, PartialDeliveryOfLargeFrameType) {
  // Use a reserved type that takes four bytes as a varint.
  const uint64_t frame_type = 0x1f * 0x222 + 0x21;
  const QuicByteCount payload_length = 0;
  const QuicByteCount header_length =
      QuicDataWriter::GetVarInt62Len(frame_type) +
      QuicDataWriter::GetVarInt62Len(payload_length);

  auto input = std::make_unique<char[]>(header_length);
  QuicDataWriter writer(header_length, input.get());
  writer.WriteVarInt62(frame_type);
  writer.WriteVarInt62(payload_length);

  EXPECT_CALL(visitor_,
              OnUnknownFrameStart(frame_type, header_length, payload_length));
  EXPECT_CALL(visitor_, OnUnknownFrameEnd());

  auto raw_input = input.get();
  for (uint64_t i = 0; i < header_length; ++i) {
    char c = raw_input[i];
    EXPECT_EQ(1u, decoder_.ProcessInput(&c, 1));
  }

  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
  EXPECT_EQ(frame_type, current_frame_type());
}

TEST_F(HttpDecoderTest, GoAway) {
  InSequence s;
  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("07"   // type (GOAWAY)
                             "01"   // length
                             "01",  // ID
                             &input));

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnGoAwayFrame(GoAwayFrame({1})))
      .WillOnce(Return(false));
  EXPECT_EQ(input.size(), ProcessInputWithGarbageAppended(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnGoAwayFrame(GoAwayFrame({1})));
  EXPECT_EQ(input.size(), ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnGoAwayFrame(GoAwayFrame({1})));
  ProcessInputCharByChar(input);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, HeadersFrame) {
  InSequence s;
  std::string type_and_length_bytes;
  ASSERT_TRUE(
      absl::HexStringToBytes("01"   // type (HEADERS)
                             "07",  // length
                             &type_and_length_bytes));
  std::string input = absl::StrCat(type_and_length_bytes,
                                   "Headers");  // headers

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnHeadersFrameStart(2, 7)).WillOnce(Return(false));
  absl::string_view remaining_input(input);
  QuicByteCount processed_bytes =
      ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(2u, processed_bytes);
  remaining_input = remaining_input.substr(processed_bytes);

  EXPECT_CALL(visitor_, OnHeadersFramePayload(absl::string_view("Headers")))
      .WillOnce(Return(false));
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(remaining_input.size(), processed_bytes);

  EXPECT_CALL(visitor_, OnHeadersFrameEnd()).WillOnce(Return(false));
  EXPECT_EQ(0u, ProcessInputWithGarbageAppended(""));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnHeadersFrameStart(2, 7));
  EXPECT_CALL(visitor_, OnHeadersFramePayload(absl::string_view("Headers")));
  EXPECT_CALL(visitor_, OnHeadersFrameEnd());
  EXPECT_EQ(input.size(), ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnHeadersFrameStart(2, 7));
  EXPECT_CALL(visitor_, OnHeadersFramePayload(absl::string_view("H")));
  EXPECT_CALL(visitor_, OnHeadersFramePayload(absl::string_view("e")));
  EXPECT_CALL(visitor_, OnHeadersFramePayload(absl::string_view("a")));
  EXPECT_CALL(visitor_, OnHeadersFramePayload(absl::string_view("d")));
  EXPECT_CALL(visitor_, OnHeadersFramePayload(absl::string_view("e")));
  EXPECT_CALL(visitor_, OnHeadersFramePayload(absl::string_view("r")));
  EXPECT_CALL(visitor_, OnHeadersFramePayload(absl::string_view("s")));
  EXPECT_CALL(visitor_, OnHeadersFrameEnd());
  ProcessInputCharByChar(input);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, MetadataFrame) {
  InSequence s;
  std::string type_and_length_bytes;
  ASSERT_TRUE(
      absl::HexStringToBytes("404d"  // 2 byte type (METADATA)
                             "08",   // length
                             &type_and_length_bytes));
  std::string input = absl::StrCat(type_and_length_bytes,
                                   "Metadata");  // headers

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnMetadataFrameStart(3, 8)).WillOnce(Return(false));
  absl::string_view remaining_input(input);
  QuicByteCount processed_bytes =
      ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(3u, processed_bytes);
  remaining_input = remaining_input.substr(processed_bytes);

  EXPECT_CALL(visitor_, OnMetadataFramePayload(absl::string_view("Metadata")))
      .WillOnce(Return(false));
  processed_bytes = ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(remaining_input.size(), processed_bytes);

  EXPECT_CALL(visitor_, OnMetadataFrameEnd()).WillOnce(Return(false));
  EXPECT_EQ(0u, ProcessInputWithGarbageAppended(""));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnMetadataFrameStart(3, 8));
  EXPECT_CALL(visitor_, OnMetadataFramePayload(absl::string_view("Metadata")));
  EXPECT_CALL(visitor_, OnMetadataFrameEnd());
  EXPECT_EQ(input.size(), ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnMetadataFrameStart(3, 8));
  EXPECT_CALL(visitor_, OnMetadataFramePayload(absl::string_view("M")));
  EXPECT_CALL(visitor_, OnMetadataFramePayload(absl::string_view("e")));
  EXPECT_CALL(visitor_, OnMetadataFramePayload(absl::string_view("t")));
  EXPECT_CALL(visitor_, OnMetadataFramePayload(absl::string_view("a")));
  EXPECT_CALL(visitor_, OnMetadataFramePayload(absl::string_view("d")));
  EXPECT_CALL(visitor_, OnMetadataFramePayload(absl::string_view("a")));
  EXPECT_CALL(visitor_, OnMetadataFramePayload(absl::string_view("t")));
  EXPECT_CALL(visitor_, OnMetadataFramePayload(absl::string_view("a")));
  EXPECT_CALL(visitor_, OnMetadataFrameEnd());
  ProcessInputCharByChar(input);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, EmptyDataFrame) {
  InSequence s;
  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("00"   // type (DATA)
                             "00",  // length
                             &input));

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnDataFrameStart(2, 0)).WillOnce(Return(false));
  EXPECT_EQ(input.size(), ProcessInputWithGarbageAppended(input));

  EXPECT_CALL(visitor_, OnDataFrameEnd()).WillOnce(Return(false));
  EXPECT_EQ(0u, ProcessInputWithGarbageAppended(""));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnDataFrameStart(2, 0));
  EXPECT_CALL(visitor_, OnDataFrameEnd());
  EXPECT_EQ(input.size(), ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnDataFrameStart(2, 0));
  EXPECT_CALL(visitor_, OnDataFrameEnd());
  ProcessInputCharByChar(input);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, EmptyHeadersFrame) {
  InSequence s;
  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("01"   // type (HEADERS)
                             "00",  // length
                             &input));

  // Visitor pauses processing.
  EXPECT_CALL(visitor_, OnHeadersFrameStart(2, 0)).WillOnce(Return(false));
  EXPECT_EQ(input.size(), ProcessInputWithGarbageAppended(input));

  EXPECT_CALL(visitor_, OnHeadersFrameEnd()).WillOnce(Return(false));
  EXPECT_EQ(0u, ProcessInputWithGarbageAppended(""));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the full frame.
  EXPECT_CALL(visitor_, OnHeadersFrameStart(2, 0));
  EXPECT_CALL(visitor_, OnHeadersFrameEnd());
  EXPECT_EQ(input.size(), ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());

  // Process the frame incrementally.
  EXPECT_CALL(visitor_, OnHeadersFrameStart(2, 0));
  EXPECT_CALL(visitor_, OnHeadersFrameEnd());
  ProcessInputCharByChar(input);
  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, GoawayWithOverlyLargePayload) {
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "07"   // type (GOAWAY)
      "10",  // length exceeding the maximum possible length for GOAWAY frame
      &input));
  // Process all data at once.
  EXPECT_CALL(visitor_, OnError(&decoder_));
  EXPECT_EQ(2u, ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsError(QUIC_HTTP_FRAME_TOO_LARGE));
  EXPECT_EQ("Frame is too large.", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, MaxPushIdWithOverlyLargePayload) {
  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("0d"   // type (MAX_PUSH_ID)
                             "10",  // length exceeding the maximum possible
                                    // length for MAX_PUSH_ID frame
                             &input));
  // Process all data at once.
  EXPECT_CALL(visitor_, OnError(&decoder_));
  EXPECT_EQ(2u, ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsError(QUIC_HTTP_FRAME_TOO_LARGE));
  EXPECT_EQ("Frame is too large.", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, FrameWithOverlyLargePayload) {
  // Regression test for b/193919867: Ensure that reading frames with incredibly
  // large payload lengths does not lead to allocating unbounded memory.
  constexpr size_t max_input_length =
      /*max frame type varint length*/ sizeof(uint64_t) +
      /*max frame length varint length*/ sizeof(uint64_t) +
      /*one byte of payload*/ sizeof(uint8_t);
  char input[max_input_length];
  for (uint64_t frame_type = 0; frame_type < 1025; frame_type++) {
    ::testing::NiceMock<MockHttpDecoderVisitor> visitor;
    HttpDecoder decoder(&visitor);
    QuicDataWriter writer(max_input_length, input);
    ASSERT_TRUE(writer.WriteVarInt62(frame_type));  // frame type.
    ASSERT_TRUE(
        writer.WriteVarInt62(quiche::kVarInt62MaxValue));  // frame length.
    ASSERT_TRUE(writer.WriteUInt8(0x00));  // one byte of payload.
    EXPECT_NE(decoder.ProcessInput(input, writer.length()), 0u) << frame_type;
  }
}

TEST_F(HttpDecoderTest, MalformedSettingsFrame) {
  char input[30];
  QuicDataWriter writer(30, input);
  // Write type SETTINGS.
  writer.WriteUInt8(0x04);
  // Write length.
  writer.WriteVarInt62(2048 * 1024);

  writer.WriteStringPiece("Malformed payload");
  EXPECT_CALL(visitor_, OnError(&decoder_));
  EXPECT_EQ(5u, decoder_.ProcessInput(input, ABSL_ARRAYSIZE(input)));
  EXPECT_THAT(decoder_.error(), IsError(QUIC_HTTP_FRAME_TOO_LARGE));
  EXPECT_EQ("Frame is too large.", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, Http2Frame) {
  std::string input;
  ASSERT_TRUE(absl::HexStringToBytes(
      "06"   // PING in HTTP/2 but not supported in HTTP/3.
      "05"   // length
      "15",  // random payload
      &input));

  // Process the full frame.
  EXPECT_CALL(visitor_, OnError(&decoder_));
  EXPECT_EQ(1u, ProcessInput(input));
  EXPECT_THAT(decoder_.error(), IsError(QUIC_HTTP_RECEIVE_SPDY_FRAME));
  EXPECT_EQ("HTTP/2 frame received in a HTTP/3 connection: 6",
            decoder_.error_detail());
}

TEST_F(HttpDecoderTest, HeadersPausedThenData) {
  InSequence s;
  std::string headers_type_and_length_bytes;
  ASSERT_TRUE(
      absl::HexStringToBytes("01"   // type (HEADERS)
                             "07",  // length,
                             &headers_type_and_length_bytes));
  std::string headers = absl::StrCat(headers_type_and_length_bytes, "Headers");
  std::string data_type_and_length_bytes;
  ASSERT_TRUE(
      absl::HexStringToBytes("00"   // type (DATA)
                             "05",  // length
                             &data_type_and_length_bytes));
  std::string data = absl::StrCat(data_type_and_length_bytes, "Data!");
  std::string input = absl::StrCat(headers, data);

  // Visitor pauses processing, maybe because header decompression is blocked.
  EXPECT_CALL(visitor_, OnHeadersFrameStart(2, 7));
  EXPECT_CALL(visitor_, OnHeadersFramePayload(absl::string_view("Headers")));
  EXPECT_CALL(visitor_, OnHeadersFrameEnd()).WillOnce(Return(false));
  absl::string_view remaining_input(input);
  QuicByteCount processed_bytes =
      ProcessInputWithGarbageAppended(remaining_input);
  EXPECT_EQ(9u, processed_bytes);
  remaining_input = remaining_input.substr(processed_bytes);

  // Process DATA frame.
  EXPECT_CALL(visitor_, OnDataFrameStart(2, 5));
  EXPECT_CALL(visitor_, OnDataFramePayload(absl::string_view("Data!")));
  EXPECT_CALL(visitor_, OnDataFrameEnd());

  processed_bytes = ProcessInput(remaining_input);
  EXPECT_EQ(remaining_input.size(), processed_bytes);

  EXPECT_THAT(decoder_.error(), IsQuicNoError());
  EXPECT_EQ("", decoder_.error_detail());
}

TEST_F(HttpDecoderTest, CorruptFrame) {
  InSequence s;

  struct {
    const char* const input;
    const char* const error_message;
  } kTestData[] = {{"\x0D"   // type (MAX_PUSH_ID)
                    "\x01"   // length
                    "\x40",  // first byte of two-byte varint push id
                    "Unable to read MAX_PUSH_ID push_id."},
                   {"\x0D"  // type (MAX_PUSH_ID)
                    "\x04"  // length
                    "\x05"  // valid push id
                    "foo",  // superfluous data
                    "Superfluous data in MAX_PUSH_ID frame."},
                   {"\x07"   // type (GOAWAY)
                    "\x01"   // length
                    "\x40",  // first byte of two-byte varint stream id
                    "Unable to read GOAWAY ID."},
                   {"\x07"  // type (GOAWAY)
                    "\x04"  // length
                    "\x05"  // valid stream id
                    "foo",  // superfluous data
                    "Superfluous data in GOAWAY frame."},
                   {"\x40\x89"  // type (ACCEPT_CH)
                    "\x01"      // length
                    "\x40",     // first byte of two-byte varint origin length
                    "Unable to read ACCEPT_CH origin."},
                   {"\x40\x89"  // type (ACCEPT_CH)
                    "\x01"      // length
                    "\x05",     // valid origin length but no origin string
                    "Unable to read ACCEPT_CH origin."},
                   {"\x40\x89"  // type (ACCEPT_CH)
                    "\x04"      // length
                    "\x05"      // valid origin length
                    "foo",      // payload ends before origin ends
                    "Unable to read ACCEPT_CH origin."},
                   {"\x40\x89"  // type (ACCEPT_CH)
                    "\x04"      // length
                    "\x03"      // valid origin length
                    "foo",      // payload ends at end of origin: no value
                    "Unable to read ACCEPT_CH value."},
                   {"\x40\x89"  // type (ACCEPT_CH)
                    "\x05"      // length
                    "\x03"      // valid origin length
                    "foo"       // payload ends at end of origin: no value
                    "\x40",     // first byte of two-byte varint value length
                    "Unable to read ACCEPT_CH value."},
                   {"\x40\x89"  // type (ACCEPT_CH)
                    "\x08"      // length
                    "\x03"      // valid origin length
                    "foo"       // origin
                    "\x05"      // valid value length
                    "bar",      // payload ends before value ends
                    "Unable to read ACCEPT_CH value."}};

  for (const auto& test_data : kTestData) {
    {
      HttpDecoder decoder(&visitor_);
      EXPECT_CALL(visitor_, OnAcceptChFrameStart(_)).Times(AnyNumber());
      EXPECT_CALL(visitor_, OnError(&decoder));

      absl::string_view input(test_data.input);
      decoder.ProcessInput(input.data(), input.size());
      EXPECT_THAT(decoder.error(), IsError(QUIC_HTTP_FRAME_ERROR));
      EXPECT_EQ(test_data.error_message, decoder.error_detail());
    }
    {
      HttpDecoder decoder(&visitor_);
      EXPECT_CALL(visitor_, OnAcceptChFrameStart(_)).Times(AnyNumber());
      EXPECT_CALL(visitor_, OnError(&decoder));

      absl::string_view input(test_data.input);
      for (auto c : input) {
        decoder.ProcessInput(&c, 1);
      }
      EXPECT_THAT(decoder.error(), IsError(QUIC_HTTP_FRAME_ERROR));
      EXPECT_EQ(test_data.error_message, decoder.error_detail());
    }
  }
}

TEST_F(HttpDecoderTest, EmptySettingsFrame) {
  std::string input;
  ASSERT_TRUE(
      absl::HexStringToBytes("04"   // type (SETTINGS)
                             "00",  // frame length
                             &input));

  EXPECT_CALL(visitor_, OnSettingsFrameStart(2));

  SettingsFrame empty_frame;
  EXPECT_CALL(
```