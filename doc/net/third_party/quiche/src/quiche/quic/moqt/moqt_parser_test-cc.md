Response:
My thinking process to analyze the provided C++ code snippet and address the prompt's requests went something like this:

1. **Understand the Core Functionality:** The file `moqt_parser_test.cc` within the `net/third_party/quiche/src/quiche/quic/moqt/` directory immediately suggests it's a unit test file. Specifically, it's testing the parsing of MOQT (Media over QUIC Transport) messages. The `#include "quiche/quic/moqt/moqt_parser.h"` confirms this, indicating the file under test is the MOQT parser.

2. **Identify Key Components and Their Roles:**
    * **`MoqtParserTest` Class:**  This is the main test fixture, setting up the environment for individual test cases. It instantiates the parser and a visitor.
    * **`MoqtParserTestVisitor` Class:** This class acts as a receiver for the parsed messages. It implements the `MoqtControlParserVisitor` and `MoqtDataParserVisitor` interfaces, providing callbacks for different message types. This is crucial for verifying the parser's output.
    * **`MoqtControlParser` and `MoqtDataParser`:** These are the classes being tested. The control parser handles control messages, and the data parser handles data stream messages.
    * **`MoqtMessageType` and `MoqtDataStreamType`:** Enums defining the different types of MOQT messages.
    * **Test Cases (`TEST_P`, `TEST_F`):**  These are the individual tests verifying specific parsing scenarios. Parameterized tests (`TEST_P`) allow running the same test with different message types and transport protocols.
    * **Helper Functions (`GetMoqtParserTestParams`, `TypeFormatter`, `ParamNameFormatter`, `MakeMessage`):**  These functions assist in setting up and organizing the tests. `MakeMessage` is key for creating test messages.
    * **`TestMessageBase` (from `#include "quiche/quic/moqt/test_tools/moqt_test_message.h"`):**  This header, though not fully shown, provides utilities for creating and manipulating test MOQT messages.

3. **Analyze Test Scenarios:** I scanned the `TEST_P` blocks, focusing on the test names and what they were doing:
    * **`OneMessage`, `OneMessageWithLongVarints`, `TwoPartMessage`, `OneByteAtATime`, `TwoBytesAtATime`:** These tests cover basic successful parsing with different chunking and varint encoding scenarios.
    * **`EarlyFin`, `SeparateEarlyFin`:**  These test error handling when the stream ends prematurely.
    * **`PayloadLengthTooLong`, `PayloadLengthTooShort`:** These verify error detection for incorrect payload lengths in control messages.

4. **Look for JavaScript Connections (as requested):**  MOQT is a network protocol. While this specific C++ code is the implementation of the parser, MOQT itself *could* be used in conjunction with JavaScript in a browser environment. For instance, a JavaScript application might use the WebTransport API to establish a connection and send/receive MOQT messages. The C++ code on the server side (or potentially a browser implementation) would be responsible for parsing those messages.

5. **Consider Logic and Assumptions:** The tests implicitly assume that the `MoqtControlParser` and `MoqtDataParser` classes correctly implement the MOQT specification. The tests work by feeding crafted byte sequences (representing MOQT messages) to the parser and then checking if the `MoqtParserTestVisitor` receives the expected message data.

6. **Identify Potential User Errors:**  The tests for `EarlyFin`, `SeparateEarlyFin`, `PayloadLengthTooLong`, and `PayloadLengthTooShort` point to common errors developers might make when *generating* MOQT messages. These are not errors in *using* the parser, but rather errors in the message construction that the parser is designed to detect.

7. **Trace User Steps (Debugging Context):** To arrive at this code during debugging, a developer would likely be investigating issues related to MOQT message parsing. They might:
    * Encounter errors in their application that indicate a problem with MOQT message handling.
    * Look at server-side logs or network traces that show malformed MOQT messages.
    * Suspect the parsing logic and decide to examine the `moqt_parser.cc` and its tests.
    * Step through the code using a debugger, setting breakpoints in the parser and the visitor.

8. **Summarize Functionality (as requested for Part 1):** Based on the above analysis, I could then summarize the file's purpose as unit testing the MOQT parser, covering both successful and error scenarios for various MOQT message types and data stream handling.

By following these steps, I was able to extract the necessary information to answer the prompt comprehensively, covering the file's functionality, its relationship to JavaScript, logical inferences, potential user errors, and debugging context, ultimately leading to the summary for Part 1.
This is the first part of the source code file `moqt_parser_test.cc` in the Chromium network stack, specifically within the QUIC implementation for MOQT (Media over QUIC Transport).

**Functionality Summary (Part 1):**

This part of the file primarily sets up the testing framework and defines the basic structure for testing the MOQT parser. Its main functions are:

1. **Defining Test Parameters:** It defines a `MoqtParserTestParams` structure to represent different test scenarios, combining a `MoqtMessageType` or `MoqtDataStreamType` with a boolean indicating whether WebTransport is used. It also provides a function `GetMoqtParserTestParams()` to generate a comprehensive list of these parameters, covering various message types and transport protocols.

2. **Creating a Test Visitor:** It defines a `MoqtParserTestVisitor` class, which acts as a mock observer for the MOQT parser. This visitor implements the `MoqtControlParserVisitor` and `MoqtDataParserVisitor` interfaces. Its role is to receive and store the parsed messages and any parsing errors reported by the parser, allowing the tests to verify the parser's behavior.

3. **Setting up the Main Test Fixture:** It defines the `MoqtParserTest` class, which inherits from `quic::test::QuicTestWithParam`. This class:
    * Is parameterized with `MoqtParserTestParams`, meaning each test case will run for each combination of message type and transport protocol.
    * Instantiates the `MoqtControlParser` and `MoqtDataParser` (the classes being tested) with the test visitor.
    * Provides helper functions like `IsDataStream()` to check the message type and `MakeMessage()` to create test MOQT messages based on the current test parameter.
    * Has a `ProcessData()` function to feed data to the appropriate parser (control or data).

4. **Defining Basic Test Cases:** This part includes initial test cases using `TEST_P` (parameterized tests):
    * **`OneMessage`:** Tests parsing a single complete MOQT message.
    * **`OneMessageWithLongVarints`:** Tests parsing a single message with variable-length integers encoded with more bytes.
    * **`TwoPartMessage`:** Tests parsing a message that arrives in two separate chunks of data.
    * **`OneByteAtATime`:** Tests parsing a message when each byte is fed to the parser individually.
    * **`OneByteAtATimeLongerVarints`:**  Similar to `OneByteAtATime`, but with longer varints.
    * **`TwoBytesAtATime`:** Tests parsing with data chunks of a specific size.
    * **`EarlyFin`:** Tests the parser's behavior when the data stream ends prematurely (FIN bit set before a complete message).
    * **`SeparateEarlyFin`:** Similar to `EarlyFin` but the FIN arrives in a separate empty data chunk.
    * **`PayloadLengthTooLong`:** Tests the parser's reaction to a control message where the declared payload length is greater than the actual payload.
    * **`PayloadLengthTooShort`:** Tests the parser's reaction to a control message where the declared payload length is less than the actual payload.

**Relationship to JavaScript:**

While this C++ code itself is not directly JavaScript, it's part of the Chromium browser's network stack. This stack is responsible for handling network communication for web pages, including those running JavaScript.

* **Indirect Relationship via WebTransport:**  MOQT is designed to work over WebTransport, a browser API that allows JavaScript to establish bidirectional data streams over HTTP/3. JavaScript code using the WebTransport API might send and receive data that adheres to the MOQT protocol. This C++ code would be running within the browser (or a server) to parse those MOQT messages received over the WebTransport connection.

**Example:**

Imagine a JavaScript application using WebTransport to receive streaming video data using MOQT.

* **JavaScript (Sender):**  The JavaScript code on the server side might construct MOQT messages (e.g., containing video frames) and send them over the WebTransport stream.
* **Network:** The browser receives the data.
* **Chromium Network Stack (Parser):** This `moqt_parser_test.cc` (and the actual `moqt_parser.cc`) is part of the code that would parse those incoming bytes according to the MOQT specification. The `MoqtParser` would identify the message type, extract relevant fields (like track names, object IDs, payload), and pass this information to other parts of the browser.
* **JavaScript (Receiver):**  The JavaScript application on the client side would receive the parsed data (likely through WebTransport's event listeners) and could then display the video.

**Logical Inference with Assumptions:**

Let's take the `TwoPartMessage` test case as an example:

* **Assumption:** The `MakeMessage()` function, based on the `message_type_`, correctly creates a sample MOQT message as a byte string.
* **Input:** The `ProcessData()` function is called twice:
    1. First call with the first half of the message's byte string and `fin = false`.
    2. Second call with the remaining half of the message's byte string and `fin = true`.
* **Output:** The `visitor_.messages_received_` counter should be 1 after the second call, and `visitor_.last_message_` should contain the parsed message data. `visitor_.parsing_error_` should be empty.

**User or Programming Errors:**

* **Incorrect Message Construction:**  A common error would be a developer constructing an MOQT message with an incorrect length field. The `PayloadLengthTooLong` and `PayloadLengthTooShort` tests specifically check for this. For example, a developer might manually create a `SUBSCRIBE` message and calculate the length of the payload incorrectly.
* **Premature Stream Closure:** Sending a FIN bit too early (as tested by `EarlyFin` and `SeparateEarlyFin`) could happen due to errors in the application's logic for managing the WebTransport stream or QUIC stream.
* **Sending Data in Incorrect Chunks:** While less likely for typical usage, the `OneByteAtATime` and `TwoBytesAtATime` tests implicitly show how the parser should handle data arriving in arbitrary chunk sizes. An error in a custom implementation might lead to sending data in a way that the parser struggles with.

**User Operation to Reach This Code (Debugging):**

1. **User experiences an issue with a web application using MOQT over WebTransport:**  The user might see video streaming issues, errors in receiving data, or the application might behave unexpectedly.
2. **Developer investigates:** The developer might use browser developer tools to inspect network traffic and see malformed MOQT messages or errors related to WebTransport streams.
3. **Suspecting parsing issues:** The developer might suspect that the browser isn't correctly parsing the MOQT messages.
4. **Navigating the Chromium source code:** The developer would then navigate the Chromium source code to the MOQT parsing logic, likely starting with files like `moqt_parser.cc` and its associated tests in `moqt_parser_test.cc`.
5. **Setting breakpoints and running tests:** To understand the parsing process, the developer might set breakpoints in the `MoqtControlParser::ProcessData` or `MoqtDataParser::ProcessData` functions within the test environment to step through the code with specific test messages and observe how the parsing occurs and if any errors are encountered. They might run specific tests from `moqt_parser_test.cc` to isolate the problem.

In summary, this first part of `moqt_parser_test.cc` lays the foundation for thoroughly testing the MOQT parser implementation in Chromium, covering various message types, data arrival scenarios, and error conditions. While not directly JavaScript, it's crucial for enabling web applications to use MOQT effectively over WebTransport.

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/moqt_parser_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_parser.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/types/variant.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/test_tools/moqt_test_message.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace moqt::test {

namespace {

using ::testing::AnyOf;
using ::testing::HasSubstr;
using ::testing::Optional;

constexpr std::array kMessageTypes{
    MoqtMessageType::kSubscribe,
    MoqtMessageType::kSubscribeOk,
    MoqtMessageType::kSubscribeError,
    MoqtMessageType::kSubscribeUpdate,
    MoqtMessageType::kUnsubscribe,
    MoqtMessageType::kSubscribeDone,
    MoqtMessageType::kAnnounceCancel,
    MoqtMessageType::kTrackStatusRequest,
    MoqtMessageType::kTrackStatus,
    MoqtMessageType::kAnnounce,
    MoqtMessageType::kAnnounceOk,
    MoqtMessageType::kAnnounceError,
    MoqtMessageType::kUnannounce,
    MoqtMessageType::kClientSetup,
    MoqtMessageType::kServerSetup,
    MoqtMessageType::kGoAway,
    MoqtMessageType::kSubscribeAnnounces,
    MoqtMessageType::kSubscribeAnnouncesOk,
    MoqtMessageType::kSubscribeAnnouncesError,
    MoqtMessageType::kUnsubscribeAnnounces,
    MoqtMessageType::kMaxSubscribeId,
    MoqtMessageType::kFetch,
    MoqtMessageType::kFetchCancel,
    MoqtMessageType::kFetchOk,
    MoqtMessageType::kFetchError,
    MoqtMessageType::kObjectAck,
};
constexpr std::array kDataStreamTypes{
    MoqtDataStreamType::kStreamHeaderTrack,
    MoqtDataStreamType::kStreamHeaderSubgroup,
    MoqtDataStreamType::kStreamHeaderFetch,
};

using GeneralizedMessageType =
    absl::variant<MoqtMessageType, MoqtDataStreamType>;
}  // namespace

struct MoqtParserTestParams {
  MoqtParserTestParams(MoqtMessageType message_type, bool uses_web_transport)
      : message_type(message_type), uses_web_transport(uses_web_transport) {}
  explicit MoqtParserTestParams(MoqtDataStreamType message_type)
      : message_type(message_type), uses_web_transport(true) {}
  GeneralizedMessageType message_type;
  bool uses_web_transport;
};

std::vector<MoqtParserTestParams> GetMoqtParserTestParams() {
  std::vector<MoqtParserTestParams> params;

  for (MoqtMessageType message_type : kMessageTypes) {
    if (message_type == MoqtMessageType::kClientSetup) {
      for (const bool uses_web_transport : {false, true}) {
        params.push_back(
            MoqtParserTestParams(message_type, uses_web_transport));
      }
    } else {
      // All other types are processed the same for either perspective or
      // transport.
      params.push_back(MoqtParserTestParams(message_type, true));
    }
  }
  for (MoqtDataStreamType type : kDataStreamTypes) {
    params.push_back(MoqtParserTestParams(type));
  }
  return params;
}

std::string TypeFormatter(MoqtMessageType type) {
  return MoqtMessageTypeToString(type);
}
std::string TypeFormatter(MoqtDataStreamType type) {
  return MoqtDataStreamTypeToString(type);
}
std::string ParamNameFormatter(
    const testing::TestParamInfo<MoqtParserTestParams>& info) {
  return absl::visit([](auto x) { return TypeFormatter(x); },
                     info.param.message_type) +
         "_" + (info.param.uses_web_transport ? "WebTransport" : "QUIC");
}

class MoqtParserTestVisitor : public MoqtControlParserVisitor,
                              public MoqtDataParserVisitor {
 public:
  ~MoqtParserTestVisitor() = default;

  void OnObjectMessage(const MoqtObject& message, absl::string_view payload,
                       bool end_of_message) override {
    MoqtObject object = message;
    object_payloads_.push_back(std::string(payload));
    end_of_message_ = end_of_message;
    if (end_of_message) {
      ++messages_received_;
    }
    last_message_ = TestMessageBase::MessageStructuredData(object);
  }
  template <typename Message>
  void OnControlMessage(const Message& message) {
    end_of_message_ = true;
    ++messages_received_;
    last_message_ = TestMessageBase::MessageStructuredData(message);
  }
  void OnClientSetupMessage(const MoqtClientSetup& message) override {
    OnControlMessage(message);
  }
  void OnServerSetupMessage(const MoqtServerSetup& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeMessage(const MoqtSubscribe& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeOkMessage(const MoqtSubscribeOk& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeErrorMessage(const MoqtSubscribeError& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeUpdateMessage(const MoqtSubscribeUpdate& message) override {
    OnControlMessage(message);
  }
  void OnUnsubscribeMessage(const MoqtUnsubscribe& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeDoneMessage(const MoqtSubscribeDone& message) override {
    OnControlMessage(message);
  }
  void OnAnnounceMessage(const MoqtAnnounce& message) override {
    OnControlMessage(message);
  }
  void OnAnnounceOkMessage(const MoqtAnnounceOk& message) override {
    OnControlMessage(message);
  }
  void OnAnnounceErrorMessage(const MoqtAnnounceError& message) override {
    OnControlMessage(message);
  }
  void OnAnnounceCancelMessage(const MoqtAnnounceCancel& message) override {
    OnControlMessage(message);
  }
  void OnTrackStatusRequestMessage(
      const MoqtTrackStatusRequest& message) override {
    OnControlMessage(message);
  }
  void OnUnannounceMessage(const MoqtUnannounce& message) override {
    OnControlMessage(message);
  }
  void OnTrackStatusMessage(const MoqtTrackStatus& message) override {
    OnControlMessage(message);
  }
  void OnGoAwayMessage(const MoqtGoAway& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeAnnouncesMessage(
      const MoqtSubscribeAnnounces& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeAnnouncesOkMessage(
      const MoqtSubscribeAnnouncesOk& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeAnnouncesErrorMessage(
      const MoqtSubscribeAnnouncesError& message) override {
    OnControlMessage(message);
  }
  void OnUnsubscribeAnnouncesMessage(
      const MoqtUnsubscribeAnnounces& message) override {
    OnControlMessage(message);
  }
  void OnMaxSubscribeIdMessage(const MoqtMaxSubscribeId& message) override {
    OnControlMessage(message);
  }
  void OnFetchMessage(const MoqtFetch& message) override {
    OnControlMessage(message);
  }
  void OnFetchCancelMessage(const MoqtFetchCancel& message) override {
    OnControlMessage(message);
  }
  void OnFetchOkMessage(const MoqtFetchOk& message) override {
    OnControlMessage(message);
  }
  void OnFetchErrorMessage(const MoqtFetchError& message) override {
    OnControlMessage(message);
  }
  void OnObjectAckMessage(const MoqtObjectAck& message) override {
    OnControlMessage(message);
  }
  void OnParsingError(MoqtError code, absl::string_view reason) override {
    QUIC_LOG(INFO) << "Parsing error: " << reason;
    parsing_error_ = reason;
    parsing_error_code_ = code;
  }

  std::string object_payload() { return absl::StrJoin(object_payloads_, ""); }

  std::vector<std::string> object_payloads_;
  bool end_of_message_ = false;
  std::optional<std::string> parsing_error_;
  MoqtError parsing_error_code_;
  uint64_t messages_received_ = 0;
  std::optional<TestMessageBase::MessageStructuredData> last_message_;
};

class MoqtParserTest
    : public quic::test::QuicTestWithParam<MoqtParserTestParams> {
 public:
  MoqtParserTest()
      : message_type_(GetParam().message_type),
        webtrans_(GetParam().uses_web_transport),
        control_parser_(GetParam().uses_web_transport, visitor_),
        data_parser_(&visitor_) {}

  bool IsDataStream() {
    return absl::holds_alternative<MoqtDataStreamType>(message_type_);
  }

  std::unique_ptr<TestMessageBase> MakeMessage() {
    if (IsDataStream()) {
      return CreateTestDataStream(absl::get<MoqtDataStreamType>(message_type_));
    } else {
      return CreateTestMessage(absl::get<MoqtMessageType>(message_type_),
                               webtrans_);
    }
  }

  void ProcessData(absl::string_view data, bool fin) {
    if (IsDataStream()) {
      data_parser_.ProcessData(data, fin);
    } else {
      control_parser_.ProcessData(data, fin);
    }
  }

 protected:
  MoqtParserTestVisitor visitor_;
  GeneralizedMessageType message_type_;
  bool webtrans_;
  MoqtControlParser control_parser_;
  MoqtDataParser data_parser_;
};

INSTANTIATE_TEST_SUITE_P(MoqtParserTests, MoqtParserTest,
                         testing::ValuesIn(GetMoqtParserTestParams()),
                         ParamNameFormatter);

TEST_P(MoqtParserTest, OneMessage) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  ProcessData(message->PacketSample(), true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, OneMessageWithLongVarints) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->ExpandVarints();
  ProcessData(message->PacketSample(), true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, TwoPartMessage) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  // The test Object message has payload for less then half the message length,
  // so splitting the message in half will prevent the first half from being
  // processed.
  size_t first_data_size = message->total_message_size() / 2;
  ProcessData(message->PacketSample().substr(0, first_data_size), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  ProcessData(
      message->PacketSample().substr(
          first_data_size, message->total_message_size() - first_data_size),
      true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, OneByteAtATime) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  for (size_t i = 0; i < message->total_message_size(); ++i) {
    EXPECT_EQ(visitor_.messages_received_, 0);
    EXPECT_FALSE(visitor_.end_of_message_);
    bool last = i == (message->total_message_size() - 1);
    ProcessData(message->PacketSample().substr(i, 1), last);
  }
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, OneByteAtATimeLongerVarints) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->ExpandVarints();
  for (size_t i = 0; i < message->total_message_size(); ++i) {
    EXPECT_EQ(visitor_.messages_received_, 0);
    EXPECT_FALSE(visitor_.end_of_message_);
    bool last = i == (message->total_message_size() - 1);
    ProcessData(message->PacketSample().substr(i, 1), last);
  }
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, TwoBytesAtATime) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  data_parser_.set_chunk_size(1);
  for (size_t i = 0; i < message->total_message_size(); i += 3) {
    EXPECT_EQ(visitor_.messages_received_, 0);
    EXPECT_FALSE(visitor_.end_of_message_);
    bool last = (i + 2) >= message->total_message_size();
    ProcessData(message->PacketSample().substr(i, 3), last);
  }
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, EarlyFin) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  size_t first_data_size = message->total_message_size() - 1;
  ProcessData(message->PacketSample().substr(0, first_data_size), true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_THAT(visitor_.parsing_error_,
              AnyOf("FIN after incomplete message",
                    "FIN received at an unexpected point in the stream"));
}

TEST_P(MoqtParserTest, SeparateEarlyFin) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  size_t first_data_size = message->total_message_size() - 1;
  ProcessData(message->PacketSample().substr(0, first_data_size), false);
  ProcessData(absl::string_view(), true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_THAT(visitor_.parsing_error_,
              AnyOf("End of stream before complete message",
                    "FIN received at an unexpected point in the stream"));
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_P(MoqtParserTest, PayloadLengthTooLong) {
  if (IsDataStream()) {
    return;
  }
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->IncreasePayloadLengthByOne();
  ProcessData(message->PacketSample(), false);
  // The parser will actually report a message, because it's all there.
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_EQ(visitor_.parsing_error_,
            "Message length does not match payload length");
}

TEST_P(MoqtParserTest, PayloadLengthTooShort) {
  if (IsDataStream()) {
    return;
  }
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->DecreasePayloadLengthByOne();
  ProcessData(message->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_EQ(visitor_.parsing_error_,
            "Message length does not match payload length");
}

// Tests for message-specific error cases, and behaviors for a single message
// type.
class MoqtMessageSpecificTest : public quic::test::QuicTest {
 public:
  MoqtMessageSpecificTest() {}

  MoqtParserTestVisitor visitor_;

  static constexpr bool kWebTrans = true;
  static constexpr bool kRawQuic = false;
};

// Send the header + some payload, pure payload, then pure payload to end the
// message.
TEST_F(MoqtMessageSpecificTest, ThreePartObject) {
  MoqtDataParser parser(&visitor_);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>();
  EXPECT_TRUE(message->SetPayloadLength(14));
  parser.ProcessData(message->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_FALSE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "foo");

  // second part
  parser.ProcessData("bar", false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_FALSE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "foobar");

  // third part includes FIN
  parser.ProcessData("deadbeef", true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "foobardeadbeef");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

// Send the part of header, rest of header + payload, plus payload.
TEST_F(MoqtMessageSpecificTest, ThreePartObjectFirstIncomplete) {
  MoqtDataParser parser(&visitor_);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>();
  EXPECT_TRUE(message->SetPayloadLength(51));

  // first part
  parser.ProcessData(message->PacketSample().substr(0, 4), false);
  EXPECT_EQ(visitor_.messages_received_, 0);

  // second part. Add padding to it.
  message->set_wire_image_size(55);
  parser.ProcessData(
      message->PacketSample().substr(4, message->total_message_size() - 4),
      false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_FALSE(visitor_.end_of_message_);
  // The value "48" is the overall wire image size of 55 minus the non-payload
  // part of the message.
  EXPECT_EQ(visitor_.object_payload().length(), 48);

  // third part includes FIN
  parser.ProcessData("bar", true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(*visitor_.object_payloads_.crbegin(), "bar");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, StreamHeaderSubgroupFollowOn) {
  MoqtDataParser parser(&visitor_);
  // first part
  auto message1 = std::make_unique<StreamHeaderSubgroupMessage>();
  parser.ProcessData(message1->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message1->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "foo");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  // second part
  visitor_.object_payloads_.clear();
  auto message2 = std::make_unique<StreamMiddlerSubgroupMessage>();
  parser.ProcessData(message2->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message2->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "bar");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, StreamHeaderTrackFollowOn) {
  MoqtDataParser parser(&visitor_);
  // first part
  auto message1 = std::make_unique<StreamHeaderTrackMessage>();
  parser.ProcessData(message1->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message1->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "foo");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  // second part
  visitor_.object_payloads_.clear();
  auto message2 = std::make_unique<StreamMiddlerTrackMessage>();
  parser.ProcessData(message2->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message2->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "bar");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, ClientSetupRoleIsInvalid) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x0c, 0x02, 0x01, 0x02,  // versions
      0x03,                                // 3 params
      0x00, 0x01, 0x04,                    // role = invalid
      0x01, 0x03, 0x66, 0x6f, 0x6f         // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Invalid ROLE parameter");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, ServerSetupRoleIsInvalid) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x41, 0x0a, 0x01,
      0x01,                         // 1 param
      0x00, 0x01, 0x04,             // role = invalid
      0x01, 0x03, 0x66, 0x6f, 0x6f  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Invalid ROLE parameter");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SetupRoleAppearsTwice) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x0f, 0x02, 0x01, 0x02,  // versions
      0x03,                                // 3 params
      0x00, 0x01, 0x03,                    // role = PubSub
      0x00, 0x01, 0x03,                    // role = PubSub
      0x01, 0x03, 0x66, 0x6f, 0x6f         // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "ROLE parameter appears twice in SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, ClientSetupRoleIsMissing) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x09, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x01,                                // 1 param
      0x01, 0x03, 0x66, 0x6f, 0x6f,        // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "ROLE parameter missing from CLIENT_SETUP message");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, ClientSetupMaxSubscribeIdAppearsTwice) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x12, 0x02, 0x01, 0x02,  // versions
      0x04,                                // 4 params
      0x00, 0x01, 0x03,                    // role = PubSub
      0x01, 0x03, 0x66, 0x6f, 0x6f,        // path = "foo"
      0x02, 0x01, 0x32,                    // max_subscribe_id = 50
      0x02, 0x01, 0x32,                    // max_subscribe_id = 50
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "MAX_SUBSCRIBE_ID parameter appears twice in SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, ServerSetupRoleIsMissing) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x41, 0x02, 0x01, 0x00,  // 1 param
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "ROLE parameter missing from SERVER_SETUP message");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SetupRoleVarintLengthIsWrong) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x0c,             // type
      0x02, 0x01, 0x02,             // versions
      0x02,                         // 2 parameters
      0x00, 0x02, 0x03,             // role = PubSub, but length is 2
      0x01, 0x03, 0x66, 0x6f, 0x6f  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "Parameter length does not match varint encoding");

  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kParameterLengthMismatch);
}

TEST_F(MoqtMessageSpecificTest, SetupPathFromServer) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x41, 0x07,
      0x01,                          // version = 1
      0x01,                          // 1 param
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "PATH parameter in SERVER_SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SetupPathAppearsTwice) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x11, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x03,                                // 3 params
      0x00, 0x01, 0x03,                    // role = PubSub
      0x01, 0x03, 0x66, 0x6f, 0x6f,        // path = "foo"
      0x01, 0x03, 0x66, 0x6f, 0x6f,        // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "PATH parameter appears twice in CLIENT_SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SetupPathOverWebtrans) {
  MoqtControlParser parser(kWebTrans, visitor_);
  char setup[] = {
      0x40, 0x40, 0x0b, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x02,                                // 2 params
      0x00, 0x01, 0x03,                    // role = PubSub
      0x01, 0x03, 0x66, 0x6f, 0x6f,        // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "WebTransport connection is using PATH parameter in SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SetupPathMissing) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x07, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x01,                                // 1 param
      0x00, 0x01, 0x03,                    // role = PubSub
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "PATH SETUP parameter missing from Client message over QUIC");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, ServerSetupMaxSubscribeIdAppearsTwice) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x12, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x04,                                // 4 params
      0x00, 0x01, 0x03,                    // role = PubSub
      0x01, 0x03, 0x66, 0x6f, 0x6f,        // path = "foo"
      0x02, 0x01, 0x32,                    // max_subscribe_id = 50
      0x02, 0x01, 0x32,                    // max_subscribe_id = 50
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "MAX_SUBSCRIBE_ID parameter appears twice in SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeAuthorizationInfoTwice) {
  MoqtControlParser parser(kWebTrans, visitor_);
  char subscribe[] = {
      0x03, 0x1a, 0x01, 0x02, 0x01,
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x02,                          // filter_type = kLatestObject
      0x02,                          // two params
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "AUTHORIZATION_INFO parameter appears twice");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeDeliveryTimeoutTwice) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x18, 0x01, 0x02, 0x01,
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x02,                          // filter_type = kLatestObject
      0x02,                          // two params
      0x03, 0x02, 0x67, 0x10,        // delivery_timeout = 10000
      0x03, 0x02, 0x67, 0x10,        // delivery_timeout = 10000
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "DELIVERY_TIMEOUT parameter appears twice");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeDeliveryTimeoutMalformed) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x14, 0x01, 0x02, 0x01,
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x02,                          // filter_type = kLatestObject
      0x01,                          // one param
      0x03, 0x01, 0x67, 0x10,        // delivery_timeout = 10000
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "Parameter length does not match varint encoding");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kParameterLengthMismatch);
}

TEST_F(MoqtMessageSpecificTest, SubscribeMaxCacheDurationTwice) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x18, 0x01, 0x02, 0x01,
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x02,                          // filter_type = kLatestObject
      0x02,                          // two params
      0x04, 0x02, 0x67, 0x10,        // max_cache_duration = 10000
      0x04, 0x02, 0x67, 0x10,        // max_cache_duration = 10000
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "MAX_CACHE_DURATION parameter appears twice");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeMaxCacheDurationMalformed) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x14, 0x01, 0x02, 0x01,
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x02,                          // filter_type = kLatestObject
      0x01,                          // one param
      0x04, 0x01, 0x67, 0x10,        // max_cache_duration = 10000
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "Parameter length does not match varint encoding");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kParameterLengthMismatch);
}

TEST_F(MoqtMessageSpecificTest, SubscribeOkHasAuthorizationInfo) {
  MoqtControlParser parser(kWebTrans, visitor_);
  char subscribe_ok[] = {
      0x04, 0x10, 0x01, 0x03,  // subscribe_id = 1, expires = 3
      0x02, 0x01,              // group_order = 2, content exists
      0x0c, 0x14,              // largest_group_id = 12, largest_object_id = 20,
      0x02,                    // 2 parameters
      0x03, 0x02, 0x67, 0x10,  // delivery_timeout = 10000
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_
"""


```