Response:
The user is asking for a summary of the functionality of the C++ source code file `net/third_party/quiche/src/quiche/quic/moqt/moqt_parser_test.cc`, which is part 2 of 2. I need to understand what this part of the code does based on the provided test cases.

Looking at the test case names and their assertions, I can infer the following:

1. **Error Handling for Invalid Message Structures:**  The tests check for specific error conditions within different MoQT messages (e.g., `SUBSCRIBE_OK` with authorization info, `ANNOUNCE` with delivery timeout, duplicate parameters).
2. **Handling of `FIN` (End of Stream):** Tests verify how the parser reacts to receiving a `FIN` signal at unexpected points in the data stream (mid-payload, after partial payload) and receiving data after a `FIN`.
3. **Validation of Object Status:** A test confirms the parser correctly identifies invalid object status values.
4. **Size Limits for Control Messages:** A test checks the parser's behavior when encountering a large control message exceeding the size limit.
5. **Handling Unknown Message Types:** A test verifies the parser's reaction to an unknown message type.
6. **Validation of Filtering Options in `SUBSCRIBE` Messages:** Several tests focus on validating different filtering options in `SUBSCRIBE` messages, such as `LatestGroup`, `LatestObject`, `AbsoluteStart`, and `AbsoluteRange`, including checks for invalid ranges and delivery orders.
7. **Validation of `SUBSCRIBE_UPDATE` Messages:** Tests cover scenarios with invalid end group and end object values in `SUBSCRIBE_UPDATE` messages.
8. **Handling of Negative Time Deltas in `OBJECT_ACK` Messages:** A test ensures the parser can correctly handle negative time deltas in object acknowledgments.
9. **End-to-End Parsing of Multiple Messages:** A test simulates processing a sequence of different message types to ensure the parser can handle them correctly.
10. **Datagram Parsing:** Tests verify the successful parsing of datagram messages and the handling of incorrect or truncated datagrams.
11. **Specific Validations for `SUBSCRIBE_OK` and `SUBSCRIBE_DONE`:** Tests validate specific fields like `ContentExists` and delivery order in `SUBSCRIBE_OK` and `SUBSCRIBE_DONE` messages.
12. **Validation of `FETCH` Messages:** Tests check for invalid range and group order values in `FETCH` messages.
13. **Handling Padding Streams:** A test confirms that padding streams are correctly ignored.

Based on these observations, the primary function of this part of the code is to test the robustness and correctness of the MoQT control and data parsers by feeding them various valid and invalid message structures and verifying the expected outcomes (successful parsing or specific error detection).
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/moqt/moqt_parser_test.cc` 文件的第二部分，延续了第一部分的功能，主要集中在对 MoQT 协议中特定消息格式和字段进行更细致的测试，特别是针对各种错误情况和边界情况的处理。

**归纳一下它的功能：**

这部分代码的功能是 **对 MoQT 协议解析器的特定消息类型和字段进行详细的单元测试，并着重测试解析器在遇到各种错误或异常情况时的处理能力。**  它通过构造不同的消息数据（包括有效和无效的数据），并使用 `MoqtControlParser` 和 `MoqtDataParser` 进行解析，然后验证解析结果（例如，是否成功解析消息，是否产生了预期的错误，错误类型和错误码是否正确）。

具体来说，这部分测试涵盖了以下几个方面：

1. **特定字段的约束和验证:**
   - 测试某些消息中不应存在的字段（例如，`SUBSCRIBE_OK` 或 `SUBSCRIBE_UPDATE` 消息中包含 `authorization_info`，`ANNOUNCE` 消息中包含 `delivery_timeout`）。
   - 测试重复出现的字段（例如，`ANNOUNCE` 消息中 `AUTHORIZATION_INFO` 参数出现两次）。

2. **`FIN` 信号处理:**
   - 测试在数据流中意外收到 `FIN` 信号的情况（例如，在消息有效负载中间或部分接收后收到 `FIN`）。
   - 测试在 `FIN` 信号之后继续收到数据的情况。

3. **对象状态验证:**
   - 测试解析器是否能够识别并处理无效的对象状态值。

4. **消息大小限制:**
   - 测试对于非对象类型的控制消息，当消息大小超过限制时，解析器是否能够正确处理。

5. **未知消息类型处理:**
   - 测试解析器遇到未知的消息类型时是否能够产生正确的错误。

6. **`SUBSCRIBE` 消息的过滤选项验证:**
   - 测试 `SUBSCRIBE` 消息中各种过滤类型（`kLatestGroup`, `kLatestObject`, `kAbsoluteStart`, `kAbsoluteRange`）的解析和参数验证，包括对起始和结束 group/object ID 的有效性检查，以及对 delivery order 的校验。

7. **`SUBSCRIBE_UPDATE` 消息的验证:**
   - 测试 `SUBSCRIBE_UPDATE` 消息中起始和结束 group/object ID 的有效性检查。
   - 测试 `SUBSCRIBE_UPDATE` 消息中 `end_object` 存在但 `end_group` 不存在的情况。

8. **`OBJECT_ACK` 消息的验证:**
   - 测试 `OBJECT_ACK` 消息中负的时间差（`delta_from_deadline`）的解析。

9. **多消息混合解析:**
   - 测试解析器能否正确处理连续接收到的多个不同类型的消息。

10. **Datagram 消息解析:**
    - 测试成功解析 Datagram 消息的情况，并验证解析出的元数据和 payload。
    - 测试解析错误的或截断的 Datagram 消息的情况。

11. **`SUBSCRIBE_OK` 和 `SUBSCRIBE_DONE` 消息的特定字段验证:**
    - 测试 `SUBSCRIBE_OK` 和 `SUBSCRIBE_DONE` 消息中 `ContentExists` 字段的无效值。
    - 测试 `SUBSCRIBE_OK` 消息中无效的 group order 值。

12. **`FETCH` 消息的验证:**
    - 测试 `FETCH` 消息中起始和结束 object ID 的无效范围。
    - 测试 `FETCH` 消息中无效的 group order 值。

13. **Padding Stream 处理:**
    - 测试解析器是否能够正确处理和忽略 Padding Stream。

**与 JavaScript 功能的关系及举例说明：**

MoQT 协议是为在 WebTransport 上进行媒体传输而设计的。虽然这个 C++ 代码直接在 Chromium 的网络栈中运行，不涉及 JavaScript，但它所测试的解析逻辑对于最终在 JavaScript 中使用 MoQT 的开发者来说至关重要。

假设一个 JavaScript 应用使用 WebTransport 与服务器进行 MoQT 通信：

- **解析错误处理:**  如果 JavaScript 应用发送了一个格式错误的 `SUBSCRIBE` 消息（例如，包含了不应该存在的 `authorization_info`），那么后端 C++ 解析器（被这个测试代码覆盖）会检测到这个错误。虽然 JavaScript 代码本身没有直接运行到这个 C++ 测试代码，但这个测试保证了 C++ 后端能够正确地识别并处理这种错误，从而可以向 JavaScript 应用返回一个错误指示，帮助开发者调试问题。

**逻辑推理、假设输入与输出：**

以 `TEST_F(MoqtMessageSpecificTest, SubscribeOkHasAuthorizationInfo)` 为例：

* **假设输入:**  一段二进制数据，表示一个格式错误的 `SUBSCRIBE_OK` 消息，其中包含了 `authorization_info` 参数。
* **逻辑推理:**  根据 MoQT 协议规范，`SUBSCRIBE_OK` 消息不应该包含 `authorization_info`。解析器应该检测到这个错误。
* **预期输出:**  `visitor_.messages_received_` 应该为 0 (没有成功解析出消息)，`visitor_.parsing_error_` 应该包含 "SUBSCRIBE_OK has authorization info" 的错误描述，`visitor_.parsing_error_code_` 应该为 `MoqtError::kProtocolViolation`。

**用户或编程常见的使用错误举例说明：**

* **错误构造 `SUBSCRIBE` 消息:**  开发者可能错误地在客户端代码中构建了一个包含 `authorization_info` 的 `SUBSCRIBE_OK` 消息并发送到服务器。这个测试确保了服务器能够识别出这种错误，并可以采取适当的措施（例如，断开连接或发送错误响应）。
* **没有正确处理 `FIN` 信号:** 开发者可能在发送完一部分数据后就认为传输完成，提前发送了 `FIN` 信号，而实际上还有一部分数据需要发送。或者，开发者可能没有正确处理接收到的 `FIN` 信号，导致在连接已经关闭后还在尝试接收数据。这些测试场景帮助验证了底层解析器在这些情况下的行为是否符合预期。
* **使用了无效的对象状态值:** 在某些场景下，开发者可能会尝试发送带有自定义对象状态的数据，而这个状态值可能超出了协议允许的范围。这个测试确保了解析器能够识别并拒绝这些无效的状态值。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户尝试使用一个 MoQT 应用：**  用户可能正在观看一个直播流或访问一个使用 MoQT 协议的应用。
2. **客户端发送 MoQT 消息：**  用户的操作（例如，点击“订阅”按钮）触发客户端 JavaScript 代码生成并发送一个 `SUBSCRIBE` 消息给服务器。
3. **服务器接收 WebTransport 连接的数据流：**  服务器的网络栈接收到来自客户端的 WebTransport 数据流。
4. **MoqtControlParser 处理数据：**  服务器端的 `MoqtControlParser` 类（被这个测试文件测试）负责解析接收到的数据。
5. **触发测试用例中的场景：** 如果客户端发送的 `SUBSCRIBE` 消息中错误地包含了 `authorization_info`，那么服务器端的 `MoqtControlParser` 在解析时就会触发 `TEST_F(MoqtMessageSpecificTest, SubscribeOkHasAuthorizationInfo)`  这类测试用例所模拟的场景。
6. **解析错误被捕获：**  `MoqtControlParser` 会检测到协议违规，设置 `visitor_.parsing_error_` 和 `visitor_.parsing_error_code_`。
7. **服务器采取行动：**  根据解析错误，服务器可能会断开与客户端的连接，发送错误响应，或者记录错误日志。
8. **开发者调试：**  如果用户遇到了问题，开发者可以通过查看服务器端的日志或使用网络抓包工具来分析客户端发送的消息，并比对服务器端的错误信息。这个测试文件中的测试用例可以帮助开发者理解服务器端是如何解析和验证这些消息的，从而定位问题所在。

总而言之，这部分测试代码是确保 MoQT 协议解析器健壮性和正确性的重要组成部分，它模拟了各种可能出现的错误场景，帮助开发者在早期发现并修复潜在的协议解析问题，从而提高基于 MoQT 协议的应用的稳定性和可靠性。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/moqt_parser_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
view(subscribe_ok, sizeof(subscribe_ok)),
                     false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_, "SUBSCRIBE_OK has authorization info");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeUpdateHasAuthorizationInfo) {
  MoqtControlParser parser(kWebTrans, visitor_);
  char subscribe_update[] = {
      0x02, 0x0c, 0x02, 0x03, 0x01, 0x05, 0x06,  // start and end sequences
      0xaa,                                      // priority = 0xaa
      0x01,                                      // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,              // authorization_info = "bar"
  };
  parser.ProcessData(
      absl::string_view(subscribe_update, sizeof(subscribe_update)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_, "SUBSCRIBE_UPDATE has authorization info");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, AnnounceAuthorizationInfoTwice) {
  MoqtControlParser parser(kWebTrans, visitor_);
  char announce[] = {
      0x06, 0x10, 0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x02,                                      // 2 params
      0x02, 0x03, 0x62, 0x61, 0x72,              // authorization_info = "bar"
      0x02, 0x03, 0x62, 0x61, 0x72,              // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(announce, sizeof(announce)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "AUTHORIZATION_INFO parameter appears twice");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, AnnounceHasDeliveryTimeout) {
  MoqtControlParser parser(kWebTrans, visitor_);
  char announce[] = {
      0x06, 0x0f, 0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x02,                                      // 2 params
      0x02, 0x03, 0x62, 0x61, 0x72,              // authorization_info = "bar"
      0x03, 0x02, 0x67, 0x10,                    // delivery_timeout = 10000
  };
  parser.ProcessData(absl::string_view(announce, sizeof(announce)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "ANNOUNCE has delivery timeout");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, FinMidPayload) {
  MoqtDataParser parser(&visitor_);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>();
  parser.ProcessData(
      message->PacketSample().substr(0, message->total_message_size() - 1),
      true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "FIN received at an unexpected point in the stream");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, PartialPayloadThenFin) {
  MoqtDataParser parser(&visitor_);
  auto message = std::make_unique<StreamHeaderTrackMessage>();
  parser.ProcessData(
      message->PacketSample().substr(0, message->total_message_size() - 1),
      false);
  parser.ProcessData(absl::string_view(), true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "FIN received at an unexpected point in the stream");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, DataAfterFin) {
  MoqtControlParser parser(kRawQuic, visitor_);
  parser.ProcessData(absl::string_view(), true);  // Find FIN
  parser.ProcessData("foo", false);
  EXPECT_EQ(visitor_.parsing_error_, "Data after end of stream");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, InvalidObjectStatus) {
  MoqtDataParser parser(&visitor_);
  char stream_header_subgroup[] = {
      0x04,              // type field
      0x04, 0x05, 0x08,  // varints
      0x07,              // publisher priority
      0x06, 0x00, 0x0f,  // object middler; status = 0x0f
  };
  parser.ProcessData(
      absl::string_view(stream_header_subgroup, sizeof(stream_header_subgroup)),
      false);
  EXPECT_EQ(visitor_.parsing_error_, "Invalid object status provided");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, Setup2KB) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char big_message[2 * kMaxMessageHeaderSize];
  quic::QuicDataWriter writer(sizeof(big_message), big_message);
  writer.WriteVarInt62(static_cast<uint64_t>(MoqtMessageType::kServerSetup));
  writer.WriteVarInt62(8 + kMaxMessageHeaderSize);
  writer.WriteVarInt62(0x1);                    // version
  writer.WriteVarInt62(0x1);                    // num_params
  writer.WriteVarInt62(0xbeef);                 // unknown param
  writer.WriteVarInt62(kMaxMessageHeaderSize);  // very long parameter
  writer.WriteRepeatedByte(0x04, kMaxMessageHeaderSize);
  // Send incomplete message
  parser.ProcessData(absl::string_view(big_message, writer.length() - 1),
                     false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Cannot parse non-OBJECT messages > 2KB");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kInternalError);
}

TEST_F(MoqtMessageSpecificTest, UnknownMessageType) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char message[6];
  quic::QuicDataWriter writer(sizeof(message), message);
  writer.WriteVarInt62(0xbeef);  // unknown message type
  writer.WriteVarInt62(0x1);     // length
  writer.WriteVarInt62(0x1);     // payload
  parser.ProcessData(absl::string_view(message, writer.length()), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Unknown message type");
}

TEST_F(MoqtMessageSpecificTest, LatestGroup) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x15, 0x01, 0x02,        // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x01,                          // filter_type = kLatestGroup
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  ASSERT_TRUE(visitor_.last_message_.has_value());
  MoqtSubscribe message =
      std::get<MoqtSubscribe>(visitor_.last_message_.value());
  EXPECT_FALSE(message.start_group.has_value());
  EXPECT_EQ(message.start_object, 0);
  EXPECT_FALSE(message.end_group.has_value());
  EXPECT_FALSE(message.end_object.has_value());
}

TEST_F(MoqtMessageSpecificTest, LatestObject) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x15, 0x01, 0x02,        // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20, group order descending
      0x02,                          // filter_type = kLatestObject
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  MoqtSubscribe message =
      std::get<MoqtSubscribe>(visitor_.last_message_.value());
  EXPECT_FALSE(message.start_group.has_value());
  EXPECT_FALSE(message.start_object.has_value());
  EXPECT_FALSE(message.end_group.has_value());
  EXPECT_FALSE(message.end_object.has_value());
}

TEST_F(MoqtMessageSpecificTest, InvalidDeliveryOrder) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x15, 0x01, 0x02,        // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x08,                    // priority = 0x20 ???
      0x01,                          // filter_type = kLatestGroup
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_THAT(visitor_.parsing_error_, Optional(HasSubstr("group order")));
}

TEST_F(MoqtMessageSpecificTest, AbsoluteStart) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x17, 0x01, 0x02,        // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x03,                          // filter_type = kAbsoluteStart
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  MoqtSubscribe message =
      std::get<MoqtSubscribe>(visitor_.last_message_.value());
  EXPECT_EQ(message.start_group.value(), 4);
  EXPECT_EQ(message.start_object.value(), 1);
  EXPECT_FALSE(message.end_group.has_value());
  EXPECT_FALSE(message.end_object.has_value());
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeExplicitEndObject) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x19, 0x01, 0x02,        // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x04,                          // filter_type = kAbsoluteStart
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x07,                          // end_group = 7
      0x03,                          // end_object = 2
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  MoqtSubscribe message =
      std::get<MoqtSubscribe>(visitor_.last_message_.value());
  EXPECT_EQ(message.start_group.value(), 4);
  EXPECT_EQ(message.start_object.value(), 1);
  EXPECT_EQ(message.end_group.value(), 7);
  EXPECT_EQ(message.end_object.value(), 2);
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeWholeEndGroup) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x19, 0x01, 0x02,        // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x04,                          // filter_type = kAbsoluteRange
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x07,                          // end_group = 7
      0x00,                          // end whole group
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  MoqtSubscribe message =
      std::get<MoqtSubscribe>(visitor_.last_message_.value());
  EXPECT_EQ(message.start_group.value(), 4);
  EXPECT_EQ(message.start_object.value(), 1);
  EXPECT_EQ(message.end_group.value(), 7);
  EXPECT_FALSE(message.end_object.has_value());
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeEndGroupTooLow) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x19, 0x01, 0x02,        // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x04,                          // filter_type = kAbsoluteRange
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x03,                          // end_group = 3
      0x00,                          // end whole group
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "End group is less than start group");
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeExactlyOneObject) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x14, 0x01, 0x02,        // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x04,                          // filter_type = kAbsoluteRange
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x04,                          // end_group = 4
      0x02,                          // end object = 1
      0x00,                          // no parameters
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
}

TEST_F(MoqtMessageSpecificTest, SubscribeUpdateExactlyOneObject) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe_update[] = {
      0x02, 0x07, 0x02, 0x03, 0x01, 0x04, 0x07,  // start and end sequences
      0x20,                                      // priority
      0x00,                                      // No parameters
  };
  parser.ProcessData(
      absl::string_view(subscribe_update, sizeof(subscribe_update)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
}

TEST_F(MoqtMessageSpecificTest, SubscribeUpdateEndGroupTooLow) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe_update[] = {
      0x02, 0x0c, 0x02, 0x03, 0x01, 0x03, 0x06,  // start and end sequences
      0x20,                                      // priority
      0x01,                                      // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,              // authorization_info = "bar"
  };
  parser.ProcessData(
      absl::string_view(subscribe_update, sizeof(subscribe_update)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "End group is less than start group");
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeEndObjectTooLow) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x19, 0x01, 0x02,        // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x04,                          // filter_type = kAbsoluteRange
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x04,                          // end_group = 4
      0x01,                          // end_object = 0
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "End object comes before start object");
}

TEST_F(MoqtMessageSpecificTest, SubscribeUpdateEndObjectTooLow) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe_update[] = {
      0x02, 0x07, 0x02, 0x03, 0x02, 0x04, 0x01,  // start and end sequences
      0xf0, 0x00,                                // priority, no parameter
  };
  parser.ProcessData(
      absl::string_view(subscribe_update, sizeof(subscribe_update)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "End object comes before start object");
}

TEST_F(MoqtMessageSpecificTest, SubscribeUpdateNoEndGroup) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe_update[] = {
      0x02, 0x07, 0x02, 0x03, 0x02, 0x00, 0x01,  // start and end sequences
      0x20,                                      // priority
      0x00,                                      // No parameter
  };
  parser.ProcessData(
      absl::string_view(subscribe_update, sizeof(subscribe_update)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "SUBSCRIBE_UPDATE has end_object but no end_group");
}

TEST_F(MoqtMessageSpecificTest, ObjectAckNegativeDelta) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char object_ack[] = {
      0x71, 0x84, 0x05,  // type
      0x01, 0x10, 0x20,  // subscribe ID, group, object
      0x40, 0x81,        // -0x40 time delta
  };
  parser.ProcessData(absl::string_view(object_ack, sizeof(object_ack)), false);
  EXPECT_EQ(visitor_.parsing_error_, std::nullopt);
  ASSERT_EQ(visitor_.messages_received_, 1);
  MoqtObjectAck message =
      std::get<MoqtObjectAck>(visitor_.last_message_.value());
  EXPECT_EQ(message.subscribe_id, 0x01);
  EXPECT_EQ(message.group_id, 0x10);
  EXPECT_EQ(message.object_id, 0x20);
  EXPECT_EQ(message.delta_from_deadline,
            quic::QuicTimeDelta::FromMicroseconds(-0x40));
}

TEST_F(MoqtMessageSpecificTest, AllMessagesTogether) {
  char buffer[5000];
  MoqtControlParser parser(kRawQuic, visitor_);
  size_t write = 0;
  size_t read = 0;
  int fully_received = 0;
  std::unique_ptr<TestMessageBase> prev_message = nullptr;
  for (MoqtMessageType type : kMessageTypes) {
    // Each iteration, process from the halfway point of one message to the
    // halfway point of the next.
    std::unique_ptr<TestMessageBase> message =
        CreateTestMessage(type, kRawQuic);
    memcpy(buffer + write, message->PacketSample().data(),
           message->total_message_size());
    size_t new_read = write + message->total_message_size() / 2;
    parser.ProcessData(absl::string_view(buffer + read, new_read - read),
                       false);
    EXPECT_EQ(visitor_.messages_received_, fully_received);
    if (prev_message != nullptr) {
      EXPECT_TRUE(prev_message->EqualFieldValues(*visitor_.last_message_));
    }
    fully_received++;
    read = new_read;
    write += message->total_message_size();
    prev_message = std::move(message);
  }
  // Deliver the rest
  parser.ProcessData(absl::string_view(buffer + read, write - read), true);
  EXPECT_EQ(visitor_.messages_received_, fully_received);
  EXPECT_TRUE(prev_message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, DatagramSuccessful) {
  ObjectDatagramMessage message;
  MoqtObject object;
  absl::string_view payload = ParseDatagram(message.PacketSample(), object);
  TestMessageBase::MessageStructuredData object_metadata =
      TestMessageBase::MessageStructuredData(object);
  EXPECT_TRUE(message.EqualFieldValues(object_metadata));
  EXPECT_EQ(payload, "foo");
}

TEST_F(MoqtMessageSpecificTest, WrongMessageInDatagram) {
  StreamHeaderSubgroupMessage message;
  MoqtObject object;
  absl::string_view payload = ParseDatagram(message.PacketSample(), object);
  EXPECT_TRUE(payload.empty());
}

TEST_F(MoqtMessageSpecificTest, TruncatedDatagram) {
  ObjectDatagramMessage message;
  message.set_wire_image_size(4);
  MoqtObject object;
  absl::string_view payload = ParseDatagram(message.PacketSample(), object);
  EXPECT_TRUE(payload.empty());
}

TEST_F(MoqtMessageSpecificTest, VeryTruncatedDatagram) {
  char message = 0x40;
  MoqtObject object;
  absl::string_view payload =
      ParseDatagram(absl::string_view(&message, sizeof(message)), object);
  EXPECT_TRUE(payload.empty());
}

TEST_F(MoqtMessageSpecificTest, SubscribeOkInvalidContentExists) {
  MoqtControlParser parser(kRawQuic, visitor_);
  SubscribeOkMessage subscribe_ok;
  subscribe_ok.SetInvalidContentExists();
  parser.ProcessData(subscribe_ok.PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "SUBSCRIBE_OK ContentExists has invalid value");
}

TEST_F(MoqtMessageSpecificTest, SubscribeOkInvalidDeliveryOrder) {
  MoqtControlParser parser(kRawQuic, visitor_);
  SubscribeOkMessage subscribe_ok;
  subscribe_ok.SetInvalidDeliveryOrder();
  parser.ProcessData(subscribe_ok.PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "Invalid group order value in SUBSCRIBE_OK");
}

TEST_F(MoqtMessageSpecificTest, SubscribeDoneInvalidContentExists) {
  MoqtControlParser parser(kRawQuic, visitor_);
  SubscribeDoneMessage subscribe_done;
  subscribe_done.SetInvalidContentExists();
  parser.ProcessData(subscribe_done.PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "SUBSCRIBE_DONE ContentExists has invalid value");
}

TEST_F(MoqtMessageSpecificTest, FetchInvalidRange) {
  MoqtControlParser parser(kRawQuic, visitor_);
  FetchMessage fetch;
  fetch.SetEndObject(1, 1);
  parser.ProcessData(fetch.PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "End object comes before start object in FETCH");
}

TEST_F(MoqtMessageSpecificTest, FetchInvalidRange2) {
  MoqtControlParser parser(kRawQuic, visitor_);
  FetchMessage fetch;
  fetch.SetEndObject(0, std::nullopt);
  parser.ProcessData(fetch.PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "End object comes before start object in FETCH");
}

TEST_F(MoqtMessageSpecificTest, FetchInvalidGroupOrder) {
  MoqtControlParser parser(kRawQuic, visitor_);
  FetchMessage fetch;
  fetch.SetGroupOrder(3);
  parser.ProcessData(fetch.PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "Invalid group order value in FETCH message");
}

TEST_F(MoqtMessageSpecificTest, PaddingStream) {
  MoqtDataParser parser(&visitor_);
  std::string buffer(32, '\0');
  quic::QuicDataWriter writer(buffer.size(), buffer.data());
  ASSERT_TRUE(writer.WriteVarInt62(
      static_cast<uint64_t>(MoqtDataStreamType::kPadding)));
  for (int i = 0; i < 100; ++i) {
    parser.ProcessData(buffer, false);
    ASSERT_EQ(visitor_.messages_received_, 0);
    ASSERT_EQ(visitor_.parsing_error_, std::nullopt);
  }
}

}  // namespace moqt::test
```