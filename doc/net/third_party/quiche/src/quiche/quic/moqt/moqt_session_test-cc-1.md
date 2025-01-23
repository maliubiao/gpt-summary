Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file for the MoQ Transport protocol implementation in Chromium's network stack.

I need to analyze the code, identify the main features being tested, and then summarize them concisely. I should also look for any relationships to Javascript, logical inferences with examples, potential user errors, and debugging guidance.

Here's a breakdown of the code's main functionalities:

1. **Announce (Success & Failure):** Tests the handling of the `ANNOUNCE` message, both when it's successful and when an error occurs.
2. **Incoming Object (Full & Partial):** Tests how the `MoqtSession` handles incoming data objects, including complete objects and fragmented ones. It also checks behavior when buffering of partial objects is disabled.
3. **Object Before Subscribe (Success & Error):** Checks how the session handles receiving data objects before the corresponding `SUBSCRIBE_OK` or `SUBSCRIBE_ERROR` messages arrive.
4. **Early Object Forwarding Consistency:** Verifies that the forwarding preference of early objects matches the track's configured preference and doesn't change mid-track.
5. **Outgoing Data Stream Creation and Sending:** Tests the creation of unidirectional streams to send data objects, including queuing when streams cannot be opened immediately.
6. **Outgoing Stream Management:** Checks what happens when an outgoing stream disappears unexpectedly.
7. **Bidirectional Stream Handling (Client & Server):** Tests the establishment and error handling of the control bidirectional stream, ensuring only one is allowed.
8. **Unsubscribe Handling:** Tests the reception of `UNSUBSCRIBE` messages and the sending of `SUBSCRIBE_DONE`.
9. **Datagram Sending and Receiving:** Tests the transmission and reception of data objects via datagrams.
10. **Forwarding Preference Mismatch (Mid-Track):** Verifies the session closes if the forwarding preference of objects changes mid-track.
11. **Role-Based Restrictions (Announce & Subscribe):** Checks that publishers cannot subscribe and subscribers cannot announce.
12. **Queued Stream Opening Order:** Confirms that outgoing streams are opened in the correct order when multiple streams are queued.
这是对 `net/third_party/quiche/src/quiche/quic/moqt/moqt_session_test.cc` 文件中部分代码的分析。这部分代码主要关注 `MoqtSession` 在处理接收到的 **数据对象 (Object)** 相关的逻辑，以及一些与会话控制相关的场景。

**功能归纳:**

这部分代码主要测试了 `MoqtSession` 组件在处理以下几种情况时的行为：

*   **接收完整的和部分的数据对象 (Incoming Object):** 验证了 `MoqtSession` 正确处理接收到的完整数据对象以及分片的数据对象，并且在配置允许的情况下，可以处理不缓存部分对象的情况。
*   **在订阅确认前接收数据对象 (Object Before Subscribe):** 测试了当在收到 `SUBSCRIBE_OK` 或 `SUBSCRIBE_ERROR` 消息之前就收到数据对象时，`MoqtSession` 的行为。这涉及到数据对象的缓存和后续处理。
*   **早期数据对象的转发偏好 (Early Object Forwarding):** 验证了在 `SUBSCRIBE_OK` 之前接收到的数据对象，其转发偏好与后续正式创建的 Track 的转发偏好是否一致，以及在一个 Track 内转发偏好是否会发生变化。
*   **创建和发送数据流 (Create Incoming DataStream And Send):** 测试了 `MoqtSession` 创建单向数据流来发送数据的机制，包括在无法立即创建流时进行排队。
*   **处理单向流消失的情况 (Outgoing Stream Disappears):**  测试了当尝试发送数据时，底层单向流突然消失的情况，`MoqtSession` 如何处理。
*   **处理双向流 (One Bidirectional Stream Client/Server):** 测试了客户端和服务器端 `MoqtSession` 如何管理双向控制流，确保在会话期间只有一个双向流存在。
*   **接收取消订阅请求 (Receive Unsubscribe):** 测试了 `MoqtSession` 接收 `UNSUBSCRIBE` 消息并发送 `SUBSCRIBE_DONE` 消息的流程。
*   **发送和接收数据报 (Send/Receive Datagram):** 测试了 `MoqtSession` 使用数据报发送和接收数据对象的能力。
*   **转发偏好不匹配的情况 (Forwarding Preference Mismatch):** 测试了在一个 Track 中，如果接收到的数据对象的转发偏好发生变化，`MoqtSession` 如何处理。
*   **Publisher 和 Subscriber 的行为限制 (AnnounceToPublisher, SubscribeFromPublisher, AnnounceFromSubscriber):** 验证了 Publisher 不能发送 ANNOUNCE 消息，Subscriber 不能发送 SUBSCRIBE 消息。
*   **保证队列中的流按顺序打开 (Queued Streams Opened In Order):** 测试了当有多个待发送的数据流被放入队列时，`MoqtSession` 能够按照正确的顺序打开这些流。

**与 Javascript 的关系及举例说明:**

虽然这段 C++ 代码直接在 Chromium 的网络栈中运行，与底层的网络协议交互，但其功能直接影响到基于 WebTransport 的 MoQ 应用（通常使用 Javascript 开发）。

例如，测试 `IncomingObject` 功能确保了当一个 Javascript 的 MoQ 客户端或服务端通过 WebTransport 接收到来自对端的媒体数据片段时，Chromium 的网络栈能够正确地解析和传递这些数据。

**举例说明:**

假设一个使用 Javascript 和 WebTransport API 构建的 MoQ 客户端订阅了一个名为 "foo/bar" 的 Track，并且服务端正在发布内容。

1. **服务端发送 Object 消息:** 服务端会将媒体数据封装成 MoQ Object 消息，并通过 WebTransport 连接发送给客户端。
2. **Chromium 网络栈接收:**  Chromium 的网络栈接收到这些 WebTransport 帧，并根据 MoQ 协议解析出 Object 消息头和负载。
3. **`IncomingObject` 测试验证:** `MoqtSessionTest::IncomingObject` 这样的测试用例就模拟了这一过程，验证了 `MoqtSession` 组件能否正确解析 `MoqtObject` 的各个字段（如 `track_alias`, `group_sequence`, `object_sequence`, `payload` 等），并将数据传递给相应的 `MockRemoteTrackVisitor` 进行处理。
4. **Javascript 接收数据:** 最终，解析后的媒体数据会通过 WebTransport API 传递给 Javascript 代码，供客户端应用使用（例如，渲染视频或音频）。

**假设输入与输出 (逻辑推理):**

以 `TEST_F(MoqtSessionTest, IncomingPartialObject)` 为例：

*   **假设输入:**
    *   服务端发送一个 `MoqtObject` 消息，指示这是一个分片的对象 (`payload_length = 16`)。
    *   服务端首先发送 8 字节的 `payload = "deadbeef"`，并设置 `end_of_message = false`。
    *   服务端稍后再次发送 8 字节的 `payload = "deadbeef"`，并设置 `end_of_message = true`。
*   **预期输出:**
    *   `MockRemoteTrackVisitor` 的 `OnObjectFragment` 方法会被调用两次，每次调用都携带一部分 payload。
    *   第一次调用 `OnObjectFragment` 时，`end_of_message` 参数为 `false`。
    *   第二次调用 `OnObjectFragment` 时，`end_of_message` 参数为 `true`，表示这是对象的最后一个分片。

**用户或编程常见的使用错误举例说明:**

*   **服务端发送了转发偏好不一致的对象:**  如果在同一个 Track 中，服务端先发送了一个 `forwarding_preference` 为 `kSubgroup` 的对象，然后又发送了一个 `forwarding_preference` 为 `kTrack` 的对象，这违反了 MoQ 协议。`TEST_F(MoqtSessionTest, ForwardingPreferenceMismatch)` 就测试了这种情况，预期 `MoqtSession` 会关闭连接并报告协议错误。
*   **客户端在收到 SUBSCRIBE_OK 前就接收到了数据:** 虽然协议允许这种情况，但如果客户端的实现没有正确处理在 `SUBSCRIBE_OK` 之前到达的数据，可能会导致数据丢失或处理错误。`TEST_F(MoqtSessionTest, ObjectBeforeSubscribeOk)` 和 `TEST_F(MoqtSessionTest, ObjectBeforeSubscribeError)` 就覆盖了这种情况，确保即使在收到 `SUBSCRIBE_OK` 之前收到数据，也能正确处理。

**用户操作如何一步步到达这里 (调试线索):**

假设开发者在使用 Javascript 开发一个 MoQ 客户端，并且在接收服务端发送的媒体数据时遇到了问题，例如数据丢失或顺序错乱。

1. **Javascript 代码发起订阅:**  客户端 Javascript 代码使用 WebTransport API 向服务端发送 `SUBSCRIBE` 消息。
2. **服务端处理订阅并开始发送数据:** 服务端接收到 `SUBSCRIBE` 消息后，开始将媒体数据封装成 `MoqtObject` 消息并通过 WebTransport 发送。
3. **客户端 Chromium 网络栈接收数据:** 客户端的 Chromium 网络栈接收到来自服务端的 WebTransport 帧。
4. **`MoqtSession` 处理 Object 消息:**  接收到的帧会被传递给 `MoqtSession` 组件进行处理。相关的代码逻辑就在 `moqt_session_test.cc` 中被测试，例如 `IncomingObject` 相关的测试。
5. **数据传递给 WebTransport API:** `MoqtSession` 组件解析数据后，会将数据传递给上层的 WebTransport API。
6. **Javascript 代码接收数据:** 最终，客户端的 Javascript 代码通过 WebTransport 的相关回调函数接收到媒体数据。

如果在上述过程中出现问题，例如在 Javascript 代码中发现接收到的数据不完整，或者在应该收到数据的时候没有收到，开发者可能会：

*   **查看 WebTransport 的事件:**  检查 WebTransport API 的事件，确认连接状态和接收到的数据量。
*   **抓取网络包:** 使用 Wireshark 等工具抓取网络包，查看底层的 WebTransport 帧和 MoQ 消息内容，确认服务端是否发送了数据，以及数据的格式是否正确。
*   **查看 Chromium 内部日志:**  启用 Chromium 的网络日志，查看 `MoqtSession` 组件的处理过程，例如是否成功解析了 `MoqtObject` 消息，是否有错误发生。 `moqt_session_test.cc` 中的测试用例就覆盖了各种可能出错的情况，帮助开发者理解 `MoqtSession` 的行为。
*   **断点调试 Chromium 源码:**  如果怀疑是 Chromium 的 `MoqtSession` 组件存在问题，开发者可能需要在 Chromium 源码中设置断点，例如在 `MoqtSession::OnObjectMessage` 等函数中，来逐步调试代码，查看变量的值和执行流程，从而定位问题。

总而言之，`moqt_session_test.cc` 就像一个详细的测试蓝图，覆盖了 `MoqtSession` 组件在处理各种 MoQ 消息和状态时的行为，对于理解 MoQ 协议的实现细节以及调试基于 WebTransport 的 MoQ 应用至关重要。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/moqt_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
Call(FullTrackName{"foo"}))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kAnnounceOk);
        return absl::OkStatus();
      });
  stream_input->OnAnnounceMessage(announce);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, IncomingObject) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor_, 2);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _)).Times(1);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);
}

TEST_F(MoqtSessionTest, IncomingPartialObject) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor_, 2);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/16,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _)).Times(1);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, false);
  object_stream->OnObjectMessage(object, payload, true);  // complete the object
}

TEST_F(MoqtSessionTest, IncomingPartialObjectNoBuffer) {
  MoqtSessionParameters parameters(quic::Perspective::IS_CLIENT);
  parameters.deliver_partial_objects = true;
  MoqtSession session(&mock_session_, parameters,
                      session_callbacks_.AsSessionCallbacks());
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session, ftn, &visitor_, 2);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/16,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _)).Times(2);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, false);
  object_stream->OnObjectMessage(object, payload, true);  // complete the object
}

TEST_F(MoqtSessionTest, ObjectBeforeSubscribeOk) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/ftn,
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor_);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name, FullSequence sequence,
                    MoqtPriority publisher_priority, MoqtObjectStatus status,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(sequence.group, object.group_id);
        EXPECT_EQ(sequence.object, object.object_id);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);

  // SUBSCRIBE_OK arrives
  MoqtSubscribeOk ok = {
      /*subscribe_id=*/1,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*largest_id=*/std::nullopt,
  };
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtControlParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(visitor_, OnReply(_, _)).Times(1);
  control_stream->OnSubscribeOkMessage(ok);
}

TEST_F(MoqtSessionTest, ObjectBeforeSubscribeError) {
  MockRemoteTrackVisitor visitor;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/ftn,
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name, FullSequence sequence,
                    MoqtPriority publisher_priority, MoqtObjectStatus status,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(sequence.group, object.group_id);
        EXPECT_EQ(sequence.object, object.object_id);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);

  // SUBSCRIBE_ERROR arrives
  MoqtSubscribeError subscribe_error = {
      /*subscribe_id=*/1,
      /*error_code=*/SubscribeErrorCode::kRetryTrackAlias,
      /*reason_phrase=*/"foo",
      /*track_alias =*/3,
  };
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtControlParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Received SUBSCRIBE_ERROR after object"))
      .Times(1);
  control_stream->OnSubscribeErrorMessage(subscribe_error);
}

TEST_F(MoqtSessionTest, TwoEarlyObjectsDifferentForwarding) {
  MockRemoteTrackVisitor visitor;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/ftn,
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name, FullSequence sequence,
                    MoqtPriority publisher_priority, MoqtObjectStatus status,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(sequence.group, object.group_id);
        EXPECT_EQ(sequence.object, object.object_id);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);
  object.forwarding_preference = MoqtForwardingPreference::kTrack;
  ++object.object_id;
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Forwarding preference changes mid-track"))
      .Times(1);
  object_stream->OnObjectMessage(object, payload, true);
}

TEST_F(MoqtSessionTest, EarlyObjectForwardingDoesNotMatchTrack) {
  MockRemoteTrackVisitor visitor;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/ftn,
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name, FullSequence sequence,
                    MoqtPriority publisher_priority, MoqtObjectStatus status,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(sequence.group, object.group_id);
        EXPECT_EQ(sequence.object, object.object_id);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);

  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor, 2);
  // The track already exists, and has a different forwarding preference.
  MoqtSessionPeer::remote_track(&session_, 2)
      .CheckForwardingPreference(MoqtForwardingPreference::kTrack);

  // SUBSCRIBE_OK arrives
  MoqtSubscribeOk ok = {
      /*subscribe_id=*/1,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*largest_id=*/std::nullopt,
  };
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtControlParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Forwarding preference different in early objects"))
      .Times(1);
  control_stream->OnSubscribeOkMessage(ok);
}

TEST_F(MoqtSessionTest, CreateIncomingDataStreamAndSend) {
  FullTrackName ftn("foo", "bar");
  auto track = SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup,
                              FullSequence(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  bool fin = false;
  webtransport::test::MockStream mock_stream;
  EXPECT_CALL(mock_stream, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream, visitor()).WillOnce([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream));

  // Verify first six message fields are sent correctly
  bool correct_message = false;
  const std::string kExpectedMessage = {0x04, 0x02, 0x05, 0x00, 0x00};
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = absl::StartsWith(data[0], kExpectedMessage);
        fin |= options.send_fin();
        return absl::OkStatus();
      });
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 0))).WillRepeatedly([] {
    return PublishedObject{FullSequence(5, 0), MoqtObjectStatus::kNormal, 127,
                           MemSliceFromString("deadbeef")};
  });
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  subscription->OnNewObjectAvailable(FullSequence(5, 0));
  EXPECT_TRUE(correct_message);
}

// TODO: Test operation with multiple streams.

TEST_F(MoqtSessionTest, UnidirectionalStreamCannotBeOpened) {
  FullTrackName ftn("foo", "bar");
  auto track = SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup,
                              FullSequence(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  // Queue the outgoing stream.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false));
  subscription->OnNewObjectAvailable(FullSequence(5, 0));

  // Unblock the session, and cause the queued stream to be sent.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  bool fin = false;
  webtransport::test::MockStream mock_stream;
  EXPECT_CALL(mock_stream, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream, visitor()).WillOnce([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream));
  EXPECT_CALL(mock_stream, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 0))).WillRepeatedly([] {
    return PublishedObject{FullSequence(5, 0), MoqtObjectStatus::kNormal, 128,
                           MemSliceFromString("deadbeef")};
  });
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
}

TEST_F(MoqtSessionTest, OutgoingStreamDisappears) {
  FullTrackName ftn("foo", "bar");
  auto track = SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup,
                              FullSequence(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  // Set up an outgoing stream for a group.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  webtransport::test::MockStream mock_stream;
  EXPECT_CALL(mock_stream, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream, visitor()).WillRepeatedly([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream));

  EXPECT_CALL(mock_stream, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 0))).WillRepeatedly([] {
    return PublishedObject{FullSequence(5, 0), MoqtObjectStatus::kNormal, 128,
                           MemSliceFromString("deadbeef")};
  });
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 1))).WillOnce([] {
    return std::optional<PublishedObject>();
  });
  subscription->OnNewObjectAvailable(FullSequence(5, 0));

  // Now that the stream exists and is recorded within subscription, make it
  // disappear by returning nullptr.
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(nullptr));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 1))).Times(0);
  subscription->OnNewObjectAvailable(FullSequence(5, 1));
}

TEST_F(MoqtSessionTest, OneBidirectionalStreamClient) {
  webtransport::test::MockStream mock_stream;
  EXPECT_CALL(mock_session_, OpenOutgoingBidirectionalStream())
      .WillOnce(Return(&mock_stream));
  std::unique_ptr<webtransport::StreamVisitor> visitor;
  // Save a reference to MoqtSession::Stream
  EXPECT_CALL(mock_stream, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> new_visitor) {
        visitor = std::move(new_visitor);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillOnce(Return(webtransport::StreamId(4)));
  EXPECT_CALL(mock_session_, GetStreamById(4)).WillOnce(Return(&mock_stream));
  bool correct_message = false;
  EXPECT_CALL(mock_stream, visitor()).WillOnce([&] { return visitor.get(); });
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kClientSetup);
        return absl::OkStatus();
      });
  session_.OnSessionReady();
  EXPECT_TRUE(correct_message);

  // Peer tries to open a bidi stream.
  bool reported_error = false;
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&mock_stream));
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Bidirectional stream already open"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = (error_message == "Bidirectional stream already open");
      });
  session_.OnIncomingBidirectionalStreamAvailable();
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, OneBidirectionalStreamServer) {
  MoqtSession server_session(
      &mock_session_, MoqtSessionParameters(quic::Perspective::IS_SERVER),
      session_callbacks_.AsSessionCallbacks());
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&server_session, &mock_stream);
  MoqtClientSetup setup = {
      /*supported_versions*/ {kDefaultMoqtVersion},
      /*role=*/MoqtRole::kPubSub,
      /*path=*/std::nullopt,
  };
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kServerSetup);
        return absl::OkStatus();
      });
  EXPECT_CALL(mock_stream, GetStreamId()).WillOnce(Return(0));
  EXPECT_CALL(session_callbacks_.session_established_callback, Call()).Times(1);
  stream_input->OnClientSetupMessage(setup);

  // Peer tries to open a bidi stream.
  bool reported_error = false;
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&mock_stream));
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Bidirectional stream already open"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = (error_message == "Bidirectional stream already open");
      });
  server_session.OnIncomingBidirectionalStreamAvailable();
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, ReceiveUnsubscribe) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kTrack, FullSequence(4, 2));
  MoqtSessionPeer::AddSubscription(&session_, track, 0, 1, 3, 4);
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MoqtUnsubscribe unsubscribe = {
      /*subscribe_id=*/0,
  };
  EXPECT_CALL(mock_session_, GetStreamById(4)).WillOnce(Return(&mock_stream));
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeDone);
        return absl::OkStatus();
      });
  stream_input->OnUnsubscribeMessage(unsubscribe);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, SendDatagram) {
  FullTrackName ftn("foo", "bar");
  std::shared_ptr<MockTrackPublisher> track_publisher = SetupPublisher(
      ftn, MoqtForwardingPreference::kDatagram, FullSequence{4, 0});
  MoqtObjectListener* listener =
      MoqtSessionPeer::AddSubscription(&session_, track_publisher, 0, 2, 5, 0);

  // Publish in window.
  bool correct_message = false;
  uint8_t kExpectedMessage[] = {
      0x01, 0x02, 0x05, 0x00, 0x00, 0x08, 0x64,
      0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66,
  };
  EXPECT_CALL(mock_session_, SendOrQueueDatagram(_))
      .WillOnce([&](absl::string_view datagram) {
        if (datagram.size() == sizeof(kExpectedMessage)) {
          correct_message = (0 == memcmp(datagram.data(), kExpectedMessage,
                                         sizeof(kExpectedMessage)));
        }
        return webtransport::DatagramStatus(
            webtransport::DatagramStatusCode::kSuccess, "");
      });
  EXPECT_CALL(*track_publisher, GetCachedObject(FullSequence{5, 0}))
      .WillRepeatedly([] {
        return PublishedObject{FullSequence{5, 0}, MoqtObjectStatus::kNormal,
                               128, MemSliceFromString("deadbeef")};
      });
  listener->OnNewObjectAvailable(FullSequence(5, 0));
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, ReceiveDatagram) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor_, 2);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kDatagram,
      /*subgroup_id=*/std::nullopt,
      /*payload_length=*/8,
  };
  char datagram[] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x08, 0x64,
                     0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66};
  EXPECT_CALL(
      visitor_,
      OnObjectFragment(ftn, FullSequence{object.group_id, object.object_id},
                       object.publisher_priority, object.object_status,
                       object.forwarding_preference, payload, true))
      .Times(1);
  session_.OnDatagramReceived(absl::string_view(datagram, sizeof(datagram)));
}

TEST_F(MoqtSessionTest, ForwardingPreferenceMismatch) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor_, 2);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _)).Times(1);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);
  ++object.object_id;
  object.forwarding_preference = MoqtForwardingPreference::kTrack;
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Forwarding preference changes mid-track"))
      .Times(1);
  object_stream->OnObjectMessage(object, payload, true);
}

TEST_F(MoqtSessionTest, AnnounceToPublisher) {
  MoqtSessionPeer::set_peer_role(&session_, MoqtRole::kPublisher);
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  EXPECT_CALL(announce_resolved_callback, Call(_, _)).Times(1);
  session_.Announce(FullTrackName{"foo"},
                    announce_resolved_callback.AsStdFunction());
}

TEST_F(MoqtSessionTest, SubscribeFromPublisher) {
  MoqtSessionPeer::set_peer_role(&session_, MoqtRole::kPublisher);
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  // Request for track returns Protocol Violation.
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Received SUBSCRIBE from publisher"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_)).Times(1);
  stream_input->OnSubscribeMessage(request);
}

TEST_F(MoqtSessionTest, AnnounceFromSubscriber) {
  MoqtSessionPeer::set_peer_role(&session_, MoqtRole::kSubscriber);
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MoqtAnnounce announce = {
      /*track_namespace=*/FullTrackName{"foo"},
  };
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Received ANNOUNCE from Subscriber"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_)).Times(1);
  stream_input->OnAnnounceMessage(announce);
}

TEST_F(MoqtSessionTest, QueuedStreamsOpenedInOrder) {
  FullTrackName ftn("foo", "bar");
  auto track = SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup,
                              FullSequence(0, 0));
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kNotYetBegun));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 14, 0, 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false))
      .WillOnce(Return(false))
      .WillOnce(Return(false));
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  subscription->OnNewObjectAvailable(FullSequence(1, 0));
  subscription->OnNewObjectAvailable(FullSequence(0, 0));
  subscription->OnNewObjectAvailable(FullSequence(2, 0));
  // These should be opened in the sequence (0, 0), (1, 0), (2, 0).
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillRepeatedly(Return(true));
  webtransport::test::MockStream mock_stream0, mock_stream1, mock_stream2;
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream0))
      .WillOnce(Return(&mock_stream1))
      .WillOnce(Return(&mock_stream2));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor[3];
  EXPECT_CALL(mock_stream0, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor[0] = std::move(visitor);
      });
  EXPECT_CALL(mock_stream1, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor[1] = std::move(visitor);
      });
  EXPECT_CALL(mock_stream2, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor[2] = std::move(visitor);
      });
  EXPECT_CALL(mock_stream0, GetStreamId()).WillRepeatedly(Return(0));
  EXPECT_CALL(mock_stream1, GetStreamId()).WillRepeatedly(Return(1));
  EXPECT_CALL(mock_stream2, GetStreamId()).WillRepeatedly(Return(2));
  EXPECT_CALL(mock_stream0, visitor()).WillOnce([&]() {
    return stream_visitor[0].get();
  });
  EXPECT_CALL(mock_stream1, visitor()).WillOnce([&]() {
    return stream_visitor[1].get();
  });
  EXPECT_CALL(mock_stream2, visitor()).WillOnce([&]() {
    return stream_visitor[2].get();
  });
  EXPECT_CALL(*track, GetCachedObject(FullSequence(0, 0)))
      .WillOnce(
          Return(PublishedObject{FullSequence(0, 0), MoqtObjectStatus::kNormal,
                                 127, MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(0, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(1, 0)))
      .WillOnce(
          Return(PublishedObject{FullSequence(1, 0), MoqtObjectStatus::kNormal,
                                 127, MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(1, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(2, 0)))
      .WillOnce(
          Return(Publishe
```