Response:
The user wants to understand the functionality of the given C++ code snippet from a Chromium networking stack file. The file is `quic_spdy_session_test.cc`. I need to analyze the provided code, which consists of several test cases, and summarize its purpose. Specifically, I need to:

1. **Identify the main function of the code:**  Based on the file name and the content, it's a test file for `QuicSpdySession`.
2. **List the functionalities being tested:**  This involves going through each `TEST_P` and understanding what it's verifying. The tests seem to cover various aspects of HTTP/3 session management, including:
    - Handling `PRIORITY_UPDATE` frames.
    - Handling unknown stream types.
    - Receiving and processing control stream frames (`SETTINGS`).
    - Handling QPACK encoder and decoder stream interactions.
    - Dealing with stream closure and session destruction during header decoding.
    - Handling invalid or duplicate HTTP/3 unidirectional streams.
    - Handling errors in QPACK encoder and decoder streams.
    - Handling `GOAWAY` frames.
    - Processing `CANCEL_PUSH` frames.
    - Processing individual `SETTINGS`.
    - Handling HPACK error codes (for HTTP/2).
    - Handling closure of critical receive streams.
    - Testing flow control behavior on HTTP/3 control streams.
3. **Check for relationships with JavaScript:**  As this is low-level networking code, direct interaction with JavaScript is unlikely. However, the higher layers of the Chromium network stack that use this code are used by JavaScript in web browsers.
4. **Provide example inputs and outputs for logical reasoning:** For tests that demonstrate specific logic, I can create hypothetical inputs and expected outputs.
5. **Identify common user or programming errors:**  The tests often implicitly highlight potential errors, such as sending invalid frames or violating protocol rules.
6. **Explain how a user might reach this code (debugging):** This involves describing a user action that triggers network activity, eventually leading to this code being executed.
7. **Summarize the functionality of this part:** This is the final step, consolidating the findings from the previous steps.

**Mental Sandbox:**

- I'll iterate through each `TEST_P` block and determine the specific scenario it's testing.
- For JavaScript relevance, I'll think about how higher-level browser APIs (like `fetch`) might rely on the functionality tested here.
- For input/output examples, I'll focus on tests with clear conditional logic (e.g., based on frame types or settings).
- For user errors, I'll consider what mistakes a server or client implementation might make that these tests are designed to catch.
- For debugging, I'll trace a typical web request and see where `QuicSpdySession` comes into play.

Okay, the plan is set. I will now process the code snippet and generate the response.
这个文件 `net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session_test.cc` 是 Chromium 网络栈中 QUIC 协议实现的测试文件，专门用于测试 `QuicSpdySession` 类的功能。 `QuicSpdySession` 负责处理基于 QUIC 协议的 HTTP/2 和 HTTP/3 连接的会话管理，包括流的创建、数据的发送和接收、头部压缩、错误处理等等。

**这个代码片段（第 4 部分）主要测试了 `QuicSpdySession` 中以下方面的功能，尤其侧重于 HTTP/3 的行为：**

1. **`PRIORITY_UPDATE` 帧的处理:**
   - 测试了接收到合法的 `PRIORITY_UPDATE` 帧时，会话的行为，例如调用 `OnPriorityUpdateFrameReceived`。
   - 测试了接收到 `PRIORITY_UPDATE` 帧，但其中的 urgency 值超出允许范围 (0-7) 时，会话不会关闭连接。

2. **处理未知的流类型 (Pending Stream):**
   - 测试了当接收到未知类型的单向流时，会话会发送 `STOP_SENDING` 帧来告知对端。
   - 测试了接收到未知类型流的不同分片（有 FIN 和无 FIN 的情况），以及乱序到达的情况，会话如何正确处理，包括发送 `STOP_SENDING` 帧并忽略后续数据。

3. **接收控制流 (`ReceiveControlStream`):**
   - 测试了当接收到标识为控制流的单向流时，会话会正确识别并创建控制流。
   - 测试了在控制流上接收到 `SETTINGS` 帧时，会话会更新相应的配置，例如 QPACK 的最大表容量、最大头部列表大小等。
   - 测试了接收控制流的帧乱序到达时，`SETTINGS` 的应用顺序。

4. **禁用 QPACK 动态表:**
   - 测试了服务端配置禁用 QPACK 动态表后，即使客户端发送了 `SETTINGS` 更新动态表容量，服务端也会忽略，并发送自己的 `SETTINGS` 告知客户端服务端禁用了动态表。

5. **处理接收控制流的帧乱序到达:**
   - 测试了控制流的类型标识和 `SETTINGS` 帧乱序到达时，`SETTINGS` 的应用时机。

6. **处理头部解码被阻塞时的流关闭和会话销毁:**
   - **`StreamClosedWhileHeaderDecodingBlocked`:** 测试了当流的头部解码因为缺少 QPACK 动态表项而被阻塞时，如果该流被关闭，不会发生崩溃，并且后续收到的动态表项不会被错误地应用到已销毁的流上。
   - **`SessionDestroyedWhileHeaderDecodingBlocked`:** 测试了当会话因为头部解码被阻塞而等待 QPACK 动态表项时，如果会话被销毁，也不会发生崩溃。

7. **处理无效的传入流类型后的 `RESET_STREAM` 和 `FIN`:**
   - **`ResetAfterInvalidIncomingStreamType`:** 测试了客户端接收到服务端发送的未知类型单向流后，会发送 `STOP_SENDING` 帧，并进入 Pending 状态。如果之后收到 `RESET_STREAM` 帧，会话会正确关闭该流。
   - **`FinAfterInvalidIncomingStreamType`:**  与上类似，但测试了收到 `FIN` 帧的情况，会话也会正确关闭该流。
   - **`ResetInMiddleOfStreamType`:** 测试了客户端在接收服务端发送的流类型标识的一部分时收到 `RESET_STREAM`，会话会正确关闭该流。
   - **`FinInMiddleOfStreamType`:**  与上类似，但测试了收到 `FIN` 帧的情况。

8. **处理重复的 HTTP/3 单向流:**
   - 测试了客户端接收到重复的控制流、QPACK 编码器流或 QPACK 解码器流时，会话会检测到错误并关闭连接。

9. **处理 QPACK 编码器和解码器流的错误:**
   - **`EncoderStreamError`:** 测试了接收到包含无效索引的 QPACK 编码器流数据时，会话会关闭连接。
   - **`DecoderStreamError`:** 测试了接收到包含无效增量值的 QPACK 解码器流数据时，会话会关闭连接。

10. **处理无效的 HTTP/3 GOAWAY 帧:**
    - 测试了接收到 stream ID 不合法的 `GOAWAY` 帧时，会话会关闭连接。
    - 测试了接收到 `GOAWAY` 帧，但其中的 stream ID 比之前收到的 `GOAWAY` 帧的 stream ID 更大时，会话会关闭连接。

11. **处理 `CANCEL_PUSH` 帧:**
    - 测试了客户端接收到 `CANCEL_PUSH` 帧时，会话会关闭连接，因为客户端不应该收到 `CANCEL_PUSH` 帧。

12. **处理 `SETTINGS` 设置:**
    - **`OnSetting`:** 测试了服务端接收到 `SETTINGS` 帧中的各个设置项时，会话会正确更新内部状态，例如最大头部列表大小、QPACK 阻塞流的最大数量、QPACK 最大表容量等。

13. **处理细粒度的 HPACK 错误码 (HTTP/2):**
    - **`FineGrainedHpackErrorCodes`:** 针对 HTTP/2，测试了接收到包含 HPACK 错误的头部帧时，会话会使用更精细的 HPACK 错误码关闭连接，例如 `QUIC_HPACK_INVALID_INDEX`。

14. **处理对端关闭关键接收流:**
    - **`PeerClosesCriticalReceiveStream`:** 测试了当对端（客户端）关闭了关键的单向流（控制流、QPACK 编码器流、QPACK 解码器流）时，服务端会话会关闭连接。

15. **HTTP/3 控制流的连接级流量控制:**
    - **`H3ControlStreamsLimitedByConnectionFlowControl`:** 测试了 HTTP/3 的控制流也受连接级流量控制的限制。

**与 JavaScript 的关系：**

虽然这段 C++ 代码本身不直接与 JavaScript 交互，但它所测试的功能是支撑浏览器中 HTTP/3 通信的基础。当 JavaScript 代码（例如使用 `fetch` API）发起一个网络请求，如果该请求通过 HTTP/3 协议进行，那么 Chromium 的网络栈就会使用这部分 C++ 代码来处理底层的 QUIC 会话管理和 HTTP/3 帧的处理。

**举例说明：**

假设 JavaScript 代码发起一个 `fetch` 请求，服务器返回的响应头部非常大，需要使用 QPACK 进行压缩。如果服务器的 QPACK 动态表容量很小，而客户端发送了一个引用动态表中不存在的条目的头部帧（就像 `StreamClosedWhileHeaderDecodingBlocked` 和 `SessionDestroyedWhileHeaderDecodingBlocked` 测试中模拟的情况），那么 `QuicSpdySession` 的解码器就需要等待相应的动态表更新信息。如果在等待期间，连接或流被关闭，那么这些测试保证了 Chromium 的 QUIC 实现不会因此崩溃。

**逻辑推理的假设输入与输出：**

以 `OnPriorityUpdateFrameOutOfBoundsUrgency` 测试为例：

* **假设输入:**
    * 一个已建立的 HTTP/3 QUIC 连接。
    * 接收到来自对端的控制流数据，包含了合法的 SETTINGS 帧。
    * 接收到来自对端的控制流数据，包含了 `PRIORITY_UPDATE` 帧，其中 `urgency` 字段的值为 9。
* **预期输出:**
    * 会话的调试访问器会记录收到 `PRIORITY_UPDATE` 帧。
    * 连接不会被立即关闭（`CloseConnection` 方法不会被调用）。

**用户或编程常见的使用错误举例说明：**

* **服务端编程错误：** 服务端实现可能错误地发送了 urgency 值超出范围的 `PRIORITY_UPDATE` 帧。`OnPriorityUpdateFrameOutOfBoundsUrgency` 这个测试可以帮助发现这类服务端实现的错误。
* **客户端编程错误：** 客户端在实现 HTTP/3 时，可能会错误地打开了多个控制流，`DuplicateHttp3UnidirectionalStreams` 测试就是为了验证这种情况，并确保 Chromium 可以正确处理。
* **协议理解错误：** 对 HTTP/3 协议理解不透彻可能导致发送不符合协议规定的帧，例如客户端不应该发送 `CANCEL_PUSH` 帧。`CloseConnectionOnCancelPush` 测试覆盖了这种情况。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器地址栏输入一个 HTTPS 地址，该网站支持 HTTP/3。**
2. **浏览器发起连接请求，与服务器进行 QUIC 握手，协商使用 HTTP/3。**
3. **在 HTTP/3 会话建立后，浏览器或服务器可能需要更新流的优先级，这会涉及到 `PRIORITY_UPDATE` 帧的发送和接收，触发 `OnPriorityUpdateFrame` 相关代码的执行。**
4. **如果服务器发送了一个客户端不认识的新类型的单向流，`SimplePendingStreamType` 相关的代码会被触发。**
5. **服务器可能会发送 `SETTINGS` 帧来配置客户端的 HTTP/3 行为，例如 QPACK 的参数，这会触发 `ReceiveControlStream` 相关的代码。**
6. **如果网络环境不好，或者对端实现有 bug，可能会导致帧乱序到达，这会触发带有 "OutOfOrderDelivery" 字样的测试。**
7. **如果涉及到 QPACK 头部压缩，并且动态表的操作有延迟或者错误，可能会触发 `StreamClosedWhileHeaderDecodingBlocked` 或 `SessionDestroyedWhileHeaderDecodingBlocked` 相关的场景。**
8. **如果服务端或客户端的 HTTP/3 实现存在协议错误，例如发送了重复的关键单向流，或者发送了格式错误的 QPACK 指令，会触发相应的错误处理测试。**

通过查看这些测试用例的执行情况和相关的日志，开发者可以定位在 HTTP/3 会话管理过程中出现的各种问题。

**归纳一下它的功能 (第 4 部分):**

这部分代码主要测试了 `QuicSpdySession` 类在处理 HTTP/3 特有的帧类型和流管理方面的功能，包括优先级更新、未知流类型处理、控制流管理（包括 `SETTINGS` 帧）、QPACK 动态表禁用、头部解码阻塞时的流和会话生命周期管理、处理无效或重复的 HTTP/3 单向流、QPACK 流错误、无效的 `GOAWAY` 帧以及对 `CANCEL_PUSH` 帧的处理。此外，还包含针对 HTTP/2 的 HPACK 错误码测试和对关键接收流关闭的处理，以及 HTTP/3 控制流的连接级流量控制测试。 这些测试用例旨在确保 `QuicSpdySession` 能够正确、健壮地处理各种合法的和非法的 HTTP/3 交互，并能优雅地处理错误情况，保证网络连接的稳定性和安全性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/http/quic_spdy_session_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
StreamFrame data3(receive_control_stream_id,
                        /* fin = */ false, offset, serialized_priority_update);
  session_->OnStreamFrame(data3);
}

TEST_P(QuicSpdySessionTestServer, OnPriorityUpdateFrameOutOfBoundsUrgency) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  // Create control stream.
  QuicStreamId receive_control_stream_id =
      GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  char type[] = {kControlStream};
  absl::string_view stream_type(type, 1);
  QuicStreamOffset offset = 0;
  QuicStreamFrame data1(receive_control_stream_id, false, offset, stream_type);
  offset += stream_type.length();
  EXPECT_CALL(debug_visitor,
              OnPeerControlStreamCreated(receive_control_stream_id));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(receive_control_stream_id,
            QuicSpdySessionPeer::GetReceiveControlStream(&*session_)->id());

  // Send SETTINGS frame.
  std::string serialized_settings = HttpEncoder::SerializeSettingsFrame({});
  QuicStreamFrame data2(receive_control_stream_id, false, offset,
                        serialized_settings);
  offset += serialized_settings.length();
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(_));
  session_->OnStreamFrame(data2);

  // PRIORITY_UPDATE frame with urgency not in [0,7].
  const QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(0);
  PriorityUpdateFrame priority_update{stream_id, "u=9"};

  EXPECT_CALL(debug_visitor, OnPriorityUpdateFrameReceived(priority_update));
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);

  std::string serialized_priority_update =
      HttpEncoder::SerializePriorityUpdateFrame(priority_update);
  QuicStreamFrame data3(receive_control_stream_id,
                        /* fin = */ false, offset, serialized_priority_update);
  session_->OnStreamFrame(data3);
}

TEST_P(QuicSpdySessionTestServer, SimplePendingStreamType) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();
  char input[] = {0x04,            // type
                  'a', 'b', 'c'};  // data
  absl::string_view payload(input, ABSL_ARRAYSIZE(input));

  // This is a server test with a client-initiated unidirectional stream.
  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);

  for (bool fin : {true, false}) {
    QuicStreamFrame frame(stream_id, fin, /* offset = */ 0, payload);

    // A STOP_SENDING frame is sent in response to the unknown stream type.
    EXPECT_CALL(*connection_, SendControlFrame(_))
        .WillOnce(Invoke([stream_id](const QuicFrame& frame) {
          EXPECT_EQ(STOP_SENDING_FRAME, frame.type);

          const QuicStopSendingFrame& stop_sending = frame.stop_sending_frame;
          EXPECT_EQ(stream_id, stop_sending.stream_id);
          EXPECT_EQ(QUIC_STREAM_STREAM_CREATION_ERROR, stop_sending.error_code);
          EXPECT_EQ(
              static_cast<uint64_t>(QuicHttp3ErrorCode::STREAM_CREATION_ERROR),
              stop_sending.ietf_error_code);

          return ClearControlFrame(frame);
        }));
    session_->OnStreamFrame(frame);

    PendingStream* pending =
        QuicSessionPeer::GetPendingStream(&*session_, stream_id);
    if (fin) {
      // Stream is closed if FIN is received.
      EXPECT_FALSE(pending);
    } else {
      ASSERT_TRUE(pending);
      // The pending stream must ignore read data.
      EXPECT_TRUE(pending->sequencer()->ignore_read_data());
    }

    stream_id += QuicUtils::StreamIdDelta(transport_version());
  }
}

TEST_P(QuicSpdySessionTestServer, SimplePendingStreamTypeOutOfOrderDelivery) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();
  char input[] = {0x04,            // type
                  'a', 'b', 'c'};  // data
  absl::string_view payload(input, ABSL_ARRAYSIZE(input));

  // This is a server test with a client-initiated unidirectional stream.
  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);

  for (bool fin : {true, false}) {
    QuicStreamFrame frame1(stream_id, /* fin = */ false, /* offset = */ 0,
                           payload.substr(0, 1));
    QuicStreamFrame frame2(stream_id, fin, /* offset = */ 1, payload.substr(1));

    // Deliver frames out of order.
    session_->OnStreamFrame(frame2);
    // A STOP_SENDING frame is sent in response to the unknown stream type.
    EXPECT_CALL(*connection_, SendControlFrame(_))
        .WillOnce(Invoke(&VerifyAndClearStopSendingFrame));
    session_->OnStreamFrame(frame1);

    PendingStream* pending =
        QuicSessionPeer::GetPendingStream(&*session_, stream_id);
    if (fin) {
      // Stream is closed if FIN is received.
      EXPECT_FALSE(pending);
    } else {
      ASSERT_TRUE(pending);
      // The pending stream must ignore read data.
      EXPECT_TRUE(pending->sequencer()->ignore_read_data());
    }

    stream_id += QuicUtils::StreamIdDelta(transport_version());
  }
}

TEST_P(QuicSpdySessionTestServer,
       MultipleBytesPendingStreamTypeOutOfOrderDelivery) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();
  char input[] = {0x41, 0x00,      // type (256)
                  'a', 'b', 'c'};  // data
  absl::string_view payload(input, ABSL_ARRAYSIZE(input));

  // This is a server test with a client-initiated unidirectional stream.
  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      transport_version(), Perspective::IS_CLIENT);

  for (bool fin : {true, false}) {
    QuicStreamFrame frame1(stream_id, /* fin = */ false, /* offset = */ 0,
                           payload.substr(0, 1));
    QuicStreamFrame frame2(stream_id, /* fin = */ false, /* offset = */ 1,
                           payload.substr(1, 1));
    QuicStreamFrame frame3(stream_id, fin, /* offset = */ 2, payload.substr(2));

    // Deliver frames out of order.
    session_->OnStreamFrame(frame3);
    // The first byte does not contain the entire type varint.
    session_->OnStreamFrame(frame1);
    // A STOP_SENDING frame is sent in response to the unknown stream type.
    EXPECT_CALL(*connection_, SendControlFrame(_))
        .WillOnce(Invoke(&VerifyAndClearStopSendingFrame));
    session_->OnStreamFrame(frame2);

    PendingStream* pending =
        QuicSessionPeer::GetPendingStream(&*session_, stream_id);
    if (fin) {
      // Stream is closed if FIN is received.
      EXPECT_FALSE(pending);
    } else {
      ASSERT_TRUE(pending);
      // The pending stream must ignore read data.
      EXPECT_TRUE(pending->sequencer()->ignore_read_data());
    }

    stream_id += QuicUtils::StreamIdDelta(transport_version());
  }
}

TEST_P(QuicSpdySessionTestServer, ReceiveControlStream) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  // Use an arbitrary stream id.
  QuicStreamId stream_id =
      GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  char type[] = {kControlStream};

  QuicStreamFrame data1(stream_id, false, 0, absl::string_view(type, 1));
  EXPECT_CALL(debug_visitor, OnPeerControlStreamCreated(stream_id));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(stream_id,
            QuicSpdySessionPeer::GetReceiveControlStream(&*session_)->id());

  SettingsFrame settings;
  settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY] = 512;
  settings.values[SETTINGS_MAX_FIELD_SECTION_SIZE] = 5;
  settings.values[SETTINGS_QPACK_BLOCKED_STREAMS] = 42;
  std::string data = HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamFrame frame(stream_id, false, 1, data);

  QpackEncoder* qpack_encoder = session_->qpack_encoder();
  QpackEncoderHeaderTable* header_table =
      QpackEncoderPeer::header_table(qpack_encoder);

  EXPECT_NE(512u, header_table->maximum_dynamic_table_capacity());
  EXPECT_NE(5u, session_->max_outbound_header_list_size());
  EXPECT_NE(42u, QpackEncoderPeer::maximum_blocked_streams(qpack_encoder));

  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(settings));
  session_->OnStreamFrame(frame);

  EXPECT_EQ(512u, header_table->maximum_dynamic_table_capacity());
  EXPECT_EQ(5u, session_->max_outbound_header_list_size());
  EXPECT_EQ(42u, QpackEncoderPeer::maximum_blocked_streams(qpack_encoder));
}

TEST_P(QuicSpdySessionTestServer, ServerDisableQpackDynamicTable) {
  SetQuicFlag(quic_server_disable_qpack_dynamic_table, true);
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();

  // Use an arbitrary stream id for creating the receive control stream.
  QuicStreamId stream_id =
      GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  char type[] = {kControlStream};
  QuicStreamFrame data1(stream_id, false, 0, absl::string_view(type, 1));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(stream_id,
            QuicSpdySessionPeer::GetReceiveControlStream(&*session_)->id());
  // Receive the QPACK dynamic table capacity from the peer.
  const uint64_t capacity = 512;
  SettingsFrame settings;
  settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY] = capacity;
  std::string data = HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamFrame frame(stream_id, false, 1, data);
  session_->OnStreamFrame(frame);

  // Verify that the encoder's dynamic table capacity is 0.
  QpackEncoder* qpack_encoder = session_->qpack_encoder();
  EXPECT_EQ(capacity, qpack_encoder->MaximumDynamicTableCapacity());
  QpackEncoderHeaderTable* encoder_header_table =
      QpackEncoderPeer::header_table(qpack_encoder);
  EXPECT_EQ(capacity, encoder_header_table->maximum_dynamic_table_capacity());
  EXPECT_EQ(0, encoder_header_table->dynamic_table_capacity());

  // Verify that the advertised capacity is 0.
  SettingsFrame outgoing_settings = session_->settings();
  EXPECT_EQ(0, outgoing_settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY]);
}

TEST_P(QuicSpdySessionTestServer, DisableQpackDynamicTable) {
  SetQuicFlag(quic_server_disable_qpack_dynamic_table, false);
  qpack_maximum_dynamic_table_capacity_ = 0;
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();

  // Use an arbitrary stream id for creating the receive control stream.
  QuicStreamId stream_id =
      GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  char type[] = {kControlStream};
  QuicStreamFrame data1(stream_id, false, 0, absl::string_view(type, 1));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(stream_id,
            QuicSpdySessionPeer::GetReceiveControlStream(&*session_)->id());
  // Receive the QPACK dynamic table capacity from the peer.
  const uint64_t capacity = 512;
  SettingsFrame settings;
  settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY] = capacity;
  std::string data = HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamFrame frame(stream_id, false, 1, data);
  session_->OnStreamFrame(frame);

  // Verify that the encoder's dynamic table capacity is 0.
  QpackEncoder* qpack_encoder = session_->qpack_encoder();
  EXPECT_EQ(capacity, qpack_encoder->MaximumDynamicTableCapacity());
  QpackEncoderHeaderTable* encoder_header_table =
      QpackEncoderPeer::header_table(qpack_encoder);
  EXPECT_EQ(capacity, encoder_header_table->maximum_dynamic_table_capacity());
  EXPECT_EQ(0, encoder_header_table->dynamic_table_capacity());

  // Verify that the advertised capacity is 0.
  SettingsFrame outgoing_settings = session_->settings();
  EXPECT_EQ(0, outgoing_settings.values[SETTINGS_QPACK_MAX_TABLE_CAPACITY]);
}

TEST_P(QuicSpdySessionTestServer, ReceiveControlStreamOutOfOrderDelivery) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();
  // Use an arbitrary stream id.
  QuicStreamId stream_id =
      GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  char type[] = {kControlStream};
  SettingsFrame settings;
  settings.values[10] = 2;
  settings.values[SETTINGS_MAX_FIELD_SECTION_SIZE] = 5;
  std::string data = HttpEncoder::SerializeSettingsFrame(settings);

  QuicStreamFrame data1(stream_id, false, 1, data);
  QuicStreamFrame data2(stream_id, false, 0, absl::string_view(type, 1));

  session_->OnStreamFrame(data1);
  EXPECT_NE(5u, session_->max_outbound_header_list_size());
  session_->OnStreamFrame(data2);
  EXPECT_EQ(5u, session_->max_outbound_header_list_size());
}

// Regression test for https://crbug.com/1009551.
TEST_P(QuicSpdySessionTestServer, StreamClosedWhileHeaderDecodingBlocked) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();
  session_->qpack_decoder()->OnSetDynamicTableCapacity(1024);

  QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(0);
  TestStream* stream = session_->CreateIncomingStream(stream_id);

  // HEADERS frame referencing first dynamic table entry.
  std::string headers_frame_payload;
  ASSERT_TRUE(absl::HexStringToBytes("020080", &headers_frame_payload));
  std::string headers_frame_header =
      HttpEncoder::SerializeHeadersFrameHeader(headers_frame_payload.length());
  std::string headers_frame =
      absl::StrCat(headers_frame_header, headers_frame_payload);
  stream->OnStreamFrame(QuicStreamFrame(stream_id, false, 0, headers_frame));

  // Decoding is blocked because dynamic table entry has not been received yet.
  EXPECT_FALSE(stream->headers_decompressed());

  // Stream is closed and destroyed.
  CloseStream(stream_id);
  session_->CleanUpClosedStreams();

  // Dynamic table entry arrived on the decoder stream.
  // The destroyed stream object must not be referenced.
  session_->qpack_decoder()->OnInsertWithoutNameReference("foo", "bar");
}

// Regression test for https://crbug.com/1011294.
TEST_P(QuicSpdySessionTestServer, SessionDestroyedWhileHeaderDecodingBlocked) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  session_->qpack_decoder()->OnSetDynamicTableCapacity(1024);

  QuicStreamId stream_id = GetNthClientInitiatedBidirectionalId(0);
  TestStream* stream = session_->CreateIncomingStream(stream_id);

  // HEADERS frame referencing first dynamic table entry.
  std::string headers_frame_payload;
  ASSERT_TRUE(absl::HexStringToBytes("020080", &headers_frame_payload));
  std::string headers_frame_header =
      HttpEncoder::SerializeHeadersFrameHeader(headers_frame_payload.length());
  std::string headers_frame =
      absl::StrCat(headers_frame_header, headers_frame_payload);
  stream->OnStreamFrame(QuicStreamFrame(stream_id, false, 0, headers_frame));

  // Decoding is blocked because dynamic table entry has not been received yet.
  EXPECT_FALSE(stream->headers_decompressed());

  // |session_| gets destoyed.  That destroys QpackDecoder, a member of
  // QuicSpdySession (derived class), which destroys QpackDecoderHeaderTable.
  // Then |*stream|, owned by QuicSession (base class) get destroyed, which
  // destroys QpackProgessiveDecoder, a registered Observer of
  // QpackDecoderHeaderTable.  This must not cause a crash.
}

TEST_P(QuicSpdySessionTestClient, ResetAfterInvalidIncomingStreamType) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();

  const QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);
  ASSERT_TRUE(session_->UsesPendingStreamForFrame(STREAM_FRAME, stream_id));

  // Payload consists of two bytes.  The first byte is an unknown unidirectional
  // stream type.  The second one would be the type of a push stream, but it
  // must not be interpreted as stream type.
  std::string payload;
  ASSERT_TRUE(absl::HexStringToBytes("3f01", &payload));
  QuicStreamFrame frame(stream_id, /* fin = */ false, /* offset = */ 0,
                        payload);

  // A STOP_SENDING frame is sent in response to the unknown stream type.
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke(&VerifyAndClearStopSendingFrame));
  session_->OnStreamFrame(frame);

  // There are no active streams.
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(&*session_));

  // The pending stream is still around, because it did not receive a FIN.
  PendingStream* pending =
      QuicSessionPeer::GetPendingStream(&*session_, stream_id);
  ASSERT_TRUE(pending);

  // The pending stream must ignore read data.
  EXPECT_TRUE(pending->sequencer()->ignore_read_data());

  // If the stream frame is received again, it should be ignored.
  session_->OnStreamFrame(frame);

  // Receive RESET_STREAM.
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_id,
                               QUIC_STREAM_CANCELLED,
                               /* bytes_written = */ payload.size());

  session_->OnRstStream(rst_frame);

  // The stream is closed.
  EXPECT_FALSE(QuicSessionPeer::GetPendingStream(&*session_, stream_id));
}

TEST_P(QuicSpdySessionTestClient, FinAfterInvalidIncomingStreamType) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();

  const QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);
  ASSERT_TRUE(session_->UsesPendingStreamForFrame(STREAM_FRAME, stream_id));

  // Payload consists of two bytes.  The first byte is an unknown unidirectional
  // stream type.  The second one would be the type of a push stream, but it
  // must not be interpreted as stream type.
  std::string payload;
  ASSERT_TRUE(absl::HexStringToBytes("3f01", &payload));
  QuicStreamFrame frame(stream_id, /* fin = */ false, /* offset = */ 0,
                        payload);

  // A STOP_SENDING frame is sent in response to the unknown stream type.
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillOnce(Invoke(&VerifyAndClearStopSendingFrame));
  session_->OnStreamFrame(frame);

  // The pending stream is still around, because it did not receive a FIN.
  PendingStream* pending =
      QuicSessionPeer::GetPendingStream(&*session_, stream_id);
  EXPECT_TRUE(pending);

  // The pending stream must ignore read data.
  EXPECT_TRUE(pending->sequencer()->ignore_read_data());

  // If the stream frame is received again, it should be ignored.
  session_->OnStreamFrame(frame);

  // Receive FIN.
  session_->OnStreamFrame(QuicStreamFrame(stream_id, /* fin = */ true,
                                          /* offset = */ payload.size(), ""));

  EXPECT_FALSE(QuicSessionPeer::GetPendingStream(&*session_, stream_id));
}

TEST_P(QuicSpdySessionTestClient, ResetInMiddleOfStreamType) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  const QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);
  ASSERT_TRUE(session_->UsesPendingStreamForFrame(STREAM_FRAME, stream_id));

  // Payload is the first byte of a two byte varint encoding.
  std::string payload;
  ASSERT_TRUE(absl::HexStringToBytes("40", &payload));
  QuicStreamFrame frame(stream_id, /* fin = */ false, /* offset = */ 0,
                        payload);

  session_->OnStreamFrame(frame);
  EXPECT_TRUE(QuicSessionPeer::GetPendingStream(&*session_, stream_id));

  // Receive RESET_STREAM.
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_id,
                               QUIC_STREAM_CANCELLED,
                               /* bytes_written = */ payload.size());

  session_->OnRstStream(rst_frame);

  // The stream is closed.
  EXPECT_FALSE(QuicSessionPeer::GetPendingStream(&*session_, stream_id));
}

TEST_P(QuicSpdySessionTestClient, FinInMiddleOfStreamType) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  const QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);
  ASSERT_TRUE(session_->UsesPendingStreamForFrame(STREAM_FRAME, stream_id));

  // Payload is the first byte of a two byte varint encoding with a FIN.
  std::string payload;
  ASSERT_TRUE(absl::HexStringToBytes("40", &payload));
  QuicStreamFrame frame(stream_id, /* fin = */ true, /* offset = */ 0, payload);

  session_->OnStreamFrame(frame);
  EXPECT_FALSE(QuicSessionPeer::GetPendingStream(&*session_, stream_id));
}

TEST_P(QuicSpdySessionTestClient, DuplicateHttp3UnidirectionalStreams) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  QuicStreamId id1 =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);
  char type1[] = {kControlStream};

  QuicStreamFrame data1(id1, false, 0, absl::string_view(type1, 1));
  EXPECT_CALL(debug_visitor, OnPeerControlStreamCreated(id1));
  session_->OnStreamFrame(data1);
  QuicStreamId id2 =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 1);
  QuicStreamFrame data2(id2, false, 0, absl::string_view(type1, 1));
  EXPECT_CALL(debug_visitor, OnPeerControlStreamCreated(id2)).Times(0);
  EXPECT_QUIC_PEER_BUG(
      {
        EXPECT_CALL(*connection_,
                    CloseConnection(QUIC_HTTP_DUPLICATE_UNIDIRECTIONAL_STREAM,
                                    "Control stream is received twice.", _));
        session_->OnStreamFrame(data2);
      },
      "Received a duplicate Control stream: Closing connection.");

  QuicStreamId id3 =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 2);
  char type2[]{kQpackEncoderStream};

  QuicStreamFrame data3(id3, false, 0, absl::string_view(type2, 1));
  EXPECT_CALL(debug_visitor, OnPeerQpackEncoderStreamCreated(id3));
  session_->OnStreamFrame(data3);

  QuicStreamId id4 =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 3);
  QuicStreamFrame data4(id4, false, 0, absl::string_view(type2, 1));
  EXPECT_CALL(debug_visitor, OnPeerQpackEncoderStreamCreated(id4)).Times(0);
  EXPECT_QUIC_PEER_BUG(
      {
        EXPECT_CALL(
            *connection_,
            CloseConnection(QUIC_HTTP_DUPLICATE_UNIDIRECTIONAL_STREAM,
                            "QPACK encoder stream is received twice.", _));
        session_->OnStreamFrame(data4);
      },
      "Received a duplicate QPACK encoder stream: Closing connection.");

  QuicStreamId id5 =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 4);
  char type3[]{kQpackDecoderStream};

  QuicStreamFrame data5(id5, false, 0, absl::string_view(type3, 1));
  EXPECT_CALL(debug_visitor, OnPeerQpackDecoderStreamCreated(id5));
  session_->OnStreamFrame(data5);

  QuicStreamId id6 =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 5);
  QuicStreamFrame data6(id6, false, 0, absl::string_view(type3, 1));
  EXPECT_CALL(debug_visitor, OnPeerQpackDecoderStreamCreated(id6)).Times(0);
  EXPECT_QUIC_PEER_BUG(
      {
        EXPECT_CALL(
            *connection_,
            CloseConnection(QUIC_HTTP_DUPLICATE_UNIDIRECTIONAL_STREAM,
                            "QPACK decoder stream is received twice.", _));
        session_->OnStreamFrame(data6);
      },
      "Received a duplicate QPACK decoder stream: Closing connection.");
}

TEST_P(QuicSpdySessionTestClient, EncoderStreamError) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  std::string data;
  ASSERT_TRUE(
      absl::HexStringToBytes("02"   // Encoder stream.
                             "00",  // Duplicate entry 0, but no entries exist.
                             &data));

  QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);

  QuicStreamFrame frame(stream_id, /* fin = */ false, /* offset = */ 0, data);

  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_QPACK_ENCODER_STREAM_DUPLICATE_INVALID_RELATIVE_INDEX,
                  "Encoder stream error: Invalid relative index.", _));
  session_->OnStreamFrame(frame);
}

TEST_P(QuicSpdySessionTestClient, DecoderStreamError) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  std::string data;
  ASSERT_TRUE(absl::HexStringToBytes(
      "03"   // Decoder stream.
      "00",  // Insert Count Increment with forbidden increment value of zero.
      &data));

  QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);

  QuicStreamFrame frame(stream_id, /* fin = */ false, /* offset = */ 0, data);

  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_QPACK_DECODER_STREAM_INVALID_ZERO_INCREMENT,
                      "Decoder stream error: Invalid increment value 0.", _));
  session_->OnStreamFrame(frame);
}

TEST_P(QuicSpdySessionTestClient, InvalidHttp3GoAway) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_HTTP_GOAWAY_INVALID_STREAM_ID,
                              "GOAWAY with invalid stream ID", _));
  QuicStreamId stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 0);
  session_->OnHttp3GoAway(stream_id);
}

TEST_P(QuicSpdySessionTestClient, Http3GoAwayLargerIdThanBefore) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  EXPECT_FALSE(session_->goaway_received());
  QuicStreamId stream_id1 =
      GetNthClientInitiatedBidirectionalStreamId(transport_version(), 0);
  session_->OnHttp3GoAway(stream_id1);
  EXPECT_TRUE(session_->goaway_received());

  EXPECT_CALL(
      *connection_,
      CloseConnection(
          QUIC_HTTP_GOAWAY_ID_LARGER_THAN_PREVIOUS,
          "GOAWAY received with ID 4 greater than previously received ID 0",
          _));
  QuicStreamId stream_id2 =
      GetNthClientInitiatedBidirectionalStreamId(transport_version(), 1);
  session_->OnHttp3GoAway(stream_id2);
}

TEST_P(QuicSpdySessionTestClient, CloseConnectionOnCancelPush) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }

  CompleteHandshake();
  StrictMock<MockHttp3DebugVisitor> debug_visitor;
  session_->set_debug_visitor(&debug_visitor);

  // Create control stream.
  QuicStreamId receive_control_stream_id =
      GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 3);
  char type[] = {kControlStream};
  absl::string_view stream_type(type, 1);
  QuicStreamOffset offset = 0;
  QuicStreamFrame data1(receive_control_stream_id, /* fin = */ false, offset,
                        stream_type);
  offset += stream_type.length();
  EXPECT_CALL(debug_visitor,
              OnPeerControlStreamCreated(receive_control_stream_id));
  session_->OnStreamFrame(data1);
  EXPECT_EQ(receive_control_stream_id,
            QuicSpdySessionPeer::GetReceiveControlStream(&*session_)->id());

  // First frame has to be SETTINGS.
  std::string serialized_settings = HttpEncoder::SerializeSettingsFrame({});
  QuicStreamFrame data2(receive_control_stream_id, /* fin = */ false, offset,
                        serialized_settings);
  offset += serialized_settings.length();
  EXPECT_CALL(debug_visitor, OnSettingsFrameReceived(_));
  session_->OnStreamFrame(data2);

  std::string cancel_push_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("03"   // CANCEL_PUSH
                             "01"   // length
                             "00",  // push ID
                             &cancel_push_frame));
  QuicStreamFrame data3(receive_control_stream_id, /* fin = */ false, offset,
                        cancel_push_frame);
  EXPECT_CALL(*connection_, CloseConnection(QUIC_HTTP_FRAME_ERROR,
                                            "CANCEL_PUSH frame received.", _))
      .WillOnce(
          Invoke(connection_, &MockQuicConnection::ReallyCloseConnection));
  EXPECT_CALL(*connection_,
              SendConnectionClosePacket(QUIC_HTTP_FRAME_ERROR, _,
                                        "CANCEL_PUSH frame received."));
  session_->OnStreamFrame(data3);
}

TEST_P(QuicSpdySessionTestServer, OnSetting) {
  Initialize();
  CompleteHandshake();
  if (VersionUsesHttp3(transport_version())) {
    EXPECT_EQ(std::numeric_limits<size_t>::max(),
              session_->max_outbound_header_list_size());
    session_->OnSetting(SETTINGS_MAX_FIELD_SECTION_SIZE, 5);
    EXPECT_EQ(5u, session_->max_outbound_header_list_size());

    EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
        .WillRepeatedly(Return(WriteResult(WRITE_STATUS_OK, 0)));
    QpackEncoder* qpack_encoder = session_->qpack_encoder();
    EXPECT_EQ(0u, QpackEncoderPeer::maximum_blocked_streams(qpack_encoder));
    session_->OnSetting(SETTINGS_QPACK_BLOCKED_STREAMS, 12);
    EXPECT_EQ(12u, QpackEncoderPeer::maximum_blocked_streams(qpack_encoder));

    QpackEncoderHeaderTable* header_table =
        QpackEncoderPeer::header_table(qpack_encoder);
    EXPECT_EQ(0u, header_table->maximum_dynamic_table_capacity());
    session_->OnSetting(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 37);
    EXPECT_EQ(37u, header_table->maximum_dynamic_table_capacity());

    return;
  }

  EXPECT_EQ(std::numeric_limits<size_t>::max(),
            session_->max_outbound_header_list_size());
  session_->OnSetting(SETTINGS_MAX_FIELD_SECTION_SIZE, 5);
  EXPECT_EQ(5u, session_->max_outbound_header_list_size());

  spdy::HpackEncoder* hpack_encoder =
      QuicSpdySessionPeer::GetSpdyFramer(&*session_)->GetHpackEncoder();
  EXPECT_EQ(4096u, hpack_encoder->CurrentHeaderTableSizeSetting());
  session_->OnSetting(spdy::SETTINGS_HEADER_TABLE_SIZE, 59);
  EXPECT_EQ(59u, hpack_encoder->CurrentHeaderTableSizeSetting());
}

TEST_P(QuicSpdySessionTestServer, FineGrainedHpackErrorCodes) {
  Initialize();
  if (VersionUsesHttp3(transport_version())) {
    // HPACK is not used in HTTP/3.
    return;
  }

  QuicStreamId request_stream_id = 5;
  session_->CreateIncomingStream(request_stream_id);

  // Index 126 does not exist (static table has 61 entries and dynamic table is
  // empty).
  std::string headers_frame;
  ASSERT_TRUE(
      absl::HexStringToBytes("000006"    // length
                             "01"        // type
                             "24"        // flags: PRIORITY | END_HEADERS
                             "00000005"  // stream_id
                             "00000000"  // stream dependency
                             "10"        // weight
                             "fe",       // payload: reference to index 126.
                             &headers_frame));
  QuicStreamId headers_stream_id =
      QuicUtils::GetHeadersStreamId(transport_version());
  QuicStreamFrame data(headers_stream_id, false, 0, headers_frame);

  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HPACK_INVALID_INDEX,
                      "SPDY framing error: HPACK_INVALID_INDEX",
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  session_->OnStreamFrame(data);
}

TEST_P(QuicSpdySessionTestServer, PeerClosesCriticalReceiveStream) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  CompleteHandshake();

  struct {
    char type;
    const char* error_details;
  } kTestData[] = {
      {kControlStream, "RESET_STREAM received for receive control stream"},
      {kQpackEncoderStream, "RESET_STREAM received for QPACK receive stream"},
      {kQpackDecoderStream, "RESET_STREAM received for QPACK receive stream"},
  };
  for (size_t i = 0; i < ABSL_ARRAYSIZE(kTestData); ++i) {
    QuicStreamId stream_id =
        GetNthClientInitiatedUnidirectionalStreamId(transport_version(), i + 1);
    const QuicByteCount data_length = 1;
    QuicStreamFrame data(stream_id, false, 0,
                         absl::string_view(&kTestData[i].type, data_length));
    session_->OnStreamFrame(data);

    EXPECT_CALL(*connection_, CloseConnection(QUIC_HTTP_CLOSED_CRITICAL_STREAM,
                                              kTestData[i].error_details, _));

    QuicRstStreamFrame rst(kInvalidControlFrameId, stream_id,
                           QUIC_STREAM_CANCELLED, data_length);
    session_->OnRstStream(rst);
  }
}

TEST_P(QuicSpdySessionTestServer,
       H3ControlStreamsLimitedByConnectionFlowControl) {
  Initialize();
  if (!VersionUsesHttp3(transport_version())) {
    return;
  }
  // Ensure connection level flow control blockage.
  QuicFlowControllerPeer::SetSendWindowOffset(session_->flow_controller(), 0
"""


```