Response:
The user wants a summary of the functionality of the provided C++ code, which is part of Chromium's QUIC implementation. I need to analyze the test cases within the `QuicStreamTest` class and describe what aspects of `QuicStream` they are verifying.

Here's a breakdown of the tests and their functionalities:

1. **MarkConnectionLevelWriteBlockedOnWindowUpdateFrameWithBufferedData:** Checks if a stream correctly marks the connection as write-blocked after receiving a `WINDOW_UPDATE` frame when it has buffered data.
2. **MarkConnectionLevelWriteBlockedOnWindowUpdateFrameWithNoBufferedData:** Similar to the previous test, but verifies the behavior when there's no buffered data.
3. **RetransmitStreamData:** Tests various scenarios of retransmitting stream data, including partial and full consumption of retransmitted data.
4. **ResetStreamOnTtlExpiresRetransmitLostData:** Verifies that a stream is reset when its Time-To-Live (TTL) expires while retransmitting lost data.
5. **ResetStreamOnTtlExpiresEarlyRetransmitData:** Checks the stream reset behavior when TTL expires during an early retransmission attempt.
6. **OnStreamResetReadOrReadWrite:** Tests if receiving a `RST_STREAM` frame closes only the read side (for IETF QUIC) or both read and write sides (for Google QUIC).
7. **WindowUpdateForReadOnlyStream:** Ensures that receiving a `WINDOW_UPDATE` on a read-only stream results in a connection error.
8. **RstStreamFrameChangesCloseOffset:** Checks if receiving a `RST_STREAM` frame after receiving stream data leads to a connection error due to multiple offset changes.
9. **EmptyStreamFrameWithNoFin:** Verifies how the stream handles an empty `STREAM` frame without the FIN flag.
10. **SendRstWithCustomIetfCode:** Tests sending a `RST_STREAM` frame with a custom error code.
11. **ResetWhenOffsetReached:** Checks if a stream is correctly reset upon receiving enough data to reach a specified reliable offset defined by a `RESET_STREAM_AT` frame.
12. **ResetWhenOffsetReachedOutOfOrder:** Similar to the previous test, but data arrives out of order.
13. **HigherReliableSizeIgnored:** Verifies that if multiple `RESET_STREAM_AT` frames are received, the one with a higher reliable offset is ignored.
14. **InstantReset:** Tests if a stream is reset immediately when a `RESET_STREAM_AT` frame is received before the data.
15. **ResetIgnoredDueToFin:** Checks if a `RESET_STREAM_AT` frame is ignored if the FIN flag has already been received.
16. **ReliableOffsetBeyondFin:** Ensures that a connection error occurs if a `RESET_STREAM_AT` frame specifies a reliable offset beyond the received FIN.
17. **FinBeforeReliableOffset:** Verifies a connection error when a FIN is received before the reliable offset specified in a `RESET_STREAM_AT` frame.

These tests cover various aspects of stream lifecycle, flow control, error handling, and retransmission mechanisms within the QUIC protocol.

Regarding JavaScript relevance, there isn't a direct functional relationship. However, these tests ensure the robustness of the underlying QUIC implementation in Chromium, which is used by web browsers. This indirectly affects the performance and reliability of web applications built with JavaScript that rely on network communication.

For assumptions and input/output, I can provide examples based on some of the test cases.

For common user/programming errors, I can point out scenarios these tests are designed to prevent.

Finally, I'll outline the user actions leading to this code being executed as debugging context.
这是 Chromium 网络栈中 `net/third_party/quiche/src/quiche/quic/core/quic_stream_test.cc` 文件的第三部分，主要包含了一系列针对 `QuicStream` 类的单元测试。综合前两部分，我们可以归纳出该文件的主要功能是：**全面测试 QUIC 协议中 `QuicStream` 类的各种功能和边界情况，确保其行为符合预期。**

具体来说，这部分测试的功能包括：

*   **在接收到 WINDOW_UPDATE 帧时标记连接级别的写阻塞 (MarkConnectionLevelWriteBlockedOnWindowUpdateFrameWithBufferedData, MarkConnectionLevelWriteBlockedOnWindowUpdateFrameWithNoBufferedData):**  测试在流有或没有缓冲数据的情况下，接收到 `WINDOW_UPDATE` 帧后，流是否正确地标记了连接级别的写阻塞状态。这涉及到 QUIC 的流控机制。
*   **重传流数据 (RetransmitStreamData):** 验证 `QuicStream` 在需要重传数据时的行为，包括部分和全部重传的情况，以及与 `FIN` 标志的结合。
*   **当 TTL 过期时重置流 (ResetStreamOnTtlExpiresRetransmitLostData, ResetStreamOnTtlExpiresEarlyRetransmitData):** 测试当流的生存时间 (TTL) 过期时，即使在尝试重传数据的情况下，流也会被重置。这涉及到 QUIC 的可靠性机制和资源管理。
*   **OnStreamReset 根据版本执行单向或双向关闭 (OnStreamResetReadOrReadWrite):**  根据 QUIC 协议的版本 (特别是区分 Google QUIC 和 IETF QUIC)，测试接收到 `RST_STREAM` 帧后，流是单向关闭 (只关闭读端) 还是双向关闭 (读写端都关闭)。
*   **只读流接收到 WindowUpdate 的处理 (WindowUpdateForReadOnlyStream):**  测试当只读流 (如单向流) 接收到 `WINDOW_UPDATE` 帧时，连接是否会因为协议违反而被关闭。
*   **RstStreamFrame 改变关闭偏移量的情况 (RstStreamFrameChangesCloseOffset):** 测试在接收到流数据后，再接收到 `RST_STREAM` 帧是否会导致连接因偏移量不一致而被关闭。
*   **空的 StreamFrame 且没有 FIN 标志的处理 (EmptyStreamFrameWithNoFin):**  测试如何处理空的 `STREAM` 帧，特别是当它没有设置 `FIN` 标志时。不同版本的 QUIC 可能有不同的处理方式。
*   **发送带有自定义 IETF 代码的 RST 帧 (SendRstWithCustomIetfCode):** 测试发送 `RST_STREAM` 帧时是否能够使用自定义的 IETF 错误代码。
*   **当达到指定偏移量时重置流 (ResetWhenOffsetReached, ResetWhenOffsetReachedOutOfOrder, HigherReliableSizeIgnored, InstantReset, ResetIgnoredDueToFin, ReliableOffsetBeyondFin, FinBeforeReliableOffset):**  这些测试集中验证了 IETF QUIC 中引入的 `RESET_STREAM_AT` 帧的功能。它们测试了在接收到 `RESET_STREAM_AT` 帧后，当接收到的数据达到或超过指定的可靠偏移量时，流是否会被正确重置。测试了数据到达的顺序，以及多个 `RESET_STREAM_AT` 帧的情况，还有与 `FIN` 标志的交互。

**与 JavaScript 的功能关系:**

`quic_stream_test.cc` 文件中的代码是 C++ 实现的，直接与 JavaScript 没有功能上的关系。然而，它测试的是 Chromium 浏览器网络栈的核心 QUIC 协议实现。JavaScript 通过浏览器提供的 Web API (例如 `fetch`, `WebSocket`) 来进行网络通信，这些 API 底层可能会使用 QUIC 协议。

**举例说明:**

假设一个 JavaScript 应用使用 `fetch` API 发起一个 HTTP/3 请求（HTTP/3 基于 QUIC）。当服务器发送数据给浏览器时，数据会通过 QUIC 流传输。`quic_stream_test.cc` 中的测试确保了 `QuicStream` 类能够正确地处理各种数据接收、重传、流控和错误处理的情况。如果这些 C++ 测试失败，可能导致 JavaScript 应用的网络请求失败、数据丢失或连接不稳定。

**逻辑推理 (假设输入与输出):**

以 `MarkConnectionLevelWriteBlockedOnWindowUpdateFrameWithBufferedData` 测试为例：

*   **假设输入:**
    *   一个已经激活的 `QuicStream` 对象，并缓冲了一些待发送的数据。
    *   接收到一个 `WINDOW_UPDATE` 帧，允许发送更多数据。
*   **预期输出:**
    *   `HasWriteBlockedStreams()` 返回 `true`，表明连接级别存在写阻塞的流。
    *   `stream->HasBufferedData()` 返回 `true`，表明流仍然有缓冲数据。

**用户或编程常见的使用错误:**

这些测试主要是针对 QUIC 协议实现的，用户或程序员直接与 `QuicStream` 交互的可能性较低。但是，理解这些测试覆盖的场景可以帮助理解 QUIC 协议的工作原理，从而避免在使用基于 QUIC 的网络服务时产生误解。

例如，`WindowUpdateForReadOnlyStream` 测试提醒我们，不应该在只读流上发送流控更新，这是一种协议错误。

**用户操作到达这里的步骤 (调试线索):**

通常，用户不会直接触发这些单元测试。这些测试是由 Chromium 的开发者在开发和维护网络栈时运行的。以下是一些可能的场景，导致开发者需要查看或调试这部分代码：

1. **性能问题:** 用户报告网站加载缓慢，开发者可能需要检查 QUIC 的流控机制是否正常工作，`MarkConnectionLevelWriteBlockedOnWindowUpdateFrame*` 相关的测试可以提供线索。
2. **连接错误:** 用户遇到连接断开或重置的问题，开发者可能需要检查流的重置逻辑，例如 `ResetStreamOnTtlExpires*` 和 `OnStreamResetReadOrReadWrite` 相关的测试。
3. **协议兼容性问题:** 当新的 QUIC 版本发布或与其他 QUIC 实现互操作时出现问题，开发者可能需要检查针对特定 QUIC 版本的行为，例如 `OnStreamResetReadOrReadWrite` 中区分 Google QUIC 和 IETF QUIC 的逻辑。
4. **新功能开发或 Bug 修复:** 在实现新的 QUIC 功能或修复与流相关的 Bug 时，开发者会编写或修改这些单元测试来验证代码的正确性。例如，在实现或调试 `RESET_STREAM_AT` 功能时，会关注 `ResetWhenOffsetReached*` 等一系列测试。

总而言之，`net/third_party/quiche/src/quiche/quic/core/quic_stream_test.cc` 的这部分代码通过详尽的测试用例，保障了 QUIC 协议中流管理的关键功能的正确性和健壮性，这对于构建稳定高效的网络应用至关重要。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
teOrBufferData(data, false, nullptr);
  EXPECT_FALSE(HasWriteBlockedStreams());

  QuicWindowUpdateFrame window_update(kInvalidControlFrameId, stream_->id(),
                                      1234);

  stream->OnWindowUpdateFrame(window_update);
  // Verify stream is marked connection level write blocked.
  EXPECT_TRUE(HasWriteBlockedStreams());
  EXPECT_TRUE(stream->HasBufferedData());
}

// Regression test for b/73282665.
TEST_P(QuicStreamTest,
       MarkConnectionLevelWriteBlockedOnWindowUpdateFrameWithNoBufferedData) {
  Initialize();

  // Set the config to a small value so that a newly created stream has small
  // send flow control window.
  QuicConfigPeer::SetReceivedInitialStreamFlowControlWindow(session_->config(),
                                                            100);
  QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesIncomingBidirectional(
      session_->config(), 100);
  auto stream = new TestStream(GetNthClientInitiatedBidirectionalStreamId(
                                   GetParam().transport_version, 2),
                               session_.get(), BIDIRECTIONAL);
  session_->ActivateStream(absl::WrapUnique(stream));

  std::string data(100, '.');
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_CALL(*session_, SendBlocked(_, _)).Times(1);
  stream->WriteOrBufferData(data, false, nullptr);
  EXPECT_FALSE(HasWriteBlockedStreams());

  QuicWindowUpdateFrame window_update(kInvalidControlFrameId, stream_->id(),
                                      120);
  stream->OnWindowUpdateFrame(window_update);
  EXPECT_FALSE(stream->HasBufferedData());
  // Verify stream is marked as blocked although there is no buffered data.
  EXPECT_TRUE(HasWriteBlockedStreams());
}

TEST_P(QuicStreamTest, RetransmitStreamData) {
  Initialize();
  InSequence s;

  // Send [0, 18) with fin.
  EXPECT_CALL(*session_, WritevData(stream_->id(), _, _, _, _, _))
      .Times(2)
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  stream_->WriteOrBufferData(kData1, false, nullptr);
  stream_->WriteOrBufferData(kData1, true, nullptr);
  // Ack [10, 13).
  QuicByteCount newly_acked_length = 0;
  stream_->OnStreamFrameAcked(10, 3, false, QuicTime::Delta::Zero(),
                              QuicTime::Zero(), &newly_acked_length);
  EXPECT_EQ(3u, newly_acked_length);
  // Retransmit [0, 18) with fin, and only [0, 8) is consumed.
  EXPECT_CALL(*session_, WritevData(stream_->id(), 10, 0, NO_FIN, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 8, 0u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  EXPECT_FALSE(stream_->RetransmitStreamData(0, 18, true, PTO_RETRANSMISSION));

  // Retransmit [0, 18) with fin, and all is consumed.
  EXPECT_CALL(*session_, WritevData(stream_->id(), 10, 0, NO_FIN, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_CALL(*session_, WritevData(stream_->id(), 5, 13, FIN, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_TRUE(stream_->RetransmitStreamData(0, 18, true, PTO_RETRANSMISSION));

  // Retransmit [0, 8) with fin, and all is consumed.
  EXPECT_CALL(*session_, WritevData(stream_->id(), 8, 0, NO_FIN, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_CALL(*session_, WritevData(stream_->id(), 0, 18, FIN, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_TRUE(stream_->RetransmitStreamData(0, 8, true, PTO_RETRANSMISSION));
}

TEST_P(QuicStreamTest, ResetStreamOnTtlExpiresRetransmitLostData) {
  Initialize();

  EXPECT_CALL(*session_, WritevData(stream_->id(), 200, 0, FIN, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  std::string body(200, 'a');
  stream_->WriteOrBufferData(body, true, nullptr);

  // Set TTL to be 1 s.
  QuicTime::Delta ttl = QuicTime::Delta::FromSeconds(1);
  ASSERT_TRUE(stream_->MaybeSetTtl(ttl));
  // Verify data gets retransmitted because TTL does not expire.
  EXPECT_CALL(*session_, WritevData(stream_->id(), 100, 0, NO_FIN, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_TRUE(stream_->RetransmitStreamData(0, 100, false, PTO_RETRANSMISSION));
  stream_->OnStreamFrameLost(100, 100, true);
  EXPECT_TRUE(stream_->HasPendingRetransmission());

  connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
  // Verify stream gets reset because TTL expires.
  if (session_->version().UsesHttp3()) {
    EXPECT_CALL(*session_,
                MaybeSendStopSendingFrame(_, QuicResetStreamError::FromInternal(
                                                 QUIC_STREAM_TTL_EXPIRED)))
        .Times(1);
  }
  EXPECT_CALL(
      *session_,
      MaybeSendRstStreamFrame(
          _, QuicResetStreamError::FromInternal(QUIC_STREAM_TTL_EXPIRED), _))
      .Times(1);
  stream_->OnCanWrite();
}

TEST_P(QuicStreamTest, ResetStreamOnTtlExpiresEarlyRetransmitData) {
  Initialize();

  EXPECT_CALL(*session_, WritevData(stream_->id(), 200, 0, FIN, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  std::string body(200, 'a');
  stream_->WriteOrBufferData(body, true, nullptr);

  // Set TTL to be 1 s.
  QuicTime::Delta ttl = QuicTime::Delta::FromSeconds(1);
  ASSERT_TRUE(stream_->MaybeSetTtl(ttl));

  connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
  // Verify stream gets reset because TTL expires.
  if (session_->version().UsesHttp3()) {
    EXPECT_CALL(*session_,
                MaybeSendStopSendingFrame(_, QuicResetStreamError::FromInternal(
                                                 QUIC_STREAM_TTL_EXPIRED)))
        .Times(1);
  }
  EXPECT_CALL(
      *session_,
      MaybeSendRstStreamFrame(
          _, QuicResetStreamError::FromInternal(QUIC_STREAM_TTL_EXPIRED), _))
      .Times(1);
  stream_->RetransmitStreamData(0, 100, false, PTO_RETRANSMISSION);
}

// Test that OnStreamReset does one-way (read) closes if version 99, two way
// (read and write) if not version 99.
TEST_P(QuicStreamTest, OnStreamResetReadOrReadWrite) {
  Initialize();
  EXPECT_FALSE(stream_->write_side_closed());
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));

  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_->id(),
                               QUIC_STREAM_CANCELLED, 1234);
  stream_->OnStreamReset(rst_frame);
  if (VersionHasIetfQuicFrames(connection_->transport_version())) {
    // Version 99/IETF QUIC should close just the read side.
    EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream_));
    EXPECT_FALSE(stream_->write_side_closed());
  } else {
    // Google QUIC should close both sides of the stream.
    EXPECT_TRUE(stream_->write_side_closed());
    EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream_));
  }
}

TEST_P(QuicStreamTest, WindowUpdateForReadOnlyStream) {
  Initialize();

  QuicStreamId stream_id = QuicUtils::GetFirstUnidirectionalStreamId(
      connection_->transport_version(), Perspective::IS_CLIENT);
  TestStream stream(stream_id, session_.get(), READ_UNIDIRECTIONAL);
  QuicWindowUpdateFrame window_update_frame(kInvalidControlFrameId, stream_id,
                                            0);
  EXPECT_CALL(
      *connection_,
      CloseConnection(
          QUIC_WINDOW_UPDATE_RECEIVED_ON_READ_UNIDIRECTIONAL_STREAM,
          "WindowUpdateFrame received on READ_UNIDIRECTIONAL stream.", _));
  stream.OnWindowUpdateFrame(window_update_frame);
}

TEST_P(QuicStreamTest, RstStreamFrameChangesCloseOffset) {
  Initialize();

  QuicStreamFrame stream_frame(stream_->id(), true, 0, "abc");
  EXPECT_CALL(*stream_, OnDataAvailable());
  stream_->OnStreamFrame(stream_frame);
  QuicRstStreamFrame rst(kInvalidControlFrameId, stream_->id(),
                         QUIC_STREAM_CANCELLED, 0u);

  EXPECT_CALL(*connection_, CloseConnection(QUIC_STREAM_MULTIPLE_OFFSET, _, _));
  stream_->OnStreamReset(rst);
}

// Regression test for b/176073284.
TEST_P(QuicStreamTest, EmptyStreamFrameWithNoFin) {
  Initialize();
  QuicStreamFrame empty_stream_frame(stream_->id(), false, 0, "");
  if (stream_->version().HasIetfQuicFrames()) {
    EXPECT_CALL(*connection_,
                CloseConnection(QUIC_EMPTY_STREAM_FRAME_NO_FIN, _, _))
        .Times(0);
  } else {
    EXPECT_CALL(*connection_,
                CloseConnection(QUIC_EMPTY_STREAM_FRAME_NO_FIN, _, _));
  }
  EXPECT_CALL(*stream_, OnDataAvailable()).Times(0);
  stream_->OnStreamFrame(empty_stream_frame);
}

TEST_P(QuicStreamTest, SendRstWithCustomIetfCode) {
  Initialize();
  QuicResetStreamError error(QUIC_STREAM_CANCELLED, 0x1234abcd);
  EXPECT_CALL(*session_, MaybeSendRstStreamFrame(kTestStreamId, error, _))
      .Times(1);
  stream_->ResetWithError(error);
  EXPECT_TRUE(rst_sent());
}

TEST_P(QuicStreamTest, ResetWhenOffsetReached) {
  Initialize();
  if (!VersionHasIetfQuicFrames(session_->transport_version())) {
    return;
  }
  QuicResetStreamAtFrame rst(0, stream_->id(), QUIC_STREAM_CANCELLED, 400, 100);
  stream_->OnResetStreamAtFrame(rst);  // Nothing happens.

  // Send data to reach reliable_offset.
  char data[100];
  EXPECT_CALL(*stream_, OnDataAvailable()).WillOnce([this]() {
    stream_->ConsumeData(99);
  });
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), false, 0, absl::string_view(data, 99)));
  EXPECT_FALSE(stream_->rst_received());
  EXPECT_FALSE(stream_->read_side_closed());
  EXPECT_CALL(*stream_, OnDataAvailable()).WillOnce([this]() {
    stream_->ConsumeData(1);
  });
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, 99,
                                         absl::string_view(data + 99, 1)));
  EXPECT_TRUE(stream_->rst_received());
  EXPECT_TRUE(stream_->read_side_closed());
}

TEST_P(QuicStreamTest, ResetWhenOffsetReachedOutOfOrder) {
  Initialize();
  if (!VersionHasIetfQuicFrames(session_->transport_version())) {
    return;
  }
  QuicResetStreamAtFrame rst(0, stream_->id(), QUIC_STREAM_CANCELLED, 400, 100);
  stream_->OnResetStreamAtFrame(rst);  // Nothing happens.

  // Send data to reach reliable_offset.
  char data[100];
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, 99,
                                         absl::string_view(data + 99, 1)));
  EXPECT_FALSE(stream_->rst_received());
  EXPECT_FALSE(stream_->read_side_closed());
  EXPECT_CALL(*stream_, OnDataAvailable()).WillOnce([this]() {
    stream_->ConsumeData(100);
  });
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), false, 0, absl::string_view(data, 99)));
  EXPECT_TRUE(stream_->rst_received());
  EXPECT_TRUE(stream_->read_side_closed());
}

TEST_P(QuicStreamTest, HigherReliableSizeIgnored) {
  Initialize();
  if (!VersionHasIetfQuicFrames(session_->transport_version())) {
    return;
  }
  QuicResetStreamAtFrame rst(0, stream_->id(), QUIC_STREAM_CANCELLED, 400, 100);
  stream_->OnResetStreamAtFrame(rst);  // Nothing happens.
  QuicResetStreamAtFrame rst2(0, stream_->id(), QUIC_STREAM_CANCELLED, 400,
                              200);
  stream_->OnResetStreamAtFrame(rst2);  // Ignored.

  // Send data to reach reliable_offset.
  char data[100];
  EXPECT_CALL(*stream_, OnDataAvailable()).WillOnce([this]() {
    stream_->ConsumeData(99);
  });
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), false, 0, absl::string_view(data, 99)));
  EXPECT_FALSE(stream_->rst_received());
  EXPECT_FALSE(stream_->read_side_closed());
  EXPECT_CALL(*stream_, OnDataAvailable()).WillOnce([this]() {
    stream_->ConsumeData(1);
  });
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), false, 99,
                                         absl::string_view(data + 99, 1)));
  EXPECT_TRUE(stream_->rst_received());
  EXPECT_TRUE(stream_->read_side_closed());
}

TEST_P(QuicStreamTest, InstantReset) {
  Initialize();
  if (!VersionHasIetfQuicFrames(session_->transport_version())) {
    return;
  }
  char data[100];
  EXPECT_CALL(*stream_, OnDataAvailable()).WillOnce([this]() {
    stream_->ConsumeData(100);
  });
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), false, 0, absl::string_view(data, 100)));
  QuicResetStreamAtFrame rst(0, stream_->id(), QUIC_STREAM_CANCELLED, 400, 100);
  EXPECT_FALSE(stream_->rst_received());
  EXPECT_FALSE(stream_->read_side_closed());
  stream_->OnResetStreamAtFrame(rst);
  EXPECT_TRUE(stream_->rst_received());
  EXPECT_TRUE(stream_->read_side_closed());
}

TEST_P(QuicStreamTest, ResetIgnoredDueToFin) {
  Initialize();
  if (!VersionHasIetfQuicFrames(session_->transport_version())) {
    return;
  }
  char data[100];
  EXPECT_CALL(*stream_, OnDataAvailable()).WillOnce([this]() {
    stream_->ConsumeData(98);
  });
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), false, 0, absl::string_view(data, 98)));
  QuicResetStreamAtFrame rst(0, stream_->id(), QUIC_STREAM_CANCELLED, 100, 99);
  stream_->OnResetStreamAtFrame(rst);  // Nothing happens.
  // There is no call to OnFinRead() because the stream is responsible for
  // doing that.
  EXPECT_FALSE(stream_->rst_received());
  EXPECT_FALSE(stream_->read_side_closed());
  EXPECT_CALL(*stream_, OnDataAvailable()).WillOnce([this]() {
    stream_->ConsumeData(2);
    stream_->OnFinRead();
  });
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), true, 98,
                                         absl::string_view(data + 98, 2)));
  EXPECT_FALSE(stream_->rst_received());
  EXPECT_TRUE(stream_->read_side_closed());
}

TEST_P(QuicStreamTest, ReliableOffsetBeyondFin) {
  Initialize();
  if (!VersionHasIetfQuicFrames(session_->transport_version())) {
    return;
  }
  char data[100];
  stream_->OnStreamFrame(QuicStreamFrame(stream_->id(), true, 98,
                                         absl::string_view(data + 98, 2)));
  EXPECT_CALL(*connection_, CloseConnection(QUIC_STREAM_MULTIPLE_OFFSET, _, _))
      .Times(1);
  QuicResetStreamAtFrame rst(0, stream_->id(), QUIC_STREAM_CANCELLED, 101, 101);
  stream_->OnResetStreamAtFrame(rst);  // Nothing happens.
}

TEST_P(QuicStreamTest, FinBeforeReliableOffset) {
  Initialize();
  if (!VersionHasIetfQuicFrames(session_->transport_version())) {
    return;
  }
  QuicResetStreamAtFrame rst(0, stream_->id(), QUIC_STREAM_CANCELLED, 101, 101);
  stream_->OnResetStreamAtFrame(rst);  // Nothing happens.
  char data[100];
  EXPECT_CALL(*connection_, CloseConnection(QUIC_STREAM_MULTIPLE_OFFSET, _, _))
      .Times(1);
  stream_->OnStreamFrame(
      QuicStreamFrame(stream_->id(), true, 0, absl::string_view(data, 100)));
}

}  // namespace
}  // namespace test
}  // namespace quic

"""


```