Response:
The user wants a summary of the functionality of the provided C++ code snippet.
This snippet is part of a larger test file for `QuicStream` in Chromium's QUIC implementation.
The focus is on testing various scenarios related to sending and receiving data, handling FIN, flow control, retransmissions, and error conditions.

Here's a breakdown of the code's functionality:

1. **Flow Control Violation Test:** Verifies that sending more data than the allowed stream and connection flow control limits triggers a connection closure with the `QUIC_STREAM_LENGTH_OVERFLOW` error.

2. **Stream Too Long Test:** Checks that receiving a stream frame that exceeds the maximum stream length also results in a `QUIC_STREAM_LENGTH_OVERFLOW` error and connection closure.

3. **SetDraining Tests:**  Explores the stream's transition to the "draining" state when either incoming or outgoing data includes a FIN. It verifies the number of open and draining streams in the session.

4. **Early Response Fin Handling Test:** Confirms that a server can send a response with a FIN before fully receiving the client's request. It verifies that the received FIN from the client is still recorded.

5. **Stream Waits For Acks Test:**  Tests the logic for tracking unacknowledged stream data and the stream's `IsWaitingForAcks()` state. It checks how acks for data and FIN affect this state. It also tests retransmission and its impact on waiting for acks.

6. **Stream Data Get Acked Out Of Order Test:** Verifies that the stream correctly handles acknowledgments for data received out of order.

7. **Cancel Stream Test:** Examines the behavior of canceling a stream using `MaybeSendStopSending` and `Reset`. It checks if the stream waits for acks based on the error code and if RST_STREAM frames are sent.

8. **RstFrameReceived Tests:**  Tests how the stream reacts to receiving a `RST_STREAM` frame when it has and hasn't finished sending data. It considers differences in behavior between older QUIC versions and IETF QUIC.

9. **Connection Closed Test:** Verifies that when the connection is closed, the stream stops waiting for acknowledgments.

10. **CanWriteNewDataAfterData Test:** Checks a condition related to being able to write more data based on the amount of data already written.

11. **WriteBufferedData Test:** Focuses on testing the stream's buffering mechanism using `WriteOrBufferData` and `WriteMemSlices`. It verifies that data is buffered correctly, that `OnCanWriteNewData` is called at the right times based on buffer thresholds, and that `WriteMemSlices` behaves as expected.

12. **WritevDataReachStreamLimit Test:**  Confirms that writing data that would exceed the maximum stream length using `WriteMemSlices` triggers a `QUIC_STREAM_LENGTH_OVERFLOW` error.

13. **WriteMemSlices Test:**  Similar to `WriteBufferedData`, but specifically focuses on testing the `WriteMemSlices` function with `QuicheMemSlice` objects, including handling FIN and stream limits.

14. **StreamDataGetAckedMultipleTimes Test:** Checks the scenario where stream data is acknowledged multiple times with overlapping ack ranges.

15. **OnStreamFrameLost Test:** Simulates the loss of stream frames and verifies that the stream correctly identifies data for retransmission and handles bundling of retransmitted data and FIN.

16. **CannotBundleLostFin Test:**  Specifically checks that a lost FIN frame is retransmitted separately when data associated with it is also lost.

17. **MarkConnectionLevelWriteBlockedOnWindowUpdateFrame Test:** (Truncated in the input) Likely tests how the stream interacts with connection-level flow control and marks the connection as blocked when the stream's send window is limited.这是目录为net/third_party/quiche/src/quiche/quic/core/quic_stream_test.cc的chromium 网络栈的源代码文件的一部分，主要的功能是**测试 QUIC 流（QuicStream）的各种行为和状态转换**。

具体来说，这部分代码侧重于测试以下方面的功能：

**核心功能点:**

* **流长度限制 (Stream Length Limits):**
    * 测试当接收到的数据帧超过流的最大长度时，连接是否会正确关闭并报错 `QUIC_STREAM_LENGTH_OVERFLOW`。
    * 测试当尝试写入超过流最大长度的数据时，连接是否会正确关闭并报错 `QUIC_STREAM_LENGTH_OVERFLOW`。
* **流的 draining 状态 (Stream Draining State):**
    * 测试当流接收到带有 FIN 标志的数据帧时，流和会话的状态变化。
    * 测试当流发送带有 FIN 标志的数据时，流和会话的状态变化。
    * 验证无论 FIN 是先接收还是先发送，流都能正确进入 draining 状态。
* **提前结束响应 (Early Response FIN Handling):**
    * 测试服务器在未完全接收客户端请求的情况下发送带有 FIN 标志的响应，验证已接收的 FIN 是否被正确记录。
* **流等待 ACK (Stream Waits For Acks):**
    * 测试流在发送数据后是否会等待 ACK。
    * 验证收到 ACK 后，流是否停止等待 ACK。
    * 测试发送 FIN 后，流是否会等待 FIN 的 ACK。
    * 测试数据包丢失后重传以及 ACK 对等待 ACK 状态的影响。
* **乱序 ACK (Stream Data Get Acked Out Of Order):**
    * 测试流能否正确处理乱序到达的数据 ACK。
* **取消流 (Cancel Stream):**
    * 测试调用 `MaybeSendStopSending` 和 `Reset` 方法取消流的行为。
    * 验证取消流后，流是否停止等待 ACK。
    * 测试是否会发送 `RST_STREAM` 帧。
* **接收 RST 帧 (RstFrameReceived):**
    * 测试流接收到 `RST_STREAM` 帧时的行为，特别是当流尚未完成发送数据时。
    * 区分不同 QUIC 版本（如 IETF QUIC）对接收 `RST_STREAM` 的处理方式。
* **连接关闭 (Connection Closed):**
    * 测试当连接关闭时，流是否停止等待 ACK。
* **写入新数据条件 (CanWriteNewDataAfterData):**
    * 测试在写入一定量数据后，是否可以继续写入新数据的条件。
* **缓冲数据写入 (WriteBufferedData):**
    * 测试流的缓冲机制，当写入大量数据时，数据是否被正确缓冲。
    * 测试 `OnCanWrite` 回调在缓冲数据量达到阈值时的触发情况。
    * 区分使用 `WriteOrBufferData` 和 `WriteMemSlices` 的缓冲行为。
* **`WriteMemSlices` 写入限制 (WritevDataReachStreamLimit, WriteMemSlicesReachStreamLimit):**
    * 测试使用 `WriteMemSlices` 写入数据时，是否会受到流长度的限制，以及超过限制时是否会触发错误。
* **多次 ACK (StreamDataGetAckedMultipleTimes):**
    * 测试流能否正确处理对同一部分数据的多次 ACK。
* **数据帧丢失 (OnStreamFrameLost):**
    * 模拟数据帧丢失，测试流的重传机制。
    * 验证丢失的数据帧是否会被标记为待重传。
    * 测试 `OnCanWrite` 被调用后是否会触发重传。
    * 验证 FIN 帧在数据帧丢失情况下的处理。
* **不能捆绑丢失的 FIN (CannotBundleLostFin):**
    * 测试当数据帧和 FIN 帧同时丢失时，FIN 帧是否会单独重传，而不是与数据帧捆绑。
* **连接层面阻塞 (MarkConnectionLevelWriteBlockedOnWindowUpdateFrame):**
    * (代码片段不完整)  推测是测试当流的发送窗口受限时，是否会正确标记连接层面为写阻塞。

**与 Javascript 的关系举例说明:**

虽然这段 C++ 代码直接在 Chromium 的网络栈中运行，与 Javascript 没有直接的代码关联，但其测试的 QUIC 协议功能直接影响着 Web 浏览器中基于 QUIC 的网络连接。

假设一个使用 Javascript 的 Web 应用通过 HTTPS 发起了一个基于 QUIC 的请求：

1. **流长度限制:**  如果服务器返回的数据量超过了浏览器为该流预设的最大长度，浏览器底层的 QUIC 实现（由这段测试代码覆盖）会检测到 `QUIC_STREAM_LENGTH_OVERFLOW`，并可能关闭连接，从而阻止 Javascript 应用接收到过大的数据，防止潜在的内存溢出或安全问题。

2. **流的 draining 状态:** 当服务器发送完响应数据并发送 FIN 标志时，底层的 QUIC 流会进入 draining 状态。这会通知浏览器，该响应已完成，Javascript 可以处理接收到的数据，并知道不会再有更多数据到达。

3. **流等待 ACK:**  当 Javascript 发起 POST 请求上传数据时，浏览器底层的 QUIC 实现会发送数据帧。这段测试代码确保了 QUIC 实现能正确跟踪哪些数据帧尚未被服务器 ACK。如果某些数据帧丢失，QUIC 会进行重传，保证数据可靠传输，这对 Javascript 应用来说是透明的，但保证了上传的完整性。

4. **取消流:** 如果 Javascript 应用在请求过程中决定取消请求（例如用户点击了取消按钮），浏览器底层的 QUIC 实现可能会发送一个 `RST_STREAM` 帧来通知服务器停止发送数据。这段测试代码保证了这种取消机制的正确性。

**逻辑推理的假设输入与输出:**

**假设输入:**  一个 `QuicStream` 对象接收到一个长度超出其最大允许长度的数据帧。

**输出:**  连接对象应该调用 `CloseConnection` 方法，并传入错误码 `QUIC_STREAM_LENGTH_OVERFLOW`。

**用户或编程常见的使用错误举例说明:**

* **用户错误:** 用户可能在网络环境不佳的情况下进行大文件上传或下载，导致数据包丢失率较高。这段测试代码覆盖了数据包丢失的场景，确保 QUIC 协议能够正确处理并重传丢失的数据，从而提高用户体验，减少传输失败的情况。

* **编程错误:** 开发者在实现基于 QUIC 的应用时，可能会错误地假设可以无限量地发送或接收数据，而没有考虑到流的长度限制。这段测试代码的存在可以帮助开发者理解 QUIC 协议的限制，避免因为超过流长度限制而导致连接意外关闭的问题。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中访问一个使用 QUIC 协议的网站。**
2. **浏览器发起 HTTP/3 (基于 QUIC) 连接到服务器。**
3. **用户在网页上执行某些操作，例如点击链接或提交表单，导致浏览器通过 QUIC 连接发送或接收数据。**
4. **如果网络环境不稳定，或者服务器返回的数据量过大，可能会触发这段测试代码中涉及的某些场景：**
    * **数据包丢失:**  可能触发 `OnStreamFrameLost` 的相关测试。
    * **接收到过大的数据:** 可能触发 `StreamTooLong` 的相关测试。
    * **连接异常:** 可能触发 `ConnectionClosed` 的相关测试。
5. **当 Chromium 开发者进行网络栈的调试或测试时，他们可能会运行 `quic_stream_test.cc` 中的测试用例，以验证 QUIC 流的实现是否符合预期，并且能够处理各种边界情况和异常情况。** 例如，他们可能会模拟网络丢包、延迟等情况，来测试 QUIC 的健壮性。

**归纳一下它的功能:**

这部分 `quic_stream_test.cc` 的主要功能是**详尽地测试 QUIC 协议中流（QuicStream）的各种行为和状态转换，涵盖了流的生命周期管理、数据发送和接收、流量控制、错误处理和重传机制等方面，旨在确保 QUIC 流的实现是正确、健壮和可靠的。**  这些测试直接保障了基于 QUIC 协议的网络连接的稳定性和性能。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_stream_test.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
tal_bytes_read_ to
  // avoid flow control violation.
  QuicStreamPeer::SetReceiveWindowOffset(stream_, kMaxStreamLength + 5u);
  QuicFlowControllerPeer::SetReceiveWindowOffset(session_->flow_controller(),
                                                 kMaxStreamLength + 5u);
  QuicStreamSequencerPeer::SetFrameBufferTotalBytesRead(
      QuicStreamPeer::sequencer(stream_), kMaxStreamLength - 10u);

  EXPECT_CALL(*connection_, CloseConnection(QUIC_STREAM_LENGTH_OVERFLOW, _, _))
      .Times(0);
  QuicStreamFrame stream_frame(stream_->id(), false, kMaxStreamLength - 1, ".");
  stream_->OnStreamFrame(stream_frame);
  QuicStreamFrame stream_frame2(stream_->id(), true, kMaxStreamLength, "");
  stream_->OnStreamFrame(stream_frame2);
}

TEST_P(QuicStreamTest, StreamTooLong) {
  Initialize();
  QuicStreamFrame stream_frame(stream_->id(), false, kMaxStreamLength, ".");
  EXPECT_QUIC_PEER_BUG(
      {
        EXPECT_CALL(*connection_,
                    CloseConnection(QUIC_STREAM_LENGTH_OVERFLOW, _, _))
            .Times(1);
        stream_->OnStreamFrame(stream_frame);
      },
      absl::StrCat("Receive stream frame on stream ", stream_->id(),
                   " reaches max stream length"));
}

TEST_P(QuicStreamTest, SetDrainingIncomingOutgoing) {
  // Don't have incoming data consumed.
  Initialize();

  // Incoming data with FIN.
  QuicStreamFrame stream_frame_with_fin(stream_->id(), true, 1234, ".");
  stream_->OnStreamFrame(stream_frame_with_fin);
  // The FIN has been received but not consumed.
  EXPECT_TRUE(stream_->HasReceivedFinalOffset());
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_FALSE(stream_->reading_stopped());

  EXPECT_EQ(1u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));

  // Outgoing data with FIN.
  EXPECT_CALL(*session_, WritevData(kTestStreamId, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 2u, 0u, FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  stream_->WriteOrBufferData(absl::string_view(kData1, 2), true, nullptr);
  EXPECT_TRUE(stream_->write_side_closed());

  EXPECT_EQ(1u, QuicSessionPeer::GetNumDrainingStreams(session_.get()));
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
}

TEST_P(QuicStreamTest, SetDrainingOutgoingIncoming) {
  // Don't have incoming data consumed.
  Initialize();

  // Outgoing data with FIN.
  EXPECT_CALL(*session_, WritevData(kTestStreamId, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 2u, 0u, FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  stream_->WriteOrBufferData(absl::string_view(kData1, 2), true, nullptr);
  EXPECT_TRUE(stream_->write_side_closed());

  EXPECT_EQ(1u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));

  // Incoming data with FIN.
  QuicStreamFrame stream_frame_with_fin(stream_->id(), true, 1234, ".");
  stream_->OnStreamFrame(stream_frame_with_fin);
  // The FIN has been received but not consumed.
  EXPECT_TRUE(stream_->HasReceivedFinalOffset());
  EXPECT_FALSE(QuicStreamPeer::read_side_closed(stream_));
  EXPECT_FALSE(stream_->reading_stopped());

  EXPECT_EQ(1u, QuicSessionPeer::GetNumDrainingStreams(session_.get()));
  EXPECT_EQ(0u, QuicSessionPeer::GetNumOpenDynamicStreams(session_.get()));
}

TEST_P(QuicStreamTest, EarlyResponseFinHandling) {
  // Verify that if the server completes the response before reading the end of
  // the request, the received FIN is recorded.

  Initialize();
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));

  // Receive data for the request.
  EXPECT_CALL(*stream_, OnDataAvailable()).Times(1);
  QuicStreamFrame frame1(stream_->id(), false, 0, "Start");
  stream_->OnStreamFrame(frame1);
  // When QuicSimpleServerStream sends the response, it calls
  // QuicStream::CloseReadSide() first.
  QuicStreamPeer::CloseReadSide(stream_);
  // Send data and FIN for the response.
  stream_->WriteOrBufferData(kData1, false, nullptr);
  EXPECT_TRUE(QuicStreamPeer::read_side_closed(stream_));
  // Receive remaining data and FIN for the request.
  QuicStreamFrame frame2(stream_->id(), true, 0, "End");
  stream_->OnStreamFrame(frame2);
  EXPECT_TRUE(stream_->fin_received());
  EXPECT_TRUE(stream_->HasReceivedFinalOffset());
}

TEST_P(QuicStreamTest, StreamWaitsForAcks) {
  Initialize();
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  // Stream is not waiting for acks initially.
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_FALSE(session_->HasUnackedStreamData());

  // Send kData1.
  stream_->WriteOrBufferData(kData1, false, nullptr);
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  QuicByteCount newly_acked_length = 0;
  EXPECT_TRUE(stream_->OnStreamFrameAcked(0, 9, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(9u, newly_acked_length);
  // Stream is not waiting for acks as all sent data is acked.
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());

  // Send kData2.
  stream_->WriteOrBufferData(kData2, false, nullptr);
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  // Send FIN.
  stream_->WriteOrBufferData("", true, nullptr);
  // Fin only frame is not stored in send buffer.
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());

  // kData2 is retransmitted.
  stream_->OnStreamFrameRetransmitted(9, 9, false);

  // kData2 is acked.
  EXPECT_TRUE(stream_->OnStreamFrameAcked(9, 9, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(9u, newly_acked_length);
  // Stream is waiting for acks as FIN is not acked.
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());

  // FIN is acked.
  EXPECT_CALL(*stream_, OnWriteSideInDataRecvdState());
  EXPECT_TRUE(stream_->OnStreamFrameAcked(18, 0, true, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(0u, newly_acked_length);
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());
}

TEST_P(QuicStreamTest, StreamDataGetAckedOutOfOrder) {
  Initialize();
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  // Send data.
  stream_->WriteOrBufferData(kData1, false, nullptr);
  stream_->WriteOrBufferData(kData1, false, nullptr);
  stream_->WriteOrBufferData(kData1, false, nullptr);
  stream_->WriteOrBufferData("", true, nullptr);
  EXPECT_EQ(3u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());
  QuicByteCount newly_acked_length = 0;
  EXPECT_TRUE(stream_->OnStreamFrameAcked(9, 9, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_EQ(9u, newly_acked_length);
  EXPECT_EQ(3u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_TRUE(stream_->OnStreamFrameAcked(18, 9, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_EQ(9u, newly_acked_length);
  EXPECT_EQ(3u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_TRUE(stream_->OnStreamFrameAcked(0, 9, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_EQ(9u, newly_acked_length);
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());
  // FIN is not acked yet.
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_CALL(*stream_, OnWriteSideInDataRecvdState());
  EXPECT_TRUE(stream_->OnStreamFrameAcked(27, 0, true, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(0u, newly_acked_length);
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());
}

TEST_P(QuicStreamTest, CancelStream) {
  Initialize();
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());

  stream_->WriteOrBufferData(kData1, false, nullptr);
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  // Cancel stream.
  stream_->MaybeSendStopSending(QUIC_STREAM_NO_ERROR);
  // stream still waits for acks as the error code is QUIC_STREAM_NO_ERROR, and
  // data is going to be retransmitted.
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_CALL(*connection_,
              OnStreamReset(stream_->id(), QUIC_STREAM_CANCELLED));
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .Times(AtLeast(1))
      .WillRepeatedly(Invoke(&ClearControlFrameWithTransmissionType));

  EXPECT_CALL(*session_, MaybeSendRstStreamFrame(_, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        session_->ReallyMaybeSendRstStreamFrame(
            stream_->id(), QUIC_STREAM_CANCELLED,
            stream_->stream_bytes_written());
      }));

  stream_->Reset(QUIC_STREAM_CANCELLED);
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  // Stream stops waiting for acks as data is not going to be retransmitted.
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());
}

TEST_P(QuicStreamTest, RstFrameReceivedStreamNotFinishSending) {
  if (VersionHasIetfQuicFrames(GetParam().transport_version)) {
    // In IETF QUIC, receiving a RESET_STREAM will only close the read side. The
    // stream itself is not closed and will not send reset.
    return;
  }

  Initialize();
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());

  stream_->WriteOrBufferData(kData1, false, nullptr);
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());

  // RST_STREAM received.
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_->id(),
                               QUIC_STREAM_CANCELLED, 9);

  EXPECT_CALL(
      *session_,
      MaybeSendRstStreamFrame(
          stream_->id(),
          QuicResetStreamError::FromInternal(QUIC_RST_ACKNOWLEDGEMENT), 9));
  stream_->OnStreamReset(rst_frame);
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  // Stream stops waiting for acks as it does not finish sending and rst is
  // sent.
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());
}

TEST_P(QuicStreamTest, RstFrameReceivedStreamFinishSending) {
  Initialize();
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());

  stream_->WriteOrBufferData(kData1, true, nullptr);
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());

  // RST_STREAM received.
  QuicRstStreamFrame rst_frame(kInvalidControlFrameId, stream_->id(),
                               QUIC_STREAM_CANCELLED, 1234);
  stream_->OnStreamReset(rst_frame);
  // Stream still waits for acks as it finishes sending and has unacked data.
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
}

TEST_P(QuicStreamTest, ConnectionClosed) {
  Initialize();
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());

  stream_->WriteOrBufferData(kData1, false, nullptr);
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());
  EXPECT_CALL(
      *session_,
      MaybeSendRstStreamFrame(
          stream_->id(),
          QuicResetStreamError::FromInternal(QUIC_RST_ACKNOWLEDGEMENT), 9));
  QuicConnectionPeer::SetConnectionClose(connection_);
  QuicConnectionCloseFrame frame;
  frame.quic_error_code = QUIC_INTERNAL_ERROR;
  stream_->OnConnectionClosed(frame, ConnectionCloseSource::FROM_SELF);
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  // Stream stops waiting for acks as connection is going to close.
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());
}

TEST_P(QuicStreamTest, CanWriteNewDataAfterData) {
  SetQuicFlag(quic_buffered_data_threshold, 100);
  Initialize();
  EXPECT_TRUE(stream_->CanWriteNewDataAfterData(99));
  EXPECT_FALSE(stream_->CanWriteNewDataAfterData(100));
}

TEST_P(QuicStreamTest, WriteBufferedData) {
  // Set buffered data low water mark to be 100.
  SetQuicFlag(quic_buffered_data_threshold, 100);

  Initialize();
  std::string data(1024, 'a');
  EXPECT_TRUE(stream_->CanWriteNewData());

  // Testing WriteOrBufferData.
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 100u, 0u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  stream_->WriteOrBufferData(data, false, nullptr);
  stream_->WriteOrBufferData(data, false, nullptr);
  stream_->WriteOrBufferData(data, false, nullptr);
  EXPECT_TRUE(stream_->IsWaitingForAcks());

  // Verify all data is saved.
  EXPECT_EQ(3 * data.length() - 100, stream_->BufferedDataBytes());

  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 100, 100u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  // Buffered data size > threshold, do not ask upper layer for more data.
  EXPECT_CALL(*stream_, OnCanWriteNewData()).Times(0);
  stream_->OnCanWrite();
  EXPECT_EQ(3 * data.length() - 200, stream_->BufferedDataBytes());
  EXPECT_FALSE(stream_->CanWriteNewData());

  // Send buffered data to make buffered data size < threshold.
  QuicByteCount data_to_write =
      3 * data.length() - 200 - GetQuicFlag(quic_buffered_data_threshold) + 1;
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this, data_to_write]() {
        return session_->ConsumeData(stream_->id(), data_to_write, 200u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  // Buffered data size < threshold, ask upper layer for more data.
  EXPECT_CALL(*stream_, OnCanWriteNewData()).Times(1);
  stream_->OnCanWrite();
  EXPECT_EQ(
      static_cast<uint64_t>(GetQuicFlag(quic_buffered_data_threshold) - 1),
      stream_->BufferedDataBytes());
  EXPECT_TRUE(stream_->CanWriteNewData());

  // Flush all buffered data.
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_CALL(*stream_, OnCanWriteNewData()).Times(1);
  stream_->OnCanWrite();
  EXPECT_EQ(0u, stream_->BufferedDataBytes());
  EXPECT_FALSE(stream_->HasBufferedData());
  EXPECT_TRUE(stream_->CanWriteNewData());

  // Testing Writev.
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Return(QuicConsumedData(0, false)));
  struct iovec iov = {const_cast<char*>(data.data()), data.length()};
  quiche::QuicheMemSliceStorage storage(
      &iov, 1, session_->connection()->helper()->GetStreamSendBufferAllocator(),
      1024);
  QuicConsumedData consumed = stream_->WriteMemSlices(storage.ToSpan(), false);

  // There is no buffered data before, all data should be consumed without
  // respecting buffered data upper limit.
  EXPECT_EQ(data.length(), consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_EQ(data.length(), stream_->BufferedDataBytes());
  EXPECT_FALSE(stream_->CanWriteNewData());

  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(0);
  quiche::QuicheMemSliceStorage storage2(
      &iov, 1, session_->connection()->helper()->GetStreamSendBufferAllocator(),
      1024);
  consumed = stream_->WriteMemSlices(storage2.ToSpan(), false);
  // No Data can be consumed as buffered data is beyond upper limit.
  EXPECT_EQ(0u, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_EQ(data.length(), stream_->BufferedDataBytes());

  data_to_write = data.length() - GetQuicFlag(quic_buffered_data_threshold) + 1;
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this, data_to_write]() {
        return session_->ConsumeData(stream_->id(), data_to_write, 0u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));

  EXPECT_CALL(*stream_, OnCanWriteNewData()).Times(1);
  stream_->OnCanWrite();
  EXPECT_EQ(
      static_cast<uint64_t>(GetQuicFlag(quic_buffered_data_threshold) - 1),
      stream_->BufferedDataBytes());
  EXPECT_TRUE(stream_->CanWriteNewData());

  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(0);
  // All data can be consumed as buffered data is below upper limit.
  quiche::QuicheMemSliceStorage storage3(
      &iov, 1, session_->connection()->helper()->GetStreamSendBufferAllocator(),
      1024);
  consumed = stream_->WriteMemSlices(storage3.ToSpan(), false);
  EXPECT_EQ(data.length(), consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_EQ(data.length() + GetQuicFlag(quic_buffered_data_threshold) - 1,
            stream_->BufferedDataBytes());
  EXPECT_FALSE(stream_->CanWriteNewData());
}

TEST_P(QuicStreamTest, WritevDataReachStreamLimit) {
  Initialize();
  std::string data("aaaaa");
  QuicStreamPeer::SetStreamBytesWritten(kMaxStreamLength - data.length(),
                                        stream_);
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  struct iovec iov = {const_cast<char*>(data.data()), 5u};
  quiche::QuicheMemSliceStorage storage(
      &iov, 1, session_->connection()->helper()->GetStreamSendBufferAllocator(),
      1024);
  QuicConsumedData consumed = stream_->WriteMemSlices(storage.ToSpan(), false);
  EXPECT_EQ(data.length(), consumed.bytes_consumed);
  struct iovec iov2 = {const_cast<char*>(data.data()), 1u};
  quiche::QuicheMemSliceStorage storage2(
      &iov2, 1,
      session_->connection()->helper()->GetStreamSendBufferAllocator(), 1024);
  EXPECT_QUIC_BUG(
      {
        EXPECT_CALL(*connection_,
                    CloseConnection(QUIC_STREAM_LENGTH_OVERFLOW, _, _));
        stream_->WriteMemSlices(storage2.ToSpan(), false);
      },
      "Write too many data via stream");
}

TEST_P(QuicStreamTest, WriteMemSlices) {
  // Set buffered data low water mark to be 100.
  SetQuicFlag(quic_buffered_data_threshold, 100);

  Initialize();
  constexpr QuicByteCount kDataSize = 1024;
  quiche::QuicheBufferAllocator* allocator =
      connection_->helper()->GetStreamSendBufferAllocator();
  std::vector<quiche::QuicheMemSlice> vector1;
  vector1.push_back(
      quiche::QuicheMemSlice(quiche::QuicheBuffer(allocator, kDataSize)));
  vector1.push_back(
      quiche::QuicheMemSlice(quiche::QuicheBuffer(allocator, kDataSize)));
  std::vector<quiche::QuicheMemSlice> vector2;
  vector2.push_back(
      quiche::QuicheMemSlice(quiche::QuicheBuffer(allocator, kDataSize)));
  vector2.push_back(
      quiche::QuicheMemSlice(quiche::QuicheBuffer(allocator, kDataSize)));
  absl::Span<quiche::QuicheMemSlice> span1(vector1);
  absl::Span<quiche::QuicheMemSlice> span2(vector2);

  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 100u, 0u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  // There is no buffered data before, all data should be consumed.
  QuicConsumedData consumed = stream_->WriteMemSlices(span1, false);
  EXPECT_EQ(2048u, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_EQ(2 * kDataSize - 100, stream_->BufferedDataBytes());
  EXPECT_FALSE(stream_->fin_buffered());

  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(0);
  // No Data can be consumed as buffered data is beyond upper limit.
  consumed = stream_->WriteMemSlices(span2, true);
  EXPECT_EQ(0u, consumed.bytes_consumed);
  EXPECT_FALSE(consumed.fin_consumed);
  EXPECT_EQ(2 * kDataSize - 100, stream_->BufferedDataBytes());
  EXPECT_FALSE(stream_->fin_buffered());

  QuicByteCount data_to_write =
      2 * kDataSize - 100 - GetQuicFlag(quic_buffered_data_threshold) + 1;
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this, data_to_write]() {
        return session_->ConsumeData(stream_->id(), data_to_write, 100u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  EXPECT_CALL(*stream_, OnCanWriteNewData()).Times(1);
  stream_->OnCanWrite();
  EXPECT_EQ(
      static_cast<uint64_t>(GetQuicFlag(quic_buffered_data_threshold) - 1),
      stream_->BufferedDataBytes());
  // Try to write slices2 again.
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _)).Times(0);
  consumed = stream_->WriteMemSlices(span2, true);
  EXPECT_EQ(2048u, consumed.bytes_consumed);
  EXPECT_TRUE(consumed.fin_consumed);
  EXPECT_EQ(2 * kDataSize + GetQuicFlag(quic_buffered_data_threshold) - 1,
            stream_->BufferedDataBytes());
  EXPECT_TRUE(stream_->fin_buffered());

  // Flush all buffered data.
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  stream_->OnCanWrite();
  EXPECT_CALL(*stream_, OnCanWriteNewData()).Times(0);
  EXPECT_FALSE(stream_->HasBufferedData());
  EXPECT_TRUE(stream_->write_side_closed());
}

TEST_P(QuicStreamTest, WriteMemSlicesReachStreamLimit) {
  Initialize();
  QuicStreamPeer::SetStreamBytesWritten(kMaxStreamLength - 5u, stream_);
  std::vector<std::pair<char*, size_t>> buffers;
  quiche::QuicheMemSlice slice1 = MemSliceFromString("12345");
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 5u, 0u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  // There is no buffered data before, all data should be consumed.
  QuicConsumedData consumed = stream_->WriteMemSlice(std::move(slice1), false);
  EXPECT_EQ(5u, consumed.bytes_consumed);

  quiche::QuicheMemSlice slice2 = MemSliceFromString("6");
  EXPECT_QUIC_BUG(
      {
        EXPECT_CALL(*connection_,
                    CloseConnection(QUIC_STREAM_LENGTH_OVERFLOW, _, _));
        stream_->WriteMemSlice(std::move(slice2), false);
      },
      "Write too many data via stream");
}

TEST_P(QuicStreamTest, StreamDataGetAckedMultipleTimes) {
  Initialize();
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());

  // Send [0, 27) and fin.
  stream_->WriteOrBufferData(kData1, false, nullptr);
  stream_->WriteOrBufferData(kData1, false, nullptr);
  stream_->WriteOrBufferData(kData1, true, nullptr);
  EXPECT_EQ(3u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());
  // Ack [0, 9), [5, 22) and [18, 26)
  // Verify [0, 9) 9 bytes are acked.
  QuicByteCount newly_acked_length = 0;
  EXPECT_TRUE(stream_->OnStreamFrameAcked(0, 9, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(9u, newly_acked_length);
  EXPECT_EQ(2u, QuicStreamPeer::SendBuffer(stream_).size());
  // Verify [9, 22) 13 bytes are acked.
  EXPECT_TRUE(stream_->OnStreamFrameAcked(5, 17, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(13u, newly_acked_length);
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  // Verify [22, 26) 4 bytes are acked.
  EXPECT_TRUE(stream_->OnStreamFrameAcked(18, 8, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(4u, newly_acked_length);
  EXPECT_EQ(1u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());

  // Ack [0, 27). Verify [26, 27) 1 byte is acked.
  EXPECT_TRUE(stream_->OnStreamFrameAcked(26, 1, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(1u, newly_acked_length);
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_TRUE(stream_->IsWaitingForAcks());
  EXPECT_TRUE(session_->HasUnackedStreamData());

  // Ack Fin.
  EXPECT_CALL(*stream_, OnWriteSideInDataRecvdState()).Times(1);
  EXPECT_TRUE(stream_->OnStreamFrameAcked(27, 0, true, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(0u, newly_acked_length);
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());

  // Ack [10, 27) and fin. No new data is acked.
  EXPECT_FALSE(
      stream_->OnStreamFrameAcked(10, 17, true, QuicTime::Delta::Zero(),
                                  QuicTime::Zero(), &newly_acked_length));
  EXPECT_EQ(0u, newly_acked_length);
  EXPECT_EQ(0u, QuicStreamPeer::SendBuffer(stream_).size());
  EXPECT_FALSE(stream_->IsWaitingForAcks());
  EXPECT_FALSE(session_->HasUnackedStreamData());
}

TEST_P(QuicStreamTest, OnStreamFrameLost) {
  Initialize();

  // Send [0, 9).
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  stream_->WriteOrBufferData(kData1, false, nullptr);
  EXPECT_FALSE(stream_->HasBufferedData());
  EXPECT_TRUE(stream_->IsStreamFrameOutstanding(0, 9, false));

  // Try to send [9, 27), but connection is blocked.
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Return(QuicConsumedData(0, false)));
  stream_->WriteOrBufferData(kData2, false, nullptr);
  stream_->WriteOrBufferData(kData2, false, nullptr);
  EXPECT_TRUE(stream_->HasBufferedData());
  EXPECT_FALSE(stream_->HasPendingRetransmission());

  // Lost [0, 9). When stream gets a chance to write, only lost data is
  // transmitted.
  stream_->OnStreamFrameLost(0, 9, false);
  EXPECT_TRUE(stream_->HasPendingRetransmission());
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_CALL(*stream_, OnCanWriteNewData()).Times(1);
  stream_->OnCanWrite();
  EXPECT_FALSE(stream_->HasPendingRetransmission());
  EXPECT_TRUE(stream_->HasBufferedData());

  // This OnCanWrite causes [9, 27) to be sent.
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  stream_->OnCanWrite();
  EXPECT_FALSE(stream_->HasBufferedData());

  // Send a fin only frame.
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  stream_->WriteOrBufferData("", true, nullptr);

  // Lost [9, 27) and fin.
  stream_->OnStreamFrameLost(9, 18, false);
  stream_->OnStreamFrameLost(27, 0, true);
  EXPECT_TRUE(stream_->HasPendingRetransmission());

  // Ack [9, 18).
  QuicByteCount newly_acked_length = 0;
  EXPECT_TRUE(stream_->OnStreamFrameAcked(9, 9, false, QuicTime::Delta::Zero(),
                                          QuicTime::Zero(),
                                          &newly_acked_length));
  EXPECT_EQ(9u, newly_acked_length);
  EXPECT_FALSE(stream_->IsStreamFrameOutstanding(9, 3, false));
  EXPECT_TRUE(stream_->HasPendingRetransmission());
  // This OnCanWrite causes [18, 27) and fin to be retransmitted. Verify fin can
  // be bundled with data.
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 9u, 18u, FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  stream_->OnCanWrite();
  EXPECT_FALSE(stream_->HasPendingRetransmission());
  // Lost [9, 18) again, but it is not considered as lost because kData2
  // has been acked.
  stream_->OnStreamFrameLost(9, 9, false);
  EXPECT_FALSE(stream_->HasPendingRetransmission());
  EXPECT_TRUE(stream_->IsStreamFrameOutstanding(27, 0, true));
}

TEST_P(QuicStreamTest, CannotBundleLostFin) {
  Initialize();

  // Send [0, 18) and fin.
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  stream_->WriteOrBufferData(kData1, false, nullptr);
  stream_->WriteOrBufferData(kData2, true, nullptr);

  // Lost [0, 9) and fin.
  stream_->OnStreamFrameLost(0, 9, false);
  stream_->OnStreamFrameLost(18, 0, true);

  // Retransmit lost data. Verify [0, 9) and fin are retransmitted in two
  // frames.
  InSequence s;
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(InvokeWithoutArgs([this]() {
        return session_->ConsumeData(stream_->id(), 9u, 0u, NO_FIN,
                                     NOT_RETRANSMISSION, std::nullopt);
      }));
  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillOnce(Return(QuicConsumedData(0, true)));
  stream_->OnCanWrite();
}

TEST_P(QuicStreamTest, MarkConnectionLevelWriteBlockedOnWindowUpdateFrame) {
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

  EXPECT_CALL(*session_, WritevData(_, _, _, _, _, _))
      .WillRepeatedly(Invoke(session_.get(), &MockQuicSession::ConsumeData));
  EXPECT_CALL(*session_, SendBlocked(_, _)).Times(1);
  std::string data(1024, '.');
  stream->Wri
"""


```