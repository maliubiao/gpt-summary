Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `QuicStream` class in Chromium's QUIC implementation. I need to analyze the methods in this part of the code and describe their roles within the stream lifecycle and data transfer process. I should focus on the actions related to sending and receiving data, flow control, error handling, and stream management. Since this is part 2, I should also consider how it complements the functionality described in part 1 (although I don't have access to part 1).

Here's a breakdown of the methods and their key functions:

*   **`endingFrame`**: Handles sending `STOP_SENDING` or `RST_STREAM` frames based on whether an error occurred.
*   **`MaybeSendRstStream`**: Sends a `RST_STREAM` frame to abruptly terminate the stream.
*   **`HasBufferedData`**: Checks if there's data waiting to be sent in the send buffer.
*   **`version`, `transport_version`, `handshake_protocol`**: Accessors for connection properties.
*   **`StopReading`**: Stops further reading from the stream.
*   **`OnClose`**:  Handles the stream closing process, including sending `RST_STREAM` if necessary and cleaning up resources.
*   **`OnWindowUpdateFrame`**: Processes incoming `WINDOW_UPDATE` frames to adjust the send window.
*   **`MaybeIncreaseHighestReceivedOffset`**: Updates the highest received byte offset and informs the connection flow controller.
*   **`AddBytesSent`**: Updates the count of bytes sent on the stream and connection.
*   **`AddBytesConsumed`**: Updates the count of bytes consumed on the stream and connection.
*   **`MaybeConfigSendWindowOffset`**: Configures the initial send window offset, with checks for potential issues like 0-RTT rejection.
*   **`AddRandomPaddingAfterFin`**: Flags to add random padding after the FIN.
*   **`OnStreamFrameAcked`**: Processes acknowledgments for sent stream data.
*   **`OnStreamFrameRetransmitted`**: Handles cases where stream data is retransmitted.
*   **`OnStreamFrameLost`**: Handles cases where stream data is considered lost.
*   **`RetransmitStreamData`**:  Handles the actual retransmission of lost data.
*   **`IsWaitingForAcks`**: Checks if the stream is waiting for acknowledgments.
*   **`WriteStreamData`**: Writes data into the send buffer.
*   **`WriteBufferedData`**:  Sends buffered data based on flow control and connection state.
*   **`BufferedDataBytes`**: Returns the amount of data currently buffered for sending.
*   **`CanWriteNewData`, `CanWriteNewDataAfterData`**: Checks if more data can be written to the buffer without exceeding limits.
*   **`stream_bytes_written`**: Returns the total number of bytes written to the stream.
*   **`bytes_acked`**: Returns the set of acknowledged byte ranges.
*   **`OnStreamDataConsumed`**: Updates the send buffer after data is consumed.
*   **`WritePendingRetransmission`**:  Retransmits any data marked for retransmission.
*   **`MaybeSetTtl`**: Sets a time-to-live (TTL) deadline for the stream.
*   **`HasDeadlinePassed`**: Checks if the stream's TTL has expired.
*   **`MaybeCloseStreamWithBufferedReset`**: Checks if a buffered reset should be applied.
*   **`OnDeadlinePassed`**:  Handles the event when a stream's deadline expires.
*   **`IsFlowControlBlocked`**: Checks if the stream is flow control blocked.
*   **`highest_received_byte_offset`**: Returns the highest received byte offset.
*   **`UpdateReceiveWindowSize`**: Updates the receive window size.
*   **`GetSendWindow`, `GetReceiveWindow`**: Accessors for flow control window sizes.
*   **`OnStreamCreatedFromPendingStream`**: Handles stream creation from a pending state.
*   **`CalculateSendWindowSize`**: Calculates the available send window size considering both stream and connection level limits.

This part of the code heavily focuses on the sending side of a QUIC stream, dealing with buffering, flow control, reliable delivery mechanisms (acknowledgments and retransmissions), and stream lifecycle management.
这段代码是 `net/third_party/quiche/src/quiche/quic/core/quic_stream.cc` 文件中 `QuicStream` 类的一部分，主要负责 QUIC 流的**数据发送**和**关闭**相关的核心功能。

**归纳一下它的功能：**

1. **流的异常终止与重置:**
    *   **发送 `STOP_SENDING` 或 `RST_STREAM` 帧:** 当需要停止发送数据（`endingFrame`），或者需要立即终止流（`MaybeSendRstStream`）时，负责构建并发送相应的控制帧。
    *   **处理远端 `STOP_SENDING`:**  虽然这段代码本身不直接处理接收到的 `STOP_SENDING`，但它会在 `endingFrame` 中响应这种情况，并根据是否发生错误来决定发送 `RST_STREAM` 还是仅仅记录。

2. **流的正常关闭流程:**
    *   **标记读取和写入端关闭:**  通过 `CloseReadSide()` 和 `CloseWriteSide()` 管理流的读写状态。
    *   **发送 FIN:** 在所有数据发送完毕后，负责发送 FIN 帧来通知对端流的发送端已经结束。
    *   **处理流关闭事件 (`OnClose`)**: 当流的两端都关闭后，进行清理工作，例如在某些情况下发送 `RST_STREAM` 以确保流控状态一致，并可能通知会话清理僵尸流。

3. **流的发送缓冲区管理:**
    *   **检查是否有缓冲数据 (`HasBufferedData`)**:  判断发送缓冲区中是否有待发送的数据。
    *   **写入数据到缓冲区 (`WriteStreamData`)**:  将数据写入发送缓冲区等待发送。
    *   **发送缓冲数据 (`WriteBufferedData`)**:  根据流控窗口和连接状态，将缓冲区中的数据发送出去。
    *   **跟踪已发送和已确认的数据:**  通过 `send_buffer_` 对象管理已发送、已确认和待重传的数据。
    *   **处理数据帧的确认 (`OnStreamFrameAcked`)**:  当收到对端对数据帧的确认时，更新发送缓冲区的状态。
    *   **处理数据帧的重传 (`OnStreamFrameRetransmitted`, `RetransmitStreamData`, `WritePendingRetransmission`)**:  当数据帧丢失或超时时，负责重新发送数据。
    *   **处理数据帧的丢失 (`OnStreamFrameLost`)**:  当数据帧被判定为丢失时，更新发送缓冲区的状态以便后续重传。

4. **流的流量控制:**
    *   **处理窗口更新帧 (`OnWindowUpdateFrame`)**:  接收并处理对端发送的窗口更新帧，增大本地的发送窗口。
    *   **更新最高接收偏移 (`MaybeIncreaseHighestReceivedOffset`)**:  当接收到新的数据时，更新流和连接级别的最高接收偏移，用于流控。
    *   **记录已发送和已消费的字节数 (`AddBytesSent`, `AddBytesConsumed`)**:  维护流和连接级别的流量控制计数器。
    *   **配置发送窗口偏移 (`MaybeConfigSendWindowOffset`)**:  设置初始的发送窗口大小，并处理一些特殊情况，例如 0-RTT 拒绝。
    *   **检查是否被流控阻塞 (`IsFlowControlBlocked`)**:  判断当前流是否因为流量控制而被阻塞，无法发送更多数据。
    *   **获取流量控制窗口大小 (`GetSendWindow`, `GetReceiveWindow`)**:  获取当前流的发送和接收窗口大小。
    *   **计算发送窗口大小 (`CalculateSendWindowSize`)**:  根据流和连接级别的流量控制限制，计算实际可用的发送窗口大小。

5. **流的超时机制:**
    *   **设置 TTL (`MaybeSetTtl`)**:  为流设置一个生存时间 (TTL)，如果在指定时间内未完成，则会触发超时。
    *   **检查 TTL 是否过期 (`HasDeadlinePassed`)**:  判断流的 TTL 是否已经过期。
    *   **处理超时事件 (`OnDeadlinePassed`)**: 当流的 TTL 过期时，执行相应的处理，例如重置流。

**它与 Javascript 的功能关系：**

QUIC 协议本身是网络传输层协议，与 JavaScript 的直接功能关系并不密切。但是，在浏览器环境中，JavaScript 通过 WebTransport API 可以与 QUIC 建立连接并进行数据交互。

**举例说明：**

假设一个使用 WebTransport 的 JavaScript 应用需要向服务器发送大量数据，例如上传文件：

1. **用户操作（JavaScript）：** 用户在网页上选择了要上传的文件，JavaScript 代码通过 WebTransport 的 `send()` 方法将文件数据分片发送到服务器。
2. **数据到达 `QuicStream::WriteBufferedData`：**  JavaScript 发送的数据最终会通过浏览器的网络栈到达 `QuicStream` 对象的发送缓冲区。`WriteBufferedData` 方法负责将这些数据按照流控规则打包成 QUIC 数据帧并发送出去。
3. **流量控制（`CalculateSendWindowSize`）：**  在发送数据前，`WriteBufferedData` 会调用 `CalculateSendWindowSize` 检查当前流的发送窗口是否足够发送这部分数据。如果窗口不足，则会等待对端发送窗口更新帧。
4. **数据确认 (`OnStreamFrameAcked`)：** 当服务器确认收到发送的数据帧后，`OnStreamFrameAcked` 方法会被调用，更新本地发送缓冲区的状态，释放已确认的数据占用的空间。
5. **流关闭（JavaScript）：**  当文件上传完成后，JavaScript 代码会调用 WebTransport 流的 `close()` 方法。
6. **流关闭 (`QuicStream::OnClose`)：**  `QuicStream` 对象的 `OnClose` 方法会被触发，它会检查是否需要发送 FIN 帧，并进行一些清理工作。

**逻辑推理的假设输入与输出：**

假设输入：

*   `WriteBufferedData` 被调用，发送缓冲区中有 1000 字节数据待发送。
*   `CalculateSendWindowSize` 返回当前流的可用发送窗口为 500 字节。
*   `fin_buffered_` 为 false。

输出：

*   `WriteBufferedData` 只会发送 500 字节的数据，因为受流控限制。
*   `MaybeSendBlocked` 可能会被调用，标记流为阻塞状态，等待窗口更新。
*   `stream_delegate_->WritevData` 会被调用，`write_length` 参数为 500，`state` 参数为 `NO_FIN`。

假设输入：

*   `OnStreamFrameAcked` 被调用，收到的 ACK 确认了流上偏移 100 到 200 的 100 字节数据。
*   `send_buffer_` 中偏移 100 到 250 的数据之前标记为已发送。

输出：

*   `send_buffer_.OnStreamDataAcked` 会更新 `send_buffer_` 的状态，将偏移 100 到 200 的数据标记为已确认。
*   `newly_acked_length` 会被设置为 100。

**用户或编程常见的使用错误：**

1. **在流已经关闭后尝试写入数据：**  如果 JavaScript 代码在 WebTransport 流已经 `close()` 之后仍然尝试发送数据，会导致错误。`QuicStream` 会检查 `write_side_closed_` 状态，如果为 true 则拒绝写入。
2. **未处理流控阻塞：**  如果 JavaScript 代码没有监听 WebTransport 的 `writable` 事件，持续发送大量数据而不考虑流控，可能会导致数据积压，甚至连接断开。`QuicStream` 会通过 `IsFlowControlBlocked` 和 `MaybeSendBlocked` 机制通知上层流控状态。
3. **过早关闭流的写入端：**  如果在所有数据发送完成之前就关闭了 WebTransport 流的发送端，可能会导致部分数据丢失。`QuicStream` 的 `OnClose` 方法会在某些情况下尝试发送 `RST_STREAM` 来告知对端。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户在浏览器中访问一个支持 WebTransport 的网站。**
2. **JavaScript 代码使用 WebTransport API 创建一个连接到服务器的会话。**
3. **JavaScript 代码在一个 WebTransport 会话上创建一个单向或双向流。**
4. **用户触发了某些操作，例如点击上传按钮，导致 JavaScript 代码调用流的 `send()` 方法发送数据。**  这会导致数据被写入 `QuicStream` 的发送缓冲区。
5. **如果此时需要发送缓冲的数据，或者需要处理对端发送的窗口更新，或者需要处理收到的数据确认，就会调用到 `QuicStream` 中相应的函数，例如 `WriteBufferedData`，`OnWindowUpdateFrame`，`OnStreamFrameAcked` 等。**
6. **如果发生网络问题，例如数据包丢失，可能会触发 `OnStreamFrameLost` 或 `RetransmitStreamData`。**
7. **如果用户关闭了网页，或者 JavaScript 代码关闭了 WebTransport 流，会最终调用到 `QuicStream` 的 `OnClose` 方法。**

在调试 QUIC 连接问题时，例如数据发送延迟、连接断开等，可以查看 `net/third_party/quiche/src/quiche/quic/core/quic_stream.cc` 中的日志 (QUIC_DVLOG) 和断点，来跟踪数据在 `QuicStream` 中的流转过程，以及流控状态、确认状态等，从而定位问题的原因。例如，可以查看 `WriteBufferedData` 是否因为流控窗口为 0 而无法发送数据，或者查看 `OnStreamFrameLost` 是否频繁发生。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
endingFrame(id(), error);
  } else {
    QUICHE_DCHECK_EQ(QUIC_STREAM_NO_ERROR, error.internal_code());
    session()->MaybeSendRstStreamFrame(id(), QuicResetStreamError::NoError(),
                                       stream_bytes_written());
  }
  stop_sending_sent_ = true;
  CloseReadSide();
}

void QuicStream::MaybeSendRstStream(QuicResetStreamError error) {
  if (rst_sent_) {
    return;
  }

  if (!session()->version().UsesHttp3()) {
    QUIC_BUG_IF(quic_bug_12570_5, error.ok());
    stop_sending_sent_ = true;
    CloseReadSide();
  }
  session()->MaybeSendRstStreamFrame(id(), error, stream_bytes_written());
  rst_sent_ = true;
  CloseWriteSide();
}

bool QuicStream::HasBufferedData() const {
  QUICHE_DCHECK_GE(send_buffer_.stream_offset(), stream_bytes_written());
  return send_buffer_.stream_offset() > stream_bytes_written();
}

ParsedQuicVersion QuicStream::version() const { return session_->version(); }

QuicTransportVersion QuicStream::transport_version() const {
  return session_->transport_version();
}

HandshakeProtocol QuicStream::handshake_protocol() const {
  return session_->connection()->version().handshake_protocol;
}

void QuicStream::StopReading() {
  QUIC_DVLOG(1) << ENDPOINT << "Stop reading from stream " << id();
  sequencer_.StopReading();
}

void QuicStream::OnClose() {
  QUICHE_DCHECK(read_side_closed_ && write_side_closed_);

  if (!fin_sent_ && !rst_sent_) {
    QUIC_BUG_IF(quic_bug_12570_6, session()->connection()->connected() &&
                                      session()->version().UsesHttp3())
        << "The stream should've already sent RST in response to "
           "STOP_SENDING";
    // For flow control accounting, tell the peer how many bytes have been
    // written on this stream before termination. Done here if needed, using a
    // RST_STREAM frame.
    MaybeSendRstStream(QUIC_RST_ACKNOWLEDGEMENT);
    session_->MaybeCloseZombieStream(id_);
  }

  if (!flow_controller_.has_value() ||
      flow_controller_->FlowControlViolation() ||
      connection_flow_controller_->FlowControlViolation()) {
    return;
  }
  // The stream is being closed and will not process any further incoming bytes.
  // As there may be more bytes in flight, to ensure that both endpoints have
  // the same connection level flow control state, mark all unreceived or
  // buffered bytes as consumed.
  QuicByteCount bytes_to_consume =
      flow_controller_->highest_received_byte_offset() -
      flow_controller_->bytes_consumed();
  AddBytesConsumed(bytes_to_consume);
}

void QuicStream::OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) {
  if (type_ == READ_UNIDIRECTIONAL) {
    OnUnrecoverableError(
        QUIC_WINDOW_UPDATE_RECEIVED_ON_READ_UNIDIRECTIONAL_STREAM,
        "WindowUpdateFrame received on READ_UNIDIRECTIONAL stream.");
    return;
  }

  if (!flow_controller_.has_value()) {
    QUIC_BUG(quic_bug_10586_9)
        << ENDPOINT
        << "OnWindowUpdateFrame called on stream without flow control";
    return;
  }

  if (flow_controller_->UpdateSendWindowOffset(frame.max_data)) {
    // Let session unblock this stream.
    session_->MarkConnectionLevelWriteBlocked(id_);
  }
}

bool QuicStream::MaybeIncreaseHighestReceivedOffset(
    QuicStreamOffset new_offset) {
  if (!flow_controller_.has_value()) {
    QUIC_BUG(quic_bug_10586_10)
        << ENDPOINT
        << "MaybeIncreaseHighestReceivedOffset called on stream without "
           "flow control";
    return false;
  }
  uint64_t increment =
      new_offset - flow_controller_->highest_received_byte_offset();
  if (!flow_controller_->UpdateHighestReceivedOffset(new_offset)) {
    return false;
  }

  // If |new_offset| increased the stream flow controller's highest received
  // offset, increase the connection flow controller's value by the incremental
  // difference.
  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->UpdateHighestReceivedOffset(
        connection_flow_controller_->highest_received_byte_offset() +
        increment);
  }
  return true;
}

void QuicStream::AddBytesSent(QuicByteCount bytes) {
  if (!flow_controller_.has_value()) {
    QUIC_BUG(quic_bug_10586_11)
        << ENDPOINT << "AddBytesSent called on stream without flow control";
    return;
  }
  flow_controller_->AddBytesSent(bytes);
  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->AddBytesSent(bytes);
  }
}

void QuicStream::AddBytesConsumed(QuicByteCount bytes) {
  if (type_ == CRYPTO) {
    // A stream with type CRYPTO has no flow control, so there's nothing this
    // function needs to do. This function still gets called by the
    // QuicStreamSequencers used by QuicCryptoStream.
    return;
  }
  if (!flow_controller_.has_value()) {
    QUIC_BUG(quic_bug_12570_7)
        << ENDPOINT
        << "AddBytesConsumed called on non-crypto stream without flow control";
    return;
  }
  // Only adjust stream level flow controller if still reading.
  if (!read_side_closed_) {
    flow_controller_->AddBytesConsumed(bytes);
  }

  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->AddBytesConsumed(bytes);
  }
  MaybeCloseStreamWithBufferedReset();
}

bool QuicStream::MaybeConfigSendWindowOffset(QuicStreamOffset new_offset,
                                             bool was_zero_rtt_rejected) {
  if (!flow_controller_.has_value()) {
    QUIC_BUG(quic_bug_10586_12)
        << ENDPOINT
        << "ConfigSendWindowOffset called on stream without flow control";
    return false;
  }

  // The validation code below is for QUIC with TLS only.
  if (new_offset < flow_controller_->send_window_offset()) {
    QUICHE_DCHECK(session()->version().UsesTls());
    if (was_zero_rtt_rejected && new_offset < flow_controller_->bytes_sent()) {
      // The client is given flow control window lower than what's written in
      // 0-RTT. This QUIC implementation is unable to retransmit them.
      QUIC_BUG_IF(quic_bug_12570_8, perspective_ == Perspective::IS_SERVER)
          << "Server streams' flow control should never be configured twice.";
      OnUnrecoverableError(
          QUIC_ZERO_RTT_UNRETRANSMITTABLE,
          absl::StrCat(
              "Server rejected 0-RTT, aborting because new stream max data ",
              new_offset, " for stream ", id_, " is less than currently used: ",
              flow_controller_->bytes_sent()));
      return false;
    } else if (session()->version().AllowsLowFlowControlLimits()) {
      // In IETF QUIC, if the client receives flow control limit lower than what
      // was resumed from 0-RTT, depending on 0-RTT status, it's either the
      // peer's fault or our implementation's fault.
      QUIC_BUG_IF(quic_bug_12570_9, perspective_ == Perspective::IS_SERVER)
          << "Server streams' flow control should never be configured twice.";
      OnUnrecoverableError(
          was_zero_rtt_rejected ? QUIC_ZERO_RTT_REJECTION_LIMIT_REDUCED
                                : QUIC_ZERO_RTT_RESUMPTION_LIMIT_REDUCED,
          absl::StrCat(
              was_zero_rtt_rejected ? "Server rejected 0-RTT, aborting because "
                                    : "",
              "new stream max data ", new_offset, " decreases current limit: ",
              flow_controller_->send_window_offset()));
      return false;
    }
  }

  if (flow_controller_->UpdateSendWindowOffset(new_offset)) {
    // Let session unblock this stream.
    session_->MarkConnectionLevelWriteBlocked(id_);
  }
  return true;
}

void QuicStream::AddRandomPaddingAfterFin() {
  add_random_padding_after_fin_ = true;
}

bool QuicStream::OnStreamFrameAcked(QuicStreamOffset offset,
                                    QuicByteCount data_length, bool fin_acked,
                                    QuicTime::Delta /*ack_delay_time*/,
                                    QuicTime /*receive_timestamp*/,
                                    QuicByteCount* newly_acked_length) {
  QUIC_DVLOG(1) << ENDPOINT << "stream " << id_ << " Acking "
                << "[" << offset << ", " << offset + data_length << "]"
                << " fin = " << fin_acked;
  *newly_acked_length = 0;
  if (!send_buffer_.OnStreamDataAcked(offset, data_length,
                                      newly_acked_length)) {
    OnUnrecoverableError(QUIC_INTERNAL_ERROR, "Trying to ack unsent data.");
    return false;
  }
  if (!fin_sent_ && fin_acked) {
    OnUnrecoverableError(QUIC_INTERNAL_ERROR, "Trying to ack unsent fin.");
    return false;
  }
  // Indicates whether ack listener's OnPacketAcked should be called.
  const bool new_data_acked =
      *newly_acked_length > 0 || (fin_acked && fin_outstanding_);
  if (fin_acked) {
    fin_outstanding_ = false;
    fin_lost_ = false;
  }
  if (!IsWaitingForAcks() && write_side_closed_ &&
      !write_side_data_recvd_state_notified_) {
    OnWriteSideInDataRecvdState();
    write_side_data_recvd_state_notified_ = true;
  }
  if (!IsWaitingForAcks() && read_side_closed_ && write_side_closed_) {
    session_->MaybeCloseZombieStream(id_);
  }
  return new_data_acked;
}

void QuicStream::OnStreamFrameRetransmitted(QuicStreamOffset offset,
                                            QuicByteCount data_length,
                                            bool fin_retransmitted) {
  send_buffer_.OnStreamDataRetransmitted(offset, data_length);
  if (fin_retransmitted) {
    fin_lost_ = false;
  }
}

void QuicStream::OnStreamFrameLost(QuicStreamOffset offset,
                                   QuicByteCount data_length, bool fin_lost) {
  QUIC_DVLOG(1) << ENDPOINT << "stream " << id_ << " Losting "
                << "[" << offset << ", " << offset + data_length << "]"
                << " fin = " << fin_lost;
  if (data_length > 0) {
    send_buffer_.OnStreamDataLost(offset, data_length);
  }
  if (fin_lost && fin_outstanding_) {
    fin_lost_ = true;
  }
}

bool QuicStream::RetransmitStreamData(QuicStreamOffset offset,
                                      QuicByteCount data_length, bool fin,
                                      TransmissionType type) {
  QUICHE_DCHECK(type == PTO_RETRANSMISSION);
  if (HasDeadlinePassed()) {
    OnDeadlinePassed();
    return true;
  }
  QuicIntervalSet<QuicStreamOffset> retransmission(offset,
                                                   offset + data_length);
  retransmission.Difference(bytes_acked());
  bool retransmit_fin = fin && fin_outstanding_;
  if (retransmission.Empty() && !retransmit_fin) {
    return true;
  }
  QuicConsumedData consumed(0, false);
  for (const auto& interval : retransmission) {
    QuicStreamOffset retransmission_offset = interval.min();
    QuicByteCount retransmission_length = interval.max() - interval.min();
    const bool can_bundle_fin =
        retransmit_fin && (retransmission_offset + retransmission_length ==
                           stream_bytes_written());
    consumed = stream_delegate_->WritevData(
        id_, retransmission_length, retransmission_offset,
        can_bundle_fin ? FIN : NO_FIN, type,
        session()->GetEncryptionLevelToSendApplicationData());
    QUIC_DVLOG(1) << ENDPOINT << "stream " << id_
                  << " is forced to retransmit stream data ["
                  << retransmission_offset << ", "
                  << retransmission_offset + retransmission_length
                  << ") and fin: " << can_bundle_fin
                  << ", consumed: " << consumed;
    OnStreamFrameRetransmitted(retransmission_offset, consumed.bytes_consumed,
                               consumed.fin_consumed);
    if (can_bundle_fin) {
      retransmit_fin = !consumed.fin_consumed;
    }
    if (consumed.bytes_consumed < retransmission_length ||
        (can_bundle_fin && !consumed.fin_consumed)) {
      // Connection is write blocked.
      return false;
    }
  }
  if (retransmit_fin) {
    QUIC_DVLOG(1) << ENDPOINT << "stream " << id_
                  << " retransmits fin only frame.";
    consumed = stream_delegate_->WritevData(
        id_, 0, stream_bytes_written(), FIN, type,
        session()->GetEncryptionLevelToSendApplicationData());
    if (!consumed.fin_consumed) {
      return false;
    }
  }
  return true;
}

bool QuicStream::IsWaitingForAcks() const {
  return (!rst_sent_ || stream_error_.ok()) &&
         (send_buffer_.stream_bytes_outstanding() || fin_outstanding_);
}

bool QuicStream::WriteStreamData(QuicStreamOffset offset,
                                 QuicByteCount data_length,
                                 QuicDataWriter* writer) {
  QUICHE_DCHECK_LT(0u, data_length);
  QUIC_DVLOG(2) << ENDPOINT << "Write stream " << id_ << " data from offset "
                << offset << " length " << data_length;
  return send_buffer_.WriteStreamData(offset, data_length, writer);
}

void QuicStream::WriteBufferedData(EncryptionLevel level) {
  QUICHE_DCHECK(!write_side_closed_ && (HasBufferedData() || fin_buffered_));

  if (session_->ShouldYield(id())) {
    session_->MarkConnectionLevelWriteBlocked(id());
    return;
  }

  // Size of buffered data.
  QuicByteCount write_length = BufferedDataBytes();

  // A FIN with zero data payload should not be flow control blocked.
  bool fin_with_zero_data = (fin_buffered_ && write_length == 0);

  bool fin = fin_buffered_;

  QUIC_BUG_IF(quic_bug_10586_13, !flow_controller_.has_value())
      << ENDPOINT << "WriteBufferedData called on stream without flow control";

  // How much data flow control permits to be written.
  QuicByteCount send_window = CalculateSendWindowSize();

  if (send_window == 0 && !fin_with_zero_data) {
    // Quick return if nothing can be sent.
    MaybeSendBlocked();
    return;
  }

  if (write_length > send_window) {
    // Don't send the FIN unless all the data will be sent.
    fin = false;

    // Writing more data would be a violation of flow control.
    write_length = send_window;
    QUIC_DVLOG(1) << "stream " << id() << " shortens write length to "
                  << write_length << " due to flow control";
  }

  StreamSendingState state = fin ? FIN : NO_FIN;
  if (fin && add_random_padding_after_fin_) {
    state = FIN_AND_PADDING;
  }
  QuicConsumedData consumed_data =
      stream_delegate_->WritevData(id(), write_length, stream_bytes_written(),
                                   state, NOT_RETRANSMISSION, level);

  OnStreamDataConsumed(consumed_data.bytes_consumed);

  AddBytesSent(consumed_data.bytes_consumed);
  QUIC_DVLOG(1) << ENDPOINT << "stream " << id_ << " sends "
                << stream_bytes_written() << " bytes "
                << " and has buffered data " << BufferedDataBytes() << " bytes."
                << " fin is sent: " << consumed_data.fin_consumed
                << " fin is buffered: " << fin_buffered_;

  // The write may have generated a write error causing this stream to be
  // closed. If so, simply return without marking the stream write blocked.
  if (write_side_closed_) {
    return;
  }

  if (consumed_data.bytes_consumed == write_length) {
    if (!fin_with_zero_data) {
      MaybeSendBlocked();
    }
    if (fin && consumed_data.fin_consumed) {
      QUICHE_DCHECK(!fin_sent_);
      fin_sent_ = true;
      fin_outstanding_ = true;
      if (fin_received_) {
        QUICHE_DCHECK(!was_draining_);
        session_->StreamDraining(id_,
                                 /*unidirectional=*/type_ != BIDIRECTIONAL);
        was_draining_ = true;
      }
      CloseWriteSide();
    } else if (fin && !consumed_data.fin_consumed && !write_side_closed_) {
      session_->MarkConnectionLevelWriteBlocked(id());
    }
  } else {
    session_->MarkConnectionLevelWriteBlocked(id());
  }
  if (consumed_data.bytes_consumed > 0 || consumed_data.fin_consumed) {
    busy_counter_ = 0;
  }
}

uint64_t QuicStream::BufferedDataBytes() const {
  QUICHE_DCHECK_GE(send_buffer_.stream_offset(), stream_bytes_written());
  return send_buffer_.stream_offset() - stream_bytes_written();
}

bool QuicStream::CanWriteNewData() const {
  return BufferedDataBytes() < buffered_data_threshold_;
}

bool QuicStream::CanWriteNewDataAfterData(QuicByteCount length) const {
  return (BufferedDataBytes() + length) < buffered_data_threshold_;
}

uint64_t QuicStream::stream_bytes_written() const {
  return send_buffer_.stream_bytes_written();
}

const QuicIntervalSet<QuicStreamOffset>& QuicStream::bytes_acked() const {
  return send_buffer_.bytes_acked();
}

void QuicStream::OnStreamDataConsumed(QuicByteCount bytes_consumed) {
  send_buffer_.OnStreamDataConsumed(bytes_consumed);
}

void QuicStream::WritePendingRetransmission() {
  while (HasPendingRetransmission()) {
    QuicConsumedData consumed(0, false);
    if (!send_buffer_.HasPendingRetransmission()) {
      QUIC_DVLOG(1) << ENDPOINT << "stream " << id_
                    << " retransmits fin only frame.";
      consumed = stream_delegate_->WritevData(
          id_, 0, stream_bytes_written(), FIN, LOSS_RETRANSMISSION,
          session()->GetEncryptionLevelToSendApplicationData());
      fin_lost_ = !consumed.fin_consumed;
      if (fin_lost_) {
        // Connection is write blocked.
        return;
      }
    } else {
      StreamPendingRetransmission pending =
          send_buffer_.NextPendingRetransmission();
      // Determine whether the lost fin can be bundled with the data.
      const bool can_bundle_fin =
          fin_lost_ &&
          (pending.offset + pending.length == stream_bytes_written());
      consumed = stream_delegate_->WritevData(
          id_, pending.length, pending.offset, can_bundle_fin ? FIN : NO_FIN,
          LOSS_RETRANSMISSION,
          session()->GetEncryptionLevelToSendApplicationData());
      QUIC_DVLOG(1) << ENDPOINT << "stream " << id_
                    << " tries to retransmit stream data [" << pending.offset
                    << ", " << pending.offset + pending.length
                    << ") and fin: " << can_bundle_fin
                    << ", consumed: " << consumed;
      OnStreamFrameRetransmitted(pending.offset, consumed.bytes_consumed,
                                 consumed.fin_consumed);
      if (consumed.bytes_consumed < pending.length ||
          (can_bundle_fin && !consumed.fin_consumed)) {
        // Connection is write blocked.
        return;
      }
    }
  }
}

bool QuicStream::MaybeSetTtl(QuicTime::Delta ttl) {
  if (is_static_) {
    QUIC_BUG(quic_bug_10586_14) << "Cannot set TTL of a static stream.";
    return false;
  }
  if (deadline_.IsInitialized()) {
    QUIC_DLOG(WARNING) << "Deadline has already been set.";
    return false;
  }
  QuicTime now = session()->connection()->clock()->ApproximateNow();
  deadline_ = now + ttl;
  return true;
}

bool QuicStream::HasDeadlinePassed() const {
  if (!deadline_.IsInitialized()) {
    // No deadline has been set.
    return false;
  }
  QuicTime now = session()->connection()->clock()->ApproximateNow();
  if (now < deadline_) {
    return false;
  }
  // TTL expired.
  QUIC_DVLOG(1) << "stream " << id() << " deadline has passed";
  return true;
}

void QuicStream::MaybeCloseStreamWithBufferedReset() {
  if (buffered_reset_stream_at_.has_value() && !sequencer_.IsClosed() &&
      NumBytesConsumed() >= buffered_reset_stream_at_->reliable_offset) {
    OnStreamReset(buffered_reset_stream_at_->ToRstStream());
    buffered_reset_stream_at_ = std::nullopt;
  }
}

void QuicStream::OnDeadlinePassed() { Reset(QUIC_STREAM_TTL_EXPIRED); }

bool QuicStream::IsFlowControlBlocked() const {
  if (!flow_controller_.has_value()) {
    QUIC_BUG(quic_bug_10586_15)
        << "Trying to access non-existent flow controller.";
    return false;
  }
  return flow_controller_->IsBlocked();
}

QuicStreamOffset QuicStream::highest_received_byte_offset() const {
  if (!flow_controller_.has_value()) {
    QUIC_BUG(quic_bug_10586_16)
        << "Trying to access non-existent flow controller.";
    return 0;
  }
  return flow_controller_->highest_received_byte_offset();
}

void QuicStream::UpdateReceiveWindowSize(QuicStreamOffset size) {
  if (!flow_controller_.has_value()) {
    QUIC_BUG(quic_bug_10586_17)
        << "Trying to access non-existent flow controller.";
    return;
  }
  flow_controller_->UpdateReceiveWindowSize(size);
}

std::optional<QuicByteCount> QuicStream::GetSendWindow() const {
  return flow_controller_.has_value()
             ? std::optional<QuicByteCount>(flow_controller_->SendWindowSize())
             : std::nullopt;
}

std::optional<QuicByteCount> QuicStream::GetReceiveWindow() const {
  return flow_controller_.has_value()
             ? std::optional<QuicByteCount>(
                   flow_controller_->receive_window_size())
             : std::nullopt;
}

void QuicStream::OnStreamCreatedFromPendingStream() {
  sequencer()->SetUnblocked();
}

QuicByteCount QuicStream::CalculateSendWindowSize() const {
  QuicByteCount send_window;
  if (flow_controller_.has_value()) {
    send_window = flow_controller_->SendWindowSize();
  } else {
    send_window = std::numeric_limits<QuicByteCount>::max();
  }
  if (stream_contributes_to_connection_flow_control_) {
    send_window =
        std::min(send_window, connection_flow_controller_->SendWindowSize());
  }
  return send_window;
}

}  // namespace quic
```