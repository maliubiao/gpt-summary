Response:
The user wants a summary of the functionality of the provided C++ code for `quic_stream.cc`. I need to identify the core responsibilities of this class. Since it's part 1 of 2, the current snippet likely focuses on receiving and buffering data, handling flow control, and managing the read side of the stream.

Here's a breakdown of my thinking process to achieve the requested summary:

1. **Identify the Class:** The primary class is `QuicStream`. There's also a `PendingStream` which appears to be a temporary holder for streams before they become fully active.

2. **Core Responsibility - Data Handling (Receiving):** The code extensively deals with receiving data via `OnStreamFrame`. Key aspects include:
    * **Buffering:**  The `QuicStreamSequencer` is clearly responsible for buffering incoming data.
    * **Flow Control:**  `QuicFlowController` tracks received bytes and enforces limits to prevent overwhelming the receiver.
    * **Error Handling:**  The code checks for various error conditions like exceeding stream limits (`kMaxStreamLength`), data arriving out of order or beyond the close offset, and flow control violations.
    * **FIN Handling:**  The code detects and processes the FIN flag, indicating the end of the stream.

3. **Core Responsibility - Flow Control (Receiving):**  The `QuicFlowController` is central to managing the rate of incoming data. This involves:
    * **Tracking Received Bytes:**  Keeping track of the highest received offset.
    * **Enforcing Limits:**  Checking for flow control violations.
    * **Connection-Level Integration:**  Interacting with the session's connection-level flow control.

4. **Core Responsibility - Stream State Management (Read Side):** The code manages the read state of the stream:
    * **`read_side_closed_`:**  A boolean indicating if the read side is closed.
    * **`fin_received_`:**  A boolean tracking whether the FIN has been received.
    * **Closing the Read Side:**  The `CloseReadSide()` function handles the closure logic, including notifying the session.

5. **Secondary Responsibilities:**
    * **Reset Handling:** Processing `QuicRstStreamFrame` and `QuicResetStreamAtFrame` for abrupt stream termination.
    * **Stop Sending:** Handling `OnStopSending` from the peer, indicating they won't send more data.
    * **Priority:**  Managing stream priority using `QuicStreamPriority`.
    * **Pending Streams:** The `PendingStream` class seems to be a temporary holding area for newly created streams before they become fully active.

6. **Relationship to JavaScript (and Web Browsers):** QUIC is a transport protocol used by web browsers. The `QuicStream` class is a fundamental building block for handling data transfer within a QUIC connection. It corresponds conceptually to the `ReadableStream` API in JavaScript, which allows JavaScript code to consume data chunks as they arrive from the network.

7. **Logical Reasoning (Example):**  I can create a simple scenario:
    * **Input:**  A `QuicStreamFrame` arrives with `offset = 0`, `data = "hello"`, and `fin = false`.
    * **Processing:** The code will buffer "hello" in the sequencer, increment `stream_bytes_read_`, and potentially trigger a `OnDataAvailable()` callback.
    * **Output:** The data is now available to be read by the application layer.

8. **Common User/Programming Errors:**  A common error would be trying to write data to a stream after its write side has been closed. The code includes checks for this and logs an error.

9. **Debugging Scenario:**  A user might encounter this code during debugging if they are investigating issues with data transfer over a QUIC connection. They might be looking at why data is being buffered, why a stream is being reset, or why flow control is blocking data. They would likely trace the execution flow through the `OnStreamFrame` function.

10. **Synthesize the Summary:** Based on the above points, I can now formulate a concise summary of the code's functionality for the first part.

By following these steps, I can systematically analyze the code and generate the required summary, examples, and explanations.
这是 Chromium 网络栈中 QUIC 协议栈中 `quic_stream.cc` 文件的第一部分代码。它主要负责**管理 QUIC 连接中的单个数据流的接收部分**。

以下是该部分代码的主要功能归纳：

**核心功能：管理 QUIC 数据流的接收 (Read Side)**

1. **接收和缓冲数据 (OnStreamFrame):**
   - 处理接收到的 `QuicStreamFrame`，包含数据负载、偏移量和 FIN 标志。
   - 使用 `QuicStreamSequencer` 对接收到的数据进行排序和缓冲，处理乱序到达的数据。
   - 检查数据偏移量是否超出最大允许值 (`kMaxStreamLength`)。
   - 检查数据是否在已关闭的流上接收。
   - 检查数据偏移量是否超出已知的关闭偏移量。
   - 记录接收到的字节数。

2. **流量控制 (Flow Control):**
   - 使用 `QuicFlowController` 管理流级别的流量控制。
   - 跟踪已接收的最高字节偏移量。
   - 与连接级别的流量控制 (`connection_flow_controller_`) 协同工作。
   - 检测并处理流量控制违规行为。
   - 处理 `QuicWindowUpdateFrame`，更新发送窗口。

3. **处理流的终止 (FIN 和 RST):**
   - 接收到带有 FIN 标志的 `QuicStreamFrame` 时，标记 `fin_received_` 为 true，并可能触发流的排空 (draining) 状态。
   - 处理接收到的 `QuicRstStreamFrame` (流重置帧)，表示对端异常终止了流。
   - 检查 `QuicRstStreamFrame` 中的字节偏移量是否有效。
   - 处理接收到的 `QuicResetStreamAtFrame`，这是一种可靠的重置机制，带有一个特定的偏移量。

4. **处理 STOP_SENDING 帧 (OnStopSending):**
   - 接收到 `STOP_SENDING` 帧，表示对端不再发送数据到此流。

5. **管理流的状态:**
   - 跟踪流的读取侧是否已关闭 (`read_side_closed_`)。
   - 跟踪是否已收到 FIN (`fin_received_`)。
   - 记录流的错误状态 (`stream_error_`, `connection_error_`).

6. **PendingStream 类的使用:**
   - 定义了一个 `PendingStream` 类，用于在流被完全建立之前临时存储流的信息，特别是用于处理对端发起的流。
   - `PendingStream` 也管理着自身的流量控制和数据排序。

**与 JavaScript 的关系举例说明：**

虽然 C++ 代码本身不直接与 JavaScript 交互，但它构成了浏览器网络栈的基础，支持着 JavaScript 中的网络 API，例如 `fetch` API 或 WebSocket API 使用 QUIC 协议进行数据传输。

**举例说明:**

假设一个用户在浏览器中通过 JavaScript 的 `fetch` API 发起一个 HTTP/3 请求：

```javascript
fetch('https://example.com/data')
  .then(response => response.text())
  .then(data => console.log(data));
```

在这个过程中，`quic_stream.cc` 中 `QuicStream` 的实例会负责处理从 `example.com` 服务器接收响应数据的 QUIC 流。

- 当服务器发送数据时，浏览器的 QUIC 实现会解析接收到的 `QuicStreamFrame`，并调用 `QuicStream::OnStreamFrame`。
- `OnStreamFrame` 会将数据存储在 `sequencer_` 中。
- 如果服务器发送了 FIN 标志，`fin_received_` 会被设置为 true。
- 一旦数据准备好被 JavaScript 读取，浏览器会将数据传递给 `fetch` API 的响应处理逻辑，最终通过 `response.text()` 提供给 JavaScript 代码。

**逻辑推理的假设输入与输出：**

**假设输入：** 接收到一个 `QuicStreamFrame`，`frame.stream_id = 10`, `frame.offset = 0`, `frame.data = "Hello"`, `frame.fin = false`.

**处理过程：**

1. `QuicStream::OnStreamFrame(frame)` 被调用。
2. 断言 `frame.stream_id` 与当前流的 `id_` 相等。
3. 检查流的状态，例如是否已关闭。
4. 检查偏移量是否有效。
5. 数据 "Hello" 被添加到 `sequencer_` 中进行缓冲。
6. `stream_bytes_read_` 增加 5。
7. 检查流量控制是否受到影响。

**输出：**

- 数据 "Hello" 被缓冲，等待进一步处理。
- 流的接收字节数增加。
- 如果有数据可读，可能会通知上层协议或应用层。

**用户或编程常见的使用错误举例说明：**

**错误：** 对一个已经接收到 FIN 的流继续发送数据。

**调试线索:**

1. **用户操作:** 用户在网页上执行某些操作，触发 JavaScript 代码向服务器发送数据。
2. **JavaScript 代码:** JavaScript 使用 `fetch` 或其他网络 API 发送请求。
3. **QUIC 层:**  底层的 QUIC 实现尝试发送数据到一个服务端已经发送过 FIN 的流上。
4. **`quic_stream.cc`:** 服务端可能在之前的某个时间点发送了一个带有 FIN 标志的 `QuicStreamFrame`。
5. **代码检查:**  服务端 `QuicStream` 对象中，`fin_received_` 标志为 `true`。
6. **结果:** 当新的数据到达服务端时，`OnStreamFrame` 方法会检查 `fin_received_`，并可能忽略该数据或触发错误，因为该流已经逻辑上结束了接收。
7. **调试线索:**  调试时，可以检查服务端的 QUIC 连接状态和流的状态，查看 `fin_received_` 的值，以及是否有相关的错误日志表明尝试在已关闭的流上接收数据。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户发起网络请求:** 用户在浏览器中点击链接、提交表单或 JavaScript 代码执行 `fetch` 等操作，触发向服务器发送数据的请求。
2. **浏览器构建 HTTP 请求:** 浏览器将用户的操作转化为 HTTP 请求。
3. **QUIC 连接建立:** 如果浏览器和服务器支持 HTTP/3，则会通过 QUIC 协议建立连接。
4. **创建 QUIC 流:** 对于每个 HTTP 请求/响应，都会创建一个或多个 QUIC 流。
5. **数据传输:**  HTTP 请求和响应数据被分割成 `QuicStreamFrame` 并通过 QUIC 流进行传输。
6. **服务端接收数据:** 服务器端的 QUIC 实现接收到 `QuicStreamFrame`，并调用 `quic_stream.cc` 中的 `QuicStream::OnStreamFrame` 方法来处理接收到的数据。
7. **调试点:**  如果在服务端调试，当收到与特定用户操作相关的网络请求时，可以在 `OnStreamFrame` 中设置断点，查看接收到的数据、流的状态、流量控制信息等，从而追踪用户操作是如何一步步导致特定的网络行为的。例如，可以检查特定流 ID 的数据接收情况，以了解用户上传的文件数据是否正确到达。

**总结 `quic_stream.cc` 第一部分的功能：**

这部分代码主要负责 QUIC 流的**接收和管理**，包括接收数据帧、进行流量控制、处理流的终止信号（FIN 和 RST）、管理流的读取状态，以及为后续处理提供已排序的接收数据。 `PendingStream` 用于管理尚未完全建立的接收流。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_stream.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_stream.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <string>
#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/frames/quic_reset_stream_at_frame.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_flow_controller.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"

using spdy::SpdyPriority;

namespace quic {

#define ENDPOINT \
  (perspective_ == Perspective::IS_SERVER ? "Server: " : "Client: ")

namespace {

QuicByteCount DefaultFlowControlWindow(ParsedQuicVersion version) {
  if (!version.AllowsLowFlowControlLimits()) {
    return kDefaultFlowControlSendWindow;
  }
  return 0;
}

QuicByteCount GetInitialStreamFlowControlWindowToSend(QuicSession* session,
                                                      QuicStreamId stream_id) {
  ParsedQuicVersion version = session->connection()->version();
  if (version.handshake_protocol != PROTOCOL_TLS1_3) {
    return session->config()->GetInitialStreamFlowControlWindowToSend();
  }

  // Unidirectional streams (v99 only).
  if (VersionHasIetfQuicFrames(version.transport_version) &&
      !QuicUtils::IsBidirectionalStreamId(stream_id, version)) {
    return session->config()
        ->GetInitialMaxStreamDataBytesUnidirectionalToSend();
  }

  if (QuicUtils::IsOutgoingStreamId(version, stream_id,
                                    session->perspective())) {
    return session->config()
        ->GetInitialMaxStreamDataBytesOutgoingBidirectionalToSend();
  }

  return session->config()
      ->GetInitialMaxStreamDataBytesIncomingBidirectionalToSend();
}

QuicByteCount GetReceivedFlowControlWindow(QuicSession* session,
                                           QuicStreamId stream_id) {
  ParsedQuicVersion version = session->connection()->version();
  if (version.handshake_protocol != PROTOCOL_TLS1_3) {
    if (session->config()->HasReceivedInitialStreamFlowControlWindowBytes()) {
      return session->config()->ReceivedInitialStreamFlowControlWindowBytes();
    }

    return DefaultFlowControlWindow(version);
  }

  // Unidirectional streams (v99 only).
  if (VersionHasIetfQuicFrames(version.transport_version) &&
      !QuicUtils::IsBidirectionalStreamId(stream_id, version)) {
    if (session->config()
            ->HasReceivedInitialMaxStreamDataBytesUnidirectional()) {
      return session->config()
          ->ReceivedInitialMaxStreamDataBytesUnidirectional();
    }

    return DefaultFlowControlWindow(version);
  }

  if (QuicUtils::IsOutgoingStreamId(version, stream_id,
                                    session->perspective())) {
    if (session->config()
            ->HasReceivedInitialMaxStreamDataBytesOutgoingBidirectional()) {
      return session->config()
          ->ReceivedInitialMaxStreamDataBytesOutgoingBidirectional();
    }

    return DefaultFlowControlWindow(version);
  }

  if (session->config()
          ->HasReceivedInitialMaxStreamDataBytesIncomingBidirectional()) {
    return session->config()
        ->ReceivedInitialMaxStreamDataBytesIncomingBidirectional();
  }

  return DefaultFlowControlWindow(version);
}

}  // namespace

PendingStream::PendingStream(QuicStreamId id, QuicSession* session)
    : id_(id),
      version_(session->version()),
      stream_delegate_(session),
      stream_bytes_read_(0),
      fin_received_(false),
      is_bidirectional_(QuicUtils::GetStreamType(id, session->perspective(),
                                                 /*peer_initiated = */ true,
                                                 session->version()) ==
                        BIDIRECTIONAL),
      connection_flow_controller_(session->flow_controller()),
      flow_controller_(session, id,
                       /*is_connection_flow_controller*/ false,
                       GetReceivedFlowControlWindow(session, id),
                       GetInitialStreamFlowControlWindowToSend(session, id),
                       kStreamReceiveWindowLimit,
                       session->flow_controller()->auto_tune_receive_window(),
                       session->flow_controller()),
      sequencer_(this),
      creation_time_(session->GetClock()->ApproximateNow()) {
  if (is_bidirectional_) {
    QUIC_CODE_COUNT_N(quic_pending_stream, 3, 3);
  }
}

void PendingStream::OnDataAvailable() {
  // Data should be kept in the sequencer so that
  // QuicSession::ProcessPendingStream() can read it.
}

void PendingStream::OnFinRead() { QUICHE_DCHECK(sequencer_.IsClosed()); }

void PendingStream::AddBytesConsumed(QuicByteCount bytes) {
  // It will be called when the metadata of the stream is consumed.
  flow_controller_.AddBytesConsumed(bytes);
  connection_flow_controller_->AddBytesConsumed(bytes);
}

void PendingStream::ResetWithError(QuicResetStreamError /*error*/) {
  // Currently PendingStream is only read-unidirectional. It shouldn't send
  // Reset.
  QUICHE_NOTREACHED();
}

void PendingStream::OnUnrecoverableError(QuicErrorCode error,
                                         const std::string& details) {
  stream_delegate_->OnStreamError(error, details);
}

void PendingStream::OnUnrecoverableError(QuicErrorCode error,
                                         QuicIetfTransportErrorCodes ietf_error,
                                         const std::string& details) {
  stream_delegate_->OnStreamError(error, ietf_error, details);
}

QuicStreamId PendingStream::id() const { return id_; }

ParsedQuicVersion PendingStream::version() const { return version_; }

void PendingStream::OnStreamFrame(const QuicStreamFrame& frame) {
  QUICHE_DCHECK_EQ(frame.stream_id, id_);

  bool is_stream_too_long =
      (frame.offset > kMaxStreamLength) ||
      (kMaxStreamLength - frame.offset < frame.data_length);
  if (is_stream_too_long) {
    // Close connection if stream becomes too long.
    QUIC_PEER_BUG(quic_peer_bug_12570_1)
        << "Receive stream frame reaches max stream length. frame offset "
        << frame.offset << " length " << frame.data_length;
    OnUnrecoverableError(QUIC_STREAM_LENGTH_OVERFLOW,
                         "Peer sends more data than allowed on this stream.");
    return;
  }

  if (frame.offset + frame.data_length > sequencer_.close_offset()) {
    OnUnrecoverableError(
        QUIC_STREAM_DATA_BEYOND_CLOSE_OFFSET,
        absl::StrCat(
            "Stream ", id_,
            " received data with offset: ", frame.offset + frame.data_length,
            ", which is beyond close offset: ", sequencer()->close_offset()));
    return;
  }

  if (frame.fin) {
    fin_received_ = true;
  }

  // This count includes duplicate data received.
  QuicByteCount frame_payload_size = frame.data_length;
  stream_bytes_read_ += frame_payload_size;

  // Flow control is interested in tracking highest received offset.
  // Only interested in received frames that carry data.
  if (frame_payload_size > 0 &&
      MaybeIncreaseHighestReceivedOffset(frame.offset + frame_payload_size)) {
    // As the highest received offset has changed, check to see if this is a
    // violation of flow control.
    if (flow_controller_.FlowControlViolation() ||
        connection_flow_controller_->FlowControlViolation()) {
      OnUnrecoverableError(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA,
                           "Flow control violation after increasing offset");
      return;
    }
  }

  sequencer_.OnStreamFrame(frame);
}

void PendingStream::OnRstStreamFrame(const QuicRstStreamFrame& frame) {
  QUICHE_DCHECK_EQ(frame.stream_id, id_);

  if (frame.byte_offset > kMaxStreamLength) {
    // Peer are not suppose to write bytes more than maxium allowed.
    OnUnrecoverableError(QUIC_STREAM_LENGTH_OVERFLOW,
                         "Reset frame stream offset overflow.");
    return;
  }

  const QuicStreamOffset kMaxOffset =
      std::numeric_limits<QuicStreamOffset>::max();
  if (sequencer()->close_offset() != kMaxOffset &&
      frame.byte_offset != sequencer()->close_offset()) {
    OnUnrecoverableError(
        QUIC_STREAM_MULTIPLE_OFFSET,
        absl::StrCat("Stream ", id_,
                     " received new final offset: ", frame.byte_offset,
                     ", which is different from close offset: ",
                     sequencer()->close_offset()));
    return;
  }

  MaybeIncreaseHighestReceivedOffset(frame.byte_offset);
  if (flow_controller_.FlowControlViolation() ||
      connection_flow_controller_->FlowControlViolation()) {
    OnUnrecoverableError(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA,
                         "Flow control violation after increasing offset");
    return;
  }
}

void PendingStream::OnResetStreamAtFrame(const QuicResetStreamAtFrame& frame) {
  if (frame.reliable_offset > sequencer()->close_offset()) {
    OnUnrecoverableError(
        QUIC_STREAM_MULTIPLE_OFFSET,
        absl::StrCat(
            "Stream ", id_,
            " received reliable reset with offset: ", frame.reliable_offset,
            " greater than the FIN offset: ", sequencer()->close_offset()));
    return;
  }
  if (buffered_reset_stream_at_.has_value() &&
      (frame.reliable_offset > buffered_reset_stream_at_->reliable_offset)) {
    // Ignore a reliable reset that raises the reliable size. It might have
    // arrived out of sequence.
    return;
  }
  buffered_reset_stream_at_ = frame;
  sequencer_.OnReliableReset(frame.reliable_offset);
}

void PendingStream::OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) {
  QUICHE_DCHECK(is_bidirectional_);
  flow_controller_.UpdateSendWindowOffset(frame.max_data);
}

bool PendingStream::MaybeIncreaseHighestReceivedOffset(
    QuicStreamOffset new_offset) {
  uint64_t increment =
      new_offset - flow_controller_.highest_received_byte_offset();
  if (!flow_controller_.UpdateHighestReceivedOffset(new_offset)) {
    return false;
  }

  // If |new_offset| increased the stream flow controller's highest received
  // offset, increase the connection flow controller's value by the incremental
  // difference.
  connection_flow_controller_->UpdateHighestReceivedOffset(
      connection_flow_controller_->highest_received_byte_offset() + increment);
  return true;
}

void PendingStream::OnStopSending(
    QuicResetStreamError stop_sending_error_code) {
  if (!stop_sending_error_code_) {
    stop_sending_error_code_ = stop_sending_error_code;
  }
}

void PendingStream::MarkConsumed(QuicByteCount num_bytes) {
  sequencer_.MarkConsumed(num_bytes);
}

void PendingStream::StopReading() {
  QUIC_DVLOG(1) << "Stop reading from pending stream " << id();
  sequencer_.StopReading();
}

QuicStream::QuicStream(PendingStream* pending, QuicSession* session,
                       bool is_static)
    : QuicStream(
          pending->id_, session, std::move(pending->sequencer_), is_static,
          QuicUtils::GetStreamType(pending->id_, session->perspective(),
                                   /*peer_initiated = */ true,
                                   session->version()),
          pending->stream_bytes_read_, pending->fin_received_,
          std::move(pending->flow_controller_),
          pending->connection_flow_controller_,
          (session->GetClock()->ApproximateNow() - pending->creation_time())) {
  QUICHE_DCHECK(session->version().HasIetfQuicFrames());
  sequencer_.set_stream(this);
  buffered_reset_stream_at_ = pending->buffered_reset_stream_at();
}

namespace {

std::optional<QuicFlowController> FlowController(QuicStreamId id,
                                                 QuicSession* session,
                                                 StreamType type) {
  if (type == CRYPTO) {
    // The only QuicStream with a StreamType of CRYPTO is QuicCryptoStream, when
    // it is using crypto frames instead of stream frames. The QuicCryptoStream
    // doesn't have any flow control in that case, so we don't create a
    // QuicFlowController for it.
    return std::nullopt;
  }
  return QuicFlowController(
      session, id,
      /*is_connection_flow_controller*/ false,
      GetReceivedFlowControlWindow(session, id),
      GetInitialStreamFlowControlWindowToSend(session, id),
      kStreamReceiveWindowLimit,
      session->flow_controller()->auto_tune_receive_window(),
      session->flow_controller());
}

}  // namespace

QuicStream::QuicStream(QuicStreamId id, QuicSession* session, bool is_static,
                       StreamType type)
    : QuicStream(id, session, QuicStreamSequencer(this), is_static, type, 0,
                 false, FlowController(id, session, type),
                 session->flow_controller(), QuicTime::Delta::Zero()) {}

QuicStream::QuicStream(QuicStreamId id, QuicSession* session,
                       QuicStreamSequencer sequencer, bool is_static,
                       StreamType type, uint64_t stream_bytes_read,
                       bool fin_received,
                       std::optional<QuicFlowController> flow_controller,
                       QuicFlowController* connection_flow_controller,
                       QuicTime::Delta pending_duration)
    : sequencer_(std::move(sequencer)),
      id_(id),
      session_(session),
      stream_delegate_(session),
      stream_bytes_read_(stream_bytes_read),
      stream_error_(QuicResetStreamError::NoError()),
      connection_error_(QUIC_NO_ERROR),
      read_side_closed_(false),
      write_side_closed_(false),
      write_side_data_recvd_state_notified_(false),
      fin_buffered_(false),
      fin_sent_(false),
      fin_outstanding_(false),
      fin_lost_(false),
      fin_received_(fin_received),
      rst_sent_(false),
      rst_received_(false),
      stop_sending_sent_(false),
      flow_controller_(std::move(flow_controller)),
      connection_flow_controller_(connection_flow_controller),
      stream_contributes_to_connection_flow_control_(true),
      busy_counter_(0),
      add_random_padding_after_fin_(false),
      send_buffer_(
          session->connection()->helper()->GetStreamSendBufferAllocator()),
      buffered_data_threshold_(GetQuicFlag(quic_buffered_data_threshold)),
      is_static_(is_static),
      deadline_(QuicTime::Zero()),
      was_draining_(false),
      type_(VersionHasIetfQuicFrames(session->transport_version()) &&
                    type != CRYPTO
                ? QuicUtils::GetStreamType(id_, session->perspective(),
                                           session->IsIncomingStream(id_),
                                           session->version())
                : type),
      creation_time_(session->connection()->clock()->ApproximateNow()),
      pending_duration_(pending_duration),
      perspective_(session->perspective()) {
  if (type_ == WRITE_UNIDIRECTIONAL) {
    fin_received_ = true;
    CloseReadSide();
  } else if (type_ == READ_UNIDIRECTIONAL) {
    fin_sent_ = true;
    CloseWriteSide();
  }
  if (type_ != CRYPTO) {
    stream_delegate_->RegisterStreamPriority(id, is_static_, priority_);
  }
}

QuicStream::~QuicStream() {
  if (session_ != nullptr && IsWaitingForAcks()) {
    QUIC_DVLOG(1)
        << ENDPOINT << "Stream " << id_
        << " gets destroyed while waiting for acks. stream_bytes_outstanding = "
        << send_buffer_.stream_bytes_outstanding()
        << ", fin_outstanding: " << fin_outstanding_;
  }
  if (stream_delegate_ != nullptr && type_ != CRYPTO) {
    stream_delegate_->UnregisterStreamPriority(id());
  }
}

void QuicStream::OnStreamFrame(const QuicStreamFrame& frame) {
  QUICHE_DCHECK_EQ(frame.stream_id, id_);

  QUICHE_DCHECK(!(read_side_closed_ && write_side_closed_));

  if (frame.fin && is_static_) {
    OnUnrecoverableError(QUIC_INVALID_STREAM_ID,
                         "Attempt to close a static stream");
    return;
  }

  if (type_ == WRITE_UNIDIRECTIONAL) {
    OnUnrecoverableError(QUIC_DATA_RECEIVED_ON_WRITE_UNIDIRECTIONAL_STREAM,
                         "Data received on write unidirectional stream");
    return;
  }

  bool is_stream_too_long =
      (frame.offset > kMaxStreamLength) ||
      (kMaxStreamLength - frame.offset < frame.data_length);
  if (is_stream_too_long) {
    // Close connection if stream becomes too long.
    QUIC_PEER_BUG(quic_peer_bug_10586_1)
        << "Receive stream frame on stream " << id_
        << " reaches max stream length. frame offset " << frame.offset
        << " length " << frame.data_length << ". " << sequencer_.DebugString();
    OnUnrecoverableError(
        QUIC_STREAM_LENGTH_OVERFLOW,
        absl::StrCat("Peer sends more data than allowed on stream ", id_,
                     ". frame: offset = ", frame.offset, ", length = ",
                     frame.data_length, ". ", sequencer_.DebugString()));
    return;
  }

  if (frame.offset + frame.data_length > sequencer_.close_offset()) {
    OnUnrecoverableError(
        QUIC_STREAM_DATA_BEYOND_CLOSE_OFFSET,
        absl::StrCat(
            "Stream ", id_,
            " received data with offset: ", frame.offset + frame.data_length,
            ", which is beyond close offset: ", sequencer_.close_offset()));
    return;
  }

  if (frame.fin && !fin_received_) {
    fin_received_ = true;
    if (fin_sent_) {
      QUICHE_DCHECK(!was_draining_);
      session_->StreamDraining(id_,
                               /*unidirectional=*/type_ != BIDIRECTIONAL);
      was_draining_ = true;
    }
  }

  if (read_side_closed_) {
    QUIC_DLOG(INFO)
        << ENDPOINT << "Stream " << frame.stream_id
        << " is closed for reading. Ignoring newly received stream data.";
    // The subclass does not want to read data:  blackhole the data.
    return;
  }

  // This count includes duplicate data received.
  QuicByteCount frame_payload_size = frame.data_length;
  stream_bytes_read_ += frame_payload_size;

  // Flow control is interested in tracking highest received offset.
  // Only interested in received frames that carry data.
  if (frame_payload_size > 0 &&
      MaybeIncreaseHighestReceivedOffset(frame.offset + frame_payload_size)) {
    // As the highest received offset has changed, check to see if this is a
    // violation of flow control.
    QUIC_BUG_IF(quic_bug_12570_2, !flow_controller_.has_value())
        << ENDPOINT << "OnStreamFrame called on stream without flow control";
    if ((flow_controller_.has_value() &&
         flow_controller_->FlowControlViolation()) ||
        connection_flow_controller_->FlowControlViolation()) {
      OnUnrecoverableError(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA,
                           "Flow control violation after increasing offset");
      return;
    }
  }

  sequencer_.OnStreamFrame(frame);
}

bool QuicStream::OnStopSending(QuicResetStreamError error) {
  // Do not reset the stream if all data has been sent and acknowledged.
  if (write_side_closed() && !IsWaitingForAcks()) {
    QUIC_DVLOG(1) << ENDPOINT
                  << "Ignoring STOP_SENDING for a write closed stream, id: "
                  << id_;
    return false;
  }

  if (is_static_) {
    QUIC_DVLOG(1) << ENDPOINT
                  << "Received STOP_SENDING for a static stream, id: " << id_
                  << " Closing connection";
    OnUnrecoverableError(QUIC_INVALID_STREAM_ID,
                         "Received STOP_SENDING for a static stream");
    return false;
  }

  stream_error_ = error;
  MaybeSendRstStream(error);
  if (session()->enable_stop_sending_for_zombie_streams() &&
      read_side_closed_ && write_side_closed_ && !IsWaitingForAcks()) {
    QUIC_RELOADABLE_FLAG_COUNT_N(quic_deliver_stop_sending_to_zombie_streams, 3,
                                 3);
    session()->MaybeCloseZombieStream(id_);
  }
  return true;
}

int QuicStream::num_frames_received() const {
  return sequencer_.num_frames_received();
}

int QuicStream::num_duplicate_frames_received() const {
  return sequencer_.num_duplicate_frames_received();
}

void QuicStream::OnStreamReset(const QuicRstStreamFrame& frame) {
  rst_received_ = true;
  if (frame.byte_offset > kMaxStreamLength) {
    // Peer are not suppose to write bytes more than maxium allowed.
    OnUnrecoverableError(QUIC_STREAM_LENGTH_OVERFLOW,
                         "Reset frame stream offset overflow.");
    return;
  }

  const QuicStreamOffset kMaxOffset =
      std::numeric_limits<QuicStreamOffset>::max();
  if (sequencer()->close_offset() != kMaxOffset &&
      frame.byte_offset != sequencer()->close_offset()) {
    OnUnrecoverableError(
        QUIC_STREAM_MULTIPLE_OFFSET,
        absl::StrCat("Stream ", id_,
                     " received new final offset: ", frame.byte_offset,
                     ", which is different from close offset: ",
                     sequencer_.close_offset()));
    return;
  }

  MaybeIncreaseHighestReceivedOffset(frame.byte_offset);
  QUIC_BUG_IF(quic_bug_12570_3, !flow_controller_.has_value())
      << ENDPOINT << "OnStreamReset called on stream without flow control";
  if ((flow_controller_.has_value() &&
       flow_controller_->FlowControlViolation()) ||
      connection_flow_controller_->FlowControlViolation()) {
    OnUnrecoverableError(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA,
                         "Flow control violation after increasing offset");
    return;
  }

  stream_error_ = frame.error();
  // Google QUIC closes both sides of the stream in response to a
  // RESET_STREAM, IETF QUIC closes only the read side.
  if (!VersionHasIetfQuicFrames(transport_version())) {
    CloseWriteSide();
  }
  CloseReadSide();
}

void QuicStream::OnResetStreamAtFrame(const QuicResetStreamAtFrame& frame) {
  if (frame.reliable_offset > sequencer()->close_offset()) {
    OnUnrecoverableError(
        QUIC_STREAM_MULTIPLE_OFFSET,
        absl::StrCat(
            "Stream ", id_,
            " received reliable reset with offset: ", frame.reliable_offset,
            " greater than the FIN offset: ", sequencer()->close_offset()));
    return;
  }
  if (buffered_reset_stream_at_.has_value() &&
      (frame.reliable_offset > buffered_reset_stream_at_->reliable_offset)) {
    // Ignore a reliable reset that raises the reliable size. It might have
    // arrived out of sequence.
    return;
  }
  buffered_reset_stream_at_ = frame;
  MaybeCloseStreamWithBufferedReset();
  if (!rst_received_) {
    sequencer_.OnReliableReset(frame.reliable_offset);
  }
}

void QuicStream::OnConnectionClosed(const QuicConnectionCloseFrame& frame,
                                    ConnectionCloseSource /*source*/) {
  if (read_side_closed_ && write_side_closed_) {
    return;
  }
  auto error_code = frame.quic_error_code;
  if (error_code != QUIC_NO_ERROR) {
    stream_error_ =
        QuicResetStreamError::FromInternal(QUIC_STREAM_CONNECTION_ERROR);
    connection_error_ = error_code;
  }

  CloseWriteSide();
  CloseReadSide();
}

void QuicStream::OnFinRead() {
  QUICHE_DCHECK(sequencer_.IsClosed());
  // OnFinRead can be called due to a FIN flag in a headers block, so there may
  // have been no OnStreamFrame call with a FIN in the frame.
  fin_received_ = true;
  // If fin_sent_ is true, then CloseWriteSide has already been called, and the
  // stream will be destroyed by CloseReadSide, so don't need to call
  // StreamDraining.
  CloseReadSide();
}

void QuicStream::SetFinSent() {
  QUICHE_DCHECK(!VersionUsesHttp3(transport_version()));
  fin_sent_ = true;
}

void QuicStream::Reset(QuicRstStreamErrorCode error) {
  ResetWithError(QuicResetStreamError::FromInternal(error));
}

void QuicStream::ResetWithError(QuicResetStreamError error) {
  stream_error_ = error;
  QuicConnection::ScopedPacketFlusher flusher(session()->connection());
  MaybeSendStopSending(error);
  MaybeSendRstStream(error);

  if (read_side_closed_ && write_side_closed_ && !IsWaitingForAcks()) {
    session()->MaybeCloseZombieStream(id_);
  }
}

void QuicStream::ResetWriteSide(QuicResetStreamError error) {
  stream_error_ = error;
  MaybeSendRstStream(error);

  if (read_side_closed_ && write_side_closed_ && !IsWaitingForAcks()) {
    session()->MaybeCloseZombieStream(id_);
  }
}

void QuicStream::SendStopSending(QuicResetStreamError error) {
  stream_error_ = error;
  MaybeSendStopSending(error);

  if (read_side_closed_ && write_side_closed_ && !IsWaitingForAcks()) {
    session()->MaybeCloseZombieStream(id_);
  }
}

void QuicStream::OnUnrecoverableError(QuicErrorCode error,
                                      const std::string& details) {
  stream_delegate_->OnStreamError(error, details);
}

void QuicStream::OnUnrecoverableError(QuicErrorCode error,
                                      QuicIetfTransportErrorCodes ietf_error,
                                      const std::string& details) {
  stream_delegate_->OnStreamError(error, ietf_error, details);
}

const QuicStreamPriority& QuicStream::priority() const { return priority_; }

void QuicStream::SetPriority(const QuicStreamPriority& priority) {
  priority_ = priority;

  MaybeSendPriorityUpdateFrame();

  stream_delegate_->UpdateStreamPriority(id(), priority);
}

void QuicStream::WriteOrBufferData(
    absl::string_view data, bool fin,
    quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>
        ack_listener) {
  QUIC_BUG_IF(quic_bug_12570_4,
              QuicUtils::IsCryptoStreamId(transport_version(), id_))
      << ENDPOINT
      << "WriteOrBufferData is used to send application data, use "
         "WriteOrBufferDataAtLevel to send crypto data.";
  return WriteOrBufferDataAtLevel(
      data, fin, session()->GetEncryptionLevelToSendApplicationData(),
      ack_listener);
}

void QuicStream::WriteOrBufferDataAtLevel(
    absl::string_view data, bool fin, EncryptionLevel level,
    quiche::QuicheReferenceCountedPointer<QuicAckListenerInterface>
        ack_listener) {
  if (data.empty() && !fin) {
    QUIC_BUG(quic_bug_10586_2) << "data.empty() && !fin";
    return;
  }

  if (fin_buffered_) {
    QUIC_BUG(quic_bug_10586_3) << "Fin already buffered";
    return;
  }
  if (write_side_closed_) {
    QUIC_DLOG(ERROR) << ENDPOINT
                     << "Attempt to write when the write side is closed";
    if (type_ == READ_UNIDIRECTIONAL) {
      OnUnrecoverableError(QUIC_TRY_TO_WRITE_DATA_ON_READ_UNIDIRECTIONAL_STREAM,
                           "Try to send data on read unidirectional stream");
    }
    return;
  }

  fin_buffered_ = fin;

  bool had_buffered_data = HasBufferedData();
  // Do not respect buffered data upper limit as WriteOrBufferData guarantees
  // all data to be consumed.
  if (data.length() > 0) {
    QuicStreamOffset offset = send_buffer_.stream_offset();
    if (kMaxStreamLength - offset < data.length()) {
      QUIC_BUG(quic_bug_10586_4) << "Write too many data via stream " << id_;
      OnUnrecoverableError(
          QUIC_STREAM_LENGTH_OVERFLOW,
          absl::StrCat("Write too many data via stream ", id_));
      return;
    }
    send_buffer_.SaveStreamData(data);
    OnDataBuffered(offset, data.length(), ack_listener);
  }
  if (!had_buffered_data && (HasBufferedData() || fin_buffered_)) {
    // Write data if there is no buffered data before.
    WriteBufferedData(level);
  }
}

void QuicStream::OnCanWrite() {
  if (HasDeadlinePassed()) {
    OnDeadlinePassed();
    return;
  }
  if (HasPendingRetransmission()) {
    WritePendingRetransmission();
    // Exit early to allow other streams to write pending retransmissions if
    // any.
    return;
  }

  if (write_side_closed_) {
    QUIC_DLOG(ERROR)
        << ENDPOINT << "Stream " << id()
        << " attempting to write new data when the write side is closed";
    return;
  }
  if (HasBufferedData() || (fin_buffered_ && !fin_sent_)) {
    WriteBufferedData(session()->GetEncryptionLevelToSendApplicationData());
  }
  if (!fin_buffered_ && !fin_sent_ && CanWriteNewData()) {
    // Notify upper layer to write new data when buffered data size is below
    // low water mark.
    OnCanWriteNewData();
  }
}

void QuicStream::MaybeSendBlocked() {
  if (!flow_controller_.has_value()) {
    QUIC_BUG(quic_bug_10586_5)
        << ENDPOINT << "MaybeSendBlocked called on stream without flow control";
    return;
  }
  flow_controller_->MaybeSendBlocked();
  if (!stream_contributes_to_connection_flow_control_) {
    return;
  }
  connection_flow_controller_->MaybeSendBlocked();

  // If the stream is blocked by connection-level flow control but not by
  // stream-level flow control, add the stream to the write blocked list so that
  // the stream will be given a chance to write when a connection-level
  // WINDOW_UPDATE arrives.
  if (!write_side_closed_ && connection_flow_controller_->IsBlocked() &&
      !flow_controller_->IsBlocked()) {
    session_->MarkConnectionLevelWriteBlocked(id());
  }
}

QuicConsumedData QuicStream::WriteMemSlice(quiche::QuicheMemSlice span,
                                           bool fin) {
  return WriteMemSlices(absl::MakeSpan(&span, 1), fin);
}

QuicConsumedData QuicStream::WriteMemSlices(
    absl::Span<quiche::QuicheMemSlice> span, bool fin,
    bool buffer_unconditionally) {
  QuicConsumedData consumed_data(0, false);
  if (span.empty() && !fin) {
    QUIC_BUG(quic_bug_10586_6) << "span.empty() && !fin";
    return consumed_data;
  }

  if (fin_buffered_) {
    QUIC_BUG(quic_bug_10586_7) << "Fin already buffered";
    return consumed_data;
  }

  if (write_side_closed_) {
    QUIC_DLOG(ERROR) << ENDPOINT << "Stream " << id()
                     << " attempting to write when the write side is closed";
    if (type_ == READ_UNIDIRECTIONAL) {
      OnUnrecoverableError(QUIC_TRY_TO_WRITE_DATA_ON_READ_UNIDIRECTIONAL_STREAM,
                           "Try to send data on read unidirectional stream");
    }
    return consumed_data;
  }

  bool had_buffered_data = HasBufferedData();
  if (CanWriteNewData() || span.empty() || buffer_unconditionally) {
    consumed_data.fin_consumed = fin;
    if (!span.empty()) {
      // Buffer all data if buffered data size is below limit.
      QuicStreamOffset offset = send_buffer_.stream_offset();
      consumed_data.bytes_consumed = send_buffer_.SaveMemSliceSpan(span);
      if (offset > send_buffer_.stream_offset() ||
          kMaxStreamLength < send_buffer_.stream_offset()) {
        QUIC_BUG(quic_bug_10586_8) << "Write too many data via stream " << id_;
        OnUnrecoverableError(
            QUIC_STREAM_LENGTH_OVERFLOW,
            absl::StrCat("Write too many data via stream ", id_));
        return consumed_data;
      }
      OnDataBuffered(offset, consumed_data.bytes_consumed, nullptr);
    }
  }
  fin_buffered_ = consumed_data.fin_consumed;

  if (!had_buffered_data && (HasBufferedData() || fin_buffered_)) {
    // Write data if there is no buffered data before.
    WriteBufferedData(session()->GetEncryptionLevelToSendApplicationData());
  }

  return consumed_data;
}

bool QuicStream::HasPendingRetransmission() const {
  return send_buffer_.HasPendingRetransmission() || fin_lost_;
}

bool QuicStream::IsStreamFrameOutstanding(QuicStreamOffset offset,
                                          QuicByteCount data_length,
                                          bool fin) const {
  return send_buffer_.IsStreamDataOutstanding(offset, data_length) ||
         (fin && fin_outstanding_);
}

void QuicStream::CloseReadSide() {
  if (read_side_closed_) {
    return;
  }
  QUIC_DVLOG(1) << ENDPOINT << "Done reading from stream " << id();

  read_side_closed_ = true;
  sequencer_.ReleaseBuffer();

  if (write_side_closed_) {
    QUIC_DVLOG(1) << ENDPOINT << "Closing stream " << id();
    session_->OnStreamClosed(id());
    OnClose();
  }
}

void QuicStream::CloseWriteSide() {
  if (write_side_closed_) {
    return;
  }
  QUIC_DVLOG(1) << ENDPOINT << "Done writing to stream " << id();

  write_side_closed_ = true;
  if (read_side_closed_) {
    QUIC_DVLOG(1) << ENDPOINT << "Closing stream " << id();
    session_->OnStreamClosed(id());
    OnClose();
  }
}

void QuicStream::MaybeSendStopSending(QuicResetStreamError error) {
  if (stop_sending_sent_) {
    return;
  }

  if (!session()->version().UsesHttp3() && !error.ok()) {
    // In gQUIC, RST with error closes both read and write side.
    return;
  }

  if (session()->version().UsesHttp3()) {
    session()->MaybeSendStopS
```