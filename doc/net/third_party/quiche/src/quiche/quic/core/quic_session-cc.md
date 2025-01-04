Response:
The user wants to understand the functionality of the `quic_session.cc` file in Chromium's QUIC implementation. They are interested in:

1. **Functionality listing:** A summary of what the code does.
2. **JavaScript relationship:**  If and how this C++ code interacts with JavaScript.
3. **Logical reasoning:** Examples of input and output based on the code's logic.
4. **Common errors:**  Typical mistakes users or developers might make when interacting with this part of the system.
5. **Debugging path:** Steps a user might take that lead to this code being executed.
6. **Overall summary:** A concise recap of the file's purpose.

This is the first of four parts, so the focus should be on the functionality present in the provided code snippet.

**Plan:**

1. **Analyze the includes:** Identify the core QUIC components and general system functionalities this file depends on.
2. **Examine the class definition (`QuicSession`):**  List the member variables and their apparent purpose.
3. **Review the methods:**  Describe the key actions performed by each method, focusing on the provided code.
4. **Address each of the user's requests:**
    - Functionality: Based on the analysis, summarize the key responsibilities of `QuicSession`.
    - JavaScript: Determine if there's a direct connection. Likely indirect through the network stack.
    - Logic: Identify simple logical flows and provide examples.
    - Errors: Point out potential misuse based on method parameters or state.
    - Debugging: Describe common network-related actions that might involve QUIC.
    - Summary: Briefly recap the core function of the code.
这是 `net/third_party/quiche/src/quiche/quic/core/quic_session.cc` 文件的前一部分，它定义了 `QuicSession` 类。 `QuicSession` 是 QUIC 协议中会话管理的核心组件，负责管理一个 QUIC 连接的生命周期和状态。

**其主要功能包括：**

1. **连接管理:**
   - 持有并管理底层的 `QuicConnection` 对象，该对象负责实际的网络数据包的发送和接收。
   - 维护连接的视角 (`perspective_`)，区分客户端和服务端。
   - 跟踪连接的加密级别。
   - 处理连接关闭事件，并通知监听者。
   - 管理连接级别的流量控制 (`flow_controller_`)，限制发送数据的速率。
   - 处理版本协商成功事件。
   - 响应连接探测包。
   - 监测网络路径的质量变化。

2. **流管理:**
   - 管理会话中的 QUIC 流 (`QuicStream`)，用于双向或单向的数据传输。
   - 维护打开的流的映射 (`stream_map_`)。
   - 管理待处理的流 (`pending_stream_map_`)，用于处理在握手完成前到达的数据。
   - 跟踪流的状态，例如是否正在关闭或已关闭。
   - 管理流的创建和销毁。
   - 根据优先级管理流的写入阻塞状态 (`write_blocked_streams_`)。
   - 处理接收到的流帧数据 (`OnStreamFrame`)，将其传递给相应的流对象。
   - 处理接收到的流控制帧，如 `RST_STREAM` (重置流), `STOP_SENDING` (停止发送), `WINDOW_UPDATE` (窗口更新)。
   - 处理接收到的 `GOAWAY` 帧，表示对端不再接受新的流。

3. **控制帧管理:**
   - 管理需要发送的 QUIC 控制帧 (`control_frame_manager_`)。
   - 在合适的时间发送控制帧，例如确认帧、窗口更新帧等。

4. **加密管理:**
   - 持有并管理加密流 (`QuicCryptoStream`)，用于处理 QUIC 握手和密钥交换。
   - 处理接收到的加密帧 (`OnCryptoFrame`)。
   - 在数据包解密后通知加密流 (`OnPacketDecrypted`)。
   - 在 1-RTT 数据包被确认后通知加密流 (`OnOneRttPacketAcknowledged`)。
   - 在握手数据包发送后通知加密流 (`OnHandshakePacketSent`)。
   - 管理加密密钥的更新。
   - 处理接收到的 `HANDSHAKE_DONE` 和 `NEW_TOKEN` 帧。

5. **数据报管理:**
   - 管理用户层数据报的队列 (`datagram_queue_`)。

6. **错误处理和状态跟踪:**
   - 记录连接关闭的原因和来源。
   - 跟踪握手状态。
   - 标记 0-RTT 是否被拒绝。

7. **调试和监控:**
   - 提供日志记录功能。
   - 提供指标收集功能 (通过 `QuicServerStats`)。

**与 JavaScript 的关系：**

`quic_session.cc` 是 Chromium 网络栈的 C++ 代码，它本身不直接与 JavaScript 交互。但是，它的功能对于基于 Web 的应用程序至关重要，这些应用程序通常使用 JavaScript 进行开发。

**举例说明：**

假设一个用户在浏览器中打开一个使用了 QUIC 协议的网页。

1. **用户操作：** 用户在浏览器地址栏输入网址 `https://example.com` 并按下回车。
2. **网络请求：** 浏览器发起一个 HTTPS 请求。由于服务器支持 QUIC，浏览器可能会尝试建立 QUIC 连接。
3. **QUIC 连接建立：** Chromium 的网络栈会创建 `QuicSession` 对象来管理与服务器的 QUIC 连接。
4. **数据传输：** 当服务器响应用户的请求时，数据会通过 QUIC 流进行传输，`QuicSession` 会接收到 `QuicStreamFrame`。
5. **JavaScript 获取数据：**  接收到的数据最终会被传递到浏览器的渲染引擎，JavaScript 代码可以通过 DOM API 或 Fetch API 等方式访问这些数据并呈现给用户。

在这个过程中，`QuicSession` 负责底层的 QUIC 连接管理，而 JavaScript 负责处理和展示最终的应用层数据。JavaScript 不会直接调用 `QuicSession` 的方法，而是通过浏览器提供的更高层次的 API 与网络进行交互。

**逻辑推理（假设输入与输出）：**

假设客户端接收到一个 `WINDOW_UPDATE` 帧，其 `stream_id` 为 5，`max_data` 为 10000。

**假设输入：** 一个 `QuicWindowUpdateFrame` 对象，其 `stream_id` 为 5，`max_data` 为 10000。

**处理过程（在 `OnWindowUpdateFrame` 方法中）：**

- 代码会查找 `stream_map_` 中 `stream_id` 为 5 的 `QuicStream` 对象。
- 如果找到该流，则调用该流对象的 `OnWindowUpdateFrame` 方法，更新该流的发送窗口。

**可能输出：**

- 如果流 5 存在，则流 5 的发送窗口会被更新为 10000。这将允许客户端在该流上发送更多的数据。
- 如果流 5 不存在，并且 `stream_id` 不是连接级别的 ID，则该 `WINDOW_UPDATE` 帧可能会被忽略，或者在某些情况下，可能会触发连接错误。

**用户或编程常见的使用错误：**

1. **在流未创建前尝试发送数据：** 用户或上层代码可能会尝试在一个尚未创建或已经关闭的流上发送数据。`QuicSession` 会检查流的状态，并可能拒绝发送或触发错误。
   - **错误示例：** 在服务器端，如果客户端尝试向一个服务端尚未接受的客户端发起的流 ID 发送数据，`QuicSession` 会检测到这是一个无效的流 ID。
2. **流量控制窗口耗尽后仍然发送数据：** 用户或上层代码可能没有正确处理流量控制，导致在发送窗口耗尽后仍然尝试发送数据。这会导致数据被阻塞，直到接收到窗口更新帧。
   - **错误示例：**  如果一个流的发送窗口很小，并且应用程序尝试发送大量数据，`QuicSession` 会将该流标记为写入阻塞，并在 `OnCanWrite` 时尝试发送。
3. **错误地管理流的生命周期：**  开发者可能会错误地提前关闭流，或者忘记在不再需要时关闭流，导致资源泄漏或数据传输中断。
   - **错误示例：** 在接收到 FIN 帧后，如果上层代码没有及时清理和关闭对应的流，`QuicSession` 可能会继续持有该流的资源。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户发起网络请求：** 用户在浏览器中访问一个使用了 QUIC 协议的网站。
2. **QUIC 连接建立：** 浏览器（客户端）或服务器的网络栈会创建 `QuicSession` 对象来管理连接。
3. **数据传输或控制信息交互：**
   - **发送数据：** 用户执行某些操作导致浏览器需要向服务器发送数据（例如，提交表单）。这会涉及到 `QuicSession` 管理流的写入操作。
   - **接收数据：** 服务器响应用户请求，浏览器接收到来自服务器的数据包，这些数据包会被传递给 `QuicSession` 的 `OnStreamFrame` 或 `OnCryptoFrame` 等方法进行处理。
   - **流控制：** 服务器或客户端可能会发送 `WINDOW_UPDATE` 帧来更新对方的发送窗口，这会触发 `QuicSession` 的 `OnWindowUpdateFrame` 方法。
   - **流的创建和关闭：**  当需要新的数据传输通道时，会创建新的 QUIC 流。当数据传输完成后，流会被关闭。这些操作都会涉及到 `QuicSession` 的流管理功能。
   - **连接关闭：** 当连接需要关闭时（例如，正常关闭或发生错误），`QuicSession` 的 `OnConnectionClosed` 方法会被调用。

**作为调试线索：** 如果在调试网络问题时，你发现连接建立失败、数据传输中断、流量控制异常等问题，那么 `quic_session.cc` 中的代码可能是需要重点关注的地方。你可以通过设置断点、查看日志等方式来跟踪 `QuicSession` 的状态和方法调用，从而定位问题的原因。例如，你可以观察流的创建和关闭时机，流量控制窗口的变化，以及错误码等信息。

**功能归纳 (第 1 部分)：**

在这部分代码中，`QuicSession` 的主要功能是 **管理 QUIC 连接的生命周期和状态，并处理底层的网络数据包和控制帧。** 它负责协调 `QuicConnection` 和 `QuicStream` 等其他 QUIC 组件，维护连接和流的状态，并处理与连接建立、数据传输和流控制相关的事件。这部分代码主要关注连接和流的基础管理，以及接收到数据帧和控制帧的处理。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/core/quic_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_session.h"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/frames/quic_ack_frequency_frame.h"
#include "quiche/quic/core/frames/quic_reset_stream_at_frame.h"
#include "quiche/quic/core/frames/quic_window_update_frame.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_connection_context.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_flow_controller.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_stream_priority.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/core/quic_write_blocked_list.h"
#include "quiche/quic/core/web_transport_write_blocked_list.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_flag_utils.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_server_stats.h"
#include "quiche/quic/platform/api/quic_stack_trace.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/quiche_text_utils.h"

namespace quic {

namespace {

class ClosedStreamsCleanUpDelegate : public QuicAlarm::Delegate {
 public:
  explicit ClosedStreamsCleanUpDelegate(QuicSession* session)
      : session_(session) {}
  ClosedStreamsCleanUpDelegate(const ClosedStreamsCleanUpDelegate&) = delete;
  ClosedStreamsCleanUpDelegate& operator=(const ClosedStreamsCleanUpDelegate&) =
      delete;

  QuicConnectionContext* GetConnectionContext() override {
    return (session_->connection() == nullptr)
               ? nullptr
               : session_->connection()->context();
  }

  void OnAlarm() override { session_->CleanUpClosedStreams(); }

 private:
  QuicSession* session_;
};

class StreamCountResetAlarmDelegate : public QuicAlarm::Delegate {
 public:
  explicit StreamCountResetAlarmDelegate(QuicSession* session)
      : session_(session) {}
  StreamCountResetAlarmDelegate(const StreamCountResetAlarmDelegate&) = delete;
  StreamCountResetAlarmDelegate& operator=(
      const StreamCountResetAlarmDelegate&) = delete;

  QuicConnectionContext* GetConnectionContext() override {
    return (session_->connection() == nullptr)
               ? nullptr
               : session_->connection()->context();
  }

  void OnAlarm() override { session_->OnStreamCountReset(); }

 private:
  QuicSession* session_;
};

std::unique_ptr<QuicWriteBlockedListInterface> CreateWriteBlockedList(
    QuicPriorityType priority_type) {
  switch (priority_type) {
    case QuicPriorityType::kHttp:
      return std::make_unique<QuicWriteBlockedList>();
    case QuicPriorityType::kWebTransport:
      return std::make_unique<WebTransportWriteBlockedList>();
  }
  QUICHE_NOTREACHED();
  return nullptr;
}

}  // namespace

#define ENDPOINT \
  (perspective() == Perspective::IS_SERVER ? "Server: " : "Client: ")

QuicSession::QuicSession(
    QuicConnection* connection, Visitor* owner, const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicStreamCount num_expected_unidirectional_static_streams)
    : QuicSession(connection, owner, config, supported_versions,
                  num_expected_unidirectional_static_streams, nullptr) {}

QuicSession::QuicSession(
    QuicConnection* connection, Visitor* owner, const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicStreamCount num_expected_unidirectional_static_streams,
    std::unique_ptr<QuicDatagramQueue::Observer> datagram_observer,
    QuicPriorityType priority_type)
    : connection_(connection),
      perspective_(connection->perspective()),
      visitor_(owner),
      write_blocked_streams_(CreateWriteBlockedList(priority_type)),
      config_(config),
      stream_id_manager_(perspective(), connection->transport_version(),
                         kDefaultMaxStreamsPerConnection,
                         config_.GetMaxBidirectionalStreamsToSend()),
      ietf_streamid_manager_(perspective(), connection->version(), this, 0,
                             num_expected_unidirectional_static_streams,
                             config_.GetMaxBidirectionalStreamsToSend(),
                             config_.GetMaxUnidirectionalStreamsToSend() +
                                 num_expected_unidirectional_static_streams),
      num_draining_streams_(0),
      num_outgoing_draining_streams_(0),
      num_static_streams_(0),
      num_zombie_streams_(0),
      flow_controller_(
          this, QuicUtils::GetInvalidStreamId(connection->transport_version()),
          /*is_connection_flow_controller*/ true,
          connection->version().AllowsLowFlowControlLimits()
              ? 0
              : kMinimumFlowControlSendWindow,
          config_.GetInitialSessionFlowControlWindowToSend(),
          kSessionReceiveWindowLimit, perspective() == Perspective::IS_SERVER,
          nullptr),
      currently_writing_stream_id_(0),
      transport_goaway_sent_(false),
      transport_goaway_received_(false),
      control_frame_manager_(this),
      last_message_id_(0),
      datagram_queue_(this, std::move(datagram_observer)),
      closed_streams_clean_up_alarm_(nullptr),
      supported_versions_(supported_versions),
      is_configured_(false),
      was_zero_rtt_rejected_(false),
      liveness_testing_in_progress_(false),
      stream_count_reset_alarm_(
          absl::WrapUnique<QuicAlarm>(connection->alarm_factory()->CreateAlarm(
              new StreamCountResetAlarmDelegate(this)))),
      priority_type_(priority_type) {
  closed_streams_clean_up_alarm_ =
      absl::WrapUnique<QuicAlarm>(connection_->alarm_factory()->CreateAlarm(
          new ClosedStreamsCleanUpDelegate(this)));
  if (VersionHasIetfQuicFrames(transport_version())) {
    config_.SetMaxUnidirectionalStreamsToSend(
        config_.GetMaxUnidirectionalStreamsToSend() +
        num_expected_unidirectional_static_streams);
  }
}

void QuicSession::Initialize() {
  connection_->set_visitor(this);
  connection_->SetSessionNotifier(this);
  connection_->SetDataProducer(this);
  connection_->SetUnackedMapInitialCapacity();
  if (perspective_ == Perspective::IS_CLIENT) {
    if (config_.HasClientSentConnectionOption(kCHP1, perspective_)) {
      config_.SetDiscardLengthToSend(kDefaultMaxPacketSize);
    } else if (config_.HasClientSentConnectionOption(kCHP2, perspective_)) {
      config_.SetDiscardLengthToSend(kDefaultMaxPacketSize * 2);
    }
  }
  connection_->SetFromConfig(config_);
  if (perspective_ == Perspective::IS_CLIENT) {
    if (config_.HasClientRequestedIndependentOption(kAFFE, perspective_) &&
        version().HasIetfQuicFrames()) {
      connection_->set_can_receive_ack_frequency_frame();
      config_.SetMinAckDelayMs(kDefaultMinAckDelayTimeMs);
    }
  }
  if (perspective() == Perspective::IS_SERVER &&
      connection_->version().handshake_protocol == PROTOCOL_TLS1_3) {
    config_.SetStatelessResetTokenToSend(GetStatelessResetToken());
  }

  connection_->CreateConnectionIdManager();

  // On the server side, version negotiation has been done by the dispatcher,
  // and the server session is created with the right version.
  if (perspective() == Perspective::IS_SERVER) {
    connection_->OnSuccessfulVersionNegotiation();
  }

  if (QuicVersionUsesCryptoFrames(transport_version())) {
    return;
  }

  QUICHE_DCHECK_EQ(QuicUtils::GetCryptoStreamId(transport_version()),
                   GetMutableCryptoStream()->id());
}

QuicSession::~QuicSession() {
  if (closed_streams_clean_up_alarm_ != nullptr) {
    closed_streams_clean_up_alarm_->PermanentCancel();
  }
  if (stream_count_reset_alarm_ != nullptr) {
    stream_count_reset_alarm_->PermanentCancel();
  }
}

PendingStream* QuicSession::PendingStreamOnStreamFrame(
    const QuicStreamFrame& frame) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));
  QuicStreamId stream_id = frame.stream_id;

  PendingStream* pending = GetOrCreatePendingStream(stream_id);

  if (!pending) {
    if (frame.fin) {
      QuicStreamOffset final_byte_offset = frame.offset + frame.data_length;
      OnFinalByteOffsetReceived(stream_id, final_byte_offset);
    }
    return nullptr;
  }

  pending->OnStreamFrame(frame);
  if (!connection()->connected()) {
    return nullptr;
  }
  return pending;
}

bool QuicSession::MaybeProcessPendingStream(PendingStream* pending) {
  QUICHE_DCHECK(pending != nullptr && connection()->connected());

  if (ExceedsPerLoopStreamLimit()) {
    QUIC_DLOG(INFO) << "Skip processing pending stream " << pending->id()
                    << " because it exceeds per loop limit.";
    QUIC_CODE_COUNT_N(quic_pending_stream, 1, 3);
    return false;
  }

  QuicStreamId stream_id = pending->id();
  std::optional<QuicResetStreamError> stop_sending_error_code =
      pending->GetStopSendingErrorCode();
  QUIC_DLOG(INFO) << "Process pending stream " << pending->id();
  QuicStream* stream = ProcessPendingStream(pending);
  if (stream != nullptr) {
    // The pending stream should now be in the scope of normal streams.
    QUICHE_DCHECK(IsClosedStream(stream_id) || IsOpenStream(stream_id))
        << "Stream " << stream_id << " not created";
    if (!stream->pending_duration().IsZero()) {
      QUIC_SERVER_HISTOGRAM_TIMES("QuicStream.PendingDurationUs",
                                  stream->pending_duration().ToMicroseconds(),
                                  0, 1000 * 100, 20,
                                  "Time a stream has been pending at server.");
      ++connection()->mutable_stats().num_total_pending_streams;
    }
    pending_stream_map_.erase(stream_id);
    if (stop_sending_error_code) {
      stream->OnStopSending(*stop_sending_error_code);
      if (!connection()->connected()) {
        return false;
      }
    }
    stream->OnStreamCreatedFromPendingStream();
    return connection()->connected();
  }
  // At this point, none of the bytes has been successfully consumed by the
  // application layer. We should close the pending stream even if it is
  // bidirectionl as no application will be able to write in a bidirectional
  // stream with zero byte as input.
  if (pending->sequencer()->IsClosed()) {
    ClosePendingStream(stream_id);
  }
  return connection()->connected();
}

void QuicSession::PendingStreamOnWindowUpdateFrame(
    const QuicWindowUpdateFrame& frame) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));
  PendingStream* pending = GetOrCreatePendingStream(frame.stream_id);
  if (pending) {
    pending->OnWindowUpdateFrame(frame);
  }
}

void QuicSession::PendingStreamOnStopSendingFrame(
    const QuicStopSendingFrame& frame) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));
  PendingStream* pending = GetOrCreatePendingStream(frame.stream_id);
  if (pending) {
    pending->OnStopSending(frame.error());
  }
}

void QuicSession::OnStreamFrame(const QuicStreamFrame& frame) {
  QuicStreamId stream_id = frame.stream_id;
  if (stream_id == QuicUtils::GetInvalidStreamId(transport_version())) {
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Received data for an invalid stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  if (ShouldProcessFrameByPendingStream(STREAM_FRAME, stream_id)) {
    PendingStream* pending = PendingStreamOnStreamFrame(frame);
    if (pending != nullptr && IsEncryptionEstablished()) {
      MaybeProcessPendingStream(pending);
    }
    return;
  }

  QuicStream* stream = GetOrCreateStream(stream_id);

  if (!stream) {
    // The stream no longer exists, but we may still be interested in the
    // final stream byte offset sent by the peer. A frame with a FIN can give
    // us this offset.
    if (frame.fin) {
      QuicStreamOffset final_byte_offset = frame.offset + frame.data_length;
      OnFinalByteOffsetReceived(stream_id, final_byte_offset);
    }
    return;
  }
  stream->OnStreamFrame(frame);
}

void QuicSession::OnCryptoFrame(const QuicCryptoFrame& frame) {
  GetMutableCryptoStream()->OnCryptoFrame(frame);
}

void QuicSession::OnStopSendingFrame(const QuicStopSendingFrame& frame) {
  // STOP_SENDING is in IETF QUIC only.
  QUICHE_DCHECK(VersionHasIetfQuicFrames(transport_version()));
  QUICHE_DCHECK(QuicVersionUsesCryptoFrames(transport_version()));

  QuicStreamId stream_id = frame.stream_id;
  // If Stream ID is invalid then close the connection.
  // TODO(ianswett): This check is redundant to checks for IsClosedStream,
  // but removing it requires removing multiple QUICHE_DCHECKs.
  // TODO(ianswett): Multiple QUIC_DVLOGs could be QUIC_PEER_BUGs.
  if (stream_id == QuicUtils::GetInvalidStreamId(transport_version())) {
    QUIC_DVLOG(1) << ENDPOINT
                  << "Received STOP_SENDING with invalid stream_id: "
                  << stream_id << " Closing connection";
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Received STOP_SENDING for an invalid stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  // If stream_id is READ_UNIDIRECTIONAL, close the connection.
  if (QuicUtils::GetStreamType(stream_id, perspective(),
                               IsIncomingStream(stream_id),
                               version()) == READ_UNIDIRECTIONAL) {
    QUIC_DVLOG(1) << ENDPOINT
                  << "Received STOP_SENDING for a read-only stream_id: "
                  << stream_id << ".";
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Received STOP_SENDING for a read-only stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  if (visitor_) {
    visitor_->OnStopSendingReceived(frame);
  }
  if (ShouldProcessFrameByPendingStream(STOP_SENDING_FRAME, stream_id)) {
    PendingStreamOnStopSendingFrame(frame);
    return;
  }

  QuicStream* stream = nullptr;
  if (enable_stop_sending_for_zombie_streams_) {
    stream = GetStream(stream_id);
    if (stream != nullptr) {
      if (stream->IsZombie()) {
        QUIC_RELOADABLE_FLAG_COUNT_N(
            quic_deliver_stop_sending_to_zombie_streams, 1, 3);
      } else {
        QUIC_RELOADABLE_FLAG_COUNT_N(
            quic_deliver_stop_sending_to_zombie_streams, 2, 3);
      }
      stream->OnStopSending(frame.error());
      return;
    }
  }
  stream = GetOrCreateStream(stream_id);
  if (!stream) {
    // Errors are handled by GetOrCreateStream.
    return;
  }

  stream->OnStopSending(frame.error());
}

void QuicSession::OnPacketDecrypted(EncryptionLevel level) {
  GetMutableCryptoStream()->OnPacketDecrypted(level);
  if (liveness_testing_in_progress_) {
    liveness_testing_in_progress_ = false;
    OnCanCreateNewOutgoingStream(/*unidirectional=*/false);
  }
}

void QuicSession::OnOneRttPacketAcknowledged() {
  GetMutableCryptoStream()->OnOneRttPacketAcknowledged();
}

void QuicSession::OnHandshakePacketSent() {
  GetMutableCryptoStream()->OnHandshakePacketSent();
}

std::unique_ptr<QuicDecrypter>
QuicSession::AdvanceKeysAndCreateCurrentOneRttDecrypter() {
  return GetMutableCryptoStream()->AdvanceKeysAndCreateCurrentOneRttDecrypter();
}

std::unique_ptr<QuicEncrypter> QuicSession::CreateCurrentOneRttEncrypter() {
  return GetMutableCryptoStream()->CreateCurrentOneRttEncrypter();
}

void QuicSession::PendingStreamOnRstStream(const QuicRstStreamFrame& frame) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));
  QuicStreamId stream_id = frame.stream_id;

  PendingStream* pending = GetOrCreatePendingStream(stream_id);

  if (!pending) {
    HandleRstOnValidNonexistentStream(frame);
    return;
  }

  pending->OnRstStreamFrame(frame);
  // At this point, none of the bytes has been consumed by the application
  // layer. It is safe to close the pending stream even if it is bidirectionl as
  // no application will be able to write in a bidirectional stream with zero
  // byte as input.
  ClosePendingStream(stream_id);
}

void QuicSession::PendingStreamOnResetStreamAt(
    const QuicResetStreamAtFrame& frame) {
  QUICHE_DCHECK(VersionUsesHttp3(transport_version()));
  QuicStreamId stream_id = frame.stream_id;

  PendingStream* pending = GetOrCreatePendingStream(stream_id);

  if (!pending) {
    HandleRstOnValidNonexistentStream(frame.ToRstStream());
    return;
  }

  pending->OnResetStreamAtFrame(frame);
}

void QuicSession::OnRstStream(const QuicRstStreamFrame& frame) {
  QuicStreamId stream_id = frame.stream_id;
  if (stream_id == QuicUtils::GetInvalidStreamId(transport_version())) {
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Received data for an invalid stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  if (VersionHasIetfQuicFrames(transport_version()) &&
      QuicUtils::GetStreamType(stream_id, perspective(),
                               IsIncomingStream(stream_id),
                               version()) == WRITE_UNIDIRECTIONAL) {
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Received RESET_STREAM for a write-only stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  if (visitor_) {
    visitor_->OnRstStreamReceived(frame);
  }

  if (ShouldProcessFrameByPendingStream(RST_STREAM_FRAME, stream_id)) {
    PendingStreamOnRstStream(frame);
    return;
  }

  QuicStream* stream = GetOrCreateStream(stream_id);

  if (!stream) {
    HandleRstOnValidNonexistentStream(frame);
    return;  // Errors are handled by GetOrCreateStream.
  }
  stream->OnStreamReset(frame);
}

void QuicSession::OnResetStreamAt(const QuicResetStreamAtFrame& frame) {
  QUICHE_DCHECK(VersionHasIetfQuicFrames(transport_version()));
  QuicStreamId stream_id = frame.stream_id;
  if (stream_id == QuicUtils::GetInvalidStreamId(transport_version())) {
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Received data for an invalid stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  if (VersionHasIetfQuicFrames(transport_version()) &&
      QuicUtils::GetStreamType(stream_id, perspective(),
                               IsIncomingStream(stream_id),
                               version()) == WRITE_UNIDIRECTIONAL) {
    connection()->CloseConnection(
        QUIC_INVALID_STREAM_ID, "Received RESET_STREAM for a write-only stream",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  if (ShouldProcessFrameByPendingStream(RESET_STREAM_AT_FRAME, stream_id)) {
    PendingStreamOnResetStreamAt(frame);
    return;
  }

  QuicStream* stream = GetOrCreateStream(stream_id);

  if (!stream) {
    HandleRstOnValidNonexistentStream(frame.ToRstStream());
    return;  // Errors are handled by GetOrCreateStream.
  }
  stream->OnResetStreamAtFrame(frame);
}

void QuicSession::OnGoAway(const QuicGoAwayFrame& /*frame*/) {
  QUIC_BUG_IF(quic_bug_12435_1, version().UsesHttp3())
      << "gQUIC GOAWAY received on version " << version();

  transport_goaway_received_ = true;
}

void QuicSession::OnMessageReceived(absl::string_view message) {
  QUIC_DVLOG(1) << ENDPOINT << "Received message of length "
                << message.length();
  QUIC_DVLOG(2) << ENDPOINT << "Contents of message of length "
                << message.length() << ":" << std::endl
                << quiche::QuicheTextUtils::HexDump(message);
}

void QuicSession::OnHandshakeDoneReceived() {
  QUIC_DVLOG(1) << ENDPOINT << "OnHandshakeDoneReceived";
  GetMutableCryptoStream()->OnHandshakeDoneReceived();
}

void QuicSession::OnNewTokenReceived(absl::string_view token) {
  QUICHE_DCHECK_EQ(perspective_, Perspective::IS_CLIENT);
  GetMutableCryptoStream()->OnNewTokenReceived(token);
}

// static
void QuicSession::RecordConnectionCloseAtServer(QuicErrorCode error,
                                                ConnectionCloseSource source) {
  if (error != QUIC_NO_ERROR) {
    if (source == ConnectionCloseSource::FROM_SELF) {
      QUIC_SERVER_HISTOGRAM_ENUM(
          "quic_server_connection_close_errors", error, QUIC_LAST_ERROR,
          "QuicErrorCode for server-closed connections.");
    } else {
      QUIC_SERVER_HISTOGRAM_ENUM(
          "quic_client_connection_close_errors", error, QUIC_LAST_ERROR,
          "QuicErrorCode for client-closed connections.");
    }
  }
}

void QuicSession::OnConnectionClosed(const QuicConnectionCloseFrame& frame,
                                     ConnectionCloseSource source) {
  QUICHE_DCHECK(!connection_->connected());
  if (perspective() == Perspective::IS_SERVER) {
    RecordConnectionCloseAtServer(frame.quic_error_code, source);
  }

  if (on_closed_frame_.quic_error_code == QUIC_NO_ERROR) {
    // Save all of the connection close information
    on_closed_frame_ = frame;
    source_ = source;
  }

  GetMutableCryptoStream()->OnConnectionClosed(frame, source);

  PerformActionOnActiveStreams([this, frame, source](QuicStream* stream) {
    QuicStreamId id = stream->id();
    stream->OnConnectionClosed(frame, source);
    auto it = stream_map_.find(id);
    if (it != stream_map_.end()) {
      QUIC_BUG_IF(quic_bug_12435_2, !it->second->IsZombie())
          << ENDPOINT << "Non-zombie stream " << id
          << " failed to close under OnConnectionClosed";
    }
    return true;
  });

  closed_streams_clean_up_alarm_->Cancel();
  stream_count_reset_alarm_->Cancel();

  if (visitor_) {
    visitor_->OnConnectionClosed(connection_->GetOneActiveServerConnectionId(),
                                 frame.quic_error_code, frame.error_details,
                                 source);
  }
}

void QuicSession::OnWriteBlocked() {
  if (!connection_->connected()) {
    return;
  }
  if (visitor_) {
    visitor_->OnWriteBlocked(connection_);
  }
}

void QuicSession::OnSuccessfulVersionNegotiation(
    const ParsedQuicVersion& /*version*/) {}

void QuicSession::OnPacketReceived(const QuicSocketAddress& /*self_address*/,
                                   const QuicSocketAddress& peer_address,
                                   bool is_connectivity_probe) {
  QUICHE_DCHECK(!connection_->ignore_gquic_probing());
  if (is_connectivity_probe && perspective() == Perspective::IS_SERVER) {
    // Server only sends back a connectivity probe after received a
    // connectivity probe from a new peer address.
    connection_->SendConnectivityProbingPacket(nullptr, peer_address);
  }
}

void QuicSession::OnPathDegrading() {
  if (visitor_) {
    visitor_->OnPathDegrading();
  }
}

void QuicSession::OnForwardProgressMadeAfterPathDegrading() {}

void QuicSession::OnForwardProgressMadeAfterFlowLabelChange() {}

bool QuicSession::AllowSelfAddressChange() const { return false; }

void QuicSession::OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) {
  // Stream may be closed by the time we receive a WINDOW_UPDATE, so we can't
  // assume that it still exists.
  QuicStreamId stream_id = frame.stream_id;
  if (stream_id == QuicUtils::GetInvalidStreamId(transport_version())) {
    // This is a window update that applies to the connection, rather than an
    // individual stream.
    QUIC_DVLOG(1) << ENDPOINT
                  << "Received connection level flow control window "
                     "update with max data: "
                  << frame.max_data;
    flow_controller_.UpdateSendWindowOffset(frame.max_data);
    return;
  }

  if (VersionHasIetfQuicFrames(transport_version()) &&
      QuicUtils::GetStreamType(stream_id, perspective(),
                               IsIncomingStream(stream_id),
                               version()) == READ_UNIDIRECTIONAL) {
    connection()->CloseConnection(
        QUIC_WINDOW_UPDATE_RECEIVED_ON_READ_UNIDIRECTIONAL_STREAM,
        "WindowUpdateFrame received on READ_UNIDIRECTIONAL stream.",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  if (ShouldProcessFrameByPendingStream(WINDOW_UPDATE_FRAME, stream_id)) {
    PendingStreamOnWindowUpdateFrame(frame);
    return;
  }

  QuicStream* stream = GetOrCreateStream(stream_id);
  if (stream != nullptr) {
    stream->OnWindowUpdateFrame(frame);
  }
}

void QuicSession::OnBlockedFrame(const QuicBlockedFrame& frame) {
  // TODO(rjshade): Compare our flow control receive windows for specified
  //                streams: if we have a large window then maybe something
  //                had gone wrong with the flow control accounting.
  QUIC_DLOG(INFO) << ENDPOINT << "Received BLOCKED frame with stream id: "
                  << frame.stream_id << ", offset: " << frame.offset;
}

bool QuicSession::CheckStreamNotBusyLooping(QuicStream* stream,
                                            uint64_t previous_bytes_written,
                                            bool previous_fin_sent) {
  if (  // Stream should not be closed.
      !stream->write_side_closed() &&
      // Not connection flow control blocked.
      !flow_controller_.IsBlocked() &&
      // Detect lack of forward progress.
      previous_bytes_written == stream->stream_bytes_written() &&
      previous_fin_sent == stream->fin_sent()) {
    stream->set_busy_counter(stream->busy_counter() + 1);
    QUIC_DVLOG(1) << ENDPOINT << "Suspected busy loop on stream id "
                  << stream->id() << " stream_bytes_written "
                  << stream->stream_bytes_written() << " fin "
                  << stream->fin_sent() << " count " << stream->busy_counter();
    // Wait a few iterations before firing, the exact count is
    // arbitrary, more than a few to cover a few test-only false
    // positives.
    if (stream->busy_counter() > 20) {
      QUIC_LOG(ERROR) << ENDPOINT << "Detected busy loop on stream id "
                      << stream->id() << " stream_bytes_written "
                      << stream->stream_bytes_written() << " fin "
                      << stream->fin_sent();
      return false;
    }
  } else {
    stream->set_busy_counter(0);
  }
  return true;
}

bool QuicSession::CheckStreamWriteBlocked(QuicStream* stream) const {
  if (!stream->write_side_closed() && stream->HasBufferedData() &&
      !stream->IsFlowControlBlocked() &&
      !write_blocked_streams_->IsStreamBlocked(stream->id())) {
    QUIC_DLOG(ERROR) << ENDPOINT << "stream " << stream->id()
                     << " has buffered " << stream->BufferedDataBytes()
                     << " bytes, and is not flow control blocked, "
                        "but it is not in the write block list.";
    return false;
  }
  return true;
}

void QuicSession::OnCanWrite() {
  if (connection_->framer().is_processing_packet()) {
    // Do not write data in the middle of packet processing because rest
    // frames in the packet may change the data to write. For example, lost
    // data could be acknowledged. Also, connection is going to emit
    // OnCanWrite signal post packet processing.
    QUIC_BUG(session_write_mid_packet_processing)
        << ENDPOINT << "Try to write mid packet processing.";
    return;
  }
  if (!RetransmitLostData()) {
    // Cannot finish retransmitting lost data, connection is write blocked.
    QUIC_DVLOG(1) << ENDPOINT
                  << "Cannot finish retransmitting lost data, connection is "
                     "write blocked.";
    return;
  }
  // We limit the number of writes to the number of pending streams. If more
  // streams become pending, WillingAndAbleToWrite will be true, which will
  // cause the connection to request resumption before yielding to other
  // connections.
  // If we are connection level flow control blocked, then only allow the
  // crypto and headers streams to try writing as all other streams will be
  // blocked.
  size_t num_writes = flow_controller_.IsBlocked()
                          ? write_blocked_streams_->NumBlockedSpecialStreams()
                          : write_blocked_streams_->NumBlockedStreams();
  if (num_writes == 0 && !control_frame_manager_.WillingToWrite() &&
      datagram_queue_.empty() &&
      (!QuicVersionUsesCryptoFrames(transport_version()) ||
       !GetCryptoStream()->HasBufferedCryptoFrames())) {
    return;
  }

  QuicConnection::ScopedPacketFlusher flusher(connection_);
  if (QuicVersionUsesCryptoFrames(transport_version())) {
    QuicCryptoStream* crypto_stream = GetMutableCryptoStream();
    if (crypto_stream->HasBufferedCryptoFrames()) {
      crypto_stream->WriteBufferedCryptoFrames();
    }
    if ((GetQuicReloadableFlag(
             quic_no_write_control_frame_upon_connection_close) &&
         !connection_->connected()) ||
        crypto_stream->HasBufferedCryptoFrames()) {
      if (!connection_->connected()) {
        QUIC_RELOADABLE_FLAG_COUNT(
            quic_no_write_control_frame_upon_connection_close);
      }
      // Cannot finish writing buffered crypto frames, connection is either
      // write blocked or closed.
      return;
    }
  }
  if (control_frame_manager_.WillingToWrite()) {
    control_frame_manager_.OnCanWrite();
  }
  if (version().UsesTls() && GetHandshakeState() != HANDSHAKE_CONFIRMED &&
      connection_->in_probe_time_out()) {
    QUIC_CODE_COUNT(quic_donot_pto_stream_data_before_handshake_confirmed);
    // Do not PTO stream data before handshake gets confirmed.
    return;
  }
  // TODO(b/147146815): this makes all datagrams go before stream data.  We
  // should have a better priority scheme for this.
  if (!datagram_queue_.empty()) {
    size_t written = datagram_queue_.SendDatagrams();
    QUIC_DVLOG(1) << ENDPOINT << "Sent " << written << " datagrams";
    if (!datagram_queue_.empty()) {
      return;
    }
  }
  std::vector<QuicStreamId> last_writing_stream_ids;
  for (size_t i = 0; i < num_writes; ++i) {
    if (!(write_blocked_streams_->HasWriteBlockedSpecialStream() ||
          write_blocked_streams_->HasWriteBlockedDataStreams())) {
      // Writing one stream removed another!? Something's broken.
      QUIC_BUG(quic_bug_10866_1)
          << "WriteBlockedStream is missing, num_writes: " << num_writes
          << ", finished_writes: " << i
          << ", connected: " << connection_->connected()
          << ", connection level flow control blocked: "
          << flow_controller_.IsBlocked();
      for (QuicStreamId id : last_writing_stream_ids) {
        QUIC_LOG(WARNING) << "last_writing_stream_id: " << id;
      }
      connection_->CloseConnection(QUIC_INTERNAL_ERROR,
                                   "WriteBlockedStream is missing",
                                   ConnectionCloseBehavior::SILENT_CLOSE);
      return;
    }
    if (!CanWriteStreamData()) {
      return;
    }
    currently_writing_stream_id_ = write_blocked_streams_->PopFront();
    last_writing_stream_ids.push_back(currently_writing_stream_id_);
    QUIC_DVLOG(1) << ENDPOINT << "Removing stream "
                  << currently_writing_stream_id_ << " from write-blocked list";
    QuicStream* stream = GetOrCreateStream(currently_writing_stream_id_);
    if (stream != nullptr && !stream->IsFlowControlBlocked()) {
      // If the stream can't write all bytes it'll re-add itself to the blocked
      // list.
      uint64_t previous_bytes_written = stream->stream_bytes_written();
      bool previous_fin_sent = stream->fin_sent();
      QUIC_DVLOG(1) << ENDPOINT << "stream " << stream->id()
                    << " bytes_written " << previous_bytes_written << " fin "
                    << previous_fin_sent;
      stream->OnCanWrite();
      QUICHE_DCHECK(CheckStreamWriteBlocked(stream));
      QUICHE_DCHECK(CheckStreamNotBusyLooping(stream, previous_bytes_written,
                                              previous_fin_sent));
    }
    currently_writing_stream_id_ = 0;
  }
}

bool QuicSession::WillingAndAbleToWrite() const {
  // Schedule a write when:
  // 1) control frame manager has pending or new control frames, or
  // 2) any stream has pending retransmissions, or
  // 3) If the crypto or headers streams are blocked, or
  // 4) connection is not flow control blocked and there are write blocked
  // streams.
  if (QuicVersionUsesCryptoFrames(transport_version())) {
    if (HasPendingHandshake()) {
      return true;
    }
    if (!IsEncryptionEstablished()) {
      return false;
    }
  }
  if (control_frame_manager_.WillingToWrite() ||
      !streams_with_pen
"""


```