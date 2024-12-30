Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a larger file (`moqt_session.cc`) in the Chromium network stack. This is the second part of the file. I need to analyze the code and extract the key functionalities, especially focusing on:

1. **Message Handling:** How it processes different MoQT control and data messages.
2. **Subscription Management:** How it handles subscriptions to media tracks.
3. **Data Streaming:** How it manages the sending of media objects over data streams.
4. **Error Handling:** How it detects and handles protocol violations and other errors.
5. **Relationship to JavaScript:** Whether any of the functionalities directly relate to JavaScript (likely through APIs exposed to the browser).
6. **Logical Inferences:**  Identify any logical steps and provide example inputs and outputs.
7. **Common Usage Errors:** Point out potential errors developers might make when using this code.
8. **Debugging Context:** Explain how a user action might lead to this code being executed.

**Part 2 Focus:** Based on the provided code, this part primarily deals with:

*   Handling of `ANNOUNCE`, `ANNOUNCE_OK`, `ANNOUNCE_ERROR`, `ANNOUNCE_CANCEL`, and `MAX_SUBSCRIBE_ID` control messages.
*   The `IncomingDataStream` class, responsible for receiving and processing data objects.
*   The `PublishedSubscription` class, which manages the server-side state of a subscription.
*   The `OutgoingDataStream` class, which manages sending media objects over a WebTransport stream.

I will structure the summary to cover these aspects and synthesize a high-level overview of the file's role.
这是`net/third_party/quiche/src/quiche/quic/moqt/moqt_session.cc`文件的第二部分，主要集中在以下功能：

**核心功能归纳:**

*   **处理来自对端的 MoQT 控制消息:**  这部分代码定义了 `MoqtSession::ControlStream` 类中处理各种接收到的 MoQT 控制消息的逻辑，例如 `ANNOUNCE` (发布声明), `ANNOUNCE_OK` (发布声明确认), `ANNOUNCE_ERROR` (发布声明错误), `ANNOUNCE_CANCEL` (取消发布声明) 和 `MAX_SUBSCRIBE_ID` (最大订阅 ID)。
*   **管理接收到的数据流:**  `MoqtSession::IncomingDataStream` 类负责处理接收到的媒体数据流，包括解析 `OBJECT` 消息，处理部分对象，以及将数据转发给订阅者。
*   **维护已发布的订阅:** `MoqtSession::PublishedSubscription` 类管理服务端维护的每个发布者的订阅状态，包括订阅 ID、关联的发布者、跟踪别名、接收窗口、优先级、交付顺序以及数据流的管理。
*   **管理传出的数据流:** `MoqtSession::OutgoingDataStream` 类负责管理向订阅者发送媒体对象的 WebTransport 数据流，包括确定要发送的对象、序列化对象头和负载、以及处理流的生命周期。
*   **处理基于数据报的对象传输:** 代码也包含了在 `MoqtForwardingPreference::kDatagram` 模式下发送媒体对象的逻辑。

**具体功能分解:**

1. **`MoqtSession::ControlStream::OnAnnounceMessage(const MoqtAnnounce& message)`:**
    *   **功能:** 处理接收到的 `ANNOUNCE` 消息。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 接收到一个来自订阅者的 `ANNOUNCE` 消息，其 `track_namespace` 为 "chat.room.1"。
        *   **逻辑:**  检查自身角色，如果是订阅者则报错。调用 `session_->callbacks_.incoming_announce_callback` 来验证 `track_namespace`。
        *   **假设输出 (成功):** 如果回调函数返回空 `std::optional`，则发送 `ANNOUNCE_OK` 消息给订阅者。
        *   **假设输出 (失败):** 如果回调函数返回 `MoqtAnnounceErrorReason`，则发送包含错误代码和原因的 `ANNOUNCE_ERROR` 消息给订阅者。

2. **`MoqtSession::ControlStream::OnAnnounceOkMessage(const MoqtAnnounceOk& message)` 和 `MoqtSession::ControlStream::OnAnnounceErrorMessage(const MoqtAnnounceError& message)`:**
    *   **功能:** 处理接收到的 `ANNOUNCE_OK` 和 `ANNOUNCE_ERROR` 消息，这些消息是对先前发送的 `ANNOUNCE` 消息的响应。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 之前发送了一个 `ANNOUNCE` 消息，并且在 `session_->pending_outgoing_announces_` 中记录了相应的回调。现在接收到针对该 `track_namespace` 的 `ANNOUNCE_OK` 或 `ANNOUNCE_ERROR` 消息。
        *   **逻辑:** 从 `session_->pending_outgoing_announces_` 中找到对应的回调并执行，传递 `track_namespace` 和可能的错误信息。
        *   **输出:** 执行存储的回调函数，清除 `session_->pending_outgoing_announces_` 中的记录。

3. **`MoqtSession::ControlStream::OnMaxSubscribeIdMessage(const MoqtMaxSubscribeId& message)`:**
    *   **功能:** 处理接收到的 `MAX_SUBSCRIBE_ID` 消息，用于告知对端允许使用的最大订阅 ID。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 接收到一个来自发布者的 `MAX_SUBSCRIBE_ID` 消息，其 `max_subscribe_id` 为 10。
        *   **逻辑:** 检查自身角色，如果是订阅者则报错。检查接收到的值是否小于之前记录的值，如果是则报错。
        *   **输出:** 更新 `session_->peer_max_subscribe_id_` 的值。

4. **`MoqtSession::IncomingDataStream::OnObjectMessage(...)`:**
    *   **功能:** 处理接收到的 `OBJECT` 消息，包含媒体对象的数据。
    *   **用户或编程常见的使用错误:**  如果发布者发送了 `payload_length` 与实际 `payload` 大小不符的 `OBJECT` 消息，会导致解析错误或者数据不完整。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 接收到一个 `OBJECT` 消息，包含 track 别名、序列号、优先级、负载等信息。
        *   **逻辑:** 根据配置决定是否缓冲部分对象。查找对应的 `MoqtTrackVisitorInterface` 并调用 `OnObjectFragment` 方法，将对象片段传递给应用程序。

5. **`MoqtSession::PublishedSubscription` 类:**
    *   **功能:** 管理服务端维护的每个发布者的订阅状态。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 接收到一个来自订阅者的 `SUBSCRIBE` 消息。
        *   **逻辑:** 创建 `PublishedSubscription` 对象，关联发布者，记录订阅信息，并开始监听发布者的对象。
        *   **输出:** 当发布者有新对象时，`OnNewObjectAvailable` 方法会被调用，根据转发偏好选择发送方式（数据流或数据报）。

6. **`MoqtSession::OutgoingDataStream` 类:**
    *   **功能:** 管理向订阅者发送媒体对象的 WebTransport 数据流。
    *   **用户或编程常见的使用错误:**  如果在数据流发送过程中，关联的订阅被移除，则会导致程序错误。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:** 有新的媒体对象需要发送给订阅者，并且已经为该订阅创建了一个 `OutgoingDataStream`。
        *   **逻辑:**  `OnCanWrite` 方法会被 WebTransport 调用，该方法会从发布者的缓存中获取下一个要发送的对象，序列化对象头和负载，并通过 WebTransport 流发送。

**与 JavaScript 的关系举例说明:**

虽然这段 C++ 代码本身不直接包含 JavaScript 代码，但它所实现的功能是 WebTransport 协议中 MoQT 扩展的关键部分，而 WebTransport 是浏览器提供的 JavaScript API。

*   **JavaScript 发起订阅:**  JavaScript 代码可以使用 WebTransport API 连接到服务器，并发送 MoQT 的 `SUBSCRIBE` 消息。服务器端（由这段 C++ 代码处理）会创建 `PublishedSubscription` 对象来管理这个订阅。
*   **JavaScript 接收媒体数据:** 当服务器端通过 `OutgoingDataStream` 发送媒体对象时，浏览器端的 JavaScript 代码可以通过 WebTransport API 的 `readable` 属性监听数据流，并接收到这些媒体数据。
*   **JavaScript 处理控制消息:**  如果服务器发送 `ANNOUNCE_ERROR`，浏览器端的 JavaScript 代码可以通过监听 WebTransport 连接上的控制消息来获取错误信息，并可能采取相应的措施（例如，通知用户或尝试重新订阅）。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户访问一个支持 MoQT 的网站或应用:** 用户打开一个使用 WebTransport 协议进行媒体传输的网页或应用。
2. **JavaScript 代码发起连接和订阅:** 网页或应用的 JavaScript 代码使用 WebTransport API 连接到服务器，并发送一个 `SUBSCRIBE` 消息来订阅特定的媒体 track。
3. **服务器接收 SUBSCRIBE 消息并创建订阅:** 服务器端的 MoQT 实现（包含此代码）接收到 `SUBSCRIBE` 消息，并在 `MoqtSession` 中创建一个 `PublishedSubscription` 对象来管理这个订阅。
4. **发布者发布新的媒体对象:**  媒体发布者（可能是服务器上的另一个模块）发布了新的媒体对象。
5. **`PublishedSubscription::OnNewObjectAvailable` 被调用:**  `PublishedSubscription` 对象接收到发布者新对象的通知。
6. **根据转发偏好选择发送方式:**  如果转发偏好是 `kTrack` 或 `kSubgroup`，则可能需要创建一个新的 `OutgoingDataStream` 或者使用已有的数据流。
7. **`OutgoingDataStream::OnCanWrite` 被 WebTransport 调用:** 当 WebTransport 流可以写入数据时，`OutgoingDataStream::OnCanWrite` 方法会被调用。
8. **`OutgoingDataStream::SendObjects` 发送数据:**  `SendObjects` 方法会从发布者的缓存中获取媒体对象，并将其通过 WebTransport 流发送给客户端。
9. **客户端接收数据:** 客户端的 JavaScript 代码通过 WebTransport API 接收到媒体数据。

**调试线索:**

如果用户报告媒体播放问题（例如，无法播放、播放卡顿），开发人员可以检查以下内容：

*   **服务器是否正确接收并处理了 `SUBSCRIBE` 消息？** 检查服务器日志中是否有创建 `PublishedSubscription` 的记录。
*   **发布者是否正常发布了媒体对象？** 检查发布者的状态和日志。
*   **`PublishedSubscription` 是否正确地接收到了新对象的通知？** 在 `OnNewObjectAvailable` 方法中设置断点。
*   **是否正确地创建了 `OutgoingDataStream`？** 检查数据流的创建和关联。
*   **`OutgoingDataStream::OnCanWrite` 是否被正常调用？** 检查 WebTransport 的流状态。
*   **发送过程中是否发生错误？** 检查 `stream_->Writev` 的返回值和任何相关的错误日志。

总而言之，这部分代码负责处理 MoQT 会话中与媒体发布和订阅相关的核心逻辑，包括控制消息的处理、接收和发送媒体数据流的管理，以及维护订阅状态。它是实现 MoQT 协议的关键组成部分，并直接影响到基于 WebTransport 的实时媒体传输的效率和可靠性。

Prompt: 
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/moqt_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
colViolation,
                    "Received ANNOUNCE from Subscriber");
    return;
  }
  std::optional<MoqtAnnounceErrorReason> error =
      session_->callbacks_.incoming_announce_callback(message.track_namespace);
  if (error.has_value()) {
    MoqtAnnounceError reply;
    reply.track_namespace = message.track_namespace;
    reply.error_code = error->error_code;
    reply.reason_phrase = error->reason_phrase;
    SendOrBufferMessage(session_->framer_.SerializeAnnounceError(reply));
    return;
  }
  MoqtAnnounceOk ok;
  ok.track_namespace = message.track_namespace;
  SendOrBufferMessage(session_->framer_.SerializeAnnounceOk(ok));
}

void MoqtSession::ControlStream::OnAnnounceOkMessage(
    const MoqtAnnounceOk& message) {
  auto it = session_->pending_outgoing_announces_.find(message.track_namespace);
  if (it == session_->pending_outgoing_announces_.end()) {
    session_->Error(MoqtError::kProtocolViolation,
                    "Received ANNOUNCE_OK for nonexistent announce");
    return;
  }
  std::move(it->second)(message.track_namespace, std::nullopt);
  session_->pending_outgoing_announces_.erase(it);
}

void MoqtSession::ControlStream::OnAnnounceErrorMessage(
    const MoqtAnnounceError& message) {
  auto it = session_->pending_outgoing_announces_.find(message.track_namespace);
  if (it == session_->pending_outgoing_announces_.end()) {
    session_->Error(MoqtError::kProtocolViolation,
                    "Received ANNOUNCE_ERROR for nonexistent announce");
    return;
  }
  std::move(it->second)(
      message.track_namespace,
      MoqtAnnounceErrorReason{message.error_code,
                              std::string(message.reason_phrase)});
  session_->pending_outgoing_announces_.erase(it);
}

void MoqtSession::ControlStream::OnAnnounceCancelMessage(
    const MoqtAnnounceCancel& message) {
  // TODO: notify the application about this.
}

void MoqtSession::ControlStream::OnMaxSubscribeIdMessage(
    const MoqtMaxSubscribeId& message) {
  if (session_->peer_role_ == MoqtRole::kSubscriber) {
    QUIC_DLOG(INFO) << ENDPOINT << "Subscriber peer sent MAX_SUBSCRIBE_ID";
    session_->Error(MoqtError::kProtocolViolation,
                    "Received MAX_SUBSCRIBE_ID from Subscriber");
    return;
  }
  if (message.max_subscribe_id < session_->peer_max_subscribe_id_) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Peer sent MAX_SUBSCRIBE_ID message with "
                       "lower value than previous";
    session_->Error(MoqtError::kProtocolViolation,
                    "MAX_SUBSCRIBE_ID message has lower value than previous");
    return;
  }
  session_->peer_max_subscribe_id_ = message.max_subscribe_id;
}

void MoqtSession::ControlStream::OnParsingError(MoqtError error_code,
                                                absl::string_view reason) {
  session_->Error(error_code, absl::StrCat("Parse error: ", reason));
}

void MoqtSession::ControlStream::SendOrBufferMessage(
    quiche::QuicheBuffer message, bool fin) {
  quiche::StreamWriteOptions options;
  options.set_send_fin(fin);
  // TODO: while we buffer unconditionally, we should still at some point tear
  // down the connection if we've buffered too many control messages; otherwise,
  // there is potential for memory exhaustion attacks.
  options.set_buffer_unconditionally(true);
  std::array<absl::string_view, 1> write_vector = {message.AsStringView()};
  absl::Status success = stream_->Writev(absl::MakeSpan(write_vector), options);
  if (!success.ok()) {
    session_->Error(MoqtError::kInternalError,
                    "Failed to write a control message");
  }
}

void MoqtSession::IncomingDataStream::OnObjectMessage(const MoqtObject& message,
                                                      absl::string_view payload,
                                                      bool end_of_message) {
  QUICHE_DVLOG(1) << ENDPOINT << "Received OBJECT message on stream "
                  << stream_->GetStreamId() << " for track alias "
                  << message.track_alias << " with sequence "
                  << message.group_id << ":" << message.object_id
                  << " priority " << message.publisher_priority
                  << " forwarding_preference "
                  << MoqtForwardingPreferenceToString(
                         message.forwarding_preference)
                  << " length " << payload.size() << " length "
                  << message.payload_length << (end_of_message ? "F" : "");
  if (!session_->parameters_.deliver_partial_objects) {
    if (!end_of_message) {  // Buffer partial object.
      if (partial_object_.empty()) {
        // Avoid redundant allocations by reserving the appropriate amount of
        // memory if known.
        partial_object_.reserve(message.payload_length);
      }
      absl::StrAppend(&partial_object_, payload);
      return;
    }
    if (!partial_object_.empty()) {  // Completes the object
      absl::StrAppend(&partial_object_, payload);
      payload = absl::string_view(partial_object_);
    }
  }
  auto [full_track_name, visitor] = session_->TrackPropertiesFromAlias(message);
  if (visitor != nullptr) {
    visitor->OnObjectFragment(
        full_track_name,
        FullSequence{message.group_id, message.subgroup_id.value_or(0),
                     message.object_id},
        message.publisher_priority, message.object_status,
        message.forwarding_preference, payload, end_of_message);
  }
  partial_object_.clear();
}

void MoqtSession::IncomingDataStream::OnCanRead() {
  ForwardStreamDataToParser(*stream_, parser_);
}

void MoqtSession::IncomingDataStream::OnControlMessageReceived() {
  session_->Error(MoqtError::kProtocolViolation,
                  "Received a control message on a data stream");
}

void MoqtSession::IncomingDataStream::OnParsingError(MoqtError error_code,
                                                     absl::string_view reason) {
  session_->Error(error_code, absl::StrCat("Parse error: ", reason));
}

MoqtSession::PublishedSubscription::PublishedSubscription(
    MoqtSession* session, std::shared_ptr<MoqtTrackPublisher> track_publisher,
    const MoqtSubscribe& subscribe,
    MoqtPublishingMonitorInterface* monitoring_interface)
    : subscription_id_(subscribe.subscribe_id),
      session_(session),
      track_publisher_(track_publisher),
      track_alias_(subscribe.track_alias),
      window_(SubscribeMessageToWindow(subscribe, *track_publisher)),
      subscriber_priority_(subscribe.subscriber_priority),
      subscriber_delivery_order_(subscribe.group_order),
      monitoring_interface_(monitoring_interface) {
  track_publisher->AddObjectListener(this);
  if (monitoring_interface_ != nullptr) {
    monitoring_interface_->OnObjectAckSupportKnown(
        subscribe.parameters.object_ack_window.has_value());
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Created subscription for "
                  << subscribe.full_track_name;
  session_->subscribed_track_names_.insert(subscribe.full_track_name);
}

MoqtSession::PublishedSubscription::~PublishedSubscription() {
  track_publisher_->RemoveObjectListener(this);
  session_->subscribed_track_names_.erase(track_publisher_->GetTrackName());
}

SendStreamMap& MoqtSession::PublishedSubscription::stream_map() {
  // The stream map is lazily initialized, since initializing it requires
  // knowing the forwarding preference in advance, and it might not be known
  // when the subscription is first created.
  if (!lazily_initialized_stream_map_.has_value()) {
    QUICHE_DCHECK(
        DoesTrackStatusImplyHavingData(*track_publisher_->GetTrackStatus()));
    lazily_initialized_stream_map_.emplace(
        track_publisher_->GetForwardingPreference());
  }
  return *lazily_initialized_stream_map_;
}

void MoqtSession::PublishedSubscription::Update(
    FullSequence start, std::optional<FullSequence> end,
    MoqtPriority subscriber_priority) {
  window_.UpdateStartEnd(start, end);
  subscriber_priority_ = subscriber_priority;
  // TODO: update priority of all data streams that are currently open.

  // TODO: reset streams that are no longer in-window.
  // TODO: send SUBSCRIBE_DONE if required.
  // TODO: send an error for invalid updates now that it's a part of draft-05.
}

void MoqtSession::PublishedSubscription::set_subscriber_priority(
    MoqtPriority priority) {
  if (priority == subscriber_priority_) {
    return;
  }
  if (queued_outgoing_data_streams_.empty()) {
    subscriber_priority_ = priority;
    return;
  }
  webtransport::SendOrder old_send_order =
      FinalizeSendOrder(queued_outgoing_data_streams_.rbegin()->first);
  subscriber_priority_ = priority;
  session_->UpdateQueuedSendOrder(subscription_id_, old_send_order,
                                  FinalizeSendOrder(old_send_order));
};

void MoqtSession::PublishedSubscription::OnNewObjectAvailable(
    FullSequence sequence) {
  if (!window_.InWindow(sequence)) {
    return;
  }

  MoqtForwardingPreference forwarding_preference =
      track_publisher_->GetForwardingPreference();
  if (forwarding_preference == MoqtForwardingPreference::kDatagram) {
    SendDatagram(sequence);
    return;
  }

  std::optional<webtransport::StreamId> stream_id =
      stream_map().GetStreamForSequence(sequence);
  webtransport::Stream* raw_stream = nullptr;
  if (stream_id.has_value()) {
    raw_stream = session_->session_->GetStreamById(*stream_id);
  } else {
    raw_stream = session_->OpenOrQueueDataStream(subscription_id_, sequence);
  }
  if (raw_stream == nullptr) {
    return;
  }

  OutgoingDataStream* stream =
      static_cast<OutgoingDataStream*>(raw_stream->visitor());
  stream->SendObjects(*this);
}

void MoqtSession::PublishedSubscription::OnTrackPublisherGone() {
  session_->SubscribeIsDone(subscription_id_, SubscribeDoneCode::kGoingAway,
                            "Publisher is gone");
}

void MoqtSession::PublishedSubscription::Backfill() {
  const FullSequence start = window_.start();
  const FullSequence end = track_publisher_->GetLargestSequence();
  const MoqtForwardingPreference preference =
      track_publisher_->GetForwardingPreference();

  absl::flat_hash_set<ReducedSequenceIndex> already_opened;
  std::vector<FullSequence> objects =
      track_publisher_->GetCachedObjectsInRange(start, end);
  QUICHE_DCHECK(absl::c_is_sorted(objects));
  for (FullSequence sequence : objects) {
    auto [it, was_missing] =
        already_opened.insert(ReducedSequenceIndex(sequence, preference));
    if (!was_missing) {
      // For every stream mapping unit present, we only need to notify of the
      // earliest object on it, since the stream itself will pull the rest.
      continue;
    }
    OnNewObjectAvailable(sequence);
  }
}

std::vector<webtransport::StreamId>
MoqtSession::PublishedSubscription::GetAllStreams() const {
  if (!lazily_initialized_stream_map_.has_value()) {
    return {};
  }
  return lazily_initialized_stream_map_->GetAllStreams();
}

webtransport::SendOrder MoqtSession::PublishedSubscription::GetSendOrder(
    FullSequence sequence) const {
  MoqtForwardingPreference forwarding_preference =
      track_publisher_->GetForwardingPreference();

  MoqtPriority publisher_priority = track_publisher_->GetPublisherPriority();
  MoqtDeliveryOrder delivery_order = subscriber_delivery_order().value_or(
      track_publisher_->GetDeliveryOrder());
  switch (forwarding_preference) {
    case MoqtForwardingPreference::kTrack:
      return SendOrderForStream(subscriber_priority_, publisher_priority,
                                /*group_id=*/0, delivery_order);
      break;
    case MoqtForwardingPreference::kSubgroup:
      return SendOrderForStream(subscriber_priority_, publisher_priority,
                                sequence.group, sequence.subgroup,
                                delivery_order);
      break;
    case MoqtForwardingPreference::kDatagram:
      QUICHE_NOTREACHED();
      return 0;
  }
}

// Returns the highest send order in the subscription.
void MoqtSession::PublishedSubscription::AddQueuedOutgoingDataStream(
    FullSequence first_object) {
  std::optional<webtransport::SendOrder> start_send_order =
      queued_outgoing_data_streams_.empty()
          ? std::optional<webtransport::SendOrder>()
          : queued_outgoing_data_streams_.rbegin()->first;
  webtransport::SendOrder send_order = GetSendOrder(first_object);
  // Zero out the subscriber priority bits, since these will be added when
  // updating the session.
  queued_outgoing_data_streams_.emplace(
      UpdateSendOrderForSubscriberPriority(send_order, 0), first_object);
  if (!start_send_order.has_value()) {
    session_->UpdateQueuedSendOrder(subscription_id_, std::nullopt, send_order);
  } else if (*start_send_order < send_order) {
    session_->UpdateQueuedSendOrder(
        subscription_id_, FinalizeSendOrder(*start_send_order), send_order);
  }
}

FullSequence
MoqtSession::PublishedSubscription::NextQueuedOutgoingDataStream() {
  QUICHE_DCHECK(!queued_outgoing_data_streams_.empty());
  if (queued_outgoing_data_streams_.empty()) {
    return FullSequence();
  }
  auto it = queued_outgoing_data_streams_.rbegin();
  webtransport::SendOrder old_send_order = FinalizeSendOrder(it->first);
  FullSequence first_object = it->second;
  // converting a reverse iterator to an iterator involves incrementing it and
  // then taking base().
  queued_outgoing_data_streams_.erase((++it).base());
  if (queued_outgoing_data_streams_.empty()) {
    session_->UpdateQueuedSendOrder(subscription_id_, old_send_order,
                                    std::nullopt);
  } else {
    webtransport::SendOrder new_send_order =
        FinalizeSendOrder(queued_outgoing_data_streams_.rbegin()->first);
    if (old_send_order != new_send_order) {
      session_->UpdateQueuedSendOrder(subscription_id_, old_send_order,
                                      new_send_order);
    }
  }
  return first_object;
}

void MoqtSession::PublishedSubscription::OnDataStreamCreated(
    webtransport::StreamId id, FullSequence start_sequence) {
  stream_map().AddStream(start_sequence, id);
}
void MoqtSession::PublishedSubscription::OnDataStreamDestroyed(
    webtransport::StreamId id, FullSequence end_sequence) {
  stream_map().RemoveStream(end_sequence, id);
}

void MoqtSession::PublishedSubscription::OnObjectSent(FullSequence sequence) {
  if (largest_sent_.has_value()) {
    largest_sent_ = std::max(*largest_sent_, sequence);
  } else {
    largest_sent_ = sequence;
  }
  // TODO: send SUBSCRIBE_DONE if the subscription is done.
}

MoqtSession::OutgoingDataStream::OutgoingDataStream(
    MoqtSession* session, webtransport::Stream* stream,
    PublishedSubscription& subscription, FullSequence first_object)
    : session_(session),
      stream_(stream),
      subscription_id_(subscription.subscription_id()),
      next_object_(first_object),
      session_liveness_(session->liveness_token_) {
  UpdateSendOrder(subscription);
}

MoqtSession::OutgoingDataStream::~OutgoingDataStream() {
  // Though it might seem intuitive that the session object has to outlive the
  // connection object (and this is indeed how something like QuicSession and
  // QuicStream works), this is not the true for WebTransport visitors: the
  // session getting destroyed will inevitably lead to all related streams being
  // destroyed, but the actual order of destruction is not guaranteed.  Thus, we
  // need to check if the session still exists while accessing it in a stream
  // destructor.
  if (session_liveness_.expired()) {
    return;
  }
  auto it = session_->published_subscriptions_.find(subscription_id_);
  if (it != session_->published_subscriptions_.end()) {
    it->second->OnDataStreamDestroyed(stream_->GetStreamId(), next_object_);
  }
}

void MoqtSession::OutgoingDataStream::OnCanWrite() {
  PublishedSubscription* subscription = GetSubscriptionIfValid();
  if (subscription == nullptr) {
    return;
  }
  SendObjects(*subscription);
}

MoqtSession::PublishedSubscription*
MoqtSession::OutgoingDataStream::GetSubscriptionIfValid() {
  auto it = session_->published_subscriptions_.find(subscription_id_);
  if (it == session_->published_subscriptions_.end()) {
    stream_->ResetWithUserCode(kResetCodeSubscriptionGone);
    return nullptr;
  }

  PublishedSubscription* subscription = it->second.get();
  MoqtTrackPublisher& publisher = subscription->publisher();
  absl::StatusOr<MoqtTrackStatusCode> status = publisher.GetTrackStatus();
  if (!status.ok()) {
    // TODO: clean up the subscription.
    return nullptr;
  }
  if (!DoesTrackStatusImplyHavingData(*status)) {
    QUICHE_BUG(GetSubscriptionIfValid_InvalidTrackStatus)
        << "The track publisher returned a status indicating that no objects "
           "are available, but a stream for those objects exists.";
    session_->Error(MoqtError::kInternalError,
                    "Invalid track state provided by application");
    return nullptr;
  }
  return subscription;
}

void MoqtSession::OutgoingDataStream::SendObjects(
    PublishedSubscription& subscription) {
  while (stream_->CanWrite()) {
    std::optional<PublishedObject> object =
        subscription.publisher().GetCachedObject(next_object_);
    if (!object.has_value()) {
      break;
    }
    if (!subscription.InWindow(next_object_)) {
      // It is possible that the next object became irrelevant due to a
      // SUBSCRIBE_UPDATE.  Close the stream if so.
      bool success = stream_->SendFin();
      QUICHE_BUG_IF(OutgoingDataStream_fin_due_to_update, !success)
          << "Writing FIN failed despite CanWrite() being true.";
      return;
    }
    SendNextObject(subscription, *std::move(object));
  }
}

void MoqtSession::OutgoingDataStream::SendNextObject(
    PublishedSubscription& subscription, PublishedObject object) {
  QUICHE_DCHECK(next_object_ <= object.sequence);
  QUICHE_DCHECK(stream_->CanWrite());

  MoqtTrackPublisher& publisher = subscription.publisher();
  QUICHE_DCHECK(DoesTrackStatusImplyHavingData(*publisher.GetTrackStatus()));
  MoqtForwardingPreference forwarding_preference =
      publisher.GetForwardingPreference();

  UpdateSendOrder(subscription);

  MoqtObject header;
  header.track_alias = subscription.track_alias();
  header.group_id = object.sequence.group;
  header.object_id = object.sequence.object;
  header.publisher_priority = publisher.GetPublisherPriority();
  header.object_status = object.status;
  header.forwarding_preference = forwarding_preference;
  // TODO(martinduke): send values other than 0.
  header.subgroup_id =
      (forwarding_preference == MoqtForwardingPreference::kSubgroup)
          ? 0
          : std::optional<uint64_t>();
  header.payload_length = object.payload.length();

  quiche::QuicheBuffer serialized_header =
      session_->framer_.SerializeObjectHeader(
          header, GetMessageTypeForForwardingPreference(forwarding_preference),
          !stream_header_written_);
  bool fin = false;
  switch (forwarding_preference) {
    case MoqtForwardingPreference::kTrack:
      if (object.status == MoqtObjectStatus::kEndOfGroup ||
          object.status == MoqtObjectStatus::kGroupDoesNotExist) {
        ++next_object_.group;
        next_object_.object = 0;
      } else {
        next_object_.object = header.object_id + 1;
      }
      fin = object.status == MoqtObjectStatus::kEndOfTrack ||
            !subscription.InWindow(next_object_);
      break;

    case MoqtForwardingPreference::kSubgroup:
      // TODO(martinduke): EndOfGroup and EndOfTrack implies the ability to
      // close other streams/subgroups. PublishedObject should contain a boolean
      // if the stream is safe to close.
      next_object_.object = header.object_id + 1;
      fin = object.status == MoqtObjectStatus::kEndOfTrack ||
            object.status == MoqtObjectStatus::kEndOfGroup ||
            object.status == MoqtObjectStatus::kEndOfSubgroup ||
            object.status == MoqtObjectStatus::kGroupDoesNotExist ||
            !subscription.InWindow(next_object_);
      break;

    case MoqtForwardingPreference::kDatagram:
      QUICHE_NOTREACHED();
      break;
  }

  // TODO(vasilvv): add a version of WebTransport write API that accepts
  // memslices so that we can avoid a copy here.
  std::array<absl::string_view, 2> write_vector = {
      serialized_header.AsStringView(), object.payload.AsStringView()};
  quiche::StreamWriteOptions options;
  options.set_send_fin(fin);
  absl::Status write_status = stream_->Writev(write_vector, options);
  if (!write_status.ok()) {
    QUICHE_BUG(MoqtSession_SendNextObject_write_failed)
        << "Writing into MoQT stream failed despite CanWrite() being true "
           "before; status: "
        << write_status;
    session_->Error(MoqtError::kInternalError, "Data stream write error");
    return;
  }

  QUIC_DVLOG(1) << "Stream " << stream_->GetStreamId() << " successfully wrote "
                << object.sequence << ", fin = " << fin
                << ", next: " << next_object_;

  stream_header_written_ = true;
  subscription.OnObjectSent(object.sequence);
}

void MoqtSession::PublishedSubscription::SendDatagram(FullSequence sequence) {
  std::optional<PublishedObject> object =
      track_publisher_->GetCachedObject(sequence);
  if (!object.has_value()) {
    QUICHE_BUG(PublishedSubscription_SendDatagram_object_not_in_cache)
        << "Got notification about an object that is not in the cache";
    return;
  }

  MoqtObject header;
  header.track_alias = track_alias();
  header.group_id = object->sequence.group;
  header.object_id = object->sequence.object;
  header.publisher_priority = track_publisher_->GetPublisherPriority();
  header.object_status = object->status;
  header.forwarding_preference = MoqtForwardingPreference::kDatagram;
  header.subgroup_id = std::nullopt;
  header.payload_length = object->payload.length();
  quiche::QuicheBuffer datagram = session_->framer_.SerializeObjectDatagram(
      header, object->payload.AsStringView());
  session_->session_->SendOrQueueDatagram(datagram.AsStringView());
  OnObjectSent(object->sequence);
}

void MoqtSession::OutgoingDataStream::UpdateSendOrder(
    PublishedSubscription& subscription) {
  stream_->SetPriority(
      webtransport::StreamPriority{/*send_group_id=*/kMoqtSendGroupId,
                                   subscription.GetSendOrder(next_object_)});
}

}  // namespace moqt

"""


```