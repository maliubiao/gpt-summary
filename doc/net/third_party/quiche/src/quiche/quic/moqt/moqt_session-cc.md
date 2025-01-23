Response:
The user wants to understand the functionality of the provided C++ code snippet from `moqt_session.cc`. The request asks for a breakdown of its features, potential relationships with JavaScript, logical inference with hypothetical inputs and outputs, common user/programming errors, debugging guidance, and a summary of its core functions.

Here's a breakdown of the thinking process to address this request:

1. **Identify the Core Purpose:** The file is named `moqt_session.cc`. "moqt" likely stands for Media over QUIC Transport, and "session" suggests managing a connection. The initial `#include` directives confirm this, including headers like `quiche/quic/moqt/moqt_framer.h`, `quiche/quic/moqt/moqt_messages.h`, and `web_transport/web_transport.h`. Therefore, the primary function is to manage a MoQT session over a WebTransport or QUIC connection.

2. **Analyze Key Components:**  Scan the code for important classes and member variables.
    * `MoqtSession`: The central class.
    * `webtransport::Session* session_`:  Manages the underlying WebTransport session.
    * `MoqtSessionParameters parameters_`: Stores configuration parameters.
    * `MoqtSessionCallbacks callbacks_`:  Handles event notifications to the application.
    * `MoqtFramer framer_`:  Serializes and deserializes MoQT messages.
    * `publisher_`:  Manages published tracks (data sources).
    * `control_stream_`: Represents the control channel.
    * Data structures like `pending_outgoing_announces_`, `published_subscriptions_`, `active_subscribes_`, `remote_tracks_`, etc., indicate the session's internal state management related to announces, subscriptions, and tracks.

3. **Map Functionality Based on Code Sections:**  Go through the methods and identify their roles:
    * **Session Management:** `OnSessionReady`, `OnSessionClosed`, `Error`.
    * **Control Stream Handling:** `GetControlStream`, `SendControlMessage`, `ControlStream` nested class and its methods (`OnCanRead`, `OnClientSetupMessage`, etc.).
    * **Publishing (Server-side):** `Announce`, `SubscribeIsDone`, `OpenOrQueueDataStream`, `OpenDataStream`, `OnCanCreateNewOutgoingUnidirectionalStream`, `UpdateQueuedSendOrder`.
    * **Subscribing (Client-side):** `SubscribeAbsolute`, `SubscribeCurrentObject`, `SubscribeCurrentGroup`, the `Subscribe` overload.
    * **Data Handling:** `OnIncomingBidirectionalStreamAvailable`, `OnIncomingUnidirectionalStreamAvailable`, `OnDatagramReceived`, `TrackPropertiesFromAlias`, `OutgoingDataStream`, `IncomingDataStream`.
    * **Message Processing (Control Stream):**  Methods within `ControlStream` starting with `On...Message` (e.g., `OnClientSetupMessage`, `OnSubscribeMessage`).

4. **Address the JavaScript Relationship:**  Consider how this C++ code interacts with the browser's JavaScript environment. WebTransport is a key clue. JavaScript uses the WebTransport API to establish connections and send/receive data. This C++ code implements the MoQT protocol logic *on top* of WebTransport. Therefore, it's responsible for handling the specific MoQT framing and semantics that JavaScript wouldn't directly deal with. Examples include the `SETUP`, `SUBSCRIBE`, `ANNOUNCE` messages.

5. **Develop Hypothetical Input/Output Scenarios:** For key functions, imagine simple scenarios. For example, for `SubscribeAbsolute`, think about the client requesting a specific range of data. What message would be sent? What internal state would change?

6. **Identify Potential Errors:** Look for explicit error handling (`Error` method calls) and conditions that might lead to issues (e.g., trying to subscribe with an invalid range, sending messages in the wrong order).

7. **Trace User Actions to the Code:**  Think about how a user's interaction in a browser (using JavaScript WebTransport API) would eventually trigger events that call into this C++ code. Opening a WebTransport connection, sending or receiving data, and managing subscriptions are key user-driven actions.

8. **Focus on the "Part 1" Request:** The prompt explicitly states this is part 1 of 2. Therefore, the summary should focus on the foundational aspects of MoQT session management – establishing the connection, handling control messages, and the basic subscription/publishing mechanics. Avoid going too deep into the data streaming aspects, as that might be covered in part 2.

9. **Structure the Response:** Organize the information logically, using clear headings and bullet points for readability. Start with a general overview of the file's purpose, then delve into specific functionalities, the JavaScript relationship, error scenarios, and debugging hints. Finally, provide a concise summary for part 1.

10. **Review and Refine:**  Read through the generated response to ensure accuracy, clarity, and completeness based on the provided code snippet. Check for any inconsistencies or areas where more detail could be added. For example, explicitly mentioning the roles of publisher and subscriber.
这是 Chromium 网络栈中处理 MoQT（Media over QUIC Transport）会话的核心逻辑文件的前半部分。它定义了 `MoqtSession` 类，负责管理一个 MoQT 会话的生命周期，并处理与对等方的消息交互。

以下是该文件前半部分主要功能的归纳：

**核心功能：管理 MoQT 会话**

* **会话生命周期管理:**  处理 WebTransport 会话的启动、就绪、关闭等事件，并对应地管理 MoQT 会话的状态。
* **消息发送与接收:**  定义了如何通过控制流发送和接收各种 MoQT 控制消息（例如 SETUP, ANNOUNCE, SUBSCRIBE, SUBSCRIBE_OK/ERROR, UNSUBSCRIBE, SUBSCRIBE_UPDATE, MAX_SUBSCRIBE_ID）。
* **控制流管理:**  创建和管理 MoQT 的控制流，该流用于传输控制消息。
* **发布者和订阅者角色管理:**  区分客户端和服务端的角色（发布者或订阅者），并根据角色执行不同的逻辑。
* **订阅管理 (Publisher 侧):**
    * 接收和处理来自订阅者的 SUBSCRIBE 消息。
    * 验证订阅请求，包括 track 是否存在，以及请求的范围是否有效。
    * 管理已发布的订阅 (`published_subscriptions_`)。
    * 发送 SUBSCRIBE_OK 或 SUBSCRIBE_ERROR 消息给订阅者。
    * 处理 UNSUBSCRIBE 消息。
    * 处理 SUBSCRIBE_UPDATE 消息以更新订阅范围。
    * 管理用于传输数据的单向流的创建和队列 (`subscribes_with_queued_outgoing_data_streams_`)。
* **订阅管理 (Subscriber 侧):**
    * 发送 SUBSCRIBE 消息给发布者，请求订阅特定的 track。
    * 处理来自发布者的 SUBSCRIBE_OK 或 SUBSCRIBE_ERROR 消息。
    * 跟踪活跃的订阅 (`active_subscribes_`)。
* **Track 管理:**
    * 维护远程 track 的别名 (`remote_track_aliases_`, `remote_tracks_`)，用于在消息中简化 track 名称。
    * 处理接收到的 OBJECT 消息，并将其传递给相应的 `RemoteTrack::Visitor`。
* **错误处理:**  定义了 `Error` 方法，用于处理 MoQT 会话中的错误，并关闭底层的 WebTransport 会话。
* **优先级控制:** 支持订阅的优先级设置。
* **Object ACK 支持:**  初步支持 Object ACK 机制，允许订阅者确认接收到的特定对象 (这部分可能在后续代码中进一步展开)。
* **ANNOUNCE 机制 (Publisher 侧):** 允许发布者声明其提供的 track 命名空间。

**与 JavaScript 的功能关系：**

该 C++ 文件是 Chromium 浏览器网络栈的一部分，负责实现 MoQT 协议的底层逻辑。JavaScript 代码（通常通过 WebTransport API）会与这个 C++ 代码进行交互，来实现基于 MoQT 的媒体传输功能。

**举例说明：**

假设一个 JavaScript 应用想要订阅一个名为 "live-video" 的 track。

1. **JavaScript 端:** JavaScript 代码会使用 WebTransport API 建立与服务器的连接。
2. **C++ (OnSessionReady):**  如果当前端是客户端，`MoqtSession::OnSessionReady` 会被调用，并创建一个控制流。
3. **JavaScript 端:** JavaScript 代码构造一个 SUBSCRIBE 消息，并通过 WebTransport 的控制流发送出去。
4. **C++ (ControlStream::OnSubscribeMessage):**  C++ 端的 `MoqtSession::ControlStream::OnSubscribeMessage` 会接收到这个 SUBSCRIBE 消息。
5. **C++:** C++ 代码会查找 "live-video" 这个 track 的发布者，验证订阅请求。
6. **C++:** 如果验证成功，C++ 代码会生成一个 SUBSCRIBE_OK 消息，并通过控制流发送回 JavaScript 端。
7. **JavaScript 端:** JavaScript 代码接收到 SUBSCRIBE_OK 消息，表示订阅成功。

**逻辑推理（假设输入与输出）：**

**假设输入:**  服务端收到一个来自客户端的 `SUBSCRIBE` 消息，请求订阅名为 "sports/football" 的 track，并且指定了 `start_group=10`, `start_object=5`。

**输出:**

* 服务端会查找名为 "sports/football" 的发布者。
* 如果找到，并且发布者有数据，服务端可能会检查 `start_group` 是否小于发布者最新的 group ID。
* 如果 `start_group` 有效，服务端会创建一个针对该订阅的 `PublishedSubscription` 对象，并将其存储在 `published_subscriptions_` 中。
* 服务端会生成一个 `SUBSCRIBE_OK` 消息，其中可能包含当前发布者的最大 sequence ID。

**用户或编程常见的使用错误：**

* **在 Publisher 角色发送 SUBSCRIBE 消息:**  代码中有检查 `if (peer_role_ == MoqtRole::kSubscriber)`，如果当前会话角色是 Publisher 且尝试发送 SUBSCRIBE 消息，会导致协议违规错误。
    * **例子:**  开发者在服务端代码中错误地调用了订阅相关的 API。
* **发送的 SUBSCRIBE ID 大于对端允许的最大值:** 代码中检查 `if (next_subscribe_id_ > peer_max_subscribe_id_)`，如果发送的 SUBSCRIBE 消息的 ID 超出范围，会导致订阅失败。
    * **例子:**  客户端在没有收到服务端更新的 `MAX_SUBSCRIBE_ID` 的情况下，发送了过多的订阅请求。
* **订阅范围的起始点晚于数据的存在时间:** 代码中在处理 `SUBSCRIBE` 消息时会检查 `message.start_group` 是否有效。如果订阅者请求的起始 group 已经过时，服务端可能会返回 `SubscribeErrorCode::kInvalidRange`。
    * **例子:** 客户端请求订阅历史数据，但指定的起始时间点早于服务端保留的数据。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在浏览器中访问一个支持 MoQT 的网站或应用。**
2. **JavaScript 代码使用 WebTransport API 尝试与服务器建立连接。** 这会触发 Chromium 网络栈中处理 WebTransport 连接建立的逻辑。
3. **WebTransport 连接建立成功后，MoQT 会话开始初始化。**  `MoqtSession` 对象被创建。
4. **如果是客户端，`OnSessionReady` 会被调用，并尝试打开一个双向流作为控制流。**
5. **JavaScript 代码调用 MoQT 相关的 API，例如订阅某个 track。** 这会导致 JavaScript 代码构建一个 `SUBSCRIBE` 消息。
6. **JavaScript 代码通过 WebTransport API 的 `send()` 方法将 `SUBSCRIBE` 消息发送到服务器。**
7. **在 C++ 端，WebTransport 层的代码接收到数据，并将其传递给 `MoqtSession::ControlStream` 的 `OnCanRead()` 方法。**
8. **`OnCanRead()` 方法调用 `parser_.ProcessData()` 解析接收到的数据。**
9. **`parser_` 解析出 `SUBSCRIBE` 消息后，会调用 `MoqtSession::ControlStream::OnSubscribeMessage()` 方法。**  这就是代码执行到此文件的关键步骤。

**归纳一下它的功能 (第 1 部分):**

`net/third_party/quiche/src/quiche/quic/moqt/moqt_session.cc` 的前半部分主要负责建立和管理 MoQT 会话的基础框架，包括：

* **会话的创建、启动和关闭。**
* **控制流的建立和管理，用于传输 MoQT 控制消息。**
* **处理客户端和服务端之间的 SETUP 协商。**
* **处理发布者接收订阅请求 (SUBSCRIBE) 和响应 (SUBSCRIBE_OK/ERROR)。**
* **处理订阅者发起订阅请求 (SUBSCRIBE)。**
* **基本的 track 管理，包括别名的使用。**
* **初步支持 Object ACK 机制。**
* **处理 ANNOUNCE 消息 (Publisher 侧)。**

这部分代码是构建一个功能完善的 MoQT 会话管理器的基础，为后续的数据传输和更复杂的流控制逻辑奠定了基础。

### 提示词
```
这是目录为net/third_party/quiche/src/quiche/quic/moqt/moqt_session.cc的chromium 网络栈的源代码文件， 请列举一下它的功能, 
如果它与javascript的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_session.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>


#include "absl/algorithm/container.h"
#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/node_hash_map.h"
#include "absl/functional/bind_front.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_subscribe_windows.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/web_transport/web_transport.h"

#define ENDPOINT \
  (perspective() == Perspective::IS_SERVER ? "MoQT Server: " : "MoQT Client: ")

namespace moqt {

namespace {

using ::quic::Perspective;

constexpr MoqtPriority kDefaultSubscriberPriority = 0x80;

// WebTransport lets applications split a session into multiple send groups
// that have equal weight for scheduling. We don't have a use for that, so the
// send group is always the same.
constexpr webtransport::SendGroupId kMoqtSendGroupId = 0;

bool PublisherHasData(const MoqtTrackPublisher& publisher) {
  absl::StatusOr<MoqtTrackStatusCode> status = publisher.GetTrackStatus();
  return status.ok() && DoesTrackStatusImplyHavingData(*status);
}

SubscribeWindow SubscribeMessageToWindow(const MoqtSubscribe& subscribe,
                                         MoqtTrackPublisher& publisher) {
  const FullSequence sequence = PublisherHasData(publisher)
                                    ? publisher.GetLargestSequence()
                                    : FullSequence{0, 0};
  switch (GetFilterType(subscribe)) {
    case MoqtFilterType::kLatestGroup:
      return SubscribeWindow(sequence.group, 0);
    case MoqtFilterType::kLatestObject:
      return SubscribeWindow(sequence.group, sequence.object);
    case MoqtFilterType::kAbsoluteStart:
      return SubscribeWindow(*subscribe.start_group, *subscribe.start_object);
    case MoqtFilterType::kAbsoluteRange:
      return SubscribeWindow(*subscribe.start_group, *subscribe.start_object,
                             *subscribe.end_group, *subscribe.end_object);
    case MoqtFilterType::kNone:
      QUICHE_BUG(MoqtSession_Subscription_invalid_filter_passed);
      return SubscribeWindow(0, 0);
  }
}

class DefaultPublisher : public MoqtPublisher {
 public:
  static DefaultPublisher* GetInstance() {
    static DefaultPublisher* instance = new DefaultPublisher();
    return instance;
  }

  absl::StatusOr<std::shared_ptr<MoqtTrackPublisher>> GetTrack(
      const FullTrackName& track_name) override {
    return absl::NotFoundError("No tracks published");
  }
};
}  // namespace

MoqtSession::MoqtSession(webtransport::Session* session,
                         MoqtSessionParameters parameters,
                         MoqtSessionCallbacks callbacks)
    : session_(session),
      parameters_(parameters),
      callbacks_(std::move(callbacks)),
      framer_(quiche::SimpleBufferAllocator::Get(), parameters.using_webtrans),
      publisher_(DefaultPublisher::GetInstance()),
      local_max_subscribe_id_(parameters.max_subscribe_id),
      liveness_token_(std::make_shared<Empty>()) {}

MoqtSession::ControlStream* MoqtSession::GetControlStream() {
  if (!control_stream_.has_value()) {
    return nullptr;
  }
  webtransport::Stream* raw_stream = session_->GetStreamById(*control_stream_);
  if (raw_stream == nullptr) {
    return nullptr;
  }
  return static_cast<ControlStream*>(raw_stream->visitor());
}

void MoqtSession::SendControlMessage(quiche::QuicheBuffer message) {
  ControlStream* control_stream = GetControlStream();
  if (control_stream == nullptr) {
    QUICHE_LOG(DFATAL) << "Trying to send a message on the control stream "
                          "while it does not exist";
    return;
  }
  control_stream->SendOrBufferMessage(std::move(message));
}

void MoqtSession::OnSessionReady() {
  QUICHE_DLOG(INFO) << ENDPOINT << "Underlying session ready";
  if (parameters_.perspective == Perspective::IS_SERVER) {
    return;
  }

  webtransport::Stream* control_stream =
      session_->OpenOutgoingBidirectionalStream();
  if (control_stream == nullptr) {
    Error(MoqtError::kInternalError, "Unable to open a control stream");
    return;
  }
  control_stream->SetVisitor(
      std::make_unique<ControlStream>(this, control_stream));
  control_stream_ = control_stream->GetStreamId();
  MoqtClientSetup setup = MoqtClientSetup{
      .supported_versions = std::vector<MoqtVersion>{parameters_.version},
      .role = MoqtRole::kPubSub,
      .max_subscribe_id = parameters_.max_subscribe_id,
      .supports_object_ack = parameters_.support_object_acks,
  };
  if (!parameters_.using_webtrans) {
    setup.path = parameters_.path;
  }
  SendControlMessage(framer_.SerializeClientSetup(setup));
  QUIC_DLOG(INFO) << ENDPOINT << "Send the SETUP message";
}

void MoqtSession::OnSessionClosed(webtransport::SessionErrorCode,
                                  const std::string& error_message) {
  if (!error_.empty()) {
    // Avoid erroring out twice.
    return;
  }
  QUICHE_DLOG(INFO) << ENDPOINT << "Underlying session closed with message: "
                    << error_message;
  error_ = error_message;
  std::move(callbacks_.session_terminated_callback)(error_message);
}

void MoqtSession::OnIncomingBidirectionalStreamAvailable() {
  while (webtransport::Stream* stream =
             session_->AcceptIncomingBidirectionalStream()) {
    if (control_stream_.has_value()) {
      Error(MoqtError::kProtocolViolation, "Bidirectional stream already open");
      return;
    }
    stream->SetVisitor(std::make_unique<ControlStream>(this, stream));
    stream->visitor()->OnCanRead();
  }
}
void MoqtSession::OnIncomingUnidirectionalStreamAvailable() {
  while (webtransport::Stream* stream =
             session_->AcceptIncomingUnidirectionalStream()) {
    stream->SetVisitor(std::make_unique<IncomingDataStream>(this, stream));
    stream->visitor()->OnCanRead();
  }
}

void MoqtSession::OnDatagramReceived(absl::string_view datagram) {
  MoqtObject message;
  absl::string_view payload = ParseDatagram(datagram, message);
  QUICHE_DLOG(INFO) << ENDPOINT
                    << "Received OBJECT message in datagram for subscribe_id "
                    << " for track alias " << message.track_alias
                    << " with sequence " << message.group_id << ":"
                    << message.object_id << " priority "
                    << message.publisher_priority << " length "
                    << payload.size();
  auto [full_track_name, visitor] = TrackPropertiesFromAlias(message);
  if (visitor != nullptr) {
    visitor->OnObjectFragment(
        full_track_name, FullSequence{message.group_id, 0, message.object_id},
        message.publisher_priority, message.object_status,
        message.forwarding_preference, payload, true);
  }
}

void MoqtSession::Error(MoqtError code, absl::string_view error) {
  if (!error_.empty()) {
    // Avoid erroring out twice.
    return;
  }
  QUICHE_DLOG(INFO) << ENDPOINT << "MOQT session closed with code: "
                    << static_cast<int>(code) << " and message: " << error;
  error_ = std::string(error);
  session_->CloseSession(static_cast<uint64_t>(code), error);
  std::move(callbacks_.session_terminated_callback)(error);
}

// TODO: Create state that allows ANNOUNCE_OK/ERROR on spurious namespaces to
// trigger session errors.
void MoqtSession::Announce(FullTrackName track_namespace,
                           MoqtOutgoingAnnounceCallback announce_callback) {
  if (peer_role_ == MoqtRole::kPublisher) {
    std::move(announce_callback)(
        track_namespace,
        MoqtAnnounceErrorReason{MoqtAnnounceErrorCode::kInternalError,
                                "ANNOUNCE cannot be sent to Publisher"});
    return;
  }
  if (pending_outgoing_announces_.contains(track_namespace)) {
    std::move(announce_callback)(
        track_namespace,
        MoqtAnnounceErrorReason{
            MoqtAnnounceErrorCode::kInternalError,
            "ANNOUNCE message already outstanding for namespace"});
    return;
  }
  MoqtAnnounce message;
  message.track_namespace = track_namespace;
  SendControlMessage(framer_.SerializeAnnounce(message));
  QUIC_DLOG(INFO) << ENDPOINT << "Sent ANNOUNCE message for "
                  << message.track_namespace;
  pending_outgoing_announces_[track_namespace] = std::move(announce_callback);
}

bool MoqtSession::SubscribeAbsolute(const FullTrackName& name,
                                    uint64_t start_group, uint64_t start_object,
                                    RemoteTrack::Visitor* visitor,
                                    MoqtSubscribeParameters parameters) {
  MoqtSubscribe message;
  message.full_track_name = name;
  message.subscriber_priority = kDefaultSubscriberPriority;
  message.group_order = std::nullopt;
  message.start_group = start_group;
  message.start_object = start_object;
  message.end_group = std::nullopt;
  message.end_object = std::nullopt;
  message.parameters = std::move(parameters);
  return Subscribe(message, visitor);
}

bool MoqtSession::SubscribeAbsolute(const FullTrackName& name,
                                    uint64_t start_group, uint64_t start_object,
                                    uint64_t end_group,
                                    RemoteTrack::Visitor* visitor,
                                    MoqtSubscribeParameters parameters) {
  if (end_group < start_group) {
    QUIC_DLOG(ERROR) << "Subscription end is before beginning";
    return false;
  }
  MoqtSubscribe message;
  message.full_track_name = name;
  message.subscriber_priority = kDefaultSubscriberPriority;
  message.group_order = std::nullopt;
  message.start_group = start_group;
  message.start_object = start_object;
  message.end_group = end_group;
  message.end_object = std::nullopt;
  message.parameters = std::move(parameters);
  return Subscribe(message, visitor);
}

bool MoqtSession::SubscribeAbsolute(const FullTrackName& name,
                                    uint64_t start_group, uint64_t start_object,
                                    uint64_t end_group, uint64_t end_object,
                                    RemoteTrack::Visitor* visitor,
                                    MoqtSubscribeParameters parameters) {
  if (end_group < start_group) {
    QUIC_DLOG(ERROR) << "Subscription end is before beginning";
    return false;
  }
  if (end_group == start_group && end_object < start_object) {
    QUIC_DLOG(ERROR) << "Subscription end is before beginning";
    return false;
  }
  MoqtSubscribe message;
  message.full_track_name = name;
  message.subscriber_priority = kDefaultSubscriberPriority;
  message.group_order = std::nullopt;
  message.start_group = start_group;
  message.start_object = start_object;
  message.end_group = end_group;
  message.end_object = end_object;
  message.parameters = std::move(parameters);
  return Subscribe(message, visitor);
}

bool MoqtSession::SubscribeCurrentObject(const FullTrackName& name,
                                         RemoteTrack::Visitor* visitor,
                                         MoqtSubscribeParameters parameters) {
  MoqtSubscribe message;
  message.full_track_name = name;
  message.subscriber_priority = kDefaultSubscriberPriority;
  message.group_order = std::nullopt;
  message.start_group = std::nullopt;
  message.start_object = std::nullopt;
  message.end_group = std::nullopt;
  message.end_object = std::nullopt;
  message.parameters = std::move(parameters);
  return Subscribe(message, visitor);
}

bool MoqtSession::SubscribeCurrentGroup(const FullTrackName& name,
                                        RemoteTrack::Visitor* visitor,
                                        MoqtSubscribeParameters parameters) {
  MoqtSubscribe message;
  message.full_track_name = name;
  message.subscriber_priority = kDefaultSubscriberPriority;
  message.group_order = std::nullopt;
  // First object of current group.
  message.start_group = std::nullopt;
  message.start_object = 0;
  message.end_group = std::nullopt;
  message.end_object = std::nullopt;
  message.parameters = std::move(parameters);
  return Subscribe(message, visitor);
}

bool MoqtSession::SubscribeIsDone(uint64_t subscribe_id, SubscribeDoneCode code,
                                  absl::string_view reason_phrase) {
  auto it = published_subscriptions_.find(subscribe_id);
  if (it == published_subscriptions_.end()) {
    return false;
  }

  PublishedSubscription& subscription = *it->second;
  std::vector<webtransport::StreamId> streams_to_reset =
      subscription.GetAllStreams();

  MoqtSubscribeDone subscribe_done;
  subscribe_done.subscribe_id = subscribe_id;
  subscribe_done.status_code = code;
  subscribe_done.reason_phrase = reason_phrase;
  subscribe_done.final_id = subscription.largest_sent();
  SendControlMessage(framer_.SerializeSubscribeDone(subscribe_done));
  QUIC_DLOG(INFO) << ENDPOINT << "Sent SUBSCRIBE_DONE message for "
                  << subscribe_id;
  // Clean up the subscription
  published_subscriptions_.erase(it);
  for (webtransport::StreamId stream_id : streams_to_reset) {
    webtransport::Stream* stream = session_->GetStreamById(stream_id);
    if (stream == nullptr) {
      continue;
    }
    stream->ResetWithUserCode(kResetCodeSubscriptionGone);
  }
  return true;
}

bool MoqtSession::Subscribe(MoqtSubscribe& message,
                            RemoteTrack::Visitor* visitor) {
  if (peer_role_ == MoqtRole::kSubscriber) {
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send SUBSCRIBE to subscriber peer";
    return false;
  }
  // TODO(martinduke): support authorization info
  if (next_subscribe_id_ > peer_max_subscribe_id_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send SUBSCRIBE with ID "
                    << next_subscribe_id_
                    << " which is greater than the maximum ID "
                    << peer_max_subscribe_id_;
    return false;
  }
  message.subscribe_id = next_subscribe_id_++;
  auto it = remote_track_aliases_.find(message.full_track_name);
  if (it != remote_track_aliases_.end()) {
    message.track_alias = it->second;
    if (message.track_alias >= next_remote_track_alias_) {
      next_remote_track_alias_ = message.track_alias + 1;
    }
  } else {
    message.track_alias = next_remote_track_alias_++;
  }
  if (SupportsObjectAck() && visitor != nullptr) {
    // Since we do not expose subscribe IDs directly in the API, instead wrap
    // the session and subscribe ID in a callback.
    visitor->OnCanAckObjects(absl::bind_front(&MoqtSession::SendObjectAck, this,
                                              message.subscribe_id));
  } else {
    QUICHE_DLOG_IF(WARNING, message.parameters.object_ack_window.has_value())
        << "Attempting to set object_ack_window on a connection that does not "
           "support it.";
    message.parameters.object_ack_window = std::nullopt;
  }
  SendControlMessage(framer_.SerializeSubscribe(message));
  QUIC_DLOG(INFO) << ENDPOINT << "Sent SUBSCRIBE message for "
                  << message.full_track_name;
  active_subscribes_.try_emplace(message.subscribe_id, message, visitor);
  return true;
}

webtransport::Stream* MoqtSession::OpenOrQueueDataStream(
    uint64_t subscription_id, FullSequence first_object) {
  auto it = published_subscriptions_.find(subscription_id);
  if (it == published_subscriptions_.end()) {
    // It is possible that the subscription has been discarded while the stream
    // was in the queue; discard those streams.
    return nullptr;
  }
  PublishedSubscription& subscription = *it->second;
  if (!session_->CanOpenNextOutgoingUnidirectionalStream()) {
    subscription.AddQueuedOutgoingDataStream(first_object);
    // The subscription will notify the session about how to update the
    // session's queue.
    // TODO: limit the number of streams in the queue.
    return nullptr;
  }
  return OpenDataStream(subscription, first_object);
}

webtransport::Stream* MoqtSession::OpenDataStream(
    PublishedSubscription& subscription, FullSequence first_object) {
  webtransport::Stream* new_stream =
      session_->OpenOutgoingUnidirectionalStream();
  if (new_stream == nullptr) {
    QUICHE_BUG(MoqtSession_OpenDataStream_blocked)
        << "OpenDataStream called when creation of new streams is blocked.";
    return nullptr;
  }
  new_stream->SetVisitor(std::make_unique<OutgoingDataStream>(
      this, new_stream, subscription, first_object));
  subscription.OnDataStreamCreated(new_stream->GetStreamId(), first_object);
  return new_stream;
}

void MoqtSession::OnCanCreateNewOutgoingUnidirectionalStream() {
  while (!subscribes_with_queued_outgoing_data_streams_.empty() &&
         session_->CanOpenNextOutgoingUnidirectionalStream()) {
    auto next = subscribes_with_queued_outgoing_data_streams_.rbegin();
    auto subscription = published_subscriptions_.find(next->subscription_id);
    if (subscription == published_subscriptions_.end()) {
      // Subscription no longer exists; delete the entry.
      subscribes_with_queued_outgoing_data_streams_.erase((++next).base());
      continue;
    }
    // Open the stream. The second argument pops the item from the
    // subscription's queue, which might update
    // subscribes_with_queued_outgoing_data_streams_.
    webtransport::Stream* stream =
        OpenDataStream(*subscription->second,
                       subscription->second->NextQueuedOutgoingDataStream());
    if (stream != nullptr) {
      stream->visitor()->OnCanWrite();
    }
  }
}

void MoqtSession::UpdateQueuedSendOrder(
    uint64_t subscribe_id,
    std::optional<webtransport::SendOrder> old_send_order,
    std::optional<webtransport::SendOrder> new_send_order) {
  if (old_send_order == new_send_order) {
    return;
  }
  if (old_send_order.has_value()) {
    subscribes_with_queued_outgoing_data_streams_.erase(
        SubscriptionWithQueuedStream{*old_send_order, subscribe_id});
  }
  if (new_send_order.has_value()) {
    subscribes_with_queued_outgoing_data_streams_.emplace(*new_send_order,
                                                          subscribe_id);
  }
}

void MoqtSession::GrantMoreSubscribes(uint64_t num_subscribes) {
  local_max_subscribe_id_ += num_subscribes;
  MoqtMaxSubscribeId message;
  message.max_subscribe_id = local_max_subscribe_id_;
  SendControlMessage(framer_.SerializeMaxSubscribeId(message));
}

std::pair<FullTrackName, RemoteTrack::Visitor*>
MoqtSession::TrackPropertiesFromAlias(const MoqtObject& message) {
  auto it = remote_tracks_.find(message.track_alias);
  if (it == remote_tracks_.end()) {
    ActiveSubscribe* subscribe = nullptr;
    // SUBSCRIBE_OK has not arrived yet, but deliver the object. Indexing
    // active_subscribes_ by track alias would make this faster if the
    // subscriber has tons of incomplete subscribes.
    for (auto& open_subscribe : active_subscribes_) {
      if (open_subscribe.second.message.track_alias == message.track_alias) {
        subscribe = &open_subscribe.second;
        break;
      }
    }
    if (subscribe == nullptr) {
      return std::pair<FullTrackName, RemoteTrack::Visitor*>(
          {FullTrackName{}, nullptr});
    }
    subscribe->received_object = true;
    if (subscribe->forwarding_preference.has_value()) {
      if (message.forwarding_preference != *subscribe->forwarding_preference) {
        Error(MoqtError::kProtocolViolation,
              "Forwarding preference changes mid-track");
        return std::pair<FullTrackName, RemoteTrack::Visitor*>(
            {FullTrackName{}, nullptr});
      }
    } else {
      subscribe->forwarding_preference = message.forwarding_preference;
    }
    return std::make_pair(subscribe->message.full_track_name,
                          subscribe->visitor);
  }
  RemoteTrack& track = it->second;
  if (!track.CheckForwardingPreference(message.forwarding_preference)) {
    // Incorrect forwarding preference.
    Error(MoqtError::kProtocolViolation,
          "Forwarding preference changes mid-track");
    return std::pair<FullTrackName, RemoteTrack::Visitor*>(
        {FullTrackName{}, nullptr});
  }
  return std::make_pair(track.full_track_name(), track.visitor());
}

template <class Parser>
static void ForwardStreamDataToParser(webtransport::Stream& stream,
                                      Parser& parser) {
  bool fin =
      quiche::ProcessAllReadableRegions(stream, [&](absl::string_view chunk) {
        parser.ProcessData(chunk, /*end_of_stream=*/false);
      });
  if (fin) {
    parser.ProcessData("", /*end_of_stream=*/true);
  }
}

MoqtSession::ControlStream::ControlStream(MoqtSession* session,
                                          webtransport::Stream* stream)
    : session_(session),
      stream_(stream),
      parser_(session->parameters_.using_webtrans, *this) {
  stream_->SetPriority(
      webtransport::StreamPriority{/*send_group_id=*/kMoqtSendGroupId,
                                   /*send_order=*/kMoqtControlStreamSendOrder});
}

void MoqtSession::ControlStream::OnCanRead() {
  ForwardStreamDataToParser(*stream_, parser_);
}
void MoqtSession::ControlStream::OnCanWrite() {
  // We buffer serialized control frames unconditionally, thus OnCanWrite()
  // requires no handling for control streams.
}

void MoqtSession::ControlStream::OnResetStreamReceived(
    webtransport::StreamErrorCode error) {
  session_->Error(MoqtError::kProtocolViolation,
                  absl::StrCat("Control stream reset with error code ", error));
}
void MoqtSession::ControlStream::OnStopSendingReceived(
    webtransport::StreamErrorCode error) {
  session_->Error(MoqtError::kProtocolViolation,
                  absl::StrCat("Control stream reset with error code ", error));
}

void MoqtSession::ControlStream::OnClientSetupMessage(
    const MoqtClientSetup& message) {
  session_->control_stream_ = stream_->GetStreamId();
  if (perspective() == Perspective::IS_CLIENT) {
    session_->Error(MoqtError::kProtocolViolation,
                    "Received CLIENT_SETUP from server");
    return;
  }
  if (absl::c_find(message.supported_versions, session_->parameters_.version) ==
      message.supported_versions.end()) {
    // TODO(martinduke): Is this the right error code? See issue #346.
    session_->Error(MoqtError::kProtocolViolation,
                    absl::StrCat("Version mismatch: expected 0x",
                                 absl::Hex(session_->parameters_.version)));
    return;
  }
  session_->peer_supports_object_ack_ = message.supports_object_ack;
  QUICHE_DLOG(INFO) << ENDPOINT << "Received the SETUP message";
  if (session_->parameters_.perspective == Perspective::IS_SERVER) {
    MoqtServerSetup response;
    response.selected_version = session_->parameters_.version;
    response.role = MoqtRole::kPubSub;
    response.max_subscribe_id = session_->parameters_.max_subscribe_id;
    response.supports_object_ack = session_->parameters_.support_object_acks;
    SendOrBufferMessage(session_->framer_.SerializeServerSetup(response));
    QUIC_DLOG(INFO) << ENDPOINT << "Sent the SETUP message";
  }
  // TODO: handle role and path.
  if (message.max_subscribe_id.has_value()) {
    session_->peer_max_subscribe_id_ = *message.max_subscribe_id;
  }
  std::move(session_->callbacks_.session_established_callback)();
  session_->peer_role_ = *message.role;
}

void MoqtSession::ControlStream::OnServerSetupMessage(
    const MoqtServerSetup& message) {
  if (perspective() == Perspective::IS_SERVER) {
    session_->Error(MoqtError::kProtocolViolation,
                    "Received SERVER_SETUP from client");
    return;
  }
  if (message.selected_version != session_->parameters_.version) {
    // TODO(martinduke): Is this the right error code? See issue #346.
    session_->Error(MoqtError::kProtocolViolation,
                    absl::StrCat("Version mismatch: expected 0x",
                                 absl::Hex(session_->parameters_.version)));
    return;
  }
  session_->peer_supports_object_ack_ = message.supports_object_ack;
  QUIC_DLOG(INFO) << ENDPOINT << "Received the SETUP message";
  // TODO: handle role and path.
  if (message.max_subscribe_id.has_value()) {
    session_->peer_max_subscribe_id_ = *message.max_subscribe_id;
  }
  std::move(session_->callbacks_.session_established_callback)();
  session_->peer_role_ = *message.role;
}

void MoqtSession::ControlStream::SendSubscribeError(
    const MoqtSubscribe& message, SubscribeErrorCode error_code,
    absl::string_view reason_phrase, uint64_t track_alias) {
  MoqtSubscribeError subscribe_error;
  subscribe_error.subscribe_id = message.subscribe_id;
  subscribe_error.error_code = error_code;
  subscribe_error.reason_phrase = reason_phrase;
  subscribe_error.track_alias = track_alias;
  SendOrBufferMessage(
      session_->framer_.SerializeSubscribeError(subscribe_error));
}

void MoqtSession::ControlStream::OnSubscribeMessage(
    const MoqtSubscribe& message) {
  if (session_->peer_role_ == MoqtRole::kPublisher) {
    QUIC_DLOG(INFO) << ENDPOINT << "Publisher peer sent SUBSCRIBE";
    session_->Error(MoqtError::kProtocolViolation,
                    "Received SUBSCRIBE from publisher");
    return;
  }
  if (message.subscribe_id > session_->local_max_subscribe_id_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received SUBSCRIBE with too large ID";
    session_->Error(MoqtError::kTooManySubscribes,
                    "Received SUBSCRIBE with too large ID");
    return;
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Received a SUBSCRIBE for "
                  << message.full_track_name;

  const FullTrackName& track_name = message.full_track_name;
  absl::StatusOr<std::shared_ptr<MoqtTrackPublisher>> track_publisher =
      session_->publisher_->GetTrack(track_name);
  if (!track_publisher.ok()) {
    QUIC_DLOG(INFO) << ENDPOINT << "SUBSCRIBE for " << track_name
                    << " rejected by the application: "
                    << track_publisher.status();
    SendSubscribeError(message, SubscribeErrorCode::kTrackDoesNotExist,
                       track_publisher.status().message(), message.track_alias);
    return;
  }
  std::optional<FullSequence> largest_id;
  if (PublisherHasData(**track_publisher)) {
    largest_id = (*track_publisher)->GetLargestSequence();
  }
  if (message.start_group.has_value() && largest_id.has_value() &&
      *message.start_group < largest_id->group) {
    SendSubscribeError(message, SubscribeErrorCode::kInvalidRange,
                       "SUBSCRIBE starts in previous group",
                       message.track_alias);
    return;
  }
  MoqtDeliveryOrder delivery_order = (*track_publisher)->GetDeliveryOrder();

  MoqtPublishingMonitorInterface* monitoring = nullptr;
  auto monitoring_it =
      session_->monitoring_interfaces_for_published_tracks_.find(track_name);
  if (monitoring_it !=
      session_->monitoring_interfaces_for_published_tracks_.end()) {
    monitoring = monitoring_it->second;
    session_->monitoring_interfaces_for_published_tracks_.erase(monitoring_it);
  }

  if (session_->subscribed_track_names_.contains(track_name)) {
    session_->Error(MoqtError::kProtocolViolation,
                    "Duplicate subscribe for track");
    return;
  }
  auto subscription = std::make_unique<MoqtSession::PublishedSubscription>(
      session_, *std::move(track_publisher), message, monitoring);
  auto [it, success] = session_->published_subscriptions_.emplace(
      message.subscribe_id, std::move(subscription));
  if (!success) {
    SendSubscribeError(message, SubscribeErrorCode::kInternalError,
                       "Duplicate subscribe ID", message.track_alias);
    return;
  }

  MoqtSubscribeOk subscribe_ok;
  subscribe_ok.subscribe_id = message.subscribe_id;
  subscribe_ok.group_order = delivery_order;
  subscribe_ok.largest_id = largest_id;
  SendOrBufferMessage(session_->framer_.SerializeSubscribeOk(subscribe_ok));

  if (largest_id.has_value()) {
    it->second->Backfill();
  }
}

void MoqtSession::ControlStream::OnSubscribeOkMessage(
    const MoqtSubscribeOk& message) {
  auto it = session_->active_subscribes_.find(message.subscribe_id);
  if (it == session_->active_subscribes_.end()) {
    session_->Error(MoqtError::kProtocolViolation,
                    "Received SUBSCRIBE_OK for nonexistent subscribe");
    return;
  }
  MoqtSubscribe& subscribe = it->second.message;
  QUIC_DLOG(INFO) << ENDPOINT << "Received the SUBSCRIBE_OK for "
                  << "subscribe_id = " << message.subscribe_id << " "
                  << subscribe.full_track_name;
  // Copy the Remote Track from session_->active_subscribes_ to
  // session_->remote_tracks_.
  RemoteTrack::Visitor* visitor = it->second.visitor;
  auto [track_iter, new_entry] = session_->remote_tracks_.try_emplace(
      subscribe.track_alias, subscribe.full_track_name, subscribe.track_alias,
      visitor);
  if (it->second.forwarding_preference.has_value()) {
    if (!track_iter->second.CheckForwardingPreference(
            *it->second.forwarding_preference)) {
      session_->Error(MoqtError::kProtocolViolation,
                      "Forwarding preference different in early objects");
      return;
    }
  }
  // TODO: handle expires.
  if (visitor != nullptr) {
    visitor->OnReply(subscribe.full_track_name, std::nullopt);
  }
  session_->active_subscribes_.erase(it);
}

void MoqtSession::ControlStream::OnSubscribeErrorMessage(
    const MoqtSubscribeError& message) {
  auto it = session_->active_subscribes_.find(message.subscribe_id);
  if (it == session_->active_subscribes_.end()) {
    session_->Error(MoqtError::kProtocolViolation,
                    "Received SUBSCRIBE_ERROR for nonexistent subscribe");
    return;
  }
  if (it->second.received_object) {
    session_->Error(MoqtError::kProtocolViolation,
                    "Received SUBSCRIBE_ERROR after object");
    return;
  }
  MoqtSubscribe& subscribe = it->second.message;
  QUIC_DLOG(INFO) << ENDPOINT << "Received the SUBSCRIBE_ERROR for "
                  << "subscribe_id = " << message.subscribe_id << " ("
                  << subscribe.full_track_name << ")"
                  << ", error = " << static_cast<int>(message.error_code)
                  << " (" << message.reason_phrase << ")";
  RemoteTrack::Visitor* visitor = it->second.visitor;
  if (message.error_code == SubscribeErrorCode::kRetryTrackAlias) {
    // Automatically resubscribe with new alias.
    session_->remote_track_aliases_[subscribe.full_track_name] =
        message.track_alias;
    session_->Subscribe(subscribe, visitor);
  } else if (visitor != nullptr) {
    visitor->OnReply(subscribe.full_track_name, message.reason_phrase);
  }
  session_->active_subscribes_.erase(it);
}

void MoqtSession::ControlStream::OnUnsubscribeMessage(
    const MoqtUnsubscribe& message) {
  session_->SubscribeIsDone(message.subscribe_id,
                            SubscribeDoneCode::kUnsubscribed, "");
}

void MoqtSession::ControlStream::OnSubscribeUpdateMessage(
    const MoqtSubscribeUpdate& message) {
  auto it = session_->published_subscriptions_.find(message.subscribe_id);
  if (it == session_->published_subscriptions_.end()) {
    return;
  }
  FullSequence start(message.start_group, message.start_object);
  std::optional<FullSequence> end;
  if (message.end_group.has_value()) {
    end = FullSequence(*message.end_group, message.end_object.has_value()
                                               ? *message.end_object
                                               : UINT64_MAX);
  }
  it->second->Update(start, end, message.subscriber_priority);
}

void MoqtSession::ControlStream::OnAnnounceMessage(
    const MoqtAnnounce& message) {
  if (session_->peer_role_ == MoqtRole::kSubscriber) {
    QUIC_DLOG(INFO) << ENDPOINT << "Subscriber peer sent SUBSCRIBE";
    session_->Error(MoqtError::kProto
```