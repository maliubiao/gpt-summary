Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the Chromium Blink engine, specifically the `RTCPeerConnection` class. I need to extract the key actions and responsibilities of this code. Additionally, I need to address the relationships with JavaScript, HTML, and CSS, provide examples of logical reasoning (if present), common usage errors, and how a user's actions might lead to this code being executed, as well as summarize the overall functionality.

Here's a breakdown of the code's actions and what I need to cover:

1. **Processing Remote Description Changes:** The code deals with updates triggered by changes in the remote peer's description. This involves:
    * Handling added and removed transceivers.
    * Updating transceiver states.
    * Managing associated media streams.
    * Firing events for track additions and removals.
    * Muting and unmuting tracks.
    * Updating the lists of senders and receivers.
    * Managing signaling state changes.
    * Firing legacy stream events (`onaddstream`, `onremovestream`).
    * Firing `ontrack` events.
    * Updating ICE connection state.

2. **Setting Associated Media Streams:** This section manages the association of media streams with receivers based on stream IDs.

3. **Handling Remote Data Channels:**  It manages the addition of data channels initiated by the remote peer.

4. **Noting Interesting Usage:** This seems related to gathering usage statistics.

5. **Unregistering Peer Connection Handler:** This involves cleaning up resources when the peer connection is no longer needed.

6. **Closing Peer Connection:**  This handles the closure of the connection.

7. **Event Handling:**  The code extensively uses events for signaling state changes, ICE gathering and connection state changes, and other important lifecycle events. It manages scheduling and dispatching these events.

8. **ICE State Management:** It calculates and manages the ICE connection state based on the states of the underlying ICE transports.

9. **Peer Connection State Management:**  Similar to ICE, it manages the overall peer connection state.

10. **Internal Closure:** This performs the core cleanup actions when closing the connection.

11. **Tracing:**  This is for debugging and memory management, allowing the tracing of object relationships.

12. **Testing Hooks:**  The code includes a mechanism for setting a factory for testing purposes.

13. **Counter:**  It tracks the number of active `RTCPeerConnection` objects.

14. **Disabling Back/Forward Cache:**  This is related to browser behavior and preventing caching in certain scenarios.

**Relating to Web Technologies:**

* **JavaScript:** This code is the underlying implementation for the JavaScript `RTCPeerConnection` API. JavaScript calls to this API will trigger the execution of this C++ code. Events fired here are delivered to JavaScript event listeners.
* **HTML:**  The `<video>` and `<audio>` elements are often used to display media streams received through `RTCPeerConnection`.
* **CSS:** CSS can style the video and audio elements, but it doesn't directly interact with the core logic of `RTCPeerConnection`.

**Logical Reasoning Examples:**  The code contains conditional logic for various state transitions and event firing. I can create hypothetical scenarios to illustrate this.

**Common Usage Errors:**  Incorrectly handling events, closing the connection prematurely, or misconfiguring ICE servers are potential errors.

**User Actions:**  Actions like calling `setRemoteDescription()` in JavaScript can lead to this code being executed.

**Summary:**  The core functionality is managing the state and events related to establishing and maintaining a WebRTC peer-to-peer connection.

**Plan:**

1. Summarize the core functionalities based on the code sections.
2. Provide JavaScript examples of how the code is invoked and how it relates to HTML elements.
3. Give examples of logical reasoning within the code with hypothetical inputs and outputs.
4. Illustrate common user errors in WebRTC development that might interact with this code.
5. Describe the user steps that would lead to the execution of this code.
6. Provide a concise overall summary of the code's purpose.
这是对 `blink/renderer/modules/peerconnection/rtc_peer_connection.cc` 文件代码片段的分析，其功能主要集中在处理 `RTCPeerConnection` 对象接收到远程描述 (通常通过 `setRemoteDescription()` 调用) 后的状态更新和事件触发。

**功能归纳：**

这段代码的主要功能是响应远程会话描述的变化，并据此更新本地的 `RTCPeerConnection` 对象的状态，包括：

1. **管理和更新 RTCRtpTransceiver 对象：**
   - 移除不再存在于远程描述中的 `RTCRtpTransceiver`。
   - 创建或更新现有的 `RTCRtpTransceiver` 对象以匹配远程描述。
   - 更新 `RTCRtpTransceiver` 的状态，例如是否接收到媒体。

2. **关联远程媒体流：**
   - 根据远程描述中包含的流 ID，将远程媒体流 (`MediaStream`) 与 `RTCRtpReceiver` 关联起来。
   - 识别需要添加和移除的媒体流和轨道，并存储在 `remove_list` 和 `add_list` 中。

3. **触发与轨道相关的事件：**
   - 当远程轨道的状态发生变化（例如，从没有接收到数据变为接收到数据）时，触发 `ontrack` 事件。
   - 当远程轨道静音或取消静音时，触发相应的 `mute` 或 `unmute` 事件。

4. **更新内部状态：**
   - 更新 `rtp_senders_` 和 `rtp_receivers_` 成员，使其仅包含当前激活的 transceiver 中的 sender 和 receiver。
   - 更新信令状态 (`signaling_state_`)，并触发 `signalingstatechange` 事件。

5. **触发与流相关的事件 (为了兼容性)：**
   - 触发旧的 `onaddstream` 和 `onremovestream` 事件，以兼容旧版本的 WebRTC API。

6. **管理轨道添加到流和从流移除：**
   - 根据 `remove_list` 和 `add_list`，将轨道从相应的媒体流中移除或添加到其中，并同步触发 `removetrack` 和 `addtrack` 事件。

7. **更新 ICE 连接状态：**
   - 根据 transceiver 的变化，可能会影响底层的 ICE 传输，从而更新 ICE 连接状态。

**与 Javascript, HTML, CSS 的关系举例：**

- **Javascript:**
    - **触发代码执行:**  当 JavaScript 代码调用 `RTCPeerConnection.prototype.setRemoteDescription()` 方法并成功设置远程描述时，会触发 Blink 引擎执行这段 C++ 代码。
    - **事件传递:**  这段 C++ 代码中触发的各种事件（例如 `track`, `addstream`, `removestream`, `signalingstatechange`）会传递到 JavaScript 中注册的对应事件监听器。
        ```javascript
        const pc = new RTCPeerConnection();

        pc.ontrack = (event) => {
          console.log('Remote track received:', event.track);
          // 将接收到的轨道添加到 <video> 或 <audio> 元素
          if (event.track.kind === 'video') {
            document.getElementById('remoteVideo').srcObject = event.streams[0];
          }
        };

        pc.onsignalingstatechange = () => {
          console.log('Signaling state changed:', pc.signalingState);
        };

        async function handleRemoteSdp(remoteSdp) {
          try {
            await pc.setRemoteDescription(remoteSdp);
          } catch (e) {
            console.error('Error setting remote description:', e);
          }
        }
        ```
    - **状态反映:**  这段 C++ 代码更新的 `RTCPeerConnection` 对象的内部状态，可以通过 JavaScript 的属性（例如 `pc.signalingState`, `pc.getReceivers()`) 反映出来。

- **HTML:**
    - **媒体展示:**  接收到的远程媒体流通常会通过 JavaScript 设置到 HTML 的 `<video>` 或 `<audio>` 元素的 `srcObject` 属性上，从而在页面上显示音视频。
        ```html
        <video id="remoteVideo" autoplay playsinline></video>
        ```

- **CSS:**
    - **样式控制:** CSS 可以用来控制 `<video>` 和 `<audio>` 元素的样式，例如大小、位置等，但它不直接影响 `RTCPeerConnection` 的核心逻辑。

**逻辑推理举例 (假设输入与输出):**

**假设输入:**

1. **`removed_transceiver_ids`:**  包含一个 ID，表示远程对端移除了一个 transceiver。
2. **`platform_transceivers`:**  包含更新后的远程 transceiver 信息，其中移除了一个 transceiver。
3. **`previous_streams`:**  远程流的列表，包含被移除 transceiver 关联的流。

**逻辑推理:**

- 遍历 `removed_transceiver_ids`，找到对应的本地 `transceivers_` 中的 transceiver。
- 将被移除 transceiver 关联的轨道和流添加到 `remove_list` 中。
- 调用被移除 transceiver 的 `OnTransceiverStopped()` 方法。
- 从 `transceivers_` 列表中移除该 transceiver。
- 遍历更新后的 `platform_transceivers`，与本地的 `transceivers_` 进行比较和更新。
- 对于新接收到数据的 transceiver，如果之前没有接收数据，则将其添加到 `track_events` 列表中，准备触发 `ontrack` 事件。
- 更新 `rtp_senders_` 和 `rtp_receivers_` 列表。
- 比较 `previous_streams` 和更新后的远程流列表 `current_streams`，找出需要触发 `addstream` 和 `removestream` 事件的流。

**输出:**

- 本地的 `transceivers_` 列表不再包含被移除的 transceiver。
- `remove_list` 包含了被移除 transceiver 关联的流和轨道。
- `track_events` 列表可能包含新的 transceiver，准备触发 `ontrack` 事件。
- 可能会触发 `removetrack` 事件，将移除的轨道从其所属的流中移除。
- 可能会触发 `removestream` 事件，如果整个流都不再存在。
- 更新后的信令状态和 ICE 连接状态。

**用户或编程常见的使用错误举例：**

1. **未正确处理 `ontrack` 事件:** 用户可能忘记监听 `ontrack` 事件，导致接收到的远程媒体轨道无法被添加到 `<video>` 或 `<audio>` 元素上，从而无法播放远程音视频。
    ```javascript
    // 错误示例：忘记监听 ontrack 事件
    const pc = new RTCPeerConnection();

    pc.setRemoteDescription(remoteSdp); // 假设 remoteSdp 已经获取
    ```

2. **在 `setRemoteDescription` 之前尝试访问 receiver 或 track:**  在远程描述成功设置之前，尝试访问 `RTCRtpReceiver` 或其 `track()` 可能会导致错误，因为这些对象可能尚未创建或关联。

3. **假设 `onaddstream` 会处理所有情况:**  依赖旧的 `onaddstream` 事件来处理所有远程媒体流的添加，而忽略了 `ontrack` 事件的更细粒度的控制，可能导致在 transceiver 被复用等情况下出现问题。

4. **不理解信令状态的变化:**  在信令状态处于非稳定状态时进行某些操作（例如尝试添加 transceiver）可能会导致意外的行为或错误。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户 A 和用户 B 希望建立 WebRTC 连接。**
2. **信令过程开始:** 用户 A 或 B（通常是 Caller）创建一个 `RTCPeerConnection` 对象。
3. **Caller 创建 Offer:** Caller 调用 `pc.createOffer()` 生成本地会话描述 (SDP)。
4. **Caller 发送 Offer:** Caller 通过信令服务器将 Offer SDP 发送给 Recipient。
5. **Recipient 接收 Offer:** Recipient 的 JavaScript 代码接收到 Offer SDP。
6. **Recipient 设置远程描述:** Recipient 调用 `pc.setRemoteDescription(offerSdp)`. **这就是触发这段 C++ 代码的关键步骤。**  Blink 引擎会解析 `offerSdp`，并执行这段代码来更新 Recipient 的 `RTCPeerConnection` 对象的状态，包括创建或更新 transceiver，关联媒体流等。
7. **Recipient 创建 Answer:** Recipient 调用 `pc.createAnswer()` 生成 Answer SDP。
8. **Recipient 发送 Answer:** Recipient 通过信令服务器将 Answer SDP 发送给 Caller。
9. **Caller 接收 Answer:** Caller 的 JavaScript 代码接收到 Answer SDP。
10. **Caller 设置远程描述:** Caller 调用 `pc.setRemoteDescription(answerSdp)`，这也会触发类似的代码执行，用于更新 Caller 端的连接状态。
11. **连接建立:**  一旦双方都设置了远程描述并完成了 ICE 协商，连接就建立成功，媒体流开始传输。

**总结一下它的功能 (基于整个代码片段):**

这段代码的主要职责是**响应 `RTCPeerConnection` 对象接收到的远程会话描述的变化，同步更新本地状态，并触发相应的事件以通知 JavaScript 层状态的变更**。它负责管理 `RTCRtpTransceiver` 的生命周期，关联远程媒体流和轨道，并确保本地的 `RTCPeerConnection` 对象的状态与远程描述保持一致。这对于建立和维护 WebRTC 连接至关重要，因为它确保了双方对媒体会话的理解同步。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/rtc_peer_connection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
ctor<Member<RTCRtpTransceiver>> track_events;
  MediaStreamVector previous_streams = getRemoteStreams();
  // Remove transceivers and update their states to reflect that they are
  // necessarily stopped.
  for (auto id : removed_transceiver_ids) {
    for (auto it = transceivers_.begin(); it != transceivers_.end(); ++it) {
      if ((*it)->platform_transceiver()->Id() == id) {
        // All streams are removed on stop, update `remove_list` if necessary.
        auto* track = (*it)->receiver()->track();
        for (const auto& stream : (*it)->receiver()->streams()) {
          if (stream->getTracks().Contains(track)) {
            remove_list.push_back(std::make_pair(stream, track));
          }
        }
        (*it)->OnTransceiverStopped();
        transceivers_.erase(it);
        break;
      }
    }
  }
  for (auto& platform_transceiver : platform_transceivers) {
    auto it = FindTransceiver(*platform_transceiver);
    bool previously_had_recv =
        (it != transceivers_.end()) ? (*it)->FiredDirectionHasRecv() : false;
    RTCRtpTransceiver* transceiver =
        CreateOrUpdateTransceiver(std::move(platform_transceiver));

    size_t add_list_prev_size = add_list.size();
    // "Set the associated remote streams".
    // https://w3c.github.io/webrtc-pc/#set-associated-remote-streams
    SetAssociatedMediaStreams(
        transceiver->receiver(),
        transceiver->platform_transceiver()->Receiver()->StreamIds(),
        &remove_list, &add_list);
    // The transceiver is now up-to-date. Check if the receiver's track is now
    // considered added or removed (though a receiver's track is never truly
    // removed). A track event indicates either that the track was "added" in
    // the sense that FiredDirectionHasRecv() changed, or that a new remote
    // stream was added containing the receiver's track.
    if (is_remote_description_or_rollback &&
        ((!previously_had_recv && transceiver->FiredDirectionHasRecv()) ||
         add_list_prev_size != add_list.size())) {
      // "Process the addition of a remote track".
      // https://w3c.github.io/webrtc-pc/#process-remote-track-addition
      track_events.push_back(transceiver);
    }
    if (previously_had_recv && !transceiver->FiredDirectionHasRecv()) {
      // "Process the removal of a remote track".
      // https://w3c.github.io/webrtc-pc/#process-remote-track-removal
      if (!transceiver->receiver()->track()->muted())
        mute_tracks.push_back(transceiver->receiver()->track());
    }
  }
  // Update the rtp_senders_ and rtp_receivers_ members to only contain
  // senders and receivers that are in the current set of transceivers.
  rtp_senders_.clear();
  rtp_receivers_.clear();
  for (auto& transceiver : transceivers_) {
    rtp_senders_.push_back(transceiver->sender());
    rtp_receivers_.push_back(transceiver->receiver());
  }

  MediaStreamVector current_streams = getRemoteStreams();

  // Modify and fire "pc.onsignalingchange" synchronously.
  if (signaling_state_ == webrtc::PeerConnectionInterface::kHaveLocalOffer &&
      signaling_state == webrtc::PeerConnectionInterface::kHaveRemoteOffer) {
    // Inject missing kStable in case of implicit rollback.
    ChangeSignalingState(webrtc::PeerConnectionInterface::kStable, true);
  }
  ChangeSignalingState(signaling_state, true);

  // Mute the tracks, this fires "track.onmute" synchronously.
  for (auto& track : mute_tracks) {
    track->Component()->Source()->SetReadyState(
        MediaStreamSource::kReadyStateMuted);
  }
  // Remove/add tracks to streams, this fires "stream.onremovetrack" and
  // "stream.onaddtrack" synchronously.
  for (auto& pair : remove_list) {
    auto& stream = pair.first;
    auto& track = pair.second;
    if (stream->getTracks().Contains(track)) {
      stream->RemoveTrackAndFireEvents(
          track,
          MediaStreamDescriptorClient::DispatchEventTiming::kImmediately);
    }
  }
  for (auto& pair : add_list) {
    auto& stream = pair.first;
    auto& track = pair.second;
    if (!stream->getTracks().Contains(track)) {
      stream->AddTrackAndFireEvents(
          track,
          MediaStreamDescriptorClient::DispatchEventTiming::kImmediately);
    }
  }

  // Legacy APIs: "pc.onaddstream" and "pc.onremovestream".
  for (const auto& current_stream : current_streams) {
    if (!previous_streams.Contains(current_stream)) {
      MaybeDispatchEvent(MakeGarbageCollected<MediaStreamEvent>(
          event_type_names::kAddstream, current_stream));
    }
  }
  for (const auto& previous_stream : previous_streams) {
    if (!current_streams.Contains(previous_stream)) {
      MaybeDispatchEvent(MakeGarbageCollected<MediaStreamEvent>(
          event_type_names::kRemovestream, previous_stream));
    }
  }

  // Fire "pc.ontrack" synchronously.
  for (auto& transceiver : track_events) {
    auto* track_event = MakeGarbageCollected<RTCTrackEvent>(
        transceiver->receiver(), transceiver->receiver()->track(),
        transceiver->receiver()->streams(), transceiver);
    MaybeDispatchEvent(track_event);
  }

  // Unmute "pc.ontrack" tracks. Fires "track.onunmute" synchronously.
  // TODO(https://crbug.com/889487): The correct thing to do is to unmute in
  // response to receiving RTP packets.
  for (auto& transceiver : track_events) {
    transceiver->receiver()->track()->Component()->Source()->SetReadyState(
        MediaStreamSource::kReadyStateLive);
  }

  // Transceiver modifications can cause changes in the set of ICE
  // transports, which may affect ICE transport state.
  // Note - this must be done every time the set of ICE transports happens.
  // At the moment this only happens in SLD/SRD, and this function is called
  // whenever these functions complete.
  UpdateIceConnectionState();
}

void RTCPeerConnection::SetAssociatedMediaStreams(
    RTCRtpReceiver* receiver,
    const Vector<String>& stream_ids,
    HeapVector<std::pair<Member<MediaStream>, Member<MediaStreamTrack>>>*
        remove_list,
    HeapVector<std::pair<Member<MediaStream>, Member<MediaStreamTrack>>>*
        add_list) {
  MediaStreamVector known_streams = getRemoteStreams();

  MediaStreamVector streams;
  for (const auto& stream_id : stream_ids) {
    MediaStream* curr_stream = nullptr;
    for (const auto& known_stream : known_streams) {
      if (known_stream->id() == stream_id) {
        curr_stream = known_stream;
        break;
      }
    }
    if (!curr_stream) {
      curr_stream = MediaStream::Create(
          GetExecutionContext(),
          MakeGarbageCollected<MediaStreamDescriptor>(
              static_cast<String>(stream_id), MediaStreamComponentVector(),
              MediaStreamComponentVector()));
    }
    streams.push_back(curr_stream);
  }

  const MediaStreamVector& prev_streams = receiver->streams();
  if (remove_list) {
    for (const auto& stream : prev_streams) {
      if (!streams.Contains(stream))
        remove_list->push_back(std::make_pair(stream, receiver->track()));
    }
  }
  if (add_list) {
    for (const auto& stream : streams) {
      if (!prev_streams.Contains(stream))
        add_list->push_back(std::make_pair(stream, receiver->track()));
    }
  }
  receiver->set_streams(std::move(streams));
}

void RTCPeerConnection::DidAddRemoteDataChannel(
    rtc::scoped_refptr<webrtc::DataChannelInterface> channel) {
  DCHECK(!closed_);
  DCHECK(GetExecutionContext()->IsContextThread());

  if (signaling_state_ ==
      webrtc::PeerConnectionInterface::SignalingState::kClosed)
    return;

  auto* blink_channel = MakeGarbageCollected<RTCDataChannel>(
      GetExecutionContext(), std::move(channel));
  blink_channel->SetStateToOpenWithoutEvent();
  MaybeDispatchEvent(MakeGarbageCollected<RTCDataChannelEvent>(
      event_type_names::kDatachannel, blink_channel));
  // The event handler might have closed the channel.
  if (blink_channel->readyState() == V8RTCDataChannelState::Enum::kOpen) {
    blink_channel->DispatchOpenEvent();
  }
}

void RTCPeerConnection::DidNoteInterestingUsage(int usage_pattern) {
  if (!GetExecutionContext())
    return;
  ukm::SourceId source_id = GetExecutionContext()->UkmSourceID();
  ukm::builders::WebRTC_AddressHarvesting(source_id)
      .SetUsagePattern(usage_pattern)
      .Record(GetExecutionContext()->UkmRecorder());
}

void RTCPeerConnection::UnregisterPeerConnectionHandler() {
  if (peer_handler_unregistered_) {
    DCHECK(scheduled_events_.empty())
        << "Undelivered events can cause memory leaks due to "
        << "WrapPersistent(this) in setup function callbacks";
    return;
  }

  peer_handler_unregistered_ = true;
  ice_connection_state_ = webrtc::PeerConnectionInterface::kIceConnectionClosed;
  signaling_state_ = webrtc::PeerConnectionInterface::SignalingState::kClosed;

  peer_handler_->CloseAndUnregister();
  dispatch_scheduled_events_task_handle_.Cancel();
  scheduled_events_.clear();
  feature_handle_for_scheduler_.reset();
}

void RTCPeerConnection::ClosePeerConnection() {
  DCHECK(signaling_state_ !=
         webrtc::PeerConnectionInterface::SignalingState::kClosed);
  CloseInternal();
}

const AtomicString& RTCPeerConnection::InterfaceName() const {
  return event_target_names::kRTCPeerConnection;
}

ExecutionContext* RTCPeerConnection::GetExecutionContext() const {
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

void RTCPeerConnection::ContextDestroyed() {
  suppress_events_ = true;
  if (!closed_) {
    CloseInternal();
  }
  UnregisterPeerConnectionHandler();
}

void RTCPeerConnection::ChangeSignalingState(
    webrtc::PeerConnectionInterface::SignalingState signaling_state,
    bool dispatch_event_immediately) {
  if (signaling_state_ == signaling_state)
    return;
  if (signaling_state_ !=
      webrtc::PeerConnectionInterface::SignalingState::kClosed) {
    signaling_state_ = signaling_state;
    Event* event = Event::Create(event_type_names::kSignalingstatechange);
    if (dispatch_event_immediately)
      MaybeDispatchEvent(event);
    else
      ScheduleDispatchEvent(event);
  }
}

void RTCPeerConnection::ChangeIceGatheringState(
    webrtc::PeerConnectionInterface::IceGatheringState ice_gathering_state) {
  if (ice_connection_state_ !=
      webrtc::PeerConnectionInterface::kIceConnectionClosed) {
    ScheduleDispatchEvent(
        Event::Create(event_type_names::kIcegatheringstatechange),
        WTF::BindOnce(&RTCPeerConnection::SetIceGatheringState,
                      WrapPersistent(this), ice_gathering_state));
    if (ice_gathering_state ==
        webrtc::PeerConnectionInterface::kIceGatheringComplete) {
      // If ICE gathering is completed, generate a null ICE candidate, to
      // signal end of candidates.
      ScheduleDispatchEvent(RTCPeerConnectionIceEvent::Create(nullptr));
    }
  }
}

bool RTCPeerConnection::SetIceGatheringState(
    webrtc::PeerConnectionInterface::IceGatheringState ice_gathering_state) {
  if (ice_connection_state_ !=
          webrtc::PeerConnectionInterface::kIceConnectionClosed &&
      ice_gathering_state_ != ice_gathering_state) {
    ice_gathering_state_ = ice_gathering_state;
    return true;
  }
  return false;
}

void RTCPeerConnection::ChangeIceConnectionState(
    webrtc::PeerConnectionInterface::IceConnectionState ice_connection_state) {
  if (closed_) {
    return;
  }
  if (ice_connection_state_ == ice_connection_state) {
    return;
  }
  ice_connection_state_ = ice_connection_state;
  MaybeDispatchEvent(
      Event::Create(event_type_names::kIceconnectionstatechange));
}

webrtc::PeerConnectionInterface::IceConnectionState
RTCPeerConnection::ComputeIceConnectionState() {
  if (closed_)
    return webrtc::PeerConnectionInterface::kIceConnectionClosed;
  if (HasAnyFailedIceTransport())
    return webrtc::PeerConnectionInterface::kIceConnectionFailed;
  if (HasAnyDisconnectedIceTransport())
    return webrtc::PeerConnectionInterface::kIceConnectionDisconnected;
  if (HasAllNewOrClosedIceTransports())
    return webrtc::PeerConnectionInterface::kIceConnectionNew;
  if (HasAnyNewOrCheckingIceTransport())
    return webrtc::PeerConnectionInterface::kIceConnectionChecking;
  if (HasAllCompletedOrClosedIceTransports())
    return webrtc::PeerConnectionInterface::kIceConnectionCompleted;
  if (HasAllConnectedCompletedOrClosedIceTransports())
    return webrtc::PeerConnectionInterface::kIceConnectionConnected;

  return ice_connection_state_;
}

bool RTCPeerConnection::HasAnyFailedIceTransport() const {
  for (auto& transport : ActiveIceTransports()) {
    if (transport->GetState() == webrtc::IceTransportState::kFailed)
      return true;
  }
  return false;
}

bool RTCPeerConnection::HasAnyDisconnectedIceTransport() const {
  for (auto& transport : ActiveIceTransports()) {
    if (transport->GetState() == webrtc::IceTransportState::kDisconnected)
      return true;
  }
  return false;
}

bool RTCPeerConnection::HasAllNewOrClosedIceTransports() const {
  for (auto& transport : ActiveIceTransports()) {
    if (transport->GetState() != webrtc::IceTransportState::kNew &&
        transport->GetState() != webrtc::IceTransportState::kClosed)
      return false;
  }
  return true;
}

bool RTCPeerConnection::HasAnyNewOrCheckingIceTransport() const {
  for (auto& transport : ActiveIceTransports()) {
    if (transport->GetState() == webrtc::IceTransportState::kNew ||
        transport->GetState() == webrtc::IceTransportState::kChecking)
      return true;
  }
  return false;
}

bool RTCPeerConnection::HasAllCompletedOrClosedIceTransports() const {
  for (auto& transport : ActiveIceTransports()) {
    if (transport->GetState() != webrtc::IceTransportState::kCompleted &&
        transport->GetState() != webrtc::IceTransportState::kClosed)
      return false;
  }
  return true;
}

bool RTCPeerConnection::HasAllConnectedCompletedOrClosedIceTransports() const {
  for (auto& transport : ActiveIceTransports()) {
    if (transport->GetState() != webrtc::IceTransportState::kConnected &&
        transport->GetState() != webrtc::IceTransportState::kCompleted &&
        transport->GetState() != webrtc::IceTransportState::kClosed)
      return false;
  }
  return true;
}

void RTCPeerConnection::ChangePeerConnectionState(
    webrtc::PeerConnectionInterface::PeerConnectionState
        peer_connection_state) {
  if (peer_connection_state_ !=
      webrtc::PeerConnectionInterface::PeerConnectionState::kClosed) {
    ScheduleDispatchEvent(
        Event::Create(event_type_names::kConnectionstatechange),
        WTF::BindOnce(&RTCPeerConnection::SetPeerConnectionState,
                      WrapPersistent(this), peer_connection_state));
  }
}

bool RTCPeerConnection::SetPeerConnectionState(
    webrtc::PeerConnectionInterface::PeerConnectionState
        peer_connection_state) {
  if (peer_connection_state_ !=
          webrtc::PeerConnectionInterface::PeerConnectionState::kClosed &&
      peer_connection_state_ != peer_connection_state) {
    peer_connection_state_ = peer_connection_state;
    return true;
  }
  return false;
}

void RTCPeerConnection::CloseInternal() {
  DCHECK(signaling_state_ !=
         webrtc::PeerConnectionInterface::SignalingState::kClosed);
  peer_handler_->Close();
  closed_ = true;

  ChangeIceConnectionState(
      webrtc::PeerConnectionInterface::kIceConnectionClosed);
  SetPeerConnectionState(
      webrtc::PeerConnectionInterface::PeerConnectionState::kClosed);
  ChangeSignalingState(webrtc::PeerConnectionInterface::SignalingState::kClosed,
                       false);
  for (auto& transceiver : transceivers_) {
    transceiver->OnTransceiverStopped();
  }
  if (sctp_transport_) {
    sctp_transport_->Close();
  }
  // Since Close() can trigger JS-level callbacks, iterate over a copy
  // of the transports list.
  auto dtls_transports_copy = dtls_transports_by_native_transport_;
  for (auto& dtls_transport_iter : dtls_transports_copy) {
    // Since "value" is a WeakPtr, check if it's still valid.
    if (dtls_transport_iter.value) {
      dtls_transport_iter.value->Close();
    }
  }

  feature_handle_for_scheduler_.reset();
}

void RTCPeerConnection::MaybeDispatchEvent(Event* event) {
  if (suppress_events_)
    return;
  DispatchEvent(*event);
}

void RTCPeerConnection::ScheduleDispatchEvent(Event* event) {
  ScheduleDispatchEvent(event, BoolFunction());
}

void RTCPeerConnection::ScheduleDispatchEvent(Event* event,
                                              BoolFunction setup_function) {
  if (peer_handler_unregistered_) {
    DCHECK(scheduled_events_.empty())
        << "Undelivered events can cause memory leaks due to "
        << "WrapPersistent(this) in setup function callbacks";
    return;
  }
  if (suppress_events_) {
    // If suppressed due to closing we also want to ignore the event, but we
    // don't need to crash.
    return;
  }

  scheduled_events_.push_back(
      MakeGarbageCollected<EventWrapper>(event, std::move(setup_function)));

  if (dispatch_scheduled_events_task_handle_.IsActive())
    return;

  if (auto* context = GetExecutionContext()) {
    if (dispatch_events_task_created_callback_for_testing_) {
      context->GetTaskRunner(TaskType::kNetworking)
          ->PostTask(
              FROM_HERE,
              std::move(dispatch_events_task_created_callback_for_testing_));
    }

    // WebRTC spec specifies kNetworking as task source.
    // https://www.w3.org/TR/webrtc/#operation
    dispatch_scheduled_events_task_handle_ = PostCancellableTask(
        *context->GetTaskRunner(TaskType::kNetworking), FROM_HERE,
        WTF::BindOnce(&RTCPeerConnection::DispatchScheduledEvents,
                      WrapPersistent(this)));
  }
}

void RTCPeerConnection::DispatchScheduledEvents() {
  if (peer_handler_unregistered_) {
    DCHECK(scheduled_events_.empty())
        << "Undelivered events can cause memory leaks due to "
        << "WrapPersistent(this) in setup function callbacks";
    return;
  }
  if (suppress_events_) {
    // If suppressed due to closing we also want to ignore the event, but we
    // don't need to crash.
    return;
  }

  HeapVector<Member<EventWrapper>> events;
  events.swap(scheduled_events_);

  HeapVector<Member<EventWrapper>>::iterator it = events.begin();
  for (; it != events.end(); ++it) {
    if ((*it)->Setup()) {
      DispatchEvent(*(*it)->event_.Release());
    }
  }

  events.clear();
}

void RTCPeerConnection::Trace(Visitor* visitor) const {
  visitor->Trace(pending_local_description_);
  visitor->Trace(current_local_description_);
  visitor->Trace(pending_remote_description_);
  visitor->Trace(current_remote_description_);
  visitor->Trace(tracks_);
  visitor->Trace(rtp_senders_);
  visitor->Trace(rtp_receivers_);
  visitor->Trace(transceivers_);
  visitor->Trace(scheduled_events_);
  visitor->Trace(dtls_transports_by_native_transport_);
  visitor->Trace(ice_transports_by_native_transport_);
  visitor->Trace(sctp_transport_);
  visitor->Trace(rtp_transport_);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  MediaStreamObserver::Trace(visitor);
}

// static
void RTCPeerConnection::SetRtcPeerConnectionHandlerFactoryForTesting(
    RtcPeerConnectionHandlerFactoryCallback callback) {
  DCHECK(g_create_rpc_peer_connection_handler_callback_.Get().is_null());
  g_create_rpc_peer_connection_handler_callback_.Get() = std::move(callback);
}

int RTCPeerConnection::PeerConnectionCount() {
  return InstanceCounters::CounterValue(
      InstanceCounters::kRTCPeerConnectionCounter);
}

int RTCPeerConnection::PeerConnectionCountLimit() {
  return kMaxPeerConnections;
}

void RTCPeerConnection::DisableBackForwardCache(ExecutionContext* context) {
  LocalDOMWindow* window = To<LocalDOMWindow>(context);
  // Two features are registered here:
  // - `kWebRTC`: a non-sticky feature that will disable BFCache for any page.
  // It will be reset after the `RTCPeerConnection` is closed.
  // - `kWebRTCSticky`: a sticky feature that will only disable BFCache for the
  // page containing "Cache-Control: no-store" header. It won't be reset even if
  // the `RTCPeerConnection` is closed.
  feature_handle_for_scheduler_ =
      window->GetFrame()->GetFrameScheduler()->RegisterFeature(
          SchedulingPolicy::Feature::kWebRTC,
          SchedulingPolicy{SchedulingPolicy::DisableBackForwardCache()});
  window->GetFrame()->GetFrameScheduler()->RegisterStickyFeature(
      SchedulingPolicy::Feature::kWebRTCSticky,
      SchedulingPolicy{SchedulingPolicy::DisableBackForwardCache()});
}

}  // namespace blink
```