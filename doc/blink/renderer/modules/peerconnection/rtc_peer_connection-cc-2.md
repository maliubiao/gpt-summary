Response:
The user wants a summary of the provided C++ code snippet, which is a part of the `RTCPeerConnection` implementation in Chromium's Blink engine. I need to extract the main functionalities within this section of the code.

Here's a breakdown of the code:

1. **Adding and Removing ICE Candidates:** The `addIceCandidate` function handles the process of adding ICE candidates to the peer connection.
2. **Getting Connection States:** Several functions (`signalingState`, `iceGatheringState`, `iceConnectionState`, `connectionState`) provide the current state of the peer connection. These states reflect the progress of establishing a connection.
3. **Trickle ICE:** The `canTrickleIceCandidates` function checks if the connection can use trickle ICE.
4. **Restarting ICE:** The `restartIce` function initiates the process of gathering new ICE candidates.
5. **Adding and Removing Media Streams:** `addStream` and `removeStream` manage the association of media streams with the peer connection.
6. **Getting Local and Remote Streams:** `getLocalStreams` and `getRemoteStreams` retrieve the lists of local and remote media streams, respectively.
7. **Getting Statistics:** The `getStats` function allows retrieving statistics about the connection, senders, or receivers.
8. **Accessing Senders, Receivers, and Transceivers:**  Functions like `getTransceivers`, `getSenders`, and `getReceivers` provide access to the lists of RTP transceivers, senders, and receivers.
9. **Adding and Removing Tracks:** `addTrack` and `removeTrack` manage individual media tracks within the connection.
10. **Creating Data Channels:**  `createDataChannel` sets up data channels for arbitrary data transfer.
11. **Utility and Helper Functions:** Several internal helper functions are present, such as `FindSenderForTrackAndStream`, `FindSender`, `FindReceiver`, `FindTransceiver`, `CreateOrUpdateSender`, `CreateOrUpdateReceiver`, `CreateOrUpdateTransceiver`, `CreateOrUpdateDtlsTransport`, `CreateOrUpdateIceTransport`, and `RegisterTrack`. These manage the internal state and objects of the `RTCPeerConnection`.
12. **Creating DTMF Senders:** The `createDTMFSender` function creates a DTMF sender for a specific audio track.
13. **Closing the Connection:** The `close` function gracefully closes the peer connection.
14. **Event Handling:** Several functions like `NegotiationNeeded`, `DidGenerateICECandidate`, `DidFailICECandidate`, `DidChangeSessionDescriptions`, `DidChangeIceGatheringState`, `DidChangePeerConnectionState`, `DidModifySctpTransport`, and `DidModifyTransceivers` handle events and state changes during the connection lifecycle.

Now, let's address the specific requirements:

*   **Functionality Listing:** This can be directly derived from the code analysis above.
*   **Relationship with JavaScript, HTML, CSS:** This code is the backend implementation of the JavaScript WebRTC API. I need to provide examples of how JavaScript interacts with these C++ functionalities.
*   **Logical Reasoning (Hypothetical Input/Output):**  Choose a simple function, like `signalingState`, and illustrate how its output depends on internal state.
*   **User/Programming Errors:**  Focus on common mistakes when using the WebRTC API that might lead to issues within this C++ code.
*   **User Operations to Reach Here:** Describe the steps a user might take in a web application that would trigger this code.
*   **Part 3 Summary:** Summarize the main functionalities covered in this specific code block.
这是 `blink/renderer/modules/peerconnection/rtc_peer_connection.cc` 文件的第三部分代码，主要负责处理 RTCPeerConnection 对象的各种操作和状态管理。以下是其功能的详细列举：

**核心功能：**

1. **添加和管理 ICE Candidate：**
    *   `addIceCandidate`： 接收并处理来自远程对等端的 ICE candidate，将其添加到本地的 ICE Agent 中，用于建立连接。

2. **获取连接状态：**
    *   `signalingState`： 返回当前的信令状态，例如 `stable`（稳定）、`have-local-offer`（已创建本地 Offer）、`have-remote-offer`（已收到远程 Offer）等。
    *   `iceGatheringState`： 返回 ICE 收集状态，例如 `new`（新创建）、`gathering`（正在收集）、`complete`（收集完成）。
    *   `iceConnectionState`： 返回 ICE 连接状态，例如 `new`（新连接）、`checking`（正在检查）、`connected`（已连接）、`failed`（失败）等。
    *   `connectionState`： 返回整个 PeerConnection 的连接状态，例如 `new`（新创建）、`connecting`（正在连接）、`connected`（已连接）、`failed`（失败）等。

3. **ICE Trickling 支持：**
    *   `canTrickleIceCandidates`：  判断是否可以在收到完整的 SDP 之前发送 ICE candidates (trickle ICE)。

4. **重启 ICE 协商：**
    *   `restartIce`： 强制重新启动 ICE 协商过程，用于处理网络变更等情况。

5. **添加和移除媒体流：**
    *   `addStream`： 将本地 `MediaStream` 添加到 RTCPeerConnection 中，并为其包含的每个 `MediaStreamTrack` 创建相应的 sender。
    *   `removeStream`： 从 RTCPeerConnection 中移除指定的 `MediaStream`，并移除相关的 sender。

6. **获取本地和远程媒体流：**
    *   `getLocalStreams`： 返回添加到此 RTCPeerConnection 的本地 `MediaStream` 列表。
    *   `getRemoteStreams`： 返回从此 RTCPeerConnection 接收到的远程 `MediaStream` 列表。

7. **获取连接统计信息：**
    *   `getStats`： 异步获取 RTCPeerConnection 的统计信息报告，可以针对整个连接，也可以针对特定的 `MediaStreamTrack`。

8. **获取 RTP Sender、Receiver 和 Transceiver：**
    *   `getTransceivers`： 返回与此 RTCPeerConnection 关联的 `RTCRtpTransceiver` 列表。
    *   `getSenders`： 返回与此 RTCPeerConnection 关联的 `RTCRtpSender` 列表。
    *   `getReceivers`： 返回与此 RTCPeerConnection 关联的 `RTCRtpReceiver` 列表。

9. **RTP Contributing Source 缓存：**
    *   `GetRtpContributingSourceCache`： 提供访问 RTP Contributing Source 缓存的接口。

10. **添加 RTP Transceiver：**
    *   `addTransceiver`： 允许添加新的 RTP 收发器，用于协商和发送/接收媒体。可以指定 `MediaStreamTrack` 或媒体类型（"audio" 或 "video"）。

11. **添加和移除媒体轨道：**
    *   `addTrack`： 将本地 `MediaStreamTrack` 添加到 RTCPeerConnection 中，并创建或复用一个 `RTCRtpSender`。
    *   `removeTrack`： 从 RTCPeerConnection 中移除指定的 `RTCRtpSender` 及其关联的 `MediaStreamTrack`。

12. **获取 SCTP Transport 对象：**
    *   `sctp`： 返回用于数据通道的 `RTCSctpTransport` 对象。

13. **创建数据通道：**
    *   `createDataChannel`： 创建一个新的 `RTCDataChannel`，用于在对等端之间传输任意数据。

14. **内部辅助函数：**
    *   `GetTrackForTesting`： 用于测试，根据 `MediaStreamComponent` 获取 `MediaStreamTrack`。
    *   `FindSenderForTrackAndStream`：  查找特定 `MediaStreamTrack` 和 `MediaStream` 的 `RTCRtpSender`。
    *   `FindSender`、`FindReceiver`、`FindTransceiver`： 在内部列表中查找对应的 Sender、Receiver 和 Transceiver 对象。
    *   `CreateOrUpdateSender`、`CreateOrUpdateReceiver`、`CreateOrUpdateTransceiver`： 创建或更新内部的 Sender、Receiver 和 Transceiver 对象。
    *   `CreateOrUpdateDtlsTransport`、`CreateOrUpdateIceTransport`： 创建或更新 DTLS 和 ICE Transport 对象。
    *   `RegisterTrack`： 注册 `MediaStreamTrack` 到内部管理。

15. **创建 DTMF Sender：**
    *   `createDTMFSender`： 为指定的音频 `MediaStreamTrack` 创建一个 `RTCDTMFSender` 对象，用于发送 DTMF 音调。

16. **关闭连接：**
    *   `close`： 关闭 RTCPeerConnection，清理相关资源。

17. **记录 SDP 信息：**
    *   `NoteSdpCreated`： 记录创建的本地 Offer 或 Answer 的 SDP 内容。

18. **处理媒体流轨道添加和移除事件：**
    *   `OnStreamAddTrack`、`OnStreamRemoveTrack`： 响应 `MediaStream` 中轨道的添加和移除事件，并更新 RTCPeerConnection 的状态。

19. **事件触发：**
    *   `NegotiationNeeded`： 触发 `negotiationneeded` 事件，表明需要进行新的信令协商。
    *   `DidGenerateICECandidate`：  处理新生成的 ICE candidate，并触发 `icecandidate` 事件。
    *   `DidFailICECandidate`： 处理 ICE candidate 收集失败的情况，并触发 `icecandidateerror` 事件。
    *   `DidChangeSessionDescriptions`：  处理本地和远程 Session Description 的变更。
    *   `DidChangeIceGatheringState`： 处理 ICE 收集状态的变更，并触发 `icegatheringstatechange` 事件。
    *   `DidChangePeerConnectionState`： 处理 PeerConnection 状态的变更，并触发 `connectionstatechange` 和 `iceconnectionstatechange` 事件。
    *   `DidModifySctpTransport`： 处理 SCTP Transport 状态的变更。
    *   `DidModifyTransceivers`： 处理 Transceiver 集合的变更。

**与 JavaScript, HTML, CSS 的关系：**

此 C++ 代码是 WebRTC API 在浏览器内核中的底层实现，JavaScript 代码通过这些接口与本地的网络和媒体功能进行交互。

*   **JavaScript 调用:**  JavaScript 代码中创建和操作 `RTCPeerConnection` 对象时，最终会调用到这些 C++ 方法。例如：
    ```javascript
    // 创建 RTCPeerConnection 对象
    const pc = new RTCPeerConnection();

    // 添加 ICE candidate
    pc.addIceCandidate(candidate);

    // 获取信令状态
    const state = pc.signalingState;

    // 创建数据通道
    const dataChannel = pc.createDataChannel("myChannel");
    ```
    这些 JavaScript API 的调用会被 Blink 引擎转换为对 `rtc_peer_connection.cc` 中相应 C++ 方法的调用。

*   **HTML 元素:**  HTML 中的 `<video>` 或 `<audio>` 标签通常用于展示本地或远程的媒体流。`RTCPeerConnection` 建立连接后，可以将接收到的远程媒体流设置为这些 HTML 元素的 `srcObject` 属性，从而在页面上播放。

*   **CSS 样式:** CSS 主要负责控制 HTML 元素的样式和布局，与 `RTCPeerConnection` 本身的功能没有直接关系。但是，CSS 可以用来美化显示媒体流的 `<video>` 或 `<audio>` 元素。

**逻辑推理（假设输入与输出）：**

假设用户在 JavaScript 中调用 `pc.signalingState`:

*   **假设输入：**  在内部，`signaling_state_` 成员变量当前的值是 `webrtc::PeerConnectionInterface::SignalingState::kHaveRemoteOffer`。
*   **逻辑推理：**  `signalingState()` 函数会根据 `signaling_state_` 的值进行 `switch` 判断，找到 `case webrtc::PeerConnectionInterface::SignalingState::kHaveRemoteOffer:` 分支。
*   **预期输出：** 函数返回 `V8RTCSignalingState(V8RTCSignalingState::Enum::kHaveRemoteOffer)`，最终在 JavaScript 中 `pc.signalingState` 将返回字符串 `"have-remote-offer"`。

**用户或编程常见的使用错误：**

1. **在 `closed` 状态下调用方法：** 用户可能在 `RTCPeerConnection` 已经关闭后尝试调用诸如 `addIceCandidate`、`createOffer` 等方法。这会导致异常或无操作。
    *   **示例:**
        ```javascript
        pc.close();
        pc.createOffer(); // 可能会抛出错误
        ```
    *   **C++ 代码中的处理：** 很多方法（如 `addIceCandidate`、`addTrack`、`createDataChannel` 等）都会首先检查 `closed_` 状态，并在 `closed` 时直接返回或抛出异常。

2. **在错误的信令状态下调用方法：** 某些方法只能在特定的信令状态下调用。例如，只有在 `stable` 状态下才能调用 `createOffer` 或 `createAnswer`。
    *   **示例:**
        ```javascript
        pc.createOffer();
        pc.addIceCandidate(candidate);
        pc.createOffer(); // 在非 stable 状态下调用，可能会失败
        ```
    *   **C++ 代码中的处理：** `ThrowExceptionIfSignalingStateClosed` 等辅助函数用于检查信令状态，并在不合法的状态下抛出异常。

3. **添加已存在的 Track：**  尝试多次添加同一个 `MediaStreamTrack` 到 `RTCPeerConnection` 会导致错误。
    *   **示例:**
        ```javascript
        const track = localStream.getVideoTracks()[0];
        pc.addTrack(track, localStream);
        pc.addTrack(track, localStream); // 第二次添加会失败
        ```
    *   **C++ 代码中的处理：** `addTrack` 方法会检查 `rtp_senders_` 中是否已存在相同的 track，如果存在则抛出异常。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户打开一个网页，该网页使用了 WebRTC 技术。**
2. **JavaScript 代码创建了一个 `RTCPeerConnection` 对象。**  这会在 Blink 引擎中创建一个对应的 `RTCPeerConnection` C++ 对象。
3. **用户操作（例如点击按钮）触发 JavaScript 代码调用 `createOffer()` 方法。** 这会导致调用 `rtc_peer_connection.cc` 中的 `createOffer()` 方法。
4. **`createOffer()` 方法内部会调用底层的 WebRTC 库生成 SDP。**
5. **生成的 SDP 会通过信令服务器发送给远程对等端。**
6. **远程对等端收到 Offer 后，其 JavaScript 代码会调用 `setRemoteDescription()` 方法。**  这会导致调用远程对等端的 `rtc_peer_connection.cc` 中的 `SetRemoteDescription()` 方法。
7. **远程对等端生成 Answer 并通过信令服务器发送回来。**
8. **本地用户收到 Answer 后，其 JavaScript 代码会调用 `setRemoteDescription()` 方法。**  这会再次调用本地 `rtc_peer_connection.cc` 中的 `SetRemoteDescription()` 方法。
9. **在连接建立过程中，双方会收集 ICE candidates。当本地收集到新的 ICE candidate 时，会触发 `onicecandidate` 事件，JavaScript 代码会将 candidate 通过信令服务器发送给远程。**
10. **远程对等端收到 ICE candidate 后，会调用 `addIceCandidate()` 方法。** 这就是此代码片段中 `addIceCandidate` 方法被调用的场景。
11. **当连接状态发生变化时（例如 ICE 连接状态变为 `connected`），会触发 `oniceconnectionstatechange` 或 `onconnectionstatechange` 事件。**  这些状态变化是由 `rtc_peer_connection.cc` 中的 `DidChangeIceConnectionState` 和 `DidChangePeerConnectionState` 方法触发的。

**这是第3部分，共4部分，请归纳一下它的功能:**

这部分代码主要负责 **RTCPeerConnection 对象的核心操作和状态管理**。它实现了大部分用于控制连接生命周期、管理媒体流和轨道、处理 ICE 协商、以及获取连接状态的关键方法。简单来说，它是 `RTCPeerConnection` 在 JavaScript 中暴露的功能在 C++ 层的具体实现，负责与底层的 WebRTC 库进行交互，并维护连接的内部状态。

### 提示词
```
这是目录为blink/renderer/modules/peerconnection/rtc_peer_connection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
tImpl>(
      GetExecutionContext(), this, success_callback, error_callback);
  peer_handler_->AddIceCandidate(request, std::move(platform_candidate));
  return ToResolvedUndefinedPromise(script_state);
}

V8RTCSignalingState RTCPeerConnection::signalingState() const {
  switch (signaling_state_) {
    case webrtc::PeerConnectionInterface::SignalingState::kStable:
      return V8RTCSignalingState(V8RTCSignalingState::Enum::kStable);
    case webrtc::PeerConnectionInterface::SignalingState::kHaveLocalOffer:
      return V8RTCSignalingState(V8RTCSignalingState::Enum::kHaveLocalOffer);
    case webrtc::PeerConnectionInterface::SignalingState::kHaveLocalPrAnswer:
      return V8RTCSignalingState(V8RTCSignalingState::Enum::kHaveLocalPranswer);
    case webrtc::PeerConnectionInterface::SignalingState::kHaveRemoteOffer:
      return V8RTCSignalingState(V8RTCSignalingState::Enum::kHaveRemoteOffer);
    case webrtc::PeerConnectionInterface::SignalingState::kHaveRemotePrAnswer:
      return V8RTCSignalingState(
          V8RTCSignalingState::Enum::kHaveRemotePranswer);
    case webrtc::PeerConnectionInterface::SignalingState::kClosed:
      return V8RTCSignalingState(V8RTCSignalingState::Enum::kClosed);
  }
  NOTREACHED();
}

V8RTCIceGatheringState RTCPeerConnection::iceGatheringState() const {
  switch (ice_gathering_state_) {
    case webrtc::PeerConnectionInterface::IceGatheringState::kIceGatheringNew:
      return V8RTCIceGatheringState(V8RTCIceGatheringState::Enum::kNew);
    case webrtc::PeerConnectionInterface::IceGatheringState::
        kIceGatheringGathering:
      return V8RTCIceGatheringState(V8RTCIceGatheringState::Enum::kGathering);
    case webrtc::PeerConnectionInterface::IceGatheringState::
        kIceGatheringComplete:
      return V8RTCIceGatheringState(V8RTCIceGatheringState::Enum::kComplete);
  }
  NOTREACHED();
}

V8RTCIceConnectionState RTCPeerConnection::iceConnectionState() const {
  if (closed_) {
    return V8RTCIceConnectionState(V8RTCIceConnectionState::Enum::kClosed);
  }
  switch (ice_connection_state_) {
    case webrtc::PeerConnectionInterface::IceConnectionState::kIceConnectionNew:
      return V8RTCIceConnectionState(V8RTCIceConnectionState::Enum::kNew);
    case webrtc::PeerConnectionInterface::IceConnectionState::
        kIceConnectionChecking:
      return V8RTCIceConnectionState(V8RTCIceConnectionState::Enum::kChecking);
    case webrtc::PeerConnectionInterface::IceConnectionState::
        kIceConnectionConnected:
      return V8RTCIceConnectionState(V8RTCIceConnectionState::Enum::kConnected);
    case webrtc::PeerConnectionInterface::IceConnectionState::
        kIceConnectionCompleted:
      return V8RTCIceConnectionState(V8RTCIceConnectionState::Enum::kCompleted);
    case webrtc::PeerConnectionInterface::IceConnectionState::
        kIceConnectionFailed:
      return V8RTCIceConnectionState(V8RTCIceConnectionState::Enum::kFailed);
    case webrtc::PeerConnectionInterface::IceConnectionState::
        kIceConnectionDisconnected:
      return V8RTCIceConnectionState(
          V8RTCIceConnectionState::Enum::kDisconnected);
    case webrtc::PeerConnectionInterface::IceConnectionState::
        kIceConnectionClosed:
      return V8RTCIceConnectionState(V8RTCIceConnectionState::Enum::kClosed);
    case webrtc::PeerConnectionInterface::IceConnectionState::kIceConnectionMax:
      // Should not happen.
      break;
  }
  NOTREACHED();
}

V8RTCPeerConnectionState RTCPeerConnection::connectionState() const {
  if (closed_) {
    return V8RTCPeerConnectionState(V8RTCPeerConnectionState::Enum::kClosed);
  }
  switch (peer_connection_state_) {
    case webrtc::PeerConnectionInterface::PeerConnectionState::kNew:
      return V8RTCPeerConnectionState(V8RTCPeerConnectionState::Enum::kNew);
    case webrtc::PeerConnectionInterface::PeerConnectionState::kConnecting:
      return V8RTCPeerConnectionState(
          V8RTCPeerConnectionState::Enum::kConnecting);
    case webrtc::PeerConnectionInterface::PeerConnectionState::kConnected:
      return V8RTCPeerConnectionState(
          V8RTCPeerConnectionState::Enum::kConnected);
    case webrtc::PeerConnectionInterface::PeerConnectionState::kFailed:
      return V8RTCPeerConnectionState(V8RTCPeerConnectionState::Enum::kFailed);
    case webrtc::PeerConnectionInterface::PeerConnectionState::kDisconnected:
      return V8RTCPeerConnectionState(
          V8RTCPeerConnectionState::Enum::kDisconnected);
    case webrtc::PeerConnectionInterface::PeerConnectionState::kClosed:
      return V8RTCPeerConnectionState(V8RTCPeerConnectionState::Enum::kClosed);
  }
  NOTREACHED();
}

std::optional<bool> RTCPeerConnection::canTrickleIceCandidates() const {
  if (closed_ || !remoteDescription()) {
    return std::nullopt;
  }
  webrtc::PeerConnectionInterface* native_connection =
      peer_handler_->NativePeerConnection();
  if (!native_connection) {
    return std::nullopt;
  }
  std::optional<bool> can_trickle =
      native_connection->can_trickle_ice_candidates();
  if (!can_trickle) {
    return std::nullopt;
  }
  return *can_trickle;
}

void RTCPeerConnection::restartIce() {
  if (closed_)
    return;
  peer_handler_->RestartIce();
}

void RTCPeerConnection::addStream(ScriptState* script_state,
                                  MediaStream* stream,
                                  ExceptionState& exception_state) {
  if (ThrowExceptionIfSignalingStateClosed(signaling_state_, &exception_state))
    return;

  MediaStreamVector streams;
  streams.push_back(stream);
  for (const auto& track : stream->getTracks()) {
    addTrack(track, streams, IGNORE_EXCEPTION);
  }

  stream->RegisterObserver(this);
}

void RTCPeerConnection::removeStream(MediaStream* stream,
                                     ExceptionState& exception_state) {
  if (ThrowExceptionIfSignalingStateClosed(signaling_state_, &exception_state))
    return;
  for (const auto& track : stream->getTracks()) {
    auto* sender = FindSenderForTrackAndStream(track, stream);
    if (!sender)
      continue;
    removeTrack(sender, IGNORE_EXCEPTION);
  }
  stream->UnregisterObserver(this);
}

MediaStreamVector RTCPeerConnection::getLocalStreams() const {
  MediaStreamVector local_streams;
  for (const auto& transceiver : transceivers_) {
    if (!transceiver->DirectionHasSend())
      continue;
    for (const auto& stream : transceiver->sender()->streams()) {
      if (!local_streams.Contains(stream))
        local_streams.push_back(stream);
    }
  }
  return local_streams;
}

MediaStreamVector RTCPeerConnection::getRemoteStreams() const {
  MediaStreamVector remote_streams;
  for (const auto& transceiver : transceivers_) {
    if (!transceiver->DirectionHasRecv())
      continue;
    for (const auto& stream : transceiver->receiver()->streams()) {
      if (!remote_streams.Contains(stream))
        remote_streams.push_back(stream);
    }
  }
  return remote_streams;
}

ScriptPromise<RTCStatsReport> RTCPeerConnection::getStats(
    ScriptState* script_state,
    MediaStreamTrack* selector,
    ExceptionState& exception_state) {
  if (!selector) {
    ExecutionContext* context = ExecutionContext::From(script_state);
    UseCounter::Count(context, WebFeature::kRTCPeerConnectionGetStats);

    if (!peer_handler_) {
      LOG(ERROR) << "Internal error: peer_handler_ has been discarded";
      exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                        "Internal error: release in progress");
      return EmptyPromise();
    }
    auto* resolver =
        MakeGarbageCollected<ScriptPromiseResolver<RTCStatsReport>>(
            script_state, exception_state.GetContext());
    auto promise = resolver->Promise();
    if (peer_handler_unregistered_) {
      LOG(ERROR) << "Internal error: context is destroyed";
      // This is needed to have the resolver release its internal resources
      // while leaving the associated promise pending as specified.
      resolver->Detach();
    } else {
      peer_handler_->GetStats(WTF::BindOnce(WebRTCStatsReportCallbackResolver,
                                            WrapPersistent(resolver)));
    }
    return promise;
  }

  // Find the sender or receiver that represent the selector.
  size_t track_uses = 0u;
  RTCRtpSender* track_sender = nullptr;
  for (const auto& sender : rtp_senders_) {
    if (sender->track() == selector) {
      ++track_uses;
      track_sender = sender;
    }
  }
  RTCRtpReceiver* track_receiver = nullptr;
  for (const auto& receiver : rtp_receivers_) {
    if (receiver->track() == selector) {
      ++track_uses;
      track_receiver = receiver;
    }
  }
  if (track_uses == 0u) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "There is no sender or receiver for the track.");
    return EmptyPromise();
  }
  if (track_uses > 1u) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "There are more than one sender or receiver for the track.");
    return EmptyPromise();
  }
  // There is just one use of the track, a sender or receiver.
  if (track_sender) {
    DCHECK(!track_receiver);
    return track_sender->getStats(script_state);
  }
  DCHECK(track_receiver);
  return track_receiver->getStats(script_state);
}

const HeapVector<Member<RTCRtpTransceiver>>&
RTCPeerConnection::getTransceivers() const {
  return transceivers_;
}

const HeapVector<Member<RTCRtpSender>>& RTCPeerConnection::getSenders() const {
  return rtp_senders_;
}

const HeapVector<Member<RTCRtpReceiver>>& RTCPeerConnection::getReceivers()
    const {
  return rtp_receivers_;
}

RtpContributingSourceCache& RTCPeerConnection::GetRtpContributingSourceCache() {
  DCHECK(rtp_contributing_source_cache_.has_value());
  return rtp_contributing_source_cache_.value();
}

std::optional<webrtc::RtpTransceiverInit> ValidateRtpTransceiverInit(
    ExecutionContext* execution_context,
    ExceptionState& exception_state,
    const RTCRtpTransceiverInit* init,
    const String kind) {
  auto webrtc_init = ToRtpTransceiverInit(execution_context, init, kind);
  // Validate sendEncodings.
  for (auto& encoding : webrtc_init.send_encodings) {
    if (encoding.rid.length() > 16) {
      exception_state.ThrowTypeError("Illegal length of rid");
      return std::nullopt;
    }
    // Allowed characters: a-z 0-9 _ and -
    if (encoding.rid.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLM"
                                       "NOPQRSTUVWXYZ0123456789-_") !=
        std::string::npos) {
      exception_state.ThrowTypeError("Illegal character in rid");
      return std::nullopt;
    }
  }
  return webrtc_init;
}

RTCRtpTransceiver* RTCPeerConnection::addTransceiver(
    const V8UnionMediaStreamTrackOrString* track_or_kind,
    const RTCRtpTransceiverInit* init,
    ExceptionState& exception_state) {
  if (ThrowExceptionIfSignalingStateClosed(signaling_state_,
                                           &exception_state)) {
    return nullptr;
  }
  webrtc::RTCErrorOr<std::unique_ptr<RTCRtpTransceiverPlatform>> result =
      webrtc::RTCError(webrtc::RTCErrorType::UNSUPPORTED_OPERATION);
  switch (track_or_kind->GetContentType()) {
    case V8UnionMediaStreamTrackOrString::ContentType::kMediaStreamTrack: {
      MediaStreamTrack* track = track_or_kind->GetAsMediaStreamTrack();

      auto webrtc_init = ValidateRtpTransceiverInit(
          GetExecutionContext(), exception_state, init, track->kind());
      if (!webrtc_init) {
        return nullptr;
      }

      RegisterTrack(track);
      result = peer_handler_->AddTransceiverWithTrack(track->Component(),
                                                      std::move(*webrtc_init));
      break;
    }
    case V8UnionMediaStreamTrackOrString::ContentType::kString: {
      const String& kind_string = track_or_kind->GetAsString();
      // TODO(hbos): Make cricket::MediaType an allowed identifier in
      // rtc_peer_connection.cc and use that instead of a boolean.
      String kind;
      if (kind_string == "audio") {
        kind = webrtc::MediaStreamTrackInterface::kAudioKind;
      } else if (kind_string == "video") {
        kind = webrtc::MediaStreamTrackInterface::kVideoKind;
      } else {
        exception_state.ThrowTypeError(
            "The argument provided as parameter 1 is not a valid "
            "MediaStreamTrack kind ('audio' or 'video').");
        return nullptr;
      }

      auto webrtc_init = ValidateRtpTransceiverInit(
          GetExecutionContext(), exception_state, init, kind);
      if (!webrtc_init) {
        return nullptr;
      }

      result = peer_handler_->AddTransceiverWithKind(std::move(kind),
                                                     std::move(*webrtc_init));
      break;
    }
  }
  if (!result.ok()) {
    ThrowExceptionFromRTCError(result.error(), exception_state);
    return nullptr;
  }
  return CreateOrUpdateTransceiver(result.MoveValue());
}

RTCRtpSender* RTCPeerConnection::addTrack(MediaStreamTrack* track,
                                          MediaStreamVector streams,
                                          ExceptionState& exception_state) {
  DCHECK(track);
  DCHECK(track->Component());
  if (ThrowExceptionIfSignalingStateClosed(signaling_state_, &exception_state))
    return nullptr;
  for (const auto& sender : rtp_senders_) {
    if (sender->track() == track) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidAccessError,
          "A sender already exists for the track.");
      return nullptr;
    }
  }

  MediaStreamDescriptorVector descriptors(streams.size());
  for (wtf_size_t i = 0; i < streams.size(); ++i) {
    descriptors[i] = streams[i]->Descriptor();
  }
  webrtc::RTCErrorOr<std::unique_ptr<RTCRtpTransceiverPlatform>>
      error_or_transceiver =
          peer_handler_->AddTrack(track->Component(), descriptors);
  if (!error_or_transceiver.ok()) {
    ThrowExceptionFromRTCError(error_or_transceiver.error(), exception_state);
    return nullptr;
  }

  auto platform_transceiver = error_or_transceiver.MoveValue();

  // The track must be known to the peer connection when performing
  // CreateOrUpdateSender() below.
  RegisterTrack(track);

  auto stream_ids = platform_transceiver->Sender()->StreamIds();
  RTCRtpTransceiver* transceiver =
      CreateOrUpdateTransceiver(std::move(platform_transceiver));
  RTCRtpSender* sender = transceiver->sender();
  // Newly created senders have no streams set, we have to set it ourselves.
  sender->set_streams(streams);
  // The native sender may have filtered out duplicates.
  DCHECK_LE(stream_ids.size(), streams.size());
  return sender;
}

void RTCPeerConnection::removeTrack(RTCRtpSender* sender,
                                    ExceptionState& exception_state) {
  DCHECK(sender);
  if (ThrowExceptionIfSignalingStateClosed(signaling_state_, &exception_state))
    return;
  auto it = FindSender(*sender->web_sender());
  if (it == rtp_senders_.end()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidAccessError,
        "The sender was not created by this peer connection.");
    return;
  }

  auto error_or_transceiver = peer_handler_->RemoveTrack(sender->web_sender());
  if (!error_or_transceiver.ok()) {
    ThrowExceptionFromRTCError(error_or_transceiver.error(), exception_state);
    return;
  }
  if (!error_or_transceiver.value()) {
    // There is no transceiver to update - the operation was cancelled, such
    // as if the transceiver was rolled back.
    return;
  }
  CreateOrUpdateTransceiver(error_or_transceiver.MoveValue());
}

RTCSctpTransport* RTCPeerConnection::sctp() const {
  return sctp_transport_.Get();
}

RTCDataChannel* RTCPeerConnection::createDataChannel(
    ScriptState* script_state,
    String label,
    const RTCDataChannelInit* data_channel_dict,
    ExceptionState& exception_state) {
  if (ThrowExceptionIfSignalingStateClosed(signaling_state_, &exception_state))
    return nullptr;

  webrtc::DataChannelInit init;
  // TODO(jiayl): remove the deprecated reliable field once Libjingle is updated
  // to handle that.
  init.reliable = false;
  init.ordered = data_channel_dict->ordered();
  ExecutionContext* context = ExecutionContext::From(script_state);
  if (data_channel_dict->hasMaxPacketLifeTime()) {
    UseCounter::Count(
        context,
        WebFeature::kRTCPeerConnectionCreateDataChannelMaxPacketLifeTime);
    init.maxRetransmitTime = data_channel_dict->maxPacketLifeTime();
  }
  if (data_channel_dict->hasMaxRetransmits()) {
    UseCounter::Count(
        context, WebFeature::kRTCPeerConnectionCreateDataChannelMaxRetransmits);
    init.maxRetransmits = data_channel_dict->maxRetransmits();
  }
  init.protocol = data_channel_dict->protocol().Utf8();
  init.negotiated = data_channel_dict->negotiated();
  if (data_channel_dict->hasId())
    init.id = data_channel_dict->id();
  if (data_channel_dict->hasPriority()) {
    init.priority = [&] {
      if (data_channel_dict->priority() == "very-low") {
        return webrtc::PriorityValue(webrtc::Priority::kVeryLow);
      }
      if (data_channel_dict->priority() == "low") {
        return webrtc::PriorityValue(webrtc::Priority::kLow);
      }
      if (data_channel_dict->priority() == "medium") {
        return webrtc::PriorityValue(webrtc::Priority::kMedium);
      }
      if (data_channel_dict->priority() == "high") {
        return webrtc::PriorityValue(webrtc::Priority::kHigh);
      }
      NOTREACHED();
    }();
  }
  // Checks from WebRTC specification section 6.1
  // If [[DataChannelLabel]] is longer than 65535 bytes, throw a
  // TypeError.
  if (label.Utf8().length() > 65535) {
    exception_state.ThrowTypeError("RTCDataChannel label too long");
    return nullptr;
  }
  // If [[DataChannelProtocol]] is longer than 65535 bytes long, throw a
  // TypeError.
  if (init.protocol.length() > 65535) {
    exception_state.ThrowTypeError("RTCDataChannel protocol too long");
    return nullptr;
  }
  // If [[Negotiated]] is true and [[DataChannelId]] is null, throw a TypeError.
  if (init.negotiated && init.id == -1) {
    exception_state.ThrowTypeError(
        "RTCDataChannel must have id set if negotiated is true");
    return nullptr;
  }
  // If both [[MaxPacketLifeTime]] and [[MaxRetransmits]] attributes are set
  // (not null), throw a TypeError.
  if (init.maxRetransmitTime >= 0 && init.maxRetransmits >= 0) {
    exception_state.ThrowTypeError(
        "RTCDataChannel cannot have both max retransmits and max lifetime");
    return nullptr;
  }
  // If [[DataChannelId]] is equal to 65535, which is greater than the maximum
  // allowed ID of 65534 but still qualifies as an unsigned short, throw a
  // TypeError.
  if (init.id >= 65535) {
    exception_state.ThrowTypeError("RTCDataChannel cannot have id > 65534");
    return nullptr;
  }
  // Further checks of DataChannelId are done in the webrtc layer.

  rtc::scoped_refptr<webrtc::DataChannelInterface> webrtc_channel =
      peer_handler_->CreateDataChannel(label, init);
  if (!webrtc_channel) {
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "RTCDataChannel creation failed");
    return nullptr;
  }
  auto* channel = MakeGarbageCollected<RTCDataChannel>(
      GetExecutionContext(), std::move(webrtc_channel));

  return channel;
}

MediaStreamTrack* RTCPeerConnection::GetTrackForTesting(
    MediaStreamComponent* component) const {
  auto it = tracks_.find(component);
  if (it != tracks_.end()) {
    return it->value.Get();
  } else {
    return nullptr;
  }
}

RTCRtpSender* RTCPeerConnection::FindSenderForTrackAndStream(
    MediaStreamTrack* track,
    MediaStream* stream) {
  for (const auto& rtp_sender : rtp_senders_) {
    if (rtp_sender->track() == track) {
      auto streams = rtp_sender->streams();
      if (streams.size() == 1u && streams[0] == stream)
        return rtp_sender.Get();
    }
  }
  return nullptr;
}

HeapVector<Member<RTCRtpSender>>::iterator RTCPeerConnection::FindSender(
    const RTCRtpSenderPlatform& web_sender) {
  return base::ranges::find_if(rtp_senders_, [&](const auto& sender) {
    return sender->web_sender()->Id() == web_sender.Id();
  });
}

HeapVector<Member<RTCRtpReceiver>>::iterator RTCPeerConnection::FindReceiver(
    const RTCRtpReceiverPlatform& platform_receiver) {
  return base::ranges::find_if(rtp_receivers_, [&](const auto& receiver) {
    return receiver->platform_receiver()->Id() == platform_receiver.Id();
  });
}

HeapVector<Member<RTCRtpTransceiver>>::iterator
RTCPeerConnection::FindTransceiver(
    const RTCRtpTransceiverPlatform& platform_transceiver) {
  return base::ranges::find_if(transceivers_, [&](const auto& transceiver) {
    return transceiver->platform_transceiver()->Id() ==
           platform_transceiver.Id();
  });
}

RTCRtpSender* RTCPeerConnection::CreateOrUpdateSender(
    std::unique_ptr<RTCRtpSenderPlatform> rtp_sender_platform,
    String kind) {
  // The track corresponding to |web_track| must already be known to us by being
  // in |tracks_|, as is a prerequisite of CreateOrUpdateSender().
  MediaStreamComponent* component = rtp_sender_platform->Track();
  MediaStreamTrack* track = nullptr;
  if (component) {
    track = tracks_.at(component);
    DCHECK(track);
  }

  // Create or update sender. If the web sender has stream IDs the sender's
  // streams need to be set separately outside of this method.
  auto sender_it = FindSender(*rtp_sender_platform);
  RTCRtpSender* sender;
  if (sender_it == rtp_senders_.end()) {
    // Create new sender (with empty stream set).
    sender = MakeGarbageCollected<RTCRtpSender>(
        this, std::move(rtp_sender_platform), kind, track, MediaStreamVector(),
        encoded_insertable_streams_,
        GetExecutionContext()->GetTaskRunner(TaskType::kInternalMedia));
    rtp_senders_.push_back(sender);
  } else {
    // Update existing sender (not touching the stream set).
    sender = *sender_it;
    DCHECK_EQ(sender->web_sender()->Id(), rtp_sender_platform->Id());
    sender->SetTrack(track);
  }
  sender->set_transport(CreateOrUpdateDtlsTransport(
      sender->web_sender()->DtlsTransport(),
      sender->web_sender()->DtlsTransportInformation()));
  return sender;
}

RTCRtpReceiver* RTCPeerConnection::CreateOrUpdateReceiver(
    std::unique_ptr<RTCRtpReceiverPlatform> platform_receiver) {
  auto receiver_it = FindReceiver(*platform_receiver);
  // Create track.
  MediaStreamTrack* track;
  if (receiver_it == rtp_receivers_.end()) {
    track = MakeGarbageCollected<MediaStreamTrackImpl>(
        GetExecutionContext(), platform_receiver->Track());
    RegisterTrack(track);
  } else {
    track = (*receiver_it)->track();
  }

  // Create or update receiver. If the web receiver has stream IDs the
  // receiver's streams need to be set separately outside of this method.
  RTCRtpReceiver* receiver;
  if (receiver_it == rtp_receivers_.end()) {
    // Create new receiver.
    receiver = MakeGarbageCollected<RTCRtpReceiver>(
        this, std::move(platform_receiver), track, MediaStreamVector(),
        encoded_insertable_streams_,
        GetExecutionContext()->GetTaskRunner(TaskType::kInternalMedia));
    // Receiving tracks should be muted by default. SetReadyState() propagates
    // the related state changes to ensure it is muted on all layers. It also
    // fires events - which is not desired - but because they fire synchronously
    // there are no listeners to detect this so this is indistinguishable from
    // having constructed the track in an already muted state.
    receiver->track()->Component()->Source()->SetReadyState(
        MediaStreamSource::kReadyStateMuted);
    rtp_receivers_.push_back(receiver);
  } else {
    // Update existing receiver is a no-op.
    receiver = *receiver_it;
    DCHECK_EQ(receiver->platform_receiver()->Id(), platform_receiver->Id());
    DCHECK_EQ(receiver->track(), track);  // Its track should never change.
  }
  receiver->set_transport(CreateOrUpdateDtlsTransport(
      receiver->platform_receiver()->DtlsTransport(),
      receiver->platform_receiver()->DtlsTransportInformation()));
  return receiver;
}

RTCRtpTransceiver* RTCPeerConnection::CreateOrUpdateTransceiver(
    std::unique_ptr<RTCRtpTransceiverPlatform> platform_transceiver) {
  String kind = (platform_transceiver->Receiver()->Track()->GetSourceType() ==
                 MediaStreamSource::kTypeAudio)
                    ? "audio"
                    : "video";
  RTCRtpSender* sender =
      CreateOrUpdateSender(platform_transceiver->Sender(), kind);
  RTCRtpReceiver* receiver =
      CreateOrUpdateReceiver(platform_transceiver->Receiver());

  RTCRtpTransceiver* transceiver;
  auto transceiver_it = FindTransceiver(*platform_transceiver);
  if (transceiver_it == transceivers_.end()) {
    // Create new tranceiver.
    transceiver = MakeGarbageCollected<RTCRtpTransceiver>(
        this, std::move(platform_transceiver), sender, receiver);
    transceivers_.push_back(transceiver);
  } else {
    // Update existing transceiver.
    transceiver = *transceiver_it;
    // The sender and receiver have already been updated above.
    DCHECK_EQ(transceiver->sender(), sender);
    DCHECK_EQ(transceiver->receiver(), receiver);
    transceiver->UpdateMembers();
  }
  return transceiver;
}

RTCDtlsTransport* RTCPeerConnection::CreateOrUpdateDtlsTransport(
    rtc::scoped_refptr<webrtc::DtlsTransportInterface> native_transport,
    const webrtc::DtlsTransportInformation& information) {
  if (!native_transport.get()) {
    return nullptr;
  }
  auto& transport = dtls_transports_by_native_transport_
                        .insert(native_transport.get(), nullptr)
                        .stored_value->value;
  if (!transport) {
    RTCIceTransport* ice_transport =
        CreateOrUpdateIceTransport(native_transport->ice_transport());
    transport = MakeGarbageCollected<RTCDtlsTransport>(
        GetExecutionContext(), std::move(native_transport), ice_transport);
  }
  transport->ChangeState(information);
  return transport.Get();
}

RTCIceTransport* RTCPeerConnection::CreateOrUpdateIceTransport(
    rtc::scoped_refptr<webrtc::IceTransportInterface> ice_transport) {
  if (!ice_transport.get()) {
    return nullptr;
  }
  auto& transport =
      ice_transports_by_native_transport_.insert(ice_transport.get(), nullptr)
          .stored_value->value;
  if (!transport) {
    transport = RTCIceTransport::Create(GetExecutionContext(),
                                        std::move(ice_transport), this);
  }
  return transport.Get();
}

RTCDTMFSender* RTCPeerConnection::createDTMFSender(
    MediaStreamTrack* track,
    ExceptionState& exception_state) {
  if (ThrowExceptionIfSignalingStateClosed(signaling_state_, &exception_state))
    return nullptr;
  if (track->kind() != "audio") {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "track.kind is not 'audio'.");
    return nullptr;
  }
  RTCRtpSender* found_rtp_sender = nullptr;
  for (const auto& rtp_sender : rtp_senders_) {
    if (rtp_sender->track() == track) {
      found_rtp_sender = rtp_sender;
      break;
    }
  }
  if (!found_rtp_sender) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "No RTCRtpSender is available for the track provided.");
    return nullptr;
  }
  RTCDTMFSender* dtmf_sender = found_rtp_sender->dtmf();
  if (!dtmf_sender) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Unable to create DTMF sender for track");
    return nullptr;
  }
  return dtmf_sender;
}

void RTCPeerConnection::close() {
  suppress_events_ = true;
  if (signaling_state_ ==
      webrtc::PeerConnectionInterface::SignalingState::kClosed) {
    return;
  }
  CloseInternal();
}

void RTCPeerConnection::RegisterTrack(MediaStreamTrack* track) {
  DCHECK(track);
  tracks_.insert(track->Component(), track);
}

void RTCPeerConnection::NoteSdpCreated(const RTCSessionDescriptionInit& desc) {
  if (desc.type() == "offer") {
    last_offer_ = desc.sdp();
  } else if (desc.type() == "answer") {
    last_answer_ = desc.sdp();
  }
}

void RTCPeerConnection::OnStreamAddTrack(MediaStream* stream,
                                         MediaStreamTrack* track,
                                         ExceptionState& exception_state) {
  MediaStreamVector streams;
  streams.push_back(stream);
  addTrack(track, streams, exception_state);
}

void RTCPeerConnection::OnStreamRemoveTrack(MediaStream* stream,
                                            MediaStreamTrack* track,
                                            ExceptionState& exception_state) {
  auto* sender = FindSenderForTrackAndStream(track, stream);
  if (sender) {
    removeTrack(sender, exception_state);
  }
}

void RTCPeerConnection::NegotiationNeeded() {
  DCHECK(!closed_);
  MaybeDispatchEvent(Event::Create(event_type_names::kNegotiationneeded));
}

void RTCPeerConnection::DidGenerateICECandidate(
    RTCIceCandidatePlatform* platform_candidate) {
  DCHECK(!closed_);
  DCHECK(GetExecutionContext()->IsContextThread());
  DCHECK(platform_candidate);
  RTCIceCandidate* ice_candidate = RTCIceCandidate::Create(platform_candidate);
  MaybeDispatchEvent(RTCPeerConnectionIceEvent::Create(ice_candidate));
}

void RTCPeerConnection::DidFailICECandidate(const String& address,
                                            std::optional<uint16_t> port,
                                            const String& host_candidate,
                                            const String& url,
                                            int error_code,
                                            const String& error_text) {
  DCHECK(!closed_);
  DCHECK(GetExecutionContext()->IsContextThread());
  MaybeDispatchEvent(RTCPeerConnectionIceErrorEvent::Create(
      address, port, host_candidate, url, error_code, error_text));
}

void RTCPeerConnection::DidChangeSessionDescriptions(
    RTCSessionDescriptionPlatform* pending_local_description,
    RTCSessionDescriptionPlatform* current_local_description,
    RTCSessionDescriptionPlatform* pending_remote_description,
    RTCSessionDescriptionPlatform* current_remote_description) {
  DCHECK(!closed_);
  DCHECK(GetExecutionContext()->IsContextThread());
  pending_local_description_ =
      pending_local_description
          ? RTCSessionDescription::Create(pending_local_description)
          : nullptr;
  current_local_description_ =
      current_local_description
          ? RTCSessionDescription::Create(current_local_description)
          : nullptr;
  pending_remote_description_ =
      pending_remote_description
          ? RTCSessionDescription::Create(pending_remote_description)
          : nullptr;
  current_remote_description_ =
      current_remote_description
          ? RTCSessionDescription::Create(current_remote_description)
          : nullptr;
}

void RTCPeerConnection::DidChangeIceGatheringState(
    webrtc::PeerConnectionInterface::IceGatheringState new_state) {
  DCHECK(!closed_);
  DCHECK(GetExecutionContext()->IsContextThread());
  ChangeIceGatheringState(new_state);
}

void RTCPeerConnection::DidChangePeerConnectionState(
    webrtc::PeerConnectionInterface::PeerConnectionState new_state) {
  DCHECK(!closed_);
  DCHECK(GetExecutionContext()->IsContextThread());
  ChangePeerConnectionState(new_state);
}

void RTCPeerConnection::DidModifySctpTransport(
    WebRTCSctpTransportSnapshot snapshot) {
  if (!snapshot.transport) {
    sctp_transport_ = nullptr;
    return;
  }
  if (!sctp_transport_ ||
      sctp_transport_->native_transport() != snapshot.transport) {
    sctp_transport_ = MakeGarbageCollected<RTCSctpTransport>(
        GetExecutionContext(), snapshot.transport);
  }
  if (!sctp_transport_->transport() ||
      sctp_transport_->transport()->native_transport() !=
          snapshot.sctp_transport_state.dtls_transport()) {
    sctp_transport_->SetTransport(CreateOrUpdateDtlsTransport(
        snapshot.sctp_transport_state.dtls_transport(),
        snapshot.dtls_transport_state));
  }
  sctp_transport_->ChangeState(snapshot.sctp_transport_state);
}

void RTCPeerConnection::DidModifyTransceivers(
    webrtc::PeerConnectionInterface::SignalingState signaling_state,
    Vector<std::unique_ptr<RTCRtpTransceiverPlatform>> platform_transceivers,
    Vector<uintptr_t> removed_transceiver_ids,
    bool is_remote_description_or_rollback) {
  HeapVector<Member<MediaStreamTrack>> mute_tracks;
  HeapVector<std::pair<Member<MediaStream>, Member<MediaStreamTrack>>>
      remove_list;
  HeapVector<std::pair<Member<MediaStream>, Member<MediaStreamTrack>>> add_list;
  HeapVe
```