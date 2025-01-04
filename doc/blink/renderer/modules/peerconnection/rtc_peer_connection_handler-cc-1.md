Response:
The user wants to understand the functionality of the provided C++ code snippet from `rtc_peer_connection_handler.cc`. This is part 2 of 3. The request has several constraints:

1. **List functionalities:** Identify the main purposes of the code.
2. **Relate to web technologies:** Explain how the C++ code interacts with JavaScript, HTML, and CSS. Provide examples if applicable.
3. **Logical reasoning:**  If any part of the code involves conditional logic or decision-making, illustrate with hypothetical inputs and outputs.
4. **Common errors:** Point out potential mistakes users or programmers might make when interacting with this code.
5. **User operation to reach here:** Describe a sequence of user actions that could lead to the execution of this specific code.
6. **Part 2 summarization:**  Concisely summarize the functionality of this specific code block.

Let's break down the code section by section:

* **`_implicit_rollback = true;`**: This seems to be a configuration flag, possibly related to session description handling.
* **`configuration_.pacer_burst_interval = ...;`**: Sets a pacing parameter for sending data.
* **`configuration_.set_stats_timestamp_with_environment_clock(true);`**: Configures how timestamps for statistics are generated.
* **`peer_connection_observer_ = ...;`**: Creates an observer object to handle events from the underlying WebRTC implementation.
* **`native_peer_connection_ = ...;`**:  The core part - creates the actual WebRTC peer connection object using a dependency factory. Error handling is present.
* **`signaling_thread_ = ...;`**: Retrieves the task runner for the signaling thread, crucial for WebRTC's asynchronous operations.
* **`peer_connection_observer_->Initialize(signaling_thread_);`**: Initializes the observer with the signaling thread.
* **`peer_connection_tracker_->RegisterPeerConnection(...)`**: Registers this connection with a tracker for debugging and monitoring.
* **`return !!client_on_stack;`**:  A seemingly unrelated return statement, likely related to the context where this function is called.

* **`InitializeForTest(...)`**: A separate initialization function specifically for testing purposes. It takes a configuration and a tracker as input.

* **`CreateOffer(...)`**:  This function is responsible for initiating the SDP offer creation process. It interacts with JavaScript via callbacks and handles options for the offer.
* **`CreateOfferOnSignalingThread(...)`**: This is the signaling thread counterpart of `CreateOffer`, where the actual WebRTC API call to create the offer happens. It populates the `transceiver_state_surfacer`.

* **`CreateAnswer(...)`**: Similar to `CreateOffer`, but for creating an SDP answer. It takes a request and options.

* **`IsOfferOrAnswer(...)`**: A helper function to check if a session description is an offer or an answer.

* **`SetLocalDescription(...)` (two overloads)**: These functions handle setting the local session description. One takes a pre-parsed description, the other triggers implicit generation. They involve asynchronous operations on the signaling thread.

* **`SetRemoteDescription(...)`**: Handles setting the remote session description, also involving asynchronous operations and parsing.

* **`GetConfiguration()`**: Returns the current peer connection configuration.

* **`SetConfiguration(...)`**: Allows updating the peer connection configuration.

* **`AddIceCandidate(...)`**:  Adds an ICE candidate received from the remote peer. This involves asynchronous handling and callbacks.

* **`RestartIce()`**: Triggers an ICE restart.

* **`GetStandardStatsForTracker(...)`**:  Collects statistics for internal tracking.

* **`EmitCurrentStateForTracker()`**:  Sends the current state of the peer connection to the tracker.

* **`GetStats(...)`**: Retrieves detailed statistics about the connection and its components. This is an asynchronous operation.

* **`AddTransceiverWithTrack(...)`**: Adds a transceiver (for sending or receiving media) associated with an existing media track.

* **`AddTransceiverWithTrackOnSignalingThread(...)`**: The signaling thread implementation of `AddTransceiverWithTrack`.

* **`AddTransceiverWithKind(...)`**: Adds a transceiver based on the media kind (audio or video) without a pre-existing track.

* **`AddTransceiverWithMediaTypeOnSignalingThread(...)`**: The signaling thread implementation of `AddTransceiverWithKind`.

* **`AddTrack(...)`**: Adds a media track to the peer connection. This might involve creating a new transceiver.

* **`AddTrackOnSignalingThread(...)`**: The signaling thread implementation of `AddTrack`.

* **`RemoveTrack(...)`**: Removes a media track from the peer connection.

* **`RemoveTrackOnSignalingThread(...)`**: The signaling thread implementation of `RemoveTrack`.

**Part 2 Summary:** This section of `RTCPeerConnectionHandler.cc` primarily focuses on the core functionalities of establishing and managing a WebRTC peer connection. It includes initialization routines, methods for creating and setting session descriptions (offer/answer), adding and removing ICE candidates, re-starting ICE, retrieving statistics, and adding/removing media tracks and transceivers. A key aspect is the use of a separate signaling thread for many of these operations, ensuring thread safety and proper interaction with the underlying WebRTC implementation. It also includes mechanisms for tracking and debugging the peer connection's state.
这是`blink/renderer/modules/peerconnection/rtc_peer_connection_handler.cc`文件的第二部分代码，主要负责以下功能：

**核心功能：管理 WebRTC PeerConnection 的生命周期和状态，并提供与本地和远程对等端交互的接口。**

**具体功能归纳：**

1. **初始化 PeerConnection 对象：**
   - `Initialize()`:  初始化本地 PeerConnection 对象，包括配置 pacer、设置统计时间戳、创建观察者对象、创建底层的 `native_peer_connection_` 对象，并获取 signaling 线程。
   - `InitializeForTest()`: 提供用于测试的初始化方法，允许传入自定义的配置和 tracker。

2. **创建和处理 SDP (Session Description Protocol)：**
   - `CreateOffer()`:  生成本地的 SDP offer。它会调用底层的 WebRTC API 在 signaling 线程上执行。此方法还会处理 RTCRtpTransceiver 的状态更新。
   - `CreateOfferOnSignalingThread()`: 在 signaling 线程上实际调用 WebRTC 的 `CreateOffer` 方法。
   - `CreateAnswer()`: 生成本地的 SDP answer，响应远程的 offer。
   - `IsOfferOrAnswer()`:  辅助函数，判断给定的 SessionDescription 是否为 offer 或 answer 类型。
   - `SetLocalDescription()`: 设置本地的 SDP 描述。有两个重载版本，一个接受已解析的 SDP，另一个用于隐式设置（通常用于 rollback）。该操作会在 signaling 线程上执行。
   - `SetRemoteDescription()`: 设置远程的 SDP 描述。该操作会在 signaling 线程上执行。

3. **配置 PeerConnection：**
   - `GetConfiguration()`: 获取当前的 PeerConnection 配置。
   - `SetConfiguration()`:  更新 PeerConnection 的配置，例如服务器信息、ICE 配置等。

4. **处理 ICE (Interactive Connectivity Establishment) 候选者：**
   - `AddIceCandidate()`:  添加从远程对等端接收到的 ICE 候选者。该操作会将候选者传递到 signaling 线程进行处理，并更新会话描述。
   - `RestartIce()`: 触发 ICE 重启，用于处理网络变化或 NAT traversal 问题。

5. **获取和报告统计信息：**
   - `GetStandardStatsForTracker()`:  获取标准的统计信息用于内部跟踪。
   - `EmitCurrentStateForTracker()`:  将当前的 PeerConnection 状态（如 signaling 状态、ICE 连接状态等）发送到 tracker 进行监控。
   - `GetStats()`:  获取详细的连接统计信息，该操作在 signaling 线程上执行。

6. **管理 RTP Transceiver (用于发送和接收媒体)：**
   - `AddTransceiverWithTrack()`:  添加一个新的 RTP transceiver，关联到一个已有的媒体轨道。
   - `AddTransceiverWithTrackOnSignalingThread()`: 在 signaling 线程上执行 `AddTransceiverWithTrack` 的实际操作。
   - `AddTransceiverWithKind()`: 添加一个新的 RTP transceiver，根据媒体类型（audio 或 video）创建，不依赖于已有的媒体轨道。
   - `AddTransceiverWithMediaTypeOnSignalingThread()`: 在 signaling 线程上执行 `AddTransceiverWithKind` 的实际操作。
   - `AddTrack()`:  向 PeerConnection 添加一个媒体轨道。这可能会创建一个新的 transceiver。
   - `AddTrackOnSignalingThread()`: 在 signaling 线程上执行 `AddTrack` 的实际操作。
   - `RemoveTrack()`: 从 PeerConnection 移除一个媒体轨道。
   - `RemoveTrackOnSignalingThread()`: 在 signaling 线程上执行 `RemoveTrack` 的实际操作。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 文件是 Chromium Blink 引擎的一部分，负责 WebRTC 功能的底层实现。它通过 JavaScript API 暴露功能，供 Web 开发者使用。

* **JavaScript:**  JavaScript 代码通过 `RTCPeerConnection` API 与这个 C++ 代码交互。例如：
    * 当 JavaScript 调用 `pc.createOffer()` 时，最终会调用到 C++ 的 `RTCPeerConnectionHandler::CreateOffer()`。
    * 当 JavaScript 调用 `pc.setLocalDescription(offer)` 或 `pc.setRemoteDescription(answer)` 时，会分别调用到 C++ 的 `RTCPeerConnectionHandler::SetLocalDescription()` 和 `RTCPeerConnectionHandler::SetRemoteDescription()`。
    * 当 JavaScript 调用 `pc.addIceCandidate(candidate)` 时，会调用到 C++ 的 `RTCPeerConnectionHandler::AddIceCandidate()`。
    * 当 JavaScript 调用 `pc.addTrack(mediaStreamTrack, ...)` 或 `pc.addTransceiver(...)` 时，会调用到 C++ 相应的 `AddTrack` 和 `AddTransceiver` 方法。
    * 当 JavaScript 调用 `pc.getStats()` 时，会调用到 C++ 的 `RTCPeerConnectionHandler::GetStats()`。

* **HTML:** HTML 主要用于构建网页结构，包含 JavaScript 代码，并可能包含 `<video>` 或 `<audio>` 标签来显示或播放媒体流。这个 C++ 代码不直接操作 HTML 元素，但它的功能支持了通过 JavaScript 将媒体流渲染到这些 HTML 元素上。

* **CSS:** CSS 用于控制网页的样式。这个 C++ 代码与 CSS 没有直接关系，但 CSS 可以用于控制 `<video>` 和 `<audio>` 元素的显示效果。

**逻辑推理示例：**

**假设输入 (在 JavaScript 中):**

```javascript
const pc = new RTCPeerConnection();
const offerOptions = {
  offerToReceiveAudio: true,
  offerToReceiveVideo: false,
  iceRestart: true
};
pc.createOffer(offerOptions)
  .then(offer => {
    // ...
  });
```

**C++ 中的逻辑推理 (简化):**

在 `RTCPeerConnectionHandler::CreateOffer()` 中，会根据 `offerOptions` 创建 `webrtc::PeerConnectionInterface::RTCOfferAnswerOptions` 对象。

```c++
  webrtc::PeerConnectionInterface::RTCOfferAnswerOptions webrtc_options;
  if (options) {
    webrtc_options.offer_to_receive_audio = options->OfferToReceiveAudio(); // true
    webrtc_options.offer_to_receive_video = options->OfferToReceiveVideo(); // false
    webrtc_options.voice_activity_detection = options->VoiceActivityDetection(); // 默认值
    webrtc_options.ice_restart = options->IceRestart(); // true
  }
```

**输出 (最终 SDP 中的部分内容):**

生成的 SDP offer 中会包含请求接收音频的 media description (`m=audio ...`)，但不包含请求接收视频的 media description。`ice-options: ... restart-ice` 属性会表明这是一个 ICE restart 的 offer。

**用户或编程常见的使用错误：**

1. **在错误的线程上调用 PeerConnection 的方法：** 大部分操作需要在特定的线程上执行（例如，很多操作需要在 signaling 线程上）。直接从非 UI 线程或 worker 线程调用可能会导致崩溃或未定义的行为。
   * **示例:** 在一个异步回调函数中，忘记使用 `PostTask` 将操作调度到主线程或 signaling 线程。

2. **设置 SDP 描述的顺序错误：** 必须先设置本地描述，然后才能设置远程描述。设置顺序错误会导致连接失败。
   * **示例:** 在 offer 创建完成之前就尝试设置远程描述。

3. **ICE 协商失败：** 网络配置问题（例如防火墙阻止 UDP 流量）可能导致 ICE 协商失败，最终导致连接无法建立。
   * **示例:** 用户在一个受限的网络环境中尝试建立 WebRTC 连接，但没有配置 STUN/TURN 服务器。

4. **添加 ICE 候选者的时机不正确：**  必须在调用 `setRemoteDescription()` 之后，但在 ICE 协商完成之前添加接收到的 ICE 候选者。
   * **示例:** 在 `setRemoteDescription()` 之前就尝试添加远程 ICE 候选者。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户打开一个网页，该网页使用了 WebRTC 技术。**
2. **网页中的 JavaScript 代码创建了一个 `RTCPeerConnection` 对象。**
3. **JavaScript 代码调用 `pc.createOffer()` 方法，希望与远程对等端建立连接或协商媒体会话。**  这个调用会触发 C++ 中 `RTCPeerConnectionHandler::CreateOffer()` 的执行。
4. **（或者）JavaScript 代码接收到来自远程对等端的 SDP offer，并调用 `pc.setRemoteDescription(remoteOffer)` 方法。** 这会触发 C++ 中 `RTCPeerConnectionHandler::SetRemoteDescription()` 的执行。
5. **（或者）JavaScript 代码接收到来自远程对等端的 ICE 候选者，并调用 `pc.addIceCandidate(remoteCandidate)` 方法。** 这会触发 C++ 中 `RTCPeerConnectionHandler::AddIceCandidate()` 的执行。
6. **在这些过程中，如果需要更新本地配置，JavaScript 代码可能会调用 `pc.setConfiguration(config)`。** 这会触发 C++ 中 `RTCPeerConnectionHandler::SetConfiguration()` 的执行。
7. **为了发送本地媒体，JavaScript 代码可能会调用 `pc.addTrack(localStream.getVideoTracks()[0], localStream)`。** 这会触发 C++ 中 `RTCPeerConnectionHandler::AddTrack()` 的执行。
8. **为了获取连接状态或统计信息，JavaScript 代码可能会调用 `pc.getStats()`。** 这会触发 C++ 中 `RTCPeerConnectionHandler::GetStats()` 的执行。

这些用户操作会在 JavaScript 层调用 WebRTC API，这些 API 调用最终会映射到 `rtc_peer_connection_handler.cc` 中的相应 C++ 方法。通过查看 Chrome 的 `chrome://webrtc-internals` 页面，开发者可以追踪这些 API 调用和 PeerConnection 的状态变化，从而帮助调试问题。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_peer_connection_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
_implicit_rollback = true;

  // Apply 40 ms worth of bursting. See webrtc::TaskQueuePacedSender.
  configuration_.pacer_burst_interval = webrtc::TimeDelta::Millis(40);

  configuration_.set_stats_timestamp_with_environment_clock(true);

  peer_connection_observer_ =
      MakeGarbageCollected<Observer>(weak_factory_.GetWeakPtr(), task_runner_);
  native_peer_connection_ = dependency_factory_->CreatePeerConnection(
      configuration_, frame_, peer_connection_observer_, exception_state,
      rtp_transport);
  if (!native_peer_connection_.get()) {
    LOG(ERROR) << "Failed to initialize native PeerConnection.";
    return false;
  }
  // Now the signaling thread exists.
  signaling_thread_ = dependency_factory_->GetWebRtcSignalingTaskRunner();
  peer_connection_observer_->Initialize(signaling_thread_);

  if (peer_connection_tracker_) {
    peer_connection_tracker_->RegisterPeerConnection(this, configuration_,
                                                     frame_);
  }
  // Gratuitous usage of client_on_stack to prevent compiler errors.
  return !!client_on_stack;
}

bool RTCPeerConnectionHandler::InitializeForTest(
    const webrtc::PeerConnectionInterface::RTCConfiguration&
        server_configuration,
    PeerConnectionTracker* peer_connection_tracker,
    ExceptionState& exception_state,
    RTCRtpTransport* rtp_transport) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  DCHECK(dependency_factory_);

  CHECK(!initialize_called_);
  initialize_called_ = true;

  configuration_ = server_configuration;

  peer_connection_observer_ =
      MakeGarbageCollected<Observer>(weak_factory_.GetWeakPtr(), task_runner_);

  native_peer_connection_ = dependency_factory_->CreatePeerConnection(
      configuration_, nullptr, peer_connection_observer_, exception_state,
      rtp_transport);
  if (!native_peer_connection_.get()) {
    LOG(ERROR) << "Failed to initialize native PeerConnection.";
    return false;
  }
  // Now the signaling thread exists.
  signaling_thread_ = dependency_factory_->GetWebRtcSignalingTaskRunner();
  peer_connection_observer_->Initialize(signaling_thread_);
  peer_connection_tracker_ = peer_connection_tracker;
  return true;
}

Vector<std::unique_ptr<RTCRtpTransceiverPlatform>>
RTCPeerConnectionHandler::CreateOffer(RTCSessionDescriptionRequest* request,
                                      RTCOfferOptionsPlatform* options) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::createOffer");

  if (peer_connection_tracker_)
    peer_connection_tracker_->TrackCreateOffer(this, options);

  webrtc::PeerConnectionInterface::RTCOfferAnswerOptions webrtc_options;
  if (options) {
    webrtc_options.offer_to_receive_audio = options->OfferToReceiveAudio();
    webrtc_options.offer_to_receive_video = options->OfferToReceiveVideo();
    webrtc_options.voice_activity_detection = options->VoiceActivityDetection();
    webrtc_options.ice_restart = options->IceRestart();
  }

  scoped_refptr<CreateSessionDescriptionRequest> description_request(
      new rtc::RefCountedObject<CreateSessionDescriptionRequest>(
          task_runner_, request, weak_factory_.GetWeakPtr(),
          peer_connection_tracker_, PeerConnectionTracker::kActionCreateOffer));

  blink::TransceiverStateSurfacer transceiver_state_surfacer(
      task_runner_, signaling_thread());
  RunSynchronousOnceClosureOnSignalingThread(
      base::BindOnce(&RTCPeerConnectionHandler::CreateOfferOnSignalingThread,
                     base::Unretained(this),
                     base::Unretained(description_request.get()),
                     std::move(webrtc_options),
                     base::Unretained(&transceiver_state_surfacer)),
      "CreateOfferOnSignalingThread");
  DCHECK(transceiver_state_surfacer.is_initialized());

  auto transceiver_states = transceiver_state_surfacer.ObtainStates();
  Vector<std::unique_ptr<RTCRtpTransceiverPlatform>> transceivers;
  for (auto& transceiver_state : transceiver_states) {
    auto transceiver = CreateOrUpdateTransceiver(
        std::move(transceiver_state), blink::TransceiverStateUpdateMode::kAll);
    transceivers.push_back(std::move(transceiver));
  }
  return transceivers;
}

void RTCPeerConnectionHandler::CreateOfferOnSignalingThread(
    webrtc::CreateSessionDescriptionObserver* observer,
    webrtc::PeerConnectionInterface::RTCOfferAnswerOptions offer_options,
    blink::TransceiverStateSurfacer* transceiver_state_surfacer) {
  native_peer_connection_->CreateOffer(observer, offer_options);
  std::vector<rtc::scoped_refptr<webrtc::RtpTransceiverInterface>>
      transceivers = native_peer_connection_->GetTransceivers();
  transceiver_state_surfacer->Initialize(
      native_peer_connection_, track_adapter_map_, std::move(transceivers));
}

void RTCPeerConnectionHandler::CreateAnswer(
    blink::RTCSessionDescriptionRequest* request,
    blink::RTCAnswerOptionsPlatform* options) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::createAnswer");
  scoped_refptr<CreateSessionDescriptionRequest> description_request(
      new rtc::RefCountedObject<CreateSessionDescriptionRequest>(
          task_runner_, request, weak_factory_.GetWeakPtr(),
          peer_connection_tracker_,
          PeerConnectionTracker::kActionCreateAnswer));
  // TODO(tommi): Do this asynchronously via e.g. PostTaskAndReply.
  webrtc::PeerConnectionInterface::RTCOfferAnswerOptions webrtc_options;
  if (options) {
    webrtc_options.voice_activity_detection = options->VoiceActivityDetection();
  }
  native_peer_connection_->CreateAnswer(description_request.get(),
                                        webrtc_options);

  if (peer_connection_tracker_)
    peer_connection_tracker_->TrackCreateAnswer(this, options);
}

bool IsOfferOrAnswer(const webrtc::SessionDescriptionInterface* native_desc) {
  DCHECK(native_desc);
  return native_desc->type() == "offer" || native_desc->type() == "answer";
}

void RTCPeerConnectionHandler::SetLocalDescription(
    blink::RTCVoidRequest* request) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::setLocalDescription");

  if (peer_connection_tracker_)
    peer_connection_tracker_->TrackSetSessionDescriptionImplicit(this);

  scoped_refptr<WebRtcSetDescriptionObserverImpl> content_observer =
      base::MakeRefCounted<WebRtcSetDescriptionObserverImpl>(
          weak_factory_.GetWeakPtr(), request, peer_connection_tracker_,
          task_runner_,
          PeerConnectionTracker::kActionSetLocalDescriptionImplicit,
          /*is_rollback=*/true);

  rtc::scoped_refptr<webrtc::SetLocalDescriptionObserverInterface>
      webrtc_observer(WebRtcSetLocalDescriptionObserverHandler::Create(
                          task_runner_, signaling_thread(),
                          native_peer_connection_, track_adapter_map_,
                          content_observer)
                          .get());

  PostCrossThreadTask(
      *signaling_thread().get(), FROM_HERE,
      CrossThreadBindOnce(
          &RunClosureWithTrace,
          CrossThreadBindOnce(
              static_cast<void (webrtc::PeerConnectionInterface::*)(
                  rtc::scoped_refptr<
                      webrtc::SetLocalDescriptionObserverInterface>)>(
                  &webrtc::PeerConnectionInterface::SetLocalDescription),
              native_peer_connection_, webrtc_observer),
          CrossThreadUnretained("SetLocalDescription")));
}

void RTCPeerConnectionHandler::SetLocalDescription(
    blink::RTCVoidRequest* request,
    ParsedSessionDescription parsed_sdp) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::setLocalDescription");

  String sdp = parsed_sdp.sdp();
  String type = parsed_sdp.type();

  if (peer_connection_tracker_) {
    peer_connection_tracker_->TrackSetSessionDescription(
        this, sdp, type, PeerConnectionTracker::kSourceLocal);
  }

  const webrtc::SessionDescriptionInterface* native_desc =
      parsed_sdp.description();
  if (!native_desc) {
    webrtc::SdpParseError error(parsed_sdp.error());
    StringBuilder reason_str;
    reason_str.Append("Failed to parse SessionDescription. ");
    reason_str.Append(error.line.c_str());
    reason_str.Append(" ");
    reason_str.Append(error.description.c_str());
    LOG(ERROR) << reason_str.ToString();
    if (peer_connection_tracker_) {
      peer_connection_tracker_->TrackSessionDescriptionCallback(
          this, PeerConnectionTracker::kActionSetLocalDescription, "OnFailure",
          reason_str.ToString());
    }
    // Warning: this line triggers the error callback to be executed, causing
    // arbitrary JavaScript to be executed synchronously. As a result, it is
    // possible for |this| to be deleted after this line. See
    // https://crbug.com/1005251.
    if (request) {
      request->RequestFailed(webrtc::RTCError(
          webrtc::RTCErrorType::INTERNAL_ERROR, reason_str.ToString().Utf8()));
    }
    return;
  }

  if (!first_local_description_ && IsOfferOrAnswer(native_desc)) {
    first_local_description_ =
        std::make_unique<FirstSessionDescription>(native_desc);
    if (first_remote_description_) {
      ReportFirstSessionDescriptions(*first_local_description_,
                                     *first_remote_description_);
    }
  }

  scoped_refptr<WebRtcSetDescriptionObserverImpl> content_observer =
      base::MakeRefCounted<WebRtcSetDescriptionObserverImpl>(
          weak_factory_.GetWeakPtr(), request, peer_connection_tracker_,
          task_runner_, PeerConnectionTracker::kActionSetLocalDescription,
          type == "rollback");

  rtc::scoped_refptr<webrtc::SetLocalDescriptionObserverInterface>
      webrtc_observer(WebRtcSetLocalDescriptionObserverHandler::Create(
                          task_runner_, signaling_thread(),
                          native_peer_connection_, track_adapter_map_,
                          content_observer)
                          .get());

  PostCrossThreadTask(
      *signaling_thread().get(), FROM_HERE,
      CrossThreadBindOnce(
          &RunClosureWithTrace,
          CrossThreadBindOnce(
              static_cast<void (webrtc::PeerConnectionInterface::*)(
                  std::unique_ptr<webrtc::SessionDescriptionInterface>,
                  rtc::scoped_refptr<
                      webrtc::SetLocalDescriptionObserverInterface>)>(
                  &webrtc::PeerConnectionInterface::SetLocalDescription),
              native_peer_connection_, parsed_sdp.release(), webrtc_observer),
          CrossThreadUnretained("SetLocalDescription")));
}

void RTCPeerConnectionHandler::SetRemoteDescription(
    blink::RTCVoidRequest* request,
    ParsedSessionDescription parsed_sdp) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::setRemoteDescription");

  String sdp = parsed_sdp.sdp();
  String type = parsed_sdp.type();

  if (peer_connection_tracker_) {
    peer_connection_tracker_->TrackSetSessionDescription(
        this, sdp, type, PeerConnectionTracker::kSourceRemote);
  }

  webrtc::SdpParseError error(parsed_sdp.error());
  const webrtc::SessionDescriptionInterface* native_desc =
      parsed_sdp.description();
  if (!native_desc) {
    StringBuilder reason_str;
    reason_str.Append("Failed to parse SessionDescription. ");
    reason_str.Append(error.line.c_str());
    reason_str.Append(" ");
    reason_str.Append(error.description.c_str());
    LOG(ERROR) << reason_str.ToString();
    if (peer_connection_tracker_) {
      peer_connection_tracker_->TrackSessionDescriptionCallback(
          this, PeerConnectionTracker::kActionSetRemoteDescription, "OnFailure",
          reason_str.ToString());
    }
    // Warning: this line triggers the error callback to be executed, causing
    // arbitrary JavaScript to be executed synchronously. As a result, it is
    // possible for |this| to be deleted after this line. See
    // https://crbug.com/1005251.
    if (request) {
      request->RequestFailed(
          webrtc::RTCError(webrtc::RTCErrorType::UNSUPPORTED_OPERATION,
                           reason_str.ToString().Utf8()));
    }
    return;
  }

  if (!first_remote_description_ && IsOfferOrAnswer(native_desc)) {
    first_remote_description_ =
        std::make_unique<FirstSessionDescription>(native_desc);
    if (first_local_description_) {
      ReportFirstSessionDescriptions(*first_local_description_,
                                     *first_remote_description_);
    }
  }

  scoped_refptr<WebRtcSetDescriptionObserverImpl> content_observer =
      base::MakeRefCounted<WebRtcSetDescriptionObserverImpl>(
          weak_factory_.GetWeakPtr(), request, peer_connection_tracker_,
          task_runner_, PeerConnectionTracker::kActionSetRemoteDescription,
          type == "rollback");

  rtc::scoped_refptr<webrtc::SetRemoteDescriptionObserverInterface>
      webrtc_observer(WebRtcSetRemoteDescriptionObserverHandler::Create(
                          task_runner_, signaling_thread(),
                          native_peer_connection_, track_adapter_map_,
                          content_observer)
                          .get());

  PostCrossThreadTask(
      *signaling_thread().get(), FROM_HERE,
      CrossThreadBindOnce(
          &RunClosureWithTrace,
          CrossThreadBindOnce(
              static_cast<void (webrtc::PeerConnectionInterface::*)(
                  std::unique_ptr<webrtc::SessionDescriptionInterface>,
                  rtc::scoped_refptr<
                      webrtc::SetRemoteDescriptionObserverInterface>)>(
                  &webrtc::PeerConnectionInterface::SetRemoteDescription),
              native_peer_connection_, parsed_sdp.release(), webrtc_observer),
          CrossThreadUnretained("SetRemoteDescription")));
}

const webrtc::PeerConnectionInterface::RTCConfiguration&
RTCPeerConnectionHandler::GetConfiguration() const {
  return configuration_;
}

webrtc::RTCErrorType RTCPeerConnectionHandler::SetConfiguration(
    const webrtc::PeerConnectionInterface::RTCConfiguration& blink_config) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::setConfiguration");

  // Update the configuration with the potentially modified fields
  webrtc::PeerConnectionInterface::RTCConfiguration new_configuration =
      configuration_;
  new_configuration.servers = blink_config.servers;
  new_configuration.type = blink_config.type;
  new_configuration.bundle_policy = blink_config.bundle_policy;
  new_configuration.rtcp_mux_policy = blink_config.rtcp_mux_policy;
  new_configuration.certificates = blink_config.certificates;
  new_configuration.ice_candidate_pool_size =
      blink_config.ice_candidate_pool_size;

  if (peer_connection_tracker_)
    peer_connection_tracker_->TrackSetConfiguration(this, new_configuration);

  webrtc::RTCError webrtc_error =
      native_peer_connection_->SetConfiguration(new_configuration);
  if (webrtc_error.ok()) {
    configuration_ = new_configuration;
  }

  return webrtc_error.type();
}

void RTCPeerConnectionHandler::AddIceCandidate(
    RTCVoidRequest* request,
    RTCIceCandidatePlatform* candidate) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  DCHECK(dependency_factory_);
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::addIceCandidate");
  std::unique_ptr<webrtc::IceCandidateInterface> native_candidate(
      dependency_factory_->CreateIceCandidate(
          candidate->SdpMid(),
          candidate->SdpMLineIndex()
              ? static_cast<int>(*candidate->SdpMLineIndex())
              : -1,
          candidate->Candidate()));

  auto callback_on_task_runner =
      [](base::WeakPtr<RTCPeerConnectionHandler> handler_weak_ptr,
         CrossThreadPersistent<PeerConnectionTracker> tracker_ptr,
         std::unique_ptr<webrtc::SessionDescriptionInterface>
             pending_local_description,
         std::unique_ptr<webrtc::SessionDescriptionInterface>
             current_local_description,
         std::unique_ptr<webrtc::SessionDescriptionInterface>
             pending_remote_description,
         std::unique_ptr<webrtc::SessionDescriptionInterface>
             current_remote_description,
         CrossThreadPersistent<RTCIceCandidatePlatform> candidate,
         webrtc::RTCError result, RTCVoidRequest* request) {
        // Inform tracker (chrome://webrtc-internals).
        // Note that because the WTF::CrossThreadBindOnce() below uses a
        // CrossThreadWeakPersistent when binding |tracker_ptr| this lambda may
        // be invoked with a null |tracker_ptr| so we have to guard against it.
        if (handler_weak_ptr && tracker_ptr) {
          tracker_ptr->TrackAddIceCandidate(
              handler_weak_ptr.get(), candidate,
              PeerConnectionTracker::kSourceRemote, result.ok());
        }
        // Update session descriptions.
        if (handler_weak_ptr) {
          handler_weak_ptr->OnSessionDescriptionsUpdated(
              std::move(pending_local_description),
              std::move(current_local_description),
              std::move(pending_remote_description),
              std::move(current_remote_description));
        }
        // Resolve promise.
        if (result.ok())
          request->RequestSucceeded();
        else
          request->RequestFailed(result);
      };

  native_peer_connection_->AddIceCandidate(
      std::move(native_candidate),
      [pc = native_peer_connection_, task_runner = task_runner_,
       handler_weak_ptr = weak_factory_.GetWeakPtr(),
       tracker_weak_ptr =
           WrapCrossThreadWeakPersistent(peer_connection_tracker_.Get()),
       persistent_candidate = WrapCrossThreadPersistent(candidate),
       persistent_request = WrapCrossThreadPersistent(request),
       callback_on_task_runner =
           std::move(callback_on_task_runner)](webrtc::RTCError result) {
        // Grab a snapshot of all the session descriptions. AddIceCandidate may
        // have modified the remote description.
        std::unique_ptr<webrtc::SessionDescriptionInterface>
            pending_local_description =
                CopySessionDescription(pc->pending_local_description());
        std::unique_ptr<webrtc::SessionDescriptionInterface>
            current_local_description =
                CopySessionDescription(pc->current_local_description());
        std::unique_ptr<webrtc::SessionDescriptionInterface>
            pending_remote_description =
                CopySessionDescription(pc->pending_remote_description());
        std::unique_ptr<webrtc::SessionDescriptionInterface>
            current_remote_description =
                CopySessionDescription(pc->current_remote_description());
        // This callback is invoked on the webrtc signaling thread (this is true
        // in production, not in rtc_peer_connection_handler_test.cc which uses
        // a fake |native_peer_connection_|). Jump back to the renderer thread.
        PostCrossThreadTask(
            *task_runner, FROM_HERE,
            WTF::CrossThreadBindOnce(
                std::move(callback_on_task_runner), handler_weak_ptr,
                tracker_weak_ptr, std::move(pending_local_description),
                std::move(current_local_description),
                std::move(pending_remote_description),
                std::move(current_remote_description),
                std::move(persistent_candidate), std::move(result),
                std::move(persistent_request)));
      });
}

void RTCPeerConnectionHandler::RestartIce() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  // The proxy invokes RestartIce() on the signaling thread.
  native_peer_connection_->RestartIce();
}

void RTCPeerConnectionHandler::GetStandardStatsForTracker(
    rtc::scoped_refptr<webrtc::RTCStatsCollectorCallback> observer) {
  native_peer_connection_->GetStats(observer.get());
}

void RTCPeerConnectionHandler::EmitCurrentStateForTracker() {
  if (!peer_connection_tracker_) {
    return;
  }
  RTC_DCHECK(native_peer_connection_);
  const webrtc::SessionDescriptionInterface* local_desc =
      native_peer_connection_->local_description();
  // If the local desc is an answer, emit it after the offer.
  if (local_desc != nullptr &&
      local_desc->GetType() == webrtc::SdpType::kOffer) {
    std::string local_sdp;
    if (local_desc->ToString(&local_sdp)) {
      peer_connection_tracker_->TrackSetSessionDescription(
          this, String(local_sdp),
          String(SdpTypeToString(local_desc->GetType())),
          PeerConnectionTracker::kSourceLocal);
    }
  }
  const webrtc::SessionDescriptionInterface* remote_desc =
      native_peer_connection_->remote_description();
  if (remote_desc != nullptr) {
    std::string remote_sdp;
    if (remote_desc->ToString(&remote_sdp)) {
      peer_connection_tracker_->TrackSetSessionDescription(
          this, String(remote_sdp),
          String(SdpTypeToString(remote_desc->GetType())),
          PeerConnectionTracker::kSourceRemote);
    }
  }

  if (local_desc != nullptr &&
      local_desc->GetType() != webrtc::SdpType::kOffer) {
    std::string local_sdp;
    if (local_desc->ToString(&local_sdp)) {
      peer_connection_tracker_->TrackSetSessionDescription(
          this, String(local_sdp),
          String(SdpTypeToString(local_desc->GetType())),
          PeerConnectionTracker::kSourceLocal);
    }
  }
  peer_connection_tracker_->TrackSignalingStateChange(
      this, native_peer_connection_->signaling_state());
  peer_connection_tracker_->TrackIceConnectionStateChange(
      this, native_peer_connection_->standardized_ice_connection_state());
  peer_connection_tracker_->TrackConnectionStateChange(
      this, native_peer_connection_->peer_connection_state());
}

void RTCPeerConnectionHandler::GetStats(RTCStatsReportCallback callback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  PostCrossThreadTask(
      *signaling_thread().get(), FROM_HERE,
      CrossThreadBindOnce(&GetRTCStatsOnSignalingThread, task_runner_,
                          native_peer_connection_,
                          CrossThreadBindOnce(std::move(callback))));
}

webrtc::RTCErrorOr<std::unique_ptr<RTCRtpTransceiverPlatform>>
RTCPeerConnectionHandler::AddTransceiverWithTrack(
    MediaStreamComponent* component,
    const webrtc::RtpTransceiverInit& init) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  std::unique_ptr<blink::WebRtcMediaStreamTrackAdapterMap::AdapterRef>
      track_ref = track_adapter_map_->GetOrCreateLocalTrackAdapter(component);
  blink::TransceiverStateSurfacer transceiver_state_surfacer(
      task_runner_, signaling_thread());
  webrtc::RTCErrorOr<rtc::scoped_refptr<webrtc::RtpTransceiverInterface>>
      error_or_transceiver;
  RunSynchronousOnceClosureOnSignalingThread(
      base::BindOnce(
          &RTCPeerConnectionHandler::AddTransceiverWithTrackOnSignalingThread,
          base::Unretained(this),
          base::RetainedRef(track_ref->webrtc_track().get()), std::cref(init),
          base::Unretained(&transceiver_state_surfacer),
          base::Unretained(&error_or_transceiver)),
      "AddTransceiverWithTrackOnSignalingThread");
  if (!error_or_transceiver.ok()) {
    // Don't leave the surfacer in a pending state.
    transceiver_state_surfacer.ObtainStates();
    return error_or_transceiver.MoveError();
  }

  auto transceiver_states = transceiver_state_surfacer.ObtainStates();
  auto transceiver =
      CreateOrUpdateTransceiver(std::move(transceiver_states[0]),
                                blink::TransceiverStateUpdateMode::kAll);
  std::unique_ptr<RTCRtpTransceiverPlatform> platform_transceiver =
      std::move(transceiver);
  if (peer_connection_tracker_) {
    size_t transceiver_index = GetTransceiverIndex(*platform_transceiver.get());
    peer_connection_tracker_->TrackAddTransceiver(
        this, PeerConnectionTracker::TransceiverUpdatedReason::kAddTransceiver,
        *platform_transceiver.get(), transceiver_index);
  }
  return platform_transceiver;
}

void RTCPeerConnectionHandler::AddTransceiverWithTrackOnSignalingThread(
    webrtc::MediaStreamTrackInterface* webrtc_track,
    webrtc::RtpTransceiverInit init,
    blink::TransceiverStateSurfacer* transceiver_state_surfacer,
    webrtc::RTCErrorOr<rtc::scoped_refptr<webrtc::RtpTransceiverInterface>>*
        error_or_transceiver) {
  *error_or_transceiver = native_peer_connection_->AddTransceiver(
      rtc::scoped_refptr<webrtc::MediaStreamTrackInterface>(webrtc_track),
      init);
  std::vector<rtc::scoped_refptr<webrtc::RtpTransceiverInterface>> transceivers;
  if (error_or_transceiver->ok())
    transceivers.push_back(error_or_transceiver->value());
  transceiver_state_surfacer->Initialize(native_peer_connection_,
                                         track_adapter_map_, transceivers);
}

webrtc::RTCErrorOr<std::unique_ptr<RTCRtpTransceiverPlatform>>
RTCPeerConnectionHandler::AddTransceiverWithKind(
    const String& kind,
    const webrtc::RtpTransceiverInit& init) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  cricket::MediaType media_type;
  if (kind == webrtc::MediaStreamTrackInterface::kAudioKind) {
    media_type = cricket::MEDIA_TYPE_AUDIO;
  } else {
    DCHECK_EQ(kind, webrtc::MediaStreamTrackInterface::kVideoKind);
    media_type = cricket::MEDIA_TYPE_VIDEO;
  }
  blink::TransceiverStateSurfacer transceiver_state_surfacer(
      task_runner_, signaling_thread());
  webrtc::RTCErrorOr<rtc::scoped_refptr<webrtc::RtpTransceiverInterface>>
      error_or_transceiver;
  RunSynchronousOnceClosureOnSignalingThread(
      base::BindOnce(&RTCPeerConnectionHandler::
                         AddTransceiverWithMediaTypeOnSignalingThread,
                     base::Unretained(this), std::cref(media_type),
                     std::cref(init),
                     base::Unretained(&transceiver_state_surfacer),
                     base::Unretained(&error_or_transceiver)),
      "AddTransceiverWithMediaTypeOnSignalingThread");
  if (!error_or_transceiver.ok()) {
    // Don't leave the surfacer in a pending state.
    transceiver_state_surfacer.ObtainStates();
    return error_or_transceiver.MoveError();
  }

  auto transceiver_states = transceiver_state_surfacer.ObtainStates();
  auto transceiver =
      CreateOrUpdateTransceiver(std::move(transceiver_states[0]),
                                blink::TransceiverStateUpdateMode::kAll);
  std::unique_ptr<RTCRtpTransceiverPlatform> platform_transceiver =
      std::move(transceiver);
  if (peer_connection_tracker_) {
    size_t transceiver_index = GetTransceiverIndex(*platform_transceiver.get());
    peer_connection_tracker_->TrackAddTransceiver(
        this, PeerConnectionTracker::TransceiverUpdatedReason::kAddTransceiver,
        *platform_transceiver.get(), transceiver_index);
  }
  return std::move(platform_transceiver);
}

void RTCPeerConnectionHandler::AddTransceiverWithMediaTypeOnSignalingThread(
    cricket::MediaType media_type,
    webrtc::RtpTransceiverInit init,
    blink::TransceiverStateSurfacer* transceiver_state_surfacer,
    webrtc::RTCErrorOr<rtc::scoped_refptr<webrtc::RtpTransceiverInterface>>*
        error_or_transceiver) {
  *error_or_transceiver =
      native_peer_connection_->AddTransceiver(media_type, init);
  std::vector<rtc::scoped_refptr<webrtc::RtpTransceiverInterface>> transceivers;
  if (error_or_transceiver->ok())
    transceivers.push_back(error_or_transceiver->value());
  transceiver_state_surfacer->Initialize(native_peer_connection_,
                                         track_adapter_map_, transceivers);
}

webrtc::RTCErrorOr<std::unique_ptr<RTCRtpTransceiverPlatform>>
RTCPeerConnectionHandler::AddTrack(
    MediaStreamComponent* component,
    const MediaStreamDescriptorVector& descriptors) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::AddTrack");

  std::unique_ptr<blink::WebRtcMediaStreamTrackAdapterMap::AdapterRef>
      track_ref = track_adapter_map_->GetOrCreateLocalTrackAdapter(component);
  std::vector<std::string> stream_ids(descriptors.size());
  for (WTF::wtf_size_t i = 0; i < descriptors.size(); ++i)
    stream_ids[i] = descriptors[i]->Id().Utf8();

  // Invoke native AddTrack() on the signaling thread and surface the resulting
  // transceiver.
  blink::TransceiverStateSurfacer transceiver_state_surfacer(
      task_runner_, signaling_thread());
  webrtc::RTCErrorOr<rtc::scoped_refptr<webrtc::RtpSenderInterface>>
      error_or_sender;
  RunSynchronousOnceClosureOnSignalingThread(
      base::BindOnce(&RTCPeerConnectionHandler::AddTrackOnSignalingThread,
                     base::Unretained(this),
                     base::RetainedRef(track_ref->webrtc_track().get()),
                     std::move(stream_ids),
                     base::Unretained(&transceiver_state_surfacer),
                     base::Unretained(&error_or_sender)),
      "AddTrackOnSignalingThread");
  DCHECK(transceiver_state_surfacer.is_initialized());
  if (!error_or_sender.ok()) {
    // Don't leave the surfacer in a pending state.
    transceiver_state_surfacer.ObtainStates();
    return error_or_sender.MoveError();
  }
  track_metrics_.AddTrack(MediaStreamTrackMetrics::Direction::kSend,
                          MediaStreamTrackMetricsKind(component),
                          component->Id().Utf8());

  auto transceiver_states = transceiver_state_surfacer.ObtainStates();
  DCHECK_EQ(transceiver_states.size(), 1u);
  auto transceiver_state = std::move(transceiver_states[0]);

  std::unique_ptr<RTCRtpTransceiverPlatform> platform_transceiver;
  // Create or recycle a transceiver.
  auto transceiver = CreateOrUpdateTransceiver(
      std::move(transceiver_state), blink::TransceiverStateUpdateMode::kAll);
  platform_transceiver = std::move(transceiver);
  if (peer_connection_tracker_) {
    size_t transceiver_index = GetTransceiverIndex(*platform_transceiver.get());
    peer_connection_tracker_->TrackAddTransceiver(
        this, PeerConnectionTracker::TransceiverUpdatedReason::kAddTrack,
        *platform_transceiver.get(), transceiver_index);
  }
  for (const auto& stream_id : rtp_senders_.back()->state().stream_ids()) {
    if (GetLocalStreamUsageCount(rtp_senders_, stream_id) == 1u) {
      // This is the first occurrence of this stream.
      blink::PerSessionWebRTCAPIMetrics::GetInstance()
          ->IncrementStreamCounter();
    }
  }
  return platform_transceiver;
}

void RTCPeerConnectionHandler::AddTrackOnSignalingThread(
    webrtc::MediaStreamTrackInterface* track,
    std::vector<std::string> stream_ids,
    blink::TransceiverStateSurfacer* transceiver_state_surfacer,
    webrtc::RTCErrorOr<rtc::scoped_refptr<webrtc::RtpSenderInterface>>*
        error_or_sender) {
  *error_or_sender = native_peer_connection_->AddTrack(
      rtc::scoped_refptr<webrtc::MediaStreamTrackInterface>(track), stream_ids);
  std::vector<rtc::scoped_refptr<webrtc::RtpTransceiverInterface>> transceivers;
  if (error_or_sender->ok()) {
    auto sender = error_or_sender->value();
    rtc::scoped_refptr<webrtc::RtpTransceiverInterface> transceiver_for_sender;
    for (const auto& transceiver : native_peer_connection_->GetTransceivers()) {
      if (transceiver->sender() == sender) {
        transceiver_for_sender = transceiver;
        break;
      }
    }
    DCHECK(transceiver_for_sender);
    transceivers = {transceiver_for_sender};
  }
  transceiver_state_surfacer->Initialize(
      native_peer_connection_, track_adapter_map_, std::move(transceivers));
}

webrtc::RTCErrorOr<std::unique_ptr<RTCRtpTransceiverPlatform>>
RTCPeerConnectionHandler::RemoveTrack(blink::RTCRtpSenderPlatform* web_sender) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::RemoveTrack");
  auto it = FindSender(web_sender->Id());
  if (it == rtp_senders_.end())
    return webrtc::RTCError(webrtc::RTCErrorType::INVALID_PARAMETER);
  const auto& sender = *it;
  auto webrtc_sender = sender->state().webrtc_sender();

  blink::TransceiverStateSurfacer transceiver_state_surfacer(
      task_runner_, signaling_thread());
  std::optional<webrtc::RTCError> result;
  RunSynchronousOnceClosureOnSignalingThread(
      base::BindOnce(&RTCPeerConnectionHandler::RemoveTrackOnSignalingThread,
                     base::Unretained(this),
                     base::RetainedRef(webrtc_sender.get()),
                     base::Unretained(&transceiver_state_surfacer),
                     base::Unretained(&result)),
      "RemoveTrackOnSignalingThread");
  DCHECK(transceiver_st
"""


```