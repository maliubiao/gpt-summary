Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the Chromium Blink engine and resides in the `rtc_peer_connection_handler.cc` file. This is the third part of a three-part request.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Class:** The code snippet is part of the `RTCPeerConnectionHandler` class. The name strongly suggests its primary role is managing the underlying WebRTC peer connection.

2. **Scan for Key Methods and Attributes:** Look for methods that perform actions or manage state related to a peer connection. Keywords like `Create`, `Add`, `Remove`, `Get`, `Set`, `On`, `Track`, `Close`, and attributes like `is_closed_` are good indicators.

3. **Group Functionality by Domain:** Organize the identified methods and attributes into logical groups. For instance, handling tracks, managing transceivers, dealing with ICE candidates, managing data channels, and reporting metrics are distinct areas.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):** Consider how the functionality of this C++ class interacts with the JavaScript WebRTC API. Think about the events and methods available in JavaScript's `RTCPeerConnection` and how they might map to the C++ code.

5. **Identify Logical Reasoning and Potential Inputs/Outputs:**  For methods that perform some processing, infer the inputs and outputs. For example, `CreateOrUpdateTransceiver` takes `RtpTransceiverState` as input and returns a `RTCRtpTransceiverImpl` object.

6. **Recognize User Errors:**  Consider common mistakes developers make when using the WebRTC API that might trigger code within this class. Incorrect order of operations or providing invalid parameters are common examples.

7. **Trace User Operations:**  Imagine the steps a user takes in a web application that lead to this C++ code being executed. Starting with creating an `RTCPeerConnection` object and then performing actions like adding tracks or creating offers are good starting points.

8. **Focus on the "Part 3" aspect:**  Since this is the final part, ensure the summary builds upon the previous parts (though the user didn't provide those here). The summary should encompass the concluding aspects of the class's functionality.

**Detailed Breakdown of Code Snippet Analysis:**

* **Transceiver Management (Continued):** The snippet continues to handle the lifecycle of `RTCRtpTransceiver` objects. The `RemoveTrackOnSignalingThread` function clearly handles the removal of tracks, updating transceiver states accordingly. The `GetPlatformSenders` method provides a way to retrieve the current senders.

* **Closing the Connection:** The `CloseClientPeerConnection` and `Close` methods handle the shutdown process.

* **Thermal and Speed Limit Monitoring:** The code introduces mechanisms for tracking thermal state (`MaybeCreateThermalUmaListner`, `OnThermalStateChange`) and network speed limits (`OnSpeedLimitChange`). These likely influence media encoding and transmission.

* **Event Logging:** The `StartEventLog` and `StopEventLog` functions suggest the capability to record detailed internal events for debugging and analysis.

* **Data Channels:** The `CreateDataChannel` function allows the creation of data channels for arbitrary data transfer. The `OnDataChannel` method handles the reception of remotely initiated data channels.

* **Session Description Updates:** `OnSessionDescriptionsUpdated` is crucial for informing the JavaScript side about changes in the local and remote session descriptions during the negotiation process.

* **ICE Candidate Handling:** The `OnIceCandidate` and `OnIceCandidateError` methods deal with the generation and failure of ICE candidates, essential for establishing media connections.

* **Metrics and Reporting:**  Several methods like `ReportFirstSessionDescriptions`, `ReportICEState`, and the usage of `PeerConnectionTracker` indicate the collection of internal metrics for performance analysis and debugging.

* **Internal Helpers:** The code includes helper functions like `FindSender`, `FindReceiver`, `FindTransceiver`, and `CreateOrUpdateTransceiver` that encapsulate internal logic for managing collections of related objects.

* **Thread Safety:** The frequent use of `DCHECK(task_runner_->RunsTasksInCurrentSequence());` emphasizes the importance of thread safety within this class and its reliance on specific task runners.

By following these steps and carefully examining the code, a comprehensive summary of the `RTCPeerConnectionHandler`'s functionality can be generated, including its connections to web technologies, potential user errors, and typical usage scenarios. The "Part 3" context reinforces the need to present a holistic view of the class's responsibilities.
这是`blink/renderer/modules/peerconnection/rtc_peer_connection_handler.cc`文件的第三部分，延续了前两部分的内容，主要负责实现 `RTCPeerConnection` 的底层功能，对接 WebRTC 原生层，并与 Blink 渲染引擎的其他模块进行交互。

**本部分归纳的功能如下:**

1. **移除 Track (Remove Track):**
   - `RemoveTrackOnSignalingThread`: 在信令线程上实际执行移除 track 的操作。
   - 它会调用 WebRTC 原生层的 `RemoveTrackOrError` 方法。
   - 如果移除成功，它会更新 `transceiver_state_surfacer` 以反映 track 的移除。
   - **与 Javascript 的关系:** 当 Javascript 代码调用 `RTCPeerConnection.removeTrack()` 时，最终会触发此方法在信令线程上的执行。
   - **假设输入与输出:**
     - **假设输入:** 一个指向要移除的 `RtpSenderInterface` 的指针，一个 `TransceiverStateSurfacer` 对象，一个用于接收结果的 `std::optional<webrtc::RTCError>` 指针。
     - **假设输出:** `result` 指针指向的 `std::optional` 会被赋值，如果操作成功则包含 `webrtc::RTCError::OK()`, 否则包含错误信息。
   - **用户使用错误:** 用户在 `RTCPeerConnection` 状态不合适时调用 `removeTrack()`，例如连接已经关闭。

2. **获取所有 Sender (Get Senders):**
   - `GetPlatformSenders`: 返回一个包含所有 `RTCRtpSenderPlatform` 对象的 `Vector`。这些对象代表了当前的发送器。
   - **与 Javascript 的关系:**  对应 Javascript 中 `RTCPeerConnection.getSenders()` 方法。

3. **关闭 PeerConnection (Close PeerConnection):**
   - `CloseClientPeerConnection`: 通知客户端（Blink 的上层抽象）关闭 `RTCPeerConnection`。
   - `Close`:  执行关闭 `RTCPeerConnection` 的操作，包括调用 WebRTC 原生层的 `Close()` 方法，并标记 `is_closed_` 为 true。
   - **与 Javascript 的关系:**  对应 Javascript 中 `RTCPeerConnection.close()` 方法。

4. **热状态和速度限制监听 (Thermal and Speed Limit Listeners):**
   - `MaybeCreateThermalUmaListner`:  根据是否存在视频 track 来决定是否创建 `ThermalUmaListener` 用于上报热状态信息。
   - `thermal_uma_listener()`, `speed_limit_uma_listener()`: 提供访问监听器的接口。
   - `OnThermalStateChange`:  接收设备热状态变化的通知，并更新 `thermal_resource_` (如果启用了相关 Feature) 和通知 `ThermalUmaListener`。
   - `OnSpeedLimitChange`: 接收网络速度限制变化的通知，并通知 `SpeedLimitUmaListener`。
   - **用户使用错误:** 这部分功能主要是内部使用，用户一般不会直接操作，但设备过热或网络速度过慢可能会影响 WebRTC 的性能。

5. **事件日志 (Event Log):**
   - `StartEventLog`: 启动 WebRTC 事件日志记录，将日志输出到 `RtcEventLogOutputSinkProxy`。
   - `StopEventLog`: 停止 WebRTC 事件日志记录。
   - `OnWebRtcEventLogWrite`:  当 WebRTC 事件日志有输出时被调用，会将日志信息传递给 `peer_connection_tracker_` 用于 Chrome 的 `chrome://webrtc-internals/` 页面显示。
   - **与 Javascript 的关系:**  用户可以通过某些实验性 API 或浏览器标志来启用/禁用事件日志，但这并不是标准的 WebRTC API。

6. **创建 DataChannel (Create Data Channel):**
   - `CreateDataChannel`:  根据给定的标签和配置创建 `DataChannelInterface` 对象，并调用 WebRTC 原生层的 `CreateDataChannelOrError` 方法。
   - **与 Javascript 的关系:**  对应 Javascript 中 `RTCPeerConnection.createDataChannel()` 方法。
   - **假设输入与输出:**
     - **假设输入:** 一个表示 data channel 标签的 `String`，一个 `webrtc::DataChannelInit` 对象包含 data channel 的配置。
     - **假设输出:**  返回一个指向新创建的 `DataChannelInterface` 对象的智能指针，如果创建失败则返回 `nullptr`。
   - **用户使用错误:**  尝试创建已经存在的 data channel，或者提供的配置参数不合法。

7. **同步执行闭包 (Run Synchronous Closure):**
   - `RunSynchronousOnceClosureOnSignalingThread`:  在信令线程上同步执行给定的闭包。如果当前线程已经是信令线程，则直接执行；否则，将闭包 पोस्ट 到信令线程并等待执行完成。
   - **内部使用:** 用于确保某些需要在信令线程上执行的操作能够同步完成。

8. **SessionDescription 更新回调 (Session Descriptions Updated Callback):**
   - `OnSessionDescriptionsUpdated`: 当本地或远端的 SessionDescription 更新时被调用，将更新后的描述信息转换为 Blink 的表示 (`WebRTCSessionDescription`) 并通知客户端。
   - **与 Javascript 的关系:**  当 `setLocalDescription` 或 `setRemoteDescription` 操作成功时，会触发此回调，最终会触发 Javascript 中 `RTCPeerConnection` 的相关事件。

9. **信令状态跟踪 (Signaling State Tracking):**
   - `TrackSignalingChange`: 跟踪 `RTCPeerConnection` 的信令状态变化，并将信息传递给 `peer_connection_tracker_` 用于调试和监控。
   - **与 Javascript 的关系:**  信令状态的变化会触发 Javascript 中 `signalingstatechange` 事件。

10. **ICE 连接状态回调和跟踪 (ICE Connection State Callbacks and Tracking):**
    - `OnIceConnectionChange`: 当底层的 ICE 连接状态发生变化时被调用，用于 UMA 统计。
    - `TrackIceConnectionStateChange`: 跟踪 ICE 连接状态变化，并将信息传递给 `peer_connection_tracker_`。
    - **与 Javascript 的关系:** ICE 连接状态的变化会触发 Javascript 中 `iceconnectionstatechange` 事件。

11. **连接状态回调 (Connection State Callback):**
    - `OnConnectionChange`: 当 `RTCPeerConnection` 的整体连接状态发生变化时被调用，并通知客户端。
    - **与 Javascript 的关系:** 连接状态的变化会触发 Javascript 中 `connectionstatechange` 事件。

12. **ICE 收集状态回调 (ICE Gathering State Callback):**
    - `OnIceGatheringChange`: 当 ICE 收集状态发生变化时被调用，并通知客户端。
    - **与 Javascript 的关系:** ICE 收集状态的变化会触发 Javascript 中 `icegatheringstatechange` 事件。

13. **协商需要事件 (Negotiation Needed Event):**
    - `OnNegotiationNeededEvent`: 当需要重新协商会话时被调用，会检查是否应该触发 `negotiationneeded` 事件，并通知客户端。
    - **与 Javascript 的关系:**  触发 Javascript 中的 `negotiationneeded` 事件。

14. **SCTP Transport 修改回调 (SCTP Transport Modification Callback):**
    - `OnModifySctpTransport`: 当 SCTP transport 的状态发生变化时被调用，并将状态信息通知客户端。
    - **与 Javascript 的关系:**  与 data channel 相关，用户可以通过 Javascript API 获取 SCTP transport 的信息。

15. **Transceiver 修改回调 (Transceiver Modification Callback):**
    - `OnModifyTransceivers`: 当 transceiver 的状态因设置本地或远端描述而发生变化时被调用。它会创建或更新 `RTCRtpTransceiverPlatform` 对象，并通知客户端 transceiver 的添加、修改和移除。
    - **与 Javascript 的关系:**  当 `setLocalDescription` 或 `setRemoteDescription` 操作导致 transceiver 状态变化时会触发此回调，最终影响 Javascript 中 `RTCPeerConnection.getTransceivers()` 返回的结果以及 `track` 事件。

16. **接收 DataChannel 回调 (Data Channel Received Callback):**
    - `OnDataChannel`: 当接收到远端创建的 data channel 时被调用，并通知客户端。
    - **与 Javascript 的关系:**  触发 Javascript 中 `datachannel` 事件。

17. **ICE Candidate 回调 (ICE Candidate Callback):**
    - `OnIceCandidate`: 当生成新的 ICE candidate 时被调用，并将 candidate 信息转换为 `RTCIceCandidatePlatform` 对象并通知客户端。
    - **与 Javascript 的关系:**  触发 Javascript 中 `icecandidate` 事件。
    - **用户操作到达这里的步骤:**
        1. Javascript 代码创建 `RTCPeerConnection` 对象。
        2. 设置 `icecandidate` 事件监听器。
        3. 调用 `createOffer()` 或 `createAnswer()` 触发 ICE 收集过程。
        4. WebRTC 原生层收集到新的 ICE candidate。
        5. WebRTC 原生层回调 `RTCPeerConnectionHandler::OnIceCandidate`。
   - **用户使用错误:**  网络环境配置不当导致无法生成有效的 ICE candidate。

18. **ICE Candidate 错误回调 (ICE Candidate Error Callback):**
    - `OnIceCandidateError`: 当 ICE candidate 收集过程中发生错误时被调用，并将错误信息通知客户端。
    - **与 Javascript 的关系:**  触发 Javascript 中 `icecandidateerror` 事件。

19. **有趣的使用模式回调 (Interesting Usage Callback):**
    - `OnInterestingUsage`: 当 WebRTC 观察到一些有趣的 usage pattern 时被调用，并通知客户端。
    - **与 Javascript 的关系:**  这通常用于内部统计和调试，Javascript 中没有直接对应的事件。

20. **报告首个 SessionDescription (Report First Session Descriptions):**
    - `ReportFirstSessionDescriptions`:  分析本地和远端首个 SessionDescription，并上报关于音视频 track 和 rtcp-mux 的统计信息。

21. **查找 Sender/Receiver/Transceiver (Find Sender/Receiver/Transceiver):**
    - `FindSender`, `FindReceiver`, `FindTransceiver`:  用于在内部列表中查找对应的 sender, receiver 或 transceiver 对象。

22. **获取 Transceiver 索引 (Get Transceiver Index):**
    - `GetTransceiverIndex`: 获取给定 `RTCRtpTransceiverPlatform` 对象在内部列表中的索引。

23. **创建或更新 Transceiver (Create or Update Transceiver):**
    - `CreateOrUpdateTransceiver`:  根据给定的 `RtpTransceiverState` 创建新的或更新已有的 `RTCRtpTransceiverImpl` 对象。它会同时处理相关的 sender 和 receiver 的创建或更新。

24. **获取信令线程 (Get Signaling Thread):**
    - `signaling_thread()`: 返回信令线程的 `TaskRunner`。

25. **报告 ICE 状态 (Report ICE State):**
    - `ReportICEState`: 记录已经观察到的 ICE 连接状态，用于 UMA 统计，避免重复记录。

**总结来说，这部分代码主要负责处理 `RTCPeerConnection` 生命周期中的关键操作，例如移除 track，关闭连接，处理热状态和速度限制，管理事件日志，创建 data channel，更新会话描述，跟踪连接状态变化，以及管理 transceiver 和 ICE candidate。它作为 Blink 渲染引擎中 WebRTC 功能的核心组成部分，将 Javascript 的 WebRTC API 调用转化为对底层 WebRTC 原生接口的操作，并负责将原生层的事件回调传递到 Javascript 层。**

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_peer_connection_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
ate_surfacer.is_initialized());
  if (!result || !result->ok()) {
    // Don't leave the surfacer in a pending state.
    transceiver_state_surfacer.ObtainStates();
    if (!result) {
      // Operation has been cancelled.
      return std::unique_ptr<RTCRtpTransceiverPlatform>(nullptr);
    }
    return std::move(*result);
  }

  auto transceiver_states = transceiver_state_surfacer.ObtainStates();
  DCHECK_EQ(transceiver_states.size(), 1u);
  auto transceiver_state = std::move(transceiver_states[0]);

  // Update the transceiver.
  auto transceiver = CreateOrUpdateTransceiver(
      std::move(transceiver_state), blink::TransceiverStateUpdateMode::kAll);
  if (peer_connection_tracker_) {
    size_t transceiver_index = GetTransceiverIndex(*transceiver);
    peer_connection_tracker_->TrackModifyTransceiver(
        this, PeerConnectionTracker::TransceiverUpdatedReason::kRemoveTrack,
        *transceiver.get(), transceiver_index);
  }
  std::unique_ptr<RTCRtpTransceiverPlatform> platform_transceiver =
      std::move(transceiver);
  return platform_transceiver;
}

void RTCPeerConnectionHandler::RemoveTrackOnSignalingThread(
    webrtc::RtpSenderInterface* sender,
    blink::TransceiverStateSurfacer* transceiver_state_surfacer,
    std::optional<webrtc::RTCError>* result) {
  *result = native_peer_connection_->RemoveTrackOrError(
      rtc::scoped_refptr<webrtc::RtpSenderInterface>(sender));
  std::vector<rtc::scoped_refptr<webrtc::RtpTransceiverInterface>> transceivers;
  if ((*result)->ok()) {
    rtc::scoped_refptr<webrtc::RtpTransceiverInterface> transceiver_for_sender =
        nullptr;
    for (const auto& transceiver : native_peer_connection_->GetTransceivers()) {
      if (transceiver->sender() == sender) {
        transceiver_for_sender = transceiver;
        break;
      }
    }
    if (!transceiver_for_sender) {
      // If the transceiver doesn't exist, it must have been rolled back while
      // we were performing removeTrack(). Abort this operation.
      *result = std::nullopt;
    } else {
      transceivers = {transceiver_for_sender};
    }
  }
  transceiver_state_surfacer->Initialize(
      native_peer_connection_, track_adapter_map_, std::move(transceivers));
}

Vector<std::unique_ptr<blink::RTCRtpSenderPlatform>>
RTCPeerConnectionHandler::GetPlatformSenders() const {
  Vector<std::unique_ptr<blink::RTCRtpSenderPlatform>> senders;
  for (const auto& sender : rtp_senders_) {
    senders.push_back(sender->ShallowCopy());
  }
  return senders;
}

void RTCPeerConnectionHandler::CloseClientPeerConnection() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  if (!is_closed_)
    client_->ClosePeerConnection();
}

void RTCPeerConnectionHandler::MaybeCreateThermalUmaListner() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  // Instantiate the speed limit listener if we have one track.
  if (!speed_limit_uma_listener_) {
    for (const auto& sender : rtp_senders_) {
      if (sender->Track()) {
        speed_limit_uma_listener_ =
            std::make_unique<SpeedLimitUmaListener>(task_runner_);
        speed_limit_uma_listener_->OnSpeedLimitChange(last_speed_limit_);
        break;
      }
    }
  }
  if (!thermal_uma_listener_) {
    // Instantiate the thermal uma listener only if we are sending video.
    for (const auto& sender : rtp_senders_) {
      if (sender->Track() &&
          sender->Track()->GetSourceType() == MediaStreamSource::kTypeVideo) {
        thermal_uma_listener_ = ThermalUmaListener::Create(task_runner_);
        thermal_uma_listener_->OnThermalMeasurement(last_thermal_state_);
        return;
      }
    }
  }
}

ThermalUmaListener* RTCPeerConnectionHandler::thermal_uma_listener() const {
  return thermal_uma_listener_.get();
}

SpeedLimitUmaListener* RTCPeerConnectionHandler::speed_limit_uma_listener()
    const {
  return speed_limit_uma_listener_.get();
}

void RTCPeerConnectionHandler::OnThermalStateChange(
    mojom::blink::DeviceThermalState thermal_state) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  if (is_closed_)
    return;
  last_thermal_state_ = thermal_state;
  if (thermal_uma_listener_) {
    thermal_uma_listener_->OnThermalMeasurement(thermal_state);
  }
  if (!base::FeatureList::IsEnabled(kWebRtcThermalResource))
    return;
  if (!thermal_resource_) {
    thermal_resource_ = ThermalResource::Create(task_runner_);
    native_peer_connection_->AddAdaptationResource(
        rtc::scoped_refptr<ThermalResource>(thermal_resource_.get()));
  }
  thermal_resource_->OnThermalMeasurement(thermal_state);
}

void RTCPeerConnectionHandler::OnSpeedLimitChange(int32_t speed_limit) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  if (is_closed_)
    return;
  last_speed_limit_ = speed_limit;
  if (speed_limit_uma_listener_)
    speed_limit_uma_listener_->OnSpeedLimitChange(speed_limit);
}

void RTCPeerConnectionHandler::StartEventLog(int output_period_ms) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  // TODO(eladalon): StartRtcEventLog() return value is not useful; remove it
  // or find a way to be able to use it.
  // https://crbug.com/775415
  native_peer_connection_->StartRtcEventLog(
      std::make_unique<RtcEventLogOutputSinkProxy>(peer_connection_observer_),
      output_period_ms);
}

void RTCPeerConnectionHandler::StopEventLog() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  native_peer_connection_->StopRtcEventLog();
}

void RTCPeerConnectionHandler::OnWebRtcEventLogWrite(
    const WTF::Vector<uint8_t>& output) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  if (peer_connection_tracker_) {
    peer_connection_tracker_->TrackRtcEventLogWrite(this, output);
  }
}

rtc::scoped_refptr<DataChannelInterface>
RTCPeerConnectionHandler::CreateDataChannel(
    const String& label,
    const webrtc::DataChannelInit& init) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::createDataChannel");
  DVLOG(1) << "createDataChannel label " << label.Utf8();

  webrtc::RTCErrorOr<rtc::scoped_refptr<DataChannelInterface>> webrtc_channel =
      native_peer_connection_->CreateDataChannelOrError(label.Utf8(), &init);
  if (!webrtc_channel.ok()) {
    DLOG(ERROR) << "Could not create native data channel: "
                << webrtc_channel.error().message();
    return nullptr;
  }
  if (peer_connection_tracker_) {
    peer_connection_tracker_->TrackCreateDataChannel(
        this, webrtc_channel.value().get(),
        PeerConnectionTracker::kSourceLocal);
  }

  return webrtc_channel.value();
}

void RTCPeerConnectionHandler::Close() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  DVLOG(1) << "RTCPeerConnectionHandler::stop";

  if (is_closed_ || !native_peer_connection_.get())
    return;  // Already stopped.

  if (peer_connection_tracker_)
    peer_connection_tracker_->TrackClose(this);

  native_peer_connection_->Close();

  // This object may no longer forward call backs to blink.
  is_closed_ = true;
}

webrtc::PeerConnectionInterface*
RTCPeerConnectionHandler::NativePeerConnection() {
  return native_peer_connection();
}

void RTCPeerConnectionHandler::RunSynchronousOnceClosureOnSignalingThread(
    base::OnceClosure closure,
    const char* trace_event_name) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  scoped_refptr<base::SingleThreadTaskRunner> thread(signaling_thread());
  if (!thread.get() || thread->BelongsToCurrentThread()) {
    TRACE_EVENT0("webrtc", trace_event_name);
    std::move(closure).Run();
  } else {
    base::WaitableEvent event(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                              base::WaitableEvent::InitialState::NOT_SIGNALED);
    thread->PostTask(
        FROM_HERE,
        base::BindOnce(&RunSynchronousOnceClosure, std::move(closure),
                       base::Unretained(trace_event_name),
                       base::Unretained(&event)));
    event.Wait();
  }
}

void RTCPeerConnectionHandler::OnSessionDescriptionsUpdated(
    std::unique_ptr<webrtc::SessionDescriptionInterface>
        pending_local_description,
    std::unique_ptr<webrtc::SessionDescriptionInterface>
        current_local_description,
    std::unique_ptr<webrtc::SessionDescriptionInterface>
        pending_remote_description,
    std::unique_ptr<webrtc::SessionDescriptionInterface>
        current_remote_description) {
  // Prevent garbage collection of client_ during processing.
  auto* client_on_stack = client_.Get();
  if (!client_on_stack || is_closed_) {
    return;
  }
  client_on_stack->DidChangeSessionDescriptions(
      pending_local_description
          ? CreateWebKitSessionDescription(pending_local_description.get())
          : nullptr,
      current_local_description
          ? CreateWebKitSessionDescription(current_local_description.get())
          : nullptr,
      pending_remote_description
          ? CreateWebKitSessionDescription(pending_remote_description.get())
          : nullptr,
      current_remote_description
          ? CreateWebKitSessionDescription(current_remote_description.get())
          : nullptr);
}

// Note: This function is purely for chrome://webrtc-internals/ tracking
// purposes. The JavaScript visible event and attribute is processed together
// with transceiver or receiver changes.
void RTCPeerConnectionHandler::TrackSignalingChange(
    webrtc::PeerConnectionInterface::SignalingState new_state) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::TrackSignalingChange");
  if (previous_signaling_state_ ==
          webrtc::PeerConnectionInterface::kHaveLocalOffer &&
      new_state == webrtc::PeerConnectionInterface::kHaveRemoteOffer) {
    // Inject missing kStable in case of implicit rollback.
    auto stable_state = webrtc::PeerConnectionInterface::kStable;
    if (peer_connection_tracker_)
      peer_connection_tracker_->TrackSignalingStateChange(this, stable_state);
  }
  previous_signaling_state_ = new_state;
  if (peer_connection_tracker_)
    peer_connection_tracker_->TrackSignalingStateChange(this, new_state);
}

// Called any time the lower layer IceConnectionState changes, which is NOT in
// sync with the iceConnectionState that is exposed to JavaScript (that one is
// computed by RTCPeerConnection::UpdateIceConnectionState)! This method is
// purely used for UMA reporting. We may want to consider wiring this up to
// UpdateIceConnectionState() instead...
void RTCPeerConnectionHandler::OnIceConnectionChange(
    webrtc::PeerConnectionInterface::IceConnectionState new_state) {
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::OnIceConnectionChange");
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  ReportICEState(new_state);
  track_metrics_.IceConnectionChange(new_state);
}

void RTCPeerConnectionHandler::TrackIceConnectionStateChange(
    webrtc::PeerConnectionInterface::IceConnectionState state) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  if (!peer_connection_tracker_)
    return;
  peer_connection_tracker_->TrackIceConnectionStateChange(this, state);
}

// Called any time the combined peerconnection state changes
void RTCPeerConnectionHandler::OnConnectionChange(
    webrtc::PeerConnectionInterface::PeerConnectionState new_state) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  if (peer_connection_tracker_)
    peer_connection_tracker_->TrackConnectionStateChange(this, new_state);
  if (!is_closed_)
    client_->DidChangePeerConnectionState(new_state);
}

// Called any time the IceGatheringState changes
void RTCPeerConnectionHandler::OnIceGatheringChange(
    webrtc::PeerConnectionInterface::IceGatheringState new_state) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::OnIceGatheringChange");
  if (peer_connection_tracker_)
    peer_connection_tracker_->TrackIceGatheringStateChange(this, new_state);
  if (!is_closed_)
    client_->DidChangeIceGatheringState(new_state);
}

void RTCPeerConnectionHandler::OnNegotiationNeededEvent(uint32_t event_id) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::OnNegotiationNeededEvent");
  if (is_closed_)
    return;
  if (!native_peer_connection_->ShouldFireNegotiationNeededEvent(event_id)) {
    return;
  }
  if (peer_connection_tracker_)
    peer_connection_tracker_->TrackOnRenegotiationNeeded(this);
  client_->NegotiationNeeded();
}

void RTCPeerConnectionHandler::OnModifySctpTransport(
    blink::WebRTCSctpTransportSnapshot state) {
  if (client_)
    client_->DidModifySctpTransport(state);
}

void RTCPeerConnectionHandler::OnModifyTransceivers(
    webrtc::PeerConnectionInterface::SignalingState signaling_state,
    std::vector<blink::RtpTransceiverState> transceiver_states,
    bool is_remote_description,
    bool is_rollback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  Vector<std::unique_ptr<RTCRtpTransceiverPlatform>> platform_transceivers(
      base::checked_cast<WTF::wtf_size_t>(transceiver_states.size()));
  PeerConnectionTracker::TransceiverUpdatedReason update_reason =
      !is_remote_description ? PeerConnectionTracker::TransceiverUpdatedReason::
                                   kSetLocalDescription
                             : PeerConnectionTracker::TransceiverUpdatedReason::
                                   kSetRemoteDescription;
  Vector<uintptr_t> ids(
      base::checked_cast<wtf_size_t>(transceiver_states.size()));
  for (WTF::wtf_size_t i = 0; i < transceiver_states.size(); ++i) {
    // Figure out if this transceiver is new or if setting the state modified
    // the transceiver such that it should be logged by the
    // |peer_connection_tracker_|.
    uintptr_t transceiver_id = blink::RTCRtpTransceiverImpl::GetId(
        transceiver_states[i].webrtc_transceiver().get());
    ids[i] = transceiver_id;
    auto it = FindTransceiver(transceiver_id);
    bool transceiver_is_new = (it == rtp_transceivers_.end());
    bool transceiver_was_modified = false;
    if (!transceiver_is_new) {
      const auto& previous_state = (*it)->state();
      transceiver_was_modified =
          previous_state.mid() != transceiver_states[i].mid() ||
          previous_state.direction() != transceiver_states[i].direction() ||
          previous_state.current_direction() !=
              transceiver_states[i].current_direction() ||
          previous_state.header_extensions_negotiated() !=
              transceiver_states[i].header_extensions_negotiated();
    }

    // Update the transceiver.
    platform_transceivers[i] = CreateOrUpdateTransceiver(
        std::move(transceiver_states[i]),
        blink::TransceiverStateUpdateMode::kSetDescription);

    // Log a "transceiverAdded" or "transceiverModified" event in
    // chrome://webrtc-internals if new or modified.
    if (peer_connection_tracker_ &&
        (transceiver_is_new || transceiver_was_modified)) {
      size_t transceiver_index = GetTransceiverIndex(*platform_transceivers[i]);
      if (transceiver_is_new) {
        peer_connection_tracker_->TrackAddTransceiver(
            this, update_reason, *platform_transceivers[i].get(),
            transceiver_index);
      } else if (transceiver_was_modified) {
        peer_connection_tracker_->TrackModifyTransceiver(
            this, update_reason, *platform_transceivers[i].get(),
            transceiver_index);
      }
    }
  }
  // Search for removed transceivers by comparing to previous state. All of
  // these transceivers will have been stopped in the WebRTC layers, but we do
  // not have access to their states anymore. So it is up to `client_` to ensure
  // removed transceivers are reflected as "stopped" in JavaScript.
  Vector<uintptr_t> removed_transceivers;
  for (auto transceiver_id : previous_transceiver_ids_) {
    if (!base::Contains(ids, transceiver_id)) {
      removed_transceivers.emplace_back(transceiver_id);
      rtp_transceivers_.erase(FindTransceiver(transceiver_id));
    }
  }
  previous_transceiver_ids_ = ids;
  if (!is_closed_) {
    client_->DidModifyTransceivers(
        signaling_state, std::move(platform_transceivers), removed_transceivers,
        is_remote_description || is_rollback);
  }
}

void RTCPeerConnectionHandler::OnDataChannel(
    rtc::scoped_refptr<DataChannelInterface> channel) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::OnDataChannelImpl");

  if (peer_connection_tracker_) {
    peer_connection_tracker_->TrackCreateDataChannel(
        this, channel.get(), PeerConnectionTracker::kSourceRemote);
  }

  if (!is_closed_)
    client_->DidAddRemoteDataChannel(std::move(channel));
}

void RTCPeerConnectionHandler::OnIceCandidate(const String& sdp,
                                              const String& sdp_mid,
                                              int sdp_mline_index,
                                              int component,
                                              int address_family,
                                              const String& usernameFragment,
                                              const String& url) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  // In order to ensure that the RTCPeerConnection is not garbage collected
  // from under the function, we keep a pointer to it on the stack.
  auto* client_on_stack = client_.Get();
  if (!client_on_stack) {
    return;
  }
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::OnIceCandidateImpl");
  std::optional<String> url_or_null;
  if (!url.empty()) {
    url_or_null = url;
  }
  // This line can cause garbage collection.
  auto* platform_candidate = MakeGarbageCollected<RTCIceCandidatePlatform>(
      sdp, sdp_mid, sdp_mline_index, usernameFragment, url_or_null);
  if (peer_connection_tracker_) {
    peer_connection_tracker_->TrackAddIceCandidate(
        this, platform_candidate, PeerConnectionTracker::kSourceLocal, true);
  }

  if (!is_closed_ && client_on_stack) {
    client_on_stack->DidGenerateICECandidate(platform_candidate);
  }
}

void RTCPeerConnectionHandler::OnIceCandidateError(const String& address,
                                                   std::optional<uint16_t> port,
                                                   const String& host_candidate,
                                                   const String& url,
                                                   int error_code,
                                                   const String& error_text) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RTCPeerConnectionHandler::OnIceCandidateError");
  if (peer_connection_tracker_) {
    peer_connection_tracker_->TrackIceCandidateError(
        this, address, port, host_candidate, url, error_code, error_text);
  }
  if (!is_closed_) {
    client_->DidFailICECandidate(address, port, host_candidate, url, error_code,
                                 error_text);
  }
}

void RTCPeerConnectionHandler::OnInterestingUsage(int usage_pattern) {
  if (client_)
    client_->DidNoteInterestingUsage(usage_pattern);
}

RTCPeerConnectionHandler::FirstSessionDescription::FirstSessionDescription(
    const webrtc::SessionDescriptionInterface* sdesc) {
  DCHECK(sdesc);

  for (const auto& content : sdesc->description()->contents()) {
    if (content.type == cricket::MediaProtocolType::kRtp) {
      const auto* mdesc = content.media_description();
      audio = audio || (mdesc->type() == cricket::MEDIA_TYPE_AUDIO);
      video = video || (mdesc->type() == cricket::MEDIA_TYPE_VIDEO);
      rtcp_mux = rtcp_mux || mdesc->rtcp_mux();
    }
  }
}

void RTCPeerConnectionHandler::ReportFirstSessionDescriptions(
    const FirstSessionDescription& local,
    const FirstSessionDescription& remote) {
  RtcpMux rtcp_mux = RtcpMux::kEnabled;
  if ((!local.audio && !local.video) || (!remote.audio && !remote.video)) {
    rtcp_mux = RtcpMux::kNoMedia;
  } else if (!local.rtcp_mux || !remote.rtcp_mux) {
    rtcp_mux = RtcpMux::kDisabled;
  }

  UMA_HISTOGRAM_ENUMERATION("WebRTC.PeerConnection.RtcpMux", rtcp_mux,
                            RtcpMux::kMax);

  // TODO(pthatcher): Reports stats about whether we have audio and
  // video or not.
}

Vector<std::unique_ptr<blink::RTCRtpSenderImpl>>::iterator
RTCPeerConnectionHandler::FindSender(uintptr_t id) {
  return base::ranges::find_if(
      rtp_senders_, [id](const auto& sender) { return sender->Id() == id; });
}

Vector<std::unique_ptr<blink::RTCRtpReceiverImpl>>::iterator
RTCPeerConnectionHandler::FindReceiver(uintptr_t id) {
  return base::ranges::find_if(rtp_receivers_, [id](const auto& receiver) {
    return receiver->Id() == id;
  });
}

Vector<std::unique_ptr<blink::RTCRtpTransceiverImpl>>::iterator
RTCPeerConnectionHandler::FindTransceiver(uintptr_t id) {
  return base::ranges::find_if(
      rtp_transceivers_,
      [id](const auto& transceiver) { return transceiver->Id() == id; });
}

wtf_size_t RTCPeerConnectionHandler::GetTransceiverIndex(
    const RTCRtpTransceiverPlatform& platform_transceiver) {
  for (wtf_size_t i = 0; i < rtp_transceivers_.size(); ++i) {
    if (platform_transceiver.Id() == rtp_transceivers_[i]->Id())
      return i;
  }
  NOTREACHED();
}

std::unique_ptr<blink::RTCRtpTransceiverImpl>
RTCPeerConnectionHandler::CreateOrUpdateTransceiver(
    blink::RtpTransceiverState transceiver_state,
    blink::TransceiverStateUpdateMode update_mode) {
  CHECK(dependency_factory_);
  DCHECK(transceiver_state.is_initialized());
  DCHECK(transceiver_state.sender_state());
  DCHECK(transceiver_state.receiver_state());
  auto webrtc_transceiver = transceiver_state.webrtc_transceiver();
  auto webrtc_sender = transceiver_state.sender_state()->webrtc_sender();
  auto webrtc_receiver = transceiver_state.receiver_state()->webrtc_receiver();

  std::unique_ptr<blink::RTCRtpTransceiverImpl> transceiver;
  auto it = FindTransceiver(
      blink::RTCRtpTransceiverImpl::GetId(webrtc_transceiver.get()));
  if (it == rtp_transceivers_.end()) {
    // Create a new transceiver, including a sender and a receiver.
    transceiver = std::make_unique<blink::RTCRtpTransceiverImpl>(
        native_peer_connection_, track_adapter_map_,
        std::move(transceiver_state), encoded_insertable_streams_,
        dependency_factory_->CreateDecodeMetronome());
    rtp_transceivers_.push_back(transceiver->ShallowCopy());
    DCHECK(FindSender(blink::RTCRtpSenderImpl::getId(webrtc_sender.get())) ==
           rtp_senders_.end());
    rtp_senders_.push_back(std::make_unique<blink::RTCRtpSenderImpl>(
        *transceiver->content_sender()));
    MaybeCreateThermalUmaListner();
    DCHECK(FindReceiver(blink::RTCRtpReceiverImpl::getId(
               webrtc_receiver.get())) == rtp_receivers_.end());
    rtp_receivers_.push_back(std::make_unique<blink::RTCRtpReceiverImpl>(
        *transceiver->content_receiver()));
  } else {
    // Update the transceiver. This also updates the sender and receiver.
    transceiver = (*it)->ShallowCopy();
    transceiver->set_state(std::move(transceiver_state), update_mode);
    DCHECK(FindSender(blink::RTCRtpSenderImpl::getId(webrtc_sender.get())) !=
           rtp_senders_.end());
    DCHECK(FindReceiver(blink::RTCRtpReceiverImpl::getId(
               webrtc_receiver.get())) != rtp_receivers_.end());
  }
  return transceiver;
}

scoped_refptr<base::SingleThreadTaskRunner>
RTCPeerConnectionHandler::signaling_thread() const {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  return signaling_thread_;
}

void RTCPeerConnectionHandler::ReportICEState(
    webrtc::PeerConnectionInterface::IceConnectionState new_state) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  if (ice_state_seen_[new_state])
    return;
  ice_state_seen_[new_state] = true;
  UMA_HISTOGRAM_ENUMERATION("WebRTC.PeerConnection.ConnectionState", new_state,
                            webrtc::PeerConnectionInterface::kIceConnectionMax);
}

}  // namespace blink

"""


```