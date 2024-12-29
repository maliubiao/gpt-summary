Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine file. This is the second part of a multi-part question, so I need to summarise the functionality of *this specific part*.

The code consists of several unit tests for the `RTCPeerConnectionHandler` class. These tests cover various aspects of the WebRTC API, including:

- **Adding and removing ICE candidates**: Testing the `AddIceCandidate` functionality.
- **Adding and removing media streams**: Testing how streams are added and removed, and how this affects senders.
- **Handling stopped audio and video tracks in streams**: Ensuring streams with stopped tracks can be added.
- **Observing changes in connection state**: Testing how state changes are propagated to the client and tracker.
- **Observing changes in ICE gathering state**: Testing the notification of ICE gathering progress.
- **Handling new ICE candidates**: Testing the callback when a new local ICE candidate is generated.
- **Handling renegotiation needed events**:  Testing the notification for renegotiation requirements.
- **Creating data channels**: Testing the creation of data channels.
- **Checking insertable streams configuration**: Verifying the configuration of insertable streams.
- **Handling thermal resource events**: Testing the integration with thermal state changes.
- **Handling speed limit events**: Testing the integration with speed limit events.
- **Handling scenarios where the handler or client is deleted**:  Ensuring proper cleanup and preventing crashes.

For each test, the code sets up expectations using Google Mock to verify interactions with mock objects (like `mock_peer_connection_`, `mock_client_`, `mock_tracker_`). The tests then execute the code under test and assert the expected outcomes.

To provide a good summary, I'll focus on the core functionalities being tested in this specific snippet and how they relate to the overall WebRTC process.
这是对位于 `blink/renderer/modules/peerconnection/rtc_peer_connection_handler_test.cc` 的 Chromium Blink 引擎源代码文件的第二部分功能的归纳。

**主要功能归纳：**

这部分代码主要包含针对 `RTCPeerConnectionHandler` 类的单元测试，涵盖了以下关键功能点：

1. **ICE Candidate 管理：**
   - 测试了 `AddIceCandidate` 方法，验证了添加远端 ICE candidate 的流程，并检查了是否正确地更新了内部状态（例如 SDP）。

2. **媒体流管理：**
   - 测试了 `AddStream` 和 `RemoveStream` 方法，验证了添加和移除本地媒体流的流程。
   - 验证了添加流后，对应的发送器（sender）会被创建，并关联到流中的轨道（track）。
   - 验证了移除流并不会真正删除发送器，而是将发送器的轨道设置为 null。
   - 测试了添加包含已停止的音视频轨道的流的情况，确保能够正常处理。

3. **状态变化通知：**
   - 测试了当 `RTCPeerConnection` 的连接状态（`OnConnectionChange`）发生变化时，`RTCPeerConnectionHandler` 如何通知其客户端（`mock_client_`）和跟踪器（`mock_tracker_`）。涵盖了所有可能的连接状态：`kNew`, `kConnecting`, `kConnected`, `kDisconnected`, `kFailed`, `kClosed`。
   - 测试了当 ICE gathering 状态（`OnIceGatheringChange`）发生变化时，`RTCPeerConnectionHandler` 如何通知其客户端和跟踪器。涵盖了 `kIceGatheringNew`, `kIceGatheringGathering`, `kIceGatheringComplete` 状态。

4. **ICE Candidate 生成通知：**
   - 测试了当生成新的本地 ICE candidate (`OnIceCandidate`) 时，`RTCPeerConnectionHandler` 如何通知其客户端，并携带 candidate 的相关信息（sdpMid, mlineindex, sdp）。

5. **协商需求通知：**
   - 测试了当需要重新协商会话 (`OnRenegotiationNeeded`) 时，`RTCPeerConnectionHandler` 如何通知其客户端。

6. **Data Channel 创建：**
   - 测试了 `CreateDataChannel` 方法，验证了创建数据通道的功能，并检查了新创建的通道的标签（label）。

7. **Insertable Streams 配置：**
   - 测试了 `RTCPeerConnectionHandler` 对可插入媒体流配置的处理。

8. **热管理资源（Thermal Resource）：**
   - 测试了 `RTCPeerConnectionHandler` 如何响应设备的热状态变化 (`OnThermalStateChange`)，并创建和管理 `ThermalResource` 以进行自适应调整。
   - 验证了当 `kWebRtcThermalResource` 特性被禁用时，不会创建 `ThermalResource`。
   - 验证了 `ThermalResource` 如何根据不同的热状态提供资源使用情况的测量结果。

9. **速度限制管理（Speed Limit）：**
   - 测试了在添加媒体流时，是否会创建用于速度限制的监听器。

10. **对象生命周期管理：**
    - 测试了在 `RTCPeerConnectionHandler` 被删除后，接收到的 ICE candidate 会被忽略，避免悬空指针。
    - 测试了在客户端对象被垃圾回收后，`RTCPeerConnectionHandler` 对 ICE candidate 的处理。

**与 JavaScript, HTML, CSS 的关系举例：**

这些测试的功能直接对应了 WebRTC API 在 JavaScript 中的使用，例如：

* **`addIceCandidate()` (JavaScript):**  `TEST_F(RTCPeerConnectionHandlerTest, AddIceCandidate)` 测试了 Blink 引擎中相应的 C++ 实现。用户在 JavaScript 中调用 `addIceCandidate()` 来添加从信令服务器获取的远端 ICE candidate。
   ```javascript
   // 假设 remoteIceCandidate 是从信令服务器获取的
   pc.addIceCandidate(remoteIceCandidate).then(() => {
     console.log('ICE candidate 添加成功');
   }).catch(error => {
     console.error('添加 ICE candidate 出错:', error);
   });
   ```

* **`addTrack()` / `removeTrack()` / `addStream()` / `removeStream()` (JavaScript):** `TEST_F(RTCPeerConnectionHandlerTest, addAndRemoveStream)` 和相关测试模拟了 JavaScript 中添加和移除媒体流的操作。
   ```javascript
   // 添加本地媒体流
   navigator.mediaDevices.getUserMedia({ audio: true, video: true })
     .then(stream => {
       pc.addStream(stream); // 或者使用 addTrack 逐个添加轨道
     });

   // 移除本地媒体流
   pc.removeStream(localStream); // 或者使用 removeTrack 移除特定轨道
   ```

* **`oniceconnectionstatechange` (JavaScript):** `TEST_F(RTCPeerConnectionHandlerTest, OnConnectionChange)` 测试了当连接状态改变时，Blink 引擎如何触发 JavaScript 中的 `iceconnectionstatechange` 事件。
   ```javascript
   pc.oniceconnectionstatechange = function() {
     console.log('ICE 连接状态改变:', pc.iceConnectionState);
   };
   ```

* **`onicegatheringstatechange` (JavaScript):** `TEST_F(RTCPeerConnectionHandlerTest, OnIceGatheringChange)` 测试了当 ICE gathering 状态改变时，Blink 引擎如何触发 JavaScript 中的 `icegatheringstatechange` 事件。
   ```javascript
   pc.onicegatheringstatechange = function() {
     console.log('ICE gathering 状态改变:', pc.iceGatheringState);
   };
   ```

* **`onicecandidate` (JavaScript):** `TEST_F(RTCPeerConnectionHandlerTest, OnIceCandidate)` 测试了当生成新的本地 ICE candidate 时，Blink 引擎如何触发 JavaScript 中的 `icecandidate` 事件。
   ```javascript
   pc.onicecandidate = function(event) {
     if (event.candidate) {
       console.log('新的 ICE candidate:', event.candidate.candidate);
       // 将 candidate 发送给信令服务器
     }
   };
   ```

* **`negotiationneeded` (JavaScript):** `TEST_F(RTCPeerConnectionHandlerTest, OnRenegotiationNeeded)` 测试了 Blink 引擎如何触发 JavaScript 中的 `negotiationneeded` 事件。
   ```javascript
   pc.onnegotiationneeded = function() {
     console.log('需要重新协商');
     // 创建 offer 并发送
   };
   ```

* **`createDataChannel()` (JavaScript):** `TEST_F(RTCPeerConnectionHandlerTest, CreateDataChannel)` 测试了 Blink 引擎中创建数据通道的实现。
   ```javascript
   const dataChannel = pc.createDataChannel('myChannel');
   ```

CSS 通常不直接与这些底层 WebRTC 功能交互，但 CSS 的渲染性能可能会受到 WebRTC 视频流的影响，例如，当视频解码和渲染占用过多资源时，可能会影响页面动画的流畅性。热管理资源的相关测试就隐含了对性能优化的关注。

**逻辑推理与假设输入输出：**

以 `TEST_F(RTCPeerConnectionHandlerTest, AddIceCandidate)` 为例：

* **假设输入：** 一个包含有效 SDP 行的 `RTCIceCandidate` 对象，例如 `RTCIceCandidate({candidate: 'candidate:1 1 UDP ...', sdpMid: 'sdpMid', sdpMLineIndex: 1})`。
* **预期输出：**
    - `request->was_called()` 为 `true`，表示异步操作已完成。
    - `mock_peer_connection_->ice_sdp()` 等于传入的 candidate 的 SDP。
    - `mock_peer_connection_->sdp_mline_index()` 等于传入的 `sdpMLineIndex`。
    - `mock_peer_connection_->sdp_mid()` 等于传入的 `sdpMid`。

**用户或编程常见使用错误举例：**

* **未处理 `addIceCandidate()` 的 Promise 错误：**  在 JavaScript 中，如果提供的 ICE candidate 无效或网络出现问题，`addIceCandidate()` 返回的 Promise 可能会 rejected。开发者需要捕获并处理这些错误。
   ```javascript
   pc.addIceCandidate(invalidCandidate)
     .catch(error => {
       console.error("添加 ICE candidate 失败:", error); // 常见错误处理
     });
   ```
* **在连接建立后尝试添加或移除流：**  在某些状态下，`RTCPeerConnection` 的状态不允许添加或移除流。开发者需要根据连接状态来控制这些操作。
* **忘记处理 `onicecandidate` 事件：** 如果开发者没有正确监听 `onicecandidate` 事件并将生成的 candidate 发送给远端，则无法建立连接。
* **在 `negotiationneeded` 事件中没有创建和发送 offer/answer：** 如果开发者没有响应 `negotiationneeded` 事件，重新协商将无法完成。

**用户操作到达此处的调试线索：**

当开发者在使用 WebRTC 功能时遇到问题，例如：

1. **无法建立连接：**  这可能与 ICE candidate 的交换有关。调试时，开发者可能会检查 `addIceCandidate` 的调用是否成功，以及收到的 candidate 是否正确。
2. **媒体流无法添加或显示：** 开发者可能会检查 `addStream` 或 `addTrack` 的调用，以及是否正确获取了本地媒体流。
3. **连接意外断开或状态异常：**  开发者可能会查看 `iceconnectionstatechange` 事件，并尝试理解为什么连接状态发生了变化。
4. **数据通道无法正常工作：** 开发者可能会检查数据通道的创建过程和状态。

为了调试这些问题，Chromium 的开发者可能会使用以下方法：

* **设置断点：** 在 `rtc_peer_connection_handler_test.cc` 的相关测试用例中设置断点，模拟用户操作，查看 `RTCPeerConnectionHandler` 的内部状态和方法调用。
* **查看日志：** WebRTC 和 Chromium 提供了丰富的日志信息，可以帮助开发者追踪问题的根源。
* **使用 `chrome://webrtc-internals`：**  这是一个 Chrome 提供的内部页面，可以查看 WebRTC 连接的详细信息，包括 ICE candidate 的交换、连接状态、统计数据等。

总而言之，这部分测试代码确保了 `RTCPeerConnectionHandler` 能够正确地处理 WebRTC 连接的各个关键环节，并与底层的 WebRTC 实现以及上层的 JavaScript API 正确交互。 它可以帮助开发者理解当 JavaScript 调用 WebRTC API 时，Blink 引擎内部发生了什么，并为调试 WebRTC 相关问题提供了线索。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_peer_connection_handler_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
->AddIceCandidate(request, candidate);
  RunMessageLoopsUntilIdle();
  EXPECT_TRUE(request->was_called());
  EXPECT_EQ(kDummySdp, mock_peer_connection_->ice_sdp());
  EXPECT_EQ(1, mock_peer_connection_->sdp_mline_index());
  EXPECT_EQ("sdpMid", mock_peer_connection_->sdp_mid());
}

TEST_F(RTCPeerConnectionHandlerTest, addAndRemoveStream) {
  String stream_label = "local_stream";
  MediaStreamDescriptor* local_stream = CreateLocalMediaStream(stream_label);

  EXPECT_CALL(
      *mock_tracker_.Get(),
      TrackAddTransceiver(
          pc_handler_.get(),
          PeerConnectionTracker::TransceiverUpdatedReason::kAddTrack, _, _))
      .Times(2);
  EXPECT_TRUE(AddStream(local_stream));
  EXPECT_EQ(stream_label.Utf8(), mock_peer_connection_->stream_label());
  EXPECT_EQ(2u, mock_peer_connection_->GetSenders().size());

  EXPECT_FALSE(AddStream(local_stream));
  EXPECT_TRUE(RemoveStream(local_stream));
  // Senders are not removed, only their tracks are nulled.
  ASSERT_EQ(2u, mock_peer_connection_->GetSenders().size());
  EXPECT_EQ(mock_peer_connection_->GetSenders()[0]->track(), nullptr);
  EXPECT_EQ(mock_peer_connection_->GetSenders()[0]->track(), nullptr);

  StopAllTracks(local_stream);
}

TEST_F(RTCPeerConnectionHandlerTest, addStreamWithStoppedAudioAndVideoTrack) {
  String stream_label = "local_stream";
  MediaStreamDescriptor* local_stream = CreateLocalMediaStream(stream_label);

  auto audio_components = local_stream->AudioComponents();
  auto* native_audio_source =
      MediaStreamAudioSource::From(audio_components[0]->Source());
  native_audio_source->StopSource();

  auto video_tracks = local_stream->VideoComponents();
  auto* native_video_source = static_cast<MediaStreamVideoSource*>(
      video_tracks[0]->Source()->GetPlatformSource());
  native_video_source->StopSource();

  EXPECT_TRUE(AddStream(local_stream));
  EXPECT_EQ(stream_label.Utf8(), mock_peer_connection_->stream_label());
  EXPECT_EQ(2u, mock_peer_connection_->GetSenders().size());

  StopAllTracks(local_stream);
}

TEST_F(RTCPeerConnectionHandlerTest, OnConnectionChange) {
  testing::InSequence sequence;

  webrtc::PeerConnectionInterface::PeerConnectionState new_state =
      webrtc::PeerConnectionInterface::PeerConnectionState::kNew;
  EXPECT_CALL(*mock_tracker_.Get(),
              TrackConnectionStateChange(
                  pc_handler_.get(),
                  webrtc::PeerConnectionInterface::PeerConnectionState::kNew));
  EXPECT_CALL(*mock_client_.Get(),
              DidChangePeerConnectionState(
                  webrtc::PeerConnectionInterface::PeerConnectionState::kNew));
  pc_handler_->observer()->OnConnectionChange(new_state);

  new_state = webrtc::PeerConnectionInterface::PeerConnectionState::kConnecting;
  EXPECT_CALL(
      *mock_tracker_.Get(),
      TrackConnectionStateChange(
          pc_handler_.get(),
          webrtc::PeerConnectionInterface::PeerConnectionState::kConnecting));
  EXPECT_CALL(
      *mock_client_.Get(),
      DidChangePeerConnectionState(
          webrtc::PeerConnectionInterface::PeerConnectionState::kConnecting));
  pc_handler_->observer()->OnConnectionChange(new_state);

  new_state = webrtc::PeerConnectionInterface::PeerConnectionState::kConnected;
  EXPECT_CALL(
      *mock_tracker_.Get(),
      TrackConnectionStateChange(
          pc_handler_.get(),
          webrtc::PeerConnectionInterface::PeerConnectionState::kConnected));
  EXPECT_CALL(
      *mock_client_.Get(),
      DidChangePeerConnectionState(
          webrtc::PeerConnectionInterface::PeerConnectionState::kConnected));
  pc_handler_->observer()->OnConnectionChange(new_state);

  new_state =
      webrtc::PeerConnectionInterface::PeerConnectionState::kDisconnected;
  EXPECT_CALL(
      *mock_tracker_.Get(),
      TrackConnectionStateChange(
          pc_handler_.get(),
          webrtc::PeerConnectionInterface::PeerConnectionState::kDisconnected));
  EXPECT_CALL(
      *mock_client_.Get(),
      DidChangePeerConnectionState(
          webrtc::PeerConnectionInterface::PeerConnectionState::kDisconnected));
  pc_handler_->observer()->OnConnectionChange(new_state);

  new_state = webrtc::PeerConnectionInterface::PeerConnectionState::kFailed;
  EXPECT_CALL(
      *mock_tracker_.Get(),
      TrackConnectionStateChange(
          pc_handler_.get(),
          webrtc::PeerConnectionInterface::PeerConnectionState::kFailed));
  EXPECT_CALL(
      *mock_client_.Get(),
      DidChangePeerConnectionState(
          webrtc::PeerConnectionInterface::PeerConnectionState::kFailed));
  pc_handler_->observer()->OnConnectionChange(new_state);

  new_state = webrtc::PeerConnectionInterface::PeerConnectionState::kClosed;
  EXPECT_CALL(
      *mock_tracker_.Get(),
      TrackConnectionStateChange(
          pc_handler_.get(),
          webrtc::PeerConnectionInterface::PeerConnectionState::kClosed));
  EXPECT_CALL(
      *mock_client_.Get(),
      DidChangePeerConnectionState(
          webrtc::PeerConnectionInterface::PeerConnectionState::kClosed));
  pc_handler_->observer()->OnConnectionChange(new_state);
}

TEST_F(RTCPeerConnectionHandlerTest, OnIceGatheringChange) {
  testing::InSequence sequence;
  EXPECT_CALL(*mock_tracker_.Get(),
              TrackIceGatheringStateChange(
                  pc_handler_.get(),
                  webrtc::PeerConnectionInterface::kIceGatheringNew));
  EXPECT_CALL(*mock_client_.Get(),
              DidChangeIceGatheringState(
                  webrtc::PeerConnectionInterface::kIceGatheringNew));
  EXPECT_CALL(*mock_tracker_.Get(),
              TrackIceGatheringStateChange(
                  pc_handler_.get(),
                  webrtc::PeerConnectionInterface::kIceGatheringGathering));
  EXPECT_CALL(*mock_client_.Get(),
              DidChangeIceGatheringState(
                  webrtc::PeerConnectionInterface::kIceGatheringGathering));
  EXPECT_CALL(*mock_tracker_.Get(),
              TrackIceGatheringStateChange(
                  pc_handler_.get(),
                  webrtc::PeerConnectionInterface::kIceGatheringComplete));
  EXPECT_CALL(*mock_client_.Get(),
              DidChangeIceGatheringState(
                  webrtc::PeerConnectionInterface::kIceGatheringComplete));

  webrtc::PeerConnectionInterface::IceGatheringState new_state =
      webrtc::PeerConnectionInterface::kIceGatheringNew;
  pc_handler_->observer()->OnIceGatheringChange(new_state);

  new_state = webrtc::PeerConnectionInterface::kIceGatheringGathering;
  pc_handler_->observer()->OnIceGatheringChange(new_state);

  new_state = webrtc::PeerConnectionInterface::kIceGatheringComplete;
  pc_handler_->observer()->OnIceGatheringChange(new_state);

  // Check NULL candidate after ice gathering is completed.
  EXPECT_EQ("", mock_client_->candidate_mid());
  EXPECT_FALSE(mock_client_->candidate_mlineindex().has_value());
  EXPECT_EQ("", mock_client_->candidate_sdp());
}

TEST_F(RTCPeerConnectionHandlerTest, OnIceCandidate) {
  testing::InSequence sequence;
  EXPECT_CALL(*mock_tracker_.Get(),
              TrackAddIceCandidate(pc_handler_.get(), _,
                                   PeerConnectionTracker::kSourceLocal, true));
  EXPECT_CALL(*mock_client_.Get(), DidGenerateICECandidate(_));

  std::unique_ptr<webrtc::IceCandidateInterface> native_candidate(
      mock_dependency_factory_->CreateIceCandidate("sdpMid", 1, kDummySdp));
  pc_handler_->observer()->OnIceCandidate(native_candidate.get());
  RunMessageLoopsUntilIdle();
  EXPECT_EQ("sdpMid", mock_client_->candidate_mid());
  EXPECT_EQ(1, mock_client_->candidate_mlineindex());
  EXPECT_EQ(kDummySdp, mock_client_->candidate_sdp());
}

TEST_F(RTCPeerConnectionHandlerTest, OnRenegotiationNeeded) {
  testing::InSequence sequence;
  EXPECT_CALL(*mock_peer_connection_, ShouldFireNegotiationNeededEvent)
      .WillOnce(Return(true));
  EXPECT_CALL(*mock_tracker_.Get(),
              TrackOnRenegotiationNeeded(pc_handler_.get()));
  EXPECT_CALL(*mock_client_.Get(), NegotiationNeeded());
  pc_handler_->observer()->OnNegotiationNeededEvent(42);
}

TEST_F(RTCPeerConnectionHandlerTest, CreateDataChannel) {
  blink::WebString label = "d1";
  EXPECT_CALL(*mock_tracker_.Get(),
              TrackCreateDataChannel(pc_handler_.get(), testing::NotNull(),
                                     PeerConnectionTracker::kSourceLocal));
  rtc::scoped_refptr<webrtc::DataChannelInterface> channel =
      pc_handler_->CreateDataChannel("d1", webrtc::DataChannelInit());
  EXPECT_TRUE(channel.get());
  EXPECT_EQ(label.Utf8(), channel->label());
}

TEST_F(RTCPeerConnectionHandlerTest, CheckInsertableStreamsConfig) {
  for (bool encoded_insertable_streams : {true, false}) {
    auto handler = std::make_unique<RTCPeerConnectionHandlerUnderTest>(
        mock_client_.Get(), mock_dependency_factory_.Get(),
        encoded_insertable_streams);
    EXPECT_EQ(handler->encoded_insertable_streams(),
              encoded_insertable_streams);
  }
}

TEST_F(RTCPeerConnectionHandlerTest, ThermalResourceDefaultValue) {
  EXPECT_TRUE(mock_peer_connection_->adaptation_resources().empty());
  pc_handler_->OnThermalStateChange(
      mojom::blink::DeviceThermalState::kCritical);
#if BUILDFLAG(IS_MAC) || BUILDFLAG(IS_CHROMEOS)
  bool expect_disabled = false;
#else
  bool expect_disabled = true;
#endif
  // A ThermalResource is created in response to the thermal signal.
  EXPECT_EQ(mock_peer_connection_->adaptation_resources().empty(),
            expect_disabled);
}

TEST_F(RTCPeerConnectionHandlerTest,
       ThermalStateChangeDoesNothingIfThermalResourceIsDisabled) {
  // Overwrite base::Feature kWebRtcThermalResource's default to DISABLED.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndDisableFeature(kWebRtcThermalResource);

  EXPECT_TRUE(mock_peer_connection_->adaptation_resources().empty());
  pc_handler_->OnThermalStateChange(
      mojom::blink::DeviceThermalState::kCritical);
  // A ThermalResource is created in response to the thermal signal.
  EXPECT_TRUE(mock_peer_connection_->adaptation_resources().empty());
}

TEST_F(RTCPeerConnectionHandlerTest,
       ThermalStateChangeTriggersThermalResourceIfEnabled) {
  // Overwrite base::Feature kWebRtcThermalResource's default to ENABLED.
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeature(kWebRtcThermalResource);

  EXPECT_TRUE(mock_peer_connection_->adaptation_resources().empty());
  // ThermalResource is created and injected on the fly.
  pc_handler_->OnThermalStateChange(
      mojom::blink::DeviceThermalState::kCritical);
  auto resources = mock_peer_connection_->adaptation_resources();
  ASSERT_EQ(1u, resources.size());
  auto thermal_resource = resources[0];
  EXPECT_EQ("ThermalResource", thermal_resource->Name());
  // The initial kOveruse is observed.
  FakeResourceListener resource_listener;
  thermal_resource->SetResourceListener(&resource_listener);
  EXPECT_EQ(1u, resource_listener.measurement_count());
  EXPECT_EQ(webrtc::ResourceUsageState::kOveruse,
            resource_listener.latest_measurement());
  // ThermalResource responds to new measurements.
  pc_handler_->OnThermalStateChange(mojom::blink::DeviceThermalState::kNominal);
  EXPECT_EQ(2u, resource_listener.measurement_count());
  EXPECT_EQ(webrtc::ResourceUsageState::kUnderuse,
            resource_listener.latest_measurement());
  thermal_resource->SetResourceListener(nullptr);
}

TEST_F(RTCPeerConnectionHandlerTest,
       ThermalStateUmaListenerCreatedWhenVideoStreamAdded) {
  base::HistogramTester histogram;
  EXPECT_FALSE(pc_handler_->HasThermalUmaListener());
  MediaStreamDescriptor* local_stream = CreateLocalMediaStream("local_stream");
  EXPECT_TRUE(AddStream(local_stream));
  EXPECT_TRUE(pc_handler_->HasThermalUmaListener());
}

TEST_F(RTCPeerConnectionHandlerTest,
       SpeedLimitUmaListenerCreatedWhenStreamAdded) {
  base::HistogramTester histogram;
  EXPECT_FALSE(pc_handler_->HasSpeedLimitUmaListener());
  MediaStreamDescriptor* local_stream = CreateLocalMediaStream("local_stream");
  EXPECT_TRUE(AddStream(local_stream));
  EXPECT_TRUE(pc_handler_->HasSpeedLimitUmaListener());
}

TEST_F(RTCPeerConnectionHandlerTest, CandidatesIgnoredWheHandlerDeleted) {
  auto* observer = pc_handler_->observer();
  std::unique_ptr<webrtc::IceCandidateInterface> native_candidate(
      mock_dependency_factory_->CreateIceCandidate("sdpMid", 1, kDummySdp));
  pc_handler_.reset();
  observer->OnIceCandidate(native_candidate.get());
}

TEST_F(RTCPeerConnectionHandlerTest,
       CandidatesIgnoredWheHandlerDeletedFromEvent) {
  auto* observer = pc_handler_->observer();
  std::unique_ptr<webrtc::IceCandidateInterface> native_candidate(
      mock_dependency_factory_->CreateIceCandidate("sdpMid", 1, kDummySdp));
  EXPECT_CALL(*mock_client_, DidChangeSessionDescriptions(_, _, _, _))
      .WillOnce(testing::Invoke([&] { pc_handler_.reset(); }));
  observer->OnIceCandidate(native_candidate.get());
}

TEST_F(RTCPeerConnectionHandlerTest,
       OnIceCandidateAfterClientGarbageCollectionDoesNothing) {
  testing::InSequence sequence;
  EXPECT_CALL(*mock_tracker_.Get(),
              TrackAddIceCandidate(pc_handler_.get(), _,
                                   PeerConnectionTracker::kSourceLocal, true))
      .Times(0);

  std::unique_ptr<webrtc::IceCandidateInterface> native_candidate(
      mock_dependency_factory_->CreateIceCandidate("sdpMid", 1, kDummySdp));
  mock_client_ = nullptr;
  WebHeap::CollectAllGarbageForTesting();
  pc_handler_->observer()->OnIceCandidate(native_candidate.get());
  RunMessageLoopsUntilIdle();
}

TEST_F(RTCPeerConnectionHandlerTest,
       OnIceCandidateAfterClientGarbageCollectionFails) {
  DummyExceptionStateForTesting exception_state;
  auto pc_handler = CreateRTCPeerConnectionHandlerUnderTest();
  mock_client_ = nullptr;
  WebHeap::CollectAllGarbageForTesting();
  EXPECT_FALSE(pc_handler->Initialize(
      /*context=*/nullptr, webrtc::PeerConnectionInterface::RTCConfiguration(),
      /*frame=*/nullptr, exception_state, /*rtp_transport=*/nullptr));
}

}  // namespace blink

"""


```