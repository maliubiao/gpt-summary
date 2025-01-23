Response:
The user wants a summary of the functionality of the provided C++ code for a Chromium Blink engine component. I need to identify the core purpose of the code and how its various test cases contribute to validating that functionality. The user also asks for connections to web technologies (JavaScript, HTML, CSS), examples of logical reasoning with input/output, common user/programming errors, and how user actions lead to this code.

Here's a breakdown of the code's functionality:

1. **Core Functionality:** The code tests the `MediaStreamVideoTrack` class, which is responsible for handling video data within the WebRTC framework in Blink. This includes:
    *   Receiving video frames from a source.
    *   Delivering these frames to sinks (consumers of the video stream).
    *   Handling encoded video frames.
    *   Managing constraints on the video stream (e.g., minimum/maximum frame rate).
    *   Notifying sinks about changes in constraints.
    *   Handling changes in the sub-capture target version (relevant for screen capture).
    *   Managing the enabled/disabled state of the track.
    *   Propagating content hints.
    *   Handling the stopping of the video source.
    *   Implementing a timer to request refresh frames, especially relevant for screen casting.

2. **Connections to Web Technologies:**  `MediaStreamVideoTrack` is a core part of the WebRTC API, which is heavily used in JavaScript for real-time communication features.

3. **Logical Reasoning:**  The tests demonstrate logical behavior, like ensuring frames are dropped when the sub-capture target version is outdated and delivered when it's current.

4. **User/Programming Errors:**  The tests indirectly highlight potential issues like not handling sub-capture target version changes correctly or failing to manage video constraints properly.

5. **User Operations:** User actions that lead to this code being executed involve any interaction with web pages that use WebRTC to capture and display video (e.g., video calls, screen sharing).

Now, I'll synthesize these points into a concise summary for "part 2".
这是对`blink/renderer/modules/mediastream/media_stream_video_track_test.cc`文件功能的归纳总结，延续了第一部分的分析。

**功能归纳:**

这部分代码主要关注 `MediaStreamVideoTrack` 及其与编码后视频帧（encoded video frames）相关的特性测试。同时也测试了视频轨道在约束条件变化时的行为，以及与屏幕共享相关的刷新帧机制。

**具体功能点包括:**

1. **编码后视频帧的处理 (Encoded Video Frames):**
    *   测试连接和断开编码后的视频接收器（encoded sink）的功能，验证了在连接和断开时对源 (`mock_source()`) 的 `OnEncodedSinkEnabled`、`OnEncodedSinkDisabled` 和 `OnCapturingLinkSecured` 方法的调用。
    *   测试在编码后的接收器连接后，能否正确传输编码后的视频帧 (`DeliverEncodedVideoFrame`)。
    *   测试了在启用和禁用视频轨道时，编码后视频帧的分发逻辑。特别关注了在禁用状态下收到关键帧和非关键帧的处理，以及重新启用后是否需要关键帧才能恢复分发。
    *   测试了内容提示类型 (`ContentHintType`) 能否正确地传递到编码后的接收器。
    *   测试了当视频源停止 (`StopSource()`) 时，编码后的接收器的状态是否能正确更新为 `kReadyStateEnded`。

2. **视频约束 (Video Constraints):**
    *   测试了当视频轨道的约束条件发生变化时 (例如，`SetMinimumFrameRate`, `SetTrackAdapterSettings` 设置了最大帧率)，能否通知到已连接的视频接收器 (`OnVideoConstraintsChanged`)。
    *   测试了新的视频接收器连接到已经设置了约束条件的视频轨道时，能否立即收到这些约束条件的信息。

3. **刷新帧定时器 (Refresh Frame Timer) - 与屏幕共享相关:**
    *   测试了对于标记为屏幕共享的视频轨道，设置最小帧率 (`SetMinimumFrameRate`) 后，是否会启动刷新帧定时器，并定期调用源的 `OnRequestRefreshFrame` 方法，以确保屏幕内容及时更新。
    *   测试了对于非屏幕共享的视频轨道，设置最小帧率后是否不会启动刷新帧定时器。
    *   测试了当视频接收器不需要强制的最小帧率时（`GetRequiredMinFramesPerSec()` 返回 0），刷新帧定时器是否不会运行。
    *   测试了 `blink::MediaStreamVideoWebRtcSink` 这类特定的接收器有默认的最小帧率要求，即使视频轨道本身没有设置，也会触发刷新帧定时器。
    *   测试了当有多个接收器连接时，会取所有接收器中最大的最小帧率要求来驱动刷新帧定时器。
    *   测试了接收器被移除后，刷新帧定时器会根据剩余接收器的需求进行调整。
    *   测试了通过 `NotifyConstraintsConfigurationComplete()` 方法设置最小帧率也能启动刷新帧定时器。
    *   测试了当通过 `NotifyConstraintsConfigurationComplete()` 方法但未设置最小帧率时，刷新帧定时器不会启动。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **JavaScript:** WebRTC API 在 JavaScript 中被广泛使用，例如通过 `getUserMedia()` 获取媒体流，然后可以将视频流通过 `RTCPeerConnection` 发送给远端。`MediaStreamVideoTrack` 对象在 JavaScript 中有对应的表示，开发者可以通过 JavaScript 代码设置视频轨道的属性和监听事件。例如，JavaScript 代码可以调用 `videoTrack.enabled = false` 来禁用视频轨道，这会触发 C++ 代码中相应的逻辑。
*   **HTML:** `<video>` 标签常用于显示视频流。JavaScript 可以将 `MediaStream` 对象设置为 `<video>` 元素的 `srcObject` 属性，从而将视频流渲染到 HTML 页面上。`MediaStreamVideoTrack` 承载的视频数据最终会通过 HTML 元素展示给用户。
*   **CSS:** CSS 可以用来控制 `<video>` 元素的样式，例如大小、边框等，但与 `MediaStreamVideoTrack` 的核心功能没有直接的逻辑关系。

**逻辑推理的假设输入与输出:**

*   **假设输入:**  一个编码后的视频接收器连接到一个启用了视频轨道的 `MediaStreamVideoTrack`。视频源 `mock_source()` 产生了一个关键帧。
*   **预期输出:** 编码后的视频接收器的 `OnEncodedVideoFrame` 方法会被调用，参数是该关键帧的数据。

*   **假设输入:**  一个编码后的视频接收器连接到一个禁用了视频轨道的 `MediaStreamVideoTrack`。视频源 `mock_source()` 产生了一个非关键帧。
*   **预期输出:** 编码后的视频接收器的 `OnEncodedVideoFrame` 方法不会被调用，直到轨道被重新启用且收到一个关键帧。

**涉及用户或者编程常见的使用错误，举例说明:**

*   **用户错误:** 用户可能在网络状况不佳时尝试进行视频通话，导致视频帧丢失或延迟。这可能会触发与帧丢弃相关的逻辑，例如在第一部分中测试的 `OnNotifyFrameDropped`。
*   **编程错误:** 开发者可能在设置 WebRTC 连接时，没有正确处理视频轨道的约束条件。例如，可能在屏幕共享场景下没有设置合适的最小帧率，导致共享内容更新不及时。这部分代码的测试确保了 Blink 引擎能够正确处理这些约束条件。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户发起视频通话或屏幕共享:**  用户在浏览器中打开一个支持 WebRTC 的网页应用，例如一个在线会议应用。用户点击“发起视频通话”或“共享屏幕”按钮。
2. **JavaScript 调用 WebRTC API:**  网页应用的 JavaScript 代码会调用 `navigator.mediaDevices.getUserMedia()` (对于摄像头) 或 `navigator.mediaDevices.getDisplayMedia()` (对于屏幕共享) 来获取媒体流。
3. **创建 MediaStream 和 MediaStreamTrack 对象:**  浏览器底层会创建 `MediaStream` 对象，其中包含 `MediaStreamVideoTrack` 对象来处理视频数据。
4. **连接视频接收器:**  如果需要将本地视频发送给远端，或者需要在本地预览视频，JavaScript 代码会将 `MediaStreamTrack` 对象添加到 `RTCPeerConnection` 或赋值给 `<video>` 元素的 `srcObject` 属性。这会在 Blink 引擎内部创建相应的视频接收器，并连接到 `MediaStreamVideoTrack`。
5. **视频帧处理:**  当摄像头或屏幕捕获模块产生视频帧时，这些帧会传递到 `MediaStreamVideoTrack`。相关的逻辑（例如，检查 sub-capture target version，应用约束条件，分发给接收器）会在 `media_stream_video_track_test.cc` 中测试。
6. **调试线索:**  如果在视频通话或屏幕共享过程中出现问题，例如画面卡顿、帧率过低、屏幕内容更新不及时等，开发者可能会检查 Blink 引擎的日志，查看 `MediaStreamVideoTrack` 相关的行为，例如是否正确处理了帧丢弃、约束条件或者刷新帧定时器。`media_stream_video_track_test.cc` 中的测试用例可以帮助开发者理解和调试这些问题。

总而言之，这部分测试代码专注于验证 `MediaStreamVideoTrack` 处理编码后视频帧、管理视频约束以及在屏幕共享场景下维护帧率的核心逻辑，确保了 WebRTC 视频功能的稳定性和可靠性。

### 提示词
```
这是目录为blink/renderer/modules/mediastream/media_stream_video_track_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
t_version =
      5;  // No longer current version.
  base::RunLoop run_loop;
  EXPECT_CALL(sink,
              OnNotifyFrameDropped(media::VideoCaptureFrameDropReason::
                                       kSubCaptureTargetVersionNotCurrent))
      .WillOnce(RunOnceClosure(run_loop.QuitClosure()));
  mock_source()->DeliverVideoFrame(std::move(frame));
  run_loop.Run();

  sink.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest,
       DeliversNewFramesAfterSubCaptureTargetVersionChanges) {
  InitializeSource();
  MockMediaStreamVideoSink sink;

  // Track is initialized with sub-capture-target version 5.
  EXPECT_CALL(*mock_source(), GetSubCaptureTargetVersion).WillOnce(Return(5));
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectToTrack(track);
  MediaStreamVideoTrack::From(track)->SetSinkNotifyFrameDroppedCallback(
      &sink, sink.GetNotifyFrameDroppedCB());

  // Crop version updated to 6.
  mock_source()->DeliverNewSubCaptureTargetVersion(6);

  scoped_refptr<media::VideoFrame> frame =
      media::VideoFrame::CreateBlackFrame(gfx::Size(600, 400));
  // Frame with current sub-capture-target version should be delivered.
  frame->metadata().sub_capture_target_version = 6;
  EXPECT_CALL(sink, OnNotifyFrameDropped).Times(0);
  DeliverVideoFrameAndWaitForRenderer(std::move(frame), &sink);

  sink.DisconnectFromTrack();
}

class MediaStreamVideoTrackEncodedTest : public MediaStreamVideoTrackTest {
 public:
  void InitializeSource() override {
    MediaStreamVideoTrackTest::InitializeSource();
    ON_CALL(*mock_source(), SupportsEncodedOutput).WillByDefault(Return(true));
  }
};

TEST_F(MediaStreamVideoTrackEncodedTest, ConnectEncodedSink) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  EXPECT_CALL(*mock_source(), OnEncodedSinkEnabled);
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(false));
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(true)).Times(0);
  EXPECT_CALL(*mock_source(), OnEncodedSinkDisabled).Times(0);
  sink.ConnectEncodedToTrack(track);
  Mock::VerifyAndClearExpectations(mock_source());
  sink.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoTrackEncodedTest, DisconnectEncodedSink) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectEncodedToTrack(track);
  EXPECT_CALL(*mock_source(), OnEncodedSinkDisabled);
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(true));
  sink.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoTrackEncodedTest,
       CapturingLinkSecuredWithEncodedAndNormalTracks) {
  InitializeSource();
  MockMediaStreamVideoSink sink1;
  WebMediaStreamTrack track1 = CreateTrack();
  InSequence s;
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(true));
  sink1.ConnectToTrack(track1);
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(false));
  MockMediaStreamVideoSink sink2;
  WebMediaStreamTrack track2 = CreateTrack();
  sink2.ConnectEncodedToTrack(track2);
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(false));
  sink1.DisconnectFromTrack();
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(true));
  sink2.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoTrackEncodedTest, TransferOneEncodedVideoFrame) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectEncodedToTrack(track);
  base::RunLoop run_loop;
  base::RepeatingClosure quit_closure = run_loop.QuitClosure();
  EXPECT_CALL(sink, OnEncodedVideoFrame).WillOnce(Invoke([&](base::TimeTicks) {
    std::move(quit_closure).Run();
  }));
  mock_source()->DeliverEncodedVideoFrame(
      base::MakeRefCounted<MockEncodedVideoFrame>());
  run_loop.Run();
  Mock::VerifyAndClearExpectations(mock_source());
  sink.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoTrackEncodedTest, SupportsEncodedDisableEnable) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectEncodedToTrack(track);

  auto key_frame = base::MakeRefCounted<MockEncodedVideoFrame>();
  EXPECT_CALL(*key_frame, IsKeyFrame).WillRepeatedly(Return(true));
  auto delta_frame = base::MakeRefCounted<MockEncodedVideoFrame>();
  EXPECT_CALL(*delta_frame, IsKeyFrame).WillRepeatedly(Return(false));

  DeliverEncodedVideoFrameAndWait(key_frame, &sink);

  // Key frame when disabled -> shouldn't get dispatched
  MediaStreamVideoTrack::From(track)->SetEnabled(false);
  EXPECT_FALSE(sink.enabled());
  {
    EXPECT_CALL(sink, OnEncodedVideoFrame).Times(0);
    mock_source()->DeliverEncodedVideoFrame(key_frame);
    DepleteIOCallbacks();
  }

  // Delta frame when disabled -> shouldn't get dispatched until key frame
  // appears.
  EXPECT_CALL(*mock_source(), OnRequestRefreshFrame);
  MediaStreamVideoTrack::From(track)->SetEnabled(true);
  EXPECT_TRUE(sink.enabled());
  {
    EXPECT_CALL(sink, OnEncodedVideoFrame).Times(0);
    mock_source()->DeliverEncodedVideoFrame(delta_frame);
    DepleteIOCallbacks();
  }

  // After a key frame things should be flowing again.
  DeliverEncodedVideoFrameAndWait(key_frame, &sink);
  DeliverEncodedVideoFrameAndWait(delta_frame, &sink);

  Mock::VerifyAndClearExpectations(mock_source());
  sink.DisconnectEncodedFromTrack();
}

TEST_P(MediaStreamVideoTrackEncodedTest, PropagatesContentHintType) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectEncodedToTrack(track);
  MediaStreamVideoTrack::From(track)->SetContentHint(GetParam());
  EXPECT_EQ(sink.content_hint(), GetParam());
  sink.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoTrackEncodedTest, SourceStopped) {
  InitializeSource();
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track = CreateTrack();
  sink.ConnectEncodedToTrack(track);
  EXPECT_EQ(WebMediaStreamSource::kReadyStateLive, sink.state());

  mock_source()->StopSource();
  EXPECT_EQ(WebMediaStreamSource::kReadyStateEnded, sink.state());
  sink.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, DeliversConstraintsToKnownSinks) {
  InitializeSource();
  WebMediaStreamTrack track = CreateTrack();
  MockMediaStreamVideoSink sink1;
  EXPECT_CALL(sink1,
              OnVideoConstraintsChanged(Eq(std::nullopt), Eq(std::nullopt)));
  sink1.ConnectToTrack(track);
  MockMediaStreamVideoSink sink2;
  EXPECT_CALL(sink2,
              OnVideoConstraintsChanged(Eq(std::nullopt), Eq(std::nullopt)));
  sink2.ConnectToTrack(track);
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  Mock::VerifyAndClearExpectations(&sink1);
  Mock::VerifyAndClearExpectations(&sink2);

  EXPECT_CALL(sink1,
              OnVideoConstraintsChanged(Eq(std::nullopt), Eq(std::nullopt)));
  EXPECT_CALL(sink2,
              OnVideoConstraintsChanged(Eq(std::nullopt), Eq(std::nullopt)));
  native_track->SetTrackAdapterSettings(VideoTrackAdapterSettings());
  native_track->NotifyConstraintsConfigurationComplete();
  Mock::VerifyAndClearExpectations(&sink1);
  Mock::VerifyAndClearExpectations(&sink2);

  native_track->SetMinimumFrameRate(200);
  EXPECT_CALL(sink1,
              OnVideoConstraintsChanged(Optional(200.0), Eq(std::nullopt)));
  EXPECT_CALL(sink2,
              OnVideoConstraintsChanged(Optional(200.0), Eq(std::nullopt)));
  native_track->SetTrackAdapterSettings(VideoTrackAdapterSettings());
  native_track->NotifyConstraintsConfigurationComplete();
  Mock::VerifyAndClearExpectations(&sink1);
  Mock::VerifyAndClearExpectations(&sink2);

  EXPECT_CALL(sink1,
              OnVideoConstraintsChanged(Optional(200.0), Optional(300.0)));
  EXPECT_CALL(sink2,
              OnVideoConstraintsChanged(Optional(200.0), Optional(300.0)));
  VideoTrackAdapterSettings settings;
  settings.set_max_frame_rate(300);
  native_track->SetTrackAdapterSettings(settings);
  native_track->NotifyConstraintsConfigurationComplete();
  EXPECT_THAT(native_track->max_frame_rate(), testing::Optional(300));
  Mock::VerifyAndClearExpectations(&sink1);
  Mock::VerifyAndClearExpectations(&sink2);

  sink1.DisconnectFromTrack();
  sink2.DisconnectFromTrack();
}

TEST_F(MediaStreamVideoTrackTest, DeliversConstraintsToNewSinks) {
  InitializeSource();
  WebMediaStreamTrack track = CreateTrack();
  MediaStreamVideoTrack* const native_track =
      MediaStreamVideoTrack::From(track);
  native_track->SetMinimumFrameRate(10);
  VideoTrackAdapterSettings settings;
  settings.set_max_frame_rate(20);
  native_track->SetTrackAdapterSettings(settings);
  native_track->NotifyConstraintsConfigurationComplete();
  EXPECT_THAT(native_track->max_frame_rate(), testing::Optional(20));

  MockMediaStreamVideoSink sink1;
  sink1.ConnectToTrack(track);
  Mock::VerifyAndClearExpectations(&sink1);

  MockMediaStreamVideoSink sink2;
  EXPECT_CALL(sink1, OnVideoConstraintsChanged).Times(0);
  EXPECT_CALL(sink2, OnVideoConstraintsChanged(Optional(10.0), Optional(20.0)));
  sink2.ConnectToTrack(track);
}

INSTANTIATE_TEST_SUITE_P(,
                         MediaStreamVideoTrackTest,
                         Values(ContentHintType::kVideoMotion,
                                ContentHintType::kVideoDetail,
                                ContentHintType::kVideoText));

INSTANTIATE_TEST_SUITE_P(,
                         MediaStreamVideoTrackEncodedTest,
                         Values(ContentHintType::kVideoMotion,
                                ContentHintType::kVideoDetail,
                                ContentHintType::kVideoText));

class MediaStreamVideoTrackRefreshFrameTimerTest
    : public MediaStreamVideoTrackTest {
 public:
  void SetUp() override { InitializeSource(); }
};

TEST_F(MediaStreamVideoTrackRefreshFrameTimerTest,
       SetMinFrameRateForScreenCastTrack) {
  // |RequestRefreshFrame| should be called exactly twice within kMinFrameRate
  // interval: First time from |AddSink| and second time from the refresh timer.
  EXPECT_CALL(*mock_source(), OnRequestRefreshFrame).Times(2);
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track =
      CreateTrackWithSettings(VideoTrackAdapterSettings());
  auto* video_track = MediaStreamVideoTrack::From(track);
  video_track->SetMinimumFrameRate(kMinFrameRate);
  video_track->SetIsScreencastForTesting(true);

  sink.ConnectToTrack(track);
  test::RunDelayedTasks(base::Hertz(kMinFrameRate));

  EXPECT_TRUE(video_track->IsRefreshFrameTimerRunningForTesting());
  video_track->StopAndNotify(base::DoNothing());
  EXPECT_FALSE(video_track->IsRefreshFrameTimerRunningForTesting());
}

TEST_F(MediaStreamVideoTrackRefreshFrameTimerTest,
       SetMinFrameRateForNonScreenCastTrack) {
  // |RequestRefreshFrame| should only be called once from |AddSink| since
  // refresh frame timer is not running.
  EXPECT_CALL(*mock_source(), OnRequestRefreshFrame).Times(1);
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track =
      CreateTrackWithSettings(VideoTrackAdapterSettings());

  auto* video_track = MediaStreamVideoTrack::From(track);
  video_track->SetMinimumFrameRate(kMinFrameRate);
  // Refresh frame timer will not be run when |is_screencast_| is false.
  video_track->SetIsScreencastForTesting(false);

  sink.ConnectToTrack(track);
  test::RunDelayedTasks(base::Hertz(kMinFrameRate));

  EXPECT_FALSE(video_track->IsRefreshFrameTimerRunningForTesting());
}

TEST_F(MediaStreamVideoTrackRefreshFrameTimerTest, RequiredRefreshRate) {
  // Sinks that have a required min frames per sec as 0 will not lead
  // to video track running the refresh frame timer.
  EXPECT_CALL(*mock_source(), OnRequestRefreshFrame).Times(1);

  MockMediaStreamVideoSink sink;
  EXPECT_EQ(sink.GetRequiredMinFramesPerSec(), 0);

  WebMediaStreamTrack track =
      CreateTrackWithSettings(VideoTrackAdapterSettings());
  auto* video_track = MediaStreamVideoTrack::From(track);
  video_track->SetIsScreencastForTesting(true);

  sink.ConnectToTrack(track);
  test::RunDelayedTasks(base::Seconds(1));
}

TEST_F(MediaStreamVideoTrackRefreshFrameTimerTest,
       RequiredRefreshRateWebRTCSink) {
  // WebRTC sink has a required min frames per sec set to 1 so when we do
  // not have any min frame rate set on the video track, this required rate will
  // be used by the timer.
  EXPECT_CALL(*mock_source(), OnRequestRefreshFrame).Times(2);

  WebMediaStreamTrack track = MediaStreamVideoTrack::CreateVideoTrack(
      mock_source(), WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
      true);
  MediaStreamVideoTrack::From(track)->SetIsScreencastForTesting(true);

  Persistent<MediaStreamComponent> media_stream_component = *track;
  blink::MediaStreamVideoWebRtcSink webrtc_sink(
      media_stream_component,
      MakeGarbageCollected<MockPeerConnectionDependencyFactory>(),
      blink::scheduler::GetSingleThreadTaskRunnerForTesting());
  EXPECT_EQ(webrtc_sink.GetRequiredMinFramesPerSec(), 1);

  test::RunDelayedTasks(base::Seconds(1));
}

TEST_F(MediaStreamVideoTrackRefreshFrameTimerTest,
       RequiredRefreshRateMultipleSinksAdded) {
  // |RequestRefreshFrame| will be called once for every sink added (twice here)
  // and third time from the refresh frame timer started by WebRTC sink. We will
  // pick the maximum of all the required refresh rates to run the timer.
  EXPECT_CALL(*mock_source(), OnRequestRefreshFrame).Times(3);

  WebMediaStreamTrack track = MediaStreamVideoTrack::CreateVideoTrack(
      mock_source(), WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
      true);
  MediaStreamVideoTrack::From(track)->SetIsScreencastForTesting(true);

  // First sink.
  MockMediaStreamVideoSink sink;
  EXPECT_EQ(sink.GetRequiredMinFramesPerSec(), 0);
  sink.ConnectToTrack(track);

  // Second sink.
  Persistent<MediaStreamComponent> media_stream_component = *track;
  blink::MediaStreamVideoWebRtcSink webrtc_sink(
      media_stream_component,
      MakeGarbageCollected<MockPeerConnectionDependencyFactory>(),
      blink::scheduler::GetSingleThreadTaskRunnerForTesting());
  EXPECT_EQ(webrtc_sink.GetRequiredMinFramesPerSec(), 1);

  test::RunDelayedTasks(base::Seconds(1));
}

TEST_F(MediaStreamVideoTrackRefreshFrameTimerTest,
       RequiredRefreshRateMultipleSinksAddedAndRemoved) {
  // |RequestRefreshFrame| will be called once for every sink added (twice
  // here). The second sink (webrtc sink) does have a required min frames per
  // sec but it is removed.
  EXPECT_CALL(*mock_source(), OnRequestRefreshFrame).Times(2);

  WebMediaStreamTrack track = MediaStreamVideoTrack::CreateVideoTrack(
      mock_source(), WebPlatformMediaStreamSource::ConstraintsOnceCallback(),
      true);
  MediaStreamVideoTrack::From(track)->SetIsScreencastForTesting(true);

  // First sink.
  MockMediaStreamVideoSink sink;
  EXPECT_EQ(sink.GetRequiredMinFramesPerSec(), 0);
  sink.ConnectToTrack(track);

  // Second sink added and then removed. The destructor for
  // MediaStreamVideoWebRtcSink calls DisconnectFromTrack.
  {
    Persistent<MediaStreamComponent> media_stream_component = *track;
    blink::MediaStreamVideoWebRtcSink webrtc_sink(
        media_stream_component,
        MakeGarbageCollected<MockPeerConnectionDependencyFactory>(),
        blink::scheduler::GetSingleThreadTaskRunnerForTesting());
    EXPECT_EQ(webrtc_sink.GetRequiredMinFramesPerSec(), 1);
  }

  test::RunDelayedTasks(base::Seconds(1));
}

TEST_F(MediaStreamVideoTrackRefreshFrameTimerTest,
       NotifyConstraintsStartsTimerIfMinFpsIsSet) {
  // |RequestRefreshFrame| should be called exactly twice within kMinFrameRate
  // interval: First time from |NotifyConstraintsConfigurationComplete| and
  // second time from the refresh timer.
  EXPECT_CALL(*mock_source(), OnRequestRefreshFrame).Times(2);
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track =
      CreateTrackWithSettings(VideoTrackAdapterSettings());
  auto* video_track = MediaStreamVideoTrack::From(track);

  video_track->SetIsScreencastForTesting(true);
  sink.ConnectToTrack(track);
  video_track->SetMinimumFrameRate(kMinFrameRate);
  video_track->NotifyConstraintsConfigurationComplete();

  test::RunDelayedTasks(base::Hertz(kMinFrameRate));

  EXPECT_TRUE(video_track->IsRefreshFrameTimerRunningForTesting());
  video_track->StopAndNotify(base::DoNothing());
  EXPECT_FALSE(video_track->IsRefreshFrameTimerRunningForTesting());
}

TEST_F(MediaStreamVideoTrackRefreshFrameTimerTest,
       NotifyConstraintsDontStartTimerIfMinFpsIsUnset) {
  // |RequestRefreshFrame| should only be called once from |AddSink| since
  // refresh frame timer is not running.
  EXPECT_CALL(*mock_source(), OnRequestRefreshFrame).Times(1);
  MockMediaStreamVideoSink sink;
  WebMediaStreamTrack track =
      CreateTrackWithSettings(VideoTrackAdapterSettings());
  auto* video_track = MediaStreamVideoTrack::From(track);

  video_track->SetIsScreencastForTesting(true);
  sink.ConnectToTrack(track);
  video_track->NotifyConstraintsConfigurationComplete();

  test::RunDelayedTasks(base::Hertz(kMinFrameRate));

  EXPECT_FALSE(video_track->IsRefreshFrameTimerRunningForTesting());
}

}  // namespace media_stream_video_track_test
}  // namespace blink
```