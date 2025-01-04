Response:
The user wants to understand the functionality of the provided C++ code snippet from a Chromium Blink engine test file. Specifically, they are asking for:

1. **Functionality Summary:** A general overview of what the code does.
2. **Relevance to Web Technologies:**  Connection to JavaScript, HTML, and CSS with examples.
3. **Logic and Input/Output:**  Understanding the conditional behavior of the tests with hypothetical inputs.
4. **Common Usage Errors:** Identifying potential mistakes developers might make when using the tested functionality.
5. **User Interaction for Debugging:**  Describing how a user's actions could lead to this code being executed during debugging.
6. **Overall Summary (Part 2):** A concise conclusion of the file's purpose, considering it's the second part of a larger file.

Let's break down the code section by section to address each of these points.

**Code Analysis (Part 2):**

* **`TEST_F(MediaStreamVideoSourceTest, StopSuspendedTrack)`:** Tests the scenario where a video track is temporarily disassociated from a "sink" (consumer), which might cause the underlying source to be suspended. It then checks that adding another track prevents the source from staying suspended.
* **`TEST_F(MediaStreamVideoSourceTest, AddTrackAfterStoppingSource)`:** Verifies the behavior when a new video track is created *after* the source has been explicitly stopped. This likely involves checking if the new track's start attempt fails correctly.
* **`TEST_F(MediaStreamVideoSourceTest, AddsEncodedSinkWhenEncodedConsumerAppears)`:** Focuses on the "encoded" data path for video. It checks that when a consumer requests the encoded video stream, the source is notified (likely to start producing encoded data).
* **`TEST_F(MediaStreamVideoSourceTest, AddsEncodedSinkWhenEncodedConsumersAppear)`:**  Similar to the above, but with multiple consumers requesting the encoded stream.
* **`TEST_F(MediaStreamVideoSourceTest, RemovesEncodedSinkWhenEncodedConsumerDisappears)`:**  Tests the opposite of the above – when an encoded stream consumer disconnects, the source should be notified (likely to stop producing encoded data if no other encoded consumers remain).
* **`TEST_F(MediaStreamVideoSourceTest, RemovesEncodedSinkWhenEncodedConsumersDisappear)`:** Similar to the above, but with multiple consumers disconnecting.
* **`TEST_F(MediaStreamVideoSourceTest, RemovesEncodedSinkWhenTrackStops)`:** Checks that stopping a video track also triggers the removal of the encoded sink, even if encoded consumers were connected.
* **`TEST_F(MediaStreamVideoSourceTest, CapturingLinkSecureOnlyEncodedSinks)`:** Examines the "secure" status of the video capturing link. It seems to test that when only encoded sinks are connected, the link might not be considered secure until a consumer actively requests the data.
* **`TEST_F(MediaStreamVideoSourceTest, CapturingLinkSecureTracksAndEncodedSinks)`:**  Tests the secure status when both regular video tracks and encoded sinks are involved.
* **`TEST_F(MediaStreamVideoSourceTest, CanDiscardAlpha)`:**  Tests whether the video source can optimize by discarding the alpha channel (transparency) if the connected consumers don't need it.
* **`TEST_F(MediaStreamVideoSourceTest, CanDiscardAlphaIfOtherSinksDiscard)`:**  A more complex scenario for alpha discarding, considering different types of sinks (those that explicitly don't need alpha, those that default to needing it, and those that depend on other sinks).
* **`TEST_F(MediaStreamVideoSourceTest, CanDiscardAlphaMultipleTracks)`:** Checks the alpha discarding logic when multiple video tracks are involved.
* **`TEST_F(MediaStreamVideoSourceTest, ConfiguredFrameRate)`:**  Tests how the configured frame rate of a video track is determined, especially when there are adjustments made by "adapters" (which can modify the frame rate).

**Planning the Response:**

Now, I'll structure the response based on the user's requirements, drawing information from the code analysis. I'll pay close attention to providing concrete examples for web technologies and user errors. For the debugging scenario, I'll think about the steps a user might take in a web application that would lead to the execution of these video source functionalities.
这是对 `blink/renderer/modules/mediastream/media_stream_video_source_test.cc` 文件第二部分的分析和功能归纳。

**功能归纳 (针对第二部分):**

这部分测试用例主要集中在以下几个方面，进一步验证了 `MediaStreamVideoSource` 的行为和生命周期管理：

1. **暂停和恢复:**  测试了当一个视频轨道暂时没有消费者（sink）时，视频源是否会暂停，以及后续添加新的轨道是否会阻止源进入暂停状态。
2. **停止后的添加轨道:**  验证了在视频源被明确停止后，再尝试添加新的视频轨道时，源的状态和回调函数的行为。
3. **编码数据流的处理:** 详细测试了当有消费者请求编码后的视频数据时 (`encoded sink`)，`MediaStreamVideoSource` 如何管理和通知底层源。包括：
    * 当第一个编码消费者出现时，是否正确地启用了编码输出。
    * 当有多个编码消费者时，是否能正确处理。
    * 当编码消费者消失时，是否正确地禁用了编码输出。
    * 当视频轨道停止时，是否会同时移除相关的编码输出。
4. **安全连接状态:** 测试了 `MediaStreamVideoSource` 如何根据是否存在安全的消费者（例如，需要加密的连接）来更新捕获链路的安全性状态。这涉及到编码消费者和普通消费者两种情况。
5. **Alpha 通道处理:** 深入测试了视频源是否可以根据消费者的需求丢弃 Alpha 通道（透明度信息）以进行优化。这包括：
    * 当所有消费者都不需要 Alpha 通道时，源可以丢弃。
    * 当有消费者需要 Alpha 通道时，源不能丢弃。
    * 考虑了不同类型的消费者，例如明确不需要 Alpha 通道的消费者和依赖其他消费者需求的消费者。
    * 涉及多个视频轨道的情况，判断是否所有轨道都需要 Alpha 通道才能保留。
6. **配置帧率:** 测试了视频源如何处理配置的帧率，特别是当视频轨道有适配器（adapter）调整帧率时，最终生效的帧率是如何确定的。

**与 JavaScript, HTML, CSS 的关系举例:**

虽然这个 C++ 文件是底层引擎代码的测试，但它直接关联着 Web API `MediaStream` 和相关接口，这些 API 是 JavaScript 可以直接操作的。

* **JavaScript `MediaStreamTrack.stop()`:**  测试用例 `TEST_F(MediaStreamVideoSourceTest, StopSuspendedTrack)` 和 `TEST_F(MediaStreamVideoSourceTest, AddTrackAfterStoppingSource)` 模拟了 JavaScript 中调用 `track.stop()` 的场景。当 JavaScript 调用 `track.stop()` 时，底层会触发 `MediaStreamTrackPlatform::Stop()`，进而影响 `MediaStreamVideoSource` 的状态。
    * **假设输入 (JavaScript):**  用户在网页上点击一个按钮，触发 JavaScript 代码 `videoTrack.stop()`.
    * **输出 (C++ 测试):**  `MediaStreamVideoSource` 的状态会变为 `kReadyStateEnded`，并且相关的资源会被释放或标记为可以释放。
* **JavaScript 获取编码后的视频流 (`MediaRecorder`, `EncodedMediaStreamTrack` 等):** 测试用例 `TEST_F(MediaStreamVideoSourceTest, AddsEncodedSinkWhenEncodedConsumerAppears)` 等模拟了 JavaScript 代码尝试获取视频轨道的编码数据流的场景，例如使用 `MediaRecorder` API 录制视频，或者使用 `EncodedMediaStreamTrack` API 处理编码后的帧。
    * **假设输入 (JavaScript):**  网页上的 JavaScript 代码创建了一个 `MediaRecorder` 对象，并将其与一个 `MediaStreamTrack` 关联。
    * **输出 (C++ 测试):** `MediaStreamVideoSource` 会收到通知，知道有一个编码数据的消费者，并调用 `OnEncodedSinkEnabled` 等方法。
* **HTML `<video>` 元素播放视频:**  虽然测试用例没有直接模拟 `<video>` 元素，但 `MockMediaStreamVideoSink` 可以被看作是 `<video>` 元素的底层抽象。当一个 `MediaStreamTrack` 被设置为 `<video>` 元素的 `srcObject` 时，`<video>` 元素就成为了视频数据的消费者。测试用例中 `ConnectToTrack` 和 `DisconnectFromTrack` 模拟了这个过程。
* **CSS 影响透明度:** 测试用例 `TEST_F(MediaStreamVideoSourceTest, CanDiscardAlpha)` 间接关联到 CSS 中对视频透明度的处理。虽然 CSS 不直接控制视频流的 Alpha 通道是否被编码，但它会影响最终的渲染结果。如果 CSS 不需要显示透明效果，那么底层引擎可以优化，不处理 Alpha 通道，这正是这个测试用例验证的。

**逻辑推理，假设输入与输出:**

* **测试用例: `TEST_F(MediaStreamVideoSourceTest, StopSuspendedTrack)`**
    * **假设输入:**
        1. 创建一个视频轨道 `web_track1` 并启动源。
        2. 将 `web_track1` 添加到一个 sink (模拟播放器开始播放)。
        3. 将 `web_track1` 从 sink 中移除 (模拟播放器暂停或停止播放)。
        4. 停止 `web_track1`。
        5. 创建第二个视频轨道 `web_track2`。
        6. 将 `web_track2` 添加到一个 sink。
    * **预期输出:** 在第6步之后，视频源不应该处于暂停 (suspended) 状态，因为 `web_track2` 仍然有消费者。
* **测试用例: `TEST_F(MediaStreamVideoSourceTest, AddTrackAfterStoppingSource)`**
    * **假设输入:**
        1. 创建一个视频轨道 `web_track1` 并启动源。
        2. 停止 `web_track1` (通过 `StopAndNotify`)。
        3. 创建第二个视频轨道 `track2`。
    * **预期输出:** 当创建 `track2` 时，由于源已经被停止，尝试启动 `track2` 的操作可能会失败，或者其状态直接为非活动状态，并且会触发失败的回调 (NumberOfFailedConstraintsCallbacks 会增加)。

**用户或编程常见的使用错误:**

* **忘记处理 `track.stop()` 后的资源释放:**  开发者可能在 JavaScript 中调用 `track.stop()` 后，没有正确处理相关的资源释放，导致内存泄漏或其他问题。测试用例验证了底层引擎在 `stop()` 调用后的行为，确保资源被清理。
* **不理解编码数据流的生命周期:** 开发者可能错误地假设编码数据流会一直可用，即使没有消费者。测试用例验证了当没有编码数据消费者时，源会停止生成编码数据，避免不必要的资源消耗。
* **错误地假设 Alpha 通道始终可用:**  开发者可能没有考虑到视频源可以根据消费者的需求丢弃 Alpha 通道。如果他们的代码依赖于 Alpha 通道的存在，可能会在某些情况下出现错误。测试用例帮助确保底层引擎的这种优化行为是正确的。
* **对帧率配置的理解偏差:** 开发者可能没有意识到适配器可以修改视频轨道的帧率。测试用例验证了最终生效的帧率是如何确定的，帮助开发者更好地理解和控制视频流的帧率。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户打开一个包含音视频功能的网页:** 网页可能使用了 `getUserMedia` 获取用户的摄像头或屏幕共享。
2. **网页创建 `MediaStream` 和 `MediaStreamTrack` 对象:**  JavaScript 代码会操作这些对象来控制音视频流。
3. **用户开始录制视频或进行视频通话:**  这可能涉及到使用 `MediaRecorder` API 或将 `MediaStreamTrack` 设置为 `<video>` 元素的 `srcObject`。
4. **如果涉及到编码数据流:** 用户可能正在使用 `MediaRecorder` 录制视频，或者使用 `EncodedMediaStreamTrack` 处理编码后的帧。
5. **用户可能会暂停、停止录制或结束通话:**  这些操作会触发 JavaScript 代码调用 `track.stop()` 或从 `<video>` 元素中移除 `srcObject`。
6. **如果网页动态地添加或移除视频轨道:**  例如，在视频会议中，新的参与者加入或离开，或者网页动态地切换摄像头。
7. **当开发者进行调试时:** 他们可能会在浏览器开发者工具中查看 `MediaStreamTrack` 的状态，或者检查相关的回调函数是否被正确调用。如果出现问题，他们可能会深入到 Blink 引擎的源代码中进行调试，这时就可能涉及到 `media_stream_video_source_test.cc` 中测试的代码路径。

**总结 (第二部分功能):**

总的来说，`blink/renderer/modules/mediastream/media_stream_video_source_test.cc` 的第二部分专注于测试 `MediaStreamVideoSource` 在更复杂的场景下的行为，特别是关于资源生命周期管理（暂停、停止）、编码数据流的处理、安全连接状态以及 Alpha 通道和帧率的优化处理。这些测试用例确保了当 JavaScript 代码以各种方式操作 `MediaStreamTrack` 时，底层的 C++ 代码能够正确地管理视频源的状态和资源，并且能够根据消费者的需求进行优化。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_video_source_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
ult, MediaStreamVideoSource::RestartResult::IS_STOPPED);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  mock_source()->StopSource();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateEnded);
}

TEST_F(MediaStreamVideoSourceTest, StartStopAndNotifyRestartSupported) {
  WebMediaStreamTrack web_track = CreateTrack("123");
  mock_source()->EnableStopForRestart();
  mock_source()->StartMockedSource();
  EXPECT_EQ(NumberOfSuccessConstraintsCallbacks(), 1);
  EXPECT_EQ(web_track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  EXPECT_CALL(*this, MockNotification());
  MediaStreamTrackPlatform* track =
      MediaStreamTrackPlatform::GetTrack(web_track);
  track->StopAndNotify(WTF::BindOnce(
      &MediaStreamVideoSourceTest::MockNotification, base::Unretained(this)));
  EXPECT_EQ(web_track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateEnded);
  base::RunLoop().RunUntilIdle();
}

TEST_F(MediaStreamVideoSourceTest, StartStopAndNotifyRestartNotSupported) {
  WebMediaStreamTrack web_track = CreateTrack("123");
  mock_source()->DisableStopForRestart();
  mock_source()->StartMockedSource();
  EXPECT_EQ(NumberOfSuccessConstraintsCallbacks(), 1);
  EXPECT_EQ(web_track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  EXPECT_CALL(*this, MockNotification());
  MediaStreamTrackPlatform* track =
      MediaStreamTrackPlatform::GetTrack(web_track);
  track->StopAndNotify(WTF::BindOnce(
      &MediaStreamVideoSourceTest::MockNotification, base::Unretained(this)));
  EXPECT_EQ(web_track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateEnded);
  base::RunLoop().RunUntilIdle();
}

TEST_F(MediaStreamVideoSourceTest, StopSuspendedTrack) {
  WebMediaStreamTrack web_track1 = CreateTrack("123");
  mock_source()->StartMockedSource();
  WebMediaStreamTrack web_track2 = CreateTrack("123");

  // Simulate assigning |track1| to a sink, then removing it from the sink, and
  // then stopping it.
  MediaStreamVideoTrack* track1 = MediaStreamVideoTrack::From(web_track1);
  mock_source()->UpdateHasConsumers(track1, true);
  mock_source()->UpdateHasConsumers(track1, false);
  track1->Stop();

  // Simulate assigning |track2| to a sink. The source should not be suspended.
  MediaStreamVideoTrack* track2 = MediaStreamVideoTrack::From(web_track2);
  mock_source()->UpdateHasConsumers(track2, true);
  EXPECT_FALSE(mock_source()->is_suspended());
}

TEST_F(MediaStreamVideoSourceTest, AddTrackAfterStoppingSource) {
  WebMediaStreamTrack web_track1 = CreateTrack("123");
  mock_source()->StartMockedSource();
  EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());
  EXPECT_EQ(0, NumberOfFailedConstraintsCallbacks());

  MediaStreamVideoTrack* track1 = MediaStreamVideoTrack::From(web_track1);
  EXPECT_CALL(*this, MockNotification());
  // This is equivalent to track.stop() in JavaScript.
  track1->StopAndNotify(WTF::BindOnce(
      &MediaStreamVideoSourceTest::MockNotification, base::Unretained(this)));

  WebMediaStreamTrack track2 = CreateTrack("456");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, NumberOfSuccessConstraintsCallbacks());
  EXPECT_EQ(1, NumberOfFailedConstraintsCallbacks());
}

TEST_F(MediaStreamVideoSourceTest, AddsEncodedSinkWhenEncodedConsumerAppears) {
  EXPECT_CALL(*mock_source(), OnEncodedSinkEnabled).Times(1);
  EXPECT_CALL(*mock_source(), OnEncodedSinkDisabled).Times(0);

  WebMediaStreamTrack track = CreateTrack();
  MockMediaStreamVideoSink sink;
  sink.ConnectEncodedToTrack(track);

  Mock::VerifyAndClearExpectations(mock_source());
  sink.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoSourceTest, AddsEncodedSinkWhenEncodedConsumersAppear) {
  EXPECT_CALL(*mock_source(), OnEncodedSinkEnabled).Times(1);
  EXPECT_CALL(*mock_source(), OnEncodedSinkDisabled).Times(0);

  WebMediaStreamTrack track1 = CreateTrack();
  MockMediaStreamVideoSink sink1;
  sink1.ConnectEncodedToTrack(track1);
  WebMediaStreamTrack track2 = CreateTrack();
  MockMediaStreamVideoSink sink2;
  sink2.ConnectEncodedToTrack(track2);

  Mock::VerifyAndClearExpectations(mock_source());
  sink1.DisconnectEncodedFromTrack();
  sink2.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoSourceTest,
       RemovesEncodedSinkWhenEncodedConsumerDisappears) {
  EXPECT_CALL(*mock_source(), OnEncodedSinkDisabled).Times(1);
  WebMediaStreamTrack track = CreateTrack();
  MockMediaStreamVideoSink sink;
  sink.ConnectEncodedToTrack(track);
  sink.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoSourceTest,
       RemovesEncodedSinkWhenEncodedConsumersDisappear) {
  EXPECT_CALL(*mock_source(), OnEncodedSinkDisabled).Times(1);
  WebMediaStreamTrack track1 = CreateTrack();
  MockMediaStreamVideoSink sink1;
  sink1.ConnectEncodedToTrack(track1);
  WebMediaStreamTrack track2 = CreateTrack();
  MockMediaStreamVideoSink sink2;
  sink2.ConnectEncodedToTrack(track2);
  sink1.DisconnectEncodedFromTrack();
  sink2.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoSourceTest, RemovesEncodedSinkWhenTrackStops) {
  EXPECT_CALL(*mock_source(), OnEncodedSinkDisabled).Times(1);
  WebMediaStreamTrack track = CreateTrack();
  MockMediaStreamVideoSink sink;
  sink.ConnectEncodedToTrack(track);
  MediaStreamVideoTrack* native_track = MediaStreamVideoTrack::From(track);
  native_track->Stop();
  sink.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoSourceTest, CapturingLinkSecureOnlyEncodedSinks) {
  InSequence s;
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(false));
  WebMediaStreamTrack track = CreateTrack();
  MockMediaStreamVideoSink sink;
  sink.ConnectEncodedToTrack(track);
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(true));
  sink.DisconnectEncodedFromTrack();
}

TEST_F(MediaStreamVideoSourceTest, CapturingLinkSecureTracksAndEncodedSinks) {
  InSequence s;
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(true));
  WebMediaStreamTrack track = CreateTrack();
  mock_source()->UpdateCapturingLinkSecure(MediaStreamVideoTrack::From(track),
                                           true);

  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(false));
  MockMediaStreamVideoSink sink;
  sink.ConnectEncodedToTrack(track);
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(true));
  sink.DisconnectEncodedFromTrack();
  EXPECT_CALL(*mock_source(), OnCapturingLinkSecured(false));
  mock_source()->UpdateCapturingLinkSecure(MediaStreamVideoTrack::From(track),
                                           false);
}

TEST_F(MediaStreamVideoSourceTest, CanDiscardAlpha) {
  InSequence s;
  WebMediaStreamTrack track = CreateTrack();

  MockMediaStreamVideoSink sink_no_alpha;
  sink_no_alpha.SetUsesAlpha(MediaStreamVideoSink::UsesAlpha::kNo);
  MockMediaStreamVideoSink sink_alpha;
  sink_alpha.SetUsesAlpha(MediaStreamVideoSink::UsesAlpha::kDefault);

  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(true));
  sink_no_alpha.ConnectToTrack(track);

  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(false));
  sink_alpha.ConnectToTrack(track);

  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(false));
  sink_no_alpha.DisconnectFromTrack();

  // Called once when removing the sink from the track, again when the track is
  // removed from the source.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(true));
  sink_alpha.DisconnectFromTrack();

  // Extra call when destroying the track.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(true));
}

TEST_F(MediaStreamVideoSourceTest, CanDiscardAlphaIfOtherSinksDiscard) {
  InSequence s;
  WebMediaStreamTrack track = CreateTrack();

  MockMediaStreamVideoSink sink_no_alpha;
  sink_no_alpha.SetUsesAlpha(MediaStreamVideoSink::UsesAlpha::kNo);
  MockMediaStreamVideoSink sink_depends;
  sink_depends.SetUsesAlpha(
      MediaStreamVideoSink::UsesAlpha::kDependsOnOtherSinks);
  MockMediaStreamVideoSink sink_alpha;
  sink_alpha.SetUsesAlpha(MediaStreamVideoSink::UsesAlpha::kDefault);

  // Keep alpha if the only sink is DependsOnOtherSinks.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(false));
  sink_depends.ConnectToTrack(track);

  // Now alpha can be dropped since other sink drops alpha.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(true));
  sink_no_alpha.ConnectToTrack(track);

  // Alpha can not longer be dropped since a sink uses it.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(false));
  sink_alpha.ConnectToTrack(track);

  // Now that alpha track is removes, alpha can be discarded again.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(true));
  sink_alpha.DisconnectFromTrack();

  // Now that the alpha dropping track is disconnected, we keep alpha since the
  // only sink depends on other sinks, which keeps alpha by default.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(false));
  sink_no_alpha.DisconnectFromTrack();

  // Alpha is discarded if there are no sinks connected.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(true));
  sink_depends.DisconnectFromTrack();

  // Extra call when destroying the track.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(true));
}

TEST_F(MediaStreamVideoSourceTest, CanDiscardAlphaMultipleTracks) {
  InSequence s;
  WebMediaStreamTrack track_no_alpha = CreateTrack();
  WebMediaStreamTrack track_with_alpha = CreateTrack();

  MockMediaStreamVideoSink sink_no_alpha;
  sink_no_alpha.SetUsesAlpha(MediaStreamVideoSink::UsesAlpha::kNo);
  MockMediaStreamVideoSink sink_alpha;
  sink_alpha.SetUsesAlpha(MediaStreamVideoSink::UsesAlpha::kDefault);

  // Adding just the track with no alpha, the source can discard alpha.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(true));
  sink_no_alpha.ConnectToTrack(track_no_alpha);

  // Adding both tracks, the source can no longer discard.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(false));
  sink_alpha.ConnectToTrack(track_with_alpha);

  // Even when removing the track with no alpha, we still can't discard alpha.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(false));
  sink_no_alpha.DisconnectFromTrack();

  // Removing all tracks, we can now discard alpha again.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(true));
  sink_alpha.DisconnectFromTrack();

  // Extra call when destroying the tracks.
  EXPECT_CALL(*mock_source(), OnSourceCanDiscardAlpha(true)).Times(2);
}

TEST_F(MediaStreamVideoSourceTest, ConfiguredFrameRate) {
  WebMediaStreamTrack track =
      CreateTrackAndStartSource(640, 480, kSourceFrameRate);
  MockMediaStreamVideoSink sink;
  sink.ConnectToTrack(track);
  EXPECT_EQ(track.Source().GetReadyState(),
            WebMediaStreamSource::kReadyStateLive);

  MediaStreamVideoTrack* native_track = MediaStreamVideoTrack::From(track);
  MediaStreamTrackPlatform::Settings settings;
  native_track->GetSettings(settings);
  EXPECT_EQ(settings.frame_rate, kSourceFrameRate);

  source()->ReconfigureTrack(
      native_track,
      VideoTrackAdapterSettings(gfx::Size(640, 480), kSourceFrameRate + 1));
  native_track->GetSettings(settings);
  // Since the adapter frame rate is greater than the source frame rate,
  // the configured rate returned by GetSettings() is the source frame rate.
  EXPECT_EQ(settings.frame_rate, kSourceFrameRate);

  source()->ReconfigureTrack(
      native_track,
      VideoTrackAdapterSettings(gfx::Size(640, 480), kSourceFrameRate - 1));
  native_track->GetSettings(settings);
  // Since the adapter frame rate is less than the source frame rate,
  // the configured rate returned by GetSettings() is the adapter frame rate.
  EXPECT_EQ(settings.frame_rate, kSourceFrameRate - 1);
}

}  // namespace blink

"""


```