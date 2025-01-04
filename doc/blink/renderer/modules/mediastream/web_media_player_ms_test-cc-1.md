Response:
The user wants me to summarize the functionality of the provided C++ code snippet, which is part of a larger test file for the `WebMediaPlayerMS` class in the Chromium Blink engine. I need to identify the key actions being tested and their purpose. Since this is part 2 of 3, I should focus on the specific tests included in this segment.

Here's a breakdown of the tests in this segment:

1. **`PictureInPictureStateChangeNotCalled`**: Checks that the `OnPictureInPictureStateChange` callback is *not* called for audio elements, even when explicitly set to picture-in-picture mode for testing.
2. **`NoWaitForFrameForAudioOnly`**: Tests that `WebMediaPlayerMS` doesn't wait for video frames if only an audio renderer is available.
3. **`Playing_Normal`**: Tests normal video playback with increasing timestamps.
4. **`PlayThenPause`**: Tests pausing video playback and verifies that a "frozen" frame is maintained.
5. **`PlayThenPauseThenPlay`**: Tests resuming playback after pausing.
6. **`RotationChange`**: Tests how the player handles changes in video rotation metadata.
7. **`OpacityChange`**: Tests how the player handles changes in video frame opacity.
8. **`BackgroundRendering`**: Tests how the player behaves when switching to a background rendering mode.
9. **`FrameSizeChange`**: Tests how the player handles changes in video frame size.
10. **`CreateHardwareFrames`**: Tests the usage of `GpuMemoryBufferVideoFramePool` for hardware frame creation.
11. **`HiddenPlayerTests` (Android only)**: Tests the behavior of the player when the page is hidden or shown.
12. **`RequestVideoFrameCallback`**: Tests the `RequestVideoFrameCallback` API with and without the frame scheduling algorithm.
13. **`RequestVideoFrameCallback_ForcesBeginFrames`**: Tests that `RequestVideoFrameCallback` forces begin frames on the compositor.
14. **`GetVideoFramePresentationMetadata`**: Tests the `GetVideoFramePresentationMetadata` API with and without the frame scheduling algorithm.
15. **`DuplicateFrameTimestamp`**: Tests the player's behavior when it receives frames with duplicate timestamps.
16. **`HandlesArbitraryTimestampConversions`**: Tests the player's ability to handle various timestamp conversions.
17. **`OutOfOrderEnqueue`**: Tests the player's behavior when video frames are enqueued out of order.

Based on these observations, I can now summarize the functionality of this part of the test file.
这是`blink/renderer/modules/mediastream/web_media_player_ms_test.cc`文件的第二部分，主要包含以下功能测试：

**总体功能归纳:**

这部分测试用例主要关注 `WebMediaPlayerMS` 在各种播放状态和条件下的行为，特别是与视频帧处理、渲染、以及特定场景下的优化（如音频元素、后台渲染）相关的逻辑。  它验证了 `WebMediaPlayerMS` 是否正确地管理视频帧的显示，以及与渲染相关的回调是否按预期触发。

**具体功能点:**

* **音频元素处理:**
    * **不等待帧 (`NoWaitForFrameForAudio`, `NoWaitForFrameForAudioOnly`):**  验证了对于纯音频或被标记为音频的元素，`WebMediaPlayerMS` 不会等待视频帧的到达，而是直接进入 `HaveEnoughData` 状态。
    * **不调用画中画状态改变 (`PictureInPictureStateChangeNotCalled`):**  确认了音频元素不会触发画中画状态改变的回调。

* **正常播放流程 (`Playing_Normal`):** 测试了当提供一系列时间戳递增的视频帧时，`WebMediaPlayerMS` 是否能够正常播放。

* **播放和暂停 (`PlayThenPause`, `PlayThenPauseThenPlay`):**
    * 验证了暂停操作是否能够正确地冻结当前帧。
    * 验证了暂停后是否可以正常恢复播放。

* **视频帧属性变化处理:**
    * **旋转 (`RotationChange`):** 测试了当视频帧的旋转信息发生变化时，`WebMediaPlayerMS` 是否能够更新视频的自然尺寸以及正确设置渲染变换。
    * **透明度 (`OpacityChange`):** 测试了 `WebMediaPlayerMS` 是否能够根据视频帧的透明度信息来更新渲染图层的透明度。
    * **尺寸变化 (`FrameSizeChange`):** 测试了当视频帧的尺寸发生变化时，`WebMediaPlayerMS` 是否能够触发 `sizeChanged` 回调并更新元数据。

* **后台渲染 (`BackgroundRendering`):** 测试了在后台渲染模式下，即使没有显式调用 `pause`，`WebMediaPlayerMS` 也能继续处理视频帧，而不会积压。

* **硬件加速 (`CreateHardwareFrames`):**  测试了当启用硬件加速时，`WebMediaPlayerMS` 是否会按照预期的顺序调用 `GpuMemoryBufferVideoFramePool` 来创建硬件视频帧。

* **隐藏状态 (Android 特定 `HiddenPlayerTests`):**  在 Android 平台上，测试了当页面隐藏或显示时，`WebMediaPlayerMS` 的播放状态是否符合预期，例如隐藏时不暂停，显示后继续播放等。

* **请求视频帧回调 (`RequestVideoFrameCallback`, `RequestVideoFrameCallbackWithNoAlgorithm`, `RequestVideoFrameCallback_ForcesBeginFrames`):**
    * 测试了 `RequestVideoFrameCallback` API 的基本功能，包括有无调度算法的情况。
    * 验证了调用 `RequestVideoFrameCallback` 是否会强制 compositor 开始合成帧。

* **获取视频帧显示元数据 (`GetVideoFramePresentationMetadata`, `GetVideoFramePresentationMetadataWithNoAlgorithm`):**  测试了 `GetVideoFramePresentationMetadata` API 的功能，包括有无调度算法的情况。

* **处理重复时间戳 (`DuplicateFrameTimestamp`):** 测试了当接收到具有重复时间戳的视频帧时，`WebMediaPlayerMS` 的处理逻辑。

* **处理任意时间戳转换 (`HandlesArbitraryTimestampConversions`):** 测试了 `WebMediaPlayerMS` 处理各种时间戳转换的能力。

* **乱序入队 (`OutOfOrderEnqueue`):** 测试了当视频帧被乱序添加到队列时，`WebMediaPlayerMS` 的行为。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**  这些测试模拟了 JavaScript 通过 HTMLMediaElement API 与 `WebMediaPlayerMS` 交互的场景。例如，`player_->Play()` 模拟了 JavaScript 调用 `videoElement.play()`，`player_->Pause()` 模拟了 `videoElement.pause()`。
* **HTML:**  `is_audio_element_ = true;`  模拟了 HTML 中使用了 `<audio>` 标签而不是 `<video>` 标签。`CheckSizeChanged(gfx::Size(kStandardWidth, kStandardHeight))` 验证了视频的自然尺寸是否与 HTML 中定义的尺寸一致（如果没有定义，则使用视频流的尺寸）。
* **CSS:**  虽然这部分代码没有直接涉及到 CSS，但是 `OpacityChange` 测试间接地与 CSS 的 `opacity` 属性相关。当视频帧的元数据指示透明度变化时，`WebMediaPlayerMS` 会更新渲染图层的状态，这最终会影响到页面上视频元素的显示效果，类似于 CSS `opacity` 的作用。

**逻辑推理、假设输入与输出:**

* **假设输入 (以 `NoWaitForFrameForAudio` 为例):**
    * 设置 `is_audio_element_ = true;`
    * 不向 `MockMediaStreamVideoRenderer` 提供任何视频帧。
* **预期输出:**
    * `DoReadyStateChanged` 回调会被调用，状态会依次变为 `kReadyStateHaveNothing` 和 `kReadyStateHaveEnoughData`，而不会停留在等待视频帧的中间状态。

* **假设输入 (以 `RotationChange` 为例):**
    * 提供一系列包含不同 `media::VIDEO_ROTATION` 值的视频帧。
* **预期输出:**
    * `NaturalSize()` 方法返回的尺寸会随着旋转角度的变化而调整（宽度和高度互换）。
    * 如果启用了 SurfaceLayer，则会调用 `submitter_ptr_->SetTransform()` 来设置渲染变换。

**用户或编程常见的使用错误举例说明:**

* **错误假设音频元素需要视频帧:**  开发者可能会错误地认为即使是 `<audio>` 元素也需要提供视频轨道的数据才能开始播放。`NoWaitForFrameForAudio` 测试就验证了引擎不会在这种情况下卡住。
* **未能处理视频旋转信息:**  开发者在处理视频播放时可能没有考虑到视频可能包含旋转信息，导致显示不正确。`RotationChange` 测试验证了引擎能够正确处理这种情况，但开发者也需要在自己的代码中适配不同旋转角度的视频尺寸。
* **在后台渲染时误操作:** 开发者可能在页面不可见时仍然进行一些与前台渲染相关的操作，导致资源浪费或错误。`BackgroundRendering` 测试展示了引擎在后台渲染时的一些行为，帮助开发者理解其工作方式。

**用户操作如何一步步的到达这里作为调试线索:**

1. **用户访问包含 `<video>` 或 `<audio>` 元素的网页。**
2. **JavaScript 代码通过 `HTMLMediaElement` API (如 `play()`, `pause()`) 控制媒体播放。**
3. **如果媒体源是 MediaStream API (例如来自摄像头或麦克风的流)，则 `WebMediaPlayerMS` 会被创建和使用。**
4. **当视频帧到达时，`WebMediaPlayerMS` 会处理这些帧，并将其传递给渲染流水线。**
5. **在调试过程中，如果发现视频播放出现问题，例如画面静止、旋转错误、透明度异常等，开发者可能会查看 `WebMediaPlayerMS` 相关的代码。**
6. **`web_media_player_ms_test.cc` 文件中的测试用例可以帮助开发者理解 `WebMediaPlayerMS` 在各种情况下的预期行为，从而缩小问题范围。** 例如，如果发现音频元素播放前有延迟，可以参考 `NoWaitForFrameForAudio` 测试；如果发现视频旋转不正确，可以参考 `RotationChange` 测试。

总而言之，这部分测试用例覆盖了 `WebMediaPlayerMS` 核心的视频帧处理和渲染逻辑，以及针对特定场景的优化策略，为保证 Chromium 浏览器中 MediaStream API 的正确性和稳定性提供了重要的保障。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/web_media_player_ms_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
tVideoFrameCallback())
      .Times(1)
      .WillOnce(testing::Invoke([&]() {
        if (!algorithm_enabled && !enable_surface_layer_for_video_) {
          metadata = player_->GetVideoFramePresentationMetadata();
          // We use EXPECT_GE to compare the deadline_max value with the
          // expected display time. This is because the deadline_max_ member
          // gets updated in the RenderFrame() function which may get called
          // multiple times before the OnRequestVideoFrameCallback() is invoked.
          EXPECT_GE(deadline_max_, metadata->expected_display_time);
        }
      }));
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  testing::Mock::VerifyAndClearExpectations(this);
}

TEST_P(WebMediaPlayerMSTest, NoDataDuringLoadForVideo) {
  InitializeWebMediaPlayerMS();
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata))
      .Times(0);
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData))
      .Times(0);

  LoadAndGetFrameProvider(true);

  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  testing::Mock::VerifyAndClearExpectations(this);

  EXPECT_CALL(*this, DoSetCcLayer(false));
}

TEST_P(WebMediaPlayerMSTest, NoWaitForFrameForAudio) {
  InitializeWebMediaPlayerMS();
  is_audio_element_ = true;
  auto audio_renderer = base::MakeRefCounted<MockMediaStreamAudioRenderer>();
  render_factory_->set_audio_renderer(audio_renderer);
  EXPECT_CALL(*this,
              DoNetworkStateChanged(WebMediaPlayer::kNetworkStateLoading));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveNothing));

  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData));

  player_->Load(WebMediaPlayer::kLoadTypeURL, WebMediaPlayerSource(),
                WebMediaPlayer::kCorsModeUnspecified,
                /*is_cache_disabled=*/false);

  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  testing::Mock::VerifyAndClearExpectations(this);

  EXPECT_CALL(*this, DoSetCcLayer(false));
}

// Test that OnPictureInPictureStateChange is not called for audio elements.
// This test explicitly sets display type to picture in picture, for an audio
// element, for testing purposes only (See crbug.com/1403547 for reference).
TEST_P(WebMediaPlayerMSTest, PictureInPictureStateChangeNotCalled) {
  InitializeWebMediaPlayerMS();
  is_audio_element_ = true;
  MockMediaStreamVideoRenderer* provider = LoadAndGetFrameProvider(true);

  Vector<int> timestamps({0, 33, 66, 100, 133, 166, 200, 233, 266, 300, 333,
                          366, 400, 433, 466, 500, 533, 566, 600});
  provider->QueueFrames(timestamps);

  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*submitter_ptr_, StartRendering());
    EXPECT_CALL(*this, GetDisplayType())
        .WillRepeatedly(Return(DisplayType::kPictureInPicture));

  } else {
    EXPECT_CALL(*this, DoSetCcLayer(true));
    EXPECT_CALL(*this, DoStartRendering());
  }
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData));
  EXPECT_CALL(*this,
              CheckSizeChanged(gfx::Size(kStandardWidth, kStandardHeight)));
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  const gfx::Size& natural_size = player_->NaturalSize();
  EXPECT_EQ(kStandardWidth, natural_size.width());
  EXPECT_EQ(kStandardHeight, natural_size.height());
  testing::Mock::VerifyAndClearExpectations(this);

  EXPECT_CALL(*this, DoSetCcLayer(false));
  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*submitter_ptr_, StopUsingProvider());
  } else {
    EXPECT_CALL(*this, DoStopRendering());
  }
  EXPECT_CALL(*this, DoOnPictureInPictureStateChange()).Times(0);
}

TEST_P(WebMediaPlayerMSTest, NoWaitForFrameForAudioOnly) {
  InitializeWebMediaPlayerMS();
  render_factory_->set_support_video_renderer(false);
  auto audio_renderer = base::MakeRefCounted<MockMediaStreamAudioRenderer>();
  render_factory_->set_audio_renderer(audio_renderer);
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData));
  LoadAndGetFrameProvider(true);
  EXPECT_CALL(*this, DoSetCcLayer(false));
}

TEST_P(WebMediaPlayerMSTest, Playing_Normal) {
  // This test sends a bunch of normal frames with increasing timestamps
  // and verifies that they are produced by WebMediaPlayerMS in appropriate
  // order.

  InitializeWebMediaPlayerMS();

  MockMediaStreamVideoRenderer* provider = LoadAndGetFrameProvider(true);

  Vector<int> timestamps({0, 33, 66, 100, 133, 166, 200, 233, 266, 300, 333,
                          366, 400, 433, 466, 500, 533, 566, 600});
  provider->QueueFrames(timestamps);

  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*submitter_ptr_, StartRendering());
  } else {
    EXPECT_CALL(*this, DoSetCcLayer(true));
    EXPECT_CALL(*this, DoStartRendering());
  }
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData));
  EXPECT_CALL(*this,
              CheckSizeChanged(gfx::Size(kStandardWidth, kStandardHeight)));
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  const gfx::Size& natural_size = player_->NaturalSize();
  EXPECT_EQ(kStandardWidth, natural_size.width());
  EXPECT_EQ(kStandardHeight, natural_size.height());
  testing::Mock::VerifyAndClearExpectations(this);

  EXPECT_CALL(*this, DoSetCcLayer(false));
  if (enable_surface_layer_for_video_)
    EXPECT_CALL(*submitter_ptr_, StopUsingProvider());
  else
    EXPECT_CALL(*this, DoStopRendering());
}

TEST_P(WebMediaPlayerMSTest, PlayThenPause) {
  InitializeWebMediaPlayerMS();
  const bool opaque_frame = testing::get<1>(GetParam());
  const bool odd_size_frame = testing::get<2>(GetParam());
  // In the middle of this test, WebMediaPlayerMS::pause will be called, and we
  // are going to verify that during the pause stage, a frame gets freezed, and
  // cc::VideoFrameProviderClient should also be paused.
  MockMediaStreamVideoRenderer* provider = LoadAndGetFrameProvider(false);

  const int kTestBrake = static_cast<int>(FrameType::TEST_BRAKE);
  Vector<int> timestamps({0,   33,  66,  100, 133, kTestBrake, 166,
                          200, 233, 266, 300, 333, 366,        400,
                          433, 466, 500, 533, 566, 600});
  provider->QueueFrames(timestamps, opaque_frame, odd_size_frame);

  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer());
    EXPECT_CALL(*submitter_ptr_, StartRendering());
  } else {
    EXPECT_CALL(*this, DoSetCcLayer(true));
    EXPECT_CALL(*this, DoStartRendering());
  }
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData));
  gfx::Size frame_size =
      gfx::Size(kStandardWidth - (odd_size_frame ? kOddSizeOffset : 0),
                kStandardHeight - (odd_size_frame ? kOddSizeOffset : 0));
  EXPECT_CALL(*this, CheckSizeChanged(frame_size));
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  testing::Mock::VerifyAndClearExpectations(this);

  // Here we call pause, and expect a freezing frame.
  if (enable_surface_layer_for_video_)
    EXPECT_CALL(*submitter_ptr_, StopRendering());
  else
    EXPECT_CALL(*this, DoStopRendering());

  player_->Pause();
  auto prev_frame = compositor_->GetCurrentFrame();
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  auto after_frame = compositor_->GetCurrentFrame();
  EXPECT_EQ(prev_frame->timestamp(), after_frame->timestamp());
  testing::Mock::VerifyAndClearExpectations(this);

  EXPECT_CALL(*this, DoSetCcLayer(false));
}

TEST_P(WebMediaPlayerMSTest, PlayThenPauseThenPlay) {
  InitializeWebMediaPlayerMS();
  const bool opaque_frame = testing::get<1>(GetParam());
  const bool odd_size_frame = testing::get<2>(GetParam());
  // Similary to PlayAndPause test above, this one focuses on testing that
  // WebMediaPlayerMS can be resumed after a period of paused status.
  MockMediaStreamVideoRenderer* provider = LoadAndGetFrameProvider(false);

  const int kTestBrake = static_cast<int>(FrameType::TEST_BRAKE);
  Vector<int> timestamps({0,   33,         66,  100, 133, kTestBrake, 166,
                          200, 233,        266, 300, 333, 366,        400,
                          433, kTestBrake, 466, 500, 533, 566,        600});
  provider->QueueFrames(timestamps, opaque_frame, odd_size_frame);

  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer());
    EXPECT_CALL(*submitter_ptr_, StartRendering());
  } else {
    EXPECT_CALL(*this, DoSetCcLayer(true));
    EXPECT_CALL(*this, DoStartRendering());
  }
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData));
  gfx::Size frame_size =
      gfx::Size(kStandardWidth - (odd_size_frame ? kOddSizeOffset : 0),
                kStandardHeight - (odd_size_frame ? kOddSizeOffset : 0));
  EXPECT_CALL(*this, CheckSizeChanged(frame_size));
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  testing::Mock::VerifyAndClearExpectations(this);

  // Here we call pause, and expect a freezing frame.
  if (enable_surface_layer_for_video_)
    EXPECT_CALL(*submitter_ptr_, StopRendering());
  else
    EXPECT_CALL(*this, DoStopRendering());

  player_->Pause();
  auto prev_frame = compositor_->GetCurrentFrame();
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  auto after_frame = compositor_->GetCurrentFrame();
  EXPECT_EQ(prev_frame->timestamp(), after_frame->timestamp());
  testing::Mock::VerifyAndClearExpectations(this);

  // We resume the player, and expect rendering can continue.
  if (enable_surface_layer_for_video_)
    EXPECT_CALL(*submitter_ptr_, StartRendering());
  else
    EXPECT_CALL(*this, DoStartRendering());

  player_->Play();
  prev_frame = compositor_->GetCurrentFrame();
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  after_frame = compositor_->GetCurrentFrame();
  EXPECT_NE(prev_frame->timestamp(), after_frame->timestamp());
  testing::Mock::VerifyAndClearExpectations(this);

  EXPECT_CALL(*this, DoSetCcLayer(false));
  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*submitter_ptr_, StopUsingProvider());
  } else {
    EXPECT_CALL(*this, DoStopRendering());
  }
}

// During this test, we check that when we send rotated video frames, it applies
// to player's natural size.
TEST_P(WebMediaPlayerMSTest, RotationChange) {
  InitializeWebMediaPlayerMS();
  MockMediaStreamVideoRenderer* provider = LoadAndGetFrameProvider(true);

  const int kTestBrake = static_cast<int>(FrameType::TEST_BRAKE);
  Vector<int> timestamps({0, kTestBrake});
  provider->QueueFrames(timestamps, false, false, 17, media::VIDEO_ROTATION_90);
  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer());
    EXPECT_CALL(*submitter_ptr_, StartRendering());
  } else {
    EXPECT_CALL(*this, DoSetCcLayer(true));
    EXPECT_CALL(*this, DoStartRendering());
  }
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData));
  // Expect SizeChanged happens 3 times for the 3 rotation changes because the
  // natural size changes on each rotation change. However, CheckSizeChanged
  // checks the compositor size, which is pre-rotation and is the same for the
  // 3 rotation changes.
  EXPECT_CALL(*this,
              CheckSizeChanged(gfx::Size(kStandardWidth, kStandardHeight)))
      .Times(3);
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  // Advance the clock by 100 milliseconds to emulate real clock timing.
  task_environment_.AdvanceClock(base::Milliseconds(100));
  // The exact ordering of delayed vs non-delayed tasks is not defined.
  // Make sure we run all non-delayed tasks (E.G. CheckForFrameChanges) before
  // testing state.
  base::RunLoop().RunUntilIdle();
  gfx::Size natural_size = player_->NaturalSize();
  // Check that height and width are flipped.
  EXPECT_EQ(kStandardHeight, natural_size.width());
  EXPECT_EQ(kStandardWidth, natural_size.height());

  // Change rotation.
  timestamps = Vector<int>({33, kTestBrake});
  provider->QueueFrames(timestamps, false, false, 17, media::VIDEO_ROTATION_0);
  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*submitter_ptr_, SetTransform(media::kNoTransformation));
  } else {
    EXPECT_CALL(*this, DoSetCcLayer(true));
    EXPECT_CALL(*this, DoStopRendering()).WillOnce([&]() {
      scheduler::GetSingleThreadTaskRunnerForTesting()->PostTask(
          FROM_HERE, WTF::BindOnce(
                         [](WebMediaPlayerMSTest* test) {
                           // Turn off rendering here to avoid an infinite loop.
                           test->SetRendering(/*rendering=*/false);
                         },
                         WTF::Unretained(this)));
    });
    EXPECT_CALL(*this, DoStartRendering());
  }
  // Kickstart the Provider InjectFrame as that task may not be running
  // anymore. This is needed now as we switched to mock clock.
  provider->InjectFrame();
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  // Advance the clock by 100 milliseconds to emulate real clock timing.
  task_environment_.AdvanceClock(base::Milliseconds(100));
  base::RunLoop().RunUntilIdle();
  natural_size = player_->NaturalSize();
  EXPECT_EQ(kStandardHeight, natural_size.height());
  EXPECT_EQ(kStandardWidth, natural_size.width());

  // Change rotation again.
  // Enable rendering again as we turned it off above.
  SetRendering(/*rendering=*/true);
  timestamps = Vector<int>({66, kTestBrake});
  provider->QueueFrames(timestamps, false, false, 17, media::VIDEO_ROTATION_90);
  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(
        *submitter_ptr_,
        SetTransform(media::VideoTransformation(media::VIDEO_ROTATION_90)));
  } else {
    EXPECT_CALL(*this, DoSetCcLayer(true));
    EXPECT_CALL(*this, DoStopRendering()).WillOnce([&]() {
      scheduler::GetSingleThreadTaskRunnerForTesting()->PostTask(
          FROM_HERE, WTF::BindOnce(
                         [](WebMediaPlayerMSTest* test) {
                           // Turn off rendering here to avoid an infinite loop.
                           test->SetRendering(/*rendering=*/false);
                         },
                         WTF::Unretained(this)));
    });
    EXPECT_CALL(*this, DoStartRendering());
  }
  // Kickstart the Provider InjectFrame as that task may not be running
  // anymore. This is needed now as we switched to mock clock.
  provider->InjectFrame();
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  // Advance the clock by 100 milliseconds to emulate real clock timing.
  task_environment_.AdvanceClock(base::Milliseconds(100));
  base::RunLoop().RunUntilIdle();
  natural_size = player_->NaturalSize();
  EXPECT_EQ(kStandardHeight, natural_size.width());
  EXPECT_EQ(kStandardWidth, natural_size.height());

  testing::Mock::VerifyAndClearExpectations(this);
  EXPECT_CALL(*this, DoSetCcLayer(false));

  if (enable_surface_layer_for_video_)
    EXPECT_CALL(*submitter_ptr_, StopUsingProvider());
}

// During this test, we check that web layer changes opacity according to the
// given frames.
TEST_P(WebMediaPlayerMSTest, OpacityChange) {
  InitializeWebMediaPlayerMS();
  MockMediaStreamVideoRenderer* provider = LoadAndGetFrameProvider(true);

  // Push one opaque frame.
  const int kTestBrake = static_cast<int>(FrameType::TEST_BRAKE);
  Vector<int> timestamps({0, kTestBrake});
  provider->QueueFrames(timestamps, true);

  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer());
    EXPECT_CALL(*submitter_ptr_, StartRendering());
  } else {
    EXPECT_CALL(*this, DoSetCcLayer(true));
    EXPECT_CALL(*this, DoStartRendering());
  }
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData));
  EXPECT_CALL(*this,
              CheckSizeChanged(gfx::Size(kStandardWidth, kStandardHeight)));
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  // The exact ordering of delayed vs non-delayed tasks is not defined.
  // Make sure we run all non-delayed tasks before testing state.
  base::RunLoop().RunUntilIdle();
  if (!enable_surface_layer_for_video_) {
    ASSERT_TRUE(layer_);
    EXPECT_TRUE(layer_->contents_opaque());
  }

  // Push one transparent frame.
  timestamps = Vector<int>({33, kTestBrake});
  provider->QueueFrames(timestamps, false);
  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*surface_layer_bridge_ptr_, SetContentsOpaque(false));
  }
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  base::RunLoop().RunUntilIdle();
  if (!enable_surface_layer_for_video_) {
    EXPECT_FALSE(layer_->contents_opaque());
  }

  // Push another transparent frame.
  timestamps = Vector<int>({66, kTestBrake});
  provider->QueueFrames(timestamps, true);
  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*surface_layer_bridge_ptr_, SetContentsOpaque(true));
  }
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  base::RunLoop().RunUntilIdle();
  if (!enable_surface_layer_for_video_) {
    EXPECT_TRUE(layer_->contents_opaque());
  }

  testing::Mock::VerifyAndClearExpectations(this);
  EXPECT_CALL(*this, DoSetCcLayer(false));
  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*submitter_ptr_, StopUsingProvider());
  } else {
    EXPECT_CALL(*this, DoStopRendering());
  }
}

TEST_P(WebMediaPlayerMSTest, BackgroundRendering) {
  // During this test, we will switch to background rendering mode, in which
  // WebMediaPlayerMS::pause does not get called, but
  // cc::VideoFrameProviderClient simply stops asking frames from
  // WebMediaPlayerMS without an explicit notification. We should expect that
  // WebMediaPlayerMS can digest old frames, rather than piling frames up and
  // explode.
  InitializeWebMediaPlayerMS();
  MockMediaStreamVideoRenderer* provider = LoadAndGetFrameProvider(true);

  const int kTestBrake = static_cast<int>(FrameType::TEST_BRAKE);
  Vector<int> timestamps({0,   33,         66,  100, 133, kTestBrake, 166,
                          200, 233,        266, 300, 333, 366,        400,
                          433, kTestBrake, 466, 500, 533, 566,        600});
  provider->QueueFrames(timestamps);

  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer());
    EXPECT_CALL(*submitter_ptr_, StartRendering());
  } else {
    EXPECT_CALL(*this, DoSetCcLayer(true));
    EXPECT_CALL(*this, DoStartRendering());
  }
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData));
  gfx::Size frame_size = gfx::Size(kStandardWidth, kStandardHeight);
  EXPECT_CALL(*this, CheckSizeChanged(frame_size));
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  testing::Mock::VerifyAndClearExpectations(this);

  // Switch to background rendering, expect rendering to continue for all the
  // frames between kTestBrake frames.
  if (enable_surface_layer_for_video_)
    EXPECT_CALL(*submitter_ptr_, DidReceiveFrame()).Times(testing::AtLeast(1));
  else
    EXPECT_CALL(*this, DoDidReceiveFrame()).Times(testing::AtLeast(1));

  SetBackgroundRendering(true);
  auto prev_frame = compositor_->GetCurrentFrame();
  // Advance the clock by 10 milliseconds to emulate the real system clock.
  task_environment_.AdvanceClock(base::Milliseconds(10));
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  auto after_frame = compositor_->GetCurrentFrame();
  EXPECT_NE(prev_frame->timestamp(), after_frame->timestamp());

  // Switch to foreground rendering.
  SetBackgroundRendering(false);
  prev_frame = compositor_->GetCurrentFrame();
  // Advance the clock by 10 milliseconds to emulate the real system clock.
  task_environment_.AdvanceClock(base::Milliseconds(10));
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  after_frame = compositor_->GetCurrentFrame();
  EXPECT_NE(prev_frame->timestamp(), after_frame->timestamp());
  testing::Mock::VerifyAndClearExpectations(this);

  EXPECT_CALL(*this, DoSetCcLayer(false));
  if (enable_surface_layer_for_video_)
    EXPECT_CALL(*submitter_ptr_, StopUsingProvider());
  else
    EXPECT_CALL(*this, DoStopRendering());
}

TEST_P(WebMediaPlayerMSTest, FrameSizeChange) {
  // During this test, the frame size of the input changes.
  // We need to make sure, when sizeChanged() gets called, new size should be
  // returned by GetMetadata().
  InitializeWebMediaPlayerMS();
  MockMediaStreamVideoRenderer* provider = LoadAndGetFrameProvider(true);

  Vector<int> timestamps({0, 33, 66, 100, 133, 166, 200, 233, 266, 300, 333,
                          366, 400, 433, 466, 500, 533, 566, 600});
  provider->QueueFrames(timestamps, false, false, 7);

  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer());
    EXPECT_CALL(*submitter_ptr_, StartRendering());
  } else {
    EXPECT_CALL(*this, DoSetCcLayer(true));
    EXPECT_CALL(*this, DoStartRendering());
  }
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData));
  EXPECT_CALL(*this,
              CheckSizeChanged(gfx::Size(kStandardWidth, kStandardHeight)));
  EXPECT_CALL(*this, CheckSizeChanged(
                         gfx::Size(kStandardWidth * 2, kStandardHeight * 2)));
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);
  testing::Mock::VerifyAndClearExpectations(this);

  EXPECT_CALL(*this, DoSetCcLayer(false));
  if (enable_surface_layer_for_video_)
    EXPECT_CALL(*submitter_ptr_, StopUsingProvider());
  else
    EXPECT_CALL(*this, DoStopRendering());
}

// Tests that GpuMemoryBufferVideoFramePool is called in the expected sequence.
TEST_P(WebMediaPlayerMSTest, CreateHardwareFrames) {
  InitializeWebMediaPlayerMS();
  MockMediaStreamVideoRenderer* provider = LoadAndGetFrameProvider(false);
  SetGpuMemoryBufferVideoForTesting();

  const int kTestBrake = static_cast<int>(FrameType::TEST_BRAKE);
  Vector<int> timestamps({0, kTestBrake});
  provider->QueueFrames(timestamps);
  message_loop_controller_.RunAndWaitForStatus(media::PIPELINE_OK);

  ASSERT_EQ(1u, frame_ready_cbs_.size());
  if (enable_surface_layer_for_video_) {
    EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer());
    EXPECT_CALL(*submitter_ptr_, StartRendering());
  } else {
    EXPECT_CALL(*this, DoSetCcLayer(true));
    EXPECT_CALL(*this, DoStartRendering());
  }
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveMetadata));
  EXPECT_CALL(*this,
              DoReadyStateChanged(WebMediaPlayer::kReadyStateHaveEnoughData));
  EXPECT_CALL(*this, CheckSizeChanged(provider->get_standard_size()));

  // Run all the tasks that will assign current frame in
  // WebMediaPlayerMSCompositor.
  std::move(frame_ready_cbs_[0]).Run();
  base::RunLoop().RunUntilIdle();

  auto frame = compositor_->GetCurrentFrame();
  ASSERT_TRUE(frame);
  testing::Mock::VerifyAndClearExpectations(this);

  EXPECT_CALL(*this, DoSetCcLayer(false));
  if (enable_surface_layer_for_video_)
    EXPECT_CALL(*submitter_ptr_, StopUsingProvider());
  else
    EXPECT_CALL(*this, DoStopRendering());
}
#if BUILDFLAG(IS_ANDROID)
TEST_P(WebMediaPlayerMSTest, HiddenPlayerTests) {
  InitializeWebMediaPlayerMS();
  LoadAndGetFrameProvider(true);

  // Hidden status should not affect playback.
  delegate_.set_page_hidden(true);
  player_->Play();
  EXPECT_FALSE(player_->Paused());

  // A hidden player should start still be playing upon shown.
  delegate_.set_page_hidden(false);
  player_->OnPageShown();
  EXPECT_FALSE(player_->Paused());

  // A hidden event should not pause the player.
  delegate_.set_page_hidden(true);
  player_->OnPageHidden();
  EXPECT_FALSE(player_->Paused());

  // A user generated pause() should clear the automatic resumption.
  player_->Pause();
  delegate_.set_page_hidden(false);
  player_->OnPageShown();
  EXPECT_TRUE(player_->Paused());

  // A user generated play() should start playback.
  player_->Play();
  EXPECT_FALSE(player_->Paused());

  // An OnSuspendRequested() without forced suspension should do nothing.
  player_->OnIdleTimeout();
  EXPECT_FALSE(player_->Paused());

  // An OnSuspendRequested() with forced suspension should pause playback.
  player_->SuspendForFrameClosed();
  EXPECT_TRUE(player_->Paused());

  // OnShown() should restart after a forced suspension.
  player_->OnPageShown();
  EXPECT_FALSE(player_->Paused());
  EXPECT_CALL(*this, DoSetCcLayer(false));

  base::RunLoop().RunUntilIdle();
}
#endif

TEST_P(WebMediaPlayerMSTest, RequestVideoFrameCallback) {
  TestRequestFrameCallbackWithVideoFrameMetadata(/*algorithm_enabled=*/true);
}

TEST_P(WebMediaPlayerMSTest, RequestVideoFrameCallbackWithNoAlgorithm) {
  TestRequestFrameCallbackWithVideoFrameMetadata(/*algorithm_enabled=*/false);
}

TEST_P(WebMediaPlayerMSTest, RequestVideoFrameCallback_ForcesBeginFrames) {
  InitializeWebMediaPlayerMS();

  if (!enable_surface_layer_for_video_)
    return;

  LoadAndGetFrameProvider(true);

  EXPECT_CALL(*submitter_ptr_, SetForceBeginFrames(true));
  player_->RequestVideoFrameCallback();
  base::RunLoop().RunUntilIdle();

  testing::Mock::VerifyAndClearExpectations(submitter_ptr_);

  // The flag should be un-set when stop receiving callbacks.
  base::RunLoop run_loop;
  EXPECT_CALL(*submitter_ptr_, SetForceBeginFrames(false))
      .WillOnce(base::test::RunClosure(run_loop.QuitClosure()));
  run_loop.Run();

  testing::Mock::VerifyAndClear(submitter_ptr_);
}

TEST_P(WebMediaPlayerMSTest, GetVideoFramePresentationMetadata) {
  TestGetVideoFramePresentationMetadata(/*algorithm_enabled=*/true);
}

TEST_P(WebMediaPlayerMSTest, GetVideoFramePresentationMetadataWithNoAlgorithm) {
  TestGetVideoFramePresentationMetadata(/*algorithm_enabled=*/false);
}

TEST_P(WebMediaPlayerMSTest, DuplicateFrameTimestamp) {
  InitializeWebMediaPlayerMS();
  LoadAndGetFrameProvider(true);

  const bool opaque_frame = testing::get<1>(GetParam());
  const bool odd_size_frame = testing::get<2>(GetParam());

  gfx::Size frame_size(kStandardWidth - (odd_size_frame ? kOddSizeOffset : 0),
                       kStandardHeight - (odd_size_frame ? kOddSizeOffset : 0));

  constexpr auto kStep = base::Milliseconds(25);
  auto frame = media::VideoFrame::CreateZeroInitializedFrame(
      opaque_frame ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A,
      frame_size, gfx::Rect(frame_size), frame_size, kStep);
  frame->metadata().reference_time = base::TimeTicks::Now() + kStep;
  auto frame2 = media::VideoFrame::CreateZeroInitializedFrame(
      opaque_frame ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A,
      frame_size, gfx::Rect(frame_size), frame_size, kStep);
  frame2->metadata().reference_time = base::TimeTicks::Now() + kStep;
  auto frame3 = media::VideoFrame::CreateZeroInitializedFrame(
      opaque_frame ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A,
      frame_size, gfx::Rect(frame_size), frame_size, kStep * 2);
  frame3->metadata().reference_time = base::TimeTicks::Now() + kStep * 2;

  compositor_->StartRendering();
  task_environment_.RunUntilIdle();
  base::TimeTicks deadline = base::TimeTicks::Now();
  // Call UpdateCurrentFrame() to initialize last_deadline_max_ in
  // WebMediaPlayerMSCompositor.
  EXPECT_TRUE(compositor_->UpdateCurrentFrame(deadline, deadline + kStep));

  compositor_->EnqueueFrame(std::move(frame), true);
  compositor_->EnqueueFrame(std::move(frame2), true);
  compositor_->EnqueueFrame(std::move(frame3), true);

  deadline += kStep;  // Don't start deadline at zero.

  for (int i = 1; i <= 2; ++i) {
    EXPECT_TRUE(compositor_->UpdateCurrentFrame(deadline, deadline + kStep));
    deadline += kStep;
    frame = compositor_->GetCurrentFrame();
    EXPECT_EQ(frame->timestamp(), kStep * i);
    compositor_->PutCurrentFrame();
  }

  compositor_->StopRendering();
  task_environment_.RunUntilIdle();
}

TEST_P(WebMediaPlayerMSTest, HandlesArbitraryTimestampConversions) {
  InitializeWebMediaPlayerMS();
  LoadAndGetFrameProvider(true);

  const bool opaque_frame = testing::get<1>(GetParam());
  const bool odd_size_frame = testing::get<2>(GetParam());

  gfx::Size frame_size(kStandardWidth - (odd_size_frame ? kOddSizeOffset : 0),
                       kStandardHeight - (odd_size_frame ? kOddSizeOffset : 0));

  constexpr auto kStep = base::Milliseconds(25);
  auto frame = media::VideoFrame::CreateZeroInitializedFrame(
      opaque_frame ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A,
      frame_size, gfx::Rect(frame_size), frame_size, kStep);
  frame->metadata().reference_time = base::TimeTicks::Now() + kStep;
  frame->metadata().frame_duration = kStep - base::Microseconds(1);
  auto frame2 = media::VideoFrame::CreateZeroInitializedFrame(
      opaque_frame ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A,
      frame_size, gfx::Rect(frame_size), frame_size, kStep * 2);
  frame2->metadata().reference_time = base::TimeTicks::Now() + kStep * 2;
  frame2->metadata().frame_duration = kStep - base::Microseconds(1);

  compositor_->StartRendering();
  task_environment_.RunUntilIdle();
  base::TimeTicks deadline = base::TimeTicks::Now();
  // Call UpdateCurrentFrame() to initialize last_deadline_max_ in
  // WebMediaPlayerMSCompositor.
  EXPECT_TRUE(compositor_->UpdateCurrentFrame(deadline, deadline + kStep));

  compositor_->EnqueueFrame(std::move(frame), true);
  compositor_->EnqueueFrame(std::move(frame2), true);

  deadline += kStep;  // Don't start deadline at zero.

  for (int i = 1; i <= 2; ++i) {
    EXPECT_TRUE(compositor_->UpdateCurrentFrame(deadline, deadline + kStep));
    deadline += kStep;
    frame = compositor_->GetCurrentFrame();
    EXPECT_EQ(frame->timestamp(), kStep * i);
    compositor_->PutCurrentFrame();
  }

  compositor_->StopRendering();
  task_environment_.RunUntilIdle();
}

TEST_P(WebMediaPlayerMSTest, OutOfOrderEnqueue) {
  InitializeWebMediaPlayerMS();
  LoadAndGetFrameProvider(true);

  const bool opaque_frame = testing::get<1>(GetParam());
  const bool odd_size_frame = testing::get<2>(GetParam());

  gfx::Size frame_size(kStandardWidth - (odd_size_frame ? kOddSizeOffset : 0),
                       kStandardHeight - (odd_size_frame ? kOddSizeOffset : 0));

  constexpr auto kStep = base::Milliseconds(25);
  auto frame = media::VideoFrame::CreateZeroInitializedFrame(
      opaque_frame ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A,
      frame_size, gfx::Rect(frame_size), frame_size, kStep);
  frame->metadata().reference_time = base::TimeTicks::Now() + kStep;
  auto frame2 = media::VideoFrame::CreateZeroInitializedFrame(
      opaque_frame ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A,
      frame_size, gfx::Rect(frame_size), frame_size, kStep * 2);
  frame2->metadata().reference_time = base::TimeTicks::Now() + kStep * 2;
  auto frame3 = media::VideoFrame::CreateZeroInitializedFrame(
      opaque_frame ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A,
      frame_size, gfx::Rect(frame_size), frame_size, kStep * 3);
  frame3->metadata().reference_time = base::TimeTicks::Now() + kStep * 3;

  compositor_->StartRendering();
  task_environment_.RunUntilIdle();
  base::TimeTicks deadline = base::TimeTicks::Now();
  // Call UpdateCurrentFrame() to initialize last_deadline_max_ in
  // WebMediaPlayerMSCompositor.
  EXPECT_TRUE(compositor_->UpdateCurrentFrame(deadline, deadline + kStep));

  compositor_->EnqueueFrame(std::move(frame), true);
  compositor_->EnqueueFrame(std::move(frame3), true
"""


```