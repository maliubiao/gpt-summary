Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a unit test for the `WebMediaPlayerImpl` class in the Chromium Blink engine. I need to identify the main purpose of the tests and any interactions with web technologies like JavaScript, HTML, and CSS. I should also look for examples of logical reasoning, common user errors, and debugging clues.

**Plan:**

1. **Identify the core purpose:** The code contains a series of `TEST_F` macros, indicating unit tests. The tests focus on verifying the behavior of `WebMediaPlayerImpl` under various conditions.
2. **Analyze individual tests:** I'll go through each test case and summarize what aspect of `WebMediaPlayerImpl` it's testing.
3. **Look for web technology connections:**  I'll watch for interactions with concepts like media metadata, playback state (playing, paused), volume, seeking, encryption, and display types (fullscreen, picture-in-picture). These have direct counterparts in web media APIs.
4. **Identify logical reasoning:** Tests often involve setting up certain conditions (input) and verifying the resulting state or emitted events (output). I'll look for these patterns.
5. **Consider user errors:** Some tests might implicitly cover scenarios caused by incorrect user actions or website configurations.
6. **Think about debugging:**  The tests themselves can serve as debugging clues for developers working on the media player implementation.
7. **Synthesize the information:** I'll combine the findings into a concise summary of the code snippet's functionality.
这是`blink/renderer/core/exported/web_media_player_impl_unittest.cc`文件的第3部分，主要功能是**测试`WebMediaPlayerImpl`类在各种媒体播放状态和事件下的行为和状态变化**。  它涵盖了媒体播放器的多个方面，包括播放位置状态更新、无媒体流的处理、加密媒体的处理、等待状态、错误处理、视频配置和尺寸变化、以及与页面和帧可见性相关的行为。

下面列举一下它具体测试的功能，并说明与JavaScript, HTML, CSS的关系，以及逻辑推理、用户错误和调试线索：

**1. 媒体播放位置状态 (Media Position State):**

*   **功能:** 测试 `WebMediaPlayerImpl` 如何报告媒体的当前播放位置、播放速率、总时长以及是否到达媒体结尾。
*   **与 JavaScript/HTML 的关系:**
    *   JavaScript 通过 HTMLMediaElement 接口 (例如 `<video>` 或 `<audio>`) 的 `currentTime`, `playbackRate`, `duration` 属性来获取这些信息。测试中模拟了这些属性变化时，底层 `WebMediaPlayerImpl` 的行为。
    *   HTML 的 `<video>` 和 `<audio>` 元素触发的 `timeupdate` 事件与 `WebMediaPlayerImpl::OnTimeUpdate()` 密切相关。
*   **逻辑推理 (假设输入/输出):**
    *   **假设输入:**  播放速率设置为 1.0，播放一段时间后调用 `OnTimeUpdate()`。
    *   **预期输出:**  `DidPlayerMediaPositionStateChange` 回调被调用，报告当前的播放速率、总时长、当前播放时间（非零）和 `end_of_media` 为 false。
    *   **假设输入:**  播放器暂停后调用 `OnTimeUpdate()`。
    *   **预期输出:** `DidPlayerMediaPositionStateChange` 回调被调用，报告播放速率为 0.0。
    *   **假设输入:**  播放到媒体末尾后调用 `OnTimeUpdate()`。
    *   **预期输出:** `DidPlayerMediaPositionStateChange` 回调被调用，报告 `end_of_media` 为 true。
*   **用户/编程常见错误:**  JavaScript 代码可能错误地假设 `timeupdate` 事件的触发频率，或者在媒体未加载完成时就尝试访问 `currentTime` 或 `duration`。
*   **调试线索:** 如果前端报告的播放位置与预期不符，可以查看 `WebMediaPlayerImpl::OnTimeUpdate()` 的调用时机和 `DidPlayerMediaPositionStateChange` 回调的参数，以确定底层是否正确计算和报告了播放状态。

**2. 无媒体流 (No Streams):**

*   **功能:** 测试当媒体不包含音频或视频流时 `WebMediaPlayerImpl` 的处理逻辑，预期会触发错误。
*   **与 JavaScript/HTML 的关系:**  如果尝试播放一个不包含任何有效媒体流的资源，HTMLMediaElement 会触发 `error` 事件。
*   **逻辑推理 (假设输入/输出):**
    *   **假设输入:**  `OnMetadata` 被调用，但 `metadata` 对象中没有音频或视频流信息。
    *   **预期输出:**  `NetworkStateChanged` 回调被调用，且网络状态为 `kNetworkStateFormatError`，同时 `ReadyStateChanged` 不会被调用。
*   **用户/编程常见错误:**  开发者可能错误地链接到或尝试播放一个损坏的或不完整的媒体文件。
*   **调试线索:** 如果前端收到 `error` 事件，但原因不明，可以查看 `WebMediaPlayerImpl` 的网络状态和就绪状态，以判断是否是由于媒体格式错误导致的。

**3. 加密媒体 (Encrypted):**

*   **功能:** 测试 `WebMediaPlayerImpl` 处理加密媒体的流程，包括触发加密事件、等待密钥、处理 CDM (Content Decryption Module) 的关联。
*   **与 JavaScript/HTML 的关系:**
    *   与 HTMLMediaElement 的 Encrypted Media Extensions (EME) API 密切相关。当遇到加密内容时，会触发 `encrypted` 事件。
    *   JavaScript 代码会使用 `requestMediaKeySystemAccess` 来请求访问 CDM，并使用 `createMediaKeys` 和 `setMediaKeys` 将 CDM 与媒体元素关联。
*   **逻辑推理 (假设输入/输出):**
    *   **假设输入:**  加载一个加密的媒体文件。
    *   **预期输出:** `Encrypted` 回调被调用，携带初始化数据类型和数据。
    *   **假设输入:**  没有可用的 CDM 或 CDM 不支持所需的解密器。
    *   **预期输出:**  网络状态变为 `kNetworkStateFormatError`。
*   **用户/编程常见错误:**  没有正确配置 CDM，或者浏览器不支持所需的加密方案。
*   **调试线索:** 如果前端没有收到 `encrypted` 事件，或者在处理加密事件时发生错误，可以检查 `WebMediaPlayerImpl` 中与 CDM 关联和事件触发相关的逻辑。

**4. 等待状态 (Waiting):**

*   **功能:** 测试 `WebMediaPlayerImpl` 在各种等待条件下的行为，例如等待解密密钥或安全表面丢失。
*   **与 JavaScript/HTML 的关系:**  HTMLMediaElement 会在需要缓冲数据或等待其他条件时触发 `waiting` 事件。
*   **逻辑推理 (假设输入/输出):**
    *   **假设输入:**  接收到 `Waiting` 事件，原因是 `kNoDecryptionKey`。
    *   **预期输出:**  `DidBlockPlaybackWaitingForKey` 回调被调用。
    *   **假设输入:**  接收到 `Waiting` 事件，原因是 `kSecureSurfaceLost`。
    *   **预期输出:**  播放器进入暂停状态 (IsSuspended 为 true)。
*   **用户/编程常见错误:**  网络连接不稳定导致缓冲不足，或者在安全上下文中播放非安全内容。
*   **调试线索:**  如果前端频繁触发 `waiting` 事件，可以检查 `WebMediaPlayerImpl` 中导致等待的原因，例如缓冲状态、解密状态或安全表面状态。

**5. 错误处理 (Error Handling - 通过硬件上下文重置测试):**

*   **功能:**  测试当底层渲染器遇到硬件上下文重置错误 (`PIPELINE_ERROR_HARDWARE_CONTEXT_RESET`) 时，`WebMediaPlayerImpl` 如何尝试恢复，例如通过重新创建渲染器。
*   **与 JavaScript/HTML 的关系:**  底层的硬件错误最终可能导致 HTMLMediaElement 触发 `error` 事件。
*   **逻辑推理 (假设输入/输出):**
    *   **假设输入:**  渲染器报告 `PIPELINE_ERROR_HARDWARE_CONTEXT_RESET`。
    *   **预期输出:** `WebMediaPlayerImpl` 会暂停并重新初始化渲染管道。
*   **用户/编程常见错误:**  通常是用户环境问题，例如显卡驱动程序问题。
*   **调试线索:**  如果前端收到 `error` 事件，且错误码指示硬件问题，可以查看 `WebMediaPlayerImpl` 中处理硬件错误的逻辑，以及是否成功进行了恢复尝试。

**6. 视频配置和尺寸变化 (Video Config and Size Change):**

*   **功能:** 测试 `WebMediaPlayerImpl` 如何处理视频解码配置的变化（例如编解码器、profile）和视频的自然尺寸变化。
*   **与 JavaScript/HTML 的关系:**
    *   视频的自然尺寸可以通过 HTMLMediaElement 的 `videoWidth` 和 `videoHeight` 属性获取。当尺寸变化时，会触发 `resize` 事件。
    *   可以通过 Media Capabilities API 查询浏览器支持的视频解码配置。
*   **逻辑推理 (假设输入/输出):**
    *   **假设输入:**  接收到新的视频解码配置 (例如，不同的编解码器 profile)。
    *   **预期输出:**  可能需要重新创建用于统计视频解码性能的 `VideoDecodeStatsReporter` 对象。
    *   **假设输入:**  接收到视频自然尺寸变化的通知。
    *   **预期输出:**  `SizeChanged` 回调被调用，且 `WebMediaPlayerImpl::NaturalSize()` 返回新的尺寸。
*   **用户/编程常见错误:**  开发者可能没有正确处理视频尺寸变化导致的布局问题。
*   **调试线索:**  如果前端报告的视频尺寸不正确，或者布局出现问题，可以检查 `WebMediaPlayerImpl` 中处理尺寸变化的逻辑和 `SizeChanged` 回调的触发。

**7. 与页面和帧可见性相关的行为 (Visibility and Playback):**

*   **功能:** 测试当页面或包含媒体元素的 frame 变为不可见时，`WebMediaPlayerImpl` 是否按预期暂停播放。
*   **与 JavaScript/HTML 的关系:**  可以通过 Page Visibility API 监听页面的可见性变化 (`visibilitychange` 事件)。
*   **逻辑推理 (假设输入/输出):**
    *   **假设输入:**  包含媒体元素的 frame 变为不可见。
    *   **预期输出:**  如果 `shouldPauseWhenFrameIsHidden` 为 true，则播放器会暂停。
    *   **假设输入:**  页面变为不可见，但 frame 仍然可见。
    *   **预期输出:**  如果 `shouldPauseWhenFrameIsHidden` 为 false (但页面可见性暂停功能启用)，则播放器会暂停。
*   **用户/编程常见错误:**  在页面不可见时仍然进行资源密集型操作，例如持续播放视频。
*   **调试线索:**  如果播放器在页面或 frame 不可见时没有按预期暂停，可以检查 `WebMediaPlayerImpl` 中处理可见性变化的逻辑和相关标志位的状态。

**8. 其他测试:**

*   **冻结状态通知 (Notifies Observer When Frozen):** 测试 `OnFrozen` 事件的触发。
*   **后台空闲暂停定时器 (Background Idle Pause Timer):** 测试后台暂停定时器是否根据是否存在音频流而启用。
*   **无限时长处理 (Infinite Duration):** 测试对无限时长媒体的处理。
*   **内容图层设置 (Set Contents Layer):** 测试如何获取和设置用于渲染视频内容的图层。
*   **播放速率变化日志 (Playback Rate Change Media Logs):** 测试播放速率变化时是否记录日志。
*   **画中画状态变化 (Picture In Picture State Change):** 测试 SurfaceId 更新时是否触发画中画状态变化通知。
*   **显示类型变化 (Display Type Change):** 测试不同显示类型 (内联、画中画、全屏) 之间的切换。
*   **帧接收器层级注册 (Register Frame Sink Hierarchy):** 测试与 CompositorFrameSink 的连接。

**归纳一下第3部分的功能:**

总而言之，这个代码片段主要集中于测试 `WebMediaPlayerImpl` 在播放过程中的各种状态变化和事件响应，包括但不限于：

*   **精确地报告和更新媒体播放位置和状态。**
*   **优雅地处理没有媒体流的情况。**
*   **正确地初始化和管理加密媒体的解密流程。**
*   **响应不同的等待条件并采取相应的行动。**
*   **处理底层渲染器可能发生的错误并尝试恢复。**
*   **适应视频配置和尺寸的变化。**
*   **根据页面和帧的可见性状态来控制播放行为。**

这些测试确保了 `WebMediaPlayerImpl` 作为 Chromium 媒体播放器的核心组件，能够可靠且正确地处理各种媒体播放场景，并与上层的 JavaScript API 和 HTML 元素协同工作。

Prompt: 
```
这是目录为blink/renderer/core/exported/web_media_player_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
udio_decoder_config = TestAudioConfig::Normal();

  EXPECT_CALL(client_, WasAlwaysMuted()).WillRepeatedly(Return(true));

  InitializeWebMediaPlayerImpl();
  SetPaused(false);

  EXPECT_CALL(delegate_, DidMediaMetadataChange(_, false, true, _));
  OnMetadata(metadata);
  testing::Mock::VerifyAndClearExpectations(&client_);
  testing::Mock::VerifyAndClearExpectations(&delegate_);

  EXPECT_CALL(client_, WasAlwaysMuted()).WillRepeatedly(Return(false));
  EXPECT_CALL(delegate_, DidMediaMetadataChange(_, true, true, _));
  wmpi_->SetVolume(1.0);
}

TEST_F(WebMediaPlayerImplTest, MediaPositionState_Playing) {
  InitializeWebMediaPlayerImpl();
  LoadAndWaitForReadyState(kAudioOnlyTestFile,
                           WebMediaPlayer::kReadyStateHaveFutureData);
  wmpi_->SetRate(1.0);
  Play();

  EXPECT_CALL(client_, DidPlayerMediaPositionStateChange(
                           1.0, kAudioOnlyTestFileDuration, base::TimeDelta(),
                           /*end_of_media=*/false));
  wmpi_->OnTimeUpdate();
}

TEST_F(WebMediaPlayerImplTest, MediaPositionState_Paused) {
  InitializeWebMediaPlayerImpl();
  LoadAndWaitForReadyState(kAudioOnlyTestFile,
                           WebMediaPlayer::kReadyStateHaveFutureData);
  wmpi_->SetRate(1.0);

  // The effective playback rate is 0.0 while paused.
  EXPECT_CALL(client_, DidPlayerMediaPositionStateChange(
                           0.0, kAudioOnlyTestFileDuration, base::TimeDelta(),
                           /*end_of_media=*/false));
  wmpi_->OnTimeUpdate();
}

TEST_F(WebMediaPlayerImplTest, MediaPositionState_PositionChange) {
  InitializeWebMediaPlayerImpl();
  LoadAndWaitForReadyState(kAudioOnlyTestFile,
                           WebMediaPlayer::kReadyStateHaveFutureData);
  wmpi_->SetRate(0.5);
  Play();

  testing::Sequence sequence;
  EXPECT_CALL(client_, DidPlayerMediaPositionStateChange(
                           0.0, kAudioOnlyTestFileDuration, base::Seconds(0.1),
                           /*end_of_media=*/false))
      .InSequence(sequence);
  wmpi_->Seek(0.1);
  wmpi_->OnTimeUpdate();

  // If we load enough data to resume playback the position should be updated.
  EXPECT_CALL(client_, DidPlayerMediaPositionStateChange(
                           0.5, kAudioOnlyTestFileDuration, base::Seconds(0.1),
                           /*end_of_media=*/false))
      .InSequence(sequence);
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  wmpi_->OnTimeUpdate();

  // No media time progress -> no MediaPositionState change.
  wmpi_->OnTimeUpdate();
}

TEST_F(WebMediaPlayerImplTest, MediaPositionState_EndOfMedia) {
  InitializeWebMediaPlayerImpl();
  LoadAndWaitForReadyState(kAudioOnlyTestFile,
                           WebMediaPlayer::kReadyStateHaveFutureData);
  wmpi_->SetRate(1.0);
  Play();
  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);

  testing::Sequence sequence;
  EXPECT_CALL(client_, DidPlayerMediaPositionStateChange(
                           1.0, kAudioOnlyTestFileDuration, base::TimeDelta(),
                           /*end_of_media=*/false))
      .InSequence(sequence);
  wmpi_->OnTimeUpdate();

  // If we play through to the end of media the position should be updated.
  EXPECT_CALL(client_, DidPlayerMediaPositionStateChange(
                           1.0, kAudioOnlyTestFileDuration, base::TimeDelta(),
                           /*end_of_media=*/true))
      .InSequence(sequence);
  SetEnded(true);
  wmpi_->OnTimeUpdate();
}

TEST_F(WebMediaPlayerImplTest, MediaPositionState_Underflow) {
  InitializeWebMediaPlayerImpl();
  LoadAndWaitForReadyState(kAudioOnlyTestFile,
                           WebMediaPlayer::kReadyStateHaveFutureData);
  wmpi_->SetRate(1.0);
  Play();

  // Underflow will set the effective playback rate to 0.0.
  EXPECT_CALL(client_, DidPlayerMediaPositionStateChange(
                           0.0, kAudioOnlyTestFileDuration, base::TimeDelta(),
                           /*end_of_media=*/false));
  SetReadyState(WebMediaPlayer::kReadyStateHaveCurrentData);
  wmpi_->OnTimeUpdate();
}

// It's possible for current time to be infinite if the page seeks to
// |media::kInfiniteDuration| (2**64 - 1) when duration is infinite.
TEST_F(WebMediaPlayerImplTest, MediaPositionState_InfiniteCurrentTime) {
  InitializeWebMediaPlayerImpl();
  SetDuration(media::kInfiniteDuration);
  wmpi_->OnTimeUpdate();

  EXPECT_CALL(client_,
              DidPlayerMediaPositionStateChange(0.0, media::kInfiniteDuration,
                                                media::kInfiniteDuration,
                                                /*end_of_media=*/false));
  wmpi_->Seek(media::kInfiniteDuration.InSecondsF());
  wmpi_->OnTimeUpdate();

  testing::Mock::VerifyAndClearExpectations(&client_);

  EXPECT_CALL(client_, DidPlayerMediaPositionStateChange(_, _, _, _)).Times(0);
  wmpi_->OnTimeUpdate();
}

TEST_F(WebMediaPlayerImplTest, NoStreams) {
  InitializeWebMediaPlayerImpl();
  media::PipelineMetadata metadata;

  EXPECT_CALL(client_, SetCcLayer(_)).Times(0);
  EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer()).Times(0);
  EXPECT_CALL(*surface_layer_bridge_ptr_, GetSurfaceId()).Times(0);
  EXPECT_CALL(*compositor_, EnableSubmission(_, _, _)).Times(0);

  // Since there is no audio nor video to play, OnError should occur with
  // resulting network state error update, and transition to HAVE_METADATA
  // should not occur.
  EXPECT_CALL(client_, NetworkStateChanged()).Times(1);
  EXPECT_CALL(client_, ReadyStateChanged()).Times(0);

  // No assertions in the production code should fail.
  OnMetadata(metadata);

  EXPECT_EQ(wmpi_->GetNetworkState(), WebMediaPlayer::kNetworkStateFormatError);
  EXPECT_EQ(wmpi_->GetReadyState(), WebMediaPlayer::kReadyStateHaveNothing);
}

TEST_F(WebMediaPlayerImplTest, Encrypted) {
  InitializeWebMediaPlayerImpl();

  // To avoid PreloadMetadataLazyLoad.
  wmpi_->SetPreload(WebMediaPlayer::kPreloadAuto);

  {
    base::RunLoop run_loop;
    EXPECT_CALL(encrypted_client_,
                Encrypted(media::EmeInitDataType::WEBM, NotNull(), Gt(0u)));
    EXPECT_CALL(encrypted_client_, DidBlockPlaybackWaitingForKey());
    EXPECT_CALL(encrypted_client_, DidResumePlaybackBlockedForKey())
        .WillRepeatedly(RunClosure(run_loop.QuitClosure()));
    Load(kEncryptedVideoOnlyTestFile);
    run_loop.Run();
  }

  CreateCdm();

  // The CDM doesn't support Decryptor nor CDM ID. Pipeline startup will fail.
  EXPECT_CALL(mock_cdm_context_, GetDecryptor())
      .Times(AnyNumber())
      .WillRepeatedly(Return(nullptr));

  {
    // Wait for kNetworkStateFormatError caused by Renderer initialization
    // error.
    base::RunLoop run_loop;
    EXPECT_CALL(client_, NetworkStateChanged()).WillOnce(Invoke([&] {
      if (wmpi_->GetNetworkState() == WebMediaPlayer::kNetworkStateFormatError)
        run_loop.QuitClosure().Run();
    }));
    SetCdm();
    run_loop.Run();
  }
}

TEST_F(WebMediaPlayerImplTest, Waiting_NoDecryptionKey) {
  InitializeWebMediaPlayerImpl();

  // Use non-encrypted file here since we don't have a CDM. Otherwise pipeline
  // initialization will stall waiting for a CDM to be set.
  LoadAndWaitForCurrentData(kVideoOnlyTestFile);

  EXPECT_CALL(encrypted_client_, DidBlockPlaybackWaitingForKey());
  EXPECT_CALL(encrypted_client_, DidResumePlaybackBlockedForKey());

  OnWaiting(media::WaitingReason::kNoDecryptionKey);
}

TEST_F(WebMediaPlayerImplTest, Waiting_SecureSurfaceLost) {
  InitializeWebMediaPlayerImpl();

  LoadAndWaitForReadyState(kVideoOnlyTestFile,
                           WebMediaPlayer::kReadyStateHaveFutureData);
  wmpi_->SetRate(1.0);
  Play();

  EXPECT_FALSE(IsSuspended());

  OnWaiting(media::WaitingReason::kSecureSurfaceLost);
  EXPECT_TRUE(IsSuspended());
}

ACTION(ReportHaveEnough) {
  arg0->OnBufferingStateChange(media::BUFFERING_HAVE_ENOUGH,
                               media::BUFFERING_CHANGE_REASON_UNKNOWN);
}

ACTION(ReportHardwareContextReset) {
  arg0->OnError(media::PIPELINE_ERROR_HARDWARE_CONTEXT_RESET);
}

#if BUILDFLAG(IS_WIN)

// Tests that for encrypted media, when a CDM is attached that requires
// MediaFoundationRenderer, the pipeline will fallback to create a new Renderer
// for RendererType::kMediaFoundation.
TEST_F(WebMediaPlayerImplTest, FallbackToMediaFoundationRenderer) {
  InitializeWebMediaPlayerImpl();
  // To avoid PreloadMetadataLazyLoad.
  wmpi_->SetPreload(WebMediaPlayer::kPreloadAuto);

  // Use MockRendererFactory for kMediaFoundation where the created Renderer
  // will take the CDM, complete Renderer initialization and report HAVE_ENOUGH
  // so that WMPI can reach kReadyStateHaveCurrentData.
  auto mock_renderer_factory = std::make_unique<media::MockRendererFactory>();
  EXPECT_CALL(*mock_renderer_factory, CreateRenderer(_, _, _, _, _, _))
      .WillOnce(testing::WithoutArgs(Invoke([]() {
        auto mock_renderer = std::make_unique<NiceMock<media::MockRenderer>>();
        EXPECT_CALL(*mock_renderer, OnSetCdm(_, _))
            .WillOnce(RunOnceCallback<1>(true));
        EXPECT_CALL(*mock_renderer, OnInitialize(_, _, _))
            .WillOnce(DoAll(RunOnceCallback<2>(media::PIPELINE_OK),
                            WithArg<1>(ReportHaveEnough())));
        return mock_renderer;
      })));

  renderer_factory_selector_->AddFactory(media::RendererType::kMediaFoundation,
                                         std::move(mock_renderer_factory));

  // Create and set CDM. The CDM doesn't support a Decryptor and requires Media
  // Foundation Renderer.
  EXPECT_CALL(mock_cdm_context_, GetDecryptor())
      .WillRepeatedly(Return(nullptr));
  EXPECT_CALL(mock_cdm_context_, RequiresMediaFoundationRenderer())
      .WillRepeatedly(Return(true));

  CreateCdm();
  SetCdm();

  // Load encrypted media and expect encrypted event.
  EXPECT_CALL(encrypted_client_,
              Encrypted(media::EmeInitDataType::WEBM, NotNull(), Gt(0u)));

  base::RunLoop run_loop;
  // MediaFoundationRenderer doesn't use AudioService.
  EXPECT_CALL(client_, DidUseAudioServiceChange(/*uses_audio_service=*/false))
      .WillOnce(RunClosure(run_loop.QuitClosure()));
  Load(kEncryptedVideoOnlyTestFile);
  run_loop.Run();
}

// Tests that when PIPELINE_ERROR_HARDWARE_CONTEXT_RESET happens, the pipeline
// will suspend/resume the pipeline, which will create a new Renderer.
TEST_F(WebMediaPlayerImplTest, PipelineErrorHardwareContextReset) {
  InitializeWebMediaPlayerImpl();
  // To avoid PreloadMetadataLazyLoad.
  wmpi_->SetPreload(WebMediaPlayer::kPreloadAuto);

  base::RunLoop run_loop;

  // Use MockRendererFactory which will create two Renderers. The first will
  // report a PIPELINE_ERROR_HARDWARE_CONTEXT_RESET after initialization. The
  // second one will initialize normally and quit the loop to complete the test.
  auto mock_renderer_factory = std::make_unique<media::MockRendererFactory>();
  EXPECT_CALL(*mock_renderer_factory, CreateRenderer(_, _, _, _, _, _))
      .WillOnce(testing::WithoutArgs(Invoke([]() {
        auto mock_renderer = std::make_unique<NiceMock<media::MockRenderer>>();
        EXPECT_CALL(*mock_renderer, OnInitialize(_, _, _))
            .WillOnce(DoAll(RunOnceCallback<2>(media::PIPELINE_OK),
                            WithArg<1>(ReportHardwareContextReset())));
        return mock_renderer;
      })))
      .WillOnce(testing::WithoutArgs(Invoke([&]() {
        auto mock_renderer = std::make_unique<NiceMock<media::MockRenderer>>();
        EXPECT_CALL(*mock_renderer, OnInitialize(_, _, _))
            .WillOnce(DoAll(RunOnceCallback<2>(media::PIPELINE_OK),
                            RunClosure(run_loop.QuitClosure())));
        return mock_renderer;
      })));

  renderer_factory_selector_->AddFactory(media::RendererType::kTest,
                                         std::move(mock_renderer_factory));
  renderer_factory_selector_->SetBaseRendererType(media::RendererType::kTest);

  Load(kVideoOnlyTestFile);
  run_loop.Run();
}

// Same as above, but tests that when PIPELINE_ERROR_HARDWARE_CONTEXT_RESET
// happens twice, the pipeline will always suspend/resume the pipeline, which
// will create new Renderers. See https://crbug.com/1454226 for the context.
TEST_F(WebMediaPlayerImplTest, PipelineErrorHardwareContextReset_Twice) {
  InitializeWebMediaPlayerImpl();
  // To avoid PreloadMetadataLazyLoad.
  wmpi_->SetPreload(WebMediaPlayer::kPreloadAuto);

  base::RunLoop run_loop;

  // Use MockRendererFactory which will create three Renderers. The first two
  // will report a PIPELINE_ERROR_HARDWARE_CONTEXT_RESET after initialization.
  // The third one will initialize normally and quit the loop to complete the
  // test.
  auto mock_renderer_factory = std::make_unique<media::MockRendererFactory>();
  EXPECT_CALL(*mock_renderer_factory, CreateRenderer(_, _, _, _, _, _))
      .WillOnce(testing::WithoutArgs(Invoke([]() {
        auto mock_renderer = std::make_unique<NiceMock<media::MockRenderer>>();
        EXPECT_CALL(*mock_renderer, OnInitialize(_, _, _))
            .WillOnce(DoAll(RunOnceCallback<2>(media::PIPELINE_OK),
                            WithArg<1>(ReportHardwareContextReset())));
        return mock_renderer;
      })))
      .WillOnce(testing::WithoutArgs(Invoke([]() {
        auto mock_renderer = std::make_unique<NiceMock<media::MockRenderer>>();
        EXPECT_CALL(*mock_renderer, OnInitialize(_, _, _))
            .WillOnce(DoAll(RunOnceCallback<2>(media::PIPELINE_OK),
                            WithArg<1>(ReportHardwareContextReset())));
        return mock_renderer;
      })))
      .WillOnce(testing::WithoutArgs(Invoke([&]() {
        auto mock_renderer = std::make_unique<NiceMock<media::MockRenderer>>();
        EXPECT_CALL(*mock_renderer, OnInitialize(_, _, _))
            .WillOnce(DoAll(RunOnceCallback<2>(media::PIPELINE_OK),
                            RunClosure(run_loop.QuitClosure())));
        return mock_renderer;
      })));

  renderer_factory_selector_->AddFactory(media::RendererType::kTest,
                                         std::move(mock_renderer_factory));
  renderer_factory_selector_->SetBaseRendererType(media::RendererType::kTest);

  Load(kVideoOnlyTestFile);
  run_loop.Run();
}

#endif  // BUILDFLAG(IS_WIN)

TEST_F(WebMediaPlayerImplTest, VideoConfigChange) {
  InitializeWebMediaPlayerImpl();
  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.video_decoder_config = TestVideoConfig::NormalCodecProfile(
      media::VideoCodec::kVP9, media::VP9PROFILE_PROFILE0);
  metadata.natural_size = gfx::Size(320, 240);

  // Arrival of metadata should trigger creation of reporter with video config
  // with profile matching test config.
  OnMetadata(metadata);
  VideoDecodeStatsReporter* last_reporter = GetVideoStatsReporter();
  ASSERT_NE(nullptr, last_reporter);
  ASSERT_EQ(media::VP9PROFILE_PROFILE0, GetVideoStatsReporterCodecProfile());

  // Changing the codec profile should trigger recreation of the reporter.
  auto new_profile_config = TestVideoConfig::NormalCodecProfile(
      media::VideoCodec::kVP9, media::VP9PROFILE_PROFILE1);
  OnVideoConfigChange(new_profile_config);
  ASSERT_EQ(media::VP9PROFILE_PROFILE1, GetVideoStatsReporterCodecProfile());
  ASSERT_NE(last_reporter, GetVideoStatsReporter());
  last_reporter = GetVideoStatsReporter();

  // Changing the codec (implies changing profile) should similarly trigger
  // recreation of the reporter.
  auto new_codec_config =
      TestVideoConfig::NormalCodecProfile(media::VideoCodec::kVP8);
  OnVideoConfigChange(new_codec_config);
  ASSERT_EQ(media::VP8PROFILE_MIN, GetVideoStatsReporterCodecProfile());
  ASSERT_NE(last_reporter, GetVideoStatsReporter());
  last_reporter = GetVideoStatsReporter();

  // Changing other aspects of the config (like colorspace) should not trigger
  // recreation of the reporter
  media::VideoDecoderConfig new_color_config =
      TestVideoConfig::NormalWithColorSpace(media::VideoCodec::kVP8,
                                            media::VideoColorSpace::REC709());
  ASSERT_EQ(media::VP8PROFILE_MIN, new_color_config.profile());
  OnVideoConfigChange(new_color_config);
  ASSERT_EQ(last_reporter, GetVideoStatsReporter());
  ASSERT_EQ(media::VP8PROFILE_MIN, GetVideoStatsReporterCodecProfile());

  EXPECT_CALL(*surface_layer_bridge_ptr_, ClearObserver());
}

TEST_F(WebMediaPlayerImplTest, NaturalSizeChange) {
  InitializeWebMediaPlayerImpl();
  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.video_decoder_config = TestVideoConfig::NormalCodecProfile(
      media::VideoCodec::kVP8, media::VP8PROFILE_MIN);
  metadata.natural_size = gfx::Size(320, 240);

  OnMetadata(metadata);
  ASSERT_EQ(gfx::Size(320, 240), wmpi_->NaturalSize());

  // Arrival of metadata should trigger creation of reporter with original size.
  VideoDecodeStatsReporter* orig_stats_reporter = GetVideoStatsReporter();
  ASSERT_NE(nullptr, orig_stats_reporter);
  ASSERT_TRUE(
      orig_stats_reporter->MatchesBucketedNaturalSize(gfx::Size(320, 240)));

  EXPECT_CALL(client_, SizeChanged());
  OnVideoNaturalSizeChange(gfx::Size(1920, 1080));
  ASSERT_EQ(gfx::Size(1920, 1080), wmpi_->NaturalSize());

  // New natural size triggers new reporter to be created.
  ASSERT_NE(orig_stats_reporter, GetVideoStatsReporter());
  ASSERT_TRUE(GetVideoStatsReporter()->MatchesBucketedNaturalSize(
      gfx::Size(1920, 1080)));

  EXPECT_CALL(*surface_layer_bridge_ptr_, ClearObserver());
}

TEST_F(WebMediaPlayerImplTest, NaturalSizeChange_Rotated) {
  InitializeWebMediaPlayerImpl();
  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.video_decoder_config =
      TestVideoConfig::NormalRotated(media::VIDEO_ROTATION_90);
  metadata.natural_size = gfx::Size(320, 240);

  OnMetadata(metadata);
  ASSERT_EQ(gfx::Size(320, 240), wmpi_->NaturalSize());

  // Arrival of metadata should trigger creation of reporter with original size.
  VideoDecodeStatsReporter* orig_stats_reporter = GetVideoStatsReporter();
  ASSERT_NE(nullptr, orig_stats_reporter);
  ASSERT_TRUE(
      orig_stats_reporter->MatchesBucketedNaturalSize(gfx::Size(320, 240)));

  EXPECT_CALL(client_, SizeChanged());
  // For 90/270deg rotations, the natural size should be transposed.
  OnVideoNaturalSizeChange(gfx::Size(1920, 1080));
  ASSERT_EQ(gfx::Size(1080, 1920), wmpi_->NaturalSize());

  // New natural size triggers new reporter to be created.
  ASSERT_NE(orig_stats_reporter, GetVideoStatsReporter());
  ASSERT_TRUE(GetVideoStatsReporter()->MatchesBucketedNaturalSize(
      gfx::Size(1080, 1920)));

  EXPECT_CALL(*surface_layer_bridge_ptr_, ClearObserver());
}

TEST_F(WebMediaPlayerImplTest, VideoLockedWhenPausedWhenHidden) {
  InitializeWebMediaPlayerImpl();

  // Setting metadata initializes |watch_time_reporter_| used in play().
  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.video_decoder_config = TestVideoConfig::Normal();

  OnMetadata(metadata);

  EXPECT_FALSE(IsVideoLockedWhenPausedWhenHidden());

  // Backgrounding the player sets the lock.
  BackgroundPlayer(BackgroundBehaviorType::Page);
  EXPECT_TRUE(IsVideoLockedWhenPausedWhenHidden());

  // Play without a user gesture doesn't unlock the player.
  Play();
  EXPECT_TRUE(IsVideoLockedWhenPausedWhenHidden());

  // With a user gesture it does unlock the player.
  GetWebLocalFrame()->NotifyUserActivation(
      mojom::UserActivationNotificationType::kTest);
  Play();
  EXPECT_FALSE(IsVideoLockedWhenPausedWhenHidden());

  // Pause without a user gesture doesn't lock the player.
  GetWebLocalFrame()->ConsumeTransientUserActivation();
  Pause();
  EXPECT_FALSE(IsVideoLockedWhenPausedWhenHidden());

  // With a user gesture, pause does lock the player.
  GetWebLocalFrame()->NotifyUserActivation(
      mojom::UserActivationNotificationType::kTest);
  Pause();
  EXPECT_TRUE(IsVideoLockedWhenPausedWhenHidden());

  // Foregrounding the player unsets the lock.
  ForegroundPlayer(BackgroundBehaviorType::Page);
  EXPECT_FALSE(IsVideoLockedWhenPausedWhenHidden());

  EXPECT_CALL(*surface_layer_bridge_ptr_, ClearObserver());
}

TEST_F(WebMediaPlayerImplTest,
       PageEventsHasNoEffectIfPausedDueToFrameVisibility) {
  // Adding a demuxer and loading a media is necessary to make sure that the
  // pipeline will start and that `WebMediaPlayerImpl::PauseVideoIfNeeded` won't
  // return early.
  std::unique_ptr<media::MockDemuxer> demuxer =
      std::make_unique<NiceMock<media::MockDemuxer>>();
  ON_CALL(*demuxer, IsSeekable()).WillByDefault(Return(true));
  InitializeWebMediaPlayerImpl(std::move(demuxer));
  // We need to load a media file to start the pipeline.
  Load(kVideoOnlyTestFile);
  EXPECT_FALSE(IsSuspended());

  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.video_decoder_config = TestVideoConfig::Normal();
  EXPECT_CALL(delegate_, DidMediaMetadataChange(_, false, true, _)).Times(2);
  OnMetadata(metadata);

  wmpi_->SetShouldPauseWhenFrameIsHidden(true);

  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetSeeking(false);
  Play();
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_FALSE(IsPausedBecauseFrameHidden());

  BackgroundPlayer(BackgroundBehaviorType::Frame);
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_TRUE(IsPausedBecauseFrameHidden());

  BackgroundPlayer(BackgroundBehaviorType::Page);
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_TRUE(IsPausedBecauseFrameHidden());

  ForegroundPlayer(BackgroundBehaviorType::Page);
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_TRUE(IsPausedBecauseFrameHidden());

  ForegroundPlayer(BackgroundBehaviorType::Frame);
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_FALSE(IsPausedBecauseFrameHidden());
}

TEST_F(WebMediaPlayerImplTest,
       FrameVisibilityEventsHavePrecedenceOverPageEvents) {
  // Adding a demuxer and loading a media is necessary to make sure that the
  // pipeline will start and that `WebMediaPlayerImpl::PauseVideoIfNeeded` won't
  // return early.
  std::unique_ptr<media::MockDemuxer> demuxer =
      std::make_unique<NiceMock<media::MockDemuxer>>();
  ON_CALL(*demuxer, IsSeekable()).WillByDefault(Return(true));
  InitializeWebMediaPlayerImpl(std::move(demuxer));
  // We need to load a media file to start the pipeline.
  Load(kVideoOnlyTestFile);
  EXPECT_FALSE(IsSuspended());

  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.video_decoder_config = TestVideoConfig::Normal();
  EXPECT_CALL(delegate_, DidMediaMetadataChange(_, false, true, _)).Times(2);
  OnMetadata(metadata);

  wmpi_->SetShouldPauseWhenFrameIsHidden(true);

  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetSeeking(false);
  Play();
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_FALSE(IsPausedBecauseFrameHidden());

  BackgroundPlayer(BackgroundBehaviorType::Page);
  EXPECT_TRUE(IsPausedBecausePageHidden());
  EXPECT_FALSE(IsPausedBecauseFrameHidden());

  BackgroundPlayer(BackgroundBehaviorType::Frame);
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_TRUE(IsPausedBecauseFrameHidden());

  ForegroundPlayer(BackgroundBehaviorType::Page);
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_TRUE(IsPausedBecauseFrameHidden());

  ForegroundPlayer(BackgroundBehaviorType::Frame);
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_FALSE(IsPausedBecauseFrameHidden());
}

// When `WebMediaPlayerImpl::should_pause_when_frame_is_hidden` is false, frame
// visibility changes should not affect the playback state.
TEST_F(WebMediaPlayerImplTest, DisabledFlagShouldPauseWhenFrameIsHidden) {
  // Adding a demuxer and loading a media is necessary to make sure that the
  // pipeline will start and that `WebMediaPlayerImpl::PauseVideoIfNeeded` won't
  // return early.
  std::unique_ptr<media::MockDemuxer> demuxer =
      std::make_unique<NiceMock<media::MockDemuxer>>();
  ON_CALL(*demuxer, IsSeekable()).WillByDefault(Return(true));
  InitializeWebMediaPlayerImpl(std::move(demuxer));
  // We need to load a media file to start the pipeline.
  Load(kVideoOnlyTestFile);
  EXPECT_FALSE(IsSuspended());

  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.video_decoder_config = TestVideoConfig::Normal();
  EXPECT_CALL(delegate_, DidMediaMetadataChange(_, false, true, _)).Times(2);
  OnMetadata(metadata);

  wmpi_->SetShouldPauseWhenFrameIsHidden(false);

  SetReadyState(WebMediaPlayer::kReadyStateHaveFutureData);
  SetSeeking(false);
  Play();
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_FALSE(IsPausedBecauseFrameHidden());

  BackgroundPlayer(BackgroundBehaviorType::Page);
  EXPECT_TRUE(IsPausedBecausePageHidden());
  EXPECT_FALSE(IsPausedBecauseFrameHidden());

  BackgroundPlayer(BackgroundBehaviorType::Frame);
  EXPECT_TRUE(IsPausedBecausePageHidden());
  EXPECT_FALSE(IsPausedBecauseFrameHidden());

  ForegroundPlayer(BackgroundBehaviorType::Page);
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_FALSE(IsPausedBecauseFrameHidden());

  ForegroundPlayer(BackgroundBehaviorType::Frame);
  EXPECT_FALSE(IsPausedBecausePageHidden());
  EXPECT_FALSE(IsPausedBecauseFrameHidden());
}

TEST_F(WebMediaPlayerImplTest, NotifiesObserverWhenFrozen) {
  InitializeWebMediaPlayerImpl();
  EXPECT_CALL(mock_observer_, OnFrozen());
  wmpi_->OnFrozen();
}

TEST_F(WebMediaPlayerImplTest, BackgroundIdlePauseTimerDependsOnAudio) {
  InitializeWebMediaPlayerImpl();
  SetSuspendState(true);
  SetPaused(false);

  ASSERT_TRUE(IsSuspended());

  // Video-only players are not paused when suspended.
  SetMetadata(false, true);
  ScheduleIdlePauseTimer();
  EXPECT_FALSE(IsIdlePauseTimerRunning());

  SetMetadata(true, true);
  ScheduleIdlePauseTimer();
  EXPECT_TRUE(IsIdlePauseTimerRunning());

  EXPECT_CALL(client_,
              PausePlayback(
                  MediaPlayerClient::PauseReason::kSuspendedPlayerIdleTimeout));
  FireIdlePauseTimer();
  base::RunLoop().RunUntilIdle();
}

// Verifies that an infinite duration doesn't muck up GetCurrentTimeInternal.
TEST_F(WebMediaPlayerImplTest, InfiniteDuration) {
  InitializeWebMediaPlayerImpl();
  SetDuration(media::kInfiniteDuration);

  // Send metadata so we have a watch time reporter created.
  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.video_decoder_config = TestVideoConfig::Normal();
  metadata.has_audio = true;
  metadata.audio_decoder_config = TestAudioConfig::Normal();
  metadata.natural_size = gfx::Size(400, 400);

  OnMetadata(metadata);

  EXPECT_EQ(std::numeric_limits<double>::infinity(), wmpi_->Duration());
  EXPECT_EQ(0, wmpi_->CurrentTime());
  EXPECT_EQ(base::TimeDelta(), GetCurrentTimeInternal());

  SetEnded(true);
  EXPECT_EQ(0, wmpi_->CurrentTime());
  EXPECT_EQ(base::TimeDelta(), GetCurrentTimeInternal());

  // Pause should not pick up infinity for the current time.
  wmpi_->Pause();
  EXPECT_EQ(0, wmpi_->CurrentTime());
  EXPECT_EQ(base::TimeDelta(), GetCurrentTimeInternal());

  EXPECT_CALL(*surface_layer_bridge_ptr_, ClearObserver());
}

TEST_F(WebMediaPlayerImplTest, SetContentsLayerGetsWebLayerFromBridge) {
  InitializeWebMediaPlayerImpl();

  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.video_decoder_config =
      TestVideoConfig::NormalRotated(media::VIDEO_ROTATION_90);
  metadata.natural_size = gfx::Size(320, 240);

  EXPECT_CALL(client_, SetCcLayer(_)).Times(0);
  EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer());
  EXPECT_CALL(*surface_layer_bridge_ptr_, GetSurfaceId())
      .WillOnce(ReturnRef(surface_id_));
  EXPECT_CALL(*surface_layer_bridge_ptr_, SetContentsOpaque(false));
  EXPECT_CALL(*compositor_, EnableSubmission(_, _, _));

  // We only call the callback to create the bridge in OnMetadata, so we need
  // to call it.
  OnMetadata(metadata);

  scoped_refptr<cc::Layer> layer = cc::Layer::Create();

  EXPECT_CALL(*surface_layer_bridge_ptr_, GetCcLayer())
      .WillRepeatedly(Return(layer.get()));
  EXPECT_CALL(client_, SetCcLayer(Eq(layer.get())));
  EXPECT_CALL(*surface_layer_bridge_ptr_, SetContentsOpaque(false));
  wmpi_->RegisterContentsLayer(layer.get());

  EXPECT_CALL(*surface_layer_bridge_ptr_, ClearObserver());
}

TEST_F(WebMediaPlayerImplTest, PlaybackRateChangeMediaLogs) {
  InitializeWebMediaPlayerImpl();

  {
    InSequence s;

    // Expect precisely one rate change log from this test case.
    EXPECT_MEDIA_LOG_ON(*media_log_, PlaybackRateChanged("0", "0.8"));
    EXPECT_MEDIA_LOG_ON(*media_log_, WmpiDestroyed());

    wmpi_->SetRate(0.0);  // No change from initial rate, so no log.
    wmpi_->SetRate(0.8);  // This should log change from 0 -> 0.8
    wmpi_->SetRate(0.8);  // No change from previous rate, so no log.
  }
}

// Tests that updating the surface id calls OnPictureInPictureStateChange.
TEST_F(WebMediaPlayerImplTest, PictureInPictureStateChange) {
  InitializeWebMediaPlayerImpl();

  EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer());
  EXPECT_CALL(*surface_layer_bridge_ptr_, GetSurfaceId())
      .WillRepeatedly(ReturnRef(surface_id_));
  EXPECT_CALL(*compositor_, EnableSubmission(_, _, _));
  EXPECT_CALL(*surface_layer_bridge_ptr_, SetContentsOpaque(false));

  media::PipelineMetadata metadata;
  metadata.has_video = true;
  OnMetadata(metadata);

  EXPECT_CALL(client_, GetDisplayType())
      .WillRepeatedly(Return(DisplayType::kPictureInPicture));
  EXPECT_CALL(client_, OnPictureInPictureStateChange()).Times(1);

  wmpi_->OnSurfaceIdUpdated(surface_id_);

  EXPECT_CALL(*surface_layer_bridge_ptr_, ClearObserver());
}

// Test that OnPictureInPictureStateChange is not called for audio elements.
// This test explicitly sets display type to picture in picture, for an audio
// element, for testing purposes only (See crbug.com/1403547 for reference).
TEST_F(WebMediaPlayerImplTest, OnPictureInPictureStateChangeNotCalled) {
  InitializeWebMediaPlayerImpl();

  EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer());
  EXPECT_CALL(*surface_layer_bridge_ptr_, GetSurfaceId())
      .WillRepeatedly(ReturnRef(surface_id_));
  EXPECT_CALL(*compositor_, EnableSubmission(_, _, _));
  EXPECT_CALL(*surface_layer_bridge_ptr_, SetContentsOpaque(false));

  media::PipelineMetadata metadata;
  metadata.has_video = true;
  metadata.has_audio = true;
  OnMetadata(metadata);

  EXPECT_CALL(client_, IsAudioElement()).WillOnce(Return(true));
  EXPECT_CALL(client_, GetDisplayType())
      .WillRepeatedly(Return(DisplayType::kPictureInPicture));
  EXPECT_CALL(client_, OnPictureInPictureStateChange()).Times(0);

  wmpi_->OnSurfaceIdUpdated(surface_id_);

  EXPECT_CALL(*surface_layer_bridge_ptr_, ClearObserver());
}

TEST_F(WebMediaPlayerImplTest, DisplayTypeChange) {
  InitializeWebMediaPlayerImpl();

  scoped_refptr<cc::Layer> layer = cc::Layer::Create();

  EXPECT_CALL(*surface_layer_bridge_ptr_, CreateSurfaceLayer());
  EXPECT_CALL(*surface_layer_bridge_ptr_, GetSurfaceId())
      .WillRepeatedly(ReturnRef(surface_id_));
  EXPECT_CALL(*compositor_, EnableSubmission(_, _, _));
  EXPECT_CALL(*surface_layer_bridge_ptr_, SetContentsOpaque(false));
  EXPECT_CALL(*surface_layer_bridge_ptr_, GetCcLayer())
      .WillRepeatedly(Return(layer.get()));

  media::PipelineMetadata metadata;
  metadata.has_video = true;
  OnMetadata(metadata);

  // When entering PIP mode the CC layer is set to null so we are not
  // compositing the video in the original window.
  EXPECT_CALL(client_, IsInAutoPIP()).WillOnce(Return(false));
  EXPECT_CALL(client_, SetCcLayer(nullptr));
  wmpi_->OnDisplayTypeChanged(DisplayType::kPictureInPicture);

  // When switching back to the inline mode the CC layer is set back to the
  // bridge CC layer.
  EXPECT_CALL(client_, SetCcLayer(testing::NotNull()));
  wmpi_->OnDisplayTypeChanged(DisplayType::kInline);

  // When in persistent state (e.g. auto-pip), video is not playing in the
  // regular Picture-in-Picture mode. Don't set the CC layer to null.
  EXPECT_CALL(client_, IsInAutoPIP()).WillOnce(Return(true));
  EXPECT_CALL(client_, SetCcLayer(_)).Times(0);
  wmpi_->OnDisplayTypeChanged(DisplayType::kPictureInPicture);

  // When switching back to fullscreen mode the CC layer is set back to the
  // bridge CC layer.
  EXPECT_CALL(client_, SetCcLayer(testing::NotNull()));
  wmpi_->OnDisplayTypeChanged(DisplayType::kFullscreen);

  EXPECT_CALL(*surface_layer_bridge_ptr_, ClearObserver());
}

TEST_F(WebMediaPlayerImplTest, RegisterFrameSinkHierarchy) {
  InitializeWebMediaPlayerImpl();
  media::PipelineMetadata metadata;
  metadata.has_video = true;
  OnMetadata(metadata);

  EXPECT_CALL(*surface_layer_bridge_ptr_, RegisterFrameSinkHierarchy());
  wmpi_->RegisterFrameSinkHierarchy();

  EXPECT_CALL(*surface_layer_bridge_ptr_, UnregisterFrameSinkHierarchy());
  wmpi_->UnregisterFrameSinkHierarchy();
}

TEST_F(WebMediaPlayerImplTest, O
"""


```