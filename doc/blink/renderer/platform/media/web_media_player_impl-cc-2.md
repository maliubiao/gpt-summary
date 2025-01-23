Response: The user wants a summary of the functionalities of the provided C++ code snippet from `web_media_player_impl.cc`. The summary should cover:
1. **General functions**: What does this part of the code do?
2. **Relation to web technologies**: How does it interact with JavaScript, HTML, and CSS? Provide examples.
3. **Logical reasoning**: If the code performs any logical deductions, provide examples with hypothetical inputs and outputs.
4. **Common user/programming errors**:  Highlight potential pitfalls for users or developers.
5. **Overall function**: A concluding summary of the code's purpose within the larger `WebMediaPlayerImpl`.

Let's break down the code and analyze each part:

*   **Memory Management**: The `OnMemoryDump` functions suggest the code is involved in tracking and reporting memory usage related to media playback.
*   **Idle Pausing**: `ScheduleIdlePauseTimer` indicates a mechanism for pausing playback after a period of inactivity.
*   **Watch Time Reporting**:  The `CreateWatchTimeReporter` and related methods manage reporting of playback statistics.
*   **Visibility Handling**:  Functions like `IsPageHidden`, `IsFrameHidden`, `ShouldPausePlaybackWhenHidden`, and `UpdateBackgroundVideoOptimizationState` deal with how playback behaves when the page or frame is hidden.
*   **Remote Rendering**: `SwitchToRemoteRenderer` and `SwitchToLocalRenderer` suggest support for casting or remote playback.
*   **Metrics Reporting**: The `WriteSplitHistogram` and various `Record...` functions are used for collecting and reporting media playback statistics.
*   **First Frame Handling**:  `OnFirstFrame` handles events when the first video frame is rendered.
*   **Encryption Handling**: `RecordEncryptionScheme` tracks encryption information.
*   **Buffering and Playback Rate**: `MaybeUpdateBufferSizesForPlayback` indicates involvement in managing buffer sizes based on playback rate.
*   **Smoothness Helper**: `UpdateSmoothnessHelper` suggests an experimental feature related to playback smoothness.
*   **Audio Focus**: `HasUnmutedAudio` relates to managing audio focus.
*   **Video Capture**: `IsVideoBeingCaptured` checks if the video is being captured.
*   **Frame Sink Hierarchy**: `RegisterFrameSinkHierarchy` and `UnregisterFrameSinkHierarchy` seem related to how the video is rendered within the browser's compositing system.
*   **Video Occlusion**: `RecordVideoOcclusionState` tracks if the video is occluded.
*   **Session UMA Reporting**: `ReportSessionUMAs` is responsible for reporting aggregated metrics at the end of a playback session.
*   **Timing Allow Origin**: `PassedTimingAllowOriginCheck` verifies cross-origin access permissions.
*   **Metadata Change**: `DidMediaMetadataChange` handles events when media metadata changes.

Now, let's map these functionalities to the specific requests:

*   **Javascript/HTML/CSS relation**:  The playback controls and visibility are directly influenced by JavaScript. HTML provides the `<video>` or `<audio>` elements, and CSS affects the styling.
*   **Logical Reasoning**:  The decision-making around pausing when hidden or disabling video tracks involves logical conditions.
*   **User/Programming Errors**:  Incorrectly handling visibility changes or not checking for playback errors are potential issues.

Finally, let's synthesize the findings into a structured response.
这是 `blink/renderer/platform/media/web_media_player_impl.cc` 源代码文件的第 3 部分，延续了之前代码的功能，主要负责媒体播放器实现的以下功能：

**1. 内存管理和监控 (Memory Management and Monitoring):**

*   **`OnMainThreadMemoryDump` 和 `OnMediaThreadMemoryDump`:** 这两个函数负责在 Chromium 的内存转储过程中报告 WebMediaPlayerImpl 及其相关组件（如 demuxer）的内存使用情况。这对于性能分析和内存泄漏检测至关重要。
    *   **与 JavaScript, HTML, CSS 的关系:**  当网页使用 `<video>` 或 `<audio>` 标签播放媒体时，浏览器会创建 `WebMediaPlayerImpl` 实例。这些函数报告的内存使用情况最终会影响到浏览器的整体内存占用，可能导致页面性能下降或崩溃。开发者可以通过浏览器提供的性能工具（如 Chrome DevTools 的 Memory 面板）查看这些信息。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  一个网页正在播放一个大型视频文件。
        *   **输出:**  `OnMainThreadMemoryDump` 和 `OnMediaThreadMemoryDump` 会报告视频解码器、音频解码器、数据源和 demuxer 消耗的内存量。这些报告会包含在浏览器的内存快照中。

**2. 空闲暂停定时器 (Idle Pause Timer):**

*   **`ScheduleIdlePauseTimer`:** 当播放器处于暂停状态（但不是因为页面隐藏），处于挂起状态且有音频时，此函数会启动一个定时器。如果定时器触发，它会暂停播放。这可能用于在后台节省资源。
    *   **与 JavaScript, HTML, CSS 的关系:**  JavaScript 可以调用 `pause()` 方法来暂停播放器。`ScheduleIdlePauseTimer` 提供了一种浏览器自动暂停的机制，即使 JavaScript 没有明确调用暂停。这有助于优化资源使用。

**3. 观看时间报告器 (Watch Time Reporter):**

*   **`CreateWatchTimeReporter` 和 `UpdateSecondaryProperties`:** 这些函数创建并更新 `WatchTimeReporter` 对象，用于收集和报告媒体播放的各种统计信息，例如播放时长、分辨率、编解码器等。这些数据用于分析用户行为和改进媒体体验。
    *   **与 JavaScript, HTML, CSS 的关系:**  `WatchTimeReporter` 记录的统计信息可以用于分析用户在网页上观看媒体的行为，例如用户观看了多少视频，使用了哪些功能（如全屏、画中画）。这些信息可以帮助网站开发者优化他们的媒体内容和用户界面。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  用户在一个网页上播放了一个 MP4 视频，并将其切换到全屏模式。
        *   **输出:**  `CreateWatchTimeReporter` 会根据视频的音频和视频轨道信息进行初始化，并记录视频的自然尺寸。当用户切换到全屏时，`watch_time_reporter_->OnDisplayTypeFullscreen()` 会被调用，记录这一事件。

**4. 页面和帧可见性处理 (Page and Frame Visibility Handling):**

*   **`IsPageHidden`, `IsFrameHidden`, `IsPausedBecausePageHidden`, `IsPausedBecauseFrameHidden`, `ShouldPausePlaybackWhenHidden`, `ShouldDisableVideoWhenHidden`, `UpdateBackgroundVideoOptimizationState`, `PauseVideoIfNeeded`, `EnableVideoTrackIfNeeded`, `DisableVideoTrackIfNeeded`, `OnBecameVisible`:**  这些函数处理当包含媒体播放器的页面或 iframe 被隐藏或重新显示时的播放行为。它们决定是否暂停播放、禁用视频轨道以节省资源。
    *   **与 JavaScript, HTML, CSS 的关系:**  浏览器会通知 `WebMediaPlayerImpl` 页面或帧的可见性变化，这通常是由用户的操作（如切换标签页、最小化窗口）或 JavaScript 代码引起的。HTML 的 `visibilitychange` 事件和 CSS 的 `visibility` 属性与这些功能密切相关。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  一个包含正在播放视频的标签页被用户切换到后台。`delegate_->IsPageHidden()` 返回 `true`。
        *   **输出:**  `ShouldPausePlaybackWhenHidden()` 会根据配置和媒体类型判断是否需要暂停。如果需要暂停，`PauseVideoIfNeeded()` 会被调用，最终导致播放器暂停。
        *   **假设输入:**  一个视频在后台标签页播放时，`ShouldDisableVideoWhenHidden()` 判断可以禁用视频轨道。
        *   **输出:**  `DisableVideoTrackIfNeeded()` 会被调用，通知底层媒体管道停止解码视频，从而节省资源。

**5. 远程渲染 (Remote Rendering):**

*   **`SwitchToRemoteRenderer` 和 `SwitchToLocalRenderer`:**  这些函数处理将媒体渲染切换到远程设备（如 Chromecast）或从远程设备切回本地渲染的过程。
    *   **与 JavaScript, HTML, CSS 的关系:**  Web API（如 Remote Playback API）允许 JavaScript 代码发起和控制远程播放。这些 C++ 函数响应来自渲染进程的指令，执行实际的渲染切换操作。

**6. 性能统计和指标记录 (Performance Statistics and Metrics Recording):**

*   **`WriteSplitHistogram`, `RecordUnderflowDuration`, `RecordVideoNaturalSize`, `OnFirstFrame`, `RecordEncryptionScheme`, `MaybeSetContainerNameForMetrics`, `MaybeUpdateBufferSizesForPlayback`, `OnSimpleWatchTimerTick`, `ReportSessionUMAs`, `RecordVideoOcclusionState`:**  这些函数用于记录各种媒体播放相关的性能指标和事件，并将这些数据报告给 Chromium 的 UMA (User Metrics Analysis) 系统。这些数据用于分析媒体播放的性能和用户体验。
    *   **与 JavaScript, HTML, CSS 的关系:**  这些底层性能指标的收集有助于浏览器开发者了解不同网页、不同媒体格式和不同网络条件下媒体播放的性能瓶颈。这些信息可以驱动浏览器和网页技术的改进。
    *   **逻辑推理 (假设输入与输出):**
        *   **假设输入:**  视频播放过程中发生了缓冲不足。
        *   **输出:**  `RecordUnderflowDuration()` 会记录缓冲不足的持续时间，并将其作为 UMA 数据发送。
        *   **假设输入:**  视频的第一帧被成功解码并显示。
        *   **输出:**  `OnFirstFrame()` 会记录从加载开始到第一帧显示的时间间隔，并将其作为 UMA 数据发送。

**7. 其他功能:**

*   **`ForceStaleStateForTesting`, `IsSuspendedForTesting`, `DidLazyLoad`, `IsOpaque`, `GetDelegateId`, `GetSurfaceId`, `RequestVideoFrameCallback`, `GetVideoFramePresentationMetadata`, `UpdateFrameIfStale`, `AsWeakPtr`, `SetPipelineStatisticsForTest`, `GetPipelineStatistics`, `SetPipelineMediaDurationForTest`, `GetPipelineMediaDuration`, `GetMediaContentType`, `SetTickClockForTest`, `IsInPictureInPicture`, `UpdateSmoothnessHelper`, `GetLearningTaskController`, `HasUnmutedAudio`, `IsVideoBeingCaptured`, `RegisterFrameSinkHierarchy`, `UnregisterFrameSinkHierarchy`, `PassedTimingAllowOriginCheck`, `DidMediaMetadataChange`, `GetSrcAfterRedirects`:**  这些函数涵盖了各种辅助功能，例如测试支持、获取播放器状态、处理画中画模式、实现实验性的平滑度辅助功能、获取重定向后的 URL、检查跨域权限以及处理媒体元数据的变化。

**用户或编程常见的使用错误示例:**

*   **未正确处理页面或帧的可见性变化:**  开发者可能没有正确监听 `visibilitychange` 事件或使用 Page Visibility API，导致媒体在后台仍然播放，浪费用户资源。
*   **假设媒体总是可见的:**  代码中需要考虑媒体可能在后台播放的情况，例如，不应该在隐藏状态下执行需要用户交互的操作。
*   **错误地假设远程播放总是成功的:**  网络问题或设备兼容性可能导致远程播放失败，需要有相应的错误处理机制。
*   **过度依赖同步操作:**  在媒体播放的关键路径上执行耗时的同步操作可能会导致卡顿。应该尽可能使用异步操作。

**归纳一下它的功能 (Summary of its function):**

这部分代码是 `WebMediaPlayerImpl` 的核心组成部分，主要负责管理媒体播放器的运行时行为，包括内存管理、后台优化、远程播放控制、性能监控和各种状态管理。它确保了在各种场景下（例如，页面隐藏、远程播放）媒体播放器能够正确高效地工作，并收集必要的性能数据用于分析和改进。它与 JavaScript、HTML 和 CSS 通过浏览器提供的 API 和事件进行交互，共同实现了网页上的媒体播放功能。

### 提示词
```
这是目录为blink/renderer/platform/media/web_media_player_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ce_memory_usage
           << ", Demuxer: " << demuxer_memory_usage;

  const int64_t delta = current_memory_usage - last_reported_memory_usage_;
  last_reported_memory_usage_ = current_memory_usage;
  external_memory_accounter_.Update(isolate_.get(), delta);
}

void WebMediaPlayerImpl::OnMainThreadMemoryDump(
    media::MediaPlayerLoggingID id,
    const base::trace_event::MemoryDumpArgs& args,
    base::trace_event::ProcessMemoryDump* pmd) {
  const auto stats = GetPipelineStatistics();
  auto player_node_name =
      base::StringPrintf("media/webmediaplayer/player_0x%x", id);
  auto* player_node = pmd->CreateAllocatorDump(player_node_name);
  player_node->AddScalar(
      base::trace_event::MemoryAllocatorDump::kNameObjectCount,
      base::trace_event::MemoryAllocatorDump::kUnitsObjects, 1);

  if (args.level_of_detail !=
      base::trace_event::MemoryDumpLevelOfDetail::kBackground) {
    bool suspended = pipeline_controller_->IsPipelineSuspended();
    auto player_state =
        base::StringPrintf("Paused: %d Ended: %d ReadyState: %d Suspended: %d",
                           paused_, ended_, GetReadyState(), suspended);
    player_node->AddString("player_state", "", player_state);
  }

  CreateAllocation(pmd, id, "audio", stats.audio_memory_usage);
  CreateAllocation(pmd, id, "video", stats.video_memory_usage);

  if (demuxer_manager_->HasDataSource()) {
    CreateAllocation(pmd, id, "data_source",
                     demuxer_manager_->GetDataSourceMemoryUsage());
  }
}

// static
void WebMediaPlayerImpl::OnMediaThreadMemoryDump(
    media::MediaPlayerLoggingID id,
    Demuxer* demuxer,
    const base::trace_event::MemoryDumpArgs& args,
    base::trace_event::ProcessMemoryDump* pmd) {
  if (!demuxer)
    return;

  CreateAllocation(pmd, id, "demuxer", demuxer->GetMemoryUsage());
}

void WebMediaPlayerImpl::ScheduleIdlePauseTimer() {
  // Only schedule the pause timer if we're not paused or paused but going to
  // resume when foregrounded, and are suspended and have audio.
  if ((paused_ && !IsPausedBecausePageHidden()) ||
      !pipeline_controller_->IsSuspended() || !HasAudio()) {
    return;
  }

#if BUILDFLAG(IS_ANDROID)
  // Don't pause videos casted as part of RemotePlayback.
  if (is_flinging_)
    return;
#endif

  // Idle timeout chosen arbitrarily.
  background_pause_timer_.Start(
      FROM_HERE, base::Seconds(5),
      base::BindOnce(
          &MediaPlayerClient::PausePlayback, base::Unretained(client_),
          MediaPlayerClient::PauseReason::kSuspendedPlayerIdleTimeout));
}

void WebMediaPlayerImpl::CreateWatchTimeReporter() {
  if (!HasVideo() && !HasAudio())
    return;

  // MediaPlayerRenderer does not know about tracks until playback starts.
  // Assume audio-only unless the natural size has been detected.
  bool has_video = pipeline_metadata_.has_video;
  if (using_media_player_renderer_) {
    has_video = !pipeline_metadata_.natural_size.IsEmpty();
  }

  // Create the watch time reporter and synchronize its initial state.
  watch_time_reporter_ = std::make_unique<WatchTimeReporter>(
      media::mojom::PlaybackProperties::New(
          pipeline_metadata_.has_audio, has_video, false, false,
          GetDemuxerType() == media::DemuxerType::kChunkDemuxer, is_encrypted_,
          embedded_media_experience_enabled_,
          media::mojom::MediaStreamType::kNone, renderer_type_),
      pipeline_metadata_.natural_size,
      base::BindRepeating(&WebMediaPlayerImpl::GetCurrentTimeInternal,
                          base::Unretained(this)),
      base::BindRepeating(&WebMediaPlayerImpl::GetPipelineStatistics,
                          base::Unretained(this)),
      media_metrics_provider_.get(),
      frame_->GetTaskRunner(TaskType::kInternalMedia));
  watch_time_reporter_->OnVolumeChange(volume_);
  watch_time_reporter_->OnDurationChanged(GetPipelineMediaDuration());

  if (delegate_->IsPageHidden()) {
    watch_time_reporter_->OnHidden();
  } else {
    watch_time_reporter_->OnShown();
  }

  if (client_->HasNativeControls())
    watch_time_reporter_->OnNativeControlsEnabled();
  else
    watch_time_reporter_->OnNativeControlsDisabled();

  switch (client_->GetDisplayType()) {
    case DisplayType::kInline:
      watch_time_reporter_->OnDisplayTypeInline();
      break;
    case DisplayType::kFullscreen:
      watch_time_reporter_->OnDisplayTypeFullscreen();
      break;
    case DisplayType::kPictureInPicture:
      watch_time_reporter_->OnDisplayTypePictureInPicture();
      break;
  }

  UpdateSecondaryProperties();

  // If the WatchTimeReporter was recreated in the middle of playback, we want
  // to resume playback here too since we won't get another play() call. When
  // seeking, the seek completion will restart it if necessary.
  if (!paused_ && !seeking_)
    watch_time_reporter_->OnPlaying();
}

void WebMediaPlayerImpl::UpdateSecondaryProperties() {
  watch_time_reporter_->UpdateSecondaryProperties(
      media::mojom::SecondaryPlaybackProperties::New(
          pipeline_metadata_.audio_decoder_config.codec(),
          pipeline_metadata_.video_decoder_config.codec(),
          pipeline_metadata_.audio_decoder_config.profile(),
          pipeline_metadata_.video_decoder_config.profile(),
          audio_decoder_type_, video_decoder_type_,
          pipeline_metadata_.audio_decoder_config.encryption_scheme(),
          pipeline_metadata_.video_decoder_config.encryption_scheme(),
          pipeline_metadata_.natural_size));
}

bool WebMediaPlayerImpl::IsPageHidden() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  return delegate_->IsPageHidden() && !was_suspended_for_frame_closed_;
}

bool WebMediaPlayerImpl::IsFrameHidden() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  return delegate_->IsFrameHidden() && !was_suspended_for_frame_closed_;
}

bool WebMediaPlayerImpl::IsPausedBecausePageHidden() const {
  return visibility_pause_reason_ &&
         visibility_pause_reason_ ==
             MediaPlayerClient::PauseReason::kPageHidden;
}

bool WebMediaPlayerImpl::IsPausedBecauseFrameHidden() const {
  return visibility_pause_reason_ &&
         visibility_pause_reason_ ==
             MediaPlayerClient::PauseReason::kFrameHidden;
}

bool WebMediaPlayerImpl::IsStreaming() const {
  return demuxer_manager_->IsStreaming();
}

bool WebMediaPlayerImpl::DoesOverlaySupportMetadata() const {
  return pipeline_metadata_.video_decoder_config.video_transformation() ==
         media::kNoTransformation;
}

void WebMediaPlayerImpl::UpdateRemotePlaybackCompatibility(bool is_compatible) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  client_->RemotePlaybackCompatibilityChanged(
      KURL(demuxer_manager_->LoadedUrl()), is_compatible);
}

void WebMediaPlayerImpl::ForceStaleStateForTesting(ReadyState target_state) {
  stale_state_override_for_testing_.emplace(target_state);
  UpdatePlayState();
}

bool WebMediaPlayerImpl::IsSuspendedForTesting() {
  // This intentionally uses IsPipelineSuspended since we need to know when the
  // pipeline has reached the suspended state, not when it's in suspending.
  return pipeline_controller_->IsPipelineSuspended();
}

bool WebMediaPlayerImpl::DidLazyLoad() const {
  return did_lazy_load_;
}

void WebMediaPlayerImpl::OnBecameVisible() {
  have_enough_after_lazy_load_cb_.Cancel();
  needs_first_frame_ = !has_first_frame_;
  UpdatePlayState();
}

bool WebMediaPlayerImpl::IsOpaque() const {
  return opaque_;
}

int WebMediaPlayerImpl::GetDelegateId() {
  return delegate_id_;
}

std::optional<viz::SurfaceId> WebMediaPlayerImpl::GetSurfaceId() {
  if (!surface_layer_for_video_enabled_)
    return std::nullopt;
  return bridge_->GetSurfaceId();
}

void WebMediaPlayerImpl::RequestVideoFrameCallback() {
  // If the first frame hasn't been received, kick off a request to generate one
  // since we may not always do so for hidden preload=metadata playbacks.
  if (!has_first_frame_) {
    OnBecameVisible();
  }

  compositor_->SetOnFramePresentedCallback(
      base::BindPostTaskToCurrentDefault(base::BindOnce(
          &WebMediaPlayerImpl::OnNewFramePresentedCallback, weak_this_)));
}

void WebMediaPlayerImpl::OnNewFramePresentedCallback() {
  client_->OnRequestVideoFrameCallback();
}

std::unique_ptr<WebMediaPlayer::VideoFramePresentationMetadata>
WebMediaPlayerImpl::GetVideoFramePresentationMetadata() {
  return compositor_->GetLastPresentedFrameMetadata();
}

void WebMediaPlayerImpl::UpdateFrameIfStale() {
  // base::Unretained is safe here because `compositor_` is destroyed on
  // `vfc_task_runner_`. The destruction is queued from `this`' destructor,
  // which also runs on `main_task_runner_`, which makes it impossible for
  // UpdateCurrentFrameIfStale() to be queued after `compositor_`'s dtor.
  vfc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&VideoFrameCompositor::UpdateCurrentFrameIfStale,
                     base::Unretained(compositor_.get()),
                     VideoFrameCompositor::UpdateType::kBypassClient));
}

base::WeakPtr<WebMediaPlayer> WebMediaPlayerImpl::AsWeakPtr() {
  return weak_this_;
}

bool WebMediaPlayerImpl::ShouldPausePlaybackWhenHidden() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (should_pause_when_frame_is_hidden_ && IsFrameHidden()) {
    return true;
  }

  const bool preserve_audio =
      should_pause_background_muted_audio_
          ? HasUnmutedAudio() || audio_source_provider_->IsAudioBeingCaptured()
          : HasAudio();

  // Audio only stream is allowed to play when in background.
  if (!HasVideo() && preserve_audio)
    return false;

  // MediaPlayer always signals audio and video, so use an empty natural size to
  // determine if there's really video or not.
  if (using_media_player_renderer_ &&
      pipeline_metadata_.natural_size.IsEmpty() && preserve_audio) {
    return false;
  }

  // PiP is the only exception when background video playback is disabled.
  if (HasVideo() && IsInPictureInPicture())
    return false;

  // This takes precedent over every restriction except PiP.
  if (!is_background_video_playback_enabled_)
    return true;

  if (is_flinging_)
    return false;

  // If suspending background video, pause any video that's not unlocked to play
  // in the background.
  if (IsBackgroundSuspendEnabled(this)) {
    return !preserve_audio || (IsResumeBackgroundVideosEnabled() &&
                               video_locked_when_paused_when_hidden_);
  }

  if (HasVideo() && IsVideoBeingCaptured())
    return false;

  return !preserve_audio;
}

bool WebMediaPlayerImpl::ShouldDisableVideoWhenHidden() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (!is_background_video_track_optimization_supported_) {
    return false;
  }

  // Only disable the video track on audio + video playbacks, otherwise they
  // should be paused or left alone.
  if (!HasVideo() || !HasAudio()) {
    return false;
  }

  // Disabling tracks causes seeks which can cause problematic network delays
  // on streaming resources.
  if (IsStreaming()) {
    return false;
  }

  // In these cases something external needs the frames.
  if (IsInPictureInPicture() || IsVideoBeingCaptured() || is_flinging_) {
    return false;
  }

  // Videos shorter than the maximum allowed keyframe distance can be optimized.
  base::TimeDelta duration = GetPipelineMediaDuration();
  if (duration < kMaxKeyframeDistanceToDisableBackgroundVideo) {
    return true;
  }

  // Otherwise, only optimize videos with shorter average keyframe distance.
  auto stats = GetPipelineStatistics();
  return stats.video_keyframe_distance_average <
         kMaxKeyframeDistanceToDisableBackgroundVideo;
}

void WebMediaPlayerImpl::UpdateBackgroundVideoOptimizationState() {
  if (IsPageHidden() ||
      (IsFrameHidden() && should_pause_when_frame_is_hidden_)) {
    if (ShouldPausePlaybackWhenHidden()) {
      update_background_status_cb_.Cancel();
      is_background_status_change_cancelled_ = true;
      PauseVideoIfNeeded();
    } else if (is_background_status_change_cancelled_) {
      // Only trigger updates when we don't have one already scheduled.
      update_background_status_cb_.Reset(
          base::BindOnce(&WebMediaPlayerImpl::DisableVideoTrackIfNeeded,
                         base::Unretained(this)));
      is_background_status_change_cancelled_ = false;

      // Defer disable track until we're sure the clip will be backgrounded for
      // some time. Resuming may take half a second, so frequent tab switches
      // will yield a poor user experience otherwise. http://crbug.com/709302
      // may also cause AV sync issues if disable/enable happens too fast.
      main_task_runner_->PostDelayedTask(
          FROM_HERE, update_background_status_cb_.callback(),
          base::Seconds(10));
    }
  } else {
    update_background_status_cb_.Cancel();
    is_background_status_change_cancelled_ = true;
    // There no visibility-related reason to pause the video.
    visibility_pause_reason_.reset();

    EnableVideoTrackIfNeeded();
  }
}

void WebMediaPlayerImpl::PauseVideoIfNeeded() {
  DCHECK(IsPageHidden() || IsFrameHidden());

  // Don't pause video while the pipeline is stopped, resuming or seeking.
  // Also if the video is paused already.
  if (!pipeline_controller_->IsPipelineRunning() || is_pipeline_resuming_ ||
      seeking_ || paused_)
    return;

  auto pause_reason = MediaPlayerClient::PauseReason::kPageHidden;
  if (IsFrameHidden() && should_pause_when_frame_is_hidden_) {
    pause_reason = MediaPlayerClient::PauseReason::kFrameHidden;
  }

  // client_->PausePlayback() will get `visibility_pause_reason_` set to
  // std::nullopt and UpdatePlayState() called, so set
  // `visibility_pause_reason_` to the correct value after and then return.
  // TODO(crbug.com/351354996): To avoid resetting `visibility_pause_reason_`,
  // we should plumb the pause reason from here all the way through to
  // `WebMediaPlayerImpl::Pause`, where the reset is done.
  client_->PausePlayback(pause_reason);
  visibility_pause_reason_ = pause_reason;
}

void WebMediaPlayerImpl::EnableVideoTrackIfNeeded() {
  // Don't change video track while the pipeline is stopped, resuming or
  // seeking.
  if (!pipeline_controller_->IsPipelineRunning() || is_pipeline_resuming_ ||
      seeking_)
    return;

  if (video_track_disabled_) {
    video_track_disabled_ = false;
    if (client_->HasSelectedVideoTrack()) {
      SelectedVideoTrackChanged(client_->GetSelectedVideoTrackId());
    }
  }
}

void WebMediaPlayerImpl::DisableVideoTrackIfNeeded() {
  DCHECK(IsPageHidden() || IsFrameHidden());

  // Don't change video track while the pipeline is resuming or seeking.
  if (is_pipeline_resuming_ || seeking_)
    return;

  if (!video_track_disabled_ && ShouldDisableVideoWhenHidden()) {
    video_track_disabled_ = true;
    SelectedVideoTrackChanged(std::nullopt);
  }
}

void WebMediaPlayerImpl::SetPipelineStatisticsForTest(
    const media::PipelineStatistics& stats) {
  pipeline_statistics_for_test_ = std::make_optional(stats);
}

media::PipelineStatistics WebMediaPlayerImpl::GetPipelineStatistics() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  return pipeline_statistics_for_test_.value_or(
      pipeline_controller_->GetStatistics());
}

void WebMediaPlayerImpl::SetPipelineMediaDurationForTest(
    base::TimeDelta duration) {
  pipeline_media_duration_for_test_ = std::make_optional(duration);
}

base::TimeDelta WebMediaPlayerImpl::GetPipelineMediaDuration() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  return pipeline_media_duration_for_test_.value_or(
      pipeline_controller_->GetMediaDuration());
}

media::MediaContentType WebMediaPlayerImpl::GetMediaContentType() const {
  return media::DurationToMediaContentType(GetPipelineMediaDuration());
}

void WebMediaPlayerImpl::SwitchToRemoteRenderer(
    const std::string& remote_device_friendly_name) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  DCHECK(!is_remote_rendering_);
  is_remote_rendering_ = true;

  DCHECK(!disable_pipeline_auto_suspend_);
  disable_pipeline_auto_suspend_ = true;

  // Capabilities reporting should only be performed for local playbacks.
  video_decode_stats_reporter_.reset();

  // Requests to restart media pipeline. A remote renderer will be created via
  // the `renderer_factory_selector_`.
  ScheduleRestart();
  if (client_) {
    client_->MediaRemotingStarted(
        WebString::FromUTF8(remote_device_friendly_name));
  }
}

void WebMediaPlayerImpl::SwitchToLocalRenderer(
    media::MediaObserverClient::ReasonToSwitchToLocal reason) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  if (!is_remote_rendering_)
    return;  // Is currently with local renderer.
  is_remote_rendering_ = false;

  DCHECK(disable_pipeline_auto_suspend_);
  disable_pipeline_auto_suspend_ = false;

  // Capabilities reporting may resume now that playback is local.
  CreateVideoDecodeStatsReporter();

  // Requests to restart media pipeline. A local renderer will be created via
  // the `renderer_factory_selector_`.
  ScheduleRestart();
  if (client_)
    client_->MediaRemotingStopped(GetSwitchToLocalMessage(reason));
}

template <uint32_t Flags, typename... T>
void WebMediaPlayerImpl::WriteSplitHistogram(
    void (*UmaFunction)(const std::string&, T...),
    SplitHistogramName key,
    const T&... values) {
  std::string strkey = std::string(GetHistogramName(key));

  if constexpr (Flags & kEncrypted) {
    if (is_encrypted_)
      UmaFunction(strkey + ".EME", values...);
#if BUILDFLAG(IS_WIN)
    if (renderer_type_ == media::RendererType::kMediaFoundation) {
      UmaFunction(strkey + ".MediaFoundationRenderer", values...);
    }
#endif  // BUILDFLAG(IS_WIN)
  }

  if constexpr (Flags & kTotal)
    UmaFunction(strkey + ".All", values...);

  if constexpr (Flags & kPlaybackType) {
    auto demuxer_type = GetDemuxerType();
    if (!demuxer_type.has_value())
      return;
    switch (*demuxer_type) {
      case media::DemuxerType::kChunkDemuxer:
        UmaFunction(strkey + ".MSE", values...);
        break;
      case media::DemuxerType::kManifestDemuxer:
      case media::DemuxerType::kMediaUrlDemuxer:
        UmaFunction(strkey + ".HLS", values...);
        break;
      default:
        UmaFunction(strkey + ".SRC", values...);
        break;
    }
  }
}

void WebMediaPlayerImpl::RecordUnderflowDuration(base::TimeDelta duration) {
  DCHECK(demuxer_manager_->HasDataSource() ||
         GetDemuxerType() == media::DemuxerType::kChunkDemuxer ||
         GetDemuxerType() == media::DemuxerType::kManifestDemuxer);
  WriteSplitHistogram<kPlaybackType | kEncrypted>(
      &base::UmaHistogramTimes, SplitHistogramName::kUnderflowDuration2,
      duration);
}

void WebMediaPlayerImpl::RecordVideoNaturalSize(const gfx::Size& natural_size) {
  // Always report video natural size to MediaLog.
  media_log_->AddEvent<MediaLogEvent::kVideoSizeChanged>(natural_size);
  media_log_->SetProperty<MediaLogProperty::kResolution>(natural_size);

  if (initial_video_height_recorded_)
    return;

  initial_video_height_recorded_ = true;

  int height = natural_size.height();

  WriteSplitHistogram<kPlaybackType | kEncrypted | kTotal>(
      &base::UmaHistogramCustomCounts, SplitHistogramName::kVideoHeightInitial,
      height, 100, 10000, size_t{50});

  if (playback_events_recorder_)
    playback_events_recorder_->OnNaturalSizeChanged(natural_size);
}

void WebMediaPlayerImpl::SetTickClockForTest(
    const base::TickClock* tick_clock) {
  tick_clock_ = tick_clock;
  buffered_data_source_host_->SetTickClockForTest(tick_clock);
}

void WebMediaPlayerImpl::OnFirstFrame(base::TimeTicks frame_time,
                                      bool is_frame_readable) {
  DCHECK(!load_start_time_.is_null());
  DCHECK(!skip_metrics_due_to_startup_suspend_);

  has_first_frame_ = true;
  needs_first_frame_ = false;
  is_frame_readable_ = is_frame_readable;

  const base::TimeDelta elapsed = frame_time - load_start_time_;
  media_metrics_provider_->SetTimeToFirstFrame(elapsed);
  WriteSplitHistogram<kPlaybackType | kEncrypted>(
      &base::UmaHistogramMediumTimes, SplitHistogramName::kTimeToFirstFrame,
      elapsed);

  media::PipelineStatistics ps = GetPipelineStatistics();
  if (client_) {
    client_->OnFirstFrame(frame_time, ps.video_bytes_decoded);

    // Needed to signal HTMLVideoElement that it should remove the poster image.
    if (has_poster_) {
      client_->Repaint();
    }
  }
}

void WebMediaPlayerImpl::RecordEncryptionScheme(
    const std::string& stream_name,
    media::EncryptionScheme encryption_scheme) {
  DCHECK(stream_name == "Audio" || stream_name == "Video");

  // If the stream is not encrypted, don't record it.
  if (encryption_scheme == media::EncryptionScheme::kUnencrypted)
    return;

  base::UmaHistogramEnumeration(
      "Media.EME.EncryptionScheme.Initial." + stream_name,
      DetermineEncryptionSchemeUMAValue(encryption_scheme),
      EncryptionSchemeUMA::kCount);
}

bool WebMediaPlayerImpl::IsInPictureInPicture() const {
  DCHECK(client_);
  return client_->GetDisplayType() == DisplayType::kPictureInPicture;
}

void WebMediaPlayerImpl::MaybeSetContainerNameForMetrics() {
  // Pipeline startup failed before even getting a demuxer setup.
  if (!demuxer_manager_->HasDemuxer()) {
    return;
  }

  // Container has already been set.
  if (highest_ready_state_ >= WebMediaPlayer::kReadyStateHaveMetadata)
    return;

  // Only report metrics for demuxers that provide container information.
  auto container = demuxer_manager_->GetContainerForMetrics();
  if (container.has_value())
    media_metrics_provider_->SetContainerName(container.value());
}

void WebMediaPlayerImpl::MaybeUpdateBufferSizesForPlayback() {
  // Don't increase the MultiBufferDataSource buffer size until we've reached
  // kReadyStateHaveEnoughData. Otherwise we will unnecessarily slow down
  // playback startup -- it can instead be done for free after playback starts.
  if (highest_ready_state_ < kReadyStateHaveEnoughData) {
    return;
  }

  demuxer_manager_->OnDataSourcePlaybackRateChange(playback_rate_, paused_);
}

void WebMediaPlayerImpl::OnSimpleWatchTimerTick() {
  if (playback_events_recorder_)
    playback_events_recorder_->OnPipelineStatistics(GetPipelineStatistics());
}

GURL WebMediaPlayerImpl::GetSrcAfterRedirects() {
  return demuxer_manager_->GetDataSourceUrlAfterRedirects().value_or(GURL());
}

void WebMediaPlayerImpl::UpdateSmoothnessHelper() {
  // If the experiment flag is off, then do nothing.
  if (!base::FeatureList::IsEnabled(media::kMediaLearningSmoothnessExperiment))
    return;

  // If we're paused, or if we can't get all the features, then clear any
  // smoothness helper and stop.  We'll try to create it later when we're
  // playing and have all the features.
  if (paused_ || !HasVideo() || pipeline_metadata_.natural_size.IsEmpty() ||
      !last_reported_fps_) {
    smoothness_helper_.reset();
    return;
  }

  // Fill in features.
  // NOTE: this is a very bad way to do this, since it memorizes the order of
  // features in the task.  However, it'll do for now.
  learning::FeatureVector features;
  features.push_back(learning::FeatureValue(
      static_cast<int>(pipeline_metadata_.video_decoder_config.codec())));
  features.push_back(learning::FeatureValue(
      pipeline_metadata_.video_decoder_config.profile()));
  features.push_back(
      learning::FeatureValue(pipeline_metadata_.natural_size.width()));
  features.push_back(learning::FeatureValue(*last_reported_fps_));

  // If we have a smoothness helper, and we're not changing the features, then
  // do nothing.  This prevents restarting the helper for no reason.
  if (smoothness_helper_ && features == smoothness_helper_->features())
    return;

  // Create or restart the smoothness helper with `features`.
  smoothness_helper_ = SmoothnessHelper::Create(
      GetLearningTaskController(learning::tasknames::kConsecutiveBadWindows),
      GetLearningTaskController(learning::tasknames::kConsecutiveNNRs),
      features, this);
}

std::unique_ptr<learning::LearningTaskController>
WebMediaPlayerImpl::GetLearningTaskController(const char* task_name) {
  // Get the LearningTaskController for `task_id`.
  learning::LearningTask task = learning::MediaLearningTasks::Get(task_name);
  DCHECK_EQ(task.name, task_name);

  mojo::Remote<learning::mojom::LearningTaskController> remote_ltc;
  media_metrics_provider_->AcquireLearningTaskController(
      task.name, remote_ltc.BindNewPipeAndPassReceiver());
  return std::make_unique<learning::MojoLearningTaskController>(
      task, std::move(remote_ltc));
}

bool WebMediaPlayerImpl::HasUnmutedAudio() const {
  // Pretend that the media has no audio if it never played unmuted. This is to
  // avoid any action related to audible media such as taking audio focus or
  // showing a media notification. To preserve a consistent experience, it does
  // not apply if a media was audible so the system states do not flicker
  // depending on whether the user muted the player.
  return HasAudio() && !client_->WasAlwaysMuted();
}

bool WebMediaPlayerImpl::IsVideoBeingCaptured() const {
  // 5 seconds chosen arbitrarily since most videos are never captured.
  return tick_clock_->NowTicks() - last_frame_request_time_ < base::Seconds(5);
}

void WebMediaPlayerImpl::RegisterFrameSinkHierarchy() {
  if (bridge_)
    bridge_->RegisterFrameSinkHierarchy();
}

void WebMediaPlayerImpl::UnregisterFrameSinkHierarchy() {
  if (bridge_)
    bridge_->UnregisterFrameSinkHierarchy();
}

void WebMediaPlayerImpl::RecordVideoOcclusionState(
    std::string_view occlusion_state) {
  media_log_->AddEvent<MediaLogEvent::kVideoOcclusionState>(
      std::string(occlusion_state));
}

void WebMediaPlayerImpl::ReportSessionUMAs() const {
  if (renderer_type_ != media::RendererType::kRendererImpl &&
      renderer_type_ != media::RendererType::kMediaFoundation) {
    return;
  }

  // Report the `Media.DroppedFrameCount2.{RendererType}.{EncryptedOrClear}`
  // UMA.
  constexpr char kDroppedFrameUmaPrefix[] = "Media.DroppedFrameCount2.";
  std::string uma_name = kDroppedFrameUmaPrefix;
  uma_name += GetRendererName(renderer_type_);
  if (is_encrypted_)
    uma_name += ".Encrypted";
  else
    uma_name += ".Clear";
  base::UmaHistogramCounts1M(uma_name, DroppedFrameCount());

  if (!is_encrypted_) {
    // Report the `Media.FrameReadBackCount.{RendererType}` UMA.
    constexpr char kFrameReadBackUmaPrefix[] = "Media.FrameReadBackCount.";
    uma_name = kFrameReadBackUmaPrefix;
    uma_name += GetRendererName(renderer_type_);
    base::UmaHistogramCounts10M(uma_name, video_frame_readback_count_);
  }

  if (cdm_config_) {
    // Report the `Media.EME.{KeySystem}.{Robustness}.WaitingForKey` UMA.
    auto key_system_name_for_uma = media::GetKeySystemNameForUMA(
        cdm_config_->key_system, cdm_config_->use_hw_secure_codecs);
    uma_name = "Media.EME." + key_system_name_for_uma + ".WaitingForKey";
    base::UmaHistogramBoolean(uma_name, has_waiting_for_key_);
  }
}

bool WebMediaPlayerImpl::PassedTimingAllowOriginCheck() const {
  return demuxer_manager_->PassedDataSourceTimingAllowOriginCheck();
}

void WebMediaPlayerImpl::DidMediaMetadataChange() {
  media::MediaContentType content_type = GetMediaContentType();
  bool is_encrypted_media =
      pipeline_metadata_.audio_decoder_config.is_encrypted() ||
      pipeline_metadata_.video_decoder_config.is_encrypted();

  client_->DidMediaMetadataChange(
      delegate_has_audio_, HasVideo(),
      pipeline_metadata_.audio_decoder_config.codec(),
      pipeline_metadata_.video_decoder_config.codec(), content_type,
      is_encrypted_media);

  delegate_->DidMediaMetadataChange(delegate_id_, delegate_has_audio_,
                                    HasVideo(), content_type);
}

}  // namespace blink
```