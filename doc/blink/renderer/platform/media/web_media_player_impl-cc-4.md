Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_media_player_impl.cc`. The summary should cover:
1. **General functionalities:** What does this code do?
2. **Relationship with web technologies (JavaScript, HTML, CSS):** How does this code interact with these technologies? Provide examples.
3. **Logical reasoning:**  If the code performs any logical deductions, provide hypothetical inputs and outputs.
4. **Common usage errors:** Identify potential mistakes users or programmers might make.
5. **Overall function:** A concise summary of the code's purpose as the fifth and final part of the original file.

Let's break down the code section by section:

- **Memory Usage Tracking:** The code includes methods like `UpdateMemoryUsage` and `OnMainThreadMemoryDump`, suggesting it tracks and reports memory consumption of the media player.
- **Idle Pause Timer:** `ScheduleIdlePauseTimer` indicates a mechanism to pause playback when the player is idle in the background.
- **Watch Time Reporter:**  `CreateWatchTimeReporter` and related methods point to a feature that likely tracks and reports media playback time and related properties.
- **Visibility Handling:** Methods like `IsPageHidden`, `IsFrameHidden`, `PauseVideoIfNeeded`, and `DisableVideoTrackIfNeeded` suggest the code manages playback behavior based on the visibility of the page or frame.
- **Remote Rendering:**  `SwitchToRemoteRenderer` and `SwitchToLocalRenderer` indicate support for transferring media playback to a remote device.
- **Metrics Reporting:**  Various `UmaHistogram` calls and methods like `RecordUnderflowDuration` and `RecordVideoNaturalSize` show that the code collects and reports media playback statistics.
- **First Frame Handling:** `OnFirstFrame` suggests logic to handle the rendering of the initial video frame.
- **Background Video Optimization:** `UpdateBackgroundVideoOptimizationState`, `ShouldPausePlaybackWhenHidden`, and `ShouldDisableVideoWhenHidden` point to features designed to optimize resource usage when the video is playing in the background.
- **Video Frame Callbacks:** `RequestVideoFrameCallback` and `OnNewFramePresentedCallback` suggest mechanisms for synchronizing with the rendering pipeline.
- **Learning/Smoothness Helper:** `UpdateSmoothnessHelper` and `GetLearningTaskController` hint at integration with a machine learning system to potentially improve playback smoothness.
- **Video Capture Detection:** `IsVideoBeingCaptured` suggests a way to detect if the video output is being captured.
- **Frame Sink Management:** `RegisterFrameSinkHierarchy` and `UnregisterFrameSinkHierarchy` likely manage the connection of the video output to the rendering pipeline.
- **Media Metadata Handling:** `DidMediaMetadataChange` indicates handling changes in media information like audio/video presence and codecs.

Now, let's consider the interactions with web technologies:

- **JavaScript:** JavaScript controls the `<video>` or `<audio>` elements, triggering playback, pausing, seeking, and setting properties. This C++ code implements the underlying media playback logic. For example, a JavaScript `play()` call would eventually lead to this C++ code starting the media pipeline.
- **HTML:** The `<video>` and `<audio>` tags in HTML embed media content. This C++ code handles the rendering and playback of that content.
- **CSS:** CSS styles the media elements. While this C++ code doesn't directly interact with styling, it might provide information (like video dimensions) that affects how the browser renders the styled element.

For logical reasoning, let's consider the background pause timer:

**Hypothetical Input:**
- Player is playing.
- Page is hidden.
- Player has audio.

**Expected Output:**
- After 5 seconds of the page being hidden and the player being idle, the player will be paused with `PauseReason::kSuspendedPlayerIdleTimeout`.

Regarding common usage errors:

- **Not handling visibility changes:** If a web developer doesn't properly handle visibility changes (e.g., using the Page Visibility API), the media might continue playing in the background unintentionally, consuming resources.
- **Assuming immediate playback start:** Developers might assume that calling `play()` in JavaScript will start playback immediately. However, this C++ code handles asynchronous operations like buffering and decoding, so there might be a delay.

Finally, for the overall function, this code snippet focuses on memory management, background optimization, and metrics reporting within the larger context of the `WebMediaPlayerImpl`. It handles scenarios like page visibility changes, remote rendering, and integrates with a learning system.
This部分代码主要负责 **WebMediaPlayerImpl** 实例的资源管理、后台优化、以及与性能监控和外部系统的交互。以下是更详细的列表：

**主要功能:**

1. **内存使用跟踪与报告:**
    - `UpdateMemoryUsage`: 更新媒体播放器及其相关组件（如 Demuxer）的内存使用情况。
    - `OnMainThreadMemoryDump`, `OnMediaThreadMemoryDump`: 在内存转储时提供详细的内存使用信息，用于性能分析和调试。

2. **后台播放优化:**
    - `ScheduleIdlePauseTimer`: 当播放器在后台闲置一段时间后，自动暂停播放以节省资源。
    - `ShouldPausePlaybackWhenHidden`, `ShouldDisableVideoWhenHidden`:  根据页面或帧的可见性，以及用户设置和平台特性，决定是否暂停播放或禁用视频轨道以优化后台资源使用。
    - `UpdateBackgroundVideoOptimizationState`:  根据页面或帧的可见性状态，动态调整播放器的后台优化策略。
    - `PauseVideoIfNeeded`, `EnableVideoTrackIfNeeded`, `DisableVideoTrackIfNeeded`:  根据后台优化策略，实际执行暂停播放或启用/禁用视频轨道的操作。

3. **性能监控与指标记录:**
    - 通过 `base::trace_event::MemoryDumpArgs` 和 `base::trace_event::ProcessMemoryDump` 参与内存转储，提供内存使用信息。
    - 使用 UMA 宏 (`base::UmaHistogramTimes`, `base::UmaHistogramCustomCounts`, `base::UmaHistogramEnumeration`, `base::UmaHistogramBoolean`, `base::UmaHistogramCounts1M`, `base::UmaHistogramCounts10M`) 记录各种性能指标，例如首次渲染时间、播放时长、丢帧数、加密方案等。
    - `RecordUnderflowDuration`: 记录播放过程中发生缓冲不足的时间。
    - `RecordVideoNaturalSize`: 记录视频的原始尺寸。
    - `OnFirstFrame`: 记录并上报首次渲染帧的时间。
    - `ReportSessionUMAs`: 报告会话级别的 UMA 指标，例如丢帧数和是否等待密钥。

4. **与 WatchTimeReporter 的集成:**
    - `CreateWatchTimeReporter`: 创建 `WatchTimeReporter` 实例，用于更精细地跟踪用户观看时间和相关的播放属性。
    - `UpdateSecondaryProperties`: 更新 `WatchTimeReporter` 的次要播放属性，如编解码器信息。

5. **远程渲染支持:**
    - `SwitchToRemoteRenderer`, `SwitchToLocalRenderer`:  支持将媒体渲染切换到远程设备或本地，并更新相应的状态和指标。

6. **视频帧处理:**
    - `RequestVideoFrameCallback`: 请求一个视频帧回调。
    - `OnNewFramePresentedCallback`:  当新帧呈现时执行回调，通知客户端。
    - `GetVideoFramePresentationMetadata`: 获取最近呈现的视频帧的元数据。
    - `UpdateFrameIfStale`: 如果视频帧过时，则请求更新。

7. **与学习系统的集成 (SmoothnessHelper):**
    - `UpdateSmoothnessHelper`:  根据播放状态和视频属性，创建或更新 `SmoothnessHelper` 实例，用于收集数据以提升播放流畅度。
    - `GetLearningTaskController`: 获取用于特定学习任务的控制器。

8. **可见性管理:**
    - `IsPageHidden`, `IsFrameHidden`, `IsPausedBecausePageHidden`, `IsPausedBecauseFrameHidden`:  判断页面或帧是否隐藏，以及是否因为隐藏而暂停。
    - `OnBecameVisible`: 当页面或帧变为可见时执行操作。

9. **其他辅助功能:**
    - `GetPipelineStatistics`: 获取底层媒体管道的统计信息。
    - `GetPipelineMediaDuration`: 获取媒体的持续时间。
    - `GetMediaContentType`: 获取媒体内容类型。
    - `SetTickClockForTest`:  为测试设置时钟。
    - `MaybeSetContainerNameForMetrics`:  为性能指标设置容器名称。
    - `MaybeUpdateBufferSizesForPlayback`:  根据播放状态调整缓冲区大小。
    - `OnSimpleWatchTimerTick`:  定时触发事件，用于记录播放统计信息。
    - `GetSrcAfterRedirects`: 获取重定向后的资源 URL。
    - `HasUnmutedAudio`: 判断是否有未静音的音频。
    - `IsVideoBeingCaptured`: 判断视频是否正在被捕获。
    - `RegisterFrameSinkHierarchy`, `UnregisterFrameSinkHierarchy`: 注册和取消注册帧接收器层级结构。
    - `RecordVideoOcclusionState`: 记录视频遮挡状态。
    - `PassedTimingAllowOriginCheck`:  判断是否通过了 CORS 的 Timing-Allow-Origin 检查。
    - `DidMediaMetadataChange`:  当媒体元数据发生变化时通知客户端和委托。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

- **JavaScript:**
    - 当 JavaScript 调用 `video.play()` 或 `audio.play()` 时，最终会触发 `WebMediaPlayerImpl` 中的相应逻辑开始媒体管道的启动和播放。
    - JavaScript 可以通过监听事件（如 `timeupdate`, `ended`, `error`）获取媒体播放状态，这些状态的更新可能由 `WebMediaPlayerImpl` 中的逻辑触发。
    - **举例:** 当 JavaScript 调用 `video.pause()` 并且页面被隐藏时，`WebMediaPlayerImpl` 中的 `ShouldPausePlaybackWhenHidden` 和 `PauseVideoIfNeeded` 方法会被调用，最终暂停底层媒体管道。

- **HTML:**
    - `<video>` 和 `<audio>` 元素在 HTML 中定义了媒体播放器。`WebMediaPlayerImpl` 是这些元素的底层实现，负责处理媒体的加载、解码、渲染等。
    - **举例:** `<video>` 标签的 `src` 属性指定了媒体资源的 URL。`WebMediaPlayerImpl` 会通过 `DemuxerManager` 加载该资源。

- **CSS:**
    - CSS 用于控制媒体播放器的样式和布局。虽然 `WebMediaPlayerImpl` 不直接操作 CSS，但它提供的视频尺寸等信息会影响浏览器的渲染。
    - **举例:** CSS 可以设置 `<video>` 元素的宽度和高度，`WebMediaPlayerImpl` 中的 `RecordVideoNaturalSize` 记录的原始尺寸可能会影响浏览器如何缩放视频。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. **场景:** 用户最小化浏览器窗口（页面变为隐藏），并且正在播放一个有音频的视频。`is_background_video_playback_enabled_` 为 false。
2. **方法调用:** `WebMediaPlayerImpl::UpdateBackgroundVideoOptimizationState()` 被调用。

**逻辑推理:**

- `IsPageHidden()` 返回 true。
- `ShouldPausePlaybackWhenHidden()` 将返回 true，因为 `is_background_video_playback_enabled_` 为 false 并且有音频。

**预期输出:**

- `PauseVideoIfNeeded()` 被调用，导致媒体播放暂停。
- `visibility_pause_reason_` 被设置为 `MediaPlayerClient::PauseReason::kPageHidden`。

**用户或编程常见的使用错误举例:**

1. **未处理页面可见性变化:** 开发者可能没有使用 Page Visibility API 监听页面的可见性变化，导致在页面隐藏时，媒体仍然继续播放，浪费用户资源。`WebMediaPlayerImpl` 提供了后台优化的机制，但需要上层正确触发。

2. **假设播放立即开始:** 开发者可能会假设调用 `play()` 后媒体会立即开始播放，而没有考虑到缓冲和解码的时间。这可能导致 UI 上的状态显示不正确。`WebMediaPlayerImpl` 的异步特性需要开发者注意。

3. **不理解后台播放限制:** 开发者可能不了解浏览器对后台播放的限制，例如某些浏览器可能不允许在后台播放有视频的媒体。`WebMediaPlayerImpl` 会根据平台特性进行优化，但开发者也需要了解这些限制。

**归纳其功能 (作为第5部分):**

总而言之，这部分 `WebMediaPlayerImpl` 的代码专注于媒体播放器的精细化管理，尤其是在资源优化和性能监控方面。它通过跟踪内存使用、根据页面可见性动态调整播放行为、记录详细的性能指标，以及与外部系统（如 WatchTimeReporter 和学习系统）集成，来提升媒体播放的效率和用户体验。同时，它也考虑了远程渲染等特殊场景，并为上层（JavaScript, HTML）提供了可靠的媒体播放基础。

### 提示词
```
这是目录为blink/renderer/platform/media/web_media_player_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
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