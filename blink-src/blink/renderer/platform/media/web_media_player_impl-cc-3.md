Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the provided code snippet's functionality within the larger context of `web_media_player_impl.cc`. It specifically requests examples relating to JavaScript, HTML, CSS, logical inferences, and common user/programming errors. It's the 4th of 5 parts, implying I should focus on the functionalities present in this specific chunk.

2. **Initial Code Scan and Keyword Identification:** I'll quickly read through the code, noting the key function names and the actions they perform. Keywords like `Hidden`, `SuspendForFrameClosed`, `OnPageShown`, `OnIdleTimeout`, `OnFrameShown`, `OnFrameHidden`, `SetVolumeMultiplier`, `SetPersistentState`, `ScheduleRestart`, `RequestRemotePlaybackDisabled`, `RequestMediaRemoting`, `FlingingStarted`, `FlingingStopped`, `OnRemotePlayStateChange`, `SetPoster`, `MemoryDataSourceInitialized`, `DataSourceInitialized`, `MultiBufferDataSourceInitialized`, `OnDataSourceRedirected`, `NotifyDownloading`, `OnOverlayRoutingToken`, `OnOverlayInfoRequested`, `MaybeSendOverlayInfoToDecoder`, `CreateRenderer`, `GetDemuxerType`, `OnDemuxerCreated`, `StartPipeline`, `SetNetworkState`, `SetReadyState`, `GetAudioSourceProvider`, `GetCurrentFrameFromCompositor`, `UpdatePlayState`, `OnTimeUpdate`, `SetDelegateState`, `SetMemoryReportingState`, `SetSuspendState`, `UpdatePlayState_ComputePlayState`, `MakeDemuxerThreadDumper`, `CouldPlayIfEnoughData`, `IsMediaPlayerRendererClient`, `ReportMemoryUsage`, and `FinishMemoryUsageReport` stand out.

3. **Categorize Functionality:**  I'll group the functions based on the high-level actions they represent. This helps in organizing the response. My categories will likely include:
    * **Visibility/Lifecycle Management:**  `Hidden`, `SuspendForFrameClosed`, `OnPageShown`, `OnFrameShown`, `OnFrameHidden`, `OnIdleTimeout`. These relate to the player's behavior when the page or frame visibility changes.
    * **Playback Control and State:** `SetVolumeMultiplier`, `SetPersistentState`, `ScheduleRestart`, `UpdatePlayState`, `SetSuspendState`,  `UpdatePlayState_ComputePlayState`. These manage the playback itself.
    * **Remote Playback:** `RequestRemotePlaybackDisabled`, `RequestMediaRemoting`, `FlingingStarted`, `FlingingStopped`, `OnRemotePlayStateChange`. These deal with casting/remote playback features.
    * **Data Loading and Initialization:** `SetPoster`, `MemoryDataSourceInitialized`, `DataSourceInitialized`, `MultiBufferDataSourceInitialized`, `OnDataSourceRedirected`, `StartPipeline`, `OnDemuxerCreated`. These relate to the process of getting the media data.
    * **Buffering and Downloading:** `NotifyDownloading`. This relates to tracking the download progress.
    * **Overlay Management:** `OnOverlayRoutingToken`, `OnOverlayInfoRequested`, `MaybeSendOverlayInfoToDecoder`. This focuses on handling video overlays, especially on Android.
    * **Renderer Management:** `CreateRenderer`, `GetDemuxerType`, `IsMediaPlayerRendererClient`. These are about the video rendering pipeline.
    * **State Updates and Notifications:** `SetNetworkState`, `SetReadyState`, `OnTimeUpdate`, `SetDelegateState`. These are about informing the client about changes.
    * **Audio Management:** `GetAudioSourceProvider`.
    * **Frame Handling:** `GetCurrentFrameFromCompositor`.
    * **Memory Management/Reporting:** `SetMemoryReportingState`, `ReportMemoryUsage`, `FinishMemoryUsageReport`, `MakeDemuxerThreadDumper`.
    * **Utility/Helper:** `CouldPlayIfEnoughData`.

4. **Address Specific Requirements:** Now, I'll go through each category and explicitly address the requirements from the prompt:

    * **JavaScript/HTML/CSS Relationship:** I'll consider how each function might be triggered or interact with front-end code. For instance, visibility changes (`Hidden`, `OnPageShown`) are often a result of browser events handled by JavaScript. Setting the poster is directly related to the HTML `<video>` tag's `poster` attribute. Volume and playback rate are controlled by JavaScript APIs. Fullscreen transitions relate to CSS.

    * **Logical Inferences (Assumptions, Inputs, Outputs):** For functions involving decision-making (like `UpdatePlayState_ComputePlayState`), I'll try to create simplified scenarios with hypothetical inputs (e.g., is the video paused, is the page hidden?) and predict the output (e.g., should the video be suspended?).

    * **User/Programming Errors:** I'll think about common mistakes developers might make or issues users might encounter. For example, failing to handle visibility changes correctly can lead to unexpected autoplay behavior. Not setting the correct CORS headers can cause data loading errors. Incorrectly managing overlay states can lead to display issues.

5. **Synthesize the Summary:**  Based on the categorized functionality, I'll write a concise summary of the code's purpose within `web_media_player_impl.cc`. I'll highlight the key responsibilities, such as managing the media playback lifecycle, interacting with the rendering pipeline, handling visibility changes, and reporting state.

6. **Review and Refine:** I'll reread my response to ensure it's accurate, addresses all parts of the prompt, and is well-organized and easy to understand. I'll check for clarity and conciseness. Since it's part 4 of 5, I'll keep the summary focused on the functions in *this specific snippet*, without trying to encompass the entire file's functionality.

**(Self-Correction Example during the process):** Initially, I might broadly categorize everything as "media playback."  However, realizing the request asks for specific relationships (JavaScript, etc.), I would refine my categories to be more granular, like "Visibility/Lifecycle Management" or "Data Loading," which allows for more targeted examples. Similarly, when considering logical inferences, I need to make sure my hypothetical inputs and outputs are clearly defined and directly related to the function's logic. I avoid making overly complex scenarios and stick to the core functionality illustrated by the code.
这是 `blink/renderer/platform/media/web_media_player_impl.cc` 文件的一部分，主要负责实现 Web 媒体播放器的核心逻辑，特别是与播放状态、页面可见性、资源加载、渲染器和解码器交互相关的部分。

**功能归纳:**

这部分代码主要关注以下几个核心功能：

1. **页面和帧可见性管理:**
   - **暂停和恢复播放:** 根据页面或帧的隐藏和显示状态，暂停或恢复视频播放。在页面隐藏时，视频可能需要用户手势才能恢复播放。
   - **后台暂停优化:**  当页面隐藏时，会启动一个定时器，如果在一定时间内用户没有返回，则会暂停播放，避免意外的自动播放。
   - **通知渲染器可见性:**  通知合成器（compositor）页面或帧的可见状态。

2. **播放状态管理:**
   - **更新播放状态:** `UpdatePlayState()` 函数是核心，根据多种因素（例如是否正在缓冲、是否暂停、页面是否隐藏、是否在画中画等）计算并更新播放器的状态。
   - **委托状态管理:**  通知委托对象（`delegate_`）播放器的播放、暂停、结束等状态变化。
   - **内存报告状态管理:**  控制是否定期报告媒体播放器的内存使用情况。
   - **挂起状态管理:**  控制媒体管道的挂起和恢复。

3. **资源加载和初始化:**
   - **数据源初始化:**  处理数据源初始化成功或失败的情况，并根据结果启动媒体管道。
   - **网络状态管理:**  设置和更新媒体的网络状态（例如加载中、空闲、错误等）。
   - **就绪状态管理:**  设置和更新媒体的就绪状态（例如是否有足够的数据播放）。

4. **渲染器和解码器交互:**
   - **创建渲染器:** `CreateRenderer()` 函数负责创建具体的渲染器对象。
   - **Overlay 信息管理:** 处理 Android Overlay 相关的请求和信息传递，用于将视频渲染到独立的 Surface 上。
   - **Demuxer 创建和管理:** 处理 Demuxer 对象的创建和初始化。

5. **远程播放支持 (Android):**
   - **启动和停止 Flinging:** 处理 Android 平台上的 Flinging (投屏) 功能的启动和停止。
   - **处理远程播放状态变化:** 接收并处理远程播放设备的状态变化。

6. **其他功能:**
   - **设置音量倍增器:** 调整音量大小。
   - **设置持久状态:**  设置视频是否为持久状态。
   - **设置海报图:**  设置视频的封面图。
   - **处理重定向:**  当数据源发生重定向时进行处理。
   - **通知下载状态:**  通知是否正在下载媒体数据。
   - **时间更新:**  定期更新播放时间并通知客户端。
   - **内存使用报告:**  定期收集并报告媒体播放器的内存使用情况。

**与 JavaScript, HTML, CSS 的关系 (举例说明):**

* **JavaScript:**
    * **页面可见性事件触发:** 当 JavaScript 代码检测到页面隐藏或显示事件 (例如 `visibilitychange`) 时，会调用 `WebMediaPlayerImpl` 相应的 `Hidden()` 或 `OnPageShown()` 方法。
        * **假设输入:** 用户切换了浏览器标签页。
        * **输出:** `Hidden()` 方法被调用，视频暂停播放 (可能需要用户手势才能恢复)，并可能启动后台暂停定时器。
    * **控制播放状态:** JavaScript 可以调用 `play()` 和 `pause()` 方法，最终会触发 `WebMediaPlayerImpl` 的相关逻辑，例如更新 `paused_` 标志位，并调用 `UpdatePlayState()`。
        * **假设输入:** JavaScript 调用 `videoElement.pause()`.
        * **输出:** `paused_` 标志位被设置为 `true`，`UpdatePlayState()` 被调用，最终可能导致媒体管道暂停。
    * **设置音量:** JavaScript 可以设置 `videoElement.volume` 属性，最终会调用 `WebMediaPlayerImpl::SetVolumeMultiplier()` 或相关方法。
        * **假设输入:** JavaScript 设置 `videoElement.volume = 0.5;`.
        * **输出:** `WebMediaPlayerImpl::SetVolumeMultiplier(0.5)` 被调用，调整音频输出音量。
    * **处理远程播放:**  JavaScript 可以调用相关的 Web 平台 API (例如 Remote Playback API) 来请求远程播放，这会触发 `WebMediaPlayerImpl::RequestMediaRemoting()` 等方法。
        * **假设输入:** JavaScript 调用 `navigator.presentation.requestSession()`.
        * **输出:** `WebMediaPlayerImpl::RequestMediaRemoting()` 被调用，触发相应的远程播放逻辑。

* **HTML:**
    * **`<video>` 标签属性:**  HTML 的 `<video>` 标签的 `poster` 属性会影响 `WebMediaPlayerImpl::SetPoster()` 的调用。
        * **假设输入:** HTML 中有 `<video src="myvideo.mp4" poster="cover.jpg"></video>`.
        * **输出:**  `WebMediaPlayerImpl::SetPoster()` 会被调用，设置视频的封面图。
    * **`<video>` 标签事件:** `<video>` 标签触发的事件 (例如 `play`, `pause`, `ended`, `timeupdate`) 会由 Blink 引擎捕获并传递给 `WebMediaPlayerImpl` 进行处理。

* **CSS:**
    * **全屏显示:**  CSS 的全屏 API  (例如 `:fullscreen` 伪类)  可能会影响 overlay 相关的逻辑，例如是否启用 Android Overlay。
        * **假设输入:** 用户点击全屏按钮，视频进入全屏模式。
        * **输出:**  可能影响 `overlay_info_.is_fullscreen` 的值，并可能触发 overlay 状态的更新。

**逻辑推理 (假设输入与输出):**

* **`UpdatePlayState_ComputePlayState()`:**
    * **假设输入:** `is_flinging = false`, `can_auto_suspend = true`, `is_suspended = false`, `is_backgrounded = true`, `is_in_picture_in_picture = false`, `paused_ = true`, `highest_ready_state_ = kReadyStateHaveFutureData`, `delegate_->IsStale(delegate_id_) = true`.
    * **输出:** `result.is_suspended = true` (因为 idle_suspended 为 true，并且后台暂停也可能被触发), `result.delegate_state = DelegateState::PAUSED`, `result.is_idle = true`. 此场景表示视频在后台，已暂停，且被认为是 "stale" 的，因此应该被挂起，并且委托状态为暂停和空闲。

**用户或编程常见的使用错误 (举例说明):**

* **未处理页面可见性变化:**  开发者可能没有正确监听页面的 `visibilitychange` 事件，导致在页面隐藏时视频仍在后台播放，消耗用户资源和电量。
* **在后台自动播放视频:**  浏览器通常会阻止在后台自动播放视频，除非用户有交互行为。开发者如果尝试在没有用户交互的情况下在页面加载时播放视频，可能会失败。
* **Overlay 使用不当 (Android):** 在 Android 平台上，如果 overlay 的使用方式不当 (例如，在不支持 overlay 的设备上强制使用)，可能会导致视频显示异常或崩溃。
* **没有正确处理播放器的生命周期:**  开发者可能在页面卸载时没有正确释放媒体播放器资源，导致内存泄漏或其他问题。
* **假设网络总是良好:**  开发者可能没有充分考虑网络不佳的情况，导致播放卡顿或错误。需要处理各种网络状态，并为用户提供反馈。

**总结:**

这部分代码是 `WebMediaPlayerImpl` 中处理媒体播放器核心状态和行为的关键部分。它负责响应页面和帧的可见性变化，管理播放状态，处理资源加载，并与渲染器和解码器进行交互。理解这部分代码的功能有助于理解 Chromium 中媒体播放器的工作原理。

Prompt: 
```
这是目录为blink/renderer/platform/media/web_media_player_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
Hidden() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // Backgrounding a video requires a user gesture to resume playback.
  if (IsPageHidden()) {
    video_locked_when_paused_when_hidden_ = true;
  }

  if (watch_time_reporter_)
    watch_time_reporter_->OnHidden();

  if (video_decode_stats_reporter_)
    video_decode_stats_reporter_->OnHidden();

  UpdateBackgroundVideoOptimizationState();
  UpdatePlayState();

  // Schedule suspended playing media to be paused if the user doesn't come back
  // to it within some timeout period to avoid any autoplay surprises.
  ScheduleIdlePauseTimer();

  // Notify the compositor of our page visibility status.
  vfc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&VideoFrameCompositor::SetIsPageVisible,
                     base::Unretained(compositor_.get()), !IsPageHidden()));
}

void WebMediaPlayerImpl::SuspendForFrameClosed() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  was_suspended_for_frame_closed_ = true;
  UpdateBackgroundVideoOptimizationState();
  UpdatePlayState();
}

void WebMediaPlayerImpl::OnPageShown() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  background_pause_timer_.Stop();

  // Foreground videos don't require user gesture to continue playback.
  video_locked_when_paused_when_hidden_ = false;

  was_suspended_for_frame_closed_ = false;

  if (watch_time_reporter_)
    watch_time_reporter_->OnShown();

  if (video_decode_stats_reporter_)
    video_decode_stats_reporter_->OnShown();

  // Notify the compositor of our page visibility status.
  vfc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&VideoFrameCompositor::SetIsPageVisible,
                     base::Unretained(compositor_.get()), !IsPageHidden()));

  // UpdateBackgroundVideoOptimizationState will set `visibility_pause_reason_`
  // to the updated correct value. However, we need to know the previous one to
  // decide if we should resume playback.
  bool was_paused_because_page_hidden = IsPausedBecausePageHidden();
  UpdateBackgroundVideoOptimizationState();

  if (!visibility_pause_reason_ && was_paused_because_page_hidden) {
    client_->ResumePlayback();  // Calls UpdatePlayState() so return afterwards.
    return;
  }

  UpdatePlayState();
}

void WebMediaPlayerImpl::OnIdleTimeout() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // This should never be called when stale state testing overrides are used.
  DCHECK(!stale_state_override_for_testing_.has_value());

  // If we are attempting preroll, clear the stale flag.
  if (IsPrerollAttemptNeeded()) {
    delegate_->ClearStaleFlag(delegate_id_);
    return;
  }

  UpdatePlayState();
}

void WebMediaPlayerImpl::OnFrameShown() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  background_pause_timer_.Stop();

  // Foreground videos don't require user gesture to continue playback.
  video_locked_when_paused_when_hidden_ = false;

  was_suspended_for_frame_closed_ = false;

  if (watch_time_reporter_) {
    watch_time_reporter_->OnShown();
  }

  if (video_decode_stats_reporter_) {
    video_decode_stats_reporter_->OnShown();
  }

  UpdateBackgroundVideoOptimizationState();

  UpdatePlayState();
}

void WebMediaPlayerImpl::OnFrameHidden() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // Backgrounding a video requires a user gesture to resume playback.
  if (IsFrameHidden()) {
    video_locked_when_paused_when_hidden_ = true;
  }

  if (watch_time_reporter_) {
    watch_time_reporter_->OnHidden();
  }

  if (video_decode_stats_reporter_) {
    video_decode_stats_reporter_->OnHidden();
  }

  UpdateBackgroundVideoOptimizationState();
  UpdatePlayState();

  // Schedule suspended playing media to be paused if the user doesn't come back
  // to it within some timeout period to avoid any autoplay surprises.
  ScheduleIdlePauseTimer();
}

void WebMediaPlayerImpl::SetVolumeMultiplier(double multiplier) {
  volume_multiplier_ = multiplier;
  SetVolume(volume_);
}

void WebMediaPlayerImpl::SetPersistentState(bool value) {
  DVLOG(2) << __func__ << ": value=" << value;
  overlay_info_.is_persistent_video = value;
  MaybeSendOverlayInfoToDecoder();
}

void WebMediaPlayerImpl::SetPowerExperimentState(bool state) {
  if (power_status_helper_)
    power_status_helper_->UpdatePowerExperimentState(state);
}

void WebMediaPlayerImpl::ScheduleRestart() {
  // TODO(watk): All restart logic should be moved into PipelineController.
  if (pipeline_controller_->IsPipelineRunning() &&
      !pipeline_controller_->IsPipelineSuspended()) {
    pending_suspend_resume_cycle_ = true;
    UpdatePlayState();
  }
}

void WebMediaPlayerImpl::RequestRemotePlaybackDisabled(bool disabled) {
  if (observer_)
    observer_->OnRemotePlaybackDisabled(disabled);
  if (client_) {
    client_->OnRemotePlaybackDisabled(disabled);
  }
}

void WebMediaPlayerImpl::RequestMediaRemoting() {
  if (observer_) {
    observer_->OnMediaRemotingRequested();
  }
}

#if BUILDFLAG(IS_ANDROID)
void WebMediaPlayerImpl::FlingingStarted() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK(!disable_pipeline_auto_suspend_);
  disable_pipeline_auto_suspend_ = true;

  is_flinging_ = true;

  // Capabilities reporting should only be performed for local playbacks.
  video_decode_stats_reporter_.reset();

  // Requests to restart media pipeline. A flinging renderer will be created via
  // the `renderer_factory_selector_`.
  ScheduleRestart();
}

void WebMediaPlayerImpl::FlingingStopped() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK(disable_pipeline_auto_suspend_);
  disable_pipeline_auto_suspend_ = false;

  is_flinging_ = false;

  CreateVideoDecodeStatsReporter();

  ScheduleRestart();
}

void WebMediaPlayerImpl::OnRemotePlayStateChange(
    media::MediaStatus::State state) {
  DCHECK(is_flinging_);
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (state == media::MediaStatus::State::kPlaying && Paused()) {
    DVLOG(1) << __func__ << " requesting PLAY.";
    client_->ResumePlayback();
  } else if (state == media::MediaStatus::State::kPaused && !Paused()) {
    DVLOG(1) << __func__ << " requesting PAUSE.";
    client_->PausePlayback(
        MediaPlayerClient::PauseReason::kRemotePlayStateChange);
  }
}
#endif  // BUILDFLAG(IS_ANDROID)

void WebMediaPlayerImpl::SetPoster(const WebURL& poster) {
  has_poster_ = !poster.IsEmpty();
}

void WebMediaPlayerImpl::MemoryDataSourceInitialized(bool success,
                                                     size_t data_size) {
  if (success) {
    // Replace the loaded url with an empty data:// URL since it may be large.
    demuxer_manager_->SetLoadedUrl(GURL("data:,"));

    // Mark all the data as buffered.
    buffered_data_source_host_->SetTotalBytes(data_size);
    buffered_data_source_host_->AddBufferedByteRange(0, data_size);
  }
  DataSourceInitialized(success);
}

void WebMediaPlayerImpl::DataSourceInitialized(bool success) {
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (!success) {
    SetNetworkState(WebMediaPlayer::kNetworkStateFormatError);
    media_metrics_provider_->OnError(media::PIPELINE_ERROR_NETWORK);

    // Not really necessary, since the pipeline was never started, but it at
    // least this makes sure that the error handling code is in sync.
    UpdatePlayState();

    return;
  }

  StartPipeline();
}

void WebMediaPlayerImpl::MultiBufferDataSourceInitialized(bool success) {
  DVLOG(1) << __func__;
  DCHECK(demuxer_manager_->HasDataSource());
  if (observer_) {
    observer_->OnDataSourceInitialized(
        demuxer_manager_->GetDataSourceUrlAfterRedirects().value());
  }

  // No point in preloading data as we'll probably just throw it away anyways.
  if (success && IsStreaming() && preload_ > media::DataSource::METADATA)
    demuxer_manager_->SetPreload(media::DataSource::METADATA);
  DataSourceInitialized(success);
}

void WebMediaPlayerImpl::OnDataSourceRedirected() {
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (WouldTaintOrigin()) {
    audio_source_provider_->TaintOrigin();
  }
}

void WebMediaPlayerImpl::NotifyDownloading(bool is_downloading) {
  DVLOG(1) << __func__ << "(" << is_downloading << ")";
  if (!is_downloading && network_state_ == WebMediaPlayer::kNetworkStateLoading)
    SetNetworkState(WebMediaPlayer::kNetworkStateIdle);
  else if (is_downloading &&
           network_state_ == WebMediaPlayer::kNetworkStateIdle)
    SetNetworkState(WebMediaPlayer::kNetworkStateLoading);
  if (ready_state_ == ReadyState::kReadyStateHaveFutureData && !is_downloading)
    SetReadyState(WebMediaPlayer::kReadyStateHaveEnoughData);
}

void WebMediaPlayerImpl::OnOverlayRoutingToken(
    const base::UnguessableToken& token) {
  DCHECK(overlay_mode_ == OverlayMode::kUseAndroidOverlay);
  // TODO(liberato): `token` should already be a RoutingToken.
  overlay_routing_token_is_pending_ = false;
  overlay_routing_token_ = media::OverlayInfo::RoutingToken(token);
  MaybeSendOverlayInfoToDecoder();
}

void WebMediaPlayerImpl::OnOverlayInfoRequested(
    bool decoder_requires_restart_for_overlay,
    media::ProvideOverlayInfoCB provide_overlay_info_cb) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // If we get a non-null cb, a decoder is initializing and requires overlay
  // info. If we get a null cb, a previously initialized decoder is
  // unregistering for overlay info updates.
  if (!provide_overlay_info_cb) {
    decoder_requires_restart_for_overlay_ = false;
    provide_overlay_info_cb_.Reset();
    return;
  }

  // If `decoder_requires_restart_for_overlay` is true, we must restart the
  // pipeline for fullscreen transitions. The decoder is unable to switch
  // surfaces otherwise. If false, we simply need to tell the decoder about the
  // new surface and it will handle things seamlessly.
  // For encrypted video we pretend that the decoder doesn't require a restart
  // because it needs an overlay all the time anyway. We'll switch into
  // `always_enable_overlays_` mode below.
  decoder_requires_restart_for_overlay_ =
      (overlay_mode_ == OverlayMode::kUseAndroidOverlay && is_encrypted_)
          ? false
          : decoder_requires_restart_for_overlay;
  provide_overlay_info_cb_ = std::move(provide_overlay_info_cb);

  // If the decoder doesn't require restarts for surface transitions, and we're
  // using AndroidOverlay mode, we can always enable the overlay and the decoder
  // can choose whether or not to use it. Otherwise, we'll restart the decoder
  // and enable the overlay on fullscreen transitions.
  if (overlay_mode_ == OverlayMode::kUseAndroidOverlay &&
      !decoder_requires_restart_for_overlay_) {
    always_enable_overlays_ = true;
    if (!overlay_enabled_)
      EnableOverlay();
  }

  // Send the overlay info if we already have it. If not, it will be sent later.
  MaybeSendOverlayInfoToDecoder();
}

void WebMediaPlayerImpl::MaybeSendOverlayInfoToDecoder() {
  // If the decoder didn't request overlay info, then don't send it.
  if (!provide_overlay_info_cb_)
    return;

  // We should send the overlay info as long as we know it.  This includes the
  // case where `!overlay_enabled_`, since we want to tell the decoder to avoid
  // using overlays.  Assuming that the decoder has requested info, the only
  // case in which we don't want to send something is if we've requested the
  // info but not received it yet.  Then, we should wait until we do.
  //
  // Initialization requires this; AVDA should start with enough info to make an
  // overlay, so that (pre-M) the initial codec is created with the right output
  // surface; it can't switch later.
  if (overlay_mode_ == OverlayMode::kUseAndroidOverlay) {
    if (overlay_routing_token_is_pending_)
      return;

    overlay_info_.routing_token = overlay_routing_token_;
  }

  // If restart is required, the callback is one-shot only.
  if (decoder_requires_restart_for_overlay_) {
    std::move(provide_overlay_info_cb_).Run(overlay_info_);
  } else {
    provide_overlay_info_cb_.Run(overlay_info_);
  }
}

std::unique_ptr<media::Renderer> WebMediaPlayerImpl::CreateRenderer(
    std::optional<media::RendererType> renderer_type) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // Make sure that overlays are enabled if they're always allowed.
  if (always_enable_overlays_)
    EnableOverlay();

  media::RequestOverlayInfoCB request_overlay_info_cb;
#if BUILDFLAG(IS_ANDROID)
  request_overlay_info_cb =
      base::BindPostTaskToCurrentDefault(base::BindRepeating(
          &WebMediaPlayerImpl::OnOverlayInfoRequested, weak_this_));
#endif

  if (renderer_type) {
    DVLOG(1) << __func__
             << ": renderer_type=" << static_cast<int>(renderer_type.value());
    renderer_factory_selector_->SetBaseRendererType(renderer_type.value());
  }

  bool old_uses_audio_service = UsesAudioService(renderer_type_);
  renderer_type_ = renderer_factory_selector_->GetCurrentRendererType();

  // TODO(crbug/1426179): Support codec changing for Media Foundation.
  if (renderer_type_ == media::RendererType::kMediaFoundation) {
    demuxer_manager_->DisableDemuxerCanChangeType();
  }

  bool new_uses_audio_service = UsesAudioService(renderer_type_);
  if (new_uses_audio_service != old_uses_audio_service)
    client_->DidUseAudioServiceChange(new_uses_audio_service);

  media_metrics_provider_->SetRendererType(renderer_type_);
  media_log_->SetProperty<MediaLogProperty::kRendererName>(renderer_type_);

  return renderer_factory_selector_->GetCurrentFactory()->CreateRenderer(
      media_task_runner_, worker_task_runner_, audio_source_provider_.get(),
      compositor_.get(), std::move(request_overlay_info_cb),
      client_->TargetColorSpace());
}

std::optional<media::DemuxerType> WebMediaPlayerImpl::GetDemuxerType() const {
  // Note: this can't be a ternary expression because the compiler throws a fit
  // over type conversions.
  if (demuxer_manager_) {
    return demuxer_manager_->GetDemuxerType();
  }
  return std::nullopt;
}

media::PipelineStatus WebMediaPlayerImpl::OnDemuxerCreated(
    Demuxer* demuxer,
    media::Pipeline::StartType start_type,
    bool is_streaming,
    bool is_static) {
  CHECK_NE(demuxer, nullptr);
  switch (demuxer->GetDemuxerType()) {
    case media::DemuxerType::kMediaUrlDemuxer: {
      using_media_player_renderer_ = true;
      video_decode_stats_reporter_.reset();
      break;
    }
    default: {
      seeking_ = true;
      break;
    }
  }

  if (start_type != media::Pipeline::StartType::kNormal) {
    attempting_suspended_start_ = true;
  }

  pipeline_controller_->Start(start_type, demuxer, this, is_streaming,
                              is_static);
  return media::OkStatus();
}

void WebMediaPlayerImpl::StartPipeline() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  vfc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&VideoFrameCompositor::SetOnNewProcessedFrameCallback,
                     base::Unretained(compositor_.get()),
                     base::BindPostTaskToCurrentDefault(base::BindOnce(
                         &WebMediaPlayerImpl::OnFirstFrame, weak_this_))));
  base::flat_map<std::string, std::string> headers;
  // Referer is the right spelling of the HTTP header, not Referrer.
  headers[net::HttpRequestHeaders::kReferer] =
      net::URLRequestJob::ComputeReferrerForPolicy(
          frame_->GetDocument().GetReferrerPolicy(),
          GURL(frame_->GetDocument().OutgoingReferrer().Utf8()),
          demuxer_manager_->LoadedUrl())
          .spec();

  // base::Unretained(this) is safe here, since |CreateDemuxer| calls the bound
  // method directly and immediately.
  auto create_demuxer_error = demuxer_manager_->CreateDemuxer(
      load_type_ == kLoadTypeMediaSource, preload_, needs_first_frame_,
      base::BindOnce(&WebMediaPlayerImpl::OnDemuxerCreated,
                     base::Unretained(this)),
      std::move(headers));

  if (!create_demuxer_error.is_ok()) {
    return OnError(std::move(create_demuxer_error));
  }
}

void WebMediaPlayerImpl::SetNetworkState(WebMediaPlayer::NetworkState state) {
  DVLOG(1) << __func__ << "(" << state << ")";
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  network_state_ = state;
  // Always notify to ensure client has the latest value.
  client_->NetworkStateChanged();
}

void WebMediaPlayerImpl::SetReadyState(WebMediaPlayer::ReadyState state) {
  DVLOG(1) << __func__ << "(" << state << ")";
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (state == WebMediaPlayer::kReadyStateHaveEnoughData &&
      demuxer_manager_->DataSourceFullyBuffered() &&
      network_state_ == WebMediaPlayer::kNetworkStateLoading) {
    SetNetworkState(WebMediaPlayer::kNetworkStateLoaded);
  }

  ready_state_ = state;
  highest_ready_state_ = std::max(highest_ready_state_, ready_state_);

  // Always notify to ensure client has the latest value.
  client_->ReadyStateChanged();
}

scoped_refptr<WebAudioSourceProviderImpl>
WebMediaPlayerImpl::GetAudioSourceProvider() {
  return audio_source_provider_;
}

scoped_refptr<media::VideoFrame>
WebMediaPlayerImpl::GetCurrentFrameFromCompositor() const {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  TRACE_EVENT0("media", "WebMediaPlayerImpl::GetCurrentFrameFromCompositor");

  // We can't copy from protected frames.
  if (cdm_context_ref_)
    return nullptr;

  // Can be null.
  scoped_refptr<media::VideoFrame> video_frame =
      compositor_->GetCurrentFrameOnAnyThread();

  // base::Unretained is safe here because `compositor_` is destroyed on
  // `vfc_task_runner_`. The destruction is queued from `this`' destructor,
  // which also runs on `main_task_runner_`, which makes it impossible for
  // UpdateCurrentFrameIfStale() to be queued after `compositor_`'s dtor.
  vfc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&VideoFrameCompositor::UpdateCurrentFrameIfStale,
                     base::Unretained(compositor_.get()),
                     VideoFrameCompositor::UpdateType::kNormal));

  return video_frame;
}

void WebMediaPlayerImpl::UpdatePlayState() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  bool can_auto_suspend = !disable_pipeline_auto_suspend_;
  // For streaming videos, we only allow suspending at the very beginning of the
  // video, and only if we know the length of the video. (If we don't know
  // the length, it might be a dynamically generated video, and suspending
  // will not work at all.)
  if (IsStreaming()) {
    bool at_beginning =
        ready_state_ == WebMediaPlayer::kReadyStateHaveNothing ||
        CurrentTime() == 0.0;
    if (!at_beginning || GetPipelineMediaDuration() == media::kInfiniteDuration)
      can_auto_suspend = false;
  }

  bool is_suspended = pipeline_controller_->IsSuspended();
  bool is_backgrounded = IsBackgroundSuspendEnabled(this) && IsPageHidden();
  PlayState state = UpdatePlayState_ComputePlayState(
      is_flinging_, can_auto_suspend, is_suspended, is_backgrounded,
      IsInPictureInPicture());
  SetDelegateState(state.delegate_state, state.is_idle);
  SetMemoryReportingState(state.is_memory_reporting_enabled);
  SetSuspendState(state.is_suspended || pending_suspend_resume_cycle_);
  if (power_status_helper_) {
    // Make sure that we're in something like steady-state before recording.
    power_status_helper_->SetIsPlaying(
        !paused_ && !seeking_ && !IsPageHidden() && !state.is_suspended &&
        ready_state_ == kReadyStateHaveEnoughData);
  }
  UpdateSmoothnessHelper();
}

void WebMediaPlayerImpl::OnTimeUpdate() {
  // When seeking the current time can go beyond the duration so we should
  // cap the current time at the duration.
  base::TimeDelta duration = GetPipelineMediaDuration();
  base::TimeDelta current_time = GetCurrentTimeInternal();
  if (current_time > duration)
    current_time = duration;

  const double effective_playback_rate =
      paused_ || ready_state_ < kReadyStateHaveFutureData ? 0.0
                                                          : playback_rate_;

  media_session::MediaPosition new_position(effective_playback_rate, duration,
                                            current_time, ended_);

  if (!MediaPositionNeedsUpdate(media_position_state_, new_position))
    return;

  DVLOG(2) << __func__ << "(" << new_position.ToString() << ")";
  media_position_state_ = new_position;
  client_->DidPlayerMediaPositionStateChange(effective_playback_rate, duration,
                                             current_time, ended_);
}

void WebMediaPlayerImpl::SetDelegateState(DelegateState new_state,
                                          bool is_idle) {
  DCHECK(delegate_);
  DVLOG(2) << __func__ << "(" << static_cast<int>(new_state) << ", " << is_idle
           << ")";

  // Prevent duplicate delegate calls.
  // TODO(sandersd): Move this deduplication into the delegate itself.
  if (delegate_state_ == new_state)
    return;
  delegate_state_ = new_state;

  switch (new_state) {
    case DelegateState::GONE:
      delegate_->PlayerGone(delegate_id_);
      break;
    case DelegateState::PLAYING: {
      // When delegate get PlayerGone it removes all state, need to make sure
      // it is up-to-date before calling DidPlay.
      delegate_->DidMediaMetadataChange(delegate_id_, delegate_has_audio_,
                                        HasVideo(), GetMediaContentType());
      if (HasVideo())
        client_->DidPlayerSizeChange(NaturalSize());
      client_->DidPlayerStartPlaying();
      delegate_->DidPlay(delegate_id_);
      break;
    }
    case DelegateState::PAUSED:
      client_->DidPlayerPaused(ended_);
      delegate_->DidPause(delegate_id_, ended_);
      break;
  }

  delegate_->SetIdle(delegate_id_, is_idle);
}

void WebMediaPlayerImpl::SetMemoryReportingState(
    bool is_memory_reporting_enabled) {
  if (memory_usage_reporting_timer_.IsRunning() ==
      is_memory_reporting_enabled) {
    return;
  }

  if (is_memory_reporting_enabled) {
    memory_usage_reporting_timer_.Start(FROM_HERE, base::Seconds(2), this,
                                        &WebMediaPlayerImpl::ReportMemoryUsage);
  } else {
    memory_usage_reporting_timer_.Stop();
    ReportMemoryUsage();
  }
}

void WebMediaPlayerImpl::SetSuspendState(bool is_suspended) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DVLOG(2) << __func__ << "(" << is_suspended << ")";

  // Do not change the state after an error has occurred.
  // TODO(sandersd): Update PipelineController to remove the need for this.
  if (IsNetworkStateError(network_state_))
    return;

  if (is_suspended) {
    // If we were not resumed for long enough to satisfy the preroll attempt,
    // reset the clock.
    if (!preroll_attempt_pending_ && IsPrerollAttemptNeeded()) {
      preroll_attempt_pending_ = true;
      preroll_attempt_start_time_ = base::TimeTicks();
    }
    pipeline_controller_->Suspend();
  } else {
    // When resuming, start the preroll attempt clock.
    if (preroll_attempt_pending_) {
      preroll_attempt_pending_ = false;
      preroll_attempt_start_time_ = tick_clock_->NowTicks();
    }
    pipeline_controller_->Resume();
  }
}

WebMediaPlayerImpl::PlayState
WebMediaPlayerImpl::UpdatePlayState_ComputePlayState(
    bool is_flinging,
    bool can_auto_suspend,
    bool is_suspended,
    bool is_backgrounded,
    bool is_in_picture_in_picture) {
  PlayState result;

  bool must_suspend =
      was_suspended_for_frame_closed_ || pending_oneshot_suspend_;
  bool is_stale = delegate_->IsStale(delegate_id_);

  if (stale_state_override_for_testing_.has_value() &&
      ready_state_ >= stale_state_override_for_testing_.value()) {
    is_stale = true;
  }

  // This includes both data source (before pipeline startup) and pipeline
  // errors.
  bool has_error = IsNetworkStateError(network_state_);

  // Note: Even though we get play/pause signals at kReadyStateHaveMetadata, we
  // must attempt to preroll until kReadyStateHaveFutureData so that the
  // canplaythrough event will be fired to the page (which may be waiting).
  bool have_future_data =
      highest_ready_state_ >= WebMediaPlayer::kReadyStateHaveFutureData;

  // Background suspend is only enabled for paused players.
  // In the case of players with audio the session should be kept.
  bool background_suspended = can_auto_suspend && is_backgrounded && paused_ &&
                              have_future_data && !is_in_picture_in_picture;

  // Idle suspension is allowed prior to kReadyStateHaveMetadata since there
  // exist mechanisms to exit the idle state when the player is capable of
  // reaching the kReadyStateHaveMetadata state; see didLoadingProgress().
  //
  // TODO(sandersd): Make the delegate suspend idle players immediately when
  // hidden.
  bool idle_suspended = can_auto_suspend && is_stale && paused_ && !seeking_ &&
                        !overlay_info_.is_fullscreen && !needs_first_frame_;

  // If we're already suspended, see if we can wait for user interaction. Prior
  // to kReadyStateHaveMetadata, we require `is_stale` to remain suspended.
  // `is_stale` will be cleared when we receive data which may take us to
  // kReadyStateHaveMetadata.
  bool can_stay_suspended = (is_stale || have_future_data) && is_suspended &&
                            paused_ && !seeking_ && !needs_first_frame_;

  // Combined suspend state.
  result.is_suspended = must_suspend || idle_suspended ||
                        background_suspended || can_stay_suspended;

  DVLOG(3) << __func__ << ": must_suspend=" << must_suspend
           << ", idle_suspended=" << idle_suspended
           << ", background_suspended=" << background_suspended
           << ", can_stay_suspended=" << can_stay_suspended
           << ", is_stale=" << is_stale
           << ", have_future_data=" << have_future_data
           << ", paused_=" << paused_ << ", seeking_=" << seeking_;

  // We do not treat `playback_rate_` == 0 as paused. For the media session,
  // being paused implies displaying a play button, which is incorrect in this
  // case. For memory usage reporting, we just use the same definition (but we
  // don't have to).
  //
  // Similarly, we don't consider `ended_` to be paused. Blink will immediately
  // call pause() or seek(), so `ended_` should not affect the computation.
  // Despite that, `ended_` does result in a separate paused state, to simplfy
  // the contract for SetDelegateState().
  //
  // `has_remote_controls` indicates if the player can be controlled outside the
  // page (e.g. via the notification controls or by audio focus events). Idle
  // suspension does not destroy the media session, because we expect that the
  // notification controls (and audio focus) remain. With some exceptions for
  // background videos, the player only needs to have audio to have controls
  // (requires `have_current_data`).
  //
  // `alive` indicates if the player should be present (not `GONE`) to the
  // delegate, either paused or playing. The following must be true for the
  // player:
  //   - `have_current_data`, since playback can't begin before that point, we
  //     need to know whether we are paused to correctly configure the session,
  //     and also because the tracks and duration are passed to DidPlay(),
  //   - `is_flinging` is false (RemotePlayback is not handled by the delegate)
  //   - `has_error` is false as player should have no errors,
  //   - `background_suspended` is false, otherwise `has_remote_controls` must
  //     be true.
  //
  // TODO(sandersd): If Blink told us the paused state sooner, we could detect
  // if the remote controls are available sooner.

  // Background videos with audio don't have remote controls if background
  // suspend is enabled and resuming background videos is not (original Android
  // behavior).
  bool backgrounded_video_has_no_remote_controls =
      IsBackgroundSuspendEnabled(this) && !IsResumeBackgroundVideosEnabled() &&
      is_backgrounded && HasVideo();
  bool have_current_data = highest_ready_state_ >= kReadyStateHaveCurrentData;
  bool can_play = !has_error && have_current_data;
  bool has_remote_controls =
      HasAudio() && !backgrounded_video_has_no_remote_controls;
  bool alive = can_play && !is_flinging && !must_suspend &&
               (!background_suspended || has_remote_controls);
  if (!alive) {
    // Do not mark players as idle when flinging.
    result.delegate_state = DelegateState::GONE;
    result.is_idle = delegate_->IsIdle(delegate_id_) && !is_flinging;
  } else if (paused_) {
    // TODO(sandersd): Is it possible to have a suspended session, be ended,
    // and not be paused? If so we should be in a PLAYING state.
    result.delegate_state = DelegateState::PAUSED;
    result.is_idle = !seeking_;
  } else {
    result.delegate_state = DelegateState::PLAYING;
    result.is_idle = false;
  }

  // It's not critical if some cases where memory usage can change are missed,
  // since media memory changes are usually gradual.
  result.is_memory_reporting_enabled = !has_error && can_play && !is_flinging &&
                                       !result.is_suspended &&
                                       (!paused_ || seeking_);

  return result;
}

void WebMediaPlayerImpl::MakeDemuxerThreadDumper(media::Demuxer* demuxer) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK(!media_thread_mem_dumper_);

  // base::Unretained() is safe here. `demuxer` is owned by |demuxer_manager_|,
  // which is destroyed on the main thread, but before doing it
  // ~WebMediaPlayerImpl() posts a media thread task that deletes
  // |media_thread_mem_dumper_| and  waits for it to finish.
  media_thread_mem_dumper_ = std::make_unique<media::MemoryDumpProviderProxy>(
      "WebMediaPlayer_MediaThread", media_task_runner_,
      base::BindRepeating(&WebMediaPlayerImpl::OnMediaThreadMemoryDump,
                          media_player_id_, base::Unretained(demuxer)));
}

bool WebMediaPlayerImpl::CouldPlayIfEnoughData() {
  return client_->CouldPlayIfEnoughData();
}

bool WebMediaPlayerImpl::IsMediaPlayerRendererClient() {
  // MediaPlayerRendererClientFactory is the only factory that a uses
  // MediaResource::Type::URL for the moment.
  return renderer_factory_selector_->GetCurrentFactory()
             ->GetRequiredMediaResourceType() ==
         media::MediaResource::Type::KUrl;
}

void WebMediaPlayerImpl::ReportMemoryUsage() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // About base::Unretained() usage below: We destroy `demuxer_manager_` on the
  // main thread.  Before that, however, ~WebMediaPlayerImpl() posts a task to
  // the media thread and waits for it to finish.  Hence, the GetMemoryUsage()
  // task posted here must finish earlier.
  //
  // The exception to the above is when OnError() has been called. If we're in
  // the error state we've already shut down the pipeline and can't rely on it
  // to cycle the media thread before we destroy `demuxer_manager_`. In this
  // case skip collection of the demuxer memory stats.
  if (demuxer_manager_ && !IsNetworkStateError(network_state_)) {
    demuxer_manager_->RespondToDemuxerMemoryUsageReport(base::BindOnce(
        &WebMediaPlayerImpl::FinishMemoryUsageReport, weak_this_));
  } else {
    FinishMemoryUsageReport(0);
  }
}

void WebMediaPlayerImpl::FinishMemoryUsageReport(int64_t demuxer_memory_usage) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  const auto stats = GetPipelineStatistics();
  const int64_t data_source_memory_usage =
      demuxer_manager_->GetDataSourceMemoryUsage();

  // If we have video and no video memory usage and we've rendered the first
  // frame, assume the VideoFrameCompositor is holding onto the last frame after
  // we've suspended the pipeline; which thus reports zero memory usage from the
  // video renderer.
  //
  // Technically this should use the coded size, but that requires us to hop to
  // the compositor to get and byte-perfect accuracy isn't important here.
  const int64_t video_memory_usage =
      stats.video_memory_usage +
      ((pipeline_metadata_.has_video && !stats.video_memory_usage &&
        has_first_frame_)
           ? media::VideoFrame::AllocationSize(media::PIXEL_FORMAT_I420,
                                               pipeline_metadata_.natural_size)
           : 0);

  const int64_t current_memory_usage =
      stats.audio_memory_usage + video_memory_usage + data_source_memory_usage +
      demuxer_memory_usage;

  DVLOG(3) << "Memory Usage -- Total: " << current_memory_usage
           << " Audio: " << stats.audio_memory_usage
           << ", Video: " << video_memory_usage
           << ", DataSource: " << data_sour
"""


```