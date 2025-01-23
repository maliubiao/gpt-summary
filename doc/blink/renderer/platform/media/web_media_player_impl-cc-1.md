Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `WebMediaPlayerImpl` class in Chromium's Blink rendering engine. I need to identify the key actions and responsibilities within this section of the code. I should also look for connections to JavaScript, HTML, and CSS, as well as any logical reasoning, common errors, and the overall purpose of these methods.

**Functionality Breakdown:**

1. **CDM Handling:** The code deals with setting and attaching a Content Decryption Module (CDM) for encrypted media playback. This involves checking for successful attachment and handling errors.
2. **Seeking:** It handles the completion of a seek operation in the media pipeline, updating playback state and notifying the client.
3. **Pipeline State Management:**  Methods like `OnPipelineStarted`, `OnPipelineSuspended`, and `OnPipelineResumed` manage the different states of the media pipeline. Suspension logic includes considerations for lazy loading and background optimizations.
4. **Demuxer Events:**  The code handles events related to the demuxer, such as when it's opened (`OnChunkDemuxerOpened`) and when a reset is needed (`StopForDemuxerReset`).
5. **Error Handling:**  The `OnError` method deals with pipeline errors, logging them and updating the network state.
6. **Playback Completion:** The `OnEnded` method is called when playback reaches the end of the media.
7. **Metadata Handling:** The `OnMetadata` method processes media metadata, including audio and video configurations, setting up video layers, and triggering ready state changes. It also addresses a case where media might have no audio or video tracks.
8. **Surface Layer Activation:**  The code manages activating a `SurfaceLayer` for video rendering, particularly in cases like Picture-in-Picture.
9. **Buffering State Changes:** The `OnBufferingStateChange` and `OnBufferingStateChangeInternal` methods handle changes in the buffering status, updating the ready state and notifying the client.
10. **Duration Changes:** The `OnDurationChange` method is called when the media duration changes.
11. **Waiting States:** The `OnWaiting` method handles scenarios where the pipeline is waiting for certain conditions, such as the availability of a CDM or decryption key.
12. **Video Size and Opacity:** Methods like `OnVideoNaturalSizeChange` and `OnVideoOpacityChange` update the video's dimensions and opacity.
13. **Configuration Changes:** The code handles changes in audio and video configurations (`OnAudioConfigChange`, `OnVideoConfigChange`).
14. **Page Visibility:** Methods like `OnPageHidden` and `OnPageShown` react to changes in the page's visibility, potentially pausing playback for backgrounded videos.
15. **Volume and Persistent State:** The code allows setting the volume multiplier and a persistent state.
16. **Restarting the Pipeline:** The `ScheduleRestart` method handles restarting the media pipeline.
17. **Remote Playback:** Methods related to remote playback (`RequestRemotePlaybackDisabled`, `RequestMediaRemoting`, `FlingingStarted`, `FlingingStopped`, `OnRemotePlayStateChange`) are present.
18. **Data Source Initialization:** The code handles the initialization of the media data source (`DataSourceInitialized`, `MultiBufferDataSourceInitialized`).
19. **Downloading Notifications:** The `NotifyDownloading` method is called to indicate whether the media is currently being downloaded.
20. **Overlay Management:** Methods related to overlay functionality, like `OnOverlayRoutingToken`, `OnOverlayInfoRequested`, and `MaybeSendOverlayInfoToDecoder`, are included.
21. **Renderer Creation:** The `CreateRenderer` method is responsible for creating the appropriate media renderer.
22. **Demuxer Creation Callback:** The `OnDemuxerCreated` method is a callback triggered after the demuxer is created.
23. **Pipeline Starting:** The `StartPipeline` method initiates the media pipeline.
24. **State Setting:**  The code includes methods for setting the network state (`SetNetworkState`) and ready state (`SetReadyState`).
25. **Audio Source Provider:** The `GetAudioSourceProvider` method returns the audio source provider.
26. **Current Frame from Compositor:** The `GetCurrentFrameFromCompositor` method retrieves the current video frame from the compositor.
27. **Play State Updates:** The `UpdatePlayState` method recalculates and sets the overall play state of the media.
28. **Time Updates:** The `OnTimeUpdate` method handles time updates and notifies the client.
29. **Delegate State Management:** The `SetDelegateState` method manages the state of a media delegate.
30. **Memory Reporting:** Methods like `SetMemoryReportingState`, `ReportMemoryUsage`, and `FinishMemoryUsageReport` are responsible for tracking and reporting memory usage.
31. **Suspend State Management:** The `SetSuspendState` method manages the suspension of the media pipeline.
32. **Play State Computation:** The `UpdatePlayState_ComputePlayState` method calculates the derived play state based on various factors.
33. **Demuxer Thread Dumper:** The `MakeDemuxerThreadDumper` method creates a utility for dumping demuxer thread information.
34. **Checking Playability:** The `CouldPlayIfEnoughData` method checks if playback could start if enough data was available.
35. **Renderer Type Check:** The `IsMediaPlayerRendererClient` method checks the type of the current renderer.

**Connections to JavaScript, HTML, and CSS:**

*   **JavaScript:**  Many of these methods correspond to events and API calls that JavaScript in a web page can trigger or observe. For example, JavaScript can call `play()` or `pause()`, which will eventually lead to calls to `UpdatePlayState`. JavaScript receives events related to ready state (`readyState`), network state (`networkState`), time updates (`timeupdate`), duration changes (`durationchange`), and errors. The CDM related methods are used by the Encrypted Media Extensions (EME) JavaScript API.
*   **HTML:** The `<video>` and `<audio>` HTML elements are the primary drivers of this code. Attributes like `src`, `autoplay`, `controls`, `preload`, and `poster` influence the behavior managed by `WebMediaPlayerImpl`. The `SetPoster` method directly relates to the `poster` attribute.
*   **CSS:** CSS can affect the visual presentation of the media, but the direct interaction with this C++ code is less pronounced. However, CSS can influence factors like whether a video is visible (which relates to background video optimization). Fullscreen transitions, which can trigger overlay changes, are also indirectly related to CSS.

**Logical Reasoning (Assumptions and Outputs):**

*   **Assumption:** When `SetCdmInternal` is called with a valid `WebContentDecryptionModule`, the output will be that `is_encrypted_` is set to `true`, and the pipeline controller will be instructed to attach the CDM.
    *   **Input:** A valid `WebContentDecryptionModule` pointer.
    *   **Output:** `is_encrypted_` becomes true, and `pipeline_controller_->SetCdm` is called.
*   **Assumption:** When a seek operation completes successfully (`OnPipelineSeeked`), if the player was paused, the `paused_time_` will be updated. If the player was playing, the `watch_time_reporter_` and `playback_events_recorder_` will be notified.
    *   **Input:** Completion of a seek operation.
    *   **Output (if paused):** `paused_time_` is updated.
    *   **Output (if playing):** `watch_time_reporter_->OnPlaying()` and `playback_events_recorder_->OnPlaying()` are called.

**Common Usage Errors:**

*   **Setting CDM after playback has started:**  While the code handles setting the CDM after playback has started, doing so might lead to a brief interruption or a more complex setup. It's generally recommended to set the CDM before attempting to play encrypted content.
*   **Incorrectly managing ready state in JavaScript:** Developers might try to interact with the media (e.g., play, seek) before the media has reached a sufficient ready state, leading to errors or unexpected behavior. The `WebMediaPlayerImpl` manages these state transitions, and the browser exposes the `readyState` property to JavaScript to help avoid such errors.
*   **Not handling media errors:**  If a media error occurs (e.g., network error, decoding error), and the JavaScript code doesn't have proper error handling, the user might encounter a broken experience. The `OnError` method in `WebMediaPlayerImpl` signals these errors, and the browser provides the `error` event to JavaScript.

**Summary of Functionality:**

This section of `WebMediaPlayerImpl.cc` is responsible for managing the core lifecycle and operational aspects of a media player within the Chromium rendering engine. It handles everything from setting up encrypted playback (CDM integration) and managing the media pipeline's state (starting, suspending, resuming, seeking) to processing media metadata, reacting to buffering changes, and coordinating with lower-level media components and higher-level browser functionalities. It acts as a central hub for responding to various events and user interactions, ensuring smooth and correct media playback. This involves managing buffering, handling errors, updating playback state, and notifying the embedding web page about relevant changes via events and API calls.

这是 `blink/renderer/platform/media/web_media_player_impl.cc` 源代码文件的第二部分，延续了第一部分的功能，主要负责以下方面的媒体播放管理和控制：

**核心功能归纳:**

*   **CDM（Content Decryption Module）集成和管理:**
    *   `SetCdmInternal`: 接收并设置 CDM 对象，用于播放加密媒体。
    *   `OnCdmAttached`: 处理 CDM 连接到 pipeline 后的结果，成功则保存 CDM 上下文，失败则通知错误。
*   **媒体播放状态和控制:**
    *   `OnPipelineSeeked`: 处理 pipeline 完成 seek 操作后的状态更新。
    *   `OnPipelineStarted`: 处理 pipeline 启动后的状态更新。
    *   `OnPipelineSuspended`: 处理 pipeline 进入暂停状态，涉及资源释放和懒加载优化。
    *   `OnBeforePipelineResume`:  pipeline 恢复播放前的准备工作。
    *   `OnPipelineResumed`: 处理 pipeline 恢复播放后的状态更新。
    *   `OnEnded`: 处理媒体播放结束事件。
    *   `OnMetadata`: 处理媒体元数据加载完成事件，包括音视频配置、视频图层创建等。
    *   `ActivateSurfaceLayerForVideo`:  激活 `SurfaceLayer` 用于视频渲染，通常用于 Android 平台的 overlay 模式。
    *   `OnBufferingStateChange`, `OnBufferingStateChangeInternal`: 处理媒体缓冲状态变化，更新 readyState。
    *   `OnDurationChange`: 处理媒体时长变化事件。
    *   `OnWaiting`: 处理 pipeline 等待事件，例如等待 CDM 或解密密钥。
    *   `OnProgress`:  处理媒体加载进度事件，用于判断是否可以开始播放。
    *   `CanPlayThrough`: 判断媒体是否可以流畅播放到结束。
*   **视频属性管理:**
    *   `OnVideoNaturalSizeChange`: 处理视频原始尺寸变化事件。
    *   `OnVideoOpacityChange`: 处理视频不透明度变化事件。
    *   `OnVideoFrameRateChange`: 处理视频帧率变化事件。
*   **音视频配置管理:**
    *   `OnAudioConfigChange`: 处理音频配置变化事件。
    *   `OnVideoConfigChange`: 处理视频配置变化事件。
*   **音视频 pipeline 信息管理:**
    *   `OnAudioPipelineInfoChange`: 处理音频 pipeline 信息变化事件。
    *   `OnVideoPipelineInfoChange`: 处理视频 pipeline 信息变化事件。
*   **页面可见性管理和优化:**
    *   `OnPageHidden`: 处理页面隐藏事件，暂停播放并启动空闲暂停计时器。
    *   `SuspendForFrameClosed`:  当 frame 关闭时暂停播放。
    *   `OnPageShown`: 处理页面显示事件，恢复播放。
    *   `OnIdleTimeout`:  处理空闲超时事件，可能清理 stale 状态。
    *   `OnFrameShown`, `OnFrameHidden`: 处理 frame 的显示和隐藏事件，类似页面可见性管理。
*   **其他控制和信息:**
    *   `SetVolumeMultiplier`: 设置音量倍数。
    *   `SetPersistentState`: 设置播放状态是否持久化。
    *   `SetPowerExperimentState`: 设置电源实验状态。
    *   `ScheduleRestart`:  安排 pipeline 重启。
    *   `RequestRemotePlaybackDisabled`, `RequestMediaRemoting`:  控制远程播放功能。
    *   `FlingingStarted`, `FlingingStopped`, `OnRemotePlayStateChange` (Android):  处理 Android 平台的投屏功能。
    *   `SetPoster`: 设置视频封面。
    *   `MemoryDataSourceInitialized`, `DataSourceInitialized`, `MultiBufferDataSourceInitialized`:  处理数据源初始化完成事件。
    *   `OnDataSourceRedirected`: 处理数据源重定向事件。
    *   `NotifyDownloading`: 通知当前是否正在下载媒体数据。
    *   `OnOverlayRoutingToken`, `OnOverlayInfoRequested`, `MaybeSendOverlayInfoToDecoder`:  处理视频 overlay 相关的路由 token 和信息请求。
    *   `CreateRenderer`: 创建实际的媒体渲染器。
    *   `GetDemuxerType`: 获取当前使用的 demuxer 类型。
    *   `OnDemuxerCreated`:  处理 demuxer 创建完成后的回调。
    *   `StartPipeline`: 启动媒体 pipeline。
    *   `SetNetworkState`, `SetReadyState`: 设置网络状态和 ready 状态。
    *   `GetAudioSourceProvider`: 获取音频源提供器。
    *   `GetCurrentFrameFromCompositor`: 从 compositor 获取当前帧。
    *   `UpdatePlayState`: 更新播放状态，并根据状态通知 delegate。
    *   `OnTimeUpdate`:  处理时间更新事件，通知客户端。
    *   `SetDelegateState`: 设置代理对象的状态。
    *   `SetMemoryReportingState`, `ReportMemoryUsage`, `FinishMemoryUsageReport`:  管理内存使用报告。
    *   `SetSuspendState`: 设置 pipeline 的暂停状态。
    *   `UpdatePlayState_ComputePlayState`:  计算当前的播放状态。
    *   `MakeDemuxerThreadDumper`:  创建用于 dump demuxer 线程信息的工具。
    *   `CouldPlayIfEnoughData`: 判断在数据充足的情况下是否可以播放。
    *   `IsMediaPlayerRendererClient`: 判断是否是 MediaPlayerRenderer 客户端。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript:**
    *   `SetCdmInternal` 的调用通常发生在 JavaScript 调用 `navigator.requestMediaKeySystemAccess()` 并获取到 `MediaKeys` 对象后，通过 blink 内部机制传递 CDM 对象到 C++ 层。
    *   `OnPipelineSeeked` 的结果会影响到 JavaScript 中 `video.currentTime` 属性的更新，并触发 `seeked` 事件。
    *   `OnEnded` 事件对应着 JavaScript 中 `video.onended` 事件的触发。
    *   `OnMetadata` 事件中解析出的媒体时长会更新 JavaScript 中 `video.duration` 属性，音频和视频轨信息会影响到 `videoTracks` 和 `audioTracks` API。
    *   `OnBufferingStateChange` 会影响 JavaScript 中的 `video.readyState` 属性和 `waiting` 和 `canplaythrough` 等事件的触发。
    *   页面可见性相关的函数 (`OnPageHidden`, `OnPageShown`) 对应着 Page Visibility API，浏览器的实现会调用这些 C++ 方法。
    *   `SetVolumeMultiplier` 响应 JavaScript 中设置 `video.volume` 属性的操作。
    *   `SetPoster` 响应 HTML 中 `<video>` 标签的 `poster` 属性的设置。
    *   `SetNetworkState` 和 `SetReadyState` 的改变会反映到 JavaScript 中 `video.networkState` 和 `video.readyState` 属性的变化，并触发相应的事件 (`error`, `loadedmetadata`, `canplay`, `canplaythrough` 等)。
*   **HTML:**
    *   `<video>` 和 `<audio>` 标签的属性，如 `src`、`autoplay`、`controls`、`preload`、`poster` 等，会影响 `WebMediaPlayerImpl` 的行为。例如，`preload` 属性会影响 `MultiBufferDataSourceInitialized` 中 `demuxer_manager_->SetPreload` 的设置。
    *   `<video>` 标签的 `poster` 属性对应着 `SetPoster` 函数。
*   **CSS:**
    *   CSS 可以控制视频元素的显示和隐藏，这会间接影响到 `OnPageHidden` 和 `OnPageShown` 等函数的触发。
    *   全屏模式的切换可能影响 overlay 的启用，并触发 `OnOverlayInfoRequested` 等函数。

**逻辑推理 (假设输入与输出):**

*   **假设输入:**  在页面隐藏时 (`OnPageHidden` 被调用)，且当前视频正在播放 (`!paused_`)。
*   **逻辑推理:**  会启动 `background_pause_timer_`，如果在超时时间内页面没有显示，则会触发 `OnIdleTimeout`，最终可能会导致播放器暂停 (`UpdatePlayState` 中根据页面隐藏状态判断)。
*   **输出:** 如果超时且页面未显示，播放器会进入暂停状态。

*   **假设输入:**  在播放加密视频时，`SetCdmInternal` 接收到一个有效的 CDM 对象。
*   **逻辑推理:** `is_encrypted_` 会被设置为 `true`，并且会调用 `pipeline_controller_->SetCdm` 将 CDM 对象传递给 pipeline 进行处理。
*   **输出:**  加密视频的解密流程开始，后续可能会触发 `OnWaiting` 事件等待解密密钥。

**用户或编程常见的使用错误举例:**

*   **在 JavaScript 中，在 `loadedmetadata` 事件触发前尝试访问 `video.duration`:**  此时 `WebMediaPlayerImpl` 的 `OnMetadata` 方法可能尚未执行完毕，`duration` 信息还不可靠。
*   **在 JavaScript 中，假设 `canplaythrough` 事件触发后立即调用 `play()` 就不会有缓冲:**  实际情况是，即使触发了 `canplaythrough`，网络状况变化或码率切换仍可能导致缓冲。`WebMediaPlayerImpl` 的 buffering 状态管理仍然在后台运作。
*   **在 JavaScript 中，没有正确处理 `error` 事件:**  当 `WebMediaPlayerImpl` 的 `OnError` 方法被调用时，如果没有合适的错误处理，用户可能会看到一个空白的视频播放器，而开发者无法得知具体原因。

**功能归纳:**

总而言之，`WebMediaPlayerImpl.cc` 的这第二部分代码集中处理了媒体播放器的核心生命周期管理、播放控制、状态维护以及与浏览器环境的交互。它负责处理各种事件，协调媒体 pipeline 的各个组件，并向上层 JavaScript 和 HTML 提供必要的接口和通知，确保媒体播放的稳定性和正确性，并针对特定平台 (如 Android) 提供额外的功能支持。

### 提示词
```
这是目录为blink/renderer/platform/media/web_media_player_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
: UrlData::kNormal);
  std::move(cb).Run(std::move(url_data));
}

base::SequenceBound<media::HlsDataSourceProvider>
WebMediaPlayerImpl::GetHlsDataSourceProvider() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  return base::SequenceBound<media::HlsDataSourceProviderImpl>(
      main_task_runner_,
      std::make_unique<MultiBufferDataSourceFactory>(
          media_log_.get(),
          base::BindRepeating(&WebMediaPlayerImpl::GetUrlData,
                              weak_factory_.GetWeakPtr()),
          main_task_runner_, tick_clock_));
}
#endif

void WebMediaPlayerImpl::SetCdmInternal(WebContentDecryptionModule* cdm) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK(cdm);

  const bool was_encrypted = is_encrypted_;
  is_encrypted_ = true;

  // Recreate the watch time reporter if necessary.
  if (!was_encrypted) {
    media_metrics_provider_->SetIsEME();
    if (watch_time_reporter_)
      CreateWatchTimeReporter();
  }

  WebContentDecryptionModuleImpl* web_cdm =
      ToWebContentDecryptionModuleImpl(cdm);
  auto cdm_context_ref = web_cdm->GetCdmContextRef();
  if (!cdm_context_ref) {
    NOTREACHED();
  }

  // Arrival of `cdm_config_` unblocks recording of encrypted stats. Attempt to
  // create the stats reporter. Note, we do NOT guard this within !was_encypted
  // above because often the CDM arrives after the call to
  // OnEncryptedMediaInitData().
  cdm_config_ = web_cdm->GetCdmConfig();
  DCHECK(!cdm_config_->key_system.empty());

  media_log_->SetProperty<MediaLogProperty::kSetCdm>(cdm_config_.value());

  media_metrics_provider_->SetKeySystem(cdm_config_->key_system);
  if (cdm_config_->use_hw_secure_codecs)
    media_metrics_provider_->SetIsHardwareSecure();
  CreateVideoDecodeStatsReporter();

  auto* cdm_context = cdm_context_ref->GetCdmContext();
  DCHECK(cdm_context);

  // Keep the reference to the CDM, as it shouldn't be destroyed until
  // after the pipeline is done with the `cdm_context`.
  pending_cdm_context_ref_ = std::move(cdm_context_ref);
  pipeline_controller_->SetCdm(
      cdm_context,
      base::BindOnce(&WebMediaPlayerImpl::OnCdmAttached, weak_this_));
}

void WebMediaPlayerImpl::OnCdmAttached(bool success) {
  DVLOG(1) << __func__ << ": success = " << success;
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK(pending_cdm_context_ref_);

  media_log_->SetProperty<MediaLogProperty::kIsCdmAttached>(success);

  // If the CDM is set from the constructor there is no promise
  // (`set_cdm_result_`) to fulfill.
  if (success) {
    // This will release the previously attached CDM (if any).
    cdm_context_ref_ = std::move(pending_cdm_context_ref_);
    if (set_cdm_result_) {
      set_cdm_result_->Complete();
      set_cdm_result_.reset();
    }

    return;
  }

  pending_cdm_context_ref_.reset();
  if (set_cdm_result_) {
    set_cdm_result_->CompleteWithError(
        kWebContentDecryptionModuleExceptionNotSupportedError, 0,
        "Unable to set ContentDecryptionModule object");
    set_cdm_result_.reset();
  }
}

void WebMediaPlayerImpl::OnPipelineSeeked(bool time_updated) {
  TRACE_EVENT2("media", "WebMediaPlayerImpl::OnPipelineSeeked", "target",
               seek_time_.InSecondsF(), "id", media_player_id_);
  seeking_ = false;
  seek_time_ = base::TimeDelta();

  if (paused_) {
    paused_time_ = pipeline_controller_->GetMediaTime();
  } else {
    DCHECK(watch_time_reporter_);
    watch_time_reporter_->OnPlaying();
    if (playback_events_recorder_)
      playback_events_recorder_->OnPlaying();
  }
  if (time_updated)
    should_notify_time_changed_ = true;

  // Reset underflow duration upon seek; this prevents looping videos and user
  // actions from artificially inflating the duration.
  underflow_timer_.reset();

  // Background video optimizations are delayed when shown/hidden if pipeline
  // is seeking.
  UpdateBackgroundVideoOptimizationState();

  // If we successfully completed a suspended startup, we need to make a call to
  // UpdatePlayState() in case any events which should trigger a resume have
  // occurred during startup.
  if (attempting_suspended_start_ &&
      pipeline_controller_->IsPipelineSuspended()) {
    skip_metrics_due_to_startup_suspend_ = true;

    // If we successfully completed a suspended startup, signal that we have
    // reached BUFFERING_HAVE_ENOUGH so that canplay and canplaythrough fire
    // correctly. We must unfortunately always do this because it's valid for
    // elements to play while not visible nor even in the DOM.
    //
    // Note: This call is dual purpose, it is also responsible for triggering an
    // UpdatePlayState() call which may need to resume the pipeline once Blink
    // has been told about the ReadyState change.
    OnBufferingStateChangeInternal(media::BUFFERING_HAVE_ENOUGH,
                                   media::BUFFERING_CHANGE_REASON_UNKNOWN,
                                   true);
  }

  attempting_suspended_start_ = false;
}

void WebMediaPlayerImpl::OnPipelineStarted(media::PipelineStatus status) {
  media_metrics_provider_->OnStarted(status);
}

void WebMediaPlayerImpl::OnPipelineSuspended() {
  // Add a log event so the player shows up as "SUSPENDED" in media-internals.
  media_log_->AddEvent<MediaLogEvent::kSuspended>();

  pending_oneshot_suspend_ = false;

  if (attempting_suspended_start_) {
    DCHECK(pipeline_controller_->IsSuspended());
    did_lazy_load_ = !has_poster_ && HasVideo();
  }

  // Tell the data source we have enough data so that it may release the
  // connection (unless blink is waiting on us to signal play()).
  if (demuxer_manager_->HasDataSource() && !CouldPlayIfEnoughData()) {
    // `attempting_suspended_start_` will be cleared by OnPipelineSeeked() which
    // will occur after this method during a suspended startup.
    if (attempting_suspended_start_ && did_lazy_load_) {
      DCHECK(!has_first_frame_);
      DCHECK(have_enough_after_lazy_load_cb_.IsCancelled());

      // For lazy load, we won't know if the element is non-visible until a
      // layout completes, so to avoid unnecessarily tearing down the network
      // connection, briefly (250ms chosen arbitrarily) delay signaling "have
      // enough" to the MultiBufferDataSource.
      //
      // base::Unretained() is safe here since the base::CancelableOnceClosure
      // will cancel upon destruction of this class and `demuxer_manager_` is
      // gauranteeed to outlive us as a result of the DestructionHelper.
      have_enough_after_lazy_load_cb_.Reset(
          base::BindOnce(&media::DemuxerManager::OnBufferingHaveEnough,
                         base::Unretained(demuxer_manager_.get()), true));
      main_task_runner_->PostDelayedTask(
          FROM_HERE, have_enough_after_lazy_load_cb_.callback(),
          base::Milliseconds(250));
    } else {
      have_enough_after_lazy_load_cb_.Cancel();
      demuxer_manager_->OnBufferingHaveEnough(true);
    }
  }

  ReportMemoryUsage();

  if (pending_suspend_resume_cycle_) {
    pending_suspend_resume_cycle_ = false;
    UpdatePlayState();
  }
}

void WebMediaPlayerImpl::OnBeforePipelineResume() {
  // Since we're resuming, cancel closing of the network connection.
  have_enough_after_lazy_load_cb_.Cancel();

  // We went through suspended startup, so the player is only just now spooling
  // up for playback. As such adjust `load_start_time_` so it reports the same
  // metric as what would be reported if we had not suspended at startup.
  if (skip_metrics_due_to_startup_suspend_) {
    // In the event that the call to SetReadyState() initiated after pipeline
    // startup immediately tries to start playback, we should not update
    // `load_start_time_` to avoid losing visibility into the impact of a
    // suspended startup on the time until first frame / play ready for cases
    // where suspended startup was applied incorrectly.
    if (!attempting_suspended_start_)
      load_start_time_ = base::TimeTicks::Now() - time_to_metadata_;
    skip_metrics_due_to_startup_suspend_ = false;
  }

  // Enable video track if we disabled it in the background - this way the new
  // renderer will attach its callbacks to the video stream properly.
  // TODO(avayvod): Remove this when disabling and enabling video tracks in
  // non-playing state works correctly. See https://crbug.com/678374.
  EnableVideoTrackIfNeeded();
  is_pipeline_resuming_ = true;
}

void WebMediaPlayerImpl::OnPipelineResumed() {
  is_pipeline_resuming_ = false;

  UpdateBackgroundVideoOptimizationState();
}

void WebMediaPlayerImpl::OnChunkDemuxerOpened(media::ChunkDemuxer* demuxer) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  client_->MediaSourceOpened(std::make_unique<WebMediaSourceImpl>(demuxer));
}

void WebMediaPlayerImpl::OnFallback(media::PipelineStatus status) {
  media_metrics_provider_->OnFallback(std::move(status).AddHere());
}

void WebMediaPlayerImpl::StopForDemuxerReset() {
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK(pipeline_controller_);
  pipeline_controller_->Stop();

  // delete the thread dumper on the media thread.
  media_task_runner_->DeleteSoon(FROM_HERE,
                                 std::move(media_thread_mem_dumper_));
}

bool WebMediaPlayerImpl::IsSecurityOriginCryptographic() const {
  return url::Origin(frame_->GetSecurityOrigin())
      .GetURL()
      .SchemeIsCryptographic();
}

void WebMediaPlayerImpl::UpdateLoadedUrl(const GURL& url) {
  demuxer_manager_->SetLoadedUrl(url);
}

void WebMediaPlayerImpl::DemuxerRequestsSeek(base::TimeDelta seek_time) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DoSeek(seek_time, true);
}

void WebMediaPlayerImpl::RestartForHls() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  observer_->OnHlsManifestDetected();

  // Use the media player renderer if the native hls demuxer isn't compiled in
  // or if the feature is disabled.
#if BUILDFLAG(ENABLE_HLS_DEMUXER)
  if (!base::FeatureList::IsEnabled(media::kBuiltInHlsPlayer)) {
    renderer_factory_selector_->SetBaseRendererType(
        media::RendererType::kMediaPlayer);
  }
#elif BUILDFLAG(IS_ANDROID)
  renderer_factory_selector_->SetBaseRendererType(
      media::RendererType::kMediaPlayer);
#else
  // Shouldn't be reachable from desktop where hls is not enabled.
  NOTREACHED();
#endif

#if BUILDFLAG(ENABLE_HLS_DEMUXER) || BUILDFLAG(IS_ANDROID)
  SetMemoryReportingState(false);
  StartPipeline();
#endif
}

void WebMediaPlayerImpl::OnError(media::PipelineStatus status) {
  DVLOG(1) << __func__ << ": status=" << status;
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK(status != media::PIPELINE_OK);

  if (suppress_destruction_errors_)
    return;

#if BUILDFLAG(IS_WIN)
  // Hardware context reset is not an error. Restart to recover.
  // TODO(crbug.com/1208618): Find a way to break the potential infinite loop of
  // restart -> PIPELINE_ERROR_HARDWARE_CONTEXT_RESET -> restart.
  if (status == media::PIPELINE_ERROR_HARDWARE_CONTEXT_RESET) {
    ScheduleRestart();
    return;
  }
#endif  // BUILDFLAG(IS_WIN)

  MaybeSetContainerNameForMetrics();
  simple_watch_timer_.Stop();
  media_log_->NotifyError(status);
  media_metrics_provider_->OnError(status);
  if (playback_events_recorder_)
    playback_events_recorder_->OnError(status);
  if (watch_time_reporter_)
    watch_time_reporter_->OnError(status);

  if (ready_state_ == WebMediaPlayer::kReadyStateHaveNothing) {
    // Any error that occurs before reaching ReadyStateHaveMetadata should
    // be considered a format error.
    SetNetworkState(WebMediaPlayer::kNetworkStateFormatError);
  } else {
    SetNetworkState(PipelineErrorToNetworkState(status.code()));
  }

  // PipelineController::Stop() is idempotent.
  pipeline_controller_->Stop();

  UpdatePlayState();
}

void WebMediaPlayerImpl::OnEnded() {
  TRACE_EVENT2("media", "WebMediaPlayerImpl::OnEnded", "duration", Duration(),
               "id", media_player_id_);
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // Ignore state changes until we've completed all outstanding operations.
  if (!pipeline_controller_->IsStable())
    return;

  ended_ = true;
  if (!paused_) {
    client_->TimeChanged();
  }

  if (playback_events_recorder_)
    playback_events_recorder_->OnEnded();

  // We don't actually want this to run until `client_` calls seek() or pause(),
  // but that should have already happened in timeChanged() and so this is
  // expected to be a no-op.
  UpdatePlayState();
}

void WebMediaPlayerImpl::OnMetadata(const media::PipelineMetadata& metadata) {
  DVLOG(1) << __func__;
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // Cache the `time_to_metadata_` to use for adjusting the TimeToFirstFrame and
  // TimeToPlayReady metrics later if we end up doing a suspended startup.
  time_to_metadata_ = base::TimeTicks::Now() - load_start_time_;
  media_metrics_provider_->SetTimeToMetadata(time_to_metadata_);
  WriteSplitHistogram<kPlaybackType | kEncrypted>(
      &base::UmaHistogramMediumTimes, SplitHistogramName::kTimeToMetadata,
      time_to_metadata_);

  MaybeSetContainerNameForMetrics();

  pipeline_metadata_ = metadata;
  if (power_status_helper_)
    power_status_helper_->SetMetadata(metadata);

  if (HasAudio()) {
    media_metrics_provider_->SetHasAudio(metadata.audio_decoder_config.codec());
    RecordEncryptionScheme("Audio",
                           metadata.audio_decoder_config.encryption_scheme());
  }

  if (HasVideo()) {
    media_metrics_provider_->SetHasVideo(metadata.video_decoder_config.codec());
    RecordEncryptionScheme("Video",
                           metadata.video_decoder_config.encryption_scheme());

    if (overlay_enabled_) {
      // SurfaceView doesn't support rotated video, so transition back if
      // the video is now rotated.  If `always_enable_overlays_`, we keep the
      // overlay anyway so that the state machine keeps working.
      // TODO(liberato): verify if compositor feedback catches this.  If so,
      // then we don't need this check.
      if (!always_enable_overlays_ && !DoesOverlaySupportMetadata())
        DisableOverlay();
    }

    if (use_surface_layer_) {
      ActivateSurfaceLayerForVideo();
    } else {
      DCHECK(!video_layer_);
      video_layer_ = cc::VideoLayer::Create(
          compositor_.get(),
          pipeline_metadata_.video_decoder_config.video_transformation());
      video_layer_->SetContentsOpaque(opaque_);
      client_->SetCcLayer(video_layer_.get());
    }
  }

  if (observer_)
    observer_->OnMetadataChanged(pipeline_metadata_);

  delegate_has_audio_ = HasUnmutedAudio();
  DidMediaMetadataChange();

  // It could happen that the demuxer successfully completed initialization
  // (implying it had determined media metadata), but then removed all audio and
  // video streams and the ability to demux any A/V before `metadata` was
  // constructed and passed to us. One example is, with MSE-in-Workers, the
  // worker owning the MediaSource could have been terminated, or the app could
  // have explicitly removed all A/V SourceBuffers. That termination/removal
  // could race the construction of `metadata`. Regardless of load-type, we
  // shouldn't allow playback of a resource that has neither audio nor video.
  // We treat lack of A/V as if there were an error in the demuxer before
  // reaching HAVE_METADATA.
  if (!HasVideo() && !HasAudio()) {
    DVLOG(1) << __func__ << ": no audio and no video -> error";
    OnError(media::DEMUXER_ERROR_COULD_NOT_OPEN);
    return;  // Do not transition to HAVE_METADATA.
  }

  // TODO(dalecurtis): Don't create these until kReadyStateHaveFutureData; when
  // we create them early we just increase the chances of needing to throw them
  // away unnecessarily.
  CreateWatchTimeReporter();
  CreateVideoDecodeStatsReporter();

  // SetReadyState() may trigger all sorts of calls into this class (e.g.,
  // Play(), Pause(), etc) so do it last to avoid unexpected states during the
  // calls. An exception to this is UpdatePlayState(), which is safe to call and
  // needs to use the new ReadyState in its calculations.
  SetReadyState(WebMediaPlayer::kReadyStateHaveMetadata);
  UpdatePlayState();
}

void WebMediaPlayerImpl::ActivateSurfaceLayerForVideo() {
  // Note that we might or might not already be in VideoLayer mode.
  if (surface_layer_for_video_enabled_) {
    // Surface layer has already been activated.
    return;
  }

  surface_layer_for_video_enabled_ = true;

  // If we're in VideoLayer mode, then get rid of the layer.
  if (video_layer_) {
    client_->SetCcLayer(nullptr);
    video_layer_ = nullptr;
  }

  bridge_ = std::move(create_bridge_callback_)
                .Run(this, compositor_->GetUpdateSubmissionStateCallback());
  bridge_->CreateSurfaceLayer();

  // TODO(tmathmeyer) does this need support for the reflection transformation
  // as well?
  vfc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &VideoFrameCompositor::EnableSubmission,
          base::Unretained(compositor_.get()), bridge_->GetSurfaceId(),
          pipeline_metadata_.video_decoder_config.video_transformation(),
          IsInPictureInPicture()));
  bridge_->SetContentsOpaque(opaque_);

  // If the element is already in Picture-in-Picture mode, it means that it
  // was set in this mode prior to this load, with a different
  // WebMediaPlayerImpl. The new player needs to send its id, size and
  // surface id to the browser process to make sure the states are properly
  // updated.
  // TODO(872056): the surface should be activated but for some reasons, it
  // does not. It is possible that this will no longer be needed after 872056
  // is fixed.
  if (IsInPictureInPicture())
    OnSurfaceIdUpdated(bridge_->GetSurfaceId());
}

void WebMediaPlayerImpl::OnBufferingStateChange(
    media::BufferingState state,
    media::BufferingStateChangeReason reason) {
  OnBufferingStateChangeInternal(state, reason, false);
}

void WebMediaPlayerImpl::CreateVideoDecodeStatsReporter() {
  // TODO(chcunningham): destroy reporter if we initially have video but the
  // track gets disabled. Currently not possible in default desktop Chrome.
  if (!HasVideo())
    return;

  // Only record stats from the local pipeline.
  if (is_flinging_ || is_remote_rendering_ || using_media_player_renderer_)
    return;

  // Stats reporter requires a valid config. We may not have one for HLS cases
  // where URL demuxer doesn't know details of the stream.
  if (!pipeline_metadata_.video_decoder_config.IsValidConfig())
    return;

  // Profile must be known for use as index to save the reported stats.
  if (pipeline_metadata_.video_decoder_config.profile() ==
      media::VIDEO_CODEC_PROFILE_UNKNOWN) {
    return;
  }

  // CdmConfig must be provided for use as index to save encrypted stats.
  if (is_encrypted_ && !cdm_config_) {
    return;
  } else if (cdm_config_) {
    DCHECK(!cdm_config_->key_system.empty());
  }

  mojo::PendingRemote<media::mojom::VideoDecodeStatsRecorder> recorder;
  media_metrics_provider_->AcquireVideoDecodeStatsRecorder(
      recorder.InitWithNewPipeAndPassReceiver());

  // Create capabilities reporter and synchronize its initial state.
  video_decode_stats_reporter_ = std::make_unique<VideoDecodeStatsReporter>(
      std::move(recorder),
      base::BindRepeating(&WebMediaPlayerImpl::GetPipelineStatistics,
                          base::Unretained(this)),
      pipeline_metadata_.video_decoder_config.profile(),
      pipeline_metadata_.natural_size, cdm_config_,
      frame_->GetTaskRunner(TaskType::kInternalMedia));

  if (delegate_->IsPageHidden()) {
    video_decode_stats_reporter_->OnHidden();
  } else {
    video_decode_stats_reporter_->OnShown();
  }

  if (paused_)
    video_decode_stats_reporter_->OnPaused();
  else
    video_decode_stats_reporter_->OnPlaying();
}

void WebMediaPlayerImpl::OnProgress() {
  DVLOG(4) << __func__;

  // See IsPrerollAttemptNeeded() for more details. We can't use that method
  // here since it considers `preroll_attempt_start_time_` and for OnProgress()
  // events we must make the attempt -- since there may not be another event.
  if (highest_ready_state_ < ReadyState::kReadyStateHaveFutureData) {
    // Reset the preroll attempt clock.
    preroll_attempt_pending_ = true;
    preroll_attempt_start_time_ = base::TimeTicks();

    // Clear any 'stale' flag and give the pipeline a chance to resume. If we
    // are already resumed, this will cause `preroll_attempt_start_time_` to
    // be set.
    delegate_->ClearStaleFlag(delegate_id_);
    UpdatePlayState();
  } else if (ready_state_ == ReadyState::kReadyStateHaveFutureData &&
             CanPlayThrough()) {
    SetReadyState(WebMediaPlayer::kReadyStateHaveEnoughData);
  }
}

bool WebMediaPlayerImpl::CanPlayThrough() {
  if (!base::FeatureList::IsEnabled(media::kSpecCompliantCanPlayThrough))
    return true;
  if (GetDemuxerType() == media::DemuxerType::kChunkDemuxer)
    return true;
  if (demuxer_manager_->DataSourceFullyBuffered()) {
    return true;
  }
  // If we're not currently downloading, we have as much buffer as
  // we're ever going to get, which means we say we can play through.
  if (network_state_ == WebMediaPlayer::kNetworkStateIdle)
    return true;
  return buffered_data_source_host_->CanPlayThrough(
      base::Seconds(CurrentTime()), base::Seconds(Duration()),
      playback_rate_ == 0.0 ? 1.0 : playback_rate_);
}

void WebMediaPlayerImpl::OnBufferingStateChangeInternal(
    media::BufferingState state,
    media::BufferingStateChangeReason reason,
    bool for_suspended_start) {
  DVLOG(1) << __func__ << "(" << state << ", " << reason << ")";
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  // Ignore buffering state changes caused by back-to-back seeking, so as not
  // to assume the second seek has finished when it was only the first seek.
  if (pipeline_controller_->IsPendingSeek())
    return;

  media_log_->AddEvent<MediaLogEvent::kBufferingStateChanged>(
      media::SerializableBufferingState<
          media::SerializableBufferingStateType::kPipeline>{
          state, reason, for_suspended_start});

  if (state == media::BUFFERING_HAVE_ENOUGH && !for_suspended_start)
    media_metrics_provider_->SetHaveEnough();

  if (state == media::BUFFERING_HAVE_ENOUGH) {
    TRACE_EVENT1("media", "WebMediaPlayerImpl::BufferingHaveEnough", "id",
                 media_player_id_);
    // The SetReadyState() call below may clear
    // `skip_metrics_due_to_startup_suspend_` so report this first.
    if (!have_reported_time_to_play_ready_ &&
        !skip_metrics_due_to_startup_suspend_) {
      DCHECK(!for_suspended_start);
      have_reported_time_to_play_ready_ = true;
      const base::TimeDelta elapsed = base::TimeTicks::Now() - load_start_time_;
      media_metrics_provider_->SetTimeToPlayReady(elapsed);
      WriteSplitHistogram<kPlaybackType | kEncrypted>(
          &base::UmaHistogramMediumTimes, SplitHistogramName::kTimeToPlayReady,
          elapsed);
    }

    // Warning: This call may be re-entrant.
    SetReadyState(CanPlayThrough() ? WebMediaPlayer::kReadyStateHaveEnoughData
                                   : WebMediaPlayer::kReadyStateHaveFutureData);

    // Let the DataSource know we have enough data -- this is the only function
    // during which we advance to (or past) the kReadyStateHaveEnoughData state.
    // It may use this information to update buffer sizes or release unused
    // network connections.
    MaybeUpdateBufferSizesForPlayback();
    if (demuxer_manager_->HasDataSource() && !CouldPlayIfEnoughData()) {
      // For LazyLoad this will be handled during OnPipelineSuspended().
      if (for_suspended_start && did_lazy_load_)
        DCHECK(!have_enough_after_lazy_load_cb_.IsCancelled());
      else
        demuxer_manager_->OnBufferingHaveEnough(false);
    }

    // Blink expects a timeChanged() in response to a seek().
    if (should_notify_time_changed_) {
      should_notify_time_changed_ = false;
      client_->TimeChanged();
    }

    // Once we have enough, start reporting the total memory usage. We'll also
    // report once playback starts.
    ReportMemoryUsage();

    // Report the amount of time it took to leave the underflow state.
    if (underflow_timer_) {
      auto elapsed = underflow_timer_->Elapsed();
      RecordUnderflowDuration(elapsed);
      watch_time_reporter_->OnUnderflowComplete(elapsed);
      underflow_timer_.reset();
    }

    if (playback_events_recorder_)
      playback_events_recorder_->OnBufferingComplete();
  } else {
    // Buffering has underflowed.
    DCHECK_EQ(state, media::BUFFERING_HAVE_NOTHING);

    // Report the number of times we've entered the underflow state. Ensure we
    // only report the value when transitioning from HAVE_ENOUGH to
    // HAVE_NOTHING.
    if (ready_state_ == WebMediaPlayer::kReadyStateHaveEnoughData &&
        !seeking_) {
      underflow_timer_ = std::make_unique<base::ElapsedTimer>();
      watch_time_reporter_->OnUnderflow();

      if (playback_events_recorder_)
        playback_events_recorder_->OnBuffering();
    }

    // It shouldn't be possible to underflow if we've not advanced past
    // HAVE_CURRENT_DATA.
    DCHECK_GT(highest_ready_state_, WebMediaPlayer::kReadyStateHaveCurrentData);
    SetReadyState(WebMediaPlayer::kReadyStateHaveCurrentData);
  }

  // If this is an NNR, then notify the smoothness helper about it.  Note that
  // it's unclear what we should do if there is no smoothness helper yet.  As it
  // is, we just discard the NNR.
  if (state == media::BUFFERING_HAVE_NOTHING &&
      reason == media::DECODER_UNDERFLOW && smoothness_helper_) {
    smoothness_helper_->NotifyNNR();
  }

  UpdatePlayState();
}

void WebMediaPlayerImpl::OnDurationChange() {
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  if (ready_state_ == WebMediaPlayer::kReadyStateHaveNothing)
    return;

  client_->DurationChanged();
  DidMediaMetadataChange();
  demuxer_manager_->DurationChanged();

  if (watch_time_reporter_)
    watch_time_reporter_->OnDurationChanged(GetPipelineMediaDuration());
}

void WebMediaPlayerImpl::OnWaiting(media::WaitingReason reason) {
  DVLOG(2) << __func__ << ": reason=" << static_cast<int>(reason);
  DCHECK(main_task_runner_->BelongsToCurrentThread());

  switch (reason) {
    case media::WaitingReason::kNoCdm:
    case media::WaitingReason::kNoDecryptionKey:
      has_waiting_for_key_ = true;
      media_metrics_provider_->SetHasWaitingForKey();
      encrypted_client_->DidBlockPlaybackWaitingForKey();
      // TODO(jrummell): didResumePlaybackBlockedForKey() should only be called
      // when a key has been successfully added (e.g. OnSessionKeysChange() with
      // `has_additional_usable_key` = true). http://crbug.com/461903
      encrypted_client_->DidResumePlaybackBlockedForKey();
      return;

    // Ideally this should be handled by PipelineController directly without
    // being proxied here. But currently Pipeline::Client (`this`) is passed to
    // PipelineImpl directly without going through `pipeline_controller_`,
    // making it difficult to do.
    // TODO(xhwang): Handle this in PipelineController when we have a clearer
    // picture on how to refactor WebMediaPlayerImpl, PipelineController and
    // PipelineImpl.
    case media::WaitingReason::kDecoderStateLost:
      pipeline_controller_->OnDecoderStateLost();
      return;

    // On Android, it happens when the surface used by the decoder is destroyed,
    // e.g. background. We want to suspend the pipeline and hope the surface
    // will be available when resuming the pipeline by some other signals.
    case media::WaitingReason::kSecureSurfaceLost:
      if (!pipeline_controller_->IsSuspended() && !pending_oneshot_suspend_) {
        pending_oneshot_suspend_ = true;
        UpdatePlayState();
      }
      return;
  }
}

void WebMediaPlayerImpl::OnVideoNaturalSizeChange(const gfx::Size& size) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK_NE(ready_state_, WebMediaPlayer::kReadyStateHaveNothing);

  TRACE_EVENT0("media", "WebMediaPlayerImpl::OnVideoNaturalSizeChange");

  // The input `size` is from the decoded video frame, which is the original
  // natural size and need to be rotated accordingly.
  gfx::Size rotated_size = GetRotatedVideoSize(
      pipeline_metadata_.video_decoder_config.video_transformation().rotation,
      size);

  RecordVideoNaturalSize(rotated_size);

  gfx::Size old_size = pipeline_metadata_.natural_size;
  if (rotated_size == old_size)
    return;

  pipeline_metadata_.natural_size = rotated_size;

  if (using_media_player_renderer_ && old_size.IsEmpty()) {
    // If we are using MediaPlayerRenderer and this is the first size change, we
    // now know that there is a video track. This condition is paired with code
    // in CreateWatchTimeReporter() that guesses the existence of a video track.
    CreateWatchTimeReporter();
  } else {
    UpdateSecondaryProperties();
  }

  if (video_decode_stats_reporter_ &&
      !video_decode_stats_reporter_->MatchesBucketedNaturalSize(
          pipeline_metadata_.natural_size)) {
    CreateVideoDecodeStatsReporter();
  }

  // Create or replace the smoothness helper now that we have a size.
  UpdateSmoothnessHelper();

  client_->SizeChanged();

  if (observer_)
    observer_->OnMetadataChanged(pipeline_metadata_);

  client_->DidPlayerSizeChange(NaturalSize());
}

void WebMediaPlayerImpl::OnVideoOpacityChange(bool opaque) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK_NE(ready_state_, WebMediaPlayer::kReadyStateHaveNothing);

  opaque_ = opaque;
  if (!surface_layer_for_video_enabled_ && video_layer_)
    video_layer_->SetContentsOpaque(opaque_);
  else if (bridge_->GetCcLayer())
    bridge_->SetContentsOpaque(opaque_);
}

void WebMediaPlayerImpl::OnVideoFrameRateChange(std::optional<int> fps) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  if (power_status_helper_)
    power_status_helper_->SetAverageFrameRate(fps);

  last_reported_fps_ = fps;
  UpdateSmoothnessHelper();
}

void WebMediaPlayerImpl::OnAudioConfigChange(
    const media::AudioDecoderConfig& config) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK_NE(ready_state_, WebMediaPlayer::kReadyStateHaveNothing);

  const bool codec_change =
      pipeline_metadata_.audio_decoder_config.codec() != config.codec();
  const bool codec_profile_change =
      pipeline_metadata_.audio_decoder_config.profile() != config.profile();

  pipeline_metadata_.audio_decoder_config = config;

  if (observer_)
    observer_->OnMetadataChanged(pipeline_metadata_);

  if (codec_change) {
    media_metrics_provider_->SetHasAudio(
        pipeline_metadata_.audio_decoder_config.codec());
  }

  if (codec_change || codec_profile_change)
    UpdateSecondaryProperties();
}

void WebMediaPlayerImpl::OnVideoConfigChange(
    const media::VideoDecoderConfig& config) {
  DCHECK(main_task_runner_->BelongsToCurrentThread());
  DCHECK_NE(ready_state_, WebMediaPlayer::kReadyStateHaveNothing);

  const bool codec_change =
      pipeline_metadata_.video_decoder_config.codec() != config.codec();
  const bool codec_profile_change =
      pipeline_metadata_.video_decoder_config.profile() != config.profile();

  pipeline_metadata_.video_decoder_config = config;

  if (observer_)
    observer_->OnMetadataChanged(pipeline_metadata_);

  if (codec_change) {
    media_metrics_provider_->SetHasVideo(
        pipeline_metadata_.video_decoder_config.codec());
  }

  if (codec_change || codec_profile_change)
    UpdateSecondaryProperties();

  if (video_decode_stats_reporter_ && codec_profile_change)
    CreateVideoDecodeStatsReporter();
}

void WebMediaPlayerImpl::OnVideoAverageKeyframeDistanceUpdate() {
  UpdateBackgroundVideoOptimizationState();
}

void WebMediaPlayerImpl::OnAudioPipelineInfoChange(
    const media::AudioPipelineInfo& info) {
  media_metrics_provider_->SetAudioPipelineInfo(info);
  if (info.decoder_type == audio_decoder_type_)
    return;

  audio_decoder_type_ = info.decoder_type;

  // If there's no current reporter, there's nothing to be done.
  if (!watch_time_reporter_)
    return;

  UpdateSecondaryProperties();
}

void WebMediaPlayerImpl::OnVideoPipelineInfoChange(
    const media::VideoPipelineInfo& info) {
  media_metrics_provider_->SetVideoPipelineInfo(info);
  if (info.decoder_type == video_decoder_type_)
    return;

  video_decoder_type_ = info.decoder_type;

  // If there's no current reporter, there's nothing to be done.
  if (!watch_time_reporter_)
    return;

  UpdateSecondaryProperties();
}

void WebMediaPlayerImpl::OnPageHidden() {
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
```