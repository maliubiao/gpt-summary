Response:
The user wants to understand the functionality of the `HTMLMediaElement.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet and:

1. **List its functionalities:** Identify the key actions and processes implemented in the code.
2. **Explain its relationship with Javascript, HTML, and CSS:** Provide examples of how the code interacts with these web technologies.
3. **Provide logical reasoning with examples:** Illustrate the code's behavior with hypothetical inputs and outputs.
4. **Highlight common usage errors:** Point out potential mistakes developers might make when using the related APIs.
5. **Summarize its overall purpose:**  Concisely describe the file's role within the Blink engine, specifically for this final part of the analysis.

**Functionality Breakdown:**

- **Track Management:** Creating and managing audio and video tracks.
- **Network State Handling:** Setting and tracking the network state of the media element (e.g., idle, loading, loaded).
- **Play Promise Management:** Handling the promises returned by the `play()` method, including resolving and rejecting them based on various conditions.
- **Event Scheduling:** Scheduling media-related events like "playing".
- **Audio Source Providing:**  Implementing an interface for providing audio data to Web Audio API.
- **Media Controls:** Interacting with and updating media controls.
- **Autoplay Policy Enforcement:** Managing autoplay behavior.
- **Playback Control:**  Providing methods for playing, pausing, seeking, and muting media.
- **Remote Playback:** Handling communication and state related to remote playback devices.
- **Error Handling:** Setting and managing media errors.
- **Metadata Handling:** Processing and distributing media metadata changes (audio/video codecs, content type, encryption).
- **Media Player Observation:** Notifying observers about media player state changes.
- **Power Management:** Managing power consumption related to media playback.
- **Audio Output Sink Selection:** Setting the audio output device.
- **Frame Lifecycle Management:** Handling media playback when the associated frame is closed.
- **Opacity Management:** Determining if the media element should be opaque.
- **Media Source Integration:** Interacting with Media Source Extensions.
- **Fullscreen Handling:**  Tracking fullscreen state.
- **Color Space Management:** Getting the target color space.

**Relationships with Javascript, HTML, and CSS:**

- **Javascript:**  Many functions in this file are directly called or interact with Javascript APIs like `play()`, `pause()`, `currentTime`, `muted`, and event listeners for "playing", "pause", etc. Play promises are a Javascript concept. The integration with Web Audio API is also relevant.
- **HTML:** This code is responsible for the behavior of HTML media elements (`<video>` and `<audio>`). It manages the internal state and logic triggered by HTML attributes and user interactions with these elements.
- **CSS:** While this file doesn't directly manipulate CSS, its functionality can influence the visual presentation of media elements, for example, by indicating when a video is ready to be displayed or if it's in fullscreen.

**Logical Reasoning:**

- **Assumption:** A user calls `play()` on a video element.
- **Input:** `play()` is called.
- **Process:** `ScheduleResolvePlayPromises()` will be called to manage the promise associated with the `play()` call. If the video starts playing successfully, `ScheduleNotifyPlaying()` is called, which eventually leads to resolving the play promise.
- **Output:** The play promise resolves in Javascript, allowing the script to proceed.

- **Assumption:**  Media loading fails.
- **Input:** A network error occurs during media loading.
- **Process:** `SetNetworkState()` is called with an error state. `ScheduleRejectPlayPromises()` might be called with an appropriate error code.
- **Output:** The play promise associated with the media loading (if any) will be rejected in Javascript with an error message.

**Common Usage Errors:**

- **Calling `play()` without user interaction in certain contexts:** Browsers often block autoplay without user interaction to prevent unwanted noise or resource usage. This can lead to the play promise being rejected. The code manages these autoplay policies.
- **Not handling play promise rejections:** If a `play()` call fails, the promise will be rejected. If the Javascript code doesn't handle this rejection, it might lead to unhandled promise rejections and unexpected behavior. The code here sets up the rejection mechanism.
- **Incorrectly managing audio output devices:**  Setting an invalid `sinkId` might lead to audio playback issues. The code provides the mechanism to set the audio sink ID.

**Overall Purpose (Part 6):**

This final part of `html_media_element.cc` focuses on **integrating with various browser subsystems and external components** to provide the full functionality of HTML media elements. It handles interactions with the network layer, the rendering engine (for drawing to canvas), the Web Audio API, remote playback devices, and media session management. It also manages the lifecycle of play promises and handles various error scenarios. Essentially, it's responsible for the advanced features and connections beyond basic media playback.
好的，根据提供的代码片段，以下是`HTMLMediaElement.cc`文件（第6部分）的功能归纳，并结合 JavaScript、HTML 和 CSS 的关系进行举例说明，同时包含逻辑推理和常见使用错误的例子：

**功能归纳 (第6部分):**

这部分代码主要负责 `HTMLMediaElement` 与浏览器其他子系统以及外部组件的集成和交互，以实现更高级和完善的媒体功能。具体包括：

1. **与媒体播放器Host的通信:**  通过 `media::mojom::blink::MediaPlayerHost` 接口与底层的媒体播放器进行通信，请求播放、暂停、seek 等操作。
2. **媒体播放器状态的监听与通知:**  实现 `media::mojom::blink::MediaPlayerObserver` 接口，监听底层媒体播放器的状态变化（播放、暂停、静音、元数据变化、位置变化、大小变化等），并通过回调通知上层。
3. **请求用户操作相关的播放/暂停:** 提供 `RequestPlay()` 和 `RequestPause()` 方法，并在用户触发时通知框架进行用户激活，以满足浏览器的自动播放策略要求。
4. **提供 seek 功能:**  提供 `RequestSeekForward()`, `RequestSeekBackward()`, `RequestSeekTo()` 方法来控制媒体的跳转。
5. **控制静音状态:** 提供 `RequestMute()` 方法来设置媒体的静音状态。
6. **设置音量倍数:** 提供 `SetVolumeMultiplier()` 方法来调整媒体的音量倍数。
7. **实验性电源状态设置:** 提供 `SetPowerExperimentState()` 方法用于设置实验性的电源管理状态。
8. **设置音频输出设备:** 提供 `SetAudioSinkId()` 方法来指定音频输出设备。
9. **处理帧关闭时的暂停:** 提供 `SuspendForFrameClosed()` 方法处理关联帧关闭时的媒体暂停逻辑。
10. **管理媒体元素的透明度:**  `MediaShouldBeOpaque()` 方法判断媒体元素是否应该是opaque的，这与跨域资源加载和预加载状态有关。
11. **设置和报告错误:** 提供 `SetError()` 方法来设置媒体错误对象，并在发生错误时通知 Media Source Extension。
12. **向 Media Source 报告当前时间:** `ReportCurrentTimeToMediaSource()` 用于在 Media Source Extensions 的场景下同步媒体元素的当前时间。
13. **处理远程播放元数据变更:** `OnRemotePlaybackMetadataChange()` 处理远程播放相关的元数据变化，并通知 `remote_playback_client_` 和观察者。
14. **获取当前激活的 Presentation ID:** `GetActivePresentationId()` 用于获取当前激活的远程演示会话的 ID。
15. **处理 opener 上下文的销毁:** `OpenerContextObserver` 用于监听创建该媒体元素的 opener 上下文是否被销毁，并在销毁时触发 `AttachToNewFrame()`。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **JavaScript:**
    *   当 JavaScript 调用 `videoElement.play()` 时，会最终触发 `HTMLMediaElement::RequestPlay()` 方法。
    *   通过 JavaScript 可以监听 `HTMLMediaElement` 的 `playing` 事件，而 `ScheduleNotifyPlaying()` 方法会调度这个事件的触发。
    *   JavaScript 可以调用 `videoElement.currentTime = 10;` 来设置播放时间，这会间接调用 `HTMLMediaElement::setCurrentTime()`，进而可能触发底层的 seek 操作。
    *   通过 Web Audio API，JavaScript 可以获取 `HTMLMediaElement` 的音频源，而 `AudioSourceProviderImpl` 提供了将媒体元素的音频数据传递给 Web Audio API 的机制。
*   **HTML:**
    *   `<video>` 和 `<audio>` 标签在 HTML 中创建了 `HTMLMediaElement` 的实例。
    *   HTML 属性如 `autoplay` 会影响 `autoplay_policy_` 的行为，进而影响 `HTMLMediaElement` 的播放逻辑。
    *   HTML 中的 `controls` 属性会影响 `HasNativeControls()` 的返回值，从而决定是否显示原生的媒体控件。
*   **CSS:**
    *   CSS 可以控制媒体元素的样式，例如大小、位置等。虽然这个文件不直接操作 CSS，但 `GetDisplayType()` 方法会影响媒体元素在全屏状态下的显示方式。
    *   `MediaShouldBeOpaque()` 的返回值可能会影响渲染引擎如何绘制媒体元素，间接影响 CSS 的 `opacity` 属性效果。

**逻辑推理与假设输入输出:**

假设用户在一个视频元素上点击了播放按钮：

*   **假设输入:** 用户点击播放按钮。
*   **推理过程:** 浏览器接收到用户交互，JavaScript 可能会调用 `videoElement.play()`。Blink 引擎内部会调用 `HTMLMediaElement::RequestPlay()`。此方法会通知框架用户已激活，然后调用 `PlayInternal()` 启动播放流程。如果播放成功，底层媒体播放器会回调 `DidPlayerStartPlaying()`，进而通知观察者和触发 `playing` 事件。
*   **预期输出:** 视频开始播放，JavaScript 中 `play()` 返回的 Promise 被 resolve，并且触发 `playing` 事件。

假设由于网络问题，视频加载失败：

*   **假设输入:** 视频资源加载失败。
*   **推理过程:** 底层媒体播放器检测到网络错误，会调用 `HTMLMediaElement::SetNetworkState()` 设置网络状态为错误。同时，会调用 `SetError()` 设置错误对象。`ScheduleRejectPlayPromises()` 会被调用，将之前 `play()` 调用返回的 Promise 标记为 rejected。
*   **预期输出:** 视频播放失败，JavaScript 中 `play()` 返回的 Promise 被 reject，并带有相应的错误信息。可以通过监听 `error` 事件捕获错误。

**常见使用错误举例说明:**

*   **在没有用户交互的情况下尝试 `play()`:**  浏览器通常会阻止自动播放，除非满足特定条件（例如，用户与页面有交互）。如果 JavaScript 代码在页面加载时立即调用 `videoElement.play()`，而没有用户交互，`autoplay_policy_` 可能会阻止播放，导致 `play()` 返回的 Promise 被 reject。开发者需要处理 Promise 的 rejection 或者依赖用户的交互来触发播放。
*   **没有处理 `play()` Promise 的 rejection:**  `play()` 方法返回一个 Promise，开发者应该处理 Promise 的 resolve 和 reject 两种情况。如果开发者只关注 resolve，而忽略了 reject 的处理，当播放失败时可能会出现未捕获的异常或者页面行为异常。`RejectScheduledPlayPromises()` 方法负责处理 Promise 的 rejection。
*   **错误地设置 `SetAudioSinkId()`:** 如果开发者尝试设置一个不存在或者无效的音频输出设备 ID，可能会导致音频播放失败或者输出到错误的设备。

**总结 (第6部分):**

`HTMLMediaElement.cc` 的第 6 部分主要负责将 `HTMLMediaElement` 连接到浏览器的其他核心组件和外部系统，例如底层的媒体播放器、远程播放设备和 Web Audio API。它处理高级的媒体控制、状态同步、错误报告以及与用户交互和浏览器策略相关的逻辑。这部分代码是 `HTMLMediaElement` 实现完整媒体功能不可或缺的一部分，确保了 Web 开发者可以通过 JavaScript 和 HTML 方便地控制和操作媒体元素。

### 提示词
```
这是目录为blink/renderer/core/html/media/html_media_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
eateAudioTrack(
        "audio", media::MediaTrack::AudioKind::kMain, "Audio Track", "", true));
  }

  // Create a placeholder video track if the player says it has video but it
  // didn't explicitly announce the tracks.
  if (HasVideo() && !videoTracks().length()) {
    AddMediaTrack(media::MediaTrack::CreateVideoTrack(
        "video", media::MediaTrack::VideoKind::kMain, "Video Track", "", true));
  }
}

void HTMLMediaElement::SetNetworkState(NetworkState state,
                                       bool update_media_controls) {
  if (network_state_ == state)
    return;

  network_state_ = state;
  if (update_media_controls && GetMediaControls())
    GetMediaControls()->NetworkStateChanged();
}

void HTMLMediaElement::VideoWillBeDrawnToCanvas() const {
  DCHECK(IsHTMLVideoElement());
  UseCounter::Count(GetDocument(), WebFeature::kVideoInCanvas);
  autoplay_policy_->VideoWillBeDrawnToCanvas();
}

void HTMLMediaElement::ScheduleResolvePlayPromises() {
  // TODO(mlamouri): per spec, we should create a new task but we can't create
  // a new cancellable task without cancelling the previous one. There are two
  // approaches then: cancel the previous task and create a new one with the
  // appended promise list or append the new promise to the current list. The
  // latter approach is preferred because it might be the less observable
  // change.
  DCHECK(play_promise_resolve_list_.empty() ||
         play_promise_resolve_task_handle_.IsActive());
  if (play_promise_resolvers_.empty())
    return;

  play_promise_resolve_list_.AppendVector(play_promise_resolvers_);
  play_promise_resolvers_.clear();

  if (play_promise_resolve_task_handle_.IsActive())
    return;

  play_promise_resolve_task_handle_ = PostCancellableTask(
      *GetDocument().GetTaskRunner(TaskType::kMediaElementEvent), FROM_HERE,
      WTF::BindOnce(&HTMLMediaElement::ResolveScheduledPlayPromises,
                    WrapWeakPersistent(this)));
}

void HTMLMediaElement::ScheduleRejectPlayPromises(PlayPromiseError code) {
  // TODO(mlamouri): per spec, we should create a new task but we can't create
  // a new cancellable task without cancelling the previous one. There are two
  // approaches then: cancel the previous task and create a new one with the
  // appended promise list or append the new promise to the current list. The
  // latter approach is preferred because it might be the less observable
  // change.
  DCHECK(play_promise_reject_list_.empty() ||
         play_promise_reject_task_handle_.IsActive());
  if (play_promise_resolvers_.empty())
    return;

  play_promise_reject_list_.AppendVector(play_promise_resolvers_);
  play_promise_resolvers_.clear();

  if (play_promise_reject_task_handle_.IsActive())
    return;

  // TODO(nhiroki): Bind this error code to a cancellable task instead of a
  // member field.
  play_promise_error_code_ = code;
  play_promise_reject_task_handle_ = PostCancellableTask(
      *GetDocument().GetTaskRunner(TaskType::kMediaElementEvent), FROM_HERE,
      WTF::BindOnce(&HTMLMediaElement::RejectScheduledPlayPromises,
                    WrapWeakPersistent(this)));
}

void HTMLMediaElement::ScheduleNotifyPlaying() {
  ScheduleNamedEvent(event_type_names::kPlaying);
  ScheduleResolvePlayPromises();
}

void HTMLMediaElement::ResolveScheduledPlayPromises() {
  for (auto& resolver : play_promise_resolve_list_)
    resolver->DowncastTo<IDLUndefined>()->Resolve();

  play_promise_resolve_list_.clear();
}

void HTMLMediaElement::RejectScheduledPlayPromises() {
  if (play_promise_error_code_ == PlayPromiseError::kNotSupported) {
    RejectPlayPromisesInternal(
        DOMExceptionCode::kNotSupportedError,
        "Failed to load because no supported source was found.");
    return;
  }

  const char* reason = "";
  switch (play_promise_error_code_) {
    case PlayPromiseError::kPaused_Unknown:
      reason = " because the media paused";
      break;
    case PlayPromiseError::kPaused_PauseCalled:
      reason = " by a call to pause()";
      break;
    case PlayPromiseError::kPaused_EndOfPlayback:
      reason = " by end of playback";
      break;
    case PlayPromiseError::kPaused_RemovedFromDocument:
      reason = " because the media was removed from the document";
      break;
    case PlayPromiseError::kPaused_AutoplayAutoPause:
      reason = " because autoplaying background media was paused to save power";
      break;
    case PlayPromiseError::kPaused_PageHidden:
      reason = " because video-only background media was paused to save power";
      break;
    case PlayPromiseError::kPaused_SuspendedPlayerIdleTimeout:
      reason = " because the player was been suspended and became idle";
      break;
    case PlayPromiseError::kPaused_RemotePlayStateChange:
      reason = " by a pause request from a remote media player";
      break;
    case PlayPromiseError::kPaused_PauseRequestedByUser:
      reason = " because a pause was requested by the user";
      break;
    case PlayPromiseError::kPaused_PauseRequestedInternally:
      reason = " because a pause was requested by the browser";
      break;
    case PlayPromiseError::kPaused_FrameHidden:
      reason =
          " because the media playback is not allowed by the "
          "media-playback-while-not-visible permission policy";
      break;
    case PlayPromiseError::kNotSupported:
      NOTREACHED();
  }
  RejectPlayPromisesInternal(
      DOMExceptionCode::kAbortError,
      String::Format(
          "The play() request was interrupted%s. https://goo.gl/LdLk22",
          reason));
}

void HTMLMediaElement::RejectPlayPromises(DOMExceptionCode code,
                                          const String& message) {
  play_promise_reject_list_.AppendVector(play_promise_resolvers_);
  play_promise_resolvers_.clear();
  RejectPlayPromisesInternal(code, message);
}

void HTMLMediaElement::RejectPlayPromisesInternal(DOMExceptionCode code,
                                                  const String& message) {
  DCHECK(code == DOMExceptionCode::kAbortError ||
         code == DOMExceptionCode::kNotSupportedError);
  for (auto& resolver : play_promise_reject_list_)
    resolver->Reject(MakeGarbageCollected<DOMException>(code, message));

  play_promise_reject_list_.clear();
}

void HTMLMediaElement::OnRemovedFromDocumentTimerFired(TimerBase*) {
  if (InActiveDocument())
    return;

  // Video should not pause when playing in Picture-in-Picture and subsequently
  // removed from the Document.
  if (!PictureInPictureController::IsElementInPictureInPicture(this))
    PauseInternal(PlayPromiseError::kPaused_RemovedFromDocument);
}

void HTMLMediaElement::AudioSourceProviderImpl::Wrap(
    scoped_refptr<WebAudioSourceProviderImpl> provider) {
  base::AutoLock locker(provide_input_lock);

  if (web_audio_source_provider_ && provider != web_audio_source_provider_)
    web_audio_source_provider_->SetClient(nullptr);

  web_audio_source_provider_ = std::move(provider);
  if (web_audio_source_provider_)
    web_audio_source_provider_->SetClient(client_.Get());
}

void HTMLMediaElement::AudioSourceProviderImpl::SetClient(
    AudioSourceProviderClient* client) {
  base::AutoLock locker(provide_input_lock);

  if (client)
    client_ = MakeGarbageCollected<HTMLMediaElement::AudioClientImpl>(client);
  else
    client_.Clear();

  if (web_audio_source_provider_)
    web_audio_source_provider_->SetClient(client_.Get());
}

void HTMLMediaElement::AudioSourceProviderImpl::ProvideInput(
    AudioBus* bus,
    int frames_to_process) {
  DCHECK(bus);

  base::AutoTryLock try_locker(provide_input_lock);
  if (!try_locker.is_acquired() || !web_audio_source_provider_ ||
      !client_.Get()) {
    bus->Zero();
    return;
  }

  // Wrap the AudioBus channel data using WebVector.
  unsigned n = bus->NumberOfChannels();
  WebVector<float*> web_audio_data(n);
  for (unsigned i = 0; i < n; ++i)
    web_audio_data[i] = bus->Channel(i)->MutableData();

  web_audio_source_provider_->ProvideInput(web_audio_data, frames_to_process);
}

void HTMLMediaElement::AudioClientImpl::SetFormat(uint32_t number_of_channels,
                                                  float sample_rate) {
  if (client_)
    client_->SetFormat(number_of_channels, sample_rate);
}

void HTMLMediaElement::AudioClientImpl::Trace(Visitor* visitor) const {
  visitor->Trace(client_);
}

void HTMLMediaElement::AudioSourceProviderImpl::Trace(Visitor* visitor) const {
  visitor->Trace(client_);
}

bool HTMLMediaElement::HasNativeControls() {
  return ShouldShowControls();
}

bool HTMLMediaElement::IsAudioElement() {
  return IsHTMLAudioElement();
}

DisplayType HTMLMediaElement::GetDisplayType() const {
  return IsFullscreen() ? DisplayType::kFullscreen : DisplayType::kInline;
}

gfx::ColorSpace HTMLMediaElement::TargetColorSpace() {
  LocalFrame* frame = GetDocument().GetFrame();
  if (!frame)
    return gfx::ColorSpace();
  return frame->GetPage()
      ->GetChromeClient()
      .GetScreenInfo(*frame)
      .display_color_spaces.GetScreenInfoColorSpace();
}

bool HTMLMediaElement::WasAutoplayInitiated() {
  return autoplay_policy_->WasAutoplayInitiated();
}

void HTMLMediaElement::ResumePlayback() {
  autoplay_policy_->EnsureAutoplayInitiatedSet();
  PlayInternal();
}

void HTMLMediaElement::PausePlayback(PauseReason pause_reason) {
  switch (pause_reason) {
    case PauseReason::kUnknown:
      return PauseInternal(PlayPromiseError::kPaused_Unknown);
    case PauseReason::kPageHidden:
      return PauseInternal(PlayPromiseError::kPaused_PageHidden);
    case PauseReason::kSuspendedPlayerIdleTimeout:
      return PauseInternal(
          PlayPromiseError::kPaused_SuspendedPlayerIdleTimeout);
    case PauseReason::kRemotePlayStateChange:
      return PauseInternal(PlayPromiseError::kPaused_RemotePlayStateChange);
    case PauseReason::kFrameHidden:
      return PauseInternal(PlayPromiseError::kPaused_FrameHidden);
  }
  NOTREACHED();
}

void HTMLMediaElement::DidPlayerStartPlaying() {
  for (auto& observer : media_player_observer_remote_set_->Value())
    observer->OnMediaPlaying();
}

void HTMLMediaElement::DidPlayerPaused(bool stream_ended) {
  for (auto& observer : media_player_observer_remote_set_->Value())
    observer->OnMediaPaused(stream_ended);
}

void HTMLMediaElement::DidPlayerMutedStatusChange(bool muted) {
  for (auto& observer : media_player_observer_remote_set_->Value())
    observer->OnMutedStatusChanged(muted);
}

void HTMLMediaElement::DidMediaMetadataChange(
    bool has_audio,
    bool has_video,
    media::AudioCodec audio_codec,
    media::VideoCodec video_codec,
    media::MediaContentType media_content_type,
    bool is_encrypted_media) {
  for (auto& observer : media_player_observer_remote_set_->Value()) {
    observer->OnMediaMetadataChanged(has_audio, has_video, media_content_type);
  }

  video_codec_ = has_video ? std::make_optional(video_codec) : std::nullopt;
  audio_codec_ = has_audio ? std::make_optional(audio_codec) : std::nullopt;

  is_encrypted_media_ = is_encrypted_media;
  OnRemotePlaybackMetadataChange();
}

void HTMLMediaElement::DidPlayerMediaPositionStateChange(
    double playback_rate,
    base::TimeDelta duration,
    base::TimeDelta position,
    bool end_of_media) {
  for (auto& observer : media_player_observer_remote_set_->Value()) {
    observer->OnMediaPositionStateChanged(
        media_session::mojom::blink::MediaPosition::New(
            playback_rate, duration, position, base::TimeTicks::Now(),
            end_of_media));
  }
}

void HTMLMediaElement::DidDisableAudioOutputSinkChanges() {
  for (auto& observer : media_player_observer_remote_set_->Value())
    observer->OnAudioOutputSinkChangingDisabled();
}

void HTMLMediaElement::DidUseAudioServiceChange(bool uses_audio_service) {
  for (auto& observer : media_player_observer_remote_set_->Value()) {
    observer->OnUseAudioServiceChanged(uses_audio_service);
  }
}

void HTMLMediaElement::DidPlayerSizeChange(const gfx::Size& size) {
  for (auto& observer : media_player_observer_remote_set_->Value())
    observer->OnMediaSizeChanged(size);
}

void HTMLMediaElement::OnRemotePlaybackDisabled(bool disabled) {
  if (is_remote_playback_disabled_ == disabled)
    return;
  is_remote_playback_disabled_ = disabled;
  OnRemotePlaybackMetadataChange();
}

media::mojom::blink::MediaPlayerHost&
HTMLMediaElement::GetMediaPlayerHostRemote() {
  // It is an error to call this before having access to the document's frame.
  DCHECK(GetDocument().GetFrame());
  if (!media_player_host_remote_->Value().is_bound()) {
    GetDocument()
        .GetFrame()
        ->GetRemoteNavigationAssociatedInterfaces()
        ->GetInterface(
            media_player_host_remote_->Value().BindNewEndpointAndPassReceiver(
                GetDocument().GetTaskRunner(TaskType::kInternalMedia)));
  }
  return *media_player_host_remote_->Value().get();
}

mojo::PendingAssociatedReceiver<media::mojom::blink::MediaPlayerObserver>
HTMLMediaElement::AddMediaPlayerObserverAndPassReceiver() {
  mojo::PendingAssociatedRemote<media::mojom::blink::MediaPlayerObserver>
      observer;
  auto observer_receiver = observer.InitWithNewEndpointAndPassReceiver();
  media_player_observer_remote_set_->Value().Add(
      std::move(observer),
      GetDocument().GetTaskRunner(TaskType::kInternalMedia));
  return observer_receiver;
}

void HTMLMediaElement::RequestPlay() {
  LocalFrame* frame = GetDocument().GetFrame();
  if (frame) {
    LocalFrame::NotifyUserActivation(
        frame, mojom::blink::UserActivationNotificationType::kInteraction);
  }
  autoplay_policy_->EnsureAutoplayInitiatedSet();
  PlayInternal();
}

void HTMLMediaElement::RequestPause(bool triggered_by_user) {
  if (triggered_by_user) {
    LocalFrame* frame = GetDocument().GetFrame();
    if (frame) {
      LocalFrame::NotifyUserActivation(
          frame, mojom::blink::UserActivationNotificationType::kInteraction);
    }
  }
  PauseInternal(triggered_by_user
                    ? PlayPromiseError::kPaused_PauseRequestedByUser
                    : PlayPromiseError::kPaused_PauseRequestedInternally);
}

void HTMLMediaElement::RequestSeekForward(base::TimeDelta seek_time) {
  double seconds = seek_time.InSecondsF();
  DCHECK_GE(seconds, 0) << "Attempted to seek by a negative number of seconds";
  setCurrentTime(currentTime() + seconds);
}

void HTMLMediaElement::RequestSeekBackward(base::TimeDelta seek_time) {
  double seconds = seek_time.InSecondsF();
  DCHECK_GE(seconds, 0) << "Attempted to seek by a negative number of seconds";
  setCurrentTime(currentTime() - seconds);
}

void HTMLMediaElement::RequestSeekTo(base::TimeDelta seek_time) {
  setCurrentTime(seek_time.InSecondsF());
}

void HTMLMediaElement::RequestMute(bool mute) {
  setMuted(mute);
}

void HTMLMediaElement::SetVolumeMultiplier(double multiplier) {
  if (web_media_player_)
    web_media_player_->SetVolumeMultiplier(multiplier);
}

void HTMLMediaElement::SetPowerExperimentState(bool enabled) {
  if (web_media_player_)
    web_media_player_->SetPowerExperimentState(enabled);
}

void HTMLMediaElement::SetAudioSinkId(const String& sink_id) {
  auto* audio_output_controller = AudioOutputDeviceController::From(*this);
  DCHECK(audio_output_controller);

  audio_output_controller->SetSinkId(sink_id);
}

void HTMLMediaElement::SuspendForFrameClosed() {
  if (web_media_player_)
    web_media_player_->SuspendForFrameClosed();
}

bool HTMLMediaElement::MediaShouldBeOpaque() const {
  return !IsMediaDataCorsSameOrigin() && ready_state_ < kHaveMetadata &&
         EffectivePreloadType() != WebMediaPlayer::kPreloadNone;
}

void HTMLMediaElement::SetError(MediaError* error) {
  error_ = error;

  if (error) {
    DLOG(ERROR) << __func__ << ": {code=" << error->code()
                << ", message=" << error->message() << "}";
    if (media_source_attachment_)
      media_source_attachment_->OnElementError();
  }
}

void HTMLMediaElement::ReportCurrentTimeToMediaSource() {
  if (!media_source_attachment_)
    return;

  // See MediaSourceAttachment::OnElementTimeUpdate() for why the attachment
  // needs our currentTime.
  media_source_attachment_->OnElementTimeUpdate(currentTime());
}

void HTMLMediaElement::OnRemotePlaybackMetadataChange() {
  if (remote_playback_client_) {
    remote_playback_client_->MediaMetadataChanged(video_codec_, audio_codec_);
  }
  for (auto& observer : media_player_observer_remote_set_->Value()) {
    observer->OnRemotePlaybackMetadataChange(
        media_session::mojom::blink::RemotePlaybackMetadata::New(
            WTF::String(media::GetCodecName(video_codec_
                                                ? video_codec_.value()
                                                : media::VideoCodec::kUnknown)),
            WTF::String(media::GetCodecName(audio_codec_
                                                ? audio_codec_.value()
                                                : media::AudioCodec::kUnknown)),
            is_remote_playback_disabled_, is_remote_rendering_,
            WTF::String(remote_device_friendly_name_), is_encrypted_media_));
  }
}

std::string HTMLMediaElement::GetActivePresentationId() {
  if (!remote_playback_client_) {
    return std::string();
  }

  // The presentation ID is essentially a GUID preceded by the "mr_" prefix,
  // which makes it ASCII compatible.
  // If MediaRouterBase::CreatePresentationId() were changed, this line might
  // need to be updated.
  return remote_playback_client_->GetPresentationId().Ascii();
}

HTMLMediaElement::OpenerContextObserver::OpenerContextObserver(
    HTMLMediaElement* element)
    : element_(element) {}

HTMLMediaElement::OpenerContextObserver::~OpenerContextObserver() = default;

void HTMLMediaElement::OpenerContextObserver::Trace(Visitor* visitor) const {
  ContextLifecycleObserver::Trace(visitor);
  visitor->Trace(element_);
}

void HTMLMediaElement::OpenerContextObserver::ContextDestroyed() {
  element_->AttachToNewFrame();
}

STATIC_ASSERT_ENUM(WebMediaPlayer::kReadyStateHaveNothing,
                   HTMLMediaElement::kHaveNothing);
STATIC_ASSERT_ENUM(WebMediaPlayer::kReadyStateHaveMetadata,
                   HTMLMediaElement::kHaveMetadata);
STATIC_ASSERT_ENUM(WebMediaPlayer::kReadyStateHaveCurrentData,
                   HTMLMediaElement::kHaveCurrentData);
STATIC_ASSERT_ENUM(WebMediaPlayer::kReadyStateHaveFutureData,
                   HTMLMediaElement::kHaveFutureData);
STATIC_ASSERT_ENUM(WebMediaPlayer::kReadyStateHaveEnoughData,
                   HTMLMediaElement::kHaveEnoughData);

}  // namespace blink
```