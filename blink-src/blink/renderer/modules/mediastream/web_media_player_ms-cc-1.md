Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the `WebMediaPlayerMS` class in the Chromium Blink engine. This class is responsible for handling media playback from `MediaStream` sources.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Purpose:**  The class name itself (`WebMediaPlayerMS`) strongly suggests its purpose: a media player specifically for `MediaStream` sources. This will be the central theme of the summary.

2. **Analyze Key Attributes and Methods:** Go through the code, noting the significant member variables and methods. Group them by related functionalities. For instance:
    * Playback control: `Play()`, `Pause()`, `SetRate()`, `SetVolume()`, `Seek()`.
    * Video handling: `Paint()`, `GetCurrentFrameThenUpdate()`, `HasVideo()`, `NaturalSize()`, `VisibleSize()`,  `ActivateSurfaceLayerForVideo()`, `OnFirstFrameReceived()`, `OnTransformChanged()`, `OnOpacityChanged()`.
    * Audio handling: `HasAudio()`, `SetSinkId()`.
    * State management: `Paused()`, `Seeking()`, `Duration()`, `CurrentTime()`, `IsEnded()`, `GetNetworkState()`, `GetReadyState()`.
    * Lifecycle management: `Load()`, `Unload()`, `OnPageHidden()`, `OnPageShown()`.
    * Communication with other components: `delegate_`, `client_`, `compositor_`, `audio_renderer_`, `frame_deliverer_`, `bridge_`.
    * Metrics and reporting: `MaybeCreateWatchTimeReporter()`, `UpdateWatchTimeReporterSecondaryProperties()`, `GetPipelineStatistics()`.

3. **Relate to Web Technologies (JavaScript, HTML, CSS):** Consider how this C++ code interacts with web technologies. Focus on the visible effects and the underlying mechanisms.
    * **JavaScript:**  JavaScript uses the HTML `<video>` or `<audio>` elements and the `MediaStream` API to feed data to the player. The methods in this C++ class are the backend implementation of JavaScript methods called on these media elements. Think about events like `play`, `pause`, `volumechange`, etc.
    * **HTML:** The `<video>` and `<audio>` tags are the entry points. Attributes like `srcObject` (to set the `MediaStream`) and controls (to trigger playback actions) are relevant.
    * **CSS:** While not directly controlling the *logic* of the player, CSS affects how the video is *displayed*. Consider the `object-fit` property and how resizing might interact with the player's internal size calculations.

4. **Consider Logic and Data Flow:**  Think about how data flows through the system. The `MediaStream` provides the media data. The `compositor_` manages video frames, and `audio_renderer_` handles audio. The `client_` and `delegate_` communicate with the higher levels of the browser.

5. **Identify Potential Issues and User Errors:**  Think about common problems users or developers might encounter.
    * Forgetting to attach the `MediaStream` to the video/audio element.
    * Issues with permissions for accessing camera/microphone.
    * Network problems affecting remote streams.
    * Unexpected behavior when the browser tab is hidden or goes into Picture-in-Picture mode.

6. **Trace User Actions:** Imagine a user interacting with a webpage containing a `<video>` element that uses a `MediaStream`. Walk through the steps that lead to the execution of this C++ code.

7. **Structure the Summary:** Organize the findings into logical sections. Start with a high-level overview, then delve into specific functionalities, and finally address the relationships with web technologies, potential issues, and user actions.

8. **Address the "Part 2" Requirement:** Explicitly state that the summary is based on the provided code snippet and represents a continuation of the overall functionality of `WebMediaPlayerMS`.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on individual methods. **Correction:** Group methods by functionality for a more coherent summary.
* **Initial thought:**  Overlook the interaction with web technologies. **Correction:** Emphasize the role of this C++ code as the backend for JavaScript APIs.
* **Initial thought:**  Miss the significance of asynchronous operations and thread management. **Correction:**  Mention the use of task runners and cross-thread communication.
* **Initial thought:** Not clearly explain the purpose of `compositor_` and `audio_renderer_`. **Correction:** Clarify their roles in video frame management and audio rendering.

By following these steps, and iteratively refining the analysis, a comprehensive and accurate summary of the `WebMediaPlayerMS` class can be generated.
根据提供的代码片段，我们可以归纳 `WebMediaPlayerMS` 的以下功能：

**核心功能：处理和控制 MediaStream 类型的媒体播放**

这段代码是 `WebMediaPlayerMS` 类的一部分，它专门用于处理来自 `MediaStream` 的媒体数据，例如摄像头、麦克风或者屏幕共享的内容。它实现了 `WebMediaPlayer` 接口，提供了与 HTML5 `<video>` 和 `<audio>` 元素交互的能力。

**具体功能点：**

* **播放控制:**
    * `Play()`: 启动或恢复播放。
    * `Pause()`: 暂停播放。
    * `SetRate(double rate)`: 设置播放速率（但在此实现中似乎是空操作）。
    * `SetVolume(double volume)`: 设置音量。
* **视频处理:**
    * `Paint(cc::PaintCanvas* canvas, const gfx::Rect& rect, cc::PaintFlags& flags)`:  将当前视频帧绘制到指定的画布上。
    * `GetCurrentFrameThenUpdate()`: 获取当前的视频帧。
    * `ReplaceCurrentFrameWithACopy()`: 使用当前帧的副本替换当前帧（可能用于优化或特定场景）。
    * `HasVideo()`:  检查是否有视频轨道。
    * `NaturalSize()`: 获取视频的原始尺寸。
    * `VisibleSize()`: 获取当前可见的视频尺寸。
    * `OnFirstFrameReceived(media::VideoTransformation video_transform, bool is_opaque)`:  在接收到第一帧视频数据时执行的操作，包括设置就绪状态和触发大小调整。
    * `OnOpacityChanged(bool is_opaque)`: 处理视频不透明度变化。
    * `OnTransformChanged(media::VideoTransformation video_transform)`: 处理视频变换（例如旋转）。
    * `ActivateSurfaceLayerForVideo(media::VideoTransformation video_transform)`:  激活用于视频渲染的 SurfaceLayer。
* **音频处理:**
    * `HasAudio()`: 检查是否有音频轨道。
    * `SetSinkId(const WebString& sink_id, WebSetSinkIdCompleteCallback completion_callback)`: 设置音频输出设备。
* **状态管理:**
    * `Paused()`: 获取播放暂停状态。
    * `Seeking()`: 获取是否正在跳转状态（始终返回 false）。
    * `Duration()`: 获取媒体时长（对于 MediaStream 始终返回无穷大）。
    * `CurrentTime()`: 获取当前播放时间。
    * `IsEnded()`: 获取播放是否结束（对于 MediaStream 始终返回 false）。
    * `GetNetworkState()`: 获取网络状态。
    * `GetReadyState()`: 获取就绪状态。
* **生命周期管理:**
    * `OnPageHidden()`:  当页面被隐藏时执行的操作，例如暂停播放、释放资源。
    * `SuspendForFrameClosed()`: 当渲染帧关闭时执行的操作，可能暂停播放。
    * `OnPageShown()`: 当页面显示时执行的操作，例如恢复播放。
    * `OnFrameShown()` 和 `OnFrameHidden()`:  类似于 `OnPageShown()` 和 `OnPageHidden()`，但针对的是 iframe 或 frame。
* **与其他组件的交互:**
    * 使用 `delegate_` 与更上层的组件通信。
    * 使用 `client_` 与渲染层的客户端进行交互，例如通知状态变化、请求重绘等。
    * 使用 `compositor_` 管理视频帧的合成和渲染。
    * 使用 `audio_renderer_` 进行音频渲染。
    * 使用 `bridge_` 管理 SurfaceLayer 的创建和更新。
    * 使用 `frame_deliverer_` 处理视频帧的传递。
* **性能监控和报告:**
    * `MaybeCreateWatchTimeReporter()` 和 `UpdateWatchTimeReporterSecondaryProperties()`:  创建和更新用于监控播放时长的报告器。
    * `DecodedFrameCount()` 和 `DroppedFrameCount()`:  获取解码和丢弃的帧数。
    * `GetPipelineStatistics()`: 获取播放管道的统计信息。
* **其他功能:**
    * `SetPreload(WebMediaPlayer::Preload preload)`: 设置预加载行为（在此实现中似乎没有具体实现）。
    * `GetErrorMessage()`: 获取错误消息。
    * `Buffered()` 和 `Seekable()`: 获取缓冲和可跳转的时间范围（对于 MediaStream 通常为空）。
    * `OnFrozen()`: 当播放冻结时执行的操作。
    * `DidLoadingProgress()`:  指示加载是否正在进行。
    * `WouldTaintOrigin()`:  指示是否会污染源。
    * `MediaTimeForTimeValue(double timeValue)`: 将时间值转换为媒体时间。
    * `SetVolumeMultiplier(double multiplier)`: 设置音量倍增器。
    * `GetVideoFramePresentationMetadata()`: 获取视频帧的呈现元数据。
    * `RequestVideoFrameCallback()` 和 `OnNewFramePresentedCallback()`:  请求视频帧回调，用于同步渲染。
    * `SendLogMessage(const WTF::String& message)`: 发送日志消息。
    * `RegisterFrameSinkHierarchy()` 和 `UnregisterFrameSinkHierarchy()`: 注册和取消注册帧接收器层次结构。

**与 JavaScript, HTML, CSS 的关系举例：**

* **JavaScript:**
    * 当 JavaScript 代码调用 `videoElement.play()` 时，会最终触发 `WebMediaPlayerMS::Play()` 方法的执行。
    * 当 JavaScript 代码设置 `videoElement.volume = 0.5` 时，会最终调用 `WebMediaPlayerMS::SetVolume(0.5)`。
    * JavaScript 可以通过 `videoElement.srcObject = mediaStream` 将一个 `MediaStream` 对象绑定到 `<video>` 元素，这会触发 `WebMediaPlayerMS` 的加载过程。
* **HTML:**
    * `<video>` 或 `<audio>` 元素是 MediaStream 内容的宿主。`WebMediaPlayerMS` 负责渲染这些元素展示的 MediaStream 数据。
    * `<video>` 元素的 `controls` 属性会影响是否显示原生播放控件，这可能影响 `WebMediaPlayerMS` 中 WatchTimeReporter 的行为。
* **CSS:**
    * CSS 可以控制 `<video>` 元素的样式，例如尺寸、边框等，但这通常不会直接影响 `WebMediaPlayerMS` 的核心逻辑，但可能会影响 `Paint()` 方法中的绘制区域。`object-fit` 属性可能会影响视频的显示比例，这与 `NaturalSize()` 和 `VisibleSize()` 有关。

**逻辑推理的假设输入与输出:**

假设输入：

* 用户在网页上点击了一个使用 `MediaStream` 的 `<video>` 元素的播放按钮。
* 此时 `WebMediaPlayerMS` 实例已经加载了对应的 `MediaStream` 数据。

输出：

* `WebMediaPlayerMS::Play()` 方法被调用。
* 如果音频存在，`audio_renderer_->Play()` 将被调用。
* `paused_` 成员变量被设置为 `false`。
* `delegate_->SetIdle()` 被调用，表示播放器不再空闲。
* `watch_time_reporter_->OnPlaying()` 被调用，开始记录播放时长。
* 如果需要 SurfaceLayer 进行渲染，则会启动视频帧的提交。
* 视频帧开始被解码和渲染，通过 `Paint()` 方法绘制到屏幕上。

**用户或编程常见的使用错误举例说明:**

* **错误地假设 MediaStream 有固定的时长:**  用户可能会尝试获取 `videoElement.duration`，但对于 `MediaStream` 来说，其时长是无限的，这可能导致意外的逻辑错误。
* **在页面隐藏后仍然尝试操作播放器:**  例如，在 `OnPageHidden()` 调用后，JavaScript 代码仍然尝试调用 `videoElement.play()` 或修改音量，这可能导致操作失败或产生未预期的行为，因为播放器可能已经暂停或释放了某些资源。
* **没有正确处理权限问题:**  如果用户拒绝了摄像头或麦克风的访问权限，`MediaStream` 可能无法成功获取数据，导致 `WebMediaPlayerMS` 无法正常播放，开发者需要妥善处理这种情况。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户打开一个包含 `<video>` 或 `<audio>` 元素的网页。**
2. **网页的 JavaScript 代码使用 `navigator.mediaDevices.getUserMedia()` 或其他 MediaStream API 获取音视频流。**
3. **JavaScript 代码将获取到的 `MediaStream` 对象赋值给 `<video>` 或 `<audio>` 元素的 `srcObject` 属性。**  例如：`videoElement.srcObject = stream;`
4. **Blink 渲染引擎会根据 `srcObject` 的类型创建对应的 `WebMediaPlayer` 实现，这里会创建 `WebMediaPlayerMS` 的实例。**
5. **用户与播放器交互，例如点击播放按钮。**
6. **浏览器事件（例如点击事件）被传递到渲染进程。**
7. **渲染进程中的 JavaScript 代码执行相应的操作，调用 `<video>` 元素的方法，例如 `play()`。**
8. **这些 JavaScript 方法的调用会被映射到 `WebMediaPlayerMS` 对应的 C++ 方法，例如 `Play()`。**
9. **`WebMediaPlayerMS` 内部会协调各个组件（compositor, audio_renderer, frame_deliverer 等）来处理媒体数据的播放和渲染。**

在调试时，可以关注以下线索：

* **检查 JavaScript 代码中是否正确获取和设置了 `MediaStream`。**
* **在 Chrome 的 `chrome://webrtc-internals/` 页面查看 WebRTC 的连接状态和统计信息，确认 `MediaStream` 是否正常工作。**
* **使用断点或日志输出跟踪 `WebMediaPlayerMS` 中各个方法的调用顺序和参数值。**
* **检查 `delegate_` 和 `client_` 的实现，了解 `WebMediaPlayerMS` 如何与上层组件通信。**
* **如果涉及到视频渲染问题，可以关注 `compositor_` 的行为和 SurfaceLayer 的创建。**

总而言之，`WebMediaPlayerMS` 负责 `MediaStream` 类型的媒体播放控制、状态管理、渲染以及与其他浏览器组件的交互，是 Blink 引擎中处理 WebRTC 和媒体捕获等场景的关键组成部分。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/web_media_player_ms.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
nd_of_stream = */ false);
  delegate_->SetIdle(delegate_id_, true);

  paused_ = true;
}

void WebMediaPlayerMS::ReplaceCurrentFrameWithACopy() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  compositor_->ReplaceCurrentFrameWithACopy();
}

void WebMediaPlayerMS::Seek(double seconds) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

void WebMediaPlayerMS::SetRate(double rate) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

void WebMediaPlayerMS::SetVolume(double volume) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(String::Format("%s({volume=%.2f})", __func__, volume));
  volume_ = volume;
  if (audio_renderer_.get())
    audio_renderer_->SetVolume(volume_ * volume_multiplier_);
  if (watch_time_reporter_)
    watch_time_reporter_->OnVolumeChange(volume);
  client_->DidPlayerMutedStatusChange(volume == 0.0);
}

void WebMediaPlayerMS::SetLatencyHint(double seconds) {
  // WebRTC latency has separate latency APIs, focused more on network jitter
  // and implemented inside the WebRTC stack.
  // https://webrtc.org/experiments/rtp-hdrext/playout-delay/
  // https://henbos.github.io/webrtc-timing/#dom-rtcrtpreceiver-playoutdelayhint
}

void WebMediaPlayerMS::SetPreservesPitch(bool preserves_pitch) {
  // Since WebMediaPlayerMS::SetRate() is a no-op, it doesn't make sense to
  // handle pitch preservation flags. The playback rate should always be 1.0,
  // and thus there should be no pitch-shifting.
}

void WebMediaPlayerMS::SetWasPlayedWithUserActivationAndHighMediaEngagement(
    bool was_played_with_user_activation_and_high_media_engagement) {}

void WebMediaPlayerMS::SetShouldPauseWhenFrameIsHidden(
    bool should_pause_when_frame_is_hidden) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  should_pause_when_frame_is_hidden_ = should_pause_when_frame_is_hidden;
}

bool WebMediaPlayerMS::GetShouldPauseWhenFrameIsHidden() {
  return should_pause_when_frame_is_hidden_;
}

void WebMediaPlayerMS::OnRequestPictureInPicture() {
  if (!bridge_) {
    ActivateSurfaceLayerForVideo(compositor_->GetMetadata().video_transform);
  }

  DCHECK(bridge_);
  DCHECK(bridge_->GetSurfaceId().is_valid());
}

bool WebMediaPlayerMS::SetSinkId(
    const WebString& sink_id,
    WebSetSinkIdCompleteCallback completion_callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(
      String::Format("%s({sink_id=%s})", __func__, sink_id.Utf8().c_str()));

  media::OutputDeviceStatusCB callback =
      ConvertToOutputDeviceStatusCB(std::move(completion_callback));

  if (!audio_renderer_) {
    SendLogMessage(String::Format(
        "%s => (WARNING: failed to instantiate audio renderer)", __func__));
    std::move(callback).Run(media::OUTPUT_DEVICE_STATUS_ERROR_INTERNAL);
    SendLogMessage(String::Format(
        "%s => (ERROR: OUTPUT_DEVICE_STATUS_ERROR_INTERNAL)", __func__));
    return false;
  }

  auto sink_id_utf8 = sink_id.Utf8();
  audio_renderer_->SwitchOutputDevice(sink_id_utf8, std::move(callback));
  return true;
}

void WebMediaPlayerMS::SetPreload(WebMediaPlayer::Preload preload) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

bool WebMediaPlayerMS::HasVideo() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return !!video_frame_provider_;
}

bool WebMediaPlayerMS::HasAudio() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return !!audio_renderer_;
}

gfx::Size WebMediaPlayerMS::NaturalSize() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!video_frame_provider_)
    return gfx::Size();

  const auto& metadata = compositor_->GetMetadata();
  const gfx::Size& current_size = metadata.natural_size;
  const auto& rotation = metadata.video_transform.rotation;
  if (rotation == media::VIDEO_ROTATION_90 ||
      rotation == media::VIDEO_ROTATION_270) {
    return gfx::Size(current_size.height(), current_size.width());
  }
  return current_size;
}

gfx::Size WebMediaPlayerMS::VisibleSize() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  scoped_refptr<media::VideoFrame> video_frame = compositor_->GetCurrentFrame();
  if (!video_frame)
    return gfx::Size();

  const gfx::Rect& visible_rect = video_frame->visible_rect();
  const auto rotation = GetFrameTransformation(video_frame).rotation;
  if (rotation == media::VIDEO_ROTATION_90 ||
      rotation == media::VIDEO_ROTATION_270) {
    return gfx::Size(visible_rect.height(), visible_rect.width());
  }
  return visible_rect.size();
}

bool WebMediaPlayerMS::Paused() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return paused_;
}

bool WebMediaPlayerMS::Seeking() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return false;
}

double WebMediaPlayerMS::Duration() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return std::numeric_limits<double>::infinity();
}

double WebMediaPlayerMS::CurrentTime() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  const base::TimeDelta current_time =
      GetFrameTime(compositor_->GetCurrentFrame());
  if (current_time.ToInternalValue() != 0)
    return current_time.InSecondsF();
  else if (audio_renderer_.get())
    return audio_renderer_->GetCurrentRenderTime().InSecondsF();
  return 0.0;
}

bool WebMediaPlayerMS::IsEnded() const {
  // MediaStreams never end.
  return false;
}

WebMediaPlayer::NetworkState WebMediaPlayerMS::GetNetworkState() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return network_state_;
}

WebMediaPlayer::ReadyState WebMediaPlayerMS::GetReadyState() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return ready_state_;
}

WebString WebMediaPlayerMS::GetErrorMessage() const {
  return WebString::FromUTF8(media_log_->GetErrorMessage());
}

WebTimeRanges WebMediaPlayerMS::Buffered() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return buffered_;
}

WebTimeRanges WebMediaPlayerMS::Seekable() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return WebTimeRanges();
}

void WebMediaPlayerMS::OnFrozen() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(paused_);
}

bool WebMediaPlayerMS::DidLoadingProgress() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return true;
}

void WebMediaPlayerMS::Paint(cc::PaintCanvas* canvas,
                             const gfx::Rect& rect,
                             cc::PaintFlags& flags) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  const scoped_refptr<media::VideoFrame> frame = compositor_->GetCurrentFrame();

  scoped_refptr<viz::RasterContextProvider> provider;
  if (frame && frame->HasSharedImage()) {
    provider = Platform::Current()->SharedMainThreadContextProvider();
    // GPU Process crashed.
    if (!provider)
      return;
  }
  media::PaintCanvasVideoRenderer::PaintParams paint_params;
  paint_params.dest_rect = gfx::RectF(rect);
  paint_params.transformation = GetFrameTransformation(frame);
  video_renderer_.Paint(frame, canvas, flags, paint_params, provider.get());
}

scoped_refptr<media::VideoFrame> WebMediaPlayerMS::GetCurrentFrameThenUpdate() {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return compositor_->GetCurrentFrame();
}

std::optional<media::VideoFrame::ID> WebMediaPlayerMS::CurrentFrameId() const {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return compositor_->GetCurrentFrame()->unique_id();
}

bool WebMediaPlayerMS::WouldTaintOrigin() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return false;
}

double WebMediaPlayerMS::MediaTimeForTimeValue(double timeValue) const {
  return base::Seconds(timeValue).InSecondsF();
}

unsigned WebMediaPlayerMS::DecodedFrameCount() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return static_cast<unsigned>(compositor_->total_frame_count());
}

unsigned WebMediaPlayerMS::DroppedFrameCount() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return static_cast<unsigned>(compositor_->dropped_frame_count());
}

uint64_t WebMediaPlayerMS::AudioDecodedByteCount() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  NOTIMPLEMENTED();
  return 0;
}

uint64_t WebMediaPlayerMS::VideoDecodedByteCount() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  NOTIMPLEMENTED();
  return 0;
}

bool WebMediaPlayerMS::HasAvailableVideoFrame() const {
  return has_first_frame_;
}

bool WebMediaPlayerMS::HasReadableVideoFrame() const {
  return has_first_frame_;
}

void WebMediaPlayerMS::OnPageHidden() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  bool in_picture_in_picture =
      client_->GetDisplayType() == DisplayType::kPictureInPicture;

  if (watch_time_reporter_ && !in_picture_in_picture)
    watch_time_reporter_->OnHidden();

  // This method is called when the RenderFrame is sent to background or
  // suspended. During undoable tab closures OnHidden() may be called back to
  // back, so we can't rely on |render_frame_suspended_| being false here.
  if (frame_deliverer_ && !in_picture_in_picture) {
    PostCrossThreadTask(
        *video_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&FrameDeliverer::SetRenderFrameSuspended,
                            CrossThreadUnretained(frame_deliverer_.get()),
                            true));
  }

  PostCrossThreadTask(
      *compositor_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&WebMediaPlayerMSCompositor::SetIsPageVisible,
                          CrossThreadUnretained(compositor_.get()), false));

// On Android, substitute the displayed VideoFrame with a copy to avoid holding
// onto it unnecessarily.
#if BUILDFLAG(IS_ANDROID)
  if (!paused_)
    compositor_->ReplaceCurrentFrameWithACopy();
#endif  // BUILDFLAG(IS_ANDROID)
}

void WebMediaPlayerMS::SuspendForFrameClosed() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

// On Android, pause the video completely for this time period.
#if BUILDFLAG(IS_ANDROID)
  if (!paused_) {
    Pause();
    should_play_upon_shown_ = true;
  }

  delegate_->PlayerGone(delegate_id_);
#endif  // BUILDFLAG(IS_ANDROID)

  if (frame_deliverer_) {
    PostCrossThreadTask(
        *video_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&FrameDeliverer::SetRenderFrameSuspended,
                            CrossThreadUnretained(frame_deliverer_.get()),
                            true));
  }
}

void WebMediaPlayerMS::OnPageShown() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (watch_time_reporter_)
    watch_time_reporter_->OnShown();

  if (frame_deliverer_) {
    PostCrossThreadTask(
        *video_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&FrameDeliverer::SetRenderFrameSuspended,
                            CrossThreadUnretained(frame_deliverer_.get()),
                            false));
  }

  PostCrossThreadTask(
      *compositor_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&WebMediaPlayerMSCompositor::SetIsPageVisible,
                          CrossThreadUnretained(compositor_.get()), true));

// On Android, resume playback on visibility. play() clears
// |should_play_upon_shown_|.
#if BUILDFLAG(IS_ANDROID)
  if (should_play_upon_shown_)
    Play();
#endif  // BUILDFLAG(IS_ANDROID)
}

void WebMediaPlayerMS::OnIdleTimeout() {}

void WebMediaPlayerMS::OnFrameShown() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  OnPageShown();
}

void WebMediaPlayerMS::OnFrameHidden() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  OnPageHidden();
}

void WebMediaPlayerMS::SetVolumeMultiplier(double multiplier) {
  // TODO(perkj, magjed): See TODO in OnPlay().
}

void WebMediaPlayerMS::ActivateSurfaceLayerForVideo(
    media::VideoTransformation video_transform) {
  // Note that we might or might not already be in VideoLayer mode.
  DCHECK(!bridge_);

  // If we're in VideoLayer mode, then get rid of the layer.
  if (video_layer_) {
    client_->SetCcLayer(nullptr);
    video_layer_ = nullptr;
  }

  bridge_ = std::move(create_bridge_callback_)
                .Run(this, compositor_->GetUpdateSubmissionStateCallback());
  bridge_->CreateSurfaceLayer();
  bridge_->SetContentsOpaque(opaque_);

  PostCrossThreadTask(
      *compositor_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&WebMediaPlayerMSCompositor::EnableSubmission,
                          CrossThreadUnretained(compositor_.get()),
                          bridge_->GetSurfaceId(), video_transform,
                          IsInPictureInPicture()));

  // If the element is already in Picture-in-Picture mode, it means that it
  // was set in this mode prior to this load, with a different
  // WebMediaPlayerImpl. The new player needs to send its id, size and
  // surface id to the browser process to make sure the states are properly
  // updated.
  // TODO(872056): the surface should be activated but for some reason, it
  // does not. It is possible that this will no longer be needed after 872056
  // is fixed.
  if (client_->GetDisplayType() == DisplayType::kPictureInPicture) {
    OnSurfaceIdUpdated(bridge_->GetSurfaceId());
  }
}

void WebMediaPlayerMS::OnFirstFrameReceived(
    media::VideoTransformation video_transform,
    bool is_opaque) {
  DVLOG(1) << __func__;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  has_first_frame_ = true;
  OnTransformChanged(video_transform);
  OnOpacityChanged(is_opaque);

  if (use_surface_layer_)
    ActivateSurfaceLayerForVideo(video_transform);

  SetReadyState(WebMediaPlayer::kReadyStateHaveMetadata);
  SetReadyState(WebMediaPlayer::kReadyStateHaveEnoughData);
  TriggerResize();
  ResetCanvasCache();
  MaybeCreateWatchTimeReporter();
}

void WebMediaPlayerMS::OnOpacityChanged(bool is_opaque) {
  DVLOG(1) << __func__;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  opaque_ = is_opaque;
  if (!bridge_) {
    // Opacity can be changed during the session without resetting
    // |video_layer_|.
    video_layer_->SetContentsOpaque(opaque_);
  } else {
    DCHECK(bridge_);
    bridge_->SetContentsOpaque(opaque_);
  }
}

void WebMediaPlayerMS::OnTransformChanged(
    media::VideoTransformation video_transform) {
  DVLOG(1) << __func__;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!bridge_) {
    // Keep the old |video_layer_| alive until SetCcLayer() is called with a new
    // pointer, as it may use the pointer from the last call.
    auto new_video_layer =
        cc::VideoLayer::Create(compositor_.get(), video_transform);
    get_client()->SetCcLayer(new_video_layer.get());
    video_layer_ = std::move(new_video_layer);
  }
}

bool WebMediaPlayerMS::IsInPictureInPicture() const {
  DCHECK(client_);
  return (!client_->IsInAutoPIP() &&
          client_->GetDisplayType() == DisplayType::kPictureInPicture);
}

void WebMediaPlayerMS::RepaintInternal() {
  DVLOG(1) << __func__;
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  get_client()->Repaint();
}

void WebMediaPlayerMS::SetNetworkState(WebMediaPlayer::NetworkState state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(String::Format("%s => (state=%s)", __func__,
                                NetworkStateToString(network_state_)));
  network_state_ = state;
  // Always notify to ensure client has the latest value.
  get_client()->NetworkStateChanged();
}

void WebMediaPlayerMS::SetReadyState(WebMediaPlayer::ReadyState state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(String::Format("%s => (state=%s)", __func__,
                                ReadyStateToString(ready_state_)));
  ready_state_ = state;
  // Always notify to ensure client has the latest value.
  get_client()->ReadyStateChanged();
}

media::PaintCanvasVideoRenderer*
WebMediaPlayerMS::GetPaintCanvasVideoRenderer() {
  return &video_renderer_;
}

void WebMediaPlayerMS::ResetCanvasCache() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  video_renderer_.ResetCache();
}

void WebMediaPlayerMS::TriggerResize() {
  if (HasVideo())
    get_client()->SizeChanged();

  client_->DidPlayerSizeChange(NaturalSize());
  if (watch_time_reporter_)
    UpdateWatchTimeReporterSecondaryProperties();
}

void WebMediaPlayerMS::SetGpuMemoryBufferVideoForTesting(
    media::GpuMemoryBufferVideoFramePool* gpu_memory_buffer_pool) {
  CHECK(frame_deliverer_);
  frame_deliverer_->gpu_memory_buffer_pool_.reset(gpu_memory_buffer_pool);
}

void WebMediaPlayerMS::SetMediaStreamRendererFactoryForTesting(
    std::unique_ptr<MediaStreamRendererFactory> renderer_factory) {
  renderer_factory_ = std::move(renderer_factory);
}

void WebMediaPlayerMS::OnDisplayTypeChanged(DisplayType display_type) {
  if (!bridge_)
    return;

  PostCrossThreadTask(
      *compositor_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&WebMediaPlayerMSCompositor::SetForceSubmit,
                          CrossThreadUnretained(compositor_.get()),
                          display_type == DisplayType::kPictureInPicture));

  if (!watch_time_reporter_)
    return;

  switch (display_type) {
    case DisplayType::kInline:
      watch_time_reporter_->OnDisplayTypeInline();
      break;
    case DisplayType::kFullscreen:
      watch_time_reporter_->OnDisplayTypeFullscreen();
      break;
    case DisplayType::kPictureInPicture:
      watch_time_reporter_->OnDisplayTypePictureInPicture();
  }
}

void WebMediaPlayerMS::OnNewFramePresentedCallback() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  client_->OnRequestVideoFrameCallback();
}

void WebMediaPlayerMS::SendLogMessage(const WTF::String& message) const {
  WebRtcLogMessage("WMPMS::" + message.Utf8() +
                   String::Format(" [delegate_id=%d]", delegate_id_).Utf8());
}

std::unique_ptr<WebMediaPlayer::VideoFramePresentationMetadata>
WebMediaPlayerMS::GetVideoFramePresentationMetadata() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(compositor_);

  return compositor_->GetLastPresentedFrameMetadata();
}

void WebMediaPlayerMS::RequestVideoFrameCallback() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (!compositor_) {
    // Reissue the request after |compositor_| is created, in Load().
    pending_rvfc_request_ = true;
    return;
  }

  compositor_->SetOnFramePresentedCallback(
      base::BindPostTaskToCurrentDefault(base::BindOnce(
          &WebMediaPlayerMS::OnNewFramePresentedCallback, weak_this_)));

  compositor_->SetForceBeginFrames(true);

  stop_force_begin_frames_timer_->StartOneShot(kForceBeginFramesTimeout,
                                               FROM_HERE);
}

void WebMediaPlayerMS::StopForceBeginFrames(TimerBase* timer) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  compositor_->SetForceBeginFrames(false);
}

void WebMediaPlayerMS::MaybeCreateWatchTimeReporter() {
  if (!internal_frame_->web_frame())
    return;

  if (!HasAudio() && !HasVideo())
    return;

  std::optional<media::mojom::MediaStreamType> media_stream_type =
      GetMediaStreamType();
  if (!media_stream_type)
    return;

  if (watch_time_reporter_)
    return;

  if (compositor_) {
    compositor_initial_time_ = GetFrameTime(compositor_->GetCurrentFrame());
    compositor_last_time_ = compositor_initial_time_;
  }
  if (audio_renderer_) {
    audio_initial_time_ = audio_renderer_->GetCurrentRenderTime();
    audio_last_time_ = audio_initial_time_;
  }

  mojo::Remote<media::mojom::MediaMetricsProvider> media_metrics_provider;
  auto* execution_context =
      internal_frame_->frame()->DomWindow()->GetExecutionContext();
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      execution_context->GetTaskRunner(TaskType::kMediaElementEvent);
  execution_context->GetBrowserInterfaceBroker().GetInterface(
      media_metrics_provider.BindNewPipeAndPassReceiver(task_runner));
  media_metrics_provider->Initialize(false /* is_mse */,
                                     media::mojom::MediaURLScheme::kMissing,
                                     *media_stream_type);

  // Create the watch time reporter and synchronize its initial state.
  // WTF::Unretained() is safe because WebMediaPlayerMS owns the
  // |watch_time_reporter_|, and therefore outlives it.
  watch_time_reporter_ = std::make_unique<WatchTimeReporter>(
      media::mojom::PlaybackProperties::New(
          HasAudio(), HasVideo(), false /*is_background*/, false /*is_muted*/,
          false /*is_mse*/, false /*is_eme*/,
          false /*is_embedded_media_experience*/, *media_stream_type,
          media::RendererType::kRendererImpl),
      NaturalSize(),
      WTF::BindRepeating(&WebMediaPlayerMS::GetCurrentTimeInterval,
                         WTF::Unretained(this)),
      WTF::BindRepeating(&WebMediaPlayerMS::GetPipelineStatistics,
                         WTF::Unretained(this)),
      media_metrics_provider.get(),
      internal_frame_->web_frame()->GetTaskRunner(
          blink::TaskType::kInternalMedia));

  watch_time_reporter_->OnVolumeChange(volume_);

  if (delegate_->IsPageHidden()) {
    watch_time_reporter_->OnHidden();
  } else {
    watch_time_reporter_->OnShown();
  }

  if (client_) {
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
  }

  UpdateWatchTimeReporterSecondaryProperties();

  // If the WatchTimeReporter was recreated in the middle of playback, we want
  // to resume playback here too since we won't get another play() call.
  if (!paused_)
    watch_time_reporter_->OnPlaying();
}

void WebMediaPlayerMS::UpdateWatchTimeReporterSecondaryProperties() {
  // Set only the natural size and use default values for the other secondary
  // properties. MediaStreams generally operate with raw data, where there is no
  // codec information. For the MediaStreams where coded information is
  // available, the coded information is currently not accessible to the media
  // player.
  // TODO(https://crbug.com/1147813) Report codec information once accessible.
  watch_time_reporter_->UpdateSecondaryProperties(
      media::mojom::SecondaryPlaybackProperties::New(
          media::AudioCodec::kUnknown, media::VideoCodec::kUnknown,
          media::AudioCodecProfile::kUnknown,
          media::VideoCodecProfile::VIDEO_CODEC_PROFILE_UNKNOWN,
          media::AudioDecoderType::kUnknown, media::VideoDecoderType::kUnknown,
          media::EncryptionScheme::kUnencrypted,
          media::EncryptionScheme::kUnencrypted, NaturalSize()));
}

base::TimeDelta WebMediaPlayerMS::GetCurrentTimeInterval() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (compositor_) {
    compositor_last_time_ = std::max(
        compositor_last_time_, GetFrameTime(compositor_->GetCurrentFrame()));
  }
  if (audio_renderer_) {
    audio_last_time_ =
        std::max(audio_last_time_, audio_renderer_->GetCurrentRenderTime());
  }

  base::TimeDelta compositor_interval =
      compositor_last_time_ - compositor_initial_time_;
  base::TimeDelta audio_interval = audio_last_time_ - audio_initial_time_;
  return std::max(compositor_interval, audio_interval);
}

media::PipelineStatistics WebMediaPlayerMS::GetPipelineStatistics() {
  media::PipelineStatistics stats;
  stats.video_frames_decoded = DecodedFrameCount();
  stats.video_frames_dropped = DroppedFrameCount();
  return stats;
}

std::optional<media::mojom::MediaStreamType>
WebMediaPlayerMS::GetMediaStreamType() {
  if (web_stream_.IsNull())
    return std::nullopt;

  // If either the first video or audio source is remote, the media stream is
  // of remote source.
  MediaStreamDescriptor& descriptor = *web_stream_;
  MediaStreamSource* media_source = nullptr;
  if (HasVideo()) {
    auto video_components = descriptor.VideoComponents();
    DCHECK_GT(video_components.size(), 0U);
    media_source = video_components[0]->Source();
  } else if (HasAudio()) {
    auto audio_components = descriptor.AudioComponents();
    DCHECK_GT(audio_components.size(), 0U);
    media_source = audio_components[0]->Source();
  }
  if (!media_source)
    return std::nullopt;
  if (media_source->Remote())
    return media::mojom::MediaStreamType::kRemote;

  auto* platform_source = media_source->GetPlatformSource();
  if (!platform_source)
    return std::nullopt;
  switch (platform_source->device().type) {
    case mojom::blink::MediaStreamType::NO_SERVICE:
      // Element capture uses the default NO_SERVICE value since it does not set
      // a device.
      return media::mojom::MediaStreamType::kLocalElementCapture;
    case mojom::blink::MediaStreamType::DEVICE_AUDIO_CAPTURE:
    case mojom::blink::MediaStreamType::DEVICE_VIDEO_CAPTURE:
      return media::mojom::MediaStreamType::kLocalDeviceCapture;
    case mojom::blink::MediaStreamType::GUM_TAB_AUDIO_CAPTURE:
    case mojom::blink::MediaStreamType::GUM_TAB_VIDEO_CAPTURE:
      return media::mojom::MediaStreamType::kLocalTabCapture;
    case mojom::blink::MediaStreamType::GUM_DESKTOP_AUDIO_CAPTURE:
    case mojom::blink::MediaStreamType::GUM_DESKTOP_VIDEO_CAPTURE:
      return media::mojom::MediaStreamType::kLocalDesktopCapture;
    case mojom::blink::MediaStreamType::DISPLAY_AUDIO_CAPTURE:
    case mojom::blink::MediaStreamType::DISPLAY_VIDEO_CAPTURE:
    case mojom::blink::MediaStreamType::DISPLAY_VIDEO_CAPTURE_THIS_TAB:
    case mojom::blink::MediaStreamType::DISPLAY_VIDEO_CAPTURE_SET:
      return media::mojom::MediaStreamType::kLocalDisplayCapture;
    case mojom::blink::MediaStreamType::NUM_MEDIA_TYPES:
      NOTREACHED();
  }

  return std::nullopt;
}

void WebMediaPlayerMS::RegisterFrameSinkHierarchy() {
  if (bridge_)
    bridge_->RegisterFrameSinkHierarchy();
}

void WebMediaPlayerMS::UnregisterFrameSinkHierarchy() {
  if (bridge_)
    bridge_->UnregisterFrameSinkHierarchy();
}

}  // namespace blink

"""


```