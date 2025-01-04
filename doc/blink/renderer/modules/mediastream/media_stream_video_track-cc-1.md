Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the Chromium Blink engine and deals with video tracks in media streams. I need to analyze the methods and members of the `MediaStreamVideoTrack` class to understand its role and interactions.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The class name `MediaStreamVideoTrack` clearly indicates its responsibility: managing a single video track within a media stream.

2. **Analyze constructors:** The constructors reveal how `MediaStreamVideoTrack` objects are created. They take a `MediaStreamVideoSource` as input, along with various settings like adapter settings, noise reduction, and frame rate. This suggests the track's primary function is to represent and manage the flow of video data from a source.

3. **Examine key methods related to data flow:**
    * `AddSink` and `RemoveSink`:  These methods manage connections to "sinks," which are consumers of the video frames. This is a crucial aspect of a media track. The callbacks associated with `AddSink` suggest frame delivery mechanisms.
    * `AddEncodedSink` and `RemoveEncodedSink`: Similar to the above but for encoded video frames. This indicates support for both raw and encoded video.
    * `DeliverFrameOnVideoTaskRunner` and `DeliverEncodedVideoFrameOnVideoTaskRunner`: These methods, used within the `FrameDeliverer`, are the core of the frame delivery process.
    * `FrameDeliverer`: This nested class is responsible for the actual delivery of video frames to sinks, handling threading and callbacks.

4. **Analyze methods related to track control and configuration:**
    * `SetEnabled`: Controls whether the track is active.
    * `SetMinimumFrameRate`, `SetTrackAdapterSettings`:  Allow modification of track properties.
    * `GetSettings`: Provides information about the current track configuration.
    * `StopAndNotify`:  Handles the termination of the video track.

5. **Look for interactions with other components:**
    * `MediaStreamVideoSource`: The source of the video data. The `MediaStreamVideoTrack` heavily relies on the source.
    * `WebMediaStreamSink`: The destination for video frames.
    * `EncodedVideoFrameCB`, `VideoCaptureDeliverFrameCB`: Callback types used for data delivery.
    * `MediaStreamComponent`:  Used in `CreateFromComponent`, indicating the track's place within a larger media stream structure.

6. **Identify potential connections to web technologies:**
    * The presence of `WebMediaStreamSink` suggests direct interaction with JavaScript's Media Streams API.
    * Methods like `GetSettings` and the properties within the `Settings` struct (width, height, frame_rate, facing_mode, resize_mode) map to properties exposed in the JavaScript API.
    * The concept of "sinks" directly corresponds to the `MediaStreamTrack.addSink()` method in JavaScript.

7. **Infer logical reasoning and potential issues:**
    * Frame dropping (`OnFrameDroppedOnVideoTaskRunner`) is a concern, and the code includes mechanisms for handling and reporting it.
    * The `FrameDeliverer` manages threading to ensure smooth delivery.
    * The use of `WeakPtr` suggests careful handling of object lifetimes.
    * The `secure_tracker_` and alpha-related sets indicate considerations for secure contexts and alpha channel handling.

8. **Consider user interactions:** The code is not directly triggered by user actions but represents the underlying implementation of browser features. User actions like granting camera access, selecting a screen to share, or viewing a video stream in a web page will eventually lead to the creation and manipulation of these `MediaStreamVideoTrack` objects.

9. **Structure the summary:**  Organize the findings into logical categories: core functionality, interactions with other components, connections to web technologies, potential issues, and user interaction scenarios.

10. **Refine and elaborate:** Provide specific examples for the connections to JavaScript, HTML, and CSS where applicable (though CSS interaction is indirect, affecting the rendering of video elements). Explain the assumptions made for input/output scenarios related to frame delivery.

11. **Address the "Part 2" request:**  Since this is the second part, focus on summarizing the already detailed information from Part 1.

By following these steps, I can arrive at a comprehensive and accurate summary of the `MediaStreamVideoTrack`'s functionality.
好的，这是对 `blink/renderer/modules/mediastream/media_stream_video_track.cc` 文件功能的归纳总结：

**核心功能:**

`MediaStreamVideoTrack` 类在 Chromium Blink 引擎中负责管理和控制视频媒体流中的**单个视频轨道 (Video Track)**。  它是 `MediaStreamTrackPlatform` 的一个具体实现，专门处理视频数据。

**主要职责包括:**

* **管理视频源 (MediaStreamVideoSource):**  它持有视频数据来源的引用，并与源进行交互，请求帧数据、更新源的状态等。
* **处理视频帧的传递:**  它使用 `FrameDeliverer` 内部类来管理视频帧向多个“接收器 (Sinks)”的传递，包括原始视频帧和编码后的视频帧。
* **管理视频接收器 (WebMediaStreamSink):**  允许添加和移除视频帧的消费者，例如 `<video>` 元素或 JavaScript 代码创建的接收器。
* **处理视频编码接收器 (Encoded Sinks):** 允许添加和移除编码后视频帧的消费者，用于需要直接处理编码数据的场景。
* **应用视频约束 (Constraints):**  处理应用于视频轨道的约束，例如最小帧率、分辨率等，并通知接收器。
* **控制轨道状态:**  例如，启用/禁用轨道 (`SetEnabled`)，停止轨道 (`StopAndNotify`)。
* **提供轨道信息:**  例如，获取当前视频尺寸 (`GetVideoSize`)，获取轨道设置 (`GetSettings`)，获取帧统计信息 (`GetVideoFrameStats`)。
* **处理屏幕共享相关的特性:**  例如，处理子捕获目标版本更新，以及根据最小帧率需求定时请求刷新帧。
* **处理安全性:** 跟踪哪些接收器是安全的上下文。
* **处理 Alpha 通道:**  管理是否保留或丢弃 Alpha 通道信息。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**
    * 当 JavaScript 代码使用 `navigator.mediaDevices.getUserMedia()` 或 `getDisplayMedia()` 获取媒体流时，`MediaStreamVideoTrack` 对象会被创建来代表视频轨道。
    * JavaScript 可以通过 `MediaStreamTrack` 接口的方法（例如 `enabled`, `stop()`, `getSettings()`, `addSink()`) 来控制和获取 `MediaStreamVideoTrack` 的状态和信息。 例如，在 JavaScript 中设置 `videoTrack.enabled = false` 会调用到 `MediaStreamVideoTrack::SetEnabled(false)`。
    * JavaScript 可以通过 `MediaStreamTrack.addSink()` 方法添加一个 `MediaStreamSink` 对象，这会最终调用到 `MediaStreamVideoTrack::AddSink()`，开始接收视频帧。
    * JavaScript 可以监听 `MediaStreamTrack` 的 `onended` 事件，这与 `MediaStreamVideoTrack::OnReadyStateChanged(kReadyStateEnded)` 相关。

* **HTML:**
    * 当 HTML 中的 `<video>` 元素被赋予一个包含视频轨道的 `MediaStream` 对象时，Blink 引擎会在内部创建一个 `WebMediaStreamSink` 与该 `<video>` 元素关联。`MediaStreamVideoTrack::AddSink()` 会被调用，将帧数据传递给 `<video>` 元素进行渲染。
    * `<video>` 元素的属性，如 `width` 和 `height`，会影响视频的渲染，但直接与 `MediaStreamVideoTrack` 的交互较少。

* **CSS:**
    * CSS 可以控制 `<video>` 元素的样式和布局，例如大小、边框等。但这与 `MediaStreamVideoTrack` 的功能没有直接的逻辑关系。CSS 主要负责视觉呈现，而 `MediaStreamVideoTrack` 负责视频数据的管理和传递。

**逻辑推理 (假设输入与输出):**

假设输入：

1. **JavaScript 调用 `videoTrack.addSink(mySink)`:**  `mySink` 是一个 JavaScript 创建的 `MediaStreamSink` 对象。
2. **视频源产生新的视频帧。**

输出：

1. `MediaStreamVideoTrack::AddSink()` 被调用，将 `mySink` 添加到内部的接收器列表中。
2. `FrameDeliverer::DeliverFrameOnVideoTaskRunner()` (或其他帧传递方法) 会将新的视频帧传递给 `mySink` (通过其关联的回调函数)。
3. `mySink` 对象（在 JavaScript 中）会接收到视频帧数据。

**用户或编程常见的使用错误举例:**

* **用户错误:** 用户在浏览器设置中禁用了摄像头的访问权限，导致 `navigator.mediaDevices.getUserMedia()` 请求失败，从而无法创建 `MediaStreamVideoTrack` 对象。
* **编程错误:**
    * 在 `MediaStreamVideoTrack` 停止后，仍然尝试向其添加接收器，可能导致程序崩溃或未定义的行为。
    * 没有正确处理 `MediaStreamTrack` 的 `onended` 事件，导致在视频流结束后，相关的资源没有被释放。
    * 在 JavaScript 中错误地操作 `MediaStreamTrack` 对象，例如过早地调用 `stop()`，可能导致视频流中断。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户打开一个网页，该网页使用了 WebRTC 或 Media Streams API。**
2. **网页 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: true })` 或 `navigator.mediaDevices.getDisplayMedia()` 请求访问摄像头或屏幕共享。**
3. **浏览器会弹出权限请求，用户允许了该请求。**
4. **浏览器底层会创建一个 `MediaStreamVideoSource` 对象来获取视频数据。**
5. **Blink 引擎会创建一个 `MediaStreamVideoTrack` 对象，并将 `MediaStreamVideoSource` 与之关联。**
6. **如果网页在 HTML 中包含 `<video>` 元素，并且将获取到的 `MediaStream` 对象赋值给 `<video>` 元素的 `srcObject` 属性，Blink 引擎会创建一个 `WebMediaStreamSink` 与该 `<video>` 元素关联，并调用 `MediaStreamVideoTrack::AddSink()` 将其添加到接收器列表中。**
7. **视频源开始产生视频帧，这些帧通过 `MediaStreamVideoTrack` 和 `FrameDeliverer` 被传递到 `<video>` 元素进行渲染。**
8. **如果网页 JavaScript 代码调用了 `videoTrack.addSink(mySink)`，也会触发 `MediaStreamVideoTrack::AddSink()`。**

**总结 (Part 2):**

总而言之，`blink/renderer/modules/mediastream/media_stream_video_track.cc` 中定义的 `MediaStreamVideoTrack` 类是 Blink 引擎中处理视频媒体流的核心组件。它负责管理视频数据的来源、分发给不同的消费者（渲染器、JavaScript 代码等）、应用视频约束，并控制视频轨道的生命周期和状态。它在 WebRTC 和 Media Streams API 的实现中扮演着至关重要的角色，连接了底层的视频捕获和上层的 JavaScript 和 HTML 接口。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_video_track.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
->Owner(),
      std::make_unique<MediaStreamVideoTrack>(
          source, adapter_settings, noise_reduction, is_screencast,
          min_frame_rate, image_capture_device_settings, pan_tilt_zoom_allowed,
          std::move(callback), enabled));
  return WebMediaStreamTrack(component);
}

// static
MediaStreamVideoTrack* MediaStreamVideoTrack::From(
    const MediaStreamComponent* component) {
  if (!component ||
      component->GetSourceType() != MediaStreamSource::kTypeVideo) {
    return nullptr;
  }

  return static_cast<MediaStreamVideoTrack*>(component->GetPlatformTrack());
}

MediaStreamVideoTrack::MediaStreamVideoTrack(
    MediaStreamVideoSource* source,
    MediaStreamVideoSource::ConstraintsOnceCallback callback,
    bool enabled)
    : MediaStreamTrackPlatform(true),
      is_screencast_(false),
      source_(source->GetWeakPtr()) {
  frame_deliverer_ =
      base::MakeRefCounted<MediaStreamVideoTrack::FrameDeliverer>(
          source->GetTaskRunner(), source->video_task_runner(),
          weak_factory_.GetWeakPtr(), source->GetWeakPtr(), enabled,
          source->GetSubCaptureTargetVersion());
  source->AddTrack(
      this, VideoTrackAdapterSettings(),
      ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
          &MediaStreamVideoTrack::FrameDeliverer::DeliverFrameOnVideoTaskRunner,
          frame_deliverer_)),
      ConvertToBaseRepeatingCallback(
          CrossThreadBindRepeating(&MediaStreamVideoTrack::FrameDeliverer::
                                       OnFrameDroppedOnVideoTaskRunner,
                                   frame_deliverer_)),
      ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
          &MediaStreamVideoTrack::FrameDeliverer::
              DeliverEncodedVideoFrameOnVideoTaskRunner,
          frame_deliverer_)),
      ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
          &MediaStreamVideoTrack::FrameDeliverer::
              NewSubCaptureTargetVersionOnVideoTaskRunner,
          frame_deliverer_)),
      base::BindPostTaskToCurrentDefault(WTF::BindRepeating(
          &MediaStreamVideoTrack::SetSizeAndComputedFrameRate,
          weak_factory_.GetWeakPtr())),
      base::BindPostTaskToCurrentDefault(
          WTF::BindRepeating(&MediaStreamVideoTrack::set_computed_source_format,
                             weak_factory_.GetWeakPtr())),
      std::move(callback));
}

MediaStreamVideoTrack::MediaStreamVideoTrack(
    MediaStreamVideoSource* source,
    const VideoTrackAdapterSettings& adapter_settings,
    const std::optional<bool>& noise_reduction,
    bool is_screen_cast,
    const std::optional<double>& min_frame_rate,
    const ImageCaptureDeviceSettings* image_capture_device_settings,
    bool pan_tilt_zoom_allowed,
    MediaStreamVideoSource::ConstraintsOnceCallback callback,
    bool enabled)
    : MediaStreamTrackPlatform(true),
      adapter_settings_(adapter_settings),
      noise_reduction_(noise_reduction),
      is_screencast_(is_screen_cast),
      min_frame_rate_(min_frame_rate),
      image_capture_device_settings_(
          image_capture_device_settings
              ? std::make_optional(*image_capture_device_settings)
              : std::nullopt),
      pan_tilt_zoom_allowed_(pan_tilt_zoom_allowed),
      source_(source->GetWeakPtr()) {
  frame_deliverer_ =
      base::MakeRefCounted<MediaStreamVideoTrack::FrameDeliverer>(
          source->GetTaskRunner(), source->video_task_runner(),
          weak_factory_.GetWeakPtr(), source->GetWeakPtr(), enabled,
          source->GetSubCaptureTargetVersion());
  source->AddTrack(
      this, adapter_settings,
      ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
          &MediaStreamVideoTrack::FrameDeliverer::DeliverFrameOnVideoTaskRunner,
          frame_deliverer_)),
      ConvertToBaseRepeatingCallback(
          CrossThreadBindRepeating(&MediaStreamVideoTrack::FrameDeliverer::
                                       OnFrameDroppedOnVideoTaskRunner,
                                   frame_deliverer_)),
      ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
          &MediaStreamVideoTrack::FrameDeliverer::
              DeliverEncodedVideoFrameOnVideoTaskRunner,
          frame_deliverer_)),
      ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
          &MediaStreamVideoTrack::FrameDeliverer::
              NewSubCaptureTargetVersionOnVideoTaskRunner,
          frame_deliverer_)),
      base::BindPostTaskToCurrentDefault(WTF::BindRepeating(
          &MediaStreamVideoTrack::SetSizeAndComputedFrameRate,
          weak_factory_.GetWeakPtr())),
      base::BindPostTaskToCurrentDefault(
          WTF::BindRepeating(&MediaStreamVideoTrack::set_computed_source_format,
                             weak_factory_.GetWeakPtr())),
      std::move(callback));
}

MediaStreamVideoTrack::~MediaStreamVideoTrack() {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  DCHECK(sinks_.empty());
  DCHECK(encoded_sinks_.empty());
  Stop();
  DVLOG(3) << "~MediaStreamVideoTrack()";
}

std::unique_ptr<MediaStreamTrackPlatform>
MediaStreamVideoTrack::CreateFromComponent(
    const MediaStreamComponent* component,
    const String& id) {
  MediaStreamSource* source = component->Source();
  DCHECK_EQ(source->GetType(), MediaStreamSource::kTypeVideo);
  MediaStreamVideoSource* native_source =
      MediaStreamVideoSource::GetVideoSource(source);
  DCHECK(native_source);
  MediaStreamVideoTrack* original_track =
      MediaStreamVideoTrack::From(component);
  DCHECK(original_track);
  return std::make_unique<MediaStreamVideoTrack>(
      native_source, original_track->adapter_settings(),
      original_track->noise_reduction(), original_track->is_screencast(),
      original_track->min_frame_rate(),
      original_track->image_capture_device_settings()
          ? &*original_track->image_capture_device_settings()
          : nullptr,
      original_track->pan_tilt_zoom_allowed(),
      MediaStreamVideoSource::ConstraintsOnceCallback(), component->Enabled());
}

static void AddSinkInternal(Vector<WebMediaStreamSink*>* sinks,
                            WebMediaStreamSink* sink) {
  DCHECK(!base::Contains(*sinks, sink));
  sinks->push_back(sink);
}

static void RemoveSinkInternal(Vector<WebMediaStreamSink*>* sinks,
                               WebMediaStreamSink* sink) {
  auto it = base::ranges::find(*sinks, sink);
  CHECK(it != sinks->end(), base::NotFatalUntil::M130);
  sinks->erase(it);
}

void MediaStreamVideoTrack::AddSink(
    WebMediaStreamSink* sink,
    const VideoCaptureDeliverFrameCB& callback,
    MediaStreamVideoSink::IsSecure is_secure,
    MediaStreamVideoSink::UsesAlpha uses_alpha) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  AddSinkInternal(&sinks_, sink);
  frame_deliverer_->AddCallback(sink, callback);
  secure_tracker_.Add(sink, is_secure == MediaStreamVideoSink::IsSecure::kYes);
  if (uses_alpha == MediaStreamVideoSink::UsesAlpha::kDefault) {
    alpha_using_sinks_.insert(sink);
  } else if (uses_alpha == MediaStreamVideoSink::UsesAlpha::kNo) {
    alpha_discarding_sinks_.insert(sink);
  }

  // Ensure sink gets told about any constraints set.
  sink->OnVideoConstraintsChanged(min_frame_rate_,
                                  adapter_settings_.max_frame_rate());

  // Request source to deliver a frame because a new sink is added.
  if (!source_)
    return;
  UpdateSourceHasConsumers();
  RequestRefreshFrame();
  source_->UpdateCapturingLinkSecure(this,
                                     secure_tracker_.is_capturing_secure());

  source_->UpdateCanDiscardAlpha();

  if (is_screencast_)
    StartTimerForRequestingFrames();
}

bool MediaStreamVideoTrack::UsingAlpha() const {
  // Alpha can't be discarded if any sink uses alpha, or if the only sinks
  // connected are kDependsOnOtherSinks.
  bool only_sinks_with_alpha_depending_on_other_sinks =
      !sinks_.empty() && alpha_using_sinks_.empty() &&
      alpha_discarding_sinks_.empty();
  return !alpha_using_sinks_.empty() ||
         only_sinks_with_alpha_depending_on_other_sinks;
}

gfx::Size MediaStreamVideoTrack::GetVideoSize() const {
  return gfx::Size(width_, height_);
}

void MediaStreamVideoTrack::SetSinkNotifyFrameDroppedCallback(
    WebMediaStreamSink* sink,
    const VideoCaptureNotifyFrameDroppedCB& callback) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  DVLOG(1) << __func__;
  frame_deliverer_->SetNotifyFrameDroppedCallback(sink, callback);
}

void MediaStreamVideoTrack::AddEncodedSink(WebMediaStreamSink* sink,
                                           EncodedVideoFrameCB callback) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  AddSinkInternal(&encoded_sinks_, sink);
  frame_deliverer_->AddEncodedCallback(sink, std::move(callback));
  if (source_)
    source_->UpdateNumEncodedSinks();
  UpdateSourceHasConsumers();
}

void MediaStreamVideoTrack::RemoveSink(WebMediaStreamSink* sink) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  RemoveSinkInternal(&sinks_, sink);
  alpha_using_sinks_.erase(sink);
  alpha_discarding_sinks_.erase(sink);
  frame_deliverer_->RemoveCallback(sink);
  secure_tracker_.Remove(sink);
  if (!source_)
    return;
  UpdateSourceHasConsumers();
  source_->UpdateCapturingLinkSecure(this,
                                     secure_tracker_.is_capturing_secure());

  source_->UpdateCanDiscardAlpha();
  // Restart the timer with existing sinks.
  if (is_screencast_)
    StartTimerForRequestingFrames();
}

void MediaStreamVideoTrack::RemoveEncodedSink(WebMediaStreamSink* sink) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  RemoveSinkInternal(&encoded_sinks_, sink);
  frame_deliverer_->RemoveEncodedCallback(sink);
  if (source_)
    source_->UpdateNumEncodedSinks();
  UpdateSourceHasConsumers();
}

void MediaStreamVideoTrack::UpdateSourceHasConsumers() {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  if (!source_)
    return;
  bool has_consumers = !sinks_.empty() || !encoded_sinks_.empty();
  source_->UpdateHasConsumers(this, has_consumers);
}

void MediaStreamVideoTrack::SetEnabled(bool enabled) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  // If enabled, encoded sinks exist and the source supports encoded output, we
  // need a new keyframe from the source as we may have dropped data making the
  // stream undecodable.
  bool maybe_await_key_frame = false;
  if (enabled && source_ && source_->SupportsEncodedOutput() &&
      !encoded_sinks_.empty()) {
    RequestRefreshFrame();
    maybe_await_key_frame = true;
  }
  frame_deliverer_->SetEnabled(enabled, maybe_await_key_frame);
  for (auto* sink : sinks_)
    sink->OnEnabledChanged(enabled);
  for (auto* encoded_sink : encoded_sinks_)
    encoded_sink->OnEnabledChanged(enabled);
}

size_t MediaStreamVideoTrack::CountSinks() const {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  return sinks_.size();
}

size_t MediaStreamVideoTrack::CountEncodedSinks() const {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  return encoded_sinks_.size();
}

void MediaStreamVideoTrack::SetContentHint(
    WebMediaStreamTrack::ContentHintType content_hint) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  for (auto* sink : sinks_)
    sink->OnContentHintChanged(content_hint);
  for (auto* encoded_sink : encoded_sinks_)
    encoded_sink->OnContentHintChanged(content_hint);
}

void MediaStreamVideoTrack::StopAndNotify(base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  if (source_) {
    source_->RemoveTrack(this, std::move(callback));
    source_ = nullptr;
  } else if (callback) {
    std::move(callback).Run();
  }
  OnReadyStateChanged(WebMediaStreamSource::kReadyStateEnded);
  refresh_timer_.Stop();
}

void MediaStreamVideoTrack::GetSettings(
    MediaStreamTrackPlatform::Settings& settings) const {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  if (!source_)
    return;

  if (width_ && height_) {
    settings.width = width_;
    settings.height = height_;
    settings.aspect_ratio = static_cast<double>(width_) / height_;
  }

  if (std::optional<media::VideoCaptureFormat> format =
          source_->GetCurrentFormat()) {
    // For local capture-based tracks, the frame rate returned by
    // MediaStreamTrack.getSettings() must be the configured frame rate. In case
    // of frame rate decimation, the configured frame rate is the decimated
    // frame rate (i.e., the adapter frame rate). If there is no decimation, the
    // configured frame rate is the frame rate reported by the device.
    // Decimation occurs only when the adapter frame rate is lower than the
    // device frame rate.
    std::optional<double> adapter_frame_rate =
        adapter_settings_.max_frame_rate();
    settings.frame_rate =
        (!adapter_frame_rate || *adapter_frame_rate > format->frame_rate)
            ? format->frame_rate
            : *adapter_frame_rate;
  } else {
    // For other tracks, use the computed frame rate reported via
    // SetSizeAndComputedFrameRate().
    if (computed_frame_rate_)
      settings.frame_rate = *computed_frame_rate_;
  }

  settings.facing_mode = ToPlatformFacingMode(
      static_cast<mojom::blink::FacingMode>(source_->device().video_facing));
  settings.resize_mode = WebString::FromASCII(std::string(
      adapter_settings().target_size() ? WebMediaStreamTrack::kResizeModeRescale
                                       : WebMediaStreamTrack::kResizeModeNone));
  if (source_->device().display_media_info) {
    const auto& info = source_->device().display_media_info;
    settings.display_surface = info->display_surface;
    settings.logical_surface = info->logical_surface;
    settings.cursor = info->cursor;
  }
}

MediaStreamTrackPlatform::VideoFrameStats
MediaStreamVideoTrack::GetVideoFrameStats() const {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  MediaStreamTrackPlatform::VideoFrameStats stats;
  stats.deliverable_frames = frame_deliverer_->deliverable_frames();
  stats.discarded_frames = frame_deliverer_->discarded_frames();
  stats.dropped_frames = frame_deliverer_->dropped_frames();
  return stats;
}

MediaStreamTrackPlatform::CaptureHandle
MediaStreamVideoTrack::GetCaptureHandle() {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);

  MediaStreamTrackPlatform::CaptureHandle capture_handle;

  if (!source_) {
    return capture_handle;
  }

  const MediaStreamDevice& device = source_->device();
  if (!device.display_media_info) {
    return capture_handle;
  }
  const media::mojom::DisplayMediaInformationPtr& info =
      device.display_media_info;

  if (!info->capture_handle) {
    return capture_handle;
  }

  if (!info->capture_handle->origin.opaque()) {
    capture_handle.origin =
        String::FromUTF8(info->capture_handle->origin.Serialize());
  }
  capture_handle.handle =
      WebString::FromUTF16(info->capture_handle->capture_handle);

  return capture_handle;
}

void MediaStreamVideoTrack::AddSubCaptureTargetVersionCallback(
    uint32_t sub_capture_target_version,
    base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);

  frame_deliverer_->AddSubCaptureTargetVersionCallback(
      sub_capture_target_version,
      base::BindPostTask(base::SingleThreadTaskRunner::GetCurrentDefault(),
                         std::move(callback)));
}

void MediaStreamVideoTrack::RemoveSubCaptureTargetVersionCallback(
    uint32_t sub_capture_target_version) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);

  frame_deliverer_->RemoveSubCaptureTargetVersionCallback(
      sub_capture_target_version);
}

void MediaStreamVideoTrack::OnReadyStateChanged(
    WebMediaStreamSource::ReadyState state) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);

  // Copy the vectors first, since sinks might DisconnectFromTrack() and
  // invalidate iterators.

  Vector<WebMediaStreamSink*> sinks_copy(sinks_);
  for (auto* sink : sinks_copy)
    sink->OnReadyStateChanged(state);

  Vector<WebMediaStreamSink*> encoded_sinks_copy(encoded_sinks_);
  for (auto* encoded_sink : encoded_sinks_copy)
    encoded_sink->OnReadyStateChanged(state);
}

void MediaStreamVideoTrack::SetMinimumFrameRate(double min_frame_rate) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  min_frame_rate_ = min_frame_rate;
}

void MediaStreamVideoTrack::SetTrackAdapterSettings(
    const VideoTrackAdapterSettings& settings) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  adapter_settings_ = settings;
}

void MediaStreamVideoTrack::NotifyConstraintsConfigurationComplete() {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  for (auto* sink : sinks_) {
    sink->OnVideoConstraintsChanged(min_frame_rate_,
                                    adapter_settings_.max_frame_rate());
  }

  if (is_screencast_) {
    StartTimerForRequestingFrames();
  }
}

media::VideoCaptureFormat MediaStreamVideoTrack::GetComputedSourceFormat() {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  return computed_source_format_;
}

void MediaStreamVideoTrack::OnSinkDroppedFrame(
    media::VideoCaptureFrameDropReason reason) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  if (!source_) {
    return;
  }
  PostCrossThreadTask(
      *source_->video_task_runner(), FROM_HERE,
      CrossThreadBindOnce(&FrameDeliverer::LogFrameDroppedOnVideoTaskRunner,
                          frame_deliverer_, reason));
}

void MediaStreamVideoTrack::SetEmitLogMessageForTesting(
    base::RepeatingCallback<void(const std::string&)> emit_log_message) {
  frame_deliverer_->SetEmitLogMessage(std::move(emit_log_message));
}

void MediaStreamVideoTrack::StartTimerForRequestingFrames() {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);

  // Find the maximum of all the required min frames per second in the attached
  // sinks.
  double required_min_fps = 0;
  for (auto* web_sink : sinks_) {
    auto* sink = static_cast<MediaStreamVideoSink*>(web_sink);
    required_min_fps =
        std::max(required_min_fps, sink->GetRequiredMinFramesPerSec());
  }

  base::TimeDelta refresh_interval = ComputeRefreshIntervalFromBounds(
      base::Hertz(required_min_fps), min_frame_rate(), max_frame_rate());

  if (refresh_interval.is_max()) {
    refresh_timer_.Stop();
    frame_deliverer_->SetIsRefreshingForMinFrameRate(false);
  } else {
    DVLOG(1) << "Starting frame refresh timer with interval "
             << refresh_interval.InMillisecondsF() << " ms.";
    refresh_timer_.Start(FROM_HERE, refresh_interval, this,
                         &MediaStreamVideoTrack::RequestRefreshFrame);
    frame_deliverer_->SetIsRefreshingForMinFrameRate(true);
  }
}

void MediaStreamVideoTrack::RequestRefreshFrame() {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  if (source_)
    source_->RequestRefreshFrame();
}

void MediaStreamVideoTrack::ResetRefreshTimer() {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  if (refresh_timer_.IsRunning())
    refresh_timer_.Reset();
}

}  // namespace blink

"""


```