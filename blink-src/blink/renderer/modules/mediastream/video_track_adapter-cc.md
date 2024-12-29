Response:
The user is asking for a summary of the functionality of the `video_track_adapter.cc` file in the Chromium Blink engine. I need to identify the core responsibilities of this file and how it interacts with other components, particularly in the context of JavaScript, HTML, and CSS. Since this is part 1 of 2, I should focus on summarizing the overall purpose and key mechanisms implemented in this file.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the Core Class:** The file name and the code itself clearly indicate the central role of `VideoTrackAdapter`.

2. **Understand its Purpose:** The name suggests it "adapts" video tracks. Looking at the included headers and the code, it deals with:
    * `media::VideoFrame`:  Processing video frames.
    * `VideoTrackAdapterSettings`:  Configuration related to adaptation.
    * `MediaStreamVideoSource`:  Receiving video from a source.
    * Callbacks:  Interacting with other parts of the system.

3. **Pinpoint Key Functionalities:**  Scanning the methods and internal classes reveals several important functions:
    * **Resolution Adaptation:** The `VideoFrameResolutionAdapter` class strongly suggests this. It handles resizing and cropping.
    * **Frame Rate Control:**  The `max_frame_rate` setting and the logic within `DeliverFrame` and `MaybeDropFrame` confirm this. The frame monitoring functionality also plays a role here.
    * **Callbacks and Routing:**  The `AddCallbacks` and `DeliverFrame` methods show how frames are distributed to different consumers.
    * **Muting Detection:** The frame monitoring logic checks for periods without new frames.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Consider how these functionalities relate to the web:
    * **JavaScript:** The MediaStream API in JavaScript directly interacts with the underlying video processing. `getUserMedia` and `mediaDevices.getUserMedia` are key entry points. The settings passed to these APIs eventually influence the `VideoTrackAdapterSettings`. Events like `onended` and `onmute` are related to the monitoring.
    * **HTML:** The `<video>` element displays the video. The attributes of the `<video>` element, while not directly setting adapter parameters, influence how the browser renders the received frames.
    * **CSS:**  CSS can style the `<video>` element, but doesn't directly affect the core video processing logic within the adapter.

5. **Consider Logic and Assumptions:**
    * **Input/Output:**  The adapter takes raw video frames as input and produces adapted video frames (potentially resized or with a controlled frame rate) as output.
    * **Assumptions:** It assumes a stream of video frames and applies its adaptation logic based on the configured settings.

6. **Identify Potential User Errors:**  Think about common mistakes developers might make:
    * Conflicting settings: Setting both `maxWidth`/`maxHeight` and `aspectRatio` in `getUserMedia` can lead to unexpected behavior.
    * Incorrectly handling mute events: Not properly responding to muted tracks.

7. **Trace User Actions:** Imagine how a user's actions lead to this code being executed:
    * User grants camera access.
    * JavaScript calls `getUserMedia`.
    * Blink's MediaStream implementation creates a video track.
    * The `VideoTrackAdapter` is instantiated to process the video frames.

8. **Structure the Summary:**  Organize the identified functionalities and connections into a clear and concise summary. Use bullet points for readability. Emphasize the core role of adaptation and the relationship with web APIs.

9. **Review and Refine:**  Ensure the summary is accurate, complete (for Part 1), and easy to understand. Check for any jargon that needs clarification.

By following these steps, the detailed summary provided in the example can be generated, covering the key aspects of the `video_track_adapter.cc` file's functionality and its place in the broader web platform.
```
这是目录为blink/renderer/modules/mediastream/video_track_adapter.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

这个 `video_track_adapter.cc` 文件在 Chromium Blink 引擎中扮演着关键的角色，它主要负责**视频轨道的适配和处理**。更具体地说，它的核心功能是**根据用户或应用程序的需求，调整和优化从视频源接收到的视频帧，然后再将这些帧传递给下游的消费者（例如 `<video>` 元素或 WebRTC 连接）。**

以下是其详细功能列表：

**核心功能：**

1. **帧率控制 (Frame Rate Control):**
   - 允许限制输出视频帧的帧率。如果源帧率过高，`VideoTrackAdapter` 会丢弃一些帧，以确保输出帧率不超过指定的最大值。
   - **逻辑推理:** 假设输入帧率为 60fps，设置的最大帧率为 30fps。`VideoTrackAdapter` 会大致每隔一帧丢弃一帧，以维持输出接近 30fps。
   - **用户/编程错误:**  设置了过低的 `max_frame_rate` 可能会导致视频看起来卡顿。

2. **分辨率调整 (Resolution Adaptation):**
   - 可以根据设置调整视频帧的分辨率 (宽度和高度)。
   - 它可以进行裁剪 (cropping) 和缩放 (scaling) 操作。
   - **逻辑推理:** 假设输入帧分辨率为 1920x1080，目标分辨率为 640x480。`VideoTrackAdapter` 会将原始帧裁剪或缩放至目标分辨率。
   - **用户/编程错误:** 设置不合理的 `target_size` 或 `aspectRatio` 可能导致视频内容被拉伸或变形。

3. **纵横比控制 (Aspect Ratio Control):**
   - 可以确保输出视频帧的纵横比在指定的最小值和最大值之间。
   - 如果原始帧的纵横比超出范围，`VideoTrackAdapter` 会通过裁剪来调整。
   - **逻辑推理:** 假设设置了 `min_aspect_ratio` 为 1.0 和 `max_aspect_ratio` 为 1.5，而输入帧的纵横比为 2.0。`VideoTrackAdapter` 会裁剪帧的左右两侧，使其纵横比接近 1.5。

4. **帧传递和回调 (Frame Delivery and Callbacks):**
   - 接收来自 `MediaStreamVideoSource` 的原始视频帧。
   - 将处理后的视频帧传递给注册的消费者，例如 `MediaStreamVideoTrack` 的 frame deliverer。
   - 提供回调机制，通知消费者新的视频帧到达或帧被丢弃。

5. **静音状态检测 (Muted State Detection):**
   - 监视视频帧的到达情况。如果在一段时间内没有接收到新的帧，则认为视频轨道已静音。
   - **逻辑推理:** 假设在连续的 100 个帧间隔内没有接收到新帧，`VideoTrackAdapter` 可能会触发静音状态的回调。

6. **子捕获目标版本管理 (Sub-capture Target Version Management):**
   - 处理与屏幕共享等功能相关的子捕获目标版本更新的通知。

7. **设置更新 (Settings Updates):**
   - 接收并应用来自 JavaScript 或其他 Blink 组件的视频轨道设置更新。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    - **`getUserMedia()` / `mediaDevices.getUserMedia()`:** 当 JavaScript 代码调用这些 API 请求访问摄像头或麦克风时，返回的 `MediaStreamTrack` 对象背后就可能使用 `VideoTrackAdapter` 来处理视频流。开发者可以通过 `MediaTrackConstraints` 对象中的属性 (如 `width`, `height`, `frameRate`, `aspectRatio`) 来影响 `VideoTrackAdapter` 的行为。
        - **示例:**
          ```javascript
          navigator.mediaDevices.getUserMedia({ video: { width: { ideal: 640 }, height: { ideal: 480 }, frameRate: { max: 30 } } })
            .then(function(stream) {
              // ...
            });
          ```
          在这个例子中，`width`, `height`, 和 `frameRate` 的约束可能会被传递给 `VideoTrackAdapter`，指导其进行分辨率和帧率调整。
    - **`MediaStreamTrack.applyConstraints()`:** JavaScript 代码可以动态地修改视频轨道的约束，这会导致 `VideoTrackAdapter` 重新配置其行为。
        - **示例:**
          ```javascript
          videoTrack.applyConstraints({ frameRate: { max: 15 } });
          ```
          这将指示 `VideoTrackAdapter` 将输出帧率限制为 15fps。
    - **`HTMLVideoElement` (`<video>`):** 当一个 `MediaStreamTrack` 被设置为 `<video>` 元素的 `srcObject` 时，`VideoTrackAdapter` 处理后的视频帧最终会被渲染到这个元素上。
        - **示例:**
          ```html
          <video id="myVideo" autoplay></video>
          <script>
            navigator.mediaDevices.getUserMedia({ video: true })
              .then(function(stream) {
                document.getElementById('myVideo').srcObject = stream;
              });
          </script>
          ```

* **HTML:**
    - `<video>` 元素本身不直接与 `VideoTrackAdapter` 交互，但它是视频流的最终展示容器。其属性 (如 `width`, `height`) 会影响浏览器如何渲染接收到的帧，但 `VideoTrackAdapter` 在此之前已经完成了帧的处理。

* **CSS:**
    - CSS 用于样式化 HTML 元素，包括 `<video>` 元素。它可以控制视频的显示大小、边框等外观，但不会影响 `VideoTrackAdapter` 的核心视频处理逻辑。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户打开一个网页，该网页需要访问用户的摄像头。**
2. **网页上的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: true })`。**
3. **浏览器提示用户授予摄像头访问权限。**
4. **用户同意授权。**
5. **Blink 引擎创建一个 `MediaStream` 对象，其中包含一个 `MediaStreamTrack` 对象来表示视频轨道。**
6. **对于视频轨道，Blink 引擎可能会创建一个 `VideoTrackAdapter` 实例。**
7. **`VideoTrackAdapter` 连接到实际的视频源 (例如摄像头驱动)。**
8. **摄像头开始捕获视频帧，并将这些帧传递给 `VideoTrackAdapter`。**
9. **`VideoTrackAdapter` 根据当前的设置 (例如从 `getUserMedia` 传递的约束) 处理这些帧，例如调整分辨率或帧率。**
10. **处理后的帧被传递给 `MediaStreamTrack` 的消费者，例如渲染到网页上的 `<video>` 元素或通过 WebRTC 发送给远程用户。**

**调试线索:** 如果在视频显示或传输过程中出现问题 (例如分辨率不正确、帧率过低、视频卡顿)，开发人员可以通过以下方式进行调试，其中就可能涉及到 `VideoTrackAdapter`：

* **检查 `getUserMedia` 的约束:**  确认 JavaScript 代码中设置的视频约束是否正确。
* **使用 `MediaStreamTrack.getSettings()`:** 查看当前生效的视频轨道设置，这可以反映 `VideoTrackAdapter` 的配置。
* **浏览器开发者工具:**  某些浏览器 (如 Chrome) 的开发者工具可能提供关于 MediaStream 的详细信息，包括帧率和分辨率等。
* **Blink 引擎的日志:**  如果需要深入了解 `VideoTrackAdapter` 的行为，可以启用 Blink 引擎的调试日志。

**第 1 部分功能归纳：**

在第 1 部分的代码中，`VideoTrackAdapter` 的主要功能是**充当视频源和视频轨道消费者之间的中间层，负责根据配置对接收到的视频帧进行适配，包括帧率控制、分辨率调整和纵横比控制，并管理帧的传递和静音状态的检测。** 它通过 `VideoFrameResolutionAdapter` 内部类来处理具体的帧处理逻辑。它与 JavaScript 的 `getUserMedia` 和 `MediaStreamTrack` API 紧密相关，通过这些 API 接收配置信息并向下游传递处理后的视频流。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/video_track_adapter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediastream/video_track_adapter.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/containers/flat_map.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/metrics/histogram_macros.h"
#include "base/sequence_checker.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/bind_post_task.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "media/base/limits.h"
#include "media/base/video_util.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/modules/mediastream/video_track_adapter_settings.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_gfx.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"

namespace WTF {

// Template specializations of [1], needed to be able to pass WTF callbacks
// that have VideoTrackAdapterSettings or gfx::Size parameters across threads.
//
// [1] third_party/blink/renderer/platform/wtf/cross_thread_copier.h.
template <>
struct CrossThreadCopier<blink::VideoTrackAdapterSettings>
    : public CrossThreadCopierPassThrough<blink::VideoTrackAdapterSettings> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

namespace {

// Amount of frame intervals to wait before considering the source as muted, for
// the first frame and under normal conditions, respectively. First frame might
// take longer to arrive due to source startup.
const float kFirstFrameTimeoutInFrameIntervals = 100.0f;
const float kNormalFrameTimeoutInFrameIntervals = 25.0f;

// |kMaxDeltaDeviationFactor| is used to determine |max_delta_deviation_| which
// specifies the allowed deviation from |target_delta_| before dropping a frame.
// It's set to 20% to be aligned with the previous logic in this file.
constexpr float kMaxDeltaDeviationFactor = 0.2;

// If the delta between two frames is bigger than this, we will consider it to
// be invalid and reset the fps calculation.
constexpr base::TimeDelta kMaxTimeBetweenFrames = base::Milliseconds(1000);

constexpr base::TimeDelta kFrameRateChangeInterval = base::Seconds(1);
const double kFrameRateChangeRate = 0.01;
constexpr base::TimeDelta kFrameRateUpdateInterval = base::Seconds(5);

struct ComputedSettings {
  gfx::Size frame_size;
  double frame_rate = MediaStreamVideoSource::kDefaultFrameRate;
  double last_updated_frame_rate = MediaStreamVideoSource::kDefaultFrameRate;
  base::TimeDelta prev_frame_timestamp = base::TimeDelta::Max();
  base::TimeTicks new_frame_rate_timestamp;
  base::TimeTicks last_update_timestamp;
};

int ClampToValidDimension(int dimension) {
  return std::min(static_cast<int>(media::limits::kMaxDimension),
                  std::max(0, dimension));
}

void ComputeFrameRate(const base::TimeDelta& frame_timestamp,
                      double* frame_rate,
                      base::TimeDelta* prev_frame_timestamp) {
  const double delta_ms =
      (frame_timestamp - *prev_frame_timestamp).InMillisecondsF();
  *prev_frame_timestamp = frame_timestamp;
  if (delta_ms < 0)
    return;

  *frame_rate = 200 / delta_ms + 0.8 * *frame_rate;
}

// Controls the frequency of settings updates based on frame rate changes.
// Returns |true| if over the last second the computed frame rate is
// consistently kFrameRateChangeRate different than the last reported value,
// or if there hasn't been any update in the last
// kFrameRateUpdateIntervalInSeconds seconds.
bool MaybeUpdateFrameRate(ComputedSettings* settings) {
  base::TimeTicks now = base::TimeTicks::Now();

  // Update frame rate if over the last second the computed frame rate has been
  // consistently kFrameRateChangeIntervalInSeconds different than the last
  // reported value.
  if (std::abs(settings->frame_rate - settings->last_updated_frame_rate) >
      settings->last_updated_frame_rate * kFrameRateChangeRate) {
    if (now - settings->new_frame_rate_timestamp > kFrameRateChangeInterval) {
      settings->new_frame_rate_timestamp = now;
      settings->last_update_timestamp = now;
      settings->last_updated_frame_rate = settings->frame_rate;
      return true;
    }
  } else {
    settings->new_frame_rate_timestamp = now;
  }

  // Update frame rate if it hasn't been updated in the last
  // kFrameRateUpdateIntervalInSeconds seconds.
  if (now - settings->last_update_timestamp > kFrameRateUpdateInterval) {
    settings->last_update_timestamp = now;
    settings->last_updated_frame_rate = settings->frame_rate;
    return true;
  }
  return false;
}

VideoTrackAdapterSettings ReturnSettingsMaybeOverrideMaxFps(
    const VideoTrackAdapterSettings& settings) {
  VideoTrackAdapterSettings new_settings = settings;
  std::optional<double> max_fps_override =
      Platform::Current()->GetWebRtcMaxCaptureFrameRate();
  if (max_fps_override) {
    DVLOG(1) << "Overriding max frame rate.  Was="
             << settings.max_frame_rate().value_or(-1)
             << ", Now=" << *max_fps_override;
    new_settings.set_max_frame_rate(*max_fps_override);
  }
  return new_settings;
}

}  // anonymous namespace

// VideoFrameResolutionAdapter is created on and lives on the video task runner.
// It does the resolution adaptation and delivers frames to all registered
// tracks on the video task runner. All method calls must be on the video task
// runner.
class VideoTrackAdapter::VideoFrameResolutionAdapter
    : public WTF::ThreadSafeRefCounted<VideoFrameResolutionAdapter> {
 public:
  struct VideoTrackCallbacks {
    VideoCaptureDeliverFrameInternalCallback frame_callback;
    VideoCaptureNotifyFrameDroppedInternalCallback
        notify_frame_dropped_callback;
    DeliverEncodedVideoFrameInternalCallback encoded_frame_callback;
    VideoCaptureSubCaptureTargetVersionInternalCallback
        sub_capture_target_version_callback;
    VideoTrackSettingsInternalCallback settings_callback;
    VideoTrackFormatInternalCallback format_callback;
  };
  // Setting |max_frame_rate| to 0.0, means that no frame rate limitation
  // will be done.
  VideoFrameResolutionAdapter(
      scoped_refptr<base::SingleThreadTaskRunner> reader_task_runner,
      const VideoTrackAdapterSettings& settings,
      base::WeakPtr<MediaStreamVideoSource> media_stream_video_source);

  VideoFrameResolutionAdapter(const VideoFrameResolutionAdapter&) = delete;
  VideoFrameResolutionAdapter& operator=(const VideoFrameResolutionAdapter&) =
      delete;

  // Add |frame_callback|, |encoded_frame_callback| to receive video frames on
  // the video task runner, |sub_capture_target_version_callback| to receive
  // notifications when a new sub-capture-target version is acknowledged, and
  // |settings_callback| to set track settings on the main thread.
  // |frame_callback| will however be released on the main render thread.
  void AddCallbacks(
      const MediaStreamVideoTrack* track,
      VideoCaptureDeliverFrameInternalCallback frame_callback,
      VideoCaptureNotifyFrameDroppedInternalCallback
          notify_frame_dropped_callback,
      DeliverEncodedVideoFrameInternalCallback encoded_frame_callback,
      VideoCaptureSubCaptureTargetVersionInternalCallback
          sub_capture_target_version_callback,
      VideoTrackSettingsInternalCallback settings_callback,
      VideoTrackFormatInternalCallback format_callback);

  // Removes the callbacks associated with |track| if |track| has been added. It
  // is ok to call RemoveCallbacks() even if |track| has not been added.
  void RemoveCallbacks(const MediaStreamVideoTrack* track);

  // Removes the callbacks associated with |track| if |track| has been added. It
  // is ok to call RemoveAndGetCallbacks() even if the |track| has not been
  // added. The function returns the callbacks if it was removed, or empty
  // callbacks if |track| was not present in the adapter.
  VideoTrackCallbacks RemoveAndGetCallbacks(const MediaStreamVideoTrack* track);

  // The source has provided us with a frame.
  void DeliverFrame(
      scoped_refptr<media::VideoFrame> frame,
      const base::TimeTicks& estimated_capture_time,
      bool is_device_rotated);
  // This method is called when a frame is dropped, whether dropped by the
  // source (via VideoTrackAdapter::OnFrameDroppedOnVideoTaskRunner) or
  // internally (in DeliverFrame).
  void OnFrameDropped(media::VideoCaptureFrameDropReason reason);

  void DeliverEncodedVideoFrame(scoped_refptr<EncodedVideoFrame> frame,
                                base::TimeTicks estimated_capture_time);

  void NewSubCaptureTargetVersionOnVideoTaskRunner(
      uint32_t sub_capture_target_version);

  // Returns true if all arguments match with the output of this adapter.
  bool SettingsMatch(const VideoTrackAdapterSettings& settings) const;

  bool IsEmpty() const;

  // Sets frame rate to 0.0 if frame monitor has detected muted state.
  void ResetFrameRate();

 private:
  virtual ~VideoFrameResolutionAdapter();
  friend class WTF::ThreadSafeRefCounted<VideoFrameResolutionAdapter>;

  void DoDeliverFrame(
      scoped_refptr<media::VideoFrame> video_frame,
      const base::TimeTicks& estimated_capture_time);

  // Returns |true| if the input frame rate is higher that the requested max
  // frame rate and |frame| should be dropped. If it returns true, |reason| is
  // assigned to indicate the particular reason for the decision.
  bool MaybeDropFrame(const media::VideoFrame& frame,
                      float source_frame_rate,
                      media::VideoCaptureFrameDropReason* reason);

  // Updates track settings if either frame width, height or frame rate have
  // changed since last update.
  void MaybeUpdateTrackSettings(
      const VideoTrackSettingsInternalCallback& settings_callback,
      const media::VideoFrame& frame);

  // Updates computed source format for all tracks if either frame width, height
  // or frame rate have changed since last update.
  void MaybeUpdateTracksFormat(const media::VideoFrame& frame);

  // Bound to the video task runner.
  SEQUENCE_CHECKER(video_sequence_checker_);

  // The task runner where we will release VideoCaptureDeliverFrameCB
  // registered in AddCallbacks.
  const scoped_refptr<base::SingleThreadTaskRunner> renderer_task_runner_;

  base::WeakPtr<MediaStreamVideoSource> media_stream_video_source_;

  const VideoTrackAdapterSettings settings_;

  // The target timestamp delta between video frames, corresponding to the max
  // fps.
  const std::optional<base::TimeDelta> target_delta_;

  // The maximum allowed deviation from |target_delta_| before dropping a frame.
  const std::optional<base::TimeDelta> max_delta_deviation_;

  // The timestamp of the last delivered video frame.
  base::TimeDelta timestamp_last_delivered_frame_ = base::TimeDelta::Max();

  // Stores the accumulated difference between |target_delta_| and the actual
  // timestamp delta between frames that are delivered. Clamped to
  // [-max_delta_deviation, target_delta_ / 2]. This is used to allow some
  // frames to be closer than |target_delta_| in order to maintain
  // |target_delta_| on average. Without it we may end up with an average fps
  // that is half of max fps.
  base::TimeDelta accumulated_drift_;

  ComputedSettings track_settings_;
  ComputedSettings source_format_settings_;

  base::flat_map<const MediaStreamVideoTrack*, VideoTrackCallbacks> callbacks_;
};

VideoTrackAdapter::VideoFrameResolutionAdapter::VideoFrameResolutionAdapter(
    scoped_refptr<base::SingleThreadTaskRunner> reader_task_runner,
    const VideoTrackAdapterSettings& settings,
    base::WeakPtr<MediaStreamVideoSource> media_stream_video_source)
    : renderer_task_runner_(reader_task_runner),
      media_stream_video_source_(media_stream_video_source),
      settings_(ReturnSettingsMaybeOverrideMaxFps(settings)),
      target_delta_(settings_.max_frame_rate()
                        ? std::make_optional(base::Seconds(
                              1.0 / settings_.max_frame_rate().value()))
                        : std::nullopt),
      max_delta_deviation_(target_delta_
                               ? std::make_optional(kMaxDeltaDeviationFactor *
                                                    target_delta_.value())
                               : std::nullopt) {
  DVLOG(1) << __func__ << " max_framerate "
           << settings.max_frame_rate().value_or(-1);
  DCHECK(renderer_task_runner_.get());
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  CHECK_NE(0, settings_.max_aspect_ratio());
}

VideoTrackAdapter::VideoFrameResolutionAdapter::~VideoFrameResolutionAdapter() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  DCHECK(callbacks_.empty());
}

void VideoTrackAdapter::VideoFrameResolutionAdapter::AddCallbacks(
    const MediaStreamVideoTrack* track,
    VideoCaptureDeliverFrameInternalCallback frame_callback,
    VideoCaptureNotifyFrameDroppedInternalCallback
        notify_frame_dropped_callback,
    DeliverEncodedVideoFrameInternalCallback encoded_frame_callback,
    VideoCaptureSubCaptureTargetVersionInternalCallback
        sub_capture_target_version_callback,
    VideoTrackSettingsInternalCallback settings_callback,
    VideoTrackFormatInternalCallback format_callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);

  // The new track's settings should match the resolution adapter's current
  // |track_settings_| as set for existing track(s) with matching
  // VideoTrackAdapterSettings.
  if (!callbacks_.empty() && track_settings_.frame_size.width() > 0 &&
      track_settings_.frame_size.height() > 0) {
    settings_callback.Run(track_settings_.frame_size,
                          track_settings_.frame_rate);
  }

  VideoTrackCallbacks track_callbacks = {
      std::move(frame_callback),
      std::move(notify_frame_dropped_callback),
      std::move(encoded_frame_callback),
      std::move(sub_capture_target_version_callback),
      std::move(settings_callback),
      std::move(format_callback)};
  callbacks_.emplace(track, std::move(track_callbacks));
}

void VideoTrackAdapter::VideoFrameResolutionAdapter::RemoveCallbacks(
    const MediaStreamVideoTrack* track) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  callbacks_.erase(track);
}

VideoTrackAdapter::VideoFrameResolutionAdapter::VideoTrackCallbacks
VideoTrackAdapter::VideoFrameResolutionAdapter::RemoveAndGetCallbacks(
    const MediaStreamVideoTrack* track) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  VideoTrackCallbacks track_callbacks;
  auto it = callbacks_.find(track);
  if (it == callbacks_.end())
    return track_callbacks;

  track_callbacks = std::move(it->second);
  callbacks_.erase(it);
  return track_callbacks;
}

void VideoTrackAdapter::VideoFrameResolutionAdapter::DeliverFrame(
    scoped_refptr<media::VideoFrame> video_frame,
    const base::TimeTicks& estimated_capture_time,
    bool is_device_rotated) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);

  if (!video_frame) {
    DLOG(ERROR) << "Incoming frame is not valid.";
    OnFrameDropped(
        media::VideoCaptureFrameDropReason::kResolutionAdapterFrameIsNotValid);
    return;
  }

  ComputeFrameRate(video_frame->timestamp(),
                   &source_format_settings_.frame_rate,
                   &source_format_settings_.prev_frame_timestamp);
  MaybeUpdateTracksFormat(*video_frame);

  double frame_rate = video_frame->metadata().frame_rate.value_or(
      MediaStreamVideoSource::kUnknownFrameRate);

  auto frame_drop_reason = media::VideoCaptureFrameDropReason::kNone;
  if (MaybeDropFrame(*video_frame, frame_rate, &frame_drop_reason)) {
    OnFrameDropped(frame_drop_reason);
    return;
  }

  // If the frame is a texture not backed up by GPU memory we don't apply
  // cropping/scaling and deliver the frame as-is, leaving it up to the
  // destination to rescale it. Otherwise, cropping and scaling is soft-applied
  // before delivery for efficiency.
  //
  // TODO(crbug.com/362521): Allow cropping/scaling of non-GPU memory backed
  // textures.
  if (video_frame->HasSharedImage() &&
      video_frame->storage_type() !=
          media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER) {
    DoDeliverFrame(std::move(video_frame), estimated_capture_time);
    return;
  }
  // The video frame we deliver may or may not get cropping and scaling
  // soft-applied. Ultimately the listener will decide whether to use the
  // |delivered_video_frame|.
  scoped_refptr<media::VideoFrame> delivered_video_frame = video_frame;

  gfx::Size desired_size;
  CalculateDesiredSize(is_device_rotated, video_frame->natural_size(),
                       settings_, &desired_size);
  if (desired_size != video_frame->natural_size()) {
    // Get the largest centered rectangle with the same aspect ratio of
    // |desired_size| that fits entirely inside of
    // |video_frame->visible_rect()|. This will be the rect we need to crop the
    // original frame to. From this rect, the original frame can be scaled down
    // to |desired_size|.
    gfx::Rect region_in_frame = media::ComputeLetterboxRegion(
        video_frame->visible_rect(), desired_size);

    // Some consumers (for example
    // ImageCaptureFrameGrabber::SingleShotFrameHandler::ConvertAndDeliverFrame)
    // don't support pixel format conversions when the source format is YUV with
    // UV subsampled and vsible_rect().x() being odd. The conversion ends up
    // miscomputing the UV plane and ends up with a VU plane leading to a blue
    // face tint. Round x() to even to avoid. See crbug.com/1307304.
    region_in_frame.set_x(region_in_frame.x() & ~1);
    region_in_frame.set_y(region_in_frame.y() & ~1);

    // ComputeLetterboxRegion() sometimes produces odd dimensions due to
    // internal rounding errors; allow to round upwards if there's slack
    // otherwise round downwards.
    bool width_has_slack =
        region_in_frame.right() < video_frame->visible_rect().right();
    region_in_frame.set_width((region_in_frame.width() + width_has_slack) & ~1);
    bool height_has_slack =
        region_in_frame.bottom() < video_frame->visible_rect().bottom();
    region_in_frame.set_height((region_in_frame.height() + height_has_slack) &
                               ~1);

    delivered_video_frame = media::VideoFrame::WrapVideoFrame(
        video_frame, video_frame->format(), region_in_frame, desired_size);
    if (!delivered_video_frame) {
      OnFrameDropped(media::VideoCaptureFrameDropReason::
                         kResolutionAdapterWrappingFrameForCroppingFailed);
      return;
    }

    DVLOG(3) << "desired size  " << desired_size.ToString()
             << " output natural size "
             << delivered_video_frame->natural_size().ToString()
             << " output visible rect  "
             << delivered_video_frame->visible_rect().ToString();
  }
  DoDeliverFrame(std::move(delivered_video_frame), estimated_capture_time);
}

void VideoTrackAdapter::VideoFrameResolutionAdapter::DeliverEncodedVideoFrame(
    scoped_refptr<EncodedVideoFrame> frame,
    base::TimeTicks estimated_capture_time) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  for (const auto& callback : callbacks_) {
    callback.second.encoded_frame_callback.Run(frame, estimated_capture_time);
  }
}

void VideoTrackAdapter::VideoFrameResolutionAdapter::
    NewSubCaptureTargetVersionOnVideoTaskRunner(
        uint32_t sub_capture_target_version) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  for (const auto& callback : callbacks_) {
    callback.second.sub_capture_target_version_callback.Run(
        sub_capture_target_version);
  }
}

bool VideoTrackAdapter::VideoFrameResolutionAdapter::SettingsMatch(
    const VideoTrackAdapterSettings& settings) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  return settings_ == settings;
}

bool VideoTrackAdapter::VideoFrameResolutionAdapter::IsEmpty() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  return callbacks_.empty();
}

void VideoTrackAdapter::VideoFrameResolutionAdapter::DoDeliverFrame(
    scoped_refptr<media::VideoFrame> video_frame,
    const base::TimeTicks& estimated_capture_time) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  if (callbacks_.empty()) {
    OnFrameDropped(
        media::VideoCaptureFrameDropReason::kResolutionAdapterHasNoCallbacks);
  }
  for (const auto& callback : callbacks_) {
    MaybeUpdateTrackSettings(callback.second.settings_callback, *video_frame);
    callback.second.frame_callback.Run(video_frame, estimated_capture_time);
  }
}

void VideoTrackAdapter::VideoFrameResolutionAdapter::OnFrameDropped(
    media::VideoCaptureFrameDropReason reason) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  // Notify callbacks, such as
  // MediaStreamVideoTrack::FrameDeliverer::NotifyFrameDroppedOnVideoTaskRunner.
  for (const auto& callback : callbacks_) {
    callback.second.notify_frame_dropped_callback.Run(reason);
  }
}

bool VideoTrackAdapter::VideoFrameResolutionAdapter::MaybeDropFrame(
    const media::VideoFrame& frame,
    float source_frame_rate,
    media::VideoCaptureFrameDropReason* reason) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);

  // Never drop frames if the max frame rate has not been specified.
  if (!settings_.max_frame_rate().has_value()) {
    timestamp_last_delivered_frame_ = frame.timestamp();
    return false;
  }

  const base::TimeDelta delta =
      (frame.timestamp() - timestamp_last_delivered_frame_);

  // Keep the frame if the time since the last frame is completely off.
  if (delta.is_negative() || delta > kMaxTimeBetweenFrames) {
    // Reset |timestamp_last_delivered_frame_| and |accumulated_drift|.
    timestamp_last_delivered_frame_ = frame.timestamp();
    accumulated_drift_ = base::Milliseconds(0.0);
    return false;
  }

  DCHECK(target_delta_ && max_delta_deviation_);
  if (delta < target_delta_.value() - max_delta_deviation_.value() -
                  accumulated_drift_) {
    // Drop the frame because the input frame rate is too high.
    *reason = media::VideoCaptureFrameDropReason::
        kResolutionAdapterFrameRateIsHigherThanRequested;
    return true;
  }

  // Keep the frame and store the accumulated drift.
  timestamp_last_delivered_frame_ = frame.timestamp();
  accumulated_drift_ += delta - target_delta_.value();
  DCHECK_GE(accumulated_drift_, -max_delta_deviation_.value());
  // Limit the maximum accumulated drift to half of the target delta. If we
  // don't do this, it may happen that we output a series of frames too quickly
  // after a period of no frames. There is no need to actively limit the minimum
  // accumulated drift because that happens automatically when we drop frames
  // that are too close in time.
  accumulated_drift_ = std::min(accumulated_drift_, target_delta_.value() / 2);
  return false;
}

void VideoTrackAdapter::VideoFrameResolutionAdapter::MaybeUpdateTrackSettings(
    const VideoTrackSettingsInternalCallback& settings_callback,
    const media::VideoFrame& frame) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  ComputeFrameRate(frame.timestamp(), &track_settings_.frame_rate,
                   &track_settings_.prev_frame_timestamp);
  if (MaybeUpdateFrameRate(&track_settings_) ||
      frame.natural_size() != track_settings_.frame_size) {
    track_settings_.frame_size = frame.natural_size();
    settings_callback.Run(track_settings_.frame_size,
                          track_settings_.frame_rate);
  }
}
void VideoTrackAdapter::VideoFrameResolutionAdapter::MaybeUpdateTracksFormat(
    const media::VideoFrame& frame) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  if (MaybeUpdateFrameRate(&source_format_settings_) ||
      frame.natural_size() != track_settings_.frame_size) {
    source_format_settings_.frame_size = frame.natural_size();
    media::VideoCaptureFormat source_format;
    source_format.frame_size = source_format_settings_.frame_size;
    source_format.frame_rate = source_format_settings_.frame_rate;
    for (const auto& callback : callbacks_)
      callback.second.format_callback.Run(source_format);
  }
}

void VideoTrackAdapter::VideoFrameResolutionAdapter::ResetFrameRate() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(video_sequence_checker_);
  for (const auto& callback : callbacks_) {
    callback.second.settings_callback.Run(track_settings_.frame_size, 0.0);
  }
}

VideoTrackAdapter::VideoTrackAdapter(
    scoped_refptr<base::SequencedTaskRunner> video_task_runner,
    base::WeakPtr<MediaStreamVideoSource> media_stream_video_source)
    : video_task_runner_(video_task_runner),
      media_stream_video_source_(media_stream_video_source),
      renderer_task_runner_(base::SingleThreadTaskRunner::GetCurrentDefault()),
      muted_state_(false),
      frame_counter_(0),
      old_frame_counter_snapshot_(0),
      source_frame_rate_(0.0f) {
  DCHECK(video_task_runner);
}

VideoTrackAdapter::~VideoTrackAdapter() {
  DCHECK(adapters_.empty());
  DCHECK(!monitoring_frame_rate_timer_);
}

void VideoTrackAdapter::AddTrack(
    const MediaStreamVideoTrack* track,
    VideoCaptureDeliverFrameCB frame_callback,
    VideoCaptureNotifyFrameDroppedCB notify_frame_dropped_callback,
    EncodedVideoFrameCB encoded_frame_callback,
    VideoCaptureSubCaptureTargetVersionCB sub_capture_target_version_callback,
    VideoTrackSettingsCallback settings_callback,
    VideoTrackFormatCallback format_callback,
    const VideoTrackAdapterSettings& settings) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          &VideoTrackAdapter::AddTrackOnVideoTaskRunner,
          WTF::CrossThreadUnretained(this), WTF::CrossThreadUnretained(track),
          CrossThreadBindRepeating(std::move(frame_callback)),
          CrossThreadBindRepeating(std::move(notify_frame_dropped_callback)),
          CrossThreadBindRepeating(std::move(encoded_frame_callback)),
          CrossThreadBindRepeating(
              std::move(sub_capture_target_version_callback)),
          CrossThreadBindRepeating(std::move(settings_callback)),
          CrossThreadBindRepeating(std::move(format_callback)), settings));
}

void VideoTrackAdapter::AddTrackOnVideoTaskRunner(
    const MediaStreamVideoTrack* track,
    VideoCaptureDeliverFrameInternalCallback frame_callback,
    VideoCaptureNotifyFrameDroppedInternalCallback
        notify_frame_dropped_callback,
    DeliverEncodedVideoFrameInternalCallback encoded_frame_callback,
    VideoCaptureSubCaptureTargetVersionInternalCallback
        sub_capture_target_version_callback,
    VideoTrackSettingsInternalCallback settings_callback,
    VideoTrackFormatInternalCallback format_callback,
    const VideoTrackAdapterSettings& settings) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  scoped_refptr<VideoFrameResolutionAdapter> adapter;
  for (const auto& frame_adapter : adapters_) {
    if (frame_adapter->SettingsMatch(settings)) {
      adapter = frame_adapter.get();
      break;
    }
  }
  if (!adapter.get()) {
    adapter = base::MakeRefCounted<VideoFrameResolutionAdapter>(
        renderer_task_runner_, settings, media_stream_video_source_);
    adapters_.push_back(adapter);
  }

  adapter->AddCallbacks(track, std::move(frame_callback),
                        std::move(notify_frame_dropped_callback),
                        std::move(encoded_frame_callback),
                        std::move(sub_capture_target_version_callback),
                        std::move(settings_callback),
                        std::move(format_callback));
}

void VideoTrackAdapter::RemoveTrack(const MediaStreamVideoTrack* track) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&VideoTrackAdapter::RemoveTrackOnVideoTaskRunner,
                          WrapRefCounted(this), CrossThreadUnretained(track)));
}

void VideoTrackAdapter::ReconfigureTrack(
    const MediaStreamVideoTrack* track,
    const VideoTrackAdapterSettings& settings) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&VideoTrackAdapter::ReconfigureTrackOnVideoTaskRunner,
                          WrapRefCounted(this), CrossThreadUnretained(track),
                          settings));
}

void VideoTrackAdapter::StartFrameMonitoring(
    double source_frame_rate,
    const OnMutedCallback& on_muted_callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  VideoTrackAdapter::OnMutedCallback bound_on_muted_callback =
      base::BindPostTaskToCurrentDefault(on_muted_callback);

  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          &VideoTrackAdapter::StartFrameMonitoringOnVideoTaskRunner,
          WrapRefCounted(this),
          CrossThreadBindRepeating(std::move(bound_on_muted_callback)),
          source_frame_rate));
}

void VideoTrackAdapter::StopFrameMonitoring() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          &VideoTrackAdapter::StopFrameMonitoringOnVideoTaskRunner,
          WrapRefCounted(this)));
}

void VideoTrackAdapter::SetSourceFrameSize(const gfx::Size& source_frame_size) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          &VideoTrackAdapter::SetSourceFrameSizeOnVideoTaskRunner,
          WrapRefCounted(this), source_frame_size));
}

bool VideoTrackAdapter::CalculateDesiredSize(
    bool is_rotated,
    const gfx::Size& original_input_size,
    const VideoTrackAdapterSettings& settings,
    gfx::Size* desired_size) {
  // Perform all the rescaling computations as if the device was never rotated.
  int width =
      is_rotated ? original_input_size.height() : original_input_size.width();
  int height =
      is_rotated ? original_input_size.width() : original_input_size.height();
  DCHECK_GE(width, 0);
  DCHECK_GE(height, 0);

  // Rescale only if a target size was provided in |settings|.
  if (settings.target_size()) {
    // Adjust the size of the frame to the maximum allowed size.
    width =
        ClampToValidDimension(std::min(width, settings.target_size()->width()));
    height = ClampToValidDimension(
        std::min(height, settings.target_size()->height()));

    // If the area of the frame is zero, ignore aspect-ratio correction.
    if (width * height > 0) {
      double ratio = static_cast<double>(width) / height;
      DCHECK(std::isfinite(ratio));
      if (ratio > settings.max_aspect_ratio() ||
          ratio < settings.min_aspect_ratio()) {
        // Make sure |min_aspect_ratio| <= |desired_ratio| <=
        // |max_aspect_ratio|.
        double desired_ratio =
            std::max(std::min(ratio, settings.max_aspect_ratio()),
                     settings.min_aspect_ratio());
        DCHECK(std::isfinite(desired_ratio));
        DCHECK_NE(desired_ratio, 0.0);

        if (ratio < desired_ratio) {
          double desired_height_fp = (height * ratio) / desired_ratio;
          DCHECK(std::isfinite(desired_height_fp));
          height = static_cast<int>(desired_height_fp);
          // Make sure we scale to an even height to avoid rounding errors
          height = (height + 1) & ~1;
        } else if (ratio > desired_ratio) {
          double desired_width_fp = (width * desired_ratio) / ratio;
          DCHECK(std::isfinite(desired_width_fp));
          width = static_cast<int>(desired_width_fp);
          // Make sure we scale to an even width to avoid rounding errors.
          width = (width + 1) & ~1;
        }
      }
    }
  } else if (width > media::limits::kMaxDimension ||
             height > media::limits::kMaxDimension)
"""


```