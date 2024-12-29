Response:
The user wants a summary of the functionality of the provided C++ code snippet for `media_stream_video_track.cc`.

Here's a breakdown of the thinking process to generate the summary:

1. **Identify the core purpose:** The file name and the included headers (`media_stream_video_track.h`) clearly indicate this file implements the `MediaStreamVideoTrack` class. This class is fundamental to handling video within the WebRTC/Media Streams API in the Blink rendering engine.

2. **Examine key class members and methods:**  Scan the code for prominent classes, methods, and data members to understand the class's responsibilities. Key elements include:
    * `FrameDeliverer`:  A nested class responsible for managing the delivery of video frames to sinks.
    * Methods like `AddCallback`, `RemoveCallback`, `DeliverFrameOnVideoTaskRunner`, `SetEnabled`: These indicate managing the flow of video data and controlling the track's active state.
    * Mentions of `VideoCaptureDeliverFrameCB`, `EncodedVideoFrameCB`: These are callback types related to receiving raw and encoded video frames, respectively.
    * Use of `media::VideoFrame`: The fundamental data structure for video.
    * Interaction with `MediaStreamVideoSource`:  The source of the video data.
    * Use of task runners (`main_render_task_runner_`, `video_task_runner_`):  Highlights the multi-threaded nature of video processing.
    * Handling of frame dropping and related logging/metrics.

3. **Infer functionality from the elements:** Based on the identified elements, deduce the main functions:
    * **Receiving video frames:** The track receives raw or encoded video frames from a `MediaStreamVideoSource`.
    * **Delivering frames to sinks:** The track distributes these frames to registered "sinks" (consumers of the video data).
    * **Managing enabled/disabled state:** The track can be enabled or disabled, affecting frame delivery (black frames are sent when disabled for raw sinks).
    * **Handling frame drops:** The track tracks and logs dropped frames.
    * **Handling encoded video:** The track can handle encoded video frames separately.
    * **Sub-capture target versioning:** A mechanism for ensuring frame consistency in certain capture scenarios.
    * **Refresh mechanism for low frame rates:** A feature to request frames when the source is not actively producing them.

4. **Relate to web technologies (JavaScript, HTML, CSS):**  Consider how the functionality of this C++ class manifests in web development:
    * **JavaScript:** The `MediaStreamTrack` object is directly exposed to JavaScript. The `enabled` property in JS corresponds to the internal enabled state. Events like `onended` might be related to the track's lifecycle. APIs like `requestFrame()` for WebCodecs interact with the encoded frame delivery.
    * **HTML:** The `<video>` element displays the video stream. The C++ code handles the underlying data flow.
    * **CSS:** While less directly related, CSS can style the `<video>` element.

5. **Identify potential user/programming errors:** Think about how developers might misuse the API:
    * Not handling the asynchronous nature of video processing.
    * Incorrectly managing the enabled state.
    * Expecting immediate frame delivery after adding a sink.

6. **Consider the debugging perspective:** How might a developer end up looking at this code?
    * Investigating why video isn't playing.
    * Debugging frame drops or performance issues.
    * Understanding the flow of video data within the browser.

7. **Structure the summary:**  Organize the findings into logical sections: Core Functionality, Relationship to Web Technologies, Logical Inferences, User/Programming Errors, and Debugging Context.

8. **Refine the language:** Use clear and concise language, avoiding jargon where possible, or explaining it when necessary.

**(Self-Correction during the process):**

* Initially, I might have focused too much on the low-level details of frame delivery. I needed to step back and consider the higher-level purpose of the `MediaStreamVideoTrack` within the broader Media Streams API.
* I made sure to explicitly mention the role of `FrameDeliverer` as it's a key component within the class.
* I double-checked that the explanations for web technology relationships were accurate and provided concrete examples.
* I ensured that the assumptions and examples for logical inference were reasonable and illustrative.
## 功能归纳：blink/renderer/modules/mediastream/media_stream_video_track.cc (第1部分)

这个C++源代码文件 `media_stream_video_track.cc` 实现了 Chromium Blink 引擎中 `MediaStreamVideoTrack` 类的部分功能。 该类的主要职责是**管理和控制视频媒体流轨道 (video media stream track)**。

具体来说，第1部分代码主要集中在以下几个核心功能：

**1. 视频帧的接收与分发 (Video Frame Reception and Delivery):**

* **接收来自 `MediaStreamVideoSource` 的视频帧:**  `MediaStreamVideoTrack` 接收来自其关联的视频源 (`MediaStreamVideoSource`) 的原始视频帧 (`media::VideoFrame`) 或编码后的视频帧 (`EncodedVideoFrame`).
* **管理视频帧接收的回调:** 使用内部类 `FrameDeliverer` 来管理注册的回调函数 (`VideoCaptureDeliverFrameCB`, `EncodedVideoFrameCB`)，这些回调函数用于将接收到的视频帧传递给不同的“接收器”（sinks）。
* **支持原始视频帧和编码后视频帧的分发:**  代码中可以看到针对原始视频帧和编码后视频帧的不同处理路径和回调函数。
* **处理禁用状态下的帧分发:**  当视频轨道被禁用时，对于原始视频帧的接收器，会生成并分发黑帧，而不是原始帧。编码后的视频帧则不会分发。

**2. 视频轨道状态的控制 (Video Track State Control):**

* **启用/禁用视频轨道:**  提供了 `SetEnabled` 方法来控制视频轨道的启用和禁用状态。
* **处理禁用状态下的黑帧生成:** 当轨道禁用时，会创建一个黑色的 `media::VideoFrame` 并将其分发给已注册的原始视频帧接收器。
* **编码输出的等待关键帧机制:**  当启用轨道且需要编码输出时，可以选择等待下一个关键帧再开始分发编码数据。

**3. 视频帧丢弃处理与统计 (Video Frame Drop Handling and Statistics):**

* **跟踪和记录视频帧丢弃:**  代码中存在用于跟踪已丢弃帧的计数器 (`dropped_frames_`, `discarded_frames_`)，并提供了 `OnFrameDroppedOnVideoTaskRunner` 方法来处理帧丢弃事件。
* **提供帧丢弃通知回调:** 允许接收器注册帧丢弃通知回调 (`VideoCaptureNotifyFrameDroppedCB`)，以便在发生帧丢弃时得到通知。
* **记录帧丢弃的原因:**  记录帧丢弃的具体原因 (`media::VideoCaptureFrameDropReason`)，并使用 UMA (User Metrics Analysis) 进行统计。

**4. 子捕获目标版本控制 (Sub-capture Target Version Control):**

* **支持子捕获目标版本:**  引入了 `sub_capture_target_version_` 的概念，用于标识捕获目标的版本，并确保接收到的帧与预期的版本一致。
* **提供子捕获目标版本更新的回调:** 允许注册当观察到特定子捕获目标版本时的回调函数。

**5. 最小帧率刷新机制 (Minimum Frame Rate Refresh Mechanism):**

* **支持基于最小帧率的刷新:** 引入了 `is_refreshing_for_min_frame_rate_` 标志和 `ResetRefreshTimer` 方法，用于在需要维持最小帧率时，定时请求新的帧。

**6. 多线程处理 (Multi-threading Handling):**

* **使用任务运行器 (Task Runners):** 代码中大量使用了 `base::SingleThreadTaskRunner` 和 `base::SequencedTaskRunner` 来确保在正确的线程上执行操作，例如主渲染线程和视频处理线程。
* **使用跨线程的绑定 (Cross-Thread Binding):** 使用 `CrossThreadBindOnce` 和 `CrossThreadBindRepeating` 将回调函数和方法调用调度到不同的线程上执行。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**
    * **`MediaStreamTrack` 对象:**  `MediaStreamVideoTrack` 在 JavaScript 中对应的是 `MediaStreamTrack` 对象，通过该对象，JavaScript 可以控制视频轨道的启用状态 (`track.enabled = true/false`)。
    * **`addTrack()` 方法:** 当使用 `getUserMedia()` 或其他 API 获取到 `MediaStream` 对象后，可以使用 `addTrack()` 方法将 `MediaStreamVideoTrack` 添加到 `MediaStream` 中，从而在 HTML `<video>` 元素中播放。
    * **`requestFrame()` 方法 (WebCodecs API):**  对于编码后的视频流，JavaScript 可以使用 WebCodecs API 的 `requestFrame()` 方法请求新的编码帧，这会触发 `MediaStreamVideoTrack` 中编码帧的分发逻辑。
    * **事件监听:** JavaScript 可以监听 `MediaStreamTrack` 上的事件，例如 `ended` 事件，这可能与 `MediaStreamVideoTrack` 的生命周期管理有关。

* **HTML:**
    * **`<video>` 元素:**  `MediaStreamVideoTrack` 最终会将视频帧数据提供给 HTML 的 `<video>` 元素进行渲染显示。 `<video>` 元素的 `srcObject` 属性可以设置为包含该视频轨道的 `MediaStream` 对象。

* **CSS:**
    * **`<video>` 元素的样式:** CSS 可以用于控制 `<video>` 元素的显示样式，例如大小、边框等，但与 `MediaStreamVideoTrack` 的内部逻辑没有直接关系。

**逻辑推理的假设输入与输出 (例子):**

**假设输入:**

1. JavaScript 代码将一个 `MediaStreamVideoTrack` 对象的 `enabled` 属性设置为 `false`。
2. 视频源 (`MediaStreamVideoSource`) 不断产生新的视频帧。

**输出:**

1. `MediaStreamVideoTrack` 内部的 `enabled_` 标志会被设置为 `false`。
2. 当 `FrameDeliverer` 接收到来自视频源的原始视频帧时，会调用 `GetBlackFrame` 方法生成一个与原始帧尺寸相同的黑帧。
3. 黑帧会被分发给所有已注册的原始视频帧接收器。
4. 编码后的视频帧会被丢弃，不会分发给编码帧接收器。

**用户或编程常见的使用错误 (例子):**

* **错误地认为禁用轨道会立即停止所有处理:** 用户可能认为在 JavaScript 中设置 `track.enabled = false` 后，`MediaStreamVideoSource` 也会立即停止产生帧。但实际上，`MediaStreamVideoTrack` 仍然会接收帧，只是会替换为黑帧进行分发。开发者需要理解 `MediaStreamVideoTrack` 和 `MediaStreamVideoSource` 的职责划分。
* **未处理异步性:**  添加或移除视频接收器是异步操作，开发者需要确保在添加接收器完成后再期望接收到帧。直接假设添加接收器后立即就能收到帧可能会导致错误。
* **在错误线程上调用方法:** 例如，直接在非主渲染线程上调用 `AddCallback` 或 `RemoveCallback` 方法，这会导致断言失败或未定义的行为。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个网页，该网页使用了 WebRTC 或 Media Streams API。**
2. **网页 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 获取用户的摄像头视频流。**
3. **`getUserMedia()` 内部会创建 `MediaStreamVideoTrack` 对象来表示摄像头捕获的视频轨道。**
4. **网页 JavaScript 代码可能会将这个视频轨道添加到 `<video>` 元素中进行显示。**
5. **在调试过程中，如果开发者需要深入了解视频帧是如何被接收、处理和分发的，或者需要排查视频流的启用/禁用问题、帧丢弃问题等，就可能会查看 `blink/renderer/modules/mediastream/media_stream_video_track.cc` 这个文件。**
6. **例如，开发者可能想知道当 `track.enabled = false` 时，视频帧是如何被处理的，或者当网络条件不好导致帧丢弃时，系统是如何记录和通知的。**
7. **此外，如果涉及到特定的捕获场景，例如屏幕共享，开发者可能需要了解子捕获目标版本控制是如何工作的。**

总而言之，`blink/renderer/modules/mediastream/media_stream_video_track.cc` 的第1部分主要负责 `MediaStreamVideoTrack` 核心的视频帧管理和轨道状态控制功能，是实现 WebRTC 和 Media Streams API 中视频轨道功能的重要组成部分。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_stream_video_track.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"

#include <string>
#include <utility>

#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/location.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/ranges/algorithm.h"
#include "base/task/bind_post_task.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "media/base/limits.h"
#include "media/capture/video_capture_types.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/public/web/modules/mediastream/media_stream_video_sink.h"
#include "third_party/blink/public/web/web_local_frame.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_constraints_util_video_device.h"
#include "third_party/blink/renderer/platform/allow_discouraged_type.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component_impl.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
namespace {

// A lower-bound for the refresh interval.
constexpr base::TimeDelta kLowerBoundRefreshInterval =
    base::Hertz(media::limits::kMaxFramesPerSecond);

// This alias mimics the definition of VideoCaptureDeliverFrameCB.
using VideoCaptureDeliverFrameInternalCallback = WTF::CrossThreadFunction<void(
    scoped_refptr<media::VideoFrame> video_frame,
    base::TimeTicks estimated_capture_time)>;

// This alias mimics the definition of VideoCaptureNotifyFrameDroppedCB.
using VideoCaptureNotifyFrameDroppedInternalCallback =
    WTF::CrossThreadFunction<void(media::VideoCaptureFrameDropReason)>;

// Mimics blink::EncodedVideoFrameCB
using EncodedVideoFrameInternalCallback =
    WTF::CrossThreadFunction<void(scoped_refptr<EncodedVideoFrame> frame,
                                  base::TimeTicks estimated_capture_time)>;

base::TimeDelta ComputeRefreshIntervalFromBounds(
    const base::TimeDelta required_min_refresh_interval,
    const std::optional<double>& min_frame_rate,
    const std::optional<double>& max_frame_rate) {
  // Start with the default required refresh interval, and refine based on
  // constraints. If a minimum frameRate is provided, use that. Otherwise, use
  // the maximum frameRate if it happens to be less than the default.
  base::TimeDelta refresh_interval = required_min_refresh_interval;
  if (min_frame_rate.has_value())
    refresh_interval = base::Hertz(*min_frame_rate);

  if (max_frame_rate.has_value()) {
    refresh_interval = std::max(refresh_interval, base::Hertz(*max_frame_rate));
  }

  if (refresh_interval < kLowerBoundRefreshInterval)
    refresh_interval = kLowerBoundRefreshInterval;

  return refresh_interval;
}

void LogVideoFrameDropUMA(media::VideoCaptureFrameDropReason reason,
                          mojom::blink::MediaStreamType stream_type) {
  const int kEnumCount =
      static_cast<int>(media::VideoCaptureFrameDropReason::kMaxValue) + 1;
  UMA_HISTOGRAM_ENUMERATION("Media.VideoCapture.Track.FrameDrop", reason,
                            kEnumCount);
  switch (stream_type) {
    case mojom::blink::MediaStreamType::DEVICE_VIDEO_CAPTURE:
      UMA_HISTOGRAM_ENUMERATION(
          "Media.VideoCapture.Track.FrameDrop.DeviceCapture", reason,
          kEnumCount);
      break;
    case mojom::blink::MediaStreamType::GUM_TAB_VIDEO_CAPTURE:
      UMA_HISTOGRAM_ENUMERATION(
          "Media.VideoCapture.Track.FrameDrop.GumTabCapture", reason,
          kEnumCount);
      break;
    case mojom::blink::MediaStreamType::GUM_DESKTOP_VIDEO_CAPTURE:
      UMA_HISTOGRAM_ENUMERATION(
          "Media.VideoCapture.Track.FrameDrop.GumDesktopCapture", reason,
          kEnumCount);
      break;
    case mojom::blink::MediaStreamType::DISPLAY_VIDEO_CAPTURE:
      UMA_HISTOGRAM_ENUMERATION(
          "Media.VideoCapture.Track.FrameDrop.DisplayCapture", reason,
          kEnumCount);
      break;
    case mojom::blink::MediaStreamType::DISPLAY_VIDEO_CAPTURE_THIS_TAB:
      UMA_HISTOGRAM_ENUMERATION(
          "Media.VideoCapture.Track.FrameDrop.DisplayCaptureCurrentTab", reason,
          kEnumCount);
      break;
    case mojom::blink::MediaStreamType::DISPLAY_VIDEO_CAPTURE_SET:
      UMA_HISTOGRAM_ENUMERATION(
          "Media.VideoCapture.Track.FrameDrop.DisplayCaptureSet", reason,
          kEnumCount);
      break;
    case mojom::blink::MediaStreamType::NO_SERVICE:
    case mojom::blink::MediaStreamType::DEVICE_AUDIO_CAPTURE:
    case mojom::blink::MediaStreamType::GUM_TAB_AUDIO_CAPTURE:
    case mojom::blink::MediaStreamType::GUM_DESKTOP_AUDIO_CAPTURE:
    case mojom::blink::MediaStreamType::DISPLAY_AUDIO_CAPTURE:
    case mojom::blink::MediaStreamType::NUM_MEDIA_TYPES:
      break;
  }
}

}  // namespace

// MediaStreamVideoTrack::FrameDeliverer is a helper class used for registering
// VideoCaptureDeliverFrameCB/EncodedVideoFrameCB callbacks on the main render
// thread to receive video frames on the video task runner. Frames are only
// delivered to the sinks if the track is enabled. If the track is disabled, a
// black frame is instead forwarded to the sinks at the same frame rate. A
// disabled track does not forward data to encoded sinks.
class MediaStreamVideoTrack::FrameDeliverer
    : public WTF::ThreadSafeRefCounted<FrameDeliverer> {
 public:
  using VideoSinkId = WebMediaStreamSink*;

  FrameDeliverer(
      scoped_refptr<base::SingleThreadTaskRunner> main_render_task_runner,
      scoped_refptr<base::SequencedTaskRunner> video_task_runner,
      base::WeakPtr<MediaStreamVideoTrack> media_stream_video_track,
      base::WeakPtr<MediaStreamVideoSource> media_stream_video_source,
      bool enabled,
      uint32_t sub_capture_target_version);

  FrameDeliverer(const FrameDeliverer&) = delete;
  FrameDeliverer& operator=(const FrameDeliverer&) = delete;

  // Sets whether the track is enabled or not. If getting enabled and encoded
  // output is enabled, the deliverer will wait until the next key frame before
  // it resumes producing encoded data.
  void SetEnabled(bool enabled, bool await_key_frame);

  // Add |callback| to receive video frames on the video task runner.
  // Must be called on the main render thread.
  void AddCallback(VideoSinkId id, VideoCaptureDeliverFrameCB callback);

  // Sets the frame dropped callback of the sink of frame |id].
  void SetNotifyFrameDroppedCallback(VideoSinkId id,
                                     VideoCaptureNotifyFrameDroppedCB callback);

  // Add |callback| to receive encoded video frames on the video task runner.
  // Must be called on the main render thread.
  void AddEncodedCallback(VideoSinkId id, EncodedVideoFrameCB callback);

  // Removes |callback| associated with |id| from receiving video frames if |id|
  // has been added. It is ok to call RemoveCallback even if the |id| has not
  // been added. Note that the added callback will be reset on the main thread.
  // Must be called on the main render thread.
  void RemoveCallback(VideoSinkId id);

  // Removes encoded callback associated with |id| from receiving video frames
  // if |id| has been added. It is ok to call RemoveEncodedCallback even if the
  // |id| has not been added. Note that the added callback will be reset on the
  // main thread. Must be called on the main render thread.
  void RemoveEncodedCallback(VideoSinkId id);

  // Triggers all registered callbacks with |frame| and |estimated_capture_time|
  // as parameters. Must be called on the video task runner.
  void DeliverFrameOnVideoTaskRunner(
      scoped_refptr<media::VideoFrame> frame,
      base::TimeTicks estimated_capture_time);

  // A frame was dropped instead of delivered. This is the main handler of frame
  // drops: it updates dropped/discarded counters, invokes
  // LogFrameDroppedOnVideoTaskRunner() and notifies `callbacks_` (i.e. sinks)
  // that a frame was dropped.
  void OnFrameDroppedOnVideoTaskRunner(
      media::VideoCaptureFrameDropReason reason);

  // Can be called from any task runner (is atomic).
  size_t deliverable_frames() const { return deliverable_frames_; }
  size_t discarded_frames() const { return discarded_frames_; }
  size_t dropped_frames() const { return dropped_frames_; }

  // Triggers all encoded callbacks with |frame| and |estimated_capture_time|.
  // Must be called on the video task runner.
  void DeliverEncodedVideoFrameOnVideoTaskRunner(
      scoped_refptr<EncodedVideoFrame> frame,
      base::TimeTicks estimated_capture_time);

  // Called when a sub-capture-target-version is acknowledged by the capture
  // module. After this, it is guaranteed that all subsequent frames will be
  // associated with a sub-capture-target-version that is >=
  // |sub_capture_target_version|. Must be called on the video task runner.
  void NewSubCaptureTargetVersionOnVideoTaskRunner(
      uint32_t sub_capture_target_version);

  void SetIsRefreshingForMinFrameRate(bool is_refreshing_for_min_frame_rate);

  void AddSubCaptureTargetVersionCallback(uint32_t sub_capture_target_version,
                                          base::OnceClosure callback);
  void RemoveSubCaptureTargetVersionCallback(
      uint32_t sub_capture_target_version);

  // Performs logging and UMAs relating to frame drops. This includes both
  // frames dropped prior to delivery (OnFrameDroppedOnVideoTaskRunner) and
  // MediaStreamVideoTrack::OnSinkDroppedFrame().
  void LogFrameDroppedOnVideoTaskRunner(
      media::VideoCaptureFrameDropReason reason);

  void SetEmitLogMessage(
      base::RepeatingCallback<void(const std::string&)> emit_log_message);

 private:
  friend class WTF::ThreadSafeRefCounted<FrameDeliverer>;

  // Struct containing sink id, frame delivery and frame dropped callbacks.
  struct VideoIdCallbacks {
    VideoSinkId id;
    VideoCaptureDeliverFrameInternalCallback deliver_frame;
    VideoCaptureNotifyFrameDroppedInternalCallback notify_frame_dropped;
  };

  virtual ~FrameDeliverer();
  void AddCallbackOnVideoTaskRunner(
      VideoSinkId id,
      VideoCaptureDeliverFrameInternalCallback callback);
  void SetNotifyFrameDroppedCallbackOnVideoTaskRunner(
      VideoSinkId id,
      VideoCaptureNotifyFrameDroppedInternalCallback callback,
      const scoped_refptr<base::SingleThreadTaskRunner>& task_runner);
  void RemoveCallbackOnVideoTaskRunner(
      VideoSinkId id,
      const scoped_refptr<base::SingleThreadTaskRunner>& task_runner);

  void AddEncodedCallbackOnVideoTaskRunner(
      VideoSinkId id,
      EncodedVideoFrameInternalCallback callback);
  void RemoveEncodedCallbackOnVideoTaskRunner(
      VideoSinkId id,
      const scoped_refptr<base::SingleThreadTaskRunner>& task_runner);

  void SetEnabledOnVideoTaskRunner(bool enabled, bool await_key_frame);

  void SetIsRefreshingForMinFrameRateOnVideoTaskRunner(
      bool is_refreshing_for_min_frame_rate);

  void AddSubCaptureTargetVersionCallbackOnVideoTaskRunner(
      uint32_t sub_capture_target_version,
      WTF::CrossThreadOnceClosure callback);
  void RemoveSubCaptureTargetVersionCallbackOnVideoTaskRunner(
      uint32_t sub_capture_target_version);

  // Returns a black frame where the size and time stamp is set to the same as
  // as in |reference_frame|.
  scoped_refptr<media::VideoFrame> GetBlackFrame(
      const media::VideoFrame& reference_frame);

  // Used to DCHECK that AddCallback and RemoveCallback are called on the main
  // Render Thread.
  THREAD_CHECKER(main_render_thread_checker_);
  const scoped_refptr<base::SequencedTaskRunner> video_task_runner_;
  const scoped_refptr<base::SingleThreadTaskRunner> main_render_task_runner_;

  base::WeakPtr<MediaStreamVideoTrack> media_stream_video_track_;
  base::WeakPtr<MediaStreamVideoSource> media_stream_video_source_;
  const mojom::blink::MediaStreamType stream_type_;

  bool enabled_;
  scoped_refptr<media::VideoFrame> black_frame_;
  bool emit_frame_drop_events_;

  Vector<VideoIdCallbacks> callbacks_;
  HashMap<VideoSinkId, EncodedVideoFrameInternalCallback> encoded_callbacks_;

  // Frame counters for the MediaStreamTrack Statistics API. The counters are
  // only incremented when the track is enabled (even though a disabled track
  // delivers black frames).
  std::atomic<size_t> deliverable_frames_ = 0;
  std::atomic<size_t> discarded_frames_ = 0;
  std::atomic<size_t> dropped_frames_ = 0;

  // Helper methods for LogFrameDroppedOnVideoTaskRunner().
  void MaybeEmitFrameDropLogMessage(media::VideoCaptureFrameDropReason reason);
  void EmitLogMessage(const std::string& message);
  base::RepeatingCallback<void(const std::string&)> emit_log_message_;
  // States relating to frame drop logging and UMAs.
  struct FrameDropLogState {
    explicit FrameDropLogState(media::VideoCaptureFrameDropReason reason =
                                   media::VideoCaptureFrameDropReason::kNone);

    int drop_count = 0;
    media::VideoCaptureFrameDropReason drop_reason =
        media::VideoCaptureFrameDropReason::kNone;
    bool max_log_count_exceeded = false;
  };
  FrameDropLogState frame_drop_log_state_;
  // Tracks how often each frame-drop reason was encountered to decide whether
  // or not to LOG the console.
  std::map<media::VideoCaptureFrameDropReason, int> frame_drop_log_counters_
      ALLOW_DISCOURAGED_TYPE("TODO(crbug.com/1481448)");

  // Callbacks that will be invoked a single time when a
  // sub-capture-target-version is observed that is at least equal to the key.
  // The map itself (sub_capture_target_version_callbacks_) is bound to the
  // video task runner. The callbacks are bound to their respective threads
  // (BindPostTask).
  HashMap<uint32_t, WTF::CrossThreadOnceClosure>
      sub_capture_target_version_callbacks_;

  bool await_next_key_frame_;

  // This should only be accessed on the video task runner.
  bool is_refreshing_for_min_frame_rate_ = false;

  // This monotonously increasing value indicates which
  // sub-capture-target-version is expected for delivered frames.
  uint32_t sub_capture_target_version_ = 0;
};

MediaStreamVideoTrack::FrameDeliverer::FrameDropLogState::FrameDropLogState(
    media::VideoCaptureFrameDropReason reason)
    : drop_count((reason == media::VideoCaptureFrameDropReason::kNone) ? 0 : 1),
      drop_reason(reason),
      max_log_count_exceeded(false) {}

MediaStreamVideoTrack::FrameDeliverer::FrameDeliverer(
    scoped_refptr<base::SingleThreadTaskRunner> main_render_task_runner,
    scoped_refptr<base::SequencedTaskRunner> video_task_runner,
    base::WeakPtr<MediaStreamVideoTrack> media_stream_video_track,
    base::WeakPtr<MediaStreamVideoSource> media_stream_video_source,
    bool enabled,
    uint32_t sub_capture_target_version)
    : video_task_runner_(std::move(video_task_runner)),
      main_render_task_runner_(main_render_task_runner),
      media_stream_video_track_(media_stream_video_track),
      media_stream_video_source_(media_stream_video_source),
      stream_type_(media_stream_video_source_->device().type),
      enabled_(enabled),
      emit_frame_drop_events_(true),
      await_next_key_frame_(false),
      sub_capture_target_version_(sub_capture_target_version) {
  DCHECK(video_task_runner_.get());
  DCHECK(main_render_task_runner_);
  SetEmitLogMessage(ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
      &MediaStreamVideoTrack::FrameDeliverer::EmitLogMessage,
      WTF::CrossThreadUnretained(this))));
}

MediaStreamVideoTrack::FrameDeliverer::~FrameDeliverer() {
  DCHECK(callbacks_.empty());
}

void MediaStreamVideoTrack::FrameDeliverer::AddCallback(
    VideoSinkId id,
    VideoCaptureDeliverFrameCB callback) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&FrameDeliverer::AddCallbackOnVideoTaskRunner,
                          WrapRefCounted(this), WTF::CrossThreadUnretained(id),
                          CrossThreadBindRepeating(std::move(callback))));
}

void MediaStreamVideoTrack::FrameDeliverer::AddCallbackOnVideoTaskRunner(
    VideoSinkId id,
    VideoCaptureDeliverFrameInternalCallback callback) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  callbacks_.push_back(VideoIdCallbacks{
      id, std::move(callback),
      CrossThreadBindRepeating([](media::VideoCaptureFrameDropReason) {})});
}

void MediaStreamVideoTrack::FrameDeliverer::SetNotifyFrameDroppedCallback(
    VideoSinkId id,
    VideoCaptureNotifyFrameDroppedCB callback) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          &FrameDeliverer::SetNotifyFrameDroppedCallbackOnVideoTaskRunner,
          WrapRefCounted(this), WTF::CrossThreadUnretained(id),
          CrossThreadBindRepeating(std::move(callback)),
          main_render_task_runner_));
}

void MediaStreamVideoTrack::FrameDeliverer::
    SetNotifyFrameDroppedCallbackOnVideoTaskRunner(
        VideoSinkId id,
        VideoCaptureNotifyFrameDroppedInternalCallback callback,
        const scoped_refptr<base::SingleThreadTaskRunner>& task_runner) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  DVLOG(1) << __func__;
  for (auto& entry : callbacks_) {
    if (entry.id == id) {
      // Old callback destruction needs to happen on the specified task
      // runner.
      PostCrossThreadTask(
          *task_runner, FROM_HERE,
          CrossThreadBindOnce(
              [](VideoCaptureNotifyFrameDroppedInternalCallback) {},
              std::move(entry.notify_frame_dropped)));
      entry.notify_frame_dropped = std::move(callback);
    }
  }
}

void MediaStreamVideoTrack::FrameDeliverer::AddEncodedCallback(
    VideoSinkId id,
    EncodedVideoFrameCB callback) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&FrameDeliverer::AddEncodedCallbackOnVideoTaskRunner,
                          WrapRefCounted(this), WTF::CrossThreadUnretained(id),
                          CrossThreadBindRepeating(std::move(callback))));
}

void MediaStreamVideoTrack::FrameDeliverer::AddEncodedCallbackOnVideoTaskRunner(
    VideoSinkId id,
    EncodedVideoFrameInternalCallback callback) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  encoded_callbacks_.insert(id, std::move(callback));
}

void MediaStreamVideoTrack::FrameDeliverer::RemoveCallback(VideoSinkId id) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&FrameDeliverer::RemoveCallbackOnVideoTaskRunner,
                          WrapRefCounted(this), WTF::CrossThreadUnretained(id),
                          main_render_task_runner_));
}

void MediaStreamVideoTrack::FrameDeliverer::RemoveCallbackOnVideoTaskRunner(
    VideoSinkId id,
    const scoped_refptr<base::SingleThreadTaskRunner>& task_runner) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  auto it = callbacks_.begin();
  for (; it != callbacks_.end(); ++it) {
    if (it->id == id) {
      // Callback destruction needs to happen on the specified task runner.
      PostCrossThreadTask(
          *task_runner, FROM_HERE,
          CrossThreadBindOnce(
              [](VideoCaptureDeliverFrameInternalCallback frame,
                 VideoCaptureNotifyFrameDroppedInternalCallback dropped) {},
              std::move(it->deliver_frame),
              std::move(it->notify_frame_dropped)));
      callbacks_.erase(it);
      return;
    }
  }
}

void MediaStreamVideoTrack::FrameDeliverer::RemoveEncodedCallback(
    VideoSinkId id) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          &FrameDeliverer::RemoveEncodedCallbackOnVideoTaskRunner,
          WrapRefCounted(this), WTF::CrossThreadUnretained(id),
          main_render_task_runner_));
}

void MediaStreamVideoTrack::FrameDeliverer::
    RemoveEncodedCallbackOnVideoTaskRunner(
        VideoSinkId id,
        const scoped_refptr<base::SingleThreadTaskRunner>& task_runner) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());

  // Callback destruction needs to happen on the specified task runner.
  auto it = encoded_callbacks_.find(id);
  if (it == encoded_callbacks_.end())
    return;
  PostCrossThreadTask(
      *task_runner, FROM_HERE,
      CrossThreadBindOnce([](EncodedVideoFrameInternalCallback callback) {},
                          std::move(it->value)));
  encoded_callbacks_.erase(it);
}

void MediaStreamVideoTrack::FrameDeliverer::SetEnabled(bool enabled,
                                                       bool await_key_frame) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&FrameDeliverer::SetEnabledOnVideoTaskRunner,
                          WrapRefCounted(this), enabled, await_key_frame));
}

void MediaStreamVideoTrack::FrameDeliverer::SetEnabledOnVideoTaskRunner(
    bool enabled,
    bool await_key_frame) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  if (enabled != enabled_) {
    enabled_ = enabled;
    emit_frame_drop_events_ = true;
  }
  if (enabled_) {
    black_frame_ = nullptr;
    await_next_key_frame_ = await_key_frame;
  }
}

void MediaStreamVideoTrack::FrameDeliverer::SetIsRefreshingForMinFrameRate(
    bool is_refreshing_for_min_frame_rate) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          &FrameDeliverer::SetIsRefreshingForMinFrameRateOnVideoTaskRunner,
          WrapRefCounted(this), is_refreshing_for_min_frame_rate));
}

void MediaStreamVideoTrack::FrameDeliverer::AddSubCaptureTargetVersionCallback(
    uint32_t sub_capture_target_version,
    base::OnceClosure callback) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);

  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          &FrameDeliverer::AddSubCaptureTargetVersionCallbackOnVideoTaskRunner,
          WrapRefCounted(this), sub_capture_target_version,
          CrossThreadBindOnce(std::move(callback))));
}

void MediaStreamVideoTrack::FrameDeliverer::
    RemoveSubCaptureTargetVersionCallback(uint32_t sub_capture_target_version) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);

  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(
          &FrameDeliverer::
              RemoveSubCaptureTargetVersionCallbackOnVideoTaskRunner,
          WrapRefCounted(this), sub_capture_target_version));
}

void MediaStreamVideoTrack::FrameDeliverer::
    SetIsRefreshingForMinFrameRateOnVideoTaskRunner(
        bool is_refreshing_for_min_frame_rate) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  is_refreshing_for_min_frame_rate_ = is_refreshing_for_min_frame_rate;
}

void MediaStreamVideoTrack::FrameDeliverer::
    AddSubCaptureTargetVersionCallbackOnVideoTaskRunner(
        uint32_t sub_capture_target_version,
        WTF::CrossThreadOnceClosure callback) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  DCHECK(!base::Contains(sub_capture_target_version_callbacks_,
                         sub_capture_target_version));

  sub_capture_target_version_callbacks_.Set(sub_capture_target_version,
                                            std::move(callback));
}

void MediaStreamVideoTrack::FrameDeliverer::
    RemoveSubCaptureTargetVersionCallbackOnVideoTaskRunner(
        uint32_t sub_capture_target_version) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());

  // Note: Might or might not be here, depending on whether a later crop
  // version has already been observed or not.
  sub_capture_target_version_callbacks_.erase(sub_capture_target_version);
}

void MediaStreamVideoTrack::FrameDeliverer::DeliverFrameOnVideoTaskRunner(
    scoped_refptr<media::VideoFrame> frame,
    base::TimeTicks estimated_capture_time) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());

  frame_drop_log_state_ = FrameDropLogState();

  // TODO(crbug.com/1369085): Understand why we sometimes see old
  // sub-capture-target versions.
  if (frame->metadata().sub_capture_target_version !=
      sub_capture_target_version_) {
    OnFrameDroppedOnVideoTaskRunner(
        media::VideoCaptureFrameDropReason::kSubCaptureTargetVersionNotCurrent);
    return;
  }

  if (!enabled_ && emit_frame_drop_events_) {
    emit_frame_drop_events_ = false;
    LogFrameDroppedOnVideoTaskRunner(
        media::VideoCaptureFrameDropReason::
            kVideoTrackFrameDelivererNotEnabledReplacingWithBlackFrame);
  }
  scoped_refptr<media::VideoFrame> video_frame;
  if (enabled_) {
    video_frame = std::move(frame);
    ++deliverable_frames_;
  } else {
    // When disabled, a black video frame is passed along instead. The original
    // frames are dropped.
    video_frame = GetBlackFrame(*frame);
  }
  for (const auto& entry : callbacks_) {
    entry.deliver_frame.Run(video_frame, estimated_capture_time);
  }
  // The delay on refresh timer is reset each time a frame is received so that
  // it will not fire for at least an additional period. This means refresh
  // frames will only be requested when the source has halted delivery (e.g., a
  // screen capturer stops sending frames because the screen is not being
  // updated).
  if (is_refreshing_for_min_frame_rate_) {
    PostCrossThreadTask(
        *main_render_task_runner_, FROM_HERE,
        CrossThreadBindOnce(&MediaStreamVideoTrack::ResetRefreshTimer,
                            media_stream_video_track_));
  }
}

void MediaStreamVideoTrack::FrameDeliverer::OnFrameDroppedOnVideoTaskRunner(
    media::VideoCaptureFrameDropReason reason) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  DVLOG(1) << __func__;
  LogFrameDroppedOnVideoTaskRunner(reason);
  if (enabled_) {
    if (reason == media::VideoCaptureFrameDropReason::
                      kResolutionAdapterFrameRateIsHigherThanRequested) {
      ++discarded_frames_;
    } else {
      ++dropped_frames_;
    }
  }
  // Notify sinks that care about frame drops, i.e. WebRTC.
  for (const auto& entry : callbacks_) {
    entry.notify_frame_dropped.Run(reason);
  }
}

void MediaStreamVideoTrack::FrameDeliverer::LogFrameDroppedOnVideoTaskRunner(
    media::VideoCaptureFrameDropReason reason) {
  MaybeEmitFrameDropLogMessage(reason);

  if (reason == frame_drop_log_state_.drop_reason) {
    if (frame_drop_log_state_.max_log_count_exceeded) {
      return;
    }

    if (++frame_drop_log_state_.drop_count >
        kMaxConsecutiveFrameDropForSameReasonCount) {
      frame_drop_log_state_.max_log_count_exceeded = true;
      return;
    }
  } else {
    frame_drop_log_state_ = FrameDropLogState(reason);
  }

  LogVideoFrameDropUMA(reason, stream_type_);
}

void MediaStreamVideoTrack::FrameDeliverer::MaybeEmitFrameDropLogMessage(
    media::VideoCaptureFrameDropReason reason) {
  using Type = std::underlying_type<media::VideoCaptureFrameDropReason>::type;
  static_assert(
      static_cast<Type>(media::VideoCaptureFrameDropReason::kMaxValue) <= 100,
      "Risk of memory overuse.");

  static_assert(kMaxEmittedLogsForDroppedFramesBeforeSuppressing <
                    kFrequencyForSuppressedLogs,
                "");

  DCHECK_GE(static_cast<Type>(reason), 0);
  DCHECK_LE(reason, media::VideoCaptureFrameDropReason::kMaxValue);

  int& occurrences = frame_drop_log_counters_[reason];
  if (++occurrences > kMaxEmittedLogsForDroppedFramesBeforeSuppressing &&
      occurrences % kFrequencyForSuppressedLogs != 0) {
    return;
  }

  std::ostringstream string_stream;
  string_stream << "Frame dropped with reason code "
                << static_cast<Type>(reason) << ".";
  if (occurrences == kMaxEmittedLogsForDroppedFramesBeforeSuppressing) {
    string_stream << " Additional logs will be partially suppressed.";
  }

  // EmitLogMessage() unless overridden by testing.
  emit_log_message_.Run(string_stream.str());
}

void MediaStreamVideoTrack::FrameDeliverer::SetEmitLogMessage(
    base::RepeatingCallback<void(const std::string&)> emit_log_message) {
  emit_log_message_ = std::move(emit_log_message);
}

void MediaStreamVideoTrack::FrameDeliverer::EmitLogMessage(
    const std::string& message) {
  PostCrossThreadTask(*main_render_task_runner_, FROM_HERE,
                      CrossThreadBindOnce(&MediaStreamVideoSource::OnLog,
                                          media_stream_video_source_, message));
}

void MediaStreamVideoTrack::FrameDeliverer::
    DeliverEncodedVideoFrameOnVideoTaskRunner(
        scoped_refptr<EncodedVideoFrame> frame,
        base::TimeTicks estimated_capture_time) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  if (!enabled_) {
    return;
  }
  if (await_next_key_frame_ && !frame->IsKeyFrame()) {
    return;
  }
  await_next_key_frame_ = false;
  for (const auto& entry : encoded_callbacks_.Values()) {
    entry.Run(frame, estimated_capture_time);
  }
}

void MediaStreamVideoTrack::FrameDeliverer::
    NewSubCaptureTargetVersionOnVideoTaskRunner(
        uint32_t sub_capture_target_version) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  DCHECK_GT(sub_capture_target_version, sub_capture_target_version_);

  sub_capture_target_version_ = sub_capture_target_version;

  Vector<uint32_t> to_be_removed_keys;
  for (auto& iter : sub_capture_target_version_callbacks_) {
    if (iter.key > sub_capture_target_version) {
      continue;
    }
    std::move(iter.value).Run();
    to_be_removed_keys.push_back(iter.key);
  }
  sub_capture_target_version_callbacks_.RemoveAll(to_be_removed_keys);
}

scoped_refptr<media::VideoFrame>
MediaStreamVideoTrack::FrameDeliverer::GetBlackFrame(
    const media::VideoFrame& reference_frame) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  if (!black_frame_.get() ||
      black_frame_->natural_size() != reference_frame.natural_size()) {
    black_frame_ =
        media::VideoFrame::CreateBlackFrame(reference_frame.natural_size());
  }

  // Wrap |black_frame_| so we get a fresh timestamp we can modify. Frames
  // returned from this function may still be in use.
  scoped_refptr<media::VideoFrame> wrapped_black_frame =
      media::VideoFrame::WrapVideoFrame(black_frame_, black_frame_->format(),
                                        black_frame_->visible_rect(),
                                        black_frame_->natural_size());
  if (!wrapped_black_frame)
    return nullptr;

  wrapped_black_frame->set_timestamp(reference_frame.timestamp());
  wrapped_black_frame->metadata().reference_time =
      reference_frame.metadata().reference_time;

  return wrapped_black_frame;
}

// static
WebMediaStreamTrack MediaStreamVideoTrack::CreateVideoTrack(
    MediaStreamVideoSource* source,
    MediaStreamVideoSource::ConstraintsOnceCallback callback,
    bool enabled) {
  auto* component = MakeGarbageCollected<MediaStreamComponentImpl>(
      source->Owner(), std::make_unique<MediaStreamVideoTrack>(
                           source, std::move(callback), enabled));
  return WebMediaStreamTrack(component);
}

// static
WebMediaStreamTrack MediaStreamVideoTrack::CreateVideoTrack(
    MediaStreamVideoSource* source,
    const VideoTrackAdapterSettings& adapter_settings,
    const std::optional<bool>& noise_reduction,
    bool is_screencast,
    const std::optional<double>& min_frame_rate,
    const ImageCaptureDeviceSettings* image_capture_device_settings,
    bool pan_tilt_zoom_allowed,
    MediaStreamVideoSource::ConstraintsOnceCallback callback,
    bool enabled) {
  WebMediaStreamTrack track;
  auto* component = MakeGarbageCollected<MediaStreamComponentImpl>(
      source
"""


```