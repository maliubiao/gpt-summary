Response:
Let's break down the thought process for analyzing the `media_stream_remote_video_source.cc` file and generating the comprehensive explanation.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C++ source code file (`media_stream_remote_video_source.cc`) within the Chromium Blink rendering engine and explain its functionality, its relationship with web technologies (JavaScript, HTML, CSS), provide logical reasoning examples, illustrate common usage errors, and describe how a user's actions could lead to this code being executed.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick scan of the code, looking for key terms and structures. This immediately reveals:

* **`MediaStreamRemoteVideoSource`:** The central class, likely responsible for handling remote video streams.
* **`RemoteVideoSourceDelegate`:**  An internal helper class, suggesting a delegation pattern for handling frame reception.
* **`webrtc::VideoFrame` and `webrtc::RecordableEncodedFrame`:**  Indicates involvement with WebRTC, the core technology for real-time communication in browsers.
* **`VideoCaptureDeliverFrameCB`, `EncodedVideoFrameCB`:** Callback functions, suggesting asynchronous delivery of video frames.
* **`TrackObserver`:**  Observing the state of a media track.
* **`blink::` namespace:** Confirms it's part of the Blink rendering engine.
* **`// Copyright ... BSD-style license ...`:** Standard Chromium copyright and licensing information.
* **Includes:**  A list of included headers provides hints about dependencies (e.g., `base/task`, `media/base`, `third_party/webrtc`).
* **`OnFrame` methods:**  Crucial for processing incoming video frames.
* **`StartSourceImpl`, `StopSourceImpl`:** Methods for starting and stopping the video source.
* **`SupportsEncodedOutput`, `RequestKeyFrame`:**  Features related to video encoding.

**3. Deeper Dive into Functionality:**

Based on the initial scan, I start to build a mental model of the class's responsibilities:

* **Receiving Remote Video:** The name and the presence of `webrtc::VideoFrame` and `webrtc::RecordableEncodedFrame` strongly suggest this class is designed to handle video frames coming from a remote peer in a WebRTC connection.
* **Bridging WebRTC and Blink:** It acts as a bridge between the WebRTC world (represented by `webrtc::VideoFrame`) and the Blink rendering engine's video processing pipeline (likely involving `media::VideoFrame`).
* **Asynchronous Operations:** The use of callbacks and task runners (`base::SequencedTaskRunner`) points to asynchronous processing of video frames. This is essential for maintaining responsiveness in the browser's main thread.
* **State Management:** The `TrackObserver` and the `OnChanged` method indicate that the class monitors the state of the remote video track (e.g., live, ended).

**4. Mapping to Web Technologies (JavaScript, HTML, CSS):**

Now, the task is to connect this C++ code to the user-facing web technologies:

* **JavaScript `getUserMedia()` and `RTCPeerConnection`:** These are the core WebRTC APIs in JavaScript that initiate media streams and establish peer-to-peer connections. A remote video stream received via `RTCPeerConnection` would be the source of the video frames handled by this C++ class.
* **HTML `<video>` element:**  The eventual destination of the processed video frames. JavaScript would typically attach the remote `MediaStreamTrack` to a `<video>` element's `srcObject` property.
* **CSS (Indirectly):** While CSS doesn't directly interact with this C++ code, it's used to style the `<video>` element, affecting its size, position, and other visual properties.

**5. Constructing Logical Reasoning Examples:**

To illustrate the flow of data, I consider scenarios with input and output:

* **Scenario 1 (Raw Frames):**  A WebRTC peer sends a raw video frame. The C++ code receives it, converts it to a `media::VideoFrame`, and delivers it to a callback.
* **Scenario 2 (Encoded Frames):** A WebRTC peer sends an encoded video frame. The C++ code receives it, wraps it in an `EncodedVideoFrame` object, and delivers it to a different callback.

**6. Identifying Common Usage Errors:**

Thinking about how developers might misuse the related JavaScript APIs helps identify potential errors:

* **Not handling the `MediaStreamTrack` correctly:** Forgetting to attach the remote track to a `<video>` element.
* **Not checking the track's state:**  Trying to play video from an ended track.
* **Incorrectly managing the `RTCPeerConnection` lifecycle:**  Closing the connection prematurely.

**7. Tracing User Actions (Debugging Clues):**

To understand how a user's actions reach this code, I imagine a typical WebRTC scenario:

1. **User opens a web page:**  The starting point.
2. **JavaScript initiates WebRTC:** The page uses `getUserMedia()` (local media) or establishes an `RTCPeerConnection` (remote media).
3. **Remote peer sends video:** Data flows through the WebRTC stack.
4. **Blink receives the remote video track:** This is where `MediaStreamRemoteVideoSource` comes into play.

**8. Structuring the Explanation:**

Finally, I organize the information into logical sections:

* **Functionality:**  A high-level overview.
* **Relationship to Web Technologies:**  Connecting the C++ code to JavaScript, HTML, and CSS.
* **Logical Reasoning:**  Providing concrete examples of input and output.
* **Common Usage Errors:**  Illustrating potential developer mistakes.
* **User Actions (Debugging):**  Describing the sequence of events that lead to the execution of this code.

**Self-Correction/Refinement during the Process:**

* **Initially, I might have focused too narrowly on the C++ code itself.**  I then broadened the scope to include the surrounding WebRTC context and the interaction with JavaScript APIs.
* **I ensured that the explanations were clear and concise, avoiding overly technical jargon where possible.**  The goal is to be informative and understandable.
* **I double-checked the accuracy of the information, particularly regarding WebRTC concepts and JavaScript APIs.**

By following this structured approach, combining code analysis with an understanding of the broader web development context, I can generate a comprehensive and insightful explanation of the `media_stream_remote_video_source.cc` file.
这是 Chromium Blink 引擎中 `blink/renderer/modules/peerconnection/media_stream_remote_video_source.cc` 文件的功能说明：

**核心功能:**

这个文件的核心功能是 **管理和处理从远程 WebRTC PeerConnection 连接接收到的视频流数据**。它将 WebRTC 的视频帧数据转换成 Blink 渲染引擎可以理解和使用的格式，并将其传递给相应的渲染管道，最终显示在网页上的 `<video>` 元素中。

**更详细的功能分解:**

1. **接收 WebRTC 视频帧:**
   - `MediaStreamRemoteVideoSource` 实现了 `MediaStreamVideoSource` 接口，用于提供视频数据。
   - 它内部使用 `RemoteVideoSourceDelegate` 作为委托类来实际接收来自 WebRTC 视频轨道的 `webrtc::VideoFrame` 或 `webrtc::RecordableEncodedFrame`。
   - `RemoteVideoSourceDelegate` 实现了 WebRTC 的 `rtc::VideoSinkInterface` 接口，可以被添加到 `webrtc::VideoTrackInterface` 中，从而接收其产生的视频帧。

2. **格式转换:**
   - 将 WebRTC 的 `webrtc::VideoFrame` (可能包含不同的 buffer 类型，如 I420 或者 Native) 转换成 Blink 内部使用的 `media::VideoFrame` 格式。
   - `ConvertFromMappedWebRtcVideoFrameBuffer` 函数负责处理非 Native 类型的 buffer 的转换。
   - 对于 Native 类型的 buffer，它会直接获取底层的 `media::VideoFrame` (通过 `WebRtcVideoFrameAdapter`)。

3. **元数据处理:**
   - 从 WebRTC 的 `webrtc::VideoFrame` 中提取关键的元数据信息，并设置到 `media::VideoFrame` 中，包括：
     - **时间戳 (timestamp):**  用于同步视频播放。
     - **旋转信息 (rotation):**  指示视频帧的旋转角度。
     - **色彩空间 (color_space):**  描述视频的色彩属性。
     - **RTP 时间戳 (rtp_timestamp):**  原始 RTP 包的时间戳。
     - **处理时间 (processing_time):**  WebRTC 内部处理帧所花费的时间。
     - **捕获开始时间 (capture_begin_time):**  估计的视频帧捕获时间，基于 NTP 时间戳。
     - **接收时间 (receive_time):**  最后一个数据包的到达时间。
     - **渲染提示 (render parameters):**  例如低延迟渲染和最大合成延迟帧数。

4. **编码帧处理:**
   - 除了原始视频帧，它还能处理 WebRTC 传来的编码后的视频帧 (`webrtc::RecordableEncodedFrame`)。
   - `WebRtcEncodedVideoFrame` 类用于封装这些编码帧，并提供统一的 `EncodedVideoFrame` 接口。

5. **异步处理:**
   - 接收到的 WebRTC 视频帧通常在 WebRTC 的内部线程（libjingle 线程）上，需要通过 `PostCrossThreadTask` 调度到 Blink 的 IO 线程上进行进一步处理和传递给 `frame_callback_` 或 `encoded_frame_callback_`。

6. **状态管理:**
   - 监听 WebRTC 视频轨道的生命周期状态变化 (例如：`kLive`, `kEnded`)，并更新 `MediaStreamVideoSource` 的状态 (`WebMediaStreamSource::kReadyStateLive`, `WebMediaStreamSource::kReadyStateEnded`)，从而反映到 JavaScript 中 `MediaStreamTrack` 的状态。

7. **支持编码输出:**
   - `SupportsEncodedOutput()` 方法检查底层的 WebRTC 视频源是否支持直接输出编码后的帧。
   - `OnEncodedSinkEnabled()` 和 `OnEncodedSinkDisabled()` 方法用于控制是否将编码后的帧传递给注册的回调。

8. **请求关键帧:**
   - `RequestKeyFrame()` 方法可以触发 WebRTC 视频编码器生成一个关键帧。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    - 当 JavaScript 代码使用 `getUserMedia()` 获取本地媒体流，并通过 `RTCPeerConnection` 发送给远程 Peer 时，远程 Peer 接收到的视频轨道最终会由 `MediaStreamRemoteVideoSource` 处理。
    - 当 JavaScript 代码接收到远程的 `MediaStreamTrack` (通过 `RTCPeerConnection` 的 `ontrack` 事件)，并将这个 track 赋值给 HTML `<video>` 元素的 `srcObject` 属性时，Blink 会创建 `MediaStreamRemoteVideoSource` 来驱动这个 `<video>` 元素的渲染。
    - JavaScript 可以监听 `MediaStreamTrack` 的 `onended` 事件，这与 `MediaStreamRemoteVideoSource` 监听 WebRTC 轨道状态并更新自身状态有关。
    - JavaScript 可以通过 `requestVideoFrameCallback()` API 获取视频帧的元数据，而 `MediaStreamRemoteVideoSource` 正是将这些元数据从 WebRTC 传递到 Blink 的关键环节。

* **HTML:**
    - `<video>` 元素是最终展示远程视频流的地方。`MediaStreamRemoteVideoSource` 负责将接收到的视频数据提供给 `<video>` 元素进行渲染。

* **CSS:**
    - CSS 用于控制 `<video>` 元素的样式，例如大小、位置、边框等，但 CSS 本身不直接与 `MediaStreamRemoteVideoSource` 的功能交互。`MediaStreamRemoteVideoSource` 关注的是视频数据的处理和传递，而不是最终的视觉呈现。

**逻辑推理的假设输入与输出:**

**假设输入:**

1. **来自 WebRTC 视频轨道的 `webrtc::VideoFrame`:**
   - 包含一个 I420 格式的 buffer，分辨率为 640x480，时间戳为 1000 微秒，旋转角度为 `webrtc::kVideoRotation_90`。
   - 或者包含一个编码后的帧 `webrtc::RecordableEncodedFrame`，编码格式为 H.264，是一个关键帧。

**输出:**

1. **通过 `frame_callback_` 传递的 `media::VideoFrame`:**
   - 分辨率为 640x480。
   - 时间戳被转换为 `base::TimeDelta`。
   - `metadata().transformation` 被设置为相应的旋转枚举值。
   - 其他元数据（如 RTP 时间戳、捕获时间等）也被填充。

2. **通过 `encoded_frame_callback_` 传递的 `EncodedVideoFrame` (实际上是 `WebRtcEncodedVideoFrame`):**
   - `Codec()` 返回 `media::kCodecH264`。
   - `IsKeyFrame()` 返回 `true`。
   - `Data()` 返回编码后的视频数据。
   - `Resolution()` 返回 640x480。

**用户或编程常见的使用错误:**

1. **没有正确处理 `MediaStreamTrack` 的生命周期:**
   - **错误:** 在 `RTCPeerConnection` 断开后，或者远程流结束时，没有及时停止或清理相关的 JavaScript 对象和监听器。
   - **后果:** 可能导致内存泄漏或尝试访问已释放的资源。
   - **调试线索:**  如果在 `MediaStreamRemoteVideoSource::StopSourceImpl()` 中 `observer_` 已经为空，但状态仍然是 `MediaStreamVideoSource::LIVE`，可能说明 JavaScript 代码没有正确处理 track 的停止。

2. **假设视频帧总是以特定格式到达:**
   - **错误:**  假设远程 Peer 总是发送 I420 格式的视频帧，而没有处理其他可能的格式。
   - **后果:**  如果收到其他格式的帧，转换过程可能会失败，导致视频无法显示。
   - **调试线索:**  检查 `ConvertFromMappedWebRtcVideoFrameBuffer` 的调用是否覆盖了所有可能的 `webrtc::VideoFrameBuffer::Type`。

3. **忽略视频帧的元数据:**
   - **错误:**  在渲染视频时，忽略了 `media::VideoFrame` 中的元数据，例如旋转信息。
   - **后果:**  视频可能会以错误的 orientation 显示。
   - **调试线索:**  检查渲染管道是否正确使用了 `video_frame->metadata().transformation`。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户打开一个包含 WebRTC 功能的网页:**  例如，一个视频会议网站。
2. **网页 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` (可选):**  如果需要本地摄像头作为输入。
3. **网页 JavaScript 代码创建一个 `RTCPeerConnection` 对象:**  用于建立与远程用户的连接。
4. **网页 JavaScript 代码通过信令服务器与远程用户交换 SDP 信息 (Session Description Protocol):**  用于协商媒体能力。
5. **连接建立后，远程用户的视频流数据开始通过 WebRTC 连接传输过来。**
6. **Blink 引擎接收到远程视频流的数据包。**
7. **WebRTC 模块解码这些数据包，并生成 `webrtc::VideoFrame` 或 `webrtc::RecordableEncodedFrame`。**
8. **远程 `MediaStreamTrack` 对象被创建，并与接收到的 WebRTC 视频轨道关联。**
9. **Blink 创建 `MediaStreamRemoteVideoSource` 对象来管理这个远程视频轨道。**
10. **`RemoteVideoSourceDelegate` 被添加到 WebRTC 视频轨道的 sink 中，开始接收视频帧。**
11. **当接收到 `webrtc::VideoFrame` 或 `webrtc::RecordableEncodedFrame` 时，`RemoteVideoSourceDelegate::OnFrame()` 方法被调用。**
12. **`OnFrame()` 方法将 WebRTC 的视频帧转换为 Blink 的 `media::VideoFrame` 或 `EncodedVideoFrame`，并将其通过回调 (`frame_callback_` 或 `encoded_frame_callback_`) 传递到 Blink 的渲染管道。**
13. **渲染管道最终将视频帧数据用于更新网页上 `<video>` 元素的显示。**

**调试时，可以关注以下方面:**

* **检查 WebRTC 连接状态:**  确保连接已成功建立。
* **查看 `RTCPeerConnection` 的 `getReceivers()` 输出:**  确认是否已成功接收到远程视频轨道。
* **在 `MediaStreamRemoteVideoSource` 的构造函数和 `StartSourceImpl()` 中设置断点:**  确认对象是否被正确创建和初始化。
* **在 `RemoteVideoSourceDelegate::OnFrame()` 中设置断点:**  检查是否接收到了视频帧，并查看帧的属性（如分辨率、时间戳等）。
* **检查 `frame_callback_` 或 `encoded_frame_callback_` 的调用:**  确认视频帧数据是否被成功传递到渲染管道。
* **使用 Chrome 的 `chrome://webrtc-internals` 页面:**  查看 WebRTC 的内部状态和统计信息，例如丢包率、帧率等，以帮助诊断问题。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/media_stream_remote_video_source.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/peerconnection/media_stream_remote_video_source.h"

#include <stdint.h>

#include <utility>

#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "media/base/timestamp_constants.h"
#include "media/base/video_frame.h"
#include "media/base/video_util.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/mojom/mediastream/media_stream.mojom-blink.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/webrtc/convert_to_webrtc_video_frame_buffer.h"
#include "third_party/blink/renderer/platform/webrtc/track_observer.h"
#include "third_party/blink/renderer/platform/webrtc/webrtc_video_frame_adapter.h"
#include "third_party/blink/renderer/platform/webrtc/webrtc_video_utils.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"
#include "third_party/webrtc/api/video/i420_buffer.h"
#include "third_party/webrtc/api/video/recordable_encoded_frame.h"
#include "third_party/webrtc/rtc_base/time_utils.h"
#include "third_party/webrtc/system_wrappers/include/clock.h"

namespace blink {

namespace {

class WebRtcEncodedVideoFrame : public EncodedVideoFrame {
 public:
  explicit WebRtcEncodedVideoFrame(const webrtc::RecordableEncodedFrame& frame)
      : buffer_(frame.encoded_buffer()),
        codec_(WebRtcToMediaVideoCodec(frame.codec())),
        is_key_frame_(frame.is_key_frame()),
        resolution_(frame.resolution().width, frame.resolution().height) {
    if (frame.color_space()) {
      color_space_ = WebRtcToGfxColorSpace(*frame.color_space());
    }
  }

  base::span<const uint8_t> Data() const override {
    return base::make_span(buffer_->data(), buffer_->size());
  }

  media::VideoCodec Codec() const override { return codec_; }

  bool IsKeyFrame() const override { return is_key_frame_; }

  std::optional<gfx::ColorSpace> ColorSpace() const override {
    return color_space_;
  }

  gfx::Size Resolution() const override { return resolution_; }

 private:
  rtc::scoped_refptr<const webrtc::EncodedImageBufferInterface> buffer_;
  media::VideoCodec codec_;
  bool is_key_frame_;
  std::optional<gfx::ColorSpace> color_space_;
  gfx::Size resolution_;
};

}  // namespace

// Internal class used for receiving frames from the webrtc track on a
// libjingle thread and forward it to the IO-thread.
class MediaStreamRemoteVideoSource::RemoteVideoSourceDelegate
    : public WTF::ThreadSafeRefCounted<RemoteVideoSourceDelegate>,
      public rtc::VideoSinkInterface<webrtc::VideoFrame>,
      public rtc::VideoSinkInterface<webrtc::RecordableEncodedFrame> {
 public:
  RemoteVideoSourceDelegate(
      scoped_refptr<base::SequencedTaskRunner> video_task_runner,
      VideoCaptureDeliverFrameCB new_frame_callback,
      EncodedVideoFrameCB encoded_frame_callback,
      VideoCaptureSubCaptureTargetVersionCB
          sub_capture_target_version_callback);

 protected:
  friend class WTF::ThreadSafeRefCounted<RemoteVideoSourceDelegate>;
  ~RemoteVideoSourceDelegate() override;

  // Implements rtc::VideoSinkInterface used for receiving video frames
  // from the PeerConnection video track. May be called on a libjingle internal
  // thread.
  void OnFrame(const webrtc::VideoFrame& frame) override;

  // VideoSinkInterface<webrtc::RecordableEncodedFrame>
  void OnFrame(const webrtc::RecordableEncodedFrame& frame) override;

  void DoRenderFrameOnIOThread(scoped_refptr<media::VideoFrame> video_frame,
                               base::TimeTicks estimated_capture_time);

 private:
  void OnEncodedVideoFrameOnIO(scoped_refptr<EncodedVideoFrame> frame,
                               base::TimeTicks estimated_capture_time);

  scoped_refptr<base::SequencedTaskRunner> video_task_runner_;

  // |frame_callback_| is accessed on the IO thread.
  VideoCaptureDeliverFrameCB frame_callback_;

  // |encoded_frame_callback_| is accessed on the IO thread.
  EncodedVideoFrameCB encoded_frame_callback_;

  // |sub_capture_target_version_callback| is accessed on the IO thread.
  VideoCaptureSubCaptureTargetVersionCB sub_capture_target_version_callback_;

  // Timestamp of the first received frame.
  std::optional<base::TimeTicks> start_timestamp_;

  // WebRTC real time clock, needed to determine NTP offset.
  raw_ptr<webrtc::Clock> clock_;

  // Offset between NTP clock and WebRTC clock.
  const int64_t ntp_offset_;

  // Determined from a feature flag; if set WebRTC won't forward an unspecified
  // color space.
  const bool ignore_unspecified_color_space_;
};

MediaStreamRemoteVideoSource::RemoteVideoSourceDelegate::
    RemoteVideoSourceDelegate(
        scoped_refptr<base::SequencedTaskRunner> video_task_runner,
        VideoCaptureDeliverFrameCB new_frame_callback,
        EncodedVideoFrameCB encoded_frame_callback,
        VideoCaptureSubCaptureTargetVersionCB
            sub_capture_target_version_callback)
    : video_task_runner_(video_task_runner),
      frame_callback_(std::move(new_frame_callback)),
      encoded_frame_callback_(std::move(encoded_frame_callback)),
      sub_capture_target_version_callback_(
          std::move(sub_capture_target_version_callback)),
      clock_(webrtc::Clock::GetRealTimeClock()),
      ntp_offset_(clock_->TimeInMilliseconds() -
                  clock_->CurrentNtpInMilliseconds()),
      ignore_unspecified_color_space_(base::FeatureList::IsEnabled(
          features::kWebRtcIgnoreUnspecifiedColorSpace)) {}

MediaStreamRemoteVideoSource::RemoteVideoSourceDelegate::
    ~RemoteVideoSourceDelegate() = default;

void MediaStreamRemoteVideoSource::RemoteVideoSourceDelegate::OnFrame(
    const webrtc::VideoFrame& incoming_frame) {
  const webrtc::VideoFrame::RenderParameters render_parameters =
      incoming_frame.render_parameters();
  const bool render_immediately = render_parameters.use_low_latency_rendering ||
                                  incoming_frame.timestamp_us() == 0;

  const base::TimeTicks current_time = base::TimeTicks::Now();
  const base::TimeTicks render_time =
      render_immediately
          ? current_time
          : base::TimeTicks() +
                base::Microseconds(incoming_frame.timestamp_us());
  if (!start_timestamp_)
    start_timestamp_ = render_time;
  const base::TimeDelta elapsed_timestamp = render_time - *start_timestamp_;
  TRACE_EVENT2("webrtc", "RemoteVideoSourceDelegate::RenderFrame",
               "Ideal Render Instant", render_time.ToInternalValue(),
               "Timestamp", elapsed_timestamp.InMicroseconds());

  rtc::scoped_refptr<webrtc::VideoFrameBuffer> buffer =
      incoming_frame.video_frame_buffer();
  scoped_refptr<media::VideoFrame> video_frame;
  if (buffer->type() == webrtc::VideoFrameBuffer::Type::kNative) {
    video_frame = static_cast<WebRtcVideoFrameAdapter*>(buffer.get())
                      ->getMediaVideoFrame();
    video_frame->set_timestamp(elapsed_timestamp);
  } else {
    video_frame =
        ConvertFromMappedWebRtcVideoFrameBuffer(buffer, elapsed_timestamp);
  }
  if (!video_frame)
    return;

  // Rotation may be explicitly set sometimes.
  if (incoming_frame.rotation() != webrtc::kVideoRotation_0) {
    video_frame->metadata().transformation =
        WebRtcToMediaVideoRotation(incoming_frame.rotation());
  }

  // The second clause of the condition is controlled by the feature flag
  // WebRtcIgnoreUnspecifiedColorSpace. If the feature is enabled we won't try
  // to guess a color space if the webrtc::ColorSpace is unspecified. If the
  // feature is disabled (default), an unspecified color space will get
  // converted into a gfx::ColorSpace set to BT709.
  if (incoming_frame.color_space() &&
      !(ignore_unspecified_color_space_ &&
        incoming_frame.color_space()->primaries() ==
            webrtc::ColorSpace::PrimaryID::kUnspecified &&
        incoming_frame.color_space()->transfer() ==
            webrtc::ColorSpace::TransferID::kUnspecified &&
        incoming_frame.color_space()->matrix() ==
            webrtc::ColorSpace::MatrixID::kUnspecified)) {
    video_frame->set_color_space(
        WebRtcToGfxColorSpace(*incoming_frame.color_space()));
  }

  // Run render smoothness algorithm only when we don't have to render
  // immediately.
  if (!render_immediately)
    video_frame->metadata().reference_time = render_time;

  if (render_parameters.max_composition_delay_in_frames) {
    video_frame->metadata().maximum_composition_delay_in_frames =
        render_parameters.max_composition_delay_in_frames;
  }

  video_frame->metadata().decode_end_time = current_time;

  // RTP_TIMESTAMP, PROCESSING_TIME, and CAPTURE_BEGIN_TIME are all exposed
  // through the JavaScript callback mechanism
  // video.requestVideoFrameCallback().
  video_frame->metadata().rtp_timestamp =
      static_cast<double>(incoming_frame.rtp_timestamp());

  if (incoming_frame.processing_time()) {
    video_frame->metadata().processing_time =
        base::Microseconds(incoming_frame.processing_time()->Elapsed().us());
  }

  // Set capture time to the NTP time, which is the estimated capture time
  // converted to the local clock.
  if (incoming_frame.ntp_time_ms() > 0) {
    video_frame->metadata().capture_begin_time =
        base::TimeTicks() +
        base::Milliseconds(incoming_frame.ntp_time_ms() + ntp_offset_);
  }

  // Set receive time to arrival of last packet.
  if (!incoming_frame.packet_infos().empty()) {
    webrtc::Timestamp last_packet_arrival =
        std::max_element(
            incoming_frame.packet_infos().cbegin(),
            incoming_frame.packet_infos().cend(),
            [](const webrtc::RtpPacketInfo& a, const webrtc::RtpPacketInfo& b) {
              return a.receive_time() < b.receive_time();
            })
            ->receive_time();
    video_frame->metadata().receive_time =
        base::TimeTicks() + base::Microseconds(last_packet_arrival.us());
    base::UmaHistogramTimes(
        "WebRTC.Video.TotalReceiveDelay",
        current_time - *video_frame->metadata().receive_time);
  }

  // Use our computed render time as estimated capture time. If timestamp_us()
  // (which is actually the suggested render time) is set by WebRTC, it's based
  // on the RTP timestamps in the frame's packets, so congruent with the
  // received frame capture timestamps. If set by us, it's as congruent as we
  // can get with the timestamp sequence of frames we received.
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&RemoteVideoSourceDelegate::DoRenderFrameOnIOThread,
                          WrapRefCounted(this), video_frame, render_time));
}

void MediaStreamRemoteVideoSource::RemoteVideoSourceDelegate::
    DoRenderFrameOnIOThread(scoped_refptr<media::VideoFrame> video_frame,
                            base::TimeTicks estimated_capture_time) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  TRACE_EVENT0("webrtc", "RemoteVideoSourceDelegate::DoRenderFrameOnIOThread");
  frame_callback_.Run(std::move(video_frame), estimated_capture_time);
}

void MediaStreamRemoteVideoSource::RemoteVideoSourceDelegate::OnFrame(
    const webrtc::RecordableEncodedFrame& frame) {
  const bool render_immediately = frame.render_time().us() == 0;
  const base::TimeTicks current_time = base::TimeTicks::Now();
  const base::TimeTicks render_time =
      render_immediately
          ? current_time
          : base::TimeTicks() + base::Microseconds(frame.render_time().us());

  // Use our computed render time as estimated capture time. If render_time()
  // is set by WebRTC, it's based on the RTP timestamps in the frame's packets,
  // so congruent with the received frame capture timestamps. If set by us, it's
  // as congruent as we can get with the timestamp sequence of frames we
  // received.
  PostCrossThreadTask(
      *video_task_runner_, FROM_HERE,
      CrossThreadBindOnce(&RemoteVideoSourceDelegate::OnEncodedVideoFrameOnIO,
                          WrapRefCounted(this),
                          base::MakeRefCounted<WebRtcEncodedVideoFrame>(frame),
                          render_time));
}

void MediaStreamRemoteVideoSource::RemoteVideoSourceDelegate::
    OnEncodedVideoFrameOnIO(scoped_refptr<EncodedVideoFrame> frame,
                            base::TimeTicks estimated_capture_time) {
  DCHECK(video_task_runner_->RunsTasksInCurrentSequence());
  encoded_frame_callback_.Run(std::move(frame), estimated_capture_time);
}

MediaStreamRemoteVideoSource::MediaStreamRemoteVideoSource(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    std::unique_ptr<TrackObserver> observer)
    : MediaStreamVideoSource(std::move(task_runner)),
      observer_(std::move(observer)) {
  // The callback will be automatically cleared when 'observer_' goes out of
  // scope and no further callbacks will occur.
  observer_->SetCallback(WTF::BindRepeating(
      &MediaStreamRemoteVideoSource::OnChanged, WTF::Unretained(this)));
}

MediaStreamRemoteVideoSource::~MediaStreamRemoteVideoSource() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!observer_);
}

void MediaStreamRemoteVideoSource::OnSourceTerminated() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  StopSourceImpl();
}

void MediaStreamRemoteVideoSource::StartSourceImpl(
    VideoCaptureDeliverFrameCB frame_callback,
    EncodedVideoFrameCB encoded_frame_callback,
    VideoCaptureSubCaptureTargetVersionCB sub_capture_target_version_callback,
    // The remote track does not not report frame drops.
    VideoCaptureNotifyFrameDroppedCB) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(!delegate_.get());
  delegate_ = base::MakeRefCounted<RemoteVideoSourceDelegate>(
      video_task_runner(), std::move(frame_callback),
      std::move(encoded_frame_callback),
      std::move(sub_capture_target_version_callback));
  scoped_refptr<webrtc::VideoTrackInterface> video_track(
      static_cast<webrtc::VideoTrackInterface*>(observer_->track().get()));
  video_track->AddOrUpdateSink(delegate_.get(), rtc::VideoSinkWants());
  OnStartDone(mojom::MediaStreamRequestResult::OK);
}

void MediaStreamRemoteVideoSource::StopSourceImpl() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // StopSourceImpl is called either when MediaStreamTrack.stop is called from
  // JS or blink gc the MediaStreamSource object or when OnSourceTerminated()
  // is called. Garbage collection will happen after the PeerConnection no
  // longer receives the video track.
  if (!observer_)
    return;
  DCHECK(state() != MediaStreamVideoSource::ENDED);
  scoped_refptr<webrtc::VideoTrackInterface> video_track(
      static_cast<webrtc::VideoTrackInterface*>(observer_->track().get()));
  video_track->RemoveSink(delegate_.get());
  // This removes the references to the webrtc video track.
  observer_.reset();
}

rtc::VideoSinkInterface<webrtc::VideoFrame>*
MediaStreamRemoteVideoSource::SinkInterfaceForTesting() {
  return delegate_.get();
}

rtc::VideoSinkInterface<webrtc::RecordableEncodedFrame>*
MediaStreamRemoteVideoSource::EncodedSinkInterfaceForTesting() {
  return delegate_.get();
}

void MediaStreamRemoteVideoSource::OnChanged(
    webrtc::MediaStreamTrackInterface::TrackState state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  switch (state) {
    case webrtc::MediaStreamTrackInterface::kLive:
      SetReadyState(WebMediaStreamSource::kReadyStateLive);
      break;
    case webrtc::MediaStreamTrackInterface::kEnded:
      SetReadyState(WebMediaStreamSource::kReadyStateEnded);
      break;
    default:
      NOTREACHED();
  }
}

bool MediaStreamRemoteVideoSource::SupportsEncodedOutput() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!observer_ || !observer_->track()) {
    return false;
  }
  scoped_refptr<webrtc::VideoTrackInterface> video_track(
      static_cast<webrtc::VideoTrackInterface*>(observer_->track().get()));
  return video_track->GetSource()->SupportsEncodedOutput();
}

void MediaStreamRemoteVideoSource::RequestKeyFrame() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!observer_ || !observer_->track()) {
    return;
  }
  scoped_refptr<webrtc::VideoTrackInterface> video_track(
      static_cast<webrtc::VideoTrackInterface*>(observer_->track().get()));
  if (video_track->GetSource()) {
    video_track->GetSource()->GenerateKeyFrame();
  }
}

base::WeakPtr<MediaStreamVideoSource>
MediaStreamRemoteVideoSource::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

void MediaStreamRemoteVideoSource::OnEncodedSinkEnabled() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!observer_ || !observer_->track()) {
    return;
  }
  scoped_refptr<webrtc::VideoTrackInterface> video_track(
      static_cast<webrtc::VideoTrackInterface*>(observer_->track().get()));
  video_track->GetSource()->AddEncodedSink(delegate_.get());
}

void MediaStreamRemoteVideoSource::OnEncodedSinkDisabled() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!observer_ || !observer_->track()) {
    return;
  }
  scoped_refptr<webrtc::VideoTrackInterface> video_track(
      static_cast<webrtc::VideoTrackInterface*>(observer_->track().get()));
  video_track->GetSource()->RemoveEncodedSink(delegate_.get());
}

}  // namespace blink

"""

```