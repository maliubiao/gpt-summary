Response:
Let's break down the thought process for analyzing the `rtc_video_decoder_adapter.cc` file.

**1. Initial Understanding (Skimming and High-Level Concepts):**

* **Filename and Directory:**  `blink/renderer/platform/peerconnection/rtc_video_decoder_adapter.cc`. This immediately tells us it's part of the Blink rendering engine, involved in WebRTC peer-to-peer connections, and specifically deals with video decoding. The "adapter" part suggests it's a bridge between different video decoding mechanisms.
* **Copyright and Includes:** Standard Chromium boilerplate. The includes are crucial for identifying key dependencies:
    * `<media/base/...>`:  Indicates interaction with Chromium's media framework.
    * `third_party/blink/...`:  Shows integration within Blink.
    * `third_party/webrtc/...`: Confirms it's a wrapper around WebRTC's decoding capabilities.
    * `base/...`:  Chromium's base utilities (threading, memory, etc.).
* **Namespace:** `blink` -> `namespace blink { namespace { ... } namespace blink { ... } }`  Highlights the file's place within Blink's structure. The anonymous namespace `namespace { ... }` contains internal helper functions and constants not meant for external use.

**2. Core Functionality Identification (Looking for Key Classes and Methods):**

* **`RTCVideoDecoderAdapter` Class:** This is the primary class. Its methods will reveal the core responsibilities.
    * `Create()`: A static factory method, suggesting a specific way to instantiate the adapter.
    * `Configure()`: Likely sets up the decoder with specific settings.
    * `Decode()`: The main decoding function, taking encoded video data.
    * `RegisterDecodeCompleteCallback()`:  A callback mechanism for informing about decoded frames.
    * `Release()`:  Cleans up resources.
    * `InitializeSync()` and `ReinitializeSync()`: Synchronous initialization and re-initialization (important!).
    * `ChangeStatus()`:  Manages the decoder's internal state.
* **`RTCVideoDecoderAdapter::Impl` Class:** A private inner class. This strongly suggests the Pimpl (Pointer to Implementation) idiom, used to hide implementation details and improve compile-time dependencies. The `Impl` class likely handles the direct interaction with the underlying media framework.
    * `Initialize()`:  Asynchronous initialization of the actual decoder.
    * `Decode()`:  Decodes a single buffer.
    * `EnqueueBuffer()`: Manages a queue of incoming buffers.
    * `Flush()`:  Handles the end of a decoding stream.
    * `OnDecodeDone()`:  A callback when a decode operation finishes.
    * `OnOutput()`: A callback when a decoded frame is ready.

**3. Relationship to Web Technologies (JavaScript, HTML, CSS):**

* **WebRTC Connection:** The file's location and the use of `webrtc::...` types make it clear this is part of the video decoding pipeline for WebRTC.
* **JavaScript API:**  WebRTC functionality is exposed to JavaScript through APIs like `RTCPeerConnection`. This adapter is a backend component that makes the decoding happen when a WebRTC connection receives video.
* **HTML `<video>` Element:** Decoded video frames are eventually displayed in an HTML `<video>` element. This adapter plays a crucial role in getting the video data into a format the browser can render.
* **CSS (Indirect):** While this file doesn't directly manipulate CSS, the presentation of the decoded video in the `<video>` element can be styled using CSS.

**4. Logic and Assumptions (Analyzing Key Code Blocks):**

* **Software Fallback:** The code heavily checks for software fallback scenarios (`HasSoftwareFallback`). This is a core part of its robustness, switching to software decoding if hardware decoding fails or isn't supported. The `ResolutionMonitor` further informs this decision based on video resolution.
* **Buffer Management:** The `pending_buffers_` and `decode_timestamps_` queues in the `Impl` class are essential for handling incoming data, especially when dealing with potential reordering or delays.
* **Error Handling:** The `consecutive_error_count_` and the `ChangeStatus()` mechanism show a focus on error detection and recovery, including requesting keyframes.
* **Reinitialization:** The `ReinitializeSync()` function and the logic around `ShouldReinitializeForSettingColorSpace()` demonstrate how the decoder can dynamically adapt to changes in video properties like color space.
* **Concurrency:** The use of `base::WaitableEvent` and separate sequences (`media_sequence_checker_`, `decoding_sequence_checker_`) highlights the multithreaded nature of video decoding and the need for synchronization.

**5. Common Usage Errors (Based on Code Analysis):**

* **Incorrect Initialization:** Failing to properly initialize the decoder (e.g., missing configuration details) would lead to errors. The `InitializeSync()` and `Configure()` methods are crucial.
* **Feeding Unsupported Codecs:** If the input video stream uses a codec that the adapter doesn't support, decoding will fail. The `Create()` method does some initial codec checking.
* **Out-of-Order Frames (Implicit):** While the adapter has some buffering, significant out-of-order frames could cause issues.
* **Resource Leaks (Less likely due to RAII):**  The code uses smart pointers (`std::unique_ptr`, `rtc::scoped_refptr`), which reduces the risk of manual memory management errors, but improper release could still occur.
* **Thread Safety Issues (Mitigated by Sequences):**  Incorrectly accessing shared data across threads without proper synchronization could lead to race conditions, but the use of sequence checkers aims to prevent this.

**6. Refinement and Examples:**

After the initial analysis, I'd go back through the code to find specific examples for each point:

* **JavaScript:**  Think about the JavaScript code that would initiate a WebRTC video call and how it eventually leads to this adapter being used.
* **HTML:**  The `<video>` element is the direct recipient of the decoded frames.
* **CSS:** How CSS properties like `width`, `height`, and `object-fit` affect the display of the video.
* **Logic:**  Trace the flow of a `Decode()` call, noting how buffers are enqueued, processed, and how the `OnOutput()` callback delivers the decoded frame.
* **Errors:** Imagine scenarios where the decoder encounters corrupted data or an unsupported codec.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the adapter directly interacts with the GPU.
* **Correction:** Realized it uses `media::GpuVideoAcceleratorFactories`, indicating it's leveraging Chromium's media framework for hardware acceleration, but it's an abstraction layer.
* **Initial thought:** Focused too much on the `RTCVideoDecoderAdapter` class.
* **Correction:** Recognized the importance of the `Impl` class and the Pimpl pattern.
* **Initial thought:**  Underestimated the complexity of software fallback.
* **Correction:**  Paid closer attention to the `HasSoftwareFallback`, `ResolutionMonitor`, and the logic for switching between hardware and software decoding.

By following these steps, iteratively analyzing the code, and connecting it to broader web technologies, one can arrive at a comprehensive understanding of the `rtc_video_decoder_adapter.cc` file's functionality.
好的，让我们详细分析一下 `blink/renderer/platform/peerconnection/rtc_video_decoder_adapter.cc` 文件的功能。

**主要功能:**

这个文件的核心功能是实现一个 **WebRTC 视频解码器适配器**。它的作用是在 Blink 渲染引擎中，作为 WebRTC 的视频解码器和 Chromium 的媒体框架之间的桥梁。具体来说，它负责：

1. **接收来自 WebRTC 层的编码后的视频帧数据。**
2. **将 WebRTC 的数据格式转换为 Chromium 媒体框架可以理解的格式。**
3. **利用 Chromium 的 `media::VideoDecoder` 接口进行实际的视频解码。** 这通常会利用硬件加速的解码能力，但也会在必要时回退到软件解码。
4. **处理解码完成后的视频帧，并将其转换回 WebRTC 的 `webrtc::VideoFrame` 格式。**
5. **将解码后的视频帧传递回 WebRTC 层，以便在浏览器中显示或进行进一步处理。**
6. **管理解码器的生命周期，包括初始化、配置、解码和释放资源。**
7. **处理解码过程中的错误和状态变化，例如需要关键帧、解码错误等。**
8. **根据需要动态地重新初始化解码器，例如当视频流的分辨率或颜色空间发生变化时。**
9. **实现软件解码回退机制，当硬件解码失败或不支持时，切换到软件解码。**
10. **监控解码器的性能和错误情况，并通过 UMA 记录相关指标。**

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件本身不直接包含 JavaScript, HTML, 或 CSS 代码。然而，它在幕后支撑着 WebRTC 功能的实现，而 WebRTC 功能可以通过 JavaScript API 在网页中被调用和使用。

* **JavaScript:**
    * **`RTCPeerConnection` API:**  当网页使用 `RTCPeerConnection` 建立 WebRTC 连接并接收到远程视频流时，这个适配器会被创建和使用。JavaScript 代码会调用 `RTCPeerConnection` 的相关方法来处理接收到的媒体流，而这些操作最终会触发 `RTCVideoDecoderAdapter` 的解码过程。
    * **`MediaStream` API:** 解码后的视频帧会被封装成 `MediaStreamTrack` 的一部分，最终可以在 HTML 的 `<video>` 元素中播放。
    * **示例:**
        ```javascript
        const peerConnection = new RTCPeerConnection();
        peerConnection.ontrack = (event) => {
          if (event.track.kind === 'video') {
            const videoElement = document.getElementById('remoteVideo');
            videoElement.srcObject = event.streams[0];
          }
        };
        // ... 其他 WebRTC 连接建立和数据接收的代码
        ```
        在这个例子中，当 `ontrack` 事件触发并接收到视频轨道时，`RTCVideoDecoderAdapter` 就在后台默默地进行解码工作，使得视频数据可以被渲染到 `remoteVideo` 元素上。

* **HTML:**
    * **`<video>` 元素:** 解码后的视频最终会显示在 HTML 的 `<video>` 元素中。`RTCVideoDecoderAdapter` 的工作是确保视频数据以正确的格式和时序到达渲染管线，最终被 `<video>` 元素呈现出来。

* **CSS:**
    * **`<video>` 元素的样式:**  CSS 可以用来控制 `<video>` 元素的显示效果，例如大小、边框、布局等。虽然 `RTCVideoDecoderAdapter` 不直接参与 CSS 的处理，但它解码出的视频数据是 CSS 样式化的对象。

**逻辑推理和假设输入输出:**

假设输入是一个编码后的 H.264 视频帧，包含 RTP 时间戳和帧类型信息。

* **假设输入:**
    * `input_image.GetEncodedData()`: 指向编码后视频数据的指针。
    * `input_image.RtpTimestamp()`:  例如 `12345`。
    * `input_image._frameType`:  例如 `webrtc::VideoFrameType::kVideoFrameKey` (关键帧)。
    * `config_.codec()`:  `media::VideoCodec::kH264`。

* **逻辑推理过程:**
    1. `Decode()` 方法被调用，传入 `input_image`。
    2. `ConvertToDecoderBuffer()` 将 `webrtc::EncodedImage` 转换为 `media::DecoderBuffer`，设置时间戳和关键帧标志。
    3. 检查是否需要软件回退 (`NeedSoftwareFallback`)。
    4. 如果不需要回退，将 `media::DecoderBuffer` 提交给 Chromium 的 `media::VideoDecoder` 进行解码。
    5. 解码完成后，`OnOutput()` 方法被调用，接收解码后的 `media::VideoFrame`。
    6. `WebRtcVideoFrameAdapter` 将 `media::VideoFrame` 包装成 `webrtc::VideoFrame`。
    7. `decode_complete_callback_->Decoded()` 将解码后的 `webrtc::VideoFrame` 传递回 WebRTC 层。

* **预期输出:**
    * 通过 `decode_complete_callback_` 传递出一个解码后的 `webrtc::VideoFrame` 对象。
    * 这个 `webrtc::VideoFrame` 包含解码后的像素数据，其 RTP 时间戳与输入一致 (`12345`)。

**用户或编程常见的使用错误:**

1. **未正确初始化解码器:**  如果在 WebRTC 连接建立之前没有正确创建和配置 `RTCVideoDecoderAdapter`，后续的解码操作将会失败。这通常发生在没有调用 `RTCVideoDecoderAdapter::Create()` 或者配置参数不正确的情况下。

2. **提供不支持的视频编解码器:** 如果 WebRTC 连接协商使用了 `RTCVideoDecoderAdapter` 不支持的编解码器（例如，代码中检查了 `WebRtcToMediaVideoCodec` 的返回值），解码过程将无法进行。

3. **在错误的线程调用方法:** `RTCVideoDecoderAdapter` 的某些方法需要在特定的线程上调用（例如，解码操作需要在媒体线程上）。如果在错误的线程调用，可能会导致程序崩溃或出现未定义的行为。代码中使用了 `SEQUENCE_CHECKER` 来进行线程安全检查。

4. **假设硬件解码总是成功:**  开发者可能会假设硬件解码总是可用的，而没有考虑到硬件解码可能失败的情况。`RTCVideoDecoderAdapter` 实现了软件回退机制，但开发者需要在 WebRTC 层正确处理解码错误，以便在需要时进行重试或采取其他措施。

5. **忘记注册解码完成回调:** 如果没有通过 `RegisterDecodeCompleteCallback()` 注册回调函数，解码后的视频帧将无法传递回 WebRTC 层，导致视频无法显示。

6. **在高负载下不处理解码错误:** 在网络状况不佳或设备性能不足的情况下，解码错误可能会频繁发生。开发者需要合理处理这些错误，例如请求关键帧以同步视频流，或者采取降级策略。

**总结:**

`rtc_video_decoder_adapter.cc` 是 Blink 渲染引擎中 WebRTC 视频解码的关键组件，它负责将 WebRTC 的视频流解码成浏览器可以渲染的格式，并处理解码过程中的各种复杂情况，包括硬件加速、软件回退、错误处理和动态重初始化。它通过 C++ 实现，并在幕后支撑着 WebRTC 在 JavaScript、HTML 和 CSS 构建的网页中的视频功能。理解其功能和潜在的错误使用场景对于开发健壮的 WebRTC 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_decoder_adapter.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/peerconnection/rtc_video_decoder_adapter.h"

#include <algorithm>
#include <atomic>
#include <functional>
#include <utility>

#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/memory/raw_ptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/bind_post_task.h"
#include "base/task/sequenced_task_runner.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "base/trace_event/base_tracing.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "media/base/media_log.h"
#include "media/base/media_switches.h"
#include "media/base/media_util.h"
#include "media/base/overlay_info.h"
#include "media/base/platform_features.h"
#include "media/base/supported_types.h"
#include "media/base/video_decoder.h"
#include "media/base/video_types.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_video_decoder_fallback_recorder.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/webrtc/webrtc_video_frame_adapter.h"
#include "third_party/blink/renderer/platform/webrtc/webrtc_video_utils.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/webrtc/api/video/video_frame.h"
#include "third_party/webrtc/api/video_codecs/vp9_profile.h"
#include "third_party/webrtc/modules/video_coding/codecs/h264/include/h264.h"
#include "third_party/webrtc/rtc_base/ref_count.h"
#include "third_party/webrtc/rtc_base/ref_counted_object.h"
#include "ui/gfx/color_space.h"
#include "ui/gfx/geometry/size.h"

namespace WTF {

template <>
struct CrossThreadCopier<media::VideoDecoderConfig>
    : public CrossThreadCopierPassThrough<media::VideoDecoderConfig> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

namespace {

// Any reasonable size, will be overridden by the decoder anyway.
constexpr gfx::Size kDefaultSize(640, 480);

// Maximum number of buffers that we will queue in |pending_buffers_|.
constexpr int32_t kMaxPendingBuffers = 8;

// Maximum number of timestamps that will be maintained in |decode_timestamps_|.
// Really only needs to be a bit larger than the maximum reorder distance (which
// is presumably 0 for WebRTC), but being larger doesn't hurt much.
constexpr int32_t kMaxDecodeHistory = 32;

// Maximum number of consecutive frames that can fail to decode before
// requesting fallback to software decode.
constexpr int32_t kMaxConsecutiveErrors = 5;

void FinishWait(base::WaitableEvent* waiter, bool* result_out, bool result) {
  DVLOG(3) << __func__ << "(" << result << ")";
  *result_out = result;
  waiter->Signal();
}

void OnRequestOverlayInfo(bool decoder_requires_restart_for_overlay,
                          media::ProvideOverlayInfoCB overlay_info_cb) {
  // Android overlays are not supported.
  if (overlay_info_cb)
    std::move(overlay_info_cb).Run(media::OverlayInfo());
}

void RecordInitializationLatency(base::TimeDelta latency) {
  base::UmaHistogramTimes("Media.RTCVideoDecoderInitializationLatencyMs",
                          latency);
}

void RecordReinitializationLatency(base::TimeDelta latency) {
  base::UmaHistogramTimes("Media.RTCVideoDecoderReinitializationLatencyMs",
                          latency);
}

bool HasSoftwareFallback(media::VideoCodec video_codec) {
  if (video_codec == media::VideoCodec::kHEVC) {
    return false;
  }
// TODO(crbug.com/355256378): OpenH264 for encoding and FFmpeg for H264 decoding
// should be detangled such that software decoding can be enabled without
// software encoding.
#if BUILDFLAG(IS_ANDROID) && \
    (!BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) || !BUILDFLAG(ENABLE_OPENH264))
  return video_codec != media::VideoCodec::kH264;
#else
  return true;
#endif
}

struct EncodedImageExternalMemory
    : public media::DecoderBuffer::ExternalMemory {
 public:
  explicit EncodedImageExternalMemory(
      rtc::scoped_refptr<webrtc::EncodedImageBufferInterface> buffer_interface)
      : buffer_interface_(std::move(buffer_interface)) {
    DCHECK(buffer_interface_);
  }

  const base::span<const uint8_t> Span() const override {
    // This cast forces span's implicit constructor to treat the provided type
    // as reference-to-const instead of reference-to-non-const, which is
    // necessary for `std::contiguous_range<>` to be true, since this type
    // exposes both const and non-const `data()` methods and only the former
    // will match the span element type.
    // TODO(bugs.webrtc.org/9378): When the non-const `data()` method is
    // eliminated, this cast can be removed.
    return static_cast<const webrtc::EncodedImageBufferInterface&>(
        *buffer_interface_);
  }

 private:
  rtc::scoped_refptr<webrtc::EncodedImageBufferInterface> buffer_interface_;
};

scoped_refptr<media::DecoderBuffer> ConvertToDecoderBuffer(
    const webrtc::EncodedImage& input_image) {
  TRACE_EVENT0("webrtc", "RTCVideoDecoderAdapter::ConvertToDecoderBuffer");

  DCHECK(input_image.GetEncodedData());
  auto buffer = media::DecoderBuffer::FromExternalMemory(
      std::make_unique<EncodedImageExternalMemory>(
          input_image.GetEncodedData()));
  DCHECK(buffer);
  buffer->set_timestamp(base::Microseconds(input_image.RtpTimestamp()));
  buffer->set_is_key_frame(input_image._frameType ==
                           webrtc::VideoFrameType::kVideoFrameKey);

  const int max_sl_index = input_image.SpatialIndex().value_or(0);
  if (max_sl_index == 0)
    return buffer;

  std::vector<uint32_t> spatial_layer_frame_size;
  spatial_layer_frame_size.reserve(max_sl_index);
  for (int i = 0; i <= max_sl_index; i++) {
    const std::optional<size_t>& frame_size =
        input_image.SpatialLayerFrameSize(i);
    if (!frame_size)
      continue;
    spatial_layer_frame_size.push_back(
        base::checked_cast<uint32_t>(*frame_size));
  }

  if (spatial_layer_frame_size.size() > 1) {
    buffer->WritableSideData().spatial_layers = spatial_layer_frame_size;
  }

  return buffer;
}

std::optional<RTCVideoDecoderFallbackReason> NeedSoftwareFallback(
    const media::VideoCodec codec,
    const media::DecoderBuffer& buffer,
    const media::VideoDecoderType decoder_type) {
  // Fall back to software decoding if there's no support for VP9 spatial
  // layers. See https://crbug.com/webrtc/9304.
  const bool is_spatial_layer_buffer =
      buffer.has_side_data() && !buffer.side_data()->spatial_layers.empty();
  if (codec == media::VideoCodec::kVP9 && is_spatial_layer_buffer &&
      !media::IsVp9kSVCHWDecodingEnabled()) {
    return RTCVideoDecoderFallbackReason::kSpatialLayers;
  }

  if (codec == media::VideoCodec::kAV1 && is_spatial_layer_buffer) {
    // No hardware decoder supports AV1 SVC stream.
    return RTCVideoDecoderFallbackReason::kSpatialLayers;
  }
  return std::nullopt;
}
}  // namespace

// This class is created in the webrtc decoder thread and destroyed on the media
// thread. All the functions except constructor are executed on the media thread
// too.
class RTCVideoDecoderAdapter::Impl {
 public:
  Impl(media::GpuVideoAcceleratorFactories* const gpu_factories,
       WTF::CrossThreadRepeatingFunction<void(Status)> change_status_callback,
       base::WeakPtr<Impl>& weak_this_for_client)
      : gpu_factories_(gpu_factories),
        frame_adapter_shared_resources_(
            base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(
                gpu_factories_)),
        change_status_callback_(std::move(change_status_callback)) {
    // This is called on webrtc decoder sequence.
    DETACH_FROM_SEQUENCE(media_sequence_checker_);
    weak_decoder_this_ = weak_decoder_this_factory_.GetWeakPtr();
    weak_this_for_client = weak_decoder_this_;
  }

  ~Impl() {
    DCHECK_CALLED_ON_VALID_SEQUENCE(media_sequence_checker_);
    // |weak_decoder_this| must be invalidated on the media sequence.
    weak_decoder_this_factory_.InvalidateWeakPtrs();
  }

  void Initialize(const media::VideoDecoderConfig& config,
                  CrossThreadOnceFunction<void(bool)> init_cb,
                  base::TimeTicks start_time,
                  media::VideoDecoderType* decoder_type);
  void Decode(scoped_refptr<media::DecoderBuffer> buffer,
              base::WaitableEvent* waiter,
              std::optional<RTCVideoDecoderAdapter::DecodeResult>* result);
  absl::variant<DecodeResult, RTCVideoDecoderFallbackReason> EnqueueBuffer(
      scoped_refptr<media::DecoderBuffer> buffer);
  void Flush(WTF::CrossThreadOnceClosure flush_success_cb,
             WTF::CrossThreadOnceClosure flush_fail_cb);
  void RegisterDecodeCompleteCallback(webrtc::DecodedImageCallback* callback);

 private:
  std::optional<RTCVideoDecoderFallbackReason> NeedSoftwareFallback(
      media::VideoCodec codec,
      const media::DecoderBuffer& buffer) const;
  void DecodePendingBuffers();
  void OnDecodeDone(media::DecoderStatus status);
  void OnOutput(scoped_refptr<media::VideoFrame> frame);

  const raw_ptr<media::GpuVideoAcceleratorFactories> gpu_factories_;
  const scoped_refptr<WebRtcVideoFrameAdapter::SharedResources>
      frame_adapter_shared_resources_;

  // Set on Initialize().
  std::unique_ptr<media::MediaLog> media_log_;
  std::unique_ptr<media::VideoDecoder> video_decoder_;
  media::VideoCodec video_codec_;

  int32_t outstanding_decode_requests_ = 0;
  std::optional<base::TimeTicks> start_time_;
  raw_ptr<webrtc::DecodedImageCallback> decode_complete_callback_ = nullptr;
  int32_t consecutive_error_count_ = 0;
  // Requests that have not been submitted to the decoder yet.
  WTF::Deque<scoped_refptr<media::DecoderBuffer>> pending_buffers_;
  // Record of timestamps that have been sent to be decoded. Removing a
  // timestamp will cause the frame to be dropped when it is output.
  WTF::Deque<base::TimeDelta> decode_timestamps_;
  bool require_key_frame_ = true;
  WTF::CrossThreadRepeatingFunction<void(Status)> change_status_callback_;

  SEQUENCE_CHECKER(media_sequence_checker_);

  // They are bound to |media_task_runner_|.
  base::WeakPtr<Impl> weak_decoder_this_;
  base::WeakPtrFactory<Impl> weak_decoder_this_factory_{this};
};

void RTCVideoDecoderAdapter::Impl::Initialize(
    const media::VideoDecoderConfig& config,
    CrossThreadOnceFunction<void(bool)> init_cb,
    base::TimeTicks start_time,
    media::VideoDecoderType* decoder_type) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(media_sequence_checker_);

  // On ReinitializeSync() calls, |video_decoder_| may already be set.
  if (!video_decoder_) {
    // TODO(sandersd): Plumb a real log sink here so that we can contribute to
    // the media-internals UI. The current log just discards all messages.
    media_log_ = std::make_unique<media::NullMediaLog>();
    start_time_ = start_time;
    video_decoder_ = gpu_factories_->CreateVideoDecoder(
        media_log_.get(), WTF::BindRepeating(&OnRequestOverlayInfo));

    if (!video_decoder_) {
      std::move(init_cb).Run(false);
      return;
    }
  }

  video_codec_ = config.codec();

  media::VideoDecoder::OutputCB output_cb =
      ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
          &RTCVideoDecoderAdapter::Impl::OnOutput, weak_decoder_this_));
  video_decoder_->Initialize(
      config, /*low_delay=*/true,
      /*cdm_context=*/nullptr,
      base::BindOnce(
          [](base::OnceCallback<void(bool)> cb,
             media::VideoDecoderType* decoder_type,
             media::VideoDecoder* video_decoder, media::DecoderStatus status) {
            *decoder_type = video_decoder->GetDecoderType();
            std::move(cb).Run(status.is_ok());
          },
          ConvertToBaseOnceCallback(std::move(init_cb)),
          CrossThreadUnretained(decoder_type),
          CrossThreadUnretained(video_decoder_.get())),
      output_cb, base::DoNothing());
}

void RTCVideoDecoderAdapter::Impl::Decode(
    scoped_refptr<media::DecoderBuffer> buffer,
    base::WaitableEvent* waiter,
    std::optional<RTCVideoDecoderAdapter::DecodeResult>* result) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(media_sequence_checker_);
  TRACE_EVENT1("webrtc", "RTCVideoDecoderAdapter::Impl::Decode", "buffer",
               buffer->AsHumanReadableString());

  auto enque_result = EnqueueBuffer(std::move(buffer));
  if (const auto* fallback_reason =
          absl::get_if<RTCVideoDecoderFallbackReason>(&enque_result)) {
    RecordRTCVideoDecoderFallbackReason(video_codec_, *fallback_reason);
    if (waiter) {
      *result = std::nullopt;
      waiter->Signal();
    } else {
      change_status_callback_.Run(Status::kError);
    }
    return;
  }

  const auto* decode_result =
      absl::get_if<RTCVideoDecoderAdapter::DecodeResult>(&enque_result);
  switch (*decode_result) {
    case DecodeResult::kOk:
      DecodePendingBuffers();
      break;
    case DecodeResult::kErrorRequestKeyFrame:
      if (!require_key_frame_) {
        require_key_frame_ = true;
        if (!waiter)
          change_status_callback_.Run(Status::kNeedKeyFrame);
      }
      break;
  }
  if (waiter) {
    *result = *decode_result;
    waiter->Signal();
  }
}

absl::variant<RTCVideoDecoderAdapter::DecodeResult,
              RTCVideoDecoderFallbackReason>
RTCVideoDecoderAdapter::Impl::EnqueueBuffer(
    scoped_refptr<media::DecoderBuffer> buffer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(media_sequence_checker_);
  if (require_key_frame_) {
    // We discarded previous frame because we have too many pending buffers (see
    // logic) below. Now we need to wait for the key frame and discard
    // everything else.
    if (!buffer->is_key_frame()) {
      DVLOG(2) << "Discard non-key frame";
      return DecodeResult::kErrorRequestKeyFrame;
    }
    DVLOG(2) << "Key frame received, resume decoding";
    // ok, we got key frame and can continue decoding
    require_key_frame_ = false;
    // We don't need to call change_status_callback_.Run(Status::kOk), because
    // |status_| has been changed to kOk in DecodeInternal().
  }

  if (HasSoftwareFallback(video_codec_) &&
      pending_buffers_.size() >= kMaxPendingBuffers) {
    // We are severely behind. Drop pending buffers and request a keyframe to
    // catch up as quickly as possible.
    DVLOG(2) << "Pending buffers overflow";
    pending_buffers_.clear();
    // Actually we just discarded a frame. We must wait for the key frame and
    // drop any other non-key frame.
    if (++consecutive_error_count_ > kMaxConsecutiveErrors) {
      decode_timestamps_.clear();
      return RTCVideoDecoderFallbackReason::kConsecutivePendingBufferOverflow;
    }
    return DecodeResult::kErrorRequestKeyFrame;
  }

  pending_buffers_.push_back(std::move(buffer));
  return DecodeResult::kOk;
}

void RTCVideoDecoderAdapter::Impl::DecodePendingBuffers() {
  DVLOG(4) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(media_sequence_checker_);

  int max_decode_requests = video_decoder_->GetMaxDecodeRequests();
  while (outstanding_decode_requests_ < max_decode_requests &&
         !pending_buffers_.empty()) {
    // Take the first pending buffer.
    auto buffer = pending_buffers_.front();
    pending_buffers_.pop_front();

    // Record the timestamp.
    while (decode_timestamps_.size() >= kMaxDecodeHistory)
      decode_timestamps_.pop_front();
    decode_timestamps_.push_back(buffer->timestamp());
    // Submit for decoding.
    outstanding_decode_requests_++;
    video_decoder_->Decode(
        std::move(buffer),
        WTF::BindRepeating(&RTCVideoDecoderAdapter::Impl::OnDecodeDone,
                           weak_decoder_this_));
  }
}

void RTCVideoDecoderAdapter::Impl::Flush(
    WTF::CrossThreadOnceClosure flush_success_cb,
    WTF::CrossThreadOnceClosure flush_fail_cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(media_sequence_checker_);

  // Remove any pending tasks.
  pending_buffers_.clear();

  // Send EOS frame for flush.
  video_decoder_->Decode(
      media::DecoderBuffer::CreateEOSBuffer(),
      WTF::BindOnce(
          [](WTF::CrossThreadOnceClosure flush_success,
             WTF::CrossThreadOnceClosure flush_fail,
             media::DecoderStatus status) {
            if (status.is_ok())
              std::move(flush_success).Run();
            else
              std::move(flush_fail).Run();
          },
          std::move(flush_success_cb), std::move(flush_fail_cb)));
}

void RTCVideoDecoderAdapter::Impl::RegisterDecodeCompleteCallback(
    webrtc::DecodedImageCallback* callback) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(media_sequence_checker_);
  // decode_complete_callback_ should be called once with a valid pointer.
  DCHECK_EQ(decode_complete_callback_, nullptr);
  decode_complete_callback_ = callback;
}

void RTCVideoDecoderAdapter::Impl::OnDecodeDone(media::DecoderStatus status) {
  DVLOG(3) << __func__ << "(" << status.group() << ":"
           << static_cast<int>(status.code()) << ")";
  DCHECK_CALLED_ON_VALID_SEQUENCE(media_sequence_checker_);

  outstanding_decode_requests_--;

  if (!status.is_ok() &&
      status.code() != media::DecoderStatus::Codes::kAborted) {
    DVLOG(2) << "Entering permanent error state";
    base::UmaHistogramSparse("Media.RTCVideoDecoderError",
                             static_cast<int>(status.code()));

    change_status_callback_.Run(Status::kError);
    pending_buffers_.clear();
    decode_timestamps_.clear();
    return;
  }

  DecodePendingBuffers();
}

void RTCVideoDecoderAdapter::Impl::OnOutput(
    scoped_refptr<media::VideoFrame> frame) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(media_sequence_checker_);

  const base::TimeDelta timestamp = frame->timestamp();
  webrtc::VideoFrame rtc_frame =
      webrtc::VideoFrame::Builder()
          .set_video_frame_buffer(rtc::scoped_refptr<WebRtcVideoFrameAdapter>(
              new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(
                  std::move(frame), frame_adapter_shared_resources_)))
          .set_rtp_timestamp(static_cast<uint32_t>(timestamp.InMicroseconds()))
          .set_timestamp_us(0)
          .set_rotation(webrtc::kVideoRotation_0)
          .build();

  // Record time to first frame if we haven't yet.
  if (start_time_) {
    // We haven't recorded the first frame time yet, so do so now.
    base::UmaHistogramTimes("Media.RTCVideoDecoderFirstFrameLatencyMs",
                            base::TimeTicks::Now() - *start_time_);
    start_time_.reset();
  }

  if (!base::Contains(decode_timestamps_, timestamp)) {
    DVLOG(2) << "Discarding frame with timestamp " << timestamp;
    return;
  }

  if (!decode_complete_callback_)
    return;

  decode_complete_callback_->Decoded(rtc_frame);
  consecutive_error_count_ = 0;
}

// static
std::atomic_int RTCVideoDecoderAdapter::g_num_decoders_{0};

// static
std::unique_ptr<RTCVideoDecoderAdapter> RTCVideoDecoderAdapter::Create(
    media::GpuVideoAcceleratorFactories* gpu_factories,
    const webrtc::SdpVideoFormat& format,
    std::unique_ptr<ResolutionMonitor> resolution_monitor) {
  DVLOG(1) << __func__ << "(" << format.name << ")";

  const webrtc::VideoCodecType video_codec_type =
      webrtc::PayloadStringToCodecType(format.name);

  // Bail early for unknown codecs.
  if (WebRtcToMediaVideoCodec(video_codec_type) == media::VideoCodec::kUnknown)
    return nullptr;

  media::VideoDecoderConfig config(
      WebRtcToMediaVideoCodec(webrtc::PayloadStringToCodecType(format.name)),
      WebRtcVideoFormatToMediaVideoCodecProfile(format),
      media::VideoDecoderConfig::AlphaMode::kIsOpaque, media::VideoColorSpace(),
      media::kNoTransformation, kDefaultSize, gfx::Rect(kDefaultSize),
      kDefaultSize, media::EmptyExtraData(),
      media::EncryptionScheme::kUnencrypted);

  // HEVC does not have SW fallback, so resolution monitor is not needed.
  if (!resolution_monitor && HasSoftwareFallback(config.codec())) {
    resolution_monitor = ResolutionMonitor::Create(config.codec());
    if (!resolution_monitor) {
      DLOG(ERROR) << "Failed to create ResolutionMonitor for codec: "
                  << media::GetCodecName(config.codec());
      return nullptr;
    }
  }

  std::unique_ptr<RTCVideoDecoderAdapter> rtc_video_decoder_adapter;
  if (gpu_factories->IsDecoderConfigSupported(config) !=
      media::GpuVideoAcceleratorFactories::Supported::kFalse) {
    // Synchronously verify that the decoder can be initialized.
    rtc_video_decoder_adapter = base::WrapUnique(new RTCVideoDecoderAdapter(
        gpu_factories, config, std::move(resolution_monitor)));
    if (rtc_video_decoder_adapter->InitializeSync(config)) {
      return rtc_video_decoder_adapter;
    }
    rtc_video_decoder_adapter.reset();
  }

  // To mirror what RTCVideoDecoderStreamAdapter does a little more closely,
  // record an init failure here.  Otherwise, we only ever record successes.
  base::UmaHistogramBoolean("Media.RTCVideoDecoderInitDecodeSuccess", false);

  return nullptr;
}

RTCVideoDecoderAdapter::RTCVideoDecoderAdapter(
    media::GpuVideoAcceleratorFactories* gpu_factories,
    const media::VideoDecoderConfig& config,
    std::unique_ptr<ResolutionMonitor> resolution_monitor)
    : media_task_runner_(gpu_factories->GetTaskRunner()),
      config_(config),
      resolution_monitor_(std::move(resolution_monitor)) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);
  DVLOG(1) << __func__;
  if (HasSoftwareFallback(config.codec())) {
    CHECK(resolution_monitor_);
    CHECK_EQ(resolution_monitor_->codec(), config_.codec());
  }

  decoder_info_.implementation_name = "ExternalDecoder (Unknown)";
  decoder_info_.is_hardware_accelerated = true;

  weak_this_ = weak_this_factory_.GetWeakPtr();

  auto change_status_callback = CrossThreadBindRepeating(
      base::BindPostTaskToCurrentDefault(base::BindRepeating(
          &RTCVideoDecoderAdapter::ChangeStatus, weak_this_)));
  impl_ = std::make_unique<Impl>(gpu_factories,
                                 std::move(change_status_callback), weak_impl_);
}

RTCVideoDecoderAdapter::~RTCVideoDecoderAdapter() {
  DVLOG(1) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);

  if (have_started_decoding_) {
    g_num_decoders_ -= 1;
    CHECK_GE(g_num_decoders_, 0);
  }

  // |weak_this_factory_| must be invalidated on |decoding_sequence_checker_|.
  weak_this_factory_.InvalidateWeakPtrs();

  Release();
}

bool RTCVideoDecoderAdapter::InitializeSync(
    const media::VideoDecoderConfig& config) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);
  TRACE_EVENT0("webrtc", "RTCVideoDecoderAdapter::InitializeSync");
  DVLOG(3) << __func__;
  // This function is called on a decoder thread.
  DCHECK(!media_task_runner_->RunsTasksInCurrentSequence());
  auto start_time = base::TimeTicks::Now();

  base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;
  bool result = false;
  base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
  auto init_cb =
      CrossThreadBindOnce(&FinishWait, CrossThreadUnretained(&waiter),
                          CrossThreadUnretained(&result));
  if (PostCrossThreadTask(
          *media_task_runner_.get(), FROM_HERE,
          CrossThreadBindOnce(&RTCVideoDecoderAdapter::Impl::Initialize,
                              weak_impl_, config, std::move(init_cb),
                              start_time,
                              CrossThreadUnretained(&decoder_type_)))) {
    // TODO(crbug.com/1076817) Remove if a root cause is found.
    if (!waiter.TimedWait(base::Seconds(10))) {
      RecordInitializationLatency(base::TimeTicks::Now() - start_time);
      return false;
    }

    RecordInitializationLatency(base::TimeTicks::Now() - start_time);
  }

  decoder_info_.implementation_name =
      "ExternalDecoder (" + media::GetDecoderName(decoder_type_) + ")";
  return result;
}

bool RTCVideoDecoderAdapter::Configure(const Settings& settings) {
  DVLOG(1) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);

  if (!impl_)
    return false;

  if (WebRtcToMediaVideoCodec(settings.codec_type()) != config_.codec())
    return false;
  if (HasSoftwareFallback(config_.codec())) {
    CHECK_EQ(resolution_monitor_->codec(),
             WebRtcToMediaVideoCodec(settings.codec_type()));
  }

  const bool init_success = status_ != Status::kError;
  base::UmaHistogramBoolean("Media.RTCVideoDecoderInitDecodeSuccess",
                            init_success);

  if (init_success) {
    UMA_HISTOGRAM_ENUMERATION("Media.RTCVideoDecoderProfile", config_.profile(),
                              media::VIDEO_CODEC_PROFILE_MAX + 1);
  }
  return init_success;
}

int32_t RTCVideoDecoderAdapter::Decode(const webrtc::EncodedImage& input_image,
                                       bool missing_frames,
                                       int64_t render_time_ms) {
  TRACE_EVENT1("webrtc", "RTCVideoDecoderAdapter::Decode", "timestamp",
               base::Microseconds(input_image.RtpTimestamp()));
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);
  if (!impl_)
    return WEBRTC_VIDEO_CODEC_UNINITIALIZED;

  auto result = DecodeInternal(input_image, missing_frames, render_time_ms);
  if (!result) {
    ChangeStatus(Status::kError);
    return WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE;
  }

  return *result == DecodeResult::kOk ? WEBRTC_VIDEO_CODEC_OK
                                      : WEBRTC_VIDEO_CODEC_ERROR;
}

std::optional<RTCVideoDecoderAdapter::DecodeResult>
RTCVideoDecoderAdapter::DecodeInternal(const webrtc::EncodedImage& input_image,
                                       bool missing_frames,
                                       int64_t render_time_ms) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);

  if (status_ == Status::kError)
    return std::nullopt;

  if (missing_frames) {
    DVLOG(2) << "Missing frames";
    // We probably can't handle broken frames. Request a key frame.
    return DecodeResult::kErrorRequestKeyFrame;
  }

  if (status_ == Status::kNeedKeyFrame) {
    if (input_image._frameType != webrtc::VideoFrameType::kVideoFrameKey)
      return DecodeResult::kErrorRequestKeyFrame;

    ChangeStatus(Status::kOk);
  }

  // If color space is specified, transmit it to decoder side by
  // ReinitializeSync, then we can use the right color space to render and
  // overlay instead of gussing for webrtc use case on decoder side.

  // This also includes reinitialization for the HDR use case, i.e.
  // config_.profile() is media::VP9PROFILE_PROFILE2.
  if (ShouldReinitializeForSettingColorSpace(input_image)) {
    config_.set_color_space_info(media::VideoColorSpace::FromGfxColorSpace(
        blink::WebRtcToGfxColorSpace(*input_image.ColorSpace())));
    if (!ReinitializeSync(config_)) {
      RecordRTCVideoDecoderFallbackReason(
          config_.codec(),
          RTCVideoDecoderFallbackReason::kReinitializationFailed);
      return std::nullopt;
    }
    if (input_image._frameType != webrtc::VideoFrameType::kVideoFrameKey)
      return DecodeResult::kErrorRequestKeyFrame;
  }

  auto buffer = ConvertToDecoderBuffer(input_image);
  CHECK(buffer);
  if (HasSoftwareFallback(config_.codec()) &&
      !CheckResolutionAndNumInstances(*buffer)) {
    return std::nullopt;
  }
  if (auto fallback_reason =
          NeedSoftwareFallback(config_.codec(), *buffer, decoder_type_)) {
    RecordRTCVideoDecoderFallbackReason(config_.codec(), *fallback_reason);
    return std::nullopt;
  }

  std::optional<RTCVideoDecoderAdapter::DecodeResult>* null_result = nullptr;
  base::WaitableEvent* null_waiter = nullptr;
  if (!PostCrossThreadTask(
          *media_task_runner_.get(), FROM_HERE,
          CrossThreadBindOnce(&RTCVideoDecoderAdapter::Impl::Decode, weak_impl_,
                              std::move(buffer),
                              CrossThreadUnretained(null_waiter),
                              CrossThreadUnretained(null_result)))) {
    // TODO(b/246460597): Add rtc video decoder fallback reason about
    // PostCrossThreadTask failure.
    return std::nullopt;
  }
  return DecodeResult::kOk;
}

bool RTCVideoDecoderAdapter::CheckResolutionAndNumInstances(
    const media::DecoderBuffer& buffer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);
  DCHECK(HasSoftwareFallback(config_.codec()));

  if (!have_started_decoding_) {
    have_started_decoding_ = true;
    g_num_decoders_ += 1;
  }

  std::optional<gfx::Size> resolution =
      resolution_monitor_->GetResolution(buffer);
  if (!resolution) {
    DVLOG(1) << "Stream parse error";
    RecordRTCVideoDecoderFallbackReason(
        config_.codec(),
        RTCVideoDecoderFallbackReason::kParseErrorOnResolutionCheck);
    return false;
  }

  if (resolution->GetArea() >= kMinResolution.GetArea()) {
    return true;
  }

  // The stream resolution is smaller than |kMinResolution|. We fall back to a
  // software decoder if there are many instances.

  // This code reduces instances too much when two RTCVDAdapters reach
  // here and executes the if-condition when
  // g_num_decoders_ == kMaxDecoderInstances + 1 and then both of them
  // enters the if-statement. But this case must be rare and reducing the
  // decoder instances too much is a minor problem. So I keep this code.
  // To avoid the problem, we need a global lock.
  if (g_num_decoders_ > kMaxDecoderInstances) {
    g_num_decoders_ -= 1;
    CHECK_GE(g_num_decoders_, 0);
    have_started_decoding_ = false;
    DVLOG(1) << "Too many decoder instances";
    RecordRTCVideoDecoderFallbackReason(
        config_.codec(),
        RTCVideoDecoderFallbackReason::kTooManyInstancesAndSmallResolution);
    return false;
  }

  return true;
}

int32_t RTCVideoDecoderAdapter::RegisterDecodeCompleteCallback(
    webrtc::DecodedImageCallback* callback) {
  DVLOG(2) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);

  if (!impl_) {
    if (callback) {
      return WEBRTC_VIDEO_CODEC_UNINITIALIZED;
    }
    return WEBRTC_VIDEO_CODEC_OK;
  }

  if (!PostCrossThreadTask(
          *media_task_runner_.get(), FROM_HERE,
          CrossThreadBindOnce(
              &RTCVideoDecoderAdapter::Impl::RegisterDecodeCompleteCallback,
              weak_impl_, CrossThreadUnretained(callback)))) {
    return WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE;
  }

  if (status_ == Status::kError) {
    RecordRTCVideoDecoderFallbackReason(
        config_.codec(),
        RTCVideoDecoderFallbackReason::kPreviousErrorOnRegisterCallback);
    return WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE;
  }
  return WEBRTC_VIDEO_CODEC_OK;
}

int32_t RTCVideoDecoderAdapter::Release() {
  DVLOG(1) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);
  if (!impl_)
    return WEBRTC_VIDEO_CODEC_OK;

  base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;
  base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
  if (!PostCrossThreadTask(
          *media_task_runner_.get(), FROM_HERE,
          CrossThreadBindOnce(
              [](std::unique_ptr<Impl> impl, base::WaitableEvent* waiter) {
                impl.reset();
                waiter->Signal();
              },
              std::move(impl_), CrossThreadUnretained(&waiter)))) {
    return WEBRTC_VIDEO_CODEC_ERROR;
  }

  waiter.Wait();

  // The object pointed by |weak_impl_| has been invalidated in Impl destructor.
  // Calling reset() is optional, but it's good to invalidate the value of
  // |weak_impl_| too
  weak_impl_.reset();

  return WEBRTC_VIDEO_CODEC_OK;
}

bool RTCVideoDecoderAdapter::ShouldReinitializeForSettingColorSpace(
    const webrtc::EncodedImage& input_image) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);
  if (!input_image.ColorSpace()) {
    return false;
  }

  const gfx::ColorSpace& new_color_space =
      blink::WebRtcToGfxColorSpace(*input_image.ColorSpace());

  if (!new_color_space.IsValid()) {
    return false;
  }

  if (new_color_space != config_.color_space_info().ToGfxColorSpace()) {
    DVLOG(2) << __func__ << ", new_color_space:" << new_color_space.ToString();
    return true;
  }

  return false;
}

bool RTCVideoDecoderAdapter::ReinitializeSync(
    const media::VideoDecoderConfig& config) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);

  base::TimeTicks start_time = base::TimeTicks::Now();
  base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;
  bool result = false;
  base::WaitableEvent waiter(base::WaitableEvent::ResetPolicy::MANUAL,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
  auto init_cb =
      CrossThreadBindOnce(&FinishWait, CrossThreadUnretained(&waiter),
                          CrossThreadUnretained(&result));
  WTF::CrossThreadOnceClosure flush_success_cb = CrossThreadBindOnce(
      &RTCVideoDecoderAdapter::Impl::Initialize, weak_impl_, config,
      std::move(init_cb),
      /*start_time=*/base::TimeTicks(), CrossThreadUnretained(&decoder_type_));
  WTF::CrossThreadOnceClosure flush_fail_cb =
      CrossThreadBindOnce(&FinishWait, CrossThreadUnretained(&waiter),
                          CrossThreadUnretained(&result), false);
  if (PostCrossThreadTask(
          *media_task_runner_.get(), FROM_HERE,
          CrossThreadBindOnce(&RTCVideoDecoderAdapter::Impl::Flush, weak_impl_,
                              std::move(flush_success_cb),
                              std::move(flush_fail_cb)))) {
    waiter.Wait();
    RecordReinitializationLatency(base::TimeTicks::Now() - start_time);
  }
  return result;
}

void RTCVideoDecoderAdapter::ChangeStatus(Status new_status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(decoding_sequence_checker_);
  // It is impossible to recover once status becomes kError.
  if (status_ != Status::kError)
    status_ = new_status;
}

int RTCVideoDecoderAdapter::GetCurrentDecoderCountForTesting() {
  return g_num_decoders_;
}

void RTCVideoDecoderAdapter::IncrementCurrentDecoderCountForTesting() {
  g_num_decoders_++;
}

void RTCVideoDecoderAdapter::DecrementCurrentDecoderCountForTesting() {
  g_num_decoders_--;
}

}  // namespace blink

"""

```