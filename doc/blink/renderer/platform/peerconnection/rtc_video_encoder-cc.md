Response:
The user wants a summary of the functionality of the C++ source code file `rtc_video_encoder.cc`. The summary should cover:

1. **Core Functionality:** What the code does.
2. **Relationship to Web Technologies:** How it relates to JavaScript, HTML, and CSS.
3. **Logic and Reasoning:**  Examples of input and output if logical deductions are made.
4. **Common User/Programming Errors:** Examples of mistakes related to its use.
5. **Overall Function Summary:** A concise summary of its purpose.

Let's break down the provided code snippet to understand its core functions and relationships.

**Code Analysis - Part 1:**

* **Includes:** The file includes various headers from Chromium, WebRTC, and standard libraries. These headers indicate that the file deals with video encoding, peer-to-peer communication, memory management, threading, and possibly GPU acceleration.
* **Namespaces:** The code is within the `blink` namespace.
* **Helper Classes/Functions:**  Several small helper classes and functions are defined:
    * `ToSVCScalabilityMode`: Converts spatial layer configuration to an enum.
    * `SignaledValue`/`ScopedSignaledValue`:  Manage synchronization using waitable events.
    * `RefCountedWritableSharedMemoryMapping`: Manages shared memory for efficient data transfer.
    * `EncodedDataWrapper`: Wraps shared memory for use with WebRTC's encoded image interface.
    * `FrameChunk`:  Represents a video frame to be encoded.
    * `ConvertKbpsToBps`: Converts kilobits per second to bits per second.
    * `GetDropFrameThreshold`: Determines the threshold for dropping frames.
    * `AllocateBitrateForVEAConfig`: Allocates bitrate for the video encoder accelerator.
    * `SetLayerConfigForTemporalScalability`: Configures spatial layers for temporal scalability.
    * `IsValidTemporalSVC`: Checks if a temporal scalability mode is valid.
    * Several anonymous functions for converting between WebRTC and media library types.
    * UMA (User Metrics Analysis) recording functions.
    * Functions to check feature flags and determine if software encoding should be used.
* **Feature Flags:** The code defines and uses several feature flags, likely for enabling/disabling experimental or conditional features.
* **RTCVideoEncoder::Impl Class (Partial):** This appears to be the core class handling the video encoding logic. It inherits from `media::VideoEncodeAccelerator::Client`, suggesting it interacts with a hardware or software video encoder. The beginning of its methods like `Impl`, `CreateAndInitializeVEA`, `NotifyEncoderInfoChange`, and `Enqueue` are present.

**Plan for Generating the Summary:**

1. **Core Functionality:** Focus on the `RTCVideoEncoder::Impl` class and its interaction with `media::VideoEncodeAccelerator`. Emphasize the encoding process, handling of video frames, and communication with WebRTC.
2. **Web Technology Relationship:** Explain that this C++ code is part of the Blink rendering engine, which powers the web browser. It provides the underlying mechanism for WebRTC's video encoding, which is exposed to JavaScript through APIs like `RTCPeerConnection`. The encoded video data is ultimately used in HTML `<video>` elements or for streaming.
3. **Logic and Reasoning:**  Use the `Enqueue` method as an example. If the input is a `FrameChunk` with specific dimensions and timestamp, the output would be a call to the underlying encoder to process that frame. Consider the logic around frame dropping and buffer management.
4. **Common Errors:**  Think about scenarios where the configuration of the encoder is incorrect, leading to initialization failures. Consider issues with providing incompatible video frame formats or exceeding buffer sizes.
5. **Function Summary:** Concisely state that this file implements the video encoding functionality for WebRTC within the Blink engine, leveraging hardware or software encoders and managing the communication between WebRTC and the encoding pipeline.
```
功能列表:
1. **视频编码**: 该文件是 Chromium Blink 引擎中负责视频编码的核心组件，用于将原始视频帧压缩成适合网络传输的格式。它与 WebRTC (Web Real-Time Communication) 技术紧密相关，为浏览器中的实时音视频通信提供编码能力。
2. **与硬件加速器交互**: 代码中大量使用了 `media::VideoEncodeAccelerator` 接口，表明它支持利用 GPU 等硬件加速器进行视频编码，以提高性能和降低 CPU 占用。
3. **软件编码回退**: 虽然主要目标是使用硬件加速，但代码中也包含了在硬件加速不可用或不适用的情况下回退到软件编码的逻辑（通过 `execute_software_fallback_` ）。
4. **帧管理**:  代码负责接收来自 WebRTC 的视频帧 (`webrtc::VideoFrame`)，并将其传递给底层的视频编码器。它管理着待编码帧的队列 (`pending_frames_`) 和已提交编码但尚未完成的帧 (`submitted_frames_`).
5. **编码参数控制**:  该文件处理来自 WebRTC 的编码参数设置，例如目标码率、帧率等，并将这些参数传递给 `VideoEncodeAccelerator` 进行配置。
6. **共享内存管理**:  为了高效地在不同进程/线程之间传递视频数据，代码使用了共享内存 (`base::UnsafeSharedMemoryRegion`, `base::WritableSharedMemoryMapping`)。
7. **编码完成回调**:  当视频帧编码完成后，该文件负责接收编码后的数据，并将其通过 WebRTC 的回调机制 (`webrtc::EncodedImageCallback`) 返回给上层。
8. **错误处理**:  代码中包含了错误处理逻辑，可以捕获编码过程中出现的错误，并通过 WebRTC 的机制通知上层。
9. **统计和监控**:  使用了 UMA (User Metrics Analysis) 宏 (`UMA_HISTOGRAM_*`) 来收集视频编码相关的性能指标，用于监控和优化编码器的行为。
10. **支持不同的视频编解码器**: 代码结构表明它支持多种视频编解码器，例如 H.264、VP8、VP9、AV1 等。
11. **支持可伸缩视频编码 (SVC)**: 代码中涉及到对 SVC 的处理，例如 `webrtc::ScalableVideoController`，这允许视频流具有不同的质量层级，以适应不同的网络条件。
12. **零拷贝优化**: 代码中涉及对零拷贝的支持 (`IsZeroCopyEnabled`)，旨在减少视频数据在内存中的复制，提高编码效率。
13. **帧丢弃策略**:  代码中实现了帧丢弃的逻辑，以避免编码器缓冲区积压，从而控制延迟 (`kVideoEncoderLimitsFramesInEncoder`).

与 javascript, html, css 的功能关系举例说明:

* **javascript**:
    * **关系**:  JavaScript 代码通过 WebRTC API (例如 `RTCPeerConnection`) 使用浏览器的视频编码功能。`rtc_video_encoder.cc` 中实现的逻辑是这些 API 的底层实现，负责实际的视频压缩。
    * **举例**:  当 JavaScript 调用 `RTCPeerConnection.addTrack()` 添加一个视频轨道时，Blink 引擎会使用 `rtc_video_encoder.cc` 来编码从摄像头或屏幕捕获的视频帧。JavaScript 代码可以通过 `RTCRtpSender.getParameters()` 和 `RTCRtpSender.setParameters()` 来控制编码参数，这些参数最终会传递到 `rtc_video_encoder.cc` 进行处理。
* **html**:
    * **关系**:  HTML 的 `<video>` 元素用于显示解码后的视频流。`rtc_video_encoder.cc` 的作用是生成用于传输的编码后视频数据，这些数据最终会被接收端的浏览器解码并在 `<video>` 元素中渲染。
    * **举例**:  一个在线视频会议应用，用户的摄像头画面经过 `rtc_video_encoder.cc` 编码后，通过网络发送给其他参与者。接收端的浏览器解码这些数据，并在 HTML 页面中的 `<video>` 标签中显示对方的视频。
* **css**:
    * **关系**: CSS 主要用于控制 HTML 元素的样式和布局。虽然 CSS 不直接参与视频编码过程，但它可以影响包含 `<video>` 元素的页面的整体呈现效果，间接地与视频体验相关。
    * **举例**:  CSS 可以用来设置 `<video>` 元素的大小、边框、对齐方式等，从而影响用户观看视频的效果。

逻辑推理举例说明:

**假设输入:**

1. **编码请求:**  收到一个需要编码的 `FrameChunk`，包含一个 640x480 的视频帧，时间戳为 T1，并且 `force_keyframe` 为 true。
2. **编码器状态:** 当前硬件编码器可用，且空闲。
3. **编码参数:** 目标码率为 1Mbps，帧率为 30fps。

**逻辑推理:**

* 代码会检查当前编码器状态是否良好 (`status_ == WEBRTC_VIDEO_CODEC_OK`).
* 由于 `force_keyframe` 为 true，代码会指示底层的 `VideoEncodeAccelerator` 强制编码一个关键帧。
* 代码会将视频帧数据复制到分配好的共享内存缓冲区中，并调用 `VideoEncodeAccelerator::Encode()` 方法，将缓冲区信息和编码参数传递给硬件编码器。
*  `submitted_frames_` 队列会记录该帧的相关信息，以便后续匹配编码完成的回调。

**输出:**

* 底层的 `VideoEncodeAccelerator` 会开始对该帧进行编码，并生成包含关键帧的压缩数据。
* 最终会调用 `BitstreamBufferReady` 回调，携带编码后的数据和元数据。

用户或编程常见的使用错误举例说明:

1. **未正确初始化编码器:**  如果在调用编码方法前，没有正确地调用 `CreateAndInitializeVEA` 进行初始化，会导致编码失败。
    * **错误示例:**  直接调用 `Enqueue` 尝试编码帧，但之前没有调用过 `InitEncode` 相关的 WebRTC 方法，导致底层的 VEA 未被创建和初始化。
2. **提供不支持的视频帧格式:**  如果传递给编码器的视频帧格式与编码器支持的格式不匹配，会导致编码失败或性能下降。
    * **错误示例:** 硬件编码器可能只支持 NV12 格式，但用户提供的却是 I420 格式的视频帧。
3. **输出缓冲区不足:**  如果编码后的数据量超过了分配的输出缓冲区大小，会导致数据丢失或程序崩溃。
    * **错误示例:**  设置了过低的输出缓冲区大小，导致高分辨率或复杂场景的视频帧编码后无法完全放入缓冲区。
4. **在错误的线程调用方法:**  `RTCVideoEncoder::Impl` 中的某些方法需要在特定的线程上调用（例如，与 `VideoEncodeAccelerator` 交互的方法需要在 GPU 线程上）。在错误的线程调用会导致未定义的行为。
    * **错误示例:**  在 WebRTC 的工作线程中直接访问 `RTCVideoEncoder::Impl` 中需要 GPU 线程操作的成员变量或方法。
5. **不处理编码错误回调:**  如果编码过程中发生错误，`NotifyErrorStatus` 会被调用。如果上层代码没有正确处理这些错误，可能导致视频通信异常但用户无法感知问题。
    * **错误示例:**  `EncodedImageCallback` 中的错误信息被忽略，导致应用程序在编码失败的情况下仍然认为视频流正常。

功能归纳:

`blink/renderer/platform/peerconnection/rtc_video_encoder.cc` 文件的主要功能是作为 Chromium Blink 引擎中 WebRTC 视频编码的实现核心，负责将原始视频帧高效地压缩成适合网络传输的格式。它通过与硬件加速器交互、管理编码参数和缓冲区、处理编码完成事件以及错误处理等机制，为浏览器中的实时音视频通信提供了关键的编码能力。同时，它也具备软件编码回退机制，以确保在各种环境下都能提供视频编码服务。
```
### 提示词
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_encoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/peerconnection/rtc_video_encoder.h"

#include <memory>
#include <numeric>
#include <vector>

#include "base/command_line.h"
#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/functional/callback_helpers.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/unsafe_shared_memory_region.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/numerics/safe_conversions.h"
#include "base/strings/strcat.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/bind_post_task.h"
#include "base/task/sequenced_task_runner.h"
#include "base/thread_annotations.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "components/viz/common/resources/shared_image_format_utils.h"
#include "media/base/bitrate.h"
#include "media/base/bitstream_buffer.h"
#include "media/base/media_switches.h"
#include "media/base/media_util.h"
#include "media/base/platform_features.h"
#include "media/base/supported_types.h"
#include "media/base/svc_scalability_mode.h"
#include "media/base/video_bitrate_allocation.h"
#include "media/base/video_frame.h"
#include "media/base/video_util.h"
#include "media/capture/capture_switches.h"
#include "media/media_buildflags.h"
#include "media/mojo/clients/mojo_video_encoder_metrics_provider.h"
#include "media/parsers/h264_parser.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "media/video/video_encode_accelerator.h"
#include "media/webrtc/webrtc_features.h"
#include "third_party/blink/public/common/buildflags.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/allow_discouraged_type.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/webrtc/convert_to_webrtc_video_frame_buffer.h"
#include "third_party/blink/renderer/platform/webrtc/webrtc_video_frame_adapter.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_gfx.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/thread_safe_ref_counted.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/libyuv/include/libyuv.h"
#include "third_party/webrtc/modules/video_coding/codecs/h264/include/h264.h"
#include "third_party/webrtc/modules/video_coding/include/video_error_codes.h"
#include "third_party/webrtc/modules/video_coding/svc/create_scalability_structure.h"
#include "third_party/webrtc/modules/video_coding/svc/simulcast_to_svc_converter.h"
#include "third_party/webrtc/rtc_base/time_utils.h"
#include "ui/gfx/buffer_format_util.h"

namespace {

media::SVCScalabilityMode ToSVCScalabilityMode(
    const std::vector<media::VideoEncodeAccelerator::Config::SpatialLayer>&
        spatial_layers,
    media::SVCInterLayerPredMode inter_layer_pred) {
  if (spatial_layers.empty()) {
    return media::SVCScalabilityMode::kL1T1;
  }
  return GetSVCScalabilityMode(spatial_layers.size(),
                               spatial_layers[0].num_of_temporal_layers,
                               inter_layer_pred);
}

class SignaledValue {
 public:
  SignaledValue() : event(nullptr), val(nullptr) {}
  SignaledValue(base::WaitableEvent* event, int32_t* val)
      : event(event), val(val) {
    DCHECK(event);
  }

  ~SignaledValue() {
    if (IsValid() && !event->IsSignaled()) {
      NOTREACHED() << "never signaled";
    }
  }

  // Move-only.
  SignaledValue(const SignaledValue&) = delete;
  SignaledValue& operator=(const SignaledValue&) = delete;
  SignaledValue(SignaledValue&& other) : event(other.event), val(other.val) {
    other.event = nullptr;
    other.val = nullptr;
  }
  SignaledValue& operator=(SignaledValue&& other) {
    event = other.event;
    val = other.val;
    other.event = nullptr;
    other.val = nullptr;
    return *this;
  }

  void Signal() {
    if (!IsValid())
      return;
    event->Signal();
    event = nullptr;
  }

  void Set(int32_t v) {
    if (!val)
      return;
    *val = v;
  }

  bool IsValid() { return event; }

 private:
  raw_ptr<base::WaitableEvent> event;
  raw_ptr<int32_t> val;
};

class ScopedSignaledValue {
 public:
  ScopedSignaledValue() = default;
  ScopedSignaledValue(base::WaitableEvent* event, int32_t* val)
      : sv(event, val) {}
  explicit ScopedSignaledValue(SignaledValue sv) : sv(std::move(sv)) {}

  ~ScopedSignaledValue() { sv.Signal(); }

  ScopedSignaledValue(const ScopedSignaledValue&) = delete;
  ScopedSignaledValue& operator=(const ScopedSignaledValue&) = delete;
  ScopedSignaledValue(ScopedSignaledValue&& other) : sv(std::move(other.sv)) {
    DCHECK(!other.sv.IsValid());
  }
  ScopedSignaledValue& operator=(ScopedSignaledValue&& other) {
    sv.Signal();
    sv = std::move(other.sv);
    DCHECK(!other.sv.IsValid());
    return *this;
  }

  // Set |v|, signal |sv|, and invalidate |sv|. If |sv| is already invalidated
  // at the call, this has no effect.
  void SetAndReset(int32_t v) {
    sv.Set(v);
    reset();
  }

  // Invalidate |sv|. The invalidated value will be set by move assignment
  // operator.
  void reset() { *this = ScopedSignaledValue(); }

 private:
  SignaledValue sv;
};

// TODO(https://crbug.com/1448809): Move to base/memory/ref_counted_memory.h
class RefCountedWritableSharedMemoryMapping
    : public ThreadSafeRefCounted<RefCountedWritableSharedMemoryMapping> {
 public:
  explicit RefCountedWritableSharedMemoryMapping(
      base::WritableSharedMemoryMapping mapping)
      : mapping_(std::move(mapping)) {}

  RefCountedWritableSharedMemoryMapping(
      const RefCountedWritableSharedMemoryMapping&) = delete;
  RefCountedWritableSharedMemoryMapping& operator=(
      const RefCountedWritableSharedMemoryMapping&) = delete;

  const unsigned char* front() const {
    return static_cast<const unsigned char*>(mapping_.memory());
  }
  unsigned char* front() {
    return static_cast<unsigned char*>(mapping_.memory());
  }
  size_t size() const { return mapping_.size(); }

 private:
  friend class ThreadSafeRefCounted<RefCountedWritableSharedMemoryMapping>;
  ~RefCountedWritableSharedMemoryMapping() = default;

  base::WritableSharedMemoryMapping mapping_;
};

class EncodedDataWrapper : public webrtc::EncodedImageBufferInterface {
 public:
  EncodedDataWrapper(
      const scoped_refptr<RefCountedWritableSharedMemoryMapping>&& mapping,
      size_t size,
      base::OnceClosure reuse_buffer_callback)
      : mapping_(std::move(mapping)),
        size_(size),
        reuse_buffer_callback_(std::move(reuse_buffer_callback)) {}
  ~EncodedDataWrapper() override {
    DCHECK(reuse_buffer_callback_);
    std::move(reuse_buffer_callback_).Run();
  }
  const uint8_t* data() const override { return mapping_->front(); }
  uint8_t* data() override { return mapping_->front(); }
  size_t size() const override { return size_; }

 private:
  const scoped_refptr<RefCountedWritableSharedMemoryMapping> mapping_;
  const size_t size_;
  base::OnceClosure reuse_buffer_callback_;
};

struct FrameChunk {
  FrameChunk(const webrtc::VideoFrame& input_image, bool force_keyframe)
      : video_frame_buffer(input_image.video_frame_buffer()),
        timestamp(input_image.rtp_timestamp()),
        timestamp_us(input_image.timestamp_us()),
        render_time_ms(input_image.render_time_ms()),
        force_keyframe(force_keyframe) {
    DCHECK(video_frame_buffer);
  }

  const rtc::scoped_refptr<webrtc::VideoFrameBuffer> video_frame_buffer;
  // TODO(b/241349739): timestamp and timestamp_us should be unified as one
  // base::TimeDelta.
  const uint32_t timestamp;
  const uint64_t timestamp_us;
  const int64_t render_time_ms;

  const bool force_keyframe;
};

bool ConvertKbpsToBps(uint32_t bitrate_kbps, uint32_t* bitrate_bps) {
  if (!base::IsValueInRangeForNumericType<uint32_t>(bitrate_kbps *
                                                    UINT64_C(1000))) {
    return false;
  }
  *bitrate_bps = bitrate_kbps * 1000;
  return true;
}

uint8_t GetDropFrameThreshold(const webrtc::VideoCodec& codec_settings) {
  // This drop frame threshold is same as WebRTC.
  // https://source.chromium.org/chromium/chromium/src/+/main:third_party/webrtc/modules/video_coding/codecs/vp9/libvpx_vp9_encoder.cc
  if (codec_settings.GetFrameDropEnabled() &&
      base::FeatureList::IsEnabled(
          media::kWebRTCHardwareVideoEncoderFrameDrop)) {
    return 30;
  }
  return 0;
}

webrtc::VideoBitrateAllocation AllocateBitrateForVEAConfig(
    const media::VideoEncodeAccelerator::Config& config) {
  // The same bitrate factors as the software encoder.
  // https://source.chromium.org/chromium/chromium/src/+/main:media/video/vpx_video_encoder.cc;l=131;drc=d383d0b3e4f76789a6de2a221c61d3531f4c59da
  constexpr double kTemporalLayersBitrateScaleFactors[][3] = {
      {1.00, 0.00, 0.00},  // For one temporal layer.
      {0.60, 0.40, 0.00},  // For two temporal layers.
      {0.50, 0.20, 0.30},  // For three temporal layers.
  };
  DCHECK_EQ(config.bitrate.mode(), media::Bitrate::Mode::kConstant);
  webrtc::VideoBitrateAllocation bitrate_allocation;
  bitrate_allocation.SetBitrate(0, 0, config.bitrate.target_bps());

  for (size_t sid = 0; sid < config.spatial_layers.size(); ++sid) {
    const auto& sl = config.spatial_layers[sid];
    CHECK_EQ(sl.num_of_temporal_layers <= 3, true);
    for (size_t tid = 0; tid < sl.num_of_temporal_layers; ++tid) {
      const double factor =
          kTemporalLayersBitrateScaleFactors[sl.num_of_temporal_layers - 1]
                                            [tid];
      bitrate_allocation.SetBitrate(sid, tid, sl.bitrate_bps * factor);
    }
  }
  return bitrate_allocation;
}

// Configures the spatial layer settings to be passed to encoder.
// If some config of |codec_settings| is not supported, returns false.
bool SetLayerConfigForTemporalScalability(
    const webrtc::VideoCodec& codec_settings,
    std::vector<media::VideoEncodeAccelerator::Config::SpatialLayer>&
        spatial_layers,
    int num_temporal_layers) {
  spatial_layers.resize(1u);
  auto& sl = spatial_layers[0];
  sl.width = codec_settings.width;
  sl.height = codec_settings.height;
  if (!ConvertKbpsToBps(codec_settings.startBitrate, &sl.bitrate_bps)) {
    return false;
  }
  sl.framerate = codec_settings.maxFramerate;
  sl.max_qp = base::saturated_cast<uint8_t>(codec_settings.qpMax);
  sl.num_of_temporal_layers =
      base::saturated_cast<uint8_t>(num_temporal_layers);

  return true;
}

bool IsValidTemporalSVC(
    const std::optional<webrtc::ScalabilityMode>& scalability_mode,
    int& num_temporal_layers) {
  if (!scalability_mode.has_value()) {
    // Assume L1T1 if no scalability mode is set.
    num_temporal_layers = 1;
    return true;
  }

  switch (*scalability_mode) {
    case webrtc::ScalabilityMode::kL1T1:
      num_temporal_layers = 1;
      break;
    case webrtc::ScalabilityMode::kL1T2:
      num_temporal_layers = 2;
      break;
    case webrtc::ScalabilityMode::kL1T3:
      num_temporal_layers = 3;
      break;
    default:
      return false;
  }
  return (num_temporal_layers <= 3);
}

}  // namespace

namespace WTF {

template <>
struct CrossThreadCopier<webrtc::VideoEncoder::RateControlParameters>
    : public CrossThreadCopierPassThrough<
          webrtc::VideoEncoder::RateControlParameters> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<
    std::vector<media::VideoEncodeAccelerator::Config::SpatialLayer>>
    : public CrossThreadCopierPassThrough<
          std::vector<media::VideoEncodeAccelerator::Config::SpatialLayer>> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<FrameChunk>
    : public CrossThreadCopierPassThrough<FrameChunk> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<media::VideoEncodeAccelerator::Config>
    : public CrossThreadCopierPassThrough<
          media::VideoEncodeAccelerator::Config> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<SignaledValue> {
  static SignaledValue Copy(SignaledValue sv) {
    return sv;  // this is a move in fact.
  }
};
}  // namespace WTF

namespace blink {

namespace features {

// Enabled-by-default, except for Android where SW encoder for H264 and AV1 are
// not available. The existence of this flag remains only for testing purposes.
BASE_FEATURE(kForceSoftwareForLowResolutions,
             "ForceSoftwareForLowResolutions",
#if !BUILDFLAG(IS_ANDROID)
             base::FEATURE_ENABLED_BY_DEFAULT);
#else
             base::FEATURE_DISABLED_BY_DEFAULT);
#endif

// Avoids large latencies to build up by dropping frames when the number of
// frames that are sent to a hardware video encoder reaches a certain limit.
// See b/298660336 for details.
BASE_FEATURE(kVideoEncoderLimitsFramesInEncoder,
             "VideoEncoderLimitsFramesInEncoder",
             base::FEATURE_ENABLED_BY_DEFAULT);

// When enabled, the encoder instance is preserved on Release() call.
// Reinitialization of the encoder will reuse the instance with the new
// resolution. See b/1466102 for details.
BASE_FEATURE(kKeepEncoderInstanceOnRelease,
             "KeepEncoderInstanceOnRelease",
             base::FEATURE_ENABLED_BY_DEFAULT);

// When enabled, the supports_simulcast will be always reported to webrtc
// and incoming simulcast codec config will be rewritten as an SVC config.
BASE_FEATURE(kRtcVideoEncoderConvertSimulcastToSvc,
             "RtcVideoEncoderConvertSimulcastToSvc",
             base::FEATURE_ENABLED_BY_DEFAULT);
}  // namespace features

namespace {
media::SVCInterLayerPredMode CopyFromWebRtcInterLayerPredMode(
    const webrtc::InterLayerPredMode inter_layer_pred) {
  switch (inter_layer_pred) {
    case webrtc::InterLayerPredMode::kOff:
      return media::SVCInterLayerPredMode::kOff;
    case webrtc::InterLayerPredMode::kOn:
      return media::SVCInterLayerPredMode::kOn;
    case webrtc::InterLayerPredMode::kOnKeyPic:
      return media::SVCInterLayerPredMode::kOnKeyPic;
  }
}

// Create VEA::Config::SpatialLayer from |codec_settings|. If some config of
// |codec_settings| is not supported, returns false.
bool CreateSpatialLayersConfig(
    const webrtc::VideoCodec& codec_settings,
    std::vector<media::VideoEncodeAccelerator::Config::SpatialLayer>*
        spatial_layers,
    media::SVCInterLayerPredMode* inter_layer_pred,
    gfx::Size* highest_active_resolution) {
  std::optional<webrtc::ScalabilityMode> scalability_mode =
      codec_settings.GetScalabilityMode();
  *highest_active_resolution =
      gfx::Size(codec_settings.width, codec_settings.height);

  if (codec_settings.codecType == webrtc::kVideoCodecVP9 &&
      codec_settings.VP9().numberOfSpatialLayers > 1 &&
      !media::IsVp9kSVCHWEncodingEnabled()) {
    DVLOG(1)
        << "VP9 SVC not yet supported by HW codecs, falling back to software.";
    return false;
  }

  // We fill SpatialLayer only in temporal layer or spatial layer encoding.
  switch (codec_settings.codecType) {
    case webrtc::kVideoCodecH264:
      if (scalability_mode.has_value() &&
          *scalability_mode != webrtc::ScalabilityMode::kL1T1) {
        DVLOG(1)
            << "H264 temporal layers not yet supported by HW codecs, but use"
            << " HW codecs and leave the fallback decision to a webrtc client"
            << " by seeing metadata in webrtc::CodecSpecificInfo";

        return true;
      }
      break;
    case webrtc::kVideoCodecVP8: {
      int number_of_temporal_layers = 1;
      if (!IsValidTemporalSVC(scalability_mode, number_of_temporal_layers)) {
        return false;
      }
      if (number_of_temporal_layers > 1) {
        if (codec_settings.mode == webrtc::VideoCodecMode::kScreensharing) {
          // This is a VP8 stream with screensharing using temporal layers for
          // temporal scalability. Since this implementation does not yet
          // implement temporal layers, fall back to software codec, if cfm and
          // board is known to have a CPU that can handle it.
          if (base::FeatureList::IsEnabled(
                  features::kWebRtcScreenshareSwEncoding)) {
            // TODO(sprang): Add support for temporal layers so we don't need
            // fallback. See eg http://crbug.com/702017
            DVLOG(1) << "Falling back to software encoder.";
            return false;
          }
        }
        // Though there is no SVC in VP8 spec. We allocate 1 element in
        // spatial_layers for temporal layer encoding.
        return SetLayerConfigForTemporalScalability(
            codec_settings, *spatial_layers, number_of_temporal_layers);
      }
      break;
    }
    case webrtc::kVideoCodecVP9:
      // Since one TL and one SL can be regarded as one simple stream,
      // SpatialLayer is not filled.
      if (codec_settings.VP9().numberOfTemporalLayers > 1 ||
          codec_settings.VP9().numberOfSpatialLayers > 1) {
        std::optional<gfx::Size> top_res;
        spatial_layers->clear();
        for (size_t i = 0; i < codec_settings.VP9().numberOfSpatialLayers;
             ++i) {
          const webrtc::SpatialLayer& rtc_sl = codec_settings.spatialLayers[i];
          // We ignore non active spatial layer and don't proceed further. There
          // must NOT be an active higher spatial layer than non active spatial
          // layer.
          if (!rtc_sl.active)
            break;
          spatial_layers->emplace_back();
          auto& sl = spatial_layers->back();
          sl.width = base::checked_cast<int32_t>(rtc_sl.width);
          sl.height = base::checked_cast<int32_t>(rtc_sl.height);
          if (!ConvertKbpsToBps(rtc_sl.targetBitrate, &sl.bitrate_bps))
            return false;
          sl.framerate = base::saturated_cast<int32_t>(rtc_sl.maxFramerate);
          sl.max_qp = base::saturated_cast<uint8_t>(rtc_sl.qpMax);
          sl.num_of_temporal_layers =
              base::saturated_cast<uint8_t>(rtc_sl.numberOfTemporalLayers);

          if (!top_res.has_value()) {
            top_res = gfx::Size(rtc_sl.width, rtc_sl.height);
          } else if (top_res->width() < rtc_sl.width) {
            DCHECK_GE(rtc_sl.height, top_res->width());
            top_res = gfx::Size(rtc_sl.width, rtc_sl.height);
          }
        }

        if (top_res.has_value()) {
          *highest_active_resolution = *top_res;
        }

        if (spatial_layers->size() == 1 &&
            spatial_layers->at(0).num_of_temporal_layers == 1) {
          // Don't report spatial layers if only the base layer is active and we
          // have no temporar layers configured.
          spatial_layers->clear();
        } else {
          *inter_layer_pred = CopyFromWebRtcInterLayerPredMode(
              codec_settings.VP9().interLayerPred);
        }
      }
      break;
    case webrtc::kVideoCodecAV1: {
      int number_of_temporal_layers = 1;
      if (!IsValidTemporalSVC(scalability_mode, number_of_temporal_layers)) {
        return false;
      }
      return SetLayerConfigForTemporalScalability(
          codec_settings, *spatial_layers, number_of_temporal_layers);
    }
#if BUILDFLAG(RTC_USE_H265)
    case webrtc::kVideoCodecH265: {
      int number_of_temporal_layers = 1;
      if (!IsValidTemporalSVC(scalability_mode, number_of_temporal_layers) ||
          (number_of_temporal_layers == 2 &&
           !base::FeatureList::IsEnabled(::features::kWebRtcH265L1T2)) ||
          (number_of_temporal_layers == 3 &&
           !base::FeatureList::IsEnabled(::features::kWebRtcH265L1T3))) {
        return false;
      }
      return SetLayerConfigForTemporalScalability(
          codec_settings, *spatial_layers, number_of_temporal_layers);
    }
#endif  // BUILDFLAG(RTC_USE_H265)
    default:
      break;
  }
  return true;
}

struct ActiveSpatialLayers {
  // `spatial_index` considered active if
  // `begin_index <= spatial_index < end_index`
  size_t begin_index = 0;
  size_t end_index = 0;
  size_t size() const { return end_index - begin_index; }
};

struct FrameInfo {
 public:
  FrameInfo(const base::TimeDelta& media_timestamp,
            int32_t rtp_timestamp,
            int64_t capture_time_ms,
            const ActiveSpatialLayers& active_spatial_layers)
      : media_timestamp_(media_timestamp),
        rtp_timestamp_(rtp_timestamp),
        capture_time_ms_(capture_time_ms),
        active_spatial_layers_(active_spatial_layers) {}

  const base::TimeDelta media_timestamp_;
  const int32_t rtp_timestamp_;
  const int64_t capture_time_ms_;
  const ActiveSpatialLayers active_spatial_layers_;
  size_t produced_frames_ = 0;
};

webrtc::VideoCodecType ProfileToWebRtcVideoCodecType(
    media::VideoCodecProfile profile) {
  switch (media::VideoCodecProfileToVideoCodec(profile)) {
    case media::VideoCodec::kH264:
      return webrtc::kVideoCodecH264;
    case media::VideoCodec::kVP8:
      return webrtc::kVideoCodecVP8;
    case media::VideoCodec::kVP9:
      return webrtc::kVideoCodecVP9;
    case media::VideoCodec::kAV1:
      return webrtc::kVideoCodecAV1;
#if BUILDFLAG(RTC_USE_H265)
    case media::VideoCodec::kHEVC:
      return webrtc::kVideoCodecH265;
#endif
    default:
      NOTREACHED() << "Invalid profile " << GetProfileName(profile);
  }
}

void RecordInitEncodeUMA(int32_t init_retval,
                         media::VideoCodecProfile profile) {
  base::UmaHistogramBoolean("Media.RTCVideoEncoderInitEncodeSuccess",
                            init_retval == WEBRTC_VIDEO_CODEC_OK);
  if (init_retval != WEBRTC_VIDEO_CODEC_OK)
    return;
  UMA_HISTOGRAM_ENUMERATION("Media.RTCVideoEncoderProfile", profile,
                            media::VIDEO_CODEC_PROFILE_MAX + 1);
}

void RecordEncoderStatusUMA(const media::EncoderStatus& status,
                            webrtc::VideoCodecType type) {
  std::string histogram_name = "Media.RTCVideoEncoderStatus.";
  switch (type) {
    case webrtc::VideoCodecType::kVideoCodecH264:
      histogram_name += "H264";
      break;
    case webrtc::VideoCodecType::kVideoCodecVP8:
      histogram_name += "VP8";
      break;
    case webrtc::VideoCodecType::kVideoCodecVP9:
      histogram_name += "VP9";
      break;
    case webrtc::VideoCodecType::kVideoCodecAV1:
      histogram_name += "AV1";
      break;
#if BUILDFLAG(RTC_USE_H265)
    case webrtc::VideoCodecType::kVideoCodecH265:
      histogram_name += "H265";
      break;
#endif  // BUILDFLAG(RTC_USE_H265)
    default:
      histogram_name += "Other";
      break;
  }
  base::UmaHistogramEnumeration(histogram_name, status.code());
}

bool IsZeroCopyEnabled(webrtc::VideoContentType content_type) {
  if (content_type == webrtc::VideoContentType::SCREENSHARE) {
    // Zero copy screen capture.
#if BUILDFLAG(IS_CHROMEOS_ASH)
    // The zero-copy capture is available for all sources in ChromeOS
    // Ash-chrome.
    return base::FeatureList::IsEnabled(blink::features::kZeroCopyTabCapture);
#else
    // Currently, zero copy capture screenshare is available only for tabs.
    // Since it is impossible to determine the content source, tab, window or
    // monitor, we don't configure VideoEncodeAccelerator with NV12
    // GpuMemoryBuffer instead we configure I420 SHMEM as if it is not zero
    // copy, and we convert the NV12 GpuMemoryBuffer to I420 SHMEM in
    // RtcVideoEncoder::Impl::Encode().
    // TODO(b/267995715): Solve this problem by calling Initialize() in the
    // first frame.
    return false;
#endif
  }
  // Zero copy video capture from other sources (e.g. camera).
  return !base::CommandLine::ForCurrentProcess()->HasSwitch(
             switches::kDisableVideoCaptureUseGpuMemoryBuffer) &&
         base::CommandLine::ForCurrentProcess()->HasSwitch(
             switches::kVideoCaptureUseGpuMemoryBuffer);
}

bool UseSoftwareForLowResolution(const webrtc::VideoCodecType codec,
                                 uint16_t width,
                                 uint16_t height) {
  // Several HW encoders are known to yield worse quality compared to SW
  // encoders for smaller resolutions such as 180p. At 360p, manual testing
  // suggests HW and SW are roughly on par in terms of quality.
  // go/vp9-hardware-encoder-visual-evaluation

  // By default, Android is excluded from this logic because there are
  // situations where a codec like H264 is available in HW but not SW in which
  // case SW fallback would result in a change of codec, see
  // https://crbug.com/1469318.
  if (!base::FeatureList::IsEnabled(
          features::kForceSoftwareForLowResolutions)) {
    return false;
  }

  // H.265 does not support SW fallback, so it is excluded from low resoloution
  // fallback.
  if (codec == webrtc::kVideoCodecH265) {
    return false;
  }

  // AV1 hardware has better performance vs quality at 270p compared to other
  // codecs. So sets the threshold to 270p in AV1. See b/351090228#comment13 and
  // b/351090228#comment24 for detail.
  const uint16_t force_sw_height = codec == webrtc::kVideoCodecAV1 ? 270 : 360;

  if (height < force_sw_height) {
    LOG(WARNING) << "Fallback to SW due to low resolution being less than "
                 << force_sw_height << "p (" << width << "x" << height << ")";
    return true;
  }

  return false;
}
}  // namespace

namespace features {
// Fallback from hardware encoder (if available) to software, for WebRTC
// screensharing that uses temporal scalability.
BASE_FEATURE(kWebRtcScreenshareSwEncoding,
             "WebRtcScreenshareSwEncoding",
             base::FEATURE_DISABLED_BY_DEFAULT);
}  // namespace features

// This private class of RTCVideoEncoder does the actual work of communicating
// with a media::VideoEncodeAccelerator for handling video encoding. It can
// be created on any thread, but should subsequently be executed on
// |gpu_task_runner| including destructor.
//
// This class separates state related to the thread that RTCVideoEncoder
// operates on from the thread that |gpu_factories_| provides for accelerator
// operations (presently the media thread).
class RTCVideoEncoder::Impl : public media::VideoEncodeAccelerator::Client {
 public:
  using UpdateEncoderInfoCallback = base::RepeatingCallback<void(
      media::VideoEncoderInfo,
      std::vector<webrtc::VideoFrameBuffer::Type>)>;
  Impl(media::GpuVideoAcceleratorFactories* gpu_factories,
       scoped_refptr<media::MojoVideoEncoderMetricsProviderFactory>
           encoder_metrics_provider_factory,
       webrtc::VideoCodecType video_codec_type,
       std::optional<webrtc::ScalabilityMode> scalability_mode,
       webrtc::VideoContentType video_content_type,
       UpdateEncoderInfoCallback update_encoder_info_callback,
       base::RepeatingClosure execute_software_fallback,
       base::WeakPtr<Impl>& weak_this_for_client);

  ~Impl() override;
  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  // Create the VEA and call Initialize() on it.  Called once per instantiation,
  // and then the instance is bound forevermore to whichever thread made the
  // call.
  // RTCVideoEncoder expects to be able to call this function synchronously from
  // its own thread, hence the |init_event| argument.
  void CreateAndInitializeVEA(
      const media::VideoEncodeAccelerator::Config& vea_config,
      SignaledValue init_event);

  // Enqueue a frame from WebRTC for encoding. This function is called
  // asynchronously from webrtc encoder thread. When the error is caused, it is
  // reported by NotifyErrorStatus().
  void Enqueue(FrameChunk frame_chunk);

  // Request encoding parameter change for the underlying encoder with
  // additional size change. Requires the encoder to be in flushed state.
  void RequestEncodingParametersChangeWithSizeChange(
      const webrtc::VideoEncoder::RateControlParameters& parameters,
      const gfx::Size& input_visible_size,
      const media::VideoCodecProfile& profile,
      const media::SVCInterLayerPredMode& inter_layer_pred,
      const std::vector<media::VideoEncodeAccelerator::Config::SpatialLayer>&
          spatial_layers,
      SignaledValue event);

  // Request encoding parameter change for the underlying encoder.
  void RequestEncodingParametersChange(
      const webrtc::VideoEncoder::RateControlParameters& parameters);

  void RegisterEncodeCompleteCallback(webrtc::EncodedImageCallback* callback);

  webrtc::VideoCodecType video_codec_type() const { return video_codec_type_; }

  // media::VideoEncodeAccelerator::Client implementation.
  void RequireBitstreamBuffers(unsigned int input_count,
                               const gfx::Size& input_coded_size,
                               size_t output_buffer_size) override;
  void BitstreamBufferReady(
      int32_t bitstream_buffer_id,
      const media::BitstreamBufferMetadata& metadata) override;
  void NotifyErrorStatus(const media::EncoderStatus& status) override;
  void NotifyEncoderInfoChange(const media::VideoEncoderInfo& info) override;

#if BUILDFLAG(RTC_USE_H265)
  void SetH265ParameterSetsTrackerForTesting(
      std::unique_ptr<H265ParameterSetsTracker> tracker);
#endif
  void Suspend(SignaledValue event);

  void Drain(SignaledValue event);
  void DrainCompleted(bool success);

  void SetSimulcastToSvcConverter(std::optional<webrtc::SimulcastToSvcConverter>
                                      simulcast_to_svc_converter);

 private:
  // proxy to pass weak reference to webrtc which could be invalidated when
  // frame size changes and new output buffers are allocated.
  class EncodedBufferReferenceHolder {
   public:
    explicit EncodedBufferReferenceHolder(base::WeakPtr<Impl> impl)
        : impl_(impl) {
      weak_this_ = weak_this_factory_.GetWeakPtr();
    }
    ~EncodedBufferReferenceHolder() = default;
    base::WeakPtr<EncodedBufferReferenceHolder> GetWeakPtr() {
      return weak_this_;
    }
    void BitstreamBufferAvailable(int bitstream_buffer_id) {
      if (Impl* impl = impl_.get()) {
        impl->BitstreamBufferAvailable(bitstream_buffer_id);
      }
    }

   private:
    base::WeakPtr<Impl> impl_;
    base::WeakPtr<EncodedBufferReferenceHolder> weak_this_;
    base::WeakPtrFactory<EncodedBufferReferenceHolder> weak_this_factory_{this};
  };

  void RequestEncodingParametersChangeInternal(
      const webrtc::VideoEncoder::RateControlParameters& parameters,
      const std::optional<gfx::Size>& input_visible_size);

  enum {
    kInputBufferExtraCount = 1,  // The number of input buffers allocated, more
                                 // than what is requested by
                                 // VEA::RequireBitstreamBuffers().
    kOutputBufferCount = 3,
    kMaxFramesInEncoder = 15,  // Max number of frames the encoder is allowed
                               // to hold before dropping input frames.
                               // Avoids large delay buildups.
                               // See b/298660336 for details.
  };

  // Perform encoding on an input frame from the input queue.
  void EncodeOneFrame(FrameChunk frame_chunk);

  // Perform encoding on an input frame from the input queue using VEA native
  // input mode.  The input frame must be backed with GpuMemoryBuffer buffers.
  void EncodeOneFrameWithNativeInput(FrameChunk frame_chunk);

  // Creates a MappableSI frame filled with black pixels. Returns true if
  // the frame is successfully created; false otherwise.
  bool CreateBlackMappableSIFrame(const gfx::Size& natural_size);

  // Notify that an input frame is finished for encoding. |index| is the index
  // of the completed frame in |input_buffers_|.
  void InputBufferReleased(int index);

  // Checks if the frame size is different than hardware accelerator
  // requirements.
  bool RequiresSizeChange(const media::VideoFrame& frame) const;

  // Return an encoded output buffer to WebRTC.
  void ReturnEncodedImage(const webrtc::EncodedImage& image,
                          const webrtc::CodecSpecificInfo& info,
                          int32_t bitstream_buffer_id);

  // Gets ActiveSpatialLayers that are currently active,
  // meaning the are configured, have active=true and have non-zero bandwidth
  // allocated to them.
  // Returns an empty list if a layer encoding is not used.
  ActiveSpatialLayers GetActiveSpatialLayers() const;

  // Call VideoEncodeAccelerator::UseOutputBitstreamBuffer() for a buffer whose
  // id is |bitstream_buffer_id|.
  void UseOutputBitstreamBuffer(int32_t bitstream_buffer_id);

  // RTCVideoEncoder is given a buffer to be passed to WebRTC through the
  // RTCVideoEncoder::ReturnEncodedImage() function.  When that is complete,
  // the buffer is returned to Impl by its index using this function.
  void BitstreamBufferAvailable(int32_t bitstream_buffer_id);

  // Fill `webrtc::CodecSpecificInfo.generic_frame_info` to provide more
  // accurate description of used layering.
  void FillGenericFrameInfo(webrtc::CodecSpecificInfo& info,
                            const media::BitstreamBufferMetadata& metadata);

  // This is attached to |gpu_task_runner_|, not the thread class is constructed
  // on.
  SEQUENCE_CHECKER(sequence_checker_);

  // Factory for creating VEAs, shared memory buffers, etc.
  const raw_ptr<media::GpuVideoAcceleratorFactories> gpu_factories_;

  scoped_refptr<media::MojoVideoEncoderMetricsProviderFactory>
      encoder_metrics_provider_factory_;
  std::unique_ptr<media::VideoEncoderMetricsProvider> encoder_metrics_provider_;

  // webrtc::VideoEncoder expects InitEncode() to be synchronous. Do this by
  // waiting on the |async_init_event_| when initialization completes.
  ScopedSignaledValue async_init_event_;

  // The underlying VEA to perform encoding on.
  std::unique_ptr<media::VideoEncodeAccelerator> video_encoder_;

  // Metadata for frames passed to Encode(), matched to encoded frames using
  // timestamps.
  WTF::Deque<FrameInfo> submitted_frames_;

  // Indicates that timestamp match failed and we should no longer attempt
  // matching.
  bool failed_timestamp_match_{false};

  // The pending frames to be encoded with the boolean representing whether the
  // frame must be encoded keyframe.
  WTF::Deque<FrameChunk> pending_frames_;

  // Frame sizes.
  gfx::Size input_frame_coded_size_;
  gfx::Size input_visible_size_;

  // Shared memory buffers for input/output with the VEA.
  Vector<std::unique_ptr<base::MappedReadOnlyRegion>> input_buffers_;

  Vector<std::pair<base::UnsafeSharedMemoryRegion,
                   scoped_refptr<RefCountedWritableSharedMemoryMapping>>>
      output_buffers_;

  // The number of input buffers requested by hardware video encoder.
  size_t input_buffers_requested_count_{0};

  // The number of frames that are sent to a hardware video encoder by Encode()
  // and the encoder holds them.
  size_t frames_in_encoder_count_{0};

  // Input buffers ready to be filled with input from Encode().  As a LIFO since
  // we don't care about ordering.
  Vector<int> input_buffers_free_;

  // The number of output buffers that have been sent to a hardware video
  // encoder by VideoEncodeAccelerator::UseOutputBitstreamBuffer() and the
  // encoder holds them.
  size_t output_buffers_in_encoder_count_{0};

  // proxy to pass weak reference to webrtc which could be invalidated when
  // frame size changes and new output buffers are allocated.
  std::unique_ptr<EncodedBufferReferenceHolder>
      encoded_buffer_reference_holder_;

  // The buffer ids that are not sent to a hardware video encoder and this holds
  // them. UseOutputBitstreamBuffer() is called for them on the next Encode().
  Vector<int32_t> pending_output_buffers_;

  // Whether to send the frames to VEA as native buffer. Native buffer allows
  // VEA to pass the buffer to the encoder directly without further processing.
  bool use_native_input_{false};

  // A black frame used when the video track is disabled.
  scoped_refptr<media::VideoFrame> black_frame_;

  // The video codec type, as reported to WebRTC.
  const webrtc::VideoCodecType video_codec_type_;

  // The scalability mode, as reported to WebRTC.
  const std::optional<webrtc::ScalabilityMode> scalability_mode_;

  // Generate the dependency template and generic frame info according to
  // https://w3c.github.io/webrtc-svc/#scalabilitymodes*
  std::unique_ptr<webrtc::ScalableVideoController> svc_controller_;
  // Maintain the temporal layer idx for each frame in the encode buffer.
  Vector<uint32_t> encode_buffers_tid_;

  // The content type, as reported to WebRTC (screenshare vs realtime video).
  const webrtc::VideoContentType video_content_type_;

  // This has the same information as |encoder_info_.preferred_pixel_formats|
  // but can be used on |sequence_checker_| without acquiring the lock.
  absl::InlinedVector<webrtc::VideoFrameBuffer::Type,
                      webrtc::kMaxPreferredPixelFormats>
      preferred_pixel_formats_;

  UpdateEncoderInfoCallback update_encoder_info_callback_;

  // Calling this causes a software encoder fallback.
  base::RepeatingClosure execute_software_fallback_;

  // The spatial layer resolutions configured in VEA::Initialize(). This is set
  // only in CreateAndInitializeVEA().
  WTF::Vector<gfx::Size> init_spatial_layer_resolutions_;

  // The current active spatial layer range. This is set in
  // CreateAndInitializeVEA() and updated in RequestEncodingParametersChange().
  ActiveSpatialLayers active_spatial_layers_;

#if BUILDFLAG(RTC_USE_H265)
  // Parameter sets(VPS/SPS/PPS) tracker used for H.265, to ensure parameter
  // sets are always included in IRAP pictures.
  std::unique_ptr<H265ParameterSetsTracker> ps_tracker_;
#endif  // BUILDFLAG(RTC_USE_H265)

  // We cannot immediately return error conditions to the WebRTC user of this
  // class, as there is no error callback in the webrtc::VideoEncoder interface.
  // Instead, we cache an error status here and return it the next time an
  // interface entry point is called.
  int32_t status_ GUARDED_BY_CONTEXT(sequence_checker_){
      WEBRTC_VIDEO_CODEC_UNINITIALIZED};

  // Protect |encoded_image_callback_|. |encoded_image_callback_| is read on
  // media thread and written in webrtc encoder thread.
  mutable base::Lock lock_;

  // webrtc::VideoEncoder encode complete callback.
  // TODO(b/257021675): Don't guard this by |lock_|
  raw_ptr<webrtc::EncodedImageCallback> encoded_image_callback_
      GUARDED_BY(lock_){nullptr};

  // Used to rewrite the encoded image metadata to look like simulcast
  // instead of SVC. Set only when simulcat config is emulated by SVC one.
  std::optional<webrtc::SimulcastToSvcConverter> simulcast_to_svc_converter_;

  // They are bound to |gpu_task_runner_|, which is sequence checked by
  // |sequence_checker|.
  base::WeakPtr<Impl> weak_this_;
  base::WeakPtrFactory<Impl> weak_this_factory_{this};
};

RTCVideoEncoder::Impl::Impl(
    media::GpuVideoAcceleratorFactories* gpu_factories,
    scoped_refptr<media::MojoVideoEncoderMetricsProviderFactory>
        encoder_metrics_provider_factory,
    webrtc::VideoCodecType video_codec_type,
    std::optional<webrtc::ScalabilityMode> scalability_mode,
    webrtc::VideoContentType video_content_type,
    UpdateEncoderInfoCallback update_encoder_info_callback,
    base::RepeatingClosure execute_software_fallback,
    base::WeakPtr<Impl>& weak_this_for_client)
    : gpu_factories_(gpu_factories),
      encoder_metrics_provider_factory_(
          std::move(encoder_metrics_provider_factory)),
      video_codec_type_(video_codec_type),
      scalability_mode_(scalability_mode),
      video_content_type_(video_content_type),
      update_encoder_info_callback_(std::move(update_encoder_info_callback)),
      execute_software_fallback_(std::move(execute_software_fallback)) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
  CHECK(encoder_metrics_provider_factory_);
  preferred_pixel_formats_ = {webrtc::VideoFrameBuffer::Type::kI420};
  weak_this_ = weak_this_factory_.GetWeakPtr();
  encoded_buffer_reference_holder_ =
      std::make_unique<EncodedBufferReferenceHolder>(weak_this_);
  weak_this_for_client = weak_this_;
  if (scalability_mode_.has_value() &&
      (
#if BUILDFLAG(RTC_USE_H265)
          video_codec_type == webrtc::kVideoCodecH265 ||
#endif
          video_codec_type == webrtc::kVideoCodecAV1)) {
    svc_controller_ =
        webrtc::CreateScalabilityStructure(scalability_mode.value());
    if (!svc_controller_) {
      LOG(ERROR) << "Failed to set scalability mode "
                 << static_cast<int>(*scalability_mode_);
    }
  }
}

void RTCVideoEncoder::Impl::CreateAndInitializeVEA(
    const media::VideoEncodeAccelerator::Config& vea_config,
    SignaledValue init_event) {
  TRACE_EVENT0("webrtc", "RTCVideoEncoder::Impl::CreateAndInitializeVEA");
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  status_ = WEBRTC_VIDEO_CODEC_UNINITIALIZED;
  async_init_event_ = ScopedSignaledValue(std::move(init_event));

  video_encoder_ = gpu_factories_->CreateVideoEncodeAccelerator();
  if (!video_encoder_) {
    NotifyErrorStatus({media::EncoderStatus::Codes::kEncoderInitializationError,
                       "Failed to create VideoEncodeAccelerato"});
    return;
  }

  input_visible_size_ = vea_config.input_visible_size;
  // The valid config is NV12+kGpuMemoryBuffer and I420+kShmem.
  CHECK_EQ(
      vea_config.input_format == media::PIXEL_FORMAT_NV12,
      vea_config.storage_type ==
          media::VideoEncodeAccelerator::Config::StorageType::kGpuMemoryBuffer);
  if (vea_config.storage_type ==
      media::VideoEncodeAccelerator::Config::StorageType::kGpuMemoryBuffer) {
    use_native_input_ = true;
    preferred_pixel_formats_ = {webrtc::VideoFrameBuffer::Type::kNV12};
  }

  encoder_metrics_provider_ =
      encoder_metrics_provider_factory_->CreateVideoEncoderMetricsProvider();
  encoder_metrics_provider_->Initialize(
      vea_config.output_profile, vea_config.input_visible_size,
      /*is_hardware_encoder=*/true,
      ToSVCScalabilityMode(vea_config.spatial_layers,
                           vea_config.inter_layer_pred));
  if (!video_encoder_->Initialize(vea_config, this,
                                  std::make_unique<media::NullMediaLog>())) {
    NotifyErrorStatus({media::EncoderStatus::Codes::kEncoderInitializationError,
                       "Failed to initialize VideoEncodeAccelerator"});
    return;
  }

  init_spatial_layer_resolutions_.clear();
  for (const auto& layer : vea_config.spatial_layers) {
    init_spatial_layer_resolutions_.emplace_back(layer.width, layer.height);
  }

  active_spatial_layers_.begin_index = 0;
  active_spatial_layers_.end_index = vea_config.spatial_layers.size();

#if BUILDFLAG(RTC_USE_H265)
  if (video_codec_type_ == webrtc::kVideoCodecH265 && !ps_tracker_) {
    ps_tracker_ = std::make_unique<H265ParameterSetsTracker>();
  }
#endif  // BUILDFLAG(RTC_USE_H265)

  // RequireBitstreamBuffers or NotifyError will be called and the waiter will
  // be signaled.
}

void RTCVideoEncoder::Impl::NotifyEncoderInfoChange(
    const media::VideoEncoderInfo& info) {
  update_encoder_info_callback_.Run(
      info,
      std::vector<webrtc::VideoFrameBuffer::Type>(
          preferred_pixel_formats_.begin(), preferred_pixel_formats_.end()));
}

void RTCVideoEncoder::Impl::Enqueue(FrameChunk frame_chunk) {
  TRACE_EVENT1("webrtc", "RTCVideoEncoder::Impl::Enqueue", "timestamp",
               frame_chunk.timestamp_us);
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (status_ != WEBRTC_VIDEO_CODEC_OK) {
    // When |status_| is already not OK, the error has been notified.
    return;
  }

  // Avoid large latencies to build up by dropping frames when the number of
  // frames that are sent to a hardware video encoder reaches a certain limit.
  // `frames_in_encoder_count_` is reduced by `BitstreamBufferReady` when
  // the first spatial layer of a frame has been encoded.
  // Killswitch: blink::features::VideoEncoderLimitsFramesInEncoder.
  if (base::FeatureList::IsEnabled(
          features::kVideoEncoderLimitsFramesInEncoder) &&
      frames_in_encoder_count_ >= kMaxFramesInEncoder) {
    DVLOG(1) << "VAE drops the input frame to reduce latency";
    base::AutoLock lock(lock_);
    if (encoded_image_callback_) {
      encoded_image_callback_->OnDroppedFrame(
          webrtc::EncodedImageCallback::DropReason::kDroppedByEncoder);
    }
    return;
  }

// On Windows it is possible that RtcVideoEncoder is configured to only accept
// native inputs, but the incoming frame is not backed by GpuMemoryBuffer and
// is not a black frame.
#if BUILDFLAG(IS_WIN)
  {
    // Check if the incoming frame is backed by unowned memory. This could
    // happen when: 1. Zero-copy capture feature is turned on but device does
    // not support MediaFoundation; 2. The video track gets disabled so black
    // frames are sent.
    scoped_refptr<media::VideoFrame> frame;
    rtc::scoped_refptr<webrtc::VideoFrameBuffer> frame_buffer =
        frame_chunk.video_frame_buffer;
    // For black frames their handling will depend on the current
    // |use_native_input_| state. As a result we don't toggle
    // |use_native_input_| flag here for them.
    if (frame_buffer->type() == webrtc::VideoFrameBuffer::Type::kNative) {
      frame = static_cast<WebRtcVideoFrameAdapter*>(frame_buffer.get())
                  ->getMediaVideoFrame();
      if (frame->storage_type() == media::VideoFrame::STORAGE_UNOWNED_MEMORY) {
        if (use_native_input_) {
          use_native_input_ = false;
          // VEA previously worked with imported frames. Now they need input
          // buffers when handling non-imported frames.
          if (input_buffers_.empty()) {
            input_buffers_free_.resize(input_buffers_requested_count_);
            input_buffers_.resize(input_buffers_requested_count_);
            for (wtf_size_t i = 0; i < input_buffers_requested_count_; i++) {
              input_buffers_free_[i] = i;
              input_buffers_[i] = nullptr;
            }
          }
        }
      } else if (frame->storage_type() ==
                 media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER) {
        if (!use_native_input_) {
          use_native_input_ = true;
          // VEA previously worked with input buffers. Now they need imported
          // frames, so get rid of those buffers.
          input_buffers_free_.clear();
          input_buffers_.clear();
        }
      }
    }
  }
#endif

  if (use_native_input_) {
    DCHECK(pending_frames_.empty());
    EncodeOneFrameWithNativeInput(std::move(frame_chunk));
    return;
  }

  pending_frames_.push_back(std::move(frame_chunk));
  // When |input_buffers_free_| is empty, EncodeOneFrame() for the frame in
  // |pending_frames_| will be invoked from InputBufferReleased().
  while (!pending_frames_.empty() && !input_buffers_free_.empty()) {
    auto chunk = std::move(pending_frames_.front());
    pending_frames_.pop_front();
    EncodeOneFrame(std::move(chunk));
  }
}

void RTCVideoEncoder::Impl::BitstreamBufferAvailable(
    int32_t bitstream_buffer_id) {
  TRACE_EVENT0("webrtc", "RTCVideoEncoder::Impl::BitstreamBufferAvailable");
  DVLOG(3) << __func__ << " bitstream_buffer_id=" << bitstream_buffer_id;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  // If there is no frame in a hardware video encoder,
  // UseOutputBitstreamBuffer() call for this buffer id is postponed in the next
  // Encode() call. This avoids unnecessary thread wake up in GPU process.
  if (frames_in_encoder_count_ == 0) {
    pending_output_buffers_.push_back(bitstream_buffer_id);
    return;
  }

  UseOutputBitstreamBuffer(bitstream_buffer_id);
}

void RTCVideoEncoder::Impl::Suspend(SignaledValue event) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (status_ == WEBRTC_VIDEO_CODEC_OK) {
    status_ = WEBRTC_VIDEO_CODEC_UNINITIALIZED;
  }
  event.Set(status_);
  event.Signal();
}

void RTCVideoEncoder::Impl::Drain(SignaledValue event) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (status_ == WEBRTC_VIDEO_CODEC_OK ||
      status_ == WEBRTC_VIDEO_CODEC_UNINITIALIZED) {
    async_init_event_ = ScopedSignaledValue(std::move(event));
    video_encoder_->Flush(base::BindOnce(&RTCVideoEncoder::Impl::DrainCompleted,
                                         base::Unretained(this)));
  } else {
    event.Set(status_);
    event.Signal();
  }
}

void RTCVideoEncoder::Impl::DrainCompleted(bool success) {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (success) {
    status_ = WEBRTC_VIDEO_CODEC_UNINITIALIZED;
    async_init_event_.SetAndReset(WEBRTC_VIDEO_CODEC_UNINITIALIZED);
  } else {
    NotifyErrorStatus({media::EncoderStatus::Codes::kEncoderInitializationError,
                       "Failed to flush VideoEncodeAccelerator"});
  }
}

void RTCVideoEncoder::Impl::SetSimulcastToSvcConverter(
    std::optional<webrtc::SimulcastToSvcConverter> simulcast_to_svc_converter) {
  simulcast_to_svc_converter_ = std::move(simulcast_to_svc_converter);
}

void RTCVideoEncoder::Impl::UseOutputBitstreamBuffer(
    int32_t bitstream_buffer_id) {
  TRACE_EVENT0("webrtc", "RTCVideoEncoder::Impl::UseOutputBitstreamBuffer");
  DVLOG(3) << __func__ << " bitstream_buffer_id=" << bitstream_buffer_id;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (video_encoder_) {
    video_encoder_->UseOutputBitstreamBuffer(media::BitstreamBuffer(
        bitstream_buffer_id,
        output_buffers_[bitstream_buffer_id].first.Duplicate(),
        output_buffers_[bitstream_buffer_id].first.GetSize()));
    output_buffers_in_encoder_count_++;
  }
}

void RTCVideoEncoder::Impl::RequestEncodingParametersChange(
    const webrtc::VideoEncoder::RateControlParameters& parameters) {
  DVLOG(3) << __func__ << " bitrate=" << parameters.bitrate.ToString()
           << ", framerate=" << parameters.framerate_fps;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (status_ != WEBRTC_VIDEO_CODEC_OK)
    return;

  if (svc_controller_) {
    svc_controller_->OnRatesUpdated(parameters.bitrate);
  }

  RequestEncodingParametersChangeInternal(parameters, std::nullopt);
}

void RTCVideoEncoder::Impl::RequestEncodingParametersChangeInternal(
    const webrtc::VideoEncoder::RateControlParameters& parameters,
    const std::optional<gfx::Size>& input_visible_size) {
  // NotfiyError() has been called. Don't proceed the change request.
  if (!video_encoder_)
    return;

  uint32_t framerate =
      std::max(1u, static_cast<uint32_t>(parameters.framerate_fps + 0.5));
  // This is a workaround to zero being temporarily provided, as part of the
  // initial setup, by WebRTC.
  media::VideoBitrateAllocation allocation;
  if (parameters.bitrate.get_sum_bps() == 0u) {
    allocation.SetBitrate(0, 0, 1u);
  } else {
    active_spatial_layers_.begin_index = 0;
    active_spatial_layers_.end_index = 0;
    for (size_t spatial_id = 0;
         spatial_id < media::VideoBitrateAllocation::kMaxSpatialLayers;
         ++spatial_id) {
      for (size_t temporal_id = 0;
           temporal_id < media::VideoBitrateAllocation::kMaxTemporalLayers;
           ++temporal_id) {
        // TODO(sprang): Clean this up if/when webrtc struct moves to int.
        uint32_t temporal_layer_bitrate = base::checked_cast<int>(
            parameters.bitrate.GetBitrate(spatial_id, temporal_id));
        if (!allocation.SetBitrate(spatial_id, temporal_id,
                                   temporal_layer_bitrate)) {
          LOG(WARNING) << "Overflow in bitrate allocation: "
                       << parameters.bitrate.ToString();
          break;
        }
        if (temporal_layer_bitrate > 0) {
          if (active_spatial_layers_.end_index == 0) {
            active_spatial_layers_.begin_index = spatial_id;
          }
          active_spatial_layers_.end_index = spatial_id + 1;
        }
      }
    }
    DCHECK_EQ(allocation.GetSumBps(), parameters.bitrate.get_sum_bps());
  }
  video_encoder_->RequestEncodingParametersChange(allocation, framerate,
                                                  input_visible_size);
}

void RTCVideoEncoder::Impl::RequestEncodingParametersChangeWithSizeChange(
    const webrtc::VideoEncoder::RateControlParameters& parameters,
    const gfx::Size& input_visible_size,
    const media::VideoCodecProfile& profile,
    const media::SVCInterLayerPredMode& inter_layer_pred,
    const std::vector<media::VideoEncodeAccelerator::Config::SpatialLayer>&
        spatial_layers,
    SignaledValue event) {
  DVLOG(3) << __func__ << " bitrate=" << parameters.bitrate.ToString()
           << ", framerate=" << parameters.framerate_fps
           << ", resolution=" << input_visible_size.ToString();
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  DCHECK_EQ(status_, WEBRTC_VIDEO_CODEC_UNINITIALIZED);

  async_init_event_ = ScopedSignaledValue(std::move(event));
  if (input_visible_size == input_visible_size_) {
    // If the input visible size is the same, we expect all the resolution of
    // spatial layers should be the same.
    CHECK_EQ(init_spatial_layer_resolutions_.size(), spatial_layers.size());
    for (size_t i = 0; i < spatial_layers.size(); ++i) {
      wtf_size_t wtf_i = base::checked_cast<wtf_size_t>(i);
      CHECK_EQ(init_spatial_layer_resolutions_[wtf_i].width(),
               spatial_layers[i].width);
      CHECK_EQ(init_spatial_layer_resolutions_[wtf_i].height(),
               spatial_layers[i].height);
    }
    RequestEncodingParametersChangeInternal(parameters, std::nullopt);
    status_ = WEBRTC_VIDEO_CODEC_OK;
    async_init_event_.SetAndReset(WEBRTC_VIDEO_CODEC_OK);
    return;
  }

  DVLOG(3) << __func__ << " expecting new buffers, old size "
           << input_visible_size_.ToString();
  init_spatial_layer_resolutions_.clear();
  for (const auto& layer : spatial_layers) {
    init_spatial_layer_resolutions_.emplace_back(layer.width, layer.height);
  }
  encoder_metrics_provider_->Initialize(
      profile, input_visible_size,
      /*is_hardware_encoder=*/true,
      ToSVCScalabilityMode(spatial_layers, inter_layer_pred));

  RequestEncodingParametersChangeInternal(parameters, input_visible_size);

  input_visible_size_ = input_visible_size;
}

ActiveSpatialLayers RTCVideoEncoder::Impl::GetActiveSpatialLayers() const {
  if (init_spatial_layer_resolutions_.empty()) {
    return ActiveSpatialLayers();
  }
  return active_spatial_layers_;
}

void RTCVideoEncoder::Impl::RequireBitstreamBuffers(
    unsigned int input_count,
    const gfx::Size& input_coded_size,
    size_t output_buffer_size) {
  TRACE_EVENT0("webrtc", "RTCVideoEncoder::Impl::RequireBitstreamBuffers");
  DVLOG(3) << __func__ << " input_count=" << input_count
           << ", input_coded_size=" << input_coded_size.ToString()
           << ", output_buffer_size=" << output_buffer_size;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  auto scoped_event = std::move(async_init_event_);
  if (!video_encoder_)
    return;

  input_frame_coded_size_ = input_coded_size;
  input_buffers_requested_count_ = input_count + kInputBufferExtraCount;

  // |input_buffers_| is only needed in non import mode.
  if (!use_native_input_) {
    input_buffers_free_.resize(input_buffers_requested_count_);
    input_buffers_.resize(input_buffers_requested_count_);
    for (wtf_size_t i = 0; i < input_buffers_requested_count_; i++) {
      input_buffers_free_[i] = i;
      input_buffers_[i] = nullptr;
    }
  }

  output_buffers_.clear();
  for (int i = 0; i < kOutputBufferCount; ++i) {
    base::UnsafeSharedMemoryRegion region =
        gpu_factories_->CreateSharedMemoryRegion(output_buffer_size);
    base::WritableSharedMemoryMapping mapping = region.Map();
    if (!mapping.IsValid()) {
      NotifyErrorStatus({media::EncoderStatus::Codes::kSystemAPICallError,
                         "failed to create output buffer"});
      return;
    }
    output_buffers_.push_back(std::make_pair(
        std::move(region),
        base::MakeRefCounted<RefCountedWritableSharedMemoryMapping>(
            std::move(mapping))));
  }
  encoded_buffer_reference_holder_ =
      std::make_unique<EncodedBufferReferenceHolder>(weak_this_);

  // Immediately provide all output buffers to the VEA.
  for (wtf_size_t i = 0; i < output_buffers_.size(); ++i) {
    UseOutputBitstreamBuffer(i);
  }

  pending_output_buffers_.clear();
  pending_output_buffers_.reserve(output_buffers_.size());

  DCHECK_EQ(status_, WEBRTC_VIDEO_CODEC_UNINITIALIZED);
  status_ = WEBRTC_VIDEO_CODEC_OK;

  scoped_event.SetAndReset(WEBRTC_VIDEO_CODEC_OK);
}

void RTCVideoEncoder::Impl::FillGenericFrameInfo(
    webrtc::CodecSpecificInfo& info,
    const media::BitstreamBufferMetadata& metadata) {
  CHECK(svc_controller_);
  CHECK(metadata.svc_generic.has_value());

  const media::SVCGenericMetadata& md_generic = metadata.svc_generic.value();
  // Some codecs, like H.265, may produce output bitstream that does not follow
  // SVC spec and there is no parsing on the bitstream to get the reference
  // structure. For them, we don't fill in generic frame info, which will be
  // used to create dependency descriptor.
  if (!md_generic.follow_svc_spec &&
      (!md_generic.reference_flags || !md_generic.refresh_flags)) {
    return;
  }

  std::vector<webrtc::ScalableVideoController::LayerFrameConfig> layer_frames =
      svc_controller_->NextFrameConfig(metadata.key_frame);
  CHECK_EQ(layer_frames.size(), 1ull /*num_of_spatial_layers*/);
  CHECK_EQ(layer_frames[0].TemporalId(), md_generic.temporal_idx);

  webrtc::GenericFrameInfo generic =
      svc_controller_->OnEncodeDone(layer_frames[0]);

  // If VEA doesn't follow the SVC spec, we need to check whether
  // the reference dependency is allowed.
  if (!md_generic.follow_svc_spec) {
    if (*md_generic.refresh_flags >= 1 << webrtc::kMaxEncoderBuffers) {
      DLOG(ERROR) << "Invalid refreshed encode buffer flags: "
                  << *md_generic.refresh_flags;
      return;
    }
    generic.encoder_buffers.clear();
    if (encode_buffers_tid_.size() == 0) {
      encode_buffers_tid_.resize(webrtc::kMaxEncoderBuffers);
    }
    uint32_t temporal_id = md_generic.temporal_idx;
    for (int i = 0; i < webrtc::kMaxEncoderBuffers; i++) {
      bool referenced = !!(*md_generic.reference_flags & (1u << i));
      if (referenced) {
        if (encode_buffers_tid_[i] > temporal_id) {
          DLOG(ERROR) << "Refs upper layer frame is not allowed";
          return;
        }
        if (encode_buffers_tid_[i] == temporal_id && temporal_id != 0) {
          DLOG(ERROR)
              << "Refs same layer frame is not allowed for non-base layer";
          return;
        }
      }
      bool updated = !!(*md_generic.refresh_flags & (1u << i));
      if (updated) {
        encode_buffers_tid_[i] = temporal_id;
      }
      if (referenced || updated) {
        webrtc::CodecBufferUsage buffer(i, referenced, updated);
        generic.encoder_buffers.push_back(buffer);
      }
    }
  }

  info.generic_frame_info = generic;
  if (metadata.key_frame) {
    info.template_structure = svc_controller_->DependencyStructure();
  }
}

void RTCVideoEncoder::Impl::BitstreamBufferReady(
    int32_t bitstream_buffer_id,
    const media::BitstreamBufferMetadata& metadata) {
  TRACE_EVENT2("webrtc", "RTCVideoEncoder::Impl::BitstreamBufferReady",
               "timestamp", metadata.timestamp.InMicroseconds(),
               "bitstream_buffer_id", bitstream_buffer_id);
  DVLOG(3) << __func__ << " bitstream_buffer_id=" << bitstream_buffer_id
           << ", payload_size=" << metadata.payload_size_bytes
           << ", end_of_picture=" << metadata.end_of_picture()
           << ", key_frame=" << metadata.key_frame
           << ", timestamp ms=" << metadata.timestamp.InMicroseconds();
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (bitstream_buffer_id < 0 ||
      bitstream_buffer_id >= static_cast<int>(output_buffers_.size())) {
    NotifyErrorStatus({media::EncoderStatus::Codes::kInvalidOutputBuffer,
                       "invalid bitstream_buffer_id: " +
                           base::NumberToString(bitstream_buffer_id)});
    return;
  }

  DCHECK_NE(output_buffers_in_encoder_count_, 0u);
  output_buffers_in_encoder_count_--;

  // Decrease |frames_in_encoder_count_| on the first frame so that
  // UseOutputBitstreamBuffer() is not called until next frame if no frame but
  // the current frame is in VideoEncodeAccelerator.
  if (metadata.spatial_idx().value_or(0) == 0) {
    CHECK_NE(0u, frames_in_encoder_count_);
    frames_in_encoder_count_--;
  }

  if (status_ == WEBRTC_VIDEO_CODEC_UNINITIALIZED) {
    // The encoder has been suspended, drain remaining frames.
    BitstreamBufferAvailable(bitstream_buffer_id);
    return;
  }

  // An encoder drops a frame.
  if (metadata.dropped_frame()) {
    BitstreamBufferAvailable(bitstream_buffer_id);
    // Invoke OnDroppedFrame() only in the end of picture. How to call
    // OnDroppedFrame() in spatial layers is not defined in the webrtc encoder
    // API. We call once in spatial layers. This point will be fixed in a
    // new WebRTC encoder API.
    if (metadata.end_of_picture()) {
      base::AutoLock lock(lock_);
      if (!encoded_image_callback_) {
        return;
      }
      encoded_image_callback_->OnDroppedFrame(
          webrtc::EncodedImageCallback::DropReason::kDroppedByEncoder);
    }
    return;
  }

  scoped_refptr<RefCountedWritableSharedMemoryMapping> output_mapping =
      output_buffers_[bitstream_buffer_id].second;
  if (metadata.payload_size_bytes >
      output_buffers_[bitstream_buffer_id].second->size()) {
    NotifyErrorStatus({media::EncoderStatus::Codes::kInvalidOutputBuffer,
                       "invalid payload_size: " +
                           base::NumberToString(metadata.payload_size_bytes)});
    return;
  }

  if (metadata.end_of_picture()) {
    CHECK(encoder_metrics_provider_);
    encoder_metrics_provider_->IncrementEncodedFrameCount();
  }

  // Find RTP and capture timestamps by going through |pending_timestamps_|.
  // Derive it from current time otherwise.
  std::optional<uint32_t> rtp_timestamp;
  std::optional<int64_t> capture_timestamp_ms;
  std::optional<ActiveSpatialLayers> expected_active_spatial_layers;
  if (!failed_timestamp_match_) {
    // Pop timestamps until we have a match.
    while (!submitted_frames_.empty()) {
      auto& front_frame = submitted_frames_.front();
      const bool end_of_picture = metadata.end_of_picture();
      if (front_frame.media_timestamp_ == metadata.timestamp) {
        rtp_timestamp = front_frame.rtp_timestamp_;
        capture_timestamp_ms = front_frame.capture_time_ms_;
        expected_active_spatial_layers = front_frame.active_spatial_layers_;
        const size_t num_spatial_layers =
            std::max(front_frame.active_spatial_layers_.size(), size_t{1});
        ++front_frame.produced_frames_;

        if (front_frame.produced_frames_ == num_spatial_layers &&
            !end_of_picture) {
          // The top layer must always have the end-of-picture indicator.
          NotifyErrorStatus({media::EncoderStatus::Codes::kEncoderFailedEncode,
                             "missing end-of-picture"});
          return;
        }
        if (end_of_picture) {
          // Remove pending timestamp at the top spatial layer in the case of
          // SVC encoding.
          if (front_frame.produced_frames_ != num_spatial_layers) {
            // At least one resolution was not produced.
            NotifyErrorStatus(
                {media::EncoderStatus::Codes::kEncoderFailedEncode,
                 "missing resolution"});
            return;
          }
          submitted_frames_.pop_front();
        }
        break;
      }
      submitted_frames_.pop_front();
    }
    DCHECK(rtp_timestamp.has_value());
  }

  if (!rtp_timestamp.has_value() || !capture_timestamp_ms.has_value()) {
    failed_timestamp_match_ = true;
    submitted_frames_.clear();
    const int64_t current_time_ms =
        rtc::TimeMicros() / base::Time::kMicrosecondsPerMillisecond;
    // RTP timestamp can wrap around. Get the lower 32 bits.
    rtp_timestamp = static_cast<uint32_t>(current_time_ms * 90);
    capture_timestamp_ms = current_time_ms;
  }

  // Only H.265 bitstream may need a fix. If a fixed bitstream is available, the
  // original bitstream buffer can be released immediately.
  bool fixed_bitstream = false;
  webrtc::EncodedImage image;
#if BUILDFLAG(RTC_USE_H265)
  if (ps_tracker_.get()) {
    H265ParameterSetsTracker::FixedBitstream fixed =
        ps_tracker_->MaybeFi
```