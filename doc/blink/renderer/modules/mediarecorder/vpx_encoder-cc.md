Response:
Let's break down the thought process for analyzing the `vpx_encoder.cc` file.

1. **Understand the Core Purpose:**  The filename `vpx_encoder.cc` immediately suggests this file is responsible for encoding video frames using the VP8 or VP9 codec. The directory `blink/renderer/modules/mediarecorder/` indicates it's part of the MediaRecorder API within the Blink rendering engine (Chromium's rendering engine).

2. **Identify Key Dependencies:**  Looking at the `#include` statements is crucial. They tell us what other components this code interacts with:
    * `third_party/blink/renderer/modules/mediarecorder/vpx_encoder.h`: The header file for this class, defining its interface.
    * Standard library headers (`<algorithm>`, `<utility>`).
    * `base/`:  Chromium's base library, suggesting usage of things like `SequencedTaskRunner`, `TimeTicks`, `TimeDelta`, `SysInfo`, `strings`. This indicates asynchronous operations and system information retrieval.
    * `media/base/`:  Chromium's media library, dealing with `DecoderBuffer`, `EncoderStatus`, `VideoEncoderMetricsProvider`, `VideoFrame`, `VideoUtil`. This confirms its video encoding role.
    * `third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h`:  Indicates performance tracing using Chrome's tracing infrastructure.
    * `ui/gfx/geometry/size.h`: Deals with image dimensions.

3. **Examine the Class Structure:** The code defines a `VpxEncoder` class. Pay attention to its constructor, methods like `EncodeFrame`, `DoEncode`, `ConfigureEncoder`, and helper functions like `GetNumberOfThreadsForEncoding` and `EstimateFrameDuration`.

4. **Analyze the `EncodeFrame` Method (The Main Entry Point):** This is where the encoding process begins. Observe the steps:
    * Checks for GPU memory buffer formats and converts if necessary.
    * Retrieves frame size and estimates duration.
    * Checks if the encoder needs initialization or reconfiguration based on the frame size.
    * Handles different pixel formats (`NV12`, `I420`, `I420A`). The `I420A` case (with alpha) is interesting as it uses a separate encoder for the alpha channel.
    * Calls `DoEncode` to perform the actual encoding.
    * Tracks encoded frame count and calls the `on_encoded_video_cb_` callback.

5. **Delve into `DoEncode` (The Actual Encoding):**
    * Wraps the input `media::VideoFrame` into a `vpx_image_t` structure, which is the format libvpx expects.
    * Calls `vpx_codec_encode` from the libvpx library.
    * Handles potential encoding errors.
    * Retrieves the encoded data using `vpx_codec_get_cx_data`.
    * If encoding the alpha channel, it separately extracts and adds the alpha data to the `DecoderBuffer`.

6. **Understand `ConfigureEncoder` (Initialization and Reconfiguration):**
    * Determines the VP8 or VP9 codec based on `use_vp9_`.
    * Calls `vpx_codec_enc_config_default` to get default encoder settings.
    * Adjusts bitrate based on the provided value or frame size.
    * Sets various encoder parameters like threads, timebase, keyframe mode, and screen content settings.
    * Calls `vpx_codec_enc_init` to initialize the libvpx encoder.
    * Handles initialization errors.
    * Applies specific settings for screen sharing.

7. **Consider JavaScript/HTML/CSS Connections:** The `VpxEncoder` is used by the MediaRecorder API, which is directly exposed to JavaScript. Think about how JavaScript code would trigger this:
    * `navigator.mediaDevices.getUserMedia` (to get video stream).
    * Creating a `MediaRecorder` object, specifying a video codec (likely "video/webm; codecs=vp8" or "video/webm; codecs=vp9").
    * Calling `mediaRecorder.start()`.
    * The browser's internal plumbing then feeds `VideoFrame` objects to the `VpxEncoder`.

8. **Think About User Errors and Debugging:**  What could go wrong?
    * Incorrect codec string in `MediaRecorder`.
    * Issues with camera access or video stream.
    * Performance problems if the system is overloaded.
    * Encoder initialization failures (less common for users, more for developers).
    * Frame size changes causing re-initialization.

9. **Construct the Explanation:**  Organize the findings into logical sections: Functionality, Relationship to Web Technologies, Logical Reasoning, Common Errors, and Debugging. Use clear and concise language, providing specific examples where possible.

10. **Review and Refine:** Check for accuracy, completeness, and clarity. Ensure the explanation is easy to understand for someone familiar with web development concepts. For instance, initially, I might just say "it encodes video."  But refining it means specifying *which* codecs (VP8/VP9) and *where* it fits in the browser's architecture (MediaRecorder in Blink).

This step-by-step approach, focusing on the code's structure, dependencies, and role within the larger browser context, leads to a comprehensive understanding of the `vpx_encoder.cc` file.
这个文件是 Chromium Blink 引擎中 MediaRecorder 模块下的 `vpx_encoder.cc`，它的主要功能是**使用 libvpx 库对视频帧进行 VP8 或 VP9 编码**。

更具体地说，它实现了 `Encoder` 接口，负责将 `media::VideoFrame` 对象编码成 VP8 或 VP9 格式的比特流，以便在 WebM 容器中存储或通过网络传输。

**以下是该文件的主要功能点：**

1. **初始化和配置 VPX 编码器:**
   - 接收编码任务运行器 (`encoding_task_runner`)、是否使用 VP9 (`use_vp9`)、编码完成回调 (`on_encoded_video_cb`)、目标比特率 (`bits_per_second`)、是否是屏幕录制 (`is_screencast`) 和错误回调 (`on_error_cb`) 等参数。
   - 使用 `vpx_codec_enc_config_default` 获取默认编码配置。
   - 根据输入参数（例如目标比特率和帧大小）调整编码配置。
   - 设置编码器线程数，通常会根据 CPU 核心数进行优化。
   - 根据是否为屏幕录制应用特定的编码参数，例如静态阈值和内容调整。
   - 使用 `vpx_codec_enc_init` 初始化 VP8 或 VP9 编码器。

2. **编码视频帧 (`EncodeFrame`):**
   - 接收 `media::VideoFrame` 对象和捕获时间戳。
   - 将 GPU 内存中的 NV12 格式帧转换为内存映射帧（如果需要）。
   - 检查编码器是否已初始化，以及当前帧大小是否与编码器配置匹配。如果需要，会重新配置编码器。
   - 根据视频帧的像素格式（NV12, I420, I420A）调用 `DoEncode` 函数进行实际编码。
   - 对于包含 Alpha 通道的 `I420A` 格式，会分别编码 YUV 分量和 Alpha 分量。
   - 调用 `on_encoded_video_cb_` 回调函数，将编码后的数据传递给上层模块。

3. **实际编码操作 (`DoEncode`):**
   - 将 `media::VideoFrame` 数据包装成 libvpx 可以处理的 `vpx_image_t` 结构。
   - 调用 `vpx_codec_encode` 函数执行编码。
   - 处理编码错误。
   - 使用 `vpx_codec_get_cx_data` 获取编码后的数据包。
   - 对于 Alpha 通道的编码，会将编码后的 Alpha 数据添加到 `media::DecoderBuffer` 的边数据中。

4. **动态调整编码参数:**
   - 可以根据新的帧大小重新配置编码器。
   - 估计帧持续时间，用于编码器进行速率控制。

5. **处理 Alpha 通道:**
   - 支持编码带有 Alpha 通道的视频帧 (I420A 格式)。
   - 使用两个独立的编码器实例，一个用于编码 YUV 分量，另一个用于编码 Alpha 分量。

**与 JavaScript, HTML, CSS 的功能关系 (举例说明):**

这个文件本身并不直接涉及 JavaScript, HTML, 或 CSS 的编写。它的作用是底层的视频编码，是 MediaRecorder API 的一部分。JavaScript 代码通过 MediaRecorder API 与这个文件间接交互。

**例子：**

假设有以下 JavaScript 代码：

```javascript
navigator.mediaDevices.getUserMedia({ video: true })
  .then(stream => {
    const mediaRecorder = new MediaRecorder(stream, {
      mimeType: 'video/webm; codecs=vp9' // 或者 'video/webm; codecs=vp8'
    });

    mediaRecorder.ondataavailable = event => {
      // 处理编码后的数据
      console.log('Encoded data:', event.data);
    };

    mediaRecorder.start();

    // 一段时间后停止录制
    setTimeout(() => {
      mediaRecorder.stop();
    }, 5000);
  });
```

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户与网页交互:** 用户访问一个使用 MediaRecorder API 的网页，例如一个在线视频录制工具。
2. **JavaScript 发起媒体流请求:**  JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: true })` 请求用户的摄像头权限，并获取视频流。
3. **创建 MediaRecorder 对象:** JavaScript 代码使用获取到的视频流创建一个 `MediaRecorder` 对象，并指定了 `mimeType` 为 `video/webm; codecs=vp9` 或 `video/webm; codecs=vp8`。 这就指示了浏览器需要使用 VP9 或 VP8 编码器。
4. **MediaRecorder 开始录制:** JavaScript 代码调用 `mediaRecorder.start()` 开始录制。
5. **Blink 引擎处理录制请求:** Blink 引擎接收到录制请求，并开始从视频轨道获取视频帧。
6. **选择 VPX 编码器:** 由于 `mimeType` 中指定了 VP9 或 VP8，Blink 引擎会选择 `VpxEncoder` 来处理这些视频帧。
7. **`VpxEncoder::EncodeFrame` 被调用:**  对于每一帧从视频轨道获取到的 `media::VideoFrame`，`VpxEncoder::EncodeFrame` 方法会被调用。
8. **`DoEncode` 执行编码:** `EncodeFrame` 方法会调用 `DoEncode` 方法，利用 libvpx 库对视频帧进行实际的编码操作。
9. **编码完成回调:** 编码完成后，`on_encoded_video_cb_` 回调函数会被触发，将编码后的数据传递给 MediaRecorder API 的上层处理逻辑。
10. **`ondataavailable` 事件触发:**  MediaRecorder API 将编码后的数据封装到 `Blob` 对象中，并通过 `ondataavailable` 事件传递给 JavaScript 代码。

**逻辑推理 (假设输入与输出):**

**假设输入:**

- 一个分辨率为 640x480 的 I420 格式的 `media::VideoFrame` 对象。
- 目标比特率为 1000000 bps (1 Mbps)。
- `use_vp9_` 为 `true` (使用 VP9 编码)。
- 不是屏幕录制 (`is_screencast_` 为 `false`)。

**预期输出:**

- 一个 `media::DecoderBuffer` 对象，其中包含了使用 VP9 编码后的视频帧数据。
- 该 `DecoderBuffer` 的 `is_key_frame()` 属性可能为 `true` 或 `false`，取决于编码器的内部决策或是否显式请求了关键帧。
- 如果编码过程中没有错误，不会触发 `on_error_cb_`。

**用户或编程常见的使用错误 (举例说明):**

1. **JavaScript 中指定了错误的 `mimeType`:**
   - 错误示例：`mimeType: 'video/webm; codecs=h264'`  (此代码中只实现了 VP8/VP9 编码)
   - 结果：MediaRecorder 可能无法正常工作或抛出错误，因为找不到对应的编码器。

2. **频繁改变视频流的分辨率:**
   - 错误场景：视频源的分辨率在短时间内频繁变化。
   - 结果：`VpxEncoder` 需要频繁地重新配置编码器，这会消耗额外的 CPU 资源，可能导致性能问题甚至丢帧。

3. **在低端设备上设置过高的比特率:**
   - 错误场景：`bits_per_second` 设置得过高，超过了设备的处理能力或网络带宽。
   - 结果：编码器可能无法达到目标比特率，或者导致帧率下降，甚至编码失败。

4. **未处理 `on_error_cb_` 回调:**
   - 错误场景：编码过程中发生错误（例如 libvpx 初始化失败），但上层代码没有正确处理 `on_error_cb_` 回调。
   - 结果：用户可能不会收到任何错误提示，导致程序行为异常。

**总结:**

`vpx_encoder.cc` 是 Chromium 浏览器中 MediaRecorder API 的核心组件之一，它负责将视频帧高效地编码为 VP8 或 VP9 格式，使得网页能够进行视频录制等操作。理解这个文件的功能有助于理解浏览器如何处理视频编码以及如何调试相关的 Web 应用问题。

### 提示词
```
这是目录为blink/renderer/modules/mediarecorder/vpx_encoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediarecorder/vpx_encoder.h"

#include <algorithm>
#include <utility>

#include "base/numerics/safe_conversions.h"
#include "base/strings/strcat.h"
#include "base/system/sys_info.h"
#include "media/base/decoder_buffer.h"
#include "media/base/encoder_status.h"
#include "media/base/video_encoder_metrics_provider.h"
#include "media/base/video_frame.h"
#include "media/base/video_util.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "ui/gfx/geometry/size.h"

using media::VideoFrameMetadata;

namespace blink {

void VpxEncoder::VpxCodecDeleter::operator()(vpx_codec_ctx_t* codec) {
  if (!codec)
    return;
  vpx_codec_err_t ret = vpx_codec_destroy(codec);
  CHECK_EQ(ret, VPX_CODEC_OK);
  delete codec;
}

static int GetNumberOfThreadsForEncoding() {
  // Do not saturate CPU utilization just for encoding. On a lower-end system
  // with only 1 or 2 cores, use only one thread for encoding. On systems with
  // more cores, allow half of the cores to be used for encoding.
  return std::min(8, (base::SysInfo::NumberOfProcessors() + 1) / 2);
}

VpxEncoder::VpxEncoder(
    scoped_refptr<base::SequencedTaskRunner> encoding_task_runner,
    bool use_vp9,
    const VideoTrackRecorder::OnEncodedVideoCB& on_encoded_video_cb,
    uint32_t bits_per_second,
    bool is_screencast,
    const VideoTrackRecorder::OnErrorCB on_error_cb)
    : Encoder(std::move(encoding_task_runner),
              on_encoded_video_cb,
              bits_per_second),
      use_vp9_(use_vp9),
      is_screencast_(is_screencast),
      on_error_cb_(on_error_cb) {
  std::memset(&codec_config_, 0, sizeof(codec_config_));
  std::memset(&alpha_codec_config_, 0, sizeof(alpha_codec_config_));
  codec_config_.g_timebase.den = 0;        // Not initialized.
  alpha_codec_config_.g_timebase.den = 0;  // Not initialized.
}

bool VpxEncoder::CanEncodeAlphaChannel() const {
  return true;
}

void VpxEncoder::EncodeFrame(scoped_refptr<media::VideoFrame> frame,
                             base::TimeTicks capture_timestamp,
                             bool request_keyframe) {
  using media::VideoFrame;
  TRACE_EVENT0("media", "VpxEncoder::EncodeFrame");

  if (frame->format() == media::PIXEL_FORMAT_NV12 &&
      frame->storage_type() == media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER)
    frame = media::ConvertToMemoryMappedFrame(frame);
  if (!frame) {
    LOG(WARNING) << "Invalid video frame to encode";
    return;
  }

  const gfx::Size frame_size = frame->visible_rect().size();
  base::TimeDelta duration = EstimateFrameDuration(*frame);
  const media::Muxer::VideoParameters video_params(*frame);

  if (!IsInitialized(codec_config_) ||
      gfx::Size(codec_config_.g_w, codec_config_.g_h) != frame_size) {
    if (!ConfigureEncoder(frame_size, &codec_config_, &encoder_)) {
      return;
    }
  }

  bool force_keyframe = request_keyframe;
  scoped_refptr<media::DecoderBuffer> output_data;
  switch (frame->format()) {
    case media::PIXEL_FORMAT_NV12: {
      last_frame_had_alpha_ = false;
      DoEncode(encoder_.get(), frame_size, frame->data(VideoFrame::Plane::kY),
               frame->visible_data(VideoFrame::Plane::kY),
               frame->stride(VideoFrame::Plane::kY),
               frame->visible_data(VideoFrame::Plane::kUV),
               frame->stride(VideoFrame::Plane::kUV),
               frame->visible_data(VideoFrame::Plane::kUV) + 1,
               frame->stride(VideoFrame::Plane::kUV), duration, force_keyframe,
               &output_data, /*is_alpha=*/false, VPX_IMG_FMT_NV12);
      break;
    }
    case media::PIXEL_FORMAT_I420: {
      last_frame_had_alpha_ = false;
      DoEncode(encoder_.get(), frame_size, frame->data(VideoFrame::Plane::kY),
               frame->visible_data(VideoFrame::Plane::kY),
               frame->stride(VideoFrame::Plane::kY),
               frame->visible_data(VideoFrame::Plane::kU),
               frame->stride(VideoFrame::Plane::kU),
               frame->visible_data(VideoFrame::Plane::kV),
               frame->stride(VideoFrame::Plane::kV), duration, force_keyframe,
               &output_data, /*is_alpha=*/false, VPX_IMG_FMT_I420);
      break;
    }
    case media::PIXEL_FORMAT_I420A: {
      // Split the duration between two encoder instances if alpha is encoded.
      duration = duration / 2;
      if ((!IsInitialized(alpha_codec_config_) ||
           gfx::Size(alpha_codec_config_.g_w, alpha_codec_config_.g_h) !=
               frame_size)) {
        if (!ConfigureEncoder(frame_size, &alpha_codec_config_,
                              &alpha_encoder_)) {
          return;
        }
        u_plane_stride_ = media::VideoFrame::RowBytes(
            VideoFrame::Plane::kU, frame->format(), frame_size.width());
        v_plane_stride_ = media::VideoFrame::RowBytes(
            VideoFrame::Plane::kV, frame->format(), frame_size.width());
        v_plane_offset_ =
            media::VideoFrame::PlaneSize(frame->format(), VideoFrame::Plane::kU,
                                         frame_size)
                .GetArea();
        alpha_dummy_planes_.resize(base::checked_cast<wtf_size_t>(
            v_plane_offset_ +
            media::VideoFrame::PlaneSize(frame->format(), VideoFrame::Plane::kV,
                                         frame_size)
                .GetArea()));
        // It is more expensive to encode 0x00, so use 0x80 instead.
        std::fill(alpha_dummy_planes_.begin(), alpha_dummy_planes_.end(), 0x80);
      }
      // If we introduced a new alpha frame, force keyframe.
      force_keyframe = force_keyframe || !last_frame_had_alpha_;
      last_frame_had_alpha_ = true;

      DoEncode(encoder_.get(), frame_size, frame->data(VideoFrame::Plane::kY),
               frame->visible_data(VideoFrame::Plane::kY),
               frame->stride(VideoFrame::Plane::kY),
               frame->visible_data(VideoFrame::Plane::kU),
               frame->stride(VideoFrame::Plane::kU),
               frame->visible_data(VideoFrame::Plane::kV),
               frame->stride(VideoFrame::Plane::kV), duration, force_keyframe,
               &output_data, /*is_alpha=*/false, VPX_IMG_FMT_I420);

      bool alpha_force_keyframe = output_data->is_key_frame();
      DoEncode(alpha_encoder_.get(), frame_size,
               frame->data(VideoFrame::Plane::kA),
               frame->visible_data(VideoFrame::Plane::kA),
               frame->stride(VideoFrame::Plane::kA), alpha_dummy_planes_.data(),
               base::checked_cast<int>(u_plane_stride_),
               alpha_dummy_planes_.data() + v_plane_offset_,
               base::checked_cast<int>(v_plane_stride_), duration,
               alpha_force_keyframe, &output_data, /*is_alpha=*/true,
               VPX_IMG_FMT_I420);
      break;
    }
    default:
      NOTREACHED() << media::VideoPixelFormatToString(frame->format());
  }
  frame = nullptr;

  metrics_provider_->IncrementEncodedFrameCount();
  on_encoded_video_cb_.Run(video_params, std::move(output_data), std::nullopt,
                           capture_timestamp);
}

void VpxEncoder::DoEncode(vpx_codec_ctx_t* const encoder,
                          const gfx::Size& frame_size,
                          const uint8_t* data,
                          const uint8_t* y_plane,
                          int y_stride,
                          const uint8_t* u_plane,
                          int u_stride,
                          const uint8_t* v_plane,
                          int v_stride,
                          const base::TimeDelta& duration,
                          bool force_keyframe,
                          scoped_refptr<media::DecoderBuffer>* output_data,
                          bool is_alpha,
                          vpx_img_fmt_t img_fmt) {
  CHECK(output_data);
  DCHECK(img_fmt == VPX_IMG_FMT_I420 || img_fmt == VPX_IMG_FMT_NV12);

  vpx_image_t vpx_image;
  vpx_image_t* const result =
      vpx_img_wrap(&vpx_image, img_fmt, frame_size.width(), frame_size.height(),
                   1 /* align */, const_cast<uint8_t*>(data));
  DCHECK_EQ(result, &vpx_image);
  vpx_image.planes[VPX_PLANE_Y] = const_cast<uint8_t*>(y_plane);
  vpx_image.planes[VPX_PLANE_U] = const_cast<uint8_t*>(u_plane);
  vpx_image.planes[VPX_PLANE_V] = const_cast<uint8_t*>(v_plane);
  vpx_image.stride[VPX_PLANE_Y] = y_stride;
  vpx_image.stride[VPX_PLANE_U] = u_stride;
  vpx_image.stride[VPX_PLANE_V] = v_stride;

  const vpx_codec_flags_t flags = force_keyframe ? VPX_EFLAG_FORCE_KF : 0;
  // Encode the frame.  The presentation time stamp argument here is fixed to
  // zero to force the encoder to base its single-frame bandwidth calculations
  // entirely on |predicted_frame_duration|.
  const vpx_codec_err_t ret =
      vpx_codec_encode(encoder, &vpx_image, 0 /* pts */,
                       static_cast<unsigned long>(duration.InMicroseconds()),
                       flags, VPX_DL_REALTIME);
  if (ret != VPX_CODEC_OK) {
    metrics_provider_->SetError(
        {media::EncoderStatus::Codes::kEncoderFailedEncode,
         base::StrCat(
             {"libvpx failed to encode: ", vpx_codec_err_to_string(ret), " - ",
              vpx_codec_error_detail(encoder)})});
    on_error_cb_.Run();
    return;
  }

  vpx_codec_iter_t iter = nullptr;
  const vpx_codec_cx_pkt_t* pkt = nullptr;
  while ((pkt = vpx_codec_get_cx_data(encoder, &iter))) {
    if (pkt->kind != VPX_CODEC_CX_FRAME_PKT)
      continue;
    if (is_alpha) {
      const auto* alpha_data =
          reinterpret_cast<const uint8_t*>(pkt->data.frame.buf);
      // If is_alpha is true, it needs *output_data to already be a valid
      // scoped_refptr.
      CHECK(*output_data);
      (*output_data)->WritableSideData().alpha_data =
          base::HeapArray<uint8_t>::CopiedFrom(
              base::span<const uint8_t>(alpha_data, pkt->data.frame.sz));
    } else {
      *output_data = media::DecoderBuffer::CopyFrom(
          {reinterpret_cast<const uint8_t*>(pkt->data.frame.buf),
           pkt->data.frame.sz});
    }
    (*output_data)
        ->set_is_key_frame((pkt->data.frame.flags & VPX_FRAME_IS_KEY) != 0);
    break;
  }
}

bool VpxEncoder::ConfigureEncoder(const gfx::Size& size,
                                  vpx_codec_enc_cfg_t* codec_config,
                                  ScopedVpxCodecCtxPtr* encoder) {
  if (IsInitialized(*codec_config)) {
    // TODO(mcasas) VP8 quirk/optimisation: If the new |size| is strictly less-
    // than-or-equal than the old size, in terms of area, the existing encoder
    // instance could be reused after changing |codec_config->{g_w,g_h}|.
    DVLOG(1) << "Destroying/Re-Creating encoder for new frame size: "
             << gfx::Size(codec_config->g_w, codec_config->g_h).ToString()
             << " --> " << size.ToString() << (use_vp9_ ? " vp9" : " vp8");
    encoder->reset();
  }

  const vpx_codec_iface_t* codec_interface =
      use_vp9_ ? vpx_codec_vp9_cx() : vpx_codec_vp8_cx();
  vpx_codec_err_t result = vpx_codec_enc_config_default(
      codec_interface, codec_config, 0 /* reserved */);
  DCHECK_EQ(VPX_CODEC_OK, result);

  DCHECK_EQ(320u, codec_config->g_w);
  DCHECK_EQ(240u, codec_config->g_h);
  DCHECK_EQ(256u, codec_config->rc_target_bitrate);
  // Use the selected bitrate or adjust default bit rate to account for the
  // actual size.  Note: |rc_target_bitrate| units are kbit per second.
  if (bits_per_second_ > 0) {
    codec_config->rc_target_bitrate = bits_per_second_ / 1000;
  } else {
    codec_config->rc_target_bitrate = size.GetArea() *
                                      codec_config->rc_target_bitrate /
                                      codec_config->g_w / codec_config->g_h;
  }
  // Don't drop a frame.
  DCHECK_EQ(codec_config->rc_dropframe_thresh, 0u);
  // Both VP8/VP9 configuration should be Variable BitRate by default.
  DCHECK_EQ(VPX_VBR, codec_config->rc_end_usage);
  if (use_vp9_) {
    // Number of frames to consume before producing output.
    codec_config->g_lag_in_frames = 0;

    // DCHECK that the profile selected by default is I420 (magic number 0).
    DCHECK_EQ(0u, codec_config->g_profile);
  } else {
    // VP8 always produces frames instantaneously.
    DCHECK_EQ(0u, codec_config->g_lag_in_frames);
  }

  DCHECK(size.width());
  DCHECK(size.height());
  codec_config->g_w = size.width();
  codec_config->g_h = size.height();
  codec_config->g_pass = VPX_RC_ONE_PASS;

  // Timebase is the smallest interval used by the stream, can be set to the
  // frame rate or to e.g. microseconds.
  codec_config->g_timebase.num = 1;
  codec_config->g_timebase.den = base::Time::kMicrosecondsPerSecond;

  // The periodical keyframe interval is configured by KeyFrameRequestProcessor.
  // Aside from the periodical keyframe, let the encoder decide where to place
  // the Keyframes In VPX_KF_AUTO mode libvpx will sometimes emit keyframes out
  // of necessity.
  // Note that due to http://crbug.com/440223, it might be necessary to force a
  // key frame after 10,000frames since decoding fails after 30,000 non-key
  // frames.
  codec_config->kf_mode = VPX_KF_AUTO;

  codec_config->g_threads = GetNumberOfThreadsForEncoding();

  // Number of frames to consume before producing output.
  codec_config->g_lag_in_frames = 0;

  metrics_provider_->Initialize(
      use_vp9_ ? media::VP9PROFILE_MIN : media::VP8PROFILE_ANY, size,
      /*is_hardware_encoder=*/false);
  // Can't use ScopedVpxCodecCtxPtr until after vpx_codec_enc_init, since it's
  // not valid to call vpx_codec_destroy when vpx_codec_enc_init fails.
  auto tmp_encoder = std::make_unique<vpx_codec_ctx_t>();
  const vpx_codec_err_t ret = vpx_codec_enc_init(
      tmp_encoder.get(), codec_interface, codec_config, 0 /* flags */);
  if (ret != VPX_CODEC_OK) {
    metrics_provider_->SetError(
        {media::EncoderStatus::Codes::kEncoderInitializationError,
         base::StrCat(
             {"libvpx failed to initialize: ", vpx_codec_err_to_string(ret)})});
    DLOG(WARNING) << "vpx_codec_enc_init failed: " << ret;
    // Require the encoder to be reinitialized next frame.
    codec_config->g_timebase.den = 0;
    on_error_cb_.Run();
    return false;
  }
  encoder->reset(tmp_encoder.release());

  if (use_vp9_) {
    // Values of VP8E_SET_CPUUSED greater than 0 will increase encoder speed at
    // the expense of quality up to a maximum value of 8 for VP9, by tuning the
    // target time spent encoding the frame. Go from 8 to 5 (values for real
    // time encoding) depending on the amount of cores available in the system.
    const int kCpuUsed =
        std::max(5, 8 - base::SysInfo::NumberOfProcessors() / 2);
    result = vpx_codec_control(encoder->get(), VP8E_SET_CPUUSED, kCpuUsed);
    DLOG_IF(WARNING, VPX_CODEC_OK != result) << "VP8E_SET_CPUUSED failed";
  }

  // Tune configs for screen sharing. The values are the same as WebRTC
  // https://source.chromium.org/chromium/chromium/src/+/main:third_party/webrtc/modules/video_coding/codecs/vp8/libvpx_vp8_encoder.cc
  // https://source.chromium.org/chromium/chromium/src/+/main:third_party/webrtc/modules/video_coding/codecs/vp9/libvpx_vp9_encoder.cc
  vpx_codec_control(encoder->get(), VP8E_SET_STATIC_THRESHOLD,
                    (is_screencast_ && !use_vp9_) ? 100 : 1);
  if (is_screencast_) {
    if (use_vp9_) {
      vpx_codec_control(encoder->get(), VP9E_SET_TUNE_CONTENT,
                        VP9E_CONTENT_SCREEN);
    } else {
      // Setting 1, not 2, so the libvpx encoder doesn't drop a frame.
      vpx_codec_control(encoder->get(), VP8E_SET_SCREEN_CONTENT_MODE, 1 /*On*/);
    }
  }

  return true;
}

bool VpxEncoder::IsInitialized(const vpx_codec_enc_cfg_t& codec_config) const {
  return codec_config.g_timebase.den != 0;
}

base::TimeDelta VpxEncoder::EstimateFrameDuration(
    const media::VideoFrame& frame) {
  // If the source of the video frame did not provide the frame duration, use
  // the actual amount of time between the current and previous frame as a
  // prediction for the next frame's duration.
  // TODO(mcasas): This duration estimation could lead to artifacts if the
  // cadence of the received stream is compromised (e.g. camera freeze, pause,
  // remote packet loss).  Investigate using GetFrameRate() in this case.
  base::TimeDelta predicted_frame_duration =
      frame.timestamp() - last_frame_timestamp_;
  base::TimeDelta frame_duration =
      frame.metadata().frame_duration.value_or(predicted_frame_duration);
  last_frame_timestamp_ = frame.timestamp();
  // Make sure |frame_duration| is in a safe range of values.
  const base::TimeDelta kMaxFrameDuration = base::Seconds(1.0 / 8);
  const base::TimeDelta kMinFrameDuration = base::Milliseconds(1);
  return std::min(kMaxFrameDuration,
                  std::max(frame_duration, kMinFrameDuration));
}

}  // namespace blink
```