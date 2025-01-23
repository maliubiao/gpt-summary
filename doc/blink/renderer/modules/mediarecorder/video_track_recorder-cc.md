Response:
The user wants to understand the functionality of the `video_track_recorder.cc` file in the Chromium Blink engine. They are interested in its relationship with web technologies (JavaScript, HTML, CSS), its logic, potential user errors, and how a user's action might lead to this code being executed.

**Plan:**

1. **Identify Core Functionality:**  Analyze the code to pinpoint its main purpose. Based on the name and included headers, it's likely responsible for recording video from a media stream.
2. **Web Technology Connections:** Look for interactions with web APIs or data structures that are exposed to JavaScript, HTML, or CSS. The `MediaRecorder` API seems highly relevant.
3. **Logical Inference:**  Examine code blocks that involve decisions, data processing, or transformations. Consider possible inputs and outputs of these blocks.
4. **Common User Errors:** Think about typical mistakes users might make when using the `MediaRecorder` API that could lead to issues handled by this code.
5. **User Operation Flow:**  Outline the steps a user would take to initiate video recording, which would eventually involve this code.
6. **Summarize Functionality:**  Provide a concise overview of the file's role.
```
功能概要:

这个 `video_track_recorder.cc` 文件是 Chromium Blink 渲染引擎中 `MediaRecorder` API 的一部分，专门负责处理**视频轨道的录制**。它封装了视频编码的逻辑，将从 `MediaStream` 获取的视频帧编码成特定的格式（例如 VP8, VP9, H.264, AV1）。

**详细功能分解:**

1. **视频帧接收与处理:**
    *   接收来自 `MediaStreamVideoTrack` 的原始视频帧。
    *   可能需要进行像素格式转换 (例如 RGB 到 YUV) 以适应编码器的需求。
    *   处理视频帧的元数据，例如时间戳和旋转信息。

2. **视频编码:**
    *   支持多种视频编码格式 (通过条件编译 `#if BUILDFLAG(...)` 支持不同的编码器)。
    *   使用硬件加速 (VEA - Video Encode Accelerator) 或软件编码器进行编码。
    *   根据配置 (例如码率) 初始化和管理视频编码器。
    *   处理关键帧的请求和生成。

3. **编码数据回调:**
    *   将编码后的视频数据块传递给 `MediaRecorderHandler` 或其他模块进行后续处理 (例如复用成最终的媒体文件)。

4. **错误处理和状态管理:**
    *   处理编码过程中的错误。
    *   维护录制状态 (例如暂停)。

5. **性能指标收集:**
    *   使用 UMA (User Metrics Analysis) 记录编码相关的性能指标，例如使用的编解码器类型 (硬件或软件)。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript (MediaRecorder API):**  JavaScript 代码使用 `MediaRecorder` API 来开始、停止和控制录制过程。例如，当 JavaScript 调用 `mediaRecorder.start()` 并指定一个包含视频轨道的 `MediaStream` 时，`VideoTrackRecorder` 就会被创建并开始处理视频数据。

    ```javascript
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(function(stream) {
        const mediaRecorder = new MediaRecorder(stream, { mimeType: 'video/webm' });
        mediaRecorder.ondataavailable = function(event) {
          // 处理录制到的视频数据
          console.log('视频数据可用', event.data);
        };
        mediaRecorder.start(); // 触发 VideoTrackRecorder 的创建和启动
        // ... 稍后停止录制
        mediaRecorder.stop();
      });
    ```

*   **HTML (<video> 元素):**  `MediaStream` 通常从 `<video>` 元素捕获而来（例如使用 `captureStream()` 方法）。`VideoTrackRecorder` 处理的就是从这个流中提取的视频轨道数据。

    ```html
    <video id="myVideo" autoplay muted></video>
    <script>
      const videoElement = document.getElementById('myVideo');
      navigator.mediaDevices.getUserMedia({ video: true })
        .then(function(stream) {
          videoElement.srcObject = stream;
          const mediaRecorder = new MediaRecorder(stream);
          // ...
        });
    </script>
    ```

*   **CSS (无直接关系，但影响视频显示):** CSS 可以控制 `<video>` 元素的样式和布局，但与 `VideoTrackRecorder` 的内部工作没有直接关联。

**逻辑推理 (假设输入与输出):**

*   **假设输入:**
    *   一个 `MediaStreamVideoTrack` 对象，包含一系列视频帧。
    *   用户通过 JavaScript 的 `MediaRecorder` 指定的编码参数 (例如 `mimeType: 'video/webm; codecs=vp9'`, 这会影响 `CodecId`) 和码率。
    *   设备支持硬件 VP9 编码。

*   **逻辑推理:**
    1. `VideoTrackRecorder` 会根据 `mimeType` 解析出期望的 `CodecId` (例如 `kVp9`)。
    2. 检查系统是否支持硬件加速的 VP9 编码 (`CanUseAcceleratedEncoder` 函数会进行检查)。
    3. 如果支持，则选择硬件 VP9 编码器 (`VeaEncoder` 或类似的)。
    4. 接收到的视频帧会被传递给硬件编码器。
    5. 编码器将帧编码成 VP9 比特流。

*   **假设输出:**
    *   编码后的 VP9 视频数据块，作为 `OnEncodedVideoCB` 的参数传递出去。

**用户或编程常见的使用错误举例:**

*   **用户错误:**
    *   **未授权摄像头权限:** 用户拒绝了浏览器的摄像头访问权限，导致 `getUserMedia` 返回的 `MediaStream` 没有视频轨道，`VideoTrackRecorder` 无法工作。
    *   **指定的 `mimeType` 浏览器不支持:**  如果用户通过 JavaScript 指定了一个浏览器不支持的 `mimeType` (或者该 `mimeType` 下的编解码器组合不支持)，`VideoTrackRecorder` 可能无法找到合适的编码器。

*   **编程错误:**
    *   **在不支持 `MediaRecorder` 的浏览器中使用:**  旧版本的浏览器可能不支持 `MediaRecorder` API。
    *   **没有正确处理 `getUserMedia` 的 Promise 错误:**  如果 `getUserMedia` 失败 (例如由于安全原因或硬件问题)，没有合适的错误处理会导致后续的 `MediaRecorder` 创建失败。
    *   **在 `ondataavailable` 事件处理程序中处理大量数据时阻塞主线程:**  虽然这与 `VideoTrackRecorder` 本身关系不大，但如果编码后的数据处理不当，会导致用户界面卡顿。

**用户操作到达这里的步骤 (调试线索):**

1. **用户打开一个网页，该网页使用了 `MediaRecorder` API。**
2. **网页 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia({ video: true })` 请求访问用户的摄像头。**
3. **用户授权了摄像头访问权限。**
4. **`getUserMedia` 返回一个包含视频轨道的 `MediaStream` 对象。**
5. **网页 JavaScript 代码使用该 `MediaStream` 对象创建 `MediaRecorder` 实例，并指定了视频相关的 `mimeType`。**
6. **当 JavaScript 调用 `mediaRecorder.start()` 时，Blink 渲染引擎会创建相应的 `VideoTrackRecorder` 对象来处理视频轨道。**
7. **`VideoTrackRecorder` 开始监听来自 `MediaStreamVideoTrack` 的视频帧。**
8. **当有新的视频帧到达时，`VideoTrackRecorder` 会对其进行处理和编码。**

**功能归纳 (第 1 部分):**

`video_track_recorder.cc` 的主要功能是**负责将来自 `MediaStream` 的视频轨道数据编码成指定的格式**。它管理视频帧的接收、像素格式转换、选择和初始化合适的编码器 (硬件或软件)，并将编码后的数据传递给其他模块。这个组件是 `MediaRecorder` API 实现的关键部分，使得网页能够录制用户的摄像头视频。
```
### 提示词
```
这是目录为blink/renderer/modules/mediarecorder/video_track_recorder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/modules/mediarecorder/video_track_recorder.h"

#include <memory>

#include "base/functional/bind.h"
#include "base/functional/overloaded.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/task/bind_post_task.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "cc/paint/skia_paint_canvas.h"
#include "media/base/async_destroy_video_encoder.h"
#include "media/base/decoder_buffer.h"
#include "media/base/media_util.h"
#include "media/base/supported_types.h"
#include "media/base/video_codecs.h"
#include "media/base/video_encoder_metrics_provider.h"
#include "media/base/video_frame.h"
#include "media/base/video_util.h"
#include "media/media_buildflags.h"
#include "media/muxers/webm_muxer.h"
#include "media/renderers/paint_canvas_video_renderer.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "media/video/video_encode_accelerator_adapter.h"
#include "media/video/vpx_video_encoder.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/modules/mediarecorder/media_recorder_encoder_wrapper.h"
#include "third_party/blink/renderer/modules/mediarecorder/media_recorder_handler.h"
#include "third_party/blink/renderer/modules/mediarecorder/vea_encoder.h"
#include "third_party/blink/renderer/modules/mediarecorder/vpx_encoder.h"
#include "third_party/blink/renderer/modules/mediastream/media_stream_video_track.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_provider_util.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_component.h"
#include "third_party/blink/renderer/platform/mediastream/media_stream_source.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/sequence_bound.h"
#include "third_party/libyuv/include/libyuv.h"
#include "ui/gfx/geometry/size.h"

#if BUILDFLAG(ENABLE_OPENH264)
#include "media/video/openh264_video_encoder.h"
#include "third_party/blink/renderer/modules/mediarecorder/h264_encoder.h"
#endif  // #if BUILDFLAG(ENABLE_OPENH264)

#if BUILDFLAG(ENABLE_LIBAOM)
#include "media/video/av1_video_encoder.h"
#endif  // BUILDFLAG(ENABLE_LIBAOM)

using video_track_recorder::kVEAEncoderMinResolutionHeight;
using video_track_recorder::kVEAEncoderMinResolutionWidth;

namespace WTF {
template <>
struct CrossThreadCopier<std::vector<scoped_refptr<media::VideoFrame>>>
    : public CrossThreadCopierPassThrough<
          std::vector<scoped_refptr<media::VideoFrame>>> {
  STATIC_ONLY(CrossThreadCopier);
};

template <>
struct CrossThreadCopier<blink::KeyFrameRequestProcessor::Configuration>
    : public CrossThreadCopierPassThrough<
          blink::KeyFrameRequestProcessor::Configuration> {
  STATIC_ONLY(CrossThreadCopier);
};
}  // namespace WTF

namespace blink {

// Helper class used to bless annotation of our calls to
// CreateOffscreenGraphicsContext3DProvider using ScopedAllowBaseSyncPrimitives.
class VideoTrackRecorderImplContextProvider {
 public:
  static std::unique_ptr<WebGraphicsContext3DProvider>
  CreateOffscreenGraphicsContext(Platform::ContextAttributes context_attributes,
                                 Platform::GraphicsInfo* gl_info,
                                 const KURL& url) {
    base::ScopedAllowBaseSyncPrimitives allow;
    return CreateOffscreenGraphicsContext3DProvider(context_attributes, gl_info,
                                                    url);
  }
};

using CodecId = VideoTrackRecorder::CodecId;

libyuv::RotationMode MediaVideoRotationToRotationMode(
    media::VideoRotation rotation) {
  switch (rotation) {
    case media::VIDEO_ROTATION_0:
      return libyuv::kRotate0;
    case media::VIDEO_ROTATION_90:
      return libyuv::kRotate90;
    case media::VIDEO_ROTATION_180:
      return libyuv::kRotate180;
    case media::VIDEO_ROTATION_270:
      return libyuv::kRotate270;
  }
  NOTREACHED() << rotation;
}

namespace {

static const struct {
  CodecId codec_id;
  media::VideoCodecProfile min_profile;
  media::VideoCodecProfile max_profile;
} kPreferredCodecIdAndVEAProfiles[] = {
    {CodecId::kVp8, media::VP8PROFILE_MIN, media::VP8PROFILE_MAX},
    {CodecId::kVp9, media::VP9PROFILE_MIN, media::VP9PROFILE_MAX},
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
    {CodecId::kH264, media::H264PROFILE_MIN, media::H264PROFILE_MAX},
#endif
    {CodecId::kAv1, media::AV1PROFILE_MIN, media::AV1PROFILE_MAX},
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
    {CodecId::kHevc, media::HEVCPROFILE_MIN, media::HEVCPROFILE_MAX},
#endif
};

static_assert(std::size(kPreferredCodecIdAndVEAProfiles) ==
                  static_cast<int>(CodecId::kLast),
              "|kPreferredCodecIdAndVEAProfiles| should consider all CodecIds");

// The maximum number of frames which we'll keep frame references alive for
// encode. The number of frames in flight is further restricted by the device
// video capture max buffer pool size if it is smaller. This guarantees that
// there is limit on the number of frames in a FIFO queue that are being encoded
// and frames coming after this limit is reached are dropped.
// TODO(emircan): Make this a LIFO queue that has different sizes for each
// encoder implementation.
const size_t kMaxNumberOfFramesInEncode = 10;

void NotifyEncoderSupportKnown(base::OnceClosure callback) {
  if (!Platform::Current()) {
    DLOG(ERROR) << "Couldn't access the render thread";
    std::move(callback).Run();
    return;
  }

  media::GpuVideoAcceleratorFactories* const gpu_factories =
      Platform::Current()->GetGpuFactories();
  if (!gpu_factories || !gpu_factories->IsGpuVideoEncodeAcceleratorEnabled()) {
    DLOG(ERROR) << "Couldn't initialize GpuVideoAcceleratorFactories";
    std::move(callback).Run();
    return;
  }

  gpu_factories->NotifyEncoderSupportKnown(std::move(callback));
}

// Obtains video encode accelerator's supported profiles.
media::VideoEncodeAccelerator::SupportedProfiles GetVEASupportedProfiles() {
  if (!Platform::Current()) {
    DLOG(ERROR) << "Couldn't access the render thread";
    return media::VideoEncodeAccelerator::SupportedProfiles();
  }

  media::GpuVideoAcceleratorFactories* const gpu_factories =
      Platform::Current()->GetGpuFactories();
  if (!gpu_factories || !gpu_factories->IsGpuVideoEncodeAcceleratorEnabled()) {
    DLOG(ERROR) << "Couldn't initialize GpuVideoAcceleratorFactories";
    return media::VideoEncodeAccelerator::SupportedProfiles();
  }
  return gpu_factories->GetVideoEncodeAcceleratorSupportedProfiles().value_or(
      media::VideoEncodeAccelerator::SupportedProfiles());
}

VideoTrackRecorderImpl::CodecEnumerator* GetCodecEnumerator() {
  static VideoTrackRecorderImpl::CodecEnumerator* enumerator =
      new VideoTrackRecorderImpl::CodecEnumerator(GetVEASupportedProfiles());
  return enumerator;
}

void UmaHistogramForCodec(bool uses_acceleration, CodecId codec_id) {
  // These values are persisted to logs. Entries should not be renumbered and
  // numeric values should never be reused.
  // (kMaxValue being the only exception, as it does not map to a logged value,
  // and should be renumbered as new values are inserted.)
  enum class VideoTrackRecorderCodecHistogram : uint8_t {
    kUnknown = 0,
    kVp8Sw = 1,
    kVp8Hw = 2,
    kVp9Sw = 3,
    kVp9Hw = 4,
    kH264Sw = 5,
    kH264Hw = 6,
    kAv1Sw = 7,
    kAv1Hw = 8,
    kHevcHw = 9,
    kMaxValue = kHevcHw,
  };
  auto histogram = VideoTrackRecorderCodecHistogram::kUnknown;
  if (uses_acceleration) {
    switch (codec_id) {
      case CodecId::kVp8:
        histogram = VideoTrackRecorderCodecHistogram::kVp8Hw;
        break;
      case CodecId::kVp9:
        histogram = VideoTrackRecorderCodecHistogram::kVp9Hw;
        break;
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
      case CodecId::kH264:
        histogram = VideoTrackRecorderCodecHistogram::kH264Hw;
        break;
#endif
      case CodecId::kAv1:
        histogram = VideoTrackRecorderCodecHistogram::kAv1Hw;
        break;
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
      case CodecId::kHevc:
        histogram = VideoTrackRecorderCodecHistogram::kHevcHw;
        break;
#endif
      case CodecId::kLast:
        break;
    }
  } else {
    switch (codec_id) {
      case CodecId::kVp8:
        histogram = VideoTrackRecorderCodecHistogram::kVp8Sw;
        break;
      case CodecId::kVp9:
        histogram = VideoTrackRecorderCodecHistogram::kVp9Sw;
        break;
#if BUILDFLAG(USE_PROPRIETARY_CODECS)
      case CodecId::kH264:
        histogram = VideoTrackRecorderCodecHistogram::kH264Sw;
        break;
#endif
      case CodecId::kAv1:
        histogram = VideoTrackRecorderCodecHistogram::kAv1Sw;
        break;
#if BUILDFLAG(ENABLE_HEVC_PARSER_AND_HW_DECODER)
      case CodecId::kHevc:
#endif
      case CodecId::kLast:
        break;
    }
  }
  UMA_HISTOGRAM_ENUMERATION("Media.MediaRecorder.Codec", histogram);
}

// Returns the default codec profile for |codec_id|.
std::optional<media::VideoCodecProfile> GetMediaVideoCodecProfileForSwEncoder(
    VideoTrackRecorder::CodecId codec_id) {
  switch (codec_id) {
#if BUILDFLAG(USE_PROPRIETARY_CODECS) && BUILDFLAG(ENABLE_OPENH264)
    case CodecId::kH264:
      return media::H264PROFILE_BASELINE;
#endif  // BUILDFLAG(ENABLE_OPENH264)
    case CodecId::kVp8:
      return media::VP8PROFILE_ANY;
    case CodecId::kVp9:
      return media::VP9PROFILE_MIN;
#if BUILDFLAG(ENABLE_LIBAOM)
    case CodecId::kAv1:
      return media::AV1PROFILE_MIN;
#endif  // BUILDFLAG(ENABLE_LIBAOM)
    default:
      return std::nullopt;
  }
}

bool IsSoftwareEncoderAvailable(CodecId codec_id) {
  return GetMediaVideoCodecProfileForSwEncoder(codec_id).has_value();
}

std::optional<media::VideoCodecProfile> GetMediaVideoCodecProfile(
    VideoTrackRecorder::CodecProfile codec_profile,
    const gfx::Size& input_size,
    bool allow_vea_encoder) {
  const bool can_use_vea = VideoTrackRecorderImpl::CanUseAcceleratedEncoder(
      codec_profile, input_size.width(), input_size.height());
  if (can_use_vea && allow_vea_encoder) {
    // Hardware encoder will be used.
    // If |codec_profile.profile| is specified by a client, then the returned
    // profile is the same as it.
    // Otherwise, CanUseAcceleratedEncoder() fills the codec profile available
    // with a hardware encoder.
    CHECK(codec_profile.profile.has_value());
    return codec_profile.profile;
  } else if (!IsSoftwareEncoderAvailable(codec_profile.codec_id)) {
    LOG(ERROR) << "Can't use VEA, but must be able to use VEA, codec_id="
               << static_cast<int>(codec_profile.codec_id);
    return std::nullopt;
  }
  // Software encoder will be used.
  return codec_profile.profile.value_or(
      GetMediaVideoCodecProfileForSwEncoder(codec_profile.codec_id).value());
}

MediaRecorderEncoderWrapper::CreateEncoderCB
GetCreateHardwareVideoEncoderCallback(CodecId codec_id) {
  auto required_encoder_type =
      media::MayHaveAndAllowSelectOSSoftwareEncoder(
          MediaVideoCodecFromCodecId(codec_id))
          ? media::VideoEncodeAccelerator::Config::EncoderType::kNoPreference
          : media::VideoEncodeAccelerator::Config::EncoderType::kHardware;
  return ConvertToBaseRepeatingCallback(WTF::CrossThreadBindRepeating(
      [](media::VideoEncodeAccelerator::Config::EncoderType
             required_encoder_type,
         media::GpuVideoAcceleratorFactories* gpu_factories)
          -> std::unique_ptr<media::VideoEncoder> {
        return std::make_unique<media::AsyncDestroyVideoEncoder<
            media::VideoEncodeAcceleratorAdapter>>(
            std::make_unique<media::VideoEncodeAcceleratorAdapter>(
                gpu_factories, std::make_unique<media::NullMediaLog>(),
                base::SequencedTaskRunner::GetCurrentDefault(),
                required_encoder_type));
      },
      required_encoder_type));
}

MediaRecorderEncoderWrapper::CreateEncoderCB
GetCreateSoftwareVideoEncoderCallback(CodecId codec_id) {
  switch (codec_id) {
#if BUILDFLAG(ENABLE_OPENH264)
    case CodecId::kH264:
      return ConvertToBaseRepeatingCallback(WTF::CrossThreadBindRepeating(
          [](media::GpuVideoAcceleratorFactories* /*gpu_factories*/)
              -> std::unique_ptr<media::VideoEncoder> {
            return std::make_unique<media::OpenH264VideoEncoder>();
          }));
#endif  // BUILDFLAG(ENABLE_OPENH264)
#if BUILDFLAG(ENABLE_LIBVPX)
    case CodecId::kVp8:
    case CodecId::kVp9:
      return ConvertToBaseRepeatingCallback(WTF::CrossThreadBindRepeating(
          [](media::GpuVideoAcceleratorFactories* /*gpu_factories*/)
              -> std::unique_ptr<media::VideoEncoder> {
            return std::make_unique<media::VpxVideoEncoder>();
          }));
#endif
#if BUILDFLAG(ENABLE_LIBAOM)
    case CodecId::kAv1:
      return ConvertToBaseRepeatingCallback(WTF::CrossThreadBindRepeating(
          [](media::GpuVideoAcceleratorFactories* /*gpu_factories*/)
              -> std::unique_ptr<media::VideoEncoder> {
            return std::make_unique<media::Av1VideoEncoder>();
          }));
#endif  // BUILDFLAG(ENABLE_LIBAOM)
    default:
      NOTREACHED() << "Unsupported codec=" << static_cast<int>(codec_id);
  }
}
}  // anonymous namespace

VideoTrackRecorder::VideoTrackRecorder(
    scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner,
    WeakCell<CallbackInterface>* callback_interface)
    : TrackRecorder(base::BindPostTask(
          main_thread_task_runner,
          WTF::BindOnce(&CallbackInterface::OnSourceReadyStateChanged,
                        WrapPersistent(callback_interface)))),
      main_thread_task_runner_(std::move(main_thread_task_runner)),
      callback_interface_(callback_interface) {
  CHECK(main_thread_task_runner_);
}

VideoTrackRecorderImpl::CodecProfile::CodecProfile(CodecId codec_id)
    : codec_id(codec_id) {}

VideoTrackRecorderImpl::CodecProfile::CodecProfile(
    CodecId codec_id,
    std::optional<media::VideoCodecProfile> opt_profile,
    std::optional<media::VideoCodecLevel> opt_level)
    : codec_id(codec_id), profile(opt_profile), level(opt_level) {}

VideoTrackRecorderImpl::CodecProfile::CodecProfile(
    CodecId codec_id,
    media::VideoCodecProfile profile,
    media::VideoCodecLevel level)
    : codec_id(codec_id), profile(profile), level(level) {}

VideoTrackRecorderImpl::CodecEnumerator::CodecEnumerator(
    const media::VideoEncodeAccelerator::SupportedProfiles&
        vea_supported_profiles) {
  for (const auto& supported_profile : vea_supported_profiles) {
    const media::VideoCodecProfile codec = supported_profile.profile;
    for (auto& codec_id_and_profile : kPreferredCodecIdAndVEAProfiles) {
      if (codec >= codec_id_and_profile.min_profile &&
          codec <= codec_id_and_profile.max_profile) {
        DVLOG(2) << "Accelerated codec found: " << media::GetProfileName(codec)
                 << ", min_resolution: "
                 << supported_profile.min_resolution.ToString()
                 << ", max_resolution: "
                 << supported_profile.max_resolution.ToString()
                 << ", max_framerate: "
                 << supported_profile.max_framerate_numerator << "/"
                 << supported_profile.max_framerate_denominator;
        auto iter = supported_profiles_.find(codec_id_and_profile.codec_id);
        if (iter == supported_profiles_.end()) {
          auto result = supported_profiles_.insert(
              codec_id_and_profile.codec_id,
              media::VideoEncodeAccelerator::SupportedProfiles());
          result.stored_value->value.push_back(supported_profile);
        } else {
          iter->value.push_back(supported_profile);
        }
        if (preferred_codec_id_ == CodecId::kLast) {
          preferred_codec_id_ = codec_id_and_profile.codec_id;
        }
      }
    }
  }
}

VideoTrackRecorderImpl::CodecEnumerator::~CodecEnumerator() = default;

std::pair<media::VideoCodecProfile, bool>
VideoTrackRecorderImpl::CodecEnumerator::FindSupportedVideoCodecProfile(
    CodecId codec,
    media::VideoCodecProfile profile) const {
  const auto profiles = supported_profiles_.find(codec);
  if (profiles == supported_profiles_.end()) {
    return {media::VIDEO_CODEC_PROFILE_UNKNOWN, false};
  }
  for (const auto& p : profiles->value) {
    if (p.profile == profile) {
      const bool vbr_support =
          p.rate_control_modes & media::VideoEncodeAccelerator::kVariableMode;
      return {profile, vbr_support};
    }
  }
  return {media::VIDEO_CODEC_PROFILE_UNKNOWN, false};
}

VideoTrackRecorderImpl::CodecId
VideoTrackRecorderImpl::CodecEnumerator::GetPreferredCodecId(
    MediaTrackContainerType type) const {
  if (preferred_codec_id_ == CodecId::kLast) {
    if (type == MediaTrackContainerType::kVideoMp4 ||
        type == MediaTrackContainerType::kAudioMp4) {
      return CodecId::kVp9;
    }
    return CodecId::kVp8;
  }

  return preferred_codec_id_;
}

std::pair<media::VideoCodecProfile, bool>
VideoTrackRecorderImpl::CodecEnumerator::GetFirstSupportedVideoCodecProfile(
    CodecId codec) const {
  const auto profile = supported_profiles_.find(codec);
  if (profile == supported_profiles_.end()) {
    return {media::VIDEO_CODEC_PROFILE_UNKNOWN, false};
  }

  const auto& supported_profile = profile->value.front();
  const bool vbr_support = supported_profile.rate_control_modes &
                           media::VideoEncodeAccelerator::kVariableMode;
  return {supported_profile.profile, vbr_support};
}

media::VideoEncodeAccelerator::SupportedProfiles
VideoTrackRecorderImpl::CodecEnumerator::GetSupportedProfiles(
    CodecId codec) const {
  const auto profile = supported_profiles_.find(codec);
  return profile == supported_profiles_.end()
             ? media::VideoEncodeAccelerator::SupportedProfiles()
             : profile->value;
}

VideoTrackRecorderImpl::Counter::Counter() : count_(0u) {}

VideoTrackRecorderImpl::Counter::~Counter() = default;

void VideoTrackRecorderImpl::Counter::IncreaseCount() {
  count_++;
}

void VideoTrackRecorderImpl::Counter::DecreaseCount() {
  count_--;
}

base::WeakPtr<VideoTrackRecorderImpl::Counter>
VideoTrackRecorderImpl::Counter::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

VideoTrackRecorderImpl::Encoder::Encoder(
    scoped_refptr<base::SequencedTaskRunner> encoding_task_runner,
    const OnEncodedVideoCB& on_encoded_video_cb,
    uint32_t bits_per_second)
    : encoding_task_runner_(std::move(encoding_task_runner)),
      on_encoded_video_cb_(on_encoded_video_cb),
      bits_per_second_(bits_per_second),
      num_frames_in_encode_(
          std::make_unique<VideoTrackRecorderImpl::Counter>()) {
  CHECK(encoding_task_runner_);
  DCHECK(!on_encoded_video_cb_.is_null());
}

VideoTrackRecorderImpl::Encoder::~Encoder() = default;

void VideoTrackRecorderImpl::Encoder::InitializeEncoder(
    KeyFrameRequestProcessor::Configuration key_frame_config,
    std::unique_ptr<media::VideoEncoderMetricsProvider> metrics_provider,
    size_t frame_buffer_pool_limit) {
  key_frame_processor_.UpdateConfig(key_frame_config);
  metrics_provider_ = std::move(metrics_provider);
  frame_buffer_pool_limit_ = frame_buffer_pool_limit;
  Initialize();
}

void VideoTrackRecorderImpl::Encoder::Initialize() {}

void VideoTrackRecorderImpl::Encoder::StartFrameEncode(
    scoped_refptr<media::VideoFrame> video_frame,
    base::TimeTicks capture_timestamp) {
  if (paused_) {
    return;
  }
  auto timestamp = video_frame->metadata().capture_begin_time.value_or(
      video_frame->metadata().reference_time.value_or(capture_timestamp));
  bool force_key_frame =
      awaiting_first_frame_ ||
      key_frame_processor_.OnFrameAndShouldRequestKeyFrame(timestamp);
  if (force_key_frame) {
    key_frame_processor_.OnKeyFrame(timestamp);
  }
  awaiting_first_frame_ = false;

  if (num_frames_in_encode_->count() >
      std::min(kMaxNumberOfFramesInEncode, frame_buffer_pool_limit_)) {
    LOCAL_HISTOGRAM_BOOLEAN("Media.MediaRecorder.DroppingFrameTooManyInEncode",
                            true);
    DLOG(WARNING) << "Too many frames are queued up. Dropping this one.";
    return;
  }

  const bool is_format_supported =
      (video_frame->format() == media::PIXEL_FORMAT_NV12 &&
       video_frame->HasMappableGpuBuffer()) ||
      (video_frame->IsMappable() &&
       (video_frame->format() == media::PIXEL_FORMAT_I420 ||
        video_frame->format() == media::PIXEL_FORMAT_I420A));
  scoped_refptr<media::VideoFrame> frame = std::move(video_frame);
  // First, pixel format is converted to NV12, I420 or I420A.
  if (!is_format_supported) {
    frame = MaybeProvideEncodableFrame(std::move(frame));
  }
  if (frame && frame->format() == media::PIXEL_FORMAT_I420A &&
      !CanEncodeAlphaChannel()) {
    CHECK(!frame->HasMappableGpuBuffer());
    // Drop alpha channel if the encoder does not support it yet.
    frame = media::WrapAsI420VideoFrame(std::move(frame));
  }

  if (!frame) {
    // Explicit reasons for the frame drop are already logged.
    return;
  }
  frame->AddDestructionObserver(base::BindPostTask(
      encoding_task_runner_,
      WTF::BindOnce(&VideoTrackRecorderImpl::Counter::DecreaseCount,
                    num_frames_in_encode_->GetWeakPtr())));
  num_frames_in_encode_->IncreaseCount();
  EncodeFrame(std::move(frame), timestamp,
              request_key_frame_for_testing_ || force_key_frame);
  request_key_frame_for_testing_ = false;
}

scoped_refptr<media::VideoFrame>
VideoTrackRecorderImpl::Encoder::MaybeProvideEncodableFrame(
    scoped_refptr<media::VideoFrame> video_frame) {
  DVLOG(3) << __func__;
  scoped_refptr<media::VideoFrame> frame;
  const bool is_opaque = media::IsOpaque(video_frame->format());
  if (media::IsRGB(video_frame->format()) && video_frame->IsMappable()) {
    // It's a mapped RGB frame, no readback needed,
    // all we need is to convert RGB to I420
    auto visible_rect = video_frame->visible_rect();
    frame = frame_pool_.CreateFrame(
        is_opaque ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A,
        visible_rect.size(), visible_rect, visible_rect.size(),
        video_frame->timestamp());
    if (!frame ||
        !frame_converter_.ConvertAndScale(*video_frame, *frame).is_ok()) {
      // Send black frames (yuv = {0, 127, 127}).
      DLOG(ERROR) << "Can't convert RGB to I420";
      frame = media::VideoFrame::CreateColorFrame(
          video_frame->visible_rect().size(), 0u, 0x80, 0x80,
          video_frame->timestamp());
    }
    return frame;
  }

  // |encoder_thread_context_| is null if the GPU process has crashed or isn't
  // there
  if (!encoder_thread_context_) {
    // PaintCanvasVideoRenderer requires these settings to work.
    Platform::ContextAttributes attributes;
    attributes.enable_raster_interface = true;
    attributes.prefer_low_power_gpu = true;

    // TODO(crbug.com/1240756): This line can be removed once OOPR-Canvas has
    // shipped on all platforms
    attributes.support_grcontext = true;

    Platform::GraphicsInfo info;
    encoder_thread_context_ =
        VideoTrackRecorderImplContextProvider::CreateOffscreenGraphicsContext(
            attributes, &info, KURL("chrome://VideoTrackRecorderImpl"));

    if (encoder_thread_context_ &&
        !encoder_thread_context_->BindToCurrentSequence()) {
      encoder_thread_context_ = nullptr;
    }
  }

  if (!encoder_thread_context_) {
    // Send black frames (yuv = {0, 127, 127}).
    frame = media::VideoFrame::CreateColorFrame(
        video_frame->visible_rect().size(), 0u, 0x80, 0x80,
        video_frame->timestamp());
  } else {
    // Accelerated decoders produce ARGB/ABGR texture-backed frames (see
    // https://crbug.com/585242), fetch them using a PaintCanvasVideoRenderer.
    // Additionally, macOS accelerated decoders can produce XRGB content
    // and are treated the same way.
    //
    // This path is also used for less common formats like I422, I444, and
    // high bit depth pixel formats.

    const gfx::Size& old_visible_size = video_frame->visible_rect().size();
    gfx::Size new_visible_size = old_visible_size;

    media::VideoRotation video_rotation = media::VIDEO_ROTATION_0;
    if (video_frame->metadata().transformation) {
      video_rotation = video_frame->metadata().transformation->rotation;
    }

    if (video_rotation == media::VIDEO_ROTATION_90 ||
        video_rotation == media::VIDEO_ROTATION_270) {
      new_visible_size.SetSize(old_visible_size.height(),
                               old_visible_size.width());
    }

    frame = frame_pool_.CreateFrame(
        is_opaque ? media::PIXEL_FORMAT_I420 : media::PIXEL_FORMAT_I420A,
        new_visible_size, gfx::Rect(new_visible_size), new_visible_size,
        video_frame->timestamp());

    const SkImageInfo info = SkImageInfo::MakeN32(
        frame->visible_rect().width(), frame->visible_rect().height(),
        is_opaque ? kOpaque_SkAlphaType : kPremul_SkAlphaType);

    // Create |surface_| if it doesn't exist or incoming resolution has changed.
    if (!canvas_ || canvas_->imageInfo().width() != info.width() ||
        canvas_->imageInfo().height() != info.height()) {
      bitmap_.allocPixels(info);
      canvas_ = std::make_unique<cc::SkiaPaintCanvas>(bitmap_);
    }
    if (!video_renderer_) {
      video_renderer_ = std::make_unique<media::PaintCanvasVideoRenderer>();
    }

    encoder_thread_context_->CopyVideoFrame(video_renderer_.get(),
                                            video_frame.get(), canvas_.get());

    SkPixmap pixmap;
    if (!bitmap_.peekPixels(&pixmap)) {
      DLOG(ERROR) << "Error trying to map PaintSurface's pixels";
      return nullptr;
    }

#if SK_PMCOLOR_BYTE_ORDER(R, G, B, A)
    const uint32_t source_pixel_format = libyuv::FOURCC_ABGR;
#else
    const uint32_t source_pixel_format = libyuv::FOURCC_ARGB;
#endif
    if (libyuv::ConvertToI420(
            static_cast<uint8_t*>(pixmap.writable_addr()),
            pixmap.computeByteSize(),
            frame->GetWritableVisibleData(media::VideoFrame::Plane::kY),
            frame->stride(media::VideoFrame::Plane::kY),
            frame->GetWritableVisibleData(media::VideoFrame::Plane::kU),
            frame->stride(media::VideoFrame::Plane::kU),
            frame->GetWritableVisibleData(media::VideoFrame::Plane::kV),
            frame->stride(media::VideoFrame::Plane::kV), 0 /* crop_x */,
            0 /* crop_y */, pixmap.width(), pixmap.height(),
            old_visible_size.width(), old_visible_size.height(),
            MediaVideoRotationToRotationMode(video_rotation),
            source_pixel_format) != 0) {
      DLOG(ERROR) << "Error converting frame to I420";
      return nullptr;
    }
    if (!is_opaque) {
      // Alpha has the same alignment for both ABGR and ARGB.
      libyuv::ARGBExtractAlpha(
          static_cast<uint8_t*>(pixmap.writable_addr()),
          static_cast<int>(pixmap.rowBytes()) /* stride */,
          frame->GetWritableVisibleData(media::VideoFrame::Plane::kA),
          frame->stride(media::VideoFrame::Plane::kA), pixmap.width(),
          pixmap.height());
    }
  }
  return frame;
}

void VideoTrackRecorderImpl::Encoder::SetPaused(bool paused) {
  paused_ = paused;
}

bool VideoTrackRecorderImpl::Encoder::CanEncodeAlphaChannel() const {
  return false;
}

scoped_refptr<media::VideoFrame>
VideoTrackRecorderImpl::Encoder::ConvertToI420ForSoftwareEncoder(
    scoped_refptr<media::VideoFrame> frame) {
  DCHECK_EQ(frame->format(), media::VideoPixelFormat::PIXEL_FORMAT_NV12);

  if (frame->HasMappableGpuBuffer()) {
    frame = media::ConvertToMemoryMappedFrame(frame);
  }
  if (!frame) {
    return nullptr;
  }

  scoped_refptr<media::VideoFrame> i420_frame = frame_pool_.CreateFrame(
      media::VideoPixelFormat::PIXEL_FORMAT_I420, frame->coded_size(),
      frame->visible_rect(), frame->natural_size(), frame->timestamp());
  auto ret = libyuv::NV12ToI420(
      frame->data(0), frame->stride(0), frame->data(1), frame->stride(1),
      i420_frame->writable_data(media::VideoFrame::Plane::kY),
      i420_frame->stride(media::VideoFrame::Plane::kY),
      i420_frame->writable_data(media::VideoFrame::Plane::kU),
      i420_frame->stride(media::VideoFrame::Plane::kU),
      i420_frame->writable_data(media::VideoFrame::Plane::kV),
      i420_frame->stride(media::VideoFrame::Plane::kV),
      frame->coded_size().width(), frame->coded_size().height());
  if (ret) {
    return frame;
  }
  return i420_frame;
}

// static
VideoTrackRecorderImpl::CodecId VideoTrackRecorderImpl::GetPreferredCodecId(
    MediaTrackContainerType type) {
  return GetCodecEnumerator()->GetPreferredCodecId(type);
}

// static
bool VideoTrackRecorderImpl::CanUseAcceleratedEncoder(
    CodecProfile& codec_profile,
    size_t width,
    size_t height,
    double framerate) {
  if (IsSoftwareEncoderAvailable(codec_profile.codec_id)) {
    if (width < kVEAEncoderMinResolutionWidth) {
      return false;
    }
    if (height < kVEAEncoderMinResolutionHeight) {
      return false;
    }
  }

  const auto profiles =
      GetCodecEnumerator()->GetSupportedProfiles(codec_profile.codec_id);
  if (profiles.empty()) {
    return false;
  }

  for (const auto& profile : profiles) {
    if (profile.profile == media::VIDEO_CODEC_PROFILE_UNKNOWN) {
      return false;
    }
    // Skip other profiles if the profile is specified.
    if (codec_profile.profile && *codec_profile.profile != profile.profile) {
      continue;
    }
    // Skip if profile is OS software encoder profile and we don't allow use
    // OS software encoder.
    if (profile.is_software_codec &&
        !media::MayHaveAndAllowSelectOSSoftwareEncoder(
            media::VideoCodecProfileToVideoCodec(profile.profile))) {
      continue;
    }

    const gfx::Size& min_resolution = profile.min_resolution;
    DCHECK_GE(min_resolution.width(), 0);
    const size_t min_width = static_cast<size_t>(min_resolution.width());
    DCHECK_GE(min_resolution.height(), 0);
    const size_t min_height = static_cast<size_t>(min_resolution.height());

    const gfx::Size& max_resolution = profile.max_resolution;
    DCHECK_GE(max_resolution.width(), 0);
    const size_t max_width = static_cast<size_t>(max_resolution.width());
    DCHECK_GE(max_resolution.height(), 0);
    const size_t max_height = static_cast<size_t>(max_resolution.height());

    const bool width_within_range = max_width >= width && width >= min_width;
    const bool height_within_range =
        max_height >= height && height >= min_height;

    const bool valid_framerate =
        framerate * profile.max_framerate_denominator <=
        profile.max_framerate_numerator;

    if (width_within_range && height_within_range && valid_framerate) {
      // Record with the first found profile that satisfies the condition.
      codec_profile.profile = profile.profile;
      return true;
    }
  }
  return false;
}

VideoTrackRecorderImpl::VideoTrackRecorderImpl(
    scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner,
    CodecProfile codec_profile,
    MediaStreamComponent* track,
    WeakCell<CallbackInterface>* callback_interface,
    uint32_t bits_per_second,
    KeyFrameRequestProcessor::Configuration key_frame_config,
    size_t frame_buffer_pool_limit)
    : VideoTrackRecorder(std::move(main_thread_task_runner),
                         callback_interface),
      track_(track),
      key_frame_config_(key_frame_config),
      codec_profile_(codec_profile),
      bits_per_second_(bits_per_second),
      on_encoded_video_cb_(base::BindPostTask(
          main_thread_task_runner_,
          WTF::BindRepeating(&CallbackInterface::OnEncodedVideo,
                             WrapPersistent(callback_interface)))),
      frame_buffer_pool_limit_(frame_buffer_pool_limit) {
  TRACE_EVENT("media", "VideoTrackRecorderImpl::VideoTrac
```