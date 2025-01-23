Response:
The user wants a summary of the provided C++ code for `video_encoder.cc`. I need to identify the main functionalities of this file within the Chromium Blink rendering engine, particularly concerning video encoding using the WebCodecs API.

Here's a plan to address the user's request:

1. **Identify Core Functionality:**  The file's name and included headers suggest it handles the implementation of the `VideoEncoder` WebCodecs interface. Key aspects likely involve:
    - Accepting configuration parameters for video encoding.
    - Managing the underlying media encoder (hardware or software).
    - Handling input video frames.
    - Producing encoded video chunks.
    - Managing the lifecycle of the encoder.
2. **Relate to Web Technologies:**  Determine how this C++ code interacts with JavaScript, HTML, and CSS. The interaction will likely be through the WebCodecs API, which JavaScript uses to access encoder functionality.
3. **Analyze Logic and Data Flow:** Look for patterns in how the code processes input and generates output. This might involve analyzing function signatures, data structures, and control flow. Consider potential input configurations and their expected outputs.
4. **Identify Potential User Errors:** Based on the code's logic and the WebCodecs API, identify common mistakes developers might make when using the `VideoEncoder`.
5. **Trace User Operations:**  Outline the steps a web developer might take in JavaScript that would ultimately lead to the execution of this C++ code. This involves starting from the JavaScript API and working down to the native implementation.
6. **Summarize Functionality for Part 1:**  Provide a concise overview of the file's purpose based on the analysis above, focusing on the aspects covered in the provided code snippet.
```
这是目录为blink/renderer/modules/webcodecs/video_encoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/video_encoder.h"

#include <algorithm>
#include <string>

#include "base/containers/contains.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/clamped_math.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/trace_event/common/trace_event_common.h"
#include "base/trace_event/trace_event.h"
#include "components/viz/common/gpu/raster_context_provider.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "media/base/async_destroy_video_encoder.h"
#include "media/base/limits.h"
#include "media/base/media_log.h"
#include "media/base/mime_util.h"
#include "media/base/supported_types.h"
#include "media/base/svc_scalability_mode.h"
#include "media/base/timestamp_constants.h"
#include "media/base/video_codecs.h"
#include "media/base/video_color_space.h"
#include "media/base/video_encoder.h"
#include "media/base/video_util.h"
#include "media/media_buildflags.h"
#include "media/mojo/clients/mojo_video_encoder_metrics_provider.h"
#include "media/parsers/h264_level_limits.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "media/video/offloading_video_encoder.h"
#include "media/video/video_encode_accelerator_adapter.h"
#include "media/video/video_encoder_fallback.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_avc_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_video_chunk_metadata.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_hevc_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_svc_output_metadata.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_color_space_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options_for_av_1.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options_for_avc.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options_for_vp_9.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_support.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_pixel_format.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/modules/event_modules.h"
#include "third_party/blink/renderer/modules/webcodecs/array_buffer_util.h"
#include "third_party/blink/renderer/modules/webcodecs/background_readback.h"
#third_party/blink/renderer/modules/webcodecs/codec_state_helper.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_video_chunk.h"
#include "third_party/blink/renderer/modules/webcodecs/gpu_factories_retriever.h"
#include "third_party/blink/renderer/modules/webcodecs/video_color_space.h"
#include "third_party/blink/renderer/modules/webcodecs/video_encoder_buffer.h"
#include "third_party/blink/renderer/platform/bindings/enumeration_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_video_frame_pool.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/heap/heap_barrier_callback.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

#if BUILDFLAG(ENABLE_LIBAOM)
#include "media/video/av1_video_encoder.h"
#endif

#if BUILDFLAG(ENABLE_OPENH264)
#include "media/video/openh264_video_encoder.h"
#endif

#if BUILDFLAG(ENABLE_LIBVPX)
#include "media/video/vpx_video_encoder.h"
#endif

namespace WTF {

template <>
struct CrossThreadCopier<media::EncoderStatus>
    : public CrossThreadCopierPassThrough<media::EncoderStatus> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

using EncoderType = media::VideoEncodeAccelerator::Config::EncoderType;

namespace {

constexpr const char kCategory[] = "media";
// Controls if VideoEncoder will use timestamp from blink::VideoFrame
// instead of media::VideoFrame.
BASE_FEATURE(kUseBlinkTimestampForEncoding,
             "UseBlinkTimestampForEncoding",
             base::FEATURE_ENABLED_BY_DEFAULT);

// TODO(crbug.com/40215121): This is very similar to the method in
// video_frame.cc. It should probably be a function in video_types.cc.
media::VideoPixelFormat ToOpaqueMediaPixelFormat(media::VideoPixelFormat fmt) {
  switch (fmt) {
    case media::PIXEL_FORMAT_I420A:
      return media::PIXEL_FORMAT_I420;
    case media::PIXEL_FORMAT_YUV420AP10:
      return media::PIXEL_FORMAT_YUV420P10;
    case media::PIXEL_FORMAT_I422A:
      return media::PIXEL_FORMAT_I422;
    case media::PIXEL_FORMAT_YUV422AP10:
      return media::PIXEL_FORMAT_YUV422P10;
    case media::PIXEL_FORMAT_I444A:
      return media::PIXEL_FORMAT_I444;
    case media::PIXEL_FORMAT_YUV444AP10:
      return media::PIXEL_FORMAT_YUV444P10;
    case media::PIXEL_FORMAT_NV12A:
      return media::PIXEL_FORMAT_NV12;
    default:
      NOTIMPLEMENTED() << "Missing support for making " << fmt << " opaque.";
      return fmt;
  }
}

int ComputeMaxActiveEncodes(std::optional<int> frame_delay = std::nullopt,
                            std::optional<int> input_capacity = std::nullopt) {
  constexpr int kDefaultEncoderFrameDelay = 0;

  // The maximum number of input frames above the encoder frame delay that we
  // want to be able to enqueue in |media_encoder_|.
  constexpr int kDefaultEncoderExtraInputCapacity = 5;

  const int preferred_capacity =
      frame_delay.value_or(kDefaultEncoderFrameDelay) +
      kDefaultEncoderExtraInputCapacity;
  return input_capacity.has_value()
             ? std::min(preferred_capacity, input_capacity.value())
             : preferred_capacity;
}

media::VideoEncodeAccelerator::SupportedRateControlMode BitrateToSupportedMode(
    const media::Bitrate& bitrate) {
  switch (bitrate.mode()) {
    case media::Bitrate::Mode::kConstant:
      return media::VideoEncodeAccelerator::kConstantMode;
    case media::Bitrate::Mode::kVariable:
      return media::VideoEncodeAccelerator::kVariableMode
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_CHROMEOS)
             // On Android and ChromeOS we allow CBR-only encoders to be used
             // for VBR because most devices don't properly advertise support
             // for VBR encoding. In most cases they will initialize
             // successfully when configured for VBR.
             | media::VideoEncodeAccelerator::kConstantMode
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_CHROMEOS)
          ;

    case media::Bitrate::Mode::kExternal:
      return media::VideoEncodeAccelerator::kExternalMode;
  }
}

media::EncoderStatus IsAcceleratedConfigurationSupported(
    media::VideoCodecProfile profile,
    const media::VideoEncoder::Options& options,
    media::GpuVideoAcceleratorFactories* gpu_factories,
    EncoderType required_encoder_type) {
  if (!gpu_factories || !gpu_factories->IsGpuVideoEncodeAcceleratorEnabled()) {
    return media::EncoderStatus::Codes::kEncoderAccelerationSupportMissing;
  }

  // Hardware encoders don't currently support high bit depths or subsamplings
  // other than 4:2:0.
  if (options.subsampling.value_or(media::VideoChromaSampling::k420) !=
          media::VideoChromaSampling::k420 ||
      options.bit_depth.value_or(8) != 8) {
    return media::EncoderStatus::Codes::kEncoderUnsupportedConfig;
  }

  auto supported_profiles =
      gpu_factories->GetVideoEncodeAcceleratorSupportedProfiles().value_or(
          media::VideoEncodeAccelerator::SupportedProfiles());

  if (supported_profiles.empty()) {
    return media::EncoderStatus::Codes::kEncoderAccelerationSupportMissing;
  }

  bool found_supported_profile = false;
  for (auto& supported_profile : supported_profiles) {
    if (supported_profile.profile != profile) {
      continue;
    }

    if (supported_profile.is_software_codec) {
      if (required_encoder_type == EncoderType::kHardware) {
        continue;
      }
    } else if (required_encoder_type == EncoderType::kSoftware) {
      continue;
    }

    if (supported_profile.min_resolution.width() > options.frame_size.width() ||
        supported_profile.min_resolution.height() >
            options.frame_size.height()) {
      continue;
    }

    if (supported_profile.max_resolution.width() < options.frame_size.width() ||
        supported_profile.max_resolution.height() <
            options.frame_size.height()) {
      continue;
    }

    double max_supported_framerate =
        static_cast<double>(supported_profile.max_framerate_numerator) /
        supported_profile.max_framerate_denominator;
    if (options.framerate.has_value() &&
        options.framerate.value() > max_supported_framerate) {
      continue;
    }

    if (options.scalability_mode.has_value() &&
        !base::Contains(supported_profile.scalability_modes,
                        options.scalability_mode.value())) {
      continue;
    }

    if (options.bitrate.has_value()) {
      auto mode = BitrateToSupportedMode(options.bitrate.value());
      if (!(mode & supported_profile.rate_control_modes)) {
        continue;
      }
    }

    found_supported_profile = true;
    break;
  }
  return found_supported_profile
             ? media::EncoderStatus::Codes::kOk
             : media::EncoderStatus::Codes::kEncoderUnsupportedConfig;
}

VideoEncoderTraits::ParsedConfig* ParseConfigStatic(
    const VideoEncoderConfig* config,
    ExceptionState& exception_state) {
  auto* result = MakeGarbageCollected<VideoEncoderTraits::ParsedConfig>();

  if (config->codec().LengthWithStrippedWhiteSpace() == 0) {
    exception_state.ThrowTypeError("Invalid codec; codec is required.");
    return nullptr;
  }

  if (config->height() == 0 || config->width() == 0) {
    exception_state.ThrowTypeError(
        "Invalid size; height and width must be greater than zero.");
    return nullptr;
  }
  result->options.frame_size.SetSize(config->width(), config->height());

  if (config->alpha() == "keep") {
    result->not_supported_error_message =
        "Alpha encoding is not currently supported.";
    return result;
  }

  result->options.latency_mode =
      (config->latencyMode() == "quality")
          ? media::VideoEncoder::LatencyMode::Quality
          : media::VideoEncoder::LatencyMode::Realtime;

  if (config->hasContentHint()) {
    if (config->contentHint() == "detail" || config->contentHint() == "text") {
      result->options.content_hint = media::VideoEncoder::ContentHint::Screen;
    } else if (config->contentHint() == "motion") {
      result->options.content_hint = media::VideoEncoder::ContentHint::Camera;
    }
  }

  if (config->bitrateMode() == V8VideoEncoderBitrateMode::Enum::kQuantizer) {
    result->options.bitrate = media::Bitrate::ExternalRateControl();
  } else if (config->hasBitrate()) {
    uint32_t bps = base::saturated_cast<uint32_t>(config->bitrate());
    if (bps == 0) {
      exception_state.ThrowTypeError("Bitrate must be greater than zero.");
      return nullptr;
    }
    if (config->bitrateMode() == V8VideoEncoderBitrateMode::Enum::kConstant) {
      result->options.bitrate = media::Bitrate::ConstantBitrate(bps);
    } else {
      // VBR in media:Bitrate supports both target and peak bitrate.
      // Currently webcodecs doesn't expose peak bitrate
      // (assuming unconstrained VBR), here we just set peak as 10 times
      // target as a good enough way of expressing unconstrained VBR.
      result->options.bitrate = media::Bitrate::VariableBitrate(
          bps, base::ClampMul(bps, 10u).RawValue());
    }
  }

  if (config->hasDisplayWidth() && config->hasDisplayHeight()) {
    if (config->displayHeight() == 0 || config->displayWidth() == 0) {
      exception_state.ThrowTypeError(
          "Invalid display size; height and width must be greater than zero.");
      return nullptr;
    }
    result->display_size.emplace(config->displayWidth(),
                                 config->displayHeight());
  } else if (config->hasDisplayWidth() || config->hasDisplayHeight()) {
    exception_state.ThrowTypeError(
        "Invalid display size; both height and width must be set together.");
    return nullptr;
  }

  if (config->hasFramerate()) {
    constexpr double kMinFramerate = .0001;
    constexpr double kMaxFramerate = 1'000'000'000;
    if (std::isnan(config->framerate()) ||
        config->framerate() < kMinFramerate ||
        config->framerate() > kMaxFramerate) {
      result->not_supported_error_message = String::Format(
          "Unsupported framerate; expected range from %f to %f, received %f.",
          kMinFramerate, kMaxFramerate, config->framerate());
      return result;
    }
    result->options.framerate = config->framerate();
  } else {
    result->options.framerate =
        media::VideoEncodeAccelerator::kDefaultFramerate;
  }

  // https://w3c.github.io/webrtc-svc/
  if (config->hasScalabilityMode()) {
    if (config->scalabilityMode() == "L1T1") {
      result->options.scalability_mode = media::SVCScalabilityMode::kL1T1;
    } else if (config->scalabilityMode() == "L1T2") {
      result->options.scalability_mode = media::SVCScalabilityMode::kL1T2;
    } else if (config->scalabilityMode() == "L1T3") {
      result->options.scalability_mode = media::SVCScalabilityMode::kL1T3;
    } else if (config->scalabilityMode() == "manual") {
      result->options.manual_reference_buffer_control = true;
    } else {
      result->not_supported_error_message =
          String::Format("Unsupported scalabilityMode: %s",
                         config->scalabilityMode().Utf8().c_str());
      return result;
    }
  }

  // The IDL defines a default value of "no-preference".
  DCHECK(config->hasHardwareAcceleration());

  result->hw_pref = StringToHardwarePreference(
      IDLEnumAsString(config->hardwareAcceleration()));

  result->codec = media::VideoCodec::kUnknown;
  result->profile = media::VIDEO_CODEC_PROFILE_UNKNOWN;
  result->level = 0;
  result->codec_string = config->codec();

  auto parse_result = media::ParseVideoCodecString(
      "", config->codec().Utf8(), /*allow_ambiguous_matches=*/false);
  if (!parse_result) {
    return result;
  }

  // Some codec strings provide color space info, but for WebCodecs this is
  // ignored. Instead, the VideoFrames given to encode() are the source of truth
  // for input color space. Note also that the output color space is up to the
  // underlying codec impl. See https://github.com/w3c/webcodecs/issues/345.
  result->codec = parse_result->codec;
  result->profile = parse_result->profile;
  result->level = parse_result->level;
  result->options.subsampling = parse_result->subsampling;
  result->options.bit_depth = parse_result->bit_depth;

  // Ideally which profile supports a given subsampling would be checked by
  // ParseVideoCodecString() above. Unfortunately, ParseVideoCodecString() is
  // shared by many paths and enforcing profile and subsampling broke several
  // sites. The error messages below are more helpful anyways.
  switch (result->codec) {
    case media::VideoCodec::kH264: {
      if (config->hasAvc()) {
        std::string avc_format =
            IDLEnumAsString(config->avc()->format()).Utf8();
        if (avc_format == "avc") {
          result->options.avc.produce_annexb = false;
        } else if (avc_format == "annexb") {
          result->options.avc.produce_annexb = true;
        } else {
          NOTREACHED();
        }
      }
      break;
    }
    case media::VideoCodec::kHEVC: {
      if (config->hasHevc()) {
        std::string hevc_format =
            IDLEnumAsString(config->hevc()->format()).Utf8();
        if (hevc_format == "hevc") {
          result->options.hevc.produce_annexb = false;
        } else if (hevc_format == "annexb") {
          result->options.hevc.produce_annexb = true;
        } else {
          NOTREACHED();
        }
      }
      break;
    }
    default:
      break;
  }

  return result;
}

bool VerifyCodecSupportStatic(VideoEncoderTraits::ParsedConfig* config,
                              String* js_error_message) {
  if (config->not_supported_error_message) {
    *js_error_message = *config->not_supported_error_message;
    return false;
  }

  const auto& frame_size = config->options.frame_size;
  if (frame_size.height() > media::limits::kMaxDimension) {
    *js_error_message = String::Format(
        "Invalid height; expected range from %d to %d, received %d.", 1,
        media::limits::kMaxDimension, frame_size.height());
    return false;
  }
  if (frame_size.width() > media::limits::kMaxDimension) {
    *js_error_message = String::Format(
        "Invalid width; expected range from %d to %d, received %d.", 1,
        media::limits::kMaxDimension, frame_size.width());
    return false;
  }
  if (frame_size.Area64() > media::limits::kMaxCanvas) {
    *js_error_message = String::Format(
        "Invalid resolution; expected range from %d to %d, "
        "received %" PRIu64
        " (%d * "
        "%d).",
        1, media::limits::kMaxCanvas, frame_size.Area64(), frame_size.width(),
        frame_size.height());
    return false;
  }

  switch (config->codec) {
    case media::VideoCodec::kAV1:
    case media::VideoCodec::kVP8:
    case media::VideoCodec::kVP9:
      break;
#if BUILDFLAG(ENABLE_PLATFORM_HEVC)
    case media::VideoCodec::kHEVC:
      if (config->profile != media::VideoCodecProfile::HEVCPROFILE_MAIN) {
        *js_error_message = "Unsupported hevc profile.";
        return false;
      }
      break;
#endif

    case media::VideoCodec::kH264: {
      if (config->options.frame_size.width() % 2 != 0 ||
          config->options.frame_size.height() % 2 != 0) {
        *js_error_message = "H264 only supports even sized frames.";
        return false;
      }

      // Note: This calculation is incorrect for interlaced or MBAFF encoding;
      // but we don't support those and likely never will.
      gfx::Size coded_size(base::bits::AlignUpDeprecatedDoNotUse(
                               config->options.frame_size.width(), 16),
                           base::bits::AlignUpDeprecatedDoNotUse(
                               config->options.frame_size.height(), 16));
      uint64_t coded_area = coded_size.Area64();
      uint64_t max_coded_area =
          media::H264LevelToMaxFS(config->level) * 16ull * 16ull;
      if (coded_area > max_coded_area) {
        *js_error_message = String::Format(
            "The provided resolution (%s) has a coded area "
            "(%d*%d=%" PRIu64 ") which exceeds the maximum coded area (%" PRIu64
            ") supported by the AVC level (%1.1f) indicated "
            "by the codec string (0x%02X). You must either "
            "specify a lower resolution or higher AVC level.",
            config->options.frame_size.ToString().c_str(), coded_size.width(),
            coded_size.height(), coded_area, max_coded_area,
            config->level / 10.0f, config->level);
        return false;
      }
      break;
    }

    default:
      *js_error_message = "Unsupported codec type.";
      return false;
  }

  return true;
}

VideoEncoderConfig* CopyConfig(
    const VideoEncoderConfig& config,
    const VideoEncoderTraits::ParsedConfig& parsed_config) {
  auto* result = VideoEncoderConfig::Create();
  result->setCodec(config.codec());
  result->setWidth(config.width());
  result->setHeight(config.height());

  if (config.hasDisplayWidth())
    result->setDisplayWidth(config.displayWidth());

  if (config.hasDisplayHeight())
    result->setDisplayHeight(config.displayHeight());

  if (config.hasFramerate())
    result->setFramerate(config.framerate());

  if (config.hasBitrate())
    result->setBitrate(config.bitrate());

  if (config.hasScalabilityMode())
    result->setScalabilityMode(config.scalabilityMode());

  if (config.hasHardwareAcceleration())
    result->setHardwareAcceleration(config.hardwareAcceleration());

  if (config.hasAlpha())
    result->setAlpha(config.alpha());

  if (config.hasBitrateMode())
    result->setBitrateMode(config.bitrateMode());

  if (config.hasLatencyMode())
    result->setLatencyMode(config.latencyMode());

  if (config.hasContentHint()) {
    result->setContentHint(config.contentHint());
  }

  if (config.hasAvc() && config.avc()->hasFormat()) {
    auto* avc = AvcEncoderConfig::Create();
    avc->setFormat(config.avc()->format());
    result->setAvc(avc);
  }

  if (config.hasHevc() && config.hevc()->hasFormat()) {
    auto* hevc = HevcEncoderConfig::Create();
    hevc->setFormat(config.hevc()->format());
    result->setHevc(hevc);
  }

  return result;
}

bool CanUseGpuMemoryBufferReadback(media::VideoPixelFormat format,
                                   bool force_opaque) {
  // GMB readback only works with NV12, so only opaque buffers can be used.
  return (format == media::PIXEL_FORMAT_XBGR ||
          format == media::PIXEL_FORMAT_XRGB ||
          (force_opaque && (format == media::PIXEL_FORMAT_ABGR ||
                            format == media::PIXEL_FORMAT_ARGB))) &&
         WebGraphicsContext3DVideoFramePool::
             IsGpuMemoryBufferReadbackFromTextureEnabled();
}

EncoderType GetRequiredEncoderType(media::VideoCodecProfile profile,
                                   HardwarePreference hw_pref) {
  if (hw_pref != HardwarePreference::kPreferHardware &&
      media::MayHaveAndAllowSelectOSSoftwareEncoder(
          media::VideoCodecProfileToVideoCodec(profile))) {
    return hw_pref == HardwarePreference::kPreferSoftware
               ? EncoderType::kSoftware
               : EncoderType::kNoPreference;
  }
  return EncoderType::kHardware;
}

}  // namespace

// static
const char* VideoEncoderTraits::GetName() {
  return "VideoEncoder";
}

String VideoEncoderTraits::ParsedConfig::ToString() {
  return String::Format(
      "{codec: %s, profile: %s, level: %d, hw_pref: %s, "
      "options: {%s}, codec_string: %s, display_size: %s}",
      media::GetCodecName(codec).c_str(),
      media::GetProfileName(profile).c_str(), level,
      HardwarePreferenceToString(hw_pref).Utf8().c_str(),
      options.ToString().c_str(), codec_string.Utf8().c_str(),
      display_size ? display_size->ToString().c_str() : "");
}

// static
VideoEncoder* VideoEncoder::Create(ScriptState* script_state,
                                   const VideoEncoderInit* init,
                                   ExceptionState& exception_state) {
  auto* result =
      MakeGarbageCollected<VideoEncoder>(script_state, init, exception_state);
  return exception_state.HadException() ? nullptr : result;
}

VideoEncoder::VideoEncoder(ScriptState* script_state,
                           const VideoEncoderInit* init,
                           ExceptionState& exception_state)
    : Base(script_state, init, exception_state),
      max_active_encodes_(ComputeMaxActiveEncodes()) {
  UseCounter::Count(ExecutionContext::From(script_state),
                    WebFeature::kWebCodecs);
}

VideoEncoder::~VideoEncoder() = default;

VideoEncoder::ParsedConfig* VideoEncoder::ParseConfig(
    const VideoEncoderConfig* config,
    ExceptionState& exception_state) {
  return ParseConfigStatic(config, exception_state);
}

bool VideoEncoder::VerifyCodecSupport(ParsedConfig* config,
                                      String* js_error_message) {
  return VerifyCodecSupportStatic(config, js_
### 提示词
```
这是目录为blink/renderer/modules/webcodecs/video_encoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webcodecs/video_encoder.h"

#include <algorithm>
#include <string>

#include "base/containers/contains.h"
#include "base/format_macros.h"
#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/clamped_math.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/trace_event/common/trace_event_common.h"
#include "base/trace_event/trace_event.h"
#include "components/viz/common/gpu/raster_context_provider.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "media/base/async_destroy_video_encoder.h"
#include "media/base/limits.h"
#include "media/base/media_log.h"
#include "media/base/mime_util.h"
#include "media/base/supported_types.h"
#include "media/base/svc_scalability_mode.h"
#include "media/base/timestamp_constants.h"
#include "media/base/video_codecs.h"
#include "media/base/video_color_space.h"
#include "media/base/video_encoder.h"
#include "media/base/video_util.h"
#include "media/media_buildflags.h"
#include "media/mojo/clients/mojo_video_encoder_metrics_provider.h"
#include "media/parsers/h264_level_limits.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "media/video/offloading_video_encoder.h"
#include "media/video/video_encode_accelerator_adapter.h"
#include "media/video/video_encoder_fallback.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_function.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/to_v8_traits.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_dom_exception.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_avc_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_encoded_video_chunk_metadata.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_hevc_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_svc_output_metadata.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_color_space_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_decoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_config.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options_for_av_1.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options_for_avc.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_encode_options_for_vp_9.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_encoder_support.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_video_pixel_format.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/streams/readable_stream.h"
#include "third_party/blink/renderer/core/streams/writable_stream.h"
#include "third_party/blink/renderer/modules/event_modules.h"
#include "third_party/blink/renderer/modules/webcodecs/array_buffer_util.h"
#include "third_party/blink/renderer/modules/webcodecs/background_readback.h"
#include "third_party/blink/renderer/modules/webcodecs/codec_state_helper.h"
#include "third_party/blink/renderer/modules/webcodecs/encoded_video_chunk.h"
#include "third_party/blink/renderer/modules/webcodecs/gpu_factories_retriever.h"
#include "third_party/blink/renderer/modules/webcodecs/video_color_space.h"
#include "third_party/blink/renderer/modules/webcodecs/video_encoder_buffer.h"
#include "third_party/blink/renderer/platform/bindings/enumeration_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_video_frame_pool.h"
#include "third_party/blink/renderer/platform/heap/cross_thread_handle.h"
#include "third_party/blink/renderer/platform/heap/heap_barrier_callback.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_base.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"

#if BUILDFLAG(ENABLE_LIBAOM)
#include "media/video/av1_video_encoder.h"
#endif

#if BUILDFLAG(ENABLE_OPENH264)
#include "media/video/openh264_video_encoder.h"
#endif

#if BUILDFLAG(ENABLE_LIBVPX)
#include "media/video/vpx_video_encoder.h"
#endif

namespace WTF {

template <>
struct CrossThreadCopier<media::EncoderStatus>
    : public CrossThreadCopierPassThrough<media::EncoderStatus> {
  STATIC_ONLY(CrossThreadCopier);
};

}  // namespace WTF

namespace blink {

using EncoderType = media::VideoEncodeAccelerator::Config::EncoderType;

namespace {

constexpr const char kCategory[] = "media";
// Controls if VideoEncoder will use timestamp from blink::VideoFrame
// instead of media::VideoFrame.
BASE_FEATURE(kUseBlinkTimestampForEncoding,
             "UseBlinkTimestampForEncoding",
             base::FEATURE_ENABLED_BY_DEFAULT);

// TODO(crbug.com/40215121): This is very similar to the method in
// video_frame.cc. It should probably be a function in video_types.cc.
media::VideoPixelFormat ToOpaqueMediaPixelFormat(media::VideoPixelFormat fmt) {
  switch (fmt) {
    case media::PIXEL_FORMAT_I420A:
      return media::PIXEL_FORMAT_I420;
    case media::PIXEL_FORMAT_YUV420AP10:
      return media::PIXEL_FORMAT_YUV420P10;
    case media::PIXEL_FORMAT_I422A:
      return media::PIXEL_FORMAT_I422;
    case media::PIXEL_FORMAT_YUV422AP10:
      return media::PIXEL_FORMAT_YUV422P10;
    case media::PIXEL_FORMAT_I444A:
      return media::PIXEL_FORMAT_I444;
    case media::PIXEL_FORMAT_YUV444AP10:
      return media::PIXEL_FORMAT_YUV444P10;
    case media::PIXEL_FORMAT_NV12A:
      return media::PIXEL_FORMAT_NV12;
    default:
      NOTIMPLEMENTED() << "Missing support for making " << fmt << " opaque.";
      return fmt;
  }
}

int ComputeMaxActiveEncodes(std::optional<int> frame_delay = std::nullopt,
                            std::optional<int> input_capacity = std::nullopt) {
  constexpr int kDefaultEncoderFrameDelay = 0;

  // The maximum number of input frames above the encoder frame delay that we
  // want to be able to enqueue in |media_encoder_|.
  constexpr int kDefaultEncoderExtraInputCapacity = 5;

  const int preferred_capacity =
      frame_delay.value_or(kDefaultEncoderFrameDelay) +
      kDefaultEncoderExtraInputCapacity;
  return input_capacity.has_value()
             ? std::min(preferred_capacity, input_capacity.value())
             : preferred_capacity;
}

media::VideoEncodeAccelerator::SupportedRateControlMode BitrateToSupportedMode(
    const media::Bitrate& bitrate) {
  switch (bitrate.mode()) {
    case media::Bitrate::Mode::kConstant:
      return media::VideoEncodeAccelerator::kConstantMode;
    case media::Bitrate::Mode::kVariable:
      return media::VideoEncodeAccelerator::kVariableMode
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_CHROMEOS)
             // On Android and ChromeOS we allow CBR-only encoders to be used
             // for VBR because most devices don't properly advertise support
             // for VBR encoding. In most cases they will initialize
             // successfully when configured for VBR.
             | media::VideoEncodeAccelerator::kConstantMode
#endif  // BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_CHROMEOS)
          ;

    case media::Bitrate::Mode::kExternal:
      return media::VideoEncodeAccelerator::kExternalMode;
  }
}

media::EncoderStatus IsAcceleratedConfigurationSupported(
    media::VideoCodecProfile profile,
    const media::VideoEncoder::Options& options,
    media::GpuVideoAcceleratorFactories* gpu_factories,
    EncoderType required_encoder_type) {
  if (!gpu_factories || !gpu_factories->IsGpuVideoEncodeAcceleratorEnabled()) {
    return media::EncoderStatus::Codes::kEncoderAccelerationSupportMissing;
  }

  // Hardware encoders don't currently support high bit depths or subsamplings
  // other than 4:2:0.
  if (options.subsampling.value_or(media::VideoChromaSampling::k420) !=
          media::VideoChromaSampling::k420 ||
      options.bit_depth.value_or(8) != 8) {
    return media::EncoderStatus::Codes::kEncoderUnsupportedConfig;
  }

  auto supported_profiles =
      gpu_factories->GetVideoEncodeAcceleratorSupportedProfiles().value_or(
          media::VideoEncodeAccelerator::SupportedProfiles());

  if (supported_profiles.empty()) {
    return media::EncoderStatus::Codes::kEncoderAccelerationSupportMissing;
  }

  bool found_supported_profile = false;
  for (auto& supported_profile : supported_profiles) {
    if (supported_profile.profile != profile) {
      continue;
    }

    if (supported_profile.is_software_codec) {
      if (required_encoder_type == EncoderType::kHardware) {
        continue;
      }
    } else if (required_encoder_type == EncoderType::kSoftware) {
      continue;
    }

    if (supported_profile.min_resolution.width() > options.frame_size.width() ||
        supported_profile.min_resolution.height() >
            options.frame_size.height()) {
      continue;
    }

    if (supported_profile.max_resolution.width() < options.frame_size.width() ||
        supported_profile.max_resolution.height() <
            options.frame_size.height()) {
      continue;
    }

    double max_supported_framerate =
        static_cast<double>(supported_profile.max_framerate_numerator) /
        supported_profile.max_framerate_denominator;
    if (options.framerate.has_value() &&
        options.framerate.value() > max_supported_framerate) {
      continue;
    }

    if (options.scalability_mode.has_value() &&
        !base::Contains(supported_profile.scalability_modes,
                        options.scalability_mode.value())) {
      continue;
    }

    if (options.bitrate.has_value()) {
      auto mode = BitrateToSupportedMode(options.bitrate.value());
      if (!(mode & supported_profile.rate_control_modes)) {
        continue;
      }
    }

    found_supported_profile = true;
    break;
  }
  return found_supported_profile
             ? media::EncoderStatus::Codes::kOk
             : media::EncoderStatus::Codes::kEncoderUnsupportedConfig;
}

VideoEncoderTraits::ParsedConfig* ParseConfigStatic(
    const VideoEncoderConfig* config,
    ExceptionState& exception_state) {
  auto* result = MakeGarbageCollected<VideoEncoderTraits::ParsedConfig>();

  if (config->codec().LengthWithStrippedWhiteSpace() == 0) {
    exception_state.ThrowTypeError("Invalid codec; codec is required.");
    return nullptr;
  }

  if (config->height() == 0 || config->width() == 0) {
    exception_state.ThrowTypeError(
        "Invalid size; height and width must be greater than zero.");
    return nullptr;
  }
  result->options.frame_size.SetSize(config->width(), config->height());

  if (config->alpha() == "keep") {
    result->not_supported_error_message =
        "Alpha encoding is not currently supported.";
    return result;
  }

  result->options.latency_mode =
      (config->latencyMode() == "quality")
          ? media::VideoEncoder::LatencyMode::Quality
          : media::VideoEncoder::LatencyMode::Realtime;

  if (config->hasContentHint()) {
    if (config->contentHint() == "detail" || config->contentHint() == "text") {
      result->options.content_hint = media::VideoEncoder::ContentHint::Screen;
    } else if (config->contentHint() == "motion") {
      result->options.content_hint = media::VideoEncoder::ContentHint::Camera;
    }
  }

  if (config->bitrateMode() == V8VideoEncoderBitrateMode::Enum::kQuantizer) {
    result->options.bitrate = media::Bitrate::ExternalRateControl();
  } else if (config->hasBitrate()) {
    uint32_t bps = base::saturated_cast<uint32_t>(config->bitrate());
    if (bps == 0) {
      exception_state.ThrowTypeError("Bitrate must be greater than zero.");
      return nullptr;
    }
    if (config->bitrateMode() == V8VideoEncoderBitrateMode::Enum::kConstant) {
      result->options.bitrate = media::Bitrate::ConstantBitrate(bps);
    } else {
      // VBR in media:Bitrate supports both target and peak bitrate.
      // Currently webcodecs doesn't expose peak bitrate
      // (assuming unconstrained VBR), here we just set peak as 10 times
      // target as a good enough way of expressing unconstrained VBR.
      result->options.bitrate = media::Bitrate::VariableBitrate(
          bps, base::ClampMul(bps, 10u).RawValue());
    }
  }

  if (config->hasDisplayWidth() && config->hasDisplayHeight()) {
    if (config->displayHeight() == 0 || config->displayWidth() == 0) {
      exception_state.ThrowTypeError(
          "Invalid display size; height and width must be greater than zero.");
      return nullptr;
    }
    result->display_size.emplace(config->displayWidth(),
                                 config->displayHeight());
  } else if (config->hasDisplayWidth() || config->hasDisplayHeight()) {
    exception_state.ThrowTypeError(
        "Invalid display size; both height and width must be set together.");
    return nullptr;
  }

  if (config->hasFramerate()) {
    constexpr double kMinFramerate = .0001;
    constexpr double kMaxFramerate = 1'000'000'000;
    if (std::isnan(config->framerate()) ||
        config->framerate() < kMinFramerate ||
        config->framerate() > kMaxFramerate) {
      result->not_supported_error_message = String::Format(
          "Unsupported framerate; expected range from %f to %f, received %f.",
          kMinFramerate, kMaxFramerate, config->framerate());
      return result;
    }
    result->options.framerate = config->framerate();
  } else {
    result->options.framerate =
        media::VideoEncodeAccelerator::kDefaultFramerate;
  }

  // https://w3c.github.io/webrtc-svc/
  if (config->hasScalabilityMode()) {
    if (config->scalabilityMode() == "L1T1") {
      result->options.scalability_mode = media::SVCScalabilityMode::kL1T1;
    } else if (config->scalabilityMode() == "L1T2") {
      result->options.scalability_mode = media::SVCScalabilityMode::kL1T2;
    } else if (config->scalabilityMode() == "L1T3") {
      result->options.scalability_mode = media::SVCScalabilityMode::kL1T3;
    } else if (config->scalabilityMode() == "manual") {
      result->options.manual_reference_buffer_control = true;
    } else {
      result->not_supported_error_message =
          String::Format("Unsupported scalabilityMode: %s",
                         config->scalabilityMode().Utf8().c_str());
      return result;
    }
  }

  // The IDL defines a default value of "no-preference".
  DCHECK(config->hasHardwareAcceleration());

  result->hw_pref = StringToHardwarePreference(
      IDLEnumAsString(config->hardwareAcceleration()));

  result->codec = media::VideoCodec::kUnknown;
  result->profile = media::VIDEO_CODEC_PROFILE_UNKNOWN;
  result->level = 0;
  result->codec_string = config->codec();

  auto parse_result = media::ParseVideoCodecString(
      "", config->codec().Utf8(), /*allow_ambiguous_matches=*/false);
  if (!parse_result) {
    return result;
  }

  // Some codec strings provide color space info, but for WebCodecs this is
  // ignored. Instead, the VideoFrames given to encode() are the source of truth
  // for input color space. Note also that the output color space is up to the
  // underlying codec impl. See https://github.com/w3c/webcodecs/issues/345.
  result->codec = parse_result->codec;
  result->profile = parse_result->profile;
  result->level = parse_result->level;
  result->options.subsampling = parse_result->subsampling;
  result->options.bit_depth = parse_result->bit_depth;

  // Ideally which profile supports a given subsampling would be checked by
  // ParseVideoCodecString() above. Unfortunately, ParseVideoCodecString() is
  // shared by many paths and enforcing profile and subsampling broke several
  // sites. The error messages below are more helpful anyways.
  switch (result->codec) {
    case media::VideoCodec::kH264: {
      if (config->hasAvc()) {
        std::string avc_format =
            IDLEnumAsString(config->avc()->format()).Utf8();
        if (avc_format == "avc") {
          result->options.avc.produce_annexb = false;
        } else if (avc_format == "annexb") {
          result->options.avc.produce_annexb = true;
        } else {
          NOTREACHED();
        }
      }
      break;
    }
    case media::VideoCodec::kHEVC: {
      if (config->hasHevc()) {
        std::string hevc_format =
            IDLEnumAsString(config->hevc()->format()).Utf8();
        if (hevc_format == "hevc") {
          result->options.hevc.produce_annexb = false;
        } else if (hevc_format == "annexb") {
          result->options.hevc.produce_annexb = true;
        } else {
          NOTREACHED();
        }
      }
      break;
    }
    default:
      break;
  }

  return result;
}

bool VerifyCodecSupportStatic(VideoEncoderTraits::ParsedConfig* config,
                              String* js_error_message) {
  if (config->not_supported_error_message) {
    *js_error_message = *config->not_supported_error_message;
    return false;
  }

  const auto& frame_size = config->options.frame_size;
  if (frame_size.height() > media::limits::kMaxDimension) {
    *js_error_message = String::Format(
        "Invalid height; expected range from %d to %d, received %d.", 1,
        media::limits::kMaxDimension, frame_size.height());
    return false;
  }
  if (frame_size.width() > media::limits::kMaxDimension) {
    *js_error_message = String::Format(
        "Invalid width; expected range from %d to %d, received %d.", 1,
        media::limits::kMaxDimension, frame_size.width());
    return false;
  }
  if (frame_size.Area64() > media::limits::kMaxCanvas) {
    *js_error_message = String::Format(
        "Invalid resolution; expected range from %d to %d, "
        "received %" PRIu64
        " (%d * "
        "%d).",
        1, media::limits::kMaxCanvas, frame_size.Area64(), frame_size.width(),
        frame_size.height());
    return false;
  }

  switch (config->codec) {
    case media::VideoCodec::kAV1:
    case media::VideoCodec::kVP8:
    case media::VideoCodec::kVP9:
      break;
#if BUILDFLAG(ENABLE_PLATFORM_HEVC)
    case media::VideoCodec::kHEVC:
      if (config->profile != media::VideoCodecProfile::HEVCPROFILE_MAIN) {
        *js_error_message = "Unsupported hevc profile.";
        return false;
      }
      break;
#endif

    case media::VideoCodec::kH264: {
      if (config->options.frame_size.width() % 2 != 0 ||
          config->options.frame_size.height() % 2 != 0) {
        *js_error_message = "H264 only supports even sized frames.";
        return false;
      }

      // Note: This calculation is incorrect for interlaced or MBAFF encoding;
      // but we don't support those and likely never will.
      gfx::Size coded_size(base::bits::AlignUpDeprecatedDoNotUse(
                               config->options.frame_size.width(), 16),
                           base::bits::AlignUpDeprecatedDoNotUse(
                               config->options.frame_size.height(), 16));
      uint64_t coded_area = coded_size.Area64();
      uint64_t max_coded_area =
          media::H264LevelToMaxFS(config->level) * 16ull * 16ull;
      if (coded_area > max_coded_area) {
        *js_error_message = String::Format(
            "The provided resolution (%s) has a coded area "
            "(%d*%d=%" PRIu64 ") which exceeds the maximum coded area (%" PRIu64
            ") supported by the AVC level (%1.1f) indicated "
            "by the codec string (0x%02X). You must either "
            "specify a lower resolution or higher AVC level.",
            config->options.frame_size.ToString().c_str(), coded_size.width(),
            coded_size.height(), coded_area, max_coded_area,
            config->level / 10.0f, config->level);
        return false;
      }
      break;
    }

    default:
      *js_error_message = "Unsupported codec type.";
      return false;
  }

  return true;
}

VideoEncoderConfig* CopyConfig(
    const VideoEncoderConfig& config,
    const VideoEncoderTraits::ParsedConfig& parsed_config) {
  auto* result = VideoEncoderConfig::Create();
  result->setCodec(config.codec());
  result->setWidth(config.width());
  result->setHeight(config.height());

  if (config.hasDisplayWidth())
    result->setDisplayWidth(config.displayWidth());

  if (config.hasDisplayHeight())
    result->setDisplayHeight(config.displayHeight());

  if (config.hasFramerate())
    result->setFramerate(config.framerate());

  if (config.hasBitrate())
    result->setBitrate(config.bitrate());

  if (config.hasScalabilityMode())
    result->setScalabilityMode(config.scalabilityMode());

  if (config.hasHardwareAcceleration())
    result->setHardwareAcceleration(config.hardwareAcceleration());

  if (config.hasAlpha())
    result->setAlpha(config.alpha());

  if (config.hasBitrateMode())
    result->setBitrateMode(config.bitrateMode());

  if (config.hasLatencyMode())
    result->setLatencyMode(config.latencyMode());

  if (config.hasContentHint()) {
    result->setContentHint(config.contentHint());
  }

  if (config.hasAvc() && config.avc()->hasFormat()) {
    auto* avc = AvcEncoderConfig::Create();
    avc->setFormat(config.avc()->format());
    result->setAvc(avc);
  }

  if (config.hasHevc() && config.hevc()->hasFormat()) {
    auto* hevc = HevcEncoderConfig::Create();
    hevc->setFormat(config.hevc()->format());
    result->setHevc(hevc);
  }

  return result;
}

bool CanUseGpuMemoryBufferReadback(media::VideoPixelFormat format,
                                   bool force_opaque) {
  // GMB readback only works with NV12, so only opaque buffers can be used.
  return (format == media::PIXEL_FORMAT_XBGR ||
          format == media::PIXEL_FORMAT_XRGB ||
          (force_opaque && (format == media::PIXEL_FORMAT_ABGR ||
                            format == media::PIXEL_FORMAT_ARGB))) &&
         WebGraphicsContext3DVideoFramePool::
             IsGpuMemoryBufferReadbackFromTextureEnabled();
}

EncoderType GetRequiredEncoderType(media::VideoCodecProfile profile,
                                   HardwarePreference hw_pref) {
  if (hw_pref != HardwarePreference::kPreferHardware &&
      media::MayHaveAndAllowSelectOSSoftwareEncoder(
          media::VideoCodecProfileToVideoCodec(profile))) {
    return hw_pref == HardwarePreference::kPreferSoftware
               ? EncoderType::kSoftware
               : EncoderType::kNoPreference;
  }
  return EncoderType::kHardware;
}

}  // namespace

// static
const char* VideoEncoderTraits::GetName() {
  return "VideoEncoder";
}

String VideoEncoderTraits::ParsedConfig::ToString() {
  return String::Format(
      "{codec: %s, profile: %s, level: %d, hw_pref: %s, "
      "options: {%s}, codec_string: %s, display_size: %s}",
      media::GetCodecName(codec).c_str(),
      media::GetProfileName(profile).c_str(), level,
      HardwarePreferenceToString(hw_pref).Utf8().c_str(),
      options.ToString().c_str(), codec_string.Utf8().c_str(),
      display_size ? display_size->ToString().c_str() : "");
}

// static
VideoEncoder* VideoEncoder::Create(ScriptState* script_state,
                                   const VideoEncoderInit* init,
                                   ExceptionState& exception_state) {
  auto* result =
      MakeGarbageCollected<VideoEncoder>(script_state, init, exception_state);
  return exception_state.HadException() ? nullptr : result;
}

VideoEncoder::VideoEncoder(ScriptState* script_state,
                           const VideoEncoderInit* init,
                           ExceptionState& exception_state)
    : Base(script_state, init, exception_state),
      max_active_encodes_(ComputeMaxActiveEncodes()) {
  UseCounter::Count(ExecutionContext::From(script_state),
                    WebFeature::kWebCodecs);
}

VideoEncoder::~VideoEncoder() = default;

VideoEncoder::ParsedConfig* VideoEncoder::ParseConfig(
    const VideoEncoderConfig* config,
    ExceptionState& exception_state) {
  return ParseConfigStatic(config, exception_state);
}

bool VideoEncoder::VerifyCodecSupport(ParsedConfig* config,
                                      String* js_error_message) {
  return VerifyCodecSupportStatic(config, js_error_message);
}

media::EncoderStatus::Or<std::unique_ptr<media::VideoEncoder>>
VideoEncoder::CreateAcceleratedVideoEncoder(
    media::VideoCodecProfile profile,
    const media::VideoEncoder::Options& options,
    media::GpuVideoAcceleratorFactories* gpu_factories,
    HardwarePreference hw_pref) {
  auto required_encoder_type = GetRequiredEncoderType(profile, hw_pref);
  if (media::EncoderStatus result = IsAcceleratedConfigurationSupported(
          profile, options, gpu_factories, required_encoder_type);
      !result.is_ok()) {
    return std::move(result);
  }

  return std::unique_ptr<media::VideoEncoder>(
      std::make_unique<media::AsyncDestroyVideoEncoder<
          media::VideoEncodeAcceleratorAdapter>>(
          std::make_unique<media::VideoEncodeAcceleratorAdapter>(
              gpu_factories, logger_->log()->Clone(), callback_runner_,
              required_encoder_type)));
}

std::unique_ptr<media::VideoEncoder> CreateAv1VideoEncoder() {
#if BUILDFLAG(ENABLE_LIBAOM)
  return std::make_unique<media::Av1VideoEncoder>();
#else
  return nullptr;
#endif  // BUILDFLAG(ENABLE_LIBAOM)
}

std::unique_ptr<media::VideoEncoder> CreateVpxVideoEncoder() {
#if BUILDFLAG(ENABLE_LIBVPX)
  return std::make_unique<media::VpxVideoEncoder>();
#else
  return nullptr;
#endif  // BUILDFLAG(ENABLE_LIBVPX)
}

std::unique_ptr<media::VideoEncoder> CreateOpenH264VideoEncoder() {
#if BUILDFLAG(ENABLE_OPENH264)
  return std::make_unique<media::OpenH264VideoEncoder>();
#else
  return nullptr;
#endif  // BUILDFLAG(ENABLE_OPENH264)
}

// This method is static and takes |self| in order to make it possible to use it
// with a weak |this|. It's needed in to avoid a persistent reference cycle.
media::EncoderStatus::Or<std::unique_ptr<media::VideoEncoder>>
VideoEncoder::CreateSoftwareVideoEncoder(VideoEncoder* self,
                                         bool fallback,
                                         media::VideoCodec codec) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
  if (!self)
    return media::EncoderStatus::Codes::kEncoderIllegalState;
  std::unique_ptr<media::VideoEncoder> result;
  switch (codec) {
    case media::VideoCodec::kAV1:
      result = CreateAv1VideoEncoder();
      break;
    case media::VideoCodec::kVP8:
    case media::VideoCodec::kVP9:
      result = CreateVpxVideoEncoder();
      break;
    case media::VideoCodec::kH264:
      result = CreateOpenH264VideoEncoder();
      break;
    default:
      break;
  }
  if (!result) {
    return media::EncoderStatus::Codes::kEncoderUnsupportedCodec;
  }
  if (fallback) {
    CHECK(self->encoder_metrics_provider_);
    self->encoder_metrics_provider_->Initialize(
        self->active_config_->profile, self->active_config_->options.frame_size,
        /*is_hardware_encoder=*/false,
        self->active_config_->options.scalability_mode.value_or(
            media::SVCScalabilityMode::kL1T1));
  }
  return std::unique_ptr<media::VideoEncoder>(
      std::make_unique<media::OffloadingVideoEncoder>(std::move(result)));
}

media::EncoderStatus::Or<std::unique_ptr<media::VideoEncoder>>
VideoEncoder::CreateMediaVideoEncoder(
    const ParsedConfig& config,
    media::GpuVideoAcceleratorFactories* gpu_factories,
    bool& is_platform_encoder) {
  is_platform_encoder = true;
  if (config.hw_pref == HardwarePreference::kPreferHardware ||
      config.hw_pref == HardwarePreference::kNoPreference ||
      media::MayHaveAndAllowSelectOSSoftwareEncoder(config.codec)) {
    auto result = CreateAcceleratedVideoEncoder(config.profile, config.options,
                                                gpu_factories, config.hw_pref);
    if (config.hw_pref == HardwarePreference::kPreferHardware) {
      return result;
    } else if (result.has_value()) {
      // 'no-preference' or 'prefer-software' and we have OS software encoders.
      return std::unique_ptr<media::VideoEncoder>(
          std::make_unique<media::VideoEncoderFallback>(
              std::move(result).value(),
              ConvertToBaseOnceCallback(
                  CrossThreadBindOnce(&VideoEncoder::CreateSoftwareVideoEncoder,
                                      MakeUnwrappingCrossThreadWeakHandle(this),
                                      /*fallback=*/true, config.codec))));
    }
  }

  is_platform_encoder = false;
  return CreateSoftwareVideoEncoder(this, /*fallback=*/false, config.codec);
}

void VideoEncoder::ContinueConfigureWithGpuFactories(
    Request* request,
    media::GpuVideoAcceleratorFactories* gpu_factories) {
  DCHECK(active_config_);
  DCHECK_EQ(request->type, Request::Type::kConfigure);
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  bool is_platform_encoder = false;
  media_encoder_.reset();
  auto encoder_or_error = CreateMediaVideoEncoder(
      *active_config_, gpu_factories, is_platform_encoder);
  if (!encoder_or_error.has_value()) {
    ReportError("Encoder creation error.", std::move(encoder_or_error).error(),
                /*is_error_message_from_software_codec=*/!is_platform_encoder);
    request->EndTracing();
    return;
  }

  media_encoder_ = std::move(encoder_or_error).value();
  auto info_cb = ConvertToBaseRepeatingCallback(
      CrossThreadBindRepeating(&VideoEncoder::OnMediaEncoderInfoChanged,
                               MakeUnwrappingCrossThreadWeakHandle(this)));

  auto output_cb = ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
      &VideoEncoder::CallOutputCallback,
      MakeUnwrappingCrossThreadWeakHandle(this),
      // We can't use |active_config_| from |this| because it can change by
      // the time the callback is executed.
      MakeUnwrappingCrossThreadHandle(active_config_.Get()), reset_count_));

  auto done_callback = [](VideoEncoder* self, Request* req,
                          media::VideoCodec codec,
                          const bool is_platform_encoder,
                          media::EncoderStatus status) {
    if (!self || self->reset_count_ != req->reset_count) {
      req->EndTracing(/*aborted=*/true);
      return;
    }
    DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
    DCHECK(self->active_config_);

    MEDIA_LOG(INFO, self->logger_->log())
        << "Configured " << self->active_config_->ToString();

    if (!status.is_ok()) {
      std::string error_message;
      switch (status.code()) {
        case media::EncoderStatus::Codes::kEncoderUnsupportedProfile:
          error_message = "Unsupported codec profile.";
          break;
        case media::EncoderStatus::Codes::kEncoderUnsupportedConfig:
          error_message = "Unsupported configuration parameters.";
          break;
        default:
          error_message = "Encoder initialization error.";
          break;
      }

      self->ReportError(
          error_message.c_str(), std::move(status),
          /*is_error_message_from_software_codec=*/!is_platform_encoder);
    } else {
      base::UmaHistogramEnumeration("Blink.WebCodecs.VideoEncoder.Codec",
                                    codec);
    }
    req->E
```