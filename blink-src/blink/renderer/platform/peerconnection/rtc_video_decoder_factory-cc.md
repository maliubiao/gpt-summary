Response:
Let's break down the thought process to arrive at the comprehensive analysis of `rtc_video_decoder_factory.cc`.

**1. Initial Understanding of the File's Purpose (Based on Name and Imports):**

* **`rtc_video_decoder_factory.cc`**:  The name immediately suggests a factory responsible for creating video decoders specifically for the "Real-Time Communication" (RTC) context within the Blink rendering engine.
* **Includes:** The included headers provide significant clues:
    * `third_party/blink/renderer/platform/peerconnection/...`:  Confirms it's part of the WebRTC implementation in Blink's PeerConnection module.
    * `media/...`:  Indicates interaction with Chromium's media pipeline (video codecs, GPU acceleration).
    * `third_party/webrtc/...`: Shows it leverages the WebRTC native library.
    * `base/...`: Points to Chromium's base utilities (feature flags, logging, task runners).

**Initial Hypothesis:** This file likely handles the selection and creation of appropriate video decoders (hardware or software) for WebRTC video streams within a Chromium browser.

**2. Analyzing the Core Functionality (Step-by-Step through the Code):**

* **Codec Support Determination:** The code defines `kCodecConfigs` and `VdcToWebRtcFormat`. This immediately highlights a central function: mapping between Chromium's internal `media::VideoCodec` and `media::VideoCodecProfile` and WebRTC's `webrtc::SdpVideoFormat`. The `GetSupportedFormats()` method confirms this, as it iterates through these configurations and queries `gpu_factories_` for hardware support.
* **Hardware vs. Software Decoding:** The presence of `gpu_factories_` and `RTCVideoDecoderAdapter::Create` strongly suggests a mechanism for utilizing hardware-accelerated video decoding when available. The conditional checks (`if (gpu_factories_ && ...)`) confirm this.
* **Feature Flags:** The use of `base::FeatureList::IsEnabled()` (e.g., `kWebRtcHwAv1Decoding`, `kWebRtcAllowH265Receive`) indicates that certain decoder functionalities are controlled by runtime flags, likely for experimentation or conditional enablement.
* **Codec Profile Handling:** The code explicitly handles different profiles for codecs like VP9 and H.264, translating them to WebRTC's format parameters. This demonstrates an understanding of codec complexities.
* **`QueryCodecSupport()`:** This function is crucial for determining if a specific video format (represented by `webrtc::SdpVideoFormat`) can be decoded efficiently (power-efficient likely meaning hardware acceleration).
* **`Create()` Method:** This is the actual factory method. It uses `RTCVideoDecoderAdapter::Create` (likely the hardware decoder) and falls back to software (represented by the `nullptr` case, though the provided snippet doesn't show the *explicit* software path within this file). The `ScopedVideoDecoder` wrapper addresses thread safety for decoder destruction.
* **Error Handling/Limitations:**  The comments (e.g., about H.264 CBP/BP, the TODO about querying for max resolution) and the return of `std::nullopt` in `VdcToWebRtcFormat` reveal awareness of limitations and potential issues.
* **Threading:** The `ScopedVideoDecoder` and the use of `base::SequencedTaskRunner` highlight the importance of managing decoder lifecycle across different threads.

**3. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:** The primary link is through the WebRTC API exposed to JavaScript. The `RTCPeerConnection` API uses this factory internally when negotiating media capabilities. When a JavaScript application uses `RTCPeerConnection` to receive a video stream, this factory is involved in setting up the appropriate decoder.
* **HTML:**  The `<video>` element is the destination for the decoded video frames. The browser uses the decoders created by this factory to render the video content within the `<video>` element.
* **CSS:**  While not directly involved in *decoding*, CSS affects the presentation of the `<video>` element (size, position, styling).

**4. Logical Reasoning and Examples:**

* **Assumptions:**  The analysis relies on understanding the general principles of video decoding, WebRTC, and Chromium's architecture.
* **Input/Output:**  The examples focus on the `QueryCodecSupport()` function, demonstrating how different `SdpVideoFormat` inputs would result in different `CodecSupport` outputs based on hardware capabilities and feature flags.

**5. Common Usage Errors:**

* **JavaScript Side:**  The errors focus on incorrect usage of the WebRTC API (e.g., not checking codec support, forcing unsupported codecs).
* **Underlying System:** The examples also consider errors outside the JavaScript code, such as missing hardware drivers or disabled GPU acceleration.

**6. Structuring the Analysis:**

The final step is to organize the findings into a clear and understandable structure, covering:

* **Functionality:** A high-level overview of what the file does.
* **Relationship to Web Technologies:**  Connecting the code to the user-facing aspects of the web.
* **Logical Reasoning:** Providing concrete examples of input and output.
* **Common Errors:**  Highlighting potential pitfalls for developers and users.

**Self-Correction/Refinement:**

During the analysis, I might have initially focused too much on the hardware decoding aspect. Realizing that software decoding is also possible (even if not explicitly created *in this file*) is important. Similarly, understanding the role of feature flags requires carefully reading the code for `base::FeatureList::IsEnabled()`. The importance of thread safety (via `ScopedVideoDecoder`) might not be immediately obvious without examining the class structure. Iteratively going through the code and asking "why is this here?" helps to uncover the full purpose.
这个文件 `rtc_video_decoder_factory.cc` 的主要功能是：**为一个 WebRTC `RTCPeerConnection` 创建合适的视频解码器实例。** 它负责决定在给定的视频格式下，应该使用哪种解码器，包括硬件加速解码器和软件解码器。

更具体地说，它执行以下任务：

1. **枚举支持的视频解码格式：**  `GetSupportedFormats()` 方法会列出当前系统和浏览器支持的各种视频解码格式 (例如 VP8, VP9, H.264, AV1, H.265)。 这包括考虑硬件加速的支持情况。
2. **查询特定视频格式的支持情况：** `QueryCodecSupport()` 方法接收一个 WebRTC 的 `SdpVideoFormat` 对象（描述了一种视频编码格式），并判断当前环境是否支持高效地解码该格式。  “高效”通常意味着是否可以使用硬件加速解码。
3. **创建视频解码器实例：** `Create()` 方法是工厂的核心。当需要解码特定格式的视频流时，这个方法会被调用。它会根据 `QueryCodecSupport()` 的结果以及系统配置，创建并返回一个合适的 `webrtc::VideoDecoder` 实例。

**与 JavaScript, HTML, CSS 的关系：**

这个文件位于 Blink 引擎的底层，直接与 JavaScript, HTML, CSS 的功能没有直接的 API 交互。但是，它是实现 WebRTC 功能的关键组成部分，而 WebRTC 功能是通过 JavaScript API 暴露给网页开发者的。

**举例说明：**

1. **JavaScript:**  当一个网页使用 JavaScript 的 `RTCPeerConnection` API 接收一个远程视频流时，浏览器需要知道如何解码这个视频流。  `rtc_video_decoder_factory.cc` 提供的功能就在幕后工作，决定使用哪个解码器来处理接收到的视频数据。

   **假设：** JavaScript 代码通过 `RTCPeerConnection` 协商接收到一个 VP9 编码的视频流。

   **逻辑推理：**
   * 浏览器会调用 `RTCVideoDecoderFactory::Create()`，并传入描述 VP9 格式的 `SdpVideoFormat` 对象。
   * `RTCVideoDecoderFactory` 内部会调用 `QueryCodecSupport()` 来检查系统是否支持 VP9 硬件加速解码。
   * **假设输入：**  `SdpVideoFormat` 对象描述的是 VP9 编码，并且 GPU 支持 VP9 硬件解码。
   * **假设输出：** `Create()` 方法会创建一个 `RTCVideoDecoderAdapter` 实例，该适配器会使用底层的 GPU 视频加速器来解码 VP9 视频。

2. **HTML:**  解码后的视频帧最终会被渲染到 HTML 的 `<video>` 元素中。  `rtc_video_decoder_factory.cc` 负责提供解码能力，使得视频数据能够被浏览器理解并显示在 `<video>` 标签里。

   **例子：** 一个在线视频会议应用，使用 `<video>` 标签显示对方的视频。`rtc_video_decoder_factory.cc` 确保接收到的视频流能够被正确解码，从而呈现在用户的屏幕上。

3. **CSS:** CSS 主要负责 `<video>` 元素的样式和布局，与 `rtc_video_decoder_factory.cc` 的功能没有直接关系。CSS 控制的是如何显示解码后的视频，而不是如何进行解码。

**逻辑推理，假设输入与输出：**

**场景： 查询 H.264 视频格式的支持情况**

* **假设输入：**  `QueryCodecSupport()` 函数接收一个 `SdpVideoFormat` 对象，其 `name` 字段为 "H264"，并且包含 H.264 Profile 和 Level 信息。
* **逻辑推理：**
    * `QueryCodecSupport()` 首先将 WebRTC 的 `SdpVideoFormat` 转换为 Chromium 的 `media::VideoDecoderConfig`。
    * 它会检查 `gpu_factories_` 是否存在（表示是否有 GPU 加速）。
    * 它会调用 `gpu_factories_->IsDecoderConfigSupported()` 来判断当前的 GPU 是否支持解码该 H.264 配置。
    * 如果 GPU 支持，`is_power_efficient` 将为 `true`。
    * 最终的 `CodecSupport` 结构体会被填充，指示是否支持以及是否节能（硬件加速）。
* **假设输出 1 (GPU 支持)：** `CodecSupport{is_supported: true, is_power_efficient: true}`
* **假设输出 2 (GPU 不支持)：** `CodecSupport{is_supported: false, is_power_efficient: false}`  (在这种情况下，可能会回退到软件解码，但这部分逻辑可能在其他地方处理)。

**用户或编程常见的使用错误：**

1. **假设硬件加速可用但不检查：** 开发者可能会假设所有用户的设备都支持某种视频格式的硬件加速，而没有做相应的检查。如果用户的 GPU 驱动有问题或者不支持该格式的硬件解码，会导致视频播放性能下降或者失败。

   **例子：**  一个 WebRTC 应用强制使用 AV1 编码，但用户的浏览器或操作系统不支持 AV1 硬件解码。这会导致解码效率极低，CPU 占用率高，甚至卡顿。

2. **错误地配置 WebRTC 参数：**  虽然 `rtc_video_decoder_factory.cc` 不直接暴露 API，但开发者在 JavaScript 中配置 `RTCPeerConnection` 的 SDP (Session Description Protocol) 时，可能会指定一些浏览器不支持的编解码器或 profile。

   **例子：**  JavaScript 代码尝试只接收 H.264 High Profile，但用户的浏览器只支持 Baseline Profile 的硬件加速。这可能导致解码器创建失败。

3. **忽略 `QueryCodecSupport` 的结果：**  在创建 `RTCPeerConnection` 时，开发者应该利用浏览器提供的 API (例如 `RTCRtpReceiver.getCapabilities()`) 来查询支持的编解码器。如果盲目地选择一个不支持的编解码器，会导致连接失败或视频播放问题。

**总结：**

`rtc_video_decoder_factory.cc` 是 Blink 引擎中负责视频解码的关键组件。它抽象了不同视频编解码器的创建过程，并考虑了硬件加速的可能性。虽然开发者不能直接操作这个文件，但它的功能直接影响着 WebRTC 视频通话和在线视频应用的性能和兼容性。理解其作用有助于开发者更好地理解 WebRTC 的底层工作原理，并避免一些常见的错误配置。

Prompt: 
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_decoder_factory.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/peerconnection/rtc_video_decoder_factory.h"

#include <array>
#include <memory>

#include "base/check.h"
#include "base/feature_list.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/task/sequenced_task_runner.h"
#include "base/trace_event/base_tracing.h"
#include "build/build_config.h"
#include "media/base/media_util.h"
#include "media/base/platform_features.h"
#include "media/base/video_codecs.h"
#include "media/media_buildflags.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "media/webrtc/webrtc_features.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_video_decoder_adapter.h"
#include "third_party/blink/renderer/platform/webrtc/webrtc_video_utils.h"
#include "third_party/webrtc/api/video/resolution.h"
#include "third_party/webrtc/api/video_codecs/h264_profile_level_id.h"
#include "third_party/webrtc/api/video_codecs/vp9_profile.h"
#include "third_party/webrtc/media/base/codec.h"
#include "third_party/webrtc/media/base/media_constants.h"
#include "ui/gfx/color_space.h"
#include "ui/gfx/geometry/size.h"

#if BUILDFLAG(RTC_USE_H265)
#include "third_party/webrtc/api/video_codecs/h265_profile_tier_level.h"
#endif  // BUILDFLAG(RTC_USE_H265)

namespace blink {
namespace {

// Kill-switch for HW AV1 decoding.
BASE_FEATURE(kWebRtcHwAv1Decoding,
             "WebRtcHwAv1Decoding",
             base::FEATURE_ENABLED_BY_DEFAULT);

// The default fps and default size are used when querying gpu_factories_ to see
// if a codec profile is supported. 1280x720 at 30 fps corresponds to level 3.1
// for both VP9 and H264. This matches the maximum H264 profile level that is
// returned by the internal software decoder.
// TODO(crbug.com/1213437): Query gpu_factories_ or decoder_factory_ to
// determine the maximum resolution and frame rate.
constexpr int kDefaultFps = 30;
constexpr gfx::Size kDefaultSize(1280, 720);

struct CodecConfig {
  media::VideoCodec codec;
  media::VideoCodecProfile profile;
};

constexpr CodecConfig kCodecConfigs[] = {
    {media::VideoCodec::kVP8, media::VP8PROFILE_ANY},
    {media::VideoCodec::kVP9, media::VP9PROFILE_PROFILE0},
    {media::VideoCodec::kVP9, media::VP9PROFILE_PROFILE1},
    {media::VideoCodec::kVP9, media::VP9PROFILE_PROFILE2},
    {media::VideoCodec::kH264, media::H264PROFILE_BASELINE},
    {media::VideoCodec::kH264, media::H264PROFILE_MAIN},
    {media::VideoCodec::kH264, media::H264PROFILE_HIGH},
    {media::VideoCodec::kH264, media::H264PROFILE_HIGH444PREDICTIVEPROFILE},
    {media::VideoCodec::kAV1, media::AV1PROFILE_PROFILE_MAIN},
};

// Translate from media::VideoDecoderConfig to webrtc::SdpVideoFormat, or return
// nothing if the profile isn't supported.
std::optional<webrtc::SdpVideoFormat> VdcToWebRtcFormat(
    const media::VideoDecoderConfig& config) {
  switch (config.codec()) {
    case media::VideoCodec::kAV1:
      if (base::FeatureList::IsEnabled(kWebRtcHwAv1Decoding)) {
        return webrtc::SdpVideoFormat(cricket::kAv1CodecName);
      }
      return std::nullopt;
    case media::VideoCodec::kVP8:
      return webrtc::SdpVideoFormat(cricket::kVp8CodecName);
    case media::VideoCodec::kVP9: {
      webrtc::VP9Profile vp9_profile;
      switch (config.profile()) {
        case media::VP9PROFILE_PROFILE0:
          vp9_profile = webrtc::VP9Profile::kProfile0;
          break;
        case media::VP9PROFILE_PROFILE1:
          vp9_profile = webrtc::VP9Profile::kProfile1;
          break;
        case media::VP9PROFILE_PROFILE2:
          vp9_profile = webrtc::VP9Profile::kProfile2;
          break;
        default:
          // Unsupported profile in WebRTC.
          return std::nullopt;
      }
      return webrtc::SdpVideoFormat(
          cricket::kVp9CodecName, {{webrtc::kVP9FmtpProfileId,
                                    webrtc::VP9ProfileToString(vp9_profile)}});
    }
    case media::VideoCodec::kH264: {
      webrtc::H264Profile h264_profile;
      switch (config.profile()) {
        case media::H264PROFILE_BASELINE:
          h264_profile = webrtc::H264Profile::kProfileBaseline;
          break;
        case media::H264PROFILE_MAIN:
          h264_profile = webrtc::H264Profile::kProfileMain;
          break;
        case media::H264PROFILE_HIGH:
          h264_profile = webrtc::H264Profile::kProfileHigh;
          break;
        case media::H264PROFILE_HIGH444PREDICTIVEPROFILE:
          h264_profile = webrtc::H264Profile::kProfilePredictiveHigh444;
          break;
        default:
          // Unsupported H264 profile in WebRTC.
          return std::nullopt;
      }

      const int width = config.visible_rect().width();
      const int height = config.visible_rect().height();

      const std::optional<webrtc::H264Level> h264_level =
          webrtc::H264SupportedLevel(width * height, kDefaultFps);
      const webrtc::H264ProfileLevelId profile_level_id(
          h264_profile, h264_level.value_or(webrtc::H264Level::kLevel1));
      const std::optional<std::string> h264_profile_level_string =
          webrtc::H264ProfileLevelIdToString(profile_level_id);
      if (!h264_profile_level_string) {
        // Unsupported combination of profile and level.
        return std::nullopt;
      }

      webrtc::SdpVideoFormat format(cricket::kH264CodecName);
      format.parameters = {
          {cricket::kH264FmtpProfileLevelId, *h264_profile_level_string},
          {cricket::kH264FmtpLevelAsymmetryAllowed, "1"}};
      return format;
    }
    case media::VideoCodec::kHEVC: {
#if BUILDFLAG(RTC_USE_H265)
      if (!base::FeatureList::IsEnabled(::features::kWebRtcAllowH265Receive)) {
        return std::nullopt;
      }

      webrtc::H265Profile h265_profile;
      switch (config.profile()) {
        case media::HEVCPROFILE_MAIN:
          h265_profile = webrtc::H265Profile::kProfileMain;
          break;
        case media::HEVCPROFILE_MAIN10:
          h265_profile = webrtc::H265Profile::kProfileMain10;
          break;
        default:
          // Unsupported H265 profile in WebRTC.
          return std::nullopt;
      }

      const webrtc::Resolution resolution = {
          .width = config.visible_rect().width(),
          .height = config.visible_rect().height()};
      const std::optional<webrtc::H265Level> h265_level =
          webrtc::GetSupportedH265Level(resolution, kDefaultFps);
      const webrtc::H265ProfileTierLevel profile_tier_level(
          h265_profile, webrtc::H265Tier::kTier0,
          h265_level.value_or(webrtc::H265Level::kLevel1));

      webrtc::SdpVideoFormat format(cricket::kH265CodecName);
      format.parameters = {
          {cricket::kH265FmtpProfileId,
           webrtc::H265ProfileToString(profile_tier_level.profile)},
          {cricket::kH265FmtpTierFlag,
           webrtc::H265TierToString(profile_tier_level.tier)},
          {cricket::kH265FmtpLevelId,
           webrtc::H265LevelToString(profile_tier_level.level)},
          {cricket::kH265FmtpTxMode, "SRST"}};
      return format;
#else
      return std::nullopt;
#endif  // BUILDFLAG(RTC_USE_H265)
    }
    default:
      return std::nullopt;
  }
}

// This extra indirection is needed so that we can delete the decoder on the
// correct thread.
class ScopedVideoDecoder : public webrtc::VideoDecoder {
 public:
  ScopedVideoDecoder(
      const scoped_refptr<base::SequencedTaskRunner>& task_runner,
      std::unique_ptr<webrtc::VideoDecoder> decoder)
      : task_runner_(task_runner), decoder_(std::move(decoder)) {}

  bool Configure(const Settings& settings) override {
    return decoder_->Configure(settings);
  }
  int32_t RegisterDecodeCompleteCallback(
      webrtc::DecodedImageCallback* callback) override {
    return decoder_->RegisterDecodeCompleteCallback(callback);
  }
  int32_t Release() override { return decoder_->Release(); }
  int32_t Decode(const webrtc::EncodedImage& input_image,
                 bool missing_frames,
                 int64_t render_time_ms) override {
    return decoder_->Decode(input_image, missing_frames, render_time_ms);
  }

  DecoderInfo GetDecoderInfo() const override {
    return decoder_->GetDecoderInfo();
  }

  // Runs on Chrome_libJingle_WorkerThread. The child thread is blocked while
  // this runs.
  ~ScopedVideoDecoder() override {
    task_runner_->DeleteSoon(FROM_HERE, decoder_.release());
  }

 private:
  scoped_refptr<base::SequencedTaskRunner> task_runner_;
  std::unique_ptr<webrtc::VideoDecoder> decoder_;
};

}  // namespace

RTCVideoDecoderFactory::RTCVideoDecoderFactory(
    media::GpuVideoAcceleratorFactories* gpu_factories,
    const gfx::ColorSpace& render_color_space)
    : gpu_factories_(gpu_factories),
      render_color_space_(render_color_space) {
  if (gpu_factories_) {
    gpu_codec_support_waiter_ =
        std::make_unique<GpuCodecSupportWaiter>(gpu_factories_);
  }
  DVLOG(2) << __func__;
}

void RTCVideoDecoderFactory::CheckAndWaitDecoderSupportStatusIfNeeded() const {
  if (!gpu_codec_support_waiter_)
    return;

  if (!gpu_codec_support_waiter_->IsDecoderSupportKnown()) {
    DLOG(WARNING) << "Decoder support is unknown. Timeout "
                  << gpu_codec_support_waiter_->wait_timeout_ms()
                         .value_or(base::TimeDelta())
                         .InMilliseconds()
                  << "ms. Decoders might not be available.";
  }
}

std::vector<webrtc::SdpVideoFormat>
RTCVideoDecoderFactory::GetSupportedFormats() const {
  CheckAndWaitDecoderSupportStatusIfNeeded();

  std::vector<webrtc::SdpVideoFormat> supported_formats;
  for (auto& codec_config : kCodecConfigs) {
    media::VideoDecoderConfig config(
        codec_config.codec, codec_config.profile,
        media::VideoDecoderConfig::AlphaMode::kIsOpaque,
        media::VideoColorSpace(), media::kNoTransformation, kDefaultSize,
        gfx::Rect(kDefaultSize), kDefaultSize, media::EmptyExtraData(),
        media::EncryptionScheme::kUnencrypted);
    std::optional<webrtc::SdpVideoFormat> format;

    // The RTCVideoDecoderAdapter is for HW decoders only, so ignore it if there
    // are no gpu_factories_.
    if (gpu_factories_ &&
        gpu_factories_->IsDecoderConfigSupported(config) ==
            media::GpuVideoAcceleratorFactories::Supported::kTrue) {
      format = VdcToWebRtcFormat(config);
    }

    if (format) {
      // For H.264 decoder, packetization-mode 0/1 should be both supported.
      media::VideoCodec codec = WebRtcToMediaVideoCodec(
          webrtc::PayloadStringToCodecType(format->name));
      if (codec == media::VideoCodec::kH264) {
        const std::array<std::string, 2> kH264PacketizationModes = {{"1", "0"}};
        for (const auto& mode : kH264PacketizationModes) {
          webrtc::SdpVideoFormat h264_format = *format;
          h264_format.parameters[cricket::kH264FmtpPacketizationMode] = mode;
          supported_formats.push_back(h264_format);
        }
      } else {
        supported_formats.push_back(*format);
      }
    }
  }

  // Due to https://crbug.com/345569, HW decoders do not distinguish between
  // Constrained Baseline(CBP) and Baseline(BP) profiles. Since CBP is a subset
  // of BP, we can report support for both. It is safe to do so when SW fallback
  // is available.
  // TODO(emircan): Remove this when the bug referred above is fixed.
  cricket::AddH264ConstrainedBaselineProfileToSupportedFormats(
      &supported_formats);

#if BUILDFLAG(RTC_USE_H265)
  if (base::FeatureList::IsEnabled(::features::kWebRtcAllowH265Receive)) {
    // Check HEVC profiles/resolutions by querying |gpu_factories_| directly
    // for all it supports, but limiting to Main and Main10 profiles, as we
    // don't yet have plan to support HEVC range extensions for RTC.
    bool hevc_main_supported = false;
    bool hevc_main10_supported = false;
    gfx::Size hevc_main_max_size(0, 0);
    gfx::Size hevc_main10_max_size(0, 0);
    auto configs = gpu_factories_->GetSupportedVideoDecoderConfigs();
    if (configs) {
      for (auto& config : configs.value()) {
        if (hevc_main_supported && hevc_main10_supported) {
          break;
        }
        // Some video decoders report supported HEVC profiles within the range
        // of profile_min and profile_max; Some others report separate supported
        // configs by setting profile_min and profile_max to the same value.
        if (config.profile_min <= media::HEVCPROFILE_MAIN &&
            config.profile_max >= media::HEVCPROFILE_MAIN) {
          hevc_main_supported = true;
          hevc_main_max_size.SetSize(
              static_cast<float>(config.coded_size_max.width()),
              static_cast<float>(config.coded_size_max.height()));
        }
        if (config.profile_min <= media::HEVCPROFILE_MAIN10 &&
            config.profile_max >= media::HEVCPROFILE_MAIN10) {
          hevc_main10_supported = true;
          hevc_main10_max_size.SetSize(
              static_cast<float>(config.coded_size_max.width()),
              static_cast<float>(config.coded_size_max.height()));
        }
      }
    }
    if (hevc_main_supported) {
      media::VideoDecoderConfig hevc_main_config(
          media::VideoCodec::kHEVC, media::HEVCPROFILE_MAIN,
          media::VideoDecoderConfig::AlphaMode::kIsOpaque,
          media::VideoColorSpace(), media::kNoTransformation,
          hevc_main_max_size, gfx::Rect(hevc_main_max_size), hevc_main_max_size,
          media::EmptyExtraData(), media::EncryptionScheme::kUnencrypted);
      auto format = VdcToWebRtcFormat(hevc_main_config);
      if (format) {
        supported_formats.push_back(*format);
      }
    }
    if (hevc_main10_supported) {
      media::VideoDecoderConfig hevc_main10_config(
          media::VideoCodec::kHEVC, media::HEVCPROFILE_MAIN10,
          media::VideoDecoderConfig::AlphaMode::kIsOpaque,
          media::VideoColorSpace(), media::kNoTransformation,
          hevc_main10_max_size, gfx::Rect(hevc_main10_max_size),
          hevc_main10_max_size, media::EmptyExtraData(),
          media::EncryptionScheme::kUnencrypted);
      auto format = VdcToWebRtcFormat(hevc_main10_config);
      if (format) {
        supported_formats.push_back(*format);
      }
    }
  }
#endif  // BUILDFLAG(RTC_USE_H265)

  return supported_formats;
}

webrtc::VideoDecoderFactory::CodecSupport
RTCVideoDecoderFactory::QueryCodecSupport(const webrtc::SdpVideoFormat& format,
                                          bool reference_scaling) const {
  CheckAndWaitDecoderSupportStatusIfNeeded();

  media::VideoCodec codec =
      WebRtcToMediaVideoCodec(webrtc::PayloadStringToCodecType(format.name));

  // If WebRtcAllowH265Receive is not enabled, report H.265 as unsupported.
  if (codec == media::VideoCodec::kHEVC &&
      !base::FeatureList::IsEnabled(::features::kWebRtcAllowH265Receive)) {
    return {false, false};
  }

  if (reference_scaling) {
    // Check that the configuration is valid (e.g., H264 doesn't support SVC at
    // all and VP8 doesn't support spatial layers).
    if (codec != media::VideoCodec::kVP9 && codec != media::VideoCodec::kAV1) {
      // Invalid reference_scaling, return unsupported.
      return {false, false};
    }
    // Most HW decoders cannot handle reference scaling/spatial layers, so
    // return false if the configuration requires reference scaling unless we
    // explicitly know that the HW decoder can handle this.
    if (codec == media::VideoCodec::kVP9 &&
        !media::IsVp9kSVCHWDecodingEnabled()) {
      return {false, false};
    }
  }

  media::VideoCodecProfile codec_profile =
      WebRtcVideoFormatToMediaVideoCodecProfile(format);
  media::VideoDecoderConfig config(
      codec, codec_profile, media::VideoDecoderConfig::AlphaMode::kIsOpaque,
      media::VideoColorSpace(), media::kNoTransformation, kDefaultSize,
      gfx::Rect(kDefaultSize), kDefaultSize, media::EmptyExtraData(),
      media::EncryptionScheme::kUnencrypted);

  webrtc::VideoDecoderFactory::CodecSupport codec_support;
  // Check gpu_factories for powerEfficient.
  if (gpu_factories_) {
    if (gpu_factories_->IsDecoderConfigSupported(config) ==
        media::GpuVideoAcceleratorFactories::Supported::kTrue) {
      codec_support.is_power_efficient = true;
    }
  }

  // The codec must be supported if it's power efficient.
  codec_support.is_supported = codec_support.is_power_efficient;

  return codec_support;
}

RTCVideoDecoderFactory::~RTCVideoDecoderFactory() {
  DVLOG(2) << __func__;
}

std::unique_ptr<webrtc::VideoDecoder> RTCVideoDecoderFactory::Create(
    const webrtc::Environment& /*env*/,
    const webrtc::SdpVideoFormat& format) {
  TRACE_EVENT0("webrtc", "RTCVideoDecoderFactory::CreateVideoDecoder");
  DVLOG(2) << __func__;
  CheckAndWaitDecoderSupportStatusIfNeeded();

  auto decoder = RTCVideoDecoderAdapter::Create(gpu_factories_, format);

  // ScopedVideoDecoder uses the task runner to make sure the decoder is
  // destructed on the correct thread.
  return decoder ? std::make_unique<ScopedVideoDecoder>(
                       base::SequencedTaskRunner::GetCurrentDefault(),
                       std::move(decoder))
                 : nullptr;
}

}  // namespace blink

"""

```