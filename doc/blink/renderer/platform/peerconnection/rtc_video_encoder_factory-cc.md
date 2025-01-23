Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for a functional summary, relationships to web technologies, logic analysis with examples, and common user/programming errors related to the provided C++ code.

2. **Identify the Core Functionality:** The filename `rtc_video_encoder_factory.cc` and the inclusion of headers like `rtc_video_encoder.h`, `third_party/webrtc/api/video_codecs/video_encoder.h`, and `media/video/gpu_video_accelerator_factories.h` strongly suggest that this code is responsible for creating and managing video encoders within the WebRTC context of the Chromium browser. The "factory" part indicates a design pattern for object creation.

3. **Scan for Key Components and Concepts:**  Look for important data structures, function names, and conditional compilation directives. I see:
    * `RTCVideoEncoderFactory` class: The central class.
    * `Create()` method:  Likely the method that instantiates video encoders.
    * `GetSupportedFormats()` and `QueryCodecSupport()`:  Related to finding and checking supported video codecs.
    * `media::GpuVideoAcceleratorFactories`:  Indicates hardware acceleration is involved.
    * `webrtc::SdpVideoFormat`: A data structure for describing video formats in SDP (Session Description Protocol).
    * `#if BUILDFLAG(...)`: Conditional compilation based on build flags, hinting at platform-specific behavior and feature enabling/disabling.
    * Code for handling specific codecs like VP8, H264, VP9, AV1, and H265.
    * Logic around "profiles" (e.g., H264 Baseline, Main, High).
    * Mentions of "scalability modes" (SVC).

4. **Infer High-Level Functionality:** Based on the key components, I can infer that this code:
    * Determines which video codecs the browser can use for encoding (sending video in WebRTC calls).
    * Takes into account hardware acceleration capabilities provided by the GPU.
    * Handles different profiles and levels within video codecs.
    * Checks for feature flags to enable/disable certain encoding capabilities.
    * Provides information about supported formats to JavaScript through the WebRTC API.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **JavaScript:** This is the most direct connection. WebRTC APIs in JavaScript (`RTCPeerConnection`) are used to establish video calls. This C++ code is the underlying implementation that the JavaScript API relies on to create the actual video encoders. Specifically, when a JavaScript application sets up a video track and starts streaming, the browser needs to choose an encoder. This factory is responsible for that choice.
    * **HTML:** HTML provides the `<video>` element, which can display video streams. While this factory doesn't directly *render* the video, the encoding process it manages is crucial for *sending* video that will eventually be displayed in a remote `<video>` element.
    * **CSS:** CSS styles the visual appearance of the HTML page, including the `<video>` element. There's no direct functional relationship between this encoder factory and CSS. The encoding process is independent of how the video element is styled.

6. **Analyze Logic and Examples:** Focus on the `VEAToWebRTCFormat()` function as it translates hardware capabilities to WebRTC formats. Consider different codec profiles and how they are mapped. Think about the conditions under which a format might be supported or not. Construct simple scenarios:
    * **Input:** A `media::VideoEncodeAccelerator::SupportedProfile` indicating support for H264 Baseline Profile.
    * **Output:** A `webrtc::SdpVideoFormat` for H264 with the appropriate profile level ID parameters.
    * **Input:** A profile for an unsupported H264 profile.
    * **Output:** `std::nullopt`.
    * Consider feature flags: What happens if `kMediaFoundationVP9Encoding` is disabled on Windows?  The code explicitly disables VP9 profiles.

7. **Identify Potential User/Programming Errors:** Think about how developers using the WebRTC API in JavaScript might encounter issues related to this code:
    * **Requesting an unsupported codec:** If a JavaScript application tries to use a codec that the browser (and this factory) doesn't support, the video stream might fail.
    * **Assuming hardware encoding is always available:** Developers might not realize that hardware acceleration can be unavailable or disabled. This C++ code handles fallback scenarios, but developers should be aware of potential performance implications.
    * **Incorrectly configuring codec parameters:** While this factory handles the low-level creation, if the SDP negotiation (handled elsewhere) goes wrong or the JavaScript application specifies incorrect parameters, encoding might fail.
    * **Not checking browser compatibility:**  Different browsers support different codecs. A developer needs to be aware of these limitations.

8. **Structure the Answer:** Organize the findings into clear sections based on the prompt's requirements: Functionality, Relationship to Web Technologies, Logic Analysis, and Common Errors. Use clear and concise language. Provide code snippets or references where necessary to illustrate points.

9. **Review and Refine:**  Read through the answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For example, initially, I might just say it "creates video encoders," but refining it to "creates and manages video encoders *within the WebRTC context* and *taking into account hardware acceleration*" is more precise.

This step-by-step process allows for a thorough understanding of the code's purpose and its interaction with other parts of the system, leading to a comprehensive answer to the request.
好的，让我们来分析一下 `blink/renderer/platform/peerconnection/rtc_video_encoder_factory.cc` 这个文件。

**文件功能概要:**

`rtc_video_encoder_factory.cc` 文件在 Chromium 的 Blink 渲染引擎中，负责创建和管理 WebRTC 视频编码器（`webrtc::VideoEncoder`）的实例。  它的主要功能是：

1. **枚举和选择可用的视频编码器:**  根据系统支持的硬件和软件编码能力，以及通过 feature flags 配置的启用/禁用状态，列出所有可用的视频编码器。
2. **根据请求创建特定的视频编码器:** 当 WebRTC 需要创建一个视频编码器时（例如，在建立 `RTCPeerConnection` 并协商好视频编解码器后），这个工厂会根据指定的格式（`webrtc::SdpVideoFormat`）创建相应的 `RTCVideoEncoder` 实例。
3. **提供支持的视频格式信息:**  向 WebRTC 的其他部分提供当前支持的视频编码格式列表，这些格式会用于 SDP (Session Description Protocol) 的协商，以确定双方可以使用的共同编解码器。
4. **查询编解码器支持情况:**  根据指定的视频格式和可选的 scalability mode，判断当前是否支持该编解码器。
5. **处理不同平台和编译选项的差异:** 通过宏定义 (`BUILDFLAG`) 和 feature flags 来处理不同操作系统和编译配置下的编码器支持情况。例如，在 Windows 上启用或禁用 Media Foundation 提供的硬件编码器。
6. **集成 GPU 加速:**  利用 `media::GpuVideoAcceleratorFactories` 来获取 GPU 硬件加速编码器的支持信息，并创建能够利用 GPU 加速的编码器。
7. **集成性能指标:**  使用 `media::MojoVideoEncoderMetricsProviderFactory` 来提供视频编码器的性能指标。

**与 JavaScript, HTML, CSS 的关系举例:**

这个 C++ 文件本身不直接操作 JavaScript, HTML 或 CSS，但它是 WebRTC 功能的关键组成部分，而 WebRTC 功能是通过 JavaScript API 暴露给 Web 开发者的。

* **JavaScript:**
    * 当 JavaScript 代码使用 `RTCPeerConnection` API 创建一个连接并添加视频轨道时，浏览器会使用 `RTCVideoEncoderFactory` 来创建实际的视频编码器。
    * 例如，在 JavaScript 中：
      ```javascript
      navigator.mediaDevices.getUserMedia({ video: true, audio: true })
        .then(stream => {
          const peerConnection = new RTCPeerConnection();
          stream.getTracks().forEach(track => peerConnection.addTrack(track, stream));

          // ... (协商和发送 offer/answer) ...
        });
      ```
      当 `peerConnection.addTrack(track, stream)` 被调用后，并且在随后的 SDP 协商中确定了视频编解码器，`RTCVideoEncoderFactory` 就会被用来创建相应的编码器来处理 `track` 中的视频帧。
    * `GetSupportedFormats()` 提供的信息最终会影响到 SDP offer 中 `m=video` 行的 `RTP/SAVPF` 部分，列出浏览器支持的视频编解码器（例如 `VP8`, `H264`, `VP9`）。这些信息会被 JavaScript 通过 WebRTC API 获取并用于协商。

* **HTML:**
    * HTML 的 `<video>` 元素用于显示视频流。`RTCVideoEncoderFactory` 负责编码发送出去的视频流，而接收端的浏览器会解码这些视频流并在 `<video>` 元素中显示。虽然它不直接操作 HTML，但它是视频内容能够呈现在 HTML 页面的前提。

* **CSS:**
    * CSS 用于样式化 HTML 元素，包括 `<video>` 元素。`RTCVideoEncoderFactory` 的功能与 CSS 的样式化无关。编码过程专注于视频数据的处理，而不涉及其视觉呈现。

**逻辑推理举例 (假设输入与输出):**

假设 GPU 支持 H.264 Baseline Profile 和 VP8，并且 feature flag `kMediaFoundationH264CbpEncoding` 在 Windows 上被启用。

* **假设输入 (调用 `GetSupportedFormats()`):**  `gpu_factories` 返回的 `SupportedProfile` 列表包含 H.264 Baseline 和 VP8 的信息。`disabled_profiles` 列表为空。
* **逻辑推理:**
    * `VEAToWebRTCFormat` 函数会将 `media::VideoEncodeAccelerator::SupportedProfile` 转换为 `webrtc::SdpVideoFormat`。
    * 对于 H.264 Baseline Profile，由于 `kMediaFoundationH264CbpEncoding` 启用，会额外添加 Constrained Baseline Profile 的支持。
    * 对于 VP8，会直接转换为 "VP8" 格式。
* **预期输出 (部分):**  `GetSupportedFormats()` 返回的 `sdp_formats` 列表中会包含：
    * `webrtc::SdpVideoFormat("VP8")`
    * `webrtc::SdpVideoFormat("H264", {{"profile-level-id", "42e01f"}, {"level-asymmetry-allowed", "1"}, {"packetization-mode", "1"}})`  (Baseline Profile)
    * `webrtc::SdpVideoFormat("H264", {{"profile-level-id", "42001f"}, {"level-asymmetry-allowed", "1"}, {"packetization-mode", "1"}})`  (Constrained Baseline Profile)

**用户或编程常见的使用错误举例:**

1. **假设所有浏览器都支持相同的编解码器:**
   * **错误:**  开发者可能假设所有用户的浏览器都支持 H.265，然后在 SDP 协商中只提供 H.265 作为唯一选择。如果用户的浏览器不支持 H.265，视频连接将会失败。
   * **正确做法:**  在 SDP offer 中提供多种常见的编解码器选项（例如 VP8, H.264, VP9），以便在双方之间找到共同支持的编解码器。

2. **忽略硬件加速的可用性:**
   * **错误:**  开发者可能没有考虑到用户的硬件环境，并期望始终能够使用高性能的硬件编码器。如果硬件加速不可用（例如，GPU 驱动问题或在虚拟机中运行），编码性能可能会很差。
   * **虽然 `RTCVideoEncoderFactory` 内部会处理软件编码器的回退，但了解硬件加速的重要性可以帮助开发者更好地理解性能瓶颈。**

3. **错误地配置 feature flags 或编译选项:**
   * **错误:**  如果开发者或部署人员错误地配置了 Chromium 的 feature flags（例如禁用了某个重要的硬件编码器），即使硬件本身支持，该编码器也无法被 `RTCVideoEncoderFactory` 检测到和使用。
   * **这通常是 Chromium 内部的配置问题，但了解 feature flags 的作用有助于排查一些奇怪的编解码器支持问题。**

4. **手动指定不支持的编解码器:**
   * **错误:**  虽然通常 WebRTC 的协商机制会处理编解码器的选择，但在某些高级场景下，开发者可能会尝试手动指定编解码器。如果指定了一个 `RTCVideoEncoderFactory` 不支持的编解码器，创建编码器将会失败。

5. **未处理 `QueryCodecSupport` 的结果:**
   * **错误:**  开发者可能没有充分利用 `QueryCodecSupport` 方法来预先检查特定编解码器和 scalability mode 的支持情况，导致在尝试创建编码器时才发现不支持。
   * **正确做法:**  在需要精细控制编解码器选择的情况下，可以使用 `QueryCodecSupport` 来确保所选的编解码器是支持的。

总而言之，`rtc_video_encoder_factory.cc` 是 Chromium 中 WebRTC 视频编码功能的核心组件，它负责管理和创建视频编码器，并根据系统能力和配置提供支持的编解码器信息。理解它的功能有助于理解 WebRTC 视频通信的底层机制。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_encoder_factory.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/peerconnection/rtc_video_encoder_factory.h"

#include <memory>

#include "base/containers/contains.h"
#include "base/logging.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "media/base/media_switches.h"
#include "media/base/supported_types.h"
#include "media/media_buildflags.h"
#include "media/mojo/clients/mojo_video_encoder_metrics_provider.h"
#include "media/video/gpu_video_accelerator_factories.h"
#include "media/webrtc/webrtc_features.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/allow_discouraged_type.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_video_encoder.h"
#include "third_party/blink/renderer/platform/peerconnection/webrtc_util.h"
#include "third_party/webrtc/api/video/resolution.h"
#include "third_party/webrtc/api/video_codecs/h264_profile_level_id.h"
#include "third_party/webrtc/api/video_codecs/sdp_video_format.h"
#include "third_party/webrtc/api/video_codecs/video_encoder.h"
#include "third_party/webrtc/api/video_codecs/vp9_profile.h"
#include "third_party/webrtc/media/base/codec.h"
#include "third_party/webrtc/modules/video_coding/svc/scalability_mode_util.h"

#if BUILDFLAG(RTC_USE_H265)
#include "third_party/webrtc/api/video_codecs/h265_profile_tier_level.h"
#endif  // BUILDFLAG(RTC_USE_H265)

namespace blink {

namespace {

#if BUILDFLAG(IS_WIN)
// Enables AV1 encode acceleration for Windows.
BASE_FEATURE(kMediaFoundationAV1Encoding,
             "MediaFoundationAV1Encoding",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Enables H.264 CBP encode acceleration for Windows.
BASE_FEATURE(kMediaFoundationH264CbpEncoding,
             "MediaFoundationH264CbpEncoding",
             base::FEATURE_DISABLED_BY_DEFAULT);

// Enables VP9 encode acceleration for Windows.
BASE_FEATURE(kMediaFoundationVP9Encoding,
             "MediaFoundationVP9Encoding",
             base::FEATURE_ENABLED_BY_DEFAULT);
#endif

// Convert media::SVCScalabilityMode to webrtc::ScalabilityMode and fill
// format.scalability_modes.
void FillScalabilityModes(
    webrtc::SdpVideoFormat& format,
    const media::VideoEncodeAccelerator::SupportedProfile& profile) {
  bool disable_h265_l1t2 =
      !base::FeatureList::IsEnabled(::features::kWebRtcH265L1T2);
  bool disable_h265_l1t3 =
      disable_h265_l1t2 ||
      !base::FeatureList::IsEnabled(::features::kWebRtcH265L1T3);

  for (const media::SVCScalabilityMode& mode : profile.scalability_modes) {
    std::optional<webrtc::ScalabilityMode> scalability_mode =
        webrtc::ScalabilityModeFromString(media::GetScalabilityModeName(mode));
    if (!scalability_mode.has_value()) {
      LOG(WARNING) << "Unrecognized SVC scalability mode: "
                   << media::GetScalabilityModeName(mode);
      continue;
    }

    if (profile.profile >= media::HEVCPROFILE_MIN &&
        profile.profile <= media::HEVCPROFILE_MAX) {
      if ((scalability_mode == webrtc::ScalabilityMode::kL1T2 &&
           disable_h265_l1t2) ||
          (scalability_mode == webrtc::ScalabilityMode::kL1T3 &&
           disable_h265_l1t3)) {
        continue;
      }
    }

    format.scalability_modes.push_back(scalability_mode.value());
  }
}

// Translate from media::VideoEncodeAccelerator::SupportedProfile to
// webrtc::SdpVideoFormat, or return nothing if the profile isn't supported.
std::optional<webrtc::SdpVideoFormat> VEAToWebRTCFormat(
    const media::VideoEncodeAccelerator::SupportedProfile& profile) {
  const int width = profile.max_resolution.width();
  const int height = profile.max_resolution.height();
  const int fps = profile.max_framerate_numerator;
  DCHECK_EQ(1u, profile.max_framerate_denominator);

  if (profile.profile >= media::VP8PROFILE_MIN &&
      profile.profile <= media::VP8PROFILE_MAX) {
    webrtc::SdpVideoFormat format("VP8");
    FillScalabilityModes(format, profile);
    return format;
  }
  if (profile.profile >= media::H264PROFILE_MIN &&
      profile.profile <= media::H264PROFILE_MAX) {
#if !BUILDFLAG(IS_ANDROID)
    // Enable H264 HW encode for WebRTC when SW fallback is available, which is
    // checked by kWebRtcH264WithOpenH264FFmpeg flag. This check should be
    // removed when SW implementation is fully enabled.
    bool webrtc_h264_sw_enabled = false;
// TODO(crbug.com/355256378): OpenH264 for encoding and FFmpeg for H264 decoding
// should be detangled such that software decoding can be enabled without
// software encoding.
#if BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) && \
    BUILDFLAG(ENABLE_OPENH264)
    webrtc_h264_sw_enabled = base::FeatureList::IsEnabled(
        blink::features::kWebRtcH264WithOpenH264FFmpeg);
#endif  // BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) &&
        // BUILDFLAG(ENABLE_OPENH264)
    if (!webrtc_h264_sw_enabled) {
      return std::nullopt;
    }
#endif

    webrtc::H264Profile h264_profile;
    switch (profile.profile) {
      case media::H264PROFILE_BASELINE:
#if BUILDFLAG(IS_ANDROID)
        // Force HW H264 on Android to be CBP for most compatibility, since:
        // - Only HW H264 is available on Android at present.
        // - MediaCodec only advise BP, which works same as CBP in most cases.
        // - Some peers only expect CBP in negotiation.
        h264_profile = webrtc::H264Profile::kProfileConstrainedBaseline;
#else
        h264_profile = webrtc::H264Profile::kProfileBaseline;
#endif  // BUILDFLAG(IS_ANDROID)
        break;
      case media::H264PROFILE_MAIN:
        h264_profile = webrtc::H264Profile::kProfileMain;
        break;
      case media::H264PROFILE_HIGH:
        h264_profile = webrtc::H264Profile::kProfileHigh;
        break;
      default:
        // Unsupported H264 profile in WebRTC.
        return std::nullopt;
    }

    const std::optional<webrtc::H264Level> h264_level =
        webrtc::H264SupportedLevel(width * height, fps);
    const webrtc::H264ProfileLevelId profile_level_id(
        h264_profile, h264_level.value_or(webrtc::H264Level::kLevel1));
    const std::optional<std::string> h264_profile_level_string =
        webrtc::H264ProfileLevelIdToString(profile_level_id);
    if (!h264_profile_level_string) {
      // Unsupported combination of profile and level.
      return std::nullopt;
    }

    webrtc::SdpVideoFormat format("H264");
    format.parameters = {
        {cricket::kH264FmtpProfileLevelId, *h264_profile_level_string},
        {cricket::kH264FmtpLevelAsymmetryAllowed, "1"},
        {cricket::kH264FmtpPacketizationMode, "1"}};
    FillScalabilityModes(format, profile);
    return format;
  }

  if (profile.profile >= media::VP9PROFILE_MIN &&
      profile.profile <= media::VP9PROFILE_MAX) {
    webrtc::VP9Profile vp9_profile;
    switch (profile.profile) {
      case media::VP9PROFILE_PROFILE0:
        vp9_profile = webrtc::VP9Profile::kProfile0;
        break;
      case media::VP9PROFILE_PROFILE2:
        vp9_profile = webrtc::VP9Profile::kProfile2;
        break;
      default:
        // Unsupported VP9 profiles (profile1 & profile3) in WebRTC.
        return std::nullopt;
    }
    webrtc::SdpVideoFormat format("VP9");
    format.parameters = {
        {webrtc::kVP9FmtpProfileId,
         webrtc::VP9ProfileToString(vp9_profile)}};
    FillScalabilityModes(format, profile);
    return format;
  }

  if (profile.profile >= media::AV1PROFILE_MIN &&
      profile.profile <= media::AV1PROFILE_MAX) {
    webrtc::SdpVideoFormat format("AV1");
    FillScalabilityModes(format, profile);
    return format;
  }

  if (profile.profile >= media::HEVCPROFILE_MIN &&
      profile.profile <= media::HEVCPROFILE_MAX) {
#if BUILDFLAG(RTC_USE_H265)
    // Unlikely H.264, there is no SW encoder implementation for H.265, so we
    // will not check SW support here.
    webrtc::H265Profile h265_profile;
    switch (profile.profile) {
      case media::HEVCPROFILE_MAIN:
        h265_profile = webrtc::H265Profile::kProfileMain;
        break;
      case media::HEVCPROFILE_MAIN10:
        h265_profile = webrtc::H265Profile::kProfileMain10;
        break;
      default:
        // Unsupported H.265 profiles(main still/range extensions etc) in
        // WebRTC.
        return std::nullopt;
    }
    const webrtc::Resolution resolution = {
        .width = width,
        .height = height,
    };
    const std::optional<webrtc::H265Level> h265_level =
        webrtc::GetSupportedH265Level(resolution, fps);
    const webrtc::H265ProfileTierLevel profile_tier_level(
        h265_profile, webrtc::H265Tier::kTier0,
        h265_level.value_or(webrtc::H265Level::kLevel1));
    webrtc::SdpVideoFormat format("H265");
    format.parameters = {
        {cricket::kH265FmtpProfileId,
         webrtc::H265ProfileToString(profile_tier_level.profile)},
        {cricket::kH265FmtpTierFlag,
         webrtc::H265TierToString(profile_tier_level.tier)},
        {cricket::kH265FmtpLevelId,
         webrtc::H265LevelToString(profile_tier_level.level)},
        {cricket::kH265FmtpTxMode, "SRST"}};
    FillScalabilityModes(format, profile);
    return format;
#else
    return std::nullopt;
#endif  // BUILDFLAG(RTC_USE_H265)
  }

  return std::nullopt;
}  // namespace

struct SupportedFormats {
  bool unknown = true;
  std::vector<media::VideoCodecProfile> profiles
      ALLOW_DISCOURAGED_TYPE("Matches webrtc API");
  std::vector<webrtc::SdpVideoFormat> sdp_formats
      ALLOW_DISCOURAGED_TYPE("Matches webrtc API");
};

#if BUILDFLAG(RTC_USE_H265)
// Insert or replace the H.265 format in |supported_formats| with the higher
// level for the same profile. Assume VEA always reports same scalability modes
// for the same video profile, the scalability mode of the highest level format
// will be used, and we don't handle the case that same profile has different
// scalability modes.
void InsertOrReplaceWithHigherLevelH265Format(
    SupportedFormats* supported_formats,
    const webrtc::SdpVideoFormat& format,
    media::VideoCodecProfile profile) {
  std::optional<webrtc::H265ProfileTierLevel> new_profile_tier_level =
      webrtc::ParseSdpForH265ProfileTierLevel(format.parameters);
  if (!new_profile_tier_level.has_value()) {
    return;
  }

  DCHECK_EQ(supported_formats->profiles.size(),
            supported_formats->sdp_formats.size());

  std::optional<webrtc::H265ProfileTierLevel> existing_profile_tier_level;
  auto profile_it = std::find(supported_formats->profiles.begin(),
                              supported_formats->profiles.end(), profile);

  if (profile_it != supported_formats->profiles.end()) {
    auto index = std::distance(supported_formats->profiles.begin(), profile_it);
    existing_profile_tier_level = webrtc::ParseSdpForH265ProfileTierLevel(
        supported_formats->sdp_formats[index].parameters);

    if (existing_profile_tier_level.has_value() &&
        new_profile_tier_level->level > existing_profile_tier_level->level) {
      supported_formats->sdp_formats[index] = format;
    }
  } else {
    supported_formats->sdp_formats.push_back(format);
    supported_formats->profiles.push_back(profile);
  }
}
#endif

SupportedFormats GetSupportedFormatsInternal(
    media::GpuVideoAcceleratorFactories* gpu_factories,
    const std::vector<media::VideoCodecProfile>& disabled_profiles) {
  SupportedFormats supported_formats;
  SupportedFormats low_priority_formats;

  auto profiles = gpu_factories->GetVideoEncodeAcceleratorSupportedProfiles();
  if (!profiles)
    return supported_formats;

  // |profiles| are either the info at GpuInfo instance or the info got by
  // querying GPU process.
  supported_formats.unknown = false;
  for (const auto& profile : *profiles) {
    // Skip if profile is OS software encoder profile and we don't allow use
    // OS software encoder.
    if (profile.is_software_codec &&
        !media::MayHaveAndAllowSelectOSSoftwareEncoder(
            media::VideoCodecProfileToVideoCodec(profile.profile))) {
      continue;
    }

    if (base::Contains(disabled_profiles, profile.profile)) {
      continue;
    }

    std::optional<webrtc::SdpVideoFormat> format = VEAToWebRTCFormat(profile);
    if (format) {
      if (format->IsCodecInList(supported_formats.sdp_formats)) {
        continue;
      }
      // Supported H.265 formats must be added to the end of supported codecs.
#if BUILDFLAG(RTC_USE_H265)
      if (format->name == cricket::kH265CodecName) {
        // Avoid having duplicated formats reported via GetSupportedFormats().
        // Also ensure only the highest level format is reported for the same
        // H.265 profile.
        InsertOrReplaceWithHigherLevelH265Format(
            &low_priority_formats, format.value(), profile.profile);
        continue;
      }
#endif  // BUILDFLAG(RTC_USE_H265)
      supported_formats.profiles.push_back(profile.profile);
      supported_formats.sdp_formats.push_back(std::move(*format));

#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
#if BUILDFLAG(IS_WIN)
      const bool kShouldAddH264Cbp =
          base::FeatureList::IsEnabled(kMediaFoundationH264CbpEncoding) &&
          profile.profile == media::VideoCodecProfile::H264PROFILE_BASELINE;
#elif BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
      const bool kShouldAddH264Cbp =
          profile.profile == media::VideoCodecProfile::H264PROFILE_BASELINE;
#endif
      if (kShouldAddH264Cbp) {
        supported_formats.profiles.push_back(profile.profile);
        cricket::AddH264ConstrainedBaselineProfileToSupportedFormats(
            &supported_formats.sdp_formats);
      }
#endif
    }
  }

  supported_formats.profiles.insert(supported_formats.profiles.end(),
                                    low_priority_formats.profiles.begin(),
                                    low_priority_formats.profiles.end());
  supported_formats.sdp_formats.insert(supported_formats.sdp_formats.end(),
                                       low_priority_formats.sdp_formats.begin(),
                                       low_priority_formats.sdp_formats.end());

  DCHECK_EQ(supported_formats.profiles.size(),
            supported_formats.sdp_formats.size());

  return supported_formats;
}

bool IsConstrainedH264(const webrtc::SdpVideoFormat& format) {
  bool is_constrained_h264 = false;

  if (format.name == cricket::kH264CodecName) {
    const std::optional<webrtc::H264ProfileLevelId> profile_level_id =
        webrtc::ParseSdpForH264ProfileLevelId(format.parameters);
    if (profile_level_id &&
        profile_level_id->profile ==
            webrtc::H264Profile::kProfileConstrainedBaseline) {
      is_constrained_h264 = true;
    }
  }

  return is_constrained_h264;
}

}  // anonymous namespace

RTCVideoEncoderFactory::RTCVideoEncoderFactory(
    media::GpuVideoAcceleratorFactories* gpu_factories,
    scoped_refptr<media::MojoVideoEncoderMetricsProviderFactory>
        encoder_metrics_provider_factory)
    : gpu_factories_(gpu_factories),
      encoder_metrics_provider_factory_(
          std::move(encoder_metrics_provider_factory)),
      gpu_codec_support_waiter_(gpu_factories) {
#if BUILDFLAG(IS_WIN)
  if (!base::FeatureList::IsEnabled(kMediaFoundationVP9Encoding)) {
    disabled_profiles_.emplace_back(media::VP9PROFILE_PROFILE0);
    disabled_profiles_.emplace_back(media::VP9PROFILE_PROFILE1);
    disabled_profiles_.emplace_back(media::VP9PROFILE_PROFILE2);
    disabled_profiles_.emplace_back(media::VP9PROFILE_PROFILE3);
  }
  if (!base::FeatureList::IsEnabled(kMediaFoundationAV1Encoding)) {
    disabled_profiles_.emplace_back(media::AV1PROFILE_PROFILE_MAIN);
    disabled_profiles_.emplace_back(media::AV1PROFILE_PROFILE_HIGH);
    disabled_profiles_.emplace_back(media::AV1PROFILE_PROFILE_PRO);
  }
#endif  // BUILDFLAG(IS_WIN)

#if BUILDFLAG(RTC_USE_H265)
  // We may not need to add check for media::kPlatformHEVCEncoderSupport here
  // but it's added for consistency with other codecs like H264 and AV1.
  if (
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)
      !base::FeatureList::IsEnabled(media::kPlatformHEVCEncoderSupport) ||
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)
      !base::FeatureList::IsEnabled(::features::kWebRtcAllowH265Send)) {
    disabled_profiles_.emplace_back(media::HEVCPROFILE_MAIN);
    disabled_profiles_.emplace_back(media::HEVCPROFILE_MAIN10);
    disabled_profiles_.emplace_back(media::HEVCPROFILE_MAIN_STILL_PICTURE);
    disabled_profiles_.emplace_back(media::HEVCPROFILE_REXT);
    disabled_profiles_.emplace_back(media::HEVCPROFILE_HIGH_THROUGHPUT);
    disabled_profiles_.emplace_back(media::HEVCPROFILE_MULTIVIEW_MAIN);
    disabled_profiles_.emplace_back(media::HEVCPROFILE_SCALABLE_MAIN);
    disabled_profiles_.emplace_back(media::HEVCPROFILE_3D_MAIN);
    disabled_profiles_.emplace_back(media::HEVCPROFILE_SCREEN_EXTENDED);
    disabled_profiles_.emplace_back(media::HEVCPROFILE_SCALABLE_REXT);
    disabled_profiles_.emplace_back(
        media::HEVCPROFILE_HIGH_THROUGHPUT_SCREEN_EXTENDED);
  }
#endif  // BUILDFLAG(RTC_USE_H265)
}

RTCVideoEncoderFactory::~RTCVideoEncoderFactory() {
  // |encoder_metrics_provider_factory_| needs to be destroyed on the same
  // sequence as one that destroys the VideoEncoderMetricsProviders created by
  // it. It is gpu task runner in this case.
  gpu_factories_->GetTaskRunner()->ReleaseSoon(
      FROM_HERE, std::move(encoder_metrics_provider_factory_));
}

void RTCVideoEncoderFactory::CheckAndWaitEncoderSupportStatusIfNeeded() const {
  if (!gpu_codec_support_waiter_.IsEncoderSupportKnown()) {
    DLOG(WARNING) << "Encoder support is unknown. Timeout "
                  << gpu_codec_support_waiter_.wait_timeout_ms()
                         .value_or(base::TimeDelta())
                         .InMilliseconds()
                  << "ms. Encoders might not be available.";
  }
}

std::unique_ptr<webrtc::VideoEncoder> RTCVideoEncoderFactory::Create(
    const webrtc::Environment& env,
    const webrtc::SdpVideoFormat& format) {
  CheckAndWaitEncoderSupportStatusIfNeeded();

  std::unique_ptr<webrtc::VideoEncoder> encoder;
  bool is_constrained_h264 = IsConstrainedH264(format);
  auto supported_formats =
      GetSupportedFormatsInternal(gpu_factories_, disabled_profiles_);
  if (!supported_formats.unknown) {
    for (size_t i = 0; i < supported_formats.sdp_formats.size(); ++i) {
      if (format.IsSameCodec(supported_formats.sdp_formats[i])) {
        encoder = std::make_unique<RTCVideoEncoder>(
            supported_formats.profiles[i], is_constrained_h264, gpu_factories_,
            encoder_metrics_provider_factory_);
        break;
      }
    }
  } else {
    auto profile = WebRTCFormatToCodecProfile(format);
    if (profile) {
      encoder = std::make_unique<RTCVideoEncoder>(
          *profile, is_constrained_h264, gpu_factories_,
          encoder_metrics_provider_factory_);
    }
  }

  return encoder;
}

std::vector<webrtc::SdpVideoFormat>
RTCVideoEncoderFactory::GetSupportedFormats() const {
  CheckAndWaitEncoderSupportStatusIfNeeded();

  return GetSupportedFormatsInternal(gpu_factories_, disabled_profiles_)
      .sdp_formats;
}

webrtc::VideoEncoderFactory::CodecSupport
RTCVideoEncoderFactory::QueryCodecSupport(
    const webrtc::SdpVideoFormat& format,
    std::optional<std::string> scalability_mode) const {
  CheckAndWaitEncoderSupportStatusIfNeeded();
  SupportedFormats supported_formats =
      GetSupportedFormatsInternal(gpu_factories_, disabled_profiles_);

  for (size_t i = 0; i < supported_formats.sdp_formats.size(); ++i) {
    if (format.IsSameCodec(supported_formats.sdp_formats[i])) {
#if BUILDFLAG(RTC_USE_H265)
      // For H.265 we further check that the level-id supported is no smaller
      // than that being queried.
      if (format.name == cricket::kH265CodecName) {
        const std::optional<webrtc::H265ProfileTierLevel> profile_tier_level =
            webrtc::ParseSdpForH265ProfileTierLevel(format.parameters);
        if (profile_tier_level) {
          const std::optional<webrtc::H265ProfileTierLevel> supported_profile =
              webrtc::ParseSdpForH265ProfileTierLevel(
                  supported_formats.sdp_formats[i].parameters);
          if (supported_profile &&
              profile_tier_level->level > supported_profile->level) {
            return {/*is_supported=*/false, /*is_power_efficient=*/false};
          }
        } else {
          // If invalid format parameters are passed, we should not support it.
          break;
        }
      }
#endif  // BUILDFLAG(RTC_USE_H265)
      std::optional<webrtc::ScalabilityMode> mode =
          scalability_mode.has_value()
              ? webrtc::ScalabilityModeFromString(scalability_mode.value())
              : std::nullopt;
      if (!scalability_mode ||
          (mode.has_value() &&
           base::Contains(supported_formats.sdp_formats[i].scalability_modes,
                          mode.value()))) {
        return {/*is_supported=*/true, /*is_power_efficient=*/true};
      }
      break;
    }
  }
  return {/*is_supported=*/false, /*is_power_efficient=*/false};
}

}  // namespace blink
```