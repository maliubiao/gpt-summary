Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Understand the Goal:** The request is to understand the functionality of the `webrtc_video_utils.cc` file in the Blink rendering engine. Specifically, to identify its purpose, relationships to web technologies (JavaScript, HTML, CSS), infer logic, and point out potential user/programmer errors.

2. **Initial Skim for Keywords and Structure:**  Read through the code quickly to get a general idea. Keywords like `WebRtcToMedia`, `MediaToWebRtc`, `VideoRotation`, `VideoCodec`, `ColorSpace` stand out. The code consists primarily of functions, mostly `switch` statements. Includes like `<stdint.h>`, `<string>` aren't present, suggesting it deals with higher-level abstractions rather than low-level data manipulation. The includes `third_party/webrtc/...` and  `third_party/blink/public/common/features.h` strongly indicate interaction with the WebRTC library and Blink-specific features.

3. **Identify Core Functionality - Type Conversion:** The naming convention of the functions (`WebRtcToMediaVideoRotation`, `WebRtcToMediaVideoCodec`, etc.) strongly suggests the primary purpose is converting between WebRTC's internal representation of video properties and Blink's internal representation (likely used in the media pipeline).

4. **Analyze Individual Functions:** Go through each function and determine its specific conversion task.

    * **`WebRtcToMediaVideoRotation`:**  Converts WebRTC's `VideoRotation` enum to Blink's `media::VideoRotation` enum. This is a straightforward mapping.

    * **`WebRtcToMediaVideoCodec`:** Converts WebRTC's `VideoCodecType` enum to Blink's `media::VideoCodec` enum. Another direct mapping. The `#if BUILDFLAG(RTC_USE_H265)` suggests conditional compilation based on whether H.265 support is enabled.

    * **`WebRtcVideoFormatToMediaVideoCodecProfile`:**  This is more complex. It takes a `webrtc::SdpVideoFormat`, extracts the codec type, and then *parses parameters* within the format to determine the *profile*. This shows a deeper level of information extraction beyond just the basic codec type. The use of `std::optional` indicates that parsing these parameters might fail, leading to an "unknown" profile.

    * **`WebRtcToGfxColorSpace`:** Converts WebRTC's `ColorSpace` object to Blink's `gfx::ColorSpace` object. This involves mapping various color space attributes (primaries, transfer, matrix, range) individually. The `switch` statements handle the mapping of different standard identifiers.

    * **`GfxToWebRtcColorSpace`:**  The reverse of the previous function, converting Blink's `gfx::ColorSpace` to WebRTC's `ColorSpace`. Similar mapping logic, with `DVLOG(1)` indicating potential logging for unsupported values.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** Think about where these video properties are relevant in web development.

    * **JavaScript:**  The WebRTC API in JavaScript (`RTCPeerConnection`, `MediaStreamTrack`, etc.) is where these properties are exposed and manipulated. For example, when negotiating a video codec, JavaScript sets parameters that eventually get translated using these functions.

    * **HTML:** The `<video>` element is where the decoded video is ultimately displayed. The codec and color space information are crucial for the browser to render the video correctly.

    * **CSS:**  While CSS doesn't directly deal with video codecs or low-level color space information, it can influence the visual presentation of the `<video>` element (size, positioning, transformations). It's important to note the *indirect* relationship.

6. **Infer Logic and Provide Examples:** For functions like `WebRtcVideoFormatToMediaVideoCodecProfile`, it's useful to create hypothetical input and output scenarios to demonstrate the parameter parsing logic. Think about how SDP (Session Description Protocol) strings represent codec profiles.

7. **Identify Potential Errors:** Consider how developers might misuse the underlying WebRTC API or misunderstand the implications of different video codecs and color spaces.

    * **Incorrect SDP:**  Manually crafting SDP strings with invalid profile information can lead to errors that this code tries to handle (returning "unknown" profile).

    * **Mismatched Codec Capabilities:**  If the sender and receiver don't agree on a compatible codec or profile, video transmission will fail.

    * **Ignoring Color Space:**  Not handling color space information correctly can result in videos appearing washed out, oversaturated, or with incorrect colors.

8. **Structure the Answer:** Organize the findings into logical sections: Functionality, Relationship to Web Technologies, Logic Inference, and Common Errors. Use clear and concise language. Provide specific examples where possible.

9. **Review and Refine:** Read through the answer to ensure accuracy and clarity. Check for any ambiguities or areas where more detail might be helpful. Make sure the examples are relevant and easy to understand. For instance, initially, I might focus solely on the direct conversions, but then realize the parameter parsing in `WebRtcVideoFormatToMediaVideoCodecProfile` is a significant aspect worth highlighting. Also, ensuring the explanations for the web technology relationships clearly distinguish between direct and indirect involvement is important.
这个文件 `webrtc_video_utils.cc` 的主要功能是**在 Chromium 的 Blink 渲染引擎中，用于 WebRTC 和 Chromium 媒体框架之间进行视频相关的类型转换和信息转换。**  它定义了一系列实用函数，用于在 WebRTC 库中使用的视频数据结构和 Chromium 媒体框架中使用的对应数据结构之间进行映射。

以下是更详细的功能分解和说明：

**主要功能：**

1. **WebRTC 视频旋转角度到 Chromium 媒体旋转角度的转换:**
   - 函数：`WebRtcToMediaVideoRotation(webrtc::VideoRotation rotation)`
   - 功能：将 WebRTC 的 `webrtc::VideoRotation` 枚举值（例如 `kVideoRotation_0`, `kVideoRotation_90` 等）转换为 Chromium 媒体框架的 `media::VideoRotation` 枚举值（例如 `VIDEO_ROTATION_0`, `VIDEO_ROTATION_90` 等）。这在处理视频流的旋转信息时非常有用。

2. **WebRTC 视频编解码器类型到 Chromium 媒体编解码器类型的转换:**
   - 函数：`WebRtcToMediaVideoCodec(webrtc::VideoCodecType codec)`
   - 功能：将 WebRTC 的 `webrtc::VideoCodecType` 枚举值（例如 `kVideoCodecVP8`, `kVideoCodecH264` 等）转换为 Chromium 媒体框架的 `media::VideoCodec` 枚举值（例如 `VideoCodec::kVP8`, `VideoCodec::kH264` 等）。 这在协商和处理不同的视频编解码器时非常重要。

3. **WebRTC 视频格式到 Chromium 媒体视频编解码器配置的转换:**
   - 函数：`WebRtcVideoFormatToMediaVideoCodecProfile(const webrtc::SdpVideoFormat& format)`
   - 功能：接收一个 WebRTC 的 `webrtc::SdpVideoFormat` 对象，该对象包含视频编解码器的名称和参数，然后根据这些信息解析出对应的 Chromium 媒体框架的 `media::VideoCodecProfile` 枚举值（例如 `VP9PROFILE_PROFILE0`, `H264PROFILE_MAIN` 等）。  这涉及到解析 SDP (Session Description Protocol) 中关于视频编解码器 profile 的信息。

4. **WebRTC 色彩空间到 Chromium 图形色彩空间的转换:**
   - 函数：`WebRtcToGfxColorSpace(const webrtc::ColorSpace& color_space)`
   - 功能：将 WebRTC 的 `webrtc::ColorSpace` 对象转换为 Chromium 的 `gfx::ColorSpace` 对象。 这包括映射色彩空间的原色 (primaries)、传递函数 (transfer)、矩阵 (matrix) 和范围 (range) 等属性。

5. **Chromium 图形色彩空间到 WebRTC 色彩空间的转换:**
   - 函数：`GfxToWebRtcColorSpace(const gfx::ColorSpace& color_space)`
   - 功能：执行与 `WebRtcToGfxColorSpace` 相反的转换，将 Chromium 的 `gfx::ColorSpace` 对象转换为 WebRTC 的 `webrtc::ColorSpace` 对象。

**与 JavaScript, HTML, CSS 的关系：**

这个文件本身是 C++ 代码，不直接与 JavaScript, HTML, CSS 交互。但是，它所提供的功能是 WebRTC API 实现的关键部分，而 WebRTC API 是可以通过 JavaScript 在网页中使用的。

* **JavaScript:**
    - 当 JavaScript 代码使用 WebRTC API（例如 `RTCPeerConnection`）进行视频通信时，需要协商视频编解码器、分辨率、帧率等参数。
    - `WebRtcVideoFormatToMediaVideoCodecProfile` 中解析的 SDP 信息，正是 JavaScript 中 WebRTC API  在会话协商过程中产生的。例如，JavaScript 代码可能会设置 `RTCRtpSender` 的 `codecPreferences`，这些偏好会被转换为 SDP，而这个文件中的代码就负责解析这些 SDP 信息。
    - 同样，JavaScript 代码可以通过 `MediaStreamTrack` 的 API 获取或设置视频轨道的色彩空间信息，这些信息最终会通过 `GfxToWebRtcColorSpace` 或 `WebRtcToGfxColorSpace` 进行转换。

* **HTML:**
    - HTML 的 `<video>` 元素用于显示视频内容。当 WebRTC 连接建立并接收到视频流后，Blink 渲染引擎会使用这个文件中的转换函数来理解和处理接收到的视频数据的格式和属性，最终在 `<video>` 元素中正确渲染视频。例如，如果协商的视频编码是 H.264 Main Profile，`WebRtcVideoFormatToMediaVideoCodecProfile` 会将其转换为 `media::H264PROFILE_MAIN`，Blink 会根据这个 profile 来解码和显示视频。

* **CSS:**
    - CSS 主要负责样式和布局，它不直接处理视频编解码器或色彩空间等底层信息。但是，CSS 可以影响 `<video>` 元素的呈现方式，例如大小、位置、旋转等。  `WebRtcToMediaVideoRotation` 的转换结果可能会影响视频在页面上的初始显示方向。

**逻辑推理与假设输入输出：**

**示例 1：`WebRtcToMediaVideoCodec`**

* **假设输入:** `webrtc::kVideoCodecVP9`
* **逻辑:**  `switch` 语句会匹配 `webrtc::kVideoCodecVP9`，并返回对应的 `media::VideoCodec::kVP9`。
* **输出:** `media::VideoCodec::kVP9`

**示例 2：`WebRtcVideoFormatToMediaVideoCodecProfile`**

* **假设输入:** 一个 `webrtc::SdpVideoFormat` 对象，其 `name` 为 "VP9"，`parameters` 包含 `"profile-id=1"`。
* **逻辑:**
    1. `webrtc::PayloadStringToCodecType("VP9")` 返回 `webrtc::kVideoCodecVP9`。
    2. 进入 `case webrtc::kVideoCodecVP9:` 分支。
    3. `webrtc::ParseSdpForVP9Profile(format.parameters)` 解析参数 `"profile-id=1"`，返回 `std::optional<webrtc::VP9Profile>(webrtc::VP9Profile::kProfile1)`。
    4. `switch (*vp9_profile)` 会匹配 `webrtc::VP9Profile::kProfile1`。
* **输出:** `media::VP9PROFILE_PROFILE1`

* **假设输入:** 一个 `webrtc::SdpVideoFormat` 对象，其 `name` 为 "H264"，`parameters` 包含 `"profile-level-id=42e01f"` (对应 H.264 Baseline Profile Level 3.1)。
* **逻辑:**
    1. `webrtc::PayloadStringToCodecType("H264")` 返回 `webrtc::kVideoCodecH264`。
    2. 进入 `case webrtc::kVideoCodecH264:` 分支。
    3. `webrtc::ParseSdpForH264ProfileLevelId(format.parameters)` 解析参数 `"profile-level-id=42e01f"`，返回一个包含 `webrtc::H264Profile::kProfileBaseline` 的 `std::optional`。
    4. `switch (h264_profile_level_id->profile)` 会匹配 `webrtc::H264Profile::kProfileBaseline`。
* **输出:** `media::H264PROFILE_BASELINE`

**用户或编程常见的使用错误举例：**

1. **在 JavaScript 中错误地配置 SDP 参数：**
   - **错误:** 手动构建 SDP 字符串时，为某个编解码器设置了不存在或不合法的 profile-id。例如，为 VP9 设置了 `"profile-id=99"`。
   - **结果:** `WebRtcVideoFormatToMediaVideoCodecProfile` 在解析时会返回 `media::VIDEO_CODEC_PROFILE_UNKNOWN`，这可能导致视频解码失败或选择了错误的解码器配置。

2. **忽略色彩空间信息的匹配：**
   - **错误:** 在 WebRTC 连接的两端，发送方和接收方对视频的色彩空间理解不一致，但程序没有进行合适的色彩空间转换。
   - **结果:** 接收到的视频可能出现颜色失真，例如色彩过于鲜艳或偏灰白。虽然这个 C++ 文件负责转换，但上层逻辑需要确保在必要时调用这些转换函数。

3. **假设所有设备都支持相同的编解码器和 profile：**
   - **错误:**  在 WebRTC 应用中，没有正确处理编解码器协商失败的情况，假设所有用户的浏览器都支持特定的 H.264 profile。
   - **结果:** 如果用户的浏览器不支持该 profile，视频连接可能会失败，或者只能使用性能较差的通用 profile。

4. **手动修改 WebRTC 内部数据结构而不理解其含义：**
   - **错误:**  开发者尝试直接修改 WebRTC 内部的 `webrtc::VideoRotation` 值，但没有意识到 Blink 渲染引擎使用的是 `media::VideoRotation`。
   - **结果:**  即使 WebRTC 内部的旋转信息被修改，Blink 渲染引擎可能仍然使用旧的或默认的旋转值，导致视频显示方向不正确。这个文件提供的转换函数正是为了避免这种混淆。

总之，`webrtc_video_utils.cc` 是一个底层的工具文件，它的正确使用对于 WebRTC 视频功能的稳定性和正确性至关重要。虽然开发者通常不会直接调用这些 C++ 函数，但理解它们的功能有助于理解 WebRTC API 在浏览器内部的工作原理，并能更好地调试和解决相关问题。

### 提示词
```
这是目录为blink/renderer/platform/webrtc/webrtc_video_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/webrtc/webrtc_video_utils.h"

#include "base/logging.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/webrtc/api/video_codecs/h264_profile_level_id.h"
#if BUILDFLAG(RTC_USE_H265)
#include "third_party/webrtc/api/video_codecs/h265_profile_tier_level.h"
#endif  // BUILDFLAG(RTC_USE_H265)
#include "third_party/webrtc/api/video_codecs/video_codec.h"
#include "third_party/webrtc/api/video_codecs/vp9_profile.h"

namespace blink {

media::VideoRotation WebRtcToMediaVideoRotation(
    webrtc::VideoRotation rotation) {
  switch (rotation) {
    case webrtc::kVideoRotation_0:
      return media::VIDEO_ROTATION_0;
    case webrtc::kVideoRotation_90:
      return media::VIDEO_ROTATION_90;
    case webrtc::kVideoRotation_180:
      return media::VIDEO_ROTATION_180;
    case webrtc::kVideoRotation_270:
      return media::VIDEO_ROTATION_270;
  }
  return media::VIDEO_ROTATION_0;
}

media::VideoCodec WebRtcToMediaVideoCodec(webrtc::VideoCodecType codec) {
  switch (codec) {
    case webrtc::kVideoCodecAV1:
      return media::VideoCodec::kAV1;
    case webrtc::kVideoCodecVP8:
      return media::VideoCodec::kVP8;
    case webrtc::kVideoCodecVP9:
      return media::VideoCodec::kVP9;
    case webrtc::kVideoCodecH264:
      return media::VideoCodec::kH264;
#if BUILDFLAG(RTC_USE_H265)
    case webrtc::kVideoCodecH265:
      return media::VideoCodec::kHEVC;
#endif  // BUILDFLAG(RTC_USE_H265)
    default:
      return media::VideoCodec::kUnknown;
  }
}

media::VideoCodecProfile WebRtcVideoFormatToMediaVideoCodecProfile(
    const webrtc::SdpVideoFormat& format) {
  const webrtc::VideoCodecType video_codec_type =
      webrtc::PayloadStringToCodecType(format.name);
  switch (video_codec_type) {
    case webrtc::kVideoCodecAV1:
      return media::AV1PROFILE_PROFILE_MAIN;
    case webrtc::kVideoCodecVP8:
      return media::VP8PROFILE_ANY;
    case webrtc::kVideoCodecVP9: {
      const std::optional<webrtc::VP9Profile> vp9_profile =
          webrtc::ParseSdpForVP9Profile(format.parameters);
      // The return value is std::nullopt if the profile-id is specified
      // but its value is invalid.
      if (!vp9_profile) {
        return media::VIDEO_CODEC_PROFILE_UNKNOWN;
      }
      switch (*vp9_profile) {
        case webrtc::VP9Profile::kProfile2:
          return media::VP9PROFILE_PROFILE2;
        case webrtc::VP9Profile::kProfile1:
          return media::VP9PROFILE_PROFILE1;
        case webrtc::VP9Profile::kProfile0:
        default:
          return media::VP9PROFILE_PROFILE0;
      }
    }
    case webrtc::kVideoCodecH264: {
      const std::optional<webrtc::H264ProfileLevelId> h264_profile_level_id =
          webrtc::ParseSdpForH264ProfileLevelId(format.parameters);
      // The return value is std::nullopt if the profile-level-id is specified
      // but its value is invalid.
      if (!h264_profile_level_id) {
        return media::VIDEO_CODEC_PROFILE_UNKNOWN;
      }
      switch (h264_profile_level_id->profile) {
        case webrtc::H264Profile::kProfileMain:
          return media::H264PROFILE_MAIN;
        case webrtc::H264Profile::kProfileConstrainedHigh:
        case webrtc::H264Profile::kProfileHigh:
          return media::H264PROFILE_HIGH;
        case webrtc::H264Profile::kProfileConstrainedBaseline:
        case webrtc::H264Profile::kProfileBaseline:
        default:
          return media::H264PROFILE_BASELINE;
      }
    }
#if BUILDFLAG(RTC_USE_H265)
    case webrtc::kVideoCodecH265: {
      const std::optional<webrtc::H265ProfileTierLevel> h265_ptl =
          webrtc::ParseSdpForH265ProfileTierLevel(format.parameters);
      if (!h265_ptl) {
        return media::VIDEO_CODEC_PROFILE_UNKNOWN;
      }
      switch (h265_ptl->profile) {
        case webrtc::H265Profile::kProfileMain:
          return media::HEVCPROFILE_MAIN;
        case webrtc::H265Profile::kProfileMain10:
          return media::HEVCPROFILE_MAIN10;
        default:
          return media::VIDEO_CODEC_PROFILE_UNKNOWN;
      }
    }
#endif
    default:
      return media::VIDEO_CODEC_PROFILE_UNKNOWN;
  }
}

gfx::ColorSpace WebRtcToGfxColorSpace(const webrtc::ColorSpace& color_space) {
  gfx::ColorSpace::PrimaryID primaries = gfx::ColorSpace::PrimaryID::INVALID;
  switch (color_space.primaries()) {
    case webrtc::ColorSpace::PrimaryID::kBT709:
    case webrtc::ColorSpace::PrimaryID::kUnspecified:
      primaries = gfx::ColorSpace::PrimaryID::BT709;
      break;
    case webrtc::ColorSpace::PrimaryID::kBT470M:
      primaries = gfx::ColorSpace::PrimaryID::BT470M;
      break;
    case webrtc::ColorSpace::PrimaryID::kBT470BG:
      primaries = gfx::ColorSpace::PrimaryID::BT470BG;
      break;
    case webrtc::ColorSpace::PrimaryID::kSMPTE170M:
      primaries = gfx::ColorSpace::PrimaryID::SMPTE170M;
      break;
    case webrtc::ColorSpace::PrimaryID::kSMPTE240M:
      primaries = gfx::ColorSpace::PrimaryID::SMPTE240M;
      break;
    case webrtc::ColorSpace::PrimaryID::kFILM:
      primaries = gfx::ColorSpace::PrimaryID::FILM;
      break;
    case webrtc::ColorSpace::PrimaryID::kBT2020:
      primaries = gfx::ColorSpace::PrimaryID::BT2020;
      break;
    case webrtc::ColorSpace::PrimaryID::kSMPTEST428:
      primaries = gfx::ColorSpace::PrimaryID::SMPTEST428_1;
      break;
    case webrtc::ColorSpace::PrimaryID::kSMPTEST431:
      primaries = gfx::ColorSpace::PrimaryID::SMPTEST431_2;
      break;
    case webrtc::ColorSpace::PrimaryID::kSMPTEST432:
      primaries = gfx::ColorSpace::PrimaryID::P3;
      break;
    case webrtc::ColorSpace::PrimaryID::kJEDECP22:
      primaries = gfx::ColorSpace::PrimaryID::EBU_3213_E;
      break;
    default:
      break;
  }

  gfx::ColorSpace::TransferID transfer = gfx::ColorSpace::TransferID::INVALID;
  switch (color_space.transfer()) {
    case webrtc::ColorSpace::TransferID::kBT709:
    case webrtc::ColorSpace::TransferID::kUnspecified:
      transfer = gfx::ColorSpace::TransferID::BT709;
      break;
    case webrtc::ColorSpace::TransferID::kGAMMA22:
      transfer = gfx::ColorSpace::TransferID::GAMMA22;
      break;
    case webrtc::ColorSpace::TransferID::kGAMMA28:
      transfer = gfx::ColorSpace::TransferID::GAMMA28;
      break;
    case webrtc::ColorSpace::TransferID::kSMPTE170M:
      transfer = gfx::ColorSpace::TransferID::SMPTE170M;
      break;
    case webrtc::ColorSpace::TransferID::kSMPTE240M:
      transfer = gfx::ColorSpace::TransferID::SMPTE240M;
      break;
    case webrtc::ColorSpace::TransferID::kLINEAR:
      transfer = gfx::ColorSpace::TransferID::LINEAR;
      break;
    case webrtc::ColorSpace::TransferID::kLOG:
      transfer = gfx::ColorSpace::TransferID::LOG;
      break;
    case webrtc::ColorSpace::TransferID::kLOG_SQRT:
      transfer = gfx::ColorSpace::TransferID::LOG_SQRT;
      break;
    case webrtc::ColorSpace::TransferID::kIEC61966_2_4:
      transfer = gfx::ColorSpace::TransferID::IEC61966_2_4;
      break;
    case webrtc::ColorSpace::TransferID::kBT1361_ECG:
      transfer = gfx::ColorSpace::TransferID::BT1361_ECG;
      break;
    case webrtc::ColorSpace::TransferID::kIEC61966_2_1:
      transfer = gfx::ColorSpace::TransferID::SRGB;
      break;
    case webrtc::ColorSpace::TransferID::kBT2020_10:
      transfer = gfx::ColorSpace::TransferID::BT2020_10;
      break;
    case webrtc::ColorSpace::TransferID::kBT2020_12:
      transfer = gfx::ColorSpace::TransferID::BT2020_12;
      break;
    case webrtc::ColorSpace::TransferID::kSMPTEST2084:
      transfer = gfx::ColorSpace::TransferID::PQ;
      break;
    case webrtc::ColorSpace::TransferID::kSMPTEST428:
      transfer = gfx::ColorSpace::TransferID::SMPTEST428_1;
      break;
    case webrtc::ColorSpace::TransferID::kARIB_STD_B67:
      transfer = gfx::ColorSpace::TransferID::HLG;
      break;
    default:
      break;
  }

  gfx::ColorSpace::MatrixID matrix = gfx::ColorSpace::MatrixID::INVALID;
  switch (color_space.matrix()) {
    case webrtc::ColorSpace::MatrixID::kRGB:
      matrix = gfx::ColorSpace::MatrixID::RGB;
      break;
    case webrtc::ColorSpace::MatrixID::kBT709:
    case webrtc::ColorSpace::MatrixID::kUnspecified:
      matrix = gfx::ColorSpace::MatrixID::BT709;
      break;
    case webrtc::ColorSpace::MatrixID::kFCC:
      matrix = gfx::ColorSpace::MatrixID::FCC;
      break;
    case webrtc::ColorSpace::MatrixID::kBT470BG:
      matrix = gfx::ColorSpace::MatrixID::BT470BG;
      break;
    case webrtc::ColorSpace::MatrixID::kSMPTE170M:
      matrix = gfx::ColorSpace::MatrixID::SMPTE170M;
      break;
    case webrtc::ColorSpace::MatrixID::kSMPTE240M:
      matrix = gfx::ColorSpace::MatrixID::SMPTE240M;
      break;
    case webrtc::ColorSpace::MatrixID::kYCOCG:
      matrix = gfx::ColorSpace::MatrixID::YCOCG;
      break;
    case webrtc::ColorSpace::MatrixID::kBT2020_NCL:
      matrix = gfx::ColorSpace::MatrixID::BT2020_NCL;
      break;
    case webrtc::ColorSpace::MatrixID::kSMPTE2085:
      matrix = gfx::ColorSpace::MatrixID::YDZDX;
      break;
    default:
      break;
  }

  gfx::ColorSpace::RangeID range = gfx::ColorSpace::RangeID::INVALID;
  switch (color_space.range()) {
    case webrtc::ColorSpace::RangeID::kLimited:
      range = gfx::ColorSpace::RangeID::LIMITED;
      break;
    case webrtc::ColorSpace::RangeID::kFull:
      range = gfx::ColorSpace::RangeID::FULL;
      break;
    default:
      break;
  }

  return gfx::ColorSpace(primaries, transfer, matrix, range);
}

webrtc::ColorSpace GfxToWebRtcColorSpace(const gfx::ColorSpace& color_space) {
  webrtc::ColorSpace::PrimaryID primaries =
      webrtc::ColorSpace::PrimaryID::kUnspecified;
  switch (color_space.GetPrimaryID()) {
    case gfx::ColorSpace::PrimaryID::BT709:
      primaries = webrtc::ColorSpace::PrimaryID::kBT709;
      break;
    case gfx::ColorSpace::PrimaryID::BT470M:
      primaries = webrtc::ColorSpace::PrimaryID::kBT470M;
      break;
    case gfx::ColorSpace::PrimaryID::BT470BG:
      primaries = webrtc::ColorSpace::PrimaryID::kBT470BG;
      break;
    case gfx::ColorSpace::PrimaryID::SMPTE170M:
      primaries = webrtc::ColorSpace::PrimaryID::kSMPTE170M;
      break;
    case gfx::ColorSpace::PrimaryID::SMPTE240M:
      primaries = webrtc::ColorSpace::PrimaryID::kSMPTE240M;
      break;
    case gfx::ColorSpace::PrimaryID::FILM:
      primaries = webrtc::ColorSpace::PrimaryID::kFILM;
      break;
    case gfx::ColorSpace::PrimaryID::BT2020:
      primaries = webrtc::ColorSpace::PrimaryID::kBT2020;
      break;
    case gfx::ColorSpace::PrimaryID::SMPTEST428_1:
      primaries = webrtc::ColorSpace::PrimaryID::kSMPTEST428;
      break;
    case gfx::ColorSpace::PrimaryID::SMPTEST431_2:
      primaries = webrtc::ColorSpace::PrimaryID::kSMPTEST431;
      break;
    case gfx::ColorSpace::PrimaryID::P3:
      primaries = webrtc::ColorSpace::PrimaryID::kSMPTEST432;
      break;
    case gfx::ColorSpace::PrimaryID::EBU_3213_E:
      primaries = webrtc::ColorSpace::PrimaryID::kJEDECP22;
      break;
    default:
      DVLOG(1) << "Unsupported color primaries.";
      break;
  }

  webrtc::ColorSpace::TransferID transfer =
      webrtc::ColorSpace::TransferID::kUnspecified;
  switch (color_space.GetTransferID()) {
    case gfx::ColorSpace::TransferID::BT709:
      transfer = webrtc::ColorSpace::TransferID::kBT709;
      break;
    case gfx::ColorSpace::TransferID::GAMMA22:
      transfer = webrtc::ColorSpace::TransferID::kGAMMA22;
      break;
    case gfx::ColorSpace::TransferID::GAMMA28:
      transfer = webrtc::ColorSpace::TransferID::kGAMMA28;
      break;
    case gfx::ColorSpace::TransferID::SMPTE170M:
      transfer = webrtc::ColorSpace::TransferID::kSMPTE170M;
      break;
    case gfx::ColorSpace::TransferID::SMPTE240M:
      transfer = webrtc::ColorSpace::TransferID::kSMPTE240M;
      break;
    case gfx::ColorSpace::TransferID::LINEAR:
      transfer = webrtc::ColorSpace::TransferID::kLINEAR;
      break;
    case gfx::ColorSpace::TransferID::LOG:
      transfer = webrtc::ColorSpace::TransferID::kLOG;
      break;
    case gfx::ColorSpace::TransferID::LOG_SQRT:
      transfer = webrtc::ColorSpace::TransferID::kLOG_SQRT;
      break;
    case gfx::ColorSpace::TransferID::IEC61966_2_4:
      transfer = webrtc::ColorSpace::TransferID::kIEC61966_2_4;
      break;
    case gfx::ColorSpace::TransferID::BT1361_ECG:
      transfer = webrtc::ColorSpace::TransferID::kBT1361_ECG;
      break;
    case gfx::ColorSpace::TransferID::SRGB:
      transfer = webrtc::ColorSpace::TransferID::kIEC61966_2_1;
      break;
    case gfx::ColorSpace::TransferID::BT2020_10:
      transfer = webrtc::ColorSpace::TransferID::kBT2020_10;
      break;
    case gfx::ColorSpace::TransferID::BT2020_12:
      transfer = webrtc::ColorSpace::TransferID::kBT2020_12;
      break;
    case gfx::ColorSpace::TransferID::PQ:
      transfer = webrtc::ColorSpace::TransferID::kSMPTEST2084;
      break;
    case gfx::ColorSpace::TransferID::SMPTEST428_1:
      transfer = webrtc::ColorSpace::TransferID::kSMPTEST428;
      break;
    case gfx::ColorSpace::TransferID::HLG:
      transfer = webrtc::ColorSpace::TransferID::kARIB_STD_B67;
      break;
    default:
      DVLOG(1) << "Unsupported transfer.";
      break;
  }

  webrtc::ColorSpace::MatrixID matrix =
      webrtc::ColorSpace::MatrixID::kUnspecified;
  switch (color_space.GetMatrixID()) {
    case gfx::ColorSpace::MatrixID::RGB:
      matrix = webrtc::ColorSpace::MatrixID::kRGB;
      break;
    case gfx::ColorSpace::MatrixID::BT709:
      matrix = webrtc::ColorSpace::MatrixID::kBT709;
      break;
    case gfx::ColorSpace::MatrixID::FCC:
      matrix = webrtc::ColorSpace::MatrixID::kFCC;
      break;
    case gfx::ColorSpace::MatrixID::BT470BG:
      matrix = webrtc::ColorSpace::MatrixID::kBT470BG;
      break;
    case gfx::ColorSpace::MatrixID::SMPTE170M:
      matrix = webrtc::ColorSpace::MatrixID::kSMPTE170M;
      break;
    case gfx::ColorSpace::MatrixID::SMPTE240M:
      matrix = webrtc::ColorSpace::MatrixID::kSMPTE240M;
      break;
    case gfx::ColorSpace::MatrixID::YCOCG:
      matrix = webrtc::ColorSpace::MatrixID::kYCOCG;
      break;
    case gfx::ColorSpace::MatrixID::BT2020_NCL:
      matrix = webrtc::ColorSpace::MatrixID::kBT2020_NCL;
      break;
    case gfx::ColorSpace::MatrixID::YDZDX:
      matrix = webrtc::ColorSpace::MatrixID::kSMPTE2085;
      break;
    default:
      DVLOG(1) << "Unsupported color matrix.";
      break;
  }

  webrtc::ColorSpace::RangeID range = webrtc::ColorSpace::RangeID::kInvalid;
  switch (color_space.GetRangeID()) {
    case gfx::ColorSpace::RangeID::LIMITED:
      range = webrtc::ColorSpace::RangeID::kLimited;
      break;
    case gfx::ColorSpace::RangeID::FULL:
      range = webrtc::ColorSpace::RangeID::kFull;
      break;
    case gfx::ColorSpace::RangeID::DERIVED:
      range = webrtc::ColorSpace::RangeID::kDerived;
      break;
    default:
      DVLOG(1) << "Unsupported color range.";
      break;
  }

  return webrtc::ColorSpace(primaries, transfer, matrix, range);
}

}  // namespace blink
```