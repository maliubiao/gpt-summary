Response: Let's break down the thought process to analyze the given C++ test file and generate the desired explanation.

1. **Understand the Goal:** The primary goal is to understand the purpose of the `rtc_video_decoder_factory_test.cc` file within the Chromium Blink engine and explain its relevance to web technologies (JavaScript, HTML, CSS) if any. Additionally, we need to provide examples of logical reasoning, user/programming errors, and list its functions.

2. **Identify the Core Subject:** The file name itself, `rtc_video_decoder_factory_test.cc`, strongly suggests this file tests the `RTCVideoDecoderFactory`. The "RTC" likely stands for Real-Time Communication, which is heavily associated with WebRTC. "Decoder Factory" implies it's responsible for creating video decoders. The "test" suffix confirms it's a testing file.

3. **Examine the Includes:**  The `#include` directives provide crucial context:
    * `rtc_video_decoder_factory.h`:  This confirms that the tested class is `RTCVideoDecoderFactory`.
    * `base/test/scoped_feature_list.h` and `base/test/task_environment.h`:  These are common testing utilities in Chromium. They suggest the tests involve asynchronous operations or feature flags.
    * `media/base/platform_features.h`, `media/base/video_codecs.h`, `media/video/mock_gpu_video_accelerator_factories.h`, `media/video/video_decode_accelerator.h`, `media/webrtc/webrtc_features.h`: These headers are directly related to media processing, video decoding, and WebRTC. The presence of "mock" suggests that the tests are using simulated GPU capabilities.
    * `testing/gtest/include/gtest/gtest.h`: This indicates the use of the Google Test framework for writing unit tests.
    * `third_party/blink/public/common/features.h`:  This points to Blink-specific feature flags.
    * `third_party/webrtc/api/video_codecs/sdp_video_format.h` and `third_party/webrtc/api/video_codecs/video_decoder_factory.h`: These are WebRTC API definitions related to video codec negotiation (SDP) and video decoder creation.

4. **Analyze the Test Structure:** The code uses the Google Test framework, with `TEST_F` macros defining individual test cases within the `RTCVideoDecoderFactoryTest` fixture.

5. **Focus on Key Functionality:**  The core functionality being tested revolves around the `QueryCodecSupport` and `GetSupportedFormats` methods of the `RTCVideoDecoderFactory`. The tests verify which video codecs and their profiles are supported for decoding. The use of `MockGpuVideoDecodeAcceleratorFactories` indicates the tests are simulating different GPU capabilities to check codec support.

6. **Connect to Web Technologies:**  Think about how video decoding relates to web technologies:
    * **JavaScript:** WebRTC APIs in JavaScript (`RTCPeerConnection`) are used to establish real-time communication, including video streaming. The browser needs to decode the received video streams. The `RTCVideoDecoderFactory` plays a role in selecting and creating the appropriate video decoder based on the negotiated codecs.
    * **HTML:** The `<video>` element is used to display video content. While this file doesn't directly interact with `<video>`, the decoding process managed by the factory is essential for rendering video within the HTML page.
    * **CSS:** CSS can style the `<video>` element, but it doesn't directly influence the video decoding process.

7. **Identify Logical Reasoning and Examples:** The tests themselves represent logical reasoning. For example, the test `QueryCodecSupportReturnsExpectedResults` checks if a specific codec (like VP8 or H.264 with a certain profile) is reported as supported or unsupported under different conditions (like reference scaling).

    * **Hypothetical Input/Output (QueryCodecSupport):**
        * **Input:** `webrtc::SdpVideoFormat("VP9")`, `false` (reference scaling)
        * **Output:** `kSupportedPowerEfficient` (assuming the platform supports VP9 decoding)

8. **Consider User/Programming Errors:**
    * **Incorrect SDP:** If the JavaScript code provides an SDP offer/answer with a video codec that the browser doesn't support (and the `RTCVideoDecoderFactory` would reflect this), the video stream won't be decoded properly, leading to a broken video experience.
    * **Feature Flags:**  Enabling or disabling certain flags (like `WebRtcAllowH265Receive`) can change the supported codecs. A developer might incorrectly assume a codec is supported based on their local testing environment without considering feature flags.

9. **Synthesize and Structure the Explanation:** Organize the findings into clear sections covering:
    * File Description and Purpose
    * Relationship to Web Technologies (with examples)
    * Logical Reasoning (with input/output examples)
    * User/Programming Errors (with examples)
    * List of Functions (the test cases themselves)

10. **Refine and Review:** Ensure the explanation is accurate, comprehensive, and easy to understand. Double-check the code snippets and examples for correctness. Make sure the connection to web technologies is clearly articulated.

Self-Correction/Refinement during the process:

* **Initial thought:** Maybe this file directly manipulates the `<video>` element.
* **Correction:**  Upon closer inspection of the includes and the code, it's clear that this file focuses on the *backend* decoding logic, not the rendering aspect. The connection to `<video>` is indirect, through the WebRTC pipeline.

* **Initial thought:** List *all* functions in the file.
* **Correction:**  Focus on the *test functions* as they represent the functionality being tested. Listing internal helper functions isn't as relevant for understanding the file's overall purpose.

By following these steps, we can arrive at the well-structured and informative explanation provided in the initial prompt's answer.
好的，让我们来分析一下 `blink/renderer/platform/peerconnection/rtc_video_decoder_factory_test.cc` 这个文件。

**文件功能概述**

这个文件是一个 **单元测试文件**，用于测试 `RTCVideoDecoderFactory` 这个类的功能。`RTCVideoDecoderFactory` 的作用是为 WebRTC (Real-Time Communication in Web browsers) 提供创建视频解码器的工厂方法。它负责根据协商的视频编码格式（例如 VP8, VP9, H.264, AV1, H.265）以及设备和浏览器的能力，选择合适的视频解码器。

**与 JavaScript, HTML, CSS 的关系**

这个 C++ 文件位于 Blink 渲染引擎的底层，它并不直接与 JavaScript, HTML, 或 CSS 代码交互。然而，它的功能是 WebRTC 技术栈的关键组成部分，而 WebRTC 功能通常通过 JavaScript API 暴露给 Web 开发者。

以下是一些间接关系和例子：

* **JavaScript (WebRTC API):**
    * 当 JavaScript 代码使用 `RTCPeerConnection` API 建立视频通话时，会涉及到协商视频编解码器的过程。
    * 例如，在 SDP (Session Description Protocol) 协商中，客户端和服务器会交换支持的视频格式信息。
    * `RTCVideoDecoderFactory` 的工作就是根据这些协商好的格式（例如，SDP 中的 `m=video` 行和 `rtpmap` 属性）以及浏览器的硬件和软件解码能力，创建能够解码接收到的视频流的解码器。
    * **举例：** 假设 JavaScript 代码创建了一个 `RTCPeerConnection` 并添加了一个视频轨道。当与远端建立连接并收到包含 `VP9` 编码的视频流时，`RTCVideoDecoderFactory` 会被调用来创建一个 VP9 解码器。

* **HTML (`<video>` 元素):**
    * 当 WebRTC 连接建立后，接收到的解码后的视频帧最终会被渲染到 HTML 的 `<video>` 元素上。
    * `RTCVideoDecoderFactory` 负责确保这些帧能够被正确解码，从而让视频内容能够在 `<video>` 元素中显示出来。
    * **举例：** 用户在一个网页上参与视频会议，他们的本地摄像头画面被编码后发送到远端，远端浏览器接收到视频流后，`RTCVideoDecoderFactory` 创建解码器解码视频帧，然后这些帧被送到 `<video>` 元素进行显示。

* **CSS (间接影响):**
    * CSS 可以用来样式化 `<video>` 元素，例如设置其大小、边框等。
    * 虽然 CSS 不直接参与视频解码过程，但解码的目的是为了在 HTML 中展示，而 CSS 负责控制展示效果。
    * **举例：** CSS 可以设置 `<video>` 元素的 `width` 和 `height` 属性，从而影响用户看到的视频显示区域的大小。解码器需要根据实际的视频尺寸和可能的缩放需求进行解码。

**逻辑推理与假设输入/输出**

这个测试文件中的测试用例实际上就是在进行逻辑推理，验证 `RTCVideoDecoderFactory` 在不同输入条件下的行为是否符合预期。

**假设输入与输出示例 (基于代码中的测试用例):**

* **假设输入 1:**
    * 调用 `QueryCodecSupport` 方法。
    * 输入的 `webrtc::SdpVideoFormat` 为 `webrtc::SdpVideoFormat("VP9")`。
    * `reference_scaling` 参数为 `false`。
    * **预期输出:**  `QueryCodecSupport` 返回的 `webrtc::VideoDecoderFactory::CodecSupport` 结构体中的 `is_supported` 字段为 `true` (假设 GPU 支持 VP9 解码)。

* **假设输入 2:**
    * 调用 `QueryCodecSupport` 方法。
    * 输入的 `webrtc::SdpVideoFormat` 为 `webrtc::SdpVideoFormat("H264", {{"profile-level-id", "64001f"}})` (H.264 High Profile)。
    * `reference_scaling` 参数为 `false`。
    * **预期输出:** `is_supported` 字段为 `false` (根据代码，H.264 High Profile 在此上下文中被认为是不支持的)。

* **假设输入 3:**
    * 调用 `GetSupportedFormats` 方法。
    * **预期输出:** 返回一个包含所有支持的 `webrtc::SdpVideoFormat` 的列表，例如 `kVp9Profile0Sdp`, `kH264BaselinePacketizatonMode0Sdp` 等。

**用户或编程常见的使用错误**

虽然开发者通常不会直接操作 `RTCVideoDecoderFactory`，但与其相关的 WebRTC 使用中存在一些常见错误：

* **SDP 不匹配:** 如果客户端和服务器在 SDP 协商阶段提供的视频编解码器信息不一致，或者客户端请求的编解码器服务器不支持，`RTCVideoDecoderFactory` 可能无法找到合适的解码器，导致视频连接失败或无图像。
    * **举例：** 客户端 JavaScript 代码设置了只支持 VP8，但服务器只支持 H.264。如果没有兼容的编解码器，连接可能无法建立。
* **假设所有编解码器都可用:** 开发者可能假设所有现代浏览器都支持所有常见的视频编解码器（如 VP9, AV1），但实际情况取决于用户的浏览器版本、操作系统、硬件加速能力等。如果尝试使用不支持的编解码器，会导致解码失败。
* **忽略错误处理:** 在 WebRTC 应用中，应该对 `RTCPeerConnection` 的事件（如 `track` 事件）进行适当的错误处理。如果视频解码失败，应该能够捕获并向用户反馈，而不是让应用直接崩溃或显示空白视频。
* **错误配置 Feature Flags:** Chromium 中某些功能由 Feature Flags 控制。例如，代码中提到了 `WebRtcAllowH265Receive`。如果开发者错误地配置了这些 flags，可能会导致预期的编解码器支持发生变化，从而影响视频解码。

**文件中的主要功能 (测试用例)**

该文件包含多个测试用例，每个测试用例都验证 `RTCVideoDecoderFactory` 的不同方面。以下是一些主要的测试功能：

* **`QueryCodecSupportReturnsExpectedResults`:** 测试 `QueryCodecSupport` 方法在不同视频格式和 `reference_scaling` 参数下的返回值是否符合预期。它验证了哪些编解码器被认为是支持的或不支持的。
* **`GetSupportedFormatsReturnsAllExpectedModes`:** 测试 `GetSupportedFormats` 方法是否返回了所有预期的支持的视频格式。
* **`QueryCodecSupportH265WithWebRtcAllowH265ReceiveEnabled`:**  测试在启用 `WebRtcAllowH265Receive` Feature Flag 的情况下，`QueryCodecSupport` 方法对 H.265 编解码器的支持情况。

总而言之，`rtc_video_decoder_factory_test.cc` 是一个关键的测试文件，它确保了 Blink 引擎中的视频解码器工厂能够正确地工作，从而保证了 WebRTC 视频通话功能的稳定性和可靠性。虽然它不直接涉及 JavaScript, HTML, CSS 代码，但它是支撑这些 Web 技术实现视频功能的幕后功臣。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_decoder_factory_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/peerconnection/rtc_video_decoder_factory.h"

#include <stdint.h>

#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "media/base/platform_features.h"
#include "media/base/video_codecs.h"
#include "media/video/mock_gpu_video_accelerator_factories.h"
#include "media/video/video_decode_accelerator.h"
#include "media/webrtc/webrtc_features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/webrtc/api/video_codecs/sdp_video_format.h"
#include "third_party/webrtc/api/video_codecs/video_decoder_factory.h"

using ::testing::Return;
using ::testing::UnorderedElementsAre;

namespace blink {

namespace {
#if BUILDFLAG(RTC_USE_H265)
const media::SupportedVideoDecoderConfig kH265MaxSupportedVideoDecoderConfig =
    media::SupportedVideoDecoderConfig(
        media::VideoCodecProfile::HEVCPROFILE_MAIN,
        media::VideoCodecProfile::HEVCPROFILE_MAIN10,
        media::kDefaultSwDecodeSizeMin,
        media::kDefaultSwDecodeSizeMax,
        true,
        false);
#endif  // BUILDFLAG(RTC_USE_H265)

const webrtc::SdpVideoFormat kVp9Profile0Sdp("VP9", {{"profile-id", "0"}});
const webrtc::SdpVideoFormat kVp9Profile1Sdp("VP9", {{"profile-id", "1"}});
const webrtc::SdpVideoFormat kVp9Profile2Sdp("VP9", {{"profile-id", "2"}});
const webrtc::SdpVideoFormat kAv1Sdp("AV1", {});
const webrtc::SdpVideoFormat kH264CbPacketizatonMode0Sdp(
    "H264",
    {{"level-asymmetry-allowed", "1"},
     {"packetization-mode", "0"},
     {"profile-level-id", "42e01f"}});
const webrtc::SdpVideoFormat kH264CbPacketizatonMode1Sdp(
    "H264",
    {{"level-asymmetry-allowed", "1"},
     {"packetization-mode", "1"},
     {"profile-level-id", "42e01f"}});
const webrtc::SdpVideoFormat kH264BaselinePacketizatonMode0Sdp(
    "H264",
    {{"level-asymmetry-allowed", "1"},
     {"packetization-mode", "0"},
     {"profile-level-id", "42001f"}});
const webrtc::SdpVideoFormat kH264BaselinePacketizatonMode1Sdp(
    "H264",
    {{"level-asymmetry-allowed", "1"},
     {"packetization-mode", "1"},
     {"profile-level-id", "42001f"}});
const webrtc::SdpVideoFormat kH264MainPacketizatonMode0Sdp(
    "H264",
    {{"level-asymmetry-allowed", "1"},
     {"packetization-mode", "0"},
     {"profile-level-id", "4d001f"}});
const webrtc::SdpVideoFormat kH264MainPacketizatonMode1Sdp(
    "H264",
    {{"level-asymmetry-allowed", "1"},
     {"packetization-mode", "1"},
     {"profile-level-id", "4d001f"}});
#if BUILDFLAG(RTC_USE_H265)
const webrtc::SdpVideoFormat kH265MainProfileLevel31Sdp("H265",
                                                        {{"profile-id", "1"},
                                                         {"tier-flag", "0"},
                                                         {"level-id", "93"},
                                                         {"tx-mode", "SRST"}});
const webrtc::SdpVideoFormat kH265Main10ProfileLevel31Sdp("H265",
                                                          {{"profile-id", "2"},
                                                           {"tier-flag", "0"},
                                                           {"level-id", "93"},
                                                           {"tx-mode",
                                                            "SRST"}});
const webrtc::SdpVideoFormat kH265MainProfileLevel6Sdp("H265",
                                                       {{"profile-id", "1"},
                                                        {"tier-flag", "0"},
                                                        {"level-id", "180"},
                                                        {"tx-mode", "SRST"}});
const webrtc::SdpVideoFormat kH265Main10ProfileLevel6Sdp("H265",
                                                         {{"profile-id", "2"},
                                                          {"tier-flag", "0"},
                                                          {"level-id", "180"},
                                                          {"tx-mode", "SRST"}});
#endif  // BUILDFLAG(RTC_USE_H265)

bool Equals(webrtc::VideoDecoderFactory::CodecSupport a,
            webrtc::VideoDecoderFactory::CodecSupport b) {
  return a.is_supported == b.is_supported &&
         a.is_power_efficient == b.is_power_efficient;
}

constexpr webrtc::VideoDecoderFactory::CodecSupport kSupportedPowerEfficient = {
    true, true};
constexpr webrtc::VideoDecoderFactory::CodecSupport kUnsupported = {false,
                                                                    false};
class MockGpuVideoDecodeAcceleratorFactories
    : public media::MockGpuVideoAcceleratorFactories {
 public:
  MockGpuVideoDecodeAcceleratorFactories()
      : MockGpuVideoAcceleratorFactories(nullptr) {}

  Supported IsDecoderConfigSupported(
      const media::VideoDecoderConfig& config) override {
    if (config.codec() == media::VideoCodec::kVP9 ||
        config.codec() == media::VideoCodec::kAV1) {
      return Supported::kTrue;
    } else if (config.codec() == media::VideoCodec::kH264) {
      if (config.profile() == media::VideoCodecProfile::H264PROFILE_BASELINE ||
          config.profile() == media::VideoCodecProfile::H264PROFILE_MAIN) {
        return Supported::kTrue;
      } else {
        return Supported::kFalse;
      }
    }
#if BUILDFLAG(RTC_USE_H265)
    else if (config.codec() == media::VideoCodec::kHEVC) {
      if (config.profile() == media::VideoCodecProfile::HEVCPROFILE_MAIN) {
        return Supported::kTrue;
      } else {
        return Supported::kFalse;
      }
    }
#endif  // BUILDFLAG(RTC_USE_H265)
    else {
      return Supported::kFalse;
    }
  }

  // Since we currently only use this for checking supported decoder configs for
  // HEVC, we only add HEVC related configs for now.
  std::optional<media::SupportedVideoDecoderConfigs>
  GetSupportedVideoDecoderConfigs() override {
    media::SupportedVideoDecoderConfigs supported_configs;
#if BUILDFLAG(RTC_USE_H265)
    supported_configs.push_back({kH265MaxSupportedVideoDecoderConfig});
#endif
    return supported_configs;
  }
};

}  // anonymous namespace

class RTCVideoDecoderFactoryTest : public ::testing::Test {
 public:
  RTCVideoDecoderFactoryTest() : decoder_factory_(&mock_gpu_factories_, {}) {}

 protected:
  base::test::TaskEnvironment task_environment_;
  MockGpuVideoDecodeAcceleratorFactories mock_gpu_factories_;
  RTCVideoDecoderFactory decoder_factory_;
};

TEST_F(RTCVideoDecoderFactoryTest, QueryCodecSupportReturnsExpectedResults) {
  EXPECT_CALL(mock_gpu_factories_, IsDecoderSupportKnown())
      .WillRepeatedly(Return(true));

  // VP8 is not supported
  EXPECT_TRUE(
      Equals(decoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("VP8"),
                                                false /*reference_scaling*/),
             kUnsupported));

  // H264 high profile is not supported
  EXPECT_TRUE(Equals(
      decoder_factory_.QueryCodecSupport(
          webrtc::SdpVideoFormat("H264", {{"level-asymmetry-allowed", "1"},
                                          {"packetization-mode", "1"},
                                          {"profile-level-id", "64001f"}}),
          false /*reference_scaling*/),
      kUnsupported));

  // VP9, H264 & AV1 decode should be supported without reference scaling.
  EXPECT_TRUE(
      Equals(decoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("VP9"),
                                                false /*reference_scaling*/),
             kSupportedPowerEfficient));
  EXPECT_TRUE(
      Equals(decoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("AV1"),
                                                false /*reference_scaling*/),
             kSupportedPowerEfficient));
  EXPECT_TRUE(Equals(
      decoder_factory_.QueryCodecSupport(
          webrtc::SdpVideoFormat("H264", {{"level-asymmetry-allowed", "1"},
                                          {"packetization-mode", "1"},
                                          {"profile-level-id", "42001f"}}),
          false /*reference_scaling*/),
      kSupportedPowerEfficient));

  // AV1 decode should be supported with reference scaling.
  EXPECT_TRUE(
      Equals(decoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("AV1"),
                                                true /*reference_scaling*/),
             kSupportedPowerEfficient));

  // VP9 decode supported depending on platform.
  EXPECT_TRUE(
      Equals(decoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("VP9"),
                                                true /*reference_scaling*/),
             media::IsVp9kSVCHWDecodingEnabled() ? kSupportedPowerEfficient
                                                 : kUnsupported));

  // H264 decode not supported with reference scaling.
  EXPECT_TRUE(Equals(
      decoder_factory_.QueryCodecSupport(
          webrtc::SdpVideoFormat("H264", {{"level-asymmetry-allowed", "1"},
                                          {"packetization-mode", "1"},
                                          {"profile-level-id", "42001f"}}),
          true /*reference_scaling*/),
      kUnsupported));

  // If WebRTCAllowH265Receive is not enabled, H.265 decode should not be
  // supported.
  EXPECT_TRUE(
      Equals(decoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("H265"),
                                                false /*reference_scaling*/),
             kUnsupported));
}

TEST_F(RTCVideoDecoderFactoryTest, GetSupportedFormatsReturnsAllExpectedModes) {
  EXPECT_CALL(mock_gpu_factories_, IsDecoderSupportKnown())
      .WillRepeatedly(Return(true));

  EXPECT_THAT(
      decoder_factory_.GetSupportedFormats(),
      UnorderedElementsAre(
          kH264CbPacketizatonMode0Sdp, kH264CbPacketizatonMode1Sdp,
          kH264BaselinePacketizatonMode0Sdp, kH264BaselinePacketizatonMode1Sdp,
          kH264MainPacketizatonMode0Sdp, kH264MainPacketizatonMode1Sdp,
          kVp9Profile0Sdp, kVp9Profile1Sdp, kVp9Profile2Sdp, kAv1Sdp));
}

#if BUILDFLAG(RTC_USE_H265)
TEST_F(RTCVideoDecoderFactoryTest,
       QueryCodecSupportH265WithWebRtcAllowH265ReceiveEnabled) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitWithFeatures({::features::kWebRtcAllowH265Receive},
                                       {});
  EXPECT_CALL(mock_gpu_factories_, IsDecoderSupportKnown())
      .WillRepeatedly(Return(true));

  // H265 decode should be supported without reference scaling.
  EXPECT_TRUE(
      Equals(decoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("H265"),
                                                false /*reference_scaling*/),
             kSupportedPowerEfficient));

  // H265 decode should not be supported with reference scaling.
  EXPECT_TRUE(
      Equals(decoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("H265"),
                                                true /*reference_scaling*/),
             kUnsupported));

  // H265 decode should be supported with main profile explicitly configured.
  EXPECT_TRUE(Equals(decoder_factory_.QueryCodecSupport(
                         webrtc::SdpVideoFormat("H265", {{"profile-id", "1"}}),
                         false /*reference_scaling*/),
                     kSupportedPowerEfficient));

  // H265 main10 profile is not supported via QueryCodecSupport().
  EXPECT_TRUE(Equals(decoder_factory_.QueryCodecSupport(
                         webrtc::SdpVideoFormat("H265", {{"profile-id", "2"}}),
                         false /*reference_scaling*/),
                     kUnsupported));

  EXPECT_THAT(
      decoder_factory_.GetSupportedFormats(),
      UnorderedElementsAre(
          kH264CbPacketizatonMode0Sdp, kH264CbPacketizatonMode1Sdp,
          kH264BaselinePacketizatonMode0Sdp, kH264BaselinePacketizatonMode1Sdp,
          kH264MainPacketizatonMode0Sdp, kH264MainPacketizatonMode1Sdp,
          kVp9Profile0Sdp, kVp9Profile1Sdp, kVp9Profile2Sdp, kAv1Sdp,
          kH265MainProfileLevel6Sdp, kH265Main10ProfileLevel6Sdp));
}
#endif  // BUILDFLAG(RTC_USE_H265)
}  // namespace blink
```