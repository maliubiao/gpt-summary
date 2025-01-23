Response:
The user wants to understand the functionality of the given C++ test file for the Chromium Blink engine. I need to explain what this test file does, and if it relates to web technologies like JavaScript, HTML, or CSS. I should also provide examples of logical reasoning with inputs and outputs, and point out common user/programming errors.

**File Analysis:**

The filename `rtc_video_encoder_factory_test.cc` and the contents (including headers like `rtc_video_encoder_factory.h`, `media/base/video_codecs.h`, `third_party/webrtc/api/video_codecs/video_encoder_factory.h`) strongly indicate that this file contains unit tests for the `RTCVideoEncoderFactory` class. This class likely deals with creating and managing video encoders within the WebRTC implementation of the Blink rendering engine.

**Functionality:**

The primary function of this test file is to verify the correctness of the `RTCVideoEncoderFactory`. It does this by:

1. **Mocking Dependencies:** It creates a mock implementation of `GpuVideoEncodeAcceleratorFactories` to simulate the availability of hardware video encoders.
2. **Testing Codec Support:**  It tests the `QueryCodecSupport` method of the `RTCVideoEncoderFactory` to ensure it correctly identifies whether specific video codecs (like VP8, VP9, H.264, AV1, and potentially H.265) are supported under various conditions, including different profiles and scalability modes.
3. **Testing Supported Formats:** It tests the `GetSupportedFormats` method to verify that the factory returns the expected list of supported video formats.
4. **Feature Flag Testing:** It uses `base::test::ScopedFeatureList` to test the behavior of the factory under different feature flag configurations, especially those related to enabling/disabling specific codecs or features like SVC (Scalable Video Coding).

**Relationship to JavaScript, HTML, CSS:**

This C++ test file itself doesn't directly interact with JavaScript, HTML, or CSS *at runtime*. However, the `RTCVideoEncoderFactory` class it tests is a crucial part of the WebRTC implementation in Blink. WebRTC allows JavaScript code running in a web page (HTML) to access media devices (like cameras and microphones) and establish peer-to-peer connections for real-time communication.

*   **JavaScript:**  JavaScript code uses the `RTCPeerConnection` API to initiate and manage WebRTC connections. When a web application wants to send video, the browser's WebRTC implementation (which includes the code tested here) determines the available video encoders and selects the most appropriate one based on the supported codecs and negotiation with the remote peer.
*   **HTML:**  HTML provides the structure for web pages. While not directly involved in the encoder selection, an HTML page would host the JavaScript code that uses WebRTC.
*   **CSS:** CSS is for styling web pages and is not directly related to the video encoding process.

**Logical Reasoning Examples:**

*   **Hypothesis:** If the GPU supports H.264 Baseline Profile encoding, and the `RTCVideoEncoderFactory` is queried for support of H.264 Baseline Profile, it should report support.
    *   **Input:**  Mock GPU factory reports support for H.264 Baseline Profile. `encoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("H264", {{"profile-level-id", "42001f"}}))` is called.
    *   **Output:** The test verifies that the return value is `kSupportedPowerEfficient`.

*   **Hypothesis:** If a specific H.265 scalability mode (like L1T3) is enabled via a feature flag, the `GetSupportedFormats` method should include an H.265 format with that scalability mode.
    *   **Input:**  Feature flag `kWebRtcH265L1T3` is enabled. `encoder_factory_.GetSupportedFormats()` is called.
    *   **Output:** The test verifies that the returned list of formats includes `kH265MainProfileLevel52Sdp` (or a similar H.265 format) with `kScalabilityModes` containing `webrtc::ScalabilityMode::kL1T3`.

**Common User/Programming Errors:**

*   **Incorrect SDP Format:**  When using WebRTC in JavaScript, developers might specify the supported video codecs and their parameters in the Session Description Protocol (SDP). An incorrect or misspelled SDP attribute (e.g., `profile-lvel-id` instead of `profile-level-id`) could lead to the browser failing to find a matching encoder, even if the codec is technically supported. The tests in this file ensure that the factory correctly parses and interprets SDP parameters.
    *   **Example:**  A JavaScript application might try to offer H.264 with `profile-lvel-id`, leading to encoding failures because the browser doesn't recognize this attribute. This test file helps prevent such issues by ensuring the factory correctly handles valid `profile-level-id` values.

*   **Assuming Hardware Encoding Availability:**  Developers might assume that hardware video encoding is always available. However, it depends on the user's hardware and driver configuration. If hardware encoding is not available, the `RTCVideoEncoderFactory` might fall back to software encoding or fail to create an encoder. These tests, by mocking the GPU factory, help ensure the factory behaves correctly in both scenarios.
    *   **Example:**  A web application might try to create an H.264 encoder without checking if hardware acceleration is available. If it's not, performance might be poor. The tests here verify that the factory correctly identifies and uses hardware encoders when available.

*   **Ignoring Feature Flags:**  Chromium uses feature flags to control the availability of certain features. Developers might forget that a particular video codec or feature requires a specific flag to be enabled. The tests in this file heavily rely on feature flags to simulate different environments and ensure the factory behaves as expected under various configurations.
    *   **Example:** A developer might expect H.265 encoding to work without enabling the `kWebRtcAllowH265Send` flag. This test file explicitly checks this scenario and ensures the factory correctly reports lack of support when the flag is disabled.

这个文件 `rtc_video_encoder_factory_test.cc` 是 Chromium Blink 引擎中用于测试 `RTCVideoEncoderFactory` 类的单元测试文件。它的主要功能是验证 `RTCVideoEncoderFactory` 类在不同场景下创建和管理视频编码器的行为是否正确。

以下是该文件功能的详细列表：

1. **测试编解码器支持查询 (`QueryCodecSupport`)：**
    *   验证 `RTCVideoEncoderFactory` 能否正确判断特定视频编解码器（例如 VP8, VP9, H.264, AV1, H.265）是否被支持。
    *   测试在不同的编解码器参数（例如 profile, level, packetization-mode）下，工厂是否能正确识别支持情况。
    *   测试在启用或禁用特定 feature flag 的情况下，编解码器的支持情况是否符合预期。
    *   测试在有或没有 SVC（Scalable Video Coding）的情况下，编解码器的支持情况。

2. **测试获取支持的格式 (`GetSupportedFormats`)：**
    *   验证 `RTCVideoEncoderFactory` 能否返回所有当前支持的视频编码格式列表。
    *   测试在启用或禁用特定 feature flag 的情况下，返回的支持格式列表是否正确。
    *   验证返回的支持格式中是否包含了正确的 scalability modes 信息。

3. **模拟 GPU 硬件加速工厂：**
    *   使用 `MockGpuVideoEncodeAcceleratorFactories` 模拟 GPU 硬件加速编码器的能力，以便在测试中控制硬件编码器的可用性和支持的格式。

4. **使用 Feature Flags 进行测试：**
    *   使用 `base::test::ScopedFeatureList` 来模拟不同的 Chromium feature flag 状态，测试在不同配置下 `RTCVideoEncoderFactory` 的行为。

**与 JavaScript, HTML, CSS 的关系：**

虽然这个 C++ 测试文件本身不直接涉及 JavaScript, HTML, 或 CSS 的代码，但它测试的 `RTCVideoEncoderFactory` 类是 WebRTC 功能实现的关键部分，而 WebRTC 允许 JavaScript 在网页 (HTML) 中进行实时的音视频通信。

*   **JavaScript:** JavaScript 代码可以使用 `RTCPeerConnection` API 来协商和建立 WebRTC 连接。在进行视频通话时，浏览器需要选择合适的视频编码器。`RTCVideoEncoderFactory` 的功能就是根据 JavaScript 代码请求的编解码器和系统环境，创建相应的 `RTCVideoEncoder` 实例。这个测试文件确保了 `RTCVideoEncoderFactory` 能够正确响应 JavaScript 的请求，并根据浏览器的能力返回正确的支持信息。

    **举例说明：** 当一个 JavaScript Web 应用尝试使用 H.264 进行视频编码时，浏览器底层的 `RTCVideoEncoderFactory` 会被调用来确定 H.264 是否被支持。这个测试文件验证了在不同的 H.264 profile 和 level 设置下，`RTCVideoEncoderFactory` 能否正确判断支持情况，从而确保 JavaScript 应用能够得到正确的反馈。

*   **HTML:** HTML 提供了网页的结构，而 JavaScript 代码通常嵌入在 HTML 中。用户通过 HTML 页面上的交互来触发 WebRTC 功能，间接地使用了 `RTCVideoEncoderFactory`。

*   **CSS:** CSS 用于网页的样式，与视频编码器的选择和创建没有直接关系。

**逻辑推理示例：**

**假设输入：**

*   模拟的 GPU 硬件加速工厂 (`MockGpuVideoEncodeAcceleratorFactories`) 报告支持 H.264 Baseline Profile (`profile-level-id = 42001f`).
*   调用 `encoder_factory_.QueryCodecSupport` 方法，传入的 `webrtc::SdpVideoFormat` 参数为 H.264，并且 `profile-level-id` 设置为 "42001f"。

**输出：**

*   测试断言 (`EXPECT_TRUE`) 验证 `QueryCodecSupport` 的返回值等于 `kSupportedPowerEfficient`，表示支持且节能。

**假设输入：**

*   Feature flag `kWebRtcAllowH265Send` 被启用。
*   调用 `encoder_factory_.GetSupportedFormats` 方法。

**输出：**

*   测试断言 (`EXPECT_THAT`) 验证返回的支持格式列表中包含了 H.265 的格式 (`kH265MainProfileLevel52Sdp`, `kH265Main10ProfileLevel31Sdp`)。

**涉及用户或者编程常见的使用错误：**

1. **错误的 SDP 参数配置：** 用户或开发者在 JavaScript 中使用 WebRTC API 时，可能会错误地配置 SDP (Session Description Protocol) 中的视频编解码器参数，例如拼写错误或使用了不支持的参数组合。这会导致 `RTCVideoEncoderFactory` 无法找到匹配的编码器。

    **举例说明：**  一个开发者在 JavaScript 中尝试创建一个使用 "H264" 编码，但将 `profile-level-id` 错误地拼写为 "42001e"。 `RTCVideoEncoderFactory` 在查询时，由于无法识别这个错误的 profile-level-id，可能会返回不支持，即使系统本身支持 H.264。这个测试文件通过测试各种正确的参数组合，来确保 `RTCVideoEncoderFactory` 能够正确处理合法的输入。

2. **假设硬件编码总是可用：**  开发者可能会假设用户的设备总是支持硬件加速的视频编码。然而，实际情况是硬件编码的可用性取决于用户的硬件和驱动程序。如果硬件编码不可用，`RTCVideoEncoderFactory` 可能会回退到软件编码，或者直接返回不支持。

    **举例说明：**  一个 Web 应用没有检测硬件编码的可用性，直接尝试使用硬件加速的 H.264 编码。如果用户的 GPU 不支持，或者驱动程序有问题，`RTCVideoEncoderFactory` 可能会返回不支持，导致应用功能异常。这个测试文件通过模拟不同的 GPU 支持情况，确保 `RTCVideoEncoderFactory` 在各种硬件环境下都能正确工作。

3. **忽略 Feature Flags 的影响：**  Chromium 使用 Feature Flags 来控制某些功能的启用和禁用。开发者可能会忘记某个特定的视频编解码器或者功能需要特定的 Feature Flag 开启才能使用。

    **举例说明：**  开发者可能期望在所有版本的 Chromium 上都能使用 H.265 编码，但实际上 H.265 的支持可能需要特定的 Feature Flag (`kWebRtcAllowH265Send`) 启用。如果这个 Flag 没有启用，`RTCVideoEncoderFactory` 会报告不支持 H.265。这个测试文件通过模拟不同的 Feature Flag 状态，确保 `RTCVideoEncoderFactory` 在不同的 Flag 配置下行为符合预期。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_encoder_factory_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/peerconnection/rtc_video_encoder_factory.h"

#include <stdint.h>

#include "base/test/scoped_feature_list.h"
#include "base/test/task_environment.h"
#include "media/base/media_switches.h"
#include "media/base/svc_scalability_mode.h"
#include "media/base/video_codecs.h"
#include "media/mojo/clients/mojo_video_encoder_metrics_provider.h"
#include "media/video/mock_gpu_video_accelerator_factories.h"
#include "media/webrtc/webrtc_features.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/peerconnection/rtc_video_encoder.h"
#include "third_party/webrtc/api/video_codecs/sdp_video_format.h"
#include "third_party/webrtc/api/video_codecs/video_encoder_factory.h"

using ::testing::Return;
using ::testing::UnorderedElementsAre;

namespace blink {

namespace {

constexpr webrtc::VideoEncoderFactory::CodecSupport kSupportedPowerEfficient = {
    true, true};
constexpr webrtc::VideoEncoderFactory::CodecSupport kUnsupported = {false,
                                                                    false};
constexpr gfx::Size kMaxResolution = {1920, 1080};
constexpr uint32_t kMaxFramerateNumerator = 30;
constexpr gfx::Size kLowResolution = {320, 240};

#if BUILDFLAG(RTC_USE_H265)
// Settings from video toolbox encoder.
constexpr gfx::Size kHEVCMaxResolution = {4096, 2304};
constexpr uint32_t kHEVCMaxFramerateNumerator = 120;
#endif  // BUILDFLAG(RTC_USE_H265)

constexpr uint32_t kMaxFramerateDenominator = 1;
const std::vector<media::SVCScalabilityMode> kSVCScalabilityModes = {
    media::SVCScalabilityMode::kL1T1, media::SVCScalabilityMode::kL1T2,
    media::SVCScalabilityMode::kL1T3};
using ScalbilityModeMap ALLOW_DISCOURAGED_TYPE("Match WebRTC type") =
    absl::InlinedVector<webrtc::ScalabilityMode, webrtc::kScalabilityModeCount>;
const ScalbilityModeMap kScalabilityModes = {webrtc::ScalabilityMode::kL1T1,
                                             webrtc::ScalabilityMode::kL1T2,
                                             webrtc::ScalabilityMode::kL1T3};
const ScalbilityModeMap kReducedScalabilityModes = {
    webrtc::ScalabilityMode::kL1T1, webrtc::ScalabilityMode::kL1T2};
const ScalbilityModeMap kNoLayeringScalabilityModes = {
    webrtc::ScalabilityMode::kL1T1};

const webrtc::SdpVideoFormat kVp8Sdp("VP8", {}, kScalabilityModes);
const webrtc::SdpVideoFormat kVp9Profile0Sdp("VP9",
                                             {{"profile-id", "0"}},
                                             kScalabilityModes);
// TODO(http://crbugs.com/376306259): Ensure hardware encoder factory include
// profile-id/tier/level-idx in AV1 SDP.
const webrtc::SdpVideoFormat kAv1Profile0Sdp("AV1", {}, kScalabilityModes);
const webrtc::SdpVideoFormat kH264BaselinePacketizatonMode1Sdp(
    "H264",
    {{"level-asymmetry-allowed", "1"},
     {"packetization-mode", "1"},
     {"profile-level-id", "42001f"}},
    kScalabilityModes);
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_ANDROID)
const webrtc::SdpVideoFormat kH264ConstrainedBaselinePacketizatonMode1Sdp(
    "H264",
    {{"level-asymmetry-allowed", "1"},
     {"packetization-mode", "1"},
     {"profile-level-id", "42e01f"}},
    kScalabilityModes);
#endif  // BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_ANDROID)
#if BUILDFLAG(RTC_USE_H265)
const webrtc::SdpVideoFormat kH265MainProfileLevel31Sdp("H265",
                                                        {{"profile-id", "1"},
                                                         {"tier-flag", "0"},
                                                         {"level-id", "93"},
                                                         {"tx-mode", "SRST"}},
                                                        kScalabilityModes);
const webrtc::SdpVideoFormat kH265MainProfileLevel52Sdp("H265",
                                                        {{"profile-id", "1"},
                                                         {"tier-flag", "0"},
                                                         {"level-id", "156"},
                                                         {"tx-mode", "SRST"}},
                                                        kScalabilityModes);
const webrtc::SdpVideoFormat kH265Main10ProfileLevel31Sdp("H265",
                                                          {{"profile-id", "2"},
                                                           {"tier-flag", "0"},
                                                           {"level-id", "93"},
                                                           {"tx-mode", "SRST"}},
                                                          kScalabilityModes);
const webrtc::SdpVideoFormat kH265MainProfileLevel52SdpL1T2(
    "H265",
    {{"profile-id", "1"},
     {"tier-flag", "0"},
     {"level-id", "156"},
     {"tx-mode", "SRST"}},
    kReducedScalabilityModes);
const webrtc::SdpVideoFormat kH265Main10ProfileLevel31SdpL1T2(
    "H265",
    {{"profile-id", "2"},
     {"tier-flag", "0"},
     {"level-id", "93"},
     {"tx-mode", "SRST"}},
    kReducedScalabilityModes);
const webrtc::SdpVideoFormat kH265MainProfileLevel52SdpL1T1(
    "H265",
    {{"profile-id", "1"},
     {"tier-flag", "0"},
     {"level-id", "156"},
     {"tx-mode", "SRST"}},
    kNoLayeringScalabilityModes);
const webrtc::SdpVideoFormat kH265Main10ProfileLevel31SdpL1T1(
    "H265",
    {{"profile-id", "2"},
     {"tier-flag", "0"},
     {"level-id", "93"},
     {"tx-mode", "SRST"}},
    kNoLayeringScalabilityModes);
#endif  // BUILDFLAG(RTC_USE_H265)

bool Equals(webrtc::VideoEncoderFactory::CodecSupport a,
            webrtc::VideoEncoderFactory::CodecSupport b) {
  return a.is_supported == b.is_supported &&
         a.is_power_efficient == b.is_power_efficient;
}

class MockGpuVideoEncodeAcceleratorFactories
    : public media::MockGpuVideoAcceleratorFactories {
 public:
  MockGpuVideoEncodeAcceleratorFactories()
      : MockGpuVideoAcceleratorFactories(nullptr) {}

  std::optional<media::VideoEncodeAccelerator::SupportedProfiles>
  GetVideoEncodeAcceleratorSupportedProfiles() override {
    media::VideoEncodeAccelerator::SupportedProfiles profiles = {
        {media::H264PROFILE_BASELINE, kMaxResolution, kMaxFramerateNumerator,
         kMaxFramerateDenominator, media::VideoEncodeAccelerator::kConstantMode,
         kSVCScalabilityModes},
        {media::H264PROFILE_BASELINE, kMaxResolution, kMaxFramerateNumerator,
         kMaxFramerateDenominator, media::VideoEncodeAccelerator::kConstantMode,
         kSVCScalabilityModes},
        // H264 with mismatch between profile and resolution should be ignored.
        {media::H264PROFILE_HIGH, kLowResolution, kMaxFramerateNumerator,
         kMaxFramerateDenominator, media::VideoEncodeAccelerator::kConstantMode,
         kSVCScalabilityModes},
        {media::VP8PROFILE_ANY, kMaxResolution, kMaxFramerateNumerator,
         kMaxFramerateDenominator, media::VideoEncodeAccelerator::kConstantMode,
         kSVCScalabilityModes},
        {media::VP9PROFILE_PROFILE0, kMaxResolution, kMaxFramerateNumerator,
         kMaxFramerateDenominator, media::VideoEncodeAccelerator::kConstantMode,
         kSVCScalabilityModes},
        {media::AV1PROFILE_PROFILE_MAIN, kMaxResolution, kMaxFramerateNumerator,
         kMaxFramerateDenominator, media::VideoEncodeAccelerator::kConstantMode,
         kSVCScalabilityModes},
#if BUILDFLAG(RTC_USE_H265)
        {media::HEVCPROFILE_MAIN, kHEVCMaxResolution,
         kHEVCMaxFramerateNumerator, kMaxFramerateDenominator,
         media::VideoEncodeAccelerator::kConstantMode, kSVCScalabilityModes},
        // The profile below will produce HEVC level 3.1, which we expect not to
        // be reported as the supported level, since the profile above
        // produces HEVC level 5.2, which we will report as supported level.
        {media::HEVCPROFILE_MAIN, kMaxResolution, kHEVCMaxFramerateNumerator,
         kMaxFramerateDenominator, media::VideoEncodeAccelerator::kConstantMode,
         kSVCScalabilityModes},
        {media::HEVCPROFILE_MAIN10, kMaxResolution, kHEVCMaxFramerateNumerator,
         kMaxFramerateDenominator, media::VideoEncodeAccelerator::kConstantMode,
         kSVCScalabilityModes}
#endif  //  BUILDFLAG(RTC_USE_H265)
    };
    return profiles;
  }

  scoped_refptr<base::SequencedTaskRunner> GetTaskRunner() override {
    return base::SequencedTaskRunner::GetCurrentDefault();
  }
};

}  // anonymous namespace

class RTCVideoEncoderFactoryTest : public ::testing::Test {
 public:
  RTCVideoEncoderFactoryTest()
      : encoder_factory_(&mock_gpu_factories_,
                         /*encoder_metrics_provider_factory=*/nullptr) {}
  // Ensure all the profiles in our mock GPU factory are allowed.
  void ClearDisabledProfilesForTesting() {
    encoder_factory_.clear_disabled_profiles_for_testing();
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  MockGpuVideoEncodeAcceleratorFactories mock_gpu_factories_;
  RTCVideoEncoderFactory encoder_factory_;
};

TEST_F(RTCVideoEncoderFactoryTest, QueryCodecSupportNoSvc) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitFromCommandLine("MediaFoundationH264CbpEncoding", "");

  ClearDisabledProfilesForTesting();
  EXPECT_CALL(mock_gpu_factories_, IsEncoderSupportKnown())
      .WillRepeatedly(Return(true));
  // H.264 BP/CBP, VP8 and VP9 profile 0 are supported.
  EXPECT_TRUE(Equals(
      encoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("VP8"),
                                         /*scalability_mode=*/std::nullopt),
      kSupportedPowerEfficient));
  EXPECT_TRUE(Equals(
      encoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("VP9"),
                                         /*scalability_mode=*/std::nullopt),
      kSupportedPowerEfficient));
#if BUILDFLAG(RTC_USE_H264)
  EXPECT_TRUE(Equals(
      encoder_factory_.QueryCodecSupport(
          webrtc::SdpVideoFormat("H264", {{"level-asymmetry-allowed", "1"},
                                          {"packetization-mode", "1"},
                                          {"profile-level-id", "42001f"}}),
          /*scalability_mode=*/std::nullopt),
      kSupportedPowerEfficient));
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_LINUX)
  EXPECT_TRUE(Equals(
      encoder_factory_.QueryCodecSupport(
          webrtc::SdpVideoFormat("H264", {{"level-asymmetry-allowed", "1"},
                                          {"packetization-mode", "1"},
                                          {"profile-level-id", "42c01f"}}),
          /*scalability_mode=*/std::nullopt),
      kSupportedPowerEfficient));
#endif
#endif
  EXPECT_TRUE(Equals(
      encoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("AV1"),
                                         /*scalability_mode=*/std::nullopt),
      kSupportedPowerEfficient));

  // H264 > BP and VP9 profile 2 are unsupported.
  EXPECT_TRUE(Equals(
      encoder_factory_.QueryCodecSupport(
          webrtc::SdpVideoFormat("H264", {{"level-asymmetry-allowed", "1"},
                                          {"packetization-mode", "1"},
                                          {"profile-level-id", "4d001f"}}),
          /*scalability_mode=*/std::nullopt),
      kUnsupported));
  EXPECT_TRUE(Equals(encoder_factory_.QueryCodecSupport(
                         webrtc::SdpVideoFormat("VP9", {{"profile-id", "2"}}),
                         /*scalability_mode=*/std::nullopt),
                     kUnsupported));
}

TEST_F(RTCVideoEncoderFactoryTest, QueryCodecSupportSvc) {
  ClearDisabledProfilesForTesting();
  EXPECT_CALL(mock_gpu_factories_, IsEncoderSupportKnown())
      .WillRepeatedly(Return(true));
  // Test supported modes.
  EXPECT_TRUE(Equals(
      encoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("VP8"), "L1T2"),
      kSupportedPowerEfficient));
  EXPECT_TRUE(Equals(
      encoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("VP9"), "L1T3"),
      kSupportedPowerEfficient));

  // Test unsupported modes.
  EXPECT_TRUE(Equals(
      encoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("AV1"), "L2T1"),
      kUnsupported));
  EXPECT_TRUE(Equals(encoder_factory_.QueryCodecSupport(
                         webrtc::SdpVideoFormat("H264"), "L2T2"),
                     kUnsupported));
  EXPECT_TRUE(Equals(
      encoder_factory_.QueryCodecSupport(webrtc::SdpVideoFormat("VP8"), "L3T3"),
      kUnsupported));
}

#if BUILDFLAG(RTC_USE_H265)
TEST_F(RTCVideoEncoderFactoryTest,
       QueryCodecSupportForH265WithoutNeccessaryFeatures) {
  base::test::ScopedFeatureList scoped_feature_list;
  EXPECT_CALL(mock_gpu_factories_, IsEncoderSupportKnown())
      .WillRepeatedly(Return(true));

  // H.256 is not supported when WebRtcAllowH265Send is not enabled.
  EXPECT_TRUE(Equals(encoder_factory_.QueryCodecSupport(
                         webrtc::SdpVideoFormat("H265", {{"profile-id", "1"}}),
                         /*scalability_mode=*/std::nullopt),
                     kUnsupported));

#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)
  // H.265 is not supported when WebRtcAllowH265Send is enabled but
  // PlatformHEVCEncoderSupport is disabled.
  scoped_feature_list.InitWithFeatures({::features::kWebRtcAllowH265Send},
                                       {media::kPlatformHEVCEncoderSupport});
  EXPECT_TRUE(Equals(encoder_factory_.QueryCodecSupport(
                         webrtc::SdpVideoFormat("H265", {{"profile-id", "1"}}),
                         /*scalability_mode=*/std::nullopt),
                     kUnsupported));
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)
}

TEST_F(RTCVideoEncoderFactoryTest,
       QueryCodecSupportForH265WithNeccessaryFeatures) {
  ClearDisabledProfilesForTesting();
  base::test::ScopedFeatureList scoped_feature_list;
  std::vector<base::test::FeatureRef> enabled_features;
  enabled_features.emplace_back(::features::kWebRtcAllowH265Send);

#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)
  enabled_features.emplace_back(media::kPlatformHEVCEncoderSupport);
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)

  scoped_feature_list.InitWithFeatures(enabled_features, {});

  EXPECT_CALL(mock_gpu_factories_, IsEncoderSupportKnown())
      .WillRepeatedly(Return(true));

  // H.265 main profile is supported when both WebRtcAllowH265Send and
  // PlatformHEVCEncoderSupport are enabled. level-id, when not specified,
  // implies level 93, and tier-flag defaults to main tier.
  EXPECT_TRUE(Equals(encoder_factory_.QueryCodecSupport(
                         webrtc::SdpVideoFormat("H265", {{"profile-id", "1"}}),
                         /*scalability_mode=*/std::nullopt),
                     kSupportedPowerEfficient));

  // GPU factory reports maximum supported level to be 5.2, which is higher than
  // 3.1. As a result, RTC encoder factory reports level 3.1 to be supported as
  // well.
  EXPECT_TRUE(Equals(encoder_factory_.QueryCodecSupport(
                         webrtc::SdpVideoFormat(
                             "H265", {{"profile-id", "1"}, {"level-id", "93"}}),
                         /*scalability_mode=*/std::nullopt),
                     kSupportedPowerEfficient));

  EXPECT_TRUE(Equals(encoder_factory_.QueryCodecSupport(
                         webrtc::SdpVideoFormat("H265", {{"profile-id", "1"},
                                                         {"level-id", "156"}}),
                         /*scalability_mode=*/std::nullopt),
                     kSupportedPowerEfficient));

  EXPECT_TRUE(Equals(encoder_factory_.QueryCodecSupport(
                         webrtc::SdpVideoFormat("H265", {{"profile-id", "1"},
                                                         {"level-id", "180"}}),
                         /*scalability_mode=*/std::nullopt),
                     kUnsupported));

  EXPECT_TRUE(Equals(encoder_factory_.QueryCodecSupport(
                         webrtc::SdpVideoFormat("H265", {{"profile-id", "2"}}),
                         /*scalability_mode=*/std::nullopt),
                     kSupportedPowerEfficient));
}

TEST_F(RTCVideoEncoderFactoryTest, GetSupportedFormatsReturnsAllExpectedModes) {
  ClearDisabledProfilesForTesting();
  base::test::ScopedFeatureList scoped_feature_list;
  std::vector<base::test::FeatureRef> enabled_features;
  enabled_features.emplace_back(::features::kWebRtcAllowH265Send);
  enabled_features.emplace_back(::features::kWebRtcH265L1T2);
  enabled_features.emplace_back(::features::kWebRtcH265L1T3);

#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)
  enabled_features.emplace_back(media::kPlatformHEVCEncoderSupport);
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)

#if BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) && \
    BUILDFLAG(ENABLE_OPENH264)
  enabled_features.emplace_back(blink::features::kWebRtcH264WithOpenH264FFmpeg);
#endif  // BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) &&
        // BUILDFLAG(ENABLE_OPENH264)

  scoped_feature_list.InitWithFeatures(enabled_features, {});
  EXPECT_CALL(mock_gpu_factories_, IsEncoderSupportKnown())
      .WillRepeatedly(Return(true));

  EXPECT_THAT(encoder_factory_.GetSupportedFormats(),
              UnorderedElementsAre(
#if !BUILDFLAG(IS_ANDROID)
                  kH264BaselinePacketizatonMode1Sdp,
#endif  //  !BUILDFLAG(IS_ANDROID)
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_ANDROID)
                  kH264ConstrainedBaselinePacketizatonMode1Sdp,
#endif  // BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_ANDROID)
                  kVp8Sdp, kVp9Profile0Sdp, kH265MainProfileLevel52Sdp,
                  kH265Main10ProfileLevel31Sdp, kAv1Profile0Sdp));
}

// When WebRtcH265L1T3 flag is not enabled, GetSupportedFormats should exclude
// L1T3 from supported H.265 scalability modes.
TEST_F(RTCVideoEncoderFactoryTest,
       GetSupportedFormatsReturnsAllModesExceptH265L1T3) {
  ClearDisabledProfilesForTesting();
  base::test::ScopedFeatureList scoped_feature_list;
  std::vector<base::test::FeatureRef> enabled_features;
  enabled_features.emplace_back(::features::kWebRtcAllowH265Send);
  enabled_features.emplace_back(::features::kWebRtcH265L1T2);

#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)
  enabled_features.emplace_back(media::kPlatformHEVCEncoderSupport);
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)

#if BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) && \
    BUILDFLAG(ENABLE_OPENH264)
  enabled_features.emplace_back(blink::features::kWebRtcH264WithOpenH264FFmpeg);
#endif  // BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) &&
        // BUILDFLAG(ENABLE_OPENH264)

  scoped_feature_list.InitWithFeatures(enabled_features, {});
  EXPECT_CALL(mock_gpu_factories_, IsEncoderSupportKnown())
      .WillRepeatedly(Return(true));

  EXPECT_THAT(encoder_factory_.GetSupportedFormats(),
              UnorderedElementsAre(
#if !BUILDFLAG(IS_ANDROID)
                  kH264BaselinePacketizatonMode1Sdp,
#endif  //  !BUILDFLAG(IS_ANDROID)
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_ANDROID)
                  kH264ConstrainedBaselinePacketizatonMode1Sdp,
#endif  // BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_ANDROID)
                  kVp8Sdp, kVp9Profile0Sdp, kH265MainProfileLevel52SdpL1T2,
                  kH265Main10ProfileLevel31SdpL1T2, kAv1Profile0Sdp));
}

// When both WebRtcH265L1T2 and WebRtcH265L1T2 flags are disabled,
// GetSupportedFormats should exclude both L1T2 and L1T3 from supported H.265
// scalability modes.
TEST_F(RTCVideoEncoderFactoryTest,
       GetSupportedFormatsReturnsAllModesExceptH265L1T2AndL1T3) {
  ClearDisabledProfilesForTesting();
  base::test::ScopedFeatureList scoped_feature_list;
  std::vector<base::test::FeatureRef> enabled_features;
  std::vector<base::test::FeatureRef> disabled_features;
  enabled_features.emplace_back(::features::kWebRtcAllowH265Send);
  disabled_features.emplace_back(::features::kWebRtcH265L1T2);

#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)
  enabled_features.emplace_back(media::kPlatformHEVCEncoderSupport);
#endif  // BUILDFLAG(IS_WIN) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_ANDROID)

#if BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) && \
    BUILDFLAG(ENABLE_OPENH264)
  enabled_features.emplace_back(blink::features::kWebRtcH264WithOpenH264FFmpeg);
#endif  // BUILDFLAG(RTC_USE_H264) && BUILDFLAG(ENABLE_FFMPEG_VIDEO_DECODERS) &&
        // BUILDFLAG(ENABLE_OPENH264)

  scoped_feature_list.InitWithFeatures(enabled_features, disabled_features);
  EXPECT_CALL(mock_gpu_factories_, IsEncoderSupportKnown())
      .WillRepeatedly(Return(true));

  EXPECT_THAT(encoder_factory_.GetSupportedFormats(),
              UnorderedElementsAre(
#if !BUILDFLAG(IS_ANDROID)
                  kH264BaselinePacketizatonMode1Sdp,
#endif  //  !BUILDFLAG(IS_ANDROID)
#if BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_ANDROID)
                  kH264ConstrainedBaselinePacketizatonMode1Sdp,
#endif  // BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_ANDROID)
                  kVp8Sdp, kVp9Profile0Sdp, kH265MainProfileLevel52SdpL1T1,
                  kH265Main10ProfileLevel31SdpL1T1, kAv1Profile0Sdp));
}
#endif  // BUILDFLAG(RTC_USE_H265)

TEST_F(RTCVideoEncoderFactoryTest, SupportedFormatsHaveScalabilityModes) {
  base::test::ScopedFeatureList scoped_feature_list;
  std::vector<base::test::FeatureRef> enabled_features;
  enabled_features.emplace_back(::features::kWebRtcH265L1T2);
  enabled_features.emplace_back(::features::kWebRtcH265L1T3);
  scoped_feature_list.InitWithFeatures(enabled_features, {});

  ClearDisabledProfilesForTesting();
  EXPECT_CALL(mock_gpu_factories_, IsEncoderSupportKnown())
      .WillRepeatedly(Return(true));

  auto supported_formats = encoder_factory_.GetSupportedFormats();
  for (const auto& format : supported_formats) {
    EXPECT_THAT(format.scalability_modes,
                testing::UnorderedElementsAreArray(kScalabilityModes));
  }
}

}  // namespace blink
```