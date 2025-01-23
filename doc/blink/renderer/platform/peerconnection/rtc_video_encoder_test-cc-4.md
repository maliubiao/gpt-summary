Response:
Let's break down the thought process for analyzing this C++ test file.

**1. Initial Scan for Keywords and Structure:**

The first thing I'd do is quickly scan the code for obvious keywords and structural elements. I see:

* `TEST_F`: This immediately tells me it's a Google Test file. The `_F` suffix indicates it's using a test fixture.
* `RTCVideoEncoderTest`, `RTCVideoEncoderFrameSizeChangeTest`, `RTCVideoEncoderEncodeTest`, `RTCVideoEncoderInitTest`: These are the test fixture classes. They tell me the general areas being tested.
* `EXPECT_CALL`, `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`: These are Google Mock macros, indicating interactions with mock objects and assertions.
* `mock_vea_`, `mock_gpu_factories_`, `mock_encoder_metrics_provider_factory_`: These are likely mock objects used for testing in isolation. `vea` probably stands for Video Encode Accelerator.
* `InitEncode`, `Encode`, `Release`, `Flush`: These are methods likely being tested on the `rtc_encoder_`.
* `webrtc::VideoCodec`, `webrtc::VideoFrame`, `webrtc::EncodedImage`: These are WebRTC specific types, suggesting this code is related to WebRTC's video encoding functionality.
* `base::WaitableEvent`: This suggests asynchronous operations and waiting for events.
* `gfx::Size`:  This indicates handling of video dimensions.
* Codec names like `kVideoCodecH264`, `kVideoCodecAV1`, `kVideoCodecVP9`, `kVideoCodecH265`:  These specify the video codecs being tested.
* Scalability modes like `kL1T1`, `kL1T3`:  These point to testing scalable video coding features.
* Feature flags:  The presence of `base::test::ScopedFeatureList` suggests testing different behavior based on enabled/disabled features.

**2. Deduce the Core Functionality:**

Based on the keywords and structure, I can infer that this file tests the `RTCVideoEncoder` class in the Chromium Blink engine. This class seems to be a wrapper around a lower-level video encoding component (likely the `media::VideoEncodeAccelerator`). The tests likely focus on:

* **Initialization:** Testing different scenarios for initializing the encoder with various codec settings, resolutions, and hardware capabilities.
* **Encoding:** Testing the encoding process itself, including handling different frame types (keyframes), temporal layers, and the interaction with the underlying encoder.
* **Error Handling:**  Testing how the `RTCVideoEncoder` handles errors reported by the underlying video encoder.
* **Frame Size Changes:**  Specifically testing the ability to change the video frame size during an encoding session.
* **Software Fallback:** Testing scenarios where hardware acceleration is not available or fails, and the encoder falls back to software encoding.
* **Scalable Video Coding (SVC):** Testing the handling of temporal layers and potentially spatial layers for codecs like AV1 and H.265.
* **Metrics:** Testing the integration with a metrics provider.

**3. Identify Relationships with Web Technologies (HTML, CSS, JavaScript):**

Now, I consider how this backend C++ code relates to frontend web technologies:

* **JavaScript:** This code is part of the Blink rendering engine, which powers the browser. JavaScript code using the WebRTC API (`RTCPeerConnection`, `MediaStreamTrack`) will eventually trigger the use of this `RTCVideoEncoder` when sending video. The tests ensure the encoder behaves correctly when the JavaScript side requests encoding.
* **HTML:**  HTML provides the structure for web pages. While this specific code doesn't directly interact with HTML parsing, the video elements (`<video>`) in HTML are where the decoded video would be displayed after being transmitted via WebRTC. The encoding process tested here is crucial for the functionality of video within HTML.
* **CSS:** CSS is for styling. While CSS doesn't directly impact the *encoding* process, it can affect the *display* of the video. For example, CSS can control the size and positioning of the `<video>` element. The encoding needs to produce a bitstream that can be decoded and rendered correctly regardless of the CSS applied.

**4. Analyze Individual Test Cases for Logic and Assumptions:**

For each test case, I'd try to understand:

* **The Setup:** What objects are created, mocked, and configured before the main action?
* **The Action:** What method of `rtc_encoder_` is being called?
* **The Expectations:** What are the `EXPECT_CALL` and `EXPECT_EQ` statements checking?  What are the expected outcomes?

For example, in `FrameSizeChangeFailure`, I see:

* **Setup:** An encoder is created, encoding is set up.
* **Action:** `InitEncode` is called again with a different frame size, after an error is simulated in the underlying VEA.
* **Expectations:**  It expects `WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE`, meaning the frame size change failed, and the encoder fell back.

**5. Identify Potential User/Programming Errors:**

Based on the tested scenarios, I can infer potential errors:

* **Incorrect Codec Parameters:**  Trying to initialize the encoder with unsupported resolutions or profiles.
* **Hardware Incompatibility:**  Assuming hardware acceleration is available when it's not.
* **Incorrect Scalability Mode Configuration:** Trying to use a scalability mode not supported by the hardware.
* **Mismatched Frame Sizes:** Trying to encode frames with a size different from the initialized encoder size (without proper frame size change support).
* **Error Handling Neglect:** Not handling potential encoding errors on the JavaScript side, leading to unexpected behavior.

**6. Synthesize the Summary:**

Finally, I would summarize the functionality by combining the high-level understanding and the details learned from analyzing the test cases. I'd focus on the core purpose of the file and its relation to the broader WebRTC and browser context.

This step-by-step approach, combining broad overview with detailed analysis of specific parts, allows for a comprehensive understanding of the purpose and function of a complex code file like this.
这是对 `blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc` 文件功能的总结，基于提供的代码片段：

**文件功能归纳：**

`rtc_video_encoder_test.cc` 文件包含了对 `RTCVideoEncoder` 类的单元测试。 `RTCVideoEncoder` 是 Chromium Blink 引擎中用于视频编码的核心组件，它负责将原始视频帧编码成可以通过 WebRTC 进行传输的格式。  这个测试文件主要验证了 `RTCVideoEncoder` 在各种场景下的正确行为，包括初始化、编码、错误处理、帧大小变更以及与底层硬件加速器 (VEA - Video Encode Accelerator) 的交互。

**具体功能点 (基于提供的代码片段)：**

* **测试帧大小变更失败的情况:**  `RTCVideoEncoderFrameSizeChangeTest` 测试套件专门用于测试在编码过程中尝试更改视频帧大小时可能发生的失败情况，并验证 `RTCVideoEncoder` 是否能正确处理这些失败，例如回退到软件编码。
* **测试当 VEA 不支持 AV1 编码的特定模式时回退到软件编码:** `RTCVideoEncoderEncodeTest` 中的 `AV1SoftwareFallbackForVEANotSupport` 测试用例验证了当硬件加速器不支持 AV1 的可伸缩视频编码 (SVC) 模式时，`RTCVideoEncoder` 能否正确地回退到软件编码。
* **测试 AV1 编码中时间层 (Temporal Layer) 的通用帧信息 (Generic Frame Info):** `AV1TemporalLayerGenericFrameInfo` 测试用例检查了在 AV1 编码中，`RTCVideoEncoder` 如何处理时间层，并验证了编码后的比特流中是否包含正确的通用帧信息元数据。这涉及到检查 `CodecSpecificInfo` 结构体中 `template_structure` 和 `generic_frame_info` 的存在性。
* **测试根据支持的硬件加速能力进行初始化:** `RTCVideoEncoderInitTest` 测试套件关注 `RTCVideoEncoder` 的初始化过程。
    * `CheckInputVisibleSizeWithinSupportedDimensions`: 验证当请求编码的视频尺寸在硬件加速器支持的范围内时，初始化能否成功。
    * `CheckInputVisibleSizeBeyondSupportedDimensions`: 验证当请求编码的视频尺寸超出硬件加速器支持的范围时，`RTCVideoEncoder` 能否正确回退到软件编码。
    * `CheckInputVisibleSizeWithinSupportedDimensionsButIsSoftware`: 验证即使视频尺寸在支持范围内，但如果硬件加速器被标记为软件实现，`RTCVideoEncoder` 是否会回退。
    * `SupportedTemporalLayerIsRejectedSoftwareCodecWillFallback`:  验证当硬件加速器是软件实现时，即使支持时间层，也会回退到软件编码。
    * `SupportedTemporalLayersAreHardwareInitOK`: 验证当硬件加速器是硬件实现且支持时间层时，初始化能否成功。
* **测试 H.265 编码中时间层的支持情况 (如果启用了 H.265):**  `RTCVideoEncoderEncodeTest` 中的 `H265TemporalLayerNotSupported` 和 `H265TemporalLayerGenericFrameInfo` 测试用例（仅在 `BUILDFLAG(RTC_USE_H265)` 为真时编译）类似于 AV1 的测试，验证了 H.265 在时间层支持和通用帧信息处理方面的行为。

**与 JavaScript, HTML, CSS 的关系：**

`RTCVideoEncoder` 位于浏览器引擎的底层，直接与 JavaScript 的 WebRTC API 交互，但不直接操作 HTML 或 CSS。

* **JavaScript:** JavaScript 代码使用 `RTCPeerConnection` API 获取本地视频流，并通过 `RTCRtpSender` 将其发送到远端。在这个过程中，`RTCVideoEncoder` 会被调用来编码视频帧。例如，在 JavaScript 中调用 `sender.replaceTrack(videoTrack)`  可能会触发视频编码流程，最终使用到 `RTCVideoEncoder`。测试中模拟了编码过程，验证了 `RTCVideoEncoder` 接收到 JavaScript 传递的视频帧后能否正确编码。
* **HTML:** HTML 中的 `<video>` 元素用于展示视频。编码后的视频流最终会在远端被解码并在 `<video>` 标签中显示。`RTCVideoEncoder` 的正确工作是保证 HTML 中视频内容正常显示的基础。
* **CSS:** CSS 用于控制 HTML 元素的样式，包括 `<video>` 标签。CSS 的样式不会直接影响 `RTCVideoEncoder` 的编码逻辑，但会影响视频在页面上的呈现效果。

**逻辑推理、假设输入与输出：**

* **假设输入 (以 `FrameSizeChangeFailure` 为例):**
    * 初始化编码器使用一种编码格式 (例如 H.264) 和初始分辨率。
    * 模拟底层硬件加速器在 Flush 操作时发生错误。
    * 尝试使用新的分辨率重新初始化编码器。
* **预期输出:**
    * 第一次初始化可能成功。
    * 由于 Flush 操作失败，可能会收到一个错误通知。
    * 第二次初始化会因为某些原因失败 (例如，底层 VEA 无法处理帧大小变更)，导致 `InitEncode` 返回 `WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE`，表示回退到软件编码。

* **假设输入 (以 `AV1TemporalLayerGenericFrameInfo` 为例):**
    * 初始化 AV1 编码器并配置为使用时间层。
    * 连续编码多个视频帧。
* **预期输出:**
    * 第一个编码帧的 `CodecSpecificInfo` 中应该包含 `template_structure`。
    * 前几个编码帧的 `CodecSpecificInfo` 中应该包含 `generic_frame_info`。
    * 后续的编码帧 (根据测试逻辑，picture_id >= 3) 的 `CodecSpecificInfo` 中不应包含 `generic_frame_info` (因为测试中故意返回了无效的元数据来模拟这种情况)。

**用户或编程常见的使用错误：**

* **尝试使用硬件不支持的编码参数:** 用户或开发者可能会尝试初始化 `RTCVideoEncoder` 使用某些硬件加速器不支持的编码格式、分辨率或配置（例如，尝试使用多时间层的 AV1 编码，但硬件只支持单层）。这会导致初始化失败或回退到软件编码，性能可能下降。
* **在不支持帧大小变更的情况下尝试更改帧大小:** 如果底层硬件加速器不支持运行时帧大小变更，开发者尝试在编码过程中动态改变视频帧大小可能会导致错误或不可预测的行为。
* **没有正确处理编码器的错误回调:**  如果底层硬件加速器发生错误，`RTCVideoEncoder` 会通过回调通知上层。如果开发者没有正确处理这些错误，可能会导致视频传输中断或其他问题。
* **假设硬件加速总是可用:** 开发者可能会错误地假设硬件加速总是可用的，而没有考虑到某些平台或配置下可能只能使用软件编码。这可能导致在这些环境下性能不佳。

**总结 (基于所有部分):**

总的来说，`blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc` 文件的主要功能是 **全面测试 `RTCVideoEncoder` 类的各项功能和在各种场景下的鲁棒性**。它覆盖了初始化、正常编码、错误处理、与硬件加速器的交互、以及对特定编码格式（如 AV1 和 H.265）特性的测试。 这些测试确保了 `RTCVideoEncoder` 能够可靠地完成视频编码任务，为 WebRTC 功能提供稳定的基础。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
base::WaitableEvent error_waiter(
        base::WaitableEvent::ResetPolicy::MANUAL,
        base::WaitableEvent::InitialState::NOT_SIGNALED);
    rtc_encoder_->SetErrorWaiter(&error_waiter);

    EXPECT_CALL(*mock_vea_, Flush)
        .WillOnce(Invoke(this, &RTCVideoEncoderTest::FlushFailure));

    EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
              rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
    error_waiter.Wait();

    auto encoder_metrics_provider =
        std::make_unique<media::MockVideoEncoderMetricsProvider>();
    EXPECT_CALL(*mock_encoder_metrics_provider_factory_,
                CreateVideoEncoderMetricsProvider())
        .WillOnce(Return(ByMove(std::move(encoder_metrics_provider))));
    SetUpEncodingWithFrameSizeChangeSupport(codec);

    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK, rtc_encoder_->Release());
    RunUntilIdle();
}

TEST_F(RTCVideoEncoderFrameSizeChangeTest, FrameSizeChangeFailure) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecH264;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  SetUpEncodingWithFrameSizeChangeSupport(codec);

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK, rtc_encoder_->Release());

  codec.width *= 2;
  codec.height *= 2;

    std::vector<webrtc::VideoFrameType> frame_types;
    base::WaitableEvent error_waiter(
        base::WaitableEvent::ResetPolicy::MANUAL,
        base::WaitableEvent::InitialState::NOT_SIGNALED);
    rtc_encoder_->SetErrorWaiter(&error_waiter);

    EXPECT_CALL(*mock_vea_, Flush)
        .WillOnce(Invoke(this, &RTCVideoEncoderTest::FlushComplete));
    EXPECT_CALL(
        *mock_vea_,
        RequestEncodingParametersChange(
            _, _,
            std::optional<gfx::Size>(gfx::Size(codec.width, codec.height))))
        .WillOnce(Invoke([this](const media::Bitrate&, uint32_t,
                                const std::optional<gfx::Size>&) {
          encoder_thread_.task_runner()->PostTask(
              FROM_HERE,
              base::BindOnce(
                  &media::VideoEncodeAccelerator::Client::NotifyErrorStatus,
                  base::Unretained(client_),
                  media::EncoderStatus::Codes::kSystemAPICallError));
        }));

    EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
              rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
    error_waiter.Wait();

    auto encoder_metrics_provider =
        std::make_unique<media::MockVideoEncoderMetricsProvider>();
    EXPECT_CALL(*mock_encoder_metrics_provider_factory_,
                CreateVideoEncoderMetricsProvider())
        .WillOnce(Return(ByMove(std::move(encoder_metrics_provider))));
    SetUpEncodingWithFrameSizeChangeSupport(codec);

    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK, rtc_encoder_->Release());
}

TEST_F(RTCVideoEncoderEncodeTest, AV1SoftwareFallbackForVEANotSupport) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecAV1,
                                                 /*num_spatial_layers=*/1);
  tl_codec.SetScalabilityMode(webrtc::ScalabilityMode::kL1T3);
  CreateEncoder(tl_codec.codecType);

  media::VideoEncodeAccelerator::SupportedProfiles profiles = {
      {media::AV1PROFILE_PROFILE_MAIN,
       /*max_resolution*/ gfx::Size(1920, 1088),
       /*max_framerate_numerator*/ 30,
       /*max_framerate_denominator*/ 1,
       media::VideoEncodeAccelerator::kConstantMode,
       {media::SVCScalabilityMode::kL1T1}}};
  EXPECT_CALL(*mock_gpu_factories_.get(),
              GetVideoEncodeAcceleratorSupportedProfiles())
      .WillOnce(Return(profiles));
  // The mock gpu factories return |profiles| as VEA supported profiles, which
  // only support AV1 single layer acceleration. When requesting AV1 SVC
  // encoding, InitEncode() will fail in scalability mode check and return
  // WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE.
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
}

TEST_F(RTCVideoEncoderEncodeTest, AV1TemporalLayerGenericFrameInfo) {
  class BitStreamVerifier : public webrtc::EncodedImageCallback {
   public:
    explicit BitStreamVerifier(size_t picture_id) : picture_id_(picture_id) {}
    ~BitStreamVerifier() override = default;

    webrtc::EncodedImageCallback::Result OnEncodedImage(
        const webrtc::EncodedImage& encoded_image,
        const webrtc::CodecSpecificInfo* codec_specific_info) override {
      // The template structure should be present for the first frame.
      if (picture_id_ == 0) {
        EXPECT_TRUE(codec_specific_info->template_structure.has_value());
      }

      // The bitstream metadata is generated in
      // ReturnSVCLayerFrameWithInvalidGenericMetadata().
      if (picture_id_ >= 3) {
        EXPECT_FALSE(codec_specific_info->generic_frame_info.has_value());
      } else {
        EXPECT_TRUE(codec_specific_info->generic_frame_info.has_value());
      }

      waiter_.Signal();
      return Result(Result::OK);
    }

    void Wait() { waiter_.Wait(); }

   private:
    base::WaitableEvent waiter_;
    size_t picture_id_;
  };

  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecAV1,
                                                 /*num_spatial_layers=*/1);
  tl_codec.SetScalabilityMode(webrtc::ScalabilityMode::kL1T3);
  CreateEncoder(tl_codec.codecType);

  media::VideoEncodeAccelerator::SupportedProfiles profiles{
      {media::AV1PROFILE_PROFILE_MAIN,
       /*max_resolution*/ gfx::Size(1920, 1088),
       /*max_framerate_numerator*/ 30,
       /*max_framerate_denominator*/ 1,
       media::VideoEncodeAccelerator::kConstantMode,
       {media::SVCScalabilityMode::kL1T1, media::SVCScalabilityMode::kL1T3}}};
  EXPECT_CALL(*mock_gpu_factories_.get(),
              GetVideoEncodeAcceleratorSupportedProfiles())
      .Times(AtLeast(1))
      .WillOnce(Return(profiles));
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));

  size_t kNumEncodeFrames = 5u;
  for (size_t i = 0; i < kNumEncodeFrames; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    if (i == 0) {
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    }
    base::WaitableEvent event;
    if (i > 0) {
      EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer(_)).Times(1);
    }
    BitStreamVerifier bitstream_verifier(i);
    rtc_encoder_->RegisterEncodeCompleteCallback(&bitstream_verifier);
    EXPECT_CALL(*mock_vea_, Encode(_, _))
        .WillOnce(DoAll(
            Invoke(this, &RTCVideoEncoderTest::
                             ReturnSVCLayerFrameWithInvalidGenericMetadata),
            [&event]() { event.Signal(); }));
    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(0)
                                       .set_timestamp_us(i)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build(),
                                   &frame_types));
    event.Wait();
  }
}

TEST_F(RTCVideoEncoderInitTest,
       CheckInputVisibleSizeWithinSupportedDimensions) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitFromCommandLine("WebRtcUseMinMaxVEADimensions", "");

  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP9;
  CreateEncoder(codec_type);
  media::VideoEncodeAccelerator::SupportedProfiles profiles = {
      {
          media::VP9PROFILE_PROFILE0,
          /*max_resolution=*/gfx::Size(640, 360),
          /*max_framerate_numerator=*/30,
          /*max_framerate_denominator=*/1,
          media::VideoEncodeAccelerator::kConstantMode,
          {media::SVCScalabilityMode::kL1T1},
      },
      {media::VP9PROFILE_PROFILE0,
       /*max_resolution=*/gfx::Size(1280, 720),
       /*max_framerate_numerator=*/30,
       /*max_framerate_denominator=*/1,
       media::VideoEncodeAccelerator::kConstantMode,
       {media::SVCScalabilityMode::kL1T1}}};
  EXPECT_CALL(*mock_gpu_factories_.get(),
              GetVideoEncodeAcceleratorSupportedProfiles())
      .Times(AtLeast(1))
      .WillOnce(Return(profiles));

  webrtc::VideoCodec codec_settings;
  codec_settings.codecType = webrtc::kVideoCodecVP9;
  codec_settings.width = 1280;
  codec_settings.height = 720;

  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec_settings, kVideoEncoderSettings));
}

TEST_F(RTCVideoEncoderInitTest,
       CheckInputVisibleSizeBeyondSupportedDimensions) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitFromCommandLine("WebRtcUseMinMaxVEADimensions", "");

  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP9;
  CreateEncoder(codec_type);
  media::VideoEncodeAccelerator::SupportedProfiles profiles = {
      {
          media::VP9PROFILE_PROFILE0,
          /*max_resolution=*/gfx::Size(1280, 720),
          /*max_framerate_numerator=*/30,
          /*max_framerate_denominator=*/1,
          media::VideoEncodeAccelerator::kConstantMode,
          {media::SVCScalabilityMode::kL1T1},
      },
      {media::VP9PROFILE_PROFILE0,
       /*max_resolution=*/gfx::Size(640, 360),
       /*max_framerate_numerator=*/30,
       /*max_framerate_denominator=*/1,
       media::VideoEncodeAccelerator::kConstantMode,
       {media::SVCScalabilityMode::kL1T1}}};
  EXPECT_CALL(*mock_gpu_factories_.get(),
              GetVideoEncodeAcceleratorSupportedProfiles())
      .WillOnce(Return(profiles));

  webrtc::VideoCodec codec_settings;
  codec_settings.codecType = webrtc::kVideoCodecVP9;
  codec_settings.width = 1920;
  codec_settings.height = 1080;

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->InitEncode(&codec_settings, kVideoEncoderSettings));
}

TEST_F(RTCVideoEncoderInitTest,
       CheckInputVisibleSizeWithinSupportedDimensionsButIsSoftware) {
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitFromCommandLine("WebRtcUseMinMaxVEADimensions", "");

  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP9;
  CreateEncoder(codec_type);
  media::VideoEncodeAccelerator::SupportedProfile supported_profile;
  supported_profile.profile = media::VP9PROFILE_PROFILE0;
  supported_profile.max_resolution = gfx::Size(1280, 720);
  supported_profile.max_framerate_numerator = 30;
  supported_profile.max_framerate_denominator = 1;
  supported_profile.rate_control_modes =
      media::VideoEncodeAccelerator::kConstantMode;
  supported_profile.min_resolution = gfx::Size(16, 16);
  supported_profile.is_software_codec = true;
  supported_profile.scalability_modes = {media::SVCScalabilityMode::kL1T1};
  media::VideoEncodeAccelerator::SupportedProfiles profiles = {
      supported_profile};

  EXPECT_CALL(*mock_gpu_factories_.get(),
              GetVideoEncodeAcceleratorSupportedProfiles())
      .WillOnce(Return(profiles));

  webrtc::VideoCodec codec_settings;
  codec_settings.codecType = webrtc::kVideoCodecVP9;
  codec_settings.width = 640;
  codec_settings.height = 360;

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->InitEncode(&codec_settings, kVideoEncoderSettings));
}

TEST_F(RTCVideoEncoderInitTest,
       SupportedTemporalLayerIsRejectedSoftwareCodecWillFallback) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/1);
  CreateEncoder(tl_codec.codecType);

  media::VideoEncodeAccelerator::SupportedProfile supported_profile;
  supported_profile.profile = media::VP9PROFILE_PROFILE0;
  supported_profile.max_resolution = gfx::Size(1280, 720);
  supported_profile.max_framerate_numerator = 30;
  supported_profile.max_framerate_denominator = 1;
  supported_profile.rate_control_modes =
      media::VideoEncodeAccelerator::kConstantMode;
  supported_profile.min_resolution = gfx::Size(16, 16);
  supported_profile.is_software_codec = true;
  supported_profile.scalability_modes = {media::SVCScalabilityMode::kL1T3};
  media::VideoEncodeAccelerator::SupportedProfiles profiles = {
      supported_profile};

  EXPECT_CALL(*mock_gpu_factories_.get(),
              GetVideoEncodeAcceleratorSupportedProfiles())
      .WillOnce(Return(profiles));

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
}

TEST_F(RTCVideoEncoderInitTest, SupportedTemporalLayersAreHardwareInitOK) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/1);
  CreateEncoder(tl_codec.codecType);

  media::VideoEncodeAccelerator::SupportedProfile supported_profile;
  supported_profile.profile = media::VP9PROFILE_PROFILE0;
  supported_profile.max_resolution = gfx::Size(1280, 720);
  supported_profile.max_framerate_numerator = 30;
  supported_profile.max_framerate_denominator = 1;
  supported_profile.rate_control_modes =
      media::VideoEncodeAccelerator::kConstantMode;
  supported_profile.min_resolution = gfx::Size(16, 16);
  supported_profile.is_software_codec = false;
  supported_profile.scalability_modes = {media::SVCScalabilityMode::kL1T3};
  media::VideoEncodeAccelerator::SupportedProfiles profiles = {
      supported_profile};

  EXPECT_CALL(*mock_gpu_factories_.get(),
              GetVideoEncodeAcceleratorSupportedProfiles())
      .Times(AtLeast(1))
      .WillOnce(Return(profiles));

  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
}

#if BUILDFLAG(RTC_USE_H265)
// Test that if VEA does not support H.265 L1T2, the encoder will fail to init.
TEST_F(RTCVideoEncoderEncodeTest, H265TemporalLayerNotSupported) {
  base::test::ScopedFeatureList scoped_feature_list;
  std::vector<base::test::FeatureRef> enabled_features;
  enabled_features.emplace_back(::features::kWebRtcH265L1T2);
  scoped_feature_list.InitWithFeatures(enabled_features, {});

  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecH265,
                                                 /*num_spatial_layers=*/1);
  tl_codec.SetScalabilityMode(webrtc::ScalabilityMode::kL1T2);
  CreateEncoder(tl_codec.codecType);

  media::VideoEncodeAccelerator::SupportedProfiles profiles{
      {media::HEVCPROFILE_MAIN,
       /*max_resolution*/ gfx::Size(1920, 1088),
       /*max_framerate_numerator*/ 30,
       /*max_framerate_denominator*/ 1,
       media::VideoEncodeAccelerator::kConstantMode,
       {media::SVCScalabilityMode::kL1T1}}};
  EXPECT_CALL(*mock_gpu_factories_.get(),
              GetVideoEncodeAcceleratorSupportedProfiles())
      .WillOnce(Return(profiles));

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
}

TEST_F(RTCVideoEncoderEncodeTest, H265TemporalLayerGenericFrameInfo) {
  class BitStreamVerifier : public webrtc::EncodedImageCallback {
   public:
    explicit BitStreamVerifier(size_t picture_id) : picture_id_(picture_id) {}
    ~BitStreamVerifier() override = default;

    webrtc::EncodedImageCallback::Result OnEncodedImage(
        const webrtc::EncodedImage& encoded_image,
        const webrtc::CodecSpecificInfo* codec_specific_info) override {
      // The template structure should be present for the first frame.
      if (picture_id_ == 0) {
        EXPECT_TRUE(codec_specific_info->template_structure.has_value());
      }

      // The bitstream metadata is generated in
      // ReturnSVCLayerFrameWithInvalidGenericMetadata().
      if (picture_id_ >= 3) {
        EXPECT_FALSE(codec_specific_info->generic_frame_info.has_value());
      } else {
        EXPECT_TRUE(codec_specific_info->generic_frame_info.has_value());
      }

      waiter_.Signal();
      return Result(Result::OK);
    }

    void Wait() { waiter_.Wait(); }

   private:
    base::WaitableEvent waiter_;
    size_t picture_id_;
  };

  base::test::ScopedFeatureList scoped_feature_list;
  std::vector<base::test::FeatureRef> enabled_features;
  enabled_features.emplace_back(::features::kWebRtcH265L1T2);
  enabled_features.emplace_back(::features::kWebRtcH265L1T3);
  scoped_feature_list.InitWithFeatures(enabled_features, {});

  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecH265,
                                                 /*num_spatial_layers=*/1);
  tl_codec.SetScalabilityMode(webrtc::ScalabilityMode::kL1T3);
  CreateEncoder(tl_codec.codecType);

  media::VideoEncodeAccelerator::SupportedProfiles profiles{
      {media::HEVCPROFILE_MAIN,
       /*max_resolution*/ gfx::Size(1920, 1088),
       /*max_framerate_numerator*/ 30,
       /*max_framerate_denominator*/ 1,
       media::VideoEncodeAccelerator::kConstantMode,
       {media::SVCScalabilityMode::kL1T1, media::SVCScalabilityMode::kL1T2,
        media::SVCScalabilityMode::kL1T3}}};
  EXPECT_CALL(*mock_gpu_factories_.get(),
              GetVideoEncodeAcceleratorSupportedProfiles())
      .Times(AtLeast(1))
      .WillOnce(Return(profiles));
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));

  size_t kNumEncodeFrames = 5u;
  for (size_t i = 0; i < kNumEncodeFrames; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    if (i == 0) {
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    }
    base::WaitableEvent event;
    if (i > 0) {
      EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer(_)).Times(1);
    }
    BitStreamVerifier bitstream_verifier(i);
    rtc_encoder_->RegisterEncodeCompleteCallback(&bitstream_verifier);
    EXPECT_CALL(*mock_vea_, Encode(_, _))
        .WillOnce(DoAll(
            Invoke(this, &RTCVideoEncoderTest::
                             ReturnSVCLayerFrameWithInvalidGenericMetadata),
            [&event]() { event.Signal(); }));
    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(0)
                                       .set_timestamp_us(i)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build(),
                                   &frame_types));
    event.Wait();
  }
}
#endif  // BUILDFLAG(RTC_USE_H265)

}  // namespace blink
```