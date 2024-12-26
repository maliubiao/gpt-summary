Response:
The user wants to understand the functionality of the provided C++ code snippet from `rtc_video_encoder_test.cc`. This file seems to be testing the `RTCVideoEncoder` class in the Chromium Blink engine. The focus is on how the encoder handles errors, frame size changes, and different codec capabilities, especially around temporal layers and hardware acceleration.

Here's a breakdown of the thought process to analyze the code and generate the answer:

1. **Identify the Core Class Under Test:** The `TEST_F` macros indicate that the code is part of a unit test suite. The class being tested is likely `RTCVideoEncoder`, and the different `TEST_F` names hint at specific aspects being tested (e.g., `RTCVideoEncoderFrameSizeChangeTest`, `RTCVideoEncoderEncodeTest`, `RTCVideoEncoderInitTest`).

2. **Analyze Individual Test Cases:** Go through each `TEST_F` block and understand its purpose.

    * **`FrameSizeChangeFailure` (first instance):** This test checks what happens when flushing the encoder during a frame size change fails. It sets up an expectation for `mock_vea_->Flush` to fail and verifies that the encoder falls back to software.

    * **`FrameSizeChangeFailure` (second instance):** This test explores a different scenario where a frame size change is requested, but the underlying `VideoEncodeAccelerator` (VEA) reports an error. Again, it expects a software fallback.

    * **`AV1SoftwareFallbackForVEANotSupport`:** This tests the scenario where the hardware VEA doesn't support the requested AV1 Scalable Video Coding (SVC) mode. It verifies that the encoder correctly falls back to software.

    * **`AV1TemporalLayerGenericFrameInfo`:** This test focuses on verifying the presence of `generic_frame_info` in the `CodecSpecificInfo` for AV1 encoding with temporal layers. It checks if the information is present for some frames and absent for others, as simulated by the `ReturnSVCLayerFrameWithInvalidGenericMetadata` method.

    * **`CheckInputVisibleSizeWithinSupportedDimensions`:** This test verifies that the encoder initializes successfully when the requested video dimensions are within the hardware VEA's supported range. It specifically uses a feature flag `"WebRtcUseMinMaxVEADimensions"`.

    * **`CheckInputVisibleSizeBeyondSupportedDimensions`:**  This tests the opposite – what happens when the requested video dimensions exceed the VEA's capabilities. It expects a software fallback.

    * **`CheckInputVisibleSizeWithinSupportedDimensionsButIsSoftware`:** This test examines the case where the VEA *could* handle the dimensions, but the identified codec is marked as a software codec. It expects a software fallback.

    * **`SupportedTemporalLayerIsRejectedSoftwareCodecWillFallback`:**  This scenario tests a software codec that supports the requested temporal layers. It expects a software fallback because it's a software codec.

    * **`SupportedTemporalLayersAreHardwareInitOK`:** This tests successful initialization with hardware acceleration when the VEA supports the requested temporal layers.

    * **`H265TemporalLayerNotSupported`:**  This test, specific to H.265, checks if the encoder falls back to software when the VEA doesn't support the requested H.265 temporal layer configuration (L1T2). It uses feature flags to enable H.265 support.

    * **`H265TemporalLayerGenericFrameInfo`:**  Similar to the AV1 test, this verifies the presence and absence of `generic_frame_info` for H.265 with temporal layers. It also uses feature flags.

3. **Identify Key Concepts and Interactions:** Note the use of mocks (`mock_vea_`, `mock_gpu_factories_`, `mock_encoder_metrics_provider_factory_`), waitable events (`base::WaitableEvent`), and the interaction with the `VideoEncodeAccelerator` interface. The tests heavily rely on setting expectations for mock object calls.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Consider how these tests relate to the broader WebRTC context. The `RTCVideoEncoder` is used by the browser to encode video streams for real-time communication.

    * **JavaScript:**  JavaScript using the WebRTC API (`RTCPeerConnection`) would trigger the use of this encoder. The test scenarios directly impact how robust the video encoding is when dealing with various hardware and codec capabilities.

    * **HTML:** HTML provides the `<video>` element where the encoded video stream might be displayed. The encoder's ability to handle errors and adapt to different conditions ensures a smoother user experience.

    * **CSS:** CSS styles the video element but doesn't directly interact with the video encoding process.

5. **Infer Logical Reasoning and Assumptions:**  The tests make assumptions about the behavior of the underlying VEA and the expected outcomes of encoder initialization and encoding under different conditions. The input to the tests are codec configurations and video frames, and the outputs are status codes and verification of encoded data.

6. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when using the WebRTC API or when hardware encoders have limitations.

    * **Requesting unsupported codecs or configurations:**  The tests demonstrate how the encoder handles these scenarios, falling back to software. A user might incorrectly assume hardware acceleration for all codecs.
    * **Not handling encoder initialization errors:**  The tests highlight the importance of checking the return codes of `InitEncode`.

7. **Synthesize the Functionality Description:** Combine the understanding of individual tests and key concepts to create a comprehensive summary of the file's purpose.

8. **Address the "Part 3" Request:** Since this is the final part, summarize the overall functionality across all three parts. Based on the content of this snippet, the focus is on error handling, dynamic frame size changes, and codec/hardware capability negotiation.

**(Self-Correction/Refinement):**  Initially, I might focus too much on the low-level details of mocking. However, the user's request emphasizes understanding the *functionality* and its relation to web technologies. So, I need to abstract away some of the implementation details and focus on the higher-level purpose of the tests. Also, explicitly stating the assumptions and reasoning behind the tests makes the explanation clearer.
这是对 `blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc` 文件的最后一部分代码的分析。结合前两部分，我们可以总结出这个文件的主要功能是：**测试 Blink 引擎中 `RTCVideoEncoder` 类的各种功能，特别是关于视频编码器的初始化、编码过程中的错误处理、动态帧尺寸调整以及对不同视频编解码器和硬件加速的支持情况。**

**归纳其功能如下：**

* **测试编码器在遇到错误时的回退机制：**  这部分代码继续测试了编码器在底层 `VideoEncodeAccelerator` (VEA) 发生错误时的行为，例如 `Flush` 操作失败或请求更改编码参数失败。它验证了在这些情况下，编码器是否能够正确地回退到软件编码。
* **测试对 AV1 编解码器的支持和回退机制：**  测试了当硬件 VEA 不支持 AV1 的特定功能（例如 SVC - 可伸缩视频编码）时，`RTCVideoEncoder` 是否能正确回退到软件编码。
* **测试 AV1 和 H.265 编解码器中时间层 (Temporal Layer) 的元数据处理：**  `AV1TemporalLayerGenericFrameInfo` 和 `H265TemporalLayerGenericFrameInfo` 测试验证了编码后的比特流中，对于支持时间层的 AV1 和 H.265 视频，是否正确生成和包含了 `generic_frame_info` 元数据。这涉及到检查 `CodecSpecificInfo` 结构中的 `template_structure` 和 `generic_frame_info` 字段。
* **测试编码器初始化时对输入视频尺寸的校验：**  `CheckInputVisibleSizeWithinSupportedDimensions` 和 `CheckInputVisibleSizeBeyondSupportedDimensions` 测试了在初始化编码器时，`RTCVideoEncoder` 如何根据硬件 VEA 支持的最大分辨率来判断是否可以使用硬件加速。如果请求的视频尺寸超过了硬件能力，则应回退到软件编码。
* **测试编码器初始化时对软件编解码器的处理：**  `CheckInputVisibleSizeWithinSupportedDimensionsButIsSoftware` 和 `SupportedTemporalLayerIsRejectedSoftwareCodecWillFallback` 测试了即使硬件 VEA 可以支持某些尺寸，但如果选择的编解码器本身是软件实现的，编码器依然会回退到软件。
* **测试对支持时间层的硬件编解码器的初始化：** `SupportedTemporalLayersAreHardwareInitOK` 测试了当硬件 VEA 支持所请求的编解码器和时间层配置时，编码器是否能够成功初始化并使用硬件加速。
* **测试对 H.265 编解码器的特定功能支持：**  `H265TemporalLayerNotSupported` 和 `H265TemporalLayerGenericFrameInfo` 专门针对 H.265 编解码器进行了测试，包括对特定时间层配置（例如 L1T2）的支持情况以及元数据的处理。这部分代码使用了 feature flags 来控制 H.265 功能的启用。

**与 JavaScript, HTML, CSS 的功能关系：**

虽然这个 C++ 文件本身不直接涉及 JavaScript, HTML 或 CSS，但它测试的 `RTCVideoEncoder` 类是 WebRTC 技术栈中的核心组件，直接影响着 Web 浏览器中音视频通信的功能。

* **JavaScript:**
    * JavaScript 代码通过 WebRTC API（例如 `RTCPeerConnection`）来创建和管理音视频轨道。当需要发送视频流时，`RTCPeerConnection` 会使用 `RTCVideoEncoder` 来对视频帧进行编码。
    * 例如，JavaScript 代码可能会设置视频编码的参数，如分辨率、帧率和目标码率。`RTCVideoEncoder` 的初始化过程会读取这些参数并尝试使用合适的硬件或软件编码器。
    * 如果 `RTCVideoEncoder` 由于硬件不支持或发生错误而回退到软件编码，这可能会影响 JavaScript 代码中期望的性能和资源消耗。

* **HTML:**
    * HTML 的 `<video>` 元素用于显示接收到的视频流。编码器的功能直接影响着最终在 `<video>` 元素中呈现的视频质量和流畅度。
    * 例如，如果编码器在帧尺寸变化时处理不当，可能会导致 `<video>` 元素中显示的视频出现卡顿或失真。

* **CSS:**
    * CSS 主要负责控制 HTML 元素的样式和布局，与视频编码过程本身没有直接关系。

**逻辑推理的假设输入与输出：**

以 `FrameSizeChangeFailure` 测试的第二种情况为例：

* **假设输入:**
    * 初始编码器配置为某种分辨率（例如 640x480）。
    * 尝试将编码器的分辨率更改为更高分辨率（例如 1280x720）。
    * 底层的 VEA 在处理分辨率更改请求时返回错误状态 (`media::EncoderStatus::Codes::kSystemAPICallError`).
* **预期输出:**
    * `InitEncode` 函数返回 `WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE`，表明编码器回退到软件实现。
    * 相关的错误回调函数被触发（通过 `error_waiter.Wait()` 验证）。
    * 相关的 metrics provider 被创建。

**涉及用户或编程常见的使用错误：**

* **假设用户期望硬件加速，但实际硬件不支持特定编解码器或配置：**  例如，用户可能希望使用 H.265 编码，但用户的显卡不支持 H.265 硬件加速。在这种情况下，`RTCVideoEncoder` 会尝试使用软件编码，但如果用户没有考虑到软件编码的性能影响，可能会导致视频通话卡顿。
* **编程时没有正确处理编码器初始化失败的情况：**  开发者可能会忽略 `InitEncode` 函数的返回值，没有考虑到硬件不支持或配置错误导致初始化失败的情况。这会导致后续的编码操作出现未定义的行为。
* **在动态改变视频尺寸时，没有考虑到编码器可能需要重新初始化或发生错误：**  例如，在网络条件变化时动态调整视频分辨率是一种常见的优化策略。开发者需要处理 `RTCVideoEncoder` 在处理帧尺寸变化时可能返回的错误，并根据情况进行重试或降级处理。

总而言之，这个测试文件通过各种测试用例，确保了 `RTCVideoEncoder` 能够可靠地处理各种编码场景，包括错误情况、动态变化和不同的硬件及编解码器支持，从而保证 WebRTC 音视频通信的质量和稳定性。

Prompt: 
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
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

"""


```