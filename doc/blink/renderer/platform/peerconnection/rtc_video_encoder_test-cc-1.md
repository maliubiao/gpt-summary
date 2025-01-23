Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `rtc_video_encoder_test.cc`. This code snippet contains several test cases for the `RTCVideoEncoder` class, focusing on its encoding capabilities, especially with spatial and temporal layering (SVC), frame dropping, and handling frame size changes.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Class:** The tests are within a class named `RTCVideoEncoderEncodeTest` and `RTCVideoEncoderFrameSizeChangeTest`, clearly indicating that the target of these tests is the `RTCVideoEncoder` class.

2. **Scan Test Case Names:**  Quickly read through the names of the `TEST_F` macros. These names provide a high-level overview of the functionality being tested. Look for keywords like "EncodeSpatialLayer", "DropFrame", "CreateAndInitVP9ThreeLayerSvc", "RaiseError", "SpatialLayerTurnedOffAndOnAgain", "FrameSizeChangeSupported", "Simulcast", "MetricsProvider", "EncodeFrameWithAdapter", "EncodedBufferLifetime", "EncodeAndDropWhenTooManyFrames", "EncodeH265WithBitstreamFix".

3. **Group Related Tests:** Notice that several tests are related to spatial layering (SVC), frame size changes, and error handling. Grouping them helps in summarizing effectively.

4. **Analyze Code within Tests:**  For each group of tests, briefly examine the code within the `TEST_F` block. Look for key actions like:
    * Creating and initializing the `RTCVideoEncoder`.
    * Setting up mock objects (like `mock_vea_`).
    * Calling `rtc_encoder_->Encode()`.
    * Making assertions using `EXPECT_EQ`, `EXPECT_CALL`, `EXPECT_THAT`, `ASSERT_EQ`.
    * Using `WaitableEvent` for synchronization.
    * Registering callbacks (`RegisterEncodeCompleteCallback`).

5. **Identify Key Functionality Demonstrated:** Based on the test names and code analysis, identify the core features being tested:
    * **Basic Encoding:**  Encoding video frames.
    * **Spatial Layering (SVC):** Encoding with multiple spatial layers (different resolutions).
    * **Temporal Layering:** Implicitly tested with SVC configurations.
    * **Frame Dropping:** Testing the encoder's ability to drop frames under certain conditions.
    * **Error Handling:** Testing how the encoder handles errors like missing end-of-picture markers and resolution mismatches.
    * **Dynamic Spatial Layer Management:** Turning spatial layers on and off dynamically.
    * **Frame Size Changes:** Handling changes in input frame size.
    * **Simulcast:** Encoding multiple streams at different qualities (implemented via SVC in this case).
    * **Metrics Reporting:**  Testing the integration with a metrics provider.
    * **Frame Adapters:** Using frame adapters for pre-processing (like downscaling).
    * **Encoded Buffer Lifetime:** Ensuring encoded buffers persist beyond the encoder's lifetime.
    * **Handling Backpressure:** Dropping frames when the encoder is overloaded.
    * **H.265 Bitstream Fixes:** Injecting or modifying H.265 bitstreams.

6. **Identify Relationships to Web Technologies:** Consider how these encoding features relate to JavaScript, HTML, and CSS in a web context:
    * **JavaScript:**  JavaScript code using the WebRTC API (`RTCPeerConnection`, `RTCRtpSender`, `RTCRtpReceiver`) would be the primary user of the `RTCVideoEncoder`. It would provide the video frames and receive the encoded data.
    * **HTML:** The `<video>` element would display the decoded video.
    * **CSS:** CSS would be used for styling the `<video>` element.

7. **Identify Assumptions and Logic:**  Look for scenarios where assumptions are made or logical deductions are performed in the tests. For example, the tests assume the existence of a `MockVideoEncodeAccelerator` and check interactions with it. The logic involves setting up specific encoder configurations and verifying the encoder's behavior.

8. **Identify Common Usage Errors:**  Think about common mistakes developers might make when using a video encoder, and see if the tests cover these:
    * Providing incorrect encoder settings.
    * Not handling encoded data correctly.
    * Not understanding the implications of spatial and temporal layering.
    * Ignoring error conditions.

9. **Synthesize the Summary:** Combine the identified functionalities, relationships to web technologies, assumptions, logic, and potential usage errors into a concise summary. Since this is part 2 of 3, focus on summarizing the features covered in *this specific snippet*.

10. **Refine the Summary:** Ensure the summary is clear, accurate, and addresses all aspects of the prompt. Use precise language and avoid jargon where possible, or explain it clearly. For part 2, acknowledge that the previous part has been covered.
这是对`blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc`文件的第二部分代码的分析和功能归纳。

**功能归纳（基于第二部分代码）：**

这部分代码主要集中在测试 `RTCVideoEncoder` 在以下方面的功能，特别是针对具有空间分层（Spatial Layering - SVC）的视频编码：

1. **空间分层编码及丢帧测试:**
   - 测试了当启用空间分层编码（例如 VP9）时，`RTCVideoEncoder` 是否能够正确编码具有不同空间层（不同分辨率）的帧。
   - 特别测试了在空间分层编码中，`RTCVideoEncoder` 是否能够根据需要丢弃某些帧（例如中间的依赖层帧），并通过 `OnDroppedFrame` 回调通知。

2. **空间分层编码的初始化和配置:**
   - 测试了使用 VP9 编码器并配置不同数量的空间层时，`RTCVideoEncoder` 的初始化行为。
   - 验证了 `RTCVideoEncoder` 是否能正确解析和应用 `webrtc::VideoCodec` 中关于空间层的配置，例如宽度、高度和激活状态。
   - 测试了当仅激活部分空间层时的初始化行为。

3. **处理空间分层编码中的错误:**
   - 测试了当编码器返回的元数据中缺少 `end_of_picture` 标志时，`RTCVideoEncoder` 是否能够正确检测并报告错误。
   - 测试了当编码器返回的元数据中空间层的分辨率与预期不符时，`RTCVideoEncoder` 是否能够正确检测并报告错误。

4. **动态调整空间层激活状态:**
   - 测试了在编码过程中，通过调整码率分配，动态地关闭和重新激活某些空间层，`RTCVideoEncoder` 是否能够正确处理这种情况。
   - 验证了编码器返回的 `CodecSpecificInfoVP9` 中 `first_active_layer` 和 `num_spatial_layers` 字段是否能正确反映当前激活的空间层。

5. **支持帧尺寸变化:**
   - 测试了当底层 `VideoEncodeAccelerator` (VEA) 支持帧尺寸变化时，`RTCVideoEncoder` 是否能够正确处理帧尺寸的改变。
   - 包括在帧尺寸变化前后进行编码，并验证新的初始化配置是否正确。
   - 测试了在支持空间分层的编码中，帧尺寸变化的处理。

6. **Simulcast (多流编码) 的初始化 (通过 SVC 实现):**
   - 测试了使用 VP9 编码器并配置 Simulcast (多流编码) 时，`RTCVideoEncoder` 的初始化行为。
   - 验证了 Simulcast 是通过配置不同的空间层来实现的。
   - 测试了当 Simulcast 的配置不一致时，`RTCVideoEncoder` 是否能返回正确的错误码。

7. **集成 Metrics Provider (指标提供器):**
   - 测试了 `RTCVideoEncoder` 在发生错误时，是否会调用 `MetricsProvider` 的 `SetError` 方法来记录错误信息。
   - 测试了 `RTCVideoEncoder` 在成功编码帧后，是否会调用 `MetricsProvider` 的 `IncrementEncodedFrameCount` 方法来更新编码帧计数。

8. **使用 VideoFrameAdapter:**
   - 测试了 `RTCVideoEncoder` 能够处理使用 `WebRtcVideoFrameAdapter` 包裹的 `media::VideoFrame`。
   - 验证了即使输入帧的尺寸大于编码器配置的尺寸，`RTCVideoEncoder` 也能通过 Adapter 进行处理（可能进行下采样）。

9. **编码缓冲区的生命周期:**
   - 测试了编码后的缓冲区（`EncodedImageBufferInterface`）的生命周期是否长于 `RTCVideoEncoder` 的生命周期，确保后续使用编码数据时不会出现问题。

10. **处理编码器内部的帧积压:**
    - 测试了当发送给编码器的帧数量过多，超过其处理能力时，`RTCVideoEncoder` 是否能够主动丢弃帧，并通过 `OnDroppedFrame` 回调通知，防止内存溢出或性能问题。

11. **H.265 码流修复:**
    - (如果启用了 `RTC_USE_H265`) 测试了 `RTCVideoEncoder` 可以集成 `H265ParameterSetsTracker` 来修改或插入 H.265 码流，例如添加 SPS/PPS 等参数集。

**与 JavaScript, HTML, CSS 的关系：**

这部分代码主要测试的是 WebRTC 引擎内部的视频编码功能，与 JavaScript, HTML, CSS 的直接交互较少。但是，`RTCVideoEncoder` 是 WebRTC 中非常核心的组件，它的功能直接影响到 Web 页面中视频通话和视频流的质量和性能。

* **JavaScript:**
    * JavaScript 代码通过 WebRTC API (例如 `RTCPeerConnection`, `RTCRtpSender`) 来控制视频编码器的行为。
    * 例如，JavaScript 代码会设置视频编码器的参数 (例如码率、分辨率、帧率) 和配置 (例如是否启用 SVC)。
    * 假设输入：JavaScript 代码调用 `RTCRtpSender.replaceTrack()` 并提供了一个新的视频轨道，或者调用 `RTCRtpSender.getParameters()` 和 `RTCRtpSender.setParameters()` 来修改编码参数，这些操作最终会影响 `RTCVideoEncoder` 的配置和行为。
    * 假设输出：`RTCVideoEncoder` 编码后的数据会通过 WebRTC 的管道传递给对端，JavaScript 代码在对端通过 `RTCRtpReceiver` 接收并解码这些数据。

* **HTML:**
    * HTML 的 `<video>` 元素用于展示视频流。`RTCVideoEncoder` 的编码质量直接影响到 `<video>` 元素中显示的视频效果。
    * 例如，如果启用了空间分层编码，即使网络条件不好，也能在 `<video>` 元素中看到较低分辨率的视频，保证基本的观看体验。

* **CSS:**
    * CSS 主要用于控制 HTML 元素的样式，与 `RTCVideoEncoder` 的功能没有直接关系。但是，CSS 可以用于调整 `<video>` 元素的尺寸和布局。

**逻辑推理、假设输入与输出：**

在上述功能点中，都包含了逻辑推理和假设的输入输出。例如：

* **假设输入（空间分层丢帧测试）:**  连续编码 5 帧，并指定索引为 1 和 3 的帧应该被丢弃。
* **预期输出（空间分层丢帧测试）:**  `DropFrameVerifier` 应该收到 2 次 `OnDroppedFrame` 回调，并且最终验证只有索引为 0, 2, 4 的帧被成功编码。

* **假设输入（空间层动态开关）:**  初始配置为 3 个空间层都激活，然后通过码率控制禁用顶层空间层，再重新启用。
* **预期输出（空间层动态开关）:**  通过检查编码后的 `CodecSpecificInfoVP9`，可以验证 `first_active_layer` 和 `num_spatial_layers` 的值是否随着空间层的开关而正确变化。

**用户或编程常见的使用错误：**

1. **不理解空间分层编码的配置:**  用户可能错误地配置空间层的参数，例如分辨率、帧率等，导致编码器初始化失败或编码效果不佳。例如，为依赖的低层设置比高层更高的分辨率是错误的。

2. **错误地处理编码回调:**  用户可能没有正确实现或处理 `EncodedImageCallback` 中的回调函数，导致无法获取编码后的数据或无法处理丢帧事件。

3. **在不支持帧尺寸变化的编码器上尝试改变帧尺寸:**  如果底层的 `VideoEncodeAccelerator` 不支持帧尺寸变化，直接修改编码参数可能会导致编码失败或程序崩溃。`RTCVideoEncoder` 会尝试处理这种情况，但如果 VEA 不支持，会回退到软件编码。

4. **在高负载情况下不处理丢帧事件:**  在高网络延迟或低带宽情况下，编码器可能会丢弃帧。如果用户程序没有处理 `OnDroppedFrame` 事件，可能会导致视频播放出现卡顿或画面丢失，用户体验下降。

**总结本部分功能：**

这部分 `rtc_video_encoder_test.cc` 代码主要负责测试 `RTCVideoEncoder` 在处理具有空间分层特性的视频编码时的各种场景，包括初始化、编码、错误处理、动态调整以及与底层硬件编码加速器的交互。此外，还涵盖了帧尺寸变化、Simulcast 的配置、与 Metrics Provider 的集成、以及处理编码器内部帧积压等高级功能。这些测试确保了 `RTCVideoEncoder` 能够可靠地实现复杂的视频编码策略，为 WebRTC 应用提供高质量的视频传输能力。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(i)
                                       .set_timestamp_us(i)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build(),
                                   &frame_types));
    event.Wait();
  }
  sl_verifier.Wait();
  RunUntilIdle();
}

TEST_F(RTCVideoEncoderEncodeTest, EncodeSpatialLayerWithDropFrame) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP9;
  CreateEncoder(codec_type);
  constexpr size_t kNumSpatialLayers = 3;
  webrtc::VideoCodec sl_codec =
      GetSVCLayerCodec(webrtc::kVideoCodecVP9, kNumSpatialLayers);
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&sl_codec, kVideoEncoderSettings));

  constexpr static size_t kNumEncodeFrames = 5u;
  constexpr static size_t kDropIndices[] = {1, 3};
  class DropFrameVerifier : public webrtc::EncodedImageCallback {
   public:
    DropFrameVerifier() = default;
    ~DropFrameVerifier() override = default;

    void OnDroppedFrame(DropReason reason) override {
      AddResult(EncodeResult::kDropped);
    }

    webrtc::EncodedImageCallback::Result OnEncodedImage(
        const webrtc::EncodedImage& encoded_image,
        const webrtc::CodecSpecificInfo* codec_specific_info) override {
      if (codec_specific_info->end_of_picture) {
        AddResult(EncodeResult::kEncoded);
      }
      return Result(Result::OK);
    }

    void Verify() {
      base::AutoLock auto_lock(lock_);
      ASSERT_EQ(encode_results_.size(), kNumEncodeFrames);
      for (size_t i = 0; i < kNumEncodeFrames; ++i) {
        EncodeResult expected = EncodeResult::kEncoded;
        if (base::Contains(kDropIndices, i)) {
          expected = EncodeResult::kDropped;
        }
        EXPECT_EQ(encode_results_[i], expected);
      }
    }

   private:
    enum class EncodeResult {
      kEncoded,
      kDropped,
    };

    void AddResult(EncodeResult result) {
      base::AutoLock auto_lock(lock_);
      encode_results_.push_back(result);
    }

    base::Lock lock_;
    std::vector<EncodeResult> encode_results_ GUARDED_BY(lock_);
  };
  DropFrameVerifier dropframe_verifier;
  rtc_encoder_->RegisterEncodeCompleteCallback(&dropframe_verifier);
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
      EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer(_))
          .Times(kNumSpatialLayers);
    }
    if (base::Contains(kDropIndices, i)) {
      EXPECT_CALL(*mock_vea_, Encode)
          .WillOnce(DoAll(
              Invoke(this,
                     &RTCVideoEncoderTest::ReturnSvcFramesThatShouldBeDropped),
              [&event]() { event.Signal(); }));
    } else {
      EXPECT_CALL(*mock_vea_, Encode)
          .WillOnce(DoAll(
              Invoke(this,
                     &RTCVideoEncoderTest::ReturnSVCLayerFrameWithVp9Metadata),
              [&event]() { event.Signal(); }));
    }
    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(i)
                                       .set_timestamp_us(i)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build(),
                                   &frame_types));
    event.Wait();
  }
  RunUntilIdle();
  dropframe_verifier.Verify();
  rtc_encoder_.reset();
}

TEST_F(RTCVideoEncoderEncodeTest, CreateAndInitVP9ThreeLayerSvc) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/3);
  CreateEncoder(tl_codec.codecType);

    ExpectCreateInitAndDestroyVEA();
    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
    EXPECT_THAT(
        *config_,
        Field(&media::VideoEncodeAccelerator::Config::spatial_layers,
              ElementsAre(
                  AllOf(Field(&SpatialLayer::width, kInputFrameWidth / 4),
                        Field(&SpatialLayer::height, kInputFrameHeight / 4)),
                  AllOf(Field(&SpatialLayer::width, kInputFrameWidth / 2),
                        Field(&SpatialLayer::height, kInputFrameHeight / 2)),
                  AllOf(Field(&SpatialLayer::width, kInputFrameWidth),
                        Field(&SpatialLayer::height, kInputFrameHeight)))));
}

TEST_F(RTCVideoEncoderEncodeTest, CreateAndInitVP9SvcSinglecast) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/3);
  tl_codec.spatialLayers[1].active = false;
  tl_codec.spatialLayers[2].active = false;
  CreateEncoder(tl_codec.codecType);

  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
  EXPECT_THAT(*config_,
              Field(&media::VideoEncodeAccelerator::Config::spatial_layers,
                    ElementsAre(AllOf(
                        Field(&SpatialLayer::width, kInputFrameWidth / 4),
                        Field(&SpatialLayer::height, kInputFrameHeight / 4)))));
}

TEST_F(RTCVideoEncoderEncodeTest,
       CreateAndInitVP9SvcSinglecastWithoutTemporalLayers) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/3);
  tl_codec.spatialLayers[1].active = false;
  tl_codec.spatialLayers[2].active = false;
  tl_codec.spatialLayers[0].numberOfTemporalLayers = 1;
  tl_codec.VP9()->numberOfTemporalLayers = 1;
  CreateEncoder(tl_codec.codecType);

    ExpectCreateInitAndDestroyVEA();
    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
    EXPECT_THAT(config_->spatial_layers, IsEmpty());
}

TEST_F(RTCVideoEncoderEncodeTest,
       CreateAndInitVP9ThreeLayerSvcWithTopLayerInactive) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/3);
  tl_codec.spatialLayers[2].active = false;
  CreateEncoder(tl_codec.codecType);

    ExpectCreateInitAndDestroyVEA();
    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
    EXPECT_THAT(
        *config_,
        Field(&media::VideoEncodeAccelerator::Config::spatial_layers,
              ElementsAre(
                  AllOf(Field(&SpatialLayer::width, kInputFrameWidth / 4),
                        Field(&SpatialLayer::height, kInputFrameHeight / 4)),
                  AllOf(Field(&SpatialLayer::width, kInputFrameWidth / 2),
                        Field(&SpatialLayer::height, kInputFrameHeight / 2)))));
    EXPECT_THAT(
        *config_,
        Field(&media::VideoEncodeAccelerator::Config::input_visible_size,
              AllOf(Property(&gfx::Size::width, kInputFrameWidth / 2),
                    Property(&gfx::Size::height, kInputFrameHeight / 2))));
}

TEST_F(RTCVideoEncoderEncodeTest, RaiseErrorOnMissingEndOfPicture) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/2);
  tl_codec.VP9()->numberOfTemporalLayers = 1;
  tl_codec.spatialLayers[0].numberOfTemporalLayers = 1;
  tl_codec.spatialLayers[1].numberOfTemporalLayers = 1;
  CreateEncoder(tl_codec.codecType);
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));

  EXPECT_CALL(*mock_vea_, Encode).WillOnce([&] {
    media::BitstreamBufferMetadata metadata(
        100u /* payload_size_bytes */,
        /*keyframe=*/true,
        /*timestamp=*/base::Milliseconds(0));
    metadata.key_frame = true;
    metadata.vp9.emplace();
    metadata.vp9->end_of_picture = false;
    metadata.vp9->spatial_idx = 0;
    metadata.vp9->spatial_layer_resolutions = ToResolutionList(tl_codec);
    ASSERT_EQ(metadata.vp9->spatial_layer_resolutions.size(), 2u);
    client_->BitstreamBufferReady(/*buffer_id=*/0, metadata);

    metadata.key_frame = false;

    metadata.vp9.emplace();
    // Incorrectly mark last spatial layer with eop = false.
    metadata.vp9->end_of_picture = false;
    metadata.vp9->spatial_idx = 1;
    metadata.vp9->reference_lower_spatial_layers = true;
    client_->BitstreamBufferReady(/*buffer_id=*/1, metadata);
  });
  const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
  FillFrameBuffer(buffer);
  std::vector<webrtc::VideoFrameType> frame_types{
      webrtc::VideoFrameType::kVideoFrameKey};

  // BitstreamBufferReady() is called after the first Encode() returns.
  // The error is reported on the second call.
  base::WaitableEvent error_waiter(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  rtc_encoder_->SetErrorWaiter(&error_waiter);

  EXPECT_EQ(rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types),
            WEBRTC_VIDEO_CODEC_OK);
  error_waiter.Wait();
  EXPECT_EQ(rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types),
            WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE);
}

TEST_F(RTCVideoEncoderEncodeTest, RaiseErrorOnMismatchingResolutions) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/2);
  tl_codec.VP9()->numberOfTemporalLayers = 1;
  tl_codec.spatialLayers[0].numberOfTemporalLayers = 1;
  tl_codec.spatialLayers[1].numberOfTemporalLayers = 1;
  CreateEncoder(tl_codec.codecType);
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));

  EXPECT_CALL(*mock_vea_, Encode).WillOnce([&] {
    media::BitstreamBufferMetadata metadata(
        100u /* payload_size_bytes */,
        /*keyframe=*/true,
        /*timestamp=*/base::Milliseconds(0));
    metadata.key_frame = true;
    metadata.vp9.emplace();
    metadata.vp9->end_of_picture = false;
    metadata.vp9->spatial_layer_resolutions = {gfx::Size(
        tl_codec.spatialLayers[0].width, tl_codec.spatialLayers[0].height)};
    client_->BitstreamBufferReady(/*buffer_id=*/0, metadata);
  });

  const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
  FillFrameBuffer(buffer);
  std::vector<webrtc::VideoFrameType> frame_types{
      webrtc::VideoFrameType::kVideoFrameKey};

  // BitstreamBufferReady() is called after the first Encode() returns.
  // The error is reported on the second call.
  base::WaitableEvent error_waiter(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  rtc_encoder_->SetErrorWaiter(&error_waiter);
  EXPECT_EQ(rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types),
            WEBRTC_VIDEO_CODEC_OK);
  error_waiter.Wait();
  EXPECT_EQ(rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types),
            WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE);
}

TEST_F(RTCVideoEncoderEncodeTest, SpatialLayerTurnedOffAndOnAgain) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/2);
  tl_codec.VP9()->numberOfTemporalLayers = 1;
  tl_codec.spatialLayers[0].numberOfTemporalLayers = 1;
  tl_codec.spatialLayers[1].numberOfTemporalLayers = 1;
  CreateEncoder(tl_codec.codecType);
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));

  // Start with two active spatial layers.
  EXPECT_CALL(*mock_vea_, Encode).WillOnce([&] {
    media::BitstreamBufferMetadata metadata(
        100u /* payload_size_bytes */,
        /*keyframe=*/true,
        /*timestamp=*/base::Milliseconds(0));
    metadata.key_frame = true;
    metadata.vp9.emplace();
    metadata.vp9->end_of_picture = false;
    metadata.vp9->spatial_idx = 0;
    metadata.vp9->spatial_layer_resolutions = ToResolutionList(tl_codec);
    ASSERT_EQ(metadata.vp9->spatial_layer_resolutions.size(), 2u);
    metadata.vp9->begin_active_spatial_layer_index = 0;
    metadata.vp9->end_active_spatial_layer_index = 2;
    client_->BitstreamBufferReady(/*buffer_id=*/0, metadata);

    metadata.key_frame = false;
    metadata.vp9.emplace();
    metadata.vp9->end_of_picture = true;
    metadata.vp9->spatial_idx = 1;
    metadata.vp9->reference_lower_spatial_layers = true;
    client_->BitstreamBufferReady(/*buffer_id=*/1, metadata);
  });
  const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
  FillFrameBuffer(buffer);
  std::vector<webrtc::VideoFrameType> frame_types{
      webrtc::VideoFrameType::kVideoFrameKey};
  EXPECT_EQ(rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types),
            WEBRTC_VIDEO_CODEC_OK);
  RunUntilIdle();

  // Sind bitrate allocation disabling the top spatial layer.
  webrtc::VideoBitrateAllocation bitrate_allocation;
  bitrate_allocation.SetBitrate(0, 0, 100000);
  EXPECT_CALL(*mock_vea_, RequestEncodingParametersChange);
  rtc_encoder_->SetRates(webrtc::VideoEncoder::RateControlParameters(
      bitrate_allocation, tl_codec.maxFramerate));
  EXPECT_CALL(*mock_vea_, Encode).WillOnce([&] {
    media::BitstreamBufferMetadata metadata(
        100u /* payload_size_bytes */,
        /*keyframe=*/true,
        /*timestamp=*/base::Microseconds(1));
    metadata.vp9.emplace();
    metadata.vp9->spatial_idx = 0;
    metadata.vp9->inter_pic_predicted = true;
    metadata.vp9->spatial_layer_resolutions = {
        gfx::Size(tl_codec.spatialLayers[0].width,
                  tl_codec.spatialLayers[0].height),
    };
    metadata.vp9->begin_active_spatial_layer_index = 0;
    metadata.vp9->end_active_spatial_layer_index = 1;
    client_->BitstreamBufferReady(/*buffer_id=*/0, metadata);
  });
  frame_types[0] = webrtc::VideoFrameType::kVideoFrameDelta;
  EXPECT_EQ(rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(1)
                                     .set_timestamp_us(1)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types),
            WEBRTC_VIDEO_CODEC_OK);
  RunUntilIdle();

  // Re-enable the top layer.
  bitrate_allocation.SetBitrate(1, 0, 500000);
  EXPECT_CALL(*mock_vea_, RequestEncodingParametersChange);
  rtc_encoder_->SetRates(webrtc::VideoEncoder::RateControlParameters(
      bitrate_allocation, tl_codec.maxFramerate));
  EXPECT_CALL(*mock_vea_, Encode).WillOnce([&] {
    media::BitstreamBufferMetadata metadata(
        100u /* payload_size_bytes */,
        /*keyframe=*/true,
        /*timestamp=*/base::Microseconds(2));
    metadata.vp9.emplace();
    metadata.vp9->end_of_picture = false;
    metadata.vp9->spatial_idx = 0;
    metadata.vp9->inter_pic_predicted = true;
    metadata.vp9->spatial_layer_resolutions = {
        gfx::Size(tl_codec.spatialLayers[0].width,
                  tl_codec.spatialLayers[0].height),
        gfx::Size(tl_codec.spatialLayers[1].width,
                  tl_codec.spatialLayers[1].height),
    };
    metadata.vp9->begin_active_spatial_layer_index = 0;
    metadata.vp9->end_active_spatial_layer_index = 2;
    client_->BitstreamBufferReady(/*buffer_id=*/0, metadata);

    metadata.key_frame = false;
    metadata.vp9.emplace();
    metadata.vp9->end_of_picture = true;
    metadata.vp9->spatial_idx = 1;
    metadata.vp9->inter_pic_predicted = true;
    client_->BitstreamBufferReady(/*buffer_id=*/1, metadata);
  });
  EXPECT_EQ(rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(2)
                                     .set_timestamp_us(2)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types),
            WEBRTC_VIDEO_CODEC_OK);
  RunUntilIdle();
}

TEST_F(RTCVideoEncoderEncodeTest, LowerSpatialLayerTurnedOffAndOnAgain) {
  // This test generates 6 layer frames with following dependencies:
  // disable S0 and S2 layers
  //       |
  //       V
  // S2  O
  //     |
  // S1  O---O---O
  //     |       |
  // S0  O       O
  //           ^
  //           |
  // re-enable S0 layer

  class Vp9CodecSpecificInfoContainer : public webrtc::EncodedImageCallback {
   public:
    webrtc::EncodedImageCallback::Result OnEncodedImage(
        const webrtc::EncodedImage& encoded_image,
        const webrtc::CodecSpecificInfo* codec_specific_info) override {
      EXPECT_THAT(codec_specific_info, NotNull());
      if (codec_specific_info != nullptr) {
        EXPECT_EQ(codec_specific_info->codecType, webrtc::kVideoCodecVP9);
        infos_.push_back(codec_specific_info->codecSpecific.VP9);
      }
      if (encoded_image.TemporalIndex().has_value()) {
        EXPECT_EQ(encoded_image.TemporalIndex(),
                  codec_specific_info->codecSpecific.VP9.temporal_idx);
      }

      return Result(Result::OK);
    }

    const std::vector<webrtc::CodecSpecificInfoVP9>& infos() { return infos_; }

   private:
    std::vector<webrtc::CodecSpecificInfoVP9> infos_;
  };
  Vp9CodecSpecificInfoContainer encoded_callback;

  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/3);
  tl_codec.VP9()->numberOfTemporalLayers = 1;
  tl_codec.spatialLayers[0].numberOfTemporalLayers = 1;
  tl_codec.spatialLayers[1].numberOfTemporalLayers = 1;
  tl_codec.spatialLayers[2].numberOfTemporalLayers = 1;
  CreateEncoder(tl_codec.codecType);
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings),
            WEBRTC_VIDEO_CODEC_OK);

  rtc_encoder_->RegisterEncodeCompleteCallback(&encoded_callback);

  // Start with all three active spatial layers.
  EXPECT_CALL(*mock_vea_, Encode).WillOnce([&] {
    media::BitstreamBufferMetadata metadata(
        /*payload_size_bytes=*/100u,
        /*keyframe=*/true, /*timestamp=*/base::Milliseconds(0));
    metadata.key_frame = true;
    metadata.vp9.emplace();
    metadata.vp9->end_of_picture = false;
    metadata.vp9->spatial_idx = 0;
    metadata.vp9->spatial_layer_resolutions = ToResolutionList(tl_codec);
    ASSERT_THAT(metadata.vp9->spatial_layer_resolutions, SizeIs(3));
    metadata.vp9->begin_active_spatial_layer_index = 0;
    metadata.vp9->end_active_spatial_layer_index = 3;
    client_->BitstreamBufferReady(/*buffer_id=*/0, metadata);

    metadata.key_frame = false;
    metadata.vp9.emplace();
    metadata.vp9->end_of_picture = false;
    metadata.vp9->spatial_idx = 1;
    metadata.vp9->reference_lower_spatial_layers = true;
    client_->BitstreamBufferReady(/*buffer_id=*/1, metadata);

    metadata.key_frame = false;
    metadata.vp9.emplace();
    metadata.vp9->end_of_picture = true;
    metadata.vp9->spatial_idx = 2;
    metadata.vp9->reference_lower_spatial_layers = true;
    client_->BitstreamBufferReady(/*buffer_id=*/2, metadata);
  });
  const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
  FillFrameBuffer(buffer);
  std::vector<webrtc::VideoFrameType> frame_types{
      webrtc::VideoFrameType::kVideoFrameKey};
  EXPECT_EQ(rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types),
            WEBRTC_VIDEO_CODEC_OK);
  RunUntilIdle();
  ASSERT_THAT(encoded_callback.infos(), SizeIs(3));
  EXPECT_EQ(encoded_callback.infos()[0].first_active_layer, 0u);
  EXPECT_EQ(encoded_callback.infos()[0].num_spatial_layers, 3u);
  EXPECT_EQ(encoded_callback.infos()[1].first_active_layer, 0u);
  EXPECT_EQ(encoded_callback.infos()[1].num_spatial_layers, 3u);
  EXPECT_EQ(encoded_callback.infos()[2].first_active_layer, 0u);
  EXPECT_EQ(encoded_callback.infos()[2].num_spatial_layers, 3u);

  // Send bitrate allocation disabling the first and the last spatial layers.
  webrtc::VideoBitrateAllocation bitrate_allocation;
  bitrate_allocation.SetBitrate(/*spatial_index=*/1, 0, 500'000);
  EXPECT_CALL(*mock_vea_, RequestEncodingParametersChange);
  rtc_encoder_->SetRates(webrtc::VideoEncoder::RateControlParameters(
      bitrate_allocation, tl_codec.maxFramerate));
  EXPECT_CALL(*mock_vea_, Encode).WillOnce([&] {
    media::BitstreamBufferMetadata metadata(
        /*payload_size_bytes=*/100u,
        /*keyframe=*/true, /*timestamp=*/base::Microseconds(1));
    metadata.vp9.emplace();
    metadata.vp9->spatial_idx = 0;
    metadata.vp9->reference_lower_spatial_layers = false;
    metadata.vp9->inter_pic_predicted = true;
    metadata.vp9->spatial_layer_resolutions = {
        gfx::Size(tl_codec.spatialLayers[1].width,
                  tl_codec.spatialLayers[1].height),
    };
    metadata.vp9->begin_active_spatial_layer_index = 1;
    metadata.vp9->end_active_spatial_layer_index = 2;
    client_->BitstreamBufferReady(/*buffer_id=*/1, metadata);
  });
  frame_types[0] = webrtc::VideoFrameType::kVideoFrameDelta;
  EXPECT_EQ(rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(1)
                                     .set_timestamp_us(1)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types),
            WEBRTC_VIDEO_CODEC_OK);
  RunUntilIdle();
  ASSERT_THAT(encoded_callback.infos(), SizeIs(4));
  EXPECT_EQ(encoded_callback.infos()[3].first_active_layer, 1u);
  EXPECT_EQ(encoded_callback.infos()[3].num_spatial_layers, 2u);

  // Re-enable the bottom layer.
  bitrate_allocation.SetBitrate(0, 0, 100'000);
  EXPECT_CALL(*mock_vea_, RequestEncodingParametersChange);
  rtc_encoder_->SetRates(webrtc::VideoEncoder::RateControlParameters(
      bitrate_allocation, tl_codec.maxFramerate));
  EXPECT_CALL(*mock_vea_, Encode).WillOnce([&] {
    media::BitstreamBufferMetadata metadata(
        /*payload_size_bytes=*/100u,
        /*keyframe=*/true, /*timestamp=*/base::Microseconds(2));
    metadata.vp9.emplace();
    metadata.vp9->end_of_picture = false;
    metadata.vp9->spatial_idx = 0;
    metadata.vp9->inter_pic_predicted = false;
    metadata.vp9->spatial_layer_resolutions = {
        gfx::Size(tl_codec.spatialLayers[0].width,
                  tl_codec.spatialLayers[0].height),
        gfx::Size(tl_codec.spatialLayers[1].width,
                  tl_codec.spatialLayers[1].height),
    };
    metadata.vp9->begin_active_spatial_layer_index = 0;
    metadata.vp9->end_active_spatial_layer_index = 2;
    client_->BitstreamBufferReady(/*buffer_id=*/0, metadata);

    metadata.key_frame = false;
    metadata.vp9.emplace();
    metadata.vp9->end_of_picture = true;
    metadata.vp9->spatial_idx = 1;
    metadata.vp9->inter_pic_predicted = true;
    metadata.vp9->reference_lower_spatial_layers = true;
    client_->BitstreamBufferReady(/*buffer_id=*/1, metadata);
  });
  EXPECT_EQ(rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(2)
                                     .set_timestamp_us(2)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types),
            WEBRTC_VIDEO_CODEC_OK);
  RunUntilIdle();
  ASSERT_THAT(encoded_callback.infos(), SizeIs(6));
  EXPECT_EQ(encoded_callback.infos()[4].first_active_layer, 0u);
  EXPECT_EQ(encoded_callback.infos()[4].num_spatial_layers, 2u);
  EXPECT_EQ(encoded_callback.infos()[5].first_active_layer, 0u);
  EXPECT_EQ(encoded_callback.infos()[5].num_spatial_layers, 2u);
}

TEST_F(RTCVideoEncoderFrameSizeChangeTest,
       FrameSizeChangeSupportedVP9SpatialLayer) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/3);
  CreateEncoder(tl_codec.codecType);
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));

  // report frame size change support
  media::VideoEncoderInfo info;
  info.supports_frame_size_change = true;
  encoder_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &media::VideoEncodeAccelerator::Client::NotifyEncoderInfoChange,
          base::Unretained(client_), info));

  size_t kNumEncodeFrames = 3u;
  for (size_t i = 0; i < kNumEncodeFrames; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    if (i == 0) {
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    }
    base::WaitableEvent event;
    EXPECT_CALL(*mock_vea_, Encode(_, _))
        .WillOnce(DoAll(
            Invoke(this,
                   &RTCVideoEncoderTest::ReturnSVCLayerFrameWithVp9Metadata),
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
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK, rtc_encoder_->Release());

  // Change frame size.
  tl_codec.width *= 2;
  tl_codec.height *= 2;
  for (auto& sl : tl_codec.spatialLayers) {
    sl.width *= 2;
    sl.height *= 2;
  }
  EXPECT_CALL(*mock_vea_, Flush)
      .WillOnce(Invoke(this, &RTCVideoEncoderTest::FlushComplete));
  ExpectFrameSizeChange(gfx::Size(tl_codec.width, tl_codec.height));
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));

  ResetSVCLayerFrameTimes();
  for (size_t i = 0; i < kNumEncodeFrames; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(tl_codec.width, tl_codec.height);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    base::WaitableEvent event;
    if (i == 0) {
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    }
    EXPECT_CALL(*mock_vea_, Encode(_, _))
        .WillOnce(DoAll(
            Invoke(this,
                   &RTCVideoEncoderTest::ReturnSVCLayerFrameWithVp9Metadata),
            [&event]() { event.Signal(); }));

    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(0)
                                       .set_timestamp_us(i + 3)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build(),
                                   &frame_types));
    event.Wait();
  }
}

// Simulcast requires SVC support
TEST_F(RTCVideoEncoderEncodeTest, CreateAndInitVP9Simulcast) {
  webrtc::VideoCodec tl_codec = GetSimulcastCodec(webrtc::kVideoCodecVP9,
                                                  /*num_simulcast_streams=*/3);
  CreateEncoder(tl_codec.codecType);

  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
  // Simulcast is implemented via SVC, so expect spatial layers configuration.
  EXPECT_THAT(
      *config_,
      Field(&media::VideoEncodeAccelerator::Config::spatial_layers,
            ElementsAre(
                AllOf(Field(&SpatialLayer::width, kInputFrameWidth / 4),
                      Field(&SpatialLayer::height, kInputFrameHeight / 4)),
                AllOf(Field(&SpatialLayer::width, kInputFrameWidth / 2),
                      Field(&SpatialLayer::height, kInputFrameHeight / 2)),
                AllOf(Field(&SpatialLayer::width, kInputFrameWidth),
                      Field(&SpatialLayer::height, kInputFrameHeight)))));
}

// Simulcast requires SVC support
TEST_F(RTCVideoEncoderEncodeTest, CreateAndInitVP9SimulcastOneStream) {
  webrtc::VideoCodec tl_codec = GetSimulcastCodec(webrtc::kVideoCodecVP9,
                                                  /*num_simulcast_streams=*/3);
  tl_codec.simulcastStream[1].active = false;
  tl_codec.simulcastStream[2].active = false;
  CreateEncoder(tl_codec.codecType);

  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
  // Simulcast is implemented via SVC, so expect spatial layers configuration.
  EXPECT_THAT(*config_,
              Field(&media::VideoEncodeAccelerator::Config::spatial_layers,
                    ElementsAre(AllOf(
                        Field(&SpatialLayer::width, kInputFrameWidth / 4),
                        Field(&SpatialLayer::height, kInputFrameHeight / 4)))));
}

// Simulcast requires SVC support
TEST_F(RTCVideoEncoderEncodeTest,
       FallbacksOnInconsistentSimulcastConfiguration) {
  webrtc::VideoCodec tl_codec = GetSimulcastCodec(webrtc::kVideoCodecVP9,
                                                  /*num_simulcast_streams=*/3);
  tl_codec.simulcastStream[1].numberOfTemporalLayers = 1;
  tl_codec.simulcastStream[2].numberOfTemporalLayers = 3;
  CreateEncoder(tl_codec.codecType);

  // Inconsistent parameters should be reported as parameters error, not as a
  // software fallback request.
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_ERR_SIMULCAST_PARAMETERS_NOT_SUPPORTED,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
}

#endif  // defined(ARCH_CPU_X86_FAMILY) && BUILDFLAG(IS_CHROMEOS_ASH)

TEST_F(RTCVideoEncoderEncodeTest, MetricsProviderSetErrorIsCalledOnError) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP9;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  const auto pixel_format = media::PIXEL_FORMAT_I420;
  const auto storage_type =
      media::VideoEncodeAccelerator::Config::StorageType::kShmem;

  auto encoder_metrics_provider =
      std::make_unique<media::MockVideoEncoderMetricsProvider>();
  media::MockVideoEncoderMetricsProvider* mock_encoder_metrics_provider =
      encoder_metrics_provider.get();

  // The VEA will be owned by the RTCVideoEncoder once
  // factory.CreateVideoEncodeAccelerator() is called.
  mock_vea_ = new media::MockVideoEncodeAccelerator();
  EXPECT_CALL(*mock_gpu_factories_.get(), DoCreateVideoEncodeAccelerator())
      .WillRepeatedly(Return(mock_vea_.get()));
  EXPECT_CALL(*mock_encoder_metrics_provider_factory_,
              CreateVideoEncoderMetricsProvider())
      .WillOnce(Return(::testing::ByMove(std::move(encoder_metrics_provider))));
  EXPECT_CALL(*mock_encoder_metrics_provider,
              MockInitialize(media::VP9PROFILE_PROFILE0,
                             gfx::Size(kInputFrameWidth, kInputFrameHeight),
                             /*is_hardware_encoder=*/true,
                             media::SVCScalabilityMode::kL1T1));
  EXPECT_CALL(*mock_vea_,
              Initialize(CheckConfig(pixel_format, storage_type, false), _, _))
      .WillOnce(Invoke(this, &RTCVideoEncoderTest::Initialize));
  EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer).Times(AtLeast(3));

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
  EXPECT_CALL(*mock_vea_, Encode(_, _))
      .WillOnce(Invoke([this](scoped_refptr<media::VideoFrame>, bool) {
        encoder_thread_.task_runner()->PostTask(
            FROM_HERE,
            base::BindOnce(
                &media::VideoEncodeAccelerator::Client::NotifyErrorStatus,
                base::Unretained(client_),
                media::EncoderStatus::Codes::kEncoderFailedEncode));
      }));

  const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
  FillFrameBuffer(buffer);
  std::vector<webrtc::VideoFrameType> frame_types;
  base::WaitableEvent error_waiter(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  EXPECT_CALL(*mock_encoder_metrics_provider,
              MockSetError(CheckStatusCode(
                  media::EncoderStatus::Codes::kEncoderFailedEncode)));
  rtc_encoder_->SetErrorWaiter(&error_waiter);
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
  error_waiter.Wait();
}

TEST_F(RTCVideoEncoderEncodeTest, EncodeVp9FrameWithMetricsProvider) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP9;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  const auto pixel_format = media::PIXEL_FORMAT_I420;
  const auto storage_type =
      media::VideoEncodeAccelerator::Config::StorageType::kShmem;

  auto encoder_metrics_provider =
      std::make_unique<media::MockVideoEncoderMetricsProvider>();
  media::MockVideoEncoderMetricsProvider* mock_encoder_metrics_provider =
      encoder_metrics_provider.get();

  // The VEA will be owned by the RTCVideoEncoder once
  // factory.CreateVideoEncodeAccelerator() is called.
  mock_vea_ = new media::MockVideoEncodeAccelerator();
  EXPECT_CALL(*mock_gpu_factories_.get(), DoCreateVideoEncodeAccelerator())
      .WillRepeatedly(Return(mock_vea_.get()));
  EXPECT_CALL(*mock_encoder_metrics_provider_factory_,
              CreateVideoEncoderMetricsProvider())
      .WillOnce(Return(::testing::ByMove(std::move(encoder_metrics_provider))));
  EXPECT_CALL(*mock_encoder_metrics_provider,
              MockInitialize(media::VP9PROFILE_PROFILE0,
                             gfx::Size(kInputFrameWidth, kInputFrameHeight),
                             /*is_hardware_encoder=*/true,
                             media::SVCScalabilityMode::kL1T1));
  EXPECT_CALL(*mock_vea_,
              Initialize(CheckConfig(pixel_format, storage_type, false), _, _))
      .WillOnce(Invoke(this, &RTCVideoEncoderTest::Initialize));
  EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer).Times(AtLeast(3));

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  size_t kNumEncodeFrames = 5u;
  for (size_t i = 0; i < kNumEncodeFrames; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    if (i == 0) {
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    }
    if (i > 0) {
      EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer(_)).Times(1);
    }
    base::WaitableEvent event;
    EXPECT_CALL(*mock_vea_, Encode(_, _))
        .WillOnce(
            DoAll(Invoke(this, &RTCVideoEncoderTest::ReturnFrameWithTimeStamp),
                  [&event]() { event.Signal(); }));
    // This is executed in BitstreamBufferReady(). Therefore, it must be called
    // after ReturnFrameWithTimeStamp() completes.
    EXPECT_CALL(*mock_encoder_metrics_provider,
                MockIncrementEncodedFrameCount());
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

TEST_F(RTCVideoEncoderEncodeTest, EncodeFrameWithAdapter) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP8;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  EXPECT_CALL(*mock_vea_, Encode(_, _))
      .Times(2)
      .WillRepeatedly(Invoke(
          [](scoped_refptr<media::VideoFrame> frame, bool force_keyframe) {
            EXPECT_EQ(kInputFrameWidth, frame->visible_rect().width());
            EXPECT_EQ(kInputFrameHeight, frame->visible_rect().height());
          }));

  // Encode first frame: full size. This will pass through to the encoder.
  auto frame = media::VideoFrame::CreateBlackFrame(
      gfx::Size(kInputFrameWidth, kInputFrameHeight));
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> frame_adapter(
      new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(
          frame, base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(
                     nullptr)));
  std::vector<webrtc::VideoFrameType> frame_types;
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(frame_adapter)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));

  // Encode second frame: double size. This will trigger downscale prior to
  // encoder.
  frame = media::VideoFrame::CreateBlackFrame(
      gfx::Size(kInputFrameWidth * 2, kInputFrameHeight * 2));
  frame_adapter = new rtc::RefCountedObject<WebRtcVideoFrameAdapter>(
      frame,
      base::MakeRefCounted<WebRtcVideoFrameAdapter::SharedResources>(nullptr));
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(frame_adapter)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(123456)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
}

TEST_F(RTCVideoEncoderEncodeTest, EncodedBufferLifetimeExceedsEncoderLifetime) {
  webrtc::VideoCodec codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                              /*num_spatial_layers=*/1);
  CreateEncoder(codec.codecType);

  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  constexpr size_t kNumEncodeFrames = 3u;
  class EnodedBufferLifetimeVerifier : public webrtc::EncodedImageCallback {
   public:
    explicit EnodedBufferLifetimeVerifier() = default;
    ~EnodedBufferLifetimeVerifier() override {
      last_encoded_image_->data()[0] = 0;
    }

    webrtc::EncodedImageCallback::Result OnEncodedImage(
        const webrtc::EncodedImage& encoded_image,
        const webrtc::CodecSpecificInfo* codec_specific_info) override {
      last_encoded_image_ = encoded_image.GetEncodedData();
      if (encoded_image.RtpTimestamp() == kNumEncodeFrames - 1 &&
          codec_specific_info->end_of_picture) {
        waiter_.Signal();
      }
      return Result(Result::OK);
    }

    void Wait() { waiter_.Wait(); }

   private:
    base::WaitableEvent waiter_;
    rtc::scoped_refptr<webrtc::EncodedImageBufferInterface> last_encoded_image_;
  };

  EnodedBufferLifetimeVerifier lifetime_verifier;
  rtc_encoder_->RegisterEncodeCompleteCallback(&lifetime_verifier);
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
      EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer(_))
          .Times((i > 1) ? 1 : 0);
    }
    EXPECT_CALL(*mock_vea_, Encode)
        .WillOnce(DoAll(
            Invoke(this,
                   &RTCVideoEncoderTest::ReturnSVCLayerFrameWithVp9Metadata),
            [&event]() { event.Signal(); }));
    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(i)
                                       .set_timestamp_us(i)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build(),
                                   &frame_types));
    event.Wait();
  }
  lifetime_verifier.Wait();
  RunUntilIdle();
  rtc_encoder_.reset();
}

TEST_F(RTCVideoEncoderEncodeTest, EncodeAndDropWhenTooManyFramesInEncoder) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP8;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();

  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  class DropFrameVerifier : public webrtc::EncodedImageCallback {
   public:
    DropFrameVerifier() = default;
    ~DropFrameVerifier() override = default;

    void OnDroppedFrame(DropReason reason) override {
      EXPECT_EQ(reason, DropReason::kDroppedByEncoder);
      num_dropped_frames_++;
      CHECK(event_);
      event_->Signal();
    }

    webrtc::EncodedImageCallback::Result OnEncodedImage(
        const webrtc::EncodedImage& encoded_image,
        const webrtc::CodecSpecificInfo* codec_specific_info) override {
      if (codec_specific_info->end_of_picture) {
        num_encoded_frames_++;
        CHECK(event_);
        event_->Signal();
      }
      return Result(Result::OK);
    }

    void Verify(int num_dropped_frames, int num_encoded_frames) {
      EXPECT_EQ(num_dropped_frames_, num_dropped_frames);
      EXPECT_EQ(num_encoded_frames_, num_encoded_frames);
    }

    void SetEvent(base::WaitableEvent* event) { event_ = event; }

    void WaitEvent() { event_->Wait(); }

   private:
    raw_ptr<base::WaitableEvent> event_;
    int num_dropped_frames_{0};
    int num_encoded_frames_{0};
  };

  DropFrameVerifier dropframe_verifier;
  rtc_encoder_->RegisterEncodeCompleteCallback(&dropframe_verifier);

  constexpr static size_t kMaxFramesInEncoder = 15u;

  // Start by "loading the encoder" by building up frames sent to the VEA
  // without receiving any BitStreamBufferReady callbacks. Should lead to zero
  // dropped frames and zero encoded frames.
  base::WaitableEvent event;
  for (size_t i = 0; i < kMaxFramesInEncoder; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    if (i == 0) {
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    }
    EXPECT_CALL(*mock_vea_, Encode).WillOnce([&event]() { event.Signal(); });
    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(0)
                                       .set_timestamp_us(i)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build(),
                                   &frame_types));
    event.Wait();
    RunUntilIdle();
  }
  dropframe_verifier.Verify(0, 0);

  // At this stage the encoder holds `kMaxFramesInEncoder` frames and the next
  // frame sent to the encoder should not be encoded but dropped instead.
  // OnDroppedFrame(DropReason::kDroppedByMediaOptimizations) should be called
  // as a result and this.
  event.Reset();
  dropframe_verifier.SetEvent(&event);
  EXPECT_CALL(*mock_vea_, Encode).Times(0);
  const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
  FillFrameBuffer(buffer);
  std::vector<webrtc::VideoFrameType> frame_types;
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(kMaxFramesInEncoder)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
  dropframe_verifier.WaitEvent();
  RunUntilIdle();
  dropframe_verifier.Verify(1, 0);

  // Emulate that the first frame is now reported as encoded. This action should
  // decrement `frames_in_encoder_count_` to `kMaxFramesInEncoder` - 1 and also
  // result in the first OnEncodedImage callback.
  event.Reset();
  encoder_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &media::VideoEncodeAccelerator::Client::BitstreamBufferReady,
          base::Unretained(client_), 0,
          media::BitstreamBufferMetadata(100, true, base::Microseconds(0))));
  dropframe_verifier.WaitEvent();
  RunUntilIdle();
  dropframe_verifier.Verify(1, 1);

  // Perform one more successful encode operation leading to a second
  // OnEncodedImage callback.
  event.Reset();
  EXPECT_CALL(*mock_vea_, Encode).WillOnce(Invoke([this] {
    client_->BitstreamBufferReady(
        0, media::BitstreamBufferMetadata(100, false, base::Microseconds(1)));
  }));
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_rtp_timestamp(0)
                                     .set_timestamp_us(kMaxFramesInEncoder + 1)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
  dropframe_verifier.WaitEvent();
  RunUntilIdle();
  dropframe_verifier.Verify(1, 2);
}

#if BUILDFLAG(RTC_USE_H265)
class FakeH265ParameterSetsTracker : public H265ParameterSetsTracker {
 public:
  FakeH265ParameterSetsTracker() = delete;
  explicit FakeH265ParameterSetsTracker(
      H265ParameterSetsTracker::PacketAction action)
      : action_(action) {}
  explicit FakeH265ParameterSetsTracker(rtc::ArrayView<const uint8_t> prefix)
      : action_(H265ParameterSetsTracker::PacketAction::kInsert),
        prefix_(prefix) {
    EXPECT_GT(prefix.size(), 0u);
  }

  FixedBitstream MaybeFixBitstream(
      rtc::ArrayView<const uint8_t> bitstream) override {
    FixedBitstream fixed;
    fixed.action = action_;
    if (prefix_.size() > 0) {
      fixed.bitstream =
          webrtc::EncodedImageBuffer::Create(bitstream.size() + prefix_.size());
      memcpy(fixed.bitstream->data(), prefix_.data(), prefix_.size());
      memcpy(fixed.bitstream->data() + prefix_.size(), bitstream.data(),
             bitstream.size());
    }
    return fixed;
  }

 private:
  H265ParameterSetsTracker::PacketAction action_;
  rtc::ArrayView<const uint8_t> prefix_;
};

TEST_F(RTCVideoEncoderEncodeTest, EncodeH265WithBitstreamFix) {
  class FixedBitstreamVerifier : public webrtc::EncodedImageCallback {
   public:
    explicit FixedBitstreamVerifier(rtc::ArrayView<const uint8_t> prefix,
                                    size_t encoded_image_size)
        : prefix_(prefix), encoded_image_size_(encoded_image_size) {}

    webrtc::EncodedImageCallback::Result OnEncodedImage(
        const webrtc::EncodedImage& encoded_image,
        const webrtc::CodecSpecificInfo* codec_specific_info) override {
      EXPECT_EQ(encoded_image.size(), encoded_image_size_ + prefix_.size());
      EXPECT_THAT(
          rtc::ArrayView<const uint8_t>(encoded_image.data(), prefix_.size()),
          ::testing::ElementsAreArray(prefix_));
      waiter_.Signal();
      return Result(Result::OK);
    }

    void Wait() { waiter_.Wait(); }

   private:
    base::WaitableEvent waiter_;
    rtc::ArrayView<const uint8_t> prefix_;
    size_t encoded_image_size_;
  };

  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecH265;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  ExpectCreateInitAndDestroyVEA();

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  uint8_t prefix[] = {0x90, 0x91, 0x92, 0x93};
  rtc::ArrayView<uint8_t> prefix_view =
      rtc::ArrayView<uint8_t>(prefix, sizeof(prefix));
  rtc_encoder_->SetH265ParameterSetsTracker(
      std::make_unique<FakeH265ParameterSetsTracker>(prefix_view));
  FixedBitstreamVerifier bitstream_verifier(prefix_view,
                                            kDefaultEncodedPayloadSize);
  rtc_encoder_->RegisterEncodeCompleteCallback(&bitstream_verifier);

  EXPECT_CALL(*mock_vea_, Encode(_, _))
      .WillOnce(Invoke(this, &RTCVideoEncoderTest::ReturnFrameWithTimeStamp));

  const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
      webrtc::I420Buffer::Create(kInputFrameWidth, kInputFrameHeight);
  FillFrameBuffer(buffer);
  std::vector<webrtc::VideoFrameType> frame_types;
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                     .set_video_frame_buffer(buffer)
                                     .set_timestamp_rtp(0)
                                     .set_timestamp_us(0)
                                     .set_rotation(webrtc::kVideoRotation_0)
                                     .build(),
                                 &frame_types));
  RunUntilIdle();
}
#endif

TEST_F(RTCVideoEncoderFrameSizeChangeTest,
       FrameSizeChangeSupportedReCreateEncoder) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP9;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  EXPECT_CALL(*mock_encoder_metrics_provider_factory_,
              CreateVideoEncoderMetricsProvider())
      .WillOnce(Return(::testing::ByMove(
          std::make_unique<media::MockVideoEncoderMetricsProvider>())));
  SetUpEncodingWithFrameSizeChangeSupport(codec);
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK, rtc_encoder_->Release());

  // Change codec type.
  codec.codecType = webrtc::kVideoCodecH264;
  EXPECT_CALL(*mock_encoder_metrics_provider_factory_,
              CreateVideoEncoderMetricsProvider())
      .WillOnce(Return(::testing::ByMove(
          std::make_unique<media::MockVideoEncoderMetricsProvider>())));
  ExpectCreateInitAndDestroyVEA();
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));
}

TEST_F(RTCVideoEncoderFrameSizeChangeTest, FrameSizeChangeSupportedVP9) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecVP9;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  SetUpEncodingWithFrameSizeChangeSupport(codec);
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK, rtc_encoder_->Release());

  // Change frame size.
  codec.width *= 2;
  codec.height *= 2;
  EXPECT_CALL(*mock_vea_, Flush)
      .WillOnce(Invoke(this, &RTCVideoEncoderTest::FlushComplete));
  ExpectFrameSizeChange(gfx::Size(codec.width, codec.height));
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  size_t kNumEncodeFrames = 3u;
  for (size_t i = 0; i < kNumEncodeFrames; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(codec.width, codec.height);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    base::WaitableEvent event;
    if (i == 0) {
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    } else {
      EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer(_)).Times(1);
    }
    EXPECT_CALL(*mock_vea_, Encode(_, _))
        .WillOnce(Invoke([this, &event](scoped_refptr<media::VideoFrame> frame,
                                        bool force_keyframe) {
          client_->BitstreamBufferReady(
              0, media::BitstreamBufferMetadata(0, force_keyframe,
                                                frame->timestamp()));
          event.Signal();
        }));

    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(0)
                                       .set_timestamp_us(i + 3)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build(),
                                   &frame_types));
    event.Wait();
  }
}

TEST_F(RTCVideoEncoderFrameSizeChangeTest,
       FrameSizeChangeSupportedVP9TemporalLayer) {
  webrtc::VideoCodec tl_codec = GetSVCLayerCodec(webrtc::kVideoCodecVP9,
                                                 /*num_spatial_layers=*/1);
  CreateEncoder(tl_codec.codecType);
  ExpectCreateInitAndDestroyVEA();

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));
  // report frame size change support
  media::VideoEncoderInfo info;
  info.supports_frame_size_change = true;
  encoder_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &media::VideoEncodeAccelerator::Client::NotifyEncoderInfoChange,
          base::Unretained(client_), info));

  size_t kNumEncodeFrames = 3u;
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
    EXPECT_CALL(*mock_vea_, Encode(_, _))
        .WillOnce(DoAll(
            Invoke(this,
                   &RTCVideoEncoderTest::ReturnSVCLayerFrameWithVp9Metadata),
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
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK, rtc_encoder_->Release());

  // Change frame size.
  tl_codec.width *= 2;
  tl_codec.height *= 2;
  tl_codec.spatialLayers[0].width = tl_codec.width;
  tl_codec.spatialLayers[0].height = tl_codec.height;

  EXPECT_CALL(*mock_vea_, Flush)
      .WillOnce(Invoke(this, &RTCVideoEncoderTest::FlushComplete));
  ExpectFrameSizeChange(gfx::Size(tl_codec.width, tl_codec.height));
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&tl_codec, kVideoEncoderSettings));

  ResetSVCLayerFrameTimes();
  for (size_t i = 0; i < kNumEncodeFrames; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(tl_codec.width, tl_codec.height);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    base::WaitableEvent event;
    if (i == 0) {
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    } else {
      EXPECT_CALL(*mock_vea_, UseOutputBitstreamBuffer(_)).Times(1);
    }
    EXPECT_CALL(*mock_vea_, Encode(_, _))
        .WillOnce(DoAll(
            Invoke(this,
                   &RTCVideoEncoderTest::ReturnSVCLayerFrameWithVp9Metadata),
            [&event]() { event.Signal(); }));

    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->Encode(webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(0)
                                       .set_timestamp_us(i + 3)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build(),
                                   &frame_types));
    event.Wait();
  }
}

TEST_F(RTCVideoEncoderFrameSizeChangeTest, FrameSizeChangeSupported) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecH264;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  SetUpEncodingWithFrameSizeChangeSupport(codec);

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK, rtc_encoder_->Release());

  codec.width *= 2;
  codec.height *= 2;

  ExpectFrameSizeChange(gfx::Size(codec.width, codec.height));

  EXPECT_CALL(*mock_vea_, Flush)
      .WillOnce(Invoke(this, &RTCVideoEncoderTest::FlushComplete));
  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  EXPECT_CALL(*mock_vea_, RequestEncodingParametersChange(
                              _, _, std::optional<gfx::Size>()));

  webrtc::VideoBitrateAllocation bitrate_allocation;
  bitrate_allocation.SetBitrate(1, 0, 500000);
  rtc_encoder_->SetRates(webrtc::VideoEncoder::RateControlParameters(
      bitrate_allocation, codec.maxFramerate));

  EXPECT_CALL(*mock_vea_, Encode)
      .WillRepeatedly(Invoke(
          [this](scoped_refptr<media::VideoFrame> frame, bool force_keyframe) {
            client_->BitstreamBufferReady(
                0, media::BitstreamBufferMetadata(0, force_keyframe,
                                                  frame->timestamp()));
          }));

  for (int i = 0; i < 2; i++) {
    const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
        webrtc::I420Buffer::Create(codec.width, codec.height);
    FillFrameBuffer(buffer);
    std::vector<webrtc::VideoFrameType> frame_types;
    if (i == 0) {
      frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
    }

    webrtc::VideoFrame rtc_frame = webrtc::VideoFrame::Builder()
                                       .set_video_frame_buffer(buffer)
                                       .set_rtp_timestamp(i + 3)
                                       .set_timestamp_us(i + 3)
                                       .set_rotation(webrtc::kVideoRotation_0)
                                       .build();

    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->Encode(rtc_frame, &frame_types));
  }
  RunUntilIdle();
}

TEST_F(RTCVideoEncoderFrameSizeChangeTest,
       FrameSizeChangeSameSizeAfterSoftwareFallback) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecH264;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  SetUpEncodingWithFrameSizeChangeSupport(codec);

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK, rtc_encoder_->Release());

  codec.width -= 1;

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE,
            rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

  codec.width += 1;

    EXPECT_CALL(*mock_vea_, Flush)
        .WillOnce(Invoke(this, &RTCVideoEncoderTest::FlushComplete));
    EXPECT_CALL(*mock_vea_, RequestEncodingParametersChange(
                                _, _, std::optional<gfx::Size>()))
        .Times(AtLeast(1));

    EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
              rtc_encoder_->InitEncode(&codec, kVideoEncoderSettings));

    webrtc::VideoBitrateAllocation bitrate_allocation;
    bitrate_allocation.SetBitrate(1, 0, 500000);
    rtc_encoder_->SetRates(webrtc::VideoEncoder::RateControlParameters(
        bitrate_allocation, codec.maxFramerate));

    EXPECT_CALL(*mock_vea_, Encode)
        .WillRepeatedly(Invoke([this](scoped_refptr<media::VideoFrame> frame,
                                      bool force_keyframe) {
          client_->BitstreamBufferReady(
              0, media::BitstreamBufferMetadata(0, force_keyframe,
                                                frame->timestamp()));
        }));

    for (int i = 0; i < 2; i++) {
      const rtc::scoped_refptr<webrtc::I420Buffer> buffer =
          webrtc::I420Buffer::Create(codec.width, codec.height);
      FillFrameBuffer(buffer);
      std::vector<webrtc::VideoFrameType> frame_types;
      if (i == 0) {
        frame_types.emplace_back(webrtc::VideoFrameType::kVideoFrameKey);
      }

      webrtc::VideoFrame rtc_frame =
          webrtc::VideoFrame::Builder()
              .set_video_frame_buffer(buffer)
              .set_rtp_timestamp(i + kFramesToEncodeBeforeFrameSizeChange)
              .set_timestamp_us(i + kFramesToEncodeBeforeFrameSizeChange)
              .set_rotation(webrtc::kVideoRotation_0)
              .build();

      EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK,
                rtc_encoder_->Encode(rtc_frame, &frame_types));
    }

  RunUntilIdle();
}

TEST_F(RTCVideoEncoderFrameSizeChangeTest, FrameSizeChangeFlushFailure) {
  const webrtc::VideoCodecType codec_type = webrtc::kVideoCodecH264;
  CreateEncoder(codec_type);
  webrtc::VideoCodec codec = GetDefaultCodec();
  codec.codecType = codec_type;
  SetUpEncodingWithFrameSizeChangeSupport(codec);

  EXPECT_EQ(WEBRTC_VIDEO_CODEC_OK, rtc_encoder_->Release());

    std::vector<webrtc::VideoFrameType> frame_types;
```