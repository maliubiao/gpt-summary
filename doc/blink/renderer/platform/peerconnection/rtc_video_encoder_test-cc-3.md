Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from `rtc_video_encoder_test.cc`. This file seems to contain unit tests for `RTCVideoEncoder`, a class likely responsible for encoding video frames within the Chromium's WebRTC implementation.

I need to identify the key functionalities being tested in this part of the file. I'll go through each `TEST_F` block and summarize what it's testing. Then I will look for connections to JavaScript, HTML, and CSS, though given the nature of the code (low-level video encoding), direct connections are unlikely. I'll also analyze for logical reasoning, assumptions, and common user errors.

Here's a breakdown of the tests:

1. **`MetricsProviderSetErrorIsCalledOnError`**: Tests that an error is reported to the metrics provider when the encoder encounters an error.
2. **`EncodeVp9FrameWithMetricsProvider`**: Tests that frame encoding with VP9 triggers the correct metrics provider calls.
3. **`EncodeFrameWithAdapter`**: Tests that the encoder correctly handles frame size changes using an adapter, ensuring downscaling occurs when necessary.
4. **`EncodedBufferLifetimeExceedsEncoderLifetime`**: Tests that encoded video buffers remain valid even after the encoder is destroyed. This is crucial for asynchronous encoding pipelines.
5. **`EncodeAndDropWhenTooManyFramesInEncoder`**: Tests the encoder's behavior when it receives more frames than it can process, ensuring it drops frames and notifies the callback.
6. **`EncodeH265WithBitstreamFix`**: Tests the functionality to modify the H.265 bitstream, likely to insert parameter sets.
7. **`FrameSizeChangeSupportedReCreateEncoder`**: Tests that the encoder can be re-created when frame size changes are supported.
8. **`FrameSizeChangeSupportedVP9`**: Tests the scenario of changing frame size with VP9 encoding.
9. **`FrameSizeChangeSupportedVP9TemporalLayer`**:  Tests changing frame size when using VP9 with temporal layers (SVC).
10. **`FrameSizeChangeSupported`**: Tests general frame size change support with H.264.
11. **`FrameSizeChangeSameSizeAfterSoftwareFallback`**: Tests that a subsequent re-initialization with the original frame size works after a software fallback.
12. **`FrameSizeChangeFlushFailure`**: This test seems to be incomplete in the provided snippet.

Based on these observations, the main focus of this code is testing the encoding process, including error handling, metrics reporting, dynamic frame size changes, buffer management, and handling overloads.

Connections to web technologies are indirect. The video encoding tested here is the underlying mechanism that allows WebRTC to transmit video streams, which are then displayed in HTML using `<video>` elements and controlled by JavaScript. CSS might affect the layout and appearance of the video player, but not the encoding process itself.

For logical reasoning, the tests often assume a specific sequence of events (e.g., initialization, encoding, receiving callbacks) and verify that the encoder behaves as expected in those sequences. Input would be video frames and encoder configurations; output would be encoded video bitstreams and potentially error codes or notifications.

Common user errors might involve incorrect encoder settings, providing unsupported frame sizes, or not handling encoding callbacks correctly. However, these are mostly developer-level concerns when using the WebRTC API.
这是 `blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc` 源代码文件的第 4 部分，主要侧重于测试 `RTCVideoEncoder` 类的以下功能：

**主要功能归纳：**

1. **MetricsProvider 集成与错误处理:**
   - 测试当编码器发生错误时，是否正确调用了 `VideoEncoderMetricsProvider` 的 `SetError` 方法来记录错误。
   - 测试在 VP9 编码过程中，是否正确调用了 `VideoEncoderMetricsProvider` 的初始化和帧计数增加方法。

2. **使用 `WebRtcVideoFrameAdapter` 进行帧处理:**
   - 测试编码器能否正确处理使用 `WebRtcVideoFrameAdapter` 包装的视频帧，特别是在帧大小发生变化时，adapter 能否正确地调整帧大小。

3. **编码缓冲区的生命周期管理:**
   - 测试已编码的视频缓冲区（`EncodedImageBufferInterface`）的生命周期是否超过编码器的生命周期，确保在编码器销毁后，已编码的数据仍然有效。

4. **编码器过载时的帧丢弃机制:**
   - 测试当发送给编码器的帧过多时，编码器能够正确地丢弃帧，并通过 `OnDroppedFrame` 回调通知。

5. **H.265 码流修复 (Bitstream Fix):**
   - 测试对于 H.265 编码，是否可以插入特定的前缀（例如，SPS/PPS）到编码后的码流中。

6. **帧大小动态调整 (Frame Size Change):**
   - 测试编码器是否支持动态改变输入帧的大小，并能正确地重新创建或刷新内部的编码器实例。
   - 针对 VP9 和 H.264 编码器分别进行了测试，包括带有时间层 (Temporal Layer) 的 VP9 编码。
   - 测试了在支持帧大小更改的情况下，编码器在帧大小变化后能否正常编码。
   - 测试了在软件回退 (Software Fallback) 后，如果帧大小恢复到原始大小，编码器是否能够正常工作。
   - 测试了帧大小更改过程中，刷新 (Flush) 操作失败的情况。

**与 JavaScript, HTML, CSS 的关系 (间接关系):**

这些测试直接针对的是 Blink 渲染引擎中用于 WebRTC 视频编码的 C++ 代码。与 JavaScript、HTML 和 CSS 的关系是间接的，体现在以下方面：

* **JavaScript:**  WebRTC API 由 JavaScript 暴露给 Web 开发者。开发者可以使用 JavaScript 代码调用 `RTCPeerConnection` API 来创建视频轨道，并将本地或远程的视频流传递给编码器。这里的测试确保了底层的 C++ 视频编码器能够正确地处理这些视频流。
    * **举例:**  在 JavaScript 中，`RTCPeerConnection.addTrack()` 方法可以将一个视频轨道添加到连接中，这个视频轨道最终会被传递给底层的 `RTCVideoEncoder` 进行编码。

* **HTML:** HTML 中的 `<video>` 元素用于展示编码后的视频流。测试保证了编码器产生的码流是符合规范的，可以被浏览器解码并在 `<video>` 元素中正确渲染。
    * **举例:**  编码后的视频数据会通过 WebRTC 连接发送到远端，远端接收到数据后，解码并在 HTML 的 `<video>` 标签中显示。

* **CSS:** CSS 可以用来控制 `<video>` 元素的样式和布局，但这与视频编码器的功能没有直接关系。CSS 不会影响编码过程本身。

**逻辑推理、假设输入与输出：**

**示例 1: `MetricsProviderSetErrorIsCalledOnError`**

* **假设输入:**
    * 初始化一个 VP9 编码器。
    * 模拟编码过程中发生错误 (`media::EncoderStatus::Codes::kEncoderFailedEncode`)。
* **逻辑推理:** 编码器在遇到错误时，应该调用 `VideoEncoderMetricsProvider` 的 `SetError` 方法，并将错误状态传递给它。
* **预期输出:** `mock_encoder_metrics_provider` 的 `MockSetError` 方法被调用，并且传入的参数与模拟的错误状态一致。

**示例 2: `EncodeAndDropWhenTooManyFramesInEncoder`**

* **假设输入:**
    * 初始化一个 VP8 编码器。
    * 连续发送超过编码器缓冲区容量的视频帧，但不等待编码完成回调。
* **逻辑推理:** 当编码器缓冲区满时，新的帧应该被丢弃，并通过 `OnDroppedFrame` 回调通知。
* **预期输出:**  `OnDroppedFrame` 回调被调用，并且 `DropReason` 为 `kDroppedByEncoder`。后续接收到编码完成的回调后，编码帧的数量会增加。

**用户或编程常见的使用错误：**

1. **不正确的编码参数:**  用户可能会在 JavaScript 中设置不兼容的编码参数（例如，分辨率、帧率），导致 `InitEncode` 失败或编码效果不佳。
    * **举例:**  在 JavaScript 中，使用 `RTCRtpSender.getParameters()` 和 `RTCRtpSender.setParameters()` 设置编码参数时，如果设置了驱动不支持的分辨率，可能会导致编码失败。

2. **未处理编码完成回调:**  开发者可能没有正确注册和处理编码完成的回调 (`EncodedImageCallback`)，导致无法获取编码后的数据或无法及时释放资源。

3. **在不支持动态调整帧大小的编码器上尝试更改帧大小:**  如果底层硬件编码器不支持动态调整帧大小，但在上层仍然尝试这样做，可能会导致编码错误或性能问题。

4. **在高负载情况下没有考虑帧丢弃:**  在高网络或计算负载下，编码器可能会丢弃帧。如果应用程序没有适当的处理帧丢弃的机制，可能会导致视频卡顿或质量下降。

**总结此部分的功能：**

这部分测试代码全面地验证了 `RTCVideoEncoder` 在各种编码场景下的核心功能，包括错误报告、指标收集、帧处理、缓冲区管理、码流修复以及动态帧大小调整等关键特性。这些测试确保了 WebRTC 的视频编码模块能够稳定可靠地工作，为 Web 开发者提供高质量的实时视频通信能力。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_encoder_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
= 1;
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