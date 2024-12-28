Response:
The user is asking for a summary of the functionality of the `RTCVideoEncoder.cc` file in the Chromium Blink engine. I need to extract the key responsibilities of this class, explain its relation to web technologies like JavaScript, HTML, and CSS, provide examples of logical reasoning with input/output, list common user or programming errors, and finally, synthesize a concise summary of its purpose.

**Plan:**

1. **Identify core functions:**  Analyze the code for public methods and their roles. Keywords like `InitEncode`, `Encode`, `RegisterEncodeCompleteCallback`, `Release`, and `SetRates` are good starting points.
2. **Relate to web technologies:** Determine how the video encoding process in this file connects to the broader web platform. Consider the context of WebRTC and how it's used in web applications.
3. **Illustrate logical reasoning:** Choose a specific function (like `InitEncode`) and describe the conditional logic based on inputs like codec settings and hardware capabilities, predicting the output (success or failure).
4. **Highlight potential errors:** Look for error handling logic and scenarios where user misconfiguration or incorrect usage could lead to issues.
5. **Synthesize a summary:** Combine the identified functionalities into a concise description of the class's role.
目录为 `blink/renderer/platform/peerconnection/rtc_video_encoder.cc` 的 Chromium Blink 引擎源代码文件 `RTCVideoEncoder.cc` 的功能可以归纳如下：

**主要功能：**

1. **作为 WebRTC 视频编码器的接口：**  `RTCVideoEncoder` 类充当了 WebRTC (Real-Time Communication) 框架中视频编码功能的接口。它封装了底层硬件或软件视频编码器的初始化、配置和控制。

2. **管理视频编码器的生命周期：**  负责视频编码器的创建（`InitEncode`），编码（`Encode`），注册完成回调（`RegisterEncodeCompleteCallback`），释放资源（`Release` 和 `ReleaseImpl`）以及配置参数更新（`SetRates`）。

3. **硬件加速视频编码的支持：**  主要目标是利用硬件加速的视频编码器 (Video Encode Accelerator, VEA) 来提高编码效率和性能。它会查询系统可用的硬件编码器，并尝试使用它们。

4. **软件编码回退机制：**  当硬件编码器不可用、不支持指定格式或遇到错误时，提供回退到软件编码的机制。

5. **支持不同的视频编解码器：**  根据传入的 `codec_settings` 参数，支持多种视频编解码器，例如 H.264、VP9、AV1 等。

6. **处理 SVC (Scalable Video Coding)：**  支持将 Simulcast (多流编码) 转换为 SVC，以便在网络条件不佳时提供更灵活的视频质量调整。

7. **处理帧大小变化：**  具备在运行时处理视频帧大小变化的能力（通过 `kKeepEncoderInstanceOnRelease` Feature）。

8. **错误处理和报告：**  检测并处理编码过程中的错误，并通过回调通知上层。

9. **提供编码器信息：**  通过 `GetEncoderInfo` 方法提供当前使用的编码器的信息，例如是否硬件加速、支持的功能等。

**与 JavaScript, HTML, CSS 的关系：**

`RTCVideoEncoder.cc` 本身并不直接处理 JavaScript, HTML 或 CSS。它位于 Blink 渲染引擎的底层，负责视频编码的实际操作。 然而，它提供的功能是 WebRTC API 的一部分，而 WebRTC API 可以被 JavaScript 代码调用，从而间接地影响用户在 HTML 页面上看到的视频内容。

*   **JavaScript:**
    *   WebRTC 的 JavaScript API（例如 `RTCPeerConnection`, `RTCRtpSender`）会调用到 Blink 引擎的 C++ 代码，最终会使用到 `RTCVideoEncoder` 来对本地视频流进行编码。
    *   开发者可以通过 JavaScript 设置视频编码的参数（例如分辨率、帧率、码率），这些参数会传递到 `RTCVideoEncoder` 的 `InitEncode` 和 `SetRates` 方法中。
    *   JavaScript 可以监听 WebRTC 的事件，从而知晓视频编码的状态（例如是否成功初始化，是否发生错误）。

    **举例说明：**

    ```javascript
    // JavaScript 代码片段
    const pc = new RTCPeerConnection();
    navigator.mediaDevices.getUserMedia({ video: true })
      .then(stream => {
        const videoTrack = stream.getVideoTracks()[0];
        const sender = pc.addTrack(videoTrack, stream);
        const senderParams = sender.getParameters();
        senderParams.encodings = [{
          rid: 'high',
          maxBitrate: 1000000, // 设置最大码率
          scalabilityMode: 'L3T3' // 设置 SVC 模式
        }];
        sender.setParameters(senderParams);
      });
    ```
    在这个例子中，JavaScript 代码通过 `setParameters` 方法设置了视频编码的最大码率和 SVC 模式。这些参数最终会被传递到 `RTCVideoEncoder` 进行处理。

*   **HTML:**
    *   HTML 的 `<video>` 元素用于展示解码后的视频流。`RTCVideoEncoder` 负责编码本地视频，而解码发生在接收端的浏览器。
    *   HTML 结构可以包含控制视频流的元素（例如开始/停止按钮），这些元素的事件处理逻辑会调用 WebRTC 的 JavaScript API，从而间接地影响 `RTCVideoEncoder` 的行为。

*   **CSS:**
    *   CSS 用于控制 HTML 元素的样式，包括 `<video>` 元素的布局和外观。CSS 不直接与 `RTCVideoEncoder` 交互。

**逻辑推理示例：**

**假设输入：**

*   `codec_settings_.codecType` 为 `webrtc::kVideoCodecH264`
*   `codec_settings_.width` 为 641
*   `codec_settings_.height` 为 480

**代码片段：**

```c++
if (codec_settings_.codecType == webrtc::kVideoCodecH264 &&
    (codec_settings_.width % 2 != 0 || codec_settings_.height % 2 != 0)) {
  LOG(ERROR) << "Input video size is " << codec_settings_.width << "x"
             << codec_settings_.height << ", "
             << "but hardware H.264 encoder only supports even sized frames.";
  return WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE;
}
```

**输出：**

由于宽度 `641` 是奇数，条件成立，函数会返回 `WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE`。这意味着硬件 H.264 编码器不支持奇数宽度的帧，系统将尝试回退到软件编码。

**用户或编程常见的使用错误：**

1. **在 `InitEncode` 之前调用 `Encode` 或其他编码相关的方法：** 这会导致 `impl_` 未初始化，从而返回 `WEBRTC_VIDEO_CODEC_UNINITIALIZED` 错误。

    **示例：**

    ```c++
    RTCVideoEncoder encoder;
    webrtc::VideoFrame frame;
    encoder.Encode(frame, nullptr); // 错误：Encode 在 InitEncode 之前调用
    ```

2. **提供硬件编码器不支持的视频尺寸或编解码器配置：** 例如，尝试使用硬件 H.264 编码器编码奇数宽度的视频，会导致回退到软件编码或初始化失败。

3. **在多线程环境下不正确地使用 `RTCVideoEncoder` 的方法：** 例如，在不同的线程中同时调用 `Encode` 而没有适当的同步机制，可能会导致数据竞争或崩溃。虽然代码中使用了任务队列 (`gpu_task_runner_`) 来处理大部分操作，但理解线程安全仍然重要。

4. **没有正确处理编码完成的回调：** 如果没有正确注册和处理 `RegisterEncodeCompleteCallback`，编码后的数据将无法被上层应用获取。

5. **在 `Release` 之后继续调用编码相关的方法：**  释放编码器后，继续调用 `Encode` 等方法会导致未定义的行为。

**功能归纳（基于提供的代码片段）：**

这段代码是 `RTCVideoEncoder::InitEncode` 方法的一部分，主要负责 **初始化视频编码器**。其核心功能包括：

*   **处理 SVC 配置：**  如果配置了 SVC，会获取 SVC 转换器的配置。
*   **决定是否需要重新创建编码器实例：**  如果当前有编码器实例 (`impl_`) 且由于帧大小改变或其他原因不再适用，则会释放旧的实例。
*   **检查是否使用软件编码：**  根据分辨率和编解码器类型判断是否应该直接使用软件编码。
*   **检查硬件 H.264 编码的尺寸限制：**  对于硬件 H.264 编码器，会检查输入视频的宽度和高度是否为偶数。
*   **创建空间层配置：**  根据编解码器设置创建空间层配置（用于 SVC）。
*   **检查 VEA 对 SVC 的支持：**  判断硬件编码器是否支持 VP9/AV1 SVC。
*   **检查 VEA 对分辨率的支持：**  验证硬件编码器是否支持输入的视频分辨率。
*   **创建或获取编码器实例 (`Impl`)：**  如果需要，创建一个新的硬件或软件编码器实例。
*   **配置 VEA：**  根据编解码器设置配置 Video Encode Accelerator (VEA)。
*   **初始化编码器：**  调用底层的 `InitializeEncoder` 方法来初始化编码器。
*   **设置 SVC 转换器：**  将 SVC 转换器与编码器实例关联。

总而言之，这段代码负责根据给定的编码配置和系统能力，初始化底层的视频编码器，为后续的视频帧编码做好准备。

Prompt: 
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_encoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共4部分，请归纳一下它的功能

"""
st_to_svc_converter->GetConfig();
    // If we've rewritten config, never report software fallback on errors.
    // Let the WebRTC try to initialize each simulcast stream separately.
    initialization_error_message =
        WEBRTC_VIDEO_CODEC_ERR_SIMULCAST_PARAMETERS_NOT_SUPPORTED;
  } else {
    converted_settings = *codec_settings;
  }

  if (impl_) {
    if (!impl_initialized_ || has_error_ || !frame_size_change_supported_ ||
        !CodecSettingsUsableForFrameSizeChange(converted_settings)) {
      DVLOG(3) << __func__ << " ReleaseImpl";
      ReleaseImpl();
    }
  }

  codec_settings_ = converted_settings;

  if (UseSoftwareForLowResolution(codec_settings_.codecType,
                                  codec_settings_.width,
                                  codec_settings_.height)) {
    return initialization_error_message;
  }

  if (codec_settings_.codecType == webrtc::kVideoCodecH264 &&
      (codec_settings_.width % 2 != 0 || codec_settings_.height % 2 != 0)) {
    LOG(ERROR) << "Input video size is " << codec_settings_.width << "x"
               << codec_settings_.height << ", "
               << "but hardware H.264 encoder only supports even sized frames.";
    return WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE;
  }

  has_error_ = false;

  uint32_t bitrate_bps = 0;
  // Check for overflow converting bitrate (kilobits/sec) to bits/sec.
  if (!ConvertKbpsToBps(codec_settings_.startBitrate, &bitrate_bps)) {
    LOG(ERROR) << "Overflow converting bitrate from kbps to bps: bps="
               << codec_settings_.startBitrate;
    return WEBRTC_VIDEO_CODEC_ERR_PARAMETER;
  }

  gfx::Size input_visible_size;
  std::vector<media::VideoEncodeAccelerator::Config::SpatialLayer>
      spatial_layers;
  auto inter_layer_pred = media::SVCInterLayerPredMode::kOff;
  if (!CreateSpatialLayersConfig(codec_settings_, &spatial_layers,
                                 &inter_layer_pred, &input_visible_size)) {
    return initialization_error_message;
  }

  // Fallback to SW if VEA does not support VP9/AV1 SVC encoding. For H.265,
  // this will fail the initialization as there is no fallback.
  if ((codec_settings_.codecType == webrtc::kVideoCodecVP9 ||
#if BUILDFLAG(RTC_USE_H265)
       codec_settings_.codecType == webrtc::kVideoCodecH265 ||
#endif
       codec_settings_.codecType == webrtc::kVideoCodecAV1) &&
      !!spatial_layers.size()) {
    const auto vea_supported_profiles =
        gpu_factories_->GetVideoEncodeAcceleratorSupportedProfiles().value_or(
            media::VideoEncodeAccelerator::SupportedProfiles());
    auto support_profile = base::ranges::find_if(
        vea_supported_profiles,
        [this](const media::VideoEncodeAccelerator::SupportedProfile&
                   support_profile) {
          return this->profile_ == support_profile.profile &&
                 support_profile.scalability_modes.size() > 0;
        });
    if (vea_supported_profiles.end() != support_profile) {
      media::SVCScalabilityMode scalability_mode =
          ToSVCScalabilityMode(spatial_layers, inter_layer_pred);
      if (support_profile->scalability_modes.end() ==
          base::ranges::find_if(
              support_profile->scalability_modes,
              [&support_profile,
               scalability_mode](const media::SVCScalabilityMode& value) {
                return (value == scalability_mode) &&
                       (!support_profile->is_software_codec ||
                        media::MayHaveAndAllowSelectOSSoftwareEncoder(
                            media::VideoCodecProfileToVideoCodec(
                                support_profile->profile)));
              })) {
        return initialization_error_message;
      }
    }
  }

  // Check that |profile| supports |input_visible_size|.
  if (base::FeatureList::IsEnabled(features::kWebRtcUseMinMaxVEADimensions)) {
    const auto vea_supported_profiles =
        gpu_factories_->GetVideoEncodeAcceleratorSupportedProfiles().value_or(
            media::VideoEncodeAccelerator::SupportedProfiles());
    auto it = std::find_if(
        vea_supported_profiles.begin(), vea_supported_profiles.end(),
        [this, &input_visible_size](
            const media::VideoEncodeAccelerator::SupportedProfile&
                vea_profile) {
          return vea_profile.profile == profile_ &&
                 (!vea_profile.is_software_codec ||
                  media::MayHaveAndAllowSelectOSSoftwareEncoder(
                      media::VideoCodecProfileToVideoCodec(
                          vea_profile.profile))) &&
                 input_visible_size.width() <=
                     vea_profile.max_resolution.width() &&
                 input_visible_size.height() <=
                     vea_profile.max_resolution.height() &&
                 input_visible_size.width() >=
                     vea_profile.min_resolution.width() &&
                 input_visible_size.height() >=
                     vea_profile.min_resolution.height();
        });

    if (!vea_supported_profiles.empty() && it == vea_supported_profiles.end()) {
      LOG(ERROR) << "Requested dimensions (" << input_visible_size.ToString()
                 << ") beyond accelerator limits.";
      return initialization_error_message;
    }
  }

  auto webrtc_content_type = webrtc::VideoContentType::UNSPECIFIED;
  auto vea_content_type =
      media::VideoEncodeAccelerator::Config::ContentType::kCamera;
  if (codec_settings_.mode == webrtc::VideoCodecMode::kScreensharing) {
    webrtc_content_type = webrtc::VideoContentType::SCREENSHARE;
    vea_content_type =
        media::VideoEncodeAccelerator::Config::ContentType::kDisplay;
  }

  if (!impl_) {
    // base::Unretained(this) is safe because |impl_| is synchronously destroyed
    // in Release() so that |impl_| does not call UpdateEncoderInfo() after this
    // is destructed.
    Impl::UpdateEncoderInfoCallback update_encoder_info_callback =
        base::BindRepeating(&RTCVideoEncoder::UpdateEncoderInfo,
                            base::Unretained(this));
    base::RepeatingClosure execute_software_fallback =
        base::BindPostTaskToCurrentDefault(base::BindRepeating(
            &RTCVideoEncoder::SetError, weak_this_, ++impl_id_));

    impl_ = std::make_unique<Impl>(
        gpu_factories_, encoder_metrics_provider_factory_,
        ProfileToWebRtcVideoCodecType(profile_),
        codec_settings_.GetScalabilityMode(), webrtc_content_type,
        update_encoder_info_callback, execute_software_fallback, weak_impl_);
  }

  media::VideoPixelFormat pixel_format = media::PIXEL_FORMAT_I420;
  auto storage_type =
      media::VideoEncodeAccelerator::Config::StorageType::kShmem;
  if (IsZeroCopyEnabled(webrtc_content_type)) {
    pixel_format = media::PIXEL_FORMAT_NV12;
    storage_type =
        media::VideoEncodeAccelerator::Config::StorageType::kGpuMemoryBuffer;
  }

  media::VideoEncodeAccelerator::Config vea_config(
      pixel_format, input_visible_size, profile_,
      media::Bitrate::ConstantBitrate(bitrate_bps),
      codec_settings_.maxFramerate, storage_type, vea_content_type);
  vea_config.is_constrained_h264 = is_constrained_h264_;
  vea_config.spatial_layers = spatial_layers;
  vea_config.inter_layer_pred = inter_layer_pred;
  vea_config.drop_frame_thresh_percentage =
      GetDropFrameThreshold(codec_settings_);
  // When we don't have built in H264/H265 software encoding, allow usage of any
  // software encoders provided by the platform.
  if (media::MayHaveAndAllowSelectOSSoftwareEncoder(
          media::VideoCodecProfileToVideoCodec(profile_))) {
    vea_config.required_encoder_type =
        media::VideoEncodeAccelerator::Config::EncoderType::kNoPreference;
  }

  int32_t initialization_ret = InitializeEncoder(vea_config);
  if (initialization_ret != WEBRTC_VIDEO_CODEC_OK) {
    ReleaseImpl();
    CHECK(!impl_);
  } else {
    impl_->SetSimulcastToSvcConverter(std::move(simulcast_to_svc_converter));
  }
  return initialization_ret;
}

int32_t RTCVideoEncoder::Encode(
    const webrtc::VideoFrame& input_image,
    const std::vector<webrtc::VideoFrameType>* frame_types) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(webrtc_sequence_checker_);
  TRACE_EVENT1("webrtc", "RTCVideoEncoder::Encode", "timestamp",
               input_image.timestamp_us());
  DVLOG(3) << __func__;
  if (!impl_) {
    DVLOG(3) << "Encoder is not initialized";
    return WEBRTC_VIDEO_CODEC_UNINITIALIZED;
  }

  if (has_error_)
    return WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE;

  const bool want_key_frame =
      frame_types && frame_types->size() &&
      frame_types->front() == webrtc::VideoFrameType::kVideoFrameKey;
  PostCrossThreadTask(
      *gpu_task_runner_.get(), FROM_HERE,
      CrossThreadBindOnce(&RTCVideoEncoder::Impl::Enqueue, weak_impl_,
                          FrameChunk(input_image, want_key_frame)));
  return WEBRTC_VIDEO_CODEC_OK;
}

int32_t RTCVideoEncoder::RegisterEncodeCompleteCallback(
    webrtc::EncodedImageCallback* callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(webrtc_sequence_checker_);
  DVLOG(3) << __func__;
  if (!impl_) {
    if (!callback)
      return WEBRTC_VIDEO_CODEC_OK;
    DVLOG(3) << "Encoder is not initialized";
    return WEBRTC_VIDEO_CODEC_UNINITIALIZED;
  }

  // TOD(b/257021675): RegisterEncodeCompleteCallback() should be called twice,
  // with a valid pointer after InitEncode() and with a nullptr after Release().
  // Setting callback in |impl_| should be done asynchronously by posting the
  // task to |media_task_runner_|.
  // However, RegisterEncodeCompleteCallback() are actually called multiple
  // times with valid pointers, this may be a bug. To workaround this problem,
  // a mutex is used so that it is guaranteed that the previous callback is not
  // executed after RegisterEncodeCompleteCallback().
  impl_->RegisterEncodeCompleteCallback(callback);

  return WEBRTC_VIDEO_CODEC_OK;
}

int32_t RTCVideoEncoder::Release() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(webrtc_sequence_checker_);
  DVLOG(3) << __func__;
  if (!impl_)
    return WEBRTC_VIDEO_CODEC_OK;

  if (!frame_size_change_supported_ || !impl_initialized_ || has_error_) {
    DVLOG(3) << __func__ << " ReleaseImpl";
    ReleaseImpl();
  } else {
    base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;
    int32_t suspend_result;
    base::WaitableEvent suspend_waiter(
        base::WaitableEvent::ResetPolicy::MANUAL,
        base::WaitableEvent::InitialState::NOT_SIGNALED);
    PostCrossThreadTask(
        *gpu_task_runner_.get(), FROM_HERE,
        CrossThreadBindOnce(&RTCVideoEncoder::Impl::Suspend, weak_impl_,
                            SignaledValue(&suspend_waiter, &suspend_result)));
    suspend_waiter.Wait();
    if (suspend_result != WEBRTC_VIDEO_CODEC_UNINITIALIZED) {
      ReleaseImpl();
    }
  }

  return WEBRTC_VIDEO_CODEC_OK;
}

void RTCVideoEncoder::ReleaseImpl() {
  if (!impl_) {
    return;
  }

  base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;
  base::WaitableEvent release_waiter(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  PostCrossThreadTask(
      *gpu_task_runner_.get(), FROM_HERE,
      CrossThreadBindOnce(
          [](std::unique_ptr<Impl> impl, base::WaitableEvent* waiter) {
            impl.reset();
            waiter->Signal();
          },
          std::move(impl_), CrossThreadUnretained(&release_waiter)));

  release_waiter.Wait();

  // The object pointed by |weak_impl_| has been invalidated in Impl destructor.
  // Calling reset() is optional, but it's good to invalidate the value of
  // |weak_impl_| too
  weak_impl_.reset();
  impl_initialized_ = false;
}

void RTCVideoEncoder::SetRates(
    const webrtc::VideoEncoder::RateControlParameters& parameters) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(webrtc_sequence_checker_);
  TRACE_EVENT1("webrtc", "SetRates", "parameters",
               parameters.bitrate.ToString());
  DVLOG(3) << __func__ << " new_bit_rate=" << parameters.bitrate.ToString()
           << ", frame_rate=" << parameters.framerate_fps;
  if (!impl_) {
    DVLOG(3) << "Encoder is not initialized";
    return;
  }

  if (has_error_)
    return;

  PostCrossThreadTask(
      *gpu_task_runner_.get(), FROM_HERE,
      CrossThreadBindOnce(
          &RTCVideoEncoder::Impl::RequestEncodingParametersChange, weak_impl_,
          parameters));
  return;
}

webrtc::VideoEncoder::EncoderInfo RTCVideoEncoder::GetEncoderInfo() const {
  base::AutoLock auto_lock(lock_);
  return encoder_info_;
}

void RTCVideoEncoder::UpdateEncoderInfo(
    media::VideoEncoderInfo media_enc_info,
    std::vector<webrtc::VideoFrameBuffer::Type> preferred_pixel_formats) {
  // See b/261437029#comment7 why this needs to be done in |gpu_task_runner_|.
  DCHECK(gpu_task_runner_->RunsTasksInCurrentSequence());
  base::AutoLock auto_lock(lock_);

  frame_size_change_supported_ =
      base::FeatureList::IsEnabled(features::kKeepEncoderInstanceOnRelease) &&
      media_enc_info.supports_frame_size_change;
  encoder_info_.implementation_name = media_enc_info.implementation_name;
  encoder_info_.supports_native_handle = media_enc_info.supports_native_handle;
  encoder_info_.has_trusted_rate_controller =
      media_enc_info.has_trusted_rate_controller;
  encoder_info_.is_hardware_accelerated =
      media_enc_info.is_hardware_accelerated;
  // Simulcast is supported via VP9 SVC
  encoder_info_.supports_simulcast =
      media_enc_info.supports_simulcast ||
      (media::IsVp9kSVCHWEncodingEnabled() &&
       base::FeatureList::IsEnabled(
           features::kRtcVideoEncoderConvertSimulcastToSvc));
  encoder_info_.is_qp_trusted = media_enc_info.reports_average_qp;
  encoder_info_.requested_resolution_alignment =
      media_enc_info.requested_resolution_alignment;
  encoder_info_.apply_alignment_to_all_simulcast_layers =
      media_enc_info.apply_alignment_to_all_simulcast_layers;
  static_assert(
      webrtc::kMaxSpatialLayers >= media::VideoEncoderInfo::kMaxSpatialLayers,
      "webrtc::kMaxSpatiallayers is less than "
      "media::VideoEncoderInfo::kMaxSpatialLayers");
  for (size_t i = 0; i < std::size(media_enc_info.fps_allocation); ++i) {
    if (media_enc_info.fps_allocation[i].empty())
      continue;
    encoder_info_.fps_allocation[i] =
        absl::InlinedVector<uint8_t, webrtc::kMaxTemporalStreams>(
            media_enc_info.fps_allocation[i].begin(),
            media_enc_info.fps_allocation[i].end());
  }
  for (const auto& limit : media_enc_info.resolution_bitrate_limits) {
    encoder_info_.resolution_bitrate_limits.emplace_back(
        limit.frame_size.GetArea(), limit.min_start_bitrate_bps,
        limit.min_bitrate_bps, limit.max_bitrate_bps);
  }
  encoder_info_.preferred_pixel_formats.assign(preferred_pixel_formats.begin(),
                                               preferred_pixel_formats.end());
}

void RTCVideoEncoder::SetError(uint32_t impl_id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(webrtc_sequence_checker_);
  //  RTCVideoEncoder should reject to set error if the impl_id is not equal to
  //  current impl_id_, which means it's requested by a released impl_.
  if (impl_id == impl_id_) {
    has_error_ = true;
    impl_initialized_ = false;
  }

  if (error_callback_for_testing_)
    std::move(error_callback_for_testing_).Run();
}

#if BUILDFLAG(RTC_USE_H265)
void RTCVideoEncoder::SetH265ParameterSetsTrackerForTesting(
    std::unique_ptr<H265ParameterSetsTracker> tracker) {
  if (!impl_) {
    DVLOG(1) << "Encoder is not initialized";
    return;
  }
  impl_->SetH265ParameterSetsTrackerForTesting(std::move(tracker));
}
#endif

}  // namespace blink

"""


```