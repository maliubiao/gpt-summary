Response:
The user wants a summary of the C++ code snippet from a Chromium Blink engine file (`rtc_video_encoder.cc`). I need to identify the functionalities within the provided code, paying attention to its interaction with web technologies like JavaScript, HTML, and CSS. I also need to look for logical deductions and potential user errors.

Here's a breakdown of how to approach this:

1. **Identify Core Functionality:**  Scan the code for key actions and data structures. Look for terms like "encode," "bitstream," "metadata," "frame," "callback," and different video codec types (H264, VP8, VP9, AV1, H265).

2. **Trace Data Flow:** Observe how video frames are processed, from input to output. Note the steps involved in encoding, including potential scaling, format conversion, and the setting of codec-specific parameters.

3. **Look for Web Interactions:**  Pay close attention to the context within the Chromium/Blink environment. The file is within the `peerconnection` directory, suggesting it's part of the WebRTC implementation. Look for interactions with `webrtc` namespaces and any points where encoded data is passed back (likely via a callback).

4. **Analyze Logic:**  Examine conditional statements and loops to understand the decision-making processes within the encoding logic. Pay attention to error handling and how different encoding scenarios are managed (e.g., keyframes, temporal layers, spatial layers).

5. **Identify Potential Errors:** Consider scenarios where things might go wrong, such as incorrect input formats, buffer allocation failures, or mismatches in expected and actual encoding parameters.

6. **Relate to Web Technologies (if applicable):**  Think about how the encoding process influences the video quality and performance experienced in a web browser context. Consider aspects like frame rate, resolution, and the impact of different codecs. However, based on this snippet, the direct interaction with HTML/CSS is likely minimal as this is primarily about the encoding logic. JavaScript would interact with this through the WebRTC API.

7. **Formulate Assumptions and Outputs (for logical parts):**  For specific logical blocks (like the VP9 encoding parameter setting),  consider hypothetical input metadata and what the resulting encoded image and codec info would be.

8. **Structure the Summary:**  Organize the findings into clear categories (functionality, web relations, logical inferences, user errors).

**Constraint Checklist & Confidence Score:**

* Provide functionalities: Yes
* Relation to JavaScript, HTML, CSS with examples: Yes (JavaScript - WebRTC API interaction)
* Logical reasoning with assumptions and outputs: Yes
* User/programming errors with examples: Yes
* Part 3 of 4 summary: Yes

Confidence Score: 5/5

**Mental Sandbox Simulation:**

I'll mentally walk through the encoding process for a single frame. Input comes in, potential scaling or format conversion occurs, then the data is passed to the video encoder. The encoder outputs encoded data and metadata. This data is then packaged into an `EncodedImage` object along with codec-specific information. The `encoded_image_callback_` is the crucial point where this data likely gets back to the WebRTC pipeline and potentially to JavaScript. The code handles various codec-specific parameters based on the `video_codec_type_`. Error handling is done via `NotifyErrorStatus`.

Okay, the planning is complete. I will now proceed with generating the response.

这是 `RTCVideoEncoder::Impl::ReturnEncodedImage` 方法的代码片段，它的主要功能是处理视频编码器输出的编码数据，并将其封装成 `webrtc::EncodedImage` 对象，最终通过回调函数 `encoded_image_callback_` 返回给 WebRTC 的上层。

以下是更详细的功能列表：

1. **接收编码结果：**  该方法接收编码后的比特流数据 (`output_mapping`) 和相关的元数据 (`metadata`)。
2. **处理 H.265 参数集 (SPS/PPS)：** 如果启用了 H.265 支持 (`BUILDFLAG(RTC_USE_H265)`) 并且 `fixed.action` 指示需要插入参数集，则会将预先准备好的参数集比特流 (`fixed.bitstream`) 设置到 `image` 中。
3. **封装编码数据：** 如果不需要插入预先准备的比特流，则将编码后的比特流数据封装到一个 `EncodedDataWrapper` 对象中，并将其设置为 `image` 的编码数据。这里使用了 `base::BindPostTaskToCurrentDefault` 来确保在数据可用时调用 `EncodedBufferReferenceHolder::BitstreamBufferAvailable` 方法，用于管理输出缓冲区的生命周期。
4. **设置编码图像的属性：**  从 `metadata` 中提取信息，设置 `image` 对象的各种属性，包括：
    * 编码后的宽高 (`_encodedWidth`, `_encodedHeight`)
    * RTP 时间戳 (`_rtpTimestamp`)
    * 捕获时间戳 (`capture_time_ms_`)
    * 帧类型 (关键帧或非关键帧) (`_frameType`)
    * 内容类型 (`content_type_`)
    * 量化参数 (`qp_`)
5. **设置编解码器特定的信息：**  根据 `video_codec_type_` 设置 `webrtc::CodecSpecificInfo` 结构体，其中包含了特定编解码器需要的额外信息，例如：
    * **H.264:**  包模式、IDR 帧标识、时间层索引等。
    * **VP8:**  关键帧索引。
    * **VP9:**  时间层和空间层信息，包括 active spatial layer 的索引、分辨率、是否为 picture 的第一个帧、层间预测等。如果编码的是 SVC 流，还会进行一系列检查以确保 metadata 的正确性。
    * **AV1 和 H.265 (如果启用):**  如果 metadata 中包含 `svc_generic` 信息，则调用 `FillGenericFrameInfo` 函数填充通用帧信息。
6. **Simulcast 到 SVC 的转换：** 如果启用了 `simulcast_to_svc_converter_`，则调用其 `ConvertFrame` 方法对编码后的图像和信息进行转换。
7. **通过回调返回编码结果：**  获取锁以保证线程安全，然后调用 `encoded_image_callback_->OnEncodedImage(image, &info)` 将封装好的编码图像和编解码器信息返回给上层。
8. **处理回调错误：**  检查 `OnEncodedImage` 的返回值，如果发生错误，则记录日志。

**与 JavaScript, HTML, CSS 的关系：**

这个 C++ 代码文件是 WebRTC 引擎的一部分，负责底层的视频编码工作。它本身不直接与 JavaScript, HTML, CSS 交互，但其功能是 WebRTC 能力的基础，最终会影响到在浏览器中通过 JavaScript API（如 `RTCPeerConnection`）使用 WebRTC 进行视频通信的效果。

* **JavaScript:** JavaScript 代码会使用 WebRTC API 来获取摄像头或屏幕共享的视频流，并将其发送给远端。  `RTCVideoEncoder` 负责将这些视频帧编码成网络可以传输的格式。编码完成后，通过 `encoded_image_callback_` 返回的数据最终会被 WebRTC 管道处理，并发送出去。例如，在 JavaScript 中，你可以设置 `RTCPeerConnection` 的 `ontrack` 事件来接收远端发送过来的视频流。
* **HTML:** HTML 用于构建网页的结构，其中包括 `<video>` 元素，用于展示本地或远端的视频流。`RTCVideoEncoder` 的编码质量会直接影响到 `<video>` 元素中呈现的视频清晰度和流畅度。
* **CSS:** CSS 用于设置网页的样式，包括 `<video>` 元素的尺寸、边框等外观属性。`RTCVideoEncoder` 的编码过程会产生特定分辨率和帧率的视频流，这些属性会影响 CSS 样式的最终呈现效果。例如，如果编码分辨率与 `<video>` 元素的尺寸不匹配，浏览器可能会进行缩放，从而影响视频质量。

**逻辑推理与假设输入输出：**

**假设输入：**

* `metadata.key_frame` 为 `true` (这是一个关键帧)
* `video_codec_type_` 为 `webrtc::kVideoCodecVP9`
* `metadata.vp9` 存在，且描述了一个空间层流
* `expected_active_spatial_layers` 指示期望的 active spatial layer 范围为 `[begin_index, end_index)`
* `metadata.vp9` 中的 `begin_active_spatial_layer_index` 和 `end_active_spatial_layer_index` 与 `expected_active_spatial_layers` 相匹配
* `metadata.vp9->spatial_layer_resolutions` 与期望的分辨率列表相匹配

**输出：**

* `image._frameType` 将被设置为 `webrtc::VideoFrameType::kVideoFrameKey`
* `info.codecType` 将被设置为 `webrtc::kVideoCodecVP9`
* `info.codecSpecific.VP9` 的各种成员将被填充，包括：
    * `first_frame_in_picture` 将取决于 `metadata.vp9->spatial_idx` 是否等于 `expected_active_spatial_layers.begin_index`
    * `inter_pic_predicted` 将设置为 `metadata.vp9->inter_pic_predicted`
    * `temporal_idx` 将设置为 `metadata.vp9->temporal_idx`
    * `num_spatial_layers` 将设置为 `expected_active_spatial_layers.end_index`
    * 如果是关键帧，`vp9.ss_data_available` 将为 `true`，并且 `vp9.width` 和 `vp9.height` 数组将被填充 active spatial layer 的分辨率。
* `image._encodedWidth` 和 `image._encodedHeight` 将被设置为当前空间层的分辨率。

**用户或编程常见的使用错误：**

1. **编码器未初始化：**  如果在调用 `ReturnEncodedImage` 之前，视频编码器没有正确初始化，可能会导致空指针访问或未定义的行为。
2. **metadata 信息不完整或错误：** 如果 `metadata` 中的信息与实际编码结果不符，例如关键帧标识错误、分辨率信息错误等，会导致 WebRTC 上层处理错误。例如，如果声明是关键帧但实际不是，可能会导致解码错误。
3. **SVC metadata 不匹配：**  对于 SVC 编码（特别是 VP9），如果 `metadata.vp9` 中的空间层和时间层信息与编码器的配置不一致，例如 active layer 索引或分辨率不匹配，会导致 `NotifyErrorStatus` 被调用，指示编码失败。
4. **回调函数未注册或失效：** 如果在编码完成时，`encoded_image_callback_` 为空或者已经失效，编码后的数据将无法传递给 WebRTC 的上层。
5. **输出缓冲区管理错误：** 代码中涉及到输出缓冲区的分配和释放。如果管理不当，可能会导致内存泄漏或访问已释放的内存。

**功能归纳：**

`RTCVideoEncoder::Impl::ReturnEncodedImage` 方法负责接收底层视频编码器的输出，将编码后的比特流和元数据封装成符合 WebRTC 规范的 `webrtc::EncodedImage` 对象，并填充编解码器特定的信息。最终，它通过注册的回调函数将编码结果传递给 WebRTC 管道的上一层进行后续处理，例如 RTP 打包和网络传输。该方法还处理了 H.265 的参数集插入，并针对不同的视频编解码器（特别是 VP9 的 SVC）设置了相应的元数据。

### 提示词
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_encoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
xBitstream(rtc::MakeArrayView(
            output_mapping->front(), metadata.payload_size_bytes));
    if (fixed.action == H265ParameterSetsTracker::PacketAction::kInsert) {
      image.SetEncodedData(fixed.bitstream);
      BitstreamBufferAvailable(bitstream_buffer_id);
      fixed_bitstream = true;
    }
  }
#endif  // BUILDFLAG(RTC_USE_H265)
  if (!fixed_bitstream) {
    image.SetEncodedData(rtc::make_ref_counted<EncodedDataWrapper>(
        std::move(output_mapping), metadata.payload_size_bytes,
        base::BindPostTaskToCurrentDefault(base::BindOnce(
            &EncodedBufferReferenceHolder::BitstreamBufferAvailable,
            encoded_buffer_reference_holder_->GetWeakPtr(),
            bitstream_buffer_id))));
  }

  auto encoded_size = metadata.encoded_size.value_or(input_visible_size_);

  image._encodedWidth = encoded_size.width();
  image._encodedHeight = encoded_size.height();
  image.SetRtpTimestamp(rtp_timestamp.value());
  image.capture_time_ms_ = capture_timestamp_ms.value();
  image._frameType =
      (metadata.key_frame ? webrtc::VideoFrameType::kVideoFrameKey
                          : webrtc::VideoFrameType::kVideoFrameDelta);
  image.content_type_ = video_content_type_;
  // Default invalid qp value is -1 in webrtc::EncodedImage and
  // media::BitstreamBufferMetadata, and libwebrtc would parse bitstream to get
  // the qp if |qp_| is less than zero.
  image.qp_ = metadata.qp;

  webrtc::CodecSpecificInfo info;
  info.codecType = video_codec_type_;
  if (scalability_mode_.has_value()) {
    info.scalability_mode = scalability_mode_;
  }
  switch (video_codec_type_) {
    case webrtc::kVideoCodecH264: {
      webrtc::CodecSpecificInfoH264& h264 = info.codecSpecific.H264;
      h264.packetization_mode = webrtc::H264PacketizationMode::NonInterleaved;
      h264.idr_frame = metadata.key_frame;
      if (metadata.h264) {
        h264.temporal_idx = metadata.h264->temporal_idx;
        h264.base_layer_sync = metadata.h264->layer_sync;
        image.SetTemporalIndex(metadata.h264->temporal_idx);
      } else {
        h264.temporal_idx = webrtc::kNoTemporalIdx;
        h264.base_layer_sync = false;
      }
    } break;
    case webrtc::kVideoCodecVP8:
      info.codecSpecific.VP8.keyIdx = -1;
      if (metadata.vp8) {
        image.SetTemporalIndex(metadata.vp8->temporal_idx);
      }
      break;
    case webrtc::kVideoCodecVP9: {
      webrtc::CodecSpecificInfoVP9& vp9 = info.codecSpecific.VP9;
      if (metadata.vp9) {
        // Temporal and/or spatial layer stream.
        CHECK(expected_active_spatial_layers);
        if (metadata.key_frame) {
          if (metadata.vp9->spatial_layer_resolutions.empty()) {
            NotifyErrorStatus(
                {media::EncoderStatus::Codes::kEncoderFailedEncode,
                 "SVC resolution metadata is not filled on keyframe"});
            return;
          }

          CHECK_NE(expected_active_spatial_layers->end_index, 0u);
          const size_t expected_begin_index =
              expected_active_spatial_layers->begin_index;
          const size_t expected_end_index =
              expected_active_spatial_layers->end_index;
          const size_t begin_index =
              metadata.vp9->begin_active_spatial_layer_index;
          const size_t end_index = metadata.vp9->end_active_spatial_layer_index;
          if (begin_index != expected_begin_index ||
              end_index != expected_end_index) {
            NotifyErrorStatus(
                {media::EncoderStatus::Codes::kEncoderFailedEncode,
                 base::StrCat({"SVC active layer indices don't match "
                               "request: expected [",
                               base::NumberToString(expected_begin_index), ", ",
                               base::NumberToString(expected_end_index),
                               "), but got [",
                               base::NumberToString(begin_index), ", ",
                               base::NumberToString(end_index), ")"})});
            return;
          }

          const std::vector<gfx::Size> expected_resolutions(
              init_spatial_layer_resolutions_.begin() + begin_index,
              init_spatial_layer_resolutions_.begin() + end_index);
          if (metadata.vp9->spatial_layer_resolutions != expected_resolutions) {
            NotifyErrorStatus(
                {media::EncoderStatus::Codes::kEncoderFailedEncode,
                 "Encoded SVC resolution set does not match request"});
            return;
          }
        }
        const ActiveSpatialLayers& vea_active_spatial_layers =
            *expected_active_spatial_layers;
        CHECK_NE(vea_active_spatial_layers.end_index, 0u);
        const uint8_t spatial_index =
            metadata.vp9->spatial_idx + vea_active_spatial_layers.begin_index;
        if (spatial_index >= init_spatial_layer_resolutions_.size()) {
          NotifyErrorStatus(
              {media::EncoderStatus::Codes::kInvalidOutputBuffer,
               base::StrCat(
                   {"spatial_idx=", base::NumberToString(spatial_index),
                    " is not less than init_spatial_layer_resolutions_.size()=",
                    base::NumberToString(
                        init_spatial_layer_resolutions_.size())})});
          return;
        }
        if (spatial_index >= vea_active_spatial_layers.end_index) {
          NotifyErrorStatus(
              {media::EncoderStatus::Codes::kInvalidOutputBuffer,
               base::StrCat(
                   {"spatial_idx=", base::NumberToString(spatial_index),
                    " is not less than vea_active_spatial_layers.end_index=",
                    base::NumberToString(
                        vea_active_spatial_layers.end_index)})});
          return;
        }
        image._encodedWidth =
            init_spatial_layer_resolutions_[spatial_index].width();
        image._encodedHeight =
            init_spatial_layer_resolutions_[spatial_index].height();
        image.SetSpatialIndex(spatial_index);
        image.SetTemporalIndex(metadata.vp9->temporal_idx);

        vp9.first_frame_in_picture =
            spatial_index == vea_active_spatial_layers.begin_index;
        vp9.inter_pic_predicted = metadata.vp9->inter_pic_predicted;
        vp9.non_ref_for_inter_layer_pred =
            !metadata.vp9->referenced_by_upper_spatial_layers;
        vp9.temporal_idx = metadata.vp9->temporal_idx;
        vp9.temporal_up_switch = metadata.vp9->temporal_up_switch;
        vp9.inter_layer_predicted =
            metadata.vp9->reference_lower_spatial_layers;
        vp9.num_ref_pics = metadata.vp9->p_diffs.size();
        for (size_t i = 0; i < metadata.vp9->p_diffs.size(); ++i)
          vp9.p_diff[i] = metadata.vp9->p_diffs[i];
        vp9.ss_data_available = metadata.key_frame;

        // |num_spatial_layers| is not the number of active spatial layers,
        // but the highest spatial layer + 1.
        vp9.first_active_layer = vea_active_spatial_layers.begin_index;
        vp9.num_spatial_layers = vea_active_spatial_layers.end_index;

        if (vp9.ss_data_available) {
          vp9.spatial_layer_resolution_present = true;
          vp9.gof.num_frames_in_gof = 0;
          for (size_t i = 0; i < vea_active_spatial_layers.begin_index; ++i) {
            // Signal disabled layers.
            vp9.width[i] = 0;
            vp9.height[i] = 0;
          }
          for (size_t i = vea_active_spatial_layers.begin_index;
               i < vea_active_spatial_layers.end_index; ++i) {
            wtf_size_t wtf_i = base::checked_cast<wtf_size_t>(i);
            vp9.width[i] = init_spatial_layer_resolutions_[wtf_i].width();
            vp9.height[i] = init_spatial_layer_resolutions_[wtf_i].height();
          }
        }
        vp9.flexible_mode = true;
        vp9.gof_idx = 0;
        info.end_of_picture = metadata.end_of_picture();
      } else {
        // Simple stream, neither temporal nor spatial layer stream.
        vp9.flexible_mode = false;
        vp9.temporal_idx = webrtc::kNoTemporalIdx;
        vp9.temporal_up_switch = true;
        vp9.inter_layer_predicted = false;
        vp9.gof_idx = 0;
        vp9.num_spatial_layers = 1;
        vp9.first_frame_in_picture = true;
        vp9.spatial_layer_resolution_present = false;
        vp9.inter_pic_predicted = !metadata.key_frame;
        vp9.ss_data_available = metadata.key_frame;
        if (vp9.ss_data_available) {
          vp9.spatial_layer_resolution_present = true;
          vp9.width[0] = image._encodedWidth;
          vp9.height[0] = image._encodedHeight;
          vp9.gof.num_frames_in_gof = 1;
          vp9.gof.temporal_idx[0] = 0;
          vp9.gof.temporal_up_switch[0] = false;
          vp9.gof.num_ref_pics[0] = 1;
          vp9.gof.pid_diff[0][0] = 1;
        }
        info.end_of_picture = true;
      }
      // TODO(bugs.webrtc.org/11999): Fill `info.generic_frame_info` to
      // provide more accurate description of used layering than webrtc can
      // simulate based on the codec specific info.
    } break;
    case webrtc::kVideoCodecAV1:
      if (metadata.svc_generic) {
        FillGenericFrameInfo(info, metadata);
      }
      break;
#if BUILDFLAG(RTC_USE_H265)
    case webrtc::kVideoCodecH265:
      if (metadata.svc_generic) {
        FillGenericFrameInfo(info, metadata);
      }
      break;
#endif  // BUILDFLAG(RTC_USE_H265)
    default:
      break;
  }

  if (simulcast_to_svc_converter_) {
    simulcast_to_svc_converter_->ConvertFrame(image, info);
  }

  base::AutoLock lock(lock_);
  if (!encoded_image_callback_)
    return;

  const auto result = encoded_image_callback_->OnEncodedImage(image, &info);
  if (result.error != webrtc::EncodedImageCallback::Result::OK) {
    DVLOG(2)
        << "ReturnEncodedImage(): webrtc::EncodedImageCallback::Result.error = "
        << result.error;
  }
}

void RTCVideoEncoder::Impl::NotifyErrorStatus(
    const media::EncoderStatus& status) {
  TRACE_EVENT0("webrtc", "RTCVideoEncoder::Impl::NotifyErrorStatus");
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(!status.is_ok());
  LOG(ERROR) << "NotifyErrorStatus is called with code="
             << static_cast<int>(status.code())
             << ", message=" << status.message();
  if (encoder_metrics_provider_) {
    // |encoder_metrics_provider_| is nullptr if NotifyErrorStatus() is called
    // before it is created in CreateAndInitializeVEA().
    encoder_metrics_provider_->SetError(status);
  }
  // Don't count the error multiple times.
  if (status_ != WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE) {
    RecordEncoderStatusUMA(status, video_codec_type_);
  }

  input_visible_size_ = gfx::Size();

  video_encoder_.reset();
  status_ = WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE;

  async_init_event_.SetAndReset(WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE);

  execute_software_fallback_.Run();
}

RTCVideoEncoder::Impl::~Impl() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (video_encoder_) {
    video_encoder_.reset();
    status_ = WEBRTC_VIDEO_CODEC_UNINITIALIZED;
    RecordEncoderStatusUMA(media::EncoderStatus::Codes::kOk, video_codec_type_);
  }

  async_init_event_.reset();

  encoded_buffer_reference_holder_.reset();

  // weak_this_ must be invalidated in |gpu_task_runner_|.
  weak_this_factory_.InvalidateWeakPtrs();
}

void RTCVideoEncoder::Impl::EncodeOneFrame(FrameChunk frame_chunk) {
  DVLOG(3) << "Impl::EncodeOneFrame()";
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!input_buffers_free_.empty());
  TRACE_EVENT1("webrtc", "RTCVideoEncoder::Impl::EncodeOneFrame", "timestamp",
               frame_chunk.timestamp_us);

  if (!video_encoder_) {
    return;
  }

  const base::TimeDelta timestamp =
      base::Microseconds(frame_chunk.timestamp_us);

  scoped_refptr<media::VideoFrame> frame;
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> frame_buffer =
      frame_chunk.video_frame_buffer;

  // All non-native frames require a copy because we can't tell if non-copy
  // conditions are met.
  bool requires_copy_or_scale =
      frame_buffer->type() != webrtc::VideoFrameBuffer::Type::kNative;
  if (!requires_copy_or_scale) {
    const WebRtcVideoFrameAdapter* frame_adapter =
        static_cast<WebRtcVideoFrameAdapter*>(frame_buffer.get());
    frame = frame_adapter->getMediaVideoFrame();
    frame->set_timestamp(timestamp);
    const media::VideoFrame::StorageType storage = frame->storage_type();
    const bool is_memory_based_frame =
        storage == media::VideoFrame::STORAGE_UNOWNED_MEMORY ||
        storage == media::VideoFrame::STORAGE_OWNED_MEMORY ||
        storage == media::VideoFrame::STORAGE_SHMEM;
    const bool is_right_format = frame->format() == media::PIXEL_FORMAT_I420 ||
                                 frame->format() == media::PIXEL_FORMAT_NV12;
    requires_copy_or_scale =
        !is_right_format || RequiresSizeChange(*frame) ||
        !(is_memory_based_frame || frame->HasMappableGpuBuffer());
  }

  if (requires_copy_or_scale) {
    TRACE_EVENT0("webrtc",
                 "RTCVideoEncoder::Impl::EncodeOneFrame::CopyOrScale");
    // Native buffer scaling is performed by WebRtcVideoFrameAdapter, which may
    // be more efficient in some cases. E.g. avoiding I420 conversion or scaling
    // from a middle layer instead of top layer.
    //
    // Native buffer scaling is only supported when `input_frame_coded_size_`
    // and `input_visible_size_` strides match. This ensures the strides of the
    // frame that we pass to the encoder fits the input requirements.
    bool native_buffer_scaling =
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_CHROMEOS)
        frame_buffer->type() == webrtc::VideoFrameBuffer::Type::kNative &&
        input_frame_coded_size_ == input_visible_size_;
#else
        // TODO(https://crbug.com/1307206): Android (e.g. android-pie-arm64-rel)
        // and CrOS does not support the native buffer scaling path. Investigate
        // why and find a way to enable it, if possible.
        false;
#endif
    if (native_buffer_scaling) {
      DCHECK_EQ(frame_buffer->type(), webrtc::VideoFrameBuffer::Type::kNative);
      auto scaled_buffer = frame_buffer->Scale(input_visible_size_.width(),
                                               input_visible_size_.height());
      auto mapped_buffer =
          scaled_buffer->GetMappedFrameBuffer(preferred_pixel_formats_);
      if (!mapped_buffer) {
        mapped_buffer = scaled_buffer->ToI420();
      }
      if (!mapped_buffer) {
        NotifyErrorStatus({media::EncoderStatus::Codes::kSystemAPICallError,
                           "Failed to map buffer"});
        return;
      }

      DCHECK_NE(mapped_buffer->type(), webrtc::VideoFrameBuffer::Type::kNative);
      frame = ConvertFromMappedWebRtcVideoFrameBuffer(mapped_buffer, timestamp);
      if (!frame) {
        NotifyErrorStatus(
            {media::EncoderStatus::Codes::kFormatConversionError,
             "Failed to convert WebRTC mapped buffer to media::VideoFrame"});
        return;
      }
    } else {
      const int index = input_buffers_free_.back();
      if (!input_buffers_[index]) {
        const size_t input_frame_buffer_size =
            media::VideoFrame::AllocationSize(media::PIXEL_FORMAT_I420,
                                              input_frame_coded_size_);
        input_buffers_[index] = std::make_unique<base::MappedReadOnlyRegion>(
            base::ReadOnlySharedMemoryRegion::Create(input_frame_buffer_size));
        if (!input_buffers_[index]->IsValid()) {
          NotifyErrorStatus({media::EncoderStatus::Codes::kSystemAPICallError,
                             "Failed to create input buffer"});
          return;
        }
      }

      auto& region = input_buffers_[index]->region;
      auto& mapping = input_buffers_[index]->mapping;
      frame = media::VideoFrame::WrapExternalData(
          media::PIXEL_FORMAT_I420, input_frame_coded_size_,
          gfx::Rect(input_visible_size_), input_visible_size_,
          static_cast<uint8_t*>(mapping.memory()), mapping.size(), timestamp);
      if (!frame) {
        NotifyErrorStatus({media::EncoderStatus::Codes::kEncoderFailedEncode,
                           "Failed to create input buffer"});
        return;
      }

      // |frame| is STORAGE_UNOWNED_MEMORY at this point. Writing the data is
      // allowed.
      // Do a strided copy and scale (if necessary) the input frame to match
      // the input requirements for the encoder.
      // TODO(magjed): Downscale with an image pyramid instead.
      rtc::scoped_refptr<webrtc::I420BufferInterface> i420_buffer =
          frame_buffer->ToI420();
      if (libyuv::I420Scale(
              i420_buffer->DataY(), i420_buffer->StrideY(),
              i420_buffer->DataU(), i420_buffer->StrideU(),
              i420_buffer->DataV(), i420_buffer->StrideV(),
              i420_buffer->width(), i420_buffer->height(),
              frame->GetWritableVisibleData(media::VideoFrame::Plane::kY),
              frame->stride(media::VideoFrame::Plane::kY),
              frame->GetWritableVisibleData(media::VideoFrame::Plane::kU),
              frame->stride(media::VideoFrame::Plane::kU),
              frame->GetWritableVisibleData(media::VideoFrame::Plane::kV),
              frame->stride(media::VideoFrame::Plane::kV),
              frame->visible_rect().width(), frame->visible_rect().height(),
              libyuv::kFilterBox)) {
        NotifyErrorStatus({media::EncoderStatus::Codes::kFormatConversionError,
                           "Failed to copy buffer"});
        return;
      }

      // |frame| becomes STORAGE_SHMEM. Writing the buffer is not permitted
      // after here.
      frame->BackWithSharedMemory(&region);

      input_buffers_free_.pop_back();
      frame->AddDestructionObserver(
          base::BindPostTaskToCurrentDefault(WTF::BindOnce(
              &RTCVideoEncoder::Impl::InputBufferReleased, weak_this_, index)));
    }
  }

  if (!failed_timestamp_match_) {
    DCHECK(!base::Contains(submitted_frames_, timestamp,
                           &FrameInfo::media_timestamp_));
    submitted_frames_.emplace_back(timestamp, frame_chunk.timestamp,
                                   frame_chunk.render_time_ms,
                                   GetActiveSpatialLayers());
  }

  // Call UseOutputBitstreamBuffer() for pending output buffers.
  for (const auto& bitstream_buffer_id : pending_output_buffers_) {
    UseOutputBitstreamBuffer(bitstream_buffer_id);
  }
  pending_output_buffers_.clear();

  if (simulcast_to_svc_converter_) {
    simulcast_to_svc_converter_->EncodeStarted(frame_chunk.force_keyframe);
  }

  frames_in_encoder_count_++;
  DVLOG(3) << "frames_in_encoder_count=" << frames_in_encoder_count_;
  video_encoder_->Encode(frame, frame_chunk.force_keyframe);
}

void RTCVideoEncoder::Impl::EncodeOneFrameWithNativeInput(
    FrameChunk frame_chunk) {
  DVLOG(3) << "Impl::EncodeOneFrameWithNativeInput()";
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(input_buffers_.empty() && input_buffers_free_.empty());
  TRACE_EVENT1("webrtc", "RTCVideoEncoder::Impl::EncodeOneFrameWithNativeInput",
               "timestamp", frame_chunk.timestamp_us);

  if (!video_encoder_) {
    return;
  }

  scoped_refptr<media::VideoFrame> frame;
  rtc::scoped_refptr<webrtc::VideoFrameBuffer> frame_buffer =
      frame_chunk.video_frame_buffer;
  if (frame_buffer->type() != webrtc::VideoFrameBuffer::Type::kNative) {
    // If we get a non-native frame it's because the video track is disabled and
    // WebRTC VideoBroadcaster replaces the camera frame with a black YUV frame.
    if (!black_frame_) {
      gfx::Size natural_size(frame_buffer->width(), frame_buffer->height());
      if (!CreateBlackMappableSIFrame(natural_size)) {
        NotifyErrorStatus({media::EncoderStatus::Codes::kSystemAPICallError,
                           "Failed to allocate native buffer for black frame"});
        return;
      }
    }
    frame = media::VideoFrame::WrapVideoFrame(
        black_frame_, black_frame_->format(), black_frame_->visible_rect(),
        black_frame_->natural_size());
  } else {
    frame = static_cast<WebRtcVideoFrameAdapter*>(frame_buffer.get())
                ->getMediaVideoFrame();
  }
  frame->set_timestamp(base::Microseconds(frame_chunk.timestamp_us));

  if (frame->storage_type() != media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER) {
    NotifyErrorStatus({media::EncoderStatus::Codes::kInvalidInputFrame,
                       "frame isn't mappable shared image based VideoFrame"});
    return;
  }

  if (!failed_timestamp_match_) {
    DCHECK(!base::Contains(submitted_frames_, frame->timestamp(),
                           &FrameInfo::media_timestamp_));
    submitted_frames_.emplace_back(frame->timestamp(), frame_chunk.timestamp,
                                   frame_chunk.render_time_ms,
                                   GetActiveSpatialLayers());
  }

  // Call UseOutputBitstreamBuffer() for pending output buffers.
  for (const auto& bitstream_buffer_id : pending_output_buffers_) {
    UseOutputBitstreamBuffer(bitstream_buffer_id);
  }
  pending_output_buffers_.clear();

  frames_in_encoder_count_++;
  DVLOG(3) << "frames_in_encoder_count=" << frames_in_encoder_count_;

  video_encoder_->Encode(frame, frame_chunk.force_keyframe);
}

bool RTCVideoEncoder::Impl::CreateBlackMappableSIFrame(
    const gfx::Size& natural_size) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  const auto buffer_format = gfx::BufferFormat::YUV_420_BIPLANAR;
  const auto si_format = viz::GetSharedImageFormat(buffer_format);
  const auto buffer_usage =
      gfx::BufferUsage::VEA_READ_CAMERA_AND_CPU_READ_WRITE;

  // Setting some default usage in order to get a mappable shared image.
  const auto si_usage =
      gpu::SHARED_IMAGE_USAGE_CPU_WRITE | gpu::SHARED_IMAGE_USAGE_DISPLAY_READ;

  auto* sii = gpu_factories_->SharedImageInterface();
  if (!sii) {
    return false;
  }

  auto shared_image = sii->CreateSharedImage(
      {si_format, natural_size, gfx::ColorSpace(),
       gpu::SharedImageUsageSet(si_usage), "RTCVideoEncoder"},
      gpu::kNullSurfaceHandle, buffer_usage);
  if (!shared_image) {
    LOG(ERROR) << "Unable to create a mappable shared image.";
    return false;
  }

  // Map in order to write to it.
  auto mapping = shared_image->Map();
  if (!mapping) {
    LOG(ERROR) << "Mapping shared image failed.";
    sii->DestroySharedImage(gpu::SyncToken(), std::move(shared_image));
    return false;
  }

  // Fills the NV12 frame with YUV black (0x00, 0x80, 0x80).
  std::ranges::fill(mapping->GetMemoryForPlane(0), 0x0);
  std::ranges::fill(mapping->GetMemoryForPlane(1), 0x80);

  gpu::SyncToken sync_token = sii->GenVerifiedSyncToken();
  black_frame_ = media::VideoFrame::WrapMappableSharedImage(
      std::move(shared_image), sync_token, base::NullCallback(),
      gfx::Rect(mapping->Size()), natural_size, base::TimeDelta());
  return true;
}

void RTCVideoEncoder::Impl::InputBufferReleased(int index) {
  TRACE_EVENT0("webrtc", "RTCVideoEncoder::Impl::InputBufferReleased");
  DVLOG(3) << "Impl::InputBufferReleased(): index=" << index;
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(!use_native_input_);

  // NotfiyError() has been called. Don't proceed the frame completion.
  if (!video_encoder_)
    return;

  DCHECK_GE(index, 0);
  DCHECK_LT(index, static_cast<int>(input_buffers_.size()));
  input_buffers_free_.push_back(index);

  while (!pending_frames_.empty() && !input_buffers_free_.empty()) {
    auto chunk = std::move(pending_frames_.front());
    pending_frames_.pop_front();
    EncodeOneFrame(std::move(chunk));
  }
}

bool RTCVideoEncoder::Impl::RequiresSizeChange(
    const media::VideoFrame& frame) const {
  return (frame.coded_size() != input_frame_coded_size_ ||
          frame.visible_rect() != gfx::Rect(input_visible_size_));
}

void RTCVideoEncoder::Impl::RegisterEncodeCompleteCallback(
    webrtc::EncodedImageCallback* callback) {
  DVLOG(3) << __func__;
  base::AutoLock lock(lock_);
  encoded_image_callback_ = callback;
}

#if BUILDFLAG(RTC_USE_H265)
void RTCVideoEncoder::Impl::SetH265ParameterSetsTrackerForTesting(
    std::unique_ptr<H265ParameterSetsTracker> tracker) {
  ps_tracker_ = std::move(tracker);
}
#endif

RTCVideoEncoder::RTCVideoEncoder(
    media::VideoCodecProfile profile,
    bool is_constrained_h264,
    media::GpuVideoAcceleratorFactories* gpu_factories,
    scoped_refptr<media::MojoVideoEncoderMetricsProviderFactory>
        encoder_metrics_provider_factory)
    : profile_(profile),
      is_constrained_h264_(is_constrained_h264),
      gpu_factories_(gpu_factories),
      encoder_metrics_provider_factory_(
          std::move(encoder_metrics_provider_factory)),
      gpu_task_runner_(gpu_factories->GetTaskRunner()) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(webrtc_sequence_checker_);
  CHECK(encoder_metrics_provider_factory_);
  DVLOG(1) << "RTCVideoEncoder(): profile=" << GetProfileName(profile);

  // The default values of EncoderInfo.
  encoder_info_.scaling_settings = webrtc::VideoEncoder::ScalingSettings::kOff;
  encoder_info_.requested_resolution_alignment = 1;
  encoder_info_.apply_alignment_to_all_simulcast_layers = false;
  encoder_info_.supports_native_handle = true;
  encoder_info_.implementation_name = "ExternalEncoder";
  encoder_info_.has_trusted_rate_controller = false;
  encoder_info_.is_hardware_accelerated = true;
  encoder_info_.is_qp_trusted = true;
  encoder_info_.fps_allocation[0] = {
      webrtc::VideoEncoder::EncoderInfo::kMaxFramerateFraction};
  DCHECK(encoder_info_.resolution_bitrate_limits.empty());
  // Simulcast is supported for VP9 codec if svc is supported.
  // Since this encoder is used for all codecs, need to always
  // report true.
  encoder_info_.supports_simulcast =
      media::IsVp9kSVCHWEncodingEnabled() &&
      base::FeatureList::IsEnabled(
          features::kRtcVideoEncoderConvertSimulcastToSvc);
  encoder_info_.preferred_pixel_formats = {
      webrtc::VideoFrameBuffer::Type::kI420};

  impl_initialized_ = false;
  weak_this_ = weak_this_factory_.GetWeakPtr();
}

RTCVideoEncoder::~RTCVideoEncoder() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(webrtc_sequence_checker_);
  DVLOG(3) << __func__;

  // |weak_this_| must be invalidated on |webrtc_sequence_checker_|.
  weak_this_factory_.InvalidateWeakPtrs();

  ReleaseImpl();

  DCHECK(!impl_);

  // |encoder_metrics_provider_factory_| needs to be destroyed on the same
  // sequence as one that destroys the VideoEncoderMetricsProviders created by
  // it. It is gpu task runner in this case.
  gpu_task_runner_->ReleaseSoon(FROM_HERE,
                                std::move(encoder_metrics_provider_factory_));
}

int32_t RTCVideoEncoder::DrainEncoderAndUpdateFrameSize(
    const gfx::Size& input_visible_size,
    const webrtc::VideoEncoder::RateControlParameters& params,
    const media::SVCInterLayerPredMode& inter_layer_pred,
    const std::vector<media::VideoEncodeAccelerator::Config::SpatialLayer>&
        spatial_layers) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(webrtc_sequence_checker_);

  base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;
  base::WaitableEvent initialization_waiter(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  int32_t initialization_retval = WEBRTC_VIDEO_CODEC_UNINITIALIZED;
  {
    int32_t drain_result;
    base::WaitableEvent drain_waiter(
        base::WaitableEvent::ResetPolicy::MANUAL,
        base::WaitableEvent::InitialState::NOT_SIGNALED);
    PostCrossThreadTask(
        *gpu_task_runner_.get(), FROM_HERE,
        CrossThreadBindOnce(&RTCVideoEncoder::Impl::Drain, weak_impl_,
                            SignaledValue(&drain_waiter, &drain_result)));
    drain_waiter.Wait();
    DVLOG(3) << __func__ << " Drain complete, status " << drain_result;

    if (drain_result != WEBRTC_VIDEO_CODEC_OK &&
        drain_result != WEBRTC_VIDEO_CODEC_UNINITIALIZED) {
      return drain_result;
    }
  }

  DVLOG(3) << __func__ << ": updating frame size on existing instance";
  PostCrossThreadTask(
      *gpu_task_runner_.get(), FROM_HERE,
      CrossThreadBindOnce(
          &RTCVideoEncoder::Impl::RequestEncodingParametersChangeWithSizeChange,
          weak_impl_, params, input_visible_size, profile_, inter_layer_pred,
          spatial_layers,
          SignaledValue(&initialization_waiter, &initialization_retval)));
  initialization_waiter.Wait();
  return initialization_retval;
}

int32_t RTCVideoEncoder::InitializeEncoder(
    const media::VideoEncodeAccelerator::Config& vea_config) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(webrtc_sequence_checker_);
  TRACE_EVENT1("webrtc", "RTCVideoEncoder::InitEncode", "config",
               vea_config.AsHumanReadableString());
  DVLOG(1) << __func__ << ": config=" << vea_config.AsHumanReadableString();
  auto init_start = base::TimeTicks::Now();
  // This wait is necessary because this task is completed in GPU process
  // asynchronously but WebRTC API is synchronous.
  base::ScopedAllowBaseSyncPrimitivesOutsideBlockingScope allow_wait;
  base::WaitableEvent initialization_waiter(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  int32_t initialization_retval = WEBRTC_VIDEO_CODEC_UNINITIALIZED;

  if (!impl_initialized_) {
    DVLOG(3) << __func__ << ": CreateAndInitializeVEA";
    PostCrossThreadTask(
        *gpu_task_runner_.get(), FROM_HERE,
        CrossThreadBindOnce(
            &RTCVideoEncoder::Impl::CreateAndInitializeVEA, weak_impl_,
            vea_config,
            SignaledValue(&initialization_waiter, &initialization_retval)));
    // webrtc::VideoEncoder expects this call to be synchronous.
    initialization_waiter.Wait();
    if (initialization_retval == WEBRTC_VIDEO_CODEC_OK) {
      UMA_HISTOGRAM_TIMES("WebRTC.RTCVideoEncoder.Initialize",
                          base::TimeTicks::Now() - init_start);
      impl_initialized_ = true;
    }
    RecordInitEncodeUMA(initialization_retval, profile_);
  } else {
    DCHECK(frame_size_change_supported_);
    webrtc::VideoEncoder::RateControlParameters params(
        AllocateBitrateForVEAConfig(vea_config), vea_config.framerate);
    initialization_retval = DrainEncoderAndUpdateFrameSize(
        vea_config.input_visible_size, params, vea_config.inter_layer_pred,
        vea_config.spatial_layers);
  }
  return initialization_retval;
}

bool RTCVideoEncoder::CodecSettingsUsableForFrameSizeChange(
    const webrtc::VideoCodec& codec_settings) const {
  if (codec_settings.codecType != codec_settings_.codecType) {
    return false;
  }
  if (codec_settings.GetScalabilityMode() !=
      codec_settings_.GetScalabilityMode()) {
    return false;
  }
  if (codec_settings.GetFrameDropEnabled() !=
      codec_settings_.GetFrameDropEnabled()) {
    return false;
  }
  if (codec_settings.mode != codec_settings_.mode) {
    return false;
  }

  if (codec_settings.codecType == webrtc::kVideoCodecVP9) {
    const auto vp9 = codec_settings_.VP9();
    const auto new_vp9 = codec_settings.VP9();
    if (vp9.numberOfTemporalLayers != new_vp9.numberOfTemporalLayers ||
        vp9.numberOfSpatialLayers != new_vp9.numberOfSpatialLayers ||
        vp9.interLayerPred != new_vp9.interLayerPred) {
      return false;
    }
  }
  return true;
}

int32_t RTCVideoEncoder::InitEncode(
    const webrtc::VideoCodec* codec_settings,
    const webrtc::VideoEncoder::Settings& settings) {
  TRACE_EVENT0("webrtc", "RTCVideoEncoder::InitEncode");
  DCHECK_CALLED_ON_VALID_SEQUENCE(webrtc_sequence_checker_);
  DVLOG(1) << __func__ << " codecType=" << codec_settings->codecType
           << ", width=" << codec_settings->width
           << ", height=" << codec_settings->height
           << ", startBitrate=" << codec_settings->startBitrate;

  // Try to rewrite the simulcast config as SVC one.
  webrtc::VideoCodec converted_settings;
  std::optional<webrtc::SimulcastToSvcConverter> simulcast_to_svc_converter;

  int32_t initialization_error_message = WEBRTC_VIDEO_CODEC_FALLBACK_SOFTWARE;

  if (codec_settings->numberOfSimulcastStreams > 1) {
    // No VEA currently supports simulcast. It, however, can be
    // emulated with SVC VP9 if the streams have the same temporal
    // settings and 4:2:1 scaling.
    if (codec_settings->codecType != webrtc::kVideoCodecVP9 ||
        !base::FeatureList::IsEnabled(
            features::kRtcVideoEncoderConvertSimulcastToSvc) ||
        !webrtc::SimulcastToSvcConverter::IsConfigSupported(*codec_settings)) {
      return WEBRTC_VIDEO_CODEC_ERR_SIMULCAST_PARAMETERS_NOT_SUPPORTED;
    }
    simulcast_to_svc_converter.emplace(*codec_settings);
    converted_settings = simulca
```