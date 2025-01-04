Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of a larger file. The request also asks to identify relationships with JavaScript, HTML, and CSS, provide examples of logical reasoning with inputs and outputs, and highlight common usage errors.

**Plan:**

1. **High-Level Overview:**  Understand the primary purpose of this code block within the larger `RTCVideoEncoder.cc` file. It appears to be responsible for handling the output of the video encoding process.

2. **Key Functions:** Identify the main methods and their roles in processing the encoded video data. Look for functions that handle encoded bitstreams, manage metadata, and interface with WebRTC callbacks.

3. **Relationships with Web Technologies:** Analyze if and how the code interacts with concepts from JavaScript, HTML, or CSS. This will likely be indirect, involving data structures or APIs used in the browser's rendering or communication layers.

4. **Logical Reasoning:** Look for conditional statements and data transformations that involve specific inputs leading to predictable outputs. Focus on sections that handle different video codecs or encoding scenarios.

5. **Common Usage Errors:** Consider scenarios where the encoder might be used incorrectly or receive unexpected input, leading to errors.

6. **Synthesize Summary:** Combine the findings from the above steps into a concise summary of the code's function.

**Detailed Breakdown of the Code:**

* **Bitstream Handling:** The code receives the encoded bitstream (`output_mapping`) and prepares it for delivery. It handles cases with fixed bitstreams (e.g., parameter sets for H.265) and dynamically allocated bitstreams.
* **Metadata Processing:**  It extracts metadata about the encoded frame (size, timestamp, frame type, QP) and populates the `webrtc::EncodedImage` structure.
* **Codec-Specific Information:**  The code has distinct logic for handling metadata specific to different video codecs (H.264, VP8, VP9, AV1, H.265). This includes setting temporal and spatial layer information for scalable video coding (SVC).
* **Error Handling:** The `NotifyErrorStatus` function is used to report errors during the encoding process.
* **Callbacks:** The `encoded_image_callback_` is used to send the encoded image and codec-specific information back to the WebRTC layer.
* **Simulcast to SVC Conversion:**  The code interacts with a `simulcast_to_svc_converter_`, suggesting it can transform simulcast streams into a single SVC stream.
* **Frame Submission Tracking:** The `submitted_frames_` list is used to keep track of frames submitted for encoding.

**Relationships with Web Technologies:**

* **JavaScript:**  The encoded video data will eventually be consumed by JavaScript code in the browser, likely through the WebRTC API (e.g., `RTCPeerConnection`). The `webrtc::EncodedImageCallback` bridges this gap.
* **HTML:**  The video stream might be displayed in an HTML `<video>` element. The encoding process ensures the data is in a format suitable for decoding and rendering in the browser.
* **CSS:** CSS is not directly related to the encoding process itself, but it influences how the video is presented on the webpage (size, positioning, etc.).

**Logical Reasoning Examples:**

* **Input:** A keyframe is encoded using VP9 with SVC enabled.
* **Output:** The code will populate the `info.codecSpecific.VP9` structure with spatial layer resolutions and indexing information, setting `vp9.ss_data_available` to `true`.
* **Input:** A delta frame is encoded using H.264.
* **Output:** The code will set `h264.idr_frame` to `false` and potentially populate `h264.temporal_idx` based on available metadata.

**Common Usage Errors:**

* **Incorrect Configuration:** If the encoder is initialized with a configuration that doesn't match the input video stream (e.g., incorrect resolution or codec), errors will occur.
* **Missing Metadata:** If essential metadata is missing from the encoder's output, the `CHECK` statements might trigger, or incorrect information might be passed to WebRTC.
* **Buffer Issues:** Problems with the allocation or management of input or output buffers can lead to crashes or encoding failures.

**Synthesizing the Summary:** The code snippet focuses on the final stages of the video encoding process within the Chromium Blink engine. It receives the encoded bitstream and associated metadata from the hardware or software encoder. It then formats this information into a `webrtc::EncodedImage` object, adding codec-specific details. This object is then passed to a WebRTC callback, making the encoded frame available to the browser's communication layer. The code also handles error reporting and integrates with a mechanism to convert simulcast streams to SVC.
这是 blink 引擎 `RTCVideoEncoder.cc` 文件的第二部分，延续了第一部分关于视频编码功能的实现。 这部分代码主要负责 **处理编码完成的视频帧数据，并将其传递给 WebRTC 的回调函数**。

以下是更详细的功能归纳：

**核心功能：处理编码完成的视频帧并回调给 WebRTC**

1. **接收编码后的数据流和元数据：**
   - 接收来自底层视频编码器（VEA 或软件编码器）的编码后比特流 (`output_mapping`) 和包含编码信息的元数据 (`metadata`)。
   - 元数据包括帧的大小、时间戳、帧类型（关键帧或差分帧）、量化参数 (QP) 以及特定于编解码器的信息（如 H.264 的 temporal_idx、VP9 的空间和时间层信息等）。

2. **构建 `webrtc::EncodedImage` 对象：**
   - 将编码后的比特流包装到 `webrtc::EncodedImage` 对象中，这是 WebRTC 用于传递编码帧的标准数据结构。
   - 根据 `metadata` 中的信息设置 `EncodedImage` 的各种属性，例如：
     - `_encodedWidth` 和 `_encodedHeight`: 编码后的帧尺寸。
     - `SetRtpTimestamp`: RTP 时间戳。
     - `capture_time_ms_`: 捕获时间。
     - `_frameType`: 帧类型 (关键帧/差分帧)。
     - `content_type_`: 视频内容类型 (例如，摄像头或屏幕共享)。
     - `qp_`: 量化参数。
     - `SetTemporalIndex` 和 `SetSpatialIndex`:  设置时间和空间层索引 (用于 SVC)。

3. **处理编解码器特定的信息：**
   - 根据 `video_codec_type_` (H.264, VP8, VP9, AV1, H.265) 的不同，提取和设置 `webrtc::CodecSpecificInfo` 中的编解码器特定信息。
   - **H.264:** 设置 packetization_mode, idr_frame, temporal_idx, base_layer_sync 等。
   - **VP8:** 设置 keyIdx 和 temporal_idx。
   - **VP9:** 处理 SVC 的情况，包括验证空间层分辨率、设置空间和时间层索引、标记帧在图像中的位置、参考帧信息等。对于非 SVC 流，也设置相应的参数。
   - **AV1/H.265:** 如果启用了 SVC，则调用 `FillGenericFrameInfo` 来填充通用帧信息。

4. **Simulcast 到 SVC 的转换：**
   - 如果 `simulcast_to_svc_converter_` 存在（在第一部分中初始化），则调用其 `ConvertFrame` 方法，将 simulcast 流转换成 SVC 流的 `EncodedImage` 对象。

5. **通过回调函数将编码后的图像传递给 WebRTC：**
   - 获取注册的 `encoded_image_callback_` (通过 `RegisterEncodeCompleteCallback` 设置)。
   - 调用 `encoded_image_callback_->OnEncodedImage(image, &info)` 将编码后的图像和编解码器特定信息传递给 WebRTC 的上层。
   - 检查回调函数的返回值，如果出现错误，则会记录日志。

6. **错误处理：**
   - `NotifyErrorStatus` 函数用于报告编码过程中发生的错误。它会记录错误信息、更新编码器状态、记录 UMA 指标，并在需要时触发软件回退。

**与 JavaScript, HTML, CSS 的关系：**

- **JavaScript:** 这部分代码生成的 `webrtc::EncodedImage` 对象最终会被传递到 JavaScript 代码中，通常是通过 WebRTC 的 API (例如 `RTCPeerConnection` 的 `ontrack` 事件或 `RTCRtpSender` 的 `send` 方法)。JavaScript 代码可以使用这些数据来解码并在 HTML 页面上显示视频。
- **HTML:**  HTML 的 `<video>` 元素用于展示解码后的视频。编码过程确保视频数据符合浏览器能够解码的格式。
- **CSS:** CSS 用于控制 HTML 元素（包括 `<video>` 元素）的样式和布局，但与视频编码过程本身没有直接的功能关系。CSS 影响的是视频在页面上的呈现方式，而不是视频数据的生成。

**逻辑推理的假设输入与输出：**

**假设输入 1:**
- `video_codec_type_` 为 `webrtc::kVideoCodecVP9`。
- `metadata.key_frame` 为 `true`。
- `metadata.vp9` 存在且包含有效的空间层分辨率信息。
- 启用了 SVC (`expected_active_spatial_layers` 存在)。

**输出 1:**
- `image._frameType` 将被设置为 `webrtc::VideoFrameType::kVideoFrameKey`。
- `info.codecSpecific.VP9` 中的 `ss_data_available` 将被设置为 `true`。
- `info.codecSpecific.VP9` 中的空间层分辨率信息 (`vp9.width`, `vp9.height`) 将会填充。
- `image.SetSpatialIndex` 会被调用，设置正确的空间层索引。

**假设输入 2:**
- `video_codec_type_` 为 `webrtc::kVideoCodecH264`。
- `metadata.key_frame` 为 `false`。
- `metadata.h264` 存在且 `temporal_idx` 为 1。

**输出 2:**
- `image._frameType` 将被设置为 `webrtc::VideoFrameType::kVideoFrameDelta`。
- `info.codecSpecific.H264.idr_frame` 将被设置为 `false`。
- `info.codecSpecific.H264.temporal_idx` 将被设置为 1。
- `image.SetTemporalIndex` 会被调用，设置为 1。

**用户或编程常见的使用错误：**

1. **未正确初始化编码器：** 如果在调用编码相关方法之前没有成功初始化 `RTCVideoEncoder`，则 `video_encoder_` 可能为空，导致程序崩溃或功能异常。
2. **回调函数未注册或注册不正确：** 如果 `encoded_image_callback_` 没有被正确设置，编码后的数据将无法传递给 WebRTC 的上层。
3. **元数据不完整或错误：** 如果底层编码器提供的 `metadata` 信息不完整或与实际编码数据不符，可能会导致 WebRTC 无法正确解析编码帧。例如，SVC 的关键帧缺少空间层分辨率信息。
4. **在不支持 SVC 的情况下尝试使用 SVC 特性：** 例如，在没有启用相应 Feature Flag 或硬件不支持的情况下，尝试编码 VP9 SVC 流。
5. **处理帧时间戳错误：**  时间戳的计算和传递对于视频同步非常重要。如果时间戳信息不正确，可能会导致视频播放出现问题。
6. **错误处理不当：** 忽略 `NotifyErrorStatus` 产生的错误信息可能会导致问题难以排查。

**总结其功能：**

总而言之，`RTCVideoEncoder.cc` 的这部分代码是 blink 引擎中视频编码流程的关键组成部分。它的主要功能是将底层视频编码器产生的原始编码数据转换为 WebRTC 可以理解和使用的 `webrtc::EncodedImage` 对象，并通过回调函数将其传递给 WebRTC 的上层，以便进行网络传输和解码显示。它还负责处理不同视频编解码器的特定信息，并提供错误处理机制。

Prompt: 
```
这是目录为blink/renderer/platform/peerconnection/rtc_video_encoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
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
    converted_settings = simulcast_to_svc_converter->GetConfig();
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