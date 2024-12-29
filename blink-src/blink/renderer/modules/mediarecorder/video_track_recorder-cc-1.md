Response:
The user wants a summary of the functionalities of the `VideoTrackRecorderImpl` class in the provided C++ code. I need to extract the key actions performed by this class and explain its interactions with other parts of the system, especially concerning JavaScript, HTML, and CSS. I should also identify potential user or programming errors and how a user might end up interacting with this code.

Here's a plan:

1. **Identify Core Functionalities:** Analyze the methods and their purpose. This includes starting and stopping recording, handling video frames, encoding, pausing, resuming, and error handling.
2. **Relate to Web Technologies:** Determine how these functionalities connect to JavaScript APIs like `MediaRecorder`, HTML elements like `<video>`, and CSS styles (though the latter is less likely to have a direct connection here).
3. **Infer Logic and Data Flow:** Understand how video frames are processed, encoded, and passed along. Identify potential input and output scenarios.
4. **Spot Potential Errors:** Consider common mistakes users or developers might make that could trigger issues within this class.
5. **Trace User Interaction:** Describe the steps a user takes in a web browser that would lead to this code being executed.
6. **Summarize Functionality:** Provide a concise overview of the `VideoTrackRecorderImpl` class based on the analysis.
这是 `blink/renderer/modules/mediarecorder/video_track_recorder.cc` 源代码文件的第二部分，延续了第一部分的功能介绍。综合两部分的内容，我们可以归纳出 `VideoTrackRecorderImpl` 的主要功能是：

**核心功能：视频轨道记录和编码**

`VideoTrackRecorderImpl` 负责从 `MediaStream` 中的视频轨道捕获帧，并将其编码为指定的视频格式，以便进行录制。它扮演了 `MediaRecorder` API 和底层视频编码器之间的桥梁角色。

**具体功能点：**

1. **接收和处理视频帧:**
   - 监听 `MediaStream` 视频轨道产生的新视频帧 (`OnVideoFrame`)。
   - 将接收到的 `media::VideoFrame` 对象传递给编码器进行处理。
   - 在编码器支持信息未知时，会暂时缓存接收到的帧 (`incoming_frame_queue_`)。

2. **视频编码:**
   - 初始化视频编码器 (`InitializeEncoder`)，根据指定的编解码器配置 (`codec_profile_`)、码率 (`bits_per_second_`) 和是否允许硬件加速 (`allow_vea_encoder`) 选择合适的编码器实现（软件或硬件）。
   - 支持多种视频编码器，例如 H.264 (通过 OpenH264 或 MediaRecorderEncoderWrapper)、VP8、VP9 和 AV1 (通过 libaom 或 MediaRecorderEncoderWrapper)。
   - 可以使用硬件加速视频编码器 (VEAEncoder) 或软件编码器 (例如 H264Encoder, VpxEncoder)。
   - 使用 `MediaRecorderEncoderWrapper` 对多种编码器进行封装，提供统一的接口。
   - 异步调用编码器的 `StartFrameEncode` 方法来编码视频帧。
   - 可以根据需要强制生成关键帧 (`ForceKeyFrameForNextFrameForTesting`)。

3. **暂停和恢复录制:**
   - 提供 `Pause()` 和 `Resume()` 方法来暂停和恢复视频帧的编码。

4. **错误处理:**
   - 监听硬件编码器的错误 (`OnHardwareEncoderError`)，并在发生错误时尝试回退到软件编码。
   - 通过回调接口 (`CallbackInterface`) 通知上层模块视频编码错误 (`OnVideoEncodingError`)。

5. **编码器支持查询:**
   - 在初始化时查询编码器支持情况 (`NotifyEncoderSupportKnown`)。
   - 只有在编码器支持已知后，才会开始处理缓存的视频帧。

6. **与 MediaRecorder API 的集成:**
   - 通过 `CallbackInterface` 将编码后的视频数据 (`on_encoded_video_cb_`) 传递给 `MediaRecorder` 的上层模块。

7. **与视频轨道连接:**
   - 使用 `ConnectToTrack` 将自身注册为视频轨道的接收器，以便接收视频帧。
   - 使用 `DisconnectFromTrack` 断开与视频轨道的连接。

**与 JavaScript, HTML, CSS 的关系举例：**

1. **JavaScript:**
   - 当 JavaScript 代码调用 `MediaRecorder` API 的 `start()` 方法开始录制，并且指定了视频轨道时，`VideoTrackRecorderImpl` 的实例会被创建。
   - JavaScript 可以通过 `MediaRecorder` 的 `pause()` 和 `resume()` 方法间接地调用 `VideoTrackRecorderImpl` 的 `Pause()` 和 `Resume()` 方法。
   - `MediaRecorder` 的 `ondataavailable` 事件接收到的 `Blob` 数据，其中包含了由 `VideoTrackRecorderImpl` 编码的视频数据。

   **例子：**
   ```javascript
   navigator.mediaDevices.getUserMedia({ video: true })
     .then(stream => {
       const mediaRecorder = new MediaRecorder(stream, { mimeType: 'video/webm' });
       mediaRecorder.ondataavailable = event => {
         // 处理录制到的视频数据
         console.log(event.data);
       };
       mediaRecorder.start(); // 创建并启动 VideoTrackRecorderImpl
       // ... 一段时间后
       mediaRecorder.pause(); // 调用 VideoTrackRecorderImpl::Pause()
       // ... 稍后
       mediaRecorder.resume(); // 调用 VideoTrackRecorderImpl::Resume()
       mediaRecorder.stop();
     });
   ```

2. **HTML:**
   - `<video>` 元素可以播放由 `MediaRecorder` 录制的视频。`VideoTrackRecorderImpl` 负责生成录制所需的编码数据。

   **例子：**
   ```html
   <video controls src="recorded-video.webm"></video>
   ```

3. **CSS:**
   - CSS 本身与 `VideoTrackRecorderImpl` 的功能没有直接关系。CSS 主要用于样式控制，而 `VideoTrackRecorderImpl` 专注于视频数据的处理和编码。

**假设输入与输出 (逻辑推理):**

**假设输入：**

- 一个来自 `getUserMedia` 或屏幕捕获的 `MediaStreamTrack` 对象 (视频轨道)。
- 用户通过 JavaScript `MediaRecorder` API 启动录制。
- 指定的视频编码参数，例如码率、编解码器类型等。
- 一系列来自视频轨道的 `media::VideoFrame` 对象，带有时间戳信息。

**预期输出：**

- 编码后的视频数据，以特定格式（例如 WebM, MP4）通过回调传递给 `MediaRecorder` 的上层模块。
- 当发生错误时，通过回调通知上层模块。

**用户或编程常见的使用错误：**

1. **未处理编码错误：** 开发者可能没有正确监听和处理 `MediaRecorder` 的错误事件，导致无法得知编码过程中发生的问题。
   - **例子：** `mediaRecorder.onerror = event => { console.error('Recording error:', event.error); };` 应该被实现，但开发者可能忘记了。

2. **不支持的编解码器：** 用户或开发者尝试使用浏览器不支持的视频编解码器进行录制。
   - **例子：** 在 `MediaRecorder` 的构造函数中指定了一个不被当前浏览器支持的 `mimeType`，例如 `video/unsupported-codec`。

3. **资源限制：**  当硬件加速编码失败时，没有正确处理回退到软件编码的逻辑，或者系统资源不足导致编码失败。

4. **在不支持的环境中使用 API：**  在没有 `MediaRecorder` API 的旧版本浏览器中使用相关功能。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个网页，该网页使用了 `MediaRecorder` API。**
2. **网页上的 JavaScript 代码请求访问用户的摄像头或屏幕 (`navigator.mediaDevices.getUserMedia` 或 `navigator.mediaDevices.getDisplayMedia`)。**
3. **用户授权了摄像头或屏幕的访问。**
4. **网页上的 JavaScript 代码创建了一个 `MediaRecorder` 对象，并将获取到的 `MediaStream` 传递给它。**
5. **JavaScript 代码调用 `mediaRecorder.start()` 方法开始录制。**
6. **对于视频轨道，Blink 引擎会创建 `VideoTrackRecorderImpl` 的实例。**
7. **`VideoTrackRecorderImpl` 监听视频轨道产生的新的视频帧。**
8. **当视频轨道产生新的帧时，`OnVideoFrame` 方法会被调用。**
9. **如果编码器已初始化，视频帧会被传递给编码器进行编码。**
10. **如果编码器尚未初始化，会先进行初始化，根据配置选择硬件或软件编码器。**
11. **编码后的数据会通过回调传递给 `MediaRecorder` 的上层模块。**

**归纳其功能：**

`VideoTrackRecorderImpl` 的核心职责是实现 `MediaRecorder` API 中视频轨道的录制功能。它负责接收视频帧，选择合适的编码器，执行编码操作，并处理编码过程中的错误。它可以根据系统能力和配置选择使用硬件加速或软件编码，并通过回调将编码后的数据提供给上层模块，最终生成可用于保存或传输的视频数据。同时，它也处理录制的暂停和恢复操作。

**与 `VideoTrackRecorderPassthrough` 的区别:**

从代码来看，还有一个 `VideoTrackRecorderPassthrough` 类。它与 `VideoTrackRecorderImpl` 的主要区别在于，`VideoTrackRecorderPassthrough` 假设接收到的视频帧已经是编码过的，它主要负责处理关键帧的请求和传递已经编码的视频帧，而不需要进行实际的编码操作。这通常用于直接处理来自某些来源的已编码视频流。

Prompt: 
```
这是目录为blink/renderer/modules/mediarecorder/video_track_recorder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
kRecorderImpl");
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  DCHECK(track_);
  DCHECK(track_->GetSourceType() == MediaStreamSource::kTypeVideo);

  // Start querying for encoder support known.
  NotifyEncoderSupportKnown(
      WTF::BindOnce(&VideoTrackRecorderImpl::OnEncoderSupportKnown,
                    weak_factory_.GetWeakPtr()));

  // OnVideoFrame() will be called on Render Main thread.
  ConnectToTrack(base::BindPostTask(
      main_thread_task_runner_,
      WTF::BindRepeating(&VideoTrackRecorderImpl::OnVideoFrame,
                         weak_factory_.GetWeakPtr(),
                         /*allow_vea_encoder=*/true)));
}

VideoTrackRecorderImpl::~VideoTrackRecorderImpl() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  DisconnectFromTrack();
}

void VideoTrackRecorderImpl::OnEncoderSupportKnown() {
  TRACE_EVENT("media", "VideoTrackRecorderImpl::OnEncoderSupportKnown");
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  encoder_support_known_ = true;

  // Flush out stored frames.
  for (auto& frame_reference : incoming_frame_queue_) {
    auto media_stream_frame = std::move(frame_reference);
    // As we ask for support only initially when we try to use VEA, no frames
    // have been encoded (hence no fallback attempt has been made). Hence it's
    // safe to pass true in `allow_vea_encoder`.
    ProcessOneVideoFrame(/*allow_vea_encoder=*/true,
                         std::move(media_stream_frame.video_frame),
                         media_stream_frame.estimated_capture_time);
  }
  incoming_frame_queue_.clear();
}

void VideoTrackRecorderImpl::OnVideoFrame(
    bool allow_vea_encoder,
    scoped_refptr<media::VideoFrame> video_frame,
    base::TimeTicks capture_time) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  TRACE_EVENT("media", "VideoTrackRecorderImpl::OnVideoFrame");

  if (encoder_support_known_) {
    ProcessOneVideoFrame(allow_vea_encoder, std::move(video_frame),
                         capture_time);
  } else {
    // Return if encoder support isn't yet known. There's no limit of queued
    // frames implemented. In case it takes time for NotifyEncoderSupportKnown
    // to complete, the number of outstanding capture buffers is limited for
    // video capture and will eventually lead to the capturer stopping emitting
    // buffers. See
    // https://source.chromium.org/chromium/chromium/src/+/main:media/capture/video/video_capture_buffer_pool_util.cc.
    incoming_frame_queue_.push_back(
        MediaStreamFrame{.video_frame = std::move(video_frame),
                         .estimated_capture_time = capture_time});
  }
}

void VideoTrackRecorderImpl::ProcessOneVideoFrame(
    bool allow_vea_encoder,
    scoped_refptr<media::VideoFrame> video_frame,
    base::TimeTicks capture_time) {
  TRACE_EVENT("media", "VideoTrackRecorderImpl::ProcessOneVideoFrame");
  if (!encoder_) {
    InitializeEncoder(bits_per_second_, allow_vea_encoder,
                      video_frame->storage_type(),
                      video_frame->visible_rect().size());
  }
  if (encoder_) {
    encoder_.AsyncCall(&Encoder::StartFrameEncode)
        .WithArgs(video_frame, capture_time);
  }
}

void VideoTrackRecorderImpl::Pause() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  if (encoder_) {
    encoder_.AsyncCall(&Encoder::SetPaused).WithArgs(true);
  } else {
    should_pause_encoder_on_initialization_ = true;
  }
}

void VideoTrackRecorderImpl::Resume() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  if (encoder_) {
    encoder_.AsyncCall(&Encoder::SetPaused).WithArgs(false);
  } else {
    should_pause_encoder_on_initialization_ = false;
  }
}

void VideoTrackRecorderImpl::OnVideoFrameForTesting(
    scoped_refptr<media::VideoFrame> frame,
    base::TimeTicks timestamp,
    bool allow_vea_encoder) {
  DVLOG(3) << __func__;
  OnVideoFrame(allow_vea_encoder, std::move(frame), timestamp);
}

void VideoTrackRecorderImpl::ForceKeyFrameForNextFrameForTesting() {
  encoder_.AsyncCall(&Encoder::ForceKeyFrameForNextFrameForTesting);
}

std::unique_ptr<VideoTrackRecorder::Encoder>
VideoTrackRecorderImpl::CreateMediaVideoEncoder(
    scoped_refptr<base::SequencedTaskRunner> encoding_task_runner,
    CodecProfile codec_profile,
    bool is_screencast,
    bool create_vea_encoder) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  CHECK(codec_profile.profile.has_value());

  MediaRecorderEncoderWrapper::OnErrorCB on_error_cb;
  if (create_vea_encoder) {
    // If |on_error_cb| is called, then MediaRecorderEncoderWrapper with a
    // software encoder will be created.
    // TODO(crbug.com/1441395): This should be handled by using
    // media::VideoEncoderFallback. This should be achieved after refactoring
    // VideoTrackRecorder to call media::VideoEncoder directly.
    on_error_cb = base::BindPostTask(
        main_thread_task_runner_,
        WTF::BindOnce(&VideoTrackRecorderImpl::OnHardwareEncoderError,
                      weak_factory_.GetWeakPtr()));
  } else {
    on_error_cb = base::BindPostTask(
        main_thread_task_runner_,
        WTF::BindOnce(&CallbackInterface::OnVideoEncodingError,
                      WrapPersistent(callback_interface())));
  }

  media::GpuVideoAcceleratorFactories* gpu_factories =
      Platform::Current()->GetGpuFactories();
  return std::make_unique<MediaRecorderEncoderWrapper>(
      std::move(encoding_task_runner), *codec_profile.profile, bits_per_second_,
      is_screencast, create_vea_encoder ? gpu_factories : nullptr,
      create_vea_encoder
          ? GetCreateHardwareVideoEncoderCallback(codec_profile.codec_id)
          : GetCreateSoftwareVideoEncoderCallback(codec_profile.codec_id),
      on_encoded_video_cb_, std::move(on_error_cb));
}

std::unique_ptr<VideoTrackRecorder::Encoder>
VideoTrackRecorderImpl::CreateSoftwareVideoEncoder(
    scoped_refptr<base::SequencedTaskRunner> encoding_task_runner,
    CodecProfile codec_profile,
    bool is_screencast) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  CHECK(codec_profile.profile.has_value());

  switch (codec_profile.codec_id) {
#if BUILDFLAG(ENABLE_OPENH264)
    case CodecId::kH264:
      return std::make_unique<H264Encoder>(
          std::move(encoding_task_runner), on_encoded_video_cb_, codec_profile,
          bits_per_second_, is_screencast,
          base::BindPostTask(
              main_thread_task_runner_,
              WTF::BindRepeating(&CallbackInterface::OnVideoEncodingError,
                                 WrapPersistent(callback_interface()))));
#endif
    case CodecId::kVp8:
    case CodecId::kVp9:
      return std::make_unique<VpxEncoder>(
          std::move(encoding_task_runner),
          codec_profile.codec_id == CodecId::kVp9, on_encoded_video_cb_,
          bits_per_second_, is_screencast,
          base::BindPostTask(
              main_thread_task_runner_,
              WTF::BindRepeating(&CallbackInterface::OnVideoEncodingError,
                                 WrapPersistent(callback_interface()))));
#if BUILDFLAG(ENABLE_LIBAOM)
    case CodecId::kAv1: {
      auto on_error_cb = base::BindPostTask(
          main_thread_task_runner_,
          WTF::BindOnce(&CallbackInterface::OnVideoEncodingError,
                        WrapPersistent(callback_interface())));
      return std::make_unique<MediaRecorderEncoderWrapper>(
          std::move(encoding_task_runner), *codec_profile.profile,
          bits_per_second_, is_screencast,
          /*gpu_factories=*/nullptr,
          GetCreateSoftwareVideoEncoderCallback(CodecId::kAv1),
          on_encoded_video_cb_, std::move(on_error_cb));
    }
#endif  // BUILDFLAG(ENABLE_LIBAOM)
    default:
      NOTREACHED() << "Unsupported codec: "
                   << static_cast<int>(codec_profile.codec_id);
  }
}

std::unique_ptr<VideoTrackRecorder::Encoder>
VideoTrackRecorderImpl::CreateHardwareVideoEncoder(
    scoped_refptr<base::SequencedTaskRunner> encoding_task_runner,
    CodecProfile codec_profile,
    const gfx::Size& input_size,
    bool use_import_mode,
    bool is_screencast) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  CHECK(codec_profile.profile.has_value());
  const auto [vea_profile, vbr_supported] =
      GetCodecEnumerator()->FindSupportedVideoCodecProfile(
          codec_profile.codec_id, *codec_profile.profile);

  // VBR encoding is preferred.
  media::Bitrate::Mode bitrate_mode = vbr_supported
                                          ? media::Bitrate::Mode::kVariable
                                          : media::Bitrate::Mode::kConstant;
  return std::make_unique<VEAEncoder>(
      std::move(encoding_task_runner), on_encoded_video_cb_,
      base::BindPostTask(
          main_thread_task_runner_,
          WTF::BindRepeating(&VideoTrackRecorderImpl::OnHardwareEncoderError,
                             weak_factory_.GetWeakPtr())),
      bitrate_mode, bits_per_second_, vea_profile, codec_profile.level,
      input_size, use_import_mode, is_screencast);
}

void VideoTrackRecorderImpl::InitializeEncoder(
    uint32_t bits_per_second,
    bool allow_vea_encoder,
    media::VideoFrame::StorageType frame_storage_type,
    gfx::Size input_size) {
  TRACE_EVENT("media", "VideoTrackRecorderImpl::InitializeEncoder");
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  auto codec_profile = codec_profile_;
  const bool can_use_vea = CanUseAcceleratedEncoder(
      codec_profile, input_size.width(), input_size.height());
  CHECK(callback_interface());

  std::optional<media::VideoCodecProfile> profile =
      GetMediaVideoCodecProfile(codec_profile, input_size, allow_vea_encoder);
  if (!profile) {
    if (auto* callback = callback_interface()->Get()) {
      callback->OnVideoEncodingError();
    }
    return;
  }

  codec_profile.profile = *profile;

  const bool is_screencast =
      static_cast<const MediaStreamVideoTrack*>(track_->GetPlatformTrack())
          ->is_screencast();
  const bool use_import_mode =
      frame_storage_type == media::VideoFrame::STORAGE_GPU_MEMORY_BUFFER;
  const bool create_vea_encoder = allow_vea_encoder && can_use_vea;

  scoped_refptr<base::SequencedTaskRunner> encoding_task_runner;
  std::unique_ptr<Encoder> encoder;
  if (RuntimeEnabledFeatures::MediaRecorderUseMediaVideoEncoderEnabled()) {
    encoding_task_runner =
        base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()});
    encoder = CreateMediaVideoEncoder(encoding_task_runner, codec_profile,
                                      is_screencast, create_vea_encoder);
  } else {
    if (create_vea_encoder) {
      encoding_task_runner =
          Platform::Current()->GetGpuFactories()->GetTaskRunner();
      encoder = CreateHardwareVideoEncoder(encoding_task_runner, codec_profile,
                                           input_size, use_import_mode,
                                           is_screencast);
    } else {
      encoding_task_runner =
          base::ThreadPool::CreateSequencedTaskRunner({base::MayBlock()});
      encoder = CreateSoftwareVideoEncoder(encoding_task_runner, codec_profile,
                                           is_screencast);
    }
  }

  UmaHistogramForCodec(create_vea_encoder, codec_profile.codec_id);
  CHECK(encoder);

  auto metrics_provider =
      callback_interface()->Get()
          ? callback_interface()->Get()->CreateVideoEncoderMetricsProvider()
          : nullptr;
  CHECK(metrics_provider);
  encoder_.emplace(encoding_task_runner, std::move(encoder));
  encoder_.AsyncCall(&Encoder::InitializeEncoder)
      .WithArgs(key_frame_config_, std::move(metrics_provider),
                frame_buffer_pool_limit_);
  if (should_pause_encoder_on_initialization_) {
    encoder_.AsyncCall(&Encoder::SetPaused).WithArgs(true);
  }
}

void VideoTrackRecorderImpl::OnHardwareEncoderError() {
  DVLOG(3) << __func__;
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  // Try without VEA.
  DisconnectFromTrack();
  encoder_.Reset();
  ConnectToTrack(base::BindPostTask(
      main_thread_task_runner_,
      WTF::BindRepeating(&VideoTrackRecorderImpl::OnVideoFrame,
                         weak_factory_.GetWeakPtr(),
                         /*allow_vea_encoder=*/false)));
}

void VideoTrackRecorderImpl::ConnectToTrack(
    const VideoCaptureDeliverFrameCB& callback) {
  track_->AddSink(this, callback, MediaStreamVideoSink::IsSecure::kNo,
                  MediaStreamVideoSink::UsesAlpha::kDefault);
}

void VideoTrackRecorderImpl::DisconnectFromTrack() {
  auto* video_track =
      static_cast<MediaStreamVideoTrack*>(track_->GetPlatformTrack());
  video_track->RemoveSink(this);
}

VideoTrackRecorderPassthrough::VideoTrackRecorderPassthrough(
    scoped_refptr<base::SingleThreadTaskRunner> main_thread_task_runner,
    MediaStreamComponent* track,
    WeakCell<CallbackInterface>* callback_interface,
    KeyFrameRequestProcessor::Configuration key_frame_config)
    : VideoTrackRecorder(std::move(main_thread_task_runner),
                         callback_interface),
      track_(track),
      key_frame_processor_(key_frame_config) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  // HandleEncodedVideoFrame() will be called on Render Main thread.
  // Note: Adding an encoded sink internally generates a new key frame
  // request, no need to RequestKeyFrame().
  ConnectEncodedToTrack(
      WebMediaStreamTrack(track_),
      base::BindPostTask(
          main_thread_task_runner_,
          WTF::BindRepeating(
              &VideoTrackRecorderPassthrough::HandleEncodedVideoFrame,
              weak_factory_.GetWeakPtr(),
              WTF::BindRepeating(base::TimeTicks::Now))));
}

VideoTrackRecorderPassthrough::~VideoTrackRecorderPassthrough() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  DisconnectFromTrack();
}

void VideoTrackRecorderPassthrough::Pause() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  state_ = KeyFrameState::kPaused;
}

void VideoTrackRecorderPassthrough::Resume() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  state_ = KeyFrameState::kWaitingForKeyFrame;
  RequestKeyFrame();
}

void VideoTrackRecorderPassthrough::OnEncodedVideoFrameForTesting(
    base::TimeTicks now,
    scoped_refptr<EncodedVideoFrame> frame,
    base::TimeTicks capture_time) {
  HandleEncodedVideoFrame(
      WTF::BindRepeating([](base::TimeTicks now) { return now; }, now), frame,
      capture_time);
}

void VideoTrackRecorderPassthrough::RequestKeyFrame() {
  auto* video_track =
      static_cast<MediaStreamVideoTrack*>(track_->GetPlatformTrack());
  DCHECK(video_track->source());
  video_track->source()->RequestKeyFrame();
}

void VideoTrackRecorderPassthrough::DisconnectFromTrack() {
  // TODO(crbug.com/704136) : Remove this method when moving
  // MediaStreamVideoTrack to Oilpan's heap.
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  DisconnectEncodedFromTrack();
}

void VideoTrackRecorderPassthrough::HandleEncodedVideoFrame(
    base::RepeatingCallback<base::TimeTicks()> time_now_callback,
    scoped_refptr<EncodedVideoFrame> encoded_frame,
    base::TimeTicks estimated_capture_time) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_sequence_checker_);
  if (state_ == KeyFrameState::kPaused) {
    return;
  }
  if (state_ == KeyFrameState::kWaitingForKeyFrame &&
      !encoded_frame->IsKeyFrame()) {
    // Don't RequestKeyFrame() here - we already did this implicitly when
    // Creating/Starting or explicitly when Resuming this object.
    return;
  }
  state_ = KeyFrameState::kKeyFrameReceivedOK;

  auto now = std::move(time_now_callback).Run();
  if (encoded_frame->IsKeyFrame()) {
    key_frame_processor_.OnKeyFrame(now);
  }
  if (key_frame_processor_.OnFrameAndShouldRequestKeyFrame(now)) {
    RequestKeyFrame();
  }

  std::optional<gfx::ColorSpace> color_space;
  if (encoded_frame->ColorSpace()) {
    color_space = encoded_frame->ColorSpace();
  }

  auto buffer = media::DecoderBuffer::CopyFrom(encoded_frame->Data());
  buffer->set_is_key_frame(encoded_frame->IsKeyFrame());

  media::Muxer::VideoParameters params(encoded_frame->Resolution(),
                                       /*frame_rate=*/0.0f,
                                       /*codec=*/encoded_frame->Codec(),
                                       color_space);
  if (auto* callback = callback_interface()->Get()) {
    callback->OnPassthroughVideo(params, std::move(buffer),
                                 estimated_capture_time);
  }
}

}  // namespace blink

"""


```