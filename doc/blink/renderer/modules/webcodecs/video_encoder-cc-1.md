Response:
The user wants a summary of the functionality of the provided C++ code snippet from `video_encoder.cc`. I need to identify the core purpose of the code, its interactions with web technologies (JavaScript, HTML, CSS), and any logical assumptions, potential errors, and debugging information it reveals.

**Part 1: Functionality Identification**

The code deals with video encoding within the Chromium browser's Blink rendering engine. Key functions include:

- Initializing and configuring video encoders.
- Handling encode requests.
- Managing frame readback and memory operations.
- Processing encoding results and calling JavaScript callbacks.
- Checking if a given encoder configuration is supported.
- Managing reference frames.

**Part 2: Relationship with JavaScript, HTML, CSS**

This C++ code is part of the implementation of the WebCodecs API, which is exposed to JavaScript.

- **JavaScript:** The code interacts directly with JavaScript through callbacks. The `output_callback_` is a key example where encoded video chunks are passed back to the JavaScript environment. The `isConfigSupported` function is also directly invoked by JavaScript.
- **HTML:** While this code doesn't directly manipulate HTML, the WebCodecs API enables JavaScript to encode video captured from HTML elements like `<video>` or `<canvas>`.
- **CSS:** CSS styles might affect the rendering of the original video source before it's encoded, but this code doesn't directly interact with CSS.

**Part 3: Logical Reasoning (Assumptions, Inputs, Outputs)**

- **Assumption:** The input to the encoder is a `media::VideoFrame`.
- **Input (Hypothetical):** A JavaScript application calls `videoEncoder.encode(videoFrame)`. This triggers the `ProcessEncode` function in the C++ code.
- **Output (Hypothetical):** The encoder processes the frame and, upon completion, calls the `output_callback_` with an `EncodedVideoChunk`. This chunk is then passed back to the JavaScript application.

**Part 4: User and Programming Errors**

- **User Error:** Providing an unsupported video codec configuration to the `configure()` method will result in a `NotSupportedError` DOM exception.
- **Programming Error:** Incorrectly managing `VideoEncoderBuffer` objects (e.g., using a buffer belonging to a different encoder) will lead to a `NotAllowedError` DOM exception.

**Part 5: User Operations and Debugging**

A user navigating a website that uses the WebCodecs API for video encoding could trigger this code.

**Debugging Clue:** The `TRACE_EVENT` calls are crucial for performance monitoring and debugging. They allow developers to track the lifecycle of encoding requests.

**Part 6: Summarization (for Part 2 of 3)**

The provided code snippet focuses on the core encoding process within the `VideoEncoder` class. It manages the interaction with the underlying media encoder, handles frame readback when necessary (especially for GPU-backed frames), and ensures the encoded output is passed back to the JavaScript layer via a callback. It also handles error conditions and performs checks related to reference frame management.
好的，根据您提供的代码片段，这是 `blink/renderer/modules/webcodecs/video_encoder.cc` 文件的第二部分，主要负责 **实际的视频编码处理、帧回读以及与底层媒体编码器的交互**。

以下是该部分代码功能的归纳：

**核心功能：**

1. **编码请求处理 (`ProcessEncode`):**
   - 接收并处理来自 JavaScript 的编码请求。
   - 检查 `updateBuffer` 和 `referenceBuffers` 的所有权，防止使用其他编码器的 buffer。
   - 获取要编码的 `media::VideoFrame`。
   - 创建编码选项 (`CreateEncodeOptions`)，例如是否为关键帧。
   - 处理需要回读的帧（例如，GPU 纹理帧），将回读操作委托给 `BackgroundReadback` 或使用 `WebGraphicsContext3DVideoFramePool`。
   - 处理带有 Alpha 通道的帧，将其转换为不带 Alpha 通道的帧。
   - 调用底层媒体编码器的 `Encode` 方法进行实际编码。
   - 在编码完成后调用 `OnEncodeDone`。

2. **帧回读 (`StartReadback`, `OnReadbackDone`):**
   - 负责将 GPU 纹理帧或无法直接被底层编码器处理的帧复制到 CPU 内存中。
   - 尝试使用 `WebGraphicsContext3DVideoFramePool` 进行加速回读（通过 GpuMemoryBuffer）。
   - 如果加速回读失败或不可用，则使用 `BackgroundReadback` 进行回读。
   - `OnReadbackDone` 在回读完成后被调用，继续执行编码流程。

3. **配置和重配置处理 (`ProcessConfigure`, `ProcessReconfigure`):**
   - `ProcessConfigure`: 处理初始配置请求，验证编解码器支持，并创建或获取底层媒体编码器。
   - `ProcessReconfigure`: 处理重新配置请求，尝试在不重新初始化底层编码器的情况下更改参数。如果重配置失败，则回退到重新配置。

4. **底层媒体编码器交互：**
   - 在 `Initialize` 中创建并初始化 `media::VideoEncoder` 实例。
   - 通过 `media_encoder_->Encode` 发送编码请求。
   - 通过 `media_encoder_->Flush` 刷新编码器。
   - 通过 `media_encoder_->ChangeOptions` 更改编码器选项。
   - 接收来自底层编码器的信息变更回调 (`OnMediaEncoderInfoChanged`)，例如编码器名称、是否为硬件加速、最大活跃编码数等。

5. **编码完成回调 (`OnEncodeDone`):**
   - 在底层媒体编码器完成编码后被调用。
   - 检查是否发生错误，如果发生错误则调用 `ReportError`。
   - 递减活跃编码计数器。
   - 继续处理下一个请求 (`ProcessRequests`).

6. **输出回调 (`CallOutputCallback`):**
   - 接收来自底层媒体编码器的编码输出数据。
   - 将编码数据封装成 `EncodedVideoChunk` 对象。
   - 添加元数据信息，例如 SVC metadata、DecoderConfig (包含编解码器描述信息)。
   - 通过 JavaScript 回调 (`output_callback_`) 将 `EncodedVideoChunk` 传递回 JavaScript 环境。

7. **编码器信息变更处理 (`OnMediaEncoderInfoChanged`):**
   - 当底层媒体编码器的信息发生变化时被调用。
   - 更新编码器是否为硬件加速的标志 (`is_platform_encoder_`)。
   - 计算最大活跃编码数 (`max_active_encodes_`)。
   - 如果启用了手动参考帧控制，则根据底层编码器提供的数量创建 `VideoEncoderBuffer` 对象。

8. **查询配置支持 (`isConfigSupported`):**
   - 静态方法，用于判断给定的 `VideoEncoderConfig` 是否被支持。
   - 分别检测硬件编码器和软件编码器的支持情况。

9. **获取所有帧缓冲区 (`getAllFrameBuffers`):**
   - 返回当前编码器管理的所有帧缓冲区，仅在启用了手动参考帧控制时可用。

**与 JavaScript, HTML, CSS 的关系举例：**

* **JavaScript:**
    *  JavaScript 调用 `videoEncoder.encode(videoFrame, options)` 会最终触发 `ProcessEncode` 方法。
    *  编码完成后，`CallOutputCallback` 将生成的 `EncodedVideoChunk` 对象通过 JavaScript 回调函数返回给 JavaScript 代码。
    *  JavaScript 可以通过 `VideoEncoder.isConfigSupported(config)` 查询特定编码配置是否受支持，这会调用 C++ 的 `VideoEncoder::isConfigSupported` 方法。
    *  如果配置过程中发生错误（例如不支持的编解码器），会抛出 JavaScript 异常 (例如 `NotSupportedError`)。
* **HTML:**
    *  HTML 中的 `<video>` 元素或 `<canvas>` 元素可以作为视频编码的源。用户通过 JavaScript 获取这些元素中的视频帧数据，并传递给 `VideoEncoder` 进行编码。
* **CSS:**
    *  CSS 样式可能会影响 `<video>` 或 `<canvas>` 元素的渲染，但此 C++ 代码主要处理编码逻辑，不直接与 CSS 交互。

**逻辑推理的假设输入与输出：**

**假设输入:**

*  一个已配置的 `VideoEncoder` 对象。
*  一个来自 `<canvas>` 元素的 `media::VideoFrame` 对象，需要进行编码。
*  编码选项 `EncodeOptions`，例如 `keyFrame: true`。

**输出:**

*  如果编码成功，`CallOutputCallback` 会被调用，并向 JavaScript 返回一个包含关键帧数据的 `EncodedVideoChunk` 对象。
*  如果编码失败（例如硬件编码器出错），`OnEncodeDone` 会接收到错误状态，并通过 `ReportError` 记录错误。JavaScript 侧可能会收到一个错误事件。

**用户或编程常见的使用错误举例：**

* **用户错误:** 尝试配置一个浏览器不支持的视频编解码器 (例如，一个非常新的或罕见的编解码器)。这会导致在 `ProcessConfigure` 中 `VerifyCodecSupport` 失败，并抛出 `NotSupportedError` 异常。
* **编程错误:** 在启用了手动参考帧控制的情况下，错误地使用了不属于当前 `VideoEncoder` 实例的 `VideoEncoderBuffer` 对象作为 `updateBuffer` 或 `referenceBuffers`。这会在 `ProcessEncode` 中被检测到，并抛出 `NotAllowedError` 异常。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户访问一个使用了 WebCodecs API 的网页。**
2. **网页 JavaScript 代码创建了一个 `VideoEncoder` 实例。**
3. **JavaScript 代码调用 `encoder.configure(config)` 方法，触发 C++ 的 `ProcessConfigure`。**
4. **用户通过网页上的交互（例如点击按钮，开始录制）触发 JavaScript 代码调用 `encoder.encode(videoFrame)` 方法。**
5. **`encoder.encode()` 调用会传递到 C++ 的 `ProcessEncode` 方法。**
6. **在 `ProcessEncode` 中，如果需要回读（例如，`videoFrame` 来自 GPU 纹理），则会调用 `StartReadback`。**
7. **底层媒体编码器被初始化并执行编码操作。**
8. **编码完成后，`OnEncodeDone` 被调用。**
9. **如果编码成功，`CallOutputCallback` 将编码后的数据返回给 JavaScript。**

**总结：**

这部分代码是 `VideoEncoder` 类的核心逻辑，负责接收和处理编码请求，管理帧的回读操作，与底层的媒体编码器进行交互，并在编码完成后将数据回调给 JavaScript。它处理了配置、编码、重配置等关键流程，并包含了错误处理和性能监控的相关逻辑。这段代码是 WebCodecs API 在 Chromium 中实现视频编码功能的重要组成部分。

### 提示词
```
这是目录为blink/renderer/modules/webcodecs/video_encoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
ndTracing();

    self->blocking_request_in_progress_ = nullptr;
    self->ProcessRequests();
  };
  if (!encoder_metrics_provider_) {
    encoder_metrics_provider_ = CreateVideoEncoderMetricsProvider();
  }
  encoder_metrics_provider_->Initialize(
      active_config_->profile, active_config_->options.frame_size,
      is_platform_encoder,
      active_config_->options.scalability_mode.value_or(
          media::SVCScalabilityMode::kL1T1));
  media_encoder_->Initialize(
      active_config_->profile, active_config_->options, std::move(info_cb),
      std::move(output_cb),
      ConvertToBaseOnceCallback(CrossThreadBindOnce(
          done_callback, MakeUnwrappingCrossThreadWeakHandle(this),
          MakeUnwrappingCrossThreadHandle(request), active_config_->codec,
          is_platform_encoder)));
}

std::unique_ptr<media::VideoEncoderMetricsProvider>
VideoEncoder::CreateVideoEncoderMetricsProvider() const {
  mojo::PendingRemote<media::mojom::VideoEncoderMetricsProvider>
      video_encoder_metrics_provider;
  LocalDOMWindow* window = DomWindow();
  LocalFrame* local_frame = window ? window->GetFrame() : nullptr;
  // There is no DOM frame if WebCodecs runs in a service worker.
  if (local_frame) {
    local_frame->GetBrowserInterfaceBroker().GetInterface(
        video_encoder_metrics_provider.InitWithNewPipeAndPassReceiver());
  } else {
    Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
        video_encoder_metrics_provider.InitWithNewPipeAndPassReceiver());
  }
  return base::MakeRefCounted<media::MojoVideoEncoderMetricsProviderFactory>(
             media::mojom::VideoEncoderUseCase::kWebCodecs,
             std::move(video_encoder_metrics_provider))
      ->CreateVideoEncoderMetricsProvider();
}

bool VideoEncoder::CanReconfigure(ParsedConfig& original_config,
                                  ParsedConfig& new_config) {
  // Reconfigure is intended for things that don't require changing underlying
  // codec implementation and can be changed on the fly.
  return original_config.codec == new_config.codec &&
         original_config.profile == new_config.profile &&
         original_config.level == new_config.level &&
         original_config.hw_pref == new_config.hw_pref;
}

const AtomicString& VideoEncoder::InterfaceName() const {
  return event_target_names::kVideoEncoder;
}

bool VideoEncoder::HasPendingActivity() const {
  return (active_encodes_ > 0) || Base::HasPendingActivity();
}

void VideoEncoder::Trace(Visitor* visitor) const {
  visitor->Trace(background_readback_);
  visitor->Trace(frame_reference_buffers_);
  Base::Trace(visitor);
}

void VideoEncoder::ReportError(const char* error_message,
                               const media::EncoderStatus& status,
                               bool is_error_message_from_software_codec) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(!status.is_ok());

  // ReportError() can be called before |encoder_metrics_provider_| is created
  // in media::VideoEncoder::Initialize() (e.g. there is no available
  // media::VideoEncoder). Since the case is about webrtc::VideoEncoder failure,
  // we don't record it.
  if (encoder_metrics_provider_) {
    encoder_metrics_provider_->SetError(status);
  }

  // We don't use `is_platform_encoder_` here since it may not match where the
  // error is coming from in the case of a pending configuration change.
  HandleError(
      is_error_message_from_software_codec
          ? logger_->MakeSoftwareCodecOperationError(error_message, status)
          : logger_->MakeOperationError(error_message, status));
}

bool VideoEncoder::ReadyToProcessNextRequest() {
  if (active_encodes_ >= max_active_encodes_)
    return false;

  return Base::ReadyToProcessNextRequest();
}

bool VideoEncoder::StartReadback(scoped_refptr<media::VideoFrame> frame,
                                 ReadbackDoneCallback result_cb) {
  // TODO(crbug.com/1195433): Once support for alpha channel encoding is
  // implemented, |force_opaque| must be set based on the
  // VideoEncoderConfig.
  //
  // TODO(crbug.com/1116564): If we ever support high bit depth read back, this
  // path should do something different based on options.bit_depth.
  const bool can_use_gmb =
      active_config_->options.subsampling != media::VideoChromaSampling::k444 &&
      !disable_accelerated_frame_pool_ &&
      CanUseGpuMemoryBufferReadback(frame->format(), /*force_opaque=*/true);
  if (can_use_gmb && !accelerated_frame_pool_) {
    if (auto wrapper = SharedGpuContext::ContextProviderWrapper()) {
      accelerated_frame_pool_ =
          std::make_unique<WebGraphicsContext3DVideoFramePool>(wrapper);
    }
  }

  auto [pool_result_cb, background_result_cb] =
      base::SplitOnceCallback(std::move(result_cb));
  if (can_use_gmb && accelerated_frame_pool_) {
    // CopyRGBATextureToVideoFrame() operates on mailboxes and
    // not frames, so we must manually copy over properties relevant to
    // the encoder. We amend result callback to do exactly that.
    auto metadata_fix_lambda = [](scoped_refptr<media::VideoFrame> txt_frame,
                                  scoped_refptr<media::VideoFrame> result_frame)
        -> scoped_refptr<media::VideoFrame> {
      if (!result_frame)
        return result_frame;
      result_frame->set_timestamp(txt_frame->timestamp());
      result_frame->metadata().MergeMetadataFrom(txt_frame->metadata());
      result_frame->metadata().ClearTextureFrameMetadata();
      return result_frame;
    };

    auto callback_chain = ConvertToBaseOnceCallback(
                              CrossThreadBindOnce(metadata_fix_lambda, frame))
                              .Then(std::move(pool_result_cb));

#if BUILDFLAG(IS_APPLE)
    // The Apple hardware encoder properly sets output color spaces, so we can
    // round trip through the encoder and decoder w/o downgrading to BT.601.
    constexpr auto kDstColorSpace = gfx::ColorSpace::CreateREC709();
#else
    // When doing RGBA to YUVA conversion using `accelerated_frame_pool_`, use
    // sRGB primaries and the 601 YUV matrix. Note that this is subtly
    // different from the 601 gfx::ColorSpace because the 601 gfx::ColorSpace
    // has different (non-sRGB) primaries.
    //
    // This is necessary for our tests to pass since encoders will default to
    // BT.601 when the color space information isn't told to the encoder. When
    // coming back through the decoder it pulls out the embedded color space
    // information instead of what's provided in the config.
    //
    // https://crbug.com/1258245, https://crbug.com/1377842
    constexpr gfx::ColorSpace kDstColorSpace(
        gfx::ColorSpace::PrimaryID::BT709, gfx::ColorSpace::TransferID::SRGB,
        gfx::ColorSpace::MatrixID::SMPTE170M,
        gfx::ColorSpace::RangeID::LIMITED);
#endif

    TRACE_EVENT_NESTABLE_ASYNC_BEGIN1("media", "CopyRGBATextureToVideoFrame",
                                      this, "timestamp", frame->timestamp());
    if (accelerated_frame_pool_->CopyRGBATextureToVideoFrame(
            frame->coded_size(), frame->shared_image(),
            frame->acquire_sync_token(), kDstColorSpace,
            std::move(callback_chain))) {
      return true;
    }

    TRACE_EVENT_NESTABLE_ASYNC_END0("media", "CopyRGBATextureToVideoFrame",
                                    this);

    // Error occurred, fall through to normal readback path below.
    disable_accelerated_frame_pool_ = true;
    accelerated_frame_pool_.reset();
  }

  if (!background_readback_)
    background_readback_ = BackgroundReadback::From(*GetExecutionContext());

  if (background_readback_) {
    background_readback_->ReadbackTextureBackedFrameToMemoryFrame(
        std::move(frame), std::move(background_result_cb));
    return true;
  }

  // Oh well, none of our readback mechanisms were able to succeed.
  return false;
}

void VideoEncoder::ProcessEncode(Request* request) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK_EQ(state_, V8CodecState::Enum::kConfigured);
  DCHECK(media_encoder_);
  DCHECK_EQ(request->type, Request::Type::kEncode);
  DCHECK_GT(requested_encodes_, 0u);

  if (request->encodeOpts->hasUpdateBuffer()) {
    auto* buffer = request->encodeOpts->updateBuffer();
    if (buffer->owner() != this) {
      QueueHandleError(MakeGarbageCollected<DOMException>(
          DOMExceptionCode::kNotAllowedError,
          "updateBuffer doesn't belong to this encoder"));
      request->EndTracing();
      return;
    }
  }
  if (request->encodeOpts->hasReferenceBuffers()) {
    for (auto& buffer : request->encodeOpts->referenceBuffers()) {
      if (buffer->owner() != this) {
        QueueHandleError(MakeGarbageCollected<DOMException>(
            DOMExceptionCode::kNotAllowedError,
            "one of referenceBuffers doesn't belong to this encoder"));
        request->EndTracing();
        return;
      }
    }
  }

  auto frame = request->input->frame();
  auto encode_options = CreateEncodeOptions(request);
  active_encodes_++;
  auto encode_done_callback = ConvertToBaseOnceCallback(CrossThreadBindOnce(
      &VideoEncoder::OnEncodeDone, MakeUnwrappingCrossThreadWeakHandle(this),
      MakeUnwrappingCrossThreadHandle(request)));

  auto blink_timestamp = base::Microseconds(request->input->timestamp());
  if (frame->timestamp() != blink_timestamp &&
      base::FeatureList::IsEnabled(kUseBlinkTimestampForEncoding)) {
    // If blink::VideFrame has the timestamp different from media::VideoFrame
    // we need to use blink's timestamp, because this is what JS-devs observe
    // and it's expected to be the timestamp of the EncodedVideoChunk.
    // More context about timestamp adjustments: crbug.com/333420614,
    // crbug.com/350780007
    frame = media::VideoFrame::WrapVideoFrame(
        frame, frame->format(), frame->visible_rect(), frame->natural_size());
    frame->set_timestamp(blink_timestamp);
  }

  if (frame->metadata().frame_duration) {
    frame_metadata_[frame->timestamp()] =
        FrameMetadata{*frame->metadata().frame_duration};
  }
  request->StartTracingVideoEncode(encode_options.key_frame,
                                   frame->timestamp());

  bool mappable = frame->IsMappable() || frame->HasMappableGpuBuffer();

  // Currently underlying encoders can't handle frame backed by textures,
  // so let's readback pixel data to CPU memory.
  // TODO(crbug.com/1229845): We shouldn't be reading back frames here.
  if (!mappable) {
    DCHECK(frame->HasSharedImage());
    // Stall request processing while we wait for the copy to complete. It'd
    // be nice to not have to do this, but currently the request processing
    // loop must execute synchronously or flush() will miss frames.
    //
    // Note: Set this before calling StartReadback() since callbacks could
    // resolve synchronously.
    blocking_request_in_progress_ = request;

    auto readback_done_callback = WTF::BindOnce(
        &VideoEncoder::OnReadbackDone, WrapWeakPersistent(this),
        WrapPersistent(request), frame, std::move(encode_done_callback));

    if (StartReadback(std::move(frame), std::move(readback_done_callback))) {
      request->input->close();
    } else {
      blocking_request_in_progress_ = nullptr;
      callback_runner_->PostTask(
          FROM_HERE, ConvertToBaseOnceCallback(CrossThreadBindOnce(
                         &VideoEncoder::OnEncodeDone,
                         MakeUnwrappingCrossThreadWeakHandle(this),
                         MakeUnwrappingCrossThreadHandle(request),
                         media::EncoderStatus(
                             media::EncoderStatus::Codes::kEncoderFailedEncode,
                             "Can't readback frame textures."))));
    }
    return;
  }

  // Currently underlying encoders can't handle alpha channel, so let's
  // wrap a frame with an alpha channel into a frame without it.
  // For example such frames can come from 2D canvas context with alpha = true.
  DCHECK(mappable);
  if (media::IsYuvPlanar(frame->format()) &&
      !media::IsOpaque(frame->format())) {
    frame = media::VideoFrame::WrapVideoFrame(
        frame, ToOpaqueMediaPixelFormat(frame->format()), frame->visible_rect(),
        frame->natural_size());
  }

  --requested_encodes_;
  ScheduleDequeueEvent();
  media_encoder_->Encode(frame, encode_options,
                         std::move(encode_done_callback));

  // We passed a copy of frame() above, so this should be safe to close here.
  request->input->close();
}

media::VideoEncoder::EncodeOptions VideoEncoder::CreateEncodeOptions(
    Request* request) {
  media::VideoEncoder::EncodeOptions result;
  result.key_frame = request->encodeOpts->keyFrame();
  if (request->encodeOpts->hasUpdateBuffer()) {
    result.update_buffer = request->encodeOpts->updateBuffer()->internal_id();
  }
  if (request->encodeOpts->hasReferenceBuffers()) {
    for (auto& buffer : request->encodeOpts->referenceBuffers()) {
      result.reference_buffers.push_back(buffer->internal_id());
    }
  }
  switch (active_config_->codec) {
    case media::VideoCodec::kAV1: {
      if (!active_config_->options.bitrate.has_value() ||
          active_config_->options.bitrate->mode() !=
              media::Bitrate::Mode::kExternal) {
        break;
      }
      if (!request->encodeOpts->hasAv1() ||
          !request->encodeOpts->av1()->hasQuantizer()) {
        break;
      }
      result.quantizer = request->encodeOpts->av1()->quantizer();
      break;
    }
    case media::VideoCodec::kVP9: {
      if (!active_config_->options.bitrate.has_value() ||
          active_config_->options.bitrate->mode() !=
              media::Bitrate::Mode::kExternal) {
        break;
      }
      if (!request->encodeOpts->hasVp9() ||
          !request->encodeOpts->vp9()->hasQuantizer()) {
        break;
      }
      result.quantizer = request->encodeOpts->vp9()->quantizer();
      break;
    }
    case media::VideoCodec::kH264:
      if (!active_config_->options.bitrate.has_value() ||
          active_config_->options.bitrate->mode() !=
              media::Bitrate::Mode::kExternal) {
        break;
      }
      if (!request->encodeOpts->hasAvc() ||
          !request->encodeOpts->avc()->hasQuantizer()) {
        break;
      }
      result.quantizer = request->encodeOpts->avc()->quantizer();
      break;
    case media::VideoCodec::kVP8:
    default:
      break;
  }
  return result;
}

void VideoEncoder::OnReadbackDone(
    Request* request,
    scoped_refptr<media::VideoFrame> txt_frame,
    media::VideoEncoder::EncoderStatusCB done_callback,
    scoped_refptr<media::VideoFrame> result_frame) {
  TRACE_EVENT_NESTABLE_ASYNC_END0("media", "CopyRGBATextureToVideoFrame", this);
  if (reset_count_ != request->reset_count) {
    return;
  }

  if (!result_frame) {
    callback_runner_->PostTask(
        FROM_HERE, ConvertToBaseOnceCallback(CrossThreadBindOnce(
                       std::move(done_callback),
                       media::EncoderStatus(
                           media::EncoderStatus::Codes::kEncoderFailedEncode,
                           "Can't readback frame textures."))));
    return;
  }

  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto encode_options = CreateEncodeOptions(request);
  --requested_encodes_;
  ScheduleDequeueEvent();
  blocking_request_in_progress_ = nullptr;
  media_encoder_->Encode(std::move(result_frame), encode_options,
                         std::move(done_callback));
  ProcessRequests();
}

void VideoEncoder::OnEncodeDone(Request* request, media::EncoderStatus status) {
  if (reset_count_ != request->reset_count) {
    request->EndTracing(/*aborted=*/true);
    return;
  }
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  active_encodes_--;
  if (!status.is_ok()) {
    ReportError("Encoding error.", std::move(status),
                /*is_error_message_from_software_codec=*/!is_platform_encoder_);
  }
  request->EndTracing();
  ProcessRequests();
}

void VideoEncoder::ProcessConfigure(Request* request) {
  DCHECK_NE(state_.AsEnum(), V8CodecState::Enum::kClosed);
  DCHECK_EQ(request->type, Request::Type::kConfigure);
  DCHECK(request->config);
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  request->StartTracing();

  blocking_request_in_progress_ = request;

  active_config_ = request->config;
  String js_error_message;
  if (!VerifyCodecSupport(active_config_, &js_error_message)) {
    QueueHandleError(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError, js_error_message));
    request->EndTracing();
    return;
  }

  // TODO(crbug.com/347676170): remove this hack when we make
  // getAllFrameBuffers() async and can asynchronously get the number of
  // encoder buffers.
  if (active_config_->options.manual_reference_buffer_control &&
      active_config_->codec == media::VideoCodec::kAV1) {
    frame_reference_buffers_.clear();
    for (size_t i = 0; i < 3; ++i) {
      auto* buffer = MakeGarbageCollected<VideoEncoderBuffer>(this, i);
      frame_reference_buffers_.push_back(buffer);
    }
  }

  if (active_config_->hw_pref == HardwarePreference::kPreferSoftware &&
      !media::MayHaveAndAllowSelectOSSoftwareEncoder(active_config_->codec)) {
    ContinueConfigureWithGpuFactories(request, nullptr);
    return;
  }

  RetrieveGpuFactoriesWithKnownEncoderSupport(
      CrossThreadBindOnce(&VideoEncoder::ContinueConfigureWithGpuFactories,
                          MakeUnwrappingCrossThreadWeakHandle(this),
                          MakeUnwrappingCrossThreadHandle(request)));
}

void VideoEncoder::ProcessReconfigure(Request* request) {
  DCHECK_EQ(state_.AsEnum(), V8CodecState::Enum::kConfigured);
  DCHECK_EQ(request->type, Request::Type::kReconfigure);
  DCHECK(request->config);
  DCHECK(media_encoder_);
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  request->StartTracing();

  String js_error_message;
  if (!VerifyCodecSupport(request->config, &js_error_message)) {
    QueueHandleError(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kNotSupportedError, js_error_message));
    request->EndTracing();
    return;
  }

  auto reconf_done_callback = [](VideoEncoder* self, Request* req,
                                 media::EncoderStatus status) {
    if (!self || self->reset_count_ != req->reset_count) {
      req->EndTracing(/*aborted=*/true);
      return;
    }
    DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
    DCHECK(self->active_config_);

    req->EndTracing();

    if (status.is_ok()) {
      self->blocking_request_in_progress_ = nullptr;
      self->ProcessRequests();
    } else {
      // Reconfiguration failed. Either encoder doesn't support changing options
      // or it didn't like this particular change. Let's try to configure it
      // from scratch.
      req->type = Request::Type::kConfigure;
      self->ProcessConfigure(req);
    }
  };

  auto flush_done_callback = [](VideoEncoder* self, Request* req,
                                decltype(reconf_done_callback) reconf_callback,
                                bool is_platform_encoder,
                                media::EncoderStatus status) {
    if (!self || self->reset_count_ != req->reset_count) {
      req->EndTracing(/*aborted=*/true);
      return;
    }
    DCHECK_CALLED_ON_VALID_SEQUENCE(self->sequence_checker_);
    if (!status.is_ok()) {
      self->ReportError(
          "Encoder initialization error.", std::move(status),
          /*is_error_message_from_software_codec=*/!is_platform_encoder);
      self->blocking_request_in_progress_ = nullptr;
      req->EndTracing();
      return;
    }

    self->active_config_ = req->config;

    auto output_cb =
        ConvertToBaseRepeatingCallback(WTF::CrossThreadBindRepeating(
            &VideoEncoder::CallOutputCallback,
            MakeUnwrappingCrossThreadWeakHandle(self),
            // We can't use |active_config_| from |this| because it can change
            // by the time the callback is executed.
            MakeUnwrappingCrossThreadHandle(self->active_config_.Get()),
            self->reset_count_));

    if (!self->encoder_metrics_provider_) {
      self->encoder_metrics_provider_ =
          self->CreateVideoEncoderMetricsProvider();
    }
    self->encoder_metrics_provider_->Initialize(
        self->active_config_->profile, self->active_config_->options.frame_size,
        is_platform_encoder,
        self->active_config_->options.scalability_mode.value_or(
            media::SVCScalabilityMode::kL1T1));
    self->first_output_after_configure_ = true;
    self->media_encoder_->ChangeOptions(
        self->active_config_->options, std::move(output_cb),
        ConvertToBaseOnceCallback(CrossThreadBindOnce(
            reconf_callback, MakeUnwrappingCrossThreadWeakHandle(self),
            MakeUnwrappingCrossThreadHandle(req))));
  };

  blocking_request_in_progress_ = request;
  media_encoder_->Flush(WTF::BindOnce(
      flush_done_callback, MakeUnwrappingCrossThreadWeakHandle(this),
      MakeUnwrappingCrossThreadHandle(request), std::move(reconf_done_callback),
      is_platform_encoder_));
}

void VideoEncoder::OnMediaEncoderInfoChanged(
    const media::VideoEncoderInfo& encoder_info) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (encoder_info.is_hardware_accelerated)
    ApplyCodecPressure();
  else
    ReleaseCodecPressure();

  media::MediaLog* log = logger_->log();
  log->SetProperty<media::MediaLogProperty::kVideoEncoderName>(
      encoder_info.implementation_name);
  log->SetProperty<media::MediaLogProperty::kIsPlatformVideoEncoder>(
      encoder_info.is_hardware_accelerated);

  is_platform_encoder_ = encoder_info.is_hardware_accelerated;
  max_active_encodes_ = ComputeMaxActiveEncodes(encoder_info.frame_delay,
                                                encoder_info.input_capacity);
  if (active_config_->options.manual_reference_buffer_control) {
    frame_reference_buffers_.clear();
    for (size_t i = 0; i < encoder_info.number_of_manual_reference_buffers;
         ++i) {
      auto* buffer = MakeGarbageCollected<VideoEncoderBuffer>(this, i);
      frame_reference_buffers_.push_back(buffer);
    }
  }
  // We may have increased our capacity for active encodes.
  ProcessRequests();
}

void VideoEncoder::CallOutputCallback(
    ParsedConfig* active_config,
    uint32_t reset_count,
    media::VideoEncoderOutput output,
    std::optional<media::VideoEncoder::CodecDescription> codec_desc) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(active_config);
  if (!script_state_->ContextIsValid() || !output_callback_ ||
      state_.AsEnum() != V8CodecState::Enum::kConfigured ||
      reset_count != reset_count_) {
    return;
  }

  MarkCodecActive();

  if (output.data.empty()) {
    // The encoder drops a frame.WebCodecs doesn't specify a way of signaling
    // a frame was dropped. For now, the output callback is not invoked for the
    // dropped frame. TODO(https://www.w3.org/TR/webcodecs/#encodedvideochunk):
    // Notify a client that a frame is dropped.
    return;
  }

  auto buffer = media::DecoderBuffer::FromArray(std::move(output.data));
  buffer->set_timestamp(output.timestamp);
  buffer->set_is_key_frame(output.key_frame);

  // Get duration from |frame_metadata_|.
  const auto it = frame_metadata_.find(output.timestamp);
  if (it != frame_metadata_.end()) {
    const auto duration = it->second.duration;
    if (!duration.is_zero() && duration != media::kNoTimestamp) {
      buffer->set_duration(duration);
    }

    // While encoding happens in presentation order, outputs may be out of order
    // for some codec configurations. The maximum number of reordered outputs is
    // 16, so we can clear everything before that.
    if (it - frame_metadata_.begin() > 16) {
      frame_metadata_.erase(frame_metadata_.begin(), it + 1);
    }
  }

  auto* chunk = MakeGarbageCollected<EncodedVideoChunk>(std::move(buffer));

  auto* metadata = EncodedVideoChunkMetadata::Create();
  if (active_config->options.scalability_mode.has_value()) {
    auto* svc_metadata = SvcOutputMetadata::Create();
    svc_metadata->setTemporalLayerId(output.temporal_id);
    metadata->setSvc(svc_metadata);
  }

  // TODO(https://crbug.com/1241448): All encoders should output color space.
  // For now, fallback to 601 since that is correct most often.
  gfx::ColorSpace output_color_space = output.color_space.IsValid()
                                           ? output.color_space
                                           : gfx::ColorSpace::CreateREC601();

  if (first_output_after_configure_ || codec_desc.has_value() ||
      output_color_space != last_output_color_space_) {
    first_output_after_configure_ = false;

    if (output_color_space != last_output_color_space_) {
// This should only fail when AndroidVideoEncodeAccelerator is used since it
// doesn't support color space changes. It's not worth plumbing a signal just
// for these DCHECKs, so disable them entirely.
#if !BUILDFLAG(IS_ANDROID)
      if (active_config->codec == media::VideoCodec::kH264) {
        DCHECK(active_config->options.avc.produce_annexb ||
               codec_desc.has_value());
      }
      DCHECK(output.key_frame) << "Encoders should generate a keyframe when "
                               << "changing color space";
#endif
      last_output_color_space_ = output_color_space;
    } else if (active_config->codec == media::VideoCodec::kH264) {
      DCHECK(active_config->options.avc.produce_annexb ||
             codec_desc.has_value());
    }

    auto encoded_size =
        output.encoded_size.value_or(active_config->options.frame_size);

    auto* decoder_config = VideoDecoderConfig::Create();
    decoder_config->setCodec(active_config->codec_string);
    decoder_config->setCodedHeight(encoded_size.height());
    decoder_config->setCodedWidth(encoded_size.width());

    if (active_config->display_size.has_value()) {
      decoder_config->setDisplayAspectHeight(
          active_config->display_size.value().height());
      decoder_config->setDisplayAspectWidth(
          active_config->display_size.value().width());
    }

    VideoColorSpace* color_space =
        MakeGarbageCollected<VideoColorSpace>(output_color_space);
    decoder_config->setColorSpace(color_space->toJSON());

    if (codec_desc.has_value()) {
      auto* desc_array_buf = DOMArrayBuffer::Create(codec_desc.value());
      decoder_config->setDescription(
          MakeGarbageCollected<AllowSharedBufferSource>(desc_array_buf));
    }
    metadata->setDecoderConfig(decoder_config);
  }

  encoder_metrics_provider_->IncrementEncodedFrameCount();

  TRACE_EVENT_BEGIN1(kCategory, GetTraceNames()->output.c_str(), "timestamp",
                     chunk->timestamp());

  ScriptState::Scope scope(script_state_);
  output_callback_->InvokeAndReportException(nullptr, chunk, metadata);

  TRACE_EVENT_END0(kCategory, GetTraceNames()->output.c_str());
}

void VideoEncoder::ResetInternal(DOMException* ex) {
  Base::ResetInternal(ex);
  active_encodes_ = 0;
}

void FindAnySupported(ScriptPromiseResolver<VideoEncoderSupport>* resolver,
                      const HeapVector<Member<VideoEncoderSupport>>& supports) {
  VideoEncoderSupport* result = nullptr;
  for (auto& support : supports) {
    result = support;
    if (result->supported()) {
      break;
    }
  }
  resolver->Resolve(result);
}

static void isConfigSupportedWithSoftwareOnly(
    ScriptState* script_state,
    base::OnceCallback<void(VideoEncoderSupport*)> callback,
    VideoEncoderSupport* support,
    VideoEncoderTraits::ParsedConfig* config) {
  std::unique_ptr<media::VideoEncoder> software_encoder;
  switch (config->codec) {
    case media::VideoCodec::kAV1:
      software_encoder = CreateAv1VideoEncoder();
      break;
    case media::VideoCodec::kVP8:
    case media::VideoCodec::kVP9:
      software_encoder = CreateVpxVideoEncoder();
      break;
    case media::VideoCodec::kH264:
      software_encoder = CreateOpenH264VideoEncoder();
      break;
    default:
      break;
  }
  if (!software_encoder) {
    support->setSupported(false);
    std::move(callback).Run(support);
    return;
  }

  auto done_callback =
      [](std::unique_ptr<media::VideoEncoder> encoder,
         WTF::CrossThreadOnceFunction<void(blink::VideoEncoderSupport*)>
             callback,
         scoped_refptr<base::SingleThreadTaskRunner> runner,
         VideoEncoderSupport* support, media::EncoderStatus status) {
        support->setSupported(status.is_ok());
        std::move(callback).Run(support);
        runner->DeleteSoon(FROM_HERE, std::move(encoder));
      };

  auto* context = ExecutionContext::From(script_state);
  auto runner = context->GetTaskRunner(TaskType::kInternalDefault);
  auto* software_encoder_raw = software_encoder.get();
  software_encoder_raw->Initialize(
      config->profile, config->options, /*info_cb=*/base::DoNothing(),
      /*output_cb=*/base::DoNothing(),
      ConvertToBaseOnceCallback(CrossThreadBindOnce(
          done_callback, std::move(software_encoder),
          CrossThreadBindOnce(std::move(callback)), std::move(runner),
          MakeUnwrappingCrossThreadHandle(support))));
}

static void isConfigSupportedWithHardwareOnly(
    WTF::CrossThreadOnceFunction<void(blink::VideoEncoderSupport*)> callback,
    VideoEncoderSupport* support,
    VideoEncoderTraits::ParsedConfig* config,
    media::GpuVideoAcceleratorFactories* gpu_factories) {
  auto required_encoder_type =
      GetRequiredEncoderType(config->profile, config->hw_pref);
  bool supported =
      IsAcceleratedConfigurationSupported(config->profile, config->options,
                                          gpu_factories, required_encoder_type)
          .is_ok();
  support->setSupported(supported);
  std::move(callback).Run(support);
}

// static
ScriptPromise<VideoEncoderSupport> VideoEncoder::isConfigSupported(
    ScriptState* script_state,
    const VideoEncoderConfig* config,
    ExceptionState& exception_state) {
  auto* parsed_config = ParseConfigStatic(config, exception_state);
  if (!parsed_config) {
    DCHECK(exception_state.HadException());
    return EmptyPromise();
  }
  auto* config_copy = CopyConfig(*config, *parsed_config);

  // Run very basic coarse synchronous validation
  String unused_js_error_message;
  if (!VerifyCodecSupportStatic(parsed_config, &unused_js_error_message)) {
    auto* support = VideoEncoderSupport::Create();
    support->setConfig(config_copy);
    support->setSupported(false);
    return ToResolvedPromise<VideoEncoderSupport>(script_state, support);
  }

  // Schedule tasks for determining hardware and software encoding support and
  // register them with HeapBarrierCallback.
  wtf_size_t num_callbacks = 0;
  if (parsed_config->hw_pref != HardwarePreference::kPreferSoftware ||
      media::MayHaveAndAllowSelectOSSoftwareEncoder(parsed_config->codec)) {
    ++num_callbacks;
  }
  if (parsed_config->hw_pref != HardwarePreference::kPreferHardware) {
    ++num_callbacks;
  }
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<VideoEncoderSupport>>(
          script_state);
  auto promise = resolver->Promise();
  auto find_any_callback = HeapBarrierCallback<VideoEncoderSupport>(
      num_callbacks,
      WTF::BindOnce(&FindAnySupported, WrapPersistent(resolver)));

  if (parsed_config->hw_pref != HardwarePreference::kPreferSoftware ||
      media::MayHaveAndAllowSelectOSSoftwareEncoder(parsed_config->codec)) {
    // Hardware support not denied, detect support by hardware encoders.
    auto* support = VideoEncoderSupport::Create();
    support->setConfig(config_copy);
    auto gpu_retrieved_callback =
        CrossThreadBindOnce(isConfigSupportedWithHardwareOnly,
                            CrossThreadBindOnce(find_any_callback),
                            MakeUnwrappingCrossThreadHandle(support),
                            MakeUnwrappingCrossThreadHandle(parsed_config));
    RetrieveGpuFactoriesWithKnownEncoderSupport(
        std::move(gpu_retrieved_callback));
  }

  if (parsed_config->hw_pref != HardwarePreference::kPreferHardware) {
    // Hardware support not required, detect support by software encoders.
    auto* support = VideoEncoderSupport::Create();
    support->setConfig(config_copy);
    isConfigSupportedWithSoftwareOnly(script_state, find_any_callback, support,
                                      parsed_config);
  }

  return promise;
}

HeapVector<Member<VideoEncoderBuffer>> VideoEncoder::getAllFrameBuffers(
    ScriptState*,
    ExceptionState& exception_state) {
  if (!active_config_->options.manual_reference_buffer_control) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "getAllFrame
```