Response:
The user wants a summary of the functionality of the provided C++ code snippet from `media_capabilities.cc`. This is the second part of a three-part file. I need to focus on the functionality within this specific snippet.

Here's a breakdown of the code's actions:

1. **`kState::Trace`**:  Handles tracing of members for debugging purposes.
2. **`MediaCapabilities::decodingInfo`**: This is the main function in this snippet. It handles requests for decoding capabilities.
    - It takes a `MediaDecodingConfiguration` as input, which specifies the media format to check.
    - It performs various validations on the input configuration.
    - It handles WebRTC specific decoding info requests.
    - It handles regular media source (`media-source`) requests, checking for MSE support.
    - It checks the validity of audio and video codecs.
    - It handles Encrypted Media Extensions (EME) requests via `GetEmeSupport`.
    - For non-EME requests, it checks audio and video configuration support.
    - It queries performance information using `GetPerfInfo`.
3. **`MediaCapabilities::encodingInfo`**: Handles requests for encoding capabilities.
    - It takes a `MediaEncodingConfiguration` as input.
    - It validates the input configuration.
    - It handles WebRTC specific encoding info requests.
    - It handles "record" type encoding info requests via `MediaRecorderHandler`.
4. **`MediaCapabilities::EnsureLearningPredictors`**: Ensures that machine learning predictors for bad windows and NNRs are initialized.
5. **`MediaCapabilities::EnsurePerfHistoryService`**: Ensures the performance history service is available.
6. **`MediaCapabilities::EnsureWebrtcPerfHistoryService`**: Ensures the WebRTC performance history service is available.
7. **`MediaCapabilities::GetEmeSupport`**: Handles the logic for checking EME support.
    - It performs security checks.
    - It creates a `MediaKeySystemConfiguration` based on the input.
    - It uses `EncryptedMediaUtils` to request media key system access.
8. **`MediaCapabilities::GetPerfInfo`**: Retrieves performance information for decoding.
    - It handles audio-only cases.
    - It calls `GetPerfInfo_ML` if the machine learning experiment is enabled.
    - It queries the decode history service.
    - It calls `GetGpuFactoriesSupport` to check GPU acceleration if needed.
9. **`MediaCapabilities::GetPerfInfo_ML`**:  Retrieves performance information using machine learning predictors.
10. **`MediaCapabilities::GetGpuFactoriesSupport`**: Checks if GPU factories support the given decoding configuration.
11. **`MediaCapabilities::ResolveCallbackIfReady`**: Resolves the promise for a decoding info request once all necessary information is gathered.
这段代码是 `blink::MediaCapabilities` 类的实现的一部分，主要负责处理媒体（音频和视频）的解码和编码能力查询。这是第二部分，因此重点关注这部分代码所实现的功能。

**功能归纳:**

这段代码主要实现了以下功能：

1. **解码能力查询 (`decodingInfo`)**:
   - 接收一个 `MediaDecodingConfiguration` 对象，描述了需要查询的媒体解码配置信息（例如，编解码器、MIME 类型、分辨率、帧率、是否加密等）。
   - 对输入的解码配置进行各种有效性检查，例如 `IsValidMediaDecodingConfiguration`。
   - 针对 WebRTC 类型的解码配置，调用 `WebrtcDecodingInfoHandler` 获取解码信息。
   - 针对普通媒体源 (`media-source`)，检查是否支持 MSE (Media Source Extensions)。
   - 检查音频和视频编解码器是否有效 (`IsAudioCodecValid`, `IsVideoCodecValid`).
   - 如果配置涉及到加密媒体 (EME, Encrypted Media Extensions)，则调用 `GetEmeSupport` 来获取 EME 支持信息。
   - 如果是不加密的媒体，则检查音频和视频的配置是否被支持 (`IsAudioConfigurationSupported`, `IsVideoConfigurationSupported`)。
   - 调用 `GetPerfInfo` 来查询解码的性能信息，例如是否流畅和节能。

2. **编码能力查询 (`encodingInfo`)**:
   - 接收一个 `MediaEncodingConfiguration` 对象，描述了需要查询的媒体编码配置信息。
   - 对输入的编码配置进行有效性检查 (`IsValidMediaEncodingConfiguration`).
   - 针对 WebRTC 类型的编码配置，调用 `WebrtcEncodingInfoHandler` 获取编码信息。
   - 针对 "record" 类型的编码配置（用于媒体录制），调用 `MediaRecorderHandler` 获取编码信息。

3. **性能预测器初始化 (`EnsureLearningPredictors`)**:
   - 确保用于预测解码性能的机器学习模型（针对 "bad windows" 和 "NNRs"）已初始化。这些模型用于评估解码是否流畅。

4. **性能历史服务初始化 (`EnsurePerfHistoryService`, `EnsureWebrtcPerfHistoryService`)**:
   - 确保用于查询解码和 WebRTC 性能历史的服务已连接。这些服务存储了过往的解码/编码性能数据，用于辅助判断当前配置是否可行。

5. **EME 支持查询 (`GetEmeSupport`)**:
   - 处理加密媒体的解码能力查询。
   - 检查调用上下文是否安全（例如，是否在安全上下文下）。
   - 构建 `MediaKeySystemConfiguration` 对象，并调用 Chromium 的 EME 接口 `RequestMediaKeySystemAccess` 来查询特定密钥系统的支持情况。

6. **获取性能信息 (`GetPerfInfo`)**:
   - 针对给定的视频编解码器、profile、颜色空间和解码配置，从性能历史服务获取性能信息。
   - 如果启用了相关的机器学习实验，会调用 `GetPerfInfo_ML` 使用机器学习模型进行预测。
   - 如果需要并且满足条件，会调用 `GetGpuFactoriesSupport` 来检查 GPU 硬件加速的支持情况。

7. **机器学习性能预测 (`GetPerfInfo_ML`)**:
   - 使用之前初始化的机器学习模型 (`bad_window_predictor_`, `nnr_predictor_`) 来预测解码是否流畅。

8. **GPU 支持查询 (`GetGpuFactoriesSupport`)**:
   - 查询 GPU 视频加速工厂，以确定当前 GPU 是否支持给定的视频解码配置，从而判断解码是否节能。

9. **完成回调 (`ResolveCallbackIfReady`)**:
   - 当所有需要的性能信息（包括数据库查询、机器学习预测、GPU 支持情况）都返回后，将结果整合并解析 `decodingInfo` 请求的 Promise。

**与 JavaScript, HTML, CSS 的关系举例说明:**

- **JavaScript:**
    - `decodingInfo` 和 `encodingInfo` 方法对应着 JavaScript 中 `navigator.mediaCapabilities.decodingInfo()` 和 `navigator.mediaCapabilities.encodingInfo()` API。网站的 JavaScript 代码可以调用这些 API 来查询用户设备的媒体能力。
    ```javascript
    navigator.mediaCapabilities.decodingInfo({
      type: 'media-source',
      audio: {
        contentType: 'audio/mp4; codecs="mp4a.40.2"'
      },
      video: {
        contentType: 'video/mp4; codecs="avc1.42E01E"',
        width: 1920,
        height: 1080,
        framerate: 30
      }
    }).then(result => {
      console.log('Decoding support:', result.supported);
      console.log('Decoding smooth:', result.smooth);
      console.log('Decoding powerEfficient:', result.powerEfficient);
    });
    ```
    - EME 相关的逻辑与 JavaScript 中的 `HTMLMediaElement.requestMediaKeySystemAccess()` API 密切相关。 `GetEmeSupport` 的目标是判断给定的密钥系统和媒体配置是否被支持，这直接影响 `requestMediaKeySystemAccess()` 的成功与否。

- **HTML:**
    - `navigator.mediaCapabilities` API 通常在 HTML 页面中通过 `<script>` 标签引入的 JavaScript 代码中使用。
    - 媒体元素 `<video>` 和 `<audio>` 的 `src` 属性指定的媒体资源，其解码能力可以通过 `navigator.mediaCapabilities.decodingInfo()` 来预先查询，以避免加载不支持的资源。

- **CSS:**
    - CSS 本身不直接与 `navigator.mediaCapabilities` 交互。但是，查询到的媒体能力信息可以被 JavaScript 代码用来动态调整 HTML 元素的样式或行为。例如，如果 `decodingInfo` 返回不支持某个高分辨率视频，可以提示用户选择较低分辨率的版本，并使用 CSS 来隐藏高分辨率选项。

**逻辑推理的假设输入与输出:**

**假设输入 (针对 `decodingInfo`):**

```cpp
MediaDecodingConfiguration config;
config.setType("media-source");
MediaDecodingConfiguration_AudioConfiguration audio_config;
audio_config.setContentType("audio/aac");
config.setAudio(audio_config);
MediaDecodingConfiguration_VideoConfiguration video_config;
video_config.setContentType("video/h264");
video_config.setWidth(1920);
video_config.setHeight(1080);
video_config.setFramerate(30);
config.setVideo(video_config);
```

**预期输出 (理想情况下):**

如果设备支持解码 H.264 1080p30 的视频和 AAC 音频，且 MSE 也被支持，则 `decodingInfo` 最终会解析一个 `MediaCapabilitiesDecodingInfo` 对象，其属性可能为：

```
supported: true
smooth: true  // 假设解码性能足够流畅
powerEfficient: true // 假设可以使用硬件加速
keySystemAccess: nullptr // 因为没有配置加密信息
```

**用户或编程常见的使用错误举例:**

1. **MIME 类型错误:** 用户提供的 `contentType` 字符串不正确或浏览器不支持。例如，将音频的 `contentType` 设置为 "audio/mpeg" 而不是 "audio/mpeg; codecs=..."。这会导致 `IsValidMediaDecodingConfiguration` 返回错误，并抛出 `TypeError` 异常。

2. **编解码器名称错误:** 在 `contentType` 中指定的编解码器名称不正确或浏览器不支持。例如，`video/mp4; codecs="invalid-codec"`. 这会导致 `IsAudioCodecValid` 或 `IsVideoCodecValid` 返回错误，并在控制台输出警告信息。

3. **在非安全上下文中使用 EME:**  尝试在非 HTTPS 页面中调用 `decodingInfo` 查询加密媒体能力。这会导致 `GetEmeSupport` 抛出 `SecurityError` 异常，因为 EME 功能需要在安全上下文中才能使用。

4. **在 Worker 线程中使用 EME:** 尝试在 Service Worker 或 Web Worker 中调用 `decodingInfo` 查询加密媒体能力。 这会导致 `GetEmeSupport` 抛出 `InvalidStateError` 异常，因为 EME 在 Worker 上下文中不可用。

**用户操作到达此处的调试线索:**

1. **用户访问了一个包含媒体内容的网页。**
2. **网页的 JavaScript 代码调用了 `navigator.mediaCapabilities.decodingInfo()` 或 `navigator.mediaCapabilities.encodingInfo()` API。** 这可能是为了：
   - 提前判断用户设备是否支持播放或录制特定格式的媒体，以便做出相应的处理（例如，选择合适的媒体源，禁用不支持的功能）。
   - 在使用 Media Source Extensions 或 Media Recorder API 之前，验证配置是否可行。
   - 在使用加密媒体时，检查特定密钥系统是否可用。
3. **浏览器引擎接收到这个 API 调用，并将请求传递给 Blink 渲染引擎。**
4. **Blink 渲染引擎的 `MediaCapabilities` 对象接收到该请求。**
5. **根据请求的类型（解码或编码）和配置信息，会执行相应的逻辑，最终会进入这段代码中的 `decodingInfo` 或 `encodingInfo` 方法。**
6. **如果涉及到 EME，用户可能在之前与加密媒体内容交互过，例如尝试播放 DRM 保护的视频。** 这会触发 `requestMediaKeySystemAccess()` 调用，并最终可能通过 `GetEmeSupport` 检查设备对特定密钥系统的支持情况。

通过在 `decodingInfo` 或 `encodingInfo` 方法的入口处设置断点，或者在 `IsValidMediaDecodingConfiguration`、`GetEmeSupport` 等关键函数中设置断点，可以追踪用户操作如何一步步地到达这段代码。同时，查看浏览器的控制台输出，可以获取可能的错误信息。

Prompt: 
```
这是目录为blink/renderer/modules/media_capabilities/media_capabilities.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
kState::Trace(
    blink::Visitor* visitor) const {
  visitor->Trace(key_system_access);
  visitor->Trace(resolver);
}

ScriptPromise<MediaCapabilitiesDecodingInfo> MediaCapabilities::decodingInfo(
    ScriptState* script_state,
    const MediaDecodingConfiguration* config,
    ExceptionState& exception_state) {
  const base::TimeTicks request_time = base::TimeTicks::Now();

  if (config->hasKeySystemConfiguration()) {
    UseCounter::Count(
        ExecutionContext::From(script_state),
        WebFeature::kMediaCapabilitiesDecodingInfoWithKeySystemConfig);
  }

  const bool is_webrtc = config->type() == "webrtc";
  String message;
  if (!IsValidMediaDecodingConfiguration(config, is_webrtc, &message)) {
    exception_state.ThrowTypeError(message);
    return EmptyPromise();
  }
  // Validation errors should return above.
  DCHECK(message.empty());

  if (is_webrtc) {
    UseCounter::Count(ExecutionContext::From(script_state),
                      WebFeature::kMediaCapabilitiesDecodingInfoWebrtc);

    auto* resolver = MakeGarbageCollected<
        ScriptPromiseResolver<MediaCapabilitiesDecodingInfo>>(
        script_state, exception_state.GetContext());

    // IMPORTANT: Acquire the promise before potentially synchronously resolving
    // it in the code that follows. Otherwise the promise returned to JS will be
    // undefined. See comment above Promise() in script_promise_resolver.h
    auto promise = resolver->Promise();

    if (auto* handler = webrtc_decoding_info_handler_for_test_
                            ? webrtc_decoding_info_handler_for_test_.get()
                            : WebrtcDecodingInfoHandler::Instance()) {
      const int callback_id = CreateCallbackId();
      pending_cb_map_.insert(
          callback_id,
          MakeGarbageCollected<MediaCapabilities::PendingCallbackState>(
              resolver, nullptr, request_time, std::nullopt));

      std::optional<webrtc::SdpAudioFormat> sdp_audio_format =
          config->hasAudio()
              ? std::make_optional(ToSdpAudioFormat(config->audio()))
              : std::nullopt;

      std::optional<webrtc::SdpVideoFormat> sdp_video_format;
      bool spatial_scalability = false;
      media::VideoCodecProfile codec_profile =
          media::VIDEO_CODEC_PROFILE_UNKNOWN;
      int video_pixels = 0;
      int frames_per_second = 0;
      if (config->hasVideo()) {
        sdp_video_format =
            std::make_optional(ToSdpVideoFormat(config->video()));
        spatial_scalability = config->video()->hasSpatialScalability()
                                  ? config->video()->spatialScalability()
                                  : false;

        // Additional information needed for lookup in WebrtcVideoPerfHistory.
        codec_profile =
            WebRtcVideoFormatToMediaVideoCodecProfile(*sdp_video_format);
        video_pixels = config->video()->width() * config->video()->height();
        frames_per_second = static_cast<int>(config->video()->framerate());
      }
      media::mojom::blink::WebrtcPredictionFeaturesPtr features =
          media::mojom::blink::WebrtcPredictionFeatures::New(
              /*is_decode_stats=*/true,
              static_cast<media::mojom::blink::VideoCodecProfile>(
                  codec_profile),
              video_pixels, /*hardware_accelerated=*/false);

      handler->DecodingInfo(
          sdp_audio_format, sdp_video_format, spatial_scalability,
          WTF::BindOnce(&MediaCapabilities::OnWebrtcSupportInfo,
                        WrapPersistent(this), callback_id, std::move(features),
                        frames_per_second, OperationType::kDecoding));

      return promise;
    }
    // TODO(crbug.com/1187565): This should not happen unless we're out of
    // memory or something similar. Add UMA metric to count how often it
    // happens.
    DCHECK(false);
    DVLOG(2) << __func__ << " Could not get DecodingInfoHandler.";
    MediaCapabilitiesDecodingInfo* info = CreateDecodingInfoWith(false);
    resolver->Resolve(info);
    return promise;
  }

  String audio_mime_str;
  String audio_codec_str;
  if (config->hasAudio()) {
    DCHECK(config->audio()->hasContentType());
    bool valid_content_type = ParseContentType(
        config->audio()->contentType(), &audio_mime_str, &audio_codec_str);
    DCHECK(valid_content_type);
  }

  String video_mime_str;
  String video_codec_str;
  if (config->hasVideo()) {
    DCHECK(config->video()->hasContentType());
    bool valid_content_type = ParseContentType(
        config->video()->contentType(), &video_mime_str, &video_codec_str);
    DCHECK(valid_content_type);
  }

  // MSE support is cheap to check (regex matching). Do it first. Also, note
  // that MSE support is not implied by EME support, so do it irrespective of
  // whether we have a KeySystem configuration.
  if (config->type() == "media-source") {
    if ((config->hasAudio() &&
         !CheckMseSupport(audio_mime_str, audio_codec_str)) ||
        (config->hasVideo() &&
         !CheckMseSupport(video_mime_str, video_codec_str))) {
      // Unsupported EME queries should resolve with a null
      // MediaKeySystemAccess.
      MediaCapabilitiesDecodingInfo* info =
          CreateEncryptedDecodingInfoWith(false, nullptr);
      media_capabilities_identifiability_metrics::ReportDecodingInfoResult(
          ExecutionContext::From(script_state), config, info);
      return ToResolvedPromise<MediaCapabilitiesDecodingInfo>(script_state,
                                                              info);
    }
  }

  media::VideoCodec video_codec = media::VideoCodec::kUnknown;
  media::VideoCodecProfile video_profile = media::VIDEO_CODEC_PROFILE_UNKNOWN;

  if ((config->hasAudio() &&
       !IsAudioCodecValid(audio_mime_str, audio_codec_str, &message)) ||
      (config->hasVideo() &&
       !IsVideoCodecValid(video_mime_str, video_codec_str, &video_codec,
                          &video_profile, &message))) {
    DCHECK(!message.empty());
    if (ExecutionContext* execution_context =
            ExecutionContext::From(script_state)) {
      execution_context->AddConsoleMessage(mojom::ConsoleMessageSource::kOther,
                                           mojom::ConsoleMessageLevel::kWarning,
                                           message);
    }

    return CreateResolvedPromiseToDecodingInfoWith(false, script_state, config);
  }

  // Validation errors should return above.
  DCHECK(message.empty());

  // Fill in values for range, matrix since `VideoConfiguration` doesn't have
  // such concepts; these aren't used, but ensure VideoColorSpace.IsSpecified()
  // works as expected downstream.
  media::VideoColorSpace video_color_space;
  video_color_space.range = gfx::ColorSpace::RangeID::DERIVED;
  video_color_space.matrix = media::VideoColorSpace::MatrixID::BT709;

  gfx::HdrMetadataType hdr_metadata_type = gfx::HdrMetadataType::kNone;
  if (config->hasVideo()) {
    ParseDynamicRangeConfigurations(config->video(), &video_color_space,
                                    &hdr_metadata_type);
  }

  if (config->hasKeySystemConfiguration()) {
    // GetEmeSupport() will call the VideoDecodePerfHistory service after
    // receiving info about support for the configuration for encrypted content.
    return GetEmeSupport(script_state, video_codec, video_profile,
                         video_color_space, config, request_time,
                         exception_state);
  }

  bool audio_supported = true;

  if (config->hasAudio()) {
    audio_supported = IsAudioConfigurationSupported(
        config->audio(), audio_mime_str, audio_codec_str);
  }

  // No need to check video capabilities if video not included in configuration
  // or when audio is already known to be unsupported.
  if (!audio_supported || !config->hasVideo()) {
    return CreateResolvedPromiseToDecodingInfoWith(audio_supported,
                                                   script_state, config);
  }

  DCHECK(message.empty());
  DCHECK(config->hasVideo());

  // Return early for unsupported configurations.
  if (!IsVideoConfigurationSupported(video_mime_str, video_codec_str,
                                     video_color_space, hdr_metadata_type)) {
    return CreateResolvedPromiseToDecodingInfoWith(false, script_state, config);
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<MediaCapabilitiesDecodingInfo>>(
      script_state, exception_state.GetContext());

  // IMPORTANT: Acquire the promise before potentially synchronously resolving
  // it in the code that follows. Otherwise the promise returned to JS will be
  // undefined. See comment above Promise() in script_promise_resolver.h
  auto promise = resolver->Promise();

  GetPerfInfo(video_codec, video_profile, video_color_space, config,
              request_time, resolver, nullptr /* access */);

  return promise;
}

ScriptPromise<MediaCapabilitiesInfo> MediaCapabilities::encodingInfo(
    ScriptState* script_state,
    const MediaEncodingConfiguration* config,
    ExceptionState& exception_state) {
  if (config->type() == "record" &&
      !RuntimeEnabledFeatures::MediaCapabilitiesEncodingInfoEnabled()) {
    exception_state.ThrowTypeError(
        "The provided value 'record' is not a valid enum value of type "
        "MediaEncodingType.");
    return EmptyPromise();
    ;
  }

  const base::TimeTicks request_time = base::TimeTicks::Now();

  const bool is_webrtc = config->type() == "webrtc";
  String message;
  if (!IsValidMediaEncodingConfiguration(config, is_webrtc, &message)) {
    exception_state.ThrowTypeError(message);
    return EmptyPromise();
  }
  // Validation errors should return above.
  DCHECK(message.empty());

  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<MediaCapabilitiesInfo>>(
          script_state, exception_state.GetContext());

  // IMPORTANT: Acquire the promise before potentially synchronously resolving
  // it in the code that follows. Otherwise the promise returned to JS will be
  // undefined. See comment above Promise() in script_promise_resolver.h
  auto promise = resolver->Promise();

  if (is_webrtc) {
    UseCounter::Count(ExecutionContext::From(script_state),
                      WebFeature::kMediaCapabilitiesEncodingInfoWebrtc);

    if (auto* handler = webrtc_encoding_info_handler_for_test_
                            ? webrtc_encoding_info_handler_for_test_.get()
                            : WebrtcEncodingInfoHandler::Instance()) {
      const int callback_id = CreateCallbackId();
      pending_cb_map_.insert(
          callback_id,
          MakeGarbageCollected<MediaCapabilities::PendingCallbackState>(
              resolver, nullptr, request_time, std::nullopt));

      std::optional<webrtc::SdpAudioFormat> sdp_audio_format =
          config->hasAudio()
              ? std::make_optional(ToSdpAudioFormat(config->audio()))
              : std::nullopt;

      std::optional<webrtc::SdpVideoFormat> sdp_video_format;
      std::optional<String> scalability_mode;
      media::VideoCodecProfile codec_profile =
          media::VIDEO_CODEC_PROFILE_UNKNOWN;
      int video_pixels = 0;
      int frames_per_second = 0;
      if (config->hasVideo()) {
        sdp_video_format =
            std::make_optional(ToSdpVideoFormat(config->video()));
        scalability_mode =
            config->video()->hasScalabilityMode()
                ? std::make_optional(config->video()->scalabilityMode())
                : std::nullopt;

        // Additional information needed for lookup in WebrtcVideoPerfHistory.
        codec_profile =
            WebRtcVideoFormatToMediaVideoCodecProfile(*sdp_video_format);
        video_pixels = config->video()->width() * config->video()->height();
        frames_per_second = static_cast<int>(config->video()->framerate());
      }
      media::mojom::blink::WebrtcPredictionFeaturesPtr features =
          media::mojom::blink::WebrtcPredictionFeatures::New(
              /*is_decode_stats=*/false,
              static_cast<media::mojom::blink::VideoCodecProfile>(
                  codec_profile),
              video_pixels, /*hardware_accelerated=*/false);

      handler->EncodingInfo(
          sdp_audio_format, sdp_video_format, scalability_mode,
          WTF::BindOnce(&MediaCapabilities::OnWebrtcSupportInfo,
                        WrapPersistent(this), callback_id, std::move(features),
                        frames_per_second, OperationType::kEncoding));

      return promise;
    }
    // TODO(crbug.com/1187565): This should not happen unless we're out of
    // memory or something similar. Add UMA metric to count how often it
    // happens.
    DCHECK(false);
    DVLOG(2) << __func__ << " Could not get EncodingInfoHandler.";
    MediaCapabilitiesInfo* info = CreateEncodingInfoWith(false);
    resolver->Resolve(info);
    return promise;
  }

  DCHECK_EQ(config->type(), "record");
  DCHECK(RuntimeEnabledFeatures::MediaCapabilitiesEncodingInfoEnabled());

  auto task_runner = resolver->GetExecutionContext()->GetTaskRunner(
      TaskType::kInternalMediaRealTime);
  if (auto* handler = MakeGarbageCollected<MediaRecorderHandler>(
          task_runner, KeyFrameRequestProcessor::Configuration())) {
    task_runner->PostTask(
        FROM_HERE,
        WTF::BindOnce(&MediaRecorderHandler::EncodingInfo, WrapPersistent(handler),
                      ToWebMediaConfiguration(config),
                      WTF::BindOnce(&OnMediaCapabilitiesEncodingInfo,
                                    WrapPersistent(resolver))));

    return promise;
  }

  DVLOG(2) << __func__ << " Could not get MediaRecorderHandler.";
  MediaCapabilitiesInfo* info = CreateEncodingInfoWith(false);
  resolver->Resolve(info);
  return promise;
}

bool MediaCapabilities::EnsureLearningPredictors(
    ExecutionContext* execution_context) {
  DCHECK(execution_context && !execution_context->IsContextDestroyed());

  // One or both of these will have been bound in an earlier pass.
  if (bad_window_predictor_.is_bound() || nnr_predictor_.is_bound())
    return true;

  // MediaMetricsProvider currently only exposed via render frame.
  // TODO(chcunningham): Expose in worker contexts pending outcome of
  // media-learning experiments.
  if (execution_context->IsWorkerGlobalScope())
    return false;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      execution_context->GetTaskRunner(TaskType::kMediaElementEvent);

  mojo::Remote<media::mojom::blink::MediaMetricsProvider> metrics_provider;
  execution_context->GetBrowserInterfaceBroker().GetInterface(
      metrics_provider.BindNewPipeAndPassReceiver(task_runner));

  if (!metrics_provider)
    return false;

  if (GetLearningBadWindowThreshold() != -1.0) {
    DCHECK_GE(GetLearningBadWindowThreshold(), 0);
    metrics_provider->AcquireLearningTaskController(
        media::learning::tasknames::kConsecutiveBadWindows,
        bad_window_predictor_.BindNewPipeAndPassReceiver(task_runner));
  }

  if (GetLearningNnrThreshold() != -1.0) {
    DCHECK_GE(GetLearningNnrThreshold(), 0);
    metrics_provider->AcquireLearningTaskController(
        media::learning::tasknames::kConsecutiveNNRs,
        nnr_predictor_.BindNewPipeAndPassReceiver(task_runner));
  }

  return bad_window_predictor_.is_bound() || nnr_predictor_.is_bound();
}

bool MediaCapabilities::EnsurePerfHistoryService(
    ExecutionContext* execution_context) {
  if (decode_history_service_.is_bound())
    return true;

  if (!execution_context)
    return false;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      execution_context->GetTaskRunner(TaskType::kMediaElementEvent);

  execution_context->GetBrowserInterfaceBroker().GetInterface(
      decode_history_service_.BindNewPipeAndPassReceiver(task_runner));
  return true;
}

bool MediaCapabilities::EnsureWebrtcPerfHistoryService(
    ExecutionContext* execution_context) {
  if (webrtc_history_service_.is_bound())
    return true;

  if (!execution_context)
    return false;

  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      execution_context->GetTaskRunner(TaskType::kMediaElementEvent);

  execution_context->GetBrowserInterfaceBroker().GetInterface(
      webrtc_history_service_.BindNewPipeAndPassReceiver(task_runner));
  return true;
}

ScriptPromise<MediaCapabilitiesDecodingInfo> MediaCapabilities::GetEmeSupport(
    ScriptState* script_state,
    media::VideoCodec video_codec,
    media::VideoCodecProfile video_profile,
    media::VideoColorSpace video_color_space,
    const MediaDecodingConfiguration* configuration,
    const base::TimeTicks& request_time,
    ExceptionState& exception_state) {
  DVLOG(3) << __func__;
  DCHECK(configuration->hasKeySystemConfiguration());

  // Calling context must have a real window bound to a Page. This check is
  // ported from rMKSA (see http://crbug.com/456720).
  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The context provided is not associated with a page.");
    return EmptyPromise();
  }

  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  DCHECK(execution_context);

  // See context here:
  // https://sites.google.com/a/chromium.org/dev/Home/chromium-security/deprecating-permissions-in-cross-origin-iframes
  if (!execution_context->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kEncryptedMedia,
          ReportOptions::kReportOnFailure)) {
    UseCounter::Count(execution_context,
                      WebFeature::kEncryptedMediaDisabledByFeaturePolicy);
    execution_context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::ConsoleMessageSource::kJavaScript,
        mojom::ConsoleMessageLevel::kWarning,
        kEncryptedMediaPermissionsPolicyConsoleWarning));
    exception_state.ThrowSecurityError(
        "decodingInfo(): Creating MediaKeySystemAccess is disabled by feature "
        "policy.");
    return EmptyPromise();
  }

  if (execution_context->IsWorkerGlobalScope()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Encrypted Media decoding info not available in Worker context.");
    return EmptyPromise();
  }

  if (!execution_context->IsSecureContext()) {
    exception_state.ThrowSecurityError(
        "Encrypted Media decoding info can only be queried in a secure"
        " context.");
    return EmptyPromise();
  }

  const MediaCapabilitiesKeySystemConfiguration* key_system_config =
      configuration->keySystemConfiguration();
  if (!key_system_config->hasKeySystem() ||
      key_system_config->keySystem().empty()) {
    exception_state.ThrowTypeError("The key system String is not valid.");
    return EmptyPromise();
  }

  MediaKeySystemConfiguration* eme_config =
      MediaKeySystemConfiguration::Create();

  // Set the initDataTypes attribute to a sequence containing
  // config.keySystemConfiguration.initDataType.
  // TODO(chcunningham): double check that this default is idiomatic. Here we
  // can't check hasInitDataType() because the default ("") makes that always
  // true. The default in EME is an empty list.
  if (!key_system_config->initDataType().empty()) {
    eme_config->setInitDataTypes(
        Vector<String>(1, key_system_config->initDataType()));
  }

  // Set the distinctiveIdentifier attribute to
  // config.keySystemConfiguration.distinctiveIdentifier.
  eme_config->setDistinctiveIdentifier(
      key_system_config->distinctiveIdentifier());

  // Set the persistentState attribute to
  // config.keySystemConfiguration.persistentState.
  eme_config->setPersistentState(key_system_config->persistentState());

  // Set the sessionTypes attribute to
  // config.keySystemConfiguration.sessionTypes.
  if (key_system_config->hasSessionTypes())
    eme_config->setSessionTypes(key_system_config->sessionTypes());

  // If an audio is present in config...
  if (configuration->hasAudio()) {
    // set the audioCapabilities attribute to a sequence containing a single
    // MediaKeySystemMediaCapability, initialized as follows:
    MediaKeySystemMediaCapability* audio_capability =
        MediaKeySystemMediaCapability::Create();
    // Set the contentType attribute to config.audio.contentType.
    audio_capability->setContentType(configuration->audio()->contentType());
    // If config.keySystemConfiguration.audio is present, set the robustness
    // attribute to config.keySystemConfiguration.audio.robustness.
    if (key_system_config->hasAudio())
      audio_capability->setRobustness(key_system_config->audio()->robustness());

    eme_config->setAudioCapabilities(
        HeapVector<Member<MediaKeySystemMediaCapability>>(1, audio_capability));
  }

  // If a video is present in config...
  if (configuration->hasVideo()) {
    // set the videoCapabilities attribute to a sequence containing a single
    // MediaKeySystemMediaCapability, initialized as follows:
    MediaKeySystemMediaCapability* video_capability =
        MediaKeySystemMediaCapability::Create();
    // Set the contentType attribute to config.video.contentType.
    video_capability->setContentType(configuration->video()->contentType());
    // If config.keySystemConfiguration.video is present, set the robustness
    // attribute to config.keySystemConfiguration.video.robustness.
    if (key_system_config->hasVideo())
      video_capability->setRobustness(key_system_config->video()->robustness());

    eme_config->setVideoCapabilities(
        HeapVector<Member<MediaKeySystemMediaCapability>>(1, video_capability));
  }

  HeapVector<Member<MediaKeySystemConfiguration>> config_vector(1, eme_config);

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<MediaCapabilitiesDecodingInfo>>(script_state);
  MediaCapabilitiesKeySystemAccessInitializer* initializer =
      MakeGarbageCollected<MediaCapabilitiesKeySystemAccessInitializer>(
          execution_context, resolver, key_system_config->keySystem(),
          config_vector,
          WTF::BindOnce(&MediaCapabilities::GetPerfInfo, WrapPersistent(this),
                        video_codec, video_profile, video_color_space,
                        WrapPersistent(configuration), request_time));

  // IMPORTANT: Acquire the promise before potentially synchronously resolving
  // it in the code that follows. Otherwise the promise returned to JS will be
  // undefined. See comment above Promise() in script_promise_resolver.h
  auto promise = resolver->Promise();

  EncryptedMediaUtils::GetEncryptedMediaClientFromLocalDOMWindow(
      To<LocalDOMWindow>(execution_context))
      ->RequestMediaKeySystemAccess(WebEncryptedMediaRequest(initializer));

  return promise;
}

void MediaCapabilities::GetPerfInfo(
    media::VideoCodec video_codec,
    media::VideoCodecProfile video_profile,
    media::VideoColorSpace video_color_space,
    const MediaDecodingConfiguration* decoding_config,
    const base::TimeTicks& request_time,
    ScriptPromiseResolver<MediaCapabilitiesDecodingInfo>* resolver,
    MediaKeySystemAccess* access) {
  ExecutionContext* execution_context = resolver->GetExecutionContext();
  if (!execution_context || execution_context->IsContextDestroyed())
    return;

  if (!decoding_config->hasVideo()) {
    // Audio-only is always smooth and power efficient.
    MediaCapabilitiesDecodingInfo* info = CreateDecodingInfoWith(true);
    info->setKeySystemAccess(access);
    media_capabilities_identifiability_metrics::ReportDecodingInfoResult(
        execution_context, decoding_config, info);
    resolver->Resolve(info);
    return;
  }

  const VideoConfiguration* video_config = decoding_config->video();
  String key_system = "";
  bool use_hw_secure_codecs = false;

  if (access) {
    key_system = access->keySystem();
    use_hw_secure_codecs = access->UseHardwareSecureCodecs();
  }

  if (!EnsurePerfHistoryService(execution_context)) {
    MediaCapabilitiesDecodingInfo* info = CreateDecodingInfoWith(true);
    media_capabilities_identifiability_metrics::ReportDecodingInfoResult(
        execution_context, decoding_config, info);
    resolver->Resolve(WrapPersistent(info));
    return;
  }

  const int callback_id = CreateCallbackId();
  pending_cb_map_.insert(
      callback_id,
      MakeGarbageCollected<MediaCapabilities::PendingCallbackState>(
          resolver, access, request_time,
          media_capabilities_identifiability_metrics::
              ComputeDecodingInfoInputToken(decoding_config)));

  if (base::FeatureList::IsEnabled(media::kMediaLearningSmoothnessExperiment)) {
    GetPerfInfo_ML(execution_context, callback_id, video_codec, video_profile,
                   video_config->width(), video_config->framerate());
  }

  media::mojom::blink::PredictionFeaturesPtr features =
      media::mojom::blink::PredictionFeatures::New(
          static_cast<media::mojom::blink::VideoCodecProfile>(video_profile),
          gfx::Size(video_config->width(), video_config->height()),
          video_config->framerate(), key_system, use_hw_secure_codecs);

  decode_history_service_->GetPerfInfo(
      std::move(features), WTF::BindOnce(&MediaCapabilities::OnPerfHistoryInfo,
                                         WrapPersistent(this), callback_id));

  if (UseGpuFactoriesForPowerEfficient(execution_context, access)) {
    GetGpuFactoriesSupport(callback_id, video_codec, video_profile,
                           video_color_space, decoding_config);
  }
}

void MediaCapabilities::GetPerfInfo_ML(ExecutionContext* execution_context,
                                       int callback_id,
                                       media::VideoCodec video_codec,
                                       media::VideoCodecProfile video_profile,
                                       int width,
                                       double framerate) {
  DCHECK(execution_context && !execution_context->IsContextDestroyed());
  DCHECK(pending_cb_map_.Contains(callback_id));

  if (!EnsureLearningPredictors(execution_context)) {
    return;
  }

  // FRAGILE: Order here MUST match order in
  // WebMediaPlayerImpl::UpdateSmoothnessHelper().
  // TODO(chcunningham): refactor into something more robust.
  Vector<media::learning::FeatureValue> ml_features(
      {media::learning::FeatureValue(static_cast<int>(video_codec)),
       media::learning::FeatureValue(video_profile),
       media::learning::FeatureValue(width),
       media::learning::FeatureValue(framerate)});

  if (bad_window_predictor_.is_bound()) {
    bad_window_predictor_->PredictDistribution(
        ml_features, WTF::BindOnce(&MediaCapabilities::OnBadWindowPrediction,
                                   WrapPersistent(this), callback_id));
  }

  if (nnr_predictor_.is_bound()) {
    nnr_predictor_->PredictDistribution(
        ml_features, WTF::BindOnce(&MediaCapabilities::OnNnrPrediction,
                                   WrapPersistent(this), callback_id));
  }
}

void MediaCapabilities::GetGpuFactoriesSupport(
    int callback_id,
    media::VideoCodec video_codec,
    media::VideoCodecProfile video_profile,
    media::VideoColorSpace video_color_space,
    const MediaDecodingConfiguration* decoding_config) {
  DCHECK(decoding_config->hasVideo());
  DCHECK(pending_cb_map_.Contains(callback_id));

  PendingCallbackState* pending_cb = pending_cb_map_.at(callback_id);
  if (!pending_cb) {
    // TODO(crbug.com/1125956): Determine how this can happen and prevent it.
    return;
  }

  ExecutionContext* execution_context =
      pending_cb->resolver->GetExecutionContext();

  // Frame may become detached in the time it takes us to get callback for
  // NotifyDecoderSupportKnown. In this case, report false as a means of clean
  // shutdown.
  if (!execution_context || execution_context->IsContextDestroyed()) {
    OnGpuFactoriesSupport(callback_id, false, video_codec);
    return;
  }

  DCHECK(UseGpuFactoriesForPowerEfficient(execution_context,
                                          pending_cb->key_system_access));

  media::GpuVideoAcceleratorFactories* gpu_factories =
      Platform::Current()->GetGpuFactories();
  if (!gpu_factories) {
    OnGpuFactoriesSupport(callback_id, false, video_codec);
    return;
  }

  if (!gpu_factories->IsDecoderSupportKnown()) {
    gpu_factories->NotifyDecoderSupportKnown(WTF::BindOnce(
        &MediaCapabilities::GetGpuFactoriesSupport, WrapPersistent(this),
        callback_id, video_codec, video_profile, video_color_space,
        WrapPersistent(decoding_config)));
    return;
  }

  // TODO(chcunningham): Get the actual scheme and alpha mode from
  // |decoding_config| once implemented (its already spec'ed).
  media::EncryptionScheme encryption_scheme =
      decoding_config->hasKeySystemConfiguration()
          ? media::EncryptionScheme::kCenc
          : media::EncryptionScheme::kUnencrypted;
  media::VideoDecoderConfig::AlphaMode alpha_mode =
      media::VideoDecoderConfig::AlphaMode::kIsOpaque;

  // A few things aren't known until demuxing time. These include: coded size,
  // visible rect, and extra data. Make reasonable guesses below. Ideally the
  // differences won't be make/break GPU acceleration support.
  const VideoConfiguration* video_config = decoding_config->video();
  gfx::Size natural_size(video_config->width(), video_config->height());
  media::VideoDecoderConfig config(
      video_codec, video_profile, alpha_mode, video_color_space,
      media::VideoTransformation(), natural_size /* coded_size */,
      gfx::Rect(natural_size) /* visible_rect */, natural_size,
      media::EmptyExtraData(), encryption_scheme);

  OnGpuFactoriesSupport(
      callback_id,
      gpu_factories->IsDecoderConfigSupportedOrUnknown(config) ==
          media::GpuVideoAcceleratorFactories::Supported::kTrue,
      video_codec);
}

void MediaCapabilities::ResolveCallbackIfReady(int callback_id) {
  DCHECK(pending_cb_map_.Contains(callback_id));
  PendingCallbackState* pending_cb = pending_cb_map_.at(callback_id);
  ExecutionContext* execution_context =
      pending_cb_map_.at(callback_id)->resolver->GetExecutionContext();

  if (!pending_cb->db_is_power_efficient.has_value())
    return;

  // Both db_* fields should be set simultaneously by the DB callback.
  DCHECK(pending_cb->db_is_smooth.has_value());

  if (nnr_predictor_.is_bound() &&
      !pending_cb->is_nnr_prediction_smooth.has_value())
    return;

  if (bad_window_predictor_.is_bound() &&
      !pending_cb->is_bad_window_prediction_smooth.has_value())
    return;

  if (UseGpuFactoriesForPowerEfficient(execution_context,
                                       pending_cb->key_system_access) &&
      !pending_cb->is_gpu_factories_supported.has_value()) {
    return;
  }

  if (!pending_cb->resolver->GetExecutionContext() ||
      pending_cb->resolver->GetExecutionContext()->IsContextDestroyed()) {
    // We're too late! Now that all the callbacks have provided state, its safe
    // to erase the entry in the map.
    pending_cb_map_.erase(callback_id);
    return;
  }

  Persistent<MediaCapabilitiesDecodingInfo> info(
      MediaCapabilitiesDecodingInfo::Create());
  info->setSupported(true);
  info->setKeySystemAccess(pending_cb->key_system_access);

  if (UseGpuFactoriesForPowerEfficient(execution_context,
                                       pending_cb->key_system_access)) {
    info->setPowerEfficient(*pending_cb->is_gpu_factories_supported);
    // Builtin video codec guarantee a certain codec can be decoded under any
    // circumstances, and if the result is not powerEfficient and the video
    // codec is not builtin, that means the video will failed to play at the
    // given video config, so change the supported value to false here.
    if (!info->powerEfficient() &&
        !pending_cb->is_builtin_video_codec.value_or(true)) {
      info->setSupported(false);
    }
  } else {
    info->setPowerEfficient(*pending_cb->db_is_power_efficient);
  }

  // If ML experiment is running: AND available ML signals.
  if (pending_cb->is_bad_window_prediction_smooth.has_value() ||
      pending_cb->is_nnr_prediction_smooth.has_value()) {
    info->setSmooth(
        pending_cb->is_bad_window_prediction_smooth.value_or(true) &&
        pending_cb->is_nnr_prediction_smooth.value_or(true));
  } else {
    // Use DB when ML experiment not running.
    info->setSmooth(*pending_cb->db_is_smooth);
  }

  const base::TimeDelta process_time =
      base::TimeTicks::Now() - pending_cb->request_time;
  UMA_HISTOGRAM_TIMES("Media.Capabilities.DecodingInfo.Time.Video",
                      process_time);

  // Record another time in the appropriate subset, either clear or encrypted
  // content.
  if (pending_cb->key_system_access) {
    UMA_HISTOGRAM_TIMES("Media.C
"""


```