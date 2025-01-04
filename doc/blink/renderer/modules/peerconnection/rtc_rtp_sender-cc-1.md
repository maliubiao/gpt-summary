Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part 2 of the `rtc_rtp_sender.cc` file in the Chromium Blink engine. I need to analyze the code and identify the key actions and responsibilities of the `RTCRtpSender` class as demonstrated in this part.

Here's a breakdown of the code's functionality:

1. **Setting Parameters:**  Handles asynchronous setting of RTP sender parameters, including encoding options and degradation preferences.
2. **Clearing Parameters:** Provides a mechanism to reset the last returned parameters.
3. **Getting Statistics:** Retrieves statistics related to the RTP sender.
4. **Accessing Underlying WebRTC Sender:** Provides access to the platform-specific WebRTC sender implementation.
5. **Setting Media Stream Track:** Associates a `MediaStreamTrack` with the sender.
6. **Managing Media Streams:**  Keeps track of the `MediaStream`s associated with the sender.
7. **Setting Transceiver and Transport:**  Associates the sender with its corresponding `RTCRtpTransceiver` and `RTCDtlsTransport`.
8. **Handling DTMF:**  Manages the creation and access of the DTMF sender for audio tracks.
9. **Setting Streams (with Error Handling):** Sets the associated `MediaStream`s, with checks for the `RTCPeerConnection`'s state.
10. **Creating Encoded Streams:**  Provides the functionality to create insertable encoded streams for audio and video, enabling manipulation of the encoded media. This includes logic to prevent creating them too late or multiple times.
11. **Context Destruction Handling:** Cleans up resources when the execution context is destroyed.
12. **Tracing:**  Supports tracing for debugging and memory management.
13. **Getting Capabilities:**  Retrieves the RTP capabilities (codecs and header extensions) supported by the sender.
14. **Short-Circuiting Encoded Streams:**  Implements a mechanism to bypass the transform if no transform is set.
15. **Managing Encoded Audio Streams:**  Handles the creation and management of underlying source and sink for encoded audio streams, including callbacks for processing frames.
16. **Managing Encoded Video Streams:** Similar to audio, but for video streams.
17. **Setting and Managing Transforms:**  Allows setting an `RTCRtpScriptTransform` to manipulate encoded media, and handles attaching and detaching the transform.
18. **Logging:** Provides a logging mechanism.
这是 `blink/renderer/modules/peerconnection/rtc_rtp_sender.cc` 文件中 `RTCRtpSender` 类的部分实现，主要负责以下功能：

**核心功能：管理和控制媒体数据的发送过程**

* **设置发送参数 (SetParameters):**
    * 允许异步地更新 RTP 发送器的参数，例如编码设置（`encodings`）和降级偏好（`degradation_preference`）。
    * **假设输入:** `options` 参数可能包含编码选项，例如目标比特率、帧大小等，而 `encodings` 可能包含多个编码配置，例如用于 simulcast。
    * **逻辑推理:** 检查 `encodingOptions` 的大小是否与 `encodings` 的大小匹配，如果不匹配则拒绝请求。遍历 `encodingOptions` 并将其中的 `keyFrame` 属性应用到相应的 `encodings` 中。
    * **用户或编程常见错误:**  提供的 `encodingOptions` 数量与 `encodings` 数量不一致，会导致 `InvalidModificationError` 异常。
* **清除上次返回的参数 (ClearLastReturnedParameters):**
    * 清除缓存的上次返回的参数，可能是为了确保后续获取到最新的参数。
* **获取发送统计信息 (getStats):**
    * 异步地获取关于 RTP 发送器的统计信息，例如发送的字节数、丢包率等。
    * **与 Javascript 的关系:**  JavaScript 代码可以调用 `RTCRtpSender.getStats()` 方法来获取这些统计信息，用于监控网络质量和媒体传输状态。返回的是一个 `Promise`，resolve 的结果是 `RTCStatsReport` 对象。
* **获取底层的 WebRTC 发送器 (web_sender):**
    * 提供访问底层 WebRTC 发送器平台实现的接口。

**媒体轨道和流管理**

* **设置媒体轨道 (SetTrack):**
    * 将一个 `MediaStreamTrack` 对象关联到此 RTP 发送器。
    * **假设输入:**  一个 `MediaStreamTrack` 对象，代表音频或视频轨道。
    * **逻辑推理:**  如果之前没有设置 `kind_` (音频或视频类型)，则根据传入的 `track` 设置 `kind_`。如果已经设置了 `kind_`，则检查新传入的 `track` 的类型是否一致，如果不一致则会触发 `NOTREACHED()` 断言。
* **获取关联的媒体流 (streams):**
    * 返回与此 RTP 发送器关联的 `MediaStream` 对象列表。
* **设置关联的媒体流 (set_streams):**
    * 设置与此 RTP 发送器关联的 `MediaStream` 对象列表。

**与其他 WebRTC 组件的关联**

* **设置收发器 (set_transceiver):**
    * 将此 RTP 发送器与一个 `RTCRtpTransceiver` 对象关联。`RTCRtpTransceiver` 用于协商和控制媒体的发送和接收。
* **设置传输层 (set_transport):**
    * 将此 RTP 发送器与一个 `RTCDtlsTransport` 对象关联。`RTCDtlsTransport` 负责安全地传输 RTP 数据包。

**DTMF 支持**

* **获取 DTMF 发送器 (dtmf):**
    * 返回一个 `RTCDTMFSender` 对象，用于在音频轨道上发送双音多频信号（通常用于电话拨号）。
    * **逻辑推理:**  只有当 `kind_` 为 "audio" 时才会尝试创建 `RTCDTMFSender`。如果底层发送器无法创建 DTMF 发送器，则返回 `nullptr` 并记录错误日志。

**处理媒体流关联 (setStreams)**

* **设置关联的媒体流 (setStreams):**
    * 允许通过 `MediaStream` 的 ID 列表设置关联的媒体流。
    * **与 Javascript 的关系:** JavaScript 代码可以调用 `RTCRtpSender.setStreams()` 方法来更新与发送器关联的媒体流。
    * **用户或编程常见错误:** 在 `RTCPeerConnection` 的 `signalingState` 为 'closed' 时调用此方法会导致 `InvalidStateError` 异常。

**可插入的媒体流 (Insertable Streams)**

* **创建编码后的流 (createEncodedStreams):**
    * 允许创建可插入的编码后音频或视频流，这使得 JavaScript 代码可以直接访问和修改编码后的媒体数据。
    * **与 Javascript 的关系:** 这是 WebRTC 的 "Encoded Transform" 功能的关键部分，JavaScript 代码可以获取返回的 `RTCInsertableStreams` 对象，并通过其 `readable` 和 `writable` 属性访问编码后的媒体数据流。
    * **用户或编程常见错误:**  在 `transform_shortcircuited_` 为 true 或者已经创建过编码流的情况下再次调用此方法会导致 `InvalidStateError` 异常。
    * **逻辑推理:**  根据 `kind_` (音频或视频) 调用 `CreateEncodedAudioStreams` 或 `CreateEncodedVideoStreams` 来创建相应的流。

**内部状态管理和资源清理**

* **上下文销毁处理 (ContextDestroyed):**
    * 在执行上下文被销毁时清理资源，例如清空底层数据源和数据接收器的引用。

**调试和性能**

* **跟踪 (Trace):**
    * 用于 Blink 的垃圾回收机制，跟踪对象之间的引用关系。
* **获取能力 (getCapabilities):**
    * 返回 RTP 发送器所支持的编解码器和头部扩展能力。
    * **与 Javascript 的关系:** JavaScript 代码可以调用 `RTCRtpSender.getCapabilities()` 静态方法来获取这些能力信息。
* **短路编码流 (MaybeShortCircuitEncodedStreams):**
    * 如果没有设置 `transform_`，则启用编码流的短路模式，绕过不必要的处理。

**处理编码后的媒体数据**

* **注册/取消注册编码后的音频/视频流回调 (RegisterEncodedAudioStreamCallback, UnregisterEncodedAudioStreamCallback, RegisterEncodedVideoStreamCallback, UnregisterEncodedVideoStreamCallback):**
    * 用于设置和取消接收编码后音频或视频帧的回调函数。
* **设置音频/视频底层数据源和数据接收器 (SetAudioUnderlyingSource, SetAudioUnderlyingSink, SetVideoUnderlyingSource, SetVideoUnderlyingSink):**
    * 用于管理编码后音频和视频数据的输入和输出。
* **创建编码后的音频/视频流 (CreateEncodedAudioStreams, CreateEncodedVideoStreams):**
    * 具体实现创建可插入的编码后音频和视频流的逻辑，包括设置 ReadableStream 和 WritableStream，以及关联底层的数据源和数据接收器。
* **接收来自编码器的音频/视频帧 (OnAudioFrameFromEncoder, OnVideoFrameFromEncoder):**
    * 回调函数，用于接收编码后的音频或视频帧。
* **设置媒体流变换 (setTransform):**
    * 允许设置一个 `RTCRtpScriptTransform` 对象，用于在 JavaScript 中对编码后的媒体数据进行自定义处理。
    * **与 Javascript 的关系:**  JavaScript 代码可以通过 `RTCRtpSender.setTransform()` 方法设置一个 `TransformStream` 对象，该对象可以拦截和修改编码后的媒体数据。
    * **用户或编程常见错误:**  尝试设置一个已经被使用的 `transform` 对象会导致 `InvalidStateError` 异常。

**日志记录**

* **日志消息 (LogMessage):**
    * 用于记录 RTP 发送器的相关信息，方便调试。

**用户操作如何到达这里作为调试线索:**

1. **用户发起媒体通话:** 用户在网页上点击一个按钮或执行某些操作，触发建立 WebRTC 连接的流程。
2. **创建 RTCPeerConnection:**  JavaScript 代码会创建一个 `RTCPeerConnection` 对象。
3. **添加媒体轨道:**  使用 `RTCPeerConnection.addTrack()` 方法将本地媒体轨道（例如摄像头或麦克风的输出）添加到连接中。
4. **创建 RTCRtpSender:**  `addTrack()` 方法内部会创建一个 `RTCRtpSender` 对象来处理该轨道的发送。
5. **设置编码参数 (可选):**  JavaScript 代码可能会调用 `RTCRtpSender.setParameters()` 来调整发送参数，例如分辨率、帧率等。这对应了代码中的 `SetParameters` 函数。
6. **获取统计信息 (可选):**  为了监控连接质量，JavaScript 代码可能会周期性地调用 `RTCRtpSender.getStats()` 来获取发送统计信息。
7. **使用可插入流 (可选):**  如果网页应用使用了 "Encoded Transform" 功能，JavaScript 代码会调用 `RTCRtpSender.createEncodedStreams()` 来创建可插入的流，并通过 `setTransform()` 设置自定义的媒体处理逻辑。
8. **发送媒体数据:** 底层的 WebRTC 引擎会通过 `RTCRtpSender` 将编码后的媒体数据发送到远端。
9. **调试信息:** 如果在上述任何步骤中出现问题，开发者可能会查看日志或使用调试工具来追踪代码执行流程，最终可能会定位到 `rtc_rtp_sender.cc` 文件中的相关代码。例如，如果 `setParameters` 调用失败，开发者可能会检查传入的参数是否有效。如果媒体发送出现问题，可能会查看 `getStats` 的输出。如果使用了可插入流，可能会在 `OnAudioFrameFromEncoder` 或 `OnVideoFrameFromEncoder` 中设置断点来检查编码后的数据。

总而言之，这段代码是 `RTCRtpSender` 类中负责管理媒体发送的核心逻辑，包括参数设置、统计信息获取、媒体流管理、DTMF 支持以及与 "Encoded Transform" 功能相关的编码后数据处理。它在 WebRTC 的媒体发送流程中扮演着至关重要的角色。

Prompt: 
```
这是目录为blink/renderer/modules/peerconnection/rtc_rtp_sender.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
encoding_options = options->encodingOptions();
    if (!encoding_options.empty()) {
      if (encoding_options.size() != encodings.size()) {
        resolver->RejectWithDOMException(
            DOMExceptionCode::kInvalidModificationError,
            "encodingOptions size must match number of encodings.");
      }
      for (wtf_size_t i = 0; i < encoding_options.size(); i++) {
        encodings[i].request_key_frame = encoding_options[i]->keyFrame();
      }
    }
  }

  auto* request = MakeGarbageCollected<SetParametersRequest>(resolver, this);
  sender_->SetParameters(std::move(encodings), degradation_preference, request);
  return promise;
}

void RTCRtpSender::ClearLastReturnedParameters() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  last_returned_parameters_ = nullptr;
}

ScriptPromise<RTCStatsReport> RTCRtpSender::getStats(
    ScriptState* script_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<RTCStatsReport>>(script_state);
  auto promise = resolver->Promise();
  sender_->GetStats(WTF::BindOnce(WebRTCStatsReportCallbackResolver,
                                  WrapPersistent(resolver)));
  return promise;
}

RTCRtpSenderPlatform* RTCRtpSender::web_sender() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return sender_.get();
}

void RTCRtpSender::SetTrack(MediaStreamTrack* track) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  track_ = track;
  if (track) {
    if (kind_.IsNull()) {
      kind_ = track->kind();
    } else if (kind_ != track->kind()) {
      NOTREACHED() << "Trying to set track to a different kind: Old " << kind_
                   << " new " << track->kind();
    }
  }
}

MediaStreamVector RTCRtpSender::streams() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return streams_;
}

void RTCRtpSender::set_streams(MediaStreamVector streams) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  streams_ = std::move(streams);
}

void RTCRtpSender::set_transceiver(RTCRtpTransceiver* transceiver) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  transceiver_ = transceiver;
}

void RTCRtpSender::set_transport(RTCDtlsTransport* transport) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  transport_ = transport;
}

RTCDTMFSender* RTCRtpSender::dtmf() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // Lazy initialization of dtmf_ to avoid overhead when not used.
  if (!dtmf_ && kind_ == "audio") {
    auto handler = sender_->GetDtmfSender();
    if (!handler) {
      LOG(ERROR) << "Unable to create DTMF sender attribute on an audio sender";
      return nullptr;
    }
    dtmf_ =
        RTCDTMFSender::Create(pc_->GetExecutionContext(), std::move(handler));
  }
  return dtmf_.Get();
}

void RTCRtpSender::setStreams(HeapVector<Member<MediaStream>> streams,
                              ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (pc_->IsClosed()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The RTCPeerConnection's signalingState is 'closed'.");
    return;
  }
  Vector<String> stream_ids;
  for (auto stream : streams)
    stream_ids.emplace_back(stream->id());
  sender_->SetStreams(stream_ids);
}

RTCInsertableStreams* RTCRtpSender::createEncodedStreams(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  LogMessage(base::StringPrintf("%s({transform_shortcircuited_=%s})", __func__,
                                transform_shortcircuited_ ? "true" : "false"));
  if (transform_shortcircuited_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Too late to create encoded streams");
    return nullptr;
  }
  if (encoded_streams_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Encoded streams already created");
    return nullptr;
  }
  if (kind_ == "audio") {
    return CreateEncodedAudioStreams(script_state);
  }
  CHECK_EQ(kind_, "video");
  return CreateEncodedVideoStreams(script_state);
}

void RTCRtpSender::ContextDestroyed() {
  {
    base::AutoLock locker(audio_underlying_source_lock_);
    audio_from_encoder_underlying_source_.Clear();
  }
  {
    base::AutoLock locker(audio_underlying_sink_lock_);
    audio_to_packetizer_underlying_sink_.Clear();
  }
  {
    base::AutoLock locker(video_underlying_source_lock_);
    video_from_encoder_underlying_source_.Clear();
  }
  {
    base::AutoLock locker(video_underlying_sink_lock_);
    video_to_packetizer_underlying_sink_.Clear();
  }
}

void RTCRtpSender::Trace(Visitor* visitor) const {
  visitor->Trace(pc_);
  visitor->Trace(track_);
  visitor->Trace(transport_);
  visitor->Trace(dtmf_);
  visitor->Trace(streams_);
  visitor->Trace(last_returned_parameters_);
  visitor->Trace(transceiver_);
  visitor->Trace(encoded_streams_);
  visitor->Trace(transform_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

RTCRtpCapabilities* RTCRtpSender::getCapabilities(ScriptState* state,
                                                  const String& kind) {
  if (!state->ContextIsValid())
    return nullptr;

  if (kind != "audio" && kind != "video")
    return nullptr;

  RTCRtpCapabilities* capabilities = RTCRtpCapabilities::Create();
  capabilities->setCodecs(HeapVector<Member<RTCRtpCodecCapability>>());
  capabilities->setHeaderExtensions(
      HeapVector<Member<RTCRtpHeaderExtensionCapability>>());

  std::unique_ptr<webrtc::RtpCapabilities> rtc_capabilities =
      PeerConnectionDependencyFactory::From(*ExecutionContext::From(state))
          .GetSenderCapabilities(kind);

  HeapVector<Member<RTCRtpCodecCapability>> codecs;
  codecs.ReserveInitialCapacity(
      base::checked_cast<wtf_size_t>(rtc_capabilities->codecs.size()));
  for (const auto& rtc_codec : rtc_capabilities->codecs) {
    auto* codec = RTCRtpCodecCapability::Create();
    codec->setMimeType(WTF::String::FromUTF8(rtc_codec.mime_type()));
    if (rtc_codec.clock_rate)
      codec->setClockRate(rtc_codec.clock_rate.value());

    if (rtc_codec.num_channels)
      codec->setChannels(rtc_codec.num_channels.value());
    if (!rtc_codec.parameters.empty()) {
      std::string sdp_fmtp_line;
      for (const auto& parameter : rtc_codec.parameters) {
        if (!sdp_fmtp_line.empty())
          sdp_fmtp_line += ";";
        if (parameter.first.empty()) {
          sdp_fmtp_line += parameter.second;
        } else {
          sdp_fmtp_line += parameter.first + "=" + parameter.second;
        }
      }
      codec->setSdpFmtpLine(sdp_fmtp_line.c_str());
    }
    codecs.push_back(codec);
  }
  capabilities->setCodecs(codecs);

  HeapVector<Member<RTCRtpHeaderExtensionCapability>> header_extensions;
  header_extensions.ReserveInitialCapacity(base::checked_cast<wtf_size_t>(
      rtc_capabilities->header_extensions.size()));
  for (const auto& rtc_header_extension : rtc_capabilities->header_extensions) {
    auto* header_extension = RTCRtpHeaderExtensionCapability::Create();
    header_extension->setUri(WTF::String::FromUTF8(rtc_header_extension.uri));
    header_extensions.push_back(header_extension);
  }
  capabilities->setHeaderExtensions(header_extensions);

  if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
          IdentifiableSurface::Type::kRtcRtpSenderGetCapabilities)) {
    IdentifiableTokenBuilder builder;
    IdentifiabilityAddRTCRtpCapabilitiesToBuilder(builder, *capabilities);
    IdentifiabilityMetricBuilder(ExecutionContext::From(state)->UkmSourceID())
        .Add(IdentifiableSurface::FromTypeAndToken(
                 IdentifiableSurface::Type::kRtcRtpSenderGetCapabilities,
                 IdentifiabilityBenignStringToken(kind)),
             builder.GetToken())
        .Record(ExecutionContext::From(state)->UkmRecorder());
  }
  return capabilities;
}

void RTCRtpSender::MaybeShortCircuitEncodedStreams() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!encoded_streams_ && !transform_) {
    transform_shortcircuited_ = true;
    LogMessage("Starting short circuiting of encoded transform");
    if (kind_ == "video") {
      encoded_video_transformer_->StartShortCircuiting();
    } else {
      CHECK_EQ(kind_, "audio");
      encoded_audio_transformer_->StartShortCircuiting();
    }
  }
}

void RTCRtpSender::RegisterEncodedAudioStreamCallback() {
  CHECK(!base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback));
  // TODO(crbug.com/347915599): Delete this method once
  // kWebRtcEncodedTransformDirectCallback is fully launched.

  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_EQ(kind_, "audio");
  encoded_audio_transformer_->SetTransformerCallback(
      WTF::CrossThreadBindRepeating(&RTCRtpSender::OnAudioFrameFromEncoder,
                                    WrapCrossThreadWeakPersistent(this)));
}

void RTCRtpSender::UnregisterEncodedAudioStreamCallback() {
  // Threadsafe as this might be called from the realm to which a stream has
  // been transferred.
  encoded_audio_transformer_->ResetTransformerCallback();
}

void RTCRtpSender::SetAudioUnderlyingSource(
    RTCEncodedAudioUnderlyingSource* new_underlying_source,
    scoped_refptr<base::SingleThreadTaskRunner> new_source_task_runner) {
  if (!GetExecutionContext()) {
    // If our context is destroyed, then the RTCRtpSender, underlying
    // source(s), and transformer are about to be garbage collected, so there's
    // no reason to continue.
    return;
  }
  {
    base::AutoLock locker(audio_underlying_source_lock_);
    audio_from_encoder_underlying_source_->OnSourceTransferStarted();
    audio_from_encoder_underlying_source_ = new_underlying_source;
    if (base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback)) {
      encoded_audio_transformer_->SetTransformerCallback(
          WTF::CrossThreadBindRepeating(
              &RTCEncodedAudioUnderlyingSource::OnFrameFromSource,
              audio_from_encoder_underlying_source_));
    }
  }

  encoded_audio_transformer_->SetSourceTaskRunner(
      std::move(new_source_task_runner));
}

void RTCRtpSender::SetAudioUnderlyingSink(
    RTCEncodedAudioUnderlyingSink* new_underlying_sink) {
  if (!GetExecutionContext()) {
    // If our context is destroyed, then the RTCRtpSender and underlying
    // sink(s) are about to be garbage collected, so there's no reason to
    // continue.
    return;
  }
  base::AutoLock locker(audio_underlying_sink_lock_);
  audio_to_packetizer_underlying_sink_ = new_underlying_sink;
}

RTCInsertableStreams* RTCRtpSender::CreateEncodedAudioStreams(
    ScriptState* script_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  CHECK(!encoded_streams_);

  encoded_streams_ = RTCInsertableStreams::Create();

  {
    base::AutoLock locker(audio_underlying_source_lock_);
    DCHECK(!audio_from_encoder_underlying_source_);

    // Set up readable.
    audio_from_encoder_underlying_source_ =
        MakeGarbageCollected<RTCEncodedAudioUnderlyingSource>(
            script_state,
            WTF::CrossThreadBindOnce(
                &RTCRtpSender::UnregisterEncodedAudioStreamCallback,
                WrapCrossThreadWeakPersistent(this)));

    auto set_underlying_source =
        WTF::CrossThreadBindRepeating(&RTCRtpSender::SetAudioUnderlyingSource,
                                      WrapCrossThreadWeakPersistent(this));
    auto disconnect_callback = WTF::CrossThreadBindOnce(
        &RTCRtpSender::UnregisterEncodedAudioStreamCallback,
        WrapCrossThreadWeakPersistent(this));
    // The high water mark for the readable stream is set to 0 so that frames
    // are removed from the queue right away, without introducing a new buffer.
    ReadableStream* readable_stream =
        ReadableStream::CreateWithCountQueueingStrategy(
            script_state, audio_from_encoder_underlying_source_,
            /*high_water_mark=*/0, AllowPerChunkTransferring(false),
            std::make_unique<RtcEncodedAudioSenderSourceOptimizer>(
                std::move(set_underlying_source),
                std::move(disconnect_callback)));
    encoded_streams_->setReadable(readable_stream);

    if (base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback)) {
      encoded_audio_transformer_->SetTransformerCallback(
          WTF::CrossThreadBindRepeating(
              &RTCEncodedAudioUnderlyingSource::OnFrameFromSource,
              audio_from_encoder_underlying_source_));
    }
  }

  WritableStream* writable_stream;
  {
    base::AutoLock locker(audio_underlying_sink_lock_);
    DCHECK(!audio_to_packetizer_underlying_sink_);

    // Set up writable.
    audio_to_packetizer_underlying_sink_ =
        MakeGarbageCollected<RTCEncodedAudioUnderlyingSink>(
            script_state, encoded_audio_transformer_,
            /*detach_frame_data_on_write=*/false);

    auto set_underlying_sink =
        WTF::CrossThreadBindOnce(&RTCRtpSender::SetAudioUnderlyingSink,
                                 WrapCrossThreadWeakPersistent(this));

    // The high water mark for the stream is set to 1 so that the stream seems
    // ready to write, but without queuing frames.
    writable_stream = WritableStream::CreateWithCountQueueingStrategy(
        script_state, audio_to_packetizer_underlying_sink_,
        /*high_water_mark=*/1,
        std::make_unique<RtcEncodedAudioSenderSinkOptimizer>(
            std::move(set_underlying_sink), encoded_audio_transformer_));
  }

  encoded_streams_->setWritable(writable_stream);
  return encoded_streams_;
}

void RTCRtpSender::OnAudioFrameFromEncoder(
    std::unique_ptr<webrtc::TransformableAudioFrameInterface> frame) {
  // TODO(crbug.com/347915599): Delete this method once
  // kWebRtcEncodedTransformDirectCallback is fully launched.
  CHECK(!base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback));

  base::AutoLock locker(audio_underlying_source_lock_);
  if (audio_from_encoder_underlying_source_) {
    audio_from_encoder_underlying_source_->OnFrameFromSource(std::move(frame));
  }
}

void RTCRtpSender::RegisterEncodedVideoStreamCallback() {
  // TODO(crbug.com/347915599): Delete this method once
  // kWebRtcEncodedTransformDirectCallback is fully launched.
  CHECK(!base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback));

  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK_EQ(kind_, "video");
  encoded_video_transformer_->SetTransformerCallback(
      WTF::CrossThreadBindRepeating(&RTCRtpSender::OnVideoFrameFromEncoder,
                                    WrapCrossThreadWeakPersistent(this)));
}

void RTCRtpSender::UnregisterEncodedVideoStreamCallback() {
  // Threadsafe as this might be called from the realm to which a stream has
  // been transferred.
  encoded_video_transformer_->ResetTransformerCallback();
}

void RTCRtpSender::SetVideoUnderlyingSource(
    RTCEncodedVideoUnderlyingSource* new_underlying_source,
    scoped_refptr<base::SingleThreadTaskRunner> new_source_task_runner) {
  if (!GetExecutionContext()) {
    // If our context is destroyed, then the RTCRtpSender, underlying
    // source(s), and transformer are about to be garbage collected, so there's
    // no reason to continue.
    return;
  }
  {
    base::AutoLock locker(video_underlying_source_lock_);
    video_from_encoder_underlying_source_->OnSourceTransferStarted();
    video_from_encoder_underlying_source_ = new_underlying_source;
    if (base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback)) {
      encoded_video_transformer_->SetTransformerCallback(
          WTF::CrossThreadBindRepeating(
              &RTCEncodedVideoUnderlyingSource::OnFrameFromSource,
              video_from_encoder_underlying_source_));
    }
  }

  encoded_video_transformer_->SetSourceTaskRunner(
      std::move(new_source_task_runner));
}

void RTCRtpSender::SetVideoUnderlyingSink(
    RTCEncodedVideoUnderlyingSink* new_underlying_sink) {
  if (!GetExecutionContext()) {
    // If our context is destroyed, then the RTCRtpSender and underlying
    // sink(s) are about to be garbage collected, so there's no reason to
    // continue.
    return;
  }
  base::AutoLock locker(video_underlying_sink_lock_);
  video_to_packetizer_underlying_sink_ = new_underlying_sink;
}

RTCInsertableStreams* RTCRtpSender::CreateEncodedVideoStreams(
    ScriptState* script_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  CHECK(!encoded_streams_);

  encoded_streams_ = RTCInsertableStreams::Create();

  {
    base::AutoLock locker(video_underlying_source_lock_);
    DCHECK(!video_from_encoder_underlying_source_);

    // Set up readable.
    video_from_encoder_underlying_source_ =
        MakeGarbageCollected<RTCEncodedVideoUnderlyingSource>(
            script_state,
            WTF::CrossThreadBindOnce(
                &RTCRtpSender::UnregisterEncodedVideoStreamCallback,
                WrapCrossThreadWeakPersistent(this)));

    auto set_underlying_source =
        WTF::CrossThreadBindRepeating(&RTCRtpSender::SetVideoUnderlyingSource,
                                      WrapCrossThreadWeakPersistent(this));
    auto disconnect_callback = WTF::CrossThreadBindOnce(
        &RTCRtpSender::UnregisterEncodedVideoStreamCallback,
        WrapCrossThreadWeakPersistent(this));
    // The high water mark for the readable stream is set to 0 so that frames
    // are removed from the queue right away, without introducing a new buffer.
    ReadableStream* readable_stream =
        ReadableStream::CreateWithCountQueueingStrategy(
            script_state, video_from_encoder_underlying_source_,
            /*high_water_mark=*/0, AllowPerChunkTransferring(false),
            std::make_unique<RtcEncodedVideoSenderSourceOptimizer>(
                std::move(set_underlying_source),
                std::move(disconnect_callback)));
    encoded_streams_->setReadable(readable_stream);

    if (base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback)) {
      encoded_video_transformer_->SetTransformerCallback(
          WTF::CrossThreadBindRepeating(
              &RTCEncodedVideoUnderlyingSource::OnFrameFromSource,
              video_from_encoder_underlying_source_));
    }
  }

  WritableStream* writable_stream;
  {
    base::AutoLock locker(video_underlying_sink_lock_);
    DCHECK(!video_to_packetizer_underlying_sink_);

    // Set up writable.
    video_to_packetizer_underlying_sink_ =
        MakeGarbageCollected<RTCEncodedVideoUnderlyingSink>(
            script_state, encoded_video_transformer_,
            /*detach_frame_data_on_write=*/false);

    auto set_underlying_sink =
        WTF::CrossThreadBindOnce(&RTCRtpSender::SetVideoUnderlyingSink,
                                 WrapCrossThreadWeakPersistent(this));

    // The high water mark for the stream is set to 1 so that the stream seems
    // ready to write, but without queuing frames.
    writable_stream = WritableStream::CreateWithCountQueueingStrategy(
        script_state, video_to_packetizer_underlying_sink_,
        /*high_water_mark=*/1,
        std::make_unique<RtcEncodedVideoSenderSinkOptimizer>(
            std::move(set_underlying_sink), encoded_video_transformer_));
  }

  encoded_streams_->setWritable(writable_stream);
  return encoded_streams_;
}

void RTCRtpSender::setTransform(RTCRtpScriptTransform* transform,
                                ExceptionState& exception_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (transform_ == transform) {
    return;
  }
  if (!transform) {
    transform_->Detach();
    transform_ = nullptr;
    return;
  }
  if (transform->IsAttached()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Transform is already in use");
    return;
  }
  if (transform_) {
    transform_->Detach();
  }
  transform_ = transform;
  transform_->Attach();
  if (kind_ == "audio") {
    transform_->CreateAudioUnderlyingSourceAndSink(
        WTF::CrossThreadBindOnce(
            &RTCRtpSender::UnregisterEncodedAudioStreamCallback,
            WrapCrossThreadWeakPersistent(this)),
        encoded_audio_transformer_);
    return;
  }
  CHECK_EQ(kind_, "video");
  transform_->CreateVideoUnderlyingSourceAndSink(
      WTF::CrossThreadBindOnce(
          &RTCRtpSender::UnregisterEncodedVideoStreamCallback,
          WrapCrossThreadWeakPersistent(this)),
      encoded_video_transformer_);
}

void RTCRtpSender::OnVideoFrameFromEncoder(
    std::unique_ptr<webrtc::TransformableVideoFrameInterface> frame) {
  // TODO(crbug.com/347915599): Delete this method once
  // kWebRtcEncodedTransformDirectCallback is fully launched.
  CHECK(!base::FeatureList::IsEnabled(kWebRtcEncodedTransformDirectCallback));

  base::AutoLock locker(video_underlying_source_lock_);
  if (video_from_encoder_underlying_source_) {
    video_from_encoder_underlying_source_->OnFrameFromSource(std::move(frame));
  }
}

void RTCRtpSender::LogMessage(const std::string& message) {
  blink::WebRtcLogMessage(
      base::StringPrintf("RtpSndr::%s [this=0x%" PRIXPTR "]", message.c_str(),
                         reinterpret_cast<uintptr_t>(this)));
}

}  // namespace blink

"""


```