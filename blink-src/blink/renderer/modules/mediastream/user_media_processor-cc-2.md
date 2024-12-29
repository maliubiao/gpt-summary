Response:
The user wants to understand the functionality of the `UserMediaProcessor.cc` file in the Chromium Blink engine. They are asking for a summary of its functions, how it relates to web technologies (JavaScript, HTML, CSS), examples of logical reasoning with input/output, common user/programming errors, steps to reach this code during debugging, and a final concise summary.

**Plan:**

1. **Summarize Core Functionality:** Identify the main responsibilities of `UserMediaProcessor`, focusing on managing media streams and device access for `getUserMedia`.
2. **Relate to Web Technologies:** Explain how `UserMediaProcessor` interacts with JavaScript's `getUserMedia` API and the resulting media streams used in HTML and potentially styled with CSS.
3. **Logical Reasoning Examples:** Provide scenarios involving `getUserMedia` calls and how `UserMediaProcessor` handles them, including both success and failure cases.
4. **Common Errors:**  Point out potential mistakes developers or users might make that would involve this code.
5. **Debugging Steps:** Describe the sequence of user actions and code execution that leads to `UserMediaProcessor` being involved.
6. **Concise Summary:** Provide a brief overview of the file's role.
好的，这是对 `blink/renderer/modules/mediastream/user_media_processor.cc` 文件功能的归纳总结：

**UserMediaProcessor 的功能归纳总结 (第 3 部分，共 3 部分):**

在前两部分中，我们了解了 `UserMediaProcessor` 负责处理 `getUserMedia` 请求的生命周期，包括设备枚举、权限请求、媒体流和轨道的创建、以及与浏览器进程的通信。这第三部分主要集中在以下几个方面：

1. **处理设备和轨道的生命周期事件:**
    *   响应底层媒体设备状态的变化，例如设备停止、配置更改、句柄更改、以及缩放级别变化 (`OnDeviceStopped`, `OnDeviceChanged`, `OnDeviceRequestStateChange`, `OnDeviceCaptureConfigurationChange`, `OnDeviceCaptureHandleChange`, `OnZoomLevelChange`)。这些事件通常由浏览器进程通知给渲染进程。
    *   处理本地媒体源停止的事件 (`OnLocalSourceStopped`)，并通知浏览器进程停止对应的设备。
    *   提供停止本地媒体源的功能 (`StopLocalSource`)。

2. **管理和查找本地媒体源 (`MediaStreamSource`):**
    *   维护当前活动的本地媒体源列表 (`local_sources_`) 和正在初始化的媒体源列表 (`pending_local_sources_`)。
    *   提供根据 `MediaStreamDevice` 信息查找本地媒体源的方法 (`FindLocalSource`)。
    *   提供移除本地媒体源的方法 (`RemoveLocalSource`)。

3. **处理 `getUserMedia` 请求的成功和失败:**
    *   `OnCreateNativeTracksCompleted`:  在原生音视频轨道创建完成后被调用，根据结果判断 `getUserMedia` 请求是成功还是失败。
    *   `GetUserMediaRequestSucceeded`: 处理 `getUserMedia` 请求成功的情况，并异步回调 JavaScript。
    *   `DelayedGetUserMediaRequestSucceeded`: 异步执行 `GetUserMediaRequestSucceeded` 的逻辑。
    *   `GetUserMediaRequestFailed`: 处理 `getUserMedia` 请求失败的情况，并异步回调 JavaScript。
    *   `DelayedGetUserMediaRequestFailed`: 异步执行 `GetUserMediaRequestFailed` 的逻辑。

4. **资源清理和停止:**
    *   `StopAllProcessing`:  停止所有正在进行的 `getUserMedia` 处理，取消未完成的请求，并停止所有活动的本地媒体源。
    *   `DeleteUserMediaRequest`: 清理与特定 `UserMediaRequest` 相关的状态信息。

5. **与浏览器进程的通信:**
    *   通过 `mojom::blink::MediaStreamDispatcherHost` 接口与浏览器进程进行通信，例如停止设备、聚焦捕获表面等。

6. **辅助方法:**
    *   `InitializeSourceObject`: 初始化 `MediaStreamSource` 对象。
    *   `IsCurrentRequestInfo`: 检查给定的 `UserMediaRequest` 是否与当前正在处理的请求相关。
    *   `HasActiveSources`:  检查是否有活动的本地媒体源。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript:**
    *   当 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia()` 时，这个调用最终会触发 `UserMediaProcessor` 开始处理请求。
    *   `GetUserMediaRequestSucceeded` 和 `GetUserMediaRequestFailed` 方法最终会回调到 JavaScript 中 `getUserMedia()` 返回的 Promise 的 `then()` 或 `catch()` 方法，将成功或失败的结果传递给 JavaScript。
    *   当 JavaScript 调用 `MediaStreamTrack.stop()` 方法时，可能会触发 `UserMediaProcessor::OnLocalSourceStopped`，进而通知浏览器进程停止底层设备。

*   **HTML:**
    *   `getUserMedia` 获取的媒体流通常会赋值给 HTML5 `<video>` 或 `<audio>` 元素的 `srcObject` 属性，从而在页面上显示视频或播放音频。

*   **CSS:**
    *   CSS 可以用来控制 `<video>` 和 `<audio>` 元素的外观和布局，但这与 `UserMediaProcessor` 的直接功能关系较弱。

**逻辑推理的假设输入与输出举例:**

**假设输入:**

1. 用户在网页上点击了一个按钮，该按钮的 JavaScript 代码调用了 `navigator.mediaDevices.getUserMedia({ video: true })` 请求访问用户的摄像头。
2. 浏览器已经授予该网站访问摄像头的权限。
3. 用户的摄像头设备 ID 为 "camera123"。

**逻辑推理和输出:**

1. `UserMediaProcessor` 的某个方法（在第一部分中讨论）接收到 `getUserMedia` 请求，并创建 `RequestInfo` 对象来管理该请求。
2. `InitializeVideoSourceObject` 被调用，传入包含摄像头设备信息的 `MediaStreamDevice` 对象（设备 ID 为 "camera123"）。
3. `InitializeVideoSourceObject` 发现本地尚未存在该设备的 `MediaStreamSource`。
4. `CreateVideoSource` 被调用，创建一个 `MediaStreamVideoCapturerSource` 对象来管理摄像头的捕获。
5. `InitializeSourceObject` 创建一个新的 `MediaStreamSource` 对象，与 `MediaStreamVideoCapturerSource` 关联。
6. `local_sources_` 列表中添加了新的 `MediaStreamSource`。
7. 当摄像头启动成功后，`OnVideoSourceStarted` 被调用。
8. 最终，`OnCreateNativeTracksCompleted` 被调用，并调用 `GetUserMediaRequestSucceeded`。
9. `DelayedGetUserMediaRequestSucceeded` 异步执行，调用 `user_media_request->Succeed()`，将包含摄像头媒体流的 `MediaStream` 对象传递回 JavaScript。

**常见的使用错误举例:**

*   **用户层面:**
    *   **用户在 `getUserMedia` 弹窗中拒绝了摄像头或麦克风的访问权限。** 这会导致 `UserMediaProcessor` 的某个方法接收到失败的回调，并最终调用 `GetUserMediaRequestFailed`，将错误信息传递回 JavaScript 的 `catch()` 方法。
    *   **用户在媒体流使用过程中拔掉了摄像头设备。** 这会导致浏览器进程检测到设备移除，并通知 `UserMediaProcessor`，触发 `OnDeviceStopped` 或类似的方法，可能导致媒体流轨道停止。

*   **编程层面:**
    *   **在 `getUserMedia` 的 constraints 中指定了浏览器无法满足的硬件或分辨率要求。** 这会导致 `UserMediaProcessor` 在尝试创建媒体源时失败，并最终调用 `GetUserMediaRequestFailed`，错误类型可能是 `CONSTRAINT_NOT_SATISFIED`。
    *   **没有正确处理 `getUserMedia` 返回的 Promise 的失败情况。**  如果 `getUserMedia` 请求失败，但 JavaScript 代码没有提供 `catch()` 方法来处理错误，可能会导致程序行为异常或用户体验不佳。
    *   **在媒体流已经停止后，仍然尝试操作媒体流或轨道对象。** 这可能会导致 JavaScript 错误。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户在浏览器中访问一个需要访问摄像头或麦克风的网页。**
2. **网页的 JavaScript 代码调用 `navigator.mediaDevices.getUserMedia(constraints)`。**
3. **浏览器接收到 `getUserMedia` 请求，并可能会显示权限请求弹窗。**
4. **用户允许或拒绝权限。**
5. **如果用户允许权限，浏览器进程会开始设备枚举和初始化。**
6. **浏览器进程通过 IPC 通知渲染进程的 `UserMediaProcessor` 开始处理请求。**  与请求相关的状态信息会被存储在 `current_request_info_` 中。
7. **`UserMediaProcessor` 内部会调用 `InitializeVideoSourceObject` 或 `InitializeAudioSourceObject` 来创建对应的媒体源对象。**
8. **如果需要创建视频轨道，会调用 `CreateVideoTrack`，进而调用 `InitializeVideoSourceObject` 和 `CreateVideoSource`。**
9. **如果需要创建音频轨道，会调用 `CreateAudioTrack`，进而调用 `InitializeAudioSourceObject` 和 `CreateAudioSource`。**
10. **在音视频源启动后，`OnVideoSourceStarted` 或 `OnAudioSourceStartedOnAudioThread` 会被调用。**
11. **最终，`OnCreateNativeTracksCompleted` 会根据轨道创建结果被调用，并决定调用 `GetUserMediaRequestSucceeded` 或 `GetUserMediaRequestFailed`，将结果返回给 JavaScript。**

通过在这些关键方法上设置断点，例如 `InitializeVideoSourceObject`, `CreateVideoSource`, `OnCreateNativeTracksCompleted`, `GetUserMediaRequestSucceeded`, `GetUserMediaRequestFailed` 等，可以追踪 `getUserMedia` 请求的处理流程，并定位问题发生的位置。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/user_media_processor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
ce->IsStoppedForRestart()) {
      video_source->Restart(*video_source->GetCurrentFormat(),
                            base::DoNothing());
    }
  } else {
    NOTREACHED();
  }
}

void UserMediaProcessor::OnDeviceCaptureConfigurationChange(
    const MediaStreamDevice& device) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(base::StringPrintf(
      "OnDeviceCaptureConfigurationChange({session_id=%s}, {device_id=%s})",
      device.session_id().ToString().c_str(), device.id.c_str()));

  MediaStreamSource* const source = FindLocalSource(device);
  if (!source) {
    // This happens if the same device is used in several guM requests or
    // if a user happens to stop a track from JS at the same time
    // as the underlying media device is unplugged from the system.
    return;
  }

  source->OnDeviceCaptureConfigurationChange(device);
}

void UserMediaProcessor::OnDeviceCaptureHandleChange(
    const MediaStreamDevice& device) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(base::StringPrintf(
      "OnDeviceCaptureHandleChange({session_id=%s}, {device_id=%s})",
      device.session_id().ToString().c_str(), device.id.c_str()));

  MediaStreamSource* const source = FindLocalSource(device);
  if (!source) {
    // This happens if the same device is used in several guM requests or
    // if a user happens to stop a track from JS at the same time
    // as the underlying media device is unplugged from the system.
    return;
  }

  source->OnDeviceCaptureHandleChange(device);
}

void UserMediaProcessor::OnZoomLevelChange(const MediaStreamDevice& device,
                                           int zoom_level) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(base::StringPrintf(
      "OnZoomLevelChange({session_id=%s}, {device_id=%s})",
      device.session_id().ToString().c_str(), device.id.c_str()));

  MediaStreamSource* const source = FindLocalSource(device);
  if (!source) {
    return;
  }

  source->OnZoomLevelChange(device, zoom_level);
}

void UserMediaProcessor::Trace(Visitor* visitor) const {
  visitor->Trace(dispatcher_host_);
  visitor->Trace(frame_);
  visitor->Trace(current_request_info_);
  visitor->Trace(local_sources_);
  visitor->Trace(pending_local_sources_);
}

MediaStreamSource* UserMediaProcessor::InitializeVideoSourceObject(
    const MediaStreamDevice& device) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_);
  SendLogMessage(base::StringPrintf(
      "UMP::InitializeVideoSourceObject({request_id=%d}, {device=[id: %s, "
      "name: %s]})",
      current_request_info_->request_id(), device.id.c_str(),
      device.name.c_str()));
  MediaStreamSource* existing_source = FindLocalSource(device);
  if (existing_source) {
    DVLOG(1) << "Source already exists. Reusing source with id "
             << existing_source->Id().Utf8();
    return existing_source;
  }

  current_request_info_->StartTrace("CreateVideoSource");
  auto video_source = CreateVideoSource(
      device, WTF::BindOnce(&UserMediaProcessor::OnLocalSourceStopped,
                            WrapWeakPersistent(this)));
  video_source->SetStartCallback(WTF::BindOnce(
      &UserMediaProcessor::OnVideoSourceStarted, WrapWeakPersistent(this)));

  MediaStreamSource* source =
      InitializeSourceObject(device, std::move(video_source));

  String device_id(device.id.data());
  source->SetCapabilities(ComputeCapabilitiesForVideoSource(
      // TODO(crbug.com/704136): Change ComputeCapabilitiesForVideoSource to
      // operate over WTF::Vector.
      String::FromUTF8(device.id),
      ToStdVector(*current_request_info_->GetNativeVideoFormats(device_id)),
      static_cast<mojom::blink::FacingMode>(device.video_facing),
      current_request_info_->is_video_device_capture(), device.group_id));
  local_sources_.push_back(source);
  return source;
}

void UserMediaProcessor::OnVideoSourceStarted(
    blink::WebPlatformMediaStreamSource* source,
    MediaStreamRequestResult result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (current_request_info_) {
    current_request_info_->EndTrace("CreateVideoSource");
  }
}

MediaStreamSource* UserMediaProcessor::InitializeAudioSourceObject(
    const MediaStreamDevice& device,
    bool* is_pending) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_);
  SendLogMessage(
      base::StringPrintf("InitializeAudioSourceObject({session_id=%s})",
                         device.session_id().ToString().c_str()));

  *is_pending = true;

  // See if the source is already being initialized.
  auto* pending = FindPendingLocalSource(device);
  if (pending) {
    return pending;
  }

  MediaStreamSource* existing_source = FindLocalSource(device);
  if (existing_source) {
    DVLOG(1) << "Source already exists. Reusing source with id "
             << existing_source->Id().Utf8();
    // The only return point for non-pending sources.
    *is_pending = false;
    return existing_source;
  }

  current_request_info_->StartTrace("CreateAudioSource");
  blink::WebPlatformMediaStreamSource::ConstraintsRepeatingCallback
      source_ready = ConvertToBaseRepeatingCallback(CrossThreadBindRepeating(
          &UserMediaProcessor::OnAudioSourceStartedOnAudioThread, task_runner_,
          WrapCrossThreadWeakPersistent(this)));

  std::unique_ptr<blink::MediaStreamAudioSource> audio_source =
      CreateAudioSource(device, std::move(source_ready));
  audio_source->SetStopCallback(WTF::BindOnce(
      &UserMediaProcessor::OnLocalSourceStopped, WrapWeakPersistent(this)));

#if DCHECK_IS_ON()
  for (auto local_source : local_sources_) {
    auto* platform_source = static_cast<WebPlatformMediaStreamSource*>(
        local_source->GetPlatformSource());
    DCHECK(platform_source);
    if (platform_source->device().id == audio_source->device().id &&
        IsAudioInputMediaType(platform_source->device().type)) {
      auto* audio_platform_source =
          static_cast<MediaStreamAudioSource*>(platform_source);
      auto* processed_existing_source =
          ProcessedLocalAudioSource::From(audio_platform_source);
      auto* processed_new_source =
          ProcessedLocalAudioSource::From(audio_source.get());
      if (processed_new_source && processed_existing_source) {
        DCHECK(audio_source->HasSameNonReconfigurableSettings(
            audio_platform_source));
      }
    }
  }
#endif  // DCHECK_IS_ON()

  MediaStreamSource::Capabilities capabilities;
  capabilities.echo_cancellation = {true, false};
  capabilities.auto_gain_control = {true, false};
  capabilities.noise_suppression = {true, false};
  capabilities.voice_isolation = {true, false};
  capabilities.sample_size = {
      media::SampleFormatToBitsPerChannel(media::kSampleFormatS16),  // min
      media::SampleFormatToBitsPerChannel(media::kSampleFormatS16)   // max
  };
  auto device_parameters = audio_source->device().input;
  if (device_parameters.IsValid()) {
    capabilities.channel_count = {1, device_parameters.channels()};
    capabilities.sample_rate = {
        std::min(media::WebRtcAudioProcessingSampleRateHz(),
                 device_parameters.sample_rate()),
        std::max(media::WebRtcAudioProcessingSampleRateHz(),
                 device_parameters.sample_rate())};
    double fallback_latency =
        static_cast<double>(blink::kFallbackAudioLatencyMs) / 1000;
    double min_latency, max_latency;
    std::tie(min_latency, max_latency) =
        blink::GetMinMaxLatenciesForAudioParameters(device_parameters);
    capabilities.latency = {std::min(fallback_latency, min_latency),
                            std::max(fallback_latency, max_latency)};
  }

  capabilities.device_id = blink::WebString::FromUTF8(device.id);
  if (device.group_id) {
    capabilities.group_id = blink::WebString::FromUTF8(*device.group_id);
  }

  MediaStreamSource* source =
      InitializeSourceObject(device, std::move(audio_source));
  source->SetCapabilities(capabilities);

  // While sources are being initialized, keep them in a separate array.
  // Once they've finished initialized, they'll be moved over to local_sources_.
  // See OnAudioSourceStarted for more details.
  pending_local_sources_.push_back(source);

  return source;
}

std::unique_ptr<blink::MediaStreamAudioSource>
UserMediaProcessor::CreateAudioSource(
    const MediaStreamDevice& device,
    blink::WebPlatformMediaStreamSource::ConstraintsRepeatingCallback
        source_ready) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_);

  StreamControls* stream_controls = current_request_info_->stream_controls();
  // If the audio device is a loopback device (for screen capture), or if the
  // constraints/effects parameters indicate no audio processing is needed,
  // create an efficient, direct-path MediaStreamAudioSource instance.
  blink::AudioProcessingProperties audio_processing_properties =
      current_request_info_->audio_capture_settings()
          .audio_processing_properties();
  if (blink::IsScreenCaptureMediaType(device.type) ||
      !blink::MediaStreamAudioProcessor::WouldModifyAudio(
          audio_processing_properties)) {
    SendLogMessage(
        base::StringPrintf("%s => (no audiprocessing is used)", __func__));
    return std::make_unique<blink::LocalMediaStreamAudioSource>(
        frame_, device,
        base::OptionalToPtr(current_request_info_->audio_capture_settings()
                                .requested_buffer_size()),
        stream_controls->disable_local_echo,
        audio_processing_properties.echo_cancellation_type ==
            EchoCancellationType::kEchoCancellationSystem,
        std::move(source_ready), task_runner_);
  }

  // The audio device is not associated with screen capture and also requires
  // processing.
  SendLogMessage(
      base::StringPrintf("%s => (audiprocessing is required)", __func__));
  return std::make_unique<blink::ProcessedLocalAudioSource>(
      *frame_, device, stream_controls->disable_local_echo,
      audio_processing_properties,
      current_request_info_->audio_capture_settings().num_channels(),
      std::move(source_ready), task_runner_);
}

std::unique_ptr<blink::MediaStreamVideoSource>
UserMediaProcessor::CreateVideoSource(
    const MediaStreamDevice& device,
    blink::WebPlatformMediaStreamSource::SourceStoppedCallback stop_callback) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_);
  DCHECK(current_request_info_->video_capture_settings().HasValue());

  return std::make_unique<blink::MediaStreamVideoCapturerSource>(
      frame_->GetTaskRunner(TaskType::kInternalMediaRealTime), frame_,
      std::move(stop_callback), device,
      current_request_info_->video_capture_settings().capture_params(),
      WTF::BindRepeating(&blink::LocalVideoCapturerSource::Create,
                         frame_->GetTaskRunner(blink::TaskType::kInternalMedia),
                         WrapWeakPersistent(frame_.Get())));
}

void UserMediaProcessor::StartTracks(const String& label) {
  DCHECK(current_request_info_->request());
  SendLogMessage(base::StringPrintf("StartTracks({request_id=%d}, {label=%s})",
                                    current_request_info_->request_id(),
                                    label.Utf8().c_str()));

  WebMediaStreamDeviceObserver* media_stream_device_observer =
      GetMediaStreamDeviceObserver();

  if (media_stream_device_observer &&
      !current_request_info_->devices_set().stream_devices.empty()) {
    // TODO(crbug.com/1327960): Introduce interface to replace the four
    // separate callbacks.
    media_stream_device_observer->AddStreams(
        WebString(label), current_request_info_->devices_set(),
        {.on_device_stopped_cb = WTF::BindRepeating(
             &UserMediaProcessor::OnDeviceStopped, WrapWeakPersistent(this)),
         .on_device_changed_cb = WTF::BindRepeating(
             &UserMediaProcessor::OnDeviceChanged, WrapWeakPersistent(this)),
         .on_device_request_state_change_cb =
             WTF::BindRepeating(&UserMediaProcessor::OnDeviceRequestStateChange,
                                WrapWeakPersistent(this)),
         .on_device_capture_configuration_change_cb = WTF::BindRepeating(
             &UserMediaProcessor::OnDeviceCaptureConfigurationChange,
             WrapWeakPersistent(this)),
         .on_device_capture_handle_change_cb = WTF::BindRepeating(
             &UserMediaProcessor::OnDeviceCaptureHandleChange,
             WrapWeakPersistent(this)),
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
         .on_zoom_level_change_cb = WTF::BindRepeating(
             &UserMediaProcessor::OnZoomLevelChange, WrapWeakPersistent(this))
#endif
        });
  }

  MediaStreamsComponentsVector stream_components_set;
  for (const mojom::blink::StreamDevicesPtr& stream_devices :
       current_request_info_->devices_set().stream_devices) {
    stream_components_set.push_back(MakeGarbageCollected<MediaStreamComponents>(
        CreateAudioTrack(stream_devices->audio_device),
        CreateVideoTrack(stream_devices->video_device)));
  }

  String blink_id = label;
  current_request_info_->InitializeWebStreams(blink_id, stream_components_set);
  // Wait for the tracks to be started successfully or to fail.
  current_request_info_->CallbackOnTracksStarted(
      WTF::BindOnce(&UserMediaProcessor::OnCreateNativeTracksCompleted,
                    WrapWeakPersistent(this), label));
}

MediaStreamComponent* UserMediaProcessor::CreateVideoTrack(
    const std::optional<MediaStreamDevice>& device) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_);
  if (!device) {
    return nullptr;
  }

  current_request_info_->StartTrace("CreateVideoTrack");
  MediaStreamSource* source = InitializeVideoSourceObject(*device);
  MediaStreamComponent* component =
      current_request_info_->CreateAndStartVideoTrack(source);
  if (current_request_info_->request()->IsTransferredTrackRequest()) {
    current_request_info_->request()->SetTransferredTrackComponent(component);
  }
  return component;
}

MediaStreamComponent* UserMediaProcessor::CreateAudioTrack(
    const std::optional<MediaStreamDevice>& device) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_);
  if (!device) {
    return nullptr;
  }

  current_request_info_->StartTrace("CreateAudioTrack");
  MediaStreamDevice overriden_audio_device = *device;
  bool render_to_associated_sink =
      current_request_info_->audio_capture_settings().HasValue() &&
      current_request_info_->audio_capture_settings()
          .render_to_associated_sink();

  SendLogMessage(
      base::StringPrintf("CreateAudioTrack({render_to_associated_sink=%d})",
                         render_to_associated_sink));

  if (!render_to_associated_sink) {
    // If the GetUserMedia request did not explicitly set the constraint
    // kMediaStreamRenderToAssociatedSink, the output device id must
    // be removed.
    overriden_audio_device.matched_output_device_id.reset();
  }

  bool is_pending = false;
  MediaStreamSource* source =
      InitializeAudioSourceObject(overriden_audio_device, &is_pending);
  Member<MediaStreamComponent> component =
      MakeGarbageCollected<MediaStreamComponentImpl>(
          source,
          std::make_unique<MediaStreamAudioTrack>(true /* is_local_track */));
  if (current_request_info_->request()->IsTransferredTrackRequest()) {
    current_request_info_->request()->SetTransferredTrackComponent(component);
  }
  current_request_info_->StartAudioTrack(component, is_pending);

  // At this point the source has started, and its audio parameters have been
  // set. Thus, all audio processing properties are known and can be surfaced
  // to |source|.
  SurfaceAudioProcessingSettings(source);
  return component.Get();
}

void UserMediaProcessor::OnCreateNativeTracksCompleted(
    const String& label,
    RequestInfo* request_info,
    MediaStreamRequestResult result,
    const String& constraint_name) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(base::StringPrintf(
      "UMP::OnCreateNativeTracksCompleted({request_id=%d}, {label=%s})",
      request_info->request_id(), label.Utf8().c_str()));
  if (result == MediaStreamRequestResult::OK) {
    GetUserMediaRequestSucceeded(request_info->descriptors(),
                                 request_info->request());
  } else {
    GetUserMediaRequestFailed(result, constraint_name);

    for (const MediaStreamDescriptor* descriptor :
         *request_info->descriptors()) {
      for (auto web_track : descriptor->AudioComponents()) {
        MediaStreamTrackPlatform* track =
            MediaStreamTrackPlatform::GetTrack(WebMediaStreamTrack(web_track));
        if (track) {
          track->Stop();
        }
      }

      for (auto web_track : descriptor->VideoComponents()) {
        MediaStreamTrackPlatform* track =
            MediaStreamTrackPlatform::GetTrack(WebMediaStreamTrack(web_track));
        if (track) {
          track->Stop();
        }
      }
    }
  }

  DeleteUserMediaRequest(request_info->request());
}

void UserMediaProcessor::GetUserMediaRequestSucceeded(
    MediaStreamDescriptorVector* descriptors,
    UserMediaRequest* user_media_request) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(IsCurrentRequestInfo(user_media_request));
  SendLogMessage(
      base::StringPrintf("GetUserMediaRequestSucceeded({request_id=%d})",
                         current_request_info_->request_id()));

  // Completing the getUserMedia request can lead to that the RenderFrame and
  // the UserMediaClient/UserMediaProcessor are destroyed if the JavaScript
  // code request the frame to be destroyed within the scope of the callback.
  // Therefore, post a task to complete the request with a clean stack.
  task_runner_->PostTask(
      FROM_HERE,
      WTF::BindOnce(
          &UserMediaProcessor::DelayedGetUserMediaRequestSucceeded,
          WrapWeakPersistent(this), current_request_info_->request_id(),
          WrapPersistent(descriptors), WrapPersistent(user_media_request)));
}

void UserMediaProcessor::DelayedGetUserMediaRequestSucceeded(
    int32_t request_id,
    MediaStreamDescriptorVector* components,
    UserMediaRequest* user_media_request) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(base::StringPrintf(
      "DelayedGetUserMediaRequestSucceeded({request_id=%d}, {result=%s})",
      request_id,
      MediaStreamRequestResultToString(MediaStreamRequestResult::OK)));
  blink::LogUserMediaRequestResult(MediaStreamRequestResult::OK);
  DeleteUserMediaRequest(user_media_request);
  if (!user_media_request->IsTransferredTrackRequest()) {
    // For transferred tracks, user_media_request has already been resolved in
    // FinalizeTransferredTrackInitialization.
    user_media_request->Succeed(*components);
  }
}

void UserMediaProcessor::GetUserMediaRequestFailed(
    MediaStreamRequestResult result,
    const String& constraint_name) {
  DCHECK(current_request_info_);
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(base::StringPrintf(
      "GetUserMediaRequestFailed({request_id=%d}, constraint_name=%s)",
      current_request_info_->request_id(), constraint_name.Ascii().c_str()));

  // Completing the getUserMedia request can lead to that the RenderFrame and
  // the UserMediaClient/UserMediaProcessor are destroyed if the JavaScript
  // code request the frame to be destroyed within the scope of the callback.
  // Therefore, post a task to complete the request with a clean stack.
  task_runner_->PostTask(
      FROM_HERE,
      WTF::BindOnce(&UserMediaProcessor::DelayedGetUserMediaRequestFailed,
                    WrapWeakPersistent(this),
                    current_request_info_->request_id(),
                    WrapPersistent(current_request_info_->request()), result,
                    constraint_name));
}

void UserMediaProcessor::DelayedGetUserMediaRequestFailed(
    int32_t request_id,
    UserMediaRequest* user_media_request,
    MediaStreamRequestResult result,
    const String& constraint_name) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  blink::LogUserMediaRequestResult(result);
  SendLogMessage(base::StringPrintf(
      "DelayedGetUserMediaRequestFailed({request_id=%d}, {result=%s})",
      request_id, MediaStreamRequestResultToString(result)));
  DeleteUserMediaRequest(user_media_request);
  switch (result) {
    case MediaStreamRequestResult::OK:
    case MediaStreamRequestResult::NUM_MEDIA_REQUEST_RESULTS:
      NOTREACHED();
    case MediaStreamRequestResult::CONSTRAINT_NOT_SATISFIED:
      user_media_request->FailConstraint(constraint_name, "");
      return;
    default:
      user_media_request->Fail(result, ErrorCodeToString(result));
      return;
  }
}

MediaStreamSource* UserMediaProcessor::FindLocalSource(
    const LocalStreamSources& sources,
    const MediaStreamDevice& device) const {
  for (auto local_source : sources) {
    WebPlatformMediaStreamSource* const source =
        local_source->GetPlatformSource();
    const MediaStreamDevice& active_device = source->device();
    if (IsSameDevice(active_device, device)) {
      return local_source.Get();
    }
  }
  return nullptr;
}

MediaStreamSource* UserMediaProcessor::InitializeSourceObject(
    const MediaStreamDevice& device,
    std::unique_ptr<WebPlatformMediaStreamSource> platform_source) {
  MediaStreamSource::StreamType type = IsAudioInputMediaType(device.type)
                                           ? MediaStreamSource::kTypeAudio
                                           : MediaStreamSource::kTypeVideo;

  auto* source = MakeGarbageCollected<MediaStreamSource>(
      String::FromUTF8(device.id), device.display_id, type,
      String::FromUTF8(device.name), false /* remote */,
      std::move(platform_source));
  if (device.group_id) {
    source->SetGroupId(String::FromUTF8(*device.group_id));
  }
  return source;
}

bool UserMediaProcessor::RemoveLocalSource(MediaStreamSource* source) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(base::StringPrintf(
      "RemoveLocalSource({id=%s}, {name=%s}, {group_id=%s})",
      source->Id().Utf8().c_str(), source->GetName().Utf8().c_str(),
      source->GroupId().Utf8().c_str()));

  for (auto device_it = local_sources_.begin();
       device_it != local_sources_.end(); ++device_it) {
    if (IsSameSource(*device_it, source)) {
      local_sources_.erase(device_it);
      return true;
    }
  }

  // Check if the source was pending.
  for (auto device_it = pending_local_sources_.begin();
       device_it != pending_local_sources_.end(); ++device_it) {
    if (IsSameSource(*device_it, source)) {
      WebPlatformMediaStreamSource* const platform_source =
          source->GetPlatformSource();
      MediaStreamRequestResult result;
      String message;
      if (source->GetType() == MediaStreamSource::kTypeAudio) {
        auto error = MediaStreamAudioSource::From(source)->ErrorCode();
        switch (error.value_or(AudioSourceErrorCode::kUnknown)) {
          case AudioSourceErrorCode::kSystemPermissions:
            result = MediaStreamRequestResult::SYSTEM_PERMISSION_DENIED;
            message =
                "System Permssions prevented access to audio capture device";
            break;
          case AudioSourceErrorCode::kDeviceInUse:
            result = MediaStreamRequestResult::DEVICE_IN_USE;
            message = "Audio capture device already in use";
            break;
          default:
            result = MediaStreamRequestResult::TRACK_START_FAILURE_AUDIO;
            message = "Failed to access audio capture device";
        }
      } else {
        result = MediaStreamRequestResult::TRACK_START_FAILURE_VIDEO;
        message = "Failed to access video capture device";
      }
      NotifyCurrentRequestInfoOfAudioSourceStarted(platform_source, result,
                                                   message);
      pending_local_sources_.erase(device_it);
      return true;
    }
  }

  return false;
}

bool UserMediaProcessor::IsCurrentRequestInfo(int32_t request_id) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return current_request_info_ &&
         current_request_info_->request_id() == request_id;
}

bool UserMediaProcessor::IsCurrentRequestInfo(
    UserMediaRequest* user_media_request) const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return current_request_info_ &&
         current_request_info_->request() == user_media_request;
}

bool UserMediaProcessor::DeleteUserMediaRequest(
    UserMediaRequest* user_media_request) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (current_request_info_ &&
      current_request_info_->request() == user_media_request) {
    current_request_info_ = nullptr;
    std::move(request_completed_cb_).Run();
    return true;
  }
  return false;
}

void UserMediaProcessor::StopAllProcessing() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (current_request_info_) {
    switch (current_request_info_->state()) {
      case RequestInfo::State::kSentForGeneration:
        // Let the browser process know that the previously sent request must be
        // canceled.
        GetMediaStreamDispatcherHost()->CancelRequest(
            current_request_info_->request_id());
        [[fallthrough]];

      case RequestInfo::State::kNotSentForGeneration:
        break;

      case RequestInfo::State::kGenerated:
        break;
    }
    current_request_info_ = nullptr;
  }
  request_completed_cb_.Reset();

  // Loop through all current local sources and stop the sources.
  auto it = local_sources_.begin();
  while (it != local_sources_.end()) {
    StopLocalSource(*it, true);
    it = local_sources_.erase(it);
  }
}

void UserMediaProcessor::OnLocalSourceStopped(
    const blink::WebMediaStreamSource& source) {
  // The client can be null if the frame is already detached.
  // If it's already detached, dispatcher_host_ shouldn't be bound again.
  // (ref: crbug.com/1105842)
  if (!frame_->Client()) {
    return;
  }

  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  blink::WebPlatformMediaStreamSource* source_impl = source.GetPlatformSource();
  SendLogMessage(base::StringPrintf(
      "OnLocalSourceStopped({session_id=%s})",
      source_impl->device().session_id().ToString().c_str()));

  const bool some_source_removed = RemoveLocalSource(source);
  CHECK(some_source_removed);

  if (auto* media_stream_device_observer = GetMediaStreamDeviceObserver()) {
    media_stream_device_observer->RemoveStreamDevice(source_impl->device());
  }

  String device_id(source_impl->device().id.data());
  GetMediaStreamDispatcherHost()->StopStreamDevice(
      device_id, source_impl->device().serializable_session_id());
}

void UserMediaProcessor::StopLocalSource(MediaStreamSource* source,
                                         bool notify_dispatcher) {
  WebPlatformMediaStreamSource* source_impl = source->GetPlatformSource();
  if (!source_impl) {
    return;
  }
  SendLogMessage(base::StringPrintf(
      "StopLocalSource({session_id=%s})",
      source_impl->device().session_id().ToString().c_str()));

  if (notify_dispatcher) {
    if (auto* media_stream_device_observer = GetMediaStreamDeviceObserver()) {
      media_stream_device_observer->RemoveStreamDevice(source_impl->device());
    }

    String device_id(source_impl->device().id.data());
    GetMediaStreamDispatcherHost()->StopStreamDevice(
        device_id, source_impl->device().serializable_session_id());
  }

  source_impl->ResetSourceStoppedCallback();
  source_impl->StopSource();
}

bool UserMediaProcessor::HasActiveSources() const {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return !local_sources_.empty();
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
void UserMediaProcessor::FocusCapturedSurface(const String& label, bool focus) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  GetMediaStreamDispatcherHost()->FocusCapturedSurface(label, focus);
}
#endif

mojom::blink::MediaStreamDispatcherHost*
UserMediaProcessor::GetMediaStreamDispatcherHost() {
  if (!dispatcher_host_.is_bound()) {
    frame_->GetBrowserInterfaceBroker().GetInterface(
        dispatcher_host_.BindNewPipeAndPassReceiver(task_runner_));
  }
  return dispatcher_host_.get();
}

mojom::blink::MediaDevicesDispatcherHost*
UserMediaProcessor::GetMediaDevicesDispatcher() {
  return media_devices_dispatcher_cb_.Run();
}

const blink::AudioCaptureSettings&
UserMediaProcessor::AudioCaptureSettingsForTesting() const {
  DCHECK(current_request_info_);
  return current_request_info_->audio_capture_settings();
}

const Vector<blink::AudioCaptureSettings>&
UserMediaProcessor::EligibleAudioCaptureSettingsForTesting() const {
  DCHECK(current_request_info_);
  return current_request_info_->eligible_audio_settings();
}

const blink::VideoCaptureSettings&
UserMediaProcessor::VideoCaptureSettingsForTesting() const {
  DCHECK(current_request_info_);
  return current_request_info_->video_capture_settings();
}

const Vector<blink::VideoCaptureSettings>&
UserMediaProcessor::EligibleVideoCaptureSettingsForTesting() const {
  DCHECK(current_request_info_);
  return current_request_info_->eligible_video_settings();
}

void UserMediaProcessor::SetMediaStreamDeviceObserverForTesting(
    WebMediaStreamDeviceObserver* media_stream_device_observer) {
  DCHECK(!GetMediaStreamDeviceObserver());
  DCHECK(media_stream_device_observer);
  media_stream_device_observer_for_testing_ = media_stream_device_observer;
}

void UserMediaProcessor::KeepDeviceAliveForTransfer(
    base::UnguessableToken session_id,
    base::UnguessableToken transfer_id,
    KeepDeviceAliveForTransferCallback keep_alive_cb) {
  GetMediaStreamDispatcherHost()->KeepDeviceAliveForTransfer(
      session_id, transfer_id, std::move(keep_alive_cb));
}

}  // namespace blink

"""


```