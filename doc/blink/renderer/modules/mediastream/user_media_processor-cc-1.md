Response:
The user wants a summary of the functionality of the provided C++ code snippet from `user_media_processor.cc`. This is the second part of a three-part series, suggesting the need for a high-level overview rather than a deep dive into each function.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Identify the Core Functionality:**  The code primarily deals with setting up audio and video inputs based on user media requests. Key actions include:
    * Determining existing audio sessions.
    * Selecting appropriate audio and video device settings based on constraints.
    * Initiating the stream generation process.
    * Handling responses from the browser process regarding device access and capabilities.
    * Managing the lifecycle of media streams and their sources.

2. **Group Related Functions:** Notice how certain functions logically belong together. For example, `DetermineExistingAudioSessionId` and `DetermineExistingAudioSessionIds` are clearly related to managing audio sessions. `SetupAudioInput` and `SetupVideoInput` are about the initial setup of different media types.

3. **Trace the Flow:**  The code demonstrates a sequential flow of operations. A request comes in, audio is processed, then video, and finally, a stream is generated. Understanding this flow helps in summarizing the overall process.

4. **Identify Interactions with External Components:** The code interacts with:
    * JavaScript (through user media requests and callbacks).
    * HTML (implicitly, as user media requests originate from web pages).
    * CSS (less direct, but the ability to control media streams can affect visual elements).
    * The browser's media device infrastructure (through `GetMediaDevicesDispatcherHost`).

5. **Look for Logic and Decision Points:** The code makes decisions based on constraints, device capabilities, and the type of media requested. Highlighting these decision points is crucial for understanding the logic.

6. **Spot Potential Errors and User Mistakes:** The code handles scenarios where constraints cannot be satisfied or no hardware is available. This suggests potential user errors in specifying constraints or lacking necessary hardware.

7. **Consider the Debugging Aspect:**  The code includes logging and tracing, which are essential for debugging. The sequence of function calls and the information logged provide a trace of how the code is executed.

8. **Focus on the "Part 2" Context:**  Since this is part 2, assume that part 1 covered the initial handling of user media requests. This part seems to be focused on the detailed setup of audio and video *after* the initial request is received.

9. **Synthesize the Information:** Combine the identified functionalities, interactions, logic, and error handling into concise bullet points. Use clear and understandable language.

10. **Provide Examples:**  Illustrate the interactions with JavaScript, HTML, and CSS with concrete examples.

11. **Create Hypothetical Input/Output:**  Develop a simple scenario to demonstrate the logical flow and how different inputs lead to specific outputs (e.g., failing due to unsatisfied constraints).

12. **Illustrate Common Errors:** Give examples of common user/programming errors related to media requests.

13. **Describe User Actions Leading to this Code:** Explain the sequence of user actions in a web page that would trigger this part of the code execution.

14. **Refine and Organize:** Review the summary for clarity, accuracy, and completeness. Ensure a logical flow and consistent terminology.

**(Self-Correction during the process):**  Initially, I might focus too much on individual function details. The prompt emphasizes the overall "functionality" and its relation to web technologies. Therefore, I should shift the focus to the broader purpose of each section of code and how it contributes to the larger goal of getting user media. Also, the "Part 2" context is important – avoid repeating details likely covered in "Part 1."  Emphasize what this specific section *adds* to the overall process.
```
**这是 UserMediaProcessor.cc 文件的第 2 部分，主要负责处理用户媒体请求中的音频和视频输入设置，并最终生成媒体流。**

**归纳一下它的功能：**

1. **音频输入设置 (`SetupAudioInput`)**:
    * 判断是否需要音频输入。
    * 调用 `GetAudioInputCapabilities` 获取可用的音频设备能力。
    * 根据用户指定的音频约束 (`AudioConstraints`) 和设备能力，选择合适的音频设备设置 (`SelectSettingsAudioCapture` 或 `SelectEligibleSettingsAudioCapture`)。
    * 如果找不到满足约束的设备，则调用 `GetUserMediaRequestFailed` 报告失败。
    * 如果成功选择设备，则记录选择的设备 ID 和其他设置（例如，是否禁用本地回声）。
    * 对于某些类型的音频流（例如，屏幕共享音频），不会设置特定的设备 ID。
    * 调用 `SetupVideoInput` 继续处理视频输入。

2. **确定现有音频会话 ID (`DetermineExistingAudioSessionId`, `DetermineExistingAudioSessionIds`)**:
    * 查找已经存在的、与当前请求中指定的音频设备 ID 相同的 `MediaStreamSource` 对象。
    * 如果找到匹配的 `MediaStreamSource`，并且其音频源具有相同的可重新配置设置，则返回其会话 ID。
    * 这用于复用现有的音频会话，避免重复请求设备访问。

3. **视频输入设置 (`SetupVideoInput`)**:
    * 判断是否需要视频输入。
    * 如果不需要视频，则调用 `GenerateStreamForCurrentRequestInfo` 生成媒体流（只包含音频）。
    * 如果需要视频，则记录视频约束。
    * 设置视频流的类型 (`stream_type`) 和其他控制标志（例如，是否请求 PTZ 权限，是否为屏幕共享）。
    * 如果请求的是设备视频输入 (`DEVICE_VIDEO_CAPTURE`)，则调用 `GetVideoInputCapabilities` 获取可用的视频设备能力，然后调用 `SelectVideoDeviceSettings` 进行设置选择。
    * 如果请求的是其他类型的视频输入（例如，屏幕共享），则调用 `SelectVideoContentSettings` 进行设置选择。
    * 如果视频输入类型无效，则调用 `GetUserMediaRequestFailed` 报告失败。

4. **选择视频设备设置 (`SelectVideoDeviceSettings`)**:
    * 在获取到视频设备能力后被调用。
    * 根据用户指定的视频约束和设备能力，选择合适的视频设备设置 (`SelectSettingsVideoDeviceCapture` 或 `SelectEligibleSettingsVideoDeviceCapture`)。
    * 如果找不到满足约束的设备，则调用 `GetUserMediaRequestFailed` 报告失败。
    * 如果成功选择设备，则记录选择的设备 ID。
    * 调用 `GenerateStreamForCurrentRequestInfo` 生成媒体流。

5. **选择视频内容设置 (`SelectVideoContentSettings`)**:
    * 用于非设备视频捕获的情况（例如，屏幕共享）。
    * 根据用户指定的视频约束和屏幕尺寸，选择合适的视频内容捕获设置 (`SelectSettingsVideoContentCapture`)。
    * 如果找不到满足约束的设置，则调用 `GetUserMediaRequestFailed` 报告失败。
    * 记录选择的设备 ID（对于某些内容捕获类型）。
    * 调用 `GenerateStreamForCurrentRequestInfo` 生成媒体流。

6. **生成当前请求的媒体流 (`GenerateStreamForCurrentRequestInfo`)**:
    * 在完成音频和视频输入设置后被调用。
    * 设置请求状态为 "已发送以生成"。
    * 如果当前请求是请求转移的媒体流轨道，则调用 `GetMediaStreamDispatcherHost()->GetOpenDevice`。
    * 否则，调用 `GetMediaStreamDispatcherHost()->GenerateStreams` 请求浏览器生成媒体流，并将结果通过 `OnStreamsGenerated` 回调返回。

7. **处理 `getDisplayMedia` 的全屏捕获请求 (`IsPanTiltZoomPermissionRequested`)**:
    * 检查视频约束中是否请求了 PTZ (Pan, Tilt, Zoom) 权限。

8. **获取媒体流设备观察者 (`GetMediaStreamDeviceObserver`)**:
    * 用于获取与当前 `WebFrame` 关联的 `WebMediaStreamDeviceObserver` 对象，用于监听设备状态变化。

9. **处理打开设备的回调 (`GotOpenDevice`)**:
    * 当请求打开已转移的媒体流轨道时，浏览器会调用此回调。
    * 如果成功打开设备，则调用 `OnStreamsGenerated` 继续处理。

10. **处理媒体流生成的回调 (`OnStreamsGenerated`)**:
    * 当浏览器成功生成媒体流时调用。
    * 检查请求 ID 是否有效。
    * 如果成功生成，则记录生成的设备信息，并将设备信息设置到 `current_request_info_` 中。
    * 如果包含视频轨道，则根据设备 ID 获取更详细的视频格式信息 (`GetAllVideoInputDeviceFormats`)。
    * 如果不包含视频轨道或已获取到视频格式信息，则调用 `StartTracks` 启动媒体流轨道。
    * 如果生成失败，则调用 `OnStreamGenerationFailed`。

11. **处理获取所有视频输入设备格式的回调 (`GotAllVideoInputFormatsForDevice`)**:
    * 在 `OnStreamsGenerated` 中请求获取视频设备的详细格式信息后被调用。
    * 将获取到的格式信息添加到 `current_request_info_` 中。
    * 如果所有必需的轨道信息都已准备好，则调用 `StartTracks`。

12. **处理被取消请求的媒体流生成 (`OnStreamGeneratedForCancelledRequest`)**:
    * 当一个 `getUserMedia` 请求被取消后，浏览器可能会继续生成媒体流。
    * 此函数用于处理这种情况，并停止不再需要的设备。

13. **处理音频源启动的回调 (`OnAudioSourceStartedOnAudioThread`, `OnAudioSourceStarted`)**:
    * 当音频设备被成功打开并开始产生数据时调用。
    * 将新创建的 `MediaStreamSource` 添加到 `local_sources_` 列表中。
    * 通知 `current_request_info_` 音频源已启动。

14. **处理媒体流生成失败 (`OnStreamGenerationFailed`)**:
    * 当浏览器无法生成媒体流时调用。
    * 调用 `GetUserMediaRequestFailed` 通知请求者失败。

15. **处理设备停止 (`OnDeviceStopped`)**:
    * 当一个媒体设备被停止时调用（例如，用户拔出摄像头）。
    * 查找与该设备关联的 `MediaStreamSource`，并停止它。

16. **处理设备改变 (`OnDeviceChanged`)**:
    * 当一个媒体设备改变时调用（例如，用户选择了不同的摄像头）。
    * 查找与旧设备关联的 `MediaStreamSource`，并更新其底层的设备信息。

17. **处理设备请求状态改变 (`OnDeviceRequestStateChange`)**:
    * 当一个媒体设备的状态被请求改变时调用（例如，静音/取消静音）。
    * 查找与该设备关联的 `MediaStreamSource`，并更新其状态。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**
    * `navigator.mediaDevices.getUserMedia()` 是触发此代码执行的入口点。JavaScript 代码通过传递约束对象来指定所需的媒体类型和属性。
    * **举例：**
      ```javascript
      navigator.mediaDevices.getUserMedia({ audio: true, video: { width: 1280, height: 720 } })
        .then(function(stream) {
          // 使用 stream
        })
        .catch(function(err) {
          // 处理错误
        });
      ```
      这段 JavaScript 代码请求一个包含音频和视频的媒体流，并指定了视频的分辨率约束。这些约束会被传递到 C++ 代码中进行处理。
* **HTML:**
    * HTML 元素（如 `<video>` 或 `<audio>`) 可以用于显示或播放获取到的媒体流。
    * **举例：**
      ```html
      <video id="myVideo" autoplay playsinline></video>
      <script>
        navigator.mediaDevices.getUserMedia({ video: true })
          .then(function(stream) {
            document.getElementById('myVideo').srcObject = stream;
          });
      </script>
      ```
      这段 HTML 代码包含一个 `<video>` 元素，JavaScript 代码将获取到的视频流赋值给该元素的 `srcObject` 属性，从而在页面上显示视频。
* **CSS:**
    * CSS 可以用于控制媒体元素的样式，例如大小、位置、边框等。
    * **举例：**
      ```css
      #myVideo {
        width: 640px;
        height: 480px;
      }
      ```
      这段 CSS 代码设置了 ID 为 `myVideo` 的视频元素的宽度和高度。

**逻辑推理的例子：**

**假设输入：**

* 用户通过 JavaScript 请求获取音频和视频，并指定了特定的音频设备 ID 和最小视频宽度为 1280。
* 系统中存在两个音频设备：设备 A (ID: "audio_dev_1") 和设备 B (ID: "audio_dev_2")。
* 系统中存在两个视频设备：摄像头 C (ID: "video_dev_1", 支持 1920x1080) 和摄像头 D (ID: "video_dev_2", 支持 640x480)。

**输出：**

1. **`SetupAudioInput`**:
   * `GetAudioInputCapabilities` 获取到设备 A 和设备 B 的能力。
   * `SelectSettingsAudioCapture` 根据指定的音频设备 ID "audio_dev_1" 选择设备 A。
   * 如果设备 A 不存在或不可用，则 `GetUserMediaRequestFailed` 会被调用。
2. **`SetupVideoInput`**:
   * `GetVideoInputCapabilities` 获取到摄像头 C 和摄像头 D 的能力。
   * `SelectSettingsVideoDeviceCapture` 根据最小视频宽度 1280 的约束，选择摄像头 C (因为摄像头 D 的最大宽度只有 640)。
   * 如果没有满足约束的视频设备，则 `GetUserMediaRequestFailed` 会被调用。
3. **`GenerateStreamForCurrentRequestInfo`**:
   * 请求浏览器生成包含设备 A 的音频轨道和摄像头 C 的视频轨道的媒体流。

**用户或编程常见的使用错误：**

1. **请求不存在的设备 ID：**
   * **错误示例：** JavaScript 代码指定了一个系统中不存在的摄像头 ID。
   * **结果：** `SelectSettingsVideoDeviceCapture` 找不到匹配的设备，`GetUserMediaRequestFailed` 会被调用，导致 `getUserMedia` Promise 失败。
2. **指定了无法满足的约束：**
   * **错误示例：** JavaScript 代码请求的视频分辨率高于任何可用摄像头的支持。
   * **结果：** `SelectSettingsVideoDeviceCapture` 找不到满足约束的设备，`GetUserMediaRequestFailed` 会被调用。
3. **在没有用户授权的情况下访问设备：**
   * **错误示例：** 在用户没有授予摄像头或麦克风权限的情况下调用 `getUserMedia`。
   * **结果：** 浏览器会提示用户授权，如果用户拒绝，`getUserMedia` Promise 会失败，但这个错误通常在更早的阶段被处理，可能不会到达这个代码。
4. **在不安全的环境下（非 HTTPS）调用 `getUserMedia`：**
   * **错误示例：** 在一个 HTTP 页面上调用 `getUserMedia`。
   * **结果：** 浏览器会阻止访问设备，`getUserMedia` Promise 会失败，通常不会到达这个代码。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户访问一个网页，该网页包含使用 `getUserMedia` 的 JavaScript 代码。**
2. **JavaScript 代码调用 `navigator.mediaDevices.getUserMedia(constraints)`，其中 `constraints` 对象描述了所需的媒体类型和属性。**
3. **浏览器接收到 `getUserMedia` 请求，并开始处理。**
4. **在 Blink 渲染引擎中，`UserMediaRequest` 对象被创建，并包含了来自 JavaScript 的约束信息。**
5. **`UserMediaProcessor::ProcessUserMediaRequest` 方法被调用，启动媒体处理流程。**
6. **如果请求包含音频 (`constraints.audio` 为真)，则 `SetupAudioInput` 方法被调用。**
7. **在 `SetupAudioInput` 中，会调用 `GetMediaDevicesDispatcher()->GetAudioInputCapabilities` 向浏览器进程请求可用的音频设备能力。**
8. **浏览器进程返回音频设备能力信息。**
9. **`SelectSettingsAudioCapture` 或 `SelectEligibleSettingsAudioCapture` 方法根据约束和设备能力选择合适的音频设备。**
10. **如果请求包含视频 (`constraints.video` 为真)，则在 `SetupAudioInput` 完成后，`SetupVideoInput` 方法被调用。**
11. **类似地，`SetupVideoInput` 会调用 `GetMediaDevicesDispatcher()->GetVideoInputCapabilities` 请求视频设备能力。**
12. **浏览器进程返回视频设备能力信息。**
13. **`SelectSettingsVideoDeviceCapture` 或 `SelectVideoContentSettings` 方法根据约束和设备能力选择合适的视频设备。**
14. **最终，`GenerateStreamForCurrentRequestInfo` 方法被调用，向浏览器进程发送生成媒体流的请求。**

调试时，可以关注以下几点：

* **检查 JavaScript 代码中传递给 `getUserMedia` 的约束是否正确。**
* **查看浏览器控制台的错误信息，了解 `getUserMedia` Promise 是否被拒绝，以及拒绝的原因。**
* **使用 Chrome 的 `chrome://webrtc-internals` 页面查看详细的 WebRTC 日志，可以跟踪 `getUserMedia` 请求的处理过程，包括设备枚举、能力查询、约束匹配等。**
* **在 `UserMediaProcessor.cc` 中添加日志输出，可以了解代码执行的具体流程和变量的值。**

这是 `UserMediaProcessor.cc` 文件在处理用户媒体请求过程中非常核心的一部分，负责根据用户的需求和系统能力，选择合适的媒体设备并准备生成媒体流。
```
### 提示词
```
这是目录为blink/renderer/modules/mediastream/user_media_processor.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
_request->AudioConstraints(),
            current_request_info_->stream_controls()->audio.stream_type,
            user_media_request->ShouldDisableHardwareNoiseSuppression(),
            /*is_reconfiguration_allowed=*/true);
    if (!eligible_settings.has_value()) {
      String failed_constraint_name = String(eligible_settings.error());
      MediaStreamRequestResult result =
          failed_constraint_name.empty()
              ? MediaStreamRequestResult::NO_HARDWARE
              : MediaStreamRequestResult::CONSTRAINT_NOT_SATISFIED;
      GetUserMediaRequestFailed(result, failed_constraint_name);
      return;
    }

    std::vector<std::string> eligible_ids;
    eligible_ids.reserve(eligible_settings->size());
    for (const auto& settings : eligible_settings.value()) {
      eligible_ids.push_back(settings.device_id());
    }
    current_request_info_->stream_controls()->audio.device_ids = eligible_ids;
    current_request_info_->SetEligibleAudioCaptureSettings(
        std::move(eligible_settings.value()));
  } else {
    auto settings = SelectSettingsAudioCapture(
        capabilities, user_media_request->AudioConstraints(),
        current_request_info_->stream_controls()->audio.stream_type,
        user_media_request->ShouldDisableHardwareNoiseSuppression(),
        /*is_reconfiguration_allowed=*/true);
    if (!settings.HasValue()) {
      String failed_constraint_name = String(settings.failed_constraint_name());
      MediaStreamRequestResult result =
          failed_constraint_name.empty()
              ? MediaStreamRequestResult::NO_HARDWARE
              : MediaStreamRequestResult::CONSTRAINT_NOT_SATISFIED;
      GetUserMediaRequestFailed(result, failed_constraint_name);
      return;
    }
    if (current_request_info_->stream_controls()->audio.stream_type !=
        MediaStreamType::DISPLAY_AUDIO_CAPTURE) {
      current_request_info_->stream_controls()->audio.device_ids = {
          settings.device_id()};
      current_request_info_->stream_controls()->disable_local_echo =
          settings.disable_local_echo();
    }
    current_request_info_->SetEligibleAudioCaptureSettings({settings});
    current_request_info_->SetAudioCaptureSettings(
        settings,
        !blink::IsDeviceMediaType(
            current_request_info_->stream_controls()->audio.stream_type));
  }

  // No further audio setup required. Continue with video.
  SetupVideoInput();
}

std::optional<base::UnguessableToken>
UserMediaProcessor::DetermineExistingAudioSessionId(
    const blink::AudioCaptureSettings& settings) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_->request()->Audio());

  auto device_id = settings.device_id();

  // Create a copy of the MediaStreamSource objects that are
  // associated to the same audio device capture based on its device ID.
  HeapVector<Member<MediaStreamSource>> matching_sources;

  // Take a defensive copy, as local_sources_ can be modified during
  // destructions in GC runs triggered by the push_back allocation in this loop.
  // crbug.com/1238209
  HeapVector<Member<MediaStreamSource>> local_sources_copy = local_sources_;
  for (const auto& source : local_sources_copy) {
    MediaStreamSource* source_copy = source;
    if (source_copy->GetType() == MediaStreamSource::kTypeAudio &&
        source_copy->Id().Utf8() == device_id) {
      matching_sources.push_back(source_copy);
    }
  }

  // Return the session ID associated to the source that has the same settings
  // that have been previously selected, if one exists.
  if (!matching_sources.empty()) {
    for (auto& matching_source : matching_sources) {
      auto* audio_source = static_cast<MediaStreamAudioSource*>(
          matching_source->GetPlatformSource());
      if (audio_source->HasSameReconfigurableSettings(
              settings.audio_processing_properties())) {
        return audio_source->device().session_id();
      }
    }
  }

  return std::nullopt;
}

WTF::HashMap<String, base::UnguessableToken>
UserMediaProcessor::DetermineExistingAudioSessionIds() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_->request()->Audio());

  WTF::HashMap<String, base::UnguessableToken> session_id_map;

  for (const auto& settings :
       current_request_info_->eligible_audio_settings()) {
    auto session_id = DetermineExistingAudioSessionId(settings);
    if (session_id) {
      session_id_map.insert(String{settings.device_id()}, session_id.value());
    }
  }

  return session_id_map;
}

void UserMediaProcessor::SetupVideoInput() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_);

  UserMediaRequest* const request = current_request_info_->request();

  if (!request->Video()) {
    auto audio_session_ids = DetermineExistingAudioSessionIds();
    GenerateStreamForCurrentRequestInfo(audio_session_ids);
    return;
  }
  SendLogMessage(base::StringPrintf(
      "SetupVideoInput. request_id=%d, video constraints=%s",
      current_request_info_->request_id(),
      request->VideoConstraints().ToString().Utf8().c_str()));

  auto& video_controls = current_request_info_->stream_controls()->video;
  video_controls.stream_type = request->VideoMediaStreamType();

  StreamControls* const stream_controls =
      current_request_info_->stream_controls();

  stream_controls->request_pan_tilt_zoom_permission =
      IsPanTiltZoomPermissionRequested(request->VideoConstraints());

  stream_controls->request_all_screens =
      request->MediaRequestType() == UserMediaRequestType::kAllScreensMedia;

  stream_controls->exclude_self_browser_surface =
      request->exclude_self_browser_surface();

  stream_controls->preferred_display_surface =
      request->preferred_display_surface();

  stream_controls->dynamic_surface_switching_requested =
      request->dynamic_surface_switching_requested();

  stream_controls->exclude_monitor_type_surfaces =
      request->exclude_monitor_type_surfaces();

  if (blink::IsDeviceMediaType(video_controls.stream_type)) {
    current_request_info_->StartTrace("GetVideoInputCapabilities");
    GetMediaDevicesDispatcher()->GetVideoInputCapabilities(
        WTF::BindOnce(&UserMediaProcessor::SelectVideoDeviceSettings,
                      WrapWeakPersistent(this), WrapPersistent(request)));
  } else {
    if (!blink::IsVideoInputMediaType(video_controls.stream_type)) {
      String failed_constraint_name = String(
          request->VideoConstraints().Basic().media_stream_source.GetName());
      MediaStreamRequestResult result =
          MediaStreamRequestResult::CONSTRAINT_NOT_SATISFIED;
      GetUserMediaRequestFailed(result, failed_constraint_name);
      return;
    }
    SelectVideoContentSettings();
  }
}

// static
bool UserMediaProcessor::IsPanTiltZoomPermissionRequested(
    const MediaConstraints& constraints) {
  if (constraints.Basic().pan.IsPresent() ||
      constraints.Basic().tilt.IsPresent() ||
      constraints.Basic().zoom.IsPresent()) {
    return true;
  }

  for (const auto& advanced_set : constraints.Advanced()) {
    if (advanced_set.pan.IsPresent() || advanced_set.tilt.IsPresent() ||
        advanced_set.zoom.IsPresent()) {
      return true;
    }
  }

  return false;
}

void UserMediaProcessor::SelectVideoDeviceSettings(
    UserMediaRequest* user_media_request,
    Vector<mojom::blink::VideoInputDeviceCapabilitiesPtr>
        video_input_capabilities) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // The frame might reload or |user_media_request| might be cancelled while
  // capabilities are queried. Do nothing if a different request is being
  // processed at this point.
  if (!IsCurrentRequestInfo(user_media_request)) {
    return;
  }

  current_request_info_->EndTrace("GetVideoInputCapabilities");
  DCHECK(current_request_info_->stream_controls()->video.requested());
  DCHECK(blink::IsDeviceMediaType(
      current_request_info_->stream_controls()->video.stream_type));
  SendLogMessage(base::StringPrintf("SelectVideoDeviceSettings. request_id=%d.",
                                    current_request_info_->request_id()));

  blink::VideoDeviceCaptureCapabilities capabilities;
  capabilities.device_capabilities =
      ToVideoInputDeviceCapabilities(video_input_capabilities);
  capabilities.noise_reduction_capabilities = {std::optional<bool>(),
                                               std::optional<bool>(true),
                                               std::optional<bool>(false)};

  // Determine and log one CameraCaptureCapability per device.
  if (user_media_request->MediaRequestType() ==
          UserMediaRequestType::kUserMedia &&
      user_media_request->VideoMediaStreamType() ==
          MediaStreamType::DEVICE_VIDEO_CAPTURE) {
    for (auto& device : capabilities.device_capabilities) {
      bool has_360p = false;
      bool has_480p = false;
      bool has_720p_or_1080p = false;
      for (const auto& format : device.formats) {
        if (format.frame_size.width() == 640) {
          has_360p |= format.frame_size.height() == 360;
          has_480p |= format.frame_size.height() == 480;
        }
        has_720p_or_1080p |= format.frame_size.width() == 1280 &&
                             format.frame_size.height() == 720;
        has_720p_or_1080p |= format.frame_size.width() == 1920 &&
                             format.frame_size.height() == 1080;
      }
      if (has_720p_or_1080p) {
        if (has_360p) {
          if (has_480p) {
            LogCameraCaptureCapability(
                CameraCaptureCapability::kHdOrFullHd_360p_480p);
          } else {
            LogCameraCaptureCapability(
                CameraCaptureCapability::kHdOrFullHd_360p);
          }
        } else {
          if (has_480p) {
            LogCameraCaptureCapability(
                CameraCaptureCapability::kHdOrFullHd_480p);
          } else {
            LogCameraCaptureCapability(CameraCaptureCapability::kHdOrFullHd);
          }
        }
      } else {
        LogCameraCaptureCapability(
            CameraCaptureCapability::kHdAndFullHdMissing);
      }
    }
  }

  // Do constraints processing.
  if (ShouldDeferDeviceSettingsSelection(
          user_media_request->MediaRequestType(),
          user_media_request->VideoMediaStreamType(),
          user_media_request->GetExecutionContext())) {
    auto eligible_settings = SelectEligibleSettingsVideoDeviceCapture(
        std::move(capabilities), user_media_request->VideoConstraints(),
        blink::MediaStreamVideoSource::kDefaultWidth,
        blink::MediaStreamVideoSource::kDefaultHeight,
        blink::MediaStreamVideoSource::kDefaultFrameRate);
    if (!eligible_settings.has_value()) {
      String failed_constraint_name = String(eligible_settings.error());
      MediaStreamRequestResult result =
          failed_constraint_name.empty()
              ? MediaStreamRequestResult::NO_HARDWARE
              : MediaStreamRequestResult::CONSTRAINT_NOT_SATISFIED;
      GetUserMediaRequestFailed(result, failed_constraint_name);
      return;
    }

    std::vector<std::string> eligible_ids;
    eligible_ids.reserve(eligible_settings->size());
    for (const auto& settings : eligible_settings.value()) {
      eligible_ids.push_back(settings.device_id());
    }
    current_request_info_->stream_controls()->video.device_ids = eligible_ids;
    current_request_info_->SetEligibleVideoCaptureSettings(
        std::move(eligible_settings.value()));
  } else {
    blink::VideoCaptureSettings settings = SelectSettingsVideoDeviceCapture(
        std::move(capabilities), user_media_request->VideoConstraints(),
        blink::MediaStreamVideoSource::kDefaultWidth,
        blink::MediaStreamVideoSource::kDefaultHeight,
        blink::MediaStreamVideoSource::kDefaultFrameRate);
    if (!settings.HasValue()) {
      String failed_constraint_name = String(settings.failed_constraint_name());
      MediaStreamRequestResult result =
          failed_constraint_name.empty()
              ? MediaStreamRequestResult::NO_HARDWARE
              : MediaStreamRequestResult::CONSTRAINT_NOT_SATISFIED;
      GetUserMediaRequestFailed(result, failed_constraint_name);
      return;
    }
    current_request_info_->stream_controls()->video.device_ids = {
        settings.device_id()};
    current_request_info_->SetVideoCaptureSettings(
        settings, false /* is_content_capture */);
  }

  if (current_request_info_->request()->Audio()) {
    auto audio_session_ids = DetermineExistingAudioSessionIds();
    GenerateStreamForCurrentRequestInfo(audio_session_ids);
  } else {
    GenerateStreamForCurrentRequestInfo();
  }
}

void UserMediaProcessor::SelectVideoContentSettings() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_);
  SendLogMessage(
      base::StringPrintf("SelectVideoContentSettings. request_id=%d.",
                         current_request_info_->request_id()));
  gfx::Size screen_size = MediaStreamUtils::GetScreenSize(frame_);
  blink::VideoCaptureSettings settings =
      blink::SelectSettingsVideoContentCapture(
          current_request_info_->request()->VideoConstraints(),
          current_request_info_->stream_controls()->video.stream_type,
          screen_size.width(), screen_size.height());
  if (!settings.HasValue()) {
    String failed_constraint_name = String(settings.failed_constraint_name());
    DCHECK(!failed_constraint_name.empty());

    GetUserMediaRequestFailed(
        MediaStreamRequestResult::CONSTRAINT_NOT_SATISFIED,
        failed_constraint_name);
    return;
  }

  const MediaStreamType stream_type =
      current_request_info_->stream_controls()->video.stream_type;
  if (stream_type != MediaStreamType::DISPLAY_VIDEO_CAPTURE &&
      stream_type != MediaStreamType::DISPLAY_VIDEO_CAPTURE_THIS_TAB &&
      stream_type != MediaStreamType::DISPLAY_VIDEO_CAPTURE_SET) {
    current_request_info_->stream_controls()->video.device_ids = {
        settings.device_id()};
  }

  current_request_info_->SetVideoCaptureSettings(settings,
                                                 true /* is_content_capture */);
  GenerateStreamForCurrentRequestInfo();
}

void UserMediaProcessor::GenerateStreamForCurrentRequestInfo(
    WTF::HashMap<String, base::UnguessableToken>
        requested_audio_capture_session_ids) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(current_request_info_);
  SendLogMessage(base::StringPrintf(
      "GenerateStreamForCurrentRequestInfo({request_id=%d}, "
      "{audio.device_ids=%s}, {video.device_ids=%s})",
      current_request_info_->request_id(),
      base::JoinString(
          current_request_info_->stream_controls()->audio.device_ids, ",")
          .c_str(),
      base::JoinString(
          current_request_info_->stream_controls()->video.device_ids, ",")
          .c_str()));
  current_request_info_->set_state(RequestInfo::State::kSentForGeneration);

  // Capture trace for only non-transferred tracks.
  current_request_info_->StartTrace("GenerateStreams");

  // If SessionId is set, this request is for a transferred MediaStreamTrack and
  // GetOpenDevice() should be called.
  if (current_request_info_->request() &&
      current_request_info_->request()->IsTransferredTrackRequest()) {
    MediaStreamRequestResult result = MediaStreamRequestResult::INVALID_STATE;
    blink::mojom::blink::GetOpenDeviceResponsePtr response;
    GetMediaStreamDispatcherHost()->GetOpenDevice(
        current_request_info_->request_id(),
        *current_request_info_->request()->GetSessionId(),
        *current_request_info_->request()->GetTransferId(), &result, &response);
    GotOpenDevice(current_request_info_->request_id(), result,
                  std::move(response));
  } else {
    // The browser replies to this request by invoking OnStreamsGenerated().
    GetMediaStreamDispatcherHost()->GenerateStreams(
        current_request_info_->request_id(),
        *current_request_info_->stream_controls(),
        current_request_info_->is_processing_user_gesture(),
        mojom::blink::StreamSelectionInfo::NewSearchBySessionId(
            mojom::blink::SearchBySessionId::New(
                requested_audio_capture_session_ids)),
        WTF::BindOnce(&UserMediaProcessor::OnStreamsGenerated,
                      WrapWeakPersistent(this),
                      current_request_info_->request_id()));
  }
}

WebMediaStreamDeviceObserver*
UserMediaProcessor::GetMediaStreamDeviceObserver() {
  auto* media_stream_device_observer =
      media_stream_device_observer_for_testing_.get();
  if (frame_) {  // Can be null for tests.
    auto* web_frame =
        static_cast<WebLocalFrame*>(WebFrame::FromCoreFrame(frame_));
    if (!web_frame || !web_frame->Client()) {
      return nullptr;
    }

    // TODO(704136): Move ownership of |WebMediaStreamDeviceObserver| out of
    // RenderFrameImpl, back to UserMediaClient.
    media_stream_device_observer =
        web_frame->Client()->MediaStreamDeviceObserver();
    DCHECK(media_stream_device_observer);
  }

  return media_stream_device_observer;
}

void UserMediaProcessor::GotOpenDevice(
    int32_t request_id,
    mojom::blink::MediaStreamRequestResult result,
    mojom::blink::GetOpenDeviceResponsePtr response) {
  if (result != MediaStreamRequestResult::OK) {
    OnStreamGenerationFailed(request_id, result);
    return;
  }

  mojom::blink::StreamDevicesPtr devices = mojom::blink::StreamDevices::New();
  if (IsAudioInputMediaType(response->device.type)) {
    devices->audio_device = response->device;
  } else if (IsVideoInputMediaType(response->device.type)) {
    devices->video_device = response->device;
  } else {
    NOTREACHED();
  }

  mojom::blink::StreamDevicesSetPtr stream_devices_set =
      mojom::blink::StreamDevicesSet::New();
  stream_devices_set->stream_devices.emplace_back(std::move(devices));
  OnStreamsGenerated(request_id, result, response->label,
                     std::move(stream_devices_set),
                     response->pan_tilt_zoom_allowed);
  current_request_info_->request()->FinalizeTransferredTrackInitialization(
      *current_request_info_->descriptors());
}

void UserMediaProcessor::OnStreamsGenerated(
    int32_t request_id,
    MediaStreamRequestResult result,
    const String& label,
    mojom::blink::StreamDevicesSetPtr stream_devices_set,
    bool pan_tilt_zoom_allowed) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (current_request_info_) {
    current_request_info_->EndTrace("GenerateStreams");
  }

  if (result != MediaStreamRequestResult::OK) {
    DCHECK(!stream_devices_set);
    OnStreamGenerationFailed(request_id, result);
    return;
  }

  if (!IsCurrentRequestInfo(request_id)) {
    // This can happen if the request is canceled or the frame reloads while
    // MediaStreamDispatcherHost is processing the request.
    SendLogMessage(base::StringPrintf(
        "OnStreamsGenerated([request_id=%d]) => (ERROR: invalid request ID)",
        request_id));
    blink::LogUserMediaRequestResult(
        MediaStreamRequestResult::REQUEST_CANCELLED);
    for (const mojom::blink::StreamDevicesPtr& stream_devices :
         stream_devices_set->stream_devices) {
      OnStreamGeneratedForCancelledRequest(*stream_devices);
    }
    return;
  }

  const auto* execution_context =
      current_request_info_->request()->GetExecutionContext();
  if (ShouldDeferDeviceSettingsSelection(
          current_request_info_->request()->MediaRequestType(),
          current_request_info_->request()->AudioMediaStreamType(),
          execution_context) &&
      !current_request_info_->eligible_audio_settings().empty() &&
      stream_devices_set->stream_devices.front()->audio_device.has_value()) {
    const std::string selected_id =
        stream_devices_set->stream_devices.front()->audio_device->id;
    const auto& eligible_audio_settings =
        current_request_info_->eligible_audio_settings();
    const auto selected_audio_settings = std::find_if(
        eligible_audio_settings.begin(), eligible_audio_settings.end(),
        [selected_id](const auto& settings) {
          return settings.device_id() == selected_id;
        });
    CHECK_NE(selected_audio_settings, eligible_audio_settings.end());
    current_request_info_->SetAudioCaptureSettings(
        *selected_audio_settings,
        /*is_content_capture=*/false);
    if (current_request_info_->stream_controls()->audio.stream_type !=
        MediaStreamType::DISPLAY_AUDIO_CAPTURE) {
      current_request_info_->stream_controls()->disable_local_echo =
          selected_audio_settings->disable_local_echo();
    }
  }
  if (ShouldDeferDeviceSettingsSelection(
          current_request_info_->request()->MediaRequestType(),
          current_request_info_->request()->VideoMediaStreamType(),
          execution_context) &&
      !current_request_info_->eligible_video_settings().empty() &&
      stream_devices_set->stream_devices.front()->video_device.has_value()) {
    const std::string selected_id =
        stream_devices_set->stream_devices.front()->video_device->id;
    const auto& eligible_video_settings =
        current_request_info_->eligible_video_settings();
    const auto selected_video_settings = std::find_if(
        eligible_video_settings.begin(), eligible_video_settings.end(),
        [selected_id](const auto& settings) {
          return settings.device_id() == selected_id;
        });
    CHECK_NE(selected_video_settings, eligible_video_settings.end());
    current_request_info_->SetVideoCaptureSettings(
        *selected_video_settings,
        /*is_content_capture=*/false);
  }

  current_request_info_->set_state(RequestInfo::State::kGenerated);
  current_request_info_->set_pan_tilt_zoom_allowed(pan_tilt_zoom_allowed);

  for (const mojom::blink::StreamDevicesPtr& stream_devices :
       stream_devices_set->stream_devices) {
    MaybeLogStreamDevice(request_id, label, stream_devices->audio_device);
    MaybeLogStreamDevice(request_id, label, stream_devices->video_device);
  }

  current_request_info_->SetDevices(stream_devices_set->Clone());

  if (base::ranges::none_of(
          stream_devices_set->stream_devices,
          [](const mojom::blink::StreamDevicesPtr& stream_devices) {
            return stream_devices->video_device.has_value();
          })) {
    StartTracks(label);
    return;
  }

  if (current_request_info_->is_video_content_capture()) {
    media::VideoCaptureFormat format =
        current_request_info_->video_capture_settings().Format();
    for (const mojom::blink::StreamDevicesPtr& stream_devices :
         stream_devices_set->stream_devices) {
      if (stream_devices->video_device.has_value()) {
        String video_device_id(stream_devices->video_device.value().id.data());
        current_request_info_->AddNativeVideoFormats(
            video_device_id, {media::VideoCaptureFormat(
                                 MediaStreamUtils::GetScreenSize(frame_),
                                 format.frame_rate, format.pixel_format)});
      }
    }
    StartTracks(label);
    return;
  }

  for (const blink::mojom::blink::StreamDevicesPtr& stream_devices_ptr :
       stream_devices_set->stream_devices) {
    if (stream_devices_ptr->video_device.has_value()) {
      const MediaStreamDevice& video_device =
          stream_devices_ptr->video_device.value();

      Vector<String> video_device_ids;
      for (const mojom::blink::StreamDevicesPtr& stream_devices :
           stream_devices_set->stream_devices) {
        if (stream_devices->video_device.has_value()) {
          video_device_ids.push_back(
              stream_devices->video_device.value().id.data());
        }
      }

      SendLogMessage(base::StringPrintf(
          "OnStreamsGenerated({request_id=%d}, {label=%s}, {device=[id: %s, "
          "name: %s]}) => (Requesting video device formats)",
          request_id, label.Utf8().c_str(), video_device.id.c_str(),
          video_device.name.c_str()));
      String video_device_id(video_device.id.data());
      current_request_info_->StartTrace("GetAllVideoInputDeviceFormats");
      GetMediaDevicesDispatcher()->GetAllVideoInputDeviceFormats(
          video_device_id,
          WTF::BindOnce(&UserMediaProcessor::GotAllVideoInputFormatsForDevice,
                        WrapWeakPersistent(this),
                        WrapPersistent(current_request_info_->request()), label,
                        video_device_ids));
    }
  }
}

void UserMediaProcessor::GotAllVideoInputFormatsForDevice(
    UserMediaRequest* user_media_request,
    const String& label,
    const Vector<String>& device_ids,
    const Vector<media::VideoCaptureFormat>& formats) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // The frame might reload or |user_media_request| might be cancelled while
  // video formats are queried. Do nothing if a different request is being
  // processed at this point.
  if (!IsCurrentRequestInfo(user_media_request)) {
    return;
  }

  current_request_info_->EndTrace("GetAllVideoInputDeviceFormats");

  // TODO(crbug.com/1336564): Remove the assumption that all devices support
  // the same video formats.
  for (const String& device_id : device_ids) {
    SendLogMessage(
        base::StringPrintf("GotAllVideoInputFormatsForDevice({request_id=%d}, "
                           "{label=%s}, {device=[id: %s]})",
                           current_request_info_->request_id(),
                           label.Utf8().c_str(), device_id.Utf8().c_str()));
    current_request_info_->AddNativeVideoFormats(device_id, formats);
  }
  if (current_request_info_->CanStartTracks()) {
    StartTracks(label);
  }
}

void UserMediaProcessor::OnStreamGeneratedForCancelledRequest(
    const mojom::blink::StreamDevices& stream_devices) {
  SendLogMessage("OnStreamGeneratedForCancelledRequest()");
  // Only stop the device if the device is not used in another MediaStream.
  if (stream_devices.audio_device.has_value()) {
    const blink::MediaStreamDevice& audio_device =
        stream_devices.audio_device.value();
    if (!FindLocalSource(audio_device)) {
      GetMediaStreamDispatcherHost()->StopStreamDevice(
          String(audio_device.id.data()),
          audio_device.serializable_session_id());
    }
  }

  if (stream_devices.video_device.has_value()) {
    const blink::MediaStreamDevice& video_device =
        stream_devices.video_device.value();
    if (!FindLocalSource(video_device)) {
      GetMediaStreamDispatcherHost()->StopStreamDevice(
          String(video_device.id.data()),
          video_device.serializable_session_id());
    }
  }
}

// static
void UserMediaProcessor::OnAudioSourceStartedOnAudioThread(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    UserMediaProcessor* weak_ptr,
    blink::WebPlatformMediaStreamSource* source,
    MediaStreamRequestResult result,
    const blink::WebString& result_name) {
  PostCrossThreadTask(
      *task_runner.get(), FROM_HERE,
      CrossThreadBindOnce(&UserMediaProcessor::OnAudioSourceStarted,
                          WrapCrossThreadWeakPersistent(weak_ptr),
                          CrossThreadUnretained(source), result,
                          String(result_name)));
}

void UserMediaProcessor::OnAudioSourceStarted(
    blink::WebPlatformMediaStreamSource* source,
    MediaStreamRequestResult result,
    const String& result_name) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  for (auto it = pending_local_sources_.begin();
       it != pending_local_sources_.end(); ++it) {
    blink::WebPlatformMediaStreamSource* const source_extra_data =
        (*it)->GetPlatformSource();
    if (source_extra_data != source) {
      continue;
    }
    if (result == MediaStreamRequestResult::OK) {
      local_sources_.push_back((*it));
    }
    pending_local_sources_.erase(it);

    if (current_request_info_) {
      current_request_info_->EndTrace("CreateAudioSource");
    }

    NotifyCurrentRequestInfoOfAudioSourceStarted(source, result, result_name);
    return;
  }
}

void UserMediaProcessor::NotifyCurrentRequestInfoOfAudioSourceStarted(
    blink::WebPlatformMediaStreamSource* source,
    MediaStreamRequestResult result,
    const String& result_name) {
  // The only request possibly being processed is |current_request_info_|.
  if (current_request_info_) {
    current_request_info_->OnAudioSourceStarted(source, result, result_name);
  }
}

void UserMediaProcessor::OnStreamGenerationFailed(
    int32_t request_id,
    MediaStreamRequestResult result) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!IsCurrentRequestInfo(request_id)) {
    // This can happen if the request is canceled or the frame reloads while
    // MediaStreamDispatcherHost is processing the request.
    return;
  }
  SendLogMessage(base::StringPrintf("OnStreamGenerationFailed({request_id=%d})",
                                    current_request_info_->request_id()));

  GetUserMediaRequestFailed(result);
  DeleteUserMediaRequest(current_request_info_->request());
}

void UserMediaProcessor::OnDeviceStopped(const MediaStreamDevice& device) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(base::StringPrintf(
      "OnDeviceStopped({session_id=%s}, {device_id=%s})",
      device.session_id().ToString().c_str(), device.id.c_str()));

  MediaStreamSource* source = FindLocalSource(device);
  if (!source) {
    // This happens if the same device is used in several gUM requests or
    // if a user happens to stop a track from JS at the same time
    // as the underlying media device is unplugged from the system.
    return;
  }

  StopLocalSource(source, false);
  RemoveLocalSource(source);
}

void UserMediaProcessor::OnDeviceChanged(const MediaStreamDevice& old_device,
                                         const MediaStreamDevice& new_device) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  // TODO(https://crbug.com/1017219): possibly useful in native logs as well.
  DVLOG(1) << "UserMediaProcessor::OnDeviceChange("
           << "{old_device_id = " << old_device.id
           << ", session id = " << old_device.session_id()
           << ", type = " << old_device.type << "}"
           << "{new_device_id = " << new_device.id
           << ", session id = " << new_device.session_id()
           << ", type = " << new_device.type << "})";

  MediaStreamSource* source = FindLocalSource(old_device);
  if (!source) {
    // This happens if the same device is used in several guM requests or
    // if a user happens to stop a track from JS at the same time
    // as the underlying media device is unplugged from the system.
    DVLOG(1) << "failed to find existing source with device " << old_device.id;
    return;
  }

  if (old_device.type != MediaStreamType::NO_SERVICE &&
      new_device.type == MediaStreamType::NO_SERVICE) {
    // At present, this will only happen to the case that a new desktop capture
    // source without audio share is selected, then the previous audio capture
    // device should be stopped if existing.
    DCHECK(blink::IsAudioInputMediaType(old_device.type));
    OnDeviceStopped(old_device);
    return;
  }

  WebPlatformMediaStreamSource* const source_impl = source->GetPlatformSource();
  source_impl->ChangeSource(new_device);
}

void UserMediaProcessor::OnDeviceRequestStateChange(
    const MediaStreamDevice& device,
    const mojom::blink::MediaStreamStateChange new_state) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  SendLogMessage(base::StringPrintf(
      "OnDeviceRequestStateChange({session_id=%s}, {device_id=%s}, "
      "{new_state=%s})",
      device.session_id().ToString().c_str(), device.id.c_str(),
      (new_state == mojom::blink::MediaStreamStateChange::PAUSE ? "PAUSE"
                                                                : "PLAY")));

  MediaStreamSource* source = FindLocalSource(device);
  if (!source) {
    // This happens if the same device is used in several guM requests or
    // if a user happens to stop a track from JS at the same time
    // as the underlying media device is unplugged from the system.
    return;
  }

  WebPlatformMediaStreamSource* const source_impl = source->GetPlatformSource();
  source_impl->SetSourceMuted(new_state ==
                              mojom::blink::MediaStreamStateChange::PAUSE);
  MediaStreamVideoSource* video_source =
      static_cast<blink::MediaStreamVideoSource*>(source_impl);
  if (!video_source) {
    return;
  }
  if (new_state == mojom::blink::MediaStreamStateChange::PAUSE) {
    if (video_source->IsRunning()) {
      video_source->StopForRestart(base::DoNothing(),
                                   /*send_black_frame=*/true);
    }
  } else if (new_state == mojom::blink::MediaStreamStateChange::PLAY) {
    if (video_sour
```