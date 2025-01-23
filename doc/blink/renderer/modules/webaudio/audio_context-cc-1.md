Response:
My thinking process to analyze the provided code snippet goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the `AudioContext::cc` file, focusing on its interactions with JavaScript, HTML, CSS, and potential user errors. Since this is part 2 of 2, it specifically asks to summarize the *provided* snippet.

2. **Initial Scan for Key Concepts:** I first read through the code to identify the main functions and data members involved. Terms like `HandlePreRenderTasks`, `HandlePostRenderTasks`, `NotifyAudibleAudioStarted`, `setSinkId`, `permission`, `devices`, `error` immediately jump out as important areas of functionality.

3. **Group Functionality by Purpose:** I start grouping related functions and variables based on their apparent purpose. For example:
    * **Rendering Pipeline:**  `HandlePreRenderTasks`, `HandlePostRenderTasks`, `HandleAudibility`. These seem to be the core audio processing loop.
    * **Device Management:** `InitializeMediaDeviceService`, `DevicesEnumerated`, `OnDevicesChanged`, `UninitializeMediaDeviceService`, `setSinkId`, `IsValidSinkDescriptor`. These clearly deal with managing audio input/output devices.
    * **Permission Handling:** `OnPermissionStatusChange`, `DidInitialPermissionCheck`, `microphone_permission_status_`.
    * **Context State Management:** `ResolvePromisesForUnpause`, `StartContextInterruption`, `EndContextInterruption`, `HandleRenderError`. These manage the lifecycle and error conditions of the audio context.
    * **Communication with other components:**  `EnsureAudioContextManagerService`, `NotifyAudibleAudioStarted/Stopped`. These seem to interact with external services.

4. **Analyze Individual Functions:** I delve into the details of each function, noting:
    * **Core Logic:** What is the function actually doing?  (e.g., `HandlePreRenderTasks` updates state, processes deferred tasks, checks for stoppable sources).
    * **Data Members Used:** Which variables does the function access or modify? (e.g., `HandlePreRenderTasks` uses `pending_audio_frame_stats_`, `output_position_`, `callback_metric_`).
    * **Potential Side Effects:** Does the function trigger other actions or events? (e.g., `NotifyAudibleAudioStarted` calls `audio_context_manager_->AudioContextAudiblePlaybackStarted`).
    * **Synchronization:** Are there any locking mechanisms used? (e.g., `TryLock()` in `HandlePreRenderTasks` and `HandlePostRenderTasks`).

5. **Identify Connections to Web Technologies (JavaScript, HTML, CSS):** This is a crucial part of the request. I look for clues about how these C++ functions relate to web development concepts:
    * **JavaScript API:**  Functions like `setSinkId` directly correspond to JavaScript methods on the `AudioContext` object. Events like `sinkchange` and `error` are also JavaScript-observable. The context lifecycle (running, suspended, closed) is controlled via JavaScript.
    * **HTML Media Elements:** The code mentions "MEI" (Media Element Integration) in the `HandleAudibility` function, suggesting a connection to `<audio>` and `<video>` tags.
    * **Permissions API:** The code explicitly deals with microphone permission, a standard browser API.
    * **No Direct CSS Interaction:**  Based on the code, there's no direct manipulation of CSS. Audio processing is generally independent of visual styling.

6. **Look for Logic and Assumptions:**
    * **Assumptions:** The code assumes an audio thread (`DCHECK(IsAudioThread())`). It assumes the existence of other components like `DeferredTaskHandler`, `AudioListenerHandler`, `RealtimeAudioDestinationNode`.
    * **Input/Output (Hypothetical):** While not explicitly taking direct user input in this snippet, the `setSinkId` function provides a clear example: *Input:* a string representing a sink ID. *Output:* potentially changes the audio output device, triggers a `sinkchange` event. Similarly, permission status changes trigger device enumeration.

7. **Consider User Errors:**  I think about common mistakes developers might make when using the Web Audio API:
    * Incorrect sink IDs.
    * Not handling permission prompts correctly.
    * Issues with context state transitions (trying to start a closed context).
    * Potential race conditions if not understanding the asynchronous nature of certain operations.

8. **Trace User Actions (Debugging Clues):**  I try to reconstruct how a user's interaction could lead to this code being executed:
    * A user navigates to a webpage using Web Audio.
    * JavaScript code creates an `AudioContext`.
    * The user might be prompted for microphone permission.
    * The webpage might use `setSinkId` to select a specific output device.
    * Audio playback starts, triggering the render loop.
    * Device changes might occur.
    * Errors in the audio pipeline could occur.

9. **Synthesize the Summary:** Finally, I structure the findings into a clear and concise summary, addressing all the points raised in the original request. I use bullet points and clear language to organize the information effectively. I specifically address the "part 2 of 2" aspect by focusing on the functionality present in the given code block.

10. **Review and Refine:** I reread my summary and compare it against the code to ensure accuracy and completeness. I check for any ambiguities or areas where I could provide more clarity. For example, initially, I might just say "handles device changes," but refining it to mention the fallback behavior when a selected device is disconnected adds valuable detail.
这是对 `blink/renderer/modules/webaudio/audio_context.cc` 文件部分代码的功能归纳，延续了之前对该文件其他部分代码的分析。这段代码主要关注 `AudioContext` 对象的生命周期管理、音频渲染过程中的任务处理、设备管理、错误处理以及与外部服务的交互。

**功能归纳:**

这段代码主要负责以下功能：

1. **音频渲染过程中的任务处理:**
   - **`HandlePreRenderTasks`:** 在每个渲染量子开始时执行。
     - **同步状态更新:** 尝试获取锁以同步来自主线程的状态更改，例如节点连接、参数变化等。
     - **处理延迟任务:**  调用 `DeferredTaskHandler` 处理延迟执行的任务。
     - **处理暂停恢复的 Promise:** 解析因 `resume()` 调用而挂起的 Promise。
     - **检查可停止的音源节点:**  判断是否有音源节点因到达结束时间而需要停止。
     - **更新监听器状态:**  更新 `AudioListenerHandler` 的状态。
     - **更新输出时间戳和指标:** 记录当前的输出位置和回调指标。
     - **吸收音频帧统计信息:** 将待处理的音频帧统计信息合并到总的统计信息中。
   - **`HandlePostRenderTasks`:** 在每个渲染量子结束后执行。
     - **处理连接断开:** 调用 `DeferredTaskHandler` 处理之前因未能获取锁而延迟的连接断开操作。
     - **处理延迟任务:** 调用 `DeferredTaskHandler` 处理延迟执行的任务。
     - **请求删除处理器:**  请求在主线程上删除不再需要的 `AudioNodeHandler` 等处理器。
   - **`HandleAudibility`:** 检测输出总线是否可听。
     - **检测静音:**  判断输出是否为静音。
     - **通知可听状态变化:** 当可听状态发生变化时，向 `AudioContextManagerService` 发送通知，表明音频播放的开始或停止。

2. **音频上下文生命周期管理:**
   - **`ResolvePromisesForUnpause`:**  处理由 `resume()` 方法创建的 Promise 的解析。为了避免阻塞音频线程，解析操作会在主线程上异步执行。
   - **`NotifyAudibleAudioStarted` / `NotifyAudibleAudioStopped`:**  通知 `AudioContextManagerService` 音频播放状态的改变。
   - **`StartContextInterruption` / `EndContextInterruption`:** 处理音频上下文的中断和恢复状态，例如当页面进入后台或被其他音频流抢占时。
   - **`HandleRenderError`:**  处理音频渲染过程中发生的错误，并触发 `error` 事件。

3. **设备管理:**
   - **`OnPermissionStatusChange`:**  监听麦克风权限状态的变化，并根据状态更新输出延迟量化因子。
   - **`DidInitialPermissionCheck`:**  处理初始权限检查的结果，如果成功则不再监听后续权限变化。
   - **`InitializeMediaDeviceService` / `UninitializeMediaDeviceService`:** 初始化和反初始化 `MediaDeviceService`，用于枚举和监听音频输出设备的变更。
   - **`DevicesEnumerated`:**  接收来自 `MediaDeviceService` 的设备枚举结果，并更新内部的设备列表。
   - **`OnDevicesChanged`:**  处理音频输出设备变更的通知，并更新内部设备 ID 列表。如果当前使用的设备断开连接，则根据是否明确设置过 `sinkId` 来决定是回退到默认设备还是抛出错误。
   - **`NotifySetSinkIdBegins` / `NotifySetSinkIdIsDone`:** 处理 `setSinkId` 方法的调用，包括停止渲染、更新设备描述符、触发 `sinkchange` 事件以及恢复渲染。
   - **`UpdateV8SinkId`:** 更新 JavaScript 可见的 `sinkId` 属性。
   - **`IsValidSinkDescriptor`:** 检查给定的 `WebAudioSinkDescriptor` 是否有效（例如，对应的设备是否存在）。

4. **与其他服务的交互:**
   - **`EnsureAudioContextManagerService`:** 确保与 `AudioContextManagerService` 建立连接，用于上报音频上下文的状态。
   - **`OnAudioContextManagerServiceConnectionError`:** 处理与 `AudioContextManagerService` 连接断开的情况。
   - **`InitializeMediaDeviceService`:**  与 `MediaDeviceService` 通信以获取和监听设备信息。

5. **性能和统计:**
   - **`GetCallbackMetric`:**  获取音频回调的性能指标。
   - **`PlatformBufferDuration`:** 获取平台音频缓冲区的持续时间。
   - **`TransferAudioFrameStatsTo`:** 将音频帧统计信息传递给接收者。

**与 JavaScript, HTML, CSS 的关系:**

- **JavaScript:**
    - **`setSinkId` 方法:**  `NotifySetSinkIdBegins` 和 `NotifySetSinkIdIsDone` 直接响应 JavaScript 中 `AudioContext` 对象的 `setSinkId()` 方法调用。
    - **事件:** `DispatchEvent(*Event::Create(event_type_names::kSinkchange))` 和 `DispatchEvent(*Event::Create(event_type_names::kError))` 分别对应 JavaScript 中 `AudioContext` 对象的 `sinkchange` 和 `error` 事件。
    - **Promise:** `ResolvePromisesForUnpause` 处理 JavaScript 中 `resume()` 方法返回的 Promise。
    - **属性:** `UpdateV8SinkId` 更新了可以通过 JavaScript 访问的 `AudioContext.sinkId` 属性。
    - **状态:**  `ContextState()` 返回的音频上下文状态（running, suspended, closed, interrupted）可以通过 JavaScript 的相关属性或方法进行查询和控制。
- **HTML:**
    - **设备选择:** `setSinkId` 允许 JavaScript 代码选择特定的音频输出设备，这可能与 HTML 中通过媒体设备 ID 选择输出设备的逻辑相关。
    - **权限请求:**  `OnPermissionStatusChange` 和 `DidInitialPermissionCheck` 与浏览器处理用户授权麦克风权限的流程有关，这通常是用户与网页交互触发的。
- **CSS:**
    - 这段代码与 CSS 没有直接的功能关系。音频处理通常独立于页面的视觉样式。

**逻辑推理与假设输入/输出:**

**假设输入 (针对 `OnDevicesChanged`):**

1. **场景一：** 用户连接了一个新的音频输出设备。
   - **输入:** `device_type` 为 `mojom::blink::MediaDeviceType::kMediaAudioOutput`，`devices` 包含新连接的设备的 `WebMediaDeviceInfo`。
   - **输出:** `output_device_ids_` 将包含新设备的 ID。如果当前 `sink_descriptor_` 无效且未明确设置过 `sinkId`，则可能回退到默认设备。
2. **场景二：** 用户断开了当前正在使用的音频输出设备，且该设备是通过 `setSinkId` 明确设置的。
   - **输入:** `device_type` 为 `mojom::blink::MediaDeviceType::kMediaAudioOutput`，`devices` 不再包含当前 `sink_descriptor_` 中指定的设备。
   - **输出:**  由于 `is_sink_id_given_` 为 true，`HandleRenderError()` 将被调用，触发 `error` 事件。

**用户或编程常见的使用错误:**

1. **尝试设置无效的 `sinkId`:**  如果用户通过 JavaScript 调用 `audioContext.setSinkId('invalid-id')`，而 'invalid-id' 不存在于 `output_device_ids_` 中，则在设备变更时，`IsValidSinkDescriptor` 将返回 false，并且如果该 ID 是明确设置的，则会导致渲染错误。
2. **未处理 `sinkchange` 或 `error` 事件:**  开发者可能没有监听 `sinkchange` 事件来获知输出设备的变化，或者没有监听 `error` 事件来处理音频渲染错误。
3. **在音频上下文关闭后尝试操作:**  如果在音频上下文状态为 `closed` 时调用相关方法，可能会导致未定义行为或错误。
4. **权限问题:**  如果用户拒绝麦克风权限，可能会影响某些音频节点的功能，并且会影响输出延迟的量化精度。开发者需要妥善处理权限请求和拒绝的情况。

**用户操作如何到达这里 (调试线索):**

1. **用户访问一个使用了 Web Audio API 的网页。**
2. **网页的 JavaScript 代码创建了一个 `AudioContext` 对象。**
3. **用户可能被提示授予麦克风权限（如果网页需要使用麦克风输入）。** 这会导致 `DidInitialPermissionCheck` 和 `OnPermissionStatusChange` 被调用。
4. **网页的 JavaScript 代码可能调用了 `audioContext.setSinkId(deviceId)` 来选择特定的音频输出设备。** 这会触发 `NotifySetSinkIdBegins` 和 `NotifySetSinkIdIsDone`。
5. **音频开始播放，触发音频渲染循环，导致 `HandlePreRenderTasks` 和 `HandlePostRenderTasks` 被周期性调用。**
6. **用户的操作系统或浏览器检测到音频输出设备的变更（例如，用户插拔了耳机）。** 这会导致 `MediaDeviceService` 通知浏览器，进而调用 `AudioContext::OnDevicesChanged`。
7. **在音频渲染过程中可能发生错误，例如音频设备故障。** 这会导致 `OnRenderError` 被调用。
8. **用户可能将页面切换到后台，或者有其他音频流抢占了音频播放。** 这可能导致 `StartContextInterruption` 被调用。当页面回到前台或者抢占结束时，`EndContextInterruption` 会被调用。

总而言之，这段代码是 `AudioContext` 实现的核心部分，负责管理音频渲染的生命周期、与底层音频设备和浏览器服务交互，并为 JavaScript 开发者提供控制音频行为的接口。

### 提示词
```
这是目录为blink/renderer/modules/webaudio/audio_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
xtState::Enum::kClosed) &&
          BaseAudioContext::HasPendingActivity()) ||
         permission_receiver_.is_bound();
}

RealtimeAudioDestinationNode* AudioContext::GetRealtimeAudioDestinationNode()
    const {
  return static_cast<RealtimeAudioDestinationNode*>(destination());
}

bool AudioContext::HandlePreRenderTasks(
    uint32_t frames_to_process,
    const AudioIOPosition* output_position,
    const AudioCallbackMetric* metric,
    base::TimeDelta playout_delay,
    const media::AudioGlitchInfo& glitch_info) {
  DCHECK(IsAudioThread());

  pending_audio_frame_stats_.Update(frames_to_process, sampleRate(),
                                    playout_delay, glitch_info);

  // At the beginning of every render quantum, try to update the internal
  // rendering graph state (from main thread changes).  It's OK if the tryLock()
  // fails, we'll just take slightly longer to pick up the changes.
  if (TryLock()) {
    GetDeferredTaskHandler().HandleDeferredTasks();

    ResolvePromisesForUnpause();

    // Check to see if source nodes can be stopped because the end time has
    // passed.
    HandleStoppableSourceNodes();

    // Update the dirty state of the AudioListenerHandler.
    listener()->Handler().UpdateState();

    // Update output timestamp and metric.
    output_position_ = *output_position;
    callback_metric_ = *metric;

    audio_frame_stats_.Absorb(pending_audio_frame_stats_);

    unlock();
  }

  // Realtime context ignores the return result, but return true, just in case.
  return true;
}

void AudioContext::NotifyAudibleAudioStarted() {
  EnsureAudioContextManagerService();
  if (audio_context_manager_.is_bound()) {
    audio_context_manager_->AudioContextAudiblePlaybackStarted(context_id_);
  }
}

void AudioContext::HandlePostRenderTasks() {
  DCHECK(IsAudioThread());

  // Must use a tryLock() here too.  Don't worry, the lock will very rarely be
  // contended and this method is called frequently.  The worst that can happen
  // is that there will be some nodes which will take slightly longer than usual
  // to be deleted or removed from the render graph (in which case they'll
  // render silence).
  if (TryLock()) {
    // Take care of AudioNode tasks where the tryLock() failed previously.
    GetDeferredTaskHandler().BreakConnections();

    GetDeferredTaskHandler().HandleDeferredTasks();
    GetDeferredTaskHandler().RequestToDeleteHandlersOnMainThread();

    unlock();
  }
}

void AudioContext::HandleAudibility(AudioBus* destination_bus) {
  DCHECK(IsAudioThread());

  // Detect silence (or not) for MEI
  bool is_audible = IsAudible(destination_bus);

  if (is_audible) {
    ++total_audible_renders_;
  }

  if (was_audible_ != is_audible) {
    // Audibility changed in this render, so report the change.
    was_audible_ = is_audible;
    if (is_audible) {
      PostCrossThreadTask(
          *task_runner_, FROM_HERE,
          CrossThreadBindOnce(&AudioContext::NotifyAudibleAudioStarted,
                              WrapCrossThreadPersistent(this)));
    } else {
      PostCrossThreadTask(
          *task_runner_, FROM_HERE,
          CrossThreadBindOnce(&AudioContext::NotifyAudibleAudioStopped,
                              WrapCrossThreadPersistent(this)));
    }
  }
}

void AudioContext::ResolvePromisesForUnpause() {
  // This runs inside the BaseAudioContext's lock when handling pre-render
  // tasks.
  DCHECK(IsAudioThread());
  AssertGraphOwner();

  // Resolve any pending promises created by resume(). Only do this if we
  // haven't already started resolving these promises. This gets called very
  // often and it takes some time to resolve the promises in the main thread.
  if (!is_resolving_resume_promises_ &&
      pending_promises_resolvers_.size() > 0) {
    is_resolving_resume_promises_ = true;
    ScheduleMainThreadCleanup();
  }
}

AudioIOPosition AudioContext::OutputPosition() const {
  DeferredTaskHandler::GraphAutoLocker locker(this);
  return output_position_;
}

void AudioContext::NotifyAudibleAudioStopped() {
  EnsureAudioContextManagerService();
  if (audio_context_manager_.is_bound()) {
    audio_context_manager_->AudioContextAudiblePlaybackStopped(context_id_);
  }
}

void AudioContext::EnsureAudioContextManagerService() {
  if (audio_context_manager_.is_bound() || !GetWindow()) {
    return;
  }

  GetWindow()->GetFrame()->GetBrowserInterfaceBroker().GetInterface(
      mojo::GenericPendingReceiver(
          audio_context_manager_.BindNewPipeAndPassReceiver(
              GetWindow()->GetTaskRunner(TaskType::kInternalMedia))));

  audio_context_manager_.set_disconnect_handler(
      WTF::BindOnce(&AudioContext::OnAudioContextManagerServiceConnectionError,
                    WrapWeakPersistent(this)));
}

void AudioContext::OnAudioContextManagerServiceConnectionError() {
  audio_context_manager_.reset();
}

AudioCallbackMetric AudioContext::GetCallbackMetric() const {
  // Return a copy under the graph lock because returning a reference would
  // allow seeing the audio thread changing the struct values. This method
  // gets called once per second and the size of the struct is small, so
  // creating a copy is acceptable here.
  DeferredTaskHandler::GraphAutoLocker locker(this);
  return callback_metric_;
}

base::TimeDelta AudioContext::PlatformBufferDuration() const {
  return GetRealtimeAudioDestinationNode()
      ->GetOwnHandler()
      .GetPlatformBufferDuration();
}

void AudioContext::OnPermissionStatusChange(
    mojom::blink::PermissionStatus status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);

  microphone_permission_status_ = status;
  if (is_media_device_service_initialized_) {
    CHECK_LT(pending_device_list_updates_, std::numeric_limits<int>::max());
    pending_device_list_updates_++;
    media_device_service_->EnumerateDevices(
        /* audio input */ false,
        /* video input */ false,
        /* audio output */ true,
        /* request_video_input_capabilities */ false,
        /* request_audio_input_capabilities */ false,
        WTF::BindOnce(&AudioContext::DevicesEnumerated,
                      WrapWeakPersistent(this)));
  }
}

void AudioContext::DidInitialPermissionCheck(
    mojom::blink::PermissionDescriptorPtr descriptor,
    mojom::blink::PermissionStatus status) {
  if (descriptor->name == mojom::blink::PermissionName::AUDIO_CAPTURE &&
      status == mojom::blink::PermissionStatus::GRANTED) {
    // If the initial permission check is successful, the current implementation
    // avoids listening the future permission change in this AudioContext's
    // lifetime. This is acceptable because the current UI pattern asks to
    // reload the page when the permission is taken away.
    microphone_permission_status_ = status;
    permission_receiver_.reset();
    return;
  }

  // The initial permission check failed, start listening the future permission
  // change.
  DCHECK(permission_service_.is_bound());
  mojo::PendingRemote<mojom::blink::PermissionObserver> observer;
  permission_receiver_.Bind(
      observer.InitWithNewPipeAndPassReceiver(),
      GetExecutionContext()->GetTaskRunner(TaskType::kPermission));
  permission_service_->AddPermissionObserver(
      CreatePermissionDescriptor(mojom::blink::PermissionName::AUDIO_CAPTURE),
      microphone_permission_status_, std::move(observer));
}

double AudioContext::GetOutputLatencyQuantizingFactor() const {
  return microphone_permission_status_ ==
      mojom::blink::PermissionStatus::GRANTED
      ? kOutputLatencyMaxPrecisionFactor
      : kOutputLatencyQuatizingFactor;
}

void AudioContext::NotifySetSinkIdBegins() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);

  // This performs step 5 to 9 from the second part of setSinkId() algorithm:
  // https://webaudio.github.io/web-audio-api/#dom-audiocontext-setsinkid-domstring-or-audiosinkoptions-sinkid
  sink_transition_flag_was_running_ =
      ContextState() == V8AudioContextState::Enum::kRunning;
  destination()->GetAudioDestinationHandler().StopRendering();
  if (sink_transition_flag_was_running_) {
    SetContextState(V8AudioContextState::Enum::kSuspended);
  }
}

void AudioContext::NotifySetSinkIdIsDone(
    WebAudioSinkDescriptor pending_sink_descriptor) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);

  sink_descriptor_ = pending_sink_descriptor;

  // This performs steps 11 and 12 from the second part of the setSinkId()
  // algorithm:
  // https://webaudio.github.io/web-audio-api/#dom-audiocontext-setsinkid-domstring-or-audiosinkoptions-sinkid
  UpdateV8SinkId();
  DispatchEvent(*Event::Create(event_type_names::kSinkchange));
  if (sink_transition_flag_was_running_) {
    destination()->GetAudioDestinationHandler().StartRendering();
    SetContextState(V8AudioContextState::Enum::kRunning);
    sink_transition_flag_was_running_ = false;
  }

  // The sink ID was given and has been accepted; it will be used as an output
  // audio device.
  is_sink_id_given_ = true;
}

void AudioContext::InitializeMediaDeviceService() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);

  auto* execution_context = GetExecutionContext();

  execution_context->GetBrowserInterfaceBroker().GetInterface(
      media_device_service_.BindNewPipeAndPassReceiver(
          execution_context->GetTaskRunner(TaskType::kInternalMediaRealTime)));

  media_device_service_->AddMediaDevicesListener(
      /* audio input */ true,
      /* video input */ false,
      /* audio output */ true,
      media_device_service_receiver_.BindNewPipeAndPassRemote(
          execution_context->GetTaskRunner(TaskType::kInternalMediaRealTime)));

  is_media_device_service_initialized_ = true;

  CHECK_LT(pending_device_list_updates_, std::numeric_limits<int>::max());
  pending_device_list_updates_++;
  media_device_service_->EnumerateDevices(
      /* audio input */ false,
      /* video input */ false,
      /* audio output */ true,
      /* request_video_input_capabilities */ false,
      /* request_audio_input_capabilities */ false,
      WTF::BindOnce(&AudioContext::DevicesEnumerated,
                    WrapWeakPersistent(this)));
}

void AudioContext::DevicesEnumerated(
    const Vector<Vector<WebMediaDeviceInfo>>& enumeration,
    Vector<mojom::blink::VideoInputDeviceCapabilitiesPtr>
        video_input_capabilities,
    Vector<mojom::blink::AudioInputDeviceCapabilitiesPtr>
        audio_input_capabilities) {
  Vector<WebMediaDeviceInfo> output_devices =
      enumeration[static_cast<wtf_size_t>(
          mojom::blink::MediaDeviceType::kMediaAudioOutput)];

  TRACE_EVENT1(
      "webaudio", "AudioContext::DevicesEnumerated", "DeviceEnumeration",
      audio_utilities::GetDeviceEnumerationForTracing(output_devices));

  OnDevicesChanged(mojom::blink::MediaDeviceType::kMediaAudioOutput,
                   output_devices);

  CHECK_GT(pending_device_list_updates_, 0);
  pending_device_list_updates_--;

  // Start the first resolver in the queue once `output_device_ids_` is
  // initialized from `OnDeviceChanged()` above.
  if (!set_sink_id_resolvers_.empty() && (pending_device_list_updates_ == 0)) {
    set_sink_id_resolvers_.front()->Start();
  }
}

void AudioContext::OnDevicesChanged(mojom::blink::MediaDeviceType device_type,
                                    const Vector<WebMediaDeviceInfo>& devices) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
  SendLogMessage(__func__, "");

  if (device_type == mojom::blink::MediaDeviceType::kMediaAudioOutput) {
    output_device_ids_.clear();
    for (auto device : devices) {
      if (device.device_id == "default") {
        // Use the empty string to represent the default audio sink.
        output_device_ids_.insert(String(""));
      } else {
        output_device_ids_.insert(String::FromUTF8(device.device_id));
      }
    }
  }

  // If the device in use was disconnected (i.e. the current `sink_descriptor_`
  // is invalid), we need to decide how to handle the rendering.
  if (!IsValidSinkDescriptor(sink_descriptor_)) {
    SendLogMessage(__func__, "=> invalid sink descriptor");
    if (is_sink_id_given_) {
      // If the user's intent is to select a specific output device, do not
      // fallback to the default audio device. Invoke `RenderError` routine
      // instead.
      SendLogMessage(__func__,
                     "=> sink was explicitly specified, throwing error.");
      HandleRenderError();
    } else {
      // If there was no sink selected, manually call `SetSinkDescriptor()` to
      // fallback to the default audio output device to keep the audio playing.
      SendLogMessage(__func__,
                     "=> sink was not explicitly specified, falling back to "
                     "default sink.");
      GetExecutionContext()->AddConsoleMessage(
        MakeGarbageCollected<ConsoleMessage>(
            mojom::ConsoleMessageSource::kOther,
            mojom::ConsoleMessageLevel::kInfo,
            "[AudioContext] Fallback to the default device due to an invalid"
            " audio device change. ("
            + String(sink_descriptor_.SinkId().Utf8()) + ")"));
      sink_descriptor_ = WebAudioSinkDescriptor(
          String(""),
          To<LocalDOMWindow>(GetExecutionContext())->GetLocalFrameToken());
      auto* destination_node = GetRealtimeAudioDestinationNode();
      if (destination_node) {
        destination_node->SetSinkDescriptor(sink_descriptor_,
                                            base::DoNothing());
      }
      UpdateV8SinkId();
    }
  }
}

void AudioContext::UninitializeMediaDeviceService() {
  if (media_device_service_.is_bound()) {
    media_device_service_.reset();
  }
  if (media_device_service_receiver_.is_bound()) {
    media_device_service_receiver_.reset();
  }
  output_device_ids_.clear();
}

void AudioContext::UpdateV8SinkId() {
  if (sink_descriptor_.Type() ==
      WebAudioSinkDescriptor::AudioSinkType::kSilent) {
    v8_sink_id_->Set(AudioSinkInfo::Create(String("none")));
  } else {
    v8_sink_id_->Set(sink_descriptor_.SinkId());
  }
}

bool AudioContext::IsValidSinkDescriptor(
    const WebAudioSinkDescriptor& sink_descriptor) {
  return sink_descriptor.Type() ==
             WebAudioSinkDescriptor::AudioSinkType::kSilent ||
         output_device_ids_.Contains(sink_descriptor.SinkId());
}

void AudioContext::OnRenderError() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);

  if (!RuntimeEnabledFeatures::AudioContextOnErrorEnabled()) {
    return;
  }

  CHECK(GetExecutionContext());
  render_error_occurred_ = true;
  GetExecutionContext()->GetTaskRunner(TaskType::kMediaElementEvent)
      ->PostTask(FROM_HERE,
                 WTF::BindOnce(&AudioContext::HandleRenderError,
                               WrapPersistent(this)));
}

void AudioContext::ResumeOnPrerenderActivation() {
  CHECK(blocked_by_prerendering_);
  blocked_by_prerendering_ = false;
  switch (ContextState()) {
    case V8AudioContextState::Enum::kSuspended:
      StartRendering();
      break;
    case V8AudioContextState::Enum::kRunning:
      NOTREACHED();
    case V8AudioContextState::Enum::kClosed:
    // Prerender activation doesn't automatically resume audio playback
    // when the context is in the `interrupted` state.
    // TODO(crbug.com/374805121): Add the spec URL for this interruption
    // behavior when it has been published.
    case V8AudioContextState::Enum::kInterrupted:
      break;
  }
}

void AudioContext::TransferAudioFrameStatsTo(
    AudioFrameStatsAccumulator& receiver) {
  DeferredTaskHandler::GraphAutoLocker locker(this);
  receiver.Absorb(audio_frame_stats_);
}

int AudioContext::PendingDeviceListUpdates() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);

  return pending_device_list_updates_;
}

void AudioContext::StartContextInterruption() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
  if (!RuntimeEnabledFeatures::AudioContextInterruptedStateEnabled()) {
    return;
  }

  SendLogMessage(__func__, "");
  V8AudioContextState::Enum context_state = ContextState();
  if (context_state == V8AudioContextState::Enum::kClosed ||
      context_state == V8AudioContextState::Enum::kInterrupted) {
    return;
  }

  if (context_state == V8AudioContextState::Enum::kRunning) {
    // The context is running, so we need to stop the rendering.
    destination()->GetAudioDestinationHandler().StopRendering();
    should_transition_to_running_after_interruption_ = true;
    SetContextState(V8AudioContextState::Enum::kInterrupted);
  }

  // If the context is suspended, we don't make the transition to interrupted
  // state, because of privacy reasons. The suspended->interrupted transition is
  // only made when resumeContext() is called during an ongoing interruption.
  is_interrupted_while_suspended_ = true;
}

void AudioContext::EndContextInterruption() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
  if (!RuntimeEnabledFeatures::AudioContextInterruptedStateEnabled()) {
    return;
  }

  SendLogMessage(__func__, "");
  is_interrupted_while_suspended_ = false;
  if (ContextState() == V8AudioContextState::Enum::kClosed) {
    return;
  }

  if (should_transition_to_running_after_interruption_) {
    destination()->GetAudioDestinationHandler().StartRendering();
    should_transition_to_running_after_interruption_ = false;
    SetContextState(V8AudioContextState::Enum::kRunning);
  }
}

void AudioContext::HandleRenderError() {
  SendLogMessage(__func__, "");

  LocalDOMWindow* window = To<LocalDOMWindow>(GetExecutionContext());
  if (window && window->GetFrame()) {
    window->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kError,
        "The AudioContext encountered an error from the audio device or the "
        "WebAudio renderer."));
  }

  // Implements
  // https://webaudio.github.io/web-audio-api/#error-handling-on-a-running-audio-context
  if (ContextState() == V8AudioContextState::Enum::kRunning) {
    // TODO(https://crbug.com/353641602): starting or stopping the renderer
    // should happen on the render thread, but this is the current convention.
    destination()->GetAudioDestinationHandler().StopRendering();

    DispatchEvent(*Event::Create(event_type_names::kError));
    suspended_by_user_ = false;
    SetContextState(V8AudioContextState::Enum::kSuspended);
  } else if (ContextState() == V8AudioContextState::Enum::kSuspended) {
    DispatchEvent(*Event::Create(event_type_names::kError));
  }
}

void AudioContext::invoke_onrendererror_from_platform_for_testing() {
  GetRealtimeAudioDestinationNode()->GetOwnHandler()
      .invoke_onrendererror_from_platform_for_testing();
}

void AudioContext::SendLogMessage(const char* const function_name,
                                  const String& message) {
  WebRtcLogMessage(
      String::Format(
          "[WA]AC::%s %s [state=%s sink_descriptor_=%s, sink_id_given_=%s]",
          function_name, message.Utf8().c_str(), state().AsCStr(),
          sink_descriptor_.SinkId().Utf8().c_str(),
          is_sink_id_given_ ? "true" : "false")
          .Utf8());
}

}  // namespace blink
```