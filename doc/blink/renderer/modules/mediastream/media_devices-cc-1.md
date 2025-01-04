Response:
The user is asking for a summary of the functionality of the provided C++ code snippet, which is part of the `blink` rendering engine in Chromium. This is the second part of a two-part file. I need to extract the key responsibilities of the code within this snippet and how they relate to web technologies like JavaScript, HTML, and CSS. I also need to consider potential user errors and how a user's action might lead to this code being executed.

Here's a breakdown of the code's functionality:

1. **Setting Capture Handles:** The `SetCaptureHandleConfig` function allows a web page to define a "capture handle" – a string that can be used by other pages to identify this page as a potential source for screen capture. This involves security checks to ensure it's called from the top-level document and that the provided origins are valid.

2. **Producing Crop Targets:** The `ProduceCropTarget` function allows a web page to designate a specific HTML element as a "crop target". This means that when another page captures content from this page, it can choose to only capture the area occupied by this specific element. The function handles the communication with the browser process to get a unique identifier for this target. It also deals with potential duplicate calls.

3. **Producing Restriction Targets:** The `ProduceRestrictionTarget` function is similar to `ProduceCropTarget` but serves a different purpose. A "restriction target" likely indicates an area that should *not* be captured. Again, it involves communication with the browser process and handles duplicate calls.

4. **Event Handling and Observation:** The code includes logic for handling `devicechange` events, which are triggered when the availability of media devices (like cameras and microphones) changes. It starts and stops observing these changes based on whether there are event listeners attached.

5. **Device Enumeration:**  The `DevicesEnumerated` function processes the results of a request to list available media devices. It formats the information into `MediaDeviceInfo` objects, which are exposed to JavaScript.

6. **Error Handling:**  The code includes error handling for situations like a disconnected `MediaDevicesDispatcherHost`.

7. **Internal Communication:**  The code uses Mojo to communicate with the browser process (`MediaDevicesDispatcherHost`).

8. **Focus Window of Opportunity (Non-Android/iOS):**  The code includes functions related to closing a "focus window of opportunity," likely related to permission prompts for screen capture.

9. **Sub-capture Target Helpers (Non-Android/iOS):** The `MayProduceSubCaptureTarget` function performs checks to ensure that creating a crop or restriction target is allowed. Helper functions like `ResolveCropTargetPromise` and `ResolveRestrictionTargetPromise` handle the resolution of the promises associated with creating these targets.

Now, let's map these functionalities to the user's request, including JavaScript/HTML/CSS interactions, logical reasoning with inputs/outputs, common user errors, and how a user reaches this code.
这是对`blink/renderer/modules/mediastream/media_devices.cc`文件功能的总结，延续了前一部分的讨论。

**归纳一下它的功能:**

该代码片段主要负责以下功能：

1. **设置捕获句柄 (Capture Handle):**
   - 允许网页通过 `setCaptureHandleConfig` 方法设置一个用于屏幕共享的 "捕获句柄"。
   - 这个句柄可以是一个字符串，用于标识当前页面，方便其他页面请求捕获该页面的内容。
   - 功能上与 JavaScript 的 `navigator.mediaDevices.setCaptureHandleConfig()` API 相对应。

2. **生成裁剪目标 (Crop Target):**
   - 提供了 `produceCropTarget` 方法，允许网页将特定的 HTML 元素标记为一个 "裁剪目标"。
   - 当其他页面捕获该页面的内容时，可以选择只捕获这个裁剪目标元素及其内容。
   - 功能上与 JavaScript 的 `HTMLElement.prototype.cropTarget` API 相对应。
   - 这与 HTML 元素和 JavaScript Promise 相关联。

3. **生成限制目标 (Restriction Target):**
   - 提供了 `produceRestrictionTarget` 方法，允许网页将特定的 HTML 元素标记为一个 "限制目标"。
   - 限制目标可能用于指示不应被捕获的区域或元素，具体语义可能根据规范而定。
   - 功能上可能与正在演进的屏幕捕获 API 相关。
   - 同样与 HTML 元素和 JavaScript Promise 相关联。

4. **处理设备枚举结果:**
   - `DevicesEnumerated` 函数接收来自浏览器进程的设备枚举结果（摄像头、麦克风等）。
   - 它将这些信息转换为 `MediaDeviceInfo` 对象，这些对象最终会返回给 JavaScript 的 `navigator.mediaDevices.enumerateDevices()` 方法。

5. **内部通信:**
   - 通过 Mojo 接口 `mojom::blink::MediaDevicesDispatcherHost` 与浏览器进程进行通信，执行设备枚举、设置捕获句柄、生成裁剪/限制目标等操作。

6. **事件调度:**
   - `ScheduleDispatchEvent` 和 `DispatchScheduledEvents` 用于异步调度 `devicechange` 事件。

7. **启动和停止观察设备变化:**
   - `StartObserving` 和 `StopObserving` 管理对媒体设备变化的监听。当有 `devicechange` 事件监听器时，开始监听，否则停止。

8. **错误处理:**
   - 包含了对与浏览器进程通信失败的处理 (`OnDispatcherHostConnectionError`)。

9. **针对非 Android/iOS 平台的特定功能:**
   - 包含了 `EnqueueMicrotaskToCloseFocusWindowOfOpportunity` 和 `CloseFocusWindowOfOpportunity`，可能与屏幕捕获权限的临时授予有关。
   - `MayProduceSubCaptureTarget` 用于检查是否允许生成裁剪或限制目标。
   - `ResolveCropTargetPromise` 和 `ResolveRestrictionTargetPromise` 用于解析生成裁剪/限制目标的 Promise。

**与 javascript, html, css 的功能关系及举例说明:**

* **JavaScript:**
    * `navigator.mediaDevices.setCaptureHandleConfig(configuration)`:  `SetCaptureHandleConfig` 函数实现了这个 JavaScript API 的底层逻辑。`configuration` 参数对应于 C++ 中的 `CaptureHandleConfiguration` 对象。
        * **例子:**  一个网页可以使用 `navigator.mediaDevices.setCaptureHandleConfig({ handle: 'my-unique-handle', permittedOrigins: ['https://example.com'] })` 来设置一个捕获句柄，只有来自 `https://example.com` 的页面才能请求捕获该页面的内容。
    * `HTMLElement.prototype.cropTarget = true`:  `ProduceCropTarget` 函数实现了当 JavaScript 设置元素的 `cropTarget` 属性为 `true` 时的底层逻辑。
        * **例子:** `<div id="target" cropTarget>Important Content</div>`，当 JavaScript 设置 `document.getElementById('target').cropTarget = true;` 时，会触发 `ProduceCropTarget`，使得其他页面可以只捕获 "Important Content" 的区域。返回的 Promise 会 resolve 一个 `CropTarget` 对象，该对象可以在后续的屏幕捕获 API 中使用。
    * 未来可能存在的 `HTMLElement.prototype.restrictionTarget = true` API，`ProduceRestrictionTarget` 函数对应其底层逻辑。
    * `navigator.mediaDevices.enumerateDevices()`: `DevicesEnumerated` 函数处理浏览器进程返回的设备信息，并将其转换为 JavaScript 可用的 `MediaDeviceInfo` 对象。

* **HTML:**
    * `cropTarget` 和可能的 `restrictionTarget` 属性会添加到 HTML 元素上，作为标记。

* **CSS:**
    * CSS 本身不直接与这些功能交互，但元素的样式和布局会影响裁剪目标和限制目标的最终捕获区域。

**逻辑推理与假设输入输出:**

**假设输入 (对于 `SetCaptureHandleConfig`):**

* `config->exposeOrigin()` 为 `true`
* `config->handle()` 为字符串 "my-page-handle"
* `config->permittedOrigins()` 包含一个元素: "https://example.org"

**输出:**

*  向浏览器进程发送一个 `mojom::blink::CaptureHandleConfig` 消息，其中:
    * `expose_origin` 为 `true`
    * `capture_handle` 为 "my-page-handle"
    * `all_origins_permitted` 为 `false`
    * `permitted_origins` 包含一个 `SecurityOrigin` 对象，对应 "https://example.org"。

**假设输入 (对于 `ProduceCropTarget`):**

* JavaScript 调用 `element.cropTarget = true;`，其中 `element` 是一个 `<video>` 元素。

**输出:**

* 如果这是第一次为该元素调用，则向浏览器进程发送一个 `ProduceSubCaptureTargetId` 请求，类型为 `kCropTarget`。
* 返回一个 JavaScript Promise，该 Promise 将在收到浏览器进程的响应后 resolve 一个 `CropTarget` 对象，包含一个唯一的 ID。
* 如果之前已经为该元素生成过裁剪目标，则直接 resolve 之前生成的 `CropTarget` 对象。

**用户或编程常见的使用错误举例:**

1. **在非顶层文档中调用 `setCaptureHandleConfig`:**
   - **错误:**  在一个 `<iframe>` 内的页面中调用 `navigator.mediaDevices.setCaptureHandleConfig()`。
   - **结果:** `exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError, "Can only be called from the top-level document.");` 会被触发，JavaScript 中会抛出一个 `InvalidStateError` 异常。

2. **`permittedOrigins` 中包含无效的 origin:**
   - **错误:**  调用 `navigator.mediaDevices.setCaptureHandleConfig({ permittedOrigins: ['invalid-origin'] })`。
   - **结果:** `exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError, "Invalid origin encountered.");` 会被触发，JavaScript 中会抛出一个 `NotSupportedError` 异常。

3. **重复调用 `element.cropTarget = true` 而不等待 Promise resolve:**
   - **行为:**  用户可能希望多次获取同一个元素的裁剪目标。
   - **结果:** 代码会处理重复调用，如果 Promise 尚未 resolve，则返回相同的 Promise。如果 Promise 已经 resolve，则直接返回之前生成的 `CropTarget` 对象，并记录 UMA 指标。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问一个网页。**
2. **网页的 JavaScript 代码调用 `navigator.mediaDevices.setCaptureHandleConfig(config)`。** 这会触发 `MediaDevices::SetCaptureHandleConfig` 函数。
3. **网页的 JavaScript 代码设置一个 HTML 元素的 `cropTarget` 属性为 `true` (例如 `document.getElementById('myElement').cropTarget = true;`)。**  这会触发 `MediaDevices::ProduceCropTarget` 函数。
4. **网页的 JavaScript 代码调用 `navigator.mediaDevices.enumerateDevices()`。** 这会间接导致 `MediaDevices::StartObserving` (如果尚未开始) 和后续的设备枚举请求，最终结果会通过 `MediaDevices::DevicesEnumerated` 处理。
5. **浏览器检测到媒体设备的变化 (例如，用户插入或拔出摄像头)。**  浏览器进程会通知渲染进程，最终触发 `MediaDevices::OnDevicesChanged` 函数。

**调试线索:**

* 在 `SetCaptureHandleConfig` 中，检查 `window->GetFrame()->IsOutermostMainFrame()` 的值可以确认是否在顶层文档中调用。
* 在 `SetCaptureHandleConfig` 中，检查 `config->permittedOrigins()` 的内容可以验证允许的 origin 是否正确。
* 在 `ProduceCropTarget` 中，检查 `element->GetRegionCaptureCropId()` 可以判断是否已经生成过裁剪目标。
* 使用断点和日志输出可以跟踪与浏览器进程的 Mojo 消息传递。
* 检查 `enumerate_device_requests_` 的内容可以了解是否有待处理的设备枚举请求。

总而言之，这个代码片段是 Chromium 中处理与媒体设备、屏幕共享捕获句柄以及元素级裁剪/限制目标相关核心功能的关键部分，它连接了 JavaScript API 和浏览器底层的实现。

Prompt: 
```
这是目录为blink/renderer/modules/mediastream/media_devices.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
   return;
  }

  LocalDOMWindow* const window = To<LocalDOMWindow>(GetExecutionContext());
  if (!window || !window->GetFrame()) {
    return;
  }

  if (!window->GetFrame()->IsOutermostMainFrame()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Can only be called from the top-level document.");
    return;
  }

  auto config_ptr = mojom::blink::CaptureHandleConfig::New();
  config_ptr->expose_origin = config->exposeOrigin();
  config_ptr->capture_handle = config->handle();
  if (config->permittedOrigins().size() == 1 &&
      config->permittedOrigins()[0] == "*") {
    config_ptr->all_origins_permitted = true;
  } else {
    config_ptr->all_origins_permitted = false;
    config_ptr->permitted_origins.reserve(config->permittedOrigins().size());
    for (const auto& permitted_origin : config->permittedOrigins()) {
      if (permitted_origin == "*") {
        exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                          "Wildcard only valid in isolation.");
        return;
      }

      scoped_refptr<SecurityOrigin> origin =
          SecurityOrigin::CreateFromString(permitted_origin);
      if (!origin || origin->IsOpaque()) {
        exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                          "Invalid origin encountered.");
        return;
      }
      config_ptr->permitted_origins.emplace_back(std::move(origin));
    }
  }

  GetDispatcherHost(window->GetFrame())
      .SetCaptureHandleConfig(std::move(config_ptr));
}

ScriptPromise<CropTarget> MediaDevices::ProduceCropTarget(
    ScriptState* script_state,
    Element* element,
    ExceptionState& exception_state) {
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                    "Unsupported.");
  return EmptyPromise();
#else
  if (!MayProduceSubCaptureTarget(script_state, element, exception_state,
                                  SubCaptureTarget::Type::kCropTarget)) {
    // Exception thrown by helper.
    return EmptyPromise();
  }

  if (const RegionCaptureCropId* id = element->GetRegionCaptureCropId()) {
    // A token was produced earlier and associated with the Element.
    const base::Token token = id->value();
    DCHECK(!token.is_zero());
    auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<CropTarget>>(
        script_state, exception_state.GetContext());
    const ScriptPromise<CropTarget> promise = resolver->Promise();
    const WTF::String token_str(blink::TokenToGUID(token).AsLowercaseString());
    resolver->Resolve(MakeGarbageCollected<CropTarget>(token_str));
    RecordUma(
        SubCaptureTarget::Type::kCropTarget,
        ProduceTargetFunctionResult::kDuplicateCallAfterPromiseResolution);
    return promise;
  }

  const auto it = crop_target_resolvers_.find(element);
  if (it != crop_target_resolvers_.end()) {
    // The Element does not yet have the SubCaptureTarget attached,
    // but the production of one has already been kicked off, and a response
    // will soon arrive from the browser process.
    // The Promise we return here will be resolved along with the original one.
    RecordUma(
        SubCaptureTarget::Type::kCropTarget,
        ProduceTargetFunctionResult::kDuplicateCallBeforePromiseResolution);
    return it->value->Promise();
  }

  // Mints a new ID on the browser process.
  // Resolves after it has been produced and is ready to be used.
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<CropTarget>>(
      script_state, exception_state.GetContext());
  crop_target_resolvers_.insert(element, resolver);
  const ScriptPromise<CropTarget> promise = resolver->Promise();

  LocalDOMWindow* const window = To<LocalDOMWindow>(GetExecutionContext());
  CHECK(window);  // Guaranteed by MayProduceSubCaptureTarget() earlier.

  base::OnceCallback callback =
      WTF::BindOnce(&MediaDevices::ResolveCropTargetPromise,
                    WrapPersistent(this), WrapPersistent(element));
  GetDispatcherHost(window->GetFrame())
      .ProduceSubCaptureTargetId(SubCaptureTarget::Type::kCropTarget,
                                 std::move(callback));
  RecordUma(SubCaptureTarget::Type::kCropTarget,
            ProduceTargetFunctionResult::kPromiseProduced);
  return promise;
#endif
}

ScriptPromise<RestrictionTarget> MediaDevices::ProduceRestrictionTarget(
    ScriptState* script_state,
    Element* element,
    ExceptionState& exception_state) {
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
  exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                    "Unsupported.");
  return EmptyPromise();
#else
  if (!MayProduceSubCaptureTarget(script_state, element, exception_state,
                                  SubCaptureTarget::Type::kRestrictionTarget)) {
    // Exception thrown by helper.
    return EmptyPromise();
  }

  if (const RestrictionTargetId* id = element->GetRestrictionTargetId()) {
    // A token was produced earlier and associated with the Element.
    const base::Token token = id->value();
    DCHECK(!token.is_zero());
    auto* resolver =
        MakeGarbageCollected<ScriptPromiseResolver<RestrictionTarget>>(
            script_state, exception_state.GetContext());
    const ScriptPromise<RestrictionTarget> promise = resolver->Promise();
    const WTF::String token_str(blink::TokenToGUID(token).AsLowercaseString());
    resolver->Resolve(MakeGarbageCollected<RestrictionTarget>(token_str));
    RecordUma(
        SubCaptureTarget::Type::kRestrictionTarget,
        ProduceTargetFunctionResult::kDuplicateCallAfterPromiseResolution);
    return promise;
  }

  const auto it = restriction_target_resolvers_.find(element);
  if (it != restriction_target_resolvers_.end()) {
    // The Element does not yet have the SubCaptureTarget attached,
    // but the production of one has already been kicked off, and a response
    // will soon arrive from the browser process.
    // The Promise we return here will be resolved along with the original one.
    RecordUma(
        SubCaptureTarget::Type::kRestrictionTarget,
        ProduceTargetFunctionResult::kDuplicateCallBeforePromiseResolution);
    return it->value->Promise();
  }

  // Mints a new ID on the browser process.
  // Resolves after it has been produced and is ready to be used.
  auto* resolver =
      MakeGarbageCollected<ScriptPromiseResolver<RestrictionTarget>>(
          script_state, exception_state.GetContext());
  restriction_target_resolvers_.insert(element, resolver);
  const ScriptPromise<RestrictionTarget> promise = resolver->Promise();

  LocalDOMWindow* const window = To<LocalDOMWindow>(GetExecutionContext());
  CHECK(window);  // Guaranteed by MayProduceSubCaptureTarget() earlier.

  base::OnceCallback callback =
      WTF::BindOnce(&MediaDevices::ResolveRestrictionTargetPromise,
                    WrapPersistent(this), WrapPersistent(element));
  GetDispatcherHost(window->GetFrame())
      .ProduceSubCaptureTargetId(SubCaptureTarget::Type::kRestrictionTarget,
                                 std::move(callback));
  RecordUma(SubCaptureTarget::Type::kRestrictionTarget,
            ProduceTargetFunctionResult::kPromiseProduced);
  return promise;
#endif
}

const AtomicString& MediaDevices::InterfaceName() const {
  return event_target_names::kMediaDevices;
}

ExecutionContext* MediaDevices::GetExecutionContext() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return ExecutionContextLifecycleObserver::GetExecutionContext();
}

void MediaDevices::RemoveAllEventListeners() {
  EventTarget::RemoveAllEventListeners();
  DCHECK(!HasEventListeners());
  StopObserving();
}

void MediaDevices::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  EventTarget::AddedEventListener(event_type, registered_listener);
  StartObserving();
}

void MediaDevices::RemovedEventListener(
    const AtomicString& event_type,
    const RegisteredEventListener& registered_listener) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  EventTarget::RemovedEventListener(event_type, registered_listener);
  if (!HasEventListeners()) {
    StopObserving();
  }
}

bool MediaDevices::HasPendingActivity() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return receiver_.is_bound();
}

void MediaDevices::ContextDestroyed() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (stopped_) {
    return;
  }

  stopped_ = true;
  enumerate_device_requests_.clear();
}

void MediaDevices::OnDevicesChanged(
    mojom::blink::MediaDeviceType type,
    const Vector<WebMediaDeviceInfo>& device_infos) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DCHECK(GetExecutionContext());
  if (base::ranges::equal(current_device_infos_[static_cast<wtf_size_t>(type)],
                          device_infos, EqualDeviceForDeviceChange)) {
    return;
  }

  current_device_infos_[static_cast<wtf_size_t>(type)] = device_infos;
  if (RuntimeEnabledFeatures::OnDeviceChangeEnabled()) {
    ScheduleDispatchEvent(Event::Create(event_type_names::kDevicechange));
  }
}

void MediaDevices::ScheduleDispatchEvent(Event* event) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  scheduled_events_.push_back(event);
  if (dispatch_scheduled_events_task_handle_.IsActive()) {
    return;
  }

  auto* context = GetExecutionContext();
  DCHECK(context);
  dispatch_scheduled_events_task_handle_ = PostCancellableTask(
      *context->GetTaskRunner(TaskType::kMediaElementEvent), FROM_HERE,
      WTF::BindOnce(&MediaDevices::DispatchScheduledEvents,
                    WrapPersistent(this)));
}

void MediaDevices::DispatchScheduledEvents() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (stopped_) {
    return;
  }
  HeapVector<Member<Event>> events;
  events.swap(scheduled_events_);

  for (const auto& event : events) {
    DispatchEvent(*event);
  }
}

void MediaDevices::StartObserving() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (receiver_.is_bound() || stopped_ || starting_observation_) {
    return;
  }

  LocalDOMWindow* window = To<LocalDOMWindow>(GetExecutionContext());
  if (!window) {
    return;
  }

  starting_observation_ = true;
  GetDispatcherHost(window->GetFrame())
      .EnumerateDevices(/*request_audio_input=*/true,
                        /*request_video_input=*/true,
                        /*request_audio_output=*/true,
                        /*request_video_input_capabilities=*/false,
                        /*request_audio_input_capabilities=*/false,
                        WTF::BindOnce(&MediaDevices::FinalizeStartObserving,
                                      WrapPersistent(this)));
}

void MediaDevices::FinalizeStartObserving(
    const Vector<Vector<WebMediaDeviceInfo>>& enumeration,
    Vector<mojom::blink::VideoInputDeviceCapabilitiesPtr>
        video_input_capabilities,
    Vector<mojom::blink::AudioInputDeviceCapabilitiesPtr>
        audio_input_capabilities) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  starting_observation_ = false;
  if (receiver_.is_bound() || stopped_) {
    return;
  }

  LocalDOMWindow* window = To<LocalDOMWindow>(GetExecutionContext());
  if (!window) {
    return;
  }

  current_device_infos_ = enumeration;

  GetDispatcherHost(window->GetFrame())
      .AddMediaDevicesListener(true /* audio input */, true /* video input */,
                               true /* audio output */,
                               receiver_.BindNewPipeAndPassRemote(
                                   GetExecutionContext()->GetTaskRunner(
                                       TaskType::kMediaElementEvent)));
}

void MediaDevices::StopObserving() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!receiver_.is_bound()) {
    return;
  }
  receiver_.reset();
}

namespace {

void RecordEnumeratedDevices(ScriptState* script_state,
                             const MediaDeviceInfoVector& media_devices) {
  if (!IdentifiabilityStudySettings::Get()->ShouldSampleWebFeature(
          WebFeature::kIdentifiabilityMediaDevicesEnumerateDevices)) {
    return;
  }
  Document* document =
      LocalDOMWindow::From(script_state)->GetFrame()->GetDocument();
  IdentifiableTokenBuilder builder;
  for (const auto& device_info : media_devices) {
    // Ignore device_id since that varies per-site.
    builder.AddToken(
        IdentifiabilityBenignStringToken(device_info->kind().AsString()));
    builder.AddToken(IdentifiabilityBenignStringToken(device_info->label()));
    // Ignore group_id since that is varies per-site.
  }
  IdentifiabilityMetricBuilder(document->UkmSourceID())
      .AddWebFeature(WebFeature::kIdentifiabilityMediaDevicesEnumerateDevices,
                     builder.GetToken())
      .Record(document->UkmRecorder());
}

}  // namespace

void MediaDevices::DevicesEnumerated(
    ScriptPromiseResolverWithTracker<EnumerateDevicesResult,
                                     IDLSequence<MediaDeviceInfo>>*
        result_tracker,
    std::unique_ptr<ScopedMediaStreamTracer> tracer,
    const Vector<Vector<WebMediaDeviceInfo>>& enumeration,
    Vector<mojom::blink::VideoInputDeviceCapabilitiesPtr>
        video_input_capabilities,
    Vector<mojom::blink::AudioInputDeviceCapabilitiesPtr>
        audio_input_capabilities) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!enumerate_device_requests_.Contains(result_tracker)) {
    return;
  }

  enumerate_device_requests_.erase(result_tracker);

  ScriptState* script_state = result_tracker->GetScriptState();
  if (!script_state || !ExecutionContext::From(script_state) ||
      ExecutionContext::From(script_state)->IsContextDestroyed()) {
    return;
  }

  DCHECK_EQ(static_cast<wtf_size_t>(
                mojom::blink::MediaDeviceType::kNumMediaDeviceTypes),
            enumeration.size());

  if (!video_input_capabilities.empty()) {
    DCHECK_EQ(enumeration[static_cast<wtf_size_t>(
                              mojom::blink::MediaDeviceType::kMediaVideoInput)]
                  .size(),
              video_input_capabilities.size());
  }
  if (!audio_input_capabilities.empty()) {
    DCHECK_EQ(enumeration[static_cast<wtf_size_t>(
                              mojom::blink::MediaDeviceType::kMediaAudioInput)]
                  .size(),
              audio_input_capabilities.size());
  }

  MediaDeviceInfoVector media_devices;
  for (wtf_size_t i = 0;
       i < static_cast<wtf_size_t>(
               mojom::blink::MediaDeviceType::kNumMediaDeviceTypes);
       ++i) {
    for (wtf_size_t j = 0; j < enumeration[i].size(); ++j) {
      mojom::blink::MediaDeviceType device_type =
          static_cast<mojom::blink::MediaDeviceType>(i);
      WebMediaDeviceInfo device_info = enumeration[i][j];
      String device_label = String::FromUTF8(device_info.label);
      if (device_type == mojom::blink::MediaDeviceType::kMediaAudioInput ||
          device_type == mojom::blink::MediaDeviceType::kMediaVideoInput) {
        InputDeviceInfo* input_device_info =
            MakeGarbageCollected<InputDeviceInfo>(
                String::FromUTF8(device_info.device_id), device_label,
                String::FromUTF8(device_info.group_id), device_type);
        if (device_type == mojom::blink::MediaDeviceType::kMediaVideoInput &&
            !video_input_capabilities.empty()) {
          input_device_info->SetVideoInputCapabilities(
              std::move(video_input_capabilities[j]));
        }
        if (device_type == mojom::blink::MediaDeviceType::kMediaAudioInput &&
            !audio_input_capabilities.empty()) {
          input_device_info->SetAudioInputCapabilities(
              std::move(audio_input_capabilities[j]));
        }
        media_devices.push_back(input_device_info);
      } else {
        media_devices.push_back(MakeGarbageCollected<MediaDeviceInfo>(
            String::FromUTF8(device_info.device_id), device_label,
            String::FromUTF8(device_info.group_id), device_type));
      }
    }
  }

  RecordEnumeratedDevices(result_tracker->GetScriptState(), media_devices);
  result_tracker->Resolve(media_devices);
  tracer->End();
}

void MediaDevices::OnDispatcherHostConnectionError() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  for (ScriptPromiseResolverWithTracker<EnumerateDevicesResult,
                                        IDLSequence<MediaDeviceInfo>>*
           result_tracker : enumerate_device_requests_) {
    result_tracker->Reject<DOMException>(
        MakeGarbageCollected<DOMException>(DOMExceptionCode::kAbortError,
                                           "enumerateDevices() failed."),
        EnumerateDevicesResult::kErrorMediaDevicesDispatcherHostDisconnected);
  }
  enumerate_device_requests_.clear();
  dispatcher_host_.reset();
}

mojom::blink::MediaDevicesDispatcherHost& MediaDevices::GetDispatcherHost(
    LocalFrame* frame) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ExecutionContext* const execution_context = GetExecutionContext();
  DCHECK(execution_context);

  if (!dispatcher_host_.is_bound()) {
    // Note: kInternalMediaRealTime is a better candidate for this job,
    // but kMediaElementEvent is used for consistency.
    frame->GetBrowserInterfaceBroker().GetInterface(
        dispatcher_host_.BindNewPipeAndPassReceiver(
            execution_context->GetTaskRunner(TaskType::kMediaElementEvent)));
    dispatcher_host_.set_disconnect_handler(
        WTF::BindOnce(&MediaDevices::OnDispatcherHostConnectionError,
                      WrapWeakPersistent(this)));
  }

  DCHECK(dispatcher_host_.get());
  return *dispatcher_host_.get();
}

void MediaDevices::SetDispatcherHostForTesting(
    mojo::PendingRemote<mojom::blink::MediaDevicesDispatcherHost>
        dispatcher_host) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ExecutionContext* const execution_context = GetExecutionContext();
  DCHECK(execution_context);

  dispatcher_host_.Bind(
      std::move(dispatcher_host),
      execution_context->GetTaskRunner(TaskType::kMediaElementEvent));
  dispatcher_host_.set_disconnect_handler(
      WTF::BindOnce(&MediaDevices::OnDispatcherHostConnectionError,
                    WrapWeakPersistent(this)));
}

void MediaDevices::Trace(Visitor* visitor) const {
  visitor->Trace(dispatcher_host_);
  visitor->Trace(receiver_);
  visitor->Trace(scheduled_events_);
  visitor->Trace(enumerate_device_requests_);
#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
  visitor->Trace(crop_target_resolvers_);
  visitor->Trace(restriction_target_resolvers_);
#endif
  Supplement<Navigator>::Trace(visitor);
  EventTarget::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

#if !BUILDFLAG(IS_ANDROID) && !BUILDFLAG(IS_IOS)
void MediaDevices::EnqueueMicrotaskToCloseFocusWindowOfOpportunity(
    const String& id,
    CaptureController* capture_controller) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ExecutionContext* const context = GetExecutionContext();
  if (!context) {
    return;
  }

  context->GetAgent()->event_loop()->EnqueueMicrotask(WTF::BindOnce(
      &MediaDevices::CloseFocusWindowOfOpportunity, WrapWeakPersistent(this),
      id, WrapWeakPersistent(capture_controller)));
}

void MediaDevices::CloseFocusWindowOfOpportunity(
    const String& id,
    CaptureController* capture_controller) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ExecutionContext* const context = GetExecutionContext();
  if (!context) {
    return;  // Note: We're still back by the browser-side timer.
  }

  LocalDOMWindow* const window = To<LocalDOMWindow>(context);
  if (!window) {
    return;
  }

  if (capture_controller) {
    capture_controller->FinalizeFocusDecision();
  }

  GetDispatcherHost(window->GetFrame()).CloseFocusWindowOfOpportunity(id);
}

// Checks whether the production of a SubCaptureTarget of the given type is
// allowed. Throw an appropriate exception if not.
bool MediaDevices::MayProduceSubCaptureTarget(ScriptState* script_state,
                                              Element* element,
                                              ExceptionState& exception_state,
                                              SubCaptureTarget::Type type) {
  CHECK(type == SubCaptureTarget::Type::kCropTarget ||
        type == SubCaptureTarget::Type::kRestrictionTarget);

  if (!script_state->ContextIsValid()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Current frame is detached.");
    RecordUma(type, ProduceTargetFunctionResult::kInvalidContext);
    return false;
  }

  LocalDOMWindow* const window = To<LocalDOMWindow>(GetExecutionContext());
  if (!window) {
    RecordUma(type, ProduceTargetFunctionResult::kGenericError);
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Missing execution context.");
    return false;
  }

  if (!element) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Invalid element.");
    return false;
  }

  if (GetExecutionContext() != element->GetExecutionContext()) {
    RecordUma(type, ProduceTargetFunctionResult::
                        kElementAndMediaDevicesNotInSameExecutionContext);
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "The Element and the MediaDevices object must be same-window.");
    return false;
  }

  return true;
}

void MediaDevices::ResolveCropTargetPromise(Element* element,
                                            const WTF::String& id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(element);  // Persistent.

  const auto it = crop_target_resolvers_.find(element);
  CHECK_NE(it, crop_target_resolvers_.end(), base::NotFatalUntil::M130);
  ScriptPromiseResolver<CropTarget>* const resolver = it->value;
  crop_target_resolvers_.erase(it);

  const base::Token token = SubCaptureTargetIdToToken(id);
  if (token.is_zero()) {
    resolver->Reject();
    RecordUma(SubCaptureTarget::Type::kCropTarget,
              ProduceTargetPromiseResult::kPromiseRejected);
    return;
  }

  element->SetRegionCaptureCropId(std::make_unique<RegionCaptureCropId>(token));
  resolver->Resolve(MakeGarbageCollected<CropTarget>(id));
  RecordUma(SubCaptureTarget::Type::kCropTarget,
            ProduceTargetPromiseResult::kPromiseResolved);
}

void MediaDevices::ResolveRestrictionTargetPromise(Element* element,
                                                   const WTF::String& id) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(element);  // Persistent.

  const auto it = restriction_target_resolvers_.find(element);
  CHECK_NE(it, restriction_target_resolvers_.end(), base::NotFatalUntil::M130);
  ScriptPromiseResolver<RestrictionTarget>* const resolver = it->value;
  restriction_target_resolvers_.erase(it);

  const base::Token token = SubCaptureTargetIdToToken(id);
  if (token.is_zero()) {
    resolver->Reject();
    RecordUma(SubCaptureTarget::Type::kRestrictionTarget,
              ProduceTargetPromiseResult::kPromiseRejected);
    return;
  }

  element->SetRestrictionTargetId(std::make_unique<RestrictionTargetId>(token));
  resolver->Resolve(MakeGarbageCollected<RestrictionTarget>(id));
  RecordUma(SubCaptureTarget::Type::kRestrictionTarget,
            ProduceTargetPromiseResult::kPromiseResolved);
}
#endif

}  // namespace blink

"""


```