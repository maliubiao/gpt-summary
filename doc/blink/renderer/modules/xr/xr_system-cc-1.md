Response:
The user wants a summary of the functionality of the provided C++ code snippet from `xr_system.cc`. I need to analyze the code and explain what it does, how it interacts with web technologies, identify logical inferences, common usage errors, and describe how a user's actions can lead to this code being executed.

**Functionality Breakdown:**

1. **XR Session Management:**  The code handles the lifecycle of WebXR sessions, including requesting, starting, and ending them.
2. **Feature Negotiation:** It manages the negotiation of optional and required features for XR sessions.
3. **Communication with Browser Process:** It interacts with the browser process (via Mojo interfaces) to request services and receive updates.
4. **Fullscreen Integration:** It manages entering and exiting fullscreen mode, especially in the context of DOM overlays in XR.
5. **Error Handling:** It handles errors during session creation and other XR operations, providing feedback via console messages and promise rejections.
6. **Permissions Policy Enforcement:** It checks if requested XR features are allowed by the current Permissions Policy.
7. **Device Change Notifications:** It listens for and dispatches events when XR device availability changes.
8. **WebXR Internals Logging:**  It sends internal logging messages for debugging and analysis.
9. **Sensorless Sessions:** It supports the creation of inline sessions without requiring XR hardware.

**Interaction with Web Technologies:**

*   **JavaScript:**  This code implements the backend logic for the WebXR JavaScript API (`navigator.xr`). Functions like `requestSession`, `supportsSession`, and event listeners are implemented here.
*   **HTML:** The DOM Overlay feature directly manipulates HTML elements to display them within the XR environment. Fullscreen API interaction is also relevant.
*   **CSS:**  While not directly manipulating CSS here, the DOM Overlay feature relies on CSS for the styling of the overlaid HTML content.

**Logical Inferences and Assumptions:**

I'll look for conditional logic and make assumptions about the inputs and expected outputs.

**Common Usage Errors:**

I'll consider typical mistakes developers make when using the WebXR API.

**User Operation to Reach the Code:**

I need to trace back how a user interaction in a web page can trigger the execution of this C++ code.

**Step-by-step Thought Process for the Summary:**

1. **Identify Core Purpose:** The central theme is managing WebXR functionality within the Chromium renderer.
2. **Group Related Functions:** Combine functions that handle session creation, feature requests, etc.
3. **Focus on User-facing Actions:**  Relate the code to actions a web developer or user might take.
4. **Highlight Web Integration:** Emphasize the connections to JavaScript, HTML, and CSS.
5. **Address the Specific Questions:** Explicitly answer the parts about logical inferences, user errors, and debugging.
这是 blink 引擎中 `XRSystem` 类的部分代码，主要负责 XR (扩展现实，包括 VR 和 AR) 系统的核心功能。根据提供的代码片段，我们可以归纳出以下功能：

**主要功能归纳：**

1. **XR 会话的生命周期管理：**
    *   **退出 Present 模式 (`ExitPresent`):**  处理 XR 会话的结束。它会先检查是否因为全屏元素导致的 DOM Overlay，如果是，会先退出全屏，然后再真正结束 XR 会话。这避免了浏览器和渲染器之间关于全屏状态的竞争条件。
    *   **设置帧节流 (`SetFramesThrottled`):**  控制沉浸式 XR 会话的帧率，用于优化性能或功耗。
    *   **查询是否支持会话模式 (`supportsSession`, `isSessionSupported`, `InternalIsSessionSupported`):**  允许 JavaScript 查询特定 XR 会话模式（例如 `immersive-vr`, `immersive-ar`, `inline`）是否被支持。它会检查上下文、权限策略，并最终与浏览器进程中的 XR 服务通信。
    *   **请求会话 (`RequestSessionInternal`, `RequestImmersiveSession`, `RequestInlineSession`, `DoRequestSession`):**  处理来自 JavaScript 的创建 XR 会话的请求。它会进行各种检查（例如是否允许沉浸式会话、是否存在其他活动会话、硬件支持等），然后与浏览器进程中的 XR 服务通信。对于沉浸式会话，可能涉及到全屏模式的切换。
    *   **解析请求的特性 (`ParseRequestedFeatures`):**  解析 JavaScript 请求会话时提供的可选和必需的特性（例如 `local-floor`, `bounded-reference-space` 等），检查这些特性是否被支持、是否满足权限策略等。

2. **与浏览器进程的 XR 服务通信：**
    *   通过 `service_` 成员（`device::mojom::blink::VRService` 的接口）与浏览器进程中的 VR 服务进行通信，执行如查询支持、请求会话等操作。

3. **错误处理和日志记录：**
    *   **添加控制台消息 (`AddConsoleMessage`):**  将错误或警告消息添加到浏览器的开发者控制台。对于沉浸式会话的错误或警告，还会发送到内部 WebXR 日志系统。
    *   **添加内部 WebXR 消息 (`AddWebXrInternalsMessage`):**  将内部日志消息发送到 WebXR Internals 监听器，用于调试和分析。

4. **DOM Overlay 支持：**
    *   在退出 Present 模式和请求沉浸式会话时，处理与 DOM Overlay 相关的全屏操作，确保与 XR 会话的生命周期正确同步。

5. **权限策略检查：**
    *   在查询支持和请求会话时，会检查相关的权限策略 (`PermissionsPolicyFeature::kWebXr`) 是否允许进行 XR 操作。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

*   **JavaScript:**  `XRSystem` 提供的功能直接对应于 WebXR JavaScript API。
    *   **`navigator.xr.isSessionSupported('immersive-vr')`:**  JavaScript 调用会最终触发 `XRSystem::isSessionSupported`。
    *   **`navigator.xr.requestSession('immersive-ar', { requiredFeatures: ['camera-access'] })`:** JavaScript 调用会最终触发 `XRSystem::requestSession`，其中 `'camera-access'` 字符串会被 `ParseRequestedFeatures` 解析。
    *   **`session.end()`:** JavaScript 调用会最终触发 `XRSystem::ExitPresent`。

*   **HTML:** DOM Overlay 功能允许将 HTML 内容渲染到 XR 环境中。
    *   假设 JavaScript 代码创建了一个沉浸式 AR 会话，并指定了一个 HTML `<div>` 元素作为 DOM Overlay：
        ```javascript
        navigator.xr.requestSession('immersive-ar', {
          domOverlay: { root: document.getElementById('overlay-content') }
        });
        ```
        在这种情况下，`XRSystem` 会在会话开始时处理将该 `<div>` 元素设置为全屏（如果需要），并在 XR 环境中渲染其内容。

*   **CSS:**  DOM Overlay 中 HTML 元素的样式由 CSS 控制。
    *   在上面的 DOM Overlay 示例中，`#overlay-content` 及其子元素的样式将由页面中应用的 CSS 规则决定。

**逻辑推理的假设输入与输出：**

*   **假设输入 ( `supportsSession` )：**
    *   用户 JavaScript 调用 `navigator.xr.isSessionSupported('immersive-vr')`。
    *   设备的 XR 服务可用。
    *   权限策略允许 WebXR。
*   **输出：**
    *   如果设备支持 `immersive-vr` 模式，`InternalIsSessionSupported` 最终会通过 Promise 解析器返回 `true`。
    *   如果设备不支持，则返回 `false`。

*   **假设输入 ( `requestSession` - 成功场景)：**
    *   用户 JavaScript 调用 `navigator.xr.requestSession('inline')`。
    *   权限策略允许 WebXR。
*   **输出：**
    *   `RequestInlineSession` 会创建一个 `XRSession` 对象，并通过 Promise 解析器将其返回给 JavaScript。

*   **假设输入 ( `requestSession` - 失败场景)：**
    *   用户 JavaScript 调用 `navigator.xr.requestSession('immersive-vr')`。
    *   但设备不支持沉浸式 VR。
*   **输出：**
    *   `RequestImmersiveSession` 会尝试请求会话，但浏览器进程的 XR 服务会返回失败。
    *   `FinishSessionCreation` 会收到失败结果，并通过 Promise 解析器拒绝该 Promise，并可能在控制台输出错误消息。

**涉及用户或编程常见的使用错误及举例说明：**

*   **请求不支持的会话模式：**
    *   **错误代码：** `navigator.xr.requestSession('magic-leap')` (假设 'magic-leap' 不是有效的模式)。
    *   **结果：** `ParseRequestedFeatures` 或底层的服务通信会识别出不支持的模式，并通过 Promise 拒绝会话请求，并可能在控制台输出错误消息 "Unrecognized feature requested: magic-leap"。

*   **请求需要权限策略但未被允许的特性：**
    *   **错误代码：**  假设某个特性（例如访问特定传感器数据）需要特定的权限策略，但该策略未在页面中启用。
    *   **结果：** `ParseRequestedFeatures` 会检测到权限策略未满足，并通过 Promise 拒绝会话请求，并在控制台输出类似于 "Feature '...' is not permitted by permissions policy" 的消息。

*   **在不适当的时机调用 XR API：**
    *   **错误代码：** 在文档还未完全加载或者 `navigator.xr` 对象不存在时调用 `requestSession`。
    *   **结果：** 可能会导致 JavaScript 错误，或者 `GetExecutionContext()` 返回空指针，导致 `InternalIsSessionSupported` 或 `requestSession` 抛出异常或返回失败的 Promise。

*   **在沉浸式会话激活时尝试创建新的沉浸式会话：**
    *   **错误代码：** 在一个沉浸式会话还未结束时，再次调用 `navigator.xr.requestSession('immersive-vr')`。
    *   **结果：** `RequestImmersiveSession` 会检测到已经存在活动的沉浸式会话，并通过 Promise 拒绝新的会话请求，并在控制台输出类似于 "InvalidStateError: A request to create an immersive session is already pending, or an immersive session is already active." 的消息。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户访问一个包含 WebXR 代码的网页。**
2. **网页中的 JavaScript 代码调用了 `navigator.xr.isSessionSupported('immersive-vr')` 或 `navigator.xr.requestSession(...)`。**
3. **浏览器接收到 JavaScript 的调用，并将其传递给渲染器进程。**
4. **在渲染器进程中，Blink 引擎接收到该调用，并路由到 `modules/xr/xr_system.cc` 文件中的 `XRSystem` 类的相应方法，例如 `isSessionSupported` 或 `requestSession`。**
5. **`XRSystem` 类的方法执行各种检查（例如权限、硬件支持），并可能通过 Mojo 接口与浏览器进程中的 XR 服务通信。**
6. **浏览器进程中的 XR 服务与底层 XR 硬件或平台服务进行交互。**
7. **结果通过 Mojo 接口返回到渲染器进程的 `XRSystem` 类。**
8. **`XRSystem` 类最终通过 Promise 将结果返回给网页的 JavaScript 代码。**

**调试线索：**

*   **控制台消息：** 查看浏览器的开发者控制台，查找由 `AddConsoleMessage` 输出的错误或警告信息。
*   **断点调试：** 在 Chrome 开发者工具中，可以设置 C++ 代码的断点，例如在 `XRSystem::RequestSessionInternal` 或 `XRSystem::InternalIsSessionSupported` 等方法中，来跟踪代码的执行流程和变量的值。
*   **WebXR Internals：** Chrome 提供了 `chrome://webxr-internals` 页面，可以查看 WebXR 的内部状态和日志信息，这对于调试沉浸式会话非常有用。`AddWebXrInternalsMessage` 会将消息发送到这里。
*   **Mojo 日志：** 可以启用 Mojo 的日志记录来查看渲染器进程和浏览器进程之间 XR 相关的通信内容。

总而言之，这段代码是 Blink 引擎中处理 WebXR API 调用的核心部分，负责与浏览器进程通信，管理 XR 会话的生命周期，并确保符合规范和安全策略。它连接了 JavaScript API 和底层的 XR 平台服务。

Prompt: 
```
这是目录为blink/renderer/modules/xr/xr_system.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
rovider() {
  if (!frame_provider_) {
    frame_provider_ = MakeGarbageCollected<XRFrameProvider>(this);
  }

  return frame_provider_.Get();
}

device::mojom::blink::XREnvironmentIntegrationProvider*
XRSystem::xrEnvironmentProviderRemote() {
  return environment_provider_.get();
}

device::mojom::blink::VRService* XRSystem::BrowserService() {
  return service_.get();
}

void XRSystem::AddEnvironmentProviderErrorHandler(
    EnvironmentProviderErrorCallback callback) {
  environment_provider_error_callbacks_.push_back(std::move(callback));
}

void XRSystem::ExitPresent(base::OnceClosure on_exited) {
  DVLOG(1) << __func__;

  // If the document was potentially being shown in a DOM overlay via
  // fullscreened elements, make sure to clear any fullscreen states on exiting
  // the session. This avoids a race condition:
  // - browser side ends session and exits fullscreen (i.e. back button)
  // - renderer processes WebViewImpl::ExitFullscreen via ChromeClient
  // - JS application sets a new element to fullscreen, this is allowed
  //   because doc->IsXrOverlay() is still true at this point
  // - renderer processes XR session shutdown (this method)
  // - browser re-enters fullscreen unexpectedly
  if (LocalDOMWindow* window = DomWindow()) {
    Document* doc = window->document();
    DVLOG(3) << __func__ << ": doc->IsXrOverlay()=" << doc->IsXrOverlay();
    if (doc->IsXrOverlay()) {
      Element* fullscreen_element = Fullscreen::FullscreenElementFrom(*doc);
      DVLOG(3) << __func__ << ": fullscreen_element=" << fullscreen_element;
      if (fullscreen_element) {
        fullscreen_exit_observer_ =
            MakeGarbageCollected<XrExitFullscreenObserver>();
        // Once we exit fullscreen, we'll need to come back here to finish
        // shutting down the session.
        fullscreen_exit_observer_->ExitFullscreen(
            doc, WTF::BindOnce(&XRSystem::ExitPresent, WrapWeakPersistent(this),
                               std::move(on_exited)));
        return;
      }
    }
  }

  if (service_.is_bound()) {
    service_->ExitPresent(std::move(on_exited));
  } else {
    // The service was already shut down, run the callback immediately.
    std::move(on_exited).Run();
  }
}

void XRSystem::SetFramesThrottled(const XRSession* session, bool throttled) {
  // The service only cares if the immersive session is throttling frames.
  if (session->immersive()) {
    // If we have an immersive session, we should have a service.
    DCHECK(service_.is_bound());
    service_->SetFramesThrottled(throttled);
  }
}

ScriptPromise<IDLUndefined> XRSystem::supportsSession(
    ScriptState* script_state,
    const V8XRSessionMode& mode,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  InternalIsSessionSupported(resolver, mode, exception_state, true);
  return promise;
}

ScriptPromise<IDLBoolean> XRSystem::isSessionSupported(
    ScriptState* script_state,
    const V8XRSessionMode& mode,
    ExceptionState& exception_state) {
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLBoolean>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();
  InternalIsSessionSupported(resolver, mode, exception_state, false);
  return promise;
}

void XRSystem::AddConsoleMessage(mojom::blink::ConsoleMessageLevel error_level,
                                 const String& message) {
  DVLOG(2) << __func__ << ": error_level=" << error_level
           << ", message=" << message;

  if ((error_level == mojom::blink::ConsoleMessageLevel::kError ||
       error_level == mojom::blink::ConsoleMessageLevel::kWarning) &&
      frameProvider()->immersive_session()) {
    AddWebXrInternalsMessage(message);
  }
  GetExecutionContext()->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::blink::ConsoleMessageSource::kJavaScript, error_level, message));
}

void XRSystem::AddWebXrInternalsMessage(const String& message) {
  if (webxr_internals_renderer_listener_) {
    device::mojom::blink::XrLogMessagePtr xr_logging_statistics =
        device::mojom::blink::XrLogMessage::New();

    xr_logging_statistics->message = message;
    xr_logging_statistics->trace_id =
        frameProvider()->immersive_session()->GetTraceId();

    webxr_internals_renderer_listener_->OnConsoleLog(
        std::move(xr_logging_statistics));
  }
}

void XRSystem::InternalIsSessionSupported(ScriptPromiseResolverBase* resolver,
                                          const V8XRSessionMode& mode,
                                          ExceptionState& exception_state,
                                          bool throw_on_unsupported) {
  if (!GetExecutionContext()) {
    // Reject if the context is inaccessible.
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kNavigatorDetachedError);
    return;  // Promise will be rejected by generated bindings
  }

  device::mojom::blink::XRSessionMode session_mode =
      V8EnumToSessionMode(mode.AsEnum());
  PendingSupportsSessionQuery* query =
      MakeGarbageCollected<PendingSupportsSessionQuery>(resolver, session_mode,
                                                        throw_on_unsupported);

  if (session_mode == device::mojom::blink::XRSessionMode::kImmersiveAr &&
      !IsImmersiveArAllowed()) {
    DVLOG(2) << __func__
             << ": Immersive AR session is only supported if WebXRARModule "
                "feature is enabled by a runtime feature and web settings";
    query->Resolve(false);
    return;
  }

  if (session_mode == device::mojom::blink::XRSessionMode::kInline) {
    // inline sessions are always supported.
    query->Resolve(true);
    return;
  }

  if (!GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kWebXr,
          ReportOptions::kReportOnFailure)) {
    // Only allow the call to be made if the appropriate permissions policy is
    // in place.
    query->RejectWithSecurityError(kFeaturePolicyBlocked, &exception_state);
    return;
  }

  // If TryEnsureService() doesn't set |service_|, then we don't have any WebXR
  // hardware, so we need to reject as being unsupported.
  TryEnsureService();
  if (!service_.is_bound()) {
    query->Resolve(false, &exception_state);
    return;
  }

  device::mojom::blink::XRSessionOptionsPtr session_options =
      device::mojom::blink::XRSessionOptions::New();
  session_options->mode = query->mode();
  session_options->trace_id = query->TraceId();

  outstanding_support_queries_.insert(query);
  service_->SupportsSession(
      std::move(session_options),
      WTF::BindOnce(&XRSystem::OnSupportsSessionReturned, WrapPersistent(this),
                    WrapPersistent(query)));
}

void XRSystem::RequestSessionInternal(
    device::mojom::blink::XRSessionMode session_mode,
    PendingRequestSessionQuery* query,
    ExceptionState* exception_state) {
  // The various session request methods may have other checks that would reject
  // before needing to create the vr service, so we don't try to create it here.
  switch (session_mode) {
    case device::mojom::blink::XRSessionMode::kImmersiveVr:
    case device::mojom::blink::XRSessionMode::kImmersiveAr:
      RequestImmersiveSession(query, exception_state);
      break;
    case device::mojom::blink::XRSessionMode::kInline:
      RequestInlineSession(query, exception_state);
      break;
  }
}

void XRSystem::RequestImmersiveSession(PendingRequestSessionQuery* query,
                                       ExceptionState* exception_state) {
  DVLOG(2) << __func__;
  // Log an immersive session request if we haven't already
  if (!did_log_request_immersive_session_) {
    ukm::builders::XR_WebXR(DomWindow()->UkmSourceID())
        .SetDidRequestPresentation(1)
        .Record(DomWindow()->UkmRecorder());
    did_log_request_immersive_session_ = true;
  }

  // Make sure the request is allowed
  auto* immersive_session_request_error =
      CheckImmersiveSessionRequestAllowed(DomWindow());
  if (immersive_session_request_error) {
    DVLOG(2) << __func__
             << ": rejecting session - immersive session not allowed, reason: "
             << immersive_session_request_error;
    query->RejectWithSecurityError(immersive_session_request_error,
                                   exception_state);
    return;
  }

  // Ensure there are no other immersive sessions currently pending or active
  if (has_outstanding_immersive_request_ ||
      frameProvider()->immersive_session()) {
    DVLOG(2) << __func__
             << ": rejecting session - immersive session request is already "
                "pending or an immersive session is already active";
    query->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                  kActiveImmersiveSession, exception_state);
    return;
  }

  // If TryEnsureService() doesn't set |service_|, then we don't have any WebXR
  // hardware.
  TryEnsureService();
  if (!service_.is_bound()) {
    DVLOG(2) << __func__ << ": rejecting session - service is not bound";
    query->RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                                  kNoDevicesMessage, exception_state);
    return;
  }

  // Reject session if any of the required features were invalid.
  if (query->InvalidRequiredFeatures()) {
    DVLOG(2) << __func__ << ": rejecting session - invalid required features";
    query->RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                                  kInvalidRequiredFeatures, exception_state);
    return;
  }

  // Reworded from spec 'pending immersive session'
  has_outstanding_immersive_request_ = true;

  // Submit the request to VrServiceImpl in the Browser process
  outstanding_request_queries_.insert(query);
  auto session_options = XRSessionOptionsFromQuery(*query);

  // If we're already in fullscreen mode, we need to exit and re-enter
  // fullscreen mode to properly apply the is_xr_overlay property and reset the
  // existing navigationUI options that may be conflicting with what we want.
  // Request a fullscreen exit, and continue with the session request once that
  // completes.
  Document* doc = DomWindow()->document();
  if (Fullscreen::FullscreenElementFrom(*doc)) {
    fullscreen_exit_observer_ =
        MakeGarbageCollected<XrExitFullscreenObserver>();

    base::OnceClosure callback =
        WTF::BindOnce(&XRSystem::DoRequestSession, WrapWeakPersistent(this),
                      WrapPersistent(query), std::move(session_options));
    fullscreen_exit_observer_->ExitFullscreen(doc, std::move(callback));
    return;
  }

  DoRequestSession(std::move(query), std::move(session_options));
}

void XRSystem::DoRequestSession(
    PendingRequestSessionQuery* query,
    device::mojom::blink::XRSessionOptionsPtr session_options) {
  service_->RequestSession(
      std::move(session_options),
      WTF::BindOnce(&XRSystem::OnRequestSessionReturned,
                    WrapWeakPersistent(this), WrapPersistent(query)));
}

void XRSystem::RequestInlineSession(PendingRequestSessionQuery* query,
                                    ExceptionState* exception_state) {
  DVLOG(2) << __func__;
  // Make sure the inline session request was allowed
  auto* inline_session_request_error =
      CheckInlineSessionRequestAllowed(DomWindow()->GetFrame(), *query);
  if (inline_session_request_error) {
    query->RejectWithSecurityError(inline_session_request_error,
                                   exception_state);
    return;
  }

  // Reject session if any of the required features were invalid.
  if (query->InvalidRequiredFeatures()) {
    DVLOG(2) << __func__ << ": rejecting session - invalid required features";
    query->RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                                  kInvalidRequiredFeatures, exception_state);
    return;
  }

  auto sensor_requirement = query->GetSensorRequirement();

  // Try to get the service now. If we can't get it, then we know that we can
  // only support a sensorless session. But if we *can* get it, then we need to
  // check if we have any hardware that supports the requested features.
  TryEnsureService();

  // If no sensors are requested, or if we don't have a service and sensors are
  // not required, then just create a sensorless session.
  if (sensor_requirement == SensorRequirement::kNone ||
      (!service_.is_bound() &&
       sensor_requirement != SensorRequirement::kRequired)) {
    query->Resolve(CreateSensorlessInlineSession());
    return;
  }

  // If we don't have a service, then we don't have any WebXR hardware.
  // If we didn't already create a sensorless session, we can't create a session
  // without hardware, so just reject now.
  if (!service_.is_bound()) {
    DVLOG(2) << __func__ << ": rejecting session - no service";
    query->RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                                  kNoDevicesMessage, exception_state);
    return;
  }

  // Submit the request to VrServiceImpl in the Browser process
  outstanding_request_queries_.insert(query);
  auto session_options = XRSessionOptionsFromQuery(*query);
  service_->RequestSession(
      std::move(session_options),
      WTF::BindOnce(&XRSystem::OnRequestSessionReturned,
                    WrapWeakPersistent(this), WrapPersistent(query)));
}

XRSystem::RequestedXRSessionFeatureSet XRSystem::ParseRequestedFeatures(
    const Vector<String>& features,
    const device::mojom::blink::XRSessionMode& session_mode,
    XRSessionInit* session_init,
    mojom::blink::ConsoleMessageLevel error_level) {
  DVLOG(2) << __func__ << ": features.size()=" << features.size()
           << ", session_mode=" << session_mode;
  RequestedXRSessionFeatureSet result;

  // Iterate over all requested features, even if intermediate
  // elements are found to be invalid.
  for (const auto& feature_string : features) {
    auto feature_enum = StringToXRSessionFeature(feature_string);

    if (!feature_enum) {
      AddConsoleMessage(error_level,
                        "Unrecognized feature requested: " + feature_string);
      result.invalid_features = true;
    } else if (!IsFeatureEnabledForContext(feature_enum.value(),
                                           GetExecutionContext())) {
      AddConsoleMessage(error_level,
                        "Unsupported feature requested: " + feature_string);
      result.invalid_features = true;
    } else if (!IsFeatureValidForMode(feature_enum.value(), session_mode,
                                      session_init, GetExecutionContext(),
                                      error_level)) {
      AddConsoleMessage(error_level, "Feature '" + feature_string +
                                         "' is not supported for mode: " +
                                         SessionModeToString(session_mode));
      result.invalid_features = true;
    } else if (!HasRequiredPermissionsPolicy(GetExecutionContext(),
                                             feature_enum.value())) {
      AddConsoleMessage(error_level,
                        "Feature '" + feature_string +
                            "' is not permitted by permissions policy");
      result.invalid_features = true;
    } else {
      DVLOG(3) << __func__ << ": Adding feature " << feature_string
               << " to valid_features.";
      result.valid_features.insert(feature_enum.value());
    }
  }

  DVLOG(2) << __func__
           << ": result.invalid_features=" << result.invalid_features
           << ", result.valid_features.size()=" << result.valid_features.size();
  return result;
}

ScriptPromise<XRSession> XRSystem::requestSession(
    ScriptState* script_state,
    const V8XRSessionMode& mode,
    XRSessionInit* session_init,
    ExceptionState& exception_state) {
  DVLOG(2) << __func__;
  // TODO(https://crbug.com/968622): Make sure we don't forget to call
  // metrics-related methods when the promise gets resolved/rejected.
  if (!DomWindow()) {
    // Reject if the window is inaccessible.
    DVLOG(1) << __func__ << ": DomWindow inaccessible";

    // Do *not* record an UKM event in this case (we won't be able to access the
    // Document to get UkmRecorder anyway).
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kNavigatorDetachedError);
    return EmptyPromise();  // Will be rejected by generated
                            // bindings
  }

  device::mojom::blink::XRSessionMode session_mode =
      V8EnumToSessionMode(mode.AsEnum());

  // If the request is for immersive-ar, ensure that feature is enabled.
  if (session_mode == device::mojom::blink::XRSessionMode::kImmersiveAr &&
      !IsImmersiveArAllowed()) {
    DVLOG(1) << __func__ << ": Immersive AR not allowed";
    exception_state.ThrowTypeError(
        String::Format(kImmersiveArModeNotValid, "requestSession"));

    // We haven't created the query yet, so we can't use it to implicitly log
    // our metrics for us, so explicitly log it here, as the query requires the
    // features to be parsed before it can be built.
    ukm::builders::XR_WebXR_SessionRequest(DomWindow()->UkmSourceID())
        .SetMode(static_cast<int64_t>(session_mode))
        .SetStatus(static_cast<int64_t>(SessionRequestStatus::kOtherError))
        .Record(DomWindow()->UkmRecorder());
    return EmptyPromise();
  }

  // Parse required feature strings
  RequestedXRSessionFeatureSet required_features;
  if (session_init && session_init->hasRequiredFeatures()) {
    required_features = ParseRequestedFeatures(
        session_init->requiredFeatures(), session_mode, session_init,
        mojom::blink::ConsoleMessageLevel::kError);
  }

  // Parse optional feature strings
  RequestedXRSessionFeatureSet optional_features;
  if (session_init && session_init->hasOptionalFeatures()) {
    optional_features = ParseRequestedFeatures(
        session_init->optionalFeatures(), session_mode, session_init,
        mojom::blink::ConsoleMessageLevel::kWarning);
  }

  // Certain session modes imply default features.
  // Add those default features as required features now.
  base::span<const device::mojom::XRSessionFeature> default_features;
  switch (session_mode) {
    case device::mojom::blink::XRSessionMode::kImmersiveVr:
      default_features = kDefaultImmersiveVrFeatures;
      break;
    case device::mojom::blink::XRSessionMode::kImmersiveAr:
      default_features = kDefaultImmersiveArFeatures;
      break;
    case device::mojom::blink::XRSessionMode::kInline:
      default_features = kDefaultInlineFeatures;
      break;
  }

  for (const auto& feature : default_features) {
    if (HasRequiredPermissionsPolicy(GetExecutionContext(), feature)) {
      required_features.valid_features.insert(feature);
    } else {
      DVLOG(2) << __func__
               << ": permissions policy not satisfied for a default feature: "
               << feature;
      AddConsoleMessage(mojom::blink::ConsoleMessageLevel::kError,
                        "Permissions policy is not satisfied for feature '" +
                            XRSessionFeatureToString(feature) +
                            "' please ensure that appropriate permissions "
                            "policy is enabled.");
      required_features.invalid_features = true;
    }
  }

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<XRSession>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  PendingRequestSessionQuery* query =
      MakeGarbageCollected<PendingRequestSessionQuery>(
          DomWindow()->UkmSourceID(), resolver, session_mode,
          std::move(required_features), std::move(optional_features));

  if (query->HasFeature(device::mojom::XRSessionFeature::DOM_OVERLAY)) {
    // Prerequisites were checked by IsFeatureValidForMode and IDL.
    DCHECK(session_init);
    DCHECK(session_init->hasDomOverlay());
    DCHECK(session_init->domOverlay()->hasRoot()) << "required in IDL";
    query->SetDOMOverlayElement(session_init->domOverlay()->root());
  }

  if (query->HasFeature(device::mojom::XRSessionFeature::IMAGE_TRACKING)) {
    // Prerequisites were checked by IsFeatureValidForMode.
    DCHECK(session_init);
    DCHECK(session_init->hasTrackedImages());
    DVLOG(3) << __func__ << ": set up trackedImages";
    Vector<device::mojom::blink::XRTrackedImage> images;
    int index = 0;
    for (auto& image : session_init->trackedImages()) {
      DCHECK(image->hasImage()) << "required in IDL";
      DCHECK(image->hasWidthInMeters()) << "required in IDL";
      if (std::isnan(image->widthInMeters()) ||
          image->widthInMeters() <= 0.0f) {
        String message = String::Format(kTrackedImageWidthInvalid, index);
        query->RejectWithTypeError(message, &exception_state);
        return promise;
      }
      // Extract an SkBitmap snapshot for each image.
      scoped_refptr<StaticBitmapImage> static_bitmap_image =
          image->image()->BitmapImage();
      SkBitmap sk_bitmap = static_bitmap_image->AsSkBitmapForCurrentFrame(
          kRespectImageOrientation);
      images.emplace_back(sk_bitmap, static_bitmap_image->Size(),
                          image->widthInMeters());
      ++index;
    }
    query->SetTrackedImages(images);
  }

  if (query->HasFeature(device::mojom::XRSessionFeature::DEPTH)) {
    // Prerequisites were checked by IsFeatureValidForMode and IDL.
    DCHECK(session_init);
    DCHECK(session_init->hasDepthSensing());
    DCHECK(session_init->depthSensing()->hasUsagePreference())
        << "required in IDL";
    DCHECK(session_init->depthSensing()->hasDataFormatPreference())
        << "required in IDL";

    Vector<device::mojom::XRDepthUsage> preferred_usage =
        ParseDepthUsages(session_init->depthSensing()->usagePreference());
    Vector<device::mojom::XRDepthDataFormat> preferred_format =
        ParseDepthFormats(session_init->depthSensing()->dataFormatPreference());

    query->SetDepthSensingConfiguration(preferred_usage, preferred_format);
  }

  // Defer to request the session until the prerendering page is activated.
  if (DomWindow()->document()->IsPrerendering()) {
    // Pass a nullptr instead of |exception_state| because we can't guarantee
    // this object is alive until the prerendering page is activate.
    DomWindow()->document()->AddPostPrerenderingActivationStep(WTF::BindOnce(
        &XRSystem::RequestSessionInternal, WrapWeakPersistent(this),
        session_mode, WrapPersistent(query), /*exception_state=*/nullptr));
    return promise;
  }

  RequestSessionInternal(session_mode, query, &exception_state);
  return promise;
}

void XRSystem::MakeXrCompatibleAsync(
    device::mojom::blink::VRService::MakeXrCompatibleCallback callback) {
  if (!GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kWebXr)) {
    std::move(callback).Run(
        device::mojom::XrCompatibleResult::kWebXrFeaturePolicyBlocked);
    return;
  }

  TryEnsureService();
  if (service_.is_bound()) {
    service_->MakeXrCompatible(std::move(callback));
  } else {
    std::move(callback).Run(
        device::mojom::XrCompatibleResult::kNoDeviceAvailable);
  }
}

void XRSystem::MakeXrCompatibleSync(
    device::mojom::XrCompatibleResult* xr_compatible_result) {
  if (!GetExecutionContext()->IsFeatureEnabled(
          mojom::blink::PermissionsPolicyFeature::kWebXr)) {
    *xr_compatible_result =
        device::mojom::XrCompatibleResult::kWebXrFeaturePolicyBlocked;
    return;
  }
  *xr_compatible_result = device::mojom::XrCompatibleResult::kNoDeviceAvailable;

  TryEnsureService();
  if (service_.is_bound())
    service_->MakeXrCompatible(xr_compatible_result);
}

void XRSystem::OnSessionEnded(XRSession* session) {
  if (session->immersive()) {
    webxr_internals_renderer_listener_.reset();
  }
}

// This will be called when the XR hardware or capabilities have potentially
// changed. For example, if a new physical device was connected to the system,
// it might be able to support immersive sessions, where it couldn't before.
void XRSystem::OnDeviceChanged() {
  ExecutionContext* context = GetExecutionContext();
  if (context && context->IsFeatureEnabled(
                     mojom::blink::PermissionsPolicyFeature::kWebXr)) {
    DispatchEvent(*blink::Event::Create(event_type_names::kDevicechange));
  }
}

void XRSystem::OnSupportsSessionReturned(PendingSupportsSessionQuery* query,
                                         bool supports_session) {
  // The session query has returned and we're about to resolve or reject the
  // promise, so remove it from our outstanding list.
  DCHECK(outstanding_support_queries_.Contains(query));
  outstanding_support_queries_.erase(query);
  query->Resolve(supports_session);
}

void XRSystem::OnRequestSessionReturned(
    PendingRequestSessionQuery* query,
    device::mojom::blink::RequestSessionResultPtr result) {
  // If session creation failed, move straight on to processing that.
  if (!result->is_success()) {
    FinishSessionCreation(query, std::move(result));
    return;
  }

  Element* fullscreen_element = nullptr;
  const auto& enabled_features =
      result->get_success()->session->enabled_features;
  if (base::Contains(enabled_features,
                     device::mojom::XRSessionFeature::DOM_OVERLAY)) {
    fullscreen_element = query->DOMOverlayElement();
  }

  // Only setup for dom_overlay if the query actually had a DOMOverlayElement
  // and the session enabled dom_overlay. (Note that fullscreen_element will be
  // null if the feature was not enabled).
  bool setup_for_dom_overlay = !!fullscreen_element;

// On Android, due to the way the device renderer is configured, we always need
// to enter fullscreen if we're starting an AR session, so if we aren't supposed
// to enter DOMOverlay, we simply fullscreen the document body.
#if BUILDFLAG(IS_ANDROID)
  if (!fullscreen_element &&
      query->mode() == device::mojom::blink::XRSessionMode::kImmersiveAr) {
    fullscreen_element = DomWindow()->document()->body();
  }
#endif

  // If we don't need to enter fullscreen continue with session setup.
  if (!fullscreen_element) {
    FinishSessionCreation(query, std::move(result));
    return;
  }

  const bool session_has_camera_access = base::Contains(
      enabled_features, device::mojom::XRSessionFeature::CAMERA_ACCESS);

  // At this point, we know that we have an element that we need to make
  // fullscreen, so we do that before we continue setting up the session.
  fullscreen_enter_observer_ =
      MakeGarbageCollected<XrEnterFullscreenObserver>();
  fullscreen_enter_observer_->RequestFullscreen(
      fullscreen_element, setup_for_dom_overlay, session_has_camera_access,
      WTF::BindOnce(&XRSystem::OnFullscreenConfigured, WrapPersistent(this),
                    WrapPersistent(query), std::move(result)));
}

void XRSystem::OnFullscreenConfigured(
    PendingRequestSessionQuery* query,
    device::mojom::blink::RequestSessionResultPtr result,
    bool fullscreen_succeeded) {
  // At this point we no longer need the enter observer, so go ahead and destroy
  // it.
  fullscreen_enter_observer_ = nullptr;

  if (fullscreen_succeeded) {
    FinishSessionCreation(query, std::move(result));
  } else {
    FinishSessionCreation(
        query, device::mojom::blink::RequestSessionResult::NewFailureReason(
                   device::mojom::RequestSessionError::FULLSCREEN_ERROR));
  }
}

void XRSystem::FinishSessionCreation(
    PendingRequestSessionQuery* query,
    device::mojom::blink::RequestSessionResultPtr result) {
  DVLOG(2) << __func__;
  // The session query has returned and we're about to resolve or reject the
  // promise, so remove it from our outstanding list.
  DCHECK(outstanding_request_queries_.Contains(query));
  outstanding_request_queries_.erase(query);
  if (query->mode() == device::mojom::blink::XRSessionMode::kImmersiveVr ||
      query->mode() == device::mojom::blink::XRSessionMode::kImmersiveAr) {
    DCHECK(has_outstanding_immersive_request_);
    has_outstanding_immersive_request_ = false;
  }

  if (!result->is_success()) {
    // |service_| does not support the requested mode. Attempt to create a
    // sensorless session.
    if (query->GetSensorRequirement() != SensorRequirement::kRequired) {
      DVLOG(2) << __func__ << ": session creation failed - creating sensorless";
      XRSession* session = CreateSensorlessInlineSession();
      query->Resolve(session);
      return;
    }

    String error_message =
        String::Format("Could not create a session because: %s",
                       GetConsoleMessage(result->get_failure_reason()));
    AddConsoleMessage(mojom::blink::ConsoleMessageLevel::kError, error_message);
    query->RejectWithDOMException(DOMExceptionCode::kNotSupportedError,
                                  kSessionNotSupported, nullptr);
    return;
  }

  auto session_ptr = std::move(result->get_success()->session);
  auto metrics_recorder = std::move(result->get_success()->metrics_recorder);

  XRSessionFeatureSet enabled_features;
  for (const auto& feature : session_ptr->enabled_features) {
    DVLOG(2) << __func__ << ": feature " << feature << " will be enabled";
    enabled_features.insert(feature);
  }

  XRSession* session = CreateSession(
      query->mode(), session_ptr->enviroment_blend_mode,
      session_ptr->interaction_mode, std::move(session_ptr->client_receiver),
      std::move(session_ptr->device_config), enabled_features,
      result->get_success()->trace_id);

  frameProvider()->OnSessionStarted(session, std::move(session_ptr));

  // The session is immersive, so we need to set up the WebXR Internals
  // listener.
  if (session->immersive() && result->get_success()->xr_internals_listener) {
    webxr_internals_renderer_listener_.Bind(
        std::move(std::move(result->get_success()->xr_internals_listener)),
        GetExecutionContext()->GetTaskRunner(TaskType::kInternalDefault));
  }

  if (query->mode() == device::mojom::blink::XRSessionMode::kImmersiveVr ||
      query->mode() == device::mojom::blink::XRSessionMode::kImmersiveAr) {
    const bool anchors_enabled = base::Contains(
        enabled_features, device::mojom::XRSessionFeature::ANCHORS);
    const bool hit_test_enabled = base::Contains(
        enabled_features, device::mojom::XRSessionFeature::HIT_TEST);
    const bool environment_integration = hit_test_enabled || anchors_enabled;
    if (environment_integration) {
      // See Task Sources spreadsheet for more information:
      // https://docs.google.com/spreadsheets/d/1b-dus1Ug3A8y0lX0blkmOjJILisUASdj8x9YN_XMwYc/view
      frameProvider()
          ->GetImmersiveDataProvider()
          ->GetEnvironmentIntegrationProvider(
              environment_provider_.BindNewEndpointAndPassReceiver(
                  GetExecutionContext()->GetTaskRunner(
                      TaskType::kMiscPlatformAPI)));
      environment_provider_.set_disconnect_handler(
          WTF::BindOnce(&XRSystem::OnEnvironmentProviderDisconnect,
                        WrapWeakPersistent(this)));

      session->OnEnvironmentProviderCreated();
    }

    auto dom_overlay_feature = device::mojom::XRSessionFeature::DOM_OVERLAY;
    if (query->mode() == device::mojom::blink::XRSessionMode::kImmersiveAr &&
        query->HasFeature(dom_overlay_feature) &&
        base::Contains(enabled_features, dom_overlay_feature)) {
      DCHECK(query->DOMOverlayElement());
      // The session is using DOM overlay mode. At this point the overlay
      // element is already in fullscreen mode, and the session can proceed.
      session->SetDOMOverlayElement(query->DOMOverlayElement());
    }
  }

  UseCounter::Count(ExecutionContext::From(query->GetScriptState()),
                    WebFeature::kWebXrSessionCreated);

  query->Resolve(session, std::move(metrics_recorder));
}

void XRSystem::AddedEventListener(
    const AtomicString& event_type,
    RegisteredEventListener& registered_listener) {
  EventTarget::AddedEventListener(event_type, registered_listener);

  // If we're adding an event listener we should spin up the service, if we can,
  // so that we can actually register for notifications.
  TryEnsureService();
  if (!service_.is_bound())
    return;

  if (event_type == event_type_names::kDevicechange) {
    // Register for notifications if we haven't already.
    //
    // See https://bit.ly/2S0zRAS for task types.
    auto task_runner =
        GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI);
    if 
"""


```