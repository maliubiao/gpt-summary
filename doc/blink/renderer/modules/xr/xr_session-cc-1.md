Response:
The user wants a summary of the provided C++ code snippet from `xr_session.cc`.
This is the second part of a three-part breakdown.
The code defines the `XRSession` class functionalities related to:
- Requesting and managing animation frames (`requestAnimationFrame`, `cancelAnimationFrame`).
- Getting input sources (`inputSources`).
- Requesting hit test sources (`requestHitTestSource`, `requestHitTestSourceForTransientInput`) and handling the results.
- Managing anchors (creating, updating).
- Handling environment provider errors.
- Processing anchor and hit test data received from the device.
- Requesting light probes (`requestLightProbe`).
- Ending the session (`end`, `ForceEnd`).
- Managing framebuffer and array texture sizes.
- Handling focus and visibility changes.
- Managing the frame request lifecycle (`MaybeRequestFrame`).
- Detaching the output canvas.
- Applying pending render state.

I need to summarize these functionalities and highlight any relationships with JavaScript, HTML, and CSS, provide examples for logical deductions, common user errors, and how a user might reach this code.
好的，这是对提供的 `blink/renderer/modules/xr/xr_session.cc` 源代码文件第二部分的归纳总结：

**主要功能归纳:**

这部分代码主要负责 `XRSession` 对象在以下方面的管理和操作：

1. **动画帧管理:**
    *   `requestAnimationFrame(ScriptState* script_state, FrameRequestCallback* callback)`:  注册一个回调函数，在浏览器准备好渲染新的动画帧时执行。这允许WebXR内容同步其渲染逻辑与浏览器的刷新率。
    *   `cancelAnimationFrame(int id)`: 取消之前通过 `requestAnimationFrame` 注册的回调。

2. **输入源管理:**
    *   `inputSources(ScriptState* script_state) const`: 返回当前可用的 XR 输入源数组，例如手柄、控制器等。

3. **命中测试管理:**
    *   `requestHitTestSource(ScriptState* script_state, XRHitTestOptionsInit* options_init, ExceptionState& exception_state)`: 请求一个持续的命中测试源。它允许应用程序在世界空间中指定一个射线，并获取与场景中几何体的交点信息。
    *   `requestHitTestSourceForTransientInput(ScriptState* script_state, XRTransientInputHitTestOptionsInit* options_init, ExceptionState& exception_state)`: 请求一个针对瞬态输入（例如手柄按钮按下）的命中测试源。
    *   `OnSubscribeToHitTestResult(ScriptPromiseResolver<XRHitTestSource>* resolver, device::mojom::SubscribeToHitTestResult result, uint64_t subscription_id)`:  处理持续命中测试源订阅的结果。
    *   `OnSubscribeToHitTestForTransientInputResult(ScriptPromiseResolver<XRTransientInputHitTestSource>* resolver, device::mojom::SubscribeToHitTestResult result, uint64_t subscription_id)`: 处理瞬态输入命中测试源订阅的结果。
    *   `CleanUpUnusedHitTestSources()`: 清理不再使用的命中测试源，并取消与设备的订阅。
    *   `ProcessHitTestData(const device::mojom::blink::XRHitTestSubscriptionResultsData* hit_test_subscriptions_data)`: 处理从设备接收到的命中测试结果数据，并更新相应的 `XRHitTestSource` 对象。

4. **锚点管理:**
    *   `OnCreateAnchorResult(ScriptPromiseResolver<XRAnchor>* resolver, device::mojom::CreateAnchorResult result, uint64_t id)`: 处理创建锚点的结果。
    *   `ProcessAnchorsData(const device::mojom::blink::XRAnchorsData* tracked_anchors_data, double timestamp)`: 处理从设备接收到的锚点数据更新。

5. **环境提供器错误处理:**
    *   `OnEnvironmentProviderCreated()`:  当环境提供器创建时执行，通常用于确保错误处理程序的安装。
    *   `EnsureEnvironmentErrorHandler()`: 确保订阅了环境提供器的错误处理回调。
    *   `OnEnvironmentProviderError()`: 当环境提供器发生错误时执行，负责拒绝所有相关的未完成的 Promise。

6. **灯光探针管理:**
    *   `requestLightProbe(ScriptState* script_state, XRLightProbeInit* light_probe_init, ExceptionState& exception_state)`: 请求一个灯光探针，用于获取场景的照明信息。

7. **会话生命周期管理:**
    *   `end(ScriptState* script_state, ExceptionState& exception_state)`:  启动会话结束流程。
    *   `ForceEnd(ShutdownPolicy shutdown_policy)`: 强制结束会话。
    *   `HandleShutdown()`:  处理会话的最终关闭逻辑，包括通知页面和清理资源。

8. **帧缓冲区和纹理尺寸管理:**
    *   `NativeFramebufferScale() const`:  返回原生帧缓冲区的缩放比例。
    *   `RecommendedFramebufferScale() const`: 返回推荐的帧缓冲区缩放比例。
    *   `RecommendedFramebufferSize() const`: 返回推荐的帧缓冲区尺寸。
    *   `RecommendedArrayTextureSize() const`: 返回推荐的数组纹理尺寸。
    *   `OutputCanvasSize() const`: 返回输出画布的尺寸。

9. **可见性和焦点管理:**
    *   `OnFocusChanged()`: 当窗口焦点改变时调用。
    *   `OnVisibilityStateChanged(XRVisibilityState visibility_state)`: 当设备报告的可见性状态改变时调用。
    *   `UpdateVisibilityState()`:  根据设备状态和焦点状态更新会话的可见性状态。

10. **帧请求管理:**
    *   `MaybeRequestFrame()`:  根据会话状态、页面可见性以及是否需要渲染新帧来决定是否请求新的动画帧。

11. **画布管理:**
    *   `DetachOutputCanvas(HTMLCanvasElement* canvas)`: 从会话中移除对指定画布的观察。
    *   `ApplyPendingRenderState()`: 应用待处理的渲染状态更新。

**与 JavaScript, HTML, CSS 的关系及举例:**

*   **JavaScript:**
    *   `requestAnimationFrame`:  JavaScript 代码调用此方法来注册动画回调。例如：
        ```javascript
        renderer.setAnimationLoop( function () {
            session.requestAnimationFrame(onXRFrame);
        } );

        function onXRFrame(time, frame) {
            // 更新 XR 场景
        }
        ```
    *   `cancelAnimationFrame`: JavaScript 代码调用此方法来取消动画回调。
        ```javascript
        let frameId = session.requestAnimationFrame(onXRFrame);
        session.cancelAnimationFrame(frameId);
        ```
    *   `inputSources`:  JavaScript 代码访问 `XRSession.inputSources` 属性来获取输入设备信息。
        ```javascript
        session.addEventListener('inputsourceschange', (event) => {
          console.log('Input sources changed:', session.inputSources);
        });
        ```
    *   `requestHitTestSource`, `requestHitTestSourceForTransientInput`: JavaScript 代码调用这些方法来启动命中测试。
        ```javascript
        session.requestHitTestSource({ space: viewerSpace }).then((hitTestSource) => {
          this.hitTestSource = hitTestSource;
        });
        ```
    *   `requestLightProbe`: JavaScript 代码调用此方法来请求灯光探针。
        ```javascript
        session.requestLightProbe().then((lightProbe) => {
          this.lightProbe = lightProbe;
        });
        ```
    *   `end`: JavaScript 代码调用此方法来结束 XR 会话。
        ```javascript
        session.end();
        ```
    *   `XRSessionEvent (event_type_names::kEnd, event_type_names::kVisibilitychange)`:  当会话结束或可见性改变时，会触发 JavaScript 事件，可以通过监听这些事件来处理会话状态的变化。
        ```javascript
        session.addEventListener('end', () => {
          console.log('XR session ended.');
        });

        session.addEventListener('visibilitychange', () => {
          console.log('XR session visibility changed:', session.visibilityState);
        });
        ```

*   **HTML:**
    *   `<canvas>` 元素通常作为 WebXR 内容的渲染目标。`DetachOutputCanvas` 和 `ApplyPendingRenderState`  涉及到对 HTMLCanvasElement 的操作。

*   **CSS:**
    *   这部分代码本身不直接涉及 CSS。然而，WebXR 内容的渲染结果可能会受到 CSS 的影响，例如 Canvas 元素的样式。

**逻辑推理的假设输入与输出示例:**

**假设输入:**

*   用户在支持 WebXR 的浏览器中打开一个包含 XR 内容的网页。
*   网页 JavaScript 代码调用 `navigator.xr.requestSession('immersive-vr')` 来请求一个沉浸式 VR 会话。
*   会话成功创建，并获取了 `XRSession` 对象 `session`。
*   JavaScript 代码调用 `session.requestAnimationFrame(onXRFrame)` 来开始渲染循环。
*   一段时间后，用户移开了头显（对于沉浸式会话），或者最小化了浏览器窗口（对于内联会话）。

**输出:**

*   `OnVisibilityStateChanged` 可能会被调用，参数 `visibility_state` 可能变为 `XRVisibilityState::HIDDEN`。
*   `UpdateVisibilityState` 会更新会话的内部可见性状态。
*   `MaybeRequestFrame`  会检查新的可见性状态，如果会话变为隐藏，则停止请求新的帧，暂停渲染循环。

**用户或编程常见的使用错误示例:**

*   **忘记取消 `requestAnimationFrame`:**  如果开发者在不需要动画更新时（例如会话结束时）忘记调用 `cancelAnimationFrame`，可能会导致不必要的资源消耗和潜在的性能问题。
*   **在会话结束后调用会话方法:**  例如，在 `end` 事件触发后尝试调用 `session.requestAnimationFrame()` 或其他方法，会导致 `DOMExceptionCode::kInvalidStateError` 异常。
*   **错误地处理命中测试结果:**  开发者可能错误地解析或使用 `XRHitResult` 对象中的变换信息，导致在场景中放置虚拟物体的位置不正确。
*   **未检查功能支持:**  在调用某些需要特定设备或浏览器支持的 WebXR 功能（例如命中测试、锚点）之前，开发者应该先检查相应的功能是否可用，否则会导致 `DOMExceptionCode::kNotSupportedError` 异常。

**用户操作到达这里的调试线索:**

1. **启动 XR 会话:** 用户通过某种方式触发了网页中的 JavaScript 代码，该代码调用 `navigator.xr.requestSession()` 并成功创建了一个 `XRSession` 对象。
2. **请求动画帧:** 网页代码调用 `session.requestAnimationFrame()` 来开始渲染循环，这意味着代码执行进入了 `XRSession::requestAnimationFrame` 函数。
3. **获取输入源:** 网页代码可能调用了 `session.inputSources` 来获取连接的 XR 输入设备的信息，从而执行到 `XRSession::inputSources`。
4. **执行命中测试:** 用户可能在 XR 场景中进行了某些操作（例如移动控制器并点击按钮），导致网页代码调用 `session.requestHitTestSource()` 或 `session.requestHitTestSourceForTransientInput()` 来进行命中测试。
5. **创建或更新锚点:**  如果 XR 应用支持锚点功能，用户可能会执行某些操作来创建新的锚点，或者现有的锚点数据被更新，导致代码执行到 `XRSession::OnCreateAnchorResult` 或 `XRSession::ProcessAnchorsData`。
6. **结束 XR 会话:** 用户可能通过页面上的按钮或浏览器的操作触发了会话的结束，导致 JavaScript 代码调用 `session.end()`，最终执行到 `XRSession::end` 和后续的关闭流程。
7. **窗口焦点或可见性变化:** 用户最小化浏览器窗口、切换标签页或者对于沉浸式会话移开头显，都会导致浏览器或设备报告可见性状态的改变，从而触发 `XRSession::OnVisibilityStateChanged` 和 `XRSession::UpdateVisibilityState`。

总之，这部分代码是 `XRSession` 类的核心功能实现，负责管理 XR 会话的生命周期、渲染循环、用户输入、空间定位以及与底层 XR 设备的通信。它连接了 JavaScript API 和底层的 XR 实现。

Prompt: 
```
这是目录为blink/renderer/modules/xr/xr_session.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
0;

  int id = callback_collection_->RegisterCallback(callback);
  MaybeRequestFrame();
  return id;
}

void XRSession::cancelAnimationFrame(int id) {
  callback_collection_->CancelCallback(id);
}

XRInputSourceArray* XRSession::inputSources(ScriptState* script_state) const {
  if (!did_log_getInputSources_ && script_state->ContextIsValid()) {
    ukm::builders::XR_WebXR(GetExecutionContext()->UkmSourceID())
        .SetDidGetXRInputSources(1)
        .Record(LocalDOMWindow::From(script_state)->UkmRecorder());
    did_log_getInputSources_ = true;
  }

  return input_sources_.Get();
}

ScriptPromise<XRHitTestSource> XRSession::requestHitTestSource(
    ScriptState* script_state,
    XRHitTestOptionsInit* options_init,
    ExceptionState& exception_state) {
  DVLOG(2) << __func__;
  DCHECK(options_init);

  if (!IsFeatureEnabled(device::mojom::XRSessionFeature::HIT_TEST)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        kFeatureNotSupportedBySessionPrefix +
            XRSessionFeatureToString(
                device::mojom::XRSessionFeature::HIT_TEST));
    return {};
  }

  if (ended_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSessionEnded);
    return {};
  }

  if (!xr_->xrEnvironmentProviderRemote()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        kFeatureNotSupportedByDevicePrefix +
            XRSessionFeatureToString(
                device::mojom::XRSessionFeature::HIT_TEST));
    return {};
  }

  // 1. Grab the native origin from the passed in XRSpace.
  device::mojom::blink::XRNativeOriginInformationPtr maybe_native_origin =
      options_init && options_init->hasSpace()
          ? options_init->space()->NativeOrigin()
          : nullptr;

  if (!maybe_native_origin) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kUnableToRetrieveNativeOrigin);
    return {};
  }

  // 2. Convert the XRRay to be expressed in terms of passed in XRSpace. This
  // should only matter for spaces whose transforms are not fully known on the
  // device (for example any space containing origin-offset).
  // Null checks not needed since native origin wouldn't be set if options_init
  // or space() were null.
  gfx::Transform native_from_offset =
      options_init->space()->NativeFromOffsetMatrix();

  if (RuntimeEnabledFeatures::WebXRHitTestEntityTypesEnabled() &&
      options_init->hasEntityTypes() && options_init->entityTypes().empty()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kEntityTypesNotSpecified);
    return {};
  }

  auto entity_types = GetEntityTypesForHitTest(options_init);

  DVLOG(3) << __func__
           << ": native_from_offset = " << native_from_offset.ToString();

  // Transformation from passed in pose to |space|.

  XRRay* offsetRay = options_init && options_init->hasOffsetRay()
                         ? options_init->offsetRay()
                         : MakeGarbageCollected<XRRay>();
  auto space_from_ray = offsetRay->RawMatrix();
  auto origin_from_ray = native_from_offset * space_from_ray;

  DVLOG(3) << __func__ << ": space_from_ray = " << space_from_ray.ToString();
  DVLOG(3) << __func__ << ": origin_from_ray = " << origin_from_ray.ToString();

  device::mojom::blink::XRRayPtr ray_mojo = device::mojom::blink::XRRay::New();

  ray_mojo->origin = origin_from_ray.MapPoint({0, 0, 0});

  // Zero out the translation of origin_from_ray matrix to correctly map a 3D
  // vector.
  gfx::Vector3dF translation = origin_from_ray.To3dTranslation();
  origin_from_ray.Translate3d(-translation.x(), -translation.y(),
                              -translation.z());

  ray_mojo->direction = origin_from_ray.MapPoint({0, 0, -1}).OffsetFromOrigin();

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<XRHitTestSource>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  xr_->xrEnvironmentProviderRemote()->SubscribeToHitTest(
      maybe_native_origin->Clone(), entity_types, std::move(ray_mojo),
      resolver->WrapCallbackInScriptScope(WTF::BindOnce(
          &XRSession::OnSubscribeToHitTestResult, WrapPersistent(this))));
  request_hit_test_source_promises_.insert(resolver);

  return promise;
}

ScriptPromise<XRTransientInputHitTestSource>
XRSession::requestHitTestSourceForTransientInput(
    ScriptState* script_state,
    XRTransientInputHitTestOptionsInit* options_init,
    ExceptionState& exception_state) {
  DVLOG(2) << __func__;
  DCHECK(options_init);

  if (!IsFeatureEnabled(device::mojom::XRSessionFeature::HIT_TEST)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        kFeatureNotSupportedBySessionPrefix +
            XRSessionFeatureToString(
                device::mojom::XRSessionFeature::HIT_TEST));
    return {};
  }

  if (ended_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSessionEnded);
    return {};
  }

  if (!xr_->xrEnvironmentProviderRemote()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        kFeatureNotSupportedByDevicePrefix +
            XRSessionFeatureToString(
                device::mojom::XRSessionFeature::HIT_TEST));
    return {};
  }

  if (RuntimeEnabledFeatures::WebXRHitTestEntityTypesEnabled() &&
      options_init->hasEntityTypes() && options_init->entityTypes().empty()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kEntityTypesNotSpecified);
    return {};
  }

  auto entity_types = GetEntityTypesForHitTest(options_init);

  XRRay* offsetRay = options_init && options_init->hasOffsetRay()
                         ? options_init->offsetRay()
                         : MakeGarbageCollected<XRRay>();

  device::mojom::blink::XRRayPtr ray_mojo = device::mojom::blink::XRRay::New();
  ray_mojo->origin = {static_cast<float>(offsetRay->origin()->x()),
                      static_cast<float>(offsetRay->origin()->y()),
                      static_cast<float>(offsetRay->origin()->z())};
  ray_mojo->direction = {static_cast<float>(offsetRay->direction()->x()),
                         static_cast<float>(offsetRay->direction()->y()),
                         static_cast<float>(offsetRay->direction()->z())};

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<XRTransientInputHitTestSource>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  xr_->xrEnvironmentProviderRemote()->SubscribeToHitTestForTransientInput(
      options_init->profile(), entity_types, std::move(ray_mojo),
      resolver->WrapCallbackInScriptScope(
          WTF::BindOnce(&XRSession::OnSubscribeToHitTestForTransientInputResult,
                        WrapPersistent(this))));
  request_hit_test_source_promises_.insert(resolver);

  return promise;
}

void XRSession::OnSubscribeToHitTestResult(
    ScriptPromiseResolver<XRHitTestSource>* resolver,
    device::mojom::SubscribeToHitTestResult result,
    uint64_t subscription_id) {
  DVLOG(2) << __func__ << ": result=" << result
           << ", subscription_id=" << subscription_id;

  DCHECK(request_hit_test_source_promises_.Contains(resolver));
  request_hit_test_source_promises_.erase(resolver);

  if (result != device::mojom::SubscribeToHitTestResult::SUCCESS) {
    resolver->RejectWithDOMException(DOMExceptionCode::kOperationError,
                                     kHitTestSubscriptionFailed);
    return;
  }

  XRHitTestSource* hit_test_source =
      MakeGarbageCollected<XRHitTestSource>(subscription_id, this);

  hit_test_source_ids_to_hit_test_sources_.insert(subscription_id,
                                                  hit_test_source);
  hit_test_source_ids_.insert(subscription_id);

  resolver->Resolve(hit_test_source);
}

void XRSession::OnSubscribeToHitTestForTransientInputResult(
    ScriptPromiseResolver<XRTransientInputHitTestSource>* resolver,
    device::mojom::SubscribeToHitTestResult result,
    uint64_t subscription_id) {
  DVLOG(2) << __func__ << ": result=" << result
           << ", subscription_id=" << subscription_id;

  DCHECK(request_hit_test_source_promises_.Contains(resolver));
  request_hit_test_source_promises_.erase(resolver);

  if (result != device::mojom::SubscribeToHitTestResult::SUCCESS) {
    resolver->RejectWithDOMException(DOMExceptionCode::kOperationError,
                                     kHitTestSubscriptionFailed);
    return;
  }

  XRTransientInputHitTestSource* hit_test_source =
      MakeGarbageCollected<XRTransientInputHitTestSource>(subscription_id,
                                                          this);

  hit_test_source_ids_to_transient_input_hit_test_sources_.insert(
      subscription_id, hit_test_source);
  hit_test_source_for_transient_input_ids_.insert(subscription_id);

  resolver->Resolve(hit_test_source);
}

void XRSession::OnCreateAnchorResult(ScriptPromiseResolver<XRAnchor>* resolver,
                                     device::mojom::CreateAnchorResult result,
                                     uint64_t id) {
  DVLOG(2) << __func__ << ": result=" << result << ", id=" << id;

  DCHECK(create_anchor_promises_.Contains(resolver));
  create_anchor_promises_.erase(resolver);

  if (result == device::mojom::CreateAnchorResult::SUCCESS) {
    // Anchor was created successfully on the device. Subsequent frame update
    // must contain newly created anchor data.
    anchor_ids_to_pending_anchor_promises_.insert(id, resolver);
  } else {
    resolver->RejectWithDOMException(DOMExceptionCode::kOperationError,
                                     kAnchorCreationFailed);
  }
}

void XRSession::OnEnvironmentProviderCreated() {
  EnsureEnvironmentErrorHandler();
}

void XRSession::EnsureEnvironmentErrorHandler() {
  // Install error handler on environment provider to ensure that we get
  // notified so that we can clean up all relevant pending promises.
  if (!environment_error_handler_subscribed_ &&
      xr_->xrEnvironmentProviderRemote()) {
    environment_error_handler_subscribed_ = true;
    xr_->AddEnvironmentProviderErrorHandler(WTF::BindOnce(
        &XRSession::OnEnvironmentProviderError, WrapWeakPersistent(this)));
  }
}

void XRSession::OnEnvironmentProviderError() {
  HeapHashSet<Member<ScriptPromiseResolverBase>> create_anchor_promises;
  create_anchor_promises_.swap(create_anchor_promises);
  for (ScriptPromiseResolverBase* resolver : create_anchor_promises) {
    ScriptState* resolver_script_state = resolver->GetScriptState();
    if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                       resolver_script_state)) {
      continue;
    }
    ScriptState::Scope script_state_scope(resolver_script_state);
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     kDeviceDisconnected);
  }

  HeapHashSet<Member<ScriptPromiseResolverBase>>
      request_hit_test_source_promises;
  request_hit_test_source_promises_.swap(request_hit_test_source_promises);
  for (ScriptPromiseResolverBase* resolver : request_hit_test_source_promises) {
    ScriptState* resolver_script_state = resolver->GetScriptState();
    if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                       resolver_script_state)) {
      continue;
    }
    ScriptState::Scope script_state_scope(resolver_script_state);
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     kDeviceDisconnected);
  }

  HeapVector<Member<ImageScoreResolverType>> image_score_promises;
  image_scores_resolvers_.swap(image_score_promises);
  for (auto& resolver : image_score_promises) {
    ScriptState* resolver_script_state = resolver->GetScriptState();
    if (!IsInParallelAlgorithmRunnable(resolver->GetExecutionContext(),
                                       resolver_script_state)) {
      continue;
    }
    ScriptState::Scope script_state_scope(resolver_script_state);
    resolver->RejectWithDOMException(DOMExceptionCode::kInvalidStateError,
                                     kDeviceDisconnected);
  }
}

void XRSession::ProcessAnchorsData(
    const device::mojom::blink::XRAnchorsData* tracked_anchors_data,
    double timestamp) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("xr.debug"), __func__);

  if (!tracked_anchors_data) {
    DVLOG(3) << __func__ << ": tracked_anchors_data is null";

    // We have received a nullptr. Clear stored anchors.
    // The device can send either null or empty data - in both cases, it means
    // that there are no anchors available.
    anchor_ids_to_anchors_.clear();
    return;
  }

  TRACE_COUNTER2("xr", "Anchor statistics", "All anchors",
                 tracked_anchors_data->all_anchors_ids.size(),
                 "Updated anchors",
                 tracked_anchors_data->updated_anchors_data.size());

  DVLOG(3) << __func__ << ": updated anchors size="
           << tracked_anchors_data->updated_anchors_data.size()
           << ", all anchors size="
           << tracked_anchors_data->all_anchors_ids.size();

  HeapHashMap<uint64_t, Member<XRAnchor>> updated_anchors;

  // First, process all anchors that had their information updated (new anchors
  // are also processed here).
  for (const auto& anchor : tracked_anchors_data->updated_anchors_data) {
    DCHECK(anchor);

    auto it = anchor_ids_to_anchors_.find(anchor->id);
    if (it != anchor_ids_to_anchors_.end()) {
      updated_anchors.insert(anchor->id, it->value);
      it->value->Update(*anchor);
    } else {
      DVLOG(3) << __func__ << ": processing newly created anchor, anchor->id="
               << anchor->id;

      auto resolver_it =
          anchor_ids_to_pending_anchor_promises_.find(anchor->id);
      if (resolver_it == anchor_ids_to_pending_anchor_promises_.end()) {
        DCHECK(false)
            << "Newly created anchor must have a corresponding resolver!";
        continue;
      }

      XRAnchor* xr_anchor =
          MakeGarbageCollected<XRAnchor>(anchor->id, this, *anchor);
      resolver_it->value->DowncastTo<XRAnchor>()->Resolve(xr_anchor);
      anchor_ids_to_pending_anchor_promises_.erase(resolver_it);

      updated_anchors.insert(anchor->id, xr_anchor);
    }
  }

  // Then, copy over the anchors that were not updated but are still present.
  for (const auto& anchor_id : tracked_anchors_data->all_anchors_ids) {
    auto it_updated = updated_anchors.find(anchor_id);

    // If the anchor was already updated, there is nothing to do as it was
    // already moved to |updated_anchors|. Otherwise just copy it over as-is.
    if (it_updated == updated_anchors.end()) {
      auto it = anchor_ids_to_anchors_.find(anchor_id);
      CHECK(it != anchor_ids_to_anchors_.end(), base::NotFatalUntil::M130);
      updated_anchors.insert(anchor_id, it->value);
    }
  }

  DVLOG(3) << __func__
           << ": anchor count before update=" << anchor_ids_to_anchors_.size()
           << ", after update=" << updated_anchors.size();

  anchor_ids_to_anchors_.swap(updated_anchors);

  DCHECK(anchor_ids_to_pending_anchor_promises_.empty())
      << "All anchors should be updated in the frame in which they were "
         "created, got "
      << anchor_ids_to_pending_anchor_promises_.size()
      << " anchors that have not been updated";
}

XRPlaneSet* XRSession::GetDetectedPlanes() const {
  return plane_manager_->GetDetectedPlanes();
}

void XRSession::CleanUpUnusedHitTestSources() {
  auto unused_hit_test_source_ids = GetIdsOfUnusedHitTestSources(
      hit_test_source_ids_to_hit_test_sources_, hit_test_source_ids_);
  for (auto id : unused_hit_test_source_ids) {
    xr_->xrEnvironmentProviderRemote()->UnsubscribeFromHitTest(id);
  }

  hit_test_source_ids_.RemoveAll(unused_hit_test_source_ids);

  auto unused_transient_hit_source_ids = GetIdsOfUnusedHitTestSources(
      hit_test_source_ids_to_transient_input_hit_test_sources_,
      hit_test_source_for_transient_input_ids_);
  for (auto id : unused_transient_hit_source_ids) {
    xr_->xrEnvironmentProviderRemote()->UnsubscribeFromHitTest(id);
  }

  hit_test_source_for_transient_input_ids_.RemoveAll(
      unused_transient_hit_source_ids);

  DCHECK_HIT_TEST_SOURCES();

  DVLOG(3) << __func__ << ": Number of active hit test sources: "
           << hit_test_source_ids_.size()
           << ", number of active hit test sources for transient input: "
           << hit_test_source_for_transient_input_ids_.size();
}

void XRSession::ProcessHitTestData(
    const device::mojom::blink::XRHitTestSubscriptionResultsData*
        hit_test_subscriptions_data) {
  DVLOG(2) << __func__;

  // Application's code can just drop references to hit test sources w/o first
  // canceling them - ensure that we communicate that the subscriptions are no
  // longer present to the device.
  CleanUpUnusedHitTestSources();

  if (hit_test_subscriptions_data) {
    // We have received hit test results for hit test subscriptions - process
    // each result and notify its corresponding hit test source about new
    // results for the current frame.
    DVLOG(3) << __func__ << ": hit_test_subscriptions_data->results.size()="
             << hit_test_subscriptions_data->results.size() << ", "
             << "hit_test_subscriptions_data->transient_input_results.size()="
             << hit_test_subscriptions_data->transient_input_results.size();

    for (auto& hit_test_subscription_data :
         hit_test_subscriptions_data->results) {
      auto it = hit_test_source_ids_to_hit_test_sources_.find(
          hit_test_subscription_data->subscription_id);
      if (it != hit_test_source_ids_to_hit_test_sources_.end()) {
        it->value->Update(hit_test_subscription_data->hit_test_results);
      }
    }

    for (auto& transient_input_hit_test_subscription_data :
         hit_test_subscriptions_data->transient_input_results) {
      auto it = hit_test_source_ids_to_transient_input_hit_test_sources_.find(
          transient_input_hit_test_subscription_data->subscription_id);
      if (it !=
          hit_test_source_ids_to_transient_input_hit_test_sources_.end()) {
        it->value->Update(transient_input_hit_test_subscription_data
                              ->input_source_id_to_hit_test_results,
                          input_sources_);
      }
    }
  } else {
    DVLOG(3) << __func__ << ": hit_test_subscriptions_data unavailable";

    // We have not received hit test results for any of the hit test
    // subscriptions in the current frame - clean up the results on all hit test
    // source objects.
    for (auto& subscription_id_and_hit_test_source :
         hit_test_source_ids_to_hit_test_sources_) {
      subscription_id_and_hit_test_source.value->Update({});
    }

    for (auto& subscription_id_and_transient_input_hit_test_source :
         hit_test_source_ids_to_transient_input_hit_test_sources_) {
      subscription_id_and_transient_input_hit_test_source.value->Update(
          {}, nullptr);
    }
  }
}

ScriptPromise<XRLightProbe> XRSession::requestLightProbe(
    ScriptState* script_state,
    XRLightProbeInit* light_probe_init,
    ExceptionState& exception_state) {
  if (ended_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSessionEnded);
    return EmptyPromise();
  }

  if (!IsFeatureEnabled(device::mojom::XRSessionFeature::LIGHT_ESTIMATION)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        kFeatureNotSupportedBySessionPrefix +
            XRSessionFeatureToString(
                device::mojom::XRSessionFeature::LIGHT_ESTIMATION));
    return EmptyPromise();
  }

  if (light_probe_init->reflectionFormat() != "srgba8" &&
      light_probe_init->reflectionFormat() != "rgba16f") {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        "Reflection format \"" +
            IDLEnumAsString(light_probe_init->reflectionFormat()) +
            "\" not supported.");
    return EmptyPromise();
  }

  if (!world_light_probe_) {
    // TODO(https://crbug.com/1147569): This is problematic because it means the
    // first reflection format that gets requested is the only one that can be
    // returned.
    world_light_probe_ =
        MakeGarbageCollected<XRLightProbe>(this, light_probe_init);
  }
  return ToResolvedPromise<XRLightProbe>(script_state, world_light_probe_);
}

ScriptPromise<IDLUndefined> XRSession::end(ScriptState* script_state,
                                           ExceptionState& exception_state) {
  DVLOG(2) << __func__;
  // Don't allow a session to end twice.
  if (ended_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSessionEnded);
    return EmptyPromise();
  }

  ForceEnd(ShutdownPolicy::kWaitForResponse);

  end_session_resolver_ =
      MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
          script_state, exception_state.GetContext());
  auto promise = end_session_resolver_->Promise();

  DVLOG(1) << __func__ << ": returning promise";
  return promise;
}

void XRSession::ForceEnd(ShutdownPolicy shutdown_policy) {
  bool wait_for_response;
  switch (shutdown_policy) {
    case ShutdownPolicy::kWaitForResponse:
      wait_for_response = true;
      break;
    case ShutdownPolicy::kImmediate:
      wait_for_response = false;
      break;
  }

  DVLOG(3) << __func__ << ": wait_for_response=" << wait_for_response
           << " ended_=" << ended_
           << " waiting_for_shutdown_=" << waiting_for_shutdown_;

  // If we've already ended, then just abort.  Since this is called only by C++
  // code, and predominantly just to ensure that the session is shut down, this
  // is fine.
  if (ended_) {
    // If we're currently waiting for an OnExitPresent, but are told not
    // to expect that anymore (i.e. due to a connection error), proceed
    // to full shutdown now.
    if (!wait_for_response && waiting_for_shutdown_) {
      HandleShutdown();
    }
    return;
  }

  // Detach this session from the XR system.
  ended_ = true;
  pending_frame_ = false;

  for (unsigned i = 0; i < input_sources_->length(); i++) {
    auto* input_source = (*input_sources_)[i];
    input_source->OnRemoved();
  }

  input_sources_ = nullptr;

  if (canvas_input_provider_) {
    canvas_input_provider_->Stop();
    canvas_input_provider_ = nullptr;
  }

  xr_->ExitPresent(
      WTF::BindOnce(&XRSession::OnExitPresent, WrapWeakPersistent(this)));

  if (wait_for_response) {
    waiting_for_shutdown_ = true;
  } else {
    HandleShutdown();
  }
}

void XRSession::HandleShutdown() {
  DVLOG(2) << __func__;
  DCHECK(ended_);
  waiting_for_shutdown_ = false;

  if (xr_->IsContextDestroyed()) {
    // If this is being called due to the context being destroyed,
    // it's illegal to run JavaScript code, so we cannot emit an
    // end event or resolve the stored promise. Don't bother calling
    // the frame provider's OnSessionEnded, that's being disposed of
    // also.
    DVLOG(3) << __func__ << ": Context destroyed";
    if (end_session_resolver_) {
      end_session_resolver_->Detach();
      end_session_resolver_ = nullptr;
    }
    return;
  }

  // Notify the frame provider that we've ended. Do this before notifying the
  // page, so that if the page tries (and is able to) create a session within
  // either the promise or the event callback, it's not blocked by the frame
  // provider thinking there's still an active immersive session.
  xr_->frameProvider()->OnSessionEnded(this);
  xr_->OnSessionEnded(this);

  if (end_session_resolver_) {
    DVLOG(3) << __func__ << ": Resolving end_session_resolver_";
    end_session_resolver_->Resolve();
    end_session_resolver_ = nullptr;
  }

  DispatchEvent(*XRSessionEvent::Create(event_type_names::kEnd, this));
  DVLOG(3) << __func__ << ": session end event dispatched";

  // Now that we've notified the page that we've ended, try to restart the non-
  // immersive frame loop. Note that if the page was able to request a new
  // session in the end event, this may be a no-op.
  xr_->frameProvider()->RestartNonImmersiveFrameLoop();
}

double XRSession::NativeFramebufferScale() const {
  if (immersive()) {
    DCHECK(RecommendedFramebufferScale());

    // Return the inverse of the recommended scale, since that's what we'll need
    // to multiply the recommended size by to get back to the native size.
    return 1.0 / RecommendedFramebufferScale();
  }
  return 1.0;
}

double XRSession::RecommendedFramebufferScale() const {
  // Clamp to a reasonable min/max size for the default framebuffer scale.
  return std::clamp(device_config_->default_framebuffer_scale,
                    kMinDefaultFramebufferScale, kMaxDefaultFramebufferScale);
}

gfx::SizeF XRSession::RecommendedFramebufferSize() const {
  if (!immersive()) {
    return gfx::SizeF(OutputCanvasSize());
  }

  float scale = RecommendedFramebufferScale();
  float width = 0;
  float height = 0;

  // For the moment, concatenate all the views into a big strip.
  // Won't scale well for displays that use more than a stereo pair.
  for (const auto& view : views_) {
    const auto& viewport = view->Viewport();
    width += viewport.width();
    height = std::max<float>(height, viewport.height());
  }

  return gfx::SizeF(width * scale, height * scale);
}

gfx::SizeF XRSession::RecommendedArrayTextureSize() const {
  float scale = RecommendedFramebufferScale();
  float width = 0;
  float height = 0;

  // When using array textures the texture size should be determined by the
  // maximum size required for any viewport.
  for (const auto& view : views_) {
    const auto& viewport = view->Viewport();
    width = std::max<float>(width, viewport.width());
    height = std::max<float>(height, viewport.height());
  }

  return gfx::SizeF(width * scale, height * scale);
}

gfx::Size XRSession::OutputCanvasSize() const {
  if (!render_state_->output_canvas()) {
    return gfx::Size();
  }

  return gfx::Size(output_width_, output_height_);
}

void XRSession::OnFocusChanged() {
  UpdateVisibilityState();
}

void XRSession::OnVisibilityStateChanged(XRVisibilityState visibility_state) {
  // TODO(crbug.com/1002742): Until some ambiguities in the spec are cleared up,
  // force "visible-blurred" states from the device to report as "hidden"
  if (visibility_state == XRVisibilityState::VISIBLE_BLURRED) {
    visibility_state = XRVisibilityState::HIDDEN;
  }

  if (device_visibility_state_ != visibility_state) {
    device_visibility_state_ = visibility_state;
    UpdateVisibilityState();
  }
}

// The ultimate visibility state of the session is a combination of the devices
// reported visibility state and, for inline sessions, the frame focus, which
// will override the device visibility to "hidden" if the frame is not currently
// focused.
void XRSession::UpdateVisibilityState() {
  // Don't need to track the visibility state if the session has ended.
  if (ended_) {
    return;
  }

  XRVisibilityState state = device_visibility_state_;

  // The WebXR spec requires that if our document is not focused, that we don't
  // hand out real poses. For immersive sessions, we have to rely on the device
  // to tell us it's visibility state, as some runtimes (WMR) put focus in the
  // headset, and thus we cannot rely on Document Focus state. This is fine
  // because while the runtime reports us as focused the content owned by the
  // session should be focued, which is owned by the document. For inline, we
  // can and must rely on frame focus.
  if (!immersive() && !xr_->IsFrameFocused()) {
    state = XRVisibilityState::HIDDEN;
  }

  if (visibility_state_ != state) {
    visibility_state_ = state;

    // If the visibility state was changed to something other than hidden, we
    // may be able to restart the frame loop.
    MaybeRequestFrame();

    DispatchEvent(
        *XRSessionEvent::Create(event_type_names::kVisibilitychange, this));
  }
}

void XRSession::MaybeRequestFrame() {
  bool will_have_base_layer = !!render_state_->GetFirstLayer();
  for (const auto& init : pending_render_state_) {
    if (init->hasBaseLayer()) {
      will_have_base_layer = !!init->baseLayer();
    } else if (init->hasLayers()) {
      will_have_base_layer = init->layers()->size() > 0;
    }
  }

  // A page will not be allowed to get frames if its visibility state is hidden.
  bool page_allowed_frames = visibility_state_ != XRVisibilityState::HIDDEN;

  // A page is configured properly if it will have a base layer when the frame
  // callback gets resolved.
  bool page_configured_properly = will_have_base_layer;

  // If we have an outstanding callback registered, then we know that the page
  // actually wants frames.
  bool page_wants_frame =
      !callback_collection_->IsEmpty() || !vfc_execution_queue_.empty();

  // A page can process frames if it has its appropriate base layer set and has
  // indicated that it actually wants frames.
  bool page_can_process_frames = page_configured_properly && page_wants_frame;

  // We consider frames to be throttled if the page is not allowed frames, but
  // otherwise would be able to receive them. Therefore, if the page isn't in a
  // state to process frames, it doesn't matter if we are throttling it, any
  // "stalls" should be attributed to the page being poorly behaved.
  bool frames_throttled = page_can_process_frames && !page_allowed_frames;

  // If our throttled state has changed, notify anyone who may care
  if (frames_throttled_ != frames_throttled) {
    frames_throttled_ = frames_throttled;
    xr_->SetFramesThrottled(this, frames_throttled_);
  }

  // We can request a frame if we don't have one already pending, the page is
  // allowed to request frames, and the page is set up to properly handle frames
  // and wants one.
  bool request_frame =
      !pending_frame_ && page_allowed_frames && page_can_process_frames;
  if (request_frame) {
    xr_->frameProvider()->RequestFrame(this);
    pending_frame_ = true;
  } else {
    std::stringstream ss;
    ss << __func__
       << ": Not requesting frame, pending_frame_=" << pending_frame_
       << ", page_allowed_frames= " << page_allowed_frames
       << ", page_can_process_frames=" << page_can_process_frames
       << ", page_configured_properly=" << page_configured_properly
       << ", page_wants_frame=" << page_wants_frame
       << ", frames_throttled=" << frames_throttled_;
    xr_->AddWebXrInternalsMessage(ss.str().c_str());
  }
}

void XRSession::DetachOutputCanvas(HTMLCanvasElement* canvas) {
  if (!canvas)
    return;

  // Remove anything in this session observing the given output canvas.
  if (resize_observer_) {
    resize_observer_->unobserve(canvas);
  }

  if (canvas_input_provider_ && canvas_input_provider_->canvas() == canvas) {
    canvas_input_provider_->Stop();
    canvas_input_provider_ = nullptr;
  }
}

void XRSession::ApplyPendingRenderState() {
  DCHECK(!prev_base_layer_);
  if (pending_render_state_.size() > 0) {
    prev_base_layer_ = render_state_->GetFirstLayer();
    HTMLCanvasElement* prev_ouput_canvas = render_state_->output_canvas();

    // Loop through each pending render state and apply it to the active one.
    for (auto& init : pending_render_state_) {
      render_state_->Update(init);
    }
    pending_render_state_.clear();

    // If this is an inline session and the base layer has changed, give it an
    // opportunity to update it's drawing buffer size.
    XRLayer* base_layer = render_state_->GetFirstLayer();
    if (!immersive() && base_layer && base_layer != prev_base_layer_) {
      base_layer->OnResize();
    }

    // If the output canvas changed, remove listeners from the old one and add
    // listeners to the new one as appropriate.
    if (prev_ouput_canvas != render_state_->output_canvas()) {
      // Remove anything observing the previous canvas.
      if (prev_ouput_canvas) {
        DetachOutputCanvas(prev_ouput_canvas);
      }

      // Monitor the new canvas for resize/input events.
      HTMLCanvasElement* canvas = render_state_->output_canvas();
      if (canvas) {
        if (!resize_observer_) {
          resize_observer_ = ResizeObserver::Create(
              canvas->GetDocument().domWindow(),
              MakeGarbageCollected<XRSessionResizeObserverDelegate>(this));
        }
        resize_observer_->observe
"""


```