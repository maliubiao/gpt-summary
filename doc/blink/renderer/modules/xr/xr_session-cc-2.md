Response:
The user is asking for a summary of the functionality of the `XRSession.cc` file, particularly focusing on its interactions with JavaScript, HTML, and CSS, any logical deductions with examples, common user or programming errors, how a user's action leads to this code, and finally, a general summary of the file's purpose. This is the third part of a three-part request, so I should focus on summarizing the overall functionality, assuming the previous parts covered more specific details.

**Plan:**

1. **Summarize Core Functionality:** Based on the provided code, identify the primary responsibilities of `XRSession`.
2. **Relate to Web Technologies (JS, HTML, CSS):**  Connect the identified functionalities to how they interact with web content.
3. **Infer Logical Reasoning (with Examples):** Look for conditional logic and explain its purpose with hypothetical scenarios.
4. **Identify Potential Errors (with Examples):**  Analyze the code for error handling and common mistakes.
5. **Explain User Journey:** Describe the steps a user takes that would eventually involve this code.
6. **Provide a Concise Summary:**  Offer a brief overview of the file's role.
好的，根据提供的代码片段，我们可以归纳一下 `blink/renderer/modules/xr/xr_session.cc` 文件的功能：

**核心功能归纳:**

`XRSession` 类是 WebXR API 中 `XRSession` 接口在 Blink 渲染引擎中的实现。它的主要职责是管理和维护一个 WebXR 会话的生命周期和状态，并负责与底层设备进行通信，将设备的 XR 数据（如头部姿态、手柄输入、环境理解等）传递给 Web 内容，并将 Web 内容的渲染请求传递给设备。

更具体地说，从这段代码来看，`XRSession` 负责以下功能：

* **处理帧数据更新:** `UpdatePresentationFrameState` 方法接收来自底层设备的帧数据，包括时间戳、姿态信息、输入状态、环境理解数据等，并更新 `XRSession` 内部的状态，例如视图 (`views_`)、输入源 (`input_sources_`) 和环境理解数据（平面、锚点、图像跟踪等）。
* **管理图像跟踪:** `getTrackedImageScores` 和 `ProcessTrackedImagesData` 方法实现了图像跟踪功能，允许 Web 内容请求已跟踪图像的质量评分，并接收来自设备的图像跟踪结果。
* **更新世界理解状态:** `UpdateWorldUnderstandingStateForFrame` 方法处理来自设备的各种环境理解数据，例如平面信息、锚点数据、命中测试结果和光照估计数据。
* **处理帧渲染:** `OnFrame` 方法在每一帧开始时被调用，负责管理渲染过程。它会执行 `requestAnimationFrame` 回调，触发 WebGL 渲染，并将渲染结果提交给底层设备。
* **处理会话生命周期事件:** 代码片段中虽然没有直接展示会话开始和结束的逻辑，但可以推断 `XRSession` 负责处理会话的启动、暂停、恢复和结束。`OnExitPresent` 方法处理了从沉浸式会话退出的情况。
* **管理输入事件:** `OnInputStateChangeInternal` 和 `ProcessInputSourceEvents` 方法处理来自 XR 输入设备（例如手柄）的输入事件，更新输入源的状态，并触发 `inputsourceschange` 事件。
* **处理空间重置:** `OnMojoSpaceReset` 方法处理底层设备触发的空间重置事件，通知相关的参考空间。
* **管理命中测试源:**  `ValidateHitTestSourceExists` 和 `RemoveHitTestSource` 方法用于管理命中测试源的生命周期。
* **提供视图信息:** `views()` 和 `ViewDataForEye` 方法返回当前会话的视图信息，包括投影矩阵和视口。
* **管理参考空间:** 代码中可以看到对 `reference_spaces_` 的操作，表明 `XRSession` 管理着会话中可用的参考空间。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** `XRSession` 是 JavaScript 中 `navigator.xr.requestSession()` 返回的对象，JavaScript 代码可以通过 `XRSession` 接口调用其方法，例如 `requestAnimationFrame()`, `getViewerPose()`, `requestReferenceSpace()`, `requestHitTestSource()`, `getTrackedImageScores()` 等。`OnFrame` 方法中执行的 `ExecuteVideoFrameCallbacks` 和 `callback_collection_->ExecuteCallbacks` 就是执行 JavaScript 中通过 `requestAnimationFrame()` 注册的回调函数。
* **HTML:**
    * **`<canvas>` 元素:**  `XRSession` 可能会关联一个 HTML `<canvas>` 元素用于渲染。代码中的 `UpdateCanvasDimensions` 方法在 canvas 元素大小改变时被调用。对于内联会话，渲染通常发生在 canvas 上。
    * **DOM Overlay:**  代码中涉及到 `overlay_element_` 和 DOM Overlay 的处理。这表明 `XRSession` 需要与 HTML 元素进行交互，以便在 XR 场景中叠加 2D HTML 内容。`OnInputStateChangeInternal` 中会根据输入事件是否与 DOM Overlay 元素重叠来决定是否隐藏输入源。
* **CSS:** CSS 本身并不直接与 `XRSession.cc` 中的代码交互。但是，CSS 样式可能会影响 `<canvas>` 元素的大小和布局，从而间接地影响 `XRSession` 中与渲染相关的逻辑，例如视口的计算。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码调用 `session.requestAnimationFrame(callback)`：

* **假设输入:**  JavaScript 调用 `requestAnimationFrame` 并传入一个回调函数。
* **内部处理:** `XRSession` 会将该回调函数添加到 `callback_collection_` 中。
* **假设输入 (OnFrame):** 当浏览器接收到来自 XR 设备的下一帧数据时，`OnFrame` 方法被调用。
* **内部处理 (OnFrame):** `OnFrame` 方法会调用 `callback_collection_->ExecuteCallbacks`，从而执行 JavaScript 注册的回调函数。
* **假设输出:**  JavaScript 回调函数被执行，可以访问当前的 `XRFrame` 对象进行渲染操作。

**用户或编程常见的使用错误 (举例说明):**

* **在会话结束后调用方法:**  如果在会话已经结束后，JavaScript 代码仍然尝试调用 `XRSession` 的方法（例如 `requestReferenceSpace()`），则会抛出 `InvalidStateError` 异常。代码中的多处 `if (ended_) return;` 或 `if (ended_) { exception_state.ThrowDOMException(...); ... }` 就处理了这种情况。
* **在沉浸式会话中没有提供 Layer:**  沉浸式会话需要关联一个 `XRLayer` 进行渲染。如果开发者没有创建和提交 Layer，`OnFrame` 方法会检查 `render_state_->GetFirstLayer()`，如果没有 Layer，则不会进行渲染。这可能会导致用户在 VR 头显中看到黑屏。
* **错误地使用参考空间:**  开发者可能会请求一个设备不支持的参考空间类型。在这种情况下，`requestReferenceSpace()` 方法可能会返回一个 rejected 的 Promise。

**用户操作到达这里的步骤 (调试线索):**

1. **用户访问包含 WebXR 内容的网页:** 用户在浏览器中打开一个使用了 WebXR API 的网页。
2. **网页 JavaScript 代码请求 XR 会话:**  网页的 JavaScript 代码调用 `navigator.xr.requestSession('immersive-vr')` 或其他会话模式的方法。
3. **浏览器处理会话请求:**  浏览器接收到会话请求，并与底层 XR 系统进行交互。
4. **创建 XRSession 对象:** 如果会话请求成功，Blink 渲染引擎会创建 `XRSession` 对象。
5. **设备提供帧数据:**  XR 设备开始提供帧数据，这些数据通过 Mojo 接口传递到 Blink。
6. **调用 `UpdatePresentationFrameState`:**  Blink 接收到帧数据后，会调用 `XRSession` 对象的 `UpdatePresentationFrameState` 方法来更新会话状态。
7. **JavaScript 请求动画帧:**  网页 JavaScript 代码调用 `session.requestAnimationFrame(callback)` 来注册渲染回调。
8. **调用 `OnFrame`:**  在每一帧开始时，Blink 调用 `XRSession` 对象的 `OnFrame` 方法。
9. **执行 JavaScript 回调:** `OnFrame` 方法执行之前注册的 JavaScript 渲染回调函数。

**总结 `XRSession` 的功能:**

总而言之，`blink/renderer/modules/xr/xr_session.cc` 中的 `XRSession` 类是 WebXR API 在 Blink 渲染引擎中的核心实现，它作为 Web 内容与底层 XR 设备之间的桥梁，负责管理 XR 会话的生命周期、同步设备状态、处理输入事件、管理渲染流程以及提供各种 XR 相关的功能（如姿态追踪、环境理解、命中测试等），最终使得 Web 开发者能够构建沉浸式的 XR 应用。

### 提示词
```
这是目录为blink/renderer/modules/xr/xr_session.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
(canvas);

        // Begin processing input events on the output context's canvas.
        if (!immersive()) {
          canvas_input_provider_ =
              MakeGarbageCollected<XRCanvasInputProvider>(this, canvas);
        }

        // Get the new canvas dimensions
        UpdateCanvasDimensions(canvas);
      }
    }
  }
}

void XRSession::UpdatePresentationFrameState(
    double timestamp,
    device::mojom::blink::XRFrameDataPtr frame_data,
    int16_t frame_id,
    bool emulated_position) {
  TRACE_EVENT0("gpu", __func__);
  DVLOG(2) << __func__ << " : frame_data valid? " << (frame_data ? true : false)
           << ", emulated_position=" << emulated_position
           << ", frame_id=" << frame_id;
  // Don't process any outstanding frames once the session is ended.
  if (ended_)
    return;

  // If there are pending render state changes, apply them now, as they may
  // update the depthNear/Far used by the views.
  prev_base_layer_ = nullptr;
  ApplyPendingRenderState();

  // Update view related data.
  if (frame_data) {
    // Views need to be updated first, so that views() has valid data.
    UpdateViews(std::move(frame_data->views));

    // Apply dynamic viewport scaling if available.
    if (supports_viewport_scaling_) {
      float gpu_load = frame_data->rendering_time_ratio;
      std::optional<double> scale = std::nullopt;
      if (gpu_load > 0.0f) {
        if (!viewport_scaler_) {
          // Lazily create an instance of the viewport scaler on first use.
          viewport_scaler_ = std::make_unique<XRSessionViewportScaler>();
        }

        viewport_scaler_->UpdateRenderingTimeRatio(gpu_load);
        scale = viewport_scaler_->Scale();
        DVLOG(3) << __func__ << ": gpu_load=" << gpu_load
                 << " scale=" << *scale;
      }
      for (XRViewData* view : views()) {
        view->SetRecommendedViewportScale(scale);
      }
    }
  }

  // Update poses
  mojo_from_viewer_ =
      frame_data ? getPoseMatrix(frame_data->mojo_from_viewer) : nullptr;
  DVLOG(2) << __func__ << " : mojo_from_viewer_ valid? "
           << (mojo_from_viewer_ ? true : false);
  // TODO(https://crbug.com/1430868): We need to do this because inline sessions
  // don't have enough data to send up a mojo::XRView; but blink::XRViews rely
  // on having mojo_from_view set in a blink::XRViewData based upon the value
  // sent up in a mojo::XRView. Really, mojo::XRView should only be setting
  // viewer_from_view, and inline can go back to ignoring it, since the current
  // behavior essentially has two out of sync mojo_from_viewer transforms, one
  // is just implicitly embedded into an XRView. See
  // https://crbug.com/1428489#c7 for more details.
  if (!immersive() && mojo_from_viewer_) {
    for (XRViewData* view : views()) {
      // viewer_from_view multiplication omitted as it is identity.
      view->SetMojoFromView(*mojo_from_viewer_.get() /* * viewer_from_view */);
    }
  }

  emulated_position_ = emulated_position;

  // Finish processing reference state data then process input and reset events.
  if (frame_data) {
    // First finish updating positioning
    UpdateStageParameters(frame_data->stage_parameters_id,
                          frame_data->stage_parameters);

    // Now update the input sources
    base::span<const device::mojom::blink::XRInputSourceStatePtr> input_states;
    if (frame_data->input_state.has_value())
      input_states = frame_data->input_state.value();

    OnInputStateChangeInternal(frame_id, input_states);

    // World understanding includes hit testing for transient input sources, and
    // these sources may have been hidden when touching DOM Overlay content
    // that's inside cross-origin iframes. Since hit test subscriptions only
    // happen for existing input_sources_ entries, these touches will not
    // generate hit test results. For this to work, this step must happen
    // after OnInputStateChangeInternal which updated input sources.
    UpdateWorldUnderstandingStateForFrame(timestamp, frame_data);

    ProcessInputSourceEvents(input_states);

    // Now that all pose data is updated trigger a reset event if it's there.
    if (frame_data->mojo_space_reset) {
      OnMojoSpaceReset();
    }

    // Check if the session was ended by the |OnMojoSpaceReset| callback.
    if (ended_) {
      return;
    }
  } else {
    UpdateWorldUnderstandingStateForFrame(timestamp, frame_data);
  }
}

ScriptPromise<IDLArray<V8XRImageTrackingScore>>
XRSession::getTrackedImageScores(ScriptState* script_state,
                                 ExceptionState& exception_state) {
  DVLOG(3) << __func__;
  if (ended_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSessionEnded);
    return ScriptPromise<IDLArray<V8XRImageTrackingScore>>();
  }

  if (!IsFeatureEnabled(device::mojom::XRSessionFeature::IMAGE_TRACKING)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        kFeatureNotSupportedBySessionPrefix +
            XRSessionFeatureToString(
                device::mojom::XRSessionFeature::IMAGE_TRACKING));
    return ScriptPromise<IDLArray<V8XRImageTrackingScore>>();
  }

  auto* resolver = MakeGarbageCollected<
      ScriptPromiseResolver<IDLArray<V8XRImageTrackingScore>>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  if (tracked_image_scores_available_) {
    DVLOG(3) << __func__ << ": returning existing results";
    resolver->Resolve(tracked_image_scores_);
  } else {
    DVLOG(3) << __func__ << ": storing promise";
    image_scores_resolvers_.push_back(resolver);
  }

  return promise;
}

void XRSession::ProcessTrackedImagesData(
    const device::mojom::blink::XRTrackedImagesData* images_data) {
  DVLOG(3) << __func__;

  if (!images_data) {
    frame_tracked_images_ =
        MakeGarbageCollected<FrozenArray<XRImageTrackingResult>>();
    return;
  }

  HeapVector<Member<XRImageTrackingResult>> frame_tracked_images;
  for (const auto& image : images_data->images_data) {
    DVLOG(3) << __func__ << ": image index=" << image->index;
    frame_tracked_images.push_back(
        MakeGarbageCollected<XRImageTrackingResult>(this, *image));
  }
  frame_tracked_images_ =
      MakeGarbageCollected<FrozenArray<XRImageTrackingResult>>(
          std::move(frame_tracked_images));

  if (images_data->image_trackable_scores) {
    DVLOG(3) << ": got image_trackable_scores";
    DCHECK(!tracked_image_scores_available_);
    auto& scores = images_data->image_trackable_scores.value();
    for (WTF::wtf_size_t index = 0; index < scores.size(); ++index) {
      tracked_image_scores_.push_back(V8XRImageTrackingScore(
          scores[index] ? V8XRImageTrackingScore::Enum::kTrackable
                        : V8XRImageTrackingScore::Enum::kUntrackable));
      DVLOG(3) << __func__ << ": score[" << index
               << "]=" << tracked_image_scores_[index].AsCStr();
    }
    HeapVector<Member<ImageScoreResolverType>> image_score_promises;
    image_scores_resolvers_.swap(image_score_promises);
    for (auto& resolver : image_score_promises) {
      DVLOG(3) << __func__ << ": resolving promise";
      resolver->Resolve(tracked_image_scores_);
    }
    tracked_image_scores_available_ = true;
  }
}

const FrozenArray<XRImageTrackingResult>& XRSession::ImageTrackingResults(
    ExceptionState& exception_state) {
  if (!IsFeatureEnabled(device::mojom::XRSessionFeature::IMAGE_TRACKING)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        kFeatureNotSupportedBySessionPrefix +
            XRSessionFeatureToString(
                device::mojom::XRSessionFeature::IMAGE_TRACKING));
    return *MakeGarbageCollected<FrozenArray<XRImageTrackingResult>>();
  }

  return *frame_tracked_images_.Get();
}

void XRSession::UpdateWorldUnderstandingStateForFrame(
    double timestamp,
    const device::mojom::blink::XRFrameDataPtr& frame_data) {
  // Update objects that might change on per-frame basis.
  if (frame_data) {
    plane_manager_->ProcessPlaneInformation(
        frame_data->detected_planes_data.get(), timestamp);
    ProcessAnchorsData(frame_data->anchors_data.get(), timestamp);
    ProcessHitTestData(frame_data->hit_test_subscription_results.get());

    ProcessTrackedImagesData(frame_data->tracked_images.get());

    const device::mojom::blink::XRLightEstimationData* light_data =
        frame_data->light_estimation_data.get();
    if (world_light_probe_ && light_data) {
      world_light_probe_->ProcessLightEstimationData(light_data, timestamp);
    }

    camera_image_size_ = std::nullopt;
    if (frame_data->camera_image_size.has_value()) {
      // Let's store the camera image size. The texture ID will be filled out on
      // the XRWebGLLayer by the session once the frame starts
      // (in XRSession::OnFrame()).
      camera_image_size_ = frame_data->camera_image_size;
    }
  } else {
    plane_manager_->ProcessPlaneInformation(nullptr, timestamp);
    ProcessAnchorsData(nullptr, timestamp);
    ProcessHitTestData(nullptr);

    ProcessTrackedImagesData(nullptr);

    if (world_light_probe_) {
      world_light_probe_->ProcessLightEstimationData(nullptr, timestamp);
    }

    camera_image_size_ = std::nullopt;
  }
}

bool XRSession::IsFeatureEnabled(
    device::mojom::XRSessionFeature feature) const {
  return enabled_feature_set_.Contains(feature);
}

void XRSession::SetMetricsReporter(std::unique_ptr<MetricsReporter> reporter) {
  DCHECK(!metrics_reporter_);
  metrics_reporter_ = std::move(reporter);
}

void XRSession::OnFrame(
    double timestamp,
    scoped_refptr<gpu::ClientSharedImage> output_shared_image,
    const gpu::SyncToken& output_sync_token,
    scoped_refptr<gpu::ClientSharedImage> camera_image_shared_image,
    const gpu::SyncToken& camera_image_sync_token) {
  TRACE_EVENT0("gpu", __func__);
  DVLOG(2) << __func__ << ": ended_=" << ended_
           << ", pending_frame_=" << pending_frame_;
  // Don't process any outstanding frames once the session is ended.
  if (ended_)
    return;

  layer_shared_image_manager_.Reset();

  if (pending_frame_) {
    pending_frame_ = false;

    // Don't allow frames to be processed if there's no layers attached to the
    // session. That would allow tracking with no associated visuals.
    if (!render_state_->GetFirstLayer()) {
      DVLOG(2) << __func__ << ": frame_base_layer not present";

      // If we previously had a frame base layer, we need to still attempt to
      // submit a frame back to the runtime, as all "GetFrameData" calls need a
      // matching submit.
      if (prev_base_layer_) {
        layer_shared_image_manager_.SetLayerSharedImages(
            prev_base_layer_, output_shared_image, output_sync_token,
            camera_image_shared_image, camera_image_sync_token);

        DVLOG(2) << __func__
                 << ": prev_base_layer_ is valid, submitting frame to it";
        prev_base_layer_->OnFrameStart();
        prev_base_layer_->OnFrameEnd();
        prev_base_layer_ = nullptr;
      }
      return;
    }

    // Don't allow frames to be processed if an inline session doesn't have an
    // output canvas.
    if (!immersive() && !render_state_->output_canvas()) {
      DVLOG(2) << __func__
               << ": frames are not to be processed if an inline session "
                  "doesn't have an output canvas";
      return;
    }

    XRLayer* frame_base_layer = render_state_->GetFirstLayer();
    layer_shared_image_manager_.SetLayerSharedImages(
        frame_base_layer, output_shared_image, output_sync_token,
        camera_image_shared_image, camera_image_sync_token);

    frame_base_layer->OnFrameStart();

    // Don't allow frames to be processed if the session's visibility state is
    // "hidden".
    if (visibility_state_ == XRVisibilityState::HIDDEN) {
      DVLOG(2) << __func__
               << ": frames to be processed if the session's visibility state "
                  "is \"hidden\"";
      // If the frame is skipped because of the visibility state,
      // make sure we end the frame anyway.
      frame_base_layer->OnFrameEnd();
      return;
    }

    XRFrame* presentation_frame = CreatePresentationFrame(true);

    // If the device has opted in, mark the viewports as modifiable
    // at the start of an animation frame:
    // https://immersive-web.github.io/webxr/#ref-for-view-viewport-modifiable
    if (supports_viewport_scaling_) {
      for (XRViewData* view : views()) {
        view->SetViewportModifiable(true);
      }
    }

    // Resolve the queued requestAnimationFrame callbacks. All XR rendering will
    // happen within these calls. resolving_frame_ will be true for the duration
    // of the callbacks.
    base::AutoReset<bool> resolving(&resolving_frame_, true);
    page_animation_frame_timer_.StartTimer();
    ExecuteVideoFrameCallbacks(timestamp);
    callback_collection_->ExecuteCallbacks(this, timestamp, presentation_frame);
    page_animation_frame_timer_.StopTimer();

    frame_base_layer->OnFrameEnd();

    // Ensure the XRFrame cannot be used outside the callbacks.
    presentation_frame->Deactivate();
  }
}

void XRSession::LogGetPose() const {
  if (!did_log_getViewerPose_ && GetExecutionContext()) {
    did_log_getViewerPose_ = true;

    ukm::builders::XR_WebXR(GetExecutionContext()->UkmSourceID())
        .SetDidRequestPose(1)
        .Record(GetExecutionContext()->UkmRecorder());
  }
}

bool XRSession::CanReportPoses() const {
  // The spec has a few requirements for if poses can be reported.
  // If we have a session, then user intent is understood. Therefore, (due to
  // the way visibility state is updatd), the rest of the steps really just
  // boil down to whether or not the XRVisibilityState is Visible.
  return visibility_state_ == XRVisibilityState::VISIBLE;
}

bool XRSession::CanEnableAntiAliasing() const {
  return device_config_->enable_anti_aliasing;
}

std::optional<gfx::Transform> XRSession::GetMojoFrom(
    device::mojom::blink::XRReferenceSpaceType space_type) const {
  if (!CanReportPoses()) {
    DVLOG(2) << __func__ << ": cannot report poses, returning nullopt";
    return std::nullopt;
  }

  switch (space_type) {
    case device::mojom::blink::XRReferenceSpaceType::kViewer:
      if (!mojo_from_viewer_) {
        if (sensorless_session_) {
          return gfx::Transform();
        }

        return std::nullopt;
      }

      return *mojo_from_viewer_;
    case device::mojom::blink::XRReferenceSpaceType::kLocal:
      // TODO(https://crbug.com/1070380): This assumes that local space is
      // equivalent to mojo space! Remove the assumption once the bug is fixed.
      return gfx::Transform();
    case device::mojom::blink::XRReferenceSpaceType::kUnbounded:
      // TODO(https://crbug.com/1070380): This assumes that unbounded space is
      // equivalent to mojo space! Remove the assumption once the bug is fixed.
      return gfx::Transform();
    case device::mojom::blink::XRReferenceSpaceType::kLocalFloor:
    case device::mojom::blink::XRReferenceSpaceType::kBoundedFloor:
      // Information about -floor spaces is currently stored elsewhere (in
      // stage_parameters_). It probably should eventually move here.
      return std::nullopt;
  }
}

XRFrame* XRSession::CreatePresentationFrame(bool is_animation_frame) {
  DVLOG(2) << __func__ << ": is_animation_frame=" << is_animation_frame;

  XRFrame* presentation_frame =
      MakeGarbageCollected<XRFrame>(this, is_animation_frame);
  return presentation_frame;
}

void XRSession::UpdateInlineView() {
  if (canvas_was_resized_) {
    views_.clear();
    canvas_was_resized_ = false;
  }
  if (views_.empty()) {
    views_.emplace_back(MakeGarbageCollected<XRViewData>(
        /*index=*/0, device::mojom::blink::XREye::kNone,
        gfx::Rect(0, 0, output_width_, output_height_), graphics_api_));
  }

  float aspect = 1.0f;
  if (output_width_ && output_height_) {
    aspect =
        static_cast<float>(output_width_) / static_cast<float>(output_height_);
  }

  // In non-immersive mode, if there is no explicit projection matrix
  // provided, the projection matrix must be aligned with the
  // output canvas dimensions.
  std::optional<double> inline_vertical_fov =
      render_state_->inlineVerticalFieldOfView();

  // inlineVerticalFieldOfView should only be null in immersive mode.
  DCHECK(inline_vertical_fov.has_value());
  views_[kMonoView]->UpdateProjectionMatrixFromAspect(
      inline_vertical_fov.value(), aspect, render_state_->depthNear(),
      render_state_->depthFar());
}

// Called when the canvas element for this session's output context is resized.
void XRSession::UpdateCanvasDimensions(Element* element) {
  DCHECK(element);

  double devicePixelRatio = 1.0;
  LocalDOMWindow* window = To<LocalDOMWindow>(xr_->GetExecutionContext());
  if (window) {
    devicePixelRatio = window->GetFrame()->DevicePixelRatio();
  }

  output_width_ = element->OffsetWidth() * devicePixelRatio;
  output_height_ = element->OffsetHeight() * devicePixelRatio;

  XRLayer* base_layer = render_state_->GetFirstLayer();
  if (base_layer) {
    base_layer->OnResize();
  }

  canvas_was_resized_ = true;
  UpdateInlineView();
}

void XRSession::OnInputStateChangeInternal(
    int16_t frame_id,
    base::span<const device::mojom::blink::XRInputSourceStatePtr>
        input_states) {
  // If we're in any state other than visible, input should not be processed
  if (visibility_state_ != XRVisibilityState::VISIBLE) {
    return;
  }

  HeapVector<Member<XRInputSource>> added;
  HeapVector<Member<XRInputSource>> removed;
  last_frame_id_ = frame_id;

  DVLOG(2) << __func__ << ": frame_id=" << frame_id
           << " input_states.size()=" << input_states.size();
  // Build up our added array, and update the frame id of any active input
  // sources so we can flag the ones that are no longer active.
  for (const auto& input_state : input_states) {
    DVLOG(2) << __func__
             << ": input_state->source_id=" << input_state->source_id
             << " input_state->primary_input_pressed="
             << input_state->primary_input_pressed
             << " clicked=" << input_state->primary_input_clicked;

    XRInputSource* stored_input_source =
        input_sources_->GetWithSourceId(input_state->source_id);
    DVLOG(2) << __func__ << ": stored_input_source=" << stored_input_source;
    XRInputSource* input_source = XRInputSource::CreateOrUpdateFrom(
        stored_input_source, this, input_state);

    // Input sources should use DOM overlay hit test to check if they intersect
    // cross-origin content. If that's the case, the input source is set as
    // invisible, and must not return poses or hit test results.
    bool hide_input_source = false;
    if (IsFeatureEnabled(device::mojom::XRSessionFeature::DOM_OVERLAY) &&
        overlay_element_ && input_state->overlay_pointer_position) {
      input_source->ProcessOverlayHitTest(overlay_element_, input_state);
      if (!stored_input_source && !input_source->IsVisible()) {
        DVLOG(2) << __func__ << ": (new) hidden_input_source";
        hide_input_source = true;
      }
    }

    // Using pointer equality to determine if the pointer needs to be set.
    if (stored_input_source != input_source) {
      DVLOG(2) << __func__ << ": stored_input_source != input_source";
      if (!hide_input_source) {
        input_sources_->SetWithSourceId(input_state->source_id, input_source);
        added.push_back(input_source);
        DVLOG(2) << __func__ << ": ADDED input_source "
                 << input_state->source_id;
      }

      // If we previously had a stored_input_source, disconnect its gamepad
      // and mark that it was removed.
      if (stored_input_source) {
        stored_input_source->SetGamepadConnected(false);
        DVLOG(2) << __func__ << ": REMOVED stored_input_source";
        removed.push_back(stored_input_source);
      }
    }

    input_source->setActiveFrameId(frame_id);
  }

  // Remove any input sources that are inactive, and disconnect their gamepad.
  // Note that this is done in two passes because HeapHashMap makes no
  // guarantees about iterators on removal.
  // We use a separate array of inactive sources here rather than just
  // processing removed, because if we replaced any input sources, they would
  // also be in removed, and we'd remove our newly added source.
  Vector<uint32_t> inactive_sources;
  for (unsigned i = 0; i < input_sources_->length(); i++) {
    auto* input_source = (*input_sources_)[i];
    if (input_source->activeFrameId() != frame_id) {
      inactive_sources.push_back(input_source->source_id());
      input_source->OnRemoved();
      removed.push_back(input_source);
    }
  }

  for (uint32_t source_id : inactive_sources) {
    input_sources_->RemoveWithSourceId(source_id);
  }

  // If there have been any changes, fire the input sources change event.
  if (!added.empty() || !removed.empty()) {
    DispatchEvent(*XRInputSourcesChangeEvent::Create(
        event_type_names::kInputsourceschange, this, added, removed));
  }
}

void XRSession::ProcessInputSourceEvents(
    base::span<const device::mojom::blink::XRInputSourceStatePtr>
        input_states) {
  for (const auto& input_state : input_states) {
    // If anything during the process of updating the select state caused us
    // to end our session, we should stop processing select state updates.
    if (ended_)
      break;

    XRInputSource* input_source =
        input_sources_->GetWithSourceId(input_state->source_id);
    // The input source might not be in input_sources_ if it was created hidden.
    if (input_source) {
      input_source->UpdateButtonStates(input_state);
    }
  }
}

void XRSession::AddTransientInputSource(XRInputSource* input_source) {
  if (ended_)
    return;

  // Ensure we're not overriding an input source that's already present.
  DCHECK(!input_sources_->GetWithSourceId(input_source->source_id()));
  input_sources_->SetWithSourceId(input_source->source_id(), input_source);

  DispatchEvent(*XRInputSourcesChangeEvent::Create(
      event_type_names::kInputsourceschange, this, {input_source}, {}));
}

void XRSession::RemoveTransientInputSource(XRInputSource* input_source) {
  if (ended_)
    return;

  input_sources_->RemoveWithSourceId(input_source->source_id());

  DispatchEvent(*XRInputSourcesChangeEvent::Create(
      event_type_names::kInputsourceschange, this, {}, {input_source}));
}

void XRSession::OnMojoSpaceReset() {
  // Since this eventually dispatches an event to the page, the page could
  // create a new reference space which would invalidate our iterators; so
  // iterate over a copy of the reference space list.
  HeapVector<Member<XRReferenceSpace>> ref_spaces_copy = reference_spaces_;
  for (const auto& reference_space : ref_spaces_copy) {
    reference_space->OnReset();
  }
}

void XRSession::OnExitPresent() {
  DVLOG(2) << __func__ << ": immersive()=" << immersive()
           << " waiting_for_shutdown_=" << waiting_for_shutdown_;
  if (immersive()) {
    ForceEnd(ShutdownPolicy::kImmediate);
  } else if (waiting_for_shutdown_) {
    HandleShutdown();
  }
}

bool XRSession::ValidateHitTestSourceExists(
    XRHitTestSource* hit_test_source) const {
  DCHECK(hit_test_source);
  return base::Contains(hit_test_source_ids_, hit_test_source->id());
}

bool XRSession::ValidateHitTestSourceExists(
    XRTransientInputHitTestSource* hit_test_source) const {
  DCHECK(hit_test_source);
  return base::Contains(hit_test_source_for_transient_input_ids_,
                        hit_test_source->id());
}

bool XRSession::RemoveHitTestSource(XRHitTestSource* hit_test_source) {
  DVLOG(2) << __func__;

  DCHECK(hit_test_source);

  if (!base::Contains(hit_test_source_ids_, hit_test_source->id())) {
    DVLOG(2) << __func__
             << ": hit test source was already removed, hit_test_source->id()="
             << hit_test_source->id();
    return false;
  }

  if (ended_) {
    DVLOG(1) << __func__
             << ": attempted to remove a hit test source on a session that has "
                "already ended.";
    // Since the session has ended, we won't be able to reach out to the device
    // to remove a hit test source subscription. Just notify the caller that the
    // removal was successful.
    return true;
  }

  DCHECK_HIT_TEST_SOURCES();

  hit_test_source_ids_to_hit_test_sources_.erase(hit_test_source->id());
  hit_test_source_ids_.erase(hit_test_source->id());

  DCHECK(xr_->xrEnvironmentProviderRemote());

  xr_->xrEnvironmentProviderRemote()->UnsubscribeFromHitTest(
      hit_test_source->id());

  DCHECK_HIT_TEST_SOURCES();

  return true;
}

bool XRSession::RemoveHitTestSource(
    XRTransientInputHitTestSource* hit_test_source) {
  DVLOG(2) << __func__;

  DCHECK(hit_test_source);

  if (!base::Contains(hit_test_source_for_transient_input_ids_,
                      hit_test_source->id())) {
    DVLOG(2) << __func__
             << ": hit test source was already removed, hit_test_source->id()="
             << hit_test_source->id();
    return false;
  }

  if (ended_) {
    DVLOG(1) << __func__
             << ": attempted to remove a hit test source on a session that has "
                "already ended.";
    // Since the session has ended, we won't be able to reach out to the device
    // to remove a hit test source subscription. Just notify the caller that the
    // removal was successful.
    return true;
  }

  DCHECK_HIT_TEST_SOURCES();

  hit_test_source_ids_to_transient_input_hit_test_sources_.erase(
      hit_test_source->id());
  hit_test_source_for_transient_input_ids_.erase(hit_test_source->id());

  DCHECK(xr_->xrEnvironmentProviderRemote());

  xr_->xrEnvironmentProviderRemote()->UnsubscribeFromHitTest(
      hit_test_source->id());

  DCHECK_HIT_TEST_SOURCES();

  return true;
}

const HeapVector<Member<XRViewData>>& XRSession::views() {
  return views_;
}

XRViewData* XRSession::ViewDataForEye(device::mojom::blink::XREye eye) {
  switch (eye) {
    case device::mojom::blink::XREye::kLeft:
    case device::mojom::blink::XREye::kNone:
      return views_[0].Get();
    case device::mojom::blink::XREye::kRight:
      return views_[1].Get();
  }
}

bool XRSession::HasPendingActivity() const {
  return (!callback_collection_->IsEmpty() || !vfc_execution_queue_.empty()) &&
         !ended_;
}

void XRSession::Trace(Visitor* visitor) const {
  visitor->Trace(xr_);
  visitor->Trace(render_state_);
  visitor->Trace(world_light_probe_);
  visitor->Trace(pending_render_state_);
  visitor->Trace(end_session_resolver_);
  visitor->Trace(enabled_features_);
  visitor->Trace(input_sources_);
  visitor->Trace(resize_observer_);
  visitor->Trace(canvas_input_provider_);
  visitor->Trace(overlay_element_);
  visitor->Trace(dom_overlay_state_);
  visitor->Trace(client_receiver_);
  visitor->Trace(callback_collection_);
  visitor->Trace(create_anchor_promises_);
  visitor->Trace(request_hit_test_source_promises_);
  visitor->Trace(reference_spaces_);
  visitor->Trace(plane_manager_);
  visitor->Trace(anchor_ids_to_anchors_);
  visitor->Trace(anchor_ids_to_pending_anchor_promises_);
  visitor->Trace(prev_base_layer_);
  visitor->Trace(hit_test_source_ids_to_hit_test_sources_);
  visitor->Trace(hit_test_source_ids_to_transient_input_hit_test_sources_);
  visitor->Trace(views_);
  visitor->Trace(frame_tracked_images_);
  visitor->Trace(image_scores_resolvers_);
  EventTarget::Trace(visitor);
}

}  // namespace blink
```