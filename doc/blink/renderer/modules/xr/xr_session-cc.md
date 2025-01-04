Response:
The user wants me to analyze a C++ source code file for the Chromium Blink engine related to WebXR. They specifically asked for:

1. **Functionality:** A summary of what the code does.
2. **Relationship to Web Technologies:** How it connects to JavaScript, HTML, and CSS, with examples.
3. **Logical Reasoning:**  If any logic is present, show input and output examples.
4. **Common User/Programming Errors:**  Illustrate typical mistakes users or developers might make.
5. **User Actions Leading to This Code:** Describe the steps a user might take in a browser that would cause this code to execute.
6. **Role as a Debugging Clue:** How this file can help in debugging.
7. **Overall Summary of Functionality (for Part 1):** A concise summary based on the provided snippet.

Let's go through the code and try to extract this information.

**Code Analysis - Initial Observations:**

* **Includes:** The file includes various Blink headers related to XR (e.g., `xr_session.h`, `xr_frame.h`, `xr_reference_space.h`), bindings (`v8_xr_frame_request_callback.h`), core DOM elements (`element.h`), and platform utilities. This suggests the file manages the state and lifecycle of an XR session.
* **Namespace:** The code is within the `blink` namespace.
* **Class Definition:** The primary class is `XRSession`.
* **Constants:** Several string constants indicate error messages and unsupported features.
* **Helper Functions:** There are static helper functions for mapping reference space types to features, converting poses, and managing hit-testing entity types.
* **Data Members:**  The `XRSession` class has members for:
    *  Tracking XR-related objects like `XRFrame`, `XRReferenceSpace`, `XRInputSource`.
    *  Managing callbacks for animation frames.
    *  Handling session state (e.g., `ended_`, `visibility_state_`).
    *  Interacting with the underlying XR service (`client_receiver_`).
    *  Reporting metrics.
* **Methods:** The class has methods for:
    *  Requesting reference spaces (`requestReferenceSpace`).
    *  Updating the rendering state (`updateRenderState`).
    *  Managing animation frames (`requestAnimationFrame`).
    *  Handling hit testing.
    *  Creating anchors.
    *  Dealing with DOM overlays.
    *  Managing input sources.

**Connecting to Web Technologies:**

* **JavaScript:** The `XRSession` class is likely exposed to JavaScript via the WebXR API. Methods like `requestReferenceSpace`, `requestAnimationFrame`, and `updateRenderState` directly correspond to JavaScript methods in the `XRSession` interface.
* **HTML:**  The interaction with HTML is evident through the `SetDOMOverlayElement` method, which links an HTML element to the XR session for overlay purposes.
* **CSS:** While not directly manipulating CSS, the rendering and layout influenced by the XR session might indirectly affect CSS properties. For example, the size and position of the DOM overlay element would be governed by CSS.

**Logical Reasoning:**

The code includes logic for validating user requests (e.g., checking if a feature is supported, if the session has ended) and managing the state of the XR session.

**Common Errors:**

The string constants like `kSessionEnded`, `kReferenceSpaceNotSupported`, and `kIncompatibleLayer` directly point to common errors.

**User Actions:**

A user interacting with a website using WebXR would trigger this code. This involves requesting an XR session, entering immersive mode, and interacting with the virtual environment.

**Debugging Clue:**

This file is central to managing XR sessions, so issues related to session lifecycle, reference spaces, rendering, and input handling would likely involve this code.

**Part 1 Summary:**

Based on the first part of the code, the primary function of `xr_session.cc` is to manage the lifecycle and state of a WebXR session within the Chromium Blink engine. This includes handling requests for reference spaces, updating rendering parameters, managing animation frame callbacks, and interacting with the underlying XR service. It acts as the bridge between the JavaScript WebXR API and the native XR implementation.
这是对 Chromium Blink 引擎中 `blink/renderer/modules/xr/xr_session.cc` 源代码文件的功能归纳：

**功能归纳：**

`xr_session.cc` 文件实现了 WebXR API 中的 `XRSession` 接口，负责管理和控制一个 WebXR 会话的生命周期和状态。其主要功能包括：

* **会话管理:** 创建、启动、结束和维护 XR 会话的状态。
* **渲染控制:**  管理渲染状态（例如，视口、图层），并与底层渲染机制交互以呈现 XR 内容。
* **参考空间管理:**  处理对不同参考空间类型的请求（例如，viewer, local, local-floor），并提供坐标转换功能。
* **动画帧管理:**  处理 `requestAnimationFrame` 调用，调度回调以在每一帧进行渲染更新。
* **输入处理:**  接收和处理来自 XR 设备（例如，头显、手柄）的输入事件。
* **命中测试:**  支持执行射线投射测试以确定虚拟世界中物体的碰撞。
* **锚点管理:**  支持创建和跟踪虚拟锚点，用于持久化虚拟对象的位置。
* **DOM Overlay 支持:**  允许将 HTML 元素作为覆盖层显示在 XR 场景之上。
* **图像跟踪:**  支持跟踪现实世界中的图像。
* **平面检测:**  支持检测现实世界中的平面。
* **深度感知:**  处理深度数据的获取和使用。
* **性能指标收集:**  记录 XR 会话的性能指标。
* **错误处理:**  处理会话期间可能发生的各种错误，并向 JavaScript 层报告。

**与 JavaScript, HTML, CSS 的关系举例：**

* **JavaScript:**
    * 当 JavaScript 代码调用 `navigator.xr.requestSession()` 时，会触发 `XRSession` 对象的创建。
    * `session.requestReferenceSpace('local')`  在 JavaScript 中调用时，会在 `xr_session.cc` 中创建对应的 `XRReferenceSpace` 对象。
    * `session.requestAnimationFrame(callback)`  在 JavaScript 中注册一个回调函数，该函数将在浏览器的渲染循环中被调用，`xr_session.cc` 负责管理这些回调。
    * `session.updateRenderState({ baseLayer: ... })`  允许 JavaScript 设置用于渲染 XR 内容的 WebGL 图层，这会调用 `xr_session.cc` 中的 `updateRenderState` 方法。
    * `session.inputSources`  属性在 JavaScript 中访问 XR 输入源的信息，这些信息由 `xr_session.cc` 管理和更新。
    * `session.requestHitTestSource(...)` 在 JavaScript 中发起命中测试请求，`xr_session.cc` 会与底层 XR 服务通信执行测试。
    * `session.createAnchor(...)` 在 JavaScript 中创建锚点，会调用 `xr_session.cc` 中的 `CreateAnchorHelper` 方法。
    * `session.domOverlayState`  在 JavaScript 中访问 DOM 覆盖层的状态，该状态由 `xr_session.cc` 中的 `SetDOMOverlayElement` 方法设置。

* **HTML:**
    * 通过 JavaScript 调用 `session.domOverlayState.setElement(myElement)`，将一个 HTML 元素 (`myElement`) 与 XR 会话关联，实现在 XR 中显示 HTML 内容。`xr_session.cc` 中的 `SetDOMOverlayElement` 方法会处理此关联。

* **CSS:**
    * 虽然 `xr_session.cc` 不直接操作 CSS，但通过 DOM Overlay 功能，可以将带有 CSS 样式的 HTML 元素嵌入到 XR 场景中。这些 CSS 样式会影响覆盖层的外观。

**逻辑推理的假设输入与输出：**

* **假设输入:** JavaScript 调用 `session.requestReferenceSpace('local-floor')`。
* **输出:**
    * **假设设备支持 `local-floor`:** `xr_session.cc` 将创建一个 `XRReferenceSpace` 对象，类型为 `kLocalFloor`，并将其包装在一个 Promise 中返回给 JavaScript。
    * **假设设备不支持 `local-floor`:** `xr_session.cc` 将抛出一个 `NotSupportedError` 异常，Promise 将被拒绝。

* **假设输入:** JavaScript 调用 `session.updateRenderState({ depthNear: 0.1, depthFar: 100 })`。
* **输出:** `xr_session.cc` 中的 `render_state_` 对象的 `depthNear` 和 `depthFar` 属性将被更新。

**涉及用户或编程常见的使用错误举例：**

* **会话已结束时尝试操作:** 用户在 XR 会话结束后（例如，用户关闭了 VR 模式）仍然尝试调用 `session.requestReferenceSpace()` 或 `session.requestAnimationFrame()` 等方法。`xr_session.cc` 中会抛出 `InvalidStateError` 异常，错误信息为 "XRSession has already ended."。
* **请求不支持的参考空间:** 用户请求设备不支持的参考空间类型，例如，在一个不支持 bounded-floor 的设备上请求 'bounded-floor'。`xr_session.cc` 会抛出 `NotSupportedError` 异常，错误信息包含 "This device does not support the requested reference space type."。
* **使用不兼容的 WebGLLayer:** 用户尝试使用一个不是由当前 `XRSession` 创建的 `XRWebGLLayer` 来更新渲染状态。`xr_session.cc` 会抛出 `InvalidStateError` 异常，错误信息为 "XRWebGLLayer was created with a different session."。
* **同时设置 baseLayer 和 layers:** 用户在调用 `updateRenderState` 时，同时设置了 `baseLayer` 和 `layers` 属性。`xr_session.cc` 会抛出 `NotSupportedError` 异常，错误信息为 "Both baseLayer and layers should not be set at the same time when updating render state."。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户打开支持 WebXR 的浏览器:** 用户使用的浏览器必须支持 WebXR API。
2. **用户访问包含 WebXR 内容的网页:** 网页的 JavaScript 代码会尝试使用 WebXR 功能。
3. **网页 JavaScript 请求 XR 会话:**  JavaScript 代码调用 `navigator.xr.requestSession(...)`，例如请求沉浸式 VR 会话 `navigator.xr.requestSession('immersive-vr')`。
4. **浏览器底层开始创建 XR 会话:** 浏览器会调用 Blink 引擎的相应代码来创建 `XRSession` 对象，这涉及到 `xr_session.cc` 中的构造函数。
5. **JavaScript 与 `XRSession` 对象交互:** 网页的 JavaScript 代码会调用 `XRSession` 对象的方法，例如 `requestReferenceSpace()`, `requestAnimationFrame()`, `updateRenderState()` 等，这些调用会进入 `xr_session.cc` 中的对应方法。
6. **调试线索:** 当在调试 WebXR 应用时遇到问题，例如：
    * **会话无法启动:** 可以检查 `XRSession` 的构造函数和相关初始化代码。
    * **参考空间请求失败:** 可以查看 `requestReferenceSpace()` 方法的逻辑，确认设备是否支持请求的类型，以及是否启用了所需的功能。
    * **渲染问题:** 可以检查 `updateRenderState()` 方法，查看 WebGLLayer 的设置和参数。
    * **动画帧回调未执行或执行异常:** 可以查看 `requestAnimationFrame()` 和相关的回调管理机制。

**第一部分功能归纳：**

在提供的代码片段中，`XRSession` 类主要负责 XR 会话的创建和初始化，包括设置会话模式、环境混合模式、交互模式、启用特性等。它还处理了部分状态管理，例如通过 `UpdateViews` 方法更新视图信息。此外，代码还定义了一些辅助函数和常量，用于错误处理和特性映射。总而言之，第一部分主要关注会话的建立和基本属性的配置。

Prompt: 
```
这是目录为blink/renderer/modules/xr/xr_session.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/xr/xr_session.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "base/auto_reset.h"
#include "base/containers/contains.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "base/trace_event/trace_event.h"
#include "base/types/pass_key.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_frame_request_callback.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_hit_test_options_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_image_tracking_result.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_render_state_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_transient_input_hit_test_options_init.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_visibility_state.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/frame.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/probe/async_task_context.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer.h"
#include "third_party/blink/renderer/core/resize_observer/resize_observer_entry.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/xr/vr_service_type_converters.h"
#include "third_party/blink/renderer/modules/xr/xr_anchor_set.h"
#include "third_party/blink/renderer/modules/xr/xr_bounded_reference_space.h"
#include "third_party/blink/renderer/modules/xr/xr_camera.h"
#include "third_party/blink/renderer/modules/xr/xr_canvas_input_provider.h"
#include "third_party/blink/renderer/modules/xr/xr_cube_map.h"
#include "third_party/blink/renderer/modules/xr/xr_dom_overlay_state.h"
#include "third_party/blink/renderer/modules/xr/xr_frame.h"
#include "third_party/blink/renderer/modules/xr/xr_frame_provider.h"
#include "third_party/blink/renderer/modules/xr/xr_hit_test_source.h"
#include "third_party/blink/renderer/modules/xr/xr_image_tracking_result.h"
#include "third_party/blink/renderer/modules/xr/xr_input_source_event.h"
#include "third_party/blink/renderer/modules/xr/xr_input_sources_change_event.h"
#include "third_party/blink/renderer/modules/xr/xr_light_probe.h"
#include "third_party/blink/renderer/modules/xr/xr_plane_manager.h"
#include "third_party/blink/renderer/modules/xr/xr_ray.h"
#include "third_party/blink/renderer/modules/xr/xr_reference_space.h"
#include "third_party/blink/renderer/modules/xr/xr_render_state.h"
#include "third_party/blink/renderer/modules/xr/xr_session_event.h"
#include "third_party/blink/renderer/modules/xr/xr_session_viewport_scaler.h"
#include "third_party/blink/renderer/modules/xr/xr_system.h"
#include "third_party/blink/renderer/modules/xr/xr_transient_input_hit_test_source.h"
#include "third_party/blink/renderer/modules/xr/xr_utils.h"
#include "third_party/blink/renderer/modules/xr/xr_view.h"
#include "third_party/blink/renderer/modules/xr/xr_webgl_layer.h"
#include "third_party/blink/renderer/platform/bindings/enumeration_base.h"
#include "third_party/blink/renderer/platform/bindings/v8_throw_exception.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/text/string_operators.h"
#include "ui/gfx/geometry/point3_f.h"
#include "ui/gfx/geometry/transform.h"

namespace blink {

namespace {

const char kSessionEnded[] = "XRSession has already ended.";

const char kReferenceSpaceNotSupported[] =
    "This device does not support the requested reference space type.";

const char kIncompatibleLayer[] =
    "XRWebGLLayer was created with a different session.";

const char kBaseLayerAndLayers[] =
    "Both baseLayer and layers should not be set at the same time when "
    "updating render state.";

const char kMultiLayersNotEnabled[] =
    "This session does not support multiple layers.";

const char kDuplicateLayer[] = "All layers in render state must be unique.";

const char kInlineVerticalFOVNotSupported[] =
    "This session does not support inlineVerticalFieldOfView";

const char kFeatureNotSupportedByDevicePrefix[] =
    "Device does not support feature ";

const char kFeatureNotSupportedBySessionPrefix[] =
    "Session does not support feature ";

const char kDeviceDisconnected[] = "The XR device has been disconnected.";

const char kUnableToDecomposeMatrix[] =
    "The operation was unable to decompose a matrix and could not be "
    "completed.";

const char kUnableToRetrieveNativeOrigin[] =
    "The operation was unable to retrieve the native origin from XRSpace and "
    "could not be completed.";

const char kHitTestSubscriptionFailed[] = "Hit test subscription failed.";

const char kAnchorCreationFailed[] = "Anchor creation failed.";

const char kEntityTypesNotSpecified[] =
    "No entityTypes specified: the array cannot be empty!";

const char kSessionNotHaveSetFrameRate[] =
    "Session does not have a set frame rate.";

const float kMinDefaultFramebufferScale = 0.1f;
const float kMaxDefaultFramebufferScale = 1.0f;

// Indices into the views array.
const unsigned int kMonoView = 0;

// Returns the session feature corresponding to the given reference space type.
std::optional<device::mojom::XRSessionFeature> MapReferenceSpaceTypeToFeature(
    device::mojom::blink::XRReferenceSpaceType type) {
  switch (type) {
    case device::mojom::blink::XRReferenceSpaceType::kViewer:
      return device::mojom::XRSessionFeature::REF_SPACE_VIEWER;
    case device::mojom::blink::XRReferenceSpaceType::kLocal:
      return device::mojom::XRSessionFeature::REF_SPACE_LOCAL;
    case device::mojom::blink::XRReferenceSpaceType::kLocalFloor:
      return device::mojom::XRSessionFeature::REF_SPACE_LOCAL_FLOOR;
    case device::mojom::blink::XRReferenceSpaceType::kBoundedFloor:
      return device::mojom::XRSessionFeature::REF_SPACE_BOUNDED_FLOOR;
    case device::mojom::blink::XRReferenceSpaceType::kUnbounded:
      return device::mojom::XRSessionFeature::REF_SPACE_UNBOUNDED;
  }

  NOTREACHED();
}

std::unique_ptr<gfx::Transform> getPoseMatrix(
    const device::mojom::blink::VRPosePtr& pose) {
  if (!pose)
    return nullptr;

  device::Pose device_pose =
      device::Pose(pose->position.value_or(gfx::Point3F()),
                   pose->orientation.value_or(gfx::Quaternion()));

  return std::make_unique<gfx::Transform>(device_pose.ToTransform());
}

device::mojom::blink::EntityTypeForHitTest EntityTypeForHitTestFromEnum(
    V8XRHitTestTrackableType::Enum type) {
  switch (type) {
    case V8XRHitTestTrackableType::Enum::kPlane:
      return device::mojom::blink::EntityTypeForHitTest::PLANE;
    case V8XRHitTestTrackableType::Enum::kPoint:
      return device::mojom::blink::EntityTypeForHitTest::POINT;
  }
  NOTREACHED();
}

// Returns a vector of entity types from hit test options, without duplicates.
// OptionsType can be either XRHitTestOptionsInit or
// XRTransientInputHitTestOptionsInit.
template <typename OptionsType>
Vector<device::mojom::blink::EntityTypeForHitTest> GetEntityTypesForHitTest(
    OptionsType* options_init) {
  DCHECK(options_init);
  HashSet<device::mojom::blink::EntityTypeForHitTest> result_set;

  if (RuntimeEnabledFeatures::WebXRHitTestEntityTypesEnabled() &&
      options_init->hasEntityTypes()) {
    DVLOG(2) << __func__ << ": options_init->entityTypes().size()="
             << options_init->entityTypes().size();
    for (const auto& v8_entity_type : options_init->entityTypes()) {
      result_set.insert(EntityTypeForHitTestFromEnum(v8_entity_type.AsEnum()));
    }
  } else {
    result_set.insert(device::mojom::blink::EntityTypeForHitTest::PLANE);
  }

  DVLOG(2) << __func__ << ": result_set.size()=" << result_set.size();
  DCHECK(!result_set.empty());

  Vector<device::mojom::blink::EntityTypeForHitTest> result(result_set);

  DVLOG(2) << __func__ << ": result.size()=" << result.size();
  return result;
}

template <typename T>
HashSet<uint64_t> GetIdsOfUnusedHitTestSources(
    const HeapHashMap<uint64_t, WeakMember<T>>& id_to_hit_test_source,
    const HashSet<uint64_t>& all_ids) {
  // Gather all IDs of unused hit test sources:
  HashSet<uint64_t> unused_hit_test_source_ids;
  for (auto& id : all_ids) {
    if (!base::Contains(id_to_hit_test_source, id)) {
      unused_hit_test_source_ids.insert(id);
    }
  }

  return unused_hit_test_source_ids;
}

V8XRDepthUsage::Enum DepthUsageToEnum(device::mojom::XRDepthUsage usage) {
  switch (usage) {
    case device::mojom::XRDepthUsage::kCPUOptimized:
      return V8XRDepthUsage::Enum::kCpuOptimized;
    case device::mojom::XRDepthUsage::kGPUOptimized:
      return V8XRDepthUsage::Enum::kGpuOptimized;
  }
  NOTREACHED();
}

V8XRDepthDataFormat::Enum DepthDataFormatToEnum(
    device::mojom::XRDepthDataFormat data_format) {
  switch (data_format) {
    case device::mojom::XRDepthDataFormat::kLuminanceAlpha:
      return V8XRDepthDataFormat::Enum::kLuminanceAlpha;
    case device::mojom::XRDepthDataFormat::kFloat32:
      return V8XRDepthDataFormat::Enum::kFloat32;
    case device::mojom::XRDepthDataFormat::kUnsignedShort:
      return V8XRDepthDataFormat::Enum::kUnsignedShort;
  }
  NOTREACHED();
}

}  // namespace

#define DCHECK_HIT_TEST_SOURCES()                                         \
  do {                                                                    \
    DCHECK_EQ(hit_test_source_ids_.size(),                                \
              hit_test_source_ids_to_hit_test_sources_.size());           \
    DCHECK_EQ(                                                            \
        hit_test_source_for_transient_input_ids_.size(),                  \
        hit_test_source_ids_to_transient_input_hit_test_sources_.size()); \
  } while (0)

constexpr char XRSession::kNoRigidTransformSpecified[];
constexpr char XRSession::kUnableToRetrieveMatrix[];
constexpr char XRSession::kNoSpaceSpecified[];
constexpr char XRSession::kAnchorsFeatureNotSupported[];
constexpr char XRSession::kPlanesFeatureNotSupported[];
constexpr char XRSession::kDepthSensingFeatureNotSupported[];
constexpr char XRSession::kRawCameraAccessFeatureNotSupported[];
constexpr char XRSession::kCannotCancelHitTestSource[];
constexpr char XRSession::kCannotReportPoses[];

class XRSession::XRSessionResizeObserverDelegate final
    : public ResizeObserver::Delegate {
 public:
  explicit XRSessionResizeObserverDelegate(XRSession* session)
      : session_(session) {
    DCHECK(session);
  }
  ~XRSessionResizeObserverDelegate() override = default;

  void OnResize(
      const HeapVector<Member<ResizeObserverEntry>>& entries) override {
    DCHECK_EQ(1u, entries.size());
    session_->UpdateCanvasDimensions(entries[0]->target());
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(session_);
    ResizeObserver::Delegate::Trace(visitor);
  }

 private:
  Member<XRSession> session_;
};

XRSession::MetricsReporter::MetricsReporter(
    mojo::Remote<device::mojom::blink::XRSessionMetricsRecorder> recorder)
    : recorder_(std::move(recorder)) {}

void XRSession::MetricsReporter::ReportFeatureUsed(
    device::mojom::blink::XRSessionFeature feature) {
  using device::mojom::blink::XRSessionFeature;

  // If we've already reported using this feature, no need to report again.
  if (!reported_features_.insert(feature).is_new_entry) {
    return;
  }

  switch (feature) {
    case XRSessionFeature::REF_SPACE_VIEWER:
      recorder_->ReportFeatureUsed(XRSessionFeature::REF_SPACE_VIEWER);
      break;
    case XRSessionFeature::REF_SPACE_LOCAL:
      recorder_->ReportFeatureUsed(XRSessionFeature::REF_SPACE_LOCAL);
      break;
    case XRSessionFeature::REF_SPACE_LOCAL_FLOOR:
      recorder_->ReportFeatureUsed(XRSessionFeature::REF_SPACE_LOCAL_FLOOR);
      break;
    case XRSessionFeature::REF_SPACE_BOUNDED_FLOOR:
      recorder_->ReportFeatureUsed(XRSessionFeature::REF_SPACE_BOUNDED_FLOOR);
      break;
    case XRSessionFeature::REF_SPACE_UNBOUNDED:
      recorder_->ReportFeatureUsed(XRSessionFeature::REF_SPACE_UNBOUNDED);
      break;
    case XRSessionFeature::DOM_OVERLAY:
    case XRSessionFeature::HIT_TEST:
    case XRSessionFeature::LIGHT_ESTIMATION:
    case XRSessionFeature::ANCHORS:
    case XRSessionFeature::CAMERA_ACCESS:
    case XRSessionFeature::PLANE_DETECTION:
    case XRSessionFeature::DEPTH:
    case XRSessionFeature::IMAGE_TRACKING:
    case XRSessionFeature::HAND_INPUT:
    case XRSessionFeature::SECONDARY_VIEWS:
    case XRSessionFeature::LAYERS:
    case XRSessionFeature::FRONT_FACING:
    case XRSessionFeature::WEBGPU:
      // Not recording metrics for these features currently.
      break;
  }
}

XRSession::XRSession(
    XRSystem* xr,
    mojo::PendingReceiver<device::mojom::blink::XRSessionClient>
        client_receiver,
    device::mojom::blink::XRSessionMode mode,
    device::mojom::blink::XREnvironmentBlendMode environment_blend_mode,
    device::mojom::blink::XRInteractionMode interaction_mode,
    device::mojom::blink::XRSessionDeviceConfigPtr device_config,
    bool sensorless_session,
    XRSessionFeatureSet enabled_feature_set,
    uint64_t trace_id)
    : ActiveScriptWrappable<XRSession>({}),
      frame_tracked_images_(
          MakeGarbageCollected<FrozenArray<XRImageTrackingResult>>()),
      xr_(xr),
      mode_(mode),
      environment_integration_(
          mode == device::mojom::blink::XRSessionMode::kImmersiveAr),
      device_config_(std::move(device_config)),
      enabled_feature_set_(std::move(enabled_feature_set)),
      plane_manager_(
          MakeGarbageCollected<XRPlaneManager>(base::PassKey<XRSession>{},
                                               this)),
      input_sources_(MakeGarbageCollected<XRInputSourceArray>()),
      client_receiver_(this, xr->GetExecutionContext()),
      callback_collection_(
          MakeGarbageCollected<XRFrameRequestCallbackCollection>(
              xr->GetExecutionContext())),
      supports_viewport_scaling_(immersive() &&
                                 device_config_->supports_viewport_scaling),
      sensorless_session_(sensorless_session),
      trace_id_(trace_id) {
  FrozenArray<IDLString>::VectorType enabled_features;
  for (const auto& feature : enabled_feature_set_) {
    enabled_features.push_back(XRSessionFeatureToString(feature));
  }
  enabled_features_ =
      MakeGarbageCollected<FrozenArray<IDLString>>(std::move(enabled_features));

  if (IsFeatureEnabled(device::mojom::XRSessionFeature::WEBGPU)) {
    graphics_api_ = XRGraphicsBinding::Api::kWebGPU;
  } else {
    graphics_api_ = XRGraphicsBinding::Api::kWebGL;
  }

  client_receiver_.Bind(
      std::move(client_receiver),
      xr->GetExecutionContext()->GetTaskRunner(TaskType::kMiscPlatformAPI));
  render_state_ = MakeGarbageCollected<XRRenderState>(immersive());
  // Ensure that frame focus is considered in the initial visibilityState.
  UpdateVisibilityState();

  // XRSessionDeviceConfig::views are in the unique position of being sent up
  // as an initial value that we should never need to inspect after the first
  // frame is sent to us, so we're okay to move it here, the other values on
  // device_config_ may be referenced throughout the lifetime of the session.
  UpdateViews(std::move(device_config_->views));

  DVLOG(2) << __func__
           << ": supports_viewport_scaling_=" << supports_viewport_scaling_;

  switch (environment_blend_mode) {
    case device::mojom::blink::XREnvironmentBlendMode::kOpaque:
      blend_mode_ = V8XREnvironmentBlendMode::Enum::kOpaque;
      break;
    case device::mojom::blink::XREnvironmentBlendMode::kAdditive:
      blend_mode_ = V8XREnvironmentBlendMode::Enum::kAdditive;
      break;
    case device::mojom::blink::XREnvironmentBlendMode::kAlphaBlend:
      blend_mode_ = V8XREnvironmentBlendMode::Enum::kAlphaBlend;
      break;
    default:
      NOTREACHED() << "Unknown environment blend mode: "
                   << environment_blend_mode;
  }

  switch (interaction_mode) {
    case device::mojom::blink::XRInteractionMode::kScreenSpace:
      interaction_mode_ = V8XRInteractionMode::Enum::kScreenSpace;
      break;
    case device::mojom::blink::XRInteractionMode::kWorldSpace:
      interaction_mode_ = V8XRInteractionMode::Enum::kWorldSpace;
      break;
  }

  if (device_config_->depth_configuration) {
    auto* depth_config = device_config_->depth_configuration.get();
    depth_usage_ = DepthUsageToEnum(depth_config->depth_usage);
    depth_data_format_ = DepthDataFormatToEnum(depth_config->depth_data_format);
  }
}

void XRSession::SetDOMOverlayElement(Element* element) {
  DVLOG(2) << __func__ << ": element=" << element;
  DCHECK(enabled_feature_set_.Contains(
      device::mojom::XRSessionFeature::DOM_OVERLAY));
  DCHECK(element);

  overlay_element_ = element;

  // Set up the domOverlayState attribute. This could be done lazily on first
  // access, but it's a tiny object and it's unclear if the memory that might
  // save during XR sessions is worth the code size increase to do so. This
  // should be revisited if the state gets more complex in the future.
  //
  // At this time, "screen" is the only supported DOM Overlay type.
  dom_overlay_state_ = MakeGarbageCollected<XRDOMOverlayState>(
      V8XRDOMOverlayType::Enum::kScreen);
}

V8XRVisibilityState XRSession::visibilityState() const {
  switch (visibility_state_) {
    case XRVisibilityState::VISIBLE:
      return V8XRVisibilityState(V8XRVisibilityState::Enum::kVisible);
    case XRVisibilityState::VISIBLE_BLURRED:
      return V8XRVisibilityState(V8XRVisibilityState::Enum::kVisibleBlurred);
    case XRVisibilityState::HIDDEN:
      return V8XRVisibilityState(V8XRVisibilityState::Enum::kHidden);
  }
}

const FrozenArray<IDLString>& XRSession::enabledFeatures() const {
  return *enabled_features_.Get();
}

XRAnchorSet* XRSession::TrackedAnchors() const {
  DVLOG(3) << __func__;

  if (!IsFeatureEnabled(device::mojom::XRSessionFeature::ANCHORS)) {
    return MakeGarbageCollected<XRAnchorSet>(HeapHashSet<Member<XRAnchor>>{});
  }

  HeapHashSet<Member<XRAnchor>> result;
  for (auto& anchor_id_and_anchor : anchor_ids_to_anchors_) {
    result.insert(anchor_id_and_anchor.value);
  }

  return MakeGarbageCollected<XRAnchorSet>(result);
}

bool XRSession::immersive() const {
  return mode_ == device::mojom::blink::XRSessionMode::kImmersiveVr ||
         mode_ == device::mojom::blink::XRSessionMode::kImmersiveAr;
}

ExecutionContext* XRSession::GetExecutionContext() const {
  return xr_->GetExecutionContext();
}

const AtomicString& XRSession::InterfaceName() const {
  return event_target_names::kXRSession;
}

void XRSession::updateRenderState(XRRenderStateInit* init,
                                  ExceptionState& exception_state) {
  if (ended_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSessionEnded);
    return;
  }

  if (immersive() && init->hasInlineVerticalFieldOfView()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInlineVerticalFOVNotSupported);
    return;
  }

  // Validate that any baseLayer provided was created with this session.
  if (init->hasBaseLayer() && init->baseLayer() &&
      init->baseLayer()->session() != this) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kIncompatibleLayer);
    return;
  }

  if (RuntimeEnabledFeatures::WebXRLayersCommonEnabled() && init->hasLayers() &&
      init->layers() && !init->layers()->empty()) {
    // Validate that we don't have both layers and baseLayer set.
    if (init->hasBaseLayer() && init->baseLayer()) {
      exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                        kBaseLayerAndLayers);
      return;
    }

    // Validate that the session was created with the layers feature enabled
    // when the user wishes to render multiple layers at once.
    if (init->layers()->size() > 1 &&
        !IsFeatureEnabled(device::mojom::XRSessionFeature::LAYERS)) {
      exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                        kMultiLayersNotEnabled);
      return;
    }

    HeapHashSet<Member<const XRLayer>> unique_layers;
    for (const XRLayer* layer : *init->layers()) {
      // Check for duplicate layers.
      if (!unique_layers.insert(layer).is_new_entry) {
        exception_state.ThrowTypeError(kDuplicateLayer);
        return;
      }

      // Validate that all layers were created with this session.
      if (layer->session() != this) {
        exception_state.ThrowTypeError(kIncompatibleLayer);
        return;
      }
    }
  }

  pending_render_state_.push_back(init);

  // Updating our render state may have caused us to be in a state where we
  // should be requesting frames again. Kick off a new frame request in case
  // there are any pending callbacks to flush them out.
  MaybeRequestFrame();
}

std::optional<V8XRDepthUsage> XRSession::depthUsage(
    ExceptionState& exception_state) {
  if (!device_config_->depth_configuration) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kDepthSensingFeatureNotSupported);
    return std::nullopt;
  }

  return V8XRDepthUsage(depth_usage_);
}

std::optional<V8XRDepthDataFormat> XRSession::depthDataFormat(
    ExceptionState& exception_state) {
  if (!device_config_->depth_configuration) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kDepthSensingFeatureNotSupported);
    return std::nullopt;
  }

  return V8XRDepthDataFormat(depth_data_format_);
}

void XRSession::UpdateViews(Vector<device::mojom::blink::XRViewPtr> views) {
  // TODO(bajones): For now we assume that immersive sessions render a stereo
  // pair of views and non-immersive sessions render a single view. That doesn't
  // always hold true, however, so the view configuration should ultimately come
  // from the backing service. See also XRWebGLLayer::UpdateViewports() which
  // assumes that the views are arranged as follows.
  if (immersive()) {
    // In immersive mode the projection and view matrices must be aligned with
    // the device's physical optics.

    // If there are no views provided for this frame, keep the views we
    // currently have.
    if (views.empty()) {
      return;
    }

    // Views shouldn't be re-created on each frame because they contain
    // viewport scaling information, such as requested viewport scales.
    // However, if the number of views changed or if the order of the views
    // changed, we should recreate the views since we aren't able to match
    // the old views to the new views.
    bool create_views = false;
    bool views_resized = false;
    if (views_.size() != views.size()) {
      views_.clear();
      views_.resize(views.size());
      create_views = true;

      // If we're changing the number of views, then we need to notify the base
      // layer that it should resize; but don't do that until the new views have
      // been created and the size known. Since we may also re-create views
      // if the eyes come in a different order, use a separate bool to track if
      // a resize has occurred to cut down on noise to the base layer.
      views_resized = true;
    }

    for (wtf_size_t i = 0; !create_views && i < views.size(); ++i) {
      if (views_[i]->Eye() != views[i]->eye) {
        create_views = true;
      }
    }

    for (wtf_size_t i = 0; i < views.size(); ++i) {
      if (create_views) {
        views_[i] = MakeGarbageCollected<XRViewData>(
            i, std::move(views[i]), render_state_->depthNear(),
            render_state_->depthFar(), *device_config_, enabled_feature_set_,
            graphics_api_);
      } else {
        views_[i]->UpdateView(std::move(views[i]), render_state_->depthNear(),
                              render_state_->depthFar());
      }
    }

    XRLayer* base_layer = render_state_->GetFirstLayer();
    if (views_resized && base_layer) {
      base_layer->OnResize();
    }
  } else {  // Inline
    UpdateInlineView();
  }
}

void XRSession::UpdateStageParameters(
    uint32_t stage_parameters_id,
    const device::mojom::blink::VRStageParametersPtr& stage_parameters) {
  // Only update if the ID is different, indicating a change.
  if (stage_parameters_id_ != stage_parameters_id) {
    stage_parameters_id_ = stage_parameters_id;
    stage_parameters_ = stage_parameters.Clone();
  }
}

ScriptPromise<IDLUndefined> XRSession::updateTargetFrameRate(
    float rate,
    ExceptionState& exception_state) {
  exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                    kSessionNotHaveSetFrameRate);
  return EmptyPromise();
}

ScriptPromise<XRReferenceSpace> XRSession::requestReferenceSpace(
    ScriptState* script_state,
    const V8XRReferenceSpaceType& type,
    ExceptionState& exception_state) {
  DVLOG(2) << __func__ << ": type=" << type.AsCStr();

  if (ended_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSessionEnded);
    return EmptyPromise();
  }

  device::mojom::blink::XRReferenceSpaceType requested_type =
      XRReferenceSpace::V8EnumToReferenceSpaceType(type.AsEnum());

  if (sensorless_session_ &&
      requested_type != device::mojom::blink::XRReferenceSpaceType::kViewer) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      kReferenceSpaceNotSupported);
    return EmptyPromise();
  }

  // If the session feature required by this reference space type is not
  // enabled, reject the session.
  auto type_as_feature = MapReferenceSpaceTypeToFeature(requested_type);
  if (!type_as_feature) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      kReferenceSpaceNotSupported);
    return EmptyPromise();
  }

  // Report attempt to use this feature
  if (metrics_reporter_) {
    metrics_reporter_->ReportFeatureUsed(type_as_feature.value());
  }

  if (!IsFeatureEnabled(type_as_feature.value())) {
    DVLOG(2) << __func__ << ": feature not enabled, type=" << type.AsCStr();
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      kReferenceSpaceNotSupported);
    return EmptyPromise();
  }

  XRReferenceSpace* reference_space = nullptr;
  switch (requested_type) {
    case device::mojom::blink::XRReferenceSpaceType::kViewer:
    case device::mojom::blink::XRReferenceSpaceType::kLocal:
    case device::mojom::blink::XRReferenceSpaceType::kLocalFloor:
      reference_space =
          MakeGarbageCollected<XRReferenceSpace>(this, requested_type);
      break;
    case device::mojom::blink::XRReferenceSpaceType::kBoundedFloor: {
      if (immersive()) {
        reference_space = MakeGarbageCollected<XRBoundedReferenceSpace>(this);
      }
      break;
    }
    case device::mojom::blink::XRReferenceSpaceType::kUnbounded:
      if (immersive()) {
        reference_space =
            MakeGarbageCollected<XRReferenceSpace>(this, requested_type);
      }
      break;
  }

  // If the above switch statement failed to assign to reference_space,
  // it's because the reference space wasn't supported by the device.
  if (!reference_space) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      kReferenceSpaceNotSupported);
    return EmptyPromise();
  }

  DCHECK(reference_space);
  reference_spaces_.push_back(reference_space);
  return ToResolvedPromise<XRReferenceSpace>(script_state, reference_space);
}

ScriptPromise<XRAnchor> XRSession::CreateAnchorHelper(
    ScriptState* script_state,
    const gfx::Transform& native_origin_from_anchor,
    const device::mojom::blink::XRNativeOriginInformationPtr&
        native_origin_information,
    std::optional<uint64_t> maybe_plane_id,
    ExceptionState& exception_state) {
  DVLOG(2) << __func__;

  if (ended_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSessionEnded);
    return EmptyPromise();
  }

  // Reject the promise if device doesn't support the anchors API.
  if (!xr_->xrEnvironmentProviderRemote()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        kFeatureNotSupportedByDevicePrefix +
            XRSessionFeatureToString(device::mojom::XRSessionFeature::ANCHORS));
    return EmptyPromise();
  }

  auto maybe_native_origin_from_anchor_pose =
      CreatePose(native_origin_from_anchor);

  if (!maybe_native_origin_from_anchor_pose) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kUnableToDecomposeMatrix);
    return EmptyPromise();
  }

  DVLOG(3) << __func__
           << ": maybe_native_origin_from_anchor_pose->orientation()= "
           << maybe_native_origin_from_anchor_pose->orientation().ToString()
           << ", maybe_native_origin_from_anchor_pose->position()= "
           << maybe_native_origin_from_anchor_pose->position().ToString();

  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<XRAnchor>>(
      script_state, exception_state.GetContext());
  auto promise = resolver->Promise();

  if (maybe_plane_id) {
    xr_->xrEnvironmentProviderRemote()->CreatePlaneAnchor(
        native_origin_information->Clone(),
        *maybe_native_origin_from_anchor_pose, *maybe_plane_id,
        resolver->WrapCallbackInScriptScope(WTF::BindOnce(
            &XRSession::OnCreateAnchorResult, WrapPersistent(this))));
  } else {
    xr_->xrEnvironmentProviderRemote()->CreateAnchor(
        native_origin_information->Clone(),
        *maybe_native_origin_from_anchor_pose,
        resolver->WrapCallbackInScriptScope(WTF::BindOnce(
            &XRSession::OnCreateAnchorResult, WrapPersistent(this))));
  }

  create_anchor_promises_.insert(resolver);

  return promise;
}

std::optional<XRSession::ReferenceSpaceInformation>
XRSession::GetStationaryReferenceSpace() const {
  // For anchor creation, we should first attempt to use the local space as it
  // is supposed to be more stable, but if that is unavailable, we can try using
  // unbounded space. Otherwise, there's not much we can do & we have to return
  // nullopt.

  // Try to get mojo_from_local:
  auto reference_space_type = device::mojom::XRReferenceSpaceType::kLocal;
  auto mojo_from_space = GetMojoFrom(reference_space_type);

  if (!mojo_from_space) {
    // Local space is not available, try to get mojo_from_unbounded:
    reference_space_type = device::mojom::XRReferenceSpaceType::kUnbounded;
    mojo_from_space = GetMojoFrom(reference_space_type);
  }

  if (!mojo_from_space) {
    // Unbounded is also not available.
    return std::nullopt;
  }

  ReferenceSpaceInformation result;
  result.mojo_from_space = *mojo_from_space;
  result.native_origin =
      device::mojom::blink::XRNativeOriginInformation::NewReferenceSpaceType(
          reference_space_type);
  return result;
}

void XRSession::ScheduleVideoFrameCallbacksExecution(
    ExecuteVfcCallback execute_vfc_callback) {
  vfc_execution_queue_.push_back(std::move(execute_vfc_callback));
  MaybeRequestFrame();
}

base::TimeDelta XRSession::TakeAnimationFrameTimerAverage() {
  return page_animation_frame_timer_.TakeAverageMicroseconds();
}

void XRSession::ExecuteVideoFrameCallbacks(double timestamp) {
  Vector<ExecuteVfcCallback> execute_vfc_callbacks;
  vfc_execution_queue_.swap(execute_vfc_callbacks);
  for (auto& callback : execute_vfc_callbacks)
    std::move(callback).Run(timestamp);
}

int XRSession::requestAnimationFrame(V8XRFrameRequestCallback* callback) {
  DVLOG(3) << __func__;

  TRACE_EVENT0("gpu", __func__);
  // Don't allow any new frame requests once the session is ended.
  if (ended_)
    return 
"""


```