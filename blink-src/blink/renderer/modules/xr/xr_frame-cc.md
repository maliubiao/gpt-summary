Response:
Let's break down the thought process for analyzing this `XRFrame.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relationship to web technologies, logical reasoning examples, potential user errors, and debugging clues related to user actions.

2. **Identify the Core Class:** The file name `xr_frame.cc` and the initial `#include` directives immediately point to the `XRFrame` class as the central element. This is the primary focus.

3. **Analyze the Includes:** The `#include` statements provide valuable context. They reveal the dependencies and therefore hint at the responsibilities of `XRFrame`:
    * **Core DOM:** `DOMException` indicates interaction with standard web platform exceptions.
    * **XR Module Specific:**  `XRHitTestResult`, `XRInputSource`, `XRReferenceSpace`, etc., clearly indicate this file is part of the WebXR API implementation.
    * **Platform Bindings:** `FrozenArray` suggests interaction with JavaScript arrays.
    * **Internal Chromium:**  `third_party/blink/renderer/platform/bindings/exception_state.h` is internal infrastructure for handling exceptions in the Blink rendering engine.

4. **Examine the Class Members and Constructor:**
    * `session_`:  A pointer to an `XRSession`. This is crucial. An `XRFrame` is always associated with an `XRSession`.
    * `is_animation_frame_`: A boolean. This hints at different types of frames and their associated constraints.

5. **Analyze Public Methods (the API surface):** This is where the core functionality lies. Go through each public method and understand its purpose. Look for:
    * **`get...` methods:** These are usually for retrieving information. Pay attention to the types they return (`XRViewerPose`, `XRAnchorSet`, `XRPose`, etc.).
    * **Methods taking `ExceptionState&`:**  These methods can throw exceptions, indicating potential error conditions.
    * **Methods interacting with other XR objects:**  `getViewerPose(XRReferenceSpace*)`, `getPose(XRSpace*, XRSpace*)`, `createAnchor(XRSpace*)`, etc. These show how `XRFrame` interacts with other parts of the WebXR API.
    * **Methods related to hit testing:** `getHitTestResults`, `getHitTestResultsForTransientInput`.
    * **Methods related to anchors:** `createAnchor`, `trackedAnchors`.
    * **Methods related to depth:** `getDepthInformation`.
    * **Methods related to input:** `getJointPose`, `fillJointRadii`, `fillPoses`.
    * **Lifecycle methods:** `Deactivate`, `IsActive`.

6. **Analyze the Internal Logic of Key Methods:** Focus on the `getViewerPose`, `getPose`, and `createAnchor` methods as they seem central. Look for:
    * **Checks for `is_active_` and `is_animation_frame_`:**  These enforce valid usage.
    * **Session validation (`IsSameSession`)**:  Ensuring consistency between XR objects.
    * **Error handling (throwing `DOMException`)**:  Identifying potential error conditions and how they are reported to the web page.
    * **Matrix transformations:** The code deals with `gfx::Transform` objects, indicating manipulation of 3D poses.
    * **Interaction with the `session_` object:**  `session_->CanReportPoses()`, `session_->TrackedAnchors()`, `session_->CreateAnchorHelper()`, etc.

7. **Identify Relationships with Web Technologies:**
    * **JavaScript:** The return types of methods (e.g., `XRViewerPose*`) correspond to JavaScript objects exposed by the WebXR API. The presence of `ScriptPromise` indicates asynchronous operations.
    * **HTML:** While not directly manipulating HTML, the results of `XRFrame` methods (like the position of objects in the XR scene) are used to render content within the `<canvas>` element where WebXR is typically used.
    * **CSS:**  Again, not direct manipulation, but the transformations calculated here affect how elements are rendered, and CSS properties could indirectly influence the XR experience (e.g., styling elements overlaid on the XR view).

8. **Construct Examples for Logical Reasoning:** Choose methods with clear inputs and outputs and demonstrate how the code behaves under specific conditions. Think about:
    * **Successful cases:**  Valid inputs leading to expected outputs.
    * **Error cases:** Invalid inputs or state leading to exceptions or null returns.

9. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make when using the WebXR API. Relate these errors back to the checks and exceptions in the `XRFrame.cc` code.

10. **Trace User Actions for Debugging:**  Imagine a user interacting with a WebXR application. Describe the sequence of JavaScript calls that would eventually lead to the execution of methods in `XRFrame.cc`. This helps understand the context and potential entry points for debugging.

11. **Review and Organize:**  Structure the findings logically, using clear headings and bullet points. Ensure the explanation is comprehensive and addresses all aspects of the original request. Refine the language for clarity and accuracy.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus only on the direct functionality of each method.
* **Correction:** Realize the importance of connecting the C++ code to the JavaScript API and the overall WebXR workflow.
* **Initial thought:**  List the methods without much explanation.
* **Correction:** Elaborate on the purpose of each method, its parameters, and return values. Explain the error conditions and exception types.
* **Initial thought:** Provide simple examples.
* **Correction:**  Create more detailed and realistic examples that demonstrate different scenarios and edge cases.
* **Initial thought:**  Focus solely on the code.
* **Correction:** Consider the user perspective and how they might interact with the API, leading to potential errors.

By following this iterative process of analysis, understanding dependencies, examining the API surface, and connecting the code to the broader web development context, we can arrive at a comprehensive and accurate description of the `XRFrame.cc` file's functionality.
这是对 `blink/renderer/modules/xr/xr_frame.cc` 文件的功能进行的详细分析。

**文件功能概述:**

`XRFrame.cc` 文件定义了 Blink 渲染引擎中 `XRFrame` 类的实现。`XRFrame` 对象代表了 WebXR 会话中的一个特定时刻。它提供了在那个时刻获取 XR 设备状态（例如，头部姿势、手部追踪、环境信息）的方法，并允许执行与该时刻相关的操作（例如，创建锚点）。

**核心功能点:**

1. **获取姿势 (Poses):**
   - `getViewerPose(XRReferenceSpace*)`: 获取相对于指定 `XRReferenceSpace` 的观察者 (Viewer，通常是用户的头部) 的姿势（位置和方向）。
   - `getPose(XRSpace*, XRSpace*)`: 获取一个 `XRSpace` 相对于另一个 `XRSpace` 的姿势。`XRSpace` 可以是各种类型的空间，如本地空间、有界空间等。
   - `getJointPose(XRJointSpace*, XRSpace*)`: 获取手部关节 (`XRJointSpace`) 相对于指定 `XRSpace` 的姿势。
   - `fillPoses(const HeapVector<Member<XRSpace>>&, XRSpace*, NotShared<DOMFloat32Array>)`: 批量获取多个 `XRSpace` 相对于一个基准 `XRSpace` 的姿势，并将结果填充到 `DOMFloat32Array` 中。

2. **访问 XR 数据:**
   - `trackedAnchors()`: 返回当前帧追踪到的锚点 (`XRAnchor`) 集合。
   - `detectedPlanes()`: 返回当前帧检测到的平面 (`XRPlaneSet`) 集合。
   - `getLightEstimate(XRLightProbe*)`: 获取指定光照探针 (`XRLightProbe`) 提供的光照估计信息。
   - `getDepthInformation(XRView*)`: 获取指定视图 (`XRView`) 的深度信息，用于表示场景的深度。
   - `getImageTrackingResults()`: 返回当前帧图像追踪的结果。

3. **执行操作:**
   - `createAnchor(ScriptState*, XRRigidTransform*, XRSpace*)`: 在指定 `XRSpace` 的基础上，根据给定的偏移量创建一个新的锚点 (`XRAnchor`)。

4. **处理 Hit Testing (碰撞测试):**
   - `getHitTestResults(XRHitTestSource*)`: 获取由 `XRHitTestSource` 发起的碰撞测试的结果。
   - `getHitTestResultsForTransientInput(XRTransientInputHitTestSource*)`: 获取针对瞬态输入（如手势）的碰撞测试结果。

5. **生命周期管理:**
   - `XRFrame(XRSession*, bool)`: `XRFrame` 类的构造函数，与特定的 `XRSession` 关联。
   - `Deactivate()`: 将 `XRFrame` 标记为非活跃状态。
   - `IsActive()`: 检查 `XRFrame` 是否处于活跃状态。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`XRFrame.cc` 是 Blink 渲染引擎的 C++ 代码，它直接为 WebXR API 的 JavaScript 接口提供底层实现。当 Web 开发者在 JavaScript 中调用 WebXR API 时，最终会调用到这些 C++ 代码。

* **JavaScript:**
    - **获取姿势:** JavaScript 代码会调用 `XRFrame` 对象的 `getViewerPose()`, `getPose()` 等方法来获取设备和虚拟物体的姿势信息，用于在 3D 场景中渲染内容。
      ```javascript
      // 获取相对于本地空间的观察者姿势
      let viewerPose = xrFrame.getViewerPose(xrSession.requestReferenceSpace('local'));
      if (viewerPose) {
        // 使用 viewerPose.transform 来定位和旋转相机
        console.log("Viewer Position:", viewerPose.transform.position);
      }

      // 获取一个 XRSpace 相对于另一个 XRSpace 的姿势
      let targetSpacePose = xrFrame.getPose(targetSpace, baseSpace);
      if (targetSpacePose) {
        console.log("Target Space Position:", targetSpacePose.transform.position);
      }
      ```
    - **访问 XR 数据:** JavaScript 可以调用 `trackedAnchors`, `detectedPlanes`, `getLightEstimate` 等方法获取环境信息。
      ```javascript
      let anchors = xrFrame.trackedAnchors;
      anchors.forEach(anchor => {
        console.log("Tracked Anchor ID:", anchor.anchorId);
      });

      let lightEstimate = xrFrame.getLightEstimate(lightProbe);
      if (lightEstimate) {
        console.log("Ambient Light Intensity:", lightEstimate.primaryLightIntensity);
      }
      ```
    - **执行操作:** JavaScript 调用 `createAnchor()` 方法来在虚拟场景中创建持久化的锚点。
      ```javascript
      let transform = new XRRigidTransform({x: 0, y: 0, z: -1});
      xrFrame.createAnchor(transform, localSpace).then(anchor => {
        console.log("Created Anchor ID:", anchor.anchorId);
      });
      ```
    - **处理 Hit Testing:** JavaScript 使用 `XRFrame` 的 `getHitTestResults()` 方法来获取用户交互（如点击屏幕）在虚拟场景中的位置信息。
      ```javascript
      xrSession.requestHitTestSource({ space: viewerSpace }).then(hitTestSource => {
        xrSession.requestAnimationFrame((time, xrFrame) => {
          let hitTestResults = xrFrame.getHitTestResults(hitTestSource);
          if (hitTestResults.length > 0) {
            console.log("Hit Point:", hitTestResults[0].getPose(localSpace).transform.position);
          }
        });
      });
      ```

* **HTML:**  HTML 主要通过 `<canvas>` 元素来承载 WebXR 内容。JavaScript 代码使用 WebGL 或 WebGPU API 在 Canvas 上渲染基于 `XRFrame` 提供的数据构建的 3D 场景。`XRFrame` 本身不直接操作 HTML 元素。

* **CSS:** CSS 可以用于样式化包含 WebXR 内容的 HTML 页面，例如控制 Canvas 的布局和样式，或者样式化与 WebXR 体验相关的其他 UI 元素。`XRFrame` 不直接与 CSS 交互。

**逻辑推理的假设输入与输出:**

**示例 1: `getViewerPose()`**

* **假设输入:**
    * `XRFrame` 对象处于活跃状态 (`is_active_ = true`) 并且是动画帧 (`is_animation_frame_ = true`)。
    * 传入的 `XRReferenceSpace` 对象 (`reference_space`) 与 `XRFrame` 所属的 `XRSession` 相同。
    * `reference_space` 的 `NativeFromMojo()` 和 `OffsetFromViewer()` 方法都返回有效的、可逆的变换矩阵。
* **预期输出:** 返回一个 `XRViewerPose` 对象，其中包含了观察者在当前帧相对于指定 `XRReferenceSpace` 的姿势信息。如果任何前提条件不满足（例如，帧未激活），则会抛出 `DOMException` 或返回 `nullptr`。

**示例 2: `getPose(space, basespace)`**

* **假设输入:**
    * `XRFrame` 对象处于活跃状态。
    * `space` 和 `basespace` 都是有效的 `XRSpace` 对象，并且属于同一个 `XRSession`。
* **预期输出:** 返回一个 `XRPose` 对象，表示 `space` 相对于 `basespace` 的姿势。如果 `space` 和 `basespace` 是同一个对象，则返回一个单位变换的 `XRPose`。如果会话无法报告姿势，则会抛出 `SecurityError`。

**用户或编程常见的使用错误及举例说明:**

1. **在非活跃帧上调用方法:** 用户代码可能会尝试在一个已经结束的帧上获取姿势或执行其他操作。
   ```javascript
   xrSession.requestAnimationFrame((time, xrFrame) => {
     // ... 获取姿势等操作 ...
   });
   // ... 稍后 ...
   // 错误：尝试在之前的帧对象上操作
   let pose = previousXRFrame.getViewerPose(localSpace); // 可能导致错误
   ```
   **错误信息 (C++ 中抛出):**  `kInactiveFrame` ("XRFrame passed in to the method is no longer active.")

2. **传入不同会话的 XRSpace:**  尝试在一个 `XRFrame` 中使用属于不同 `XRSession` 的 `XRSpace` 对象。
   ```javascript
   // session1 和 session2 是不同的 XRSession 对象
   session1.requestAnimationFrame((time, frame1) => {
     session2.requestReferenceSpace('local').then(space2 => {
       // 错误：尝试获取 frame1 中 space2 的姿势
       let pose = frame1.getPose(mySpaceFromSession1, space2); // 可能导致错误
     });
   });
   ```
   **错误信息 (C++ 中抛出):** `kSessionMismatch` ("XRSpace and XRFrame sessions do not match.")

3. **在非动画帧上调用需要动画帧的方法:** 某些方法（例如，获取观察者姿势）只能在动画帧 (`requestAnimationFrame` 的回调中提供的 `XRFrame`) 上调用。
   ```javascript
   // 假设在一个非动画帧的回调中
   let pose = nonAnimationFrame.getViewerPose(localSpace); // 错误
   ```
   **错误信息 (C++ 中抛出):** `kNonAnimationFrame` ("Method can only be called on an XRFrame acquired from requestAnimationFrame.")

4. **HitTestSource 已取消后尝试获取结果:**  如果 `XRHitTestSource` 被取消，则不能再获取其结果。
   ```javascript
   let hitTestSource;
   xrSession.requestHitTestSource({ space: viewerSpace }).then(source => {
     hitTestSource = source;
     // ... 一段时间后 ...
     hitTestSource.cancel();
     xrSession.requestAnimationFrame((time, xrFrame) => {
       let results = xrFrame.getHitTestResults(hitTestSource); // 错误
     });
   });
   ```
   **错误信息 (C++ 中抛出):** `kHitTestSourceUnavailable` ("Unable to obtain hit test results for specified hit test source. Ensure that it was not already canceled.")

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动 WebXR 会话:**  用户访问一个启用了 WebXR 的网页，浏览器请求访问 XR 设备，用户同意后，创建一个 `XRSession` 对象。
2. **应用请求动画帧:**  JavaScript 代码调用 `xrSession.requestAnimationFrame(callback)` 来请求浏览器在下一次渲染循环中执行回调函数。
3. **浏览器创建 XRFrame:** 在下一次渲染循环开始时，浏览器创建一个与当前时间戳关联的 `XRFrame` 对象，并将其作为参数传递给 `requestAnimationFrame` 的回调函数。
4. **JavaScript 调用 XRFrame 的方法:** 在回调函数中，开发者编写的 JavaScript 代码会调用 `XRFrame` 对象的方法，例如 `getViewerPose()`, `getHitTestResults()`, `createAnchor()` 等。
5. **Blink 引擎执行 C++ 代码:**  当 JavaScript 调用这些方法时，Blink 引擎会将调用转发到相应的 C++ 实现，即 `XRFrame.cc` 中定义的方法。

**调试线索:**

* **检查 `XRFrame` 的 `is_active_` 和 `is_animation_frame_` 状态:** 确保在调用方法时，`XRFrame` 处于预期的活跃和动画帧状态。
* **验证 `XRSpace` 对象的 `session()` 是否与 `XRFrame` 的 `session_()` 匹配:**  确保操作中使用的 `XRSpace` 对象属于同一个 `XRSession`。
* **确认 `HitTestSource` 是否仍然有效:** 在调用 `getHitTestResults()` 之前，检查 `HitTestSource` 是否已被取消。
* **查看控制台错误信息:**  Blink 引擎抛出的 `DOMException` 或 `SecurityError` 包含有用的错误消息，可以帮助定位问题。
* **使用开发者工具断点调试:** 在 JavaScript 代码中设置断点，逐步执行，查看 `XRFrame` 对象及其相关对象的属性值，以及方法调用的返回值。
* **检查 WebXR 设备状态和权限:** 确保 XR 设备正常工作，并且网页拥有必要的设备访问权限。

总而言之，`XRFrame.cc` 文件是 WebXR API 在 Chromium Blink 引擎中的核心实现之一，负责管理和提供与特定 XR 渲染帧相关的信息和操作，是连接 JavaScript API 和底层 XR 设备的关键桥梁。理解其功能和潜在的错误使用场景对于开发健壮的 WebXR 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/xr/xr_frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/xr/xr_frame.h"

#include "third_party/blink/renderer/bindings/core/v8/frozen_array.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/modules/xr/xr_hit_test_result.h"
#include "third_party/blink/renderer/modules/xr/xr_hit_test_source.h"
#include "third_party/blink/renderer/modules/xr/xr_input_source.h"
#include "third_party/blink/renderer/modules/xr/xr_joint_space.h"
#include "third_party/blink/renderer/modules/xr/xr_light_estimate.h"
#include "third_party/blink/renderer/modules/xr/xr_light_probe.h"
#include "third_party/blink/renderer/modules/xr/xr_plane_set.h"
#include "third_party/blink/renderer/modules/xr/xr_reference_space.h"
#include "third_party/blink/renderer/modules/xr/xr_session.h"
#include "third_party/blink/renderer/modules/xr/xr_transient_input_hit_test_result.h"
#include "third_party/blink/renderer/modules/xr/xr_transient_input_hit_test_source.h"
#include "third_party/blink/renderer/modules/xr/xr_view.h"
#include "third_party/blink/renderer/modules/xr/xr_viewer_pose.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

namespace blink {

namespace {

const char kInvalidView[] =
    "XRView passed in to the method did not originate from current XRFrame.";

const char kSessionMismatch[] = "XRSpace and XRFrame sessions do not match.";

const char kHitTestSourceUnavailable[] =
    "Unable to obtain hit test results for specified hit test source. Ensure "
    "that it was not already canceled.";

const char kCannotObtainNativeOrigin[] =
    "The operation was unable to obtain necessary information and could not be "
    "completed.";

const char kSpacesSequenceTooLarge[] =
    "Insufficient buffer capacity for pose results.";

const char kMismatchedBufferSizes[] = "Buffer sizes must be equal";

std::optional<uint64_t> GetPlaneId(
    const device::mojom::blink::XRNativeOriginInformation& native_origin) {
  if (native_origin.is_plane_id()) {
    return native_origin.get_plane_id();
  }

  return std::nullopt;
}

}  // namespace

constexpr char XRFrame::kInactiveFrame[];
constexpr char XRFrame::kNonAnimationFrame[];

XRFrame::XRFrame(XRSession* session, bool is_animation_frame)
    : session_(session), is_animation_frame_(is_animation_frame) {}

XRViewerPose* XRFrame::getViewerPose(XRReferenceSpace* reference_space,
                                     ExceptionState& exception_state) {
  DCHECK(reference_space);

  DVLOG(3) << __func__ << ": is_active_=" << is_active_
           << ", is_animation_frame_=" << is_animation_frame_
           << ", reference_space->ToString()=" << reference_space->ToString();

  if (!is_active_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInactiveFrame);
    return nullptr;
  }

  if (!is_animation_frame_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kNonAnimationFrame);
    return nullptr;
  }

  // Must use a reference space created from the same session.
  if (!IsSameSession(reference_space->session(), exception_state)) {
    return nullptr;
  }

  if (!session_->CanReportPoses()) {
    exception_state.ThrowSecurityError(XRSession::kCannotReportPoses);
    return nullptr;
  }

  session_->LogGetPose();

  std::optional<gfx::Transform> native_from_mojo =
      reference_space->NativeFromMojo();
  if (!native_from_mojo) {
    DVLOG(1) << __func__ << ": native_from_mojo is invalid";
    return nullptr;
  }

  gfx::Transform ref_space_from_mojo =
      reference_space->OffsetFromNativeMatrix();
  ref_space_from_mojo.PreConcat(*native_from_mojo);

  // Can only update an XRViewerPose's views with an invertible matrix.
  if (!ref_space_from_mojo.IsInvertible()) {
    DVLOG(1) << __func__ << ": ref_space_from_mojo is not invertible";
    return nullptr;
  }

  std::optional<gfx::Transform> offset_space_from_viewer =
      reference_space->OffsetFromViewer();

  // Can only update an XRViewerPose's views with an invertible matrix.
  if (!(offset_space_from_viewer && offset_space_from_viewer->IsInvertible())) {
    DVLOG(1) << __func__
             << ": offset_space_from_viewer is invalid or not invertible - "
                "returning nullptr, offset_space_from_viewer valid? "
             << (offset_space_from_viewer ? true : false);
    return nullptr;
  }

  device::mojom::blink::XRReferenceSpaceType type = reference_space->GetType();

  // If the |reference_space| type is kViewer, we know that the pose is not
  // emulated. Otherwise, ask the session if the poses are emulated or not.
  return MakeGarbageCollected<XRViewerPose>(
      this, ref_space_from_mojo, *offset_space_from_viewer,
      (type == device::mojom::blink::XRReferenceSpaceType::kViewer)
          ? false
          : session_->EmulatedPosition());
}

XRAnchorSet* XRFrame::trackedAnchors() const {
  return session_->TrackedAnchors();
}

XRPlaneSet* XRFrame::detectedPlanes(ExceptionState& exception_state) const {
  DVLOG(3) << __func__;

  if (!is_active_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInactiveFrame);
    return nullptr;
  }

  return session_->GetDetectedPlanes();
}

XRLightEstimate* XRFrame::getLightEstimate(
    XRLightProbe* light_probe,
    ExceptionState& exception_state) const {
  if (!is_active_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInactiveFrame);
    return nullptr;
  }

  if (!is_animation_frame_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kNonAnimationFrame);
    return nullptr;
  }

  if (!light_probe) {
    return nullptr;
  }

  // Must use a light probe created from the same session.
  if (!IsSameSession(light_probe->session(), exception_state)) {
    return nullptr;
  }

  return light_probe->getLightEstimate();
}

XRCPUDepthInformation* XRFrame::getDepthInformation(
    XRView* view,
    ExceptionState& exception_state) const {
  DVLOG(2) << __func__;

  if (!session_->IsFeatureEnabled(device::mojom::XRSessionFeature::DEPTH)) {
    DVLOG(2) << __func__ << ": depth sensing is not enabled on a session";
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        XRSession::kDepthSensingFeatureNotSupported);
    return nullptr;
  }

  if (!is_active_) {
    DVLOG(2) << __func__ << ": frame is not active";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInactiveFrame);
    return nullptr;
  }

  if (!is_animation_frame_) {
    DVLOG(2) << __func__ << ": frame is not animating";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kNonAnimationFrame);
    return nullptr;
  }

  if (this != view->frame()) {
    DVLOG(2) << __func__ << ": view did not originate from the frame";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInvalidView);
    return nullptr;
  }

  return view->GetCpuDepthInformation(exception_state);
}

XRPose* XRFrame::getPose(XRSpace* space,
                         XRSpace* basespace,
                         ExceptionState& exception_state) {
  DCHECK(space);
  DCHECK(basespace);

  DVLOG(2) << __func__ << ": is_active=" << is_active_
           << ", space->ToString()=" << space->ToString()
           << ", basespace->ToString()=" << basespace->ToString();

  if (!is_active_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInactiveFrame);
    return nullptr;
  }

  if (!IsSameSession(space->session(), exception_state) ||
      !IsSameSession(basespace->session(), exception_state)) {
    return nullptr;
  }

  if (!session_->CanReportPoses()) {
    exception_state.ThrowSecurityError(XRSession::kCannotReportPoses);
    return nullptr;
  }

  // If the addresses match, the pose between the spaces is definitely an
  // identity & we can skip the rest of the logic. The pose is not emulated.
  if (space == basespace) {
    DVLOG(3) << __func__ << ": addresses match, returning identity";
    return MakeGarbageCollected<XRPose>(gfx::Transform{}, false);
  }

  // If the native origins match, the pose between the spaces is fixed and
  // depends only on their offsets from the same native origin - we can compute
  // it here and skip the rest of the logic. The pose is not emulated.
  if (space->NativeOrigin() == basespace->NativeOrigin()) {
    DVLOG(3) << __func__
             << ": native origins match, returning a pose based on offesets";
    auto basespace_from_native_origin = basespace->OffsetFromNativeMatrix();
    auto native_origin_from_space = space->NativeFromOffsetMatrix();

    return MakeGarbageCollected<XRPose>(
        basespace_from_native_origin * native_origin_from_space, false);
  }

  return space->getPose(basespace);
}

void XRFrame::Deactivate() {
  is_active_ = false;
  is_animation_frame_ = false;
}

bool XRFrame::IsActive() const {
  return is_active_;
}

const FrozenArray<XRHitTestResult>& XRFrame::getHitTestResults(
    XRHitTestSource* hit_test_source,
    ExceptionState& exception_state) {
  if (!hit_test_source ||
      !session_->ValidateHitTestSourceExists(hit_test_source)) {
    // This should only happen when hit test source was already canceled.
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kHitTestSourceUnavailable);
    return *MakeGarbageCollected<FrozenArray<XRHitTestResult>>();
  }

  return *MakeGarbageCollected<FrozenArray<XRHitTestResult>>(
      hit_test_source->Results());
}

const FrozenArray<XRTransientInputHitTestResult>&
XRFrame::getHitTestResultsForTransientInput(
    XRTransientInputHitTestSource* hit_test_source,
    ExceptionState& exception_state) {
  if (!hit_test_source ||
      !session_->ValidateHitTestSourceExists(hit_test_source)) {
    // This should only happen when hit test source was already canceled.
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kHitTestSourceUnavailable);
    return *MakeGarbageCollected<FrozenArray<XRTransientInputHitTestResult>>();
  }

  return *MakeGarbageCollected<FrozenArray<XRTransientInputHitTestResult>>(
      hit_test_source->Results());
}

ScriptPromise<XRAnchor> XRFrame::createAnchor(
    ScriptState* script_state,
    XRRigidTransform* offset_space_from_anchor,
    XRSpace* space,
    ExceptionState& exception_state) {
  DVLOG(2) << __func__;

  if (!session_->IsFeatureEnabled(device::mojom::XRSessionFeature::ANCHORS)) {
    DVLOG(2) << __func__
             << ": feature not enabled on a session, failing anchor creation";
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      XRSession::kAnchorsFeatureNotSupported);
    return {};
  }

  if (!is_active_) {
    DVLOG(2) << __func__ << ": frame not active, failing anchor creation";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInactiveFrame);
    return {};
  }

  if (!offset_space_from_anchor) {
    DVLOG(2) << __func__
             << ": offset_space_from_anchor not set, failing anchor creation";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      XRSession::kNoRigidTransformSpecified);
    return {};
  }

  if (!space) {
    DVLOG(2) << __func__ << ": space not set, failing anchor creation";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      XRSession::kNoSpaceSpecified);
    return {};
  }

  device::mojom::blink::XRNativeOriginInformationPtr maybe_native_origin =
      space->NativeOrigin();
  if (!maybe_native_origin) {
    DVLOG(2) << __func__ << ": native origin not set, failing anchor creation";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kCannotObtainNativeOrigin);
    return {};
  }

  DVLOG(3) << __func__ << ": space->ToString()=" << space->ToString();
  auto maybe_plane_id = GetPlaneId(*maybe_native_origin);

  // The passed in space may be an offset space, we need to transform the pose
  // to account for origin-offset:
  auto native_origin_from_offset_space = space->NativeFromOffsetMatrix();
  auto native_origin_from_anchor = native_origin_from_offset_space *
                                   offset_space_from_anchor->TransformMatrix();

  // We should strive to create an anchor whose location aligns with the pose
  // |offset_space_from_anchor| relative to |space|. For spaces that are
  // dynamically changing, this means we need to convert the pose to be relative
  // to stationary space, using data valid in the current frame, and change the
  // native origin relative to which the pose is expressed when communicating
  // with the device. For spaces that are classified as stationary, this
  // adjustment is not needed.

  if (space->IsStationary()) {
    // Space is considered stationary, no adjustments are needed.
    return session_->CreateAnchorHelper(script_state, native_origin_from_anchor,
                                        maybe_native_origin, maybe_plane_id,
                                        exception_state);
  }

  return CreateAnchorFromNonStationarySpace(script_state,
                                            native_origin_from_anchor, space,
                                            maybe_plane_id, exception_state);
}

ScriptPromise<XRAnchor> XRFrame::CreateAnchorFromNonStationarySpace(
    ScriptState* script_state,
    const gfx::Transform& native_origin_from_anchor,
    XRSpace* space,
    std::optional<uint64_t> maybe_plane_id,
    ExceptionState& exception_state) {
  DVLOG(2) << __func__;

  // Space is not considered stationary - need to adjust the app-provided pose.
  // Let's ask the session about the appropriate stationary reference space:
  std::optional<XRSession::ReferenceSpaceInformation>
      reference_space_information = session_->GetStationaryReferenceSpace();

  if (!reference_space_information) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      XRSession::kUnableToRetrieveMatrix);
    return {};
  }

  auto stationary_space_from_mojo =
      reference_space_information->mojo_from_space.GetCheckedInverse();

  // We now have 2 spaces - the dynamic one passed in to create anchor
  // call, and the stationary one. We also have a rigid transform
  // expressed relative to the dynamic space. Time to convert it so that it's
  // expressed relative to stationary space.

  auto mojo_from_native_origin = space->MojoFromNative();
  if (!mojo_from_native_origin) {
    DVLOG(2) << __func__ << ": native_origin not set, failing anchor creation";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      XRSession::kUnableToRetrieveMatrix);
    return {};
  }

  auto mojo_from_anchor = *mojo_from_native_origin * native_origin_from_anchor;
  auto stationary_space_from_anchor =
      stationary_space_from_mojo * mojo_from_anchor;

  // Conversion done, make the adjusted call:
  return session_->CreateAnchorHelper(
      script_state, stationary_space_from_anchor,
      reference_space_information->native_origin, maybe_plane_id,
      exception_state);
}

bool XRFrame::IsSameSession(XRSession* space_session,
                            ExceptionState& exception_state) const {
  if (space_session != session_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kSessionMismatch);
    return false;
  }
  return true;
}

const FrozenArray<XRImageTrackingResult>& XRFrame::getImageTrackingResults(
    ExceptionState& exception_state) {
  return session_->ImageTrackingResults(exception_state);
}

XRJointPose* XRFrame::getJointPose(XRJointSpace* joint,
                                   XRSpace* baseSpace,
                                   ExceptionState& exception_state) const {
  if (!is_active_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInactiveFrame);
    return nullptr;
  }

  if (!IsSameSession(baseSpace->session(), exception_state) ||
      !IsSameSession(joint->session(), exception_state)) {
    return nullptr;
  }

  if (!session_->CanReportPoses()) {
    exception_state.ThrowSecurityError(XRSession::kCannotReportPoses);
    return nullptr;
  }

  const XRPose* pose = joint->getPose(baseSpace);
  if (!pose) {
    return nullptr;
  }

  const float radius = joint->radius();

  return MakeGarbageCollected<XRJointPose>(pose->transform()->TransformMatrix(),
                                           radius);
}

bool XRFrame::fillJointRadii(
    const HeapVector<Member<XRJointSpace>>& jointSpaces,
    NotShared<DOMFloat32Array> radii,
    ExceptionState& exception_state) const {
  if (!is_active_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInactiveFrame);
    return false;
  }

  for (const auto& joint_space : jointSpaces) {
    if (!IsSameSession(joint_space->session(), exception_state)) {
      return false;
    }
  }

  if (jointSpaces.size() != radii->length()) {
    exception_state.ThrowTypeError(kMismatchedBufferSizes);
    return false;
  }

  bool all_valid = true;

  auto radii_data = radii->AsSpan();
  for (unsigned offset = 0; offset < jointSpaces.size(); offset++) {
    const XRJointSpace* joint_space = jointSpaces[offset];
    if (joint_space->handHasMissingPoses()) {
      radii_data[offset] = NAN;
      all_valid = false;
    } else {
      radii_data[offset] = joint_space->radius();
    }
  }

  return all_valid;
}

bool XRFrame::fillPoses(const HeapVector<Member<XRSpace>>& spaces,
                        XRSpace* base_space,
                        NotShared<DOMFloat32Array> transforms,
                        ExceptionState& exception_state) const {
  constexpr unsigned kFloatsPerTransform = 16;

  if (!is_active_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      kInactiveFrame);
    return false;
  }

  for (const auto& space : spaces) {
    if (!IsSameSession(space->session(), exception_state)) {
      return false;
    }
  }

  if (!IsSameSession(base_space->session(), exception_state)) {
    return false;
  }

  if (spaces.size() * kFloatsPerTransform > transforms->length()) {
    exception_state.ThrowTypeError(kSpacesSequenceTooLarge);
    return false;
  }

  if (!session_->CanReportPoses()) {
    exception_state.ThrowSecurityError(XRSession::kCannotReportPoses);
    return false;
  }

  bool all_valid = true;
  auto transforms_data = transforms->AsSpan();
  for (const auto& space : spaces) {
    auto [current_transform, remaining] =
        transforms_data.split_at(kFloatsPerTransform);
    if (const XRPose* pose = space->getPose(base_space)) {
      current_transform.copy_from(pose->transform()->matrix()->AsSpan());
    } else {
      std::ranges::fill(current_transform, NAN);
      all_valid = false;
    }
    transforms_data = remaining;
  }

  return all_valid;
}

void XRFrame::Trace(Visitor* visitor) const {
  visitor->Trace(session_);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink

"""

```