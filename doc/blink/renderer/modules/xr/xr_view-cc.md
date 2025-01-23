Response:
Let's break down the thought process to analyze the `xr_view.cc` file.

1. **Understand the Core Purpose:** The filename `xr_view.cc` and the presence of `XR` strongly suggest this file is part of the WebXR implementation within the Chromium Blink rendering engine. The term "view" likely refers to a single perspective or eye in a virtual or augmented reality experience.

2. **Identify Key Classes:**  Scan the file for class definitions. We see `XRView` and `XRViewData`. This is a strong indicator of a separation of concerns:  `XRView` likely provides the JavaScript-facing API and holds the concrete data, while `XRViewData` manages the underlying data.

3. **Analyze `XRView` Methods:** Go through each method in the `XRView` class and understand its purpose:
    * **Constructor:** Takes `XRFrame`, `XRViewData`, and a transform. This suggests a close relationship with `XRFrame` (representing a single frame in the XR session) and that transforms are crucial for positioning.
    * **`Viewport()`:** Returns an `XRViewport`. This relates to the rendering area for this view.
    * **`eye()`:** Returns an enum representing the eye (left, right, none). This is essential for stereo rendering.
    * **`frame()` and `session()`:** Accessors to related objects, showing the context of the view.
    * **`projectionMatrix()`:** Returns a matrix crucial for 3D rendering. The comment about detached array buffers hints at interaction with JavaScript and potential issues.
    * **`GetCpuDepthInformation()` and `GetWebGLDepthInformation()`:**  Relate to depth sensing, a key feature of modern XR. The separate methods suggest different ways to access depth data.
    * **`refSpaceFromView()`:** Another transform, likely defining the view's position relative to a reference space.
    * **`recommendedViewportScale()` and `requestViewportScale()`:**  Methods for dynamic viewport scaling, an optimization technique.
    * **`camera()`:**  Deals with accessing the camera image in AR scenarios. The conditional logic involving feature flags and session modes is important.
    * **`isFirstPersonObserver()`:**  Indicates if this view represents the user's perspective.
    * **`Trace()`:**  Used for Blink's tracing infrastructure (debugging/performance analysis).

4. **Analyze `XRViewData` Methods:** Do the same for `XRViewData`:
    * **Constructor:** Takes a `XRViewPtr` (from the browser process), depth information, device config, enabled features, and graphics API. This shows it's initialized with data coming from the system.
    * **`UpdateView()`:**  Updates the view data based on a new `XRViewPtr`.
    * **`UpdateProjectionMatrixFromFoV()` and `UpdateProjectionMatrixFromAspect()`:**  Calculate the projection matrix based on different parameters (field of view vs. aspect ratio). The conditional logic for WebGPU vs. WebGL is significant.
    * **`UnprojectPointer()`:**  Performs the inverse of projection, converting screen coordinates to 3D space. This is crucial for input handling.
    * **`SetMojoFromView()`:**  Sets the transform from the underlying Mojo service.
    * **`GetCpuDepthInformation()` and `GetWebGLDepthInformation()`:**  The underlying implementation for these methods.
    * **`recommendedViewportScale()` and `requestViewportScale()`:** The underlying data and logic for viewport scaling.
    * **`ApplyViewportScaleForFrame()`:**  Applies the requested viewport scale.
    * **`Trace()`:**  For Blink tracing.

5. **Identify Relationships with JavaScript/HTML/CSS:**
    * **`XRView` is a WebIDL interface:**  The methods on `XRView` directly correspond to properties and methods exposed to JavaScript through the WebXR API (e.g., `XRView.prototype.projectionMatrix`).
    * **`XRViewport`:**  The returned object is also a WebIDL interface, defining the rendering rectangle. This relates to how the browser allocates rendering resources.
    * **Projection Matrix:** Directly used in WebGL or WebGPU when rendering the scene. JavaScript code sets up the rendering context and uses this matrix.
    * **Transforms:** `XRRigidTransform` is another WebIDL interface, representing spatial transformations. These are used to position objects in the XR scene.
    * **Depth Information:**  The `XRCPUDepthInformation` and `XRWebGLDepthInformation` interfaces expose depth data to JavaScript, enabling advanced rendering and interaction techniques.
    * **Viewport Scaling:**  JavaScript can request viewport scaling to improve performance.
    * **Camera Access:** The `XRCamera` interface provides access to the device's camera feed in AR, which is used by JavaScript to overlay virtual content.

6. **Infer Functionality and Interactions:** Based on the methods and data members, deduce the overall purpose of the file:
    * **Represents a single viewpoint:** Manages data specific to one eye or perspective.
    * **Provides rendering parameters:**  Calculates and provides the projection matrix and viewport.
    * **Handles coordinate transformations:** Manages transforms between different coordinate spaces (reference space, view space, etc.).
    * **Integrates depth sensing:** Provides access to depth information.
    * **Supports dynamic viewport scaling:**  Allows for runtime adjustment of rendering resolution.
    * **Provides camera access (AR):**  Facilitates access to the device camera.

7. **Consider Logical Reasoning and Examples:** Think about how the methods would be used and provide concrete examples (like getting the projection matrix or unprojecting a pointer).

8. **Identify Potential User/Programming Errors:** Consider common mistakes developers might make when working with WebXR (e.g., detaching the projection matrix array, accessing depth data without enabling the feature).

9. **Trace User Operations:**  Think about the steps a user would take to trigger the code in this file (entering an XR session, requesting a frame, rendering a scene, interacting with the scene).

10. **Structure the Explanation:** Organize the findings into logical categories (functionality, relationship to web technologies, logical reasoning, errors, debugging).

By following these steps, you can systematically analyze a source code file like `xr_view.cc` and understand its role within a larger system. The key is to combine code inspection with knowledge of the relevant APIs and concepts (in this case, WebXR and rendering).
这是 Chromium Blink 引擎中 `blink/renderer/modules/xr/xr_view.cc` 文件的功能分析：

**核心功能:**

`XRView.cc` 文件定义了 `XRView` 类，该类代表了 WebXR API 中的一个 **观察视角 (view)**。在 XR 场景中，特别是对于头戴式显示器 (HMD)，通常需要为每只眼睛创建一个独立的视角进行渲染，以产生立体视觉效果。`XRView` 封装了与单个视角相关的信息和操作。

`XRViewData.cc` 文件定义了 `XRViewData` 类，它存储了 `XRView` 对象所需的核心数据。这种分离有助于管理和更新视图数据。

**具体功能点:**

* **视角参数存储:**  `XRViewData` 存储了与特定视角相关的核心参数，例如：
    * **眼睛类型 (`eye_`):**  指示该视角对应的是左眼、右眼还是单眼视角 (`kNone`)。
    * **投影矩阵 (`projection_matrix_`):**  用于将 3D 场景投影到 2D 屏幕上的矩阵。该矩阵定义了视锥体，决定了哪些物体可见以及它们的透视效果。
    * **模型视图矩阵 (间接通过 `ref_space_from_view_`):**  表示从参考空间到该视角空间的变换。参考空间是一个统一的坐标系，用于定位 XR 场景中的物体。
    * **视口 (`viewport_`):**  定义了渲染目标（例如 WebGL Canvas）上用于渲染该视角的矩形区域。
    * **深度信息 (`depth_manager_`)**: 如果支持深度感知，则包含管理和处理深度数据的 `XRDepthManager` 对象。
    * **是否为第一人称观察者 (`is_first_person_observer_`):** 标识该视角是否代表用户的视角。

* **投影矩阵的计算和更新:** `XRViewData` 提供了根据视场角 (FoV) 或宽高比计算和更新投影矩阵的方法 (`UpdateProjectionMatrixFromFoV`, `UpdateProjectionMatrixFromAspect`)。 它还处理不同图形 API (WebGL, WebGPU) 对投影矩阵的要求差异。

* **视口信息的获取:** `XRView` 提供了获取视口信息的方法 `Viewport()`，该方法会考虑帧缓冲的缩放比例。

* **坐标转换:**  `XRView` 提供了获取从参考空间到视角空间的变换矩阵 (`refSpaceFromView()`) 的方法。

* **深度信息的获取:** `XRView` 提供了获取 CPU 和 WebGL 深度信息的方法 (`GetCpuDepthInformation()`, `GetWebGLDepthInformation()`)，这些方法会调用 `XRViewData` 中 `depth_manager_` 的相应方法。

* **动态视口缩放:** `XRView` 和 `XRViewData` 支持动态视口缩放，允许 Web 应用根据性能需求调整渲染分辨率 (`recommendedViewportScale()`, `requestViewportScale()`, `ApplyViewportScaleForFrame()`)。

* **相机访问 (AR):**  `XRView::camera()` 方法在启用了相机访问并且处于沉浸式 AR 会话中时，会返回一个 `XRCamera` 对象，用于访问设备相机图像。

* **射线投射 (UnprojectPointer):** `XRViewData::UnprojectPointer()` 方法可以将屏幕上的 2D 点坐标反投影到 3D 空间中，这对于实现基于光标的交互非常重要。

**与 JavaScript, HTML, CSS 的关系及举例:**

`XRView` 类及其提供的数据和方法直接对应于 WebXR JavaScript API 中的 `XRView` 接口。

* **JavaScript 获取投影矩阵:**
  ```javascript
  navigator.xr.requestSession('immersive-vr').then(session => {
    session.requestAnimationFrame(function onXRFrame(time, frame) {
      const viewerPose = frame.getViewerPose(session.renderState.baseLayer.space);
      if (viewerPose) {
        viewerPose.views.forEach(view => {
          const projectionMatrix = view.projectionMatrix;
          // 使用 projectionMatrix 进行 WebGL 或 WebGPU 渲染
        });
      }
      session.requestAnimationFrame(onXRFrame);
    });
  });
  ```
  在这个例子中，JavaScript 代码通过 `XRFrame` 获取 `XRView` 对象，并访问其 `projectionMatrix` 属性，该属性的值由 `xr_view.cc` 中的 `projection_matrix_` 提供。

* **JavaScript 获取视口信息:**
  ```javascript
  navigator.xr.requestSession('immersive-vr').then(session => {
    session.requestAnimationFrame(function onXRFrame(time, frame) {
      const viewerPose = frame.getViewerPose(session.renderState.baseLayer.space);
      if (viewerPose) {
        viewerPose.views.forEach(view => {
          const viewport = session.renderState.baseLayer.getViewport(view);
          // 使用 viewport 信息配置 WebGL 渲染的裁剪区域
        });
      }
      session.requestAnimationFrame(onXRFrame);
    });
  });
  ```
  这里，JavaScript 代码调用 `XRWebGLLayer.getViewport()` 方法，最终会调用到 `xr_view.cc` 的 `XRView::Viewport()` 方法，获取渲染该视角所需的视口矩形。

* **JavaScript 获取眼睛类型:**
  ```javascript
  navigator.xr.requestSession('immersive-vr').then(session => {
    session.requestAnimationFrame(function onXRFrame(time, frame) {
      const viewerPose = frame.getViewerPose(session.renderState.baseLayer.space);
      if (viewerPose) {
        viewerPose.views.forEach(view => {
          if (view.eye === 'left') {
            // 处理左眼视角
          } else if (view.eye === 'right') {
            // 处理右眼视角
          }
        });
      }
      session.requestAnimationFrame(onXRFrame);
    });
  });
  ```
  JavaScript 代码访问 `view.eye` 属性，该属性的值由 `xr_view.cc` 中的 `eye()` 方法返回，对应着 `XRViewData` 中的 `eye_` 成员。

HTML 和 CSS 本身不直接与 `XRView.cc` 交互。`XRView.cc` 主要负责提供渲染所需的底层数据。然而，WebXR 应用通常会使用 HTML `<canvas>` 元素作为渲染目标，而 CSS 可以控制 canvas 的样式和布局。

**逻辑推理及假设输入与输出:**

**假设输入:**

* 一个启用了 WebXR 的浏览器。
* 一个请求 `immersive-vr` 或 `immersive-ar` 会话的 Web 应用程序。
* Web 应用成功获取到一个 `XRFrame` 对象。
* `XRFrame` 对象包含一个或多个 `XRView` 对象。

**逻辑推理示例 (关于投影矩阵计算):**

假设 `XRViewData` 初始化时接收到来自设备的信息，指示左眼的视场角为上 45 度，下 45 度，左 50 度，右 50 度，近裁剪面为 0.1 米，远裁剪面为 100 米。图形 API 为 WebGL。

**输入 (部分 `XRViewData` 构造函数参数):**

* `view->field_of_view->up_degrees = 45.0`
* `view->field_of_view->down_degrees = 45.0`
* `view->field_of_view->left_degrees = 50.0`
* `view->field_of_view->right_degrees = 50.0`
* `depth_near = 0.1`
* `depth_far = 100.0`
* `graphics_api = XRGraphicsBinding::Api::kWebGL`

**`XRViewData::UpdateProjectionMatrixFromFoV` 方法的内部计算:**

1. 将角度转换为弧度：`up_rad = 45 * kDegToRad`, `down_rad`, `left_rad`, `right_rad` 同理。
2. 计算正切值：`up_tan = tan(up_rad)`, `down_tan`, `left_tan`, `right_tan` 同理。
3. 计算 x 和 y 缩放：`x_scale = 2.0 / (left_tan + right_tan)`, `y_scale = 2.0 / (up_tan + down_tan)`.
4. 计算 1 / (近裁剪面 - 远裁剪面)：`inv_nf = 1.0 / (0.1 - 100.0)`.
5. 根据 WebGL 的投影矩阵公式计算 `projection_matrix_` 的各个元素。

**输出 (部分投影矩阵 - 这是一个 4x4 矩阵):**

输出会是一个 `gfx::Transform` 对象，其内部存储了一个 4x4 的浮点数矩阵。具体的数值取决于上述计算结果。例如，矩阵的第一个元素可能接近 `x_scale` 的值。

**逻辑推理示例 (关于 `UnprojectPointer`):**

**假设输入:**

* 用户在 WebGL canvas 上点击了坐标 (100, 150)。
* canvas 的宽度为 300 像素，高度为 200 像素。
* 当前 `XRView` 的投影矩阵已经计算出来。

**输入 (`XRViewData::UnprojectPointer` 方法参数):**

* `x = 100`
* `y = 150`
* `canvas_width = 300`
* `canvas_height = 200`

**`XRViewData::UnprojectPointer` 方法的内部计算:**

1. 将屏幕坐标转换为 NDC (Normalized Device Coordinates，归一化设备坐标):
   * `ndc_x = 100 / 300 * 2.0 - 1.0 = -0.333...`
   * `ndc_y = (200 - 150) / 200 * 2.0 - 1.0 = -0.5`
   * `ndc_z = -1.0` (假设投影到近裁剪面)
2. 计算投影矩阵的逆矩阵 (`inv_projection_`)。
3. 将 NDC 坐标与逆投影矩阵相乘，得到观察空间中的 3D 点坐标 (`point_in_view_space`)。
4. 计算一个“Look At”矩阵，该矩阵的方向是从原点指向 `point_in_view_space` 的方向。
5. 返回该“Look At”矩阵的逆矩阵，表示从屏幕点击位置投射出的射线方向和原点。

**输出:**

输出将是一个 `gfx::Transform` 对象，表示从屏幕坐标 (100, 150) 发出的，穿过相机原点的射线在世界坐标系中的变换矩阵。这个矩阵可以用来进行射线投射检测，例如判断用户点击了哪个 3D 对象。

**用户或编程常见的使用错误及举例:**

1. **在 WebGL 或 WebGPU 中使用错误的投影矩阵:** 开发者可能会错误地使用了其他视角的投影矩阵，或者在更新渲染状态后没有及时获取新的投影矩阵。这会导致渲染结果错位或变形。

   ```javascript
   // 错误示例：假设 views 数组中有多个 view，但只使用了第一个 view 的投影矩阵
   navigator.xr.requestSession('immersive-vr').then(session => {
     session.requestAnimationFrame(function onXRFrame(time, frame) {
       const viewerPose = frame.getViewerPose(session.renderState.baseLayer.space);
       if (viewerPose && viewerPose.views.length > 0) {
         const projectionMatrix = viewerPose.views[0].projectionMatrix; // 可能用错了
         // ... 使用 projectionMatrix 进行渲染
       }
       session.requestAnimationFrame(onXRFrame);
     });
   });
   ```

2. **错误地理解视口信息:** 开发者可能会忽略视口信息，导致渲染内容没有正确地渲染到指定的屏幕区域。

   ```javascript
   // 错误示例：没有使用 viewport 信息设置 WebGL 的 scissor 测试
   navigator.xr.requestSession('immersive-vr').then(session => {
     session.requestAnimationFrame(function onXRFrame(time, frame) {
       const viewerPose = frame.getViewerPose(session.renderState.baseLayer.space);
       if (viewerPose) {
         viewerPose.views.forEach(view => {
           const viewport = session.renderState.baseLayer.getViewport(view);
           // 缺少设置 gl.scissor(viewport.x, viewport.y, viewport.width, viewport.height);
           // 和 gl.enable(gl.SCISSOR_TEST);
           // ... 进行渲染
         });
       }
       session.requestAnimationFrame(onXRFrame);
     });
   });
   ```

3. **在不支持深度感知的会话中尝试获取深度信息:** 如果请求会话时没有请求 `depth-sensing` 功能，或者设备不支持，尝试调用 `getDepthInformation()` 会抛出错误。

   ```javascript
   navigator.xr.requestSession('immersive-vr').then(session => {
     session.requestAnimationFrame(function onXRFrame(time, frame) {
       const viewerPose = frame.getViewerPose(session.renderState.baseLayer.space);
       if (viewerPose && viewerPose.views.length > 0) {
         const depthInfo = viewerPose.views[0].getDepthInformation(session.renderState.baseLayer.space); // 如果未启用 depth-sensing 会报错
         if (depthInfo) {
           // ... 处理深度信息
         }
       }
       session.requestAnimationFrame(onXRFrame);
     });
   });
   ```

4. **错误地使用 `UnprojectPointer` 进行交互:** 开发者可能没有正确地将 `UnprojectPointer` 返回的变换矩阵应用到场景中的物体上，导致点击交互失效。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问一个包含 WebXR 内容的网页:** 用户在浏览器中打开一个使用了 WebXR API 的网页。
2. **网页请求一个 XR 会话:** 网页 JavaScript 代码调用 `navigator.xr.requestSession()` 请求一个沉浸式会话 (例如 `immersive-vr` 或 `immersive-ar`)。
3. **浏览器处理会话请求:** 浏览器内核 (包括 Blink 引擎) 接收到会话请求，并与底层的 XR 设备通信，建立 XR 会话。
4. **会话开始，请求动画帧:** Web 应用通过 `XRSession.requestAnimationFrame()` 请求浏览器在下一次渲染循环中调用回调函数。
5. **浏览器开始渲染帧:**
   * **获取设备姿态 (Pose):** 浏览器从 XR 设备获取用户头部或设备的姿态信息。
   * **创建 `XRFrame` 对象:**  Blink 引擎创建一个 `XRFrame` 对象，用于封装当前帧的信息。
   * **创建 `XRView` 对象:** 对于支持立体渲染的会话，会为每只眼睛创建一个 `XRView` 对象。`XRView` 的构造函数会被调用，传入 `XRFrame` 和从浏览器进程传递过来的 `XRViewData` 信息。
   * **计算投影矩阵等参数:**  `XRViewData` 中的方法 (例如 `UpdateProjectionMatrixFromFoV`) 会被调用，根据设备提供的参数计算投影矩阵等。
   * **将 `XRView` 对象传递给 JavaScript:**  `XRFrame.getViewerPose()` 方法返回的 `XRViewerPose` 对象包含一个 `XRView` 对象的数组，这些对象会被传递给 JavaScript 代码。
6. **JavaScript 代码访问 `XRView` 的属性和方法:**  JavaScript 代码在 `requestAnimationFrame` 回调函数中，通过 `XRView` 对象访问 `projectionMatrix`、`viewport`、`eye` 等属性，或者调用 `getDepthInformation()` 等方法。

**调试线索:**

* **断点:** 在 `XRView` 的构造函数、`XRViewData` 的构造函数、`UpdateProjectionMatrixFromFoV`、`Viewport`、`GetCpuDepthInformation` 等方法中设置断点，可以查看这些方法的调用时机和参数值。
* **日志:** 使用 `DVLOG` 宏在关键代码路径上输出日志信息，例如投影矩阵的计算结果、视口信息等。
* **WebXR 设备模拟器:** 使用 Chrome 提供的 WebXR 设备模拟器，可以模拟不同的 XR 设备和场景，方便调试不同情况下的 `XRView` 行为。
* **检查 WebXR API 的使用:** 确保 JavaScript 代码正确地调用了 WebXR API，例如正确地获取了 `XRFrame` 和 `XRView` 对象。
* **查看设备信息:** 检查浏览器接收到的 XR 设备信息是否正确，例如视场角、分辨率等。

通过以上分析，我们可以深入了解 `blink/renderer/modules/xr/xr_view.cc` 文件的功能，以及它在 WebXR 技术栈中的作用，并为调试 WebXR 应用提供有价值的线索。

### 提示词
```
这是目录为blink/renderer/modules/xr/xr_view.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#define _USE_MATH_DEFINES  // For VC++ to get M_PI. This has to be first.

#include "third_party/blink/renderer/modules/xr/xr_view.h"

#include <algorithm>
#include <cmath>

#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_eye.h"
#include "third_party/blink/renderer/modules/xr/xr_camera.h"
#include "third_party/blink/renderer/modules/xr/xr_depth_manager.h"
#include "third_party/blink/renderer/modules/xr/xr_frame.h"
#include "third_party/blink/renderer/modules/xr/xr_session.h"
#include "third_party/blink/renderer/modules/xr/xr_utils.h"
#include "ui/gfx/geometry/point3_f.h"

namespace blink {

namespace {

// Arbitrary minimum size multiplier for dynamic viewport scaling,
// where 1.0 is full framebuffer size (which may in turn be adjusted
// by framebufferScaleFactor). This should be less than or equal to
// kMinScale in xr_session_viewport_scaler.cc to allow use of the full
// dynamic viewport scaling range.
constexpr double kMinViewportScale = 0.125;

const double kDegToRad = M_PI / 180.0;

}  // namespace

XRView::XRView(XRFrame* frame,
               XRViewData* view_data,
               const gfx::Transform& ref_space_from_mojo)
    : eye_(view_data->Eye()), frame_(frame), view_data_(view_data) {
  ref_space_from_view_ = MakeGarbageCollected<XRRigidTransform>(
      ref_space_from_mojo * view_data->MojoFromView());
  projection_matrix_ =
      transformationMatrixToDOMFloat32Array(view_data->ProjectionMatrix());
}

XRViewport* XRView::Viewport(double framebuffer_scale) {
  if (!viewport_) {
    const gfx::Rect& viewport = view_data_->Viewport();
    double scale = framebuffer_scale * view_data_->CurrentViewportScale();

    viewport_ = MakeGarbageCollected<XRViewport>(
        viewport.x() * scale, viewport.y() * scale, viewport.width() * scale,
        viewport.height() * scale);
  }

  return viewport_.Get();
}

V8XREye XRView::eye() const {
  switch (eye_) {
    case device::mojom::blink::XREye::kLeft:
      return V8XREye(V8XREye::Enum::kLeft);
    case device::mojom::blink::XREye::kRight:
      return V8XREye(V8XREye::Enum::kRight);
    case device::mojom::blink::XREye::kNone:
      return V8XREye(V8XREye::Enum::kNone);
  }
  NOTREACHED();
}

XRFrame* XRView::frame() const {
  return frame_.Get();
}

XRSession* XRView::session() const {
  return frame_->session();
}

DOMFloat32Array* XRView::projectionMatrix() const {
  if (!projection_matrix_ || !projection_matrix_->Data()) {
    // A page may take the projection matrix value and detach it so
    // projection_matrix_ is a detached array buffer.  This breaks the
    // inspector, so return null instead.
    return nullptr;
  }

  return projection_matrix_.Get();
}

XRCPUDepthInformation* XRView::GetCpuDepthInformation(
    ExceptionState& exception_state) const {
  return view_data_->GetCpuDepthInformation(frame(), exception_state);
}

XRWebGLDepthInformation* XRView::GetWebGLDepthInformation(
    ExceptionState& exception_state) const {
  return view_data_->GetWebGLDepthInformation(frame(), exception_state);
}

XRViewData::XRViewData(
    wtf_size_t index,
    device::mojom::blink::XRViewPtr view,
    double depth_near,
    double depth_far,
    const device::mojom::blink::XRSessionDeviceConfig& device_config,
    const HashSet<device::mojom::XRSessionFeature>& enabled_feature_set,
    XRGraphicsBinding::Api graphics_api)
    : index_(index),
      eye_(view->eye),
      graphics_api_(graphics_api),
      viewport_(view->viewport) {
  if (base::Contains(enabled_feature_set,
                     device::mojom::XRSessionFeature::DEPTH)) {
    if (!device_config.depth_configuration) {
      DCHECK(false)
          << "The session reports that depth sensing is supported but "
             "did not report depth sensing API configuration!";
    }
    depth_manager_ = MakeGarbageCollected<XRDepthManager>(
        base::PassKey<XRViewData>{}, *device_config.depth_configuration);
  }

  UpdateView(std::move(view), depth_near, depth_far);
}

void XRViewData::UpdateView(device::mojom::blink::XRViewPtr view,
                            double depth_near,
                            double depth_far) {
  DCHECK_EQ(eye_, view->eye);

  const device::mojom::blink::VRFieldOfViewPtr& fov = view->field_of_view;
  UpdateProjectionMatrixFromFoV(
      fov->up_degrees * kDegToRad, fov->down_degrees * kDegToRad,
      fov->left_degrees * kDegToRad, fov->right_degrees * kDegToRad, depth_near,
      depth_far);

  mojo_from_view_ = view->mojo_from_view;

  viewport_ = view->viewport;
  is_first_person_observer_ = view->is_first_person_observer;
  if (depth_manager_) {
    depth_manager_->ProcessDepthInformation(std::move(view->depth_data));
  }
}

void XRViewData::UpdateProjectionMatrixFromFoV(float up_rad,
                                               float down_rad,
                                               float left_rad,
                                               float right_rad,
                                               float near_depth,
                                               float far_depth) {
  float up_tan = tanf(up_rad);
  float down_tan = tanf(down_rad);
  float left_tan = tanf(left_rad);
  float right_tan = tanf(right_rad);
  float x_scale = 2.0f / (left_tan + right_tan);
  float y_scale = 2.0f / (up_tan + down_tan);
  float inv_nf = 1.0f / (near_depth - far_depth);

  // Compute the appropriate matrix for the graphics API being used.
  // WebGPU uses a clip space with a depth range of [0, 1], which requires a
  // different projection matrix than WebGL, which uses a clip space with a
  // depth range of [-1, 1].
  if (graphics_api_ == XRGraphicsBinding::Api::kWebGPU) {
    projection_matrix_ = gfx::Transform::ColMajor(
        x_scale, 0.0f, 0.0f, 0.0f, 0.0f, y_scale, 0.0f, 0.0f,
        -((left_tan - right_tan) * x_scale * 0.5),
        ((up_tan - down_tan) * y_scale * 0.5), far_depth * inv_nf, -1.0f, 0.0f,
        0.0f, far_depth * near_depth * inv_nf, 0.0f);
  } else {
    projection_matrix_ = gfx::Transform::ColMajor(
        x_scale, 0.0f, 0.0f, 0.0f, 0.0f, y_scale, 0.0f, 0.0f,
        -((left_tan - right_tan) * x_scale * 0.5),
        ((up_tan - down_tan) * y_scale * 0.5),
        (near_depth + far_depth) * inv_nf, -1.0f, 0.0f, 0.0f,
        (2.0f * far_depth * near_depth) * inv_nf, 0.0f);
  }
}

void XRViewData::UpdateProjectionMatrixFromAspect(float fovy,
                                                  float aspect,
                                                  float near_depth,
                                                  float far_depth) {
  float f = 1.0f / tanf(fovy / 2);
  float inv_nf = 1.0f / (near_depth - far_depth);

  if (graphics_api_ == XRGraphicsBinding::Api::kWebGPU) {
    projection_matrix_ = gfx::Transform::ColMajor(
        f / aspect, 0.0f, 0.0f, 0.0f, 0.0f, f, 0.0f, 0.0f, 0.0f, 0.0f,
        far_depth * inv_nf, -1.0f, 0.0f, 0.0f, far_depth * near_depth * inv_nf,
        0.0f);
  } else {
    projection_matrix_ = gfx::Transform::ColMajor(
        f / aspect, 0.0f, 0.0f, 0.0f, 0.0f, f, 0.0f, 0.0f, 0.0f, 0.0f,
        (far_depth + near_depth) * inv_nf, -1.0f, 0.0f, 0.0f,
        (2.0f * far_depth * near_depth) * inv_nf, 0.0f);
  }

  inv_projection_dirty_ = true;
}

gfx::Transform XRViewData::UnprojectPointer(double x,
                                            double y,
                                            double canvas_width,
                                            double canvas_height) {
  // Recompute the inverse projection matrix if needed.
  if (inv_projection_dirty_) {
    inv_projection_ = projection_matrix_.InverseOrIdentity();
    inv_projection_dirty_ = false;
  }

  // Transform the x/y coordinate into WebGL normalized device coordinates.
  // Z coordinate of -1 means the point will be projected onto the projection
  // matrix near plane.
  gfx::Point3F point_in_projection_space(
      x / canvas_width * 2.0 - 1.0,
      (canvas_height - y) / canvas_height * 2.0 - 1.0, -1.0);

  gfx::Point3F point_in_view_space =
      inv_projection_.MapPoint(point_in_projection_space);

  const gfx::Vector3dF kUp(0.0, 1.0, 0.0);

  // Generate a "Look At" matrix
  gfx::Vector3dF z_axis = -point_in_view_space.OffsetFromOrigin();
  z_axis.GetNormalized(&z_axis);

  gfx::Vector3dF x_axis = gfx::CrossProduct(kUp, z_axis);
  x_axis.GetNormalized(&x_axis);

  gfx::Vector3dF y_axis = gfx::CrossProduct(z_axis, x_axis);
  y_axis.GetNormalized(&y_axis);

  // TODO(bajones): There's probably a more efficient way to do this?
  auto inv_pointer = gfx::Transform::ColMajor(
      x_axis.x(), y_axis.x(), z_axis.x(), 0.0, x_axis.y(), y_axis.y(),
      z_axis.y(), 0.0, x_axis.z(), y_axis.z(), z_axis.z(), 0.0, 0.0, 0.0, 0.0,
      1.0);
  inv_pointer.Translate3d(-point_in_view_space.x(), -point_in_view_space.y(),
                          -point_in_view_space.z());

  // LookAt matrices are view matrices (inverted), so invert before returning.
  return inv_pointer.InverseOrIdentity();
}

void XRViewData::SetMojoFromView(const gfx::Transform& mojo_from_view) {
  mojo_from_view_ = mojo_from_view;
}

XRCPUDepthInformation* XRViewData::GetCpuDepthInformation(
    const XRFrame* xr_frame,
    ExceptionState& exception_state) const {
  if (!depth_manager_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        XRSession::kDepthSensingFeatureNotSupported);
    return nullptr;
  }

  return depth_manager_->GetCpuDepthInformation(xr_frame, exception_state);
}

XRWebGLDepthInformation* XRViewData::GetWebGLDepthInformation(
    const XRFrame* xr_frame,
    ExceptionState& exception_state) const {
  if (!depth_manager_) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        XRSession::kDepthSensingFeatureNotSupported);
    return nullptr;
  }

  return depth_manager_->GetWebGLDepthInformation(xr_frame, exception_state);
}

XRRigidTransform* XRView::refSpaceFromView() const {
  return ref_space_from_view_.Get();
}

std::optional<double> XRView::recommendedViewportScale() const {
  return view_data_->recommendedViewportScale();
}

void XRView::requestViewportScale(std::optional<double> scale) {
  view_data_->requestViewportScale(scale);
}

XRCamera* XRView::camera() const {
  const bool camera_access_enabled = frame_->session()->IsFeatureEnabled(
      device::mojom::XRSessionFeature::CAMERA_ACCESS);
  const bool is_immersive_ar_session =
      frame_->session()->mode() ==
      device::mojom::blink::XRSessionMode::kImmersiveAr;

  DVLOG(3) << __func__ << ": camera_access_enabled=" << camera_access_enabled
           << ", is_immersive_ar_session=" << is_immersive_ar_session;

  if (camera_access_enabled && is_immersive_ar_session) {
    // The feature is enabled and we're in immersive-ar session, so let's return
    // a camera object if the camera image was received in the current frame.
    // Note: currently our only implementation of AR sessions is provided by
    // ARCore device, which should *not* return a frame data with camera image
    // that is not set in case the raw camera access is enabled, so we could
    // DCHECK that the camera image size has value. Since there may be other AR
    // devices that implement raw camera access via a different mechanism that's
    // not neccessarily frame-aligned, a DCHECK here would affect them.
    if (frame_->session()->CameraImageSize().has_value()) {
      return MakeGarbageCollected<XRCamera>(frame_);
    }
  }

  return nullptr;
}

bool XRView::isFirstPersonObserver() const {
  return view_data_->IsFirstPersonObserver();
}

void XRView::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(projection_matrix_);
  visitor->Trace(ref_space_from_view_);
  visitor->Trace(view_data_);
  visitor->Trace(viewport_);
  ScriptWrappable::Trace(visitor);
}

std::optional<double> XRViewData::recommendedViewportScale() const {
  return recommended_viewport_scale_;
}

void XRViewData::requestViewportScale(std::optional<double> scale) {
  if (!scale)
    return;

  requested_viewport_scale_ = std::clamp(*scale, kMinViewportScale, 1.0);
}

bool XRViewData::ApplyViewportScaleForFrame() {
  bool changed = false;

  // Dynamic viewport scaling, see steps 6 and 7 in
  // https://immersive-web.github.io/webxr/#dom-xrwebgllayer-getviewport
  if (ViewportModifiable() &&
      CurrentViewportScale() != RequestedViewportScale()) {
    DVLOG(2) << __func__
             << ": apply ViewportScale=" << RequestedViewportScale();
    SetCurrentViewportScale(RequestedViewportScale());
    changed = true;
  }
  TRACE_COUNTER1("xr", "XR viewport scale (%)", CurrentViewportScale() * 100);
  SetViewportModifiable(false);

  return changed;
}

void XRViewData::Trace(Visitor* visitor) const {
  visitor->Trace(depth_manager_);
}

}  // namespace blink
```