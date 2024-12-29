Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

1. **Understand the Goal:** The primary goal is to understand the functionality of `xr_webgl_binding.cc` within the Chromium Blink rendering engine, particularly its role in connecting WebXR with WebGL.

2. **Initial Scan and Keyword Identification:** Quickly read through the code, looking for keywords and class names. This immediately highlights:
    * `XRWebGLBinding`: The core class being analyzed.
    * `XRSession`, `XRFrame`, `XRView`, `XRCamera`, `XRLightProbe`, `XRProjectionLayer`:  These are likely related to the WebXR API.
    * `WebGLRenderingContextBase`, `WebGLTexture`:  Clearly indicates interaction with WebGL.
    * `ExceptionState`:  Suggests error handling.
    * `Create`, `getReflectionCubeMap`, `getCameraImage`, `getDepthInformation`: Key methods that represent distinct actions.

3. **Deconstruct the `Create` Method:** This method is the entry point for creating an `XRWebGLBinding`. Analyze each conditional statement:
    * `session->ended()`: Checks if the WebXR session is active.
    * `!session->immersive()`: Checks if the session is an "immersive" VR/AR session, not an inline one.
    * `webgl_context->isContextLost()`: Checks if the WebGL context is still valid.
    * `!webgl_context->IsXRCompatible()`: A crucial check to ensure the WebGL context is prepared for WebXR.
    * `session->GraphicsApi() != XRGraphicsBinding::Api::kWebGL`: Verifies that the session is indeed using WebGL, not WebGPU.

4. **Analyze Individual Methods (Functionality):**  Go through each public method of `XRWebGLBinding` and deduce its purpose:
    * `usesDepthValues()`:  Seems to indicate whether depth information is used by this binding. The current implementation always returns `false`.
    * `createProjectionLayer()`:  Related to creating projection layers, but marked as `NOTIMPLEMENTED()`.
    * `getViewSubImage()`:  Likely used to get a sub-region of a projection layer for a specific view, also `NOTIMPLEMENTED()`.
    * `getReflectionCubeMap()`:  Fetches a WebGL texture representing a reflection cubemap from an `XRLightProbe`. This involves checks for context loss, session status, and WebGL extension availability (`OES_texture_half_float`, `EXT_sRGB`). It also handles different internal formats based on WebGL version and extensions.
    * `getCameraImage()`: Retrieves a WebGL texture containing the camera feed. This involves checks for the `CAMERA_ACCESS` feature being enabled, active frame, animation frame, and ensures the camera belongs to the same session.
    * `getDepthInformation()`:  Retrieves depth information associated with a specific view. It checks for the `DEPTH` feature being enabled, active frame, and animation frame.

5. **Identify Relationships with Web Technologies:** Connect the C++ code to its counterparts in JavaScript, HTML, and CSS:
    * **JavaScript:**  Focus on how these methods would be called from the WebXR JavaScript API (e.g., `XRFrame.getViewerPose()`, `XRSession.requestAnimationFrame()`, `XRSession.requestReferenceSpace()`).
    * **HTML:**  Consider how the `<canvas>` element is involved and how the `getContext('webgl')` or `getContext('webgl2')` calls lead to the creation of the `WebGLRenderingContextBase`.
    * **CSS:** While less direct, think about how CSS might influence the layout or styling of elements within the WebXR experience.

6. **Infer Logical Reasoning (Assumptions and Outputs):** For methods with more complex logic (like `getReflectionCubeMap`), create hypothetical scenarios:
    * **Input:** A valid `XRLightProbe` with `ReflectionFormat::kReflectionFormatRGBA16F`, a WebGL1 context without the `OES_texture_half_float` extension.
    * **Output:** An exception is thrown indicating the missing extension.
    * **Input:** A valid `XRLightProbe` with `ReflectionFormat::kReflectionFormatSRGBA8`, a WebGL1 context without the `EXT_sRGB` extension.
    * **Output:** The cubemap is created with `GL_RGBA` as the internal format.

7. **Consider User/Programming Errors:** Think about common mistakes developers might make when working with WebXR and WebGL:
    * Not requesting an XR-compatible WebGL context.
    * Trying to use a lost WebGL context.
    * Not checking for required WebGL extensions.
    * Using objects (like `XRCamera`) from different `XRSession`s.
    * Calling methods at the wrong time (e.g., after the session has ended).

8. **Trace User Actions (Debugging Clues):**  Map out the sequence of user actions that could lead to the execution of the code:
    * User visits a webpage with WebXR content.
    * JavaScript code requests a WebXR session (`navigator.xr.requestSession('immersive-vr')`).
    * The browser prompts the user for permission.
    * The user grants permission.
    * JavaScript gets a `WebGLRenderingContext` from a `<canvas>`.
    * JavaScript calls `session.requestAnimationFrame()` and within the callback, calls methods that might lead to the execution of `XRWebGLBinding` methods (e.g., accessing camera feed, reflection maps, depth data).

9. **Structure the Answer:** Organize the findings logically, using headings and bullet points for clarity. Start with a high-level overview of the file's purpose, then delve into the details of each method. Address each point from the prompt (functionality, JavaScript/HTML/CSS relation, logical reasoning, errors, user actions).

10. **Refine and Review:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Correct any errors or omissions. Ensure the language is precise and avoids jargon where possible (or explains it).

This systematic approach, combining code analysis, knowledge of WebXR/WebGL APIs, and consideration of potential use cases and errors, allows for a comprehensive understanding of the `xr_webgl_binding.cc` file.
这个文件 `blink/renderer/modules/xr/xr_webgl_binding.cc` 的主要功能是 **将 WebXR API 与 WebGL API 连接起来**。  它提供了一个桥梁，允许WebXR会话使用WebGL或WebGL2上下文进行渲染。

以下是它的具体功能分解：

**1. 创建 `XRWebGLBinding` 对象：**

* `XRWebGLBinding::Create(XRSession* session, const V8XRWebGLRenderingContext* context, ExceptionState& exception_state)`:  这是一个静态方法，用于创建 `XRWebGLBinding` 的实例。
* **功能:**
    * 验证传入的 `XRSession` 是否有效（未结束，必须是 immersive 会话）。
    * 验证传入的 WebGL 上下文是否有效（未丢失，必须标记为 XR 兼容）。
    * 验证 `XRSession` 的图形 API 是否为 WebGL。
    * 如果验证通过，则创建一个新的 `XRWebGLBinding` 对象。
    * 如果验证失败，则抛出相应的 DOMException 错误。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  当 Web 开发者在 JavaScript 中使用 WebXR API 并指定使用 WebGL 进行渲染时，会间接地涉及到这个 C++ 文件。例如，当调用 `navigator.xr.requestSession('immersive-vr', { requiredFeatures: ['local-floor'], optionalFeatures: ['camera-access'] })` 获取一个 WebXR 会话，然后使用 `<canvas>` 元素的 WebGL 上下文进行渲染时，Blink 引擎内部会创建 `XRWebGLBinding` 来管理这种连接。
    ```javascript
    navigator.xr.requestSession('immersive-vr').then(session => {
      const canvas = document.createElement('canvas');
      document.body.appendChild(canvas);
      const gl = canvas.getContext('webgl', { xrCompatible: true }); // 关键：xrCompatible: true
      if (!gl) {
        console.error("Unable to initialize WebGL.");
        return;
      }
      session.updateRenderState({ baseLayer: new XRWebGLLayer(session, gl) });
      // ... 渲染循环中使用 gl 进行绘制 ...
    });
    ```
* **HTML:**  `<canvas>` 元素是 WebGL 内容的载体。  `xrCompatible: true` 上下文创建选项是连接 WebXR 和 WebGL 的关键。
    ```html
    <canvas id="xrCanvas"></canvas>
    <script>
      const canvas = document.getElementById('xrCanvas');
      const gl = canvas.getContext('webgl', { xrCompatible: true });
      // ...
    </script>
    ```
* **CSS:** CSS 主要负责页面的布局和样式，与此文件的关系相对间接。  不过，可以用来控制 `<canvas>` 元素的大小和位置。

**2. 管理 WebGL 上下文：**

* `XRWebGLBinding::XRWebGLBinding(XRSession* session, WebGLRenderingContextBase* webgl_context, bool webgl2)`: 构造函数接收 `WebGLRenderingContextBase` 对象。
* **功能:**  存储并管理与 WebXR 会话关联的 WebGL 上下文。

**3. 判断是否使用深度值：**

* `XRWebGLBinding::usesDepthValues() const`:  返回 `false`。
* **功能:**  当前实现中，这个方法总是返回 `false`，可能未来会根据不同的 WebGL 配置或扩展返回 `true`。

**4. 创建投影层 (Projection Layer)：**

* `XRWebGLBinding::createProjectionLayer(const XRProjectionLayerInit* init, ExceptionState& exception_state)`:  目前标记为 `NOTIMPLEMENTED()`。
* **功能:**  理论上，这个方法应该用于创建 WebGL 投影层，允许开发者直接将内容渲染到 XR 设备的原生显示表面。  但目前尚未实现。

**5. 获取视图子图像 (View Sub-Image)：**

* `XRWebGLBinding::getViewSubImage(XRProjectionLayer* layer, XRView* view, ExceptionState& exception_state)`:  目前标记为 `NOTIMPLEMENTED()`。
* **功能:**  理论上，这个方法应该用于获取特定视图在投影层上的子图像，用于渲染到不同的眼睛或进行其他处理。

**6. 获取反射立方体贴图 (Reflection Cube Map)：**

* `XRWebGLBinding::getReflectionCubeMap(XRLightProbe* light_probe, ExceptionState& exception_state)`:  允许开发者获取与 `XRLightProbe` 关联的反射立方体贴图的 WebGLTexture。
* **功能:**
    * 验证 WebGL 上下文和会话状态。
    * 验证 `light_probe` 是否属于同一个会话。
    * 根据 `XRLightProbe` 的反射格式和 WebGL 的能力（WebGL 2 或 WebGL 1 扩展），确定合适的内部格式、格式和类型。
    * 从 `XRLightProbe` 获取 `XRCubeMap`。
    * 创建一个新的 `WebGLTexture`。
    * 调用 `XRCubeMap::updateWebGLEnvironmentCube` 来更新 WebGLTexture 的内容。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个有效的 `XRLightProbe` 对象，其 `ReflectionFormat` 为 `kReflectionFormatRGBA16F`，当前的 WebGL 上下文是 WebGL1，并且没有启用 `GL_OES_texture_half_float` 扩展。
* **输出:**  `getReflectionCubeMap` 方法会抛出一个 `DOMException`，提示需要启用 `OES_texture_half_float` 扩展。

**7. 获取相机图像 (Camera Image)：**

* `XRWebGLBinding::getCameraImage(XRCamera* camera, ExceptionState& exception_state)`: 允许开发者获取 XRCamera 的图像数据作为 WebGLTexture。
* **功能:**
    * 验证会话是否启用了 `CAMERA_ACCESS` 特性。
    * 验证 `XRFrame` 是否处于活动状态并且是动画帧。
    * 验证 `XRCamera` 是否属于同一个会话。
    * 获取 `XRSession` 的基础渲染层 `XRWebGLLayer`。
    * 返回 `XRWebGLLayer` 持有的相机纹理。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个有效的 `XRCamera` 对象，但所属的 `XRSession` 在创建时没有请求 `camera-access` 可选特性。
* **输出:** `getCameraImage` 方法会抛出一个 `NotSupportedError` 类型的 `DOMException`，消息为 `XRSession::kRawCameraAccessFeatureNotSupported`。

**8. 获取深度信息 (Depth Information)：**

* `XRWebGLBinding::getDepthInformation(XRView* view, ExceptionState& exception_state)`: 允许开发者获取与特定 `XRView` 关联的深度信息。
* **功能:**
    * 验证 `XRView` 是否属于同一个会话。
    * 验证会话是否启用了 `DEPTH` 特性。
    * 验证 `XRFrame` 是否处于活动状态并且是动画帧。
    * 调用 `XRView::GetWebGLDepthInformation` 来获取深度信息。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个有效的 `XRView` 对象，但所属的 `XRSession` 在创建时没有请求 `depth-sensing` 可选特性。
* **输出:** `getDepthInformation` 方法会抛出一个 `NotSupportedError` 类型的 `DOMException`，消息为 `XRSession::kDepthSensingFeatureNotSupported`。

**用户或编程常见的使用错误：**

1. **未启用 XR 兼容的 WebGL 上下文:**  用户忘记在创建 WebGL 上下文时设置 `xrCompatible: true` 选项。
    ```javascript
    const gl = canvas.getContext('webgl'); // 错误：缺少 xrCompatible
    ```
    **结果:**  在 `XRWebGLBinding::Create` 中会抛出 `InvalidStateError`，提示 "WebGL context must be marked as XR compatible in order to use with an immersive XRSession"。

2. **在非 immersive 会话中使用:**  尝试在 `inline` 类型的 WebXR 会话中创建 `XRWebGLBinding`。
    ```javascript
    navigator.xr.requestSession('inline').then(session => {
      const gl = canvas.getContext('webgl', { xrCompatible: true });
      // ... 尝试创建 XRWebGLBinding ... 这将失败
    });
    ```
    **结果:** 在 `XRWebGLBinding::Create` 中会抛出 `InvalidStateError`，提示 "Cannot create an XRWebGLBinding for an inline XRSession."。

3. **在会话结束后使用:**  尝试在一个已经结束的 WebXR 会话中创建 `XRWebGLBinding` 或调用其方法。
    ```javascript
    navigator.xr.requestSession('immersive-vr').then(session => {
      session.end();
      const gl = canvas.getContext('webgl', { xrCompatible: true });
      // 尝试创建 XRWebGLBinding
    });
    ```
    **结果:** 在 `XRWebGLBinding::Create` 或其他方法中会抛出 `InvalidStateError`，提示 "Cannot create an XRWebGLBinding for an XRSession which has already ended." 或类似的错误。

4. **使用已丢失的 WebGL 上下文:**  在 WebGL 上下文丢失后（例如，由于 GPU 错误），尝试使用与该上下文关联的 `XRWebGLBinding`。
    ```javascript
    // ... 获取 gl 上下文 ...
    canvas.addEventListener('webglcontextlost', function(event) {
      // ... 尝试使用与已丢失的 gl 关联的 XRWebGLBinding ...
    }, false);
    ```
    **结果:** 在 `XRWebGLBinding::Create` 或其他需要访问 WebGL 上下文的方法中会抛出 `InvalidStateError`，提示 "Cannot create an XRWebGLBinding with a lost WebGL context." 或 "Cannot get reflection cube map with a lost context."。

5. **需要的 WebGL 扩展未启用:**  尝试获取特定格式的反射立方体贴图，但所需的 WebGL 扩展未启用。
    ```javascript
    // ... 使用一个需要 GL_OES_texture_half_float 的 light probe ...
    ```
    **结果:** 在 `getReflectionCubeMap` 中会抛出 `InvalidStateError`，提示需要相应的扩展。

6. **从不同的会话获取对象:** 尝试在一个 `XRWebGLBinding` 中使用来自不同 `XRSession` 的 `XRLightProbe` 或 `XRCamera`。
    ```javascript
    navigator.xr.requestSession('immersive-vr').then(session1 => {
      navigator.xr.requestSession('immersive-vr').then(session2 => {
        // ... 从 session2 获取一个 light probe ...
        session1.requestAnimationFrame((time, frame) => {
          const pose = frame.getViewerPose(refSpace);
          const binding = frame.session.renderState.baseLayer._glBinding;
          binding.getReflectionCubeMap(lightProbeFromSession2); // 错误
        });
      });
    });
    ```
    **结果:** 在 `getReflectionCubeMap` 或 `getCameraImage` 中会抛出 `InvalidStateError`，提示对象来自不同的会话。

**用户操作如何一步步的到达这里（作为调试线索）：**

1. **用户访问一个包含 WebXR 内容的网页。**
2. **JavaScript 代码调用 `navigator.xr.requestSession('immersive-vr', ...)` 请求一个 immersive 的 WebXR 会话。**
3. **用户授权 WebXR 会话请求。**
4. **JavaScript 代码获取一个 `<canvas>` 元素。**
5. **JavaScript 代码调用 `canvas.getContext('webgl', { xrCompatible: true })` 或 `canvas.getContext('webgl2', { xrCompatible: true })` 获取一个 XR 兼容的 WebGL 上下文。**
6. **JavaScript 代码调用 `session.updateRenderState({ baseLayer: new XRWebGLLayer(session, gl) })`，这会在 Blink 内部创建 `XRWebGLLayer`，并且 `XRWebGLBinding::Create` 会被调用来创建与该 WebGL 上下文关联的 `XRWebGLBinding` 对象。**
7. **在 WebXR 渲染循环中（`session.requestAnimationFrame` 的回调函数中），JavaScript 代码可能会调用 `XRFrame` 对象的方法，这些方法最终可能会调用 `XRWebGLBinding` 的方法，例如：**
    * 获取反射立方体贴图：`frame.getLightProbe(...)` 获取 `XRLightProbe`，然后调用 `XRWebGLBinding::getReflectionCubeMap`。
    * 获取相机图像：`frame.getViewerPose(...)` 获取 `XRViewerPose`，然后访问 `XRCamera`，最后调用 `XRWebGLBinding::getCameraImage`。
    * 获取深度信息：`frame.getViewerPose(...)` 获取 `XRViewerPose`，然后访问 `XRView`，最后调用 `XRWebGLBinding::getDepthInformation`。

**调试线索:**

* **检查 WebGL 上下文是否成功创建，并且 `xrCompatible` 选项是否为 true。**
* **确认 WebXR 会话的状态，是否已经结束。**
* **查看浏览器的开发者工具中的控制台，是否有相关的错误信息（例如，DOMException）。**
* **使用断点调试 JavaScript 代码，查看 WebXR API 的调用顺序和参数。**
* **在 Blink 渲染引擎的源代码中设置断点，例如在 `XRWebGLBinding::Create` 或其他相关方法中，以跟踪代码的执行流程。**
* **检查是否请求了必要的 WebXR 功能（例如 `camera-access`, `depth-sensing`）。**
* **确认使用的 WebGL 扩展是否已启用。**

总而言之，`xr_webgl_binding.cc` 文件是 WebXR 和 WebGL 互操作性的关键组成部分，它负责管理 WebGL 上下文，提供访问 WebGL 资源的接口，并确保 WebXR 会话和 WebGL 上下文的正确集成。

Prompt: 
```
这是目录为blink/renderer/modules/xr/xr_webgl_binding.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/xr/xr_webgl_binding.h"

#include "third_party/blink/renderer/bindings/modules/v8/v8_union_webgl2renderingcontext_webglrenderingcontext.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_projection_layer_init.h"
#include "third_party/blink/renderer/modules/webgl/webgl_rendering_context_base.h"
#include "third_party/blink/renderer/modules/webgl/webgl_texture.h"
#include "third_party/blink/renderer/modules/webgl/webgl_unowned_texture.h"
#include "third_party/blink/renderer/modules/xr/xr_camera.h"
#include "third_party/blink/renderer/modules/xr/xr_cube_map.h"
#include "third_party/blink/renderer/modules/xr/xr_frame.h"
#include "third_party/blink/renderer/modules/xr/xr_light_probe.h"
#include "third_party/blink/renderer/modules/xr/xr_projection_layer.h"
#include "third_party/blink/renderer/modules/xr/xr_render_state.h"
#include "third_party/blink/renderer/modules/xr/xr_session.h"
#include "third_party/blink/renderer/modules/xr/xr_utils.h"
#include "third_party/blink/renderer/modules/xr/xr_viewer_pose.h"
#include "third_party/blink/renderer/modules/xr/xr_webgl_layer.h"
#include "third_party/blink/renderer/modules/xr/xr_webgl_sub_image.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/gpu/extensions_3d_util.h"

namespace blink {

XRWebGLBinding* XRWebGLBinding::Create(XRSession* session,
                                       const V8XRWebGLRenderingContext* context,
                                       ExceptionState& exception_state) {
  if (session->ended()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot create an XRWebGLBinding for an "
                                      "XRSession which has already ended.");
    return nullptr;
  }

  if (!session->immersive()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot create an XRWebGLBinding for an "
                                      "inline XRSession.");
    return nullptr;
  }

  WebGLRenderingContextBase* webgl_context =
      webglRenderingContextBaseFromUnion(context);

  if (webgl_context->isContextLost()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot create an XRWebGLBinding with a "
                                      "lost WebGL context.");
    return nullptr;
  }

  if (!webgl_context->IsXRCompatible()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "WebGL context must be marked as XR compatible in order to "
        "use with an immersive XRSession");
    return nullptr;
  }

  if (session->GraphicsApi() != XRGraphicsBinding::Api::kWebGL) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot create an XRWebGLBinding with a WebGPU-based XRSession.");
    return nullptr;
  }

  return MakeGarbageCollected<XRWebGLBinding>(
      session, webgl_context, context->IsWebGL2RenderingContext());
}

XRWebGLBinding::XRWebGLBinding(XRSession* session,
                               WebGLRenderingContextBase* webgl_context,
                               bool webgl2)
    : XRGraphicsBinding(session),
      webgl_context_(webgl_context),
      webgl2_(webgl2) {}

bool XRWebGLBinding::usesDepthValues() const {
  return false;
}

XRProjectionLayer* XRWebGLBinding::createProjectionLayer(
    const XRProjectionLayerInit* init,
    ExceptionState& exception_state) {
  NOTIMPLEMENTED();
  return nullptr;
}

XRWebGLSubImage* XRWebGLBinding::getViewSubImage(
    XRProjectionLayer* layer,
    XRView* view,
    ExceptionState& exception_state) {
  NOTIMPLEMENTED();
  return nullptr;
}

WebGLTexture* XRWebGLBinding::getReflectionCubeMap(
    XRLightProbe* light_probe,
    ExceptionState& exception_state) {
  GLenum internal_format, format, type;

  if (webgl_context_->isContextLost()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot get reflection cube map with a lost context.");
    return nullptr;
  }

  if (session()->ended()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot get a reflection cube map for a session which has ended.");
    return nullptr;
  }

  if (session() != light_probe->session()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "LightProbe comes from a different session than this binding");
    return nullptr;
  }

  // Determine the internal_format, format, and type that will be passed to
  // glTexImage2D for each possible light probe reflection format. The formats
  // will differ depending on whether we're using WebGL 2 or WebGL 1 with
  // extensions.
  // Note that at this point, since we know we have a valid lightProbe, we also
  // know that we support whatever reflectionFormat it was created with, as it
  // would not have been created otherwise.
  switch (light_probe->ReflectionFormat()) {
    case XRLightProbe::kReflectionFormatRGBA16F:
      if (!webgl2_ && !webgl_context_->ExtensionsUtil()->IsExtensionEnabled(
                          "GL_OES_texture_half_float")) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kInvalidStateError,
            "WebGL contexts must have the OES_texture_half_float extension "
            "enabled "
            "prior to calling getReflectionCubeMap with a format of "
            "\"rgba16f\". "
            "This restriction does not apply to WebGL 2.0 contexts.");
        return nullptr;
      }

      internal_format = webgl2_ ? GL_RGBA16F : GL_RGBA;
      format = GL_RGBA;
      // Surprisingly GL_HALF_FLOAT and GL_HALF_FLOAT_OES have different values.
      type = webgl2_ ? GL_HALF_FLOAT : GL_HALF_FLOAT_OES;
      break;

    case XRLightProbe::kReflectionFormatSRGBA8:
      bool use_srgb =
          webgl2_ ||
          webgl_context_->ExtensionsUtil()->IsExtensionEnabled("GL_EXT_sRGB");

      if (use_srgb) {
        internal_format = webgl2_ ? GL_SRGB8_ALPHA8 : GL_SRGB_ALPHA_EXT;
      } else {
        internal_format = GL_RGBA;
      }

      format = webgl2_ ? GL_RGBA : internal_format;
      type = GL_UNSIGNED_BYTE;
      break;
  }

  XRCubeMap* cube_map = light_probe->getReflectionCubeMap();
  if (!cube_map) {
    return nullptr;
  }

  WebGLTexture* texture = MakeGarbageCollected<WebGLTexture>(webgl_context_);
  cube_map->updateWebGLEnvironmentCube(webgl_context_, texture, internal_format,
                                       format, type);

  return texture;
}

WebGLTexture* XRWebGLBinding::getCameraImage(XRCamera* camera,
                                             ExceptionState& exception_state) {
  DVLOG(3) << __func__;

  XRFrame* frame = camera->Frame();
  DCHECK(frame);

  XRSession* frame_session = frame->session();
  DCHECK(frame_session);

  if (!frame_session->IsFeatureEnabled(
          device::mojom::XRSessionFeature::CAMERA_ACCESS)) {
    DVLOG(2) << __func__ << ": raw camera access is not enabled on a session";
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        XRSession::kRawCameraAccessFeatureNotSupported);
    return nullptr;
  }

  if (!frame->IsActive()) {
    DVLOG(2) << __func__ << ": frame is not active";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      XRFrame::kInactiveFrame);
    return nullptr;
  }

  if (!frame->IsAnimationFrame()) {
    DVLOG(2) << __func__ << ": frame is not animating";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      XRFrame::kNonAnimationFrame);
    return nullptr;
  }

  if (session() != frame_session) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Camera comes from a different session than this binding");
    return nullptr;
  }

  XRWebGLLayer* base_layer = frame_session->renderState()->baseLayer();
  DCHECK(base_layer);

  // This resource is owned by the XRWebGLLayer, and is freed in OnFrameEnd();
  return base_layer->GetCameraTexture();
}

XRWebGLDepthInformation* XRWebGLBinding::getDepthInformation(
    XRView* view,
    ExceptionState& exception_state) {
  DVLOG(1) << __func__;

  XRFrame* frame = view->frame();

  if (session() != frame->session()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "View comes from a different session than this binding");
    return nullptr;
  }

  if (!session()->IsFeatureEnabled(device::mojom::XRSessionFeature::DEPTH)) {
    DVLOG(2) << __func__ << ": depth sensing is not enabled on a session";
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotSupportedError,
        XRSession::kDepthSensingFeatureNotSupported);
    return nullptr;
  }

  if (!frame->IsActive()) {
    DVLOG(2) << __func__ << ": frame is not active";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      XRFrame::kInactiveFrame);
    return nullptr;
  }

  if (!frame->IsAnimationFrame()) {
    DVLOG(2) << __func__ << ": frame is not animating";
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      XRFrame::kNonAnimationFrame);
    return nullptr;
  }

  return view->GetWebGLDepthInformation(exception_state);
}

void XRWebGLBinding::Trace(Visitor* visitor) const {
  visitor->Trace(webgl_context_);
  XRGraphicsBinding::Trace(visitor);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink

"""

```