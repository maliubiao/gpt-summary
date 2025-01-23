Response:
Let's break down the thought process for analyzing the `XRWebGLLayer.cc` file.

1. **Understand the Goal:** The request is to understand the functionality of this specific Chromium source file (`XRWebGLLayer.cc`), focusing on its relationship with web technologies (JavaScript, HTML, CSS), identifying logical reasoning, common errors, and debugging clues.

2. **Initial Scan and Keyword Spotting:**  Quickly read through the code, looking for keywords and familiar terms. "WebGL", "XRSession", "XRFrameProvider", "framebuffer", "viewport", "JavaScript", "HTMLCanvasElement" stand out. These immediately suggest the file is about integrating WebGL rendering into WebXR.

3. **Identify the Core Class:** The file defines the `XRWebGLLayer` class. This is the central element to understand. Its methods and member variables will reveal its purpose.

4. **Analyze the `Create` Method:** This static method is crucial for understanding how an `XRWebGLLayer` is instantiated.

    * **Parameters:** `XRSession`, `V8XRWebGLRenderingContext`, `XRWebGLLayerInit`, `ExceptionState`. This tells us it's created within the context of an XR session, using a WebGL context, and taking initialization options. The `ExceptionState` indicates potential error handling.
    * **Error Checks:** The code has numerous checks: `session->ended()`, `webgl_context->isContextLost()`, `!webgl_context->IsXRCompatible()`, `session->GraphicsApi()`. These checks highlight common reasons why layer creation might fail, which directly translates to potential user/programmer errors.
    * **Immersive vs. Inline Sessions:** The code branches based on `session->immersive()`. This is a fundamental distinction in WebXR, and the different handling suggests core functionalities diverge. Immersive sessions involve a separate framebuffer and compositor interaction.
    * **Framebuffer Allocation and Configuration:**  Keywords like `framebuffer_scale`, `antialias`, `depth`, `stencil`, `alpha` point to how the rendering target is configured. This connects to how developers control rendering quality and features.
    * **`XRWebGLDrawingBuffer`:**  The creation of this object for immersive sessions is significant. It acts as an intermediary between the WebGL context and the XR compositor.

5. **Analyze Key Methods:**  Focus on methods that seem to perform core actions:

    * **`framebufferWidth()`, `framebufferHeight()`:**  Getting the dimensions of the rendering target.
    * **`antialias()`:**  Checking if anti-aliasing is enabled.
    * **`getViewport()`:**  Crucial for how the rendered content is mapped onto the XR display. The scaling logic here is important.
    * **`UpdateViewports()`:** How the viewports are calculated based on session parameters.
    * **`OnFrameStart()`, `OnFrameEnd()`:** These methods clearly tie into the WebXR rendering loop. They handle framebuffer marking, shared image usage, and submission to the compositor.
    * **`OnResize()`:**  Handling changes in the output canvas or XR display size.
    * **`GetCameraTexture()`:**  Related to accessing camera feed within the XR environment.

6. **Identify Relationships with Web Technologies:**

    * **JavaScript:** The methods and the overall structure of `XRWebGLLayer` directly correspond to the WebXR API that JavaScript developers use. The `Create` method, accessing properties like `framebufferWidth`, and the rendering loop integration are all exposed to JS.
    * **HTML:** The `output_canvas()` method and the connection to `HTMLCanvasElement` link the XR rendering to the HTML structure.
    * **CSS:** While not directly manipulated by this C++ code, the resulting rendering on the canvas *is* subject to CSS styling if the canvas is part of a regular HTML page (for inline sessions). For immersive sessions, the CSS influence is minimal as the rendering is happening in a separate XR environment.

7. **Infer Logical Reasoning:** Look for conditional statements and calculations:

    * **Framebuffer scaling:** The clamping of `framebuffer_scale` demonstrates logic to ensure reasonable values.
    * **Viewport calculations:** The logic in `UpdateViewports()` based on stereoscopic vs. monoscopic views and viewport scaling.
    * **Clean frame warning:** The counter and warning mechanism in `OnFrameEnd()` implements a form of monitoring and feedback.

8. **Identify Potential User/Programmer Errors:**  The error checks in `Create` provide clear examples. Not marking a WebGL context as XR compatible, trying to use a lost context, or creating a layer after the session has ended are common pitfalls. The "clean frame" warning also points to a potential rendering issue.

9. **Trace User Operations (Debugging Clues):** Think about how a user's actions in a web application lead to the execution of this code:

    * The user navigates to a web page.
    * The JavaScript code on the page uses the WebXR API to request an XR session.
    * If the session requires WebGL rendering, the JavaScript will create an `XRWebGLLayer`. This is where the `Create` method is called.
    * During the animation frame loop (`requestAnimationFrame`), the browser's rendering engine will call `OnFrameStart()` and `OnFrameEnd()` on the `XRWebGLLayer` instance.
    * Resizing the browser window or the XR display triggers `OnResize()`.

10. **Structure the Output:** Organize the findings into logical categories as requested: functionality, relationships with web technologies, logical reasoning, user errors, and debugging clues. Provide concrete examples for each point.

11. **Refine and Elaborate:**  Review the generated output for clarity and completeness. Add more details and explanations where needed. For example, explain *why* certain checks are in place or what the implications of certain configurations are. Ensure the examples are clear and illustrative. For instance, explicitly showing JavaScript code that would trigger the `Create` method is very helpful.
This C++ source file, `xr_webgl_layer.cc`, within the Chromium Blink rendering engine, is responsible for managing the integration of WebGL rendering into WebXR experiences. It acts as a bridge between the WebXR API (used by JavaScript) and the underlying graphics system.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Creating and Managing WebGL Layers for XR Sessions:** The primary purpose is to create and manage `XRWebGLLayer` objects. These layers represent a surface onto which WebGL content can be rendered within an XR session.
* **Associating with WebGL Contexts:** It takes a `WebGLRenderingContextBase` as input, linking the XR layer to a specific WebGL rendering context. This is the context that the web application will use to draw 3D graphics.
* **Framebuffer Management (for Immersive Sessions):** For immersive XR sessions (where the user is fully immersed in VR or AR), this class manages the framebuffer used for rendering. This includes:
    * **Creation of an offscreen framebuffer:**  It can create a dedicated framebuffer separate from the main browser window's canvas.
    * **Framebuffer scaling:** It supports scaling the framebuffer resolution, allowing developers to trade off rendering quality for performance.
    * **Framebuffer properties:**  It handles options like antialiasing, depth buffers, and stencil buffers for the framebuffer.
* **Viewport Management:** It calculates and manages the viewports within the framebuffer for each eye in stereoscopic displays (or a single viewport for monoscopic displays). This defines the region of the framebuffer that each view renders to.
* **Interfacing with the XR Compositor:**  It interacts with the XR compositor (the system component responsible for displaying the XR scene) to submit the rendered WebGL content for display.
* **Handling Shared Images (for direct rendering):** It supports the use of shared memory buffers for more efficient rendering, allowing the WebGL context to render directly into a buffer that the compositor can access.
* **Camera Texture Integration:** It handles the integration of camera feeds into the WebGL scene by creating and managing WebGL textures from shared camera image buffers.
* **Lifecycle Management:** It manages the lifecycle of the layer, including destruction and cleanup of resources.

**Relationships with JavaScript, HTML, and CSS:**

* **JavaScript:** This C++ code directly implements the functionality exposed by the `XRWebGLLayer` JavaScript API.
    * **Creation:** When JavaScript calls `session.requestAnimationFrame()` and the callback attempts to create an `XRWebGLLayer` (e.g., `session.renderState.baseLayer = new XRWebGLLayer(session, glContext)`), this C++ code's `Create` method is invoked.
    * **Properties:** JavaScript can access properties like `layer.framebufferWidth`, `layer.framebufferHeight`, and `layer.antialias`. These properties are backed by the data managed in this C++ file.
    * **Methods:** JavaScript calls methods like `layer.getViewport(view)`, which maps to the `GetViewport` method in this C++ file.

    **Example:**
    ```javascript
    navigator.xr.requestSession('immersive-vr').then(session => {
      const gl = canvas.getContext('webgl', { xrCompatible: true });
      session.updateRenderState({
        baseLayer: new XRWebGLLayer(session, gl)
      });

      session.requestAnimationFrame(function render(time, frame) {
        const glLayer = session.renderState.baseLayer;
        const pose = frame.getViewerPose(session.referenceSpace);
        if (pose) {
          pose.views.forEach(view => {
            const viewport = glLayer.getViewport(view);
            gl.bindFramebuffer(gl.FRAMEBUFFER, glLayer.framebuffer); // Using the managed framebuffer
            gl.viewport(viewport.x, viewport.y, viewport.width, viewport.height);
            // ... render scene for this view ...
          });
        }
        session.requestAnimationFrame(render);
      });
    });
    ```

* **HTML:** The `XRWebGLLayer` is often associated with an `<canvas>` element in the HTML. The WebGL rendering context used by the layer is typically obtained from this canvas.
    * **`output_canvas()` method:** This method in the C++ code returns the `HTMLCanvasElement` associated with the WebGL context (for inline sessions where a separate framebuffer isn't used).

    **Example:**
    ```html
    <canvas id="myCanvas"></canvas>
    <script>
      const canvas = document.getElementById('myCanvas');
      // ... request XR session and create XRWebGLLayer using the canvas's WebGL context ...
    </script>
    ```

* **CSS:** While CSS doesn't directly control the rendering *within* the WebGL context or the XR environment, it can affect the `<canvas>` element's styling and layout in the HTML page, especially for inline XR sessions. However, for immersive sessions with a separate framebuffer, CSS has minimal direct impact on the XR rendering.

**Logical Reasoning and Assumptions:**

* **Immersive vs. Inline Sessions:** The code makes a distinction between immersive and inline XR sessions. Immersive sessions typically require dedicated framebuffers and interaction with the XR compositor, while inline sessions might render directly to the existing canvas.
    * **Assumption:** If `session->immersive()` is true, the system needs to manage a separate framebuffer.
    * **Output:** Based on this assumption, different code paths are taken for framebuffer creation and submission.
* **Stereoscopic Rendering:** The code assumes that for stereoscopic displays, there will be two views (left and right).
    * **Input:** The `session()->StereoscopicViews()` method indicates whether the session is stereoscopic.
    * **Output:** The `UpdateViewports()` method calculates separate viewports for the left and right eyes.
* **Framebuffer Scaling:** The code implements logic to clamp the requested framebuffer scale to reasonable values.
    * **Input:** `initializer->framebufferScaleFactor()` provides the developer's requested scale.
    * **Logic:** The scale is clamped between `kFramebufferMinScale` and `max_scale` to prevent excessively small or large framebuffers.
    * **Output:** The clamped `framebuffer_scale` is used to determine the framebuffer dimensions.
* **Clean Frame Warning:** The code includes logic to detect and warn the developer if the application isn't drawing anything to the framebuffer for multiple consecutive frames.
    * **Assumption:**  A clean framebuffer during an active XR session is often an error.
    * **Input:** `framebuffer_->HaveContentsChanged()` indicates if the framebuffer was modified.
    * **Logic:** A counter (`clean_frame_count`) is incremented for consecutive clean frames, and a console warning is issued if the limit is reached.
    * **Output:** A console warning message.

**User and Programming Common Errors:**

* **Creating a Layer for an Ended Session:**
    * **User Action (Programming):**  Attempting to create an `XRWebGLLayer` after the XR session has already ended.
    * **Code:**
      ```javascript
      navigator.xr.requestSession('immersive-vr').then(session => {
        session.end(); // End the session
        const gl = canvas.getContext('webgl', { xrCompatible: true });
        const layer = new XRWebGLLayer(session, gl); // Error here
      }).catch(error => { console.error(error); });
      ```
    * **Exception:** The C++ code throws a `DOMExceptionCode::kInvalidStateError` with the message: "Cannot create an XRWebGLLayer for an XRSession which has already ended."
* **Using a Lost WebGL Context:**
    * **User Action (Programming):** Trying to create a layer with a WebGL context that has been lost (e.g., due to GPU issues).
    * **Code:**
      ```javascript
      const gl = canvas.getContext('webgl', { xrCompatible: true });
      gl.getExtension('WEBGL_lose_context').loseContext(); // Simulate context loss
      navigator.xr.requestSession('immersive-vr').then(session => {
        const layer = new XRWebGLLayer(session, gl); // Error here
      }).catch(error => { console.error(error); });
      ```
    * **Exception:** The C++ code throws a `DOMExceptionCode::kInvalidStateError` with the message: "Cannot create an XRWebGLLayer with a lost WebGL context."
* **Using a Non-XR-Compatible WebGL Context with an Immersive Session:**
    * **User Action (Programming):** Creating an immersive XR session but forgetting to initialize the WebGL context with the `xrCompatible: true` option.
    * **Code:**
      ```javascript
      const gl = canvas.getContext('webgl'); // Missing xrCompatible: true
      navigator.xr.requestSession('immersive-vr').then(session => {
        const layer = new XRWebGLLayer(session, gl); // Error here
      }).catch(error => { console.error(error); });
      ```
    * **Exception:** The C++ code throws a `DOMExceptionCode::kInvalidStateError` with the message: "WebGL context must be marked as XR compatible in order to use with an immersive XRSession".
* **Not Drawing to the Framebuffer:**
    * **User Action (Programming):** The application's rendering loop doesn't actually draw anything to the WebGL framebuffer associated with the `XRWebGLLayer`. This could be due to incorrect render targets, logic errors in the rendering code, or other issues.
    * **Code:** The JavaScript rendering loop might bind the wrong framebuffer or have errors in the drawing calls.
    * **Output:** After `kCleanFrameWarningLimit` (5) consecutive frames where the framebuffer hasn't been modified, the C++ code will log a warning to the browser's developer console: "Note: The XRSession has completed multiple animation frames without drawing anything to the baseLayer's framebuffer, resulting in no visible output."

**User Operations as Debugging Clues:**

To reach this code during debugging, the following user operations and code execution would typically occur:

1. **User Navigates to a Web Page:** The user opens a web page that utilizes the WebXR API.
2. **JavaScript Requests an XR Session:** The JavaScript code on the page calls `navigator.xr.requestSession('immersive-vr' or 'inline')`.
3. **WebGL Context is Obtained:** The JavaScript code gets a WebGL rendering context from a `<canvas>` element, typically with the `xrCompatible: true` option for immersive sessions.
4. **`XRWebGLLayer` is Created:** The JavaScript code creates a new `XRWebGLLayer` instance, passing the XR session and the WebGL context: `new XRWebGLLayer(session, gl)`. This is where the `XRWebGLLayer::Create` method in this C++ file is called.
5. **Session Enters the Rendering Loop:** The XR session enters its active state, and the browser starts calling the `requestAnimationFrame` callback.
6. **`OnFrameStart()` is Called:** At the beginning of each frame, the `XRWebGLLayer::OnFrameStart()` method is called. This might involve preparing shared buffers or textures.
7. **WebGL Rendering Occurs:** The JavaScript code in the `requestAnimationFrame` callback performs WebGL rendering, typically drawing to the framebuffer associated with the `XRWebGLLayer`.
8. **`OnFrameEnd()` is Called:** After the JavaScript rendering, the `XRWebGLLayer::OnFrameEnd()` method is called. This is where the rendered content is submitted to the XR compositor. The "clean frame" check also happens here.
9. **User Resizes the Window (for Inline Sessions):** If the user resizes the browser window in an inline XR session, the `XRWebGLLayer::OnResize()` method is called to update the framebuffer and viewport sizes.
10. **Session Ends:** When the XR session ends (either programmatically or by user action), the `XRWebGLLayer` object will eventually be destructed.

**Debugging Steps to Reach This Code:**

* **Set Breakpoints:**  In Chromium's debugger, you can set breakpoints in the `XRWebGLLayer::Create`, `XRWebGLLayer::OnFrameStart`, `XRWebGLLayer::OnFrameEnd`, and `XRWebGLLayer::OnResize` methods.
* **Inspect Call Stack:** When a breakpoint is hit, examine the call stack to understand how the execution reached this code. You'll see calls originating from JavaScript and the browser's rendering pipeline.
* **Check Object Properties:** Inspect the properties of the `XRWebGLLayer` object, the associated `XRSession`, and the `WebGLRenderingContextBase` to understand their state.
* **Monitor Console Output:** Pay attention to any console warnings logged by this code, such as the "clean frame" warning.
* **Trace WebGL Calls:** Use WebGL debugging tools to monitor the WebGL API calls made by the JavaScript application to ensure it's rendering correctly to the intended framebuffer.

This comprehensive overview should give you a good understanding of the `xr_webgl_layer.cc` file's role and its interactions within the Chromium Blink rendering engine and the WebXR ecosystem.

### 提示词
```
这是目录为blink/renderer/modules/xr/xr_webgl_layer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
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

#include "third_party/blink/renderer/modules/xr/xr_webgl_layer.h"

#include <algorithm>
#include <utility>

#include "base/numerics/safe_conversions.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/imagebitmap/image_bitmap.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/modules/webgl/webgl_framebuffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_rendering_context_base.h"
#include "third_party/blink/renderer/modules/xr/xr_frame_provider.h"
#include "third_party/blink/renderer/modules/xr/xr_session.h"
#include "third_party/blink/renderer/modules/xr/xr_system.h"
#include "third_party/blink/renderer/modules/xr/xr_utils.h"
#include "third_party/blink/renderer/modules/xr/xr_view.h"
#include "third_party/blink/renderer/modules/xr/xr_viewport.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/size_f.h"

namespace blink {

namespace {

const double kFramebufferMinScale = 0.2;
const uint32_t kCleanFrameWarningLimit = 5;

const char kCleanFrameWarning[] =
    "Note: The XRSession has completed multiple animation frames without "
    "drawing anything to the baseLayer's framebuffer, resulting in no visible "
    "output.";

}  // namespace

XRWebGLLayer* XRWebGLLayer::Create(XRSession* session,
                                   const V8XRWebGLRenderingContext* context,
                                   const XRWebGLLayerInit* initializer,
                                   ExceptionState& exception_state) {
  if (session->ended()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot create an XRWebGLLayer for an "
                                      "XRSession which has already ended.");
    return nullptr;
  }

  WebGLRenderingContextBase* webgl_context =
      webglRenderingContextBaseFromUnion(context);

  if (webgl_context->isContextLost()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot create an XRWebGLLayer with a "
                                      "lost WebGL context.");
    return nullptr;
  }

  if (session->immersive() && !webgl_context->IsXRCompatible()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "WebGL context must be marked as XR compatible in order to "
        "use with an immersive XRSession");
    return nullptr;
  }

  if (session->GraphicsApi() != XRGraphicsBinding::Api::kWebGL) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot create an XRWebGLLayer with a "
                                      "WebGPU-based XRSession.");
    return nullptr;
  }

  // TODO(crbug.com/941753): In the future this should be communicated by the
  // drawing buffer and indicate whether the depth buffers are being supplied to
  // the XR compositor.
  bool compositor_supports_depth_values = false;
  bool want_ignore_depth_values = initializer->ignoreDepthValues();

  if (want_ignore_depth_values) {
    UseCounter::Count(session->GetExecutionContext(),
                      WebFeature::kWebXrIgnoreDepthValues);
  }

  // The ignoreDepthValues attribute of XRWebGLLayer may only be set to false if
  // the compositor is actually making use of the depth values and the user did
  // not set ignoreDepthValues to true explicitly.
  bool ignore_depth_values =
      !compositor_supports_depth_values || want_ignore_depth_values;

  double framebuffer_scale = 1.0;

  // Inline sessions don't go through the XR compositor, so they don't need to
  // allocate a separate drawing buffer or expose a framebuffer.
  if (!session->immersive()) {
    return MakeGarbageCollected<XRWebGLLayer>(session, webgl_context, nullptr,
                                              nullptr, framebuffer_scale,
                                              ignore_depth_values);
  }

  const bool want_antialiasing =
      initializer->antialias() && session->CanEnableAntiAliasing();
  const bool want_depth_buffer = initializer->depth();
  const bool want_stencil_buffer = initializer->stencil();
  const bool want_alpha_channel = initializer->alpha();

  // Allocate a drawing buffer to back the framebuffer if needed.
  if (initializer->hasFramebufferScaleFactor()) {
    UseCounter::Count(session->GetExecutionContext(),
                      WebFeature::kWebXrFramebufferScale);

    // The max size will be either the native resolution or the default
    // if that happens to be larger than the native res. (That can happen on
    // desktop systems.)
    double max_scale = std::max(session->NativeFramebufferScale(), 1.0);

    // Clamp the developer-requested framebuffer size to ensure it's not too
    // small to see or unreasonably large.
    // TODO(bajones): Would be best to have the max value communicated from the
    // service rather than limited to the native res.
    framebuffer_scale = std::clamp(initializer->framebufferScaleFactor(),
                                   kFramebufferMinScale, max_scale);
  }

  gfx::SizeF framebuffers_size = session->RecommendedFramebufferSize();

  gfx::Size desired_size =
      gfx::ToFlooredSize(gfx::ScaleSize(framebuffers_size, framebuffer_scale));

  // Create an opaque WebGL Framebuffer
  WebGLFramebuffer* framebuffer = WebGLFramebuffer::CreateOpaque(
      webgl_context, want_depth_buffer, want_stencil_buffer);

  scoped_refptr<XRWebGLDrawingBuffer> drawing_buffer =
      XRWebGLDrawingBuffer::Create(webgl_context->GetDrawingBuffer(),
                                   framebuffer->Object(), desired_size,
                                   want_alpha_channel, want_depth_buffer,
                                   want_stencil_buffer, want_antialiasing);

  if (!drawing_buffer) {
    exception_state.ThrowDOMException(DOMExceptionCode::kOperationError,
                                      "Unable to create a framebuffer.");
    return nullptr;
  }

  return MakeGarbageCollected<XRWebGLLayer>(
      session, webgl_context, std::move(drawing_buffer), framebuffer,
      framebuffer_scale, ignore_depth_values);
}

XRWebGLLayer::XRWebGLLayer(XRSession* session,
                           WebGLRenderingContextBase* webgl_context,
                           scoped_refptr<XRWebGLDrawingBuffer> drawing_buffer,
                           WebGLFramebuffer* framebuffer,
                           double framebuffer_scale,
                           bool ignore_depth_values)
    : XRLayer(session),
      webgl_context_(webgl_context),
      framebuffer_(framebuffer),
      framebuffer_scale_(framebuffer_scale),
      ignore_depth_values_(ignore_depth_values) {
  if (framebuffer) {
    // Must have a drawing buffer for immersive sessions.
    DCHECK(drawing_buffer);
    drawing_buffer_ = std::move(drawing_buffer);
  } else {
    // Only inline sessions are allowed to have a null drawing buffer.
    DCHECK(!session->immersive());
  }

  UpdateViewports();
}

XRWebGLLayer::~XRWebGLLayer() {
  if (drawing_buffer_) {
    drawing_buffer_->BeginDestruction();
  }
}

uint32_t XRWebGLLayer::framebufferWidth() const {
  if (drawing_buffer_) {
    return drawing_buffer_->size().width();
  }
  return webgl_context_->drawingBufferWidth();
}

uint32_t XRWebGLLayer::framebufferHeight() const {
  if (drawing_buffer_) {
    return drawing_buffer_->size().height();
  }
  return webgl_context_->drawingBufferHeight();
}

bool XRWebGLLayer::antialias() const {
  if (drawing_buffer_) {
    return drawing_buffer_->antialias();
  }
  if (!webgl_context_->isContextLost()) {
    return webgl_context_->GetDrawingBuffer()->Multisample();
  }
  return false;
}

XRViewport* XRWebGLLayer::getViewport(XRView* view) {
  if (!view || view->session() != session())
    return nullptr;

  if (view->ViewData()->ApplyViewportScaleForFrame()) {
    UpdateViewports();
  }

  // framebuffer_scale_ is the scale requested by the web developer when this
  // layer was created. The session's recommended framebuffer scale is the scale
  // requested by the XR runtime. Both scales must be applied to the viewport.
  return view->Viewport(framebuffer_scale_ *
                        session()->RecommendedFramebufferScale());
}

XRViewport* XRWebGLLayer::GetViewportForEye(device::mojom::blink::XREye eye) {
  if (viewports_dirty_)
    UpdateViewports();

  if (eye == device::mojom::blink::XREye::kRight)
    return right_viewport_.Get();

  // This code path also handles an eye of "none".
  return left_viewport_.Get();
}

double XRWebGLLayer::getNativeFramebufferScaleFactor(XRSession* session) {
  return session->NativeFramebufferScale();
}

void XRWebGLLayer::UpdateViewports() {
  uint32_t framebuffer_width = framebufferWidth();
  uint32_t framebuffer_height = framebufferHeight();
  if (framebuffer_width == 0U || framebuffer_height == 0U) {
    LOG_IF(ERROR, !webgl_context_->isContextLost())
        << __func__ << " Received width=" << framebuffer_width
        << " height=" << framebuffer_height << " without having lost context";
    return;
  }

  viewports_dirty_ = false;

  // When calculating the scaled viewport size, round down to integer value, but
  // ensure that the value is nonzero and doesn't overflow. See
  // https://immersive-web.github.io/webxr/#xrview-obtain-a-scaled-viewport
  auto rounded = [](double v) {
    return std::max(1, base::saturated_cast<int>(v));
  };

  if (session()->immersive()) {
    // Calculate new sizes with optional viewport scale applied. This assumes
    // that XRSession::views() returns views in matching order.
    if (session()->StereoscopicViews()) {
      // TODO(1275873): This technically works fine because the entire bounds is
      // still sent to the XR process, but if there are more than two views,
      // the terms "left" and "right" are not accurate. The entire bounds of
      // all viewports should be sent instead.
      double left_scale =
          session()
              ->ViewDataForEye(device::mojom::blink::XREye::kLeft)
              ->CurrentViewportScale();
      left_viewport_ = MakeGarbageCollected<XRViewport>(
          0, 0, rounded(framebuffer_width * 0.5 * left_scale),
          rounded(framebuffer_height * left_scale));
      double right_scale =
          session()
              ->ViewDataForEye(device::mojom::blink::XREye::kRight)
              ->CurrentViewportScale();
      right_viewport_ = MakeGarbageCollected<XRViewport>(
          framebuffer_width * 0.5, 0,
          rounded(framebuffer_width * 0.5 * right_scale),
          rounded(framebuffer_height * right_scale));
    } else {
      // Phone immersive AR only uses one viewport, but the second viewport is
      // needed for the UpdateLayerBounds mojo call which currently expects
      // exactly two views. This should be revisited as part of a refactor to
      // handle a more general list of viewports, cf. https://crbug.com/928433.
      double mono_scale =
          session()
              ->ViewDataForEye(device::mojom::blink::XREye::kNone)
              ->CurrentViewportScale();
      left_viewport_ = MakeGarbageCollected<XRViewport>(
          0, 0, rounded(framebuffer_width * mono_scale),
          rounded(framebuffer_height * mono_scale));
      right_viewport_ = nullptr;
    }

    session()->xr()->frameProvider()->UpdateWebGLLayerViewports(this);
  } else {
    // Currently, only immersive sessions implement dynamic viewport scaling.
    // Ignore the setting for non-immersive sessions, effectively treating
    // the minimum viewport scale as 1.0 which disables the feature.
    left_viewport_ = MakeGarbageCollected<XRViewport>(0, 0, framebuffer_width,
                                                      framebuffer_height);
  }
}

HTMLCanvasElement* XRWebGLLayer::output_canvas() const {
  if (!framebuffer_) {
    return webgl_context_->canvas();
  }
  return nullptr;
}

WebGLTexture* XRWebGLLayer::GetCameraTexture() {
  DVLOG(1) << __func__;

  // We already have a WebGL texture for the camera image - return it:
  if (camera_image_texture_) {
    return camera_image_texture_.Get();
  }

  // We don't have a WebGL texture, and we cannot create it - return null:
  if (!camera_image_shared_image_texture_) {
    return nullptr;
  }

  // We don't have a WebGL texture, but we can create it, so create, store and
  // return it:
  camera_image_texture_ = MakeGarbageCollected<WebGLUnownedTexture>(
      webgl_context_, camera_image_shared_image_texture_->id(), GL_TEXTURE_2D);

  return camera_image_texture_.Get();
}

void XRWebGLLayer::OnFrameStart() {
  if (framebuffer_) {
    framebuffer_->MarkOpaqueBufferComplete(true);
    framebuffer_->SetContentsChanged(false);

    const XRLayerSharedImages& layer_shared_images = GetSharedImages();
    const XRSharedImageData& content_image_data =
        layer_shared_images.content_image_data;
    const XRSharedImageData& camera_image_data =
        layer_shared_images.camera_image_data;

    if (content_image_data.shared_image) {
      drawing_buffer_->UseSharedBuffer(content_image_data.shared_image,
                                       content_image_data.sync_token);
      DVLOG(3) << __func__ << ": content_image_data.shared_image->mailbox()="
               << content_image_data.shared_image->mailbox().ToDebugString();
      is_direct_draw_frame = true;
    } else {
      is_direct_draw_frame = false;
    }

    if (camera_image_data.shared_image) {
      DVLOG(3) << __func__ << ": camera_image_data.shared_image->mailbox()"
               << camera_image_data.shared_image->mailbox().ToDebugString();
      CreateAndBindCameraBufferTexture(camera_image_data.shared_image,
                                       camera_image_data.sync_token);
    }
  }
}

void XRWebGLLayer::CreateAndBindCameraBufferTexture(
    const scoped_refptr<gpu::ClientSharedImage>& buffer_shared_image,
    const gpu::SyncToken& buffer_sync_token) {
  gpu::gles2::GLES2Interface* gl = drawing_buffer_->ContextGL();

  DVLOG(3) << __func__
           << ": buffer_sync_token=" << buffer_sync_token.ToDebugString();
  camera_image_shared_image_texture_ = buffer_shared_image->CreateGLTexture(gl);
  DVLOG(3) << __func__ << ": camera_image_shared_image_texture_->id()="
           << camera_image_shared_image_texture_->id();
  if (buffer_shared_image) {
    uint32_t texture_target = buffer_shared_image->GetTextureTarget();
    camera_image_texture_scoped_access_ =
        camera_image_shared_image_texture_->BeginAccess(buffer_sync_token,
                                                        /*readonly=*/true);
    gl->BindTexture(texture_target,
                    camera_image_texture_scoped_access_->texture_id());
  }
}

void XRWebGLLayer::OnFrameEnd() {
  // The session might have ended in the middle of the frame. Only perform the
  // main work of OnFrameEnd if it's still valid. Otherwise, simply ensure the
  // shared image access is properly ended.
  if (session()->ended()) {
    if (is_direct_draw_frame) {
      drawing_buffer_->DoneWithSharedBuffer();
      is_direct_draw_frame = false;
    }

    if (camera_image_texture_scoped_access_) {
      gpu::SharedImageTexture::ScopedAccess::EndAccess(
          std::move(camera_image_texture_scoped_access_));
      camera_image_shared_image_texture_.reset();
    }
    return;
  }

  if (framebuffer_) {
    framebuffer_->MarkOpaqueBufferComplete(false);
    if (is_direct_draw_frame) {
      drawing_buffer_->DoneWithSharedBuffer();
      is_direct_draw_frame = false;
    }

    // Submit the frame to the XR compositor.
    if (session()->immersive()) {
      bool framebuffer_dirty = framebuffer_->HaveContentsChanged();

      // Not drawing to the framebuffer during a session's rAF callback is
      // usually a sign that something is wrong, such as the app drawing to the
      // wrong render target. Show a warning in the console if we see that
      // happen too many times.
      if (!framebuffer_dirty) {
        // If the session doesn't have a pose then the framebuffer being clean
        // may be expected, so we won't count those frames.
        bool frame_had_pose = !!session()->GetMojoFrom(
            device::mojom::blink::XRReferenceSpaceType::kViewer);
        if (frame_had_pose) {
          clean_frame_count++;
          if (clean_frame_count == kCleanFrameWarningLimit) {
            session()->xr()->GetExecutionContext()->AddConsoleMessage(
                MakeGarbageCollected<ConsoleMessage>(
                    mojom::blink::ConsoleMessageSource::kRendering,
                    mojom::blink::ConsoleMessageLevel::kWarning,
                    kCleanFrameWarning));
          }
        }
      }

      // Need to stop accessing the camera image texture before calling
      // `SubmitWebGLLayer` so that we stop using it before the sync token
      // that `SubmitWebGLLayer` will generate.
      if (camera_image_shared_image_texture_) {
        const XRLayerSharedImages& layer_shared_images = GetSharedImages();
        // We shouldn't ever have a camera texture if the holder wasn't present:
        CHECK(layer_shared_images.camera_image_data.shared_image);

        DVLOG(3) << __func__
                 << ": deleting camera image texture, "
                    "camera_image_shared_image_texture_->id()="
                 << camera_image_shared_image_texture_->id();

        gpu::SharedImageTexture::ScopedAccess::EndAccess(
            std::move(camera_image_texture_scoped_access_));
        camera_image_shared_image_texture_.reset();

        // Notify our WebGLUnownedTexture (created from
        // camera_image_shared_image_texture_) that we have deleted it. Also,
        // release the reference since we no longer need it (note that it could
        // still be kept alive by the JS application, but should be a defunct
        // object).
        if (camera_image_texture_) {
          camera_image_texture_->OnGLDeleteTextures();
          camera_image_texture_ = nullptr;
        }
      }

      // Always call submit, but notify if the contents were changed or not.
      session()->xr()->frameProvider()->SubmitWebGLLayer(this,
                                                         framebuffer_dirty);
    }
  }
}

void XRWebGLLayer::OnResize() {
  if (drawing_buffer_) {
    gfx::SizeF framebuffers_size = session()->RecommendedFramebufferSize();

    gfx::Size desired_size = gfx::ToFlooredSize(
        gfx::ScaleSize(framebuffers_size, framebuffer_scale_));
    drawing_buffer_->Resize(desired_size);
  }

  // With both immersive and non-immersive session the viewports should be
  // recomputed when the output canvas resizes.
  viewports_dirty_ = true;
}

scoped_refptr<StaticBitmapImage> XRWebGLLayer::TransferToStaticBitmapImage() {
  if (drawing_buffer_) {
    return drawing_buffer_->TransferToStaticBitmapImage();
  }
  return nullptr;
}

void XRWebGLLayer::Trace(Visitor* visitor) const {
  visitor->Trace(left_viewport_);
  visitor->Trace(right_viewport_);
  visitor->Trace(webgl_context_);
  visitor->Trace(framebuffer_);
  visitor->Trace(camera_image_texture_);
  XRLayer::Trace(visitor);
}

}  // namespace blink
```