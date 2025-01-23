Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Core Purpose:** The file name `xr_gpu_binding.cc` immediately suggests a connection between WebXR and WebGPU. The `Binding` suffix hints at an interface or bridge between these two technologies. Reading the initial comments confirms this: it's about using WebGPU to render content in a WebXR session.

2. **Identify Key Classes and Concepts:**  Scan the `#include` directives and the class definition `XRGPUBinding`. This reveals the involved entities:
    * `XRGPUBinding`: The central class being analyzed.
    * `XRSession`: Represents an XR session.
    * `GPUDevice`: Represents a WebGPU device.
    * `XRProjectionLayer`: A layer used for rendering in XR.
    * `GPUTexture`: A WebGPU texture.
    * `XRView`: Represents a single viewpoint within an XR scene.
    * `XRGPUSubImage`: Represents a portion of a texture used for a specific view.
    * `XRGPUSwapChain`: Manages a series of textures for rendering.
    * `XRGPUTextureArraySwapChain`:  A specialized swap chain likely dealing with multiple texture layers.
    * `XRFrameProvider`:  Provides frames for the XR session.
    *  Various WebGPU-related types (`wgpu::TextureDescriptor`, `wgpu::TextureUsage`, etc.)

3. **Analyze the `Create` Method:** This is the entry point for creating an `XRGPUBinding`. Pay attention to the error conditions checked:
    * Session ended.
    * Session is inline (not immersive).
    * WebGPU device is destroyed.
    * WebGPU adapter is not XR compatible.
    * Session is not using WebGPU. These checks tell us the prerequisites for a valid `XRGPUBinding`.

4. **Examine `createProjectionLayer`:**  This method is responsible for creating a renderable layer. Note the following steps:
    * **Validation:** `CanCreateLayer` checks for basic validity (session not ended, device not destroyed).
    * **Scaling:**  The code calculates a `scale_factor` and applies it to the recommended texture size. This is crucial for performance and quality. The clamping of `scale_factor` is important to note (minimum and maximum).
    * **Texture Creation:**  `wgpu::TextureDescriptor` defines the properties of the textures used for rendering. The code creates both color and potentially depth/stencil textures.
    * **Swap Chains:**  Different swap chain types are created based on whether the session is drawing into a shared buffer. This is an important internal optimization. The comment about `XRGPUTextureArraySwapChain` being temporary is also valuable.
    * **`XRGPUProjectionLayer` Instantiation:** Finally, the layer object is created with the necessary swap chains.

5. **Investigate `getViewSubImage`:**  This method retrieves a portion of the rendering texture for a specific view. Key points:
    * **Ownership Check:**  Ensures the layer belongs to the current binding.
    * **View Validation:**  Ensures the view belongs to the same session.
    * **Texture Retrieval:** Gets the current color and depth/stencil textures from the layer's swap chains.
    * **Viewport Calculation:** `GetViewportForView` determines the rectangular region of the texture for the view.
    * **`XRGPUSubImage` Creation:** The sub-image object encapsulates the viewport and the textures.

6. **Understand `GetViewportForView`:** This is a straightforward calculation based on the layer's texture size and the view's viewport scale.

7. **Note `getPreferredColorFormat`:**  A simple method to get the preferred texture format, though the comment suggests this might change.

8. **Consider Error Handling and Validation:**  The code extensively uses `ExceptionState` to report errors. This is standard practice in Blink.

9. **Connect to Web Concepts (JavaScript, HTML, CSS):**  Now, the crucial step is to relate this C++ code to front-end technologies.
    * **JavaScript:**  The most direct link is through the WebXR API in JavaScript. A developer using `navigator.xr.requestSession('immersive-vr', { ... })` and then getting a `GPUDevice` via `requestAdapter` and `requestDevice` is the starting point. Methods like `session.requestAnimationFrame` and creating projection layers using `session.createProjectionLayer` are the JavaScript counterparts.
    * **HTML:**  While not directly manipulating this C++ code, the HTML page sets the context. It's where the JavaScript code runs. The `<canvas>` element (though not directly used by WebGPU like WebGL) represents the rendering target conceptually.
    * **CSS:**  CSS has a minimal direct impact here. It might influence the overall layout of the page containing the XR experience, but the core rendering logic is within WebXR and WebGPU.

10. **Formulate Examples:** Based on the analysis, construct concrete examples of how JavaScript interacts with the functionalities of this C++ code. Illustrate error scenarios and provide code snippets.

11. **Trace User Actions:**  Think about the sequence of user interactions that would lead to this code being executed. This involves enabling XR in the browser, visiting a WebXR page, granting permissions, and the JavaScript code initiating the XR session and rendering setup.

12. **Refine and Organize:**  Structure the findings logically, grouping related information together. Use clear and concise language. Ensure the explanation is accessible to someone familiar with web development concepts, even if they don't have deep C++ knowledge.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the C++ implementation details.
* **Correction:**  Shift focus to the *functionality* exposed by the C++ code and how it relates to the WebXR and WebGPU APIs.
* **Initial thought:**  Overlook the error handling aspects.
* **Correction:**  Emphasize the error checks in the `Create` and `createProjectionLayer` methods, and how these relate to potential developer errors.
* **Initial thought:**  Provide a very technical, low-level explanation.
* **Correction:**  Frame the explanation in terms of user-facing features and developer APIs, connecting the C++ to higher-level concepts.
* **Initial thought:**  Not explicitly consider debugging.
* **Correction:** Include the "User Operation and Debugging Clues" section to provide practical context.

By following this iterative process of understanding, analyzing, connecting, and refining, you can arrive at a comprehensive and helpful explanation of the given C++ code snippet.
好的，让我们来分析一下 `blink/renderer/modules/xr/xr_gpu_binding.cc` 文件的功能。

**核心功能：**

`XRGPUBinding` 类的主要职责是 **将 WebXR API 与 WebGPU API 连接起来**，允许开发者使用 WebGPU 来渲染沉浸式 WebXR 体验。它充当了一个桥梁，使得 WebXR 能够利用 WebGPU 提供的现代图形渲染能力。

**具体功能分解：**

1. **创建 `XRGPUBinding` 实例：**
   - `XRGPUBinding::Create(XRSession* session, GPUDevice* device, ExceptionState& exception_state)` 是创建 `XRGPUBinding` 对象的工厂方法。
   - 它会进行一系列的 **合法性检查**，确保：
     - `XRSession` 存在且未结束。
     - `XRSession` 是沉浸式会话（`immersive()` 为 true），而不是内联会话。
     - `GPUDevice` 存在且未被销毁。
     - `GPUDevice` 是由一个支持 XR 的适配器创建的（`device->adapter()->isXRCompatible()` 为 true）。
     - `XRSession` 使用的图形 API 是 WebGPU（`session->GraphicsApi() == XRGraphicsBinding::Api::kWebGPU`）。
   - 如果任何检查失败，它会抛出相应的 DOM 异常，阻止 `XRGPUBinding` 的创建。

2. **创建投影层 (`XRProjectionLayer`)：**
   - `XRGPUBinding::createProjectionLayer(const XRGPUProjectionLayerInit* init, ExceptionState& exception_state)` 方法负责创建用于渲染 XR 内容的投影层。
   - 它首先调用 `CanCreateLayer` 进行基础检查（会话未结束，设备未销毁）。
   - 接下来，它会根据 `XRGPUProjectionLayerInit` 中的 `scaleFactor` 和会话的推荐纹理大小，以及设备的最大纹理尺寸，计算出 **合适的纹理尺寸**。这里涉及到一些 **逻辑推理和限制**，以保证性能和兼容性。
   - 然后，它会创建 **颜色缓冲区交换链 (`XRGPUSwapChain`)**，用于存储渲染的颜色数据。根据会话是否使用共享缓冲区，会创建不同类型的交换链 (`XRGPUMailboxSwapChain` 或 `XRGPUStaticSwapChain`)。
   - 如果需要，它还会创建一个 **深度/模板缓冲区交换链 (`XRGPUStaticSwapChain`)**。
   - 最后，它创建一个 `XRGPUProjectionLayer` 对象，关联着创建的颜色和深度/模板缓冲区交换链。

3. **获取视图的子图像 (`XRGPUSubImage`)：**
   - `XRGPUBinding::getViewSubImage(XRProjectionLayer* layer, XRView* view, ExceptionState& exception_state)` 方法用于获取特定视图需要渲染到的纹理区域。
   - 它会检查 `layer` 是否是由当前的 `XRGPUBinding` 创建，以及 `view` 是否属于同一个 `XRSession`。
   - 它从 `XRGPUProjectionLayer` 中获取当前的 **颜色纹理 (`GPUTexture`)** 和 **深度/模板纹理 (`GPUTexture`)**。
   - 它调用 `GetViewportForView` 来计算视图在纹理中的 **视口 (`gfx::Rect`)**。
   - 最后，它创建一个 `XRGPUSubImage` 对象，包含视口信息和相关的纹理。

4. **计算视图的视口 (`gfx::Rect`)：**
   - `XRGPUBinding::GetViewportForView(XRProjectionLayer* layer, XRViewData* view)` 方法根据投影层的纹理尺寸和视图的视口缩放比例，计算出视图需要渲染的矩形区域。

5. **获取首选的颜色格式：**
   - `XRGPUBinding::getPreferredColorFormat()` 方法返回首选的 WebGPU 纹理颜色格式。

6. **检查是否可以创建层：**
   - `XRGPUBinding::CanCreateLayer(ExceptionState& exception_state)` 方法检查创建新投影层的基本条件（会话未结束，设备未销毁）。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`XRGPUBinding.cc` 是 Blink 渲染引擎的 C++ 代码，它直接与 WebXR 和 WebGPU 的 JavaScript API 实现相关联。开发者通过 JavaScript 调用 WebXR API，这些调用最终会触发 Blink 引擎中相应的 C++ 代码执行。

**JavaScript 示例：**

```javascript
// 获取 XR 系统
navigator.xr.requestSession('immersive-vr', {
  requiredFeatures: ['local-floor'],
  // 指明使用 WebGPU 进行渲染
  glslangOptions: { device: myWebGPUDevice }
}).then(session => {
  // 获取 WebGPU 设备
  const gpuDevice = myWebGPUDevice;

  // 创建 XRGPUBinding (在引擎内部，开发者无法直接访问)
  // ...

  // 创建投影层
  session.createProjectionLayer({
    colorFormat: 'rgba8unorm', // 对应 V8GPUTextureFormat::kRgba8unorm
    depthStencilFormat: 'depth24plus-stencil8', // 对应 V8GPUTextureFormat::kDepth24plusStencil8
    textureUsage: GPUTextureUsage.RENDER_ATTACHMENT | GPUTextureUsage.COPY_SRC,
    scaleFactor: 1.0
  }).then(projectionLayer => {
    session.requestAnimationFrame(function render(time, frame) {
      const pose = frame.getViewerPose(referenceSpace);
      if (pose) {
        const glLayer = projectionLayer; // 在 JavaScript 中是 XRProjectionLayer 的实例
        frame.getRenderState().baseLayer = glLayer; // 将投影层设置为渲染目标

        for (const view of pose.views) {
          const viewport = session.renderState.baseLayer.getViewport(view); // 获取视口信息
          const subImage = glLayer.getViewSubImage(view); // 获取子图像信息 (对应 XRGPUBinding::getViewSubImage)

          // 使用 subImage.colorTexture 和 subImage.depthStencilTexture 进行 WebGPU 渲染
          const renderTarget = subImage.colorTexture;
          const depthTarget = subImage.depthStencilTexture;

          // ... 进行 WebGPU 渲染管线设置和绘制调用 ...
        }
      }
      session.requestAnimationFrame(render);
    });
  });
});
```

在这个例子中：

- `session.createProjectionLayer(...)` 的调用最终会触发 `XRGPUBinding::createProjectionLayer` 的执行。
- `glLayer.getViewSubImage(view)` 的调用会触发 `XRGPUBinding::getViewSubImage` 的执行。
- `colorFormat` 和 `depthStencilFormat` 的值会影响 `XRGPUBinding::createProjectionLayer` 中纹理描述符的设置。
- `scaleFactor` 的值会被用于计算纹理尺寸。

**HTML 和 CSS：**

HTML 和 CSS 对于 `XRGPUBinding.cc` 的功能影响相对间接。HTML 用于加载包含 WebXR 和 WebGPU 代码的 JavaScript。CSS 可能影响页面的布局，但不会直接控制 WebXR 的渲染流程。

**逻辑推理的假设输入与输出：**

**假设输入 (在 `XRGPUBinding::createProjectionLayer` 中):**

- `init->scaleFactor()`: 0.8
- `session()->NativeFramebufferScale()`: 1.2
- `session()->RecommendedArrayTextureSize()`: `{ width: 1000, height: 500 }`
- `session()->array_texture_layers()`: 2
- `device_->limits()->maxTextureDimension2D()`: 2048
- `init->colorFormat()`: `V8GPUTextureFormat::kRgba8unorm`
- `init->textureUsage()`: `GPUTextureUsage.RENDER_ATTACHMENT | GPUTextureUsage.COPY_SRC`
- `init->hasDepthStencilFormat()`: true
- `*init->depthStencilFormat()`: `V8GPUTextureFormat::kDepth24plusStencil8`

**逻辑推理过程：**

1. `max_scale` = `max(1.2, 1.0)` = 1.2
2. `scale_factor` = `clamp(0.8, 0.2, 1.2)` = 0.8
3. `scaled_size` = `scale({1000, 500}, 0.8)` = `{ 800, 400 }`
4. 由于 `session()->array_texture_layers()` 为 2，`scaled_size.width()` 变为 `800 * 2 = 1600`。
5. `max_texture_size` 为 2048，`scaled_size.width()` 和 `scaled_size.height()` 都小于 2048，所以不需要进一步缩放。
6. `texture_size` = `floor({1600, 400})` = `{ 1600, 400 }`
7. 创建颜色缓冲区交换链，纹理描述符的 `size` 为 `{ 1600, 400, 1 }`，`format` 为 `wgpu::TextureFormat::RGBA8Unorm`，`usage` 对应传入的 `textureUsage`。
8. 创建包裹纹理数组的交换链。
9. 创建深度/模板缓冲区交换链，纹理描述符的 `size` 为 `{ 1600, 400, 1 }`，`format` 为 `wgpu::TextureFormat::Depth24PlusStencil8`，`usage` 对应传入的 `textureUsage`。

**假设输出：**

- 创建的 `XRGPUProjectionLayer` 将拥有一个颜色缓冲区交换链，其纹理尺寸为 1600x400。
- 如果 `init->hasDepthStencilFormat()` 为 true，则还会创建一个深度/模板缓冲区交换链，其纹理尺寸也为 1600x400。

**用户或编程常见的使用错误举例说明：**

1. **在非沉浸式会话中尝试创建 `XRGPUBinding`：**
   - **用户操作：** 开发者请求了一个内联的 WebXR 会话 (`navigator.xr.requestSession('inline')`)，然后尝试使用这个会话创建 `XRGPUBinding`。
   - **结果：** `XRGPUBinding::Create` 会抛出一个 `DOMExceptionCode::kInvalidStateError` 异常，提示 "Cannot create an XRGPUBinding for an inline XRSession."。

2. **使用已销毁的 WebGPU 设备创建 `XRGPUBinding`：**
   - **用户操作：** 开发者错误地在销毁 WebGPU 设备之后，仍然尝试使用该设备创建 `XRGPUBinding`。
   - **结果：** `XRGPUBinding::Create` 会抛出一个 `DOMExceptionCode::kInvalidStateError` 异常，提示 "Cannot create an XRGPUBinding with a destroyed WebGPU device."。

3. **提供的 `scaleFactor` 过小或过大：**
   - **用户操作：** 开发者在调用 `session.createProjectionLayer` 时，提供了超出允许范围的 `scaleFactor` 值，例如小于 `kMinScaleFactor` (0.2) 或大于 `session()->NativeFramebufferScale()`。
   - **结果：** `XRGPUBinding::createProjectionLayer` 会使用 `std::clamp` 将 `scaleFactor` 限制在有效范围内，但开发者可能没有意识到他们提供的原始值被修改了。这可能导致渲染质量不符合预期。

4. **在会话结束后尝试创建投影层：**
   - **用户操作：** 开发者在 `XRSession` 的 `end` 事件触发后，仍然尝试调用 `session.createProjectionLayer`。
   - **结果：** `XRGPUBinding::createProjectionLayer` (或其调用的 `CanCreateLayer`) 会抛出一个 `DOMExceptionCode::kInvalidStateError` 异常，提示 "Cannot create a new layer for an XRSession which has already ended."。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者遇到了一个问题，即他们使用 WebGPU 在 WebXR 中渲染时，渲染结果的尺寸不符合预期。他们可能会进行以下调试：

1. **检查 JavaScript 代码：** 查看调用 `session.createProjectionLayer` 时传递的参数，特别是 `scaleFactor` 的值。
2. **断点调试 JavaScript：** 在 `session.createProjectionLayer` 调用前后设置断点，查看传入的参数值。
3. **查看浏览器控制台的错误信息：** 如果出现异常，控制台会显示相应的错误信息，例如 `InvalidStateError` 以及错误描述。
4. **Blink 渲染引擎调试：**
   - 如果问题比较复杂，开发者可能需要查看 Blink 渲染引擎的日志或进行断点调试。
   - 他们可能会在 `blink/renderer/modules/xr/xr_gpu_binding.cc` 中的关键方法（如 `Create` 和 `createProjectionLayer`) 设置断点，例如：
     - 在 `XRGPUBinding::Create` 的入口处，检查 `session->immersive()` 的值是否正确。
     - 在 `XRGPUBinding::createProjectionLayer` 中，检查 `init->scaleFactor()` 的值，以及计算出的 `scale_factor` 和 `texture_size`。
     - 检查 WebGPU 相关的对象 (`device_`) 是否有效。
   - 通过查看这些变量的值，开发者可以理解参数是如何传递到 C++ 代码中的，以及 C++ 代码是如何处理这些参数的。
5. **WebGPU API 调试工具：** 使用浏览器提供的 WebGPU 调试工具（例如 Chrome 的 "GPU 检查器"），可以查看创建的 WebGPU 资源（如纹理）的属性，例如尺寸和格式，从而验证 `XRGPUBinding` 的行为是否符合预期。

通过以上步骤，开发者可以逐步追踪问题，从 JavaScript 代码一直深入到 Blink 渲染引擎的 C++ 代码，最终找到问题的根源。例如，他们可能会发现是由于传入了错误的 `scaleFactor` 值，或者 WebGPU 设备在创建 `XRGPUBinding` 之前就被意外销毁了。

希望以上分析能够帮助你理解 `blink/renderer/modules/xr/xr_gpu_binding.cc` 文件的功能和作用。

### 提示词
```
这是目录为blink/renderer/modules/xr/xr_gpu_binding.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/xr/xr_gpu_binding.h"

#include "third_party/blink/renderer/bindings/modules/v8/v8_xr_gpu_projection_layer_init.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_enum_conversions.h"
#include "third_party/blink/renderer/modules/webgpu/dawn_object.h"
#include "third_party/blink/renderer/modules/webgpu/gpu.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_adapter.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_device.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_supported_limits.h"
#include "third_party/blink/renderer/modules/webgpu/gpu_texture.h"
#include "third_party/blink/renderer/modules/xr/xr_frame_provider.h"
#include "third_party/blink/renderer/modules/xr/xr_gpu_projection_layer.h"
#include "third_party/blink/renderer/modules/xr/xr_gpu_sub_image.h"
#include "third_party/blink/renderer/modules/xr/xr_gpu_swap_chain.h"
#include "third_party/blink/renderer/modules/xr/xr_gpu_texture_array_swap_chain.h"
#include "third_party/blink/renderer/modules/xr/xr_session.h"
#include "third_party/blink/renderer/modules/xr/xr_system.h"
#include "third_party/blink/renderer/modules/xr/xr_view.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/size_f.h"

namespace blink {

namespace {

const double kMinScaleFactor = 0.2;

}  // namespace

XRGPUBinding* XRGPUBinding::Create(XRSession* session,
                                   GPUDevice* device,
                                   ExceptionState& exception_state) {
  DCHECK(session);
  DCHECK(device);

  if (session->ended()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot create an XRGPUBinding for an "
                                      "XRSession which has already ended.");
    return nullptr;
  }

  if (!session->immersive()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot create an XRGPUBinding for an "
                                      "inline XRSession.");
    return nullptr;
  }

  if (device->destroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot create an XRGPUBinding with a "
                                      "destroyed WebGPU device.");
    return nullptr;
  }

  if (!device->adapter()->isXRCompatible()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "WebGPU device must be created by an XR compatible adapter in order to "
        "use with an immersive XRSession");
    return nullptr;
  }

  if (session->GraphicsApi() != XRGraphicsBinding::Api::kWebGPU) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Cannot create an XRGPUBinding with a WebGL-based XRSession.");
    return nullptr;
  }

  return MakeGarbageCollected<XRGPUBinding>(session, device);
}

XRGPUBinding::XRGPUBinding(XRSession* session, GPUDevice* device)
    : XRGraphicsBinding(session), device_(device) {}

XRProjectionLayer* XRGPUBinding::createProjectionLayer(
    const XRGPUProjectionLayerInit* init,
    ExceptionState& exception_state) {
  // TODO(crbug.com/5818595): Validate the colorFormat and depthStencilFormat.

  if (!CanCreateLayer(exception_state)) {
    return nullptr;
  }

  // The max size will be either the native resolution or the default
  // if that happens to be larger than the native res. (That can happen on
  // desktop systems.)
  double max_scale = std::max(session()->NativeFramebufferScale(), 1.0);

  // Clamp the developer-requested framebuffer scale to ensure it's not too
  // small to see or unreasonably large.
  double scale_factor =
      std::clamp(init->scaleFactor(), kMinScaleFactor, max_scale);
  gfx::SizeF scaled_size =
      gfx::ScaleSize(session()->RecommendedArrayTextureSize(), scale_factor);

  // TODO(crbug.com/359418629): Remove once array Mailboxes are available.
  scaled_size.set_width(scaled_size.width() *
                        session()->array_texture_layers());

  // If the scaled texture dimensions are larger than the max texture dimension
  // for the device scale it down till it fits.
  unsigned max_texture_size = device_->limits()->maxTextureDimension2D();
  if (scaled_size.width() > max_texture_size ||
      scaled_size.height() > max_texture_size) {
    double max_dimension = std::max(scaled_size.width(), scaled_size.height());
    scaled_size = gfx::ScaleSize(scaled_size, max_texture_size / max_dimension);
  }

  gfx::Size texture_size = gfx::ToFlooredSize(scaled_size);

  // Create the side-by-side color swap chain
  wgpu::TextureDescriptor color_desc = {};
  color_desc.label = "XRProjectionLayer Color";
  color_desc.format = AsDawnEnum(init->colorFormat());
  color_desc.usage = static_cast<wgpu::TextureUsage>(init->textureUsage());
  color_desc.size = {static_cast<uint32_t>(texture_size.width()),
                     static_cast<uint32_t>(texture_size.height()),
                     static_cast<uint32_t>(1)};
  color_desc.dimension = wgpu::TextureDimension::e2D;

  XRGPUSwapChain* color_swap_chain;
  if (session()->xr()->frameProvider()->DrawingIntoSharedBuffer()) {
    color_swap_chain =
        MakeGarbageCollected<XRGPUMailboxSwapChain>(device_, color_desc);
  } else {
    // TODO(crbug.com/359418629): Replace with a shared image swap chain.
    color_swap_chain =
        MakeGarbageCollected<XRGPUStaticSwapChain>(device_, color_desc);
  }

  // Create the texture array wrapper for the side-by-side swap chain.
  // TODO(crbug.com/359418629): Remove once array Mailboxes are available.
  XRGPUTextureArraySwapChain* wrapped_swap_chain =
      MakeGarbageCollected<XRGPUTextureArraySwapChain>(
          device_, color_swap_chain, session()->array_texture_layers());

  // Create the depth/stencil swap chain
  XRGPUStaticSwapChain* depth_stencil_swap_chain = nullptr;
  if (init->hasDepthStencilFormat()) {
    wgpu::TextureDescriptor depth_stencil_desc = {};
    depth_stencil_desc.label = "XRProjectionLayer Depth/Stencil";
    depth_stencil_desc.format = AsDawnEnum(*init->depthStencilFormat());
    depth_stencil_desc.usage =
        static_cast<wgpu::TextureUsage>(init->textureUsage());
    depth_stencil_desc.size = wrapped_swap_chain->descriptor().size;
    depth_stencil_desc.dimension = wgpu::TextureDimension::e2D;

    depth_stencil_swap_chain =
        MakeGarbageCollected<XRGPUStaticSwapChain>(device_, depth_stencil_desc);
  }

  return MakeGarbageCollected<XRGPUProjectionLayer>(this, wrapped_swap_chain,
                                                    depth_stencil_swap_chain);
}

XRGPUSubImage* XRGPUBinding::getViewSubImage(XRProjectionLayer* layer,
                                             XRView* view,
                                             ExceptionState& exception_state) {
  if (!OwnsLayer(layer)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "Layer was not created with this binding.");
    return nullptr;
  }

  if (!view || view->session() != session()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "View was not created with the same session as this binding.");
    return nullptr;
  }

  XRGPUProjectionLayer* gpu_layer = static_cast<XRGPUProjectionLayer*>(layer);

  GPUTexture* color_texture =
      gpu_layer->color_swap_chain()->GetCurrentTexture();

  GPUTexture* depth_stencil_texture = nullptr;
  XRGPUSwapChain* depth_stencil_swap_chain =
      gpu_layer->depth_stencil_swap_chain();
  if (depth_stencil_swap_chain) {
    depth_stencil_texture = depth_stencil_swap_chain->GetCurrentTexture();
  }

  XRViewData* viewData = view->ViewData();
  viewData->ApplyViewportScaleForFrame();

  gfx::Rect viewport = GetViewportForView(layer, viewData);

  return MakeGarbageCollected<XRGPUSubImage>(
      viewport, view->ViewData()->index(), color_texture,
      depth_stencil_texture);
}

gfx::Rect XRGPUBinding::GetViewportForView(XRProjectionLayer* layer,
                                           XRViewData* view) {
  CHECK(OwnsLayer(layer));

  return gfx::Rect(0, 0, layer->textureWidth() * view->CurrentViewportScale(),
                   layer->textureHeight() * view->CurrentViewportScale());
}

V8GPUTextureFormat XRGPUBinding::getPreferredColorFormat() {
  // TODO(crbug.com/5818595): Replace with GPU::preferred_canvas_format()?
  return FromDawnEnum(wgpu::TextureFormat::RGBA8Unorm);
}

bool XRGPUBinding::CanCreateLayer(ExceptionState& exception_state) {
  if (session()->ended()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot create a new layer for an "
                                      "XRSession which has already ended.");
    return false;
  }

  if (device_->destroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "Cannot create a new layer with a "
                                      "destroyed WebGPU device.");
    return false;
  }

  return true;
}

void XRGPUBinding::Trace(Visitor* visitor) const {
  visitor->Trace(device_);
  XRGraphicsBinding::Trace(visitor);
  ScriptWrappable::Trace(visitor);
}

}  // namespace blink
```