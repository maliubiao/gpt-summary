Response:
Let's break down the thought process to analyze the provided `webgl_rendering_context.cc` file and generate the requested information.

**1. Understanding the Goal:**

The primary goal is to understand the purpose and functionality of this C++ file within the Chromium Blink rendering engine. Specifically, we need to identify its role in the WebGL implementation and its interactions with JavaScript, HTML, and CSS. The prompt also asks for examples, logical reasoning (with assumptions), common errors, and debugging steps.

**2. Initial Code Scan and Keyword Spotting:**

I start by quickly scanning the code for keywords and patterns that immediately reveal its nature:

* **`#include "third_party/blink/renderer/modules/webgl/webgl_rendering_context.h"`:** This is the most crucial line. It confirms this file is the *implementation* (`.cc`) for the `WebGLRenderingContext` class. This class is central to WebGL functionality.
* **`namespace blink {`:** This confirms it's part of the Blink rendering engine.
* **Copyright information:**  Indicates origin and licensing (less relevant to immediate functionality).
* **Numerous `#include` statements for other WebGL-related headers:**  This suggests the file depends on and interacts with many other WebGL components (extensions, utilities, etc.). Specifically, I notice headers like `angle_instanced_arrays.h`, `ext_blend_min_max.h`, etc., which point to specific WebGL extensions.
* **`CanvasRenderingContext* WebGLRenderingContext::Factory::Create(...)`:** This immediately tells me how this class is instantiated in the broader context of `<canvas>` elements. The "Factory" pattern is a common way to create complex objects.
* **Method names like `TransferToImageBitmap`, `RegisterContextExtensions`:**  These suggest core WebGL capabilities.

**3. Deeper Analysis - Function by Function (Conceptual):**

I mentally go through the major sections and functions, trying to understand their high-level purpose:

* **`ShouldCreateContext`:**  This looks like a preliminary check before actually creating the WebGL context. It checks for the `WebGraphicsContext3DProvider` and initializes some debugging markers.
* **`WebGLRenderingContext::Factory::Create`:**  This is the entry point for creating a `WebGLRenderingContext`. It handles the `xr_compatible` attribute, creates the underlying 3D context using `CreateWebGraphicsContext3DProvider`, and initializes the `WebGLRenderingContext` object. The error handling with `WebGLContextEvent` is important.
* **`WebGLRenderingContext::Factory::OnError`:** This seems to be a callback for reporting WebGL creation errors.
* **`WebGLRenderingContext` (constructor):** Initializes the base class (`WebGLRenderingContextBase`).
* **`AsV8RenderingContext`, `AsV8OffscreenRenderingContext`:** These methods are crucial for exposing the WebGL functionality to JavaScript via the V8 JavaScript engine. They bridge the C++ implementation to the JavaScript API.
* **`TransferToImageBitmap`:** This enables transferring the contents of the WebGL context to an `ImageBitmap` object, a feature for efficient image manipulation.
* **`RegisterContextExtensions`:** This is a key function. It's responsible for registering all the supported WebGL extensions. The long list of `RegisterExtension` calls confirms this.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

Based on the function analysis, I can start to draw connections:

* **JavaScript:** The `AsV8RenderingContext` and `AsV8OffscreenRenderingContext` methods are the direct link. JavaScript code using `canvas.getContext('webgl')` or `canvas.getContext('webgl2')` will ultimately interact with the functionality implemented in this C++ file. The methods exposed in JavaScript (like `drawArrays`, `createBuffer`, etc.) have corresponding implementations (or delegate to lower-level APIs) in the underlying C++ code.
* **HTML:** The `<canvas>` element in HTML is the entry point for using WebGL. The JavaScript `getContext('webgl')` call is made on a `<canvas>` element.
* **CSS:** While CSS doesn't directly control the *rendering logic* of WebGL, it influences the size and positioning of the `<canvas>` element on the page. The dimensions of the canvas affect the WebGL rendering surface.

**5. Logical Reasoning and Examples:**

Now I start thinking about specific scenarios and how this file plays a role:

* **Hypothetical Input/Output:** I consider a simple case: JavaScript code calling `gl.clearColor(1, 0, 0, 1)` followed by `gl.clear(gl.COLOR_BUFFER_BIT)`. The input is the JavaScript calls, and the expected output is a red canvas. The `WebGLRenderingContext` handles the interpretation and execution of these GL commands using the underlying graphics API.
* **User Errors:** I think about common mistakes developers make, like using an invalid constant name (e.g., `gl.TRIANGLES` spelled wrong), or calling a function with incorrect arguments. The `WebGLRenderingContext` (and the underlying GL implementation) would likely throw an error or produce unexpected behavior.
* **User Actions to Reach This Code:**  I trace back the steps: user opens a webpage with a `<canvas>` element, JavaScript code gets executed, calls `canvas.getContext('webgl')`, which leads to the `WebGLRenderingContext::Factory::Create` method in this file.

**6. Debugging Clues:**

I consider how this file can be relevant for debugging:

* **Context Creation Errors:** If `WebGLContextEvent` is dispatched, it suggests a problem within the `Create` method or the underlying graphics context creation.
* **Extension Issues:**  If a specific WebGL extension isn't working, checking the `RegisterContextExtensions` method can reveal if the extension is even being registered correctly.
* **Unexpected Rendering:**  While this file doesn't contain the core rendering loops, it sets up the context. Issues here could manifest as a completely broken WebGL experience.

**7. Structuring the Answer:**

Finally, I organize the information gathered into the requested categories, using clear and concise language. I provide specific code snippets and examples to illustrate the points. I also make sure to address all aspects of the prompt, including functionality, relationships with web technologies, logical reasoning, common errors, and debugging clues.

This iterative process of scanning, analyzing, connecting, and exemplifying allows me to understand the role of `webgl_rendering_context.cc` and produce a comprehensive answer.
这个文件 `blink/renderer/modules/webgl/webgl_rendering_context.cc` 是 Chromium Blink 引擎中实现 **WebGL 1.0** 渲染上下文的核心 C++ 代码文件。它的主要功能是：

**核心功能:**

1. **创建和初始化 WebGL 上下文:**  当 JavaScript 代码请求一个 WebGL 渲染上下文时（例如，通过 `canvas.getContext('webgl')`），这个文件中的代码负责创建底层的图形上下文（通常是 OpenGL ES），并初始化 WebGL 状态。
2. **管理 WebGL API 的 C++ 实现:**  它包含了许多 WebGL API 的 C++ 实现，这些 API 与 JavaScript 中暴露的 `WebGLRenderingContext` 对象的方法相对应。例如，当 JavaScript 调用 `gl.clearColor()`, `gl.drawArrays()`, `gl.createBuffer()` 等方法时，最终会调用到这个文件中的 C++ 代码。
3. **处理 WebGL 状态:**  维护和管理 WebGL 渲染的各种状态，例如颜色缓冲区的清除颜色、当前使用的着色器程序、绑定的纹理等。
4. **管理 WebGL 扩展:**  注册和管理支持的 WebGL 扩展。这些扩展提供了 WebGL 1.0 标准之外的额外功能。文件中可以看到大量 `RegisterExtension` 的调用，每个调用都对应一个 WebGL 扩展。
5. **处理上下文丢失和恢复:**  实现上下文丢失和恢复的机制。当底层图形设备出现问题时，WebGL 上下文可能会丢失。这个文件参与处理这种丢失，并允许应用程序尝试恢复上下文。
6. **与 Chromium 平台的交互:**  与 Chromium 平台的其他部分交互，例如获取图形设备信息、创建图形上下文提供器等。

**与 JavaScript, HTML, CSS 的关系和举例:**

这个文件是 WebGL 功能在 Blink 渲染引擎中的 **桥梁**，它连接了 JavaScript API 和底层的图形 API。

* **JavaScript:**
    * **功能关系:** JavaScript 代码通过 `HTMLCanvasElement` 的 `getContext('webgl')` 方法请求创建 `WebGLRenderingContext` 对象。这个文件的 `WebGLRenderingContext::Factory::Create` 方法会被调用来创建和初始化这个上下文。
    * **举例说明:**
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const gl = canvas.getContext('webgl'); // 这里会触发 blink 调用 WebGLRenderingContext::Factory::Create

        if (gl) {
          gl.clearColor(0.0, 0.0, 0.0, 1.0); // 调用 WebGL 方法，最终会调用到这个文件中的 C++ 代码
          gl.clear(gl.COLOR_BUFFER_BIT);
          // ... 其他 WebGL 绘制代码
        } else {
          console.error('无法获取 WebGL 上下文');
        }
        ```
        在这个例子中，`gl.clearColor()` 和 `gl.clear()` 的 JavaScript 调用，最终会在 `webgl_rendering_context.cc` 中找到对应的 C++ 实现，并调用底层的 OpenGL ES 函数来完成颜色设置和缓冲区清除操作。
* **HTML:**
    * **功能关系:**  WebGL 的渲染目标是 HTML 中的 `<canvas>` 元素。`webgl_rendering_context.cc` 中创建的 WebGL 上下文会绑定到这个 `<canvas>` 元素。
    * **举例说明:**  `<canvas id="myCanvas" width="500" height="300"></canvas>`  当 JavaScript 在这个 canvas 上获取 WebGL 上下文后，`webgl_rendering_context.cc` 中的代码会利用这个 canvas 的尺寸信息来创建渲染缓冲区。
* **CSS:**
    * **功能关系:** CSS 可以影响 `<canvas>` 元素的样式和布局，例如大小、位置等。虽然 CSS 不直接影响 WebGL 的内部渲染逻辑，但 canvas 的尺寸会影响 WebGL 渲染的分辨率。
    * **举例说明:**
        ```css
        #myCanvas {
          width: 800px;
          height: 600px;
          border: 1px solid black;
        }
        ```
        CSS 设置了 canvas 的宽度和高度，这些尺寸信息会被 WebGL 上下文使用，决定了渲染表面的大小。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码调用了 `gl.getParameter(gl.MAX_TEXTURE_SIZE)`。

* **假设输入:** JavaScript 调用 `gl.getParameter(gl.MAX_TEXTURE_SIZE)`。
* **`webgl_rendering_context.cc` 中的处理:**  这个文件会接收到这个请求，并查找 `gl.MAX_TEXTURE_SIZE` 常量对应的内部表示。然后，它会调用底层的 OpenGL ES API (例如 `glGetIntegerv(GL_MAX_TEXTURE_SIZE, ...)` ) 来获取图形设备支持的最大纹理尺寸。
* **输出:**  `webgl_rendering_context.cc` 将从 OpenGL ES 获取到的值返回给 JavaScript 环境。JavaScript 端接收到的输出将是一个表示最大纹理尺寸的数字。

**用户或编程常见的使用错误举例:**

1. **在 WebGL 上下文丢失后继续使用:**
    * **用户操作:** 用户打开一个使用了 WebGL 的网页，然后图形驱动程序崩溃或被更新，导致 WebGL 上下文丢失。
    * **错误:** JavaScript 代码没有正确处理 `webglcontextlost` 事件，仍然尝试调用 `gl.drawArrays()` 等方法。
    * **`webgl_rendering_context.cc` 的影响:**  由于底层图形上下文已经无效，调用相应的 C++ 实现可能会导致崩溃或者产生不可预测的行为。
2. **使用未激活的扩展:**
    * **编程错误:** 开发者尝试使用某个 WebGL 扩展的功能，但忘记先检查该扩展是否被支持和激活。
    * **错误代码示例:**
        ```javascript
        const ext = gl.getExtension('EXT_shader_texture_lod');
        gl.texLodEXT(...); // 如果 ext 为 null，则会报错
        ```
    * **`webgl_rendering_context.cc` 的影响:** `RegisterContextExtensions` 方法定义了支持的扩展。如果尝试调用未注册的扩展方法，JavaScript 层面就会报错，不会到达 C++ 代码。但如果扩展被注册了，但底层驱动不支持，则在 C++ 代码中调用 OpenGL ES 相关函数时可能会出错。
3. **向 WebGL 函数传递错误的参数类型或值:**
    * **编程错误:** 例如，向 `gl.bindBuffer()` 传递了错误的 Buffer 对象，或者向 `gl.uniformMatrix4fv()` 传递了错误的矩阵数据格式。
    * **`webgl_rendering_context.cc` 的影响:**  `webgl_rendering_context.cc` 中的 C++ 代码会进行一些参数检查。如果参数类型不匹配，可能会抛出异常或者导致 OpenGL ES 调用失败。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器地址栏输入 URL 或点击链接，访问包含 WebGL 内容的网页。**
2. **浏览器开始解析 HTML 页面，遇到 `<canvas>` 元素。**
3. **JavaScript 代码开始执行，查找 `<canvas>` 元素并调用 `canvas.getContext('webgl')`。**
4. **Blink 引擎接收到 `getContext('webgl')` 的请求，并查找对应的渲染上下文工厂。**
5. **`WebGLRenderingContext::Factory::Create` 方法被调用 (在 `webgl_rendering_context.cc` 中)。**
6. **`Create` 方法会尝试创建底层的图形上下文 (通过 `CreateWebGraphicsContext3DProvider`)。**
7. **如果创建成功，`WebGLRenderingContext` 对象被创建和初始化。**
8. **JavaScript 代码获取到 `WebGLRenderingContext` 对象，并调用其方法 (例如 `gl.clearColor`, `gl.drawArrays` 等)。**
9. **这些 JavaScript 方法调用会映射到 `webgl_rendering_context.cc` 中对应的 C++ 方法实现。**
10. **C++ 方法会调用底层的 OpenGL ES API 来执行图形操作。**

**调试线索:**

* **在 Chrome 开发者工具的 "Sources" 面板中设置断点:** 可以在 `webgl_rendering_context.cc` 中关键的函数 (例如 `Create`, `clearColor`, `drawArrays` 等) 设置断点，来追踪 WebGL API 的调用流程。
* **使用 `console.log` 或开发者工具的性能分析工具:**  可以记录 WebGL 函数的调用参数和执行时间，帮助定位性能瓶颈或错误参数。
* **检查 WebGL 错误:**  在 JavaScript 代码中使用 `gl.getError()` 来检查是否有 WebGL 错误发生。这可以指示 C++ 代码中 OpenGL ES 调用是否失败。
* **查看 Chrome 的 `chrome://gpu` 页面:**  可以查看 GPU 的相关信息，以及 WebGL 的状态，例如是否启用了硬件加速，是否存在图形驱动问题等。

总而言之，`blink/renderer/modules/webgl/webgl_rendering_context.cc` 是 WebGL 功能在 Chromium 中的核心实现，它负责将 JavaScript 的 WebGL API 调用转换为底层的图形操作，并管理 WebGL 的各种状态和扩展。理解这个文件的功能对于深入了解 WebGL 的工作原理和进行底层调试至关重要。

### 提示词
```
这是目录为blink/renderer/modules/webgl/webgl_rendering_context.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2009 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/webgl/webgl_rendering_context.h"

#include <memory>

#include "base/numerics/checked_math.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_canvasrenderingcontext2d_gpucanvascontext_imagebitmaprenderingcontext_webgl2renderingcontext_webglrenderingcontext.h"
#include "third_party/blink/renderer/bindings/modules/v8/v8_union_gpucanvascontext_imagebitmaprenderingcontext_offscreencanvasrenderingcontext2d_webgl2renderingcontext_webglrenderingcontext.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/modules/webgl/angle_instanced_arrays.h"
#include "third_party/blink/renderer/modules/webgl/ext_blend_min_max.h"
#include "third_party/blink/renderer/modules/webgl/ext_clip_control.h"
#include "third_party/blink/renderer/modules/webgl/ext_color_buffer_half_float.h"
#include "third_party/blink/renderer/modules/webgl/ext_depth_clamp.h"
#include "third_party/blink/renderer/modules/webgl/ext_disjoint_timer_query.h"
#include "third_party/blink/renderer/modules/webgl/ext_float_blend.h"
#include "third_party/blink/renderer/modules/webgl/ext_frag_depth.h"
#include "third_party/blink/renderer/modules/webgl/ext_polygon_offset_clamp.h"
#include "third_party/blink/renderer/modules/webgl/ext_shader_texture_lod.h"
#include "third_party/blink/renderer/modules/webgl/ext_srgb.h"
#include "third_party/blink/renderer/modules/webgl/ext_texture_compression_bptc.h"
#include "third_party/blink/renderer/modules/webgl/ext_texture_compression_rgtc.h"
#include "third_party/blink/renderer/modules/webgl/ext_texture_filter_anisotropic.h"
#include "third_party/blink/renderer/modules/webgl/ext_texture_mirror_clamp_to_edge.h"
#include "third_party/blink/renderer/modules/webgl/khr_parallel_shader_compile.h"
#include "third_party/blink/renderer/modules/webgl/oes_element_index_uint.h"
#include "third_party/blink/renderer/modules/webgl/oes_fbo_render_mipmap.h"
#include "third_party/blink/renderer/modules/webgl/oes_standard_derivatives.h"
#include "third_party/blink/renderer/modules/webgl/oes_texture_float.h"
#include "third_party/blink/renderer/modules/webgl/oes_texture_float_linear.h"
#include "third_party/blink/renderer/modules/webgl/oes_texture_half_float.h"
#include "third_party/blink/renderer/modules/webgl/oes_texture_half_float_linear.h"
#include "third_party/blink/renderer/modules/webgl/oes_vertex_array_object.h"
#include "third_party/blink/renderer/modules/webgl/webgl_blend_func_extended.h"
#include "third_party/blink/renderer/modules/webgl/webgl_color_buffer_float.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_astc.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_etc.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_etc1.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_pvrtc.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_s3tc.h"
#include "third_party/blink/renderer/modules/webgl/webgl_compressed_texture_s3tc_srgb.h"
#include "third_party/blink/renderer/modules/webgl/webgl_context_event.h"
#include "third_party/blink/renderer/modules/webgl/webgl_debug_renderer_info.h"
#include "third_party/blink/renderer/modules/webgl/webgl_debug_shaders.h"
#include "third_party/blink/renderer/modules/webgl/webgl_depth_texture.h"
#include "third_party/blink/renderer/modules/webgl/webgl_draw_buffers.h"
#include "third_party/blink/renderer/modules/webgl/webgl_lose_context.h"
#include "third_party/blink/renderer/modules/webgl/webgl_multi_draw.h"
#include "third_party/blink/renderer/modules/webgl/webgl_multi_draw_instanced_base_vertex_base_instance.h"
#include "third_party/blink/renderer/modules/webgl/webgl_polygon_mode.h"
#include "third_party/blink/renderer/platform/graphics/gpu/drawing_buffer.h"

namespace blink {

class ExceptionState;

// An helper function for the two create() methods. The return value is an
// indicate of whether the create() should return nullptr or not.
static bool ShouldCreateContext(
    WebGraphicsContext3DProvider* context_provider) {
  if (!context_provider)
    return false;
  gpu::gles2::GLES2Interface* gl = context_provider->ContextGL();
  std::unique_ptr<Extensions3DUtil> extensions_util =
      Extensions3DUtil::Create(gl);
  if (!extensions_util)
    return false;
  if (extensions_util->SupportsExtension("GL_EXT_debug_marker")) {
    String context_label(
        String::Format("WebGLRenderingContext-%p", context_provider));
    gl->PushGroupMarkerEXT(0, context_label.Ascii().c_str());
  }
  return true;
}

CanvasRenderingContext* WebGLRenderingContext::Factory::Create(
    CanvasRenderingContextHost* host,
    const CanvasContextCreationAttributesCore& attrs) {
  // Create a copy of attrs so flags can be modified if needed before passing
  // into the WebGLRenderingContext constructor.
  CanvasContextCreationAttributesCore attribs = attrs;

  // The xr_compatible attribute needs to be handled before creating the context
  // because the GPU process may potentially be restarted in order to be XR
  // compatible. This scenario occurs if the GPU process is not using the GPU
  // that the VR headset is plugged into. If the GPU process is restarted, the
  // WebGraphicsContext3DProvider must be created using the new one.
  if (attribs.xr_compatible &&
      !WebGLRenderingContextBase::MakeXrCompatibleSync(host)) {
    // If xr compatibility is requested and we can't be xr compatible, return a
    // context with the flag set to false.
    attribs.xr_compatible = false;
  }

  Platform::GraphicsInfo graphics_info;
  std::unique_ptr<WebGraphicsContext3DProvider> context_provider(
      CreateWebGraphicsContext3DProvider(
          host, attribs, Platform::kWebGL1ContextType, &graphics_info));
  if (!ShouldCreateContext(context_provider.get()))
    return nullptr;

  WebGLRenderingContext* rendering_context =
      MakeGarbageCollected<WebGLRenderingContext>(
          host, std::move(context_provider), graphics_info, attribs);
  if (!rendering_context->GetDrawingBuffer()) {
    host->HostDispatchEvent(
        WebGLContextEvent::Create(event_type_names::kWebglcontextcreationerror,
                                  "Could not create a WebGL context."));
    // We must dispose immediately so that when rendering_context is
    // garbage-collected, it will not interfere with a subsequently created
    // rendering context.
    rendering_context->Dispose();
    return nullptr;
  }
  rendering_context->InitializeNewContext();
  rendering_context->RegisterContextExtensions();
  return rendering_context;
}

void WebGLRenderingContext::Factory::OnError(HTMLCanvasElement* canvas,
                                             const String& error) {
  canvas->DispatchEvent(*WebGLContextEvent::Create(
      event_type_names::kWebglcontextcreationerror, error));
}

WebGLRenderingContext::WebGLRenderingContext(
    CanvasRenderingContextHost* host,
    std::unique_ptr<WebGraphicsContext3DProvider> context_provider,
    const Platform::GraphicsInfo& graphics_info,
    const CanvasContextCreationAttributesCore& requested_attributes)
    : WebGLRenderingContextBase(host,
                                std::move(context_provider),
                                graphics_info,
                                requested_attributes,
                                Platform::kWebGL1ContextType) {}

V8RenderingContext* WebGLRenderingContext::AsV8RenderingContext() {
  return MakeGarbageCollected<V8RenderingContext>(this);
}

V8OffscreenRenderingContext*
WebGLRenderingContext::AsV8OffscreenRenderingContext() {
  return MakeGarbageCollected<V8OffscreenRenderingContext>(this);
}

ImageBitmap* WebGLRenderingContext::TransferToImageBitmap(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  return TransferToImageBitmapBase(script_state);
}

void WebGLRenderingContext::RegisterContextExtensions() {
  RegisterExtension<ANGLEInstancedArrays>();
  RegisterExtension<EXTBlendMinMax>();
  RegisterExtension<EXTClipControl>();
  RegisterExtension<EXTColorBufferHalfFloat>();
  RegisterExtension<EXTDepthClamp>();
  RegisterExtension<EXTDisjointTimerQuery>(TimerQueryExtensionsEnabled()
                                           ? kApprovedExtension
                                           : kDeveloperExtension);
  RegisterExtension<EXTFloatBlend>();
  RegisterExtension<EXTFragDepth>();
  RegisterExtension<EXTPolygonOffsetClamp>();
  RegisterExtension<EXTShaderTextureLOD>();
  RegisterExtension<EXTTextureCompressionBPTC>();
  RegisterExtension<EXTTextureCompressionRGTC>();
  RegisterExtension<EXTTextureFilterAnisotropic>(kApprovedExtension);
  RegisterExtension<EXTTextureMirrorClampToEdge>();
  RegisterExtension<EXTsRGB>();
  RegisterExtension<KHRParallelShaderCompile>();
  RegisterExtension<OESElementIndexUint>();
  RegisterExtension<OESFboRenderMipmap>();
  RegisterExtension<OESStandardDerivatives>();
  RegisterExtension<OESTextureFloat>();
  RegisterExtension<OESTextureFloatLinear>();
  RegisterExtension<OESTextureHalfFloat>();
  RegisterExtension<OESTextureHalfFloatLinear>();
  RegisterExtension<OESVertexArrayObject>();
  RegisterExtension<WebGLBlendFuncExtended>();
  RegisterExtension<WebGLColorBufferFloat>();
  RegisterExtension<WebGLCompressedTextureASTC>();
  RegisterExtension<WebGLCompressedTextureETC>();
  RegisterExtension<WebGLCompressedTextureETC1>();
  RegisterExtension<WebGLCompressedTexturePVRTC>(kApprovedExtension);
  RegisterExtension<WebGLCompressedTextureS3TC>(kApprovedExtension);
  RegisterExtension<WebGLCompressedTextureS3TCsRGB>();
  RegisterExtension<WebGLDebugRendererInfo>();
  RegisterExtension<WebGLDebugShaders>();
  RegisterExtension<WebGLDepthTexture>(kApprovedExtension);
  RegisterExtension<WebGLDrawBuffers>();
  RegisterExtension<WebGLLoseContext>(kApprovedExtension);
  RegisterExtension<WebGLMultiDraw>();
  RegisterExtension<WebGLPolygonMode>();
}

}  // namespace blink
```