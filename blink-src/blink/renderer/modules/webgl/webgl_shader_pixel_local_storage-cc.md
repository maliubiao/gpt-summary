Response:
Let's break down the thought process for analyzing this WebGL PLS code.

**1. Understanding the Goal:**

The request asks for the functionality of the provided C++ code snippet, its relation to web technologies (JavaScript, HTML, CSS), potential logical inferences (with examples), common usage errors, and how a user might trigger this code. The core task is to understand what this specific C++ file does within the larger context of the Chromium browser and the WebGL API.

**2. Initial Code Scan and Keywords:**

I started by quickly scanning the code for key terms and patterns:

* **`WebGLShaderPixelLocalStorage`:** This immediately tells me the core functionality is related to Pixel Local Storage within the WebGL API.
* **`Supported` and `ExtensionName`:** These suggest this code implements a specific WebGL extension. The extension name `GL_ANGLE_shader_pixel_local_storage` (and its coherent variant) confirms this.
* **`WebGLRenderingContextBase`:** This indicates interaction with the main WebGL context in the browser.
* **`WebGLFramebuffer` and `WebGLTexture`:**  These are fundamental WebGL objects, suggesting the feature involves rendering to textures within framebuffers.
* **`framebufferTexturePixelLocalStorageWEBGL`, `framebufferPixelLocalClearValue...WEBGL`, `beginPixelLocalStorageWEBGL`, `endPixelLocalStorageWEBGL`, `pixelLocalStorageBarrierWEBGL`, `getFramebufferPixelLocalStorageParameterWEBGL`:** These function names clearly point to the operations this extension enables. The `WEBGL` suffix suggests these are the JavaScript-exposed functions.
* **`GL_MAX_PIXEL_LOCAL_STORAGE_PLANES_ANGLE`:**  This is a constant related to the maximum number of PLS "slots."
* **`ValidatePLS...` functions:**  These indicate error checking and validation of input parameters.
* **`ContextGL()`:** This suggests a direct interaction with the underlying OpenGL/ANGLE implementation.
* **`ScriptValue` and `WebGLAny`:**  These hints at how the results are returned to JavaScript.
* **`loadops` and `storeops`:** These likely refer to operations performed when pixel local storage is started and ended.

**3. Inferring Functionality:**

Based on the keywords and function names, I could start to infer the high-level functionality:

* **Enabling Pixel Local Storage:** The code manages enabling and using a specific WebGL extension.
* **Associating Textures with PLS:**  `framebufferTexturePixelLocalStorageWEBGL` likely binds a texture to a specific pixel local storage "plane" within a framebuffer.
* **Clearing PLS Data:** The `framebufferPixelLocalClearValue...WEBGL` functions allow setting initial values for the pixel local storage.
* **Controlling PLS Execution:** `beginPixelLocalStorageWEBGL`, `endPixelLocalStorageWEBGL`, and `pixelLocalStorageBarrierWEBGL` seem to control when and how pixel local storage is active during rendering.
* **Querying PLS State:**  `getFramebufferPixelLocalStorageParameterWEBGL` allows retrieval of information about the current PLS configuration.

**4. Connecting to Web Technologies:**

Now, the goal is to link this C++ code to the user-facing web technologies:

* **JavaScript:** The function names ending in `WEBGL` strongly suggest these are the JavaScript APIs exposed to developers. I would expect to see these functions available on a `WebGLRenderingContext` object after the `WEBGL_shader_pixel_local_storage` extension is enabled.
* **HTML:** HTML provides the `<canvas>` element where WebGL rendering happens. The JavaScript code using these WebGL PLS functions would operate on a `WebGLRenderingContext` obtained from a `<canvas>`.
* **CSS:** While not directly involved in the *logic* of PLS, CSS styles the `<canvas>` element. Incorrect canvas sizing could indirectly affect the rendering results, but CSS doesn't interact with the core PLS functionality.

**5. Logical Inferences and Examples:**

To illustrate the functionality, I needed to create hypothetical scenarios:

* **Assumption:**  A developer wants to store per-pixel data.
* **Input:** JavaScript calls to the functions with specific parameters (plane index, texture, clear values, load/store operations).
* **Output:** The rendered image reflects the data stored and manipulated using pixel local storage.

I focused on scenarios demonstrating the core operations: binding textures, clearing data, and the begin/end flow.

**6. Identifying Common Errors:**

Based on the validation functions (`ValidatePLS...`), I could deduce potential programmer errors:

* **Invalid Framebuffer:** Trying to use PLS with a framebuffer that doesn't support it.
* **Out-of-Bounds Plane Index:** Specifying a plane index beyond the maximum allowed.
* **Incorrect Clear Value Size:** Providing an insufficient amount of data for clearing.
* **Calling PLS functions without enabling the extension.**

**7. Tracing User Actions:**

To understand how a user reaches this code, I followed the execution path:

1. **User Interaction:** A user visits a webpage.
2. **JavaScript Execution:** The webpage's JavaScript code interacts with the WebGL API.
3. **Extension Request:** The JavaScript code enables the `WEBGL_shader_pixel_local_storage` extension.
4. **Function Calls:** The JavaScript code calls the specific PLS functions (e.g., `framebufferTexturePixelLocalStorageWEBGL`).
5. **C++ Execution:**  The browser's JavaScript engine calls the corresponding C++ implementation in `webgl_shader_pixel_local_storage.cc`.

**8. Refining and Structuring the Explanation:**

Finally, I organized the information logically, starting with a high-level summary of the file's purpose, then detailing each aspect requested: functionality, relationship to web technologies, logical inferences, common errors, and the user interaction flow. I used clear headings and bullet points to improve readability. I also ensured I provided concrete examples wherever possible. The key is to bridge the gap between the low-level C++ code and the high-level concepts of web development.
好的，让我们来分析一下 `blink/renderer/modules/webgl/webgl_shader_pixel_local_storage.cc` 这个文件的功能。

**功能概要**

这个 C++ 文件实现了名为 `WEBGL_shader_pixel_local_storage` 的 WebGL 扩展。  Pixel Local Storage (PLS) 是一种允许着色器在像素级别读写数据的机制，这些数据存储在与帧缓冲区关联的附件中。简单来说，它允许你在渲染过程中，让每个像素都有一些“本地”的存储空间，供着色器读写。

**详细功能分解**

1. **扩展支持检测 (`Supported`)**:
   - `Supported(WebGLRenderingContextBase* context)` 函数检查当前 WebGL 上下文是否支持 `GL_ANGLE_shader_pixel_local_storage` 扩展。这依赖于底层的 OpenGL/ANGLE 实现。

2. **扩展名称 (`ExtensionName`)**:
   - `ExtensionName()` 函数返回该扩展的字符串标识符 `"WEBGL_shader_pixel_local_storage"`。

3. **扩展初始化 (`WebGLShaderPixelLocalStorage` 构造函数)**:
   - 在构造函数中，会检查并启用其他相关的 WebGL 扩展，如 `OES_draw_buffers_indexed`（用于支持绑定多个颜色附件）、`EXT_color_buffer_float` 和 `EXT_color_buffer_half_float`（用于支持浮点数和半浮点数颜色缓冲区）。
   - 它还会获取最大的 PLS 平面数量 (`GL_MAX_PIXEL_LOCAL_STORAGE_PLANES_ANGLE`)，这决定了你可以为每个像素分配多少个独立的存储区域。
   - 检查并记录是否支持 coherent 的 PLS (`GL_ANGLE_shader_pixel_local_storage_coherent`)，coherent PLS 意味着不同着色器调用对 PLS 的读写操作是按照顺序执行的。

4. **获取扩展名称 (`GetName`)**:
   - `GetName()` 返回 `kWebGLShaderPixelLocalStorageName`，这通常是一个常量字符串。

5. **检查 Coherent 支持 (`isCoherent`)**:
   - `isCoherent()` 方法返回一个布尔值，指示当前环境是否支持 coherent 的像素本地存储。

6. **验证 PLS 帧缓冲区 (`ValidatePLSFramebuffer`)**:
   - 此函数检查当前绑定的 `GL_DRAW_FRAMEBUFFER` 是否是一个有效的、支持像素本地存储的帧缓冲区。如果帧缓冲区为空或者是不透明的，则会产生一个 `GL_INVALID_OPERATION` 错误。

7. **验证 PLS 平面索引 (`ValidatePLSPlaneIndex`)**:
   - 此函数检查指定的 PLS 平面索引 `plane` 是否在有效范围内 (0 到 `max_pls_planes_ - 1`)。如果索引超出范围，则会产生 `GL_INVALID_VALUE` 错误。

8. **验证 PLS 清除命令 (`ValidatePLSClearCommand`)**:
   - 此函数在执行清除 PLS 数据的操作前进行验证，确保帧缓冲区和平面索引有效，并且清除操作的数据偏移和长度是合法的，防止越界访问。

9. **绑定纹理到 PLS 平面 (`framebufferTexturePixelLocalStorageWEBGL`)**:
   - 这个函数将一个 WebGL 纹理的指定层级和层绑定到帧缓冲区的特定 PLS 平面。这使得着色器可以读写该纹理的内容作为像素的本地存储。

10. **设置 PLS 平面的清除值 (`framebufferPixelLocalClearValuefvWEBGL`, `framebufferPixelLocalClearValueivWEBGL`, `framebufferPixelLocalClearValueuivWEBGL`)**:
    - 这些函数允许你设置在开始使用 PLS 之前，每个 PLS 平面应该被清除成的初始值。它们分别用于设置浮点数、整数和无符号整数类型的清除值。

11. **开始像素本地存储 (`beginPixelLocalStorageWEBGL`)**:
    - 此函数标志着开始使用像素本地存储。它接受一个 `loadops` 向量，指定了在开始使用 PLS 时，如何加载 PLS 平面的数据。例如，可以指定 `GL_LOAD` 从先前的内容加载，或者 `GL_CLEAR` 使用之前设置的清除值。
    - 在调用底层 OpenGL 函数 `BeginPixelLocalStorageANGLE` 之前，还会触发 `ClearIfComposited`，确保在开始 PLS 之前执行任何挂起的清除操作。
    - 它还会设置上下文的 `has_activated_pixel_local_storage_` 标志为 `true`，这可能会影响后续的渲染处理。

12. **结束像素本地存储 (`endPixelLocalStorageWEBGL`)**:
    - 此函数标志着结束使用像素本地存储。它接受一个 `storeops` 向量，指定了在结束使用 PLS 时，如何处理 PLS 平面的数据。例如，可以指定 `GL_STORE` 将 PLS 的内容写回关联的纹理或渲染缓冲区。

13. **像素本地存储屏障 (`pixelLocalStorageBarrierWEBGL`)**:
    - 此函数插入一个内存屏障，确保在屏障之前的对像素本地存储的访问操作都在屏障之后的访问操作之前完成。这对于确保不同着色器调用之间数据同步非常重要，尤其是在 non-coherent 的 PLS 环境中。

14. **获取帧缓冲区像素本地存储参数 (`getFramebufferPixelLocalStorageParameterWEBGL`)**:
    - 这个函数允许 JavaScript 查询关于帧缓冲区上特定 PLS 平面的参数。可以查询的参数包括：
        - `GL_PIXEL_LOCAL_FORMAT_ANGLE`:  PLS 平面的格式。
        - `GL_PIXEL_LOCAL_TEXTURE_NAME_ANGLE`:  绑定到该 PLS 平面的纹理对象。
        - `GL_PIXEL_LOCAL_TEXTURE_LEVEL_ANGLE`:  绑定纹理的 mipmap 层级。
        - `GL_PIXEL_LOCAL_TEXTURE_LAYER_ANGLE`:  绑定纹理的层。
        - `GL_PIXEL_LOCAL_CLEAR_VALUE_FLOAT_ANGLE`, `GL_PIXEL_LOCAL_CLEAR_VALUE_INT_ANGLE`, `GL_PIXEL_LOCAL_CLEAR_VALUE_UNSIGNED_INT_ANGLE`:  PLS 平面的清除值。

**与 JavaScript, HTML, CSS 的关系**

这个 C++ 文件是 WebGL API 的底层实现的一部分，直接与 JavaScript 代码交互。

* **JavaScript**:
    - WebGL API 通过 `WebGLRenderingContext` 对象暴露给 JavaScript。
    - 当 `WEBGL_shader_pixel_local_storage` 扩展被启用后，JavaScript 代码可以使用以下方法（这些方法在 C++ 代码中实现）：
        - `gl.framebufferTexturePixelLocalStorageWEBGL(...)`
        - `gl.framebufferPixelLocalClearValuefvWEBGL(...)`
        - `gl.framebufferPixelLocalClearValueivWEBGL(...)`
        - `gl.framebufferPixelLocalClearValueuivWEBGL(...)`
        - `gl.beginPixelLocalStorageWEBGL(...)`
        - `gl.endPixelLocalStorageWEBGL(...)`
        - `gl.pixelLocalStorageBarrierWEBGL()`
        - `gl.getFramebufferPixelLocalStorageParameterWEBGL(...)`
    - **例子**:
      ```javascript
      const canvas = document.getElementById('myCanvas');
      const gl = canvas.getContext('webgl2');
      const ext = gl.getExtension('WEBGL_shader_pixel_local_storage');
      if (ext) {
        const framebuffer = gl.createFramebuffer();
        gl.bindFramebuffer(gl.DRAW_FRAMEBUFFER, framebuffer);

        // 假设已经创建了一个纹理 texture
        ext.framebufferTexturePixelLocalStorageWEBGL(0, texture, 0, 0);

        ext.framebufferPixelLocalClearValuefvWEBGL(0, [1.0, 0.0, 0.0, 1.0], 0);
        ext.beginPixelLocalStorageWEBGL([gl.CLEAR]);

        // ... 进行渲染 ...

        ext.endPixelLocalStorageWEBGL([gl.STORE]);
        gl.bindFramebuffer(gl.DRAW_FRAMEBUFFER, null);
      }
      ```

* **HTML**:
    - HTML 中的 `<canvas>` 元素是 WebGL 内容的渲染目标。JavaScript 代码获取 `<canvas>` 元素的上下文，并在其上执行 WebGL 命令。
    - **例子**:
      ```html
      <canvas id="myCanvas" width="500" height="300"></canvas>
      ```

* **CSS**:
    - CSS 用于样式化 HTML 元素，包括 `<canvas>` 元素。虽然 CSS 不直接影响 WebGL 的逻辑功能，但它可以控制 `<canvas>` 的大小和布局，从而影响渲染结果。
    - **例子**:
      ```css
      #myCanvas {
        border: 1px solid black;
      }
      ```

**逻辑推理与假设输入/输出**

**假设输入**:

1. **JavaScript 调用 `gl.getExtension('WEBGL_shader_pixel_local_storage')` 返回一个非空对象 `ext`。**
2. **创建并绑定了一个支持 PLS 的 `WebGLFramebuffer`。**
3. **创建了一个 `WebGLTexture` 对象 `texture`。**
4. **JavaScript 调用 `ext.framebufferTexturePixelLocalStorageWEBGL(0, texture, 0, 0)`。**
5. **JavaScript 调用 `ext.beginPixelLocalStorageWEBGL([gl.CLEAR])`。**

**逻辑推理**:

- `framebufferTexturePixelLocalStorageWEBGL` 函数会调用底层的 OpenGL 函数，将 `texture` 绑定到当前帧缓冲区的第 0 个 PLS 平面。
- `beginPixelLocalStorageWEBGL` 函数会调用底层的 OpenGL 函数，开始使用 PLS，并指示在开始时使用清除值（因为传入了 `gl.CLEAR`）。

**假设输出**:

- 在后续的渲染过程中，着色器可以访问与像素关联的本地存储，并且该本地存储的内容将与 `texture` 的内容相关联。
- 在 `beginPixelLocalStorageWEBGL` 调用后，第 0 个 PLS 平面的内容将被清除为之前通过 `framebufferPixelLocalClearValue...` 设置的值（如果设置过）。

**用户或编程常见的使用错误**

1. **未检查扩展支持**: 在使用 PLS 功能之前，没有先检查 `gl.getExtension('WEBGL_shader_pixel_local_storage')` 是否返回非空值。
   - **例子**: 直接调用 `ext.framebufferTexturePixelLocalStorageWEBGL(...)` 而没有检查 `ext` 是否存在。

2. **使用了不支持 PLS 的帧缓冲区**: 尝试在一个不满足 PLS 要求的帧缓冲区上使用 PLS 功能。
   - **例子**: 使用默认的帧缓冲区或者手动创建了一个不兼容的帧缓冲区。

3. **平面索引超出范围**: 传递给 PLS 函数的平面索引超出了 `GL_MAX_PIXEL_LOCAL_STORAGE_PLANES_ANGLE` 的限制。
   - **例子**: 如果 `GL_MAX_PIXEL_LOCAL_STORAGE_PLANES_ANGLE` 是 4，却调用了 `ext.framebufferTexturePixelLocalStorageWEBGL(4, ...)`。

4. **`beginPixelLocalStorageWEBGL` 和 `endPixelLocalStorageWEBGL` 不匹配**:  忘记调用 `endPixelLocalStorageWEBGL`，或者在没有调用 `beginPixelLocalStorageWEBGL` 的情况下调用 `endPixelLocalStorageWEBGL`。

5. **不正确的清除值大小或类型**:  传递给 `framebufferPixelLocalClearValue...WEBGL` 函数的数组大小或类型与 PLS 平面的格式不匹配。

**用户操作如何一步步到达这里 (调试线索)**

1. **用户访问包含 WebGL 内容的网页**: 用户在浏览器中打开一个网页，该网页使用了 WebGL 技术进行渲染。
2. **网页 JavaScript 代码初始化 WebGL 上下文**: 网页的 JavaScript 代码获取 `<canvas>` 元素的 WebGL 上下文 (`getContext('webgl')` 或 `getContext('webgl2')`)。
3. **JavaScript 代码尝试启用 `WEBGL_shader_pixel_local_storage` 扩展**: JavaScript 代码调用 `gl.getExtension('WEBGL_shader_pixel_local_storage')`。如果浏览器支持该扩展，则会返回一个扩展对象。
4. **JavaScript 代码调用 PLS 相关函数**: 开发者编写的 JavaScript 代码使用返回的扩展对象 `ext` 调用 `framebufferTexturePixelLocalStorageWEBGL`、`beginPixelLocalStorageWEBGL` 等函数来配置和使用像素本地存储。
5. **浏览器执行 JavaScript 代码，调用 Blink 渲染引擎的 C++ 代码**: 当 JavaScript 代码调用这些扩展方法时，JavaScript 引擎会调用 Blink 渲染引擎中对应的 C++ 实现，即 `webgl_shader_pixel_local_storage.cc` 中的函数。

**作为调试线索**:

- **检查扩展是否成功启用**: 在 JavaScript 代码中，首先确认 `gl.getExtension('WEBGL_shader_pixel_local_storage')` 返回了非空值。
- **检查 WebGL 错误**: 使用 `gl.getError()` 检查在调用 PLS 相关函数后是否有 WebGL 错误产生，例如 `GL_INVALID_OPERATION` 或 `GL_INVALID_VALUE`。
- **断点调试**:  如果可以访问 Chromium 的源代码，可以在 `webgl_shader_pixel_local_storage.cc` 中的相关函数设置断点，例如在 `ValidatePLSFramebuffer` 或 `framebufferTexturePixelLocalStorageWEBGL` 中，来查看参数值和执行流程。
- **查看 OpenGL/ANGLE 日志**: 如果启用了 OpenGL 或 ANGLE 的调试日志，可以查看是否有与 PLS 相关的错误或警告信息。

希望以上分析能够帮助你理解 `blink/renderer/modules/webgl/webgl_shader_pixel_local_storage.cc` 文件的功能和它在 WebGL 生态系统中的作用。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl_shader_pixel_local_storage.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2023 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/webgl/webgl_shader_pixel_local_storage.h"

#include <array>
#include "third_party/blink/renderer/bindings/modules/v8/webgl_any.h"
#include "third_party/blink/renderer/modules/webgl/webgl_framebuffer.h"
#include "third_party/blink/renderer/modules/webgl/webgl_rendering_context_base.h"

namespace blink {

bool WebGLShaderPixelLocalStorage::Supported(
    WebGLRenderingContextBase* context) {
  return context->ExtensionsUtil()->SupportsExtension(
      "GL_ANGLE_shader_pixel_local_storage");
}

const char* WebGLShaderPixelLocalStorage::ExtensionName() {
  return "WEBGL_shader_pixel_local_storage";
}

WebGLShaderPixelLocalStorage::WebGLShaderPixelLocalStorage(
    WebGLRenderingContextBase* context)
    : WebGLExtension(context),
      coherent_(context->ExtensionsUtil()->SupportsExtension(
          "GL_ANGLE_shader_pixel_local_storage_coherent")) {
  context->EnableExtensionIfSupported("OES_draw_buffers_indexed");
  context->EnableExtensionIfSupported("EXT_color_buffer_float");
  context->EnableExtensionIfSupported("EXT_color_buffer_half_float");
  context->ExtensionsUtil()->EnsureExtensionEnabled(
      "GL_ANGLE_shader_pixel_local_storage");
  context->ContextGL()->GetIntegerv(GL_MAX_PIXEL_LOCAL_STORAGE_PLANES_ANGLE,
                                    &max_pls_planes_);
}

WebGLExtensionName WebGLShaderPixelLocalStorage::GetName() const {
  return kWebGLShaderPixelLocalStorageName;
}

bool WebGLShaderPixelLocalStorage::isCoherent() const {
  return coherent_;
}

WebGLFramebuffer* WebGLShaderPixelLocalStorage::ValidatePLSFramebuffer(
    WebGLRenderingContextBase* context,
    const char* function_name) {
  WebGLFramebuffer* framebuffer_binding =
      context->GetFramebufferBinding(GL_DRAW_FRAMEBUFFER);
  if (!framebuffer_binding || !framebuffer_binding->Object() ||
      framebuffer_binding->Opaque()) {
    context->SynthesizeGLError(
        GL_INVALID_OPERATION, function_name,
        "framebuffer does not support pixel local storage");
    return nullptr;
  }
  return framebuffer_binding;
}

bool WebGLShaderPixelLocalStorage::ValidatePLSPlaneIndex(
    WebGLRenderingContextBase* context,
    const char* function_name,
    GLint plane) {
  if (plane < 0) {
    context->SynthesizeGLError(GL_INVALID_VALUE, function_name,
                               "<plane> is < 0");
    return false;
  }
  if (plane >= max_pls_planes_) {
    context->SynthesizeGLError(
        GL_INVALID_VALUE, function_name,
        "<plane> is >= GL_MAX_PIXEL_LOCAL_STORAGE_PLANES_ANGLE");
    return false;
  }
  return true;
}

bool WebGLShaderPixelLocalStorage::ValidatePLSClearCommand(
    WebGLRenderingContextBase* context,
    const char* function_name,
    GLint plane,
    size_t src_length,
    GLuint src_offset) {
  if (!ValidatePLSFramebuffer(context, function_name) ||
      !ValidatePLSPlaneIndex(context, function_name, plane)) {
    return false;
  }
  if (!base::CheckAdd(src_offset, 4u).IsValid()) {
    context->SynthesizeGLError(GL_INVALID_VALUE, function_name,
                               "clear offset is too large");
    return false;
  }
  if (src_length < src_offset + 4u) {
    context->SynthesizeGLError(GL_INVALID_VALUE, function_name,
                               "clear value must contain at least 4 elements");
    return false;
  }
  return true;
}

void WebGLShaderPixelLocalStorage::framebufferTexturePixelLocalStorageWEBGL(
    GLint plane,
    WebGLTexture* texture,
    GLint level,
    GLint layer) {
  WebGLExtensionScopedContext scoped(this);
  if (scoped.IsLost()) {
    return;
  }
  constexpr static char function_name[] =
      "framebufferTexturePixelLocalStorageWEBGL";
  WebGLRenderingContextBase* context = scoped.Context();
  WebGLFramebuffer* framebuffer =
      ValidatePLSFramebuffer(context, function_name);
  if (!framebuffer) {
    return;
  }
  if (!ValidatePLSPlaneIndex(context, function_name, plane) ||
      !context->ValidateNullableWebGLObject(function_name, texture)) {
    return;
  }
  context->ContextGL()->FramebufferTexturePixelLocalStorageANGLE(
      plane, ObjectOrZero(texture), level, layer);
  framebuffer->SetPLSTexture(plane, texture);
}

void WebGLShaderPixelLocalStorage::framebufferPixelLocalClearValuefvWEBGL(
    GLint plane,
    base::span<const GLfloat> value,
    GLuint src_offset) {
  WebGLExtensionScopedContext scoped(this);
  if (scoped.IsLost()) {
    return;
  }
  constexpr static char function_name[] =
      "framebufferPixelLocalClearValuefvWEBGL";
  WebGLRenderingContextBase* context = scoped.Context();
  if (!ValidatePLSClearCommand(context, function_name, plane, value.size(),
                               src_offset)) {
    return;
  }
  context->ContextGL()->FramebufferPixelLocalClearValuefvANGLE(
      plane, value.subspan(src_offset).data());
}

void WebGLShaderPixelLocalStorage::framebufferPixelLocalClearValueivWEBGL(
    GLint plane,
    base::span<const GLint> value,
    GLuint src_offset) {
  WebGLExtensionScopedContext scoped(this);
  if (scoped.IsLost()) {
    return;
  }
  constexpr static char function_name[] =
      "framebufferPixelLocalClearValueivWEBGL";
  WebGLRenderingContextBase* context = scoped.Context();
  if (!ValidatePLSClearCommand(context, function_name, plane, value.size(),
                               src_offset)) {
    return;
  }
  context->ContextGL()->FramebufferPixelLocalClearValueivANGLE(
      plane, value.subspan(src_offset).data());
}

void WebGLShaderPixelLocalStorage::framebufferPixelLocalClearValueuivWEBGL(
    GLint plane,
    base::span<const GLuint> value,
    GLuint src_offset) {
  WebGLExtensionScopedContext scoped(this);
  if (scoped.IsLost()) {
    return;
  }
  constexpr static char function_name[] =
      "framebufferPixelLocalClearValueuivWEBGL";
  WebGLRenderingContextBase* context = scoped.Context();
  if (!ValidatePLSClearCommand(context, function_name, plane, value.size(),
                               src_offset)) {
    return;
  }
  context->ContextGL()->FramebufferPixelLocalClearValueuivANGLE(
      plane, value.subspan(src_offset).data());
}

void WebGLShaderPixelLocalStorage::beginPixelLocalStorageWEBGL(
    const Vector<GLenum>& loadops) {
  WebGLExtensionScopedContext scoped(this);
  if (scoped.IsLost()) {
    return;
  }
  constexpr static char function_name[] = "beginPixelLocalStorageWEBGL";
  WebGLRenderingContextBase* context = scoped.Context();
  if (!ValidatePLSFramebuffer(context, function_name)) {
    return;
  }
  // Perform any deferred clears before we begin pixel local storage.
  context->ClearIfComposited(WebGLRenderingContextBase::kClearCallerOther);
  context->ContextGL()->BeginPixelLocalStorageANGLE(loadops.size(),
                                                    loadops.data());
  // Let the context know we have used pixel local storage so it will start
  // using the interrupt mechanism when it takes over the client's context.
  context->has_activated_pixel_local_storage_ = true;
}

void WebGLShaderPixelLocalStorage::endPixelLocalStorageWEBGL(
    const Vector<GLenum>& storeops) {
  WebGLExtensionScopedContext scoped(this);
  if (scoped.IsLost()) {
    return;
  }
  constexpr static char function_name[] = "endPixelLocalStorageWEBGL";
  WebGLRenderingContextBase* context = scoped.Context();
  if (!ValidatePLSFramebuffer(context, function_name)) {
    return;
  }
  context->ContextGL()->EndPixelLocalStorageANGLE(storeops.size(),
                                                  storeops.data());
}

void WebGLShaderPixelLocalStorage::pixelLocalStorageBarrierWEBGL() {
  WebGLExtensionScopedContext scoped(this);
  if (scoped.IsLost()) {
    return;
  }
  constexpr static char function_name[] = "pixelLocalStorageBarrierWEBGL";
  WebGLRenderingContextBase* context = scoped.Context();
  if (!ValidatePLSFramebuffer(context, function_name)) {
    return;
  }
  context->ContextGL()->PixelLocalStorageBarrierANGLE();
}

ScriptValue
WebGLShaderPixelLocalStorage::getFramebufferPixelLocalStorageParameterWEBGL(
    ScriptState* script_state,
    GLint plane,
    GLenum pname) {
  WebGLExtensionScopedContext scoped(this);
  if (scoped.IsLost()) {
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }
  constexpr static char function_name[] =
      "getFramebufferPixelLocalStorageParameterWEBGL";
  WebGLRenderingContextBase* context = scoped.Context();
  WebGLFramebuffer* framebuffer =
      ValidatePLSFramebuffer(context, function_name);
  if (!framebuffer) {
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }
  if (!ValidatePLSPlaneIndex(context, function_name, plane)) {
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }
  gpu::gles2::GLES2Interface* gl = context->ContextGL();
  switch (pname) {
    case GL_PIXEL_LOCAL_FORMAT_ANGLE: {
      GLint value{};
      gl->GetFramebufferPixelLocalStorageParameterivANGLE(plane, pname, &value);
      return WebGLAny(script_state, static_cast<GLenum>(value));
    }
    case GL_PIXEL_LOCAL_TEXTURE_NAME_ANGLE: {
      DCHECK(framebuffer);
      WebGLTexture* tex = framebuffer->GetPLSTexture(plane);
      GLint attachedTextureID{};
      gl->GetFramebufferPixelLocalStorageParameterivANGLE(plane, pname,
                                                          &attachedTextureID);
      if (static_cast<GLuint>(attachedTextureID) != ObjectOrZero(tex)) {
        // Implementation gap! Tracked PLS texture is out of sync with actual.
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      return WebGLAny(script_state, tex);
    }
    case GL_PIXEL_LOCAL_TEXTURE_LEVEL_ANGLE:
    case GL_PIXEL_LOCAL_TEXTURE_LAYER_ANGLE: {
      GLint value{};
      gl->GetFramebufferPixelLocalStorageParameterivANGLE(plane, pname, &value);
      return WebGLAny(script_state, value);
    }
    case GL_PIXEL_LOCAL_CLEAR_VALUE_FLOAT_ANGLE: {
      DOMFloat32Array* values = DOMFloat32Array::Create(4);
      gl->GetFramebufferPixelLocalStorageParameterfvANGLE(plane, pname,
                                                          values->Data());
      return WebGLAny(script_state, values);
    }
    case GL_PIXEL_LOCAL_CLEAR_VALUE_INT_ANGLE: {
      DOMInt32Array* values = DOMInt32Array::Create(4);
      gl->GetFramebufferPixelLocalStorageParameterivANGLE(plane, pname,
                                                          values->Data());
      return WebGLAny(script_state, values);
    }
    case GL_PIXEL_LOCAL_CLEAR_VALUE_UNSIGNED_INT_ANGLE: {
      DOMUint32Array* values = DOMUint32Array::Create(4);
      gl->GetFramebufferPixelLocalStorageParameterivANGLE(
          plane, pname, reinterpret_cast<GLint*>(values->Data()));
      return WebGLAny(script_state, values);
    }
  }
  return ScriptValue::CreateNull(script_state->GetIsolate());
}

}  // namespace blink

"""

```