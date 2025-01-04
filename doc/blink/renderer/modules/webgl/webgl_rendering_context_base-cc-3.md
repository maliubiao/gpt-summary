Response:
Let's break down the thought process for analyzing this code snippet and fulfilling the prompt's requirements.

**1. Initial Understanding & Goal:**

The core task is to analyze a chunk of C++ code from the Chromium Blink engine, specifically the `webgl_rendering_context_base.cc` file. The goal is to understand its functions, its relation to web technologies (JavaScript, HTML, CSS), potential errors, debugging tips, and summarize its purpose within the larger file.

**2. Deconstructing the Request:**

The prompt asks for several distinct pieces of information:

* **Functionality:** What do the code blocks *do*?  This involves identifying function names and their core actions.
* **Relation to JS/HTML/CSS:**  How does this C++ code interact with the web developer's world?  This requires connecting C++ functions to the corresponding WebGL JavaScript API calls.
* **Logic Inference (Input/Output):**  For specific functions, can we create simple examples of what input they might receive and what the likely outcome would be?
* **Common Errors:** What mistakes might a developer make when using the corresponding JavaScript API, leading to these code paths?
* **User Operation to Reach Here:** How does a user's interaction in a web browser ultimately trigger this C++ code?  This is about the chain of events from the web page to the browser's rendering engine.
* **Summary of Functionality (Part 4 of 11):**  Given this specific code block, what's its main contribution to the overall file?

**3. Code Analysis - The Iterative Process:**

* **Identify Key Functions:** Scan the code for function definitions. The names are often descriptive (e.g., `copyTexImage2D`, `createBuffer`, `deleteBuffer`, `depthMask`). These are the starting points for understanding the code's actions.
* **Understand Function Logic:** For each function, analyze its internal steps. Look for:
    * **Error Handling:**  `isContextLost()`, `SynthesizeGLError()`, `Validate...()` functions indicate checks and error reporting.
    * **Calls to `ContextGL()`:**  This suggests interaction with the underlying OpenGL implementation. The function names prefixed with `ContextGL()->` hint at the corresponding OpenGL ES calls (e.g., `CopyTexImage2D`, `CullFace`, `DepthMask`).
    * **Object Creation/Deletion:** `MakeGarbageCollected<...>()`, `DeleteObject()` are related to memory management and object lifecycle.
    * **State Management:**  Variables like `depth_mask_`, `stencil_enabled_`, `framebuffer_binding_` track the WebGL context's state.
    * **Validation:** Functions starting with `Validate` perform checks on input parameters or the current state.
* **Group Related Functions:** Notice patterns. For example, there's a group of `create...()` functions, and a corresponding group of `delete...()` functions. This helps in understanding the code's structure.
* **Connect to WebGL Concepts:**  As you analyze functions, connect them to your knowledge of the WebGL API. For instance, `copyTexImage2D` clearly relates to copying framebuffer content to a texture, a common WebGL operation. `createBuffer`, `createTexture`, etc., directly map to the JavaScript API for creating these resources.

**4. Addressing Specific Request Points:**

* **Functionality Listing:** Based on the code analysis, create a bulleted list of the identified functions and briefly describe what they do. Focus on the core action.
* **JS/HTML/CSS Relationship:**
    * **Identify Corresponding JS APIs:** For each C++ function, determine the corresponding JavaScript WebGL method (e.g., `copyTexImage2D` in C++ maps to `gl.copyTexImage2D()` in JavaScript).
    * **Provide Examples:** Create simple code snippets showing how these JavaScript APIs are used in web pages, and explain how they relate to HTML (the `<canvas>` element) and potentially CSS (styling the canvas).
* **Logic Inference (Input/Output):**
    * **Choose Relevant Functions:** Select functions with clear inputs and outputs (e.g., `copyTexImage2D`).
    * **Define Hypothetical Inputs:**  Invent reasonable input values for the function parameters, considering WebGL data types.
    * **Describe Expected Output/Side Effects:** Explain what the function is likely to do with those inputs (e.g., copy pixels to the texture) and any potential side effects (e.g., generating an error).
* **Common Errors:**
    * **Think Like a Developer:**  Consider common mistakes developers make when using WebGL. This often involves incorrect parameter values, using deleted objects, or violating WebGL state rules.
    * **Match Errors to Code:**  Look for `SynthesizeGLError()` calls in the C++ code and understand the conditions that trigger them.
* **User Operation to Reach Here:**
    * **Start with User Interaction:**  Begin with a typical user action on a web page (e.g., loading a page with a WebGL canvas).
    * **Trace the Call Stack (Mentally):**  Outline the steps involved from the JavaScript WebGL call to the browser's rendering engine and ultimately to the C++ code.
* **Summary of Functionality (Part 4 of 11):**
    * **Identify the Common Theme:**  Look for a unifying theme among the functions in the code block (e.g., texture manipulation, buffer management, object lifecycle).
    * **Synthesize a Concise Summary:**  Write a brief paragraph summarizing the main purpose of this code section within the broader context of the `webgl_rendering_context_base.cc` file.

**5. Refinement and Organization:**

* **Structure the Output:** Organize the information clearly using headings, bullet points, and code blocks to make it easy to read and understand.
* **Use Precise Language:**  Use accurate WebGL terminology.
* **Review and Verify:**  Double-check the information for correctness and completeness. Ensure that the examples and explanations are clear and accurate.

By following this methodical approach, combining code analysis with knowledge of WebGL concepts and potential developer errors, it's possible to generate a comprehensive and informative response to the prompt. The iterative nature of code analysis is key – you might revisit earlier assumptions or interpretations as you delve deeper into the code.
好的，让我们分析一下 `blink/renderer/modules/webgl/webgl_rendering_context_base.cc` 文件的这个代码片段（第 4 部分，共 11 部分）。

**功能归纳:**

这部分代码主要负责实现 WebGL API 中关于 **纹理操作 (Texture Operations)** 和 **资源对象管理 (Resource Object Management)** 的功能。具体来说，它包含了：

* **纹理拷贝:** 实现了将帧缓冲区内容拷贝到 2D 纹理的功能 (`copyTexImage2D`, `copyTexSubImage2D`)，并进行了格式验证。
* **资源对象创建:**  提供了创建各种 WebGL 资源对象的方法，如缓冲区 (`createBuffer`)，帧缓冲区 (`createFramebuffer`)，纹理 (`createTexture`)，程序 (`createProgram`)，渲染缓冲区 (`createRenderbuffer`) 和着色器 (`createShader`)。
* **资源对象删除:** 实现了删除各种 WebGL 资源对象的方法 (`deleteBuffer`, `deleteFramebuffer`, `deleteProgram`, `deleteRenderbuffer`, `deleteShader`, `deleteTexture`)，并处理了删除操作对上下文绑定状态的影响。
* **状态设置:**  包含了设置 WebGL 状态的函数，如剔除面 (`cullFace`)，深度函数 (`depthFunc`)，深度掩码 (`depthMask`)，深度范围 (`depthRange`)，分离着色器 (`detachShader`)，禁用/启用功能 (`disable`, `enable`)，禁用/启用顶点属性数组 (`disableVertexAttribArray`, `enableVertexAttribArray`)。
* **绘制:** 提供了执行绘制操作的函数 (`drawArrays`, `drawElements`, `DrawArraysInstancedANGLE`, `DrawElementsInstancedANGLE`)，并在内部进行了验证和性能监控。
* **帧缓冲区操作:**  提供了将渲染缓冲区和纹理附加到帧缓冲区的函数 (`framebufferRenderbuffer`, `framebufferTexture2D`)。
* **Mipmap 生成:**  实现了生成纹理 Mipmap 的功能 (`generateMipmap`)。
* **程序和着色器相关:**  提供了获取程序中激活的属性 (`getActiveAttrib`) 和 Uniform 变量 (`getActiveUniform`) 信息，以及获取附加到程序的着色器列表 (`getAttachedShaders`) 和属性位置 (`getAttribLocation`) 的功能。
* **缓冲区参数获取:** 提供了获取缓冲区参数的功能 (`getBufferParameter`)。
* **上下文属性获取:** 提供了获取 WebGL 上下文属性的功能 (`getContextAttributes`)。
* **错误处理:**  实现了获取 WebGL 错误状态的功能 (`getError`)，并管理合成错误和丢失上下文错误。
* **扩展管理:**  提供了管理和启用 WebGL 扩展的功能 (`getExtension`)。
* **帧缓冲区附件参数获取:** 提供了获取帧缓冲区附件参数的功能 (`getFramebufferAttachmentParameter`)。
* **验证函数:**  包含了一系列用于验证 WebGL 操作参数和状态的函数，例如 `ValidateCopyTexFormat`, `ValidateTexture2DBinding`, `ValidateShaderType`, `ValidateCapability`, `ValidateRenderingState`, `ValidateWebGLObject`, `ValidateBufferTarget` 等。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这段 C++ 代码是 WebGL API 的底层实现，它直接响应 JavaScript 中调用的 WebGL 方法。

* **JavaScript:** WebGL API 是通过 JavaScript 暴露给 Web 开发者的。 例如：
    * JavaScript 调用 `gl.copyTexImage2D(...)` 会最终调用到 C++ 中的 `WebGLRenderingContextBase::copyTexImage2D(...)` 函数。
    * JavaScript 调用 `gl.createBuffer()` 会调用到 C++ 中的 `WebGLRenderingContextBase::createBuffer()` 函数。
    * JavaScript 调用 `gl.drawArrays(...)` 会调用到 C++ 中的 `WebGLRenderingContextBase::drawArrays(...)` 函数。
    * JavaScript 调用 `gl.getExtension('WEBGL_depth_texture')` 会调用到 C++ 中的 `WebGLRenderingContextBase::getExtension(...)` 函数。

* **HTML:** `<canvas>` 元素是 WebGL 内容的渲染目标。 JavaScript 通过获取 `<canvas>` 元素的上下文来获得 WebGLRenderingContext 对象，从而调用 WebGL API。  例如：

```html
<canvas id="myCanvas" width="500" height="300"></canvas>
<script>
  const canvas = document.getElementById('myCanvas');
  const gl = canvas.getContext('webgl');
  if (gl) {
    // 使用 gl 对象调用 WebGL API，例如 gl.createBuffer(), gl.drawArrays() 等
  }
</script>
```

* **CSS:** CSS 可以用来设置 `<canvas>` 元素的大小和样式，但它不直接影响 WebGL 的内部渲染逻辑。WebGL 的渲染是由 JavaScript 代码和 GPU 驱动的。

**逻辑推理 (假设输入与输出):**

**示例 1: `copyTexImage2D`**

* **假设输入:**
    * `target`: `GL_TEXTURE_2D` (要拷贝到的纹理目标)
    * `level`: `0` (Mipmap 层级)
    * `internalformat`: `GL_RGBA` (纹理内部格式)
    * `x`, `y`: `0`, `0` (帧缓冲区拷贝起始坐标)
    * `width`, `height`: `256`, `256` (拷贝区域的宽度和高度)
    * `border`: `0` (必须为 0)

* **输出:**
    * 如果验证通过，会将当前绑定帧缓冲区中指定区域的像素数据拷贝到绑定的 2D 纹理对象上。
    * 如果验证失败（例如 `internalformat` 不支持拷贝，或未绑定 2D 纹理），则会生成 `GL_INVALID_ENUM` 或其他相应的 GL 错误，并且不会执行拷贝操作。

**示例 2: `createBuffer`**

* **假设输入:** 无，直接调用。

* **输出:**
    * 如果上下文未丢失，会创建一个新的 `WebGLBuffer` 对象，并返回指向该对象的指针。
    * 如果上下文已丢失，则返回 `nullptr`。

**示例 3: `deleteBuffer`**

* **假设输入:** 一个指向已创建的 `WebGLBuffer` 对象的指针 `buffer`。

* **输出:**
    * 如果上下文未丢失且 `buffer` 有效，会将该缓冲区标记为待删除，并在适当的时候释放其占用的 GPU 资源。如果该缓冲区当前被绑定，则会解除绑定。
    * 如果上下文已丢失或 `buffer` 为空，则不执行任何操作。

**用户或编程常见的使用错误举例说明:**

1. **在上下文丢失后调用 WebGL 函数:**
   * **错误:**  JavaScript 代码在 `webglcontextlost` 事件触发后，没有正确处理上下文丢失的情况，仍然调用 `gl.drawArrays()` 或其他 WebGL 函数。
   * **C++ 表现:**  在这些 C++ 函数的开头通常会有 `if (isContextLost()) return;` 的检查，如果上下文丢失，这些函数会直接返回，避免进一步的错误。
   * **调试线索:**  检查浏览器控制台是否有 "WebGL: CONTEXT_LOST_WEBGL" 错误信息。

2. **使用已删除的 WebGL 对象:**
   * **错误:** JavaScript 代码在调用 `gl.deleteBuffer(buffer)` 后，仍然尝试使用 `buffer` 对象，例如调用 `gl.bindBuffer(gl.ARRAY_BUFFER, buffer)`.
   * **C++ 表现:**  `ValidateWebGLObject` 函数会检查对象是否被标记为删除，如果已被删除，会生成 `GL_INVALID_OPERATION` 错误。
   * **调试线索:**  浏览器控制台可能会显示 "WebGL: INVALID_OPERATION: attempt to use a deleted object" 错误。

3. **向 `copyTexImage2D` 传递不支持的 `internalformat`:**
   * **错误:**  JavaScript 代码调用 `gl.copyTexImage2D(gl.TEXTURE_2D, 0, gl.RGB565, ...)`，而 `gl.RGB565` 可能不被支持用于纹理拷贝操作。
   * **C++ 表现:** `ValidateCopyTexFormat` 函数会检查 `internalformat` 是否在支持的格式列表中，如果不在列表中，会调用 `SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid internalformat");`。
   * **调试线索:** 浏览器控制台会显示 "WebGL: INVALID_ENUM: copyTexImage2D: invalid internalformat"。

4. **在程序未链接前获取属性位置:**
   * **错误:** JavaScript 代码在调用 `gl.linkProgram(program)` 之前，就尝试调用 `gl.getAttribLocation(program, 'a_position')`。
   * **C++ 表现:** `getAttribLocation` 函数会检查程序的链接状态，如果未链接，会生成 `GL_INVALID_OPERATION` 错误。
   * **调试线索:** 浏览器控制台会显示 "WebGL: INVALID_OPERATION: getAttribLocation: program not linked"。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载包含 WebGL 内容的网页:** 用户在浏览器中输入 URL 或点击链接，加载一个包含 `<canvas>` 元素并使用 WebGL API 进行渲染的网页。
2. **JavaScript 代码执行:** 网页加载完成后，JavaScript 代码开始执行。
3. **获取 WebGL 上下文:** JavaScript 代码通过 `canvas.getContext('webgl')` 或 `canvas.getContext('webgl2')` 获取 WebGLRenderingContext 对象。
4. **调用 WebGL API:** JavaScript 代码使用 `gl` 对象调用各种 WebGL API 方法，例如 `gl.createBuffer()`, `gl.bindBuffer()`, `gl.bufferData()`, `gl.createTexture()`, `gl.texImage2D()`, `gl.drawArrays()` 等。
5. **Blink 引擎处理 API 调用:**  这些 JavaScript API 调用会被传递到 Blink 引擎的 WebGL 实现层。
6. **进入 `webgl_rendering_context_base.cc`:**  Blink 引擎会将 JavaScript 的 WebGL API 调用映射到 `webgl_rendering_context_base.cc` 文件中相应的 C++ 函数。例如，`gl.drawArrays()` 会调用到 `WebGLRenderingContextBase::drawArrays()`。
7. **调用底层 OpenGL/OpenGL ES:**  `webgl_rendering_context_base.cc` 中的函数会进一步调用 Chromium 中用于与 GPU 通信的底层 OpenGL 或 OpenGL ES 接口（通过 `ContextGL()` 访问）。
8. **GPU 执行渲染:** GPU 接收到指令后，执行实际的渲染操作。

**调试线索:**

* **浏览器开发者工具 (Console):**  查看浏览器控制台是否有 WebGL 错误信息。Chromium 的 WebGL 实现会在检测到错误时输出详细的错误信息，包括错误类型和发生错误的函数。
* **断点调试:**  可以在 `webgl_rendering_context_base.cc` 中设置断点，跟踪 JavaScript WebGL API 调用是如何一步步执行到 C++ 代码的，以及查看函数参数和状态。
* **WebGL Inspector 等工具:** 使用 WebGL Inspector 等工具可以捕获 WebGL 的 API 调用序列，查看 WebGL 的状态和资源，帮助理解 WebGL 代码的执行流程。
* **Chromium 源码阅读:**  阅读 Chromium 源码可以更深入地理解 WebGL 的实现细节。

**总结这部分的功能:**

这段代码是 `WebGLRenderingContextBase` 类的核心组成部分，它实现了 WebGL API 中关于纹理操作和资源对象管理的关键功能。 它负责创建、删除和操作 WebGL 的各种资源对象，并维护和验证 WebGL 的状态，是 WebGL 功能实现的基础。 通过与底层 OpenGL/OpenGL ES 的交互，它最终驱动 GPU 完成 WebGL 内容的渲染。 这部分代码对保证 WebGL 功能的正确性和稳定性至关重要。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共11部分，请归纳一下它的功能

"""
tName)) {
    ADD_VALUES_TO_SET(supported_internal_formats_copy_tex_image_,
                      kSupportedInternalFormatsCopyTexImageFloatES3);
    is_ext_color_buffer_float_formats_added_ = true;
  }
  if (!is_ext_color_buffer_half_float_formats_added_ &&
      ExtensionEnabled(kEXTColorBufferHalfFloatName)) {
    ADD_VALUES_TO_SET(supported_internal_formats_copy_tex_image_,
                      kSupportedInternalFormatsCopyTexImageHalfFloatES3);
    is_ext_color_buffer_half_float_formats_added_ = true;
  }

  if (!base::Contains(supported_internal_formats_copy_tex_image_,
                      internalformat)) {
    SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid internalformat");
    return false;
  }

  return true;
}

void WebGLRenderingContextBase::copyTexImage2D(GLenum target,
                                               GLint level,
                                               GLenum internalformat,
                                               GLint x,
                                               GLint y,
                                               GLsizei width,
                                               GLsizei height,
                                               GLint border) {
  if (isContextLost())
    return;
  if (!ValidateTexture2DBinding("copyTexImage2D", target, true))
    return;
  if (!ValidateCopyTexFormat("copyTexImage2D", internalformat))
    return;
  if (!ValidateSettableTexFormat("copyTexImage2D", internalformat))
    return;
  WebGLFramebuffer* read_framebuffer_binding = nullptr;
  if (!ValidateReadBufferAndGetInfo("copyTexImage2D", read_framebuffer_binding))
    return;
  ClearIfComposited(kClearCallerOther);
  ScopedDrawingBufferBinder binder(GetDrawingBuffer(),
                                   read_framebuffer_binding);
  if (!binder.Succeeded()) {
    return;
  }
  ContextGL()->CopyTexImage2D(target, level, internalformat, x, y, width,
                              height, border);
}

void WebGLRenderingContextBase::copyTexSubImage2D(GLenum target,
                                                  GLint level,
                                                  GLint xoffset,
                                                  GLint yoffset,
                                                  GLint x,
                                                  GLint y,
                                                  GLsizei width,
                                                  GLsizei height) {
  if (isContextLost())
    return;
  if (!ValidateTexture2DBinding("copyTexSubImage2D", target))
    return;
  WebGLFramebuffer* read_framebuffer_binding = nullptr;
  if (!ValidateReadBufferAndGetInfo("copyTexSubImage2D",
                                    read_framebuffer_binding))
    return;
  ClearIfComposited(kClearCallerOther);
  ScopedDrawingBufferBinder binder(GetDrawingBuffer(),
                                   read_framebuffer_binding);
  if (!binder.Succeeded()) {
    return;
  }
  ContextGL()->CopyTexSubImage2D(target, level, xoffset, yoffset, x, y, width,
                                 height);
}

WebGLBuffer* WebGLRenderingContextBase::createBuffer() {
  if (isContextLost())
    return nullptr;
  return MakeGarbageCollected<WebGLBuffer>(this);
}

WebGLFramebuffer* WebGLRenderingContextBase::createFramebuffer() {
  if (isContextLost())
    return nullptr;
  return MakeGarbageCollected<WebGLFramebuffer>(this);
}

WebGLTexture* WebGLRenderingContextBase::createTexture() {
  if (isContextLost())
    return nullptr;
  return MakeGarbageCollected<WebGLTexture>(this);
}

WebGLProgram* WebGLRenderingContextBase::createProgram() {
  if (isContextLost())
    return nullptr;
  return MakeGarbageCollected<WebGLProgram>(this);
}

WebGLRenderbuffer* WebGLRenderingContextBase::createRenderbuffer() {
  if (isContextLost())
    return nullptr;
  return MakeGarbageCollected<WebGLRenderbuffer>(this);
}

void WebGLRenderingContextBase::SetBoundVertexArrayObject(
    WebGLVertexArrayObjectBase* array_object) {
  if (array_object)
    bound_vertex_array_object_ = array_object;
  else
    bound_vertex_array_object_ = default_vertex_array_object_;
}

WebGLShader* WebGLRenderingContextBase::createShader(GLenum type) {
  if (isContextLost())
    return nullptr;
  if (!ValidateShaderType("createShader", type)) {
    return nullptr;
  }

  return MakeGarbageCollected<WebGLShader>(this, type);
}

void WebGLRenderingContextBase::cullFace(GLenum mode) {
  if (isContextLost())
    return;
  ContextGL()->CullFace(mode);
}

bool WebGLRenderingContextBase::DeleteObject(WebGLObject* object) {
  if (isContextLost() || !object)
    return false;
  if (!object->Validate(ContextGroup(), this)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "delete",
                      "object does not belong to this context");
    return false;
  }
  if (object->MarkedForDeletion()) {
    // This is specified to be a no-op, including skipping all unbinding from
    // the context's attachment points that would otherwise happen.
    return false;
  }
  if (object->HasObject()) {
    // We need to pass in context here because we want
    // things in this context unbound.
    object->DeleteObject(ContextGL());
  }
  return true;
}

void WebGLRenderingContextBase::deleteBuffer(WebGLBuffer* buffer) {
  if (!DeleteObject(buffer))
    return;
  RemoveBoundBuffer(buffer);
}

void WebGLRenderingContextBase::deleteFramebuffer(
    WebGLFramebuffer* framebuffer) {
  // Don't allow the application to delete an opaque framebuffer.
  if (framebuffer && framebuffer->Opaque()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "deleteFramebuffer",
                      "cannot delete an opaque framebuffer");
    return;
  }
  if (!DeleteObject(framebuffer))
    return;
  if (framebuffer == framebuffer_binding_) {
    framebuffer_binding_ = nullptr;
    // Have to call drawingBuffer()->bind() here to bind back to internal fbo.
    GetDrawingBuffer()->Bind(GL_FRAMEBUFFER);
  }
}

void WebGLRenderingContextBase::deleteProgram(WebGLProgram* program) {
  DeleteObject(program);
  // We don't reset m_currentProgram to 0 here because the deletion of the
  // current program is delayed.
}

void WebGLRenderingContextBase::deleteRenderbuffer(
    WebGLRenderbuffer* renderbuffer) {
  if (!DeleteObject(renderbuffer))
    return;
  if (renderbuffer == renderbuffer_binding_) {
    renderbuffer_binding_ = nullptr;
  }
  if (framebuffer_binding_)
    framebuffer_binding_->RemoveAttachmentFromBoundFramebuffer(GL_FRAMEBUFFER,
                                                               renderbuffer);
  if (GetFramebufferBinding(GL_READ_FRAMEBUFFER))
    GetFramebufferBinding(GL_READ_FRAMEBUFFER)
        ->RemoveAttachmentFromBoundFramebuffer(GL_READ_FRAMEBUFFER,
                                               renderbuffer);
}

void WebGLRenderingContextBase::deleteShader(WebGLShader* shader) {
  DeleteObject(shader);
}

void WebGLRenderingContextBase::deleteTexture(WebGLTexture* texture) {
  if (texture && texture->IsOpaqueTexture()) {
    // Calling deleteTexture() on opaque textures is not allowed, see
    // https://www.w3.org/TR/webxrlayers-1/#opaque-texture
    SynthesizeGLError(GL_INVALID_OPERATION, "deleteTexture",
                      "opaque textures cannot be deleted");
    return;
  }

  if (!DeleteObject(texture))
    return;

  int max_bound_texture_index = -1;
  for (wtf_size_t i = 0; i < one_plus_max_non_default_texture_unit_; ++i) {
    if (texture == texture_units_[i].texture2d_binding_) {
      texture_units_[i].texture2d_binding_ = nullptr;
      max_bound_texture_index = i;
    }
    if (texture == texture_units_[i].texture_cube_map_binding_) {
      texture_units_[i].texture_cube_map_binding_ = nullptr;
      max_bound_texture_index = i;
    }
    if (IsWebGL2()) {
      if (texture == texture_units_[i].texture3d_binding_) {
        texture_units_[i].texture3d_binding_ = nullptr;
        max_bound_texture_index = i;
      }
      if (texture == texture_units_[i].texture2d_array_binding_) {
        texture_units_[i].texture2d_array_binding_ = nullptr;
        max_bound_texture_index = i;
      }
    }
  }
  if (framebuffer_binding_)
    framebuffer_binding_->RemoveAttachmentFromBoundFramebuffer(GL_FRAMEBUFFER,
                                                               texture);
  if (GetFramebufferBinding(GL_READ_FRAMEBUFFER))
    GetFramebufferBinding(GL_READ_FRAMEBUFFER)
        ->RemoveAttachmentFromBoundFramebuffer(GL_READ_FRAMEBUFFER, texture);

  // If the deleted was bound to the the current maximum index, trace backwards
  // to find the new max texture index.
  if (one_plus_max_non_default_texture_unit_ ==
      static_cast<wtf_size_t>(max_bound_texture_index + 1)) {
    FindNewMaxNonDefaultTextureUnit();
  }
}

void WebGLRenderingContextBase::depthFunc(GLenum func) {
  if (isContextLost())
    return;
  ContextGL()->DepthFunc(func);
}

void WebGLRenderingContextBase::depthMask(GLboolean flag) {
  if (isContextLost())
    return;
  depth_mask_ = flag;
  ContextGL()->DepthMask(flag);
}

void WebGLRenderingContextBase::depthRange(GLfloat z_near, GLfloat z_far) {
  if (isContextLost())
    return;
  // Check required by WebGL spec section 6.12
  if (z_near > z_far) {
    SynthesizeGLError(GL_INVALID_OPERATION, "depthRange", "zNear > zFar");
    return;
  }
  ContextGL()->DepthRangef(z_near, z_far);
}

void WebGLRenderingContextBase::detachShader(WebGLProgram* program,
                                             WebGLShader* shader) {
  if (!ValidateWebGLProgramOrShader("detachShader", program) ||
      !ValidateWebGLProgramOrShader("detachShader", shader))
    return;
  if (!program->DetachShader(shader)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "detachShader",
                      "shader not attached");
    return;
  }
  ContextGL()->DetachShader(ObjectOrZero(program), ObjectOrZero(shader));
  shader->OnDetached(ContextGL());
}

void WebGLRenderingContextBase::disable(GLenum cap) {
  if (isContextLost() || !ValidateCapability("disable", cap))
    return;
  if (cap == GL_STENCIL_TEST) {
    stencil_enabled_ = false;
    ApplyDepthAndStencilTest();
    return;
  }
  if (cap == GL_DEPTH_TEST) {
    depth_enabled_ = false;
    ApplyDepthAndStencilTest();
    return;
  }
  if (cap == GL_SCISSOR_TEST)
    scissor_enabled_ = false;
  if (cap == GL_RASTERIZER_DISCARD)
    rasterizer_discard_enabled_ = false;
  ContextGL()->Disable(cap);
}

void WebGLRenderingContextBase::disableVertexAttribArray(GLuint index) {
  if (isContextLost())
    return;
  if (index >= max_vertex_attribs_) {
    SynthesizeGLError(GL_INVALID_VALUE, "disableVertexAttribArray",
                      "index out of range");
    return;
  }

  bound_vertex_array_object_->SetAttribEnabled(index, false);
  ContextGL()->DisableVertexAttribArray(index);
}

bool WebGLRenderingContextBase::ValidateRenderingState(
    const char* function_name) {
  // Command buffer will not error if no program is bound.
  if (!current_program_) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "no valid shader program in use");
    return false;
  }

  return true;
}

bool WebGLRenderingContextBase::ValidateNullableWebGLObject(
    const char* function_name,
    WebGLObject* object) {
  if (isContextLost())
    return false;
  if (!object) {
    // This differs in behavior to ValidateWebGLObject; null objects are allowed
    // in these entry points.
    return true;
  }
  return ValidateWebGLObject(function_name, object);
}

bool WebGLRenderingContextBase::ValidateWebGLObject(const char* function_name,
                                                    WebGLObject* object) {
  if (isContextLost())
    return false;
  DCHECK(object);
  if (object->MarkedForDeletion()) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "attempt to use a deleted object");
    return false;
  }
  if (!object->Validate(ContextGroup(), this)) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "object does not belong to this context");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateWebGLProgramOrShader(
    const char* function_name,
    WebGLObject* object) {
  if (isContextLost())
    return false;
  DCHECK(object);
  // OpenGL ES 3.0.5 p. 45:
  // "Commands that accept shader or program object names will generate the
  // error INVALID_VALUE if the provided name is not the name of either a shader
  // or program object and INVALID_OPERATION if the provided name identifies an
  // object that is not the expected type."
  //
  // Programs and shaders also have slightly different lifetime rules than other
  // objects in the API; they continue to be usable after being marked for
  // deletion.
  if (!object->HasObject()) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      "attempt to use a deleted object");
    return false;
  }
  if (!object->Validate(ContextGroup(), this)) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "object does not belong to this context");
    return false;
  }
  return true;
}

void WebGLRenderingContextBase::drawArrays(GLenum mode,
                                           GLint first,
                                           GLsizei count) {
  if (!ValidateDrawArrays("drawArrays"))
    return;

  DrawWrapper("drawArrays", CanvasPerformanceMonitor::DrawType::kDrawArrays,
              [&]() { ContextGL()->DrawArrays(mode, first, count); });
}

void WebGLRenderingContextBase::drawElements(GLenum mode,
                                             GLsizei count,
                                             GLenum type,
                                             int64_t offset) {
  if (!ValidateDrawElements("drawElements", type, offset))
    return;

  DrawWrapper("drawElements", CanvasPerformanceMonitor::DrawType::kDrawElements,
              [&]() {
                ContextGL()->DrawElements(
                    mode, count, type,
                    reinterpret_cast<void*>(static_cast<intptr_t>(offset)));
              });
}

void WebGLRenderingContextBase::DrawArraysInstancedANGLE(GLenum mode,
                                                         GLint first,
                                                         GLsizei count,
                                                         GLsizei primcount) {
  if (!ValidateDrawArrays("drawArraysInstancedANGLE"))
    return;

  DrawWrapper("drawArraysInstancedANGLE",
              CanvasPerformanceMonitor::DrawType::kDrawArrays, [&]() {
                ContextGL()->DrawArraysInstancedANGLE(mode, first, count,
                                                      primcount);
              });
}

void WebGLRenderingContextBase::DrawElementsInstancedANGLE(GLenum mode,
                                                           GLsizei count,
                                                           GLenum type,
                                                           int64_t offset,
                                                           GLsizei primcount) {
  if (!ValidateDrawElements("drawElementsInstancedANGLE", type, offset))
    return;

  DrawWrapper("drawElementsInstancedANGLE",
              CanvasPerformanceMonitor::DrawType::kDrawElements, [&]() {
                ContextGL()->DrawElementsInstancedANGLE(
                    mode, count, type,
                    reinterpret_cast<void*>(static_cast<intptr_t>(offset)),
                    primcount);
              });
}

void WebGLRenderingContextBase::enable(GLenum cap) {
  if (isContextLost() || !ValidateCapability("enable", cap))
    return;
  if (cap == GL_STENCIL_TEST) {
    stencil_enabled_ = true;
    ApplyDepthAndStencilTest();
    return;
  }
  if (cap == GL_DEPTH_TEST) {
    depth_enabled_ = true;
    ApplyDepthAndStencilTest();
    return;
  }
  if (cap == GL_SCISSOR_TEST)
    scissor_enabled_ = true;
  if (cap == GL_RASTERIZER_DISCARD)
    rasterizer_discard_enabled_ = true;
  ContextGL()->Enable(cap);
}

void WebGLRenderingContextBase::enableVertexAttribArray(GLuint index) {
  if (isContextLost())
    return;
  if (index >= max_vertex_attribs_) {
    SynthesizeGLError(GL_INVALID_VALUE, "enableVertexAttribArray",
                      "index out of range");
    return;
  }

  bound_vertex_array_object_->SetAttribEnabled(index, true);
  ContextGL()->EnableVertexAttribArray(index);
}

void WebGLRenderingContextBase::finish() {
  if (isContextLost())
    return;
  ContextGL()->Flush();  // Intentionally a flush, not a finish.
}

void WebGLRenderingContextBase::flush() {
  if (isContextLost())
    return;
  ContextGL()->Flush();
}

void WebGLRenderingContextBase::framebufferRenderbuffer(
    GLenum target,
    GLenum attachment,
    GLenum renderbuffertarget,
    WebGLRenderbuffer* buffer) {
  if (isContextLost() || !ValidateFramebufferFuncParameters(
                             "framebufferRenderbuffer", target, attachment))
    return;
  if (renderbuffertarget != GL_RENDERBUFFER) {
    SynthesizeGLError(GL_INVALID_ENUM, "framebufferRenderbuffer",
                      "invalid target");
    return;
  }
  if (!ValidateNullableWebGLObject("framebufferRenderbuffer", buffer))
    return;
  if (buffer && (!buffer->HasEverBeenBound())) {
    SynthesizeGLError(GL_INVALID_OPERATION, "framebufferRenderbuffer",
                      "renderbuffer has never been bound");
    return;
  }
  // Don't allow the default framebuffer to be mutated; all current
  // implementations use an FBO internally in place of the default
  // FBO.
  WebGLFramebuffer* framebuffer_binding = GetFramebufferBinding(target);
  if (!framebuffer_binding || !framebuffer_binding->Object()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "framebufferRenderbuffer",
                      "no framebuffer bound");
    return;
  }
  // Don't allow modifications to opaque framebuffer attachements.
  if (framebuffer_binding && framebuffer_binding->Opaque()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "framebufferRenderbuffer",
                      "opaque framebuffer bound");
    return;
  }
  framebuffer_binding->SetAttachmentForBoundFramebuffer(target, attachment,
                                                        buffer);
  ApplyDepthAndStencilTest();
}

void WebGLRenderingContextBase::framebufferTexture2D(GLenum target,
                                                     GLenum attachment,
                                                     GLenum textarget,
                                                     WebGLTexture* texture,
                                                     GLint level) {
  if (isContextLost() || !ValidateFramebufferFuncParameters(
                             "framebufferTexture2D", target, attachment))
    return;
  if (!ValidateNullableWebGLObject("framebufferTexture2D", texture))
    return;
  // TODO(crbug.com/919711): validate texture's target against textarget.

  // Don't allow the default framebuffer to be mutated; all current
  // implementations use an FBO internally in place of the default
  // FBO.
  WebGLFramebuffer* framebuffer_binding = GetFramebufferBinding(target);
  if (!framebuffer_binding || !framebuffer_binding->Object()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "framebufferTexture2D",
                      "no framebuffer bound");
    return;
  }
  // Don't allow modifications to opaque framebuffer attachements.
  if (framebuffer_binding && framebuffer_binding->Opaque()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "framebufferTexture2D",
                      "opaque framebuffer bound");
    return;
  }
  framebuffer_binding->SetAttachmentForBoundFramebuffer(
      target, attachment, textarget, texture, level, 0, 0);
  ApplyDepthAndStencilTest();
}

void WebGLRenderingContextBase::frontFace(GLenum mode) {
  if (isContextLost())
    return;
  ContextGL()->FrontFace(mode);
}

void WebGLRenderingContextBase::generateMipmap(GLenum target) {
  if (isContextLost())
    return;
  if (!ValidateTextureBinding("generateMipmap", target))
    return;
  ContextGL()->GenerateMipmap(target);
}

WebGLActiveInfo* WebGLRenderingContextBase::getActiveAttrib(
    WebGLProgram* program,
    GLuint index) {
  if (!ValidateWebGLProgramOrShader("getActiveAttrib", program))
    return nullptr;
  GLuint program_id = ObjectNonZero(program);
  GLint max_name_length = -1;
  ContextGL()->GetProgramiv(program_id, GL_ACTIVE_ATTRIBUTE_MAX_LENGTH,
                            &max_name_length);
  if (max_name_length < 0)
    return nullptr;
  if (max_name_length == 0) {
    SynthesizeGLError(GL_INVALID_VALUE, "getActiveAttrib",
                      "no active attributes exist");
    return nullptr;
  }
  GLsizei length = 0;
  GLint size = -1;
  GLenum type = 0;
  base::span<LChar> name_buffer;
  scoped_refptr<StringImpl> name_impl =
      StringImpl::CreateUninitialized(max_name_length, name_buffer);
  ContextGL()->GetActiveAttrib(program_id, index, max_name_length, &length,
                               &size, &type,
                               reinterpret_cast<GLchar*>(name_buffer.data()));
  if (size < 0)
    return nullptr;
  return MakeGarbageCollected<WebGLActiveInfo>(name_impl->Substring(0, length),
                                               type, size);
}

WebGLActiveInfo* WebGLRenderingContextBase::getActiveUniform(
    WebGLProgram* program,
    GLuint index) {
  if (!ValidateWebGLProgramOrShader("getActiveUniform", program))
    return nullptr;
  GLuint program_id = ObjectNonZero(program);
  GLint max_name_length = -1;
  ContextGL()->GetProgramiv(program_id, GL_ACTIVE_UNIFORM_MAX_LENGTH,
                            &max_name_length);
  if (max_name_length < 0)
    return nullptr;
  if (max_name_length == 0) {
    SynthesizeGLError(GL_INVALID_VALUE, "getActiveUniform",
                      "no active uniforms exist");
    return nullptr;
  }
  GLsizei length = 0;
  GLint size = -1;
  GLenum type = 0;
  base::span<LChar> name_buffer;
  scoped_refptr<StringImpl> name_impl =
      StringImpl::CreateUninitialized(max_name_length, name_buffer);
  ContextGL()->GetActiveUniform(program_id, index, max_name_length, &length,
                                &size, &type,
                                reinterpret_cast<GLchar*>(name_buffer.data()));
  if (size < 0)
    return nullptr;
  return MakeGarbageCollected<WebGLActiveInfo>(name_impl->Substring(0, length),
                                               type, size);
}

std::optional<HeapVector<Member<WebGLShader>>>
WebGLRenderingContextBase::getAttachedShaders(WebGLProgram* program) {
  if (!ValidateWebGLProgramOrShader("getAttachedShaders", program))
    return std::nullopt;

  HeapVector<Member<WebGLShader>> shader_objects;
  for (GLenum shaderType : {GL_VERTEX_SHADER, GL_FRAGMENT_SHADER}) {
    WebGLShader* shader = program->GetAttachedShader(shaderType);
    if (shader)
      shader_objects.push_back(shader);
  }
  return shader_objects;
}

GLint WebGLRenderingContextBase::getAttribLocation(WebGLProgram* program,
                                                   const String& name) {
  if (!ValidateWebGLProgramOrShader("getAttribLocation", program))
    return -1;
  if (!ValidateLocationLength("getAttribLocation", name))
    return -1;
  if (!ValidateString("getAttribLocation", name))
    return -1;
  if (IsPrefixReserved(name))
    return -1;
  if (!program->LinkStatus(this)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "getAttribLocation",
                      "program not linked");
    return 0;
  }
  return ContextGL()->GetAttribLocation(ObjectOrZero(program),
                                        name.Utf8().c_str());
}

bool WebGLRenderingContextBase::ValidateBufferTarget(const char* function_name,
                                                     GLenum target) {
  switch (target) {
    case GL_ARRAY_BUFFER:
    case GL_ELEMENT_ARRAY_BUFFER:
      return true;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid target");
      return false;
  }
}

ScriptValue WebGLRenderingContextBase::getBufferParameter(
    ScriptState* script_state,
    GLenum target,
    GLenum pname) {
  if (isContextLost() || !ValidateBufferTarget("getBufferParameter", target))
    return ScriptValue::CreateNull(script_state->GetIsolate());

  switch (pname) {
    case GL_BUFFER_USAGE: {
      GLint value = 0;
      ContextGL()->GetBufferParameteriv(target, pname, &value);
      return WebGLAny(script_state, static_cast<unsigned>(value));
    }
    case GL_BUFFER_SIZE: {
      GLint value = 0;
      ContextGL()->GetBufferParameteriv(target, pname, &value);
      if (!IsWebGL2())
        return WebGLAny(script_state, value);
      return WebGLAny(script_state, static_cast<GLint64>(value));
    }
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getBufferParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

WebGLContextAttributes* WebGLRenderingContextBase::getContextAttributes()
    const {
  if (isContextLost())
    return nullptr;

  WebGLContextAttributes* result =
      ToWebGLContextAttributes(CreationAttributes());

  // Some requested attributes may not be honored, so we need to query the
  // underlying context/drawing buffer and adjust accordingly.
  if (CreationAttributes().depth && !GetDrawingBuffer()->HasDepthBuffer())
    result->setDepth(false);
  if (CreationAttributes().stencil && !GetDrawingBuffer()->HasStencilBuffer())
    result->setStencil(false);
  result->setAntialias(GetDrawingBuffer()->Multisample());
  result->setXrCompatible(xr_compatible_);
  result->setDesynchronized(Host()->LowLatencyEnabled());
  return result;
}

GLenum WebGLRenderingContextBase::getError() {
  if (!lost_context_errors_.empty()) {
    GLenum error = lost_context_errors_.front();
    lost_context_errors_.EraseAt(0);
    return error;
  }

  if (isContextLost())
    return GL_NO_ERROR;

  if (!synthetic_errors_.empty()) {
    GLenum error = synthetic_errors_.front();
    synthetic_errors_.EraseAt(0);
    return error;
  }

  return ContextGL()->GetError();
}

bool WebGLRenderingContextBase::ExtensionTracker::MatchesName(
    const String& name) const {
  if (DeprecatedEqualIgnoringCase(ExtensionName(), name)) {
    return true;
  }
  return false;
}

bool WebGLRenderingContextBase::ExtensionSupportedAndAllowed(
    const ExtensionTracker* tracker) {
  if (tracker->Draft() &&
      !RuntimeEnabledFeatures::WebGLDraftExtensionsEnabled())
    return false;
  if (tracker->Developer() &&
      !RuntimeEnabledFeatures::WebGLDeveloperExtensionsEnabled())
    return false;
  if (!tracker->Supported(this))
    return false;
  if (disabled_extensions_.Contains(String(tracker->ExtensionName())))
    return false;
  return true;
}

WebGLExtension* WebGLRenderingContextBase::EnableExtensionIfSupported(
    const String& name) {
  WebGLExtension* extension = nullptr;

  if (!isContextLost()) {
    for (ExtensionTracker* tracker : extensions_) {
      if (tracker->MatchesName(name)) {
        if (ExtensionSupportedAndAllowed(tracker)) {
          extension = tracker->GetExtension(this);
          if (extension) {
            if (!extension_enabled_[extension->GetName()]) {
              extension_enabled_[extension->GetName()] = true;
            }
          }
        }
        break;
      }
    }
  }

  return extension;
}

bool WebGLRenderingContextBase::TimerQueryExtensionsEnabled() {
  return (drawing_buffer_ && drawing_buffer_->ContextProvider() &&
          drawing_buffer_->ContextProvider()
              ->GetGpuFeatureInfo()
              .IsWorkaroundEnabled(gpu::ENABLE_WEBGL_TIMER_QUERY_EXTENSIONS));
}

ScriptValue WebGLRenderingContextBase::getExtension(ScriptState* script_state,
                                                    const String& name) {
  if (name == WebGLDebugRendererInfo::ExtensionName()) {
    ExecutionContext* context = ExecutionContext::From(script_state);
    UseCounter::Count(context, WebFeature::kWebGLDebugRendererInfo);
  }

  WebGLExtension* extension = EnableExtensionIfSupported(name);
  return ScriptValue(
      script_state->GetIsolate(),
      ToV8Traits<IDLNullable<WebGLExtension>>::ToV8(script_state, extension));
}

ScriptValue WebGLRenderingContextBase::getFramebufferAttachmentParameter(
    ScriptState* script_state,
    GLenum target,
    GLenum attachment,
    GLenum pname) {
  const char kFunctionName[] = "getFramebufferAttachmentParameter";
  if (isContextLost() ||
      !ValidateFramebufferFuncParameters(kFunctionName, target, attachment)) {
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  if (!framebuffer_binding_ || !framebuffer_binding_->Object()) {
    SynthesizeGLError(GL_INVALID_OPERATION, kFunctionName,
                      "no framebuffer bound");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  if (framebuffer_binding_ && framebuffer_binding_->Opaque()) {
    SynthesizeGLError(GL_INVALID_OPERATION, kFunctionName,
                      "cannot query parameters of an opaque framebuffer");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  WebGLSharedObject* attachment_object =
      framebuffer_binding_->GetAttachmentObject(attachment);
  if (!attachment_object) {
    if (pname == GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE)
      return WebGLAny(script_state, GL_NONE);
    // OpenGL ES 2.0 specifies INVALID_ENUM in this case, while desktop GL
    // specifies INVALID_OPERATION.
    SynthesizeGLError(GL_INVALID_ENUM, kFunctionName, "invalid parameter name");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  DCHECK(attachment_object->IsTexture() || attachment_object->IsRenderbuffer());
  switch (pname) {
    case GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE:
      if (attachment_object->IsTexture()) {
        return WebGLAny(script_state, GL_TEXTURE);
      }
      return WebGLAny(script_state, GL_RENDERBUFFER);
    case GL_FRAMEBUFFER_ATTACHMENT_OBJECT_NAME:
      return WebGLAny(script_state, attachment_object);
    case GL_FRAMEBUFFER_ATTACHMENT_TEXTURE_LEVEL:
    case GL_FRAMEBUFFER_ATTACHMENT_TEXTURE_CUBE_MAP_FACE:
      if (attachment_object->IsTexture()) {
        GLint value = 0;
        ContextGL()->GetFramebufferAttachmentParameteriv(target, attachment,
                                                         pname, &value);
        return WebGLAny(script_state, value);
      }
      break;
    case GL_FRAMEBUFFER_ATTACHMENT_COLOR_ENCODING_EXT:
      if (ExtensionEnabled(kEXTsRGBName)) {
        GLint value = 0;
        ContextGL()->GetFramebufferAttachmentParameteriv(target, attachment,
                                                         pname, &value);
        return WebGLAny(script_state, static_cast<unsigned>(value));
      }
      SynthesizeGLError(GL_INVALID_ENUM, kFunctionName,
                        "invalid parameter name, EXT_sRGB not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE_EXT:
      if (ExtensionEnabled(kEXTColorBufferHalfFloatName) ||
          ExtensionEnabled(kWebGLColorBufferFloatName)) {
        if (attachment == GL_DEPTH_STENCIL_ATTACHMENT) {
          SynthesizeGLError(
              GL_INVALID_OPERATION, kFunctionName,
              "component type cannot be queried for DEPTH_STENCIL_ATTACHMENT");
          return ScriptValue::CreateNull(script_state->GetIsolate());
        }
        GLint value = 0;
        ContextGL()->GetFramebufferAttachmentParameteriv(target, attachment,
                                                         pname, &value);
        return WebGLAny(script_state, static_cast<unsigned>(value));
      }
      SynthesizeGLError(
          GL_INVALID_ENUM, kFunctionName,
          "invalid parameter name, EXT_color_buffer_half_float or "
          "WEBGL_color_buffer_float not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
  SynthesizeGLError(GL_INVALID_ENUM, kFunctionName, "invalid parameter name");
  return ScriptValue::CreateNull(script_state->GetIsolate());
}

namespace {

// WebGL parameters which can be used to identify users.
// These parameters should each be uniquely defined,
// see third_party/khronos/GLES2/gl2.h for their definitions.
static const GLenum kIdentifiableGLParams[] = {
    // getParameter()
    GL_ALIASED_LINE_WIDTH_RANGE,          // GetWebGLFloatArrayParameter
    GL_ALIASED_POINT_SIZE_RANGE,          // GetWebGLFloatArrayParameter
    GL_ALPHA_BITS,                        // GetIntParameter
    GL_BLUE_BITS,                         // GetIntParameter
    GL_DEPTH_BITS,                        // GetIntParame
"""


```