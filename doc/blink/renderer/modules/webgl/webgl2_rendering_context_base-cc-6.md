Response:
Let's break down the thought process for analyzing this code snippet.

**1. Initial Understanding & Context:**

* **File Path:** `blink/renderer/modules/webgl/webgl2_rendering_context_base.cc` immediately tells us this is part of the Chromium's Blink rendering engine, specifically related to WebGL 2. The `_base` suffix often indicates a base or abstract class.
* **"Part 7 of 7":** This strongly suggests this snippet contains the concluding functionalities of this class or related set of functions. We should expect it to wrap up some tasks or perhaps handle less core, more specific operations.
* **Keywords:** The code itself uses terms like `WebGL`, `Framebuffer`, `Texture`, `Buffer`, `TransformFeedback`, which are all core concepts in WebGL.

**2. High-Level Functionality Identification (Scanning the Code):**

I'd quickly scan the function names and their general structure to get a sense of the major functionalities present. I look for patterns and recurring themes:

* **`getFramebufferAttachmentParameter`:** This clearly deals with querying parameters of framebuffer attachments.
* **`Trace`:**  This is a standard Blink mechanism for debugging and object tracking. It's not about core WebGL functionality itself but about the internal workings of the engine.
* **`ValidateTexture3DBinding`:**  Focuses on validating textures specifically for 3D or array types.
* **`GetMaxTextureLevelForTarget`:**  Retrieves the maximum texture level supported for different texture targets.
* **`getTexParameter`:**  Similar to the framebuffer function, this gets parameters related to textures.
* **`ValidateBufferDataTarget`, `ValidateBufferDataUsage`:** These are about validating buffer objects and how they are used.
* **`ValidateGetBufferSubData`, `ValidateGetBufferSubDataBounds`:**  Functions for validating data transfers to and from buffers.
* **`RemoveBoundBuffer`:**  Manages the removal of bound buffer objects.
* **`RestoreCurrentFramebuffer`:**  Resets the framebuffer binding.
* **`useProgram`:**  Handles setting the active shader program.
* **`GetMaxTransformFeedbackSeparateAttribs`:**  Retrieves limits related to transform feedback.
* **`GetPackPixelStoreParams`, `GetUnpackPixelStoreParams`:**  Functions for retrieving pixel storage parameters used in texture operations.
* **`DrawingBufferClientRestore...` functions:** These appear related to restoring OpenGL state, likely after certain operations or context losses.

**3. Categorizing and Detailing Functionality:**

Now, I'd group these functionalities and analyze them in more detail:

* **Framebuffer Management:** `getFramebufferAttachmentParameter`, `RestoreCurrentFramebuffer`. This deals with how WebGL manages rendering targets.
* **Texture Management:** `ValidateTexture3DBinding`, `GetMaxTextureLevelForTarget`, `getTexParameter`. This focuses on how WebGL handles texture objects.
* **Buffer Management:** `ValidateBufferDataTarget`, `ValidateBufferDataUsage`, `ValidateGetBufferSubData`, `ValidateGetBufferSubDataBounds`, `RemoveBoundBuffer`. This is about how WebGL handles data storage in buffers.
* **Program/Shader Management:** `useProgram`. This is about selecting the shader to use for rendering.
* **Transform Feedback:** `GetMaxTransformFeedbackSeparateAttribs`. This specifically handles a more advanced WebGL feature.
* **Pixel Storage:** `GetPackPixelStoreParams`, `GetUnpackPixelStoreParams`. This manages how pixel data is organized in memory.
* **Context State Restoration:** `DrawingBufferClientRestore...`. This is important for maintaining a consistent state.
* **Internal Blink Functionality:** `Trace`.

**4. Connecting to Web Concepts (JavaScript, HTML, CSS):**

For each category, I'd think about how it relates to the web developer's experience:

* **Framebuffer:**  Developers use JavaScript WebGL APIs to create and bind framebuffers for offscreen rendering, often needed for effects or render-to-texture.
* **Textures:**  Crucial for displaying images, videos, or procedurally generated content. Developers load images, create textures, and sample them in shaders.
* **Buffers:**  Store vertex data, indices, and other data used by shaders. Developers create buffers and upload data to them.
* **Programs/Shaders:** The core of WebGL rendering. Developers write GLSL shader code and link it into programs.
* **Transform Feedback:**  A more advanced feature where the output of vertex shaders is captured back into buffers. Developers use it for particle systems, simulations, etc.
* **Pixel Storage:** Affects how image data is transferred to and from textures. Developers might need to adjust these parameters for specific image formats or optimizations.

**5. Examples and Scenarios:**

For each connection to web concepts, I'd come up with concrete examples:

* **Framebuffer:** A developer creates a framebuffer to render a scene to a texture, which is then used as a reflection map.
* **Textures:**  Loading a `.png` image using JavaScript and then using it as a texture on a 3D model.
* **Buffers:**  Creating a buffer to hold the vertex positions of a triangle.
* **Programs/Shaders:** A simple vertex shader that transforms vertex positions and a fragment shader that outputs a solid color.

**6. User/Programming Errors:**

I'd consider common mistakes developers might make:

* **Framebuffer:**  Forgetting to bind a color attachment to a framebuffer.
* **Textures:**  Using a texture before it's fully loaded. Mismatched texture parameters.
* **Buffers:**  Trying to read from a buffer with an offset that's out of bounds. Using a buffer that hasn't been created.
* **Programs/Shaders:**  Syntax errors in GLSL code. Trying to use an attribute that hasn't been enabled.

**7. User Journey/Debugging:**

I'd imagine how a developer might end up in this part of the code during debugging:

* They are getting an error related to framebuffer attachments. They might set breakpoints in `getFramebufferAttachmentParameter`.
* They are having issues with textures not rendering correctly. They might be investigating the texture parameter settings in `getTexParameter`.
* They have performance problems related to buffer uploads and are looking at the buffer validation functions.

**8. "Part 7 of 7" Synthesis:**

Given that this is the last part, I'd expect it to handle:

* **Cleanup/State Management:**  The `DrawingBufferClientRestore...` functions fit this idea.
* **Less Core Functionality:** Things like transform feedback and specific texture parameter queries.
* **Error Handling and Validation:**  Many of the validation functions are present.

By following this structured thought process, combining code analysis with understanding of WebGL concepts and developer workflows, I can arrive at a comprehensive and accurate description of the code's functionality and its place within the larger web ecosystem.
好的，让我们来详细分析一下 `blink/renderer/modules/webgl/webgl2_rendering_context_base.cc` 文件的这段代码片段。由于这是第 7 部分，也是最后一部分，我们将重点关注本段代码的功能，并结合之前部分的内容进行归纳。

**代码功能详解**

这段代码主要集中在以下几个方面的功能：

1. **获取 Framebuffer 附件参数 (`getFramebufferAttachmentParameter`)**:
   - 这个函数负责查询指定 Framebuffer 对象上特定附件的参数。
   - 它接受目标 Framebuffer 类型 (`target`)、附件点 (`attachment`) 和要查询的参数名 (`pname`) 作为输入。
   - 根据 `pname` 的不同，它会返回附件的不同属性，例如附件的类型 (纹理或 Renderbuffer)、绑定的对象名称、纹理的层级、颜色/深度/模板缓冲区的大小等等。
   - 代码中也处理了一些 WebGL 扩展的情况，例如 `OVR_multiview2`。
   - **错误处理：**  如果传入无效的参数名或在不支持的扩展下查询相关参数，会调用 `SynthesizeGLError` 生成 WebGL 错误。

2. **追踪对象 (`Trace`)**:
   - `Trace` 函数是 Blink 引擎中用于垃圾回收和调试的机制。
   - 它会追踪当前 `WebGL2RenderingContextBase` 对象所引用的其他 WebGL 相关对象，例如 Framebuffer 绑定、Transform Feedback 绑定、Buffer 对象、Query 对象、Sampler Unit 等。
   - 这有助于垃圾回收器正确地管理这些对象，并帮助开发者进行内存泄漏等问题的调试。

3. **校验 3D 纹理绑定 (`ValidateTexture3DBinding`)**:
   - 此函数用于验证指定目标 (`target`) 上是否绑定了有效的 3D 纹理或 2D 纹理数组。
   - 它会检查是否有纹理绑定到目标，并可选地检查纹理是否是不透明的。
   - **错误处理：** 如果没有纹理绑定或绑定了不合法的纹理类型，会生成相应的 WebGL 错误。

4. **获取纹理目标的最大层级 (`GetMaxTextureLevelForTarget`)**:
   - 返回指定纹理目标 (`target`) 所支持的最大 Mipmap 层级。
   - 对于 `GL_TEXTURE_3D` 和 `GL_TEXTURE_2D_ARRAY`，它返回预先存储的值 (`max3d_texture_level_` 和 `max_texture_level_`)。
   - 其他纹理目标则调用基类 `WebGLRenderingContextBase` 的实现。

5. **获取纹理参数 (`getTexParameter`)**:
   -  类似于 Framebuffer 的 `getFramebufferAttachmentParameter`，此函数用于获取绑定到指定目标 (`target`) 的纹理对象的参数 (`pname`)。
   - 它处理了一些 WebGL2 特有的纹理参数，例如 `GL_TEXTURE_WRAP_R`、`GL_TEXTURE_COMPARE_FUNC`、`GL_TEXTURE_COMPARE_MODE`、`GL_TEXTURE_IMMUTABLE_LEVELS` 等。
   - 也处理了 `WEBGL_stencil_texturing` 扩展的相关参数。
   - 其他参数会委托给基类处理。
   - **错误处理：**  如果查询不支持的参数名或在未启用扩展的情况下查询扩展相关的参数，会生成 WebGL 错误。

6. **校验 Buffer 数据目标 (`ValidateBufferDataTarget`)**:
   - 验证 `bufferData`、`bufferSubData` 等函数的目标 (`target`) 是否合法，并返回绑定的 `WebGLBuffer` 对象。
   - 它会根据不同的目标类型（例如 `GL_ARRAY_BUFFER`、`GL_ELEMENT_ARRAY_BUFFER`、`GL_COPY_READ_BUFFER` 等）检查对应的绑定点。
   - **关键检查：**  还会检查 Buffer 是否被 Transform Feedback 绑定，并且与其他绑定点存在冲突。
   - **错误处理：** 如果目标无效或没有 Buffer 绑定，或者存在绑定冲突，会生成相应的 WebGL 错误。

7. **校验 Buffer 数据使用方式 (`ValidateBufferDataUsage`)**:
   - 验证 `bufferData` 等函数中指定的使用方式 (`usage`) 是否合法。
   - 它扩展了 WebGL1 的使用方式，添加了 `GL_STREAM_READ`、`GL_STREAM_COPY`、`GL_STATIC_READ`、`GL_STATIC_COPY`、`GL_DYNAMIC_READ`、`GL_DYNAMIC_COPY` 等 WebGL2 新增的用法。

8. **校验 `getBufferSubData` 参数 (`ValidateGetBufferSubData`)**:
   - 在执行 `getBufferSubData` 操作前，对此函数的参数进行校验。
   - 校验源偏移量 (`source_byte_offset`) 是否有效，目标 `ArrayBufferView` 和偏移量 (`destination_offset`) 以及长度 (`length`) 是否会导致溢出。
   - 同时会获取源 Buffer 对象 (`out_source_buffer`) 和目标数据指针 (`out_destination_data_ptr`) 以及长度 (`out_destination_byte_length`)。
   - **错误处理：**  如果参数无效或 Buffer 正在被 Transform Feedback 使用，会返回错误信息。

9. **校验 `getBufferSubData` 边界 (`ValidateGetBufferSubDataBounds`)**:
   - 进一步校验 `getBufferSubData` 操作的读取边界是否超出源 Buffer 的大小。
   - **错误处理：**  如果超出边界，会生成 `GL_INVALID_VALUE` 错误。

10. **移除绑定的 Buffer (`RemoveBoundBuffer`)**:
    - 当一个 `WebGLBuffer` 对象被删除时，需要从各个可能的绑定点解除绑定。
    - 此函数负责将指定的 `buffer` 从各种 Buffer 绑定点（例如 `bound_copy_read_buffer_`、`bound_uniform_buffer_`、Transform Feedback 绑定等）移除。
    - 它会调用基类的 `RemoveBoundBuffer` 来处理 WebGL1 的绑定点。

11. **恢复当前的 Framebuffer (`RestoreCurrentFramebuffer`)**:
    - 将绘制 Framebuffer 和读取 Framebuffer 恢复到之前绑定的状态。这在某些操作后需要恢复 Framebuffer 绑定时使用。

12. **使用 Program (`useProgram`)**:
    - 设置当前 WebGL 上下文使用的 Program 对象。
    - **重要检查：**  如果 Transform Feedback 正在激活且未暂停，则不允许切换 Program。
    - 其他逻辑委托给基类的 `useProgram` 实现。

13. **获取最大 Transform Feedback 分离属性数量 (`GetMaxTransformFeedbackSeparateAttribs`)**:
    - 返回硬件支持的最大 Transform Feedback 分离属性数量。

14. **获取 Pack 和 Unpack 像素存储参数 (`GetPackPixelStoreParams`, `GetUnpackPixelStoreParams`)**:
    - 返回当前设置的像素存储参数，例如对齐方式、行长度、跳过的像素/行/图像等。
    - 这些参数影响纹理数据的上传和下载。

15. **恢复 DrawingBuffer 客户端的像素解包/打包 Buffer 绑定和参数 (`DrawingBufferClientRestorePixelUnpackBufferBinding`, `DrawingBufferClientRestorePixelPackBufferBinding`, `DrawingBufferClientRestorePixelPackParameters`)**:
    - 这些函数在 DrawingBuffer 客户端恢复时被调用，用于重新绑定像素解包/打包 Buffer，并恢复相关的像素存储参数。
    - 这通常发生在上下文丢失和恢复后。

**与 JavaScript, HTML, CSS 的关系**

这个 C++ 文件是 WebGL API 的底层实现部分，它直接与浏览器的 OpenGL ES (或兼容的图形 API) 交互。它通过 Blink 引擎暴露给 JavaScript。

* **JavaScript:** WebGL 的各种函数调用，例如 `gl.getFramebufferAttachmentParameter()`, `gl.texParameteri()`, `gl.bindBuffer()`, `gl.useProgram()`, `gl.getBufferSubData()` 等，最终会映射到这个 C++ 文件中的相应实现。例如：
    ```javascript
    // JavaScript 代码
    const framebuffer = gl.createFramebuffer();
    gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);
    const attachmentType = gl.getFramebufferAttachmentParameter(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE);
    ```
    这段 JavaScript 代码中的 `gl.getFramebufferAttachmentParameter()` 调用最终会触发 `WebGL2RenderingContextBase::getFramebufferAttachmentParameter()` 的执行。

* **HTML:** HTML 中的 `<canvas>` 元素是 WebGL 内容的渲染目标。JavaScript 代码通过获取 `<canvas>` 元素的上下文来获得 WebGLRenderingContext 或 WebGL2RenderingContext 对象，并调用其方法。

* **CSS:** CSS 可以影响包含 `<canvas>` 元素的页面的布局和样式，但它不直接影响 WebGL 的内部工作。CSS 可以控制 `<canvas>` 元素的大小和位置，但这最终会影响 WebGL 的视口设置。

**逻辑推理的假设输入与输出**

以 `getFramebufferAttachmentParameter` 为例：

**假设输入：**

* `target`: `GL_FRAMEBUFFER` (或 `GL_DRAW_FRAMEBUFFER`, `GL_READ_FRAMEBUFFER`)
* `attachment`: `GL_COLOR_ATTACHMENT0`
* `pname`: `GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE`

**假设上下文：** 假设一个纹理对象已经绑定到 `GL_COLOR_ATTACHMENT0`。

**预期输出：**

* 返回 `WebGLAny(script_state, GL_TEXTURE)`，表示颜色附件 0 绑定了一个纹理。

**用户或编程常见的使用错误**

1. **在 Transform Feedback 激活且未暂停时尝试切换 Program：**
   - **用户操作：** 用户可能在开始 Transform Feedback 后，忘记暂停或结束 Transform Feedback 就尝试调用 `gl.useProgram()` 切换 Shader Program。
   - **错误：** `SynthesizeGLError(GL_INVALID_OPERATION, "useProgram", "transform feedback is active and not paused");`

2. **查询 Framebuffer 附件时使用错误的 `pname`：**
   - **用户操作：** 用户可能错误地使用了不适用于当前附件类型或 WebGL 版本的参数名。
   - **错误：** `SynthesizeGLError(GL_INVALID_ENUM, kFunctionName, "invalid parameter name");`

3. **在未启用扩展的情况下查询扩展相关的参数：**
   - **用户操作：** 用户尝试使用 `gl.getTexParameter()` 查询 `GL_DEPTH_STENCIL_TEXTURE_MODE_ANGLE`，但 `WEBGL_stencil_texturing` 扩展未启用。
   - **错误：** `SynthesizeGLError(GL_INVALID_ENUM, "getTexParameter", "invalid parameter name, WEBGL_stencil_texturing not enabled");`

4. **`getBufferSubData` 操作时指定超出 Buffer 边界的偏移量或长度：**
   - **用户操作：** 用户在调用 `gl.getBufferSubData()` 时，提供的源偏移量加上读取长度超过了 Buffer 的实际大小。
   - **错误：** `SynthesizeGLError(GL_INVALID_VALUE, function_name, "overflow of bound buffer");`

**用户操作如何一步步到达这里 (调试线索)**

假设开发者遇到了一个与获取 Framebuffer 附件参数相关的错误，他们可能会进行如下调试：

1. **JavaScript 代码调用 `gl.getFramebufferAttachmentParameter()`：** 开发者在 JavaScript 代码中调用了 `gl.getFramebufferAttachmentParameter(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, someInvalidParameter);`，并且 `someInvalidParameter` 是一个无效的参数名。

2. **Blink 引擎接收到调用：** 浏览器的 JavaScript 引擎会将这个 WebGL API 调用传递给 Blink 渲染引擎。

3. **调用 `WebGL2RenderingContextBase::getFramebufferAttachmentParameter()`：**  Blink 引擎会将这个调用路由到 `webgl2_rendering_context_base.cc` 文件中的 `getFramebufferAttachmentParameter` 函数。

4. **代码执行并触发错误：**  在 `getFramebufferAttachmentParameter` 函数内部，由于 `pname` 是无效的，代码会执行到 `SynthesizeGLError` 分支，生成一个 WebGL 错误。

5. **开发者在控制台看到错误：** 开发者在浏览器的开发者工具的控制台中会看到类似 "WebGL: INVALID_ENUM: getFramebufferAttachmentParameter: invalid parameter name" 的错误信息。

6. **设置断点调试：** 为了进一步调查，开发者可能会在 `blink/renderer/modules/webgl/webgl2_rendering_context_base.cc` 文件的 `getFramebufferAttachmentParameter` 函数入口处设置断点，或者在 `SynthesizeGLError` 的调用处设置断点，来查看具体的参数值和执行流程。

**归纳其功能 (作为第 7 部分)**

作为 `WebGL2RenderingContextBase` 的最后一部分，这段代码主要负责以下功能：

* **提供查询 WebGL 对象状态的接口：**  例如查询 Framebuffer 附件的属性、纹理的参数等。
* **执行更细粒度的参数校验：**  例如校验 `getBufferSubData` 的参数边界、Buffer 的使用方式等，以确保 WebGL 操作的正确性。
* **处理一些 WebGL2 特有的功能和扩展：** 例如 Transform Feedback 相关的限制、3D 纹理和纹理数组的处理、以及对特定扩展的支持。
* **维护和恢复 WebGL 上下文的状态：** 例如在 DrawingBuffer 客户端恢复时重新绑定 Buffer 和参数。
* **提供内部的追踪机制：**  通过 `Trace` 函数支持 Blink 引擎的垃圾回收和调试。

总而言之，这段代码完善了 `WebGL2RenderingContextBase` 类的功能，涵盖了 WebGL2 规范中一些重要的查询、校验和状态管理操作，并与底层图形 API 紧密联系，最终服务于上层的 JavaScript WebGL API。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl2_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共7部分，请归纳一下它的功能

"""
riptValue::CreateNull(script_state->GetIsolate());
      default:
        SynthesizeGLError(GL_INVALID_ENUM, kFunctionName,
                          "invalid parameter name");
        return ScriptValue::CreateNull(script_state->GetIsolate());
    }
  }

  WebGLSharedObject* attachment_object = nullptr;
  if (attachment == GL_DEPTH_STENCIL_ATTACHMENT) {
    WebGLSharedObject* depth_attachment =
        framebuffer_binding->GetAttachmentObject(GL_DEPTH_ATTACHMENT);
    WebGLSharedObject* stencil_attachment =
        framebuffer_binding->GetAttachmentObject(GL_STENCIL_ATTACHMENT);
    if (depth_attachment != stencil_attachment) {
      SynthesizeGLError(
          GL_INVALID_OPERATION, kFunctionName,
          "different objects bound to DEPTH_ATTACHMENT and STENCIL_ATTACHMENT");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    }
    attachment_object = depth_attachment;
  } else {
    attachment_object = framebuffer_binding->GetAttachmentObject(attachment);
  }

  if (!attachment_object) {
    switch (pname) {
      case GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE:
        return WebGLAny(script_state, GL_NONE);
      case GL_FRAMEBUFFER_ATTACHMENT_OBJECT_NAME:
        return ScriptValue::CreateNull(script_state->GetIsolate());
      default:
        SynthesizeGLError(GL_INVALID_OPERATION, kFunctionName,
                          "invalid parameter name");
        return ScriptValue::CreateNull(script_state->GetIsolate());
    }
  }
  DCHECK(attachment_object->IsTexture() || attachment_object->IsRenderbuffer());

  switch (pname) {
    case GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE:
      if (attachment_object->IsTexture())
        return WebGLAny(script_state, GL_TEXTURE);
      return WebGLAny(script_state, GL_RENDERBUFFER);
    case GL_FRAMEBUFFER_ATTACHMENT_OBJECT_NAME:
      return WebGLAny(script_state, attachment_object);
    case GL_FRAMEBUFFER_ATTACHMENT_TEXTURE_LEVEL:
    case GL_FRAMEBUFFER_ATTACHMENT_TEXTURE_CUBE_MAP_FACE:
    case GL_FRAMEBUFFER_ATTACHMENT_TEXTURE_LAYER:
      if (!attachment_object->IsTexture())
        break;
      [[fallthrough]];
    case GL_FRAMEBUFFER_ATTACHMENT_RED_SIZE:
    case GL_FRAMEBUFFER_ATTACHMENT_GREEN_SIZE:
    case GL_FRAMEBUFFER_ATTACHMENT_BLUE_SIZE:
    case GL_FRAMEBUFFER_ATTACHMENT_ALPHA_SIZE:
    case GL_FRAMEBUFFER_ATTACHMENT_DEPTH_SIZE:
    case GL_FRAMEBUFFER_ATTACHMENT_STENCIL_SIZE: {
      GLint value = 0;
      ContextGL()->GetFramebufferAttachmentParameteriv(target, attachment,
                                                       pname, &value);
      return WebGLAny(script_state, value);
    }
    case GL_FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE:
      if (attachment == GL_DEPTH_STENCIL_ATTACHMENT) {
        SynthesizeGLError(
            GL_INVALID_OPERATION, kFunctionName,
            "component type cannot be queried for DEPTH_STENCIL_ATTACHMENT");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      [[fallthrough]];
    case GL_FRAMEBUFFER_ATTACHMENT_COLOR_ENCODING: {
      GLint value = 0;
      ContextGL()->GetFramebufferAttachmentParameteriv(target, attachment,
                                                       pname, &value);
      return WebGLAny(script_state, static_cast<unsigned>(value));
    }
    case GL_FRAMEBUFFER_ATTACHMENT_TEXTURE_BASE_VIEW_INDEX_OVR:
    case GL_FRAMEBUFFER_ATTACHMENT_TEXTURE_NUM_VIEWS_OVR: {
      if (!ExtensionEnabled(kOVRMultiview2Name)) {
        SynthesizeGLError(GL_INVALID_ENUM, kFunctionName,
                          "invalid parameter name, OVR_multiview2 not enabled");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      }
      GLint value = 0;
      ContextGL()->GetFramebufferAttachmentParameteriv(target, attachment,
                                                       pname, &value);
      return WebGLAny(script_state, static_cast<unsigned>(value));
    }
    default:
      break;
  }
  SynthesizeGLError(GL_INVALID_ENUM, kFunctionName, "invalid parameter name");
  return ScriptValue::CreateNull(script_state->GetIsolate());
}

void WebGL2RenderingContextBase::Trace(Visitor* visitor) const {
  visitor->Trace(read_framebuffer_binding_);
  visitor->Trace(transform_feedback_binding_);
  visitor->Trace(default_transform_feedback_);
  visitor->Trace(bound_copy_read_buffer_);
  visitor->Trace(bound_copy_write_buffer_);
  visitor->Trace(bound_pixel_pack_buffer_);
  visitor->Trace(bound_pixel_unpack_buffer_);
  visitor->Trace(bound_transform_feedback_buffer_);
  visitor->Trace(bound_uniform_buffer_);
  visitor->Trace(bound_indexed_uniform_buffers_);
  visitor->Trace(current_boolean_occlusion_query_);
  visitor->Trace(current_transform_feedback_primitives_written_query_);
  visitor->Trace(current_elapsed_query_);
  visitor->Trace(sampler_units_);
  WebGLRenderingContextBase::Trace(visitor);
}

WebGLTexture* WebGL2RenderingContextBase::ValidateTexture3DBinding(
    const char* function_name,
    GLenum target,
    bool validate_opaque_textures) {
  WebGLTexture* tex = nullptr;
  switch (target) {
    case GL_TEXTURE_2D_ARRAY:
      tex = texture_units_[active_texture_unit_].texture2d_array_binding_.Get();
      break;
    case GL_TEXTURE_3D:
      tex = texture_units_[active_texture_unit_].texture3d_binding_.Get();
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid texture target");
      return nullptr;
  }
  if (!tex) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "no texture bound to target");
  } else if (validate_opaque_textures && tex->IsOpaqueTexture()) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "cannot invoke function with an opaque texture");
    return nullptr;
  }
  return tex;
}

GLint WebGL2RenderingContextBase::GetMaxTextureLevelForTarget(GLenum target) {
  switch (target) {
    case GL_TEXTURE_3D:
      return max3d_texture_level_;
    case GL_TEXTURE_2D_ARRAY:
      return max_texture_level_;
  }
  return WebGLRenderingContextBase::GetMaxTextureLevelForTarget(target);
}

ScriptValue WebGL2RenderingContextBase::getTexParameter(
    ScriptState* script_state,
    GLenum target,
    GLenum pname) {
  if (isContextLost() || !ValidateTextureBinding("getTexParameter", target))
    return ScriptValue::CreateNull(script_state->GetIsolate());

  switch (pname) {
    case GL_TEXTURE_WRAP_R:
    case GL_TEXTURE_COMPARE_FUNC:
    case GL_TEXTURE_COMPARE_MODE:
    case GL_TEXTURE_IMMUTABLE_LEVELS: {
      GLint value = 0;
      ContextGL()->GetTexParameteriv(target, pname, &value);
      return WebGLAny(script_state, static_cast<unsigned>(value));
    }
    case GL_TEXTURE_IMMUTABLE_FORMAT: {
      GLint value = 0;
      ContextGL()->GetTexParameteriv(target, pname, &value);
      return WebGLAny(script_state, static_cast<bool>(value));
    }
    case GL_TEXTURE_BASE_LEVEL:
    case GL_TEXTURE_MAX_LEVEL: {
      GLint value = 0;
      ContextGL()->GetTexParameteriv(target, pname, &value);
      return WebGLAny(script_state, value);
    }
    case GL_TEXTURE_MAX_LOD:
    case GL_TEXTURE_MIN_LOD: {
      GLfloat value = 0.f;
      ContextGL()->GetTexParameterfv(target, pname, &value);
      return WebGLAny(script_state, value);
    }
    case GL_DEPTH_STENCIL_TEXTURE_MODE_ANGLE:
      if (ExtensionEnabled(kWebGLStencilTexturingName)) {
        GLint value = 0;
        ContextGL()->GetTexParameteriv(target, pname, &value);
        return WebGLAny(script_state, value);
      }
      SynthesizeGLError(
          GL_INVALID_ENUM, "getTexParameter",
          "invalid parameter name, WEBGL_stencil_texturing not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    default:
      return WebGLRenderingContextBase::getTexParameter(script_state, target,
                                                        pname);
  }
}

WebGLBuffer* WebGL2RenderingContextBase::ValidateBufferDataTarget(
    const char* function_name,
    GLenum target) {
  WebGLBuffer* buffer = nullptr;
  switch (target) {
    case GL_ELEMENT_ARRAY_BUFFER:
      buffer = bound_vertex_array_object_->BoundElementArrayBuffer();
      break;
    case GL_ARRAY_BUFFER:
      buffer = bound_array_buffer_.Get();
      break;
    case GL_COPY_READ_BUFFER:
      buffer = bound_copy_read_buffer_.Get();
      break;
    case GL_COPY_WRITE_BUFFER:
      buffer = bound_copy_write_buffer_.Get();
      break;
    case GL_PIXEL_PACK_BUFFER:
      buffer = bound_pixel_pack_buffer_.Get();
      break;
    case GL_PIXEL_UNPACK_BUFFER:
      buffer = bound_pixel_unpack_buffer_.Get();
      break;
    case GL_TRANSFORM_FEEDBACK_BUFFER:
      buffer = bound_transform_feedback_buffer_.Get();
      break;
    case GL_UNIFORM_BUFFER:
      buffer = bound_uniform_buffer_.Get();
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid target");
      return nullptr;
  }
  if (!buffer) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name, "no buffer");
    return nullptr;
  }
  if (transform_feedback_binding_->HasBoundIndexedTransformFeedbackBuffer(
          buffer)) {
    DCHECK(buffer != bound_vertex_array_object_->BoundElementArrayBuffer());
    if (bound_indexed_uniform_buffers_.Contains(buffer) ||
        bound_vertex_array_object_->HasArrayBuffer(buffer) ||
        buffer == bound_array_buffer_ || buffer == bound_copy_read_buffer_ ||
        buffer == bound_copy_write_buffer_ ||
        buffer == bound_pixel_pack_buffer_ ||
        buffer == bound_pixel_unpack_buffer_ ||
        buffer == bound_uniform_buffer_) {
      SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                        "buffer is bound to an indexed transform feedback "
                        "binding point and some other binding point");
      return nullptr;
    }
  }
  return buffer;
}

bool WebGL2RenderingContextBase::ValidateBufferDataUsage(
    const char* function_name,
    GLenum usage) {
  switch (usage) {
    case GL_STREAM_READ:
    case GL_STREAM_COPY:
    case GL_STATIC_READ:
    case GL_STATIC_COPY:
    case GL_DYNAMIC_READ:
    case GL_DYNAMIC_COPY:
      return true;
    default:
      return WebGLRenderingContextBase::ValidateBufferDataUsage(function_name,
                                                                usage);
  }
}

const char* WebGL2RenderingContextBase::ValidateGetBufferSubData(
    const char* function_name,
    GLenum target,
    int64_t source_byte_offset,
    DOMArrayBufferView* destination_array_buffer_view,
    int64_t destination_offset,
    GLuint length,
    WebGLBuffer** out_source_buffer,
    void** out_destination_data_ptr,
    int64_t* out_destination_byte_length) {
  if (isContextLost()) {
    return "Context lost";
  }

  if (!ValidateValueFitNonNegInt32(function_name, "srcByteOffset",
                                   source_byte_offset)) {
    return "Invalid value: srcByteOffset";
  }

  WebGLBuffer* source_buffer = ValidateBufferDataTarget(function_name, target);
  if (!source_buffer) {
    return "Invalid operation: no buffer bound to target";
  }
  if (transform_feedback_binding_->active() &&
      transform_feedback_binding_->UsesBuffer(source_buffer)) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "buffer in use for transform feedback");
    return "Invalid operation: buffer in use for transform feedback";
  }
  *out_source_buffer = source_buffer;

  if (!ValidateSubSourceAndGetData(
          destination_array_buffer_view, destination_offset, length,
          out_destination_data_ptr, out_destination_byte_length)) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "overflow of dstData");
    return "Invalid value: overflow of dstData";
  }

  return nullptr;
}

const char* WebGL2RenderingContextBase::ValidateGetBufferSubDataBounds(
    const char* function_name,
    WebGLBuffer* source_buffer,
    GLintptr source_byte_offset,
    int64_t destination_byte_length) {
  base::CheckedNumeric<int64_t> src_end = source_byte_offset;
  src_end += destination_byte_length;
  if (!src_end.IsValid() || src_end.ValueOrDie() > source_buffer->GetSize()) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      "overflow of bound buffer");
    return "Invalid value: overflow of bound buffer";
  }

  return nullptr;
}

void WebGL2RenderingContextBase::RemoveBoundBuffer(WebGLBuffer* buffer) {
  if (bound_copy_read_buffer_ == buffer)
    bound_copy_read_buffer_ = nullptr;
  if (bound_copy_write_buffer_ == buffer)
    bound_copy_write_buffer_ = nullptr;
  if (bound_pixel_pack_buffer_ == buffer)
    bound_pixel_pack_buffer_ = nullptr;
  if (bound_pixel_unpack_buffer_ == buffer)
    bound_pixel_unpack_buffer_ = nullptr;
  if (bound_transform_feedback_buffer_ == buffer)
    bound_transform_feedback_buffer_ = nullptr;
  if (bound_uniform_buffer_ == buffer)
    bound_uniform_buffer_ = nullptr;

  transform_feedback_binding_->UnbindBuffer(buffer);

  for (auto& bound_buffer : bound_indexed_uniform_buffers_) {
    if (bound_buffer == buffer) {
      bound_buffer = nullptr;
    }
  }

  WebGLRenderingContextBase::RemoveBoundBuffer(buffer);
}

void WebGL2RenderingContextBase::RestoreCurrentFramebuffer() {
  bindFramebuffer(GL_DRAW_FRAMEBUFFER, framebuffer_binding_.Get());
  bindFramebuffer(GL_READ_FRAMEBUFFER, read_framebuffer_binding_.Get());
}

void WebGL2RenderingContextBase::useProgram(WebGLProgram* program) {
  if (!isContextLost() && transform_feedback_binding_->active() &&
      !transform_feedback_binding_->paused()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "useProgram",
                      "transform feedback is active and not paused");
    return;
  }
  WebGLRenderingContextBase::useProgram(program);
}

GLint WebGL2RenderingContextBase::GetMaxTransformFeedbackSeparateAttribs()
    const {
  return max_transform_feedback_separate_attribs_;
}

WebGLImageConversion::PixelStoreParams
WebGL2RenderingContextBase::GetPackPixelStoreParams() {
  WebGLImageConversion::PixelStoreParams params;
  params.alignment = pack_alignment_;
  params.row_length = pack_row_length_;
  params.skip_pixels = pack_skip_pixels_;
  params.skip_rows = pack_skip_rows_;
  return params;
}

WebGLImageConversion::PixelStoreParams
WebGL2RenderingContextBase::GetUnpackPixelStoreParams(
    TexImageDimension dimension) {
  WebGLImageConversion::PixelStoreParams params;
  params.alignment = unpack_alignment_;
  params.row_length = unpack_row_length_;
  params.skip_pixels = unpack_skip_pixels_;
  params.skip_rows = unpack_skip_rows_;
  if (dimension == kTex3D) {
    params.image_height = unpack_image_height_;
    params.skip_images = unpack_skip_images_;
  }
  return params;
}

void WebGL2RenderingContextBase::
    DrawingBufferClientRestorePixelUnpackBufferBinding() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  ContextGL()->BindBuffer(GL_PIXEL_UNPACK_BUFFER,
                          ObjectOrZero(bound_pixel_unpack_buffer_.Get()));
}

void WebGL2RenderingContextBase::
    DrawingBufferClientRestorePixelPackBufferBinding() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;
  ContextGL()->BindBuffer(GL_PIXEL_PACK_BUFFER,
                          ObjectOrZero(bound_pixel_pack_buffer_.Get()));
}

void WebGL2RenderingContextBase::
    DrawingBufferClientRestorePixelPackParameters() {
  if (destruction_in_progress_)
    return;
  if (!ContextGL())
    return;

  ContextGL()->PixelStorei(GL_PACK_ROW_LENGTH, pack_row_length_);
  ContextGL()->PixelStorei(GL_PACK_SKIP_ROWS, pack_skip_rows_);
  ContextGL()->PixelStorei(GL_PACK_SKIP_PIXELS, pack_skip_pixels_);

  WebGLRenderingContextBase::DrawingBufferClientRestorePixelPackParameters();
}

}  // namespace blink

"""


```