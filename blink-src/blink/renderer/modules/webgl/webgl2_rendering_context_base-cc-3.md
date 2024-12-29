Response:
The user wants to understand the functionality of a specific part of a Chromium source code file related to WebGL2. They have provided a code snippet and are asking for a summary of its functions, including connections to JavaScript, HTML, CSS, logical reasoning with input/output examples, common user errors, and debugging guidance. Since this is part 4 of 7, I need to focus on the functionality within this specific snippet and avoid making assumptions about the entire file.

Here's a breakdown of the code and how to address each point:

1. **List the functions:** Identify all the C++ methods defined within the provided code.
2. **Functionality of each function:** Describe what each function does based on its name and the operations it performs. Look for interactions with the underlying OpenGL context (`ContextGL()`), validations, error handling (`SynthesizeGLError`), and state management.
3. **Relationship to JavaScript, HTML, CSS:** Analyze how these C++ functions are likely exposed to JavaScript through the WebGL API. Consider the naming conventions (camelCase in JS, snake_case in C++) and parameter types. HTML and CSS are indirectly related through the `<canvas>` element where WebGL rendering occurs.
4. **Logical Reasoning (Input/Output):** For some functions, particularly those dealing with data transfer (like `compressedTexSubImage3D` and `uniform*`), provide hypothetical JavaScript calls and explain how the C++ code processes the input and interacts with the OpenGL context.
5. **Common User Errors:**  Identify common mistakes a WebGL developer might make when calling the JavaScript equivalents of these functions, based on the validation checks in the C++ code (e.g., invalid enum values, out-of-bounds data, using a function when the context is lost).
6. **User Operations and Debugging:** Describe a scenario where a user interacts with a webpage using WebGL, leading to the execution of these specific C++ functions. Explain how a developer might use debugging tools to step into this code.
7. **Part 4 Summary:**  Concisely summarize the primary functionalities covered in this code snippet, focusing on texture updates, uniform setting, and query operations.

**Mental Sandbox:**

* **`compressedTexSubImage3D`:**  This seems to handle updating parts of a 3D texture with compressed data. There are two overloads: one taking a `SharedBuffer` and another taking an offset into a bound pixel unpack buffer. Potential errors: invalid target, format, out-of-bounds offset/length, no pixel unpack buffer bound.
* **`getFragDataLocation`:**  Retrieves the location of a fragment shader output variable. Error: invalid program.
* **`uniform*` functions:**  Sets uniform variables in the currently active shader program. Lots of variations for different data types (int, uint, float) and sizes (scalar, vector, matrix). Errors: context lost, invalid location, incorrect data size.
* **`vertexAttribI4*` functions:**  Sets integer-based vertex attributes. Errors: context lost, invalid array size.
* **`vertexAttribIPointer`:**  Specifies the location and data format of integer-based vertex attribute arrays. Errors: context lost, index out of range, invalid offset, no array buffer bound.
* **`vertexAttribDivisor`:**  Controls instancing by specifying how often vertex attributes are updated. Error: index out of range.
* **`drawArraysInstanced`, `drawElementsInstanced`, `drawRangeElements`:**  Issue draw calls using instancing. Errors are likely handled in the `ValidateDraw*` functions.
* **`drawBuffers`:**  Specifies which color attachments to render to. Errors: context lost, invalid buffer enum, wrong number of buffers for default framebuffer.
* **`clearBuffer*` functions:** Clear specific buffers (color, depth, stencil) with provided values. Several overloads for different data types. Errors: context lost, invalid buffer enum, invalid array size/offset.
* **`createQuery`, `deleteQuery`, `isQuery`, `beginQuery`, `endQuery`:**  Manages query objects used for asynchronous operations like occlusion testing and timer queries. Errors: context lost, invalid query object, trying to begin a query while another is active.

**Key Insight:** This section appears to focus on updating resources (textures, uniforms, vertex attributes) and initiating drawing and query operations within the WebGL 2 context. It includes significant validation logic to catch common developer errors.

Strategizing complete. I will now generate the response based on these observations.
好的，让我们来分析一下 `blink/renderer/modules/webgl/webgl2_rendering_context_base.cc` 文件的这个代码片段的功能。

**功能概览**

这段代码主要实现了 `WebGL2RenderingContextBase` 类的一些方法，这些方法对应了 WebGL 2 API 中用于以下操作的功能：

1. **纹理数据更新 (Compressed Texture Updates):** 提供了向 3D 纹理上传或更新压缩数据的能力。
2. **获取 Fragment Shader Data Location:**  允许获取 fragment shader 中输出变量的位置。
3. **设置 Uniform 变量:**  提供了一系列方法来设置 shader program 中 uniform 变量的值，支持不同的数据类型（整型、浮点型、无符号整型）和维度（标量、向量、矩阵）。
4. **设置 Vertex Attribute (Integer):**  提供了设置整型顶点属性的方法。
5. **设置 Vertex Attribute Pointer (Integer):**  指定整型顶点属性数据的来源和格式。
6. **实例绘制 (Instanced Rendering):** 提供了控制实例绘制中顶点属性更新频率的方法，以及执行实例绘制的方法。
7. **指定渲染目标 (Draw Buffers):**  允许指定渲染结果输出到哪些颜色附件上。
8. **清除缓冲区 (Clear Buffers):**  提供了更精细的清除颜色、深度和模板缓冲区的方法，可以指定清除的值。
9. **查询对象 (Query Objects):** 提供了创建、删除、检查和使用查询对象的功能，用于异步获取渲染管线的信息。

**与 JavaScript, HTML, CSS 的关系及举例**

这些 C++ 方法是 WebGL 2 API 在 Blink 渲染引擎中的底层实现。JavaScript 代码通过调用 WebGL 2 的 API，最终会调用到这些 C++ 方法。

* **JavaScript:**  JavaScript 代码是直接与这些功能交互的接口。例如，JavaScript 中调用 `gl.compressedTexSubImage3D()` 会最终调用到 C++ 的 `WebGL2RenderingContextBase::compressedTexSubImage3D()` 方法。
    ```javascript
    // JavaScript 示例
    const gl = canvas.getContext('webgl2');
    const texture = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_3D, texture);
    // ... 设置纹理参数 ...
    const compressedData = new Uint8Array([...]); // 压缩后的纹理数据
    gl.compressedTexSubImage3D(gl.TEXTURE_3D, 0, 1, 2, 3, 4, 5, 6, gl.COMPRESSED_RGB_S3TC_DXT1_EXT, compressedData);

    const program = gl.createProgram();
    // ... 创建和链接 shader ...
    const fragColorLocation = gl.getFragDataLocation(program, 'fragColor');

    const myUniformLocation = gl.getUniformLocation(program, 'myUniform');
    gl.uniform1f(myUniformLocation, 1.0);
    gl.uniform3uiv(myUniformLocation, [1, 2, 3]);

    const vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    // ... 填充 buffer 数据 ...
    gl.vertexAttribIPointer(0, 4, gl.INT, 0, 0);
    gl.enableVertexAttribArray(0);

    gl.vertexAttribDivisor(1, 2); // 每隔 2 个实例更新一次属性

    gl.drawArraysInstanced(gl.TRIANGLES, 0, 6, 10); // 绘制 10 个实例

    gl.drawBuffers([gl.COLOR_ATTACHMENT0, gl.NONE]);

    gl.clearBufferfv(gl.COLOR, 0, [0.0, 0.5, 0.0, 1.0]);

    const query = gl.createQuery();
    gl.beginQuery(gl.ANY_SAMPLES_PASSED, query);
    // ... 绘制操作 ...
    gl.endQuery(gl.ANY_SAMPLES_PASSED);
    ```

* **HTML:**  HTML 中的 `<canvas>` 元素是 WebGL 内容的渲染目标。JavaScript 代码会获取 `<canvas>` 元素的上下文（Context），然后在其上进行 WebGL 操作。
    ```html
    <!-- HTML 示例 -->
    <canvas id="myCanvas" width="500" height="300"></canvas>
    <script>
      const canvas = document.getElementById('myCanvas');
      const gl = canvas.getContext('webgl2');
      // ... WebGL 代码 ...
    </script>
    ```

* **CSS:** CSS 可以控制 `<canvas>` 元素的样式，例如大小、边框等，但它不直接影响 WebGL 的内部渲染逻辑。

**逻辑推理及假设输入与输出**

**示例 1: `compressedTexSubImage3D`**

* **假设输入 (JavaScript 调用):**
  ```javascript
  gl.bindTexture(gl.TEXTURE_3D, my3DTexture);
  const compressedData = new Uint8Array([0x10, 0x20, 0x30, 0x40]);
  gl.compressedTexSubImage3D(gl.TEXTURE_3D, 0, 1, 1, 1, 2, 2, 2, gl.COMPRESSED_RGBA_BPTC_UNORM, compressedData);
  ```
* **C++ 代码逻辑:**
    1. 检查 WebGL 上下文是否丢失。
    2. 检查是否绑定了 `PIXEL_UNPACK_BUFFER` (这里没有)。
    3. 验证目标纹理是否为 3D 纹理。
    4. 验证压缩格式是否有效。
    5. 提取数据长度。
    6. 检查 `src_offset` 是否在数据范围内。
    7. 检查 `src_length_override` 是否在数据范围内。
    8. 调用底层 OpenGL 的 `CompressedTexSubImage3D` 函数，将 `compressedData` 的内容上传到纹理的指定区域。
* **假设输出 (C++ 代码行为):** 如果所有验证都通过，C++ 代码会调用 `ContextGL()->CompressedTexSubImage3D(...)`，将压缩数据传递给 GPU 驱动程序进行纹理更新。如果没有绑定 `PIXEL_UNPACK_BUFFER`，且数据直接传递，则使用 `data->ByteSpanMaybeShared().subspan(src_offset).data()` 获取数据指针。

**示例 2: `uniformMatrix4fv`**

* **假设输入 (JavaScript 调用):**
  ```javascript
  const matrixLocation = gl.getUniformLocation(program, 'modelViewMatrix');
  const matrixData = new Float32Array([
    1, 0, 0, 0,
    0, 1, 0, 0,
    0, 0, 1, 0,
    0, 0, 0, 1
  ]);
  gl.uniformMatrix4fv(matrixLocation, false, matrixData);
  ```
* **C++ 代码逻辑:**
    1. 检查 WebGL 上下文是否丢失。
    2. 验证 `location` 是否有效，并且属于当前使用的 program。
    3. 调用 `ValidateUniformMatrixParameters` 检查数据长度是否正确 (对于 `uniformMatrix4fv`，期望长度为 16)。
    4. 调用底层 OpenGL 的 `UniformMatrix4fv` 函数，将矩阵数据传递给 GPU 驱动程序，设置 shader 中的 uniform 变量。
* **假设输出 (C++ 代码行为):** 如果验证通过，C++ 代码会调用 `ContextGL()->UniformMatrix4fv(location->Location(), length, transpose, data)`，将 JavaScript 传递的矩阵数据发送到 GPU。

**用户或编程常见的使用错误**

1. **在 Context 丢失后调用 WebGL 函数:**  例如，在页面切换或 GPU 崩溃后，WebGL Context 可能会丢失。此时调用任何 WebGL 函数都会被代码开头的 `if (isContextLost()) return;` 拦截。
    ```javascript
    // 错误示例
    // ... (假设 context 已经丢失) ...
    gl.clearColor(1, 0, 0, 1); // 无效操作
    ```
2. **`compressedTexSubImage3D` 相关错误:**
    * **未绑定 `PIXEL_UNPACK_BUFFER` 但使用了 offset:** 如果使用 `gl.bindBuffer(gl.PIXEL_UNPACK_BUFFER, ...)` 绑定了 buffer，则可以直接传递 offset。否则，需要传递 `ArrayBufferView`。
    * **`srcOffset` 或 `srcLengthOverride` 超出范围:** 传递的偏移量或长度超过了压缩数据的实际大小。
    * **纹理目标或格式不匹配:**  例如，尝试向 2D 纹理上传压缩数据，或者使用了错误的压缩格式枚举值。
3. **Uniform 变量相关错误:**
    * **`location` 为 null 或无效:** 在 shader program link 失败或者 uniform 变量被优化掉时，`gl.getUniformLocation()` 可能会返回 null。
    * **尝试设置未使用的 uniform 变量:**  如果 shader 中声明了 uniform 变量但没有使用，某些驱动可能会将其优化掉，导致 `gl.getUniformLocation()` 返回 null。
    * **传递错误的数据类型或大小:**  例如，使用 `uniform1f` 设置一个 vec3 类型的 uniform 变量，或者传递的数组长度与 uniform 变量的维度不匹配。
4. **Vertex Attribute 相关错误:**
    * **`index` 超出范围:**  `vertexAttribIPointer` 和 `vertexAttribDivisor` 的第一个参数 `index` 必须小于 `gl.getParameter(gl.MAX_VERTEX_ATTRIBS)`。
    * **`vertexAttribIPointer` 在未绑定 `ARRAY_BUFFER` 时使用非零 `offset`:**  必须先绑定一个 `ARRAY_BUFFER`，才能使用非零的偏移量。
    * **`vertexAttribI4iv` 或 `vertexAttribI4uiv` 传递的数组大小不足 4。**
5. **Draw Call 相关错误:**
    * **在没有绑定有效 framebuffer 的情况下，`drawBuffers` 尝试设置多个渲染目标:** 只有在绑定了 framebuffer 后才能使用多个 `COLOR_ATTACHMENTi`。默认 framebuffer 只能有一个渲染目标 (`GL_BACK` 或 `GL_NONE`)。
    * **`drawBuffers` 中使用了无效的 buffer 枚举值。**
6. **Clear Buffer 相关错误:**
    * **`clearBufferiv`, `clearBufferuiv`, `clearBufferfv` 传递的 `value` 数组大小不足以填充缓冲区:** 例如，清除颜色缓冲区至少需要 4 个值。
    * **`clearBuffer` 使用了无效的 `buffer` 枚举值。**
7. **Query Object 相关错误:**
    * **尝试在已经有一个相同目标的 query 正在进行时调用 `beginQuery`。**
    * **`beginQuery` 使用了无效的 `target` 枚举值。**
    * **`endQuery` 的 `target` 与当前正在进行的 query 的目标不匹配。**

**用户操作如何一步步的到达这里 (调试线索)**

假设用户正在访问一个使用 WebGL 2 技术的网页，并且该网页正在渲染复杂的 3D 场景。以下是一些可能触发这些代码的场景：

1. **加载压缩纹理:** 网页可能正在加载一个使用压缩纹理格式 (如 DXT, ETC, BPTC) 的 3D 模型或场景。JavaScript 代码会下载压缩的纹理数据，然后调用 `gl.compressedTexSubImage3D()` 将数据上传到 GPU。
    * **调试线索:** 在 Chrome 开发者工具的 "Network" 面板中检查纹理资源的加载情况。在 "Sources" 面板中，可以在 JavaScript 代码中设置断点，查看 `compressedData` 的内容和 `gl.compressedTexSubImage3D()` 的参数。
2. **设置 Shader Uniforms:**  网页的渲染循环中，JavaScript 代码会根据场景的状态 (例如，模型的位置、光照参数、相机矩阵) 更新 shader 的 uniform 变量。例如，在每一帧渲染前，可能会调用 `gl.uniformMatrix4fv()` 更新模型视图投影矩阵。
    * **调试线索:** 在渲染循环的 JavaScript 代码中设置断点，查看 uniform 变量的值和 `gl.uniform*` 函数的调用情况。可以使用 WebGL Inspector 等工具查看当前 program 的 uniform 变量值。
3. **使用 Integer Vertex Attributes:** 如果网页使用了需要整型顶点属性的功能 (例如，实例 ID)，则会调用 `gl.vertexAttribIPointer()` 设置顶点属性指针，并在渲染时使用 `gl.vertexAttribDivisor()` 控制属性的更新频率。
    * **调试线索:** 检查顶点数据的创建和绑定过程，查看 `gl.vertexAttribIPointer()` 的参数。
4. **使用 Instanced Rendering:** 为了高效地渲染大量相似的物体，网页可能会使用实例渲染。`gl.drawArraysInstanced()` 或 `gl.drawElementsInstanced()` 会被调用。
    * **调试线索:** 检查 draw call 的参数，确认是否使用了 instanced 版本的 draw 函数。
5. **使用多个渲染目标 (MRT):** 如果网页使用了延迟渲染或其他需要将渲染结果输出到多个纹理的技术，会调用 `gl.drawBuffers()` 指定渲染目标。
    * **调试线索:** 检查 framebuffer 对象的创建和绑定，以及 `gl.drawBuffers()` 的调用。
6. **清除特定缓冲区:**  网页可能需要清除颜色缓冲区、深度缓冲区或模板缓冲区的特定部分，或者使用特定的值进行清除。
    * **调试线索:** 检查 `gl.clearBuffer*` 函数的调用。
7. **使用 Query Objects 进行性能分析或遮挡剔除:**  网页可能使用 query objects 来测量 GPU 的渲染时间或判断物体是否被遮挡。
    * **调试线索:** 检查 `gl.createQuery()`, `gl.beginQuery()`, `gl.endQuery()` 的调用，以及 `gl.getQueryResult()` 的使用。

**作为第 4 部分的功能归纳**

这段代码片段主要负责 **WebGL 2 上下文中与纹理数据更新 (特别是压缩纹理)、Shader Uniform 变量设置、整型顶点属性处理、实例渲染控制、多渲染目标配置、精细的缓冲区清除以及查询对象管理相关的底层实现。**  它提供了将 JavaScript 的 WebGL 2 API 调用转化为实际 GPU 操作的关键功能，并包含了大量的参数验证和错误处理逻辑，以确保 API 的正确使用和程序的稳定性。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl2_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共7部分，请归纳一下它的功能

"""
dTexSubImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  if (!ValidateTexture3DBinding("compressedTexSubImage3D", target))
    return;
  if (!ValidateCompressedTexFormat("compressedTexSubImage3D", format))
    return;
  GLuint data_length;
  if (!ExtractDataLengthIfValid("compressedTexSubImage3D", data, &data_length))
    return;
  if (src_offset > data_length) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexSubImage3D",
                      "srcOffset is out of range");
    return;
  }
  if (src_length_override == 0) {
    src_length_override = data_length - src_offset;
  } else if (src_length_override > data_length - src_offset) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexSubImage3D",
                      "srcLengthOverride is out of range");
    return;
  }
  if (static_cast<size_t>(src_length_override) >
      kMaximumSupportedArrayBufferSize) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexSubImage3D",
                      "src_length_override exceeds the supported range");
    return;
  }
  ContextGL()->CompressedTexSubImage3D(
      target, level, xoffset, yoffset, zoffset, width, height, depth, format,
      src_length_override,
      data->ByteSpanMaybeShared().subspan(src_offset).data());
}

void WebGL2RenderingContextBase::compressedTexSubImage3D(GLenum target,
                                                         GLint level,
                                                         GLint xoffset,
                                                         GLint yoffset,
                                                         GLint zoffset,
                                                         GLsizei width,
                                                         GLsizei height,
                                                         GLsizei depth,
                                                         GLenum format,
                                                         GLsizei image_size,
                                                         int64_t offset) {
  if (isContextLost())
    return;
  if (!bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "compressedTexSubImage3D",
                      "no bound PIXEL_UNPACK_BUFFER");
    return;
  }
  ContextGL()->CompressedTexSubImage3D(target, level, xoffset, yoffset, zoffset,
                                       width, height, depth, format, image_size,
                                       reinterpret_cast<uint8_t*>(offset));
}

GLint WebGL2RenderingContextBase::getFragDataLocation(WebGLProgram* program,
                                                      const String& name) {
  if (!ValidateWebGLProgramOrShader("getFragDataLocation", program))
    return -1;

  return ContextGL()->GetFragDataLocation(ObjectOrZero(program),
                                          name.Utf8().c_str());
}

void WebGL2RenderingContextBase::uniform1ui(
    const WebGLUniformLocation* location,
    GLuint v0) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform1ui", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform1ui(location->Location(), v0);
}

void WebGL2RenderingContextBase::uniform2ui(
    const WebGLUniformLocation* location,
    GLuint v0,
    GLuint v1) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform2ui", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform2ui(location->Location(), v0, v1);
}

void WebGL2RenderingContextBase::uniform3ui(
    const WebGLUniformLocation* location,
    GLuint v0,
    GLuint v1,
    GLuint v2) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform3ui", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform3ui(location->Location(), v0, v1, v2);
}

void WebGL2RenderingContextBase::uniform4ui(
    const WebGLUniformLocation* location,
    GLuint v0,
    GLuint v1,
    GLuint v2,
    GLuint v3) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform4ui", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform4ui(location->Location(), v0, v1, v2, v3);
}

void WebGL2RenderingContextBase::uniform1fv(
    const WebGLUniformLocation* location,
    base::span<const GLfloat> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform1fv", location, v, 1, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform1fv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniform2fv(
    const WebGLUniformLocation* location,
    base::span<const GLfloat> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform2fv", location, v, 2, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform2fv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniform3fv(
    const WebGLUniformLocation* location,
    base::span<const GLfloat> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform3fv", location, v, 3, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform3fv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniform4fv(
    const WebGLUniformLocation* location,
    base::span<const GLfloat> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform4fv", location, v, 4, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform4fv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniform1iv(
    const WebGLUniformLocation* location,
    base::span<const GLint> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform1iv", location, v, 1, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform1iv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniform2iv(
    const WebGLUniformLocation* location,
    base::span<const GLint> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform2iv", location, v, 2, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform2iv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniform3iv(
    const WebGLUniformLocation* location,
    base::span<const GLint> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform3iv", location, v, 3, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform3iv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniform4iv(
    const WebGLUniformLocation* location,
    base::span<const GLint> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform4iv", location, v, 4, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform4iv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniform1uiv(
    const WebGLUniformLocation* location,
    base::span<const GLuint> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLuint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform1uiv", location, v, 1, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform1uiv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniform2uiv(
    const WebGLUniformLocation* location,
    base::span<const GLuint> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLuint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform2uiv", location, v, 2, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform2uiv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniform3uiv(
    const WebGLUniformLocation* location,
    base::span<const GLuint> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLuint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform3uiv", location, v, 3, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform3uiv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniform4uiv(
    const WebGLUniformLocation* location,
    base::span<const GLuint> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLuint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform4uiv", location, v, 4, src_offset,
                                 src_length, &data, &length))
    return;

  ContextGL()->Uniform4uiv(location->Location(), length, data);
}

void WebGL2RenderingContextBase::uniformMatrix2fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() || !ValidateUniformMatrixParameters(
                             "uniformMatrix2fv", location, transpose, v, 4,
                             src_offset, src_length, &data, &length))
    return;
  ContextGL()->UniformMatrix2fv(location->Location(), length, transpose, data);
}

void WebGL2RenderingContextBase::uniformMatrix3fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() || !ValidateUniformMatrixParameters(
                             "uniformMatrix3fv", location, transpose, v, 9,
                             src_offset, src_length, &data, &length))
    return;
  ContextGL()->UniformMatrix3fv(location->Location(), length, transpose, data);
}

void WebGL2RenderingContextBase::uniformMatrix4fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> v,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() || !ValidateUniformMatrixParameters(
                             "uniformMatrix4fv", location, transpose, v, 16,
                             src_offset, src_length, &data, &length))
    return;
  ContextGL()->UniformMatrix4fv(location->Location(), length, transpose, data);
}

void WebGL2RenderingContextBase::uniformMatrix2x3fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> value,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() || !ValidateUniformMatrixParameters(
                             "uniformMatrix2x3fv", location, transpose, value,
                             6, src_offset, src_length, &data, &length))
    return;
  ContextGL()->UniformMatrix2x3fv(location->Location(), length, transpose,
                                  data);
}

void WebGL2RenderingContextBase::uniformMatrix3x2fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> value,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() || !ValidateUniformMatrixParameters(
                             "uniformMatrix3x2fv", location, transpose, value,
                             6, src_offset, src_length, &data, &length))
    return;
  ContextGL()->UniformMatrix3x2fv(location->Location(), length, transpose,
                                  data);
}

void WebGL2RenderingContextBase::uniformMatrix2x4fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> value,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() || !ValidateUniformMatrixParameters(
                             "uniformMatrix2x4fv", location, transpose, value,
                             8, src_offset, src_length, &data, &length))
    return;
  ContextGL()->UniformMatrix2x4fv(location->Location(), length, transpose,
                                  data);
}

void WebGL2RenderingContextBase::uniformMatrix4x2fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> value,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() || !ValidateUniformMatrixParameters(
                             "uniformMatrix4x2fv", location, transpose, value,
                             8, src_offset, src_length, &data, &length))
    return;
  ContextGL()->UniformMatrix4x2fv(location->Location(), length, transpose,
                                  data);
}

void WebGL2RenderingContextBase::uniformMatrix3x4fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> value,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() || !ValidateUniformMatrixParameters(
                             "uniformMatrix3x4fv", location, transpose, value,
                             12, src_offset, src_length, &data, &length))
    return;
  ContextGL()->UniformMatrix3x4fv(location->Location(), length, transpose,
                                  data);
}

void WebGL2RenderingContextBase::uniformMatrix4x3fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> value,
    GLuint src_offset,
    GLuint src_length) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() || !ValidateUniformMatrixParameters(
                             "uniformMatrix4x3fv", location, transpose, value,
                             12, src_offset, src_length, &data, &length))
    return;
  ContextGL()->UniformMatrix4x3fv(location->Location(), length, transpose,
                                  data);
}

void WebGL2RenderingContextBase::uniform1fv(
    const WebGLUniformLocation* location,
    base::span<const GLfloat> v) {
  WebGLRenderingContextBase::uniform1fv(location, v);
}

void WebGL2RenderingContextBase::uniform2fv(
    const WebGLUniformLocation* location,
    base::span<const GLfloat> v) {
  WebGLRenderingContextBase::uniform2fv(location, v);
}

void WebGL2RenderingContextBase::uniform3fv(
    const WebGLUniformLocation* location,
    base::span<const GLfloat> v) {
  WebGLRenderingContextBase::uniform3fv(location, v);
}

void WebGL2RenderingContextBase::uniform4fv(
    const WebGLUniformLocation* location,
    base::span<const GLfloat> v) {
  WebGLRenderingContextBase::uniform4fv(location, v);
}

void WebGL2RenderingContextBase::uniform1iv(
    const WebGLUniformLocation* location,
    base::span<const GLint> v) {
  WebGLRenderingContextBase::uniform1iv(location, v);
}

void WebGL2RenderingContextBase::uniform2iv(
    const WebGLUniformLocation* location,
    base::span<const GLint> v) {
  WebGLRenderingContextBase::uniform2iv(location, v);
}

void WebGL2RenderingContextBase::uniform3iv(
    const WebGLUniformLocation* location,
    base::span<const GLint> v) {
  WebGLRenderingContextBase::uniform3iv(location, v);
}

void WebGL2RenderingContextBase::uniform4iv(
    const WebGLUniformLocation* location,
    base::span<const GLint> v) {
  WebGLRenderingContextBase::uniform4iv(location, v);
}

void WebGL2RenderingContextBase::uniformMatrix2fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> v) {
  WebGLRenderingContextBase::uniformMatrix2fv(location, transpose, v);
}

void WebGL2RenderingContextBase::uniformMatrix3fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> v) {
  WebGLRenderingContextBase::uniformMatrix3fv(location, transpose, v);
}

void WebGL2RenderingContextBase::uniformMatrix4fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> v) {
  WebGLRenderingContextBase::uniformMatrix4fv(location, transpose, v);
}

void WebGL2RenderingContextBase::vertexAttribI4i(GLuint index,
                                                 GLint x,
                                                 GLint y,
                                                 GLint z,
                                                 GLint w) {
  if (isContextLost())
    return;
  ContextGL()->VertexAttribI4i(index, x, y, z, w);
  SetVertexAttribType(index, kInt32ArrayType);
}

void WebGL2RenderingContextBase::vertexAttribI4iv(GLuint index,
                                                  base::span<const GLint> v) {
  if (isContextLost())
    return;
  if (v.size() < 4) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttribI4iv", "invalid array");
    return;
  }
  ContextGL()->VertexAttribI4iv(index, v.data());
  SetVertexAttribType(index, kInt32ArrayType);
}

void WebGL2RenderingContextBase::vertexAttribI4ui(GLuint index,
                                                  GLuint x,
                                                  GLuint y,
                                                  GLuint z,
                                                  GLuint w) {
  if (isContextLost())
    return;
  ContextGL()->VertexAttribI4ui(index, x, y, z, w);
  SetVertexAttribType(index, kUint32ArrayType);
}

void WebGL2RenderingContextBase::vertexAttribI4uiv(GLuint index,
                                                   base::span<const GLuint> v) {
  if (isContextLost())
    return;
  if (v.size() < 4) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttribI4uiv", "invalid array");
    return;
  }
  ContextGL()->VertexAttribI4uiv(index, v.data());
  SetVertexAttribType(index, kUint32ArrayType);
}

void WebGL2RenderingContextBase::vertexAttribIPointer(GLuint index,
                                                      GLint size,
                                                      GLenum type,
                                                      GLsizei stride,
                                                      int64_t offset) {
  if (isContextLost())
    return;
  if (index >= max_vertex_attribs_) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttribIPointer",
                      "index out of range");
    return;
  }
  if (!ValidateValueFitNonNegInt32("vertexAttribIPointer", "offset", offset))
    return;
  if (!bound_array_buffer_ && offset != 0) {
    SynthesizeGLError(GL_INVALID_OPERATION, "vertexAttribIPointer",
                      "no ARRAY_BUFFER is bound and offset is non-zero");
    return;
  }

  bound_vertex_array_object_->SetArrayBufferForAttrib(index,
                                                      bound_array_buffer_);
  ContextGL()->VertexAttribIPointer(
      index, size, type, stride,
      reinterpret_cast<void*>(static_cast<intptr_t>(offset)));
}

/* Writing to the drawing buffer */
void WebGL2RenderingContextBase::vertexAttribDivisor(GLuint index,
                                                     GLuint divisor) {
  if (isContextLost())
    return;

  if (index >= max_vertex_attribs_) {
    SynthesizeGLError(GL_INVALID_VALUE, "vertexAttribDivisor",
                      "index out of range");
    return;
  }

  ContextGL()->VertexAttribDivisorANGLE(index, divisor);
}

void WebGL2RenderingContextBase::drawArraysInstanced(GLenum mode,
                                                     GLint first,
                                                     GLsizei count,
                                                     GLsizei instance_count) {
  if (!ValidateDrawArrays("drawArraysInstanced"))
    return;

  DrawWrapper("drawArraysInstanced",
              CanvasPerformanceMonitor::DrawType::kDrawArrays, [&]() {
                ContextGL()->DrawArraysInstancedANGLE(mode, first, count,
                                                      instance_count);
              });
}

void WebGL2RenderingContextBase::drawElementsInstanced(GLenum mode,
                                                       GLsizei count,
                                                       GLenum type,
                                                       int64_t offset,
                                                       GLsizei instance_count) {
  if (!ValidateDrawElements("drawElementsInstanced", type, offset))
    return;

  DrawWrapper("drawElementsInstanced",
              CanvasPerformanceMonitor::DrawType::kDrawElements, [&]() {
                ContextGL()->DrawElementsInstancedANGLE(
                    mode, count, type,
                    reinterpret_cast<void*>(static_cast<intptr_t>(offset)),
                    instance_count);
              });
}

void WebGL2RenderingContextBase::drawRangeElements(GLenum mode,
                                                   GLuint start,
                                                   GLuint end,
                                                   GLsizei count,
                                                   GLenum type,
                                                   int64_t offset) {
  if (!ValidateDrawElements("drawRangeElements", type, offset))
    return;

  DrawWrapper("drawRangeElements",
              CanvasPerformanceMonitor::DrawType::kDrawElements, [&]() {
                ContextGL()->DrawRangeElements(
                    mode, start, end, count, type,
                    reinterpret_cast<void*>(static_cast<intptr_t>(offset)));
              });
}

void WebGL2RenderingContextBase::drawBuffers(const Vector<GLenum>& buffers) {
  if (isContextLost())
    return;

  for (const auto& buf : buffers) {
    switch (buf) {
      case GL_NONE:
      case GL_BACK:
      case GL_COLOR_ATTACHMENT0:
        break;
      default:
        if (buf > GL_COLOR_ATTACHMENT0 &&
            buf < static_cast<GLenum>(GL_COLOR_ATTACHMENT0 +
                                      MaxColorAttachments())) {
          break;
        }
        SynthesizeGLError(GL_INVALID_ENUM, "drawBuffers", "invalid buffer");
        return;
    }
  }
  if (!framebuffer_binding_) {
    if (buffers.size() != 1) {
      SynthesizeGLError(GL_INVALID_OPERATION, "drawBuffers",
                        "the number of buffers is not 1");
      return;
    }
    if (buffers[0] != GL_BACK && buffers[0] != GL_NONE) {
      SynthesizeGLError(GL_INVALID_OPERATION, "drawBuffers", "BACK or NONE");
      return;
    }
    // Because the backbuffer is simulated on all current WebKit ports, we need
    // to change BACK to COLOR_ATTACHMENT0.
    GLenum value = (buffers[0] == GL_BACK) ? GL_COLOR_ATTACHMENT0 : GL_NONE;
    ContextGL()->DrawBuffersEXT(1, &value);
    SetBackDrawBuffer(buffers[0]);
  } else {
    const GLint n = base::checked_cast<GLint>(buffers.size());
    if (n > MaxDrawBuffers()) {
      SynthesizeGLError(GL_INVALID_VALUE, "drawBuffers",
                        "more than max draw buffers");
      return;
    }
    for (GLsizei i = 0; i < n; ++i) {
      if (buffers[i] != GL_NONE &&
          buffers[i] != static_cast<GLenum>(GL_COLOR_ATTACHMENT0_EXT + i)) {
        SynthesizeGLError(GL_INVALID_OPERATION, "drawBuffers",
                          "COLOR_ATTACHMENTi_EXT or NONE");
        return;
      }
    }
    framebuffer_binding_->DrawBuffers(buffers);
  }
}

bool WebGL2RenderingContextBase::ValidateClearBuffer(const char* function_name,
                                                     GLenum buffer,
                                                     size_t size,
                                                     GLuint src_offset) {
  base::CheckedNumeric<GLsizei> checked_size(size);
  checked_size -= src_offset;
  if (!checked_size.IsValid()) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      "invalid array size / srcOffset");
    return false;
  }
  switch (buffer) {
    case GL_COLOR:
      if (checked_size.ValueOrDie() < 4) {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "invalid array size / srcOffset");
        return false;
      }
      break;
    case GL_DEPTH:
    case GL_STENCIL:
      if (checked_size.ValueOrDie() < 1) {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "invalid array size / srcOffset");
        return false;
      }
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid buffer");
      return false;
  }
  return true;
}

void WebGL2RenderingContextBase::GetCurrentUnpackState(TexImageParams& params) {
  WebGLRenderingContextBase::GetCurrentUnpackState(params);
  params.unpack_skip_pixels = unpack_skip_pixels_;
  params.unpack_skip_rows = unpack_skip_rows_;
  params.unpack_skip_images = unpack_skip_images_;
  params.unpack_image_height = unpack_image_height_;
}

WebGLTexture* WebGL2RenderingContextBase::ValidateTexImageBinding(
    const TexImageParams& params) {
  const char* func_name = GetTexImageFunctionName(params.function_id);
  if (params.function_id == kTexImage3D || params.function_id == kTexSubImage3D)
    return ValidateTexture3DBinding(func_name, params.target, true);
  return ValidateTexture2DBinding(func_name, params.target, true);
}

void WebGL2RenderingContextBase::clearBufferiv(GLenum buffer,
                                               GLint drawbuffer,
                                               base::span<const GLint> value,
                                               GLuint src_offset) {
  if (isContextLost() ||
      !ValidateClearBuffer("clearBufferiv", buffer, value.size(), src_offset)) {
    return;
  }

  ScopedRGBEmulationColorMask emulation_color_mask(this, color_mask_.data(),
                                                   drawing_buffer_.get());

  // Flush any pending implicit clears. This cannot be done after the
  // user-requested clearBuffer call because of scissor test side effects.
  ClearIfComposited(kClearCallerDrawOrClear);
  // SAFETY: Already validated by ValidateClearBuffer()
  ContextGL()->ClearBufferiv(buffer, drawbuffer,
                             value.subspan(src_offset).data());
}

void WebGL2RenderingContextBase::clearBufferuiv(GLenum buffer,
                                                GLint drawbuffer,
                                                base::span<const GLuint> value,
                                                GLuint src_offset) {
  if (isContextLost() || !ValidateClearBuffer("clearBufferuiv", buffer,
                                              value.size(), src_offset)) {
    return;
  }

  ScopedRGBEmulationColorMask emulation_color_mask(this, color_mask_.data(),
                                                   drawing_buffer_.get());

  // This call is not applicable to the default framebuffer attachments
  // as they cannot have UINT type. Ignore any pending implicit clears.

  ContextGL()->ClearBufferuiv(buffer, drawbuffer,
                              value.subspan(src_offset).data());
}

void WebGL2RenderingContextBase::clearBufferfv(GLenum buffer,
                                               GLint drawbuffer,
                                               base::span<const GLfloat> value,
                                               GLuint src_offset) {
  if (isContextLost() ||
      !ValidateClearBuffer("clearBufferfv", buffer, value.size(), src_offset)) {
    return;
  }

  // As of this writing the default back buffer will always have an
  // RGB(A)/UNSIGNED_BYTE color attachment, so only clearBufferfv can
  // be used with it and consequently the emulation should only be
  // needed here. However, as support for extended color spaces is
  // added, the type of the back buffer might change, so do the
  // emulation for all clearBuffer entry points instead of just here.
  ScopedRGBEmulationColorMask emulation_color_mask(this, color_mask_.data(),
                                                   drawing_buffer_.get());

  // Flush any pending implicit clears. This cannot be done after the
  // user-requested clearBuffer call because of scissor test side effects.
  ClearIfComposited(kClearCallerDrawOrClear);

  ContextGL()->ClearBufferfv(buffer, drawbuffer,
                             value.subspan(src_offset).data());

  // This might have been used to clear the color buffer of the default back
  // buffer. Notification is required to update the canvas.
  MarkContextChanged(kCanvasChanged,
                     CanvasPerformanceMonitor::DrawType::kOther);
}

void WebGL2RenderingContextBase::clearBufferfi(GLenum buffer,
                                               GLint drawbuffer,
                                               GLfloat depth,
                                               GLint stencil) {
  if (isContextLost())
    return;

  // Flush any pending implicit clears. This cannot be done after the
  // user-requested clearBuffer call because of scissor test side effects.
  ClearIfComposited(kClearCallerDrawOrClear);

  ContextGL()->ClearBufferfi(buffer, drawbuffer, depth, stencil);
}

WebGLQuery* WebGL2RenderingContextBase::createQuery() {
  if (isContextLost())
    return nullptr;
  return MakeGarbageCollected<WebGLQuery>(this);
}

void WebGL2RenderingContextBase::deleteQuery(WebGLQuery* query) {
  if (isContextLost() || !query)
    return;

  if (current_boolean_occlusion_query_ == query) {
    ContextGL()->EndQueryEXT(current_boolean_occlusion_query_->GetTarget());
    current_boolean_occlusion_query_ = nullptr;
  }

  if (current_transform_feedback_primitives_written_query_ == query) {
    ContextGL()->EndQueryEXT(GL_TRANSFORM_FEEDBACK_PRIMITIVES_WRITTEN);
    current_transform_feedback_primitives_written_query_ = nullptr;
  }

  if (current_elapsed_query_ == query) {
    ContextGL()->EndQueryEXT(current_elapsed_query_->GetTarget());
    current_elapsed_query_ = nullptr;
  }

  DeleteObject(query);
}

bool WebGL2RenderingContextBase::isQuery(WebGLQuery* query) {
  if (!query || isContextLost() || !query->Validate(ContextGroup(), this))
    return false;

  if (query->MarkedForDeletion())
    return false;

  return ContextGL()->IsQueryEXT(query->Object());
}

void WebGL2RenderingContextBase::beginQuery(GLenum target, WebGLQuery* query) {
  if (!ValidateWebGLObject("beginQuery", query))
    return;

  if (query->GetTarget() && query->GetTarget() != target) {
    SynthesizeGLError(GL_INVALID_OPERATION, "beginQuery",
                      "query type does not match target");
    return;
  }

  switch (target) {
    case GL_ANY_SAMPLES_PASSED:
    case GL_ANY_SAMPLES_PASSED_CONSERVATIVE: {
      if (current_boolean_occlusion_query_) {
        SynthesizeGLError(GL_INVALID_OPERATION, "beginQuery",
                          "a query is already active for target");
        return;
      }
      current_boolean_occlusion_query_ = query;
    } break;
    case GL_TRANSFORM_FEEDBACK_PRIMITIVES_WRITTEN: {
      if (current_transform_feedback_primitives_written_query_) {
        SynthesizeGLError(GL_INVALID_OPERATION, "beginQuery",
                          "a query is already active for target");
        return;
      }
      current_transform_feedback_primitives_written_query_ = query;
    } break;
    case GL_TIME_ELAPSED_EXT: {
      if (!ExtensionEnabled(kEXTDisjointTimerQueryWebGL2Name)) {
        SynthesizeGLError(GL_INVALID_ENUM, "beginQuery", "invalid target");
        return;
      }
      if (current_elapsed_query_) {
        SynthesizeGLError(GL_INVALID_OPERATION, "beginQuery",
                          "a query is already active for target");
        return;
      }
      current_elapsed_query_ = query;
    } break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "beginQuery", "invalid target");
      return;
  }

  if (!query->GetTarget())
    query->SetTarget(target);

  ContextGL()->BeginQueryEXT(target, query->Object());
}

void WebGL2RenderingContextBase::endQuery(GLenum target) {
  if (isContextLost())
    return;

  switch (target) {
    case GL_ANY_SAMPLES_PASSED:
    case GL_ANY_SAMPLES_PASSED_CONSERVA
"""


```