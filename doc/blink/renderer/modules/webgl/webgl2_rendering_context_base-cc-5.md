Response:
My thinking process to analyze the provided WebGL2RenderingContextBase code snippet goes through these stages:

1. **Identify the core purpose:** The filename `webgl2_rendering_context_base.cc` immediately tells me this is part of the WebGL 2 implementation within the Chromium Blink engine. The "Base" suffix suggests it's a foundational class, likely containing common logic shared across different WebGL 2 contexts or implementations.

2. **Scan for key function names:** I quickly scan the code for prominent function names. Names like `getActiveUniformBlockParameter`, `getActiveUniformBlockName`, `uniformBlockBinding`, `createVertexArray`, `deleteVertexArray`, `bindVertexArray`, `bindFramebuffer`, `deleteFramebuffer`, `getParameter`, `ValidateCapability`, `ValidateBufferTarget`, `ValidateFramebufferTarget`, `readPixels`, and `getFramebufferAttachmentParameter` stand out. These names directly hint at the functionality provided by this class.

3. **Group related functions:** I start grouping functions based on their prefixes or related concepts. For example:
    * `getActiveUniformBlockParameter`, `getActiveUniformBlockName`, `uniformBlockBinding` are clearly related to uniform blocks in shaders.
    * `createVertexArray`, `deleteVertexArray`, `bindVertexArray`, `isVertexArray` are related to Vertex Array Objects (VAOs).
    * `bindFramebuffer`, `deleteFramebuffer`, `getFramebufferAttachmentParameter` are related to framebuffers.
    * `getParameter` retrieves various WebGL state parameters.
    * `Validate...` functions are for input validation.

4. **Analyze function logic:** I delve into the logic of individual functions to understand their specific actions. I pay attention to:
    * **Input parameters:** What data does the function take?
    * **Internal operations:** What OpenGL (ContextGL()) calls are being made?  What internal state is being modified (member variables)?
    * **Error handling:**  Are there calls to `SynthesizeGLError`? What conditions trigger errors?
    * **Return values:** What does the function return?  How is the return value used (e.g., `ScriptValue`, `String`, `bool`)?

5. **Connect to WebGL concepts:**  I relate the functions to core WebGL 2 concepts. For example:
    * Uniform blocks allow grouping shader uniforms for more efficient management.
    * VAOs encapsulate vertex attribute state.
    * Framebuffers are used for off-screen rendering.
    * `getParameter` provides information about the WebGL implementation and current state.

6. **Identify relationships to JavaScript/HTML/CSS:**  I consider how these WebGL functions are exposed to JavaScript and how they interact with the web page:
    * WebGL functions are called directly from JavaScript using the `WebGL2RenderingContext` interface.
    * Shader code (GLSL) is written as strings in JavaScript and passed to WebGL. Uniforms are variables within these shaders.
    * HTML `<canvas>` elements provide the drawing surface for WebGL.
    * CSS affects the styling of the canvas element, but not directly the WebGL rendering itself (though CSS transforms on the canvas will affect the WebGL viewport).

7. **Infer logical flows and common errors:**  Based on the function logic and error handling, I can infer common usage patterns and potential pitfalls. For example:
    * Incorrect uniform block indices will cause errors.
    * Deleting a bound VAO can lead to unexpected behavior.
    * Trying to bind a buffer to an incompatible target will fail.
    * Passing incorrect data types to `readPixels` will cause errors.

8. **Consider the debugging perspective:** I think about how a developer might end up in this code. Setting breakpoints within these functions during WebGL debugging is a key scenario. The function names themselves often appear in error messages or stack traces.

9. **Synthesize and structure the findings:** Finally, I organize my analysis into clear categories like "Functionality," "JavaScript/HTML/CSS Relationship," "Logical Inference," "Common Errors," and "Debugging."  I use examples to illustrate the concepts. Since this is part 6 of 7, I focus on summarizing the functionality covered in this specific chunk of code.

**Self-Correction/Refinement during the process:**

* Initially, I might just list function names. Then I realize I need to group them and explain *what* they do.
* I might focus too much on low-level OpenGL details. I then shift to explaining the *purpose* of these calls in the context of WebGL.
* I ensure I explicitly link the C++ code to the JavaScript API that developers actually use.
* I double-check that my examples are accurate and easy to understand.
* Because the prompt mentions it's part 6 of 7, I make sure my summary reflects the specific functionality covered in this *section*, rather than a general overview of the entire class.

By following these steps, I can generate a comprehensive and informative analysis of the provided WebGL 2 source code snippet.
这是 `blink/renderer/modules/webgl/webgl2_rendering_context_base.cc` 文件的第 6 部分（共 7 部分），主要负责实现 WebGL 2 API 中与 **Uniform Buffer Objects (UBOs)**, **Vertex Array Objects (VAOs)**, **Framebuffers (FBOs)** 相关的部分功能，以及一些 **状态查询** 和 **参数验证** 的功能。

让我们详细列举一下它的功能：

**1. Uniform Buffer Objects (UBOs) 相关功能:**

* **`ValidateUniformBlockIndex`:**  验证给定的 uniform block index 是否在 program 中有效。
    * **功能:**  检查 `uniform_block_index` 是否小于 program 中激活的 uniform block 数量。
    * **与 Javascript 关系:** 当 Javascript 代码调用 `gl.getActiveUniformBlockParameter()` 或 `gl.getActiveUniformBlockName()` 等方法时，这个函数会被调用来验证传入的 uniform block index 的有效性。
    * **假设输入与输出:**
        * **输入:** `program` (WebGLProgram 对象), `uniform_block_index` (GLuint 类型，例如 0)。假设 program 包含 2 个 active uniform blocks。
        * **输出:** 如果 `uniform_block_index < 2`，则返回 `true`，否则返回 `false`。如果 index 无效，还会调用 `SynthesizeGLError` 生成 WebGL 错误。
* **`getActiveUniformBlockParameter`:** 获取 program 中特定 uniform block 的参数信息。
    * **功能:**  根据传入的 `pname` (参数名)，返回 uniform block 的绑定点、数据大小、激活的 uniform 数量、激活的 uniform 索引、是否被顶点/片元着色器引用等信息。
    * **与 Javascript 关系:**  对应 Javascript API 的 `gl.getActiveUniformBlockParameter()` 方法。返回的值会以 Javascript 可以理解的形式（例如数字、`Uint32Array` 对象）返回。
    * **假设输入与输出:**
        * **输入:** `program`, `uniform_block_index` (例如 0), `pname` (例如 `GL_UNIFORM_BLOCK_BINDING`)。假设该 uniform block 的绑定点是 1。
        * **输出:** 返回一个 `ScriptValue`，其内部包含数字 1。如果 `pname` 是 `GL_UNIFORM_BLOCK_ACTIVE_UNIFORM_INDICES`，则返回包含 uniform 索引的 `DOMUint32Array`。
* **`getActiveUniformBlockName`:** 获取 program 中特定 uniform block 的名称。
    * **功能:**  返回 uniform block 在 GLSL 代码中定义的名称。
    * **与 Javascript 关系:** 对应 Javascript API 的 `gl.getActiveUniformBlockName()` 方法。返回的名称是一个 Javascript 字符串。
    * **假设输入与输出:**
        * **输入:** `program`, `uniform_block_index` (例如 0)。假设该 uniform block 在 GLSL 中被命名为 "Matrices"。
        * **输出:** 返回 Javascript 字符串 "Matrices"。
* **`uniformBlockBinding`:**  将 program 中特定 uniform block 的索引绑定到特定的绑定点。
    * **功能:**  允许开发者手动控制 uniform block 与 uniform buffer binding points 的对应关系。
    * **与 Javascript 关系:** 对应 Javascript API 的 `gl.uniformBlockBinding()` 方法。
    * **假设输入与输出:**
        * **输入:** `program`, `uniform_block_index` (例如 0), `uniform_block_binding` (例如 2)。
        * **输出:**  无返回值。但会更新 program 内部状态，将索引为 0 的 uniform block 绑定到 binding point 2。

**2. Vertex Array Objects (VAOs) 相关功能:**

* **`createVertexArray`:** 创建一个新的 WebGLVertexArrayObject 对象。
    * **功能:**  分配一个新的 VAO 对象，用于存储顶点属性的状态。
    * **与 Javascript 关系:** 对应 Javascript API 的 `gl.createVertexArray()` 方法。返回一个 Javascript 的 `WebGLVertexArrayObject` 对象。
    * **假设输入与输出:**
        * **输入:** 无。
        * **输出:** 返回一个新的 `WebGLVertexArrayObject` 对象。
* **`deleteVertexArray`:** 删除指定的 WebGLVertexArrayObject 对象。
    * **功能:**  释放 VAO 相关的 OpenGL 资源。
    * **与 Javascript 关系:** 对应 Javascript API 的 `gl.deleteVertexArray()` 方法。
    * **假设输入与输出:**
        * **输入:** `vertex_array` (一个 `WebGLVertexArrayObject` 对象)。
        * **输出:** 无返回值。如果 VAO 正在绑定，则会先解绑。
* **`isVertexArray`:**  检查给定的对象是否是一个有效的 WebGLVertexArrayObject 对象。
    * **功能:**  验证对象是否是属于当前上下文且未被删除的 VAO。
    * **与 Javascript 关系:** 对应 Javascript API 的 `gl.isVertexArray()` 方法。
    * **假设输入与输出:**
        * **输入:** `vertex_array` (一个对象，可能是 `WebGLVertexArrayObject` 或其他类型)。
        * **输出:** 如果 `vertex_array` 是一个有效的 VAO，则返回 `true`，否则返回 `false`。
* **`bindVertexArray`:** 绑定一个 WebGLVertexArrayObject 对象到当前上下文。
    * **功能:**  激活指定的 VAO，后续的顶点属性设置会应用到这个 VAO 上。绑定 `null` 会解绑当前的 VAO。
    * **与 Javascript 关系:** 对应 Javascript API 的 `gl.bindVertexArray()` 方法。
    * **假设输入与输出:**
        * **输入:** `vertex_array` (一个 `WebGLVertexArrayObject` 对象或 `null`)。
        * **输出:** 无返回值。如果传入一个有效的 VAO，则该 VAO 成为当前绑定的 VAO。

**3. Framebuffers (FBOs) 相关功能:**

* **`bindFramebuffer`:** 绑定一个 WebGLFramebuffer 对象到指定的 framebuffer 绑定点。
    * **功能:**  允许开发者切换渲染目标到指定的 FBO（用于离屏渲染）或默认的 framebuffer。
    * **与 Javascript 关系:** 对应 Javascript API 的 `gl.bindFramebuffer()` 方法。
    * **假设输入与输出:**
        * **输入:** `target` (`GL_DRAW_FRAMEBUFFER`, `GL_READ_FRAMEBUFFER`, 或 `GL_FRAMEBUFFER`), `buffer` (一个 `WebGLFramebuffer` 对象或 `null`)。
        * **输出:** 无返回值。更新内部状态，使指定的 framebuffer 成为指定绑定点的当前 framebuffer。
* **`deleteFramebuffer`:** 删除指定的 WebGLFramebuffer 对象。
    * **功能:**  释放 FBO 相关的 OpenGL 资源。
    * **与 Javascript 关系:** 对应 Javascript API 的 `gl.deleteFramebuffer()` 方法。
    * **用户常见错误:** 尝试删除一个 opaque 的 framebuffer (通常是浏览器内部创建的，例如用于 canvas 的默认 framebuffer)。
    * **假设输入与输出:**
        * **输入:** `framebuffer` (一个 `WebGLFramebuffer` 对象)。
        * **输出:** 无返回值。如果 FBO 正在绑定，则会解绑并重新绑定默认的 framebuffer。
* **`getFramebufferAttachmentParameter`:** 获取 framebuffer 附件的参数信息。
    * **功能:**  查询 framebuffer 附件（例如颜色缓冲、深度缓冲、模板缓冲）的类型、大小等信息。
    * **与 Javascript 关系:** 对应 Javascript API 的 `gl.getFramebufferAttachmentParameter()` 方法。
    * **假设输入与输出:**
        * **输入:** `target` (`GL_FRAMEBUFFER`, `GL_READ_FRAMEBUFFER`, `GL_DRAW_FRAMEBUFFER`), `attachment` (`GL_COLOR_ATTACHMENT0`, `GL_DEPTH_ATTACHMENT` 等), `pname` (`GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE`, `GL_FRAMEBUFFER_ATTACHMENT_RED_SIZE` 等)。
        * **输出:** 返回一个 `ScriptValue`，其内部包含查询到的参数值。

**4. 状态查询功能:**

* **`getParameter`:** 获取 WebGL 上下文的各种状态参数。
    * **功能:**  返回例如着色器语言版本、WebGL 版本、绑定的 buffer、framebuffer、纹理等信息。
    * **与 Javascript 关系:** 对应 Javascript API 的 `gl.getParameter()` 方法。
    * **假设输入与输出:**
        * **输入:** `pname` (例如 `GL_MAX_TEXTURE_SIZE`, `GL_DRAW_FRAMEBUFFER_BINDING`)。
        * **输出:** 返回一个 `ScriptValue`，其内部包含查询到的参数值。例如，如果 `pname` 是 `GL_DRAW_FRAMEBUFFER_BINDING`，且当前绑定了一个 framebuffer，则返回该 framebuffer 对象。
* **`GetInt64Parameter`:**  获取 64 位整数类型的 WebGL 参数。
* **`GetFramebufferBinding`:** 获取指定 framebuffer 绑定点的当前 framebuffer 对象。
* **`GetReadFramebufferBinding`:** 获取 `GL_READ_FRAMEBUFFER` 绑定点的当前 framebuffer 对象。

**5. 参数验证功能:**

* **`ValidateCapability`:** 验证给定的 capability (例如 `GL_RASTERIZER_DISCARD`) 是否被支持或启用。
* **`ValidateBufferTargetCompatibility`:** 验证指定的 buffer 是否可以绑定到给定的 target。例如，一个 `ELEMENT_ARRAY_BUFFER` 不应该被绑定到 `ARRAY_BUFFER`。
* **`ValidateBufferTarget`:** 验证给定的 buffer target 是否是有效的。
* **`ValidateAndUpdateBufferBindTarget`:** 验证 buffer target 的有效性，并更新内部状态，记录 buffer 的绑定情况。
* **`ValidateBufferBaseTarget`:** 验证用于 `bindBufferBase` 或 `bindBufferRange` 的 target 是否有效。
* **`ValidateAndUpdateBufferBindBaseTarget`:** 验证 `bindBufferBase` 或 `bindBufferRange` 的 target 有效性并更新内部状态。
* **`ValidateFramebufferTarget`:** 验证 framebuffer target 是否有效 (`GL_FRAMEBUFFER`, `GL_READ_FRAMEBUFFER`, `GL_DRAW_FRAMEBUFFER`).
* **`ValidateReadPixelsFormatAndType`:** 验证 `readPixels` 函数的 format 和 type 参数的组合是否有效，并检查提供的 `ArrayBufferView` 类型是否匹配。
* **`ValidateGetFramebufferAttachmentParameterFunc`:** 验证 `getFramebufferAttachmentParameter` 函数的 target 和 attachment 参数是否有效。

**与 Javascript, HTML, CSS 的关系举例:**

* **Javascript:**  所有这些 C++ 函数最终都对应着 Javascript 中 `WebGL2RenderingContext` 对象的方法。例如，Javascript 中调用 `gl.uniformBlockBinding(program, 0, 2)` 会最终调用到 C++ 的 `WebGL2RenderingContextBase::uniformBlockBinding(program, 0, 2)`。
* **HTML:**  WebGL 内容渲染在 HTML 的 `<canvas>` 元素上。Javascript 代码获取 `<canvas>` 元素的 WebGL2 上下文，然后调用这些 WebGL API 方法进行图形渲染。
* **CSS:** CSS 可以影响 `<canvas>` 元素的大小和布局，但不会直接影响 WebGL 的内部状态或渲染逻辑。

**逻辑推理的假设输入与输出:**

* **假设输入:** Javascript 调用 `gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, myIndexBuffer)`.
* **逻辑推理:**  `ValidateAndUpdateBufferBindTarget` 函数会被调用，检查 `myIndexBuffer` 是否之前绑定到了其他不兼容的 target (例如 `ARRAY_BUFFER`)。如果兼容，则将 `myIndexBuffer` 绑定到当前 VAO 的 `ELEMENT_ARRAY_BUFFER` 槽位。
* **输出:**  内部状态更新，记录 `myIndexBuffer` 已绑定为元素数组 buffer。

**用户或编程常见的使用错误举例:**

* **尝试在没有绑定 VAO 的情况下设置顶点属性:** 用户可能忘记先调用 `gl.bindVertexArray()` 绑定一个 VAO，就直接调用 `gl.vertexAttribPointer()` 等函数设置顶点属性。这会导致顶点属性设置丢失或应用到错误的 VAO 上。
* **删除正在使用的 Framebuffer:** 用户可能在仍然将一个 framebuffer 作为渲染目标的情况下调用 `gl.deleteFramebuffer()`。虽然 WebGL 实现会处理这种情况，但这仍然是一个逻辑错误，可能导致渲染结果异常。
* **`readPixels` 时提供的 ArrayBufferView 类型与 format/type 不匹配:**  例如，使用 `gl.RGBA` 和 `gl.UNSIGNED_BYTE` 读取像素，但提供的却是 `Float32Array`。`ValidateReadPixelsFormatAndType` 会检测到这个错误并生成 WebGL 错误。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在 HTML 中创建了一个 `<canvas>` 元素。**
2. **Javascript 代码获取该 canvas 的 WebGL2 渲染上下文：** `const gl = canvas.getContext('webgl2');`
3. **用户编写 Javascript 代码，调用 WebGL2 API 中的方法，例如：**
   * `gl.createVertexArray()`
   * `gl.bindVertexArray(vao)`
   * `gl.createBuffer()`
   * `gl.bindBuffer(gl.ARRAY_BUFFER, buffer)`
   * `gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW)`
   * `gl.vertexAttribPointer(...)`
   * `gl.createProgram()`
   * `gl.attachShader(...)`
   * `gl.linkProgram(program)`
   * `gl.createUniformBlock(...)`
   * `gl.getActiveUniformBlockParameter(program, ...)`
   * `gl.bindFramebuffer(gl.FRAMEBUFFER, fbo)`
   * `gl.drawArrays(...)`
4. **当这些 Javascript WebGL API 方法被调用时，Blink 引擎会将这些调用转发到对应的 C++ 实现，也就是 `webgl2_rendering_context_base.cc` 文件中的函数。**
5. **在 Chrome 开发者工具中，可以设置断点在这个文件中的特定函数上，例如 `WebGL2RenderingContextBase::bindVertexArray`，来观察代码的执行流程和 WebGL 状态。** 错误信息或性能瓶颈通常能引导开发者查看这些底层实现。

**归纳一下它的功能 (第 6 部分):**

这部分 `webgl2_rendering_context_base.cc` 的核心功能是实现了 WebGL 2 API 中与 **Uniform Buffer Objects (UBOs)**, **Vertex Array Objects (VAOs)**, 和 **Framebuffers (FBOs)** 的创建、绑定、删除以及信息查询等关键操作。此外，它还包含了大量的参数验证逻辑，确保 WebGL API 的正确使用，并提供必要的错误提示。这些功能是构建复杂 WebGL 2 应用的基础，例如管理着色器中的 uniform 数据，高效地切换顶点数据配置，以及实现离屏渲染和后处理效果。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl2_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共7部分，请归纳一下它的功能

"""
");
    return false;
  }
  GLint active_uniform_blocks = 0;
  ContextGL()->GetProgramiv(ObjectOrZero(program), GL_ACTIVE_UNIFORM_BLOCKS,
                            &active_uniform_blocks);
  if (block_index >= static_cast<GLuint>(active_uniform_blocks)) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      "invalid uniform block index");
    return false;
  }
  return true;
}

ScriptValue WebGL2RenderingContextBase::getActiveUniformBlockParameter(
    ScriptState* script_state,
    WebGLProgram* program,
    GLuint uniform_block_index,
    GLenum pname) {
  if (!ValidateWebGLProgramOrShader("getActiveUniformBlockParameter", program))
    return ScriptValue::CreateNull(script_state->GetIsolate());

  if (!ValidateUniformBlockIndex("getActiveUniformBlockParameter", program,
                                 uniform_block_index))
    return ScriptValue::CreateNull(script_state->GetIsolate());

  switch (pname) {
    case GL_UNIFORM_BLOCK_BINDING:
    case GL_UNIFORM_BLOCK_DATA_SIZE:
    case GL_UNIFORM_BLOCK_ACTIVE_UNIFORMS: {
      GLint int_value = 0;
      ContextGL()->GetActiveUniformBlockiv(
          ObjectOrZero(program), uniform_block_index, pname, &int_value);
      return WebGLAny(script_state, static_cast<unsigned>(int_value));
    }
    case GL_UNIFORM_BLOCK_ACTIVE_UNIFORM_INDICES: {
      GLint uniform_count = 0;
      ContextGL()->GetActiveUniformBlockiv(
          ObjectOrZero(program), uniform_block_index,
          GL_UNIFORM_BLOCK_ACTIVE_UNIFORMS, &uniform_count);

      Vector<GLint> indices(uniform_count);
      ContextGL()->GetActiveUniformBlockiv(
          ObjectOrZero(program), uniform_block_index, pname, indices.data());
      // SAFETY: conversion from GLint to uint32_t doesn't change size.
      static_assert(sizeof(GLint) == sizeof(uint32_t));
      auto indices_span = UNSAFE_BUFFERS(base::span<uint32_t>(
          reinterpret_cast<uint32_t*>(indices.data()), indices.size()));
      return WebGLAny(script_state, DOMUint32Array::Create(indices_span));
    }
    case GL_UNIFORM_BLOCK_REFERENCED_BY_VERTEX_SHADER:
    case GL_UNIFORM_BLOCK_REFERENCED_BY_FRAGMENT_SHADER: {
      GLint bool_value = 0;
      ContextGL()->GetActiveUniformBlockiv(
          ObjectOrZero(program), uniform_block_index, pname, &bool_value);
      return WebGLAny(script_state, static_cast<bool>(bool_value));
    }
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getActiveUniformBlockParameter",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

String WebGL2RenderingContextBase::getActiveUniformBlockName(
    WebGLProgram* program,
    GLuint uniform_block_index) {
  if (!ValidateWebGLProgramOrShader("getActiveUniformBlockName", program))
    return String();

  if (!ValidateUniformBlockIndex("getActiveUniformBlockName", program,
                                 uniform_block_index))
    return String();

  GLint max_name_length = -1;
  ContextGL()->GetProgramiv(ObjectOrZero(program),
                            GL_ACTIVE_UNIFORM_BLOCK_MAX_NAME_LENGTH,
                            &max_name_length);
  if (max_name_length <= 0) {
    // This state indicates that there are no active uniform blocks
    SynthesizeGLError(GL_INVALID_VALUE, "getActiveUniformBlockName",
                      "invalid uniform block index");
    return String();
  }
  auto name = base::HeapArray<GLchar>::WithSize(max_name_length);

  GLsizei length = 0;
  ContextGL()->GetActiveUniformBlockName(ObjectOrZero(program),
                                         uniform_block_index, max_name_length,
                                         &length, name.data());

  if (length <= 0)
    return String();
  return String(base::span(name).first(static_cast<uint32_t>(length)));
}

void WebGL2RenderingContextBase::uniformBlockBinding(
    WebGLProgram* program,
    GLuint uniform_block_index,
    GLuint uniform_block_binding) {
  if (!ValidateWebGLProgramOrShader("uniformBlockBinding", program))
    return;

  if (!ValidateUniformBlockIndex("uniformBlockBinding", program,
                                 uniform_block_index))
    return;

  ContextGL()->UniformBlockBinding(ObjectOrZero(program), uniform_block_index,
                                   uniform_block_binding);
}

WebGLVertexArrayObject* WebGL2RenderingContextBase::createVertexArray() {
  if (isContextLost())
    return nullptr;

  return MakeGarbageCollected<WebGLVertexArrayObject>(
      this, WebGLVertexArrayObjectBase::kVaoTypeUser);
}

void WebGL2RenderingContextBase::deleteVertexArray(
    WebGLVertexArrayObject* vertex_array) {
  // ValidateWebGLObject generates an error if the object has already been
  // deleted, so we must replicate most of its checks here.
  if (isContextLost() || !vertex_array)
    return;
  if (!vertex_array->Validate(ContextGroup(), this)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "deleteVertexArray",
                      "object does not belong to this context");
    return;
  }
  if (vertex_array->MarkedForDeletion())
    return;

  if (!vertex_array->IsDefaultObject() &&
      vertex_array == bound_vertex_array_object_)
    SetBoundVertexArrayObject(nullptr);

  vertex_array->DeleteObject(ContextGL());
}

bool WebGL2RenderingContextBase::isVertexArray(
    WebGLVertexArrayObject* vertex_array) {
  if (isContextLost() || !vertex_array ||
      !vertex_array->Validate(ContextGroup(), this))
    return false;

  if (!vertex_array->HasEverBeenBound())
    return false;
  if (vertex_array->MarkedForDeletion())
    return false;

  return ContextGL()->IsVertexArrayOES(vertex_array->Object());
}

void WebGL2RenderingContextBase::bindVertexArray(
    WebGLVertexArrayObject* vertex_array) {
  if (!ValidateNullableWebGLObject("bindVertexArray", vertex_array))
    return;

  if (vertex_array && !vertex_array->IsDefaultObject() &&
      vertex_array->Object()) {
    ContextGL()->BindVertexArrayOES(ObjectOrZero(vertex_array));

    vertex_array->SetHasEverBeenBound();
    SetBoundVertexArrayObject(vertex_array);
  } else {
    ContextGL()->BindVertexArrayOES(0);
    SetBoundVertexArrayObject(nullptr);
  }
}

void WebGL2RenderingContextBase::bindFramebuffer(GLenum target,
                                                 WebGLFramebuffer* buffer) {
  if (!ValidateNullableWebGLObject("bindFramebuffer", buffer))
    return;

  switch (target) {
    case GL_DRAW_FRAMEBUFFER:
      break;
    case GL_FRAMEBUFFER:
    case GL_READ_FRAMEBUFFER:
      read_framebuffer_binding_ = buffer;
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "bindFramebuffer", "invalid target");
      return;
  }

  SetFramebuffer(target, buffer);
}

void WebGL2RenderingContextBase::deleteFramebuffer(
    WebGLFramebuffer* framebuffer) {
  // Don't allow the application to delete an opaque framebuffer.
  if (framebuffer && framebuffer->Opaque()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "deleteFramebuffer",
                      "cannot delete an opaque framebuffer");
    return;
  }
  if (!DeleteObject(framebuffer))
    return;
  GLenum target = 0;
  if (framebuffer == framebuffer_binding_) {
    if (framebuffer == read_framebuffer_binding_) {
      target = GL_FRAMEBUFFER;
      framebuffer_binding_ = nullptr;
      read_framebuffer_binding_ = nullptr;
    } else {
      target = GL_DRAW_FRAMEBUFFER;
      framebuffer_binding_ = nullptr;
    }
  } else if (framebuffer == read_framebuffer_binding_) {
    target = GL_READ_FRAMEBUFFER;
    read_framebuffer_binding_ = nullptr;
  }
  if (target) {
    // Have to call drawingBuffer()->bind() here to bind back to internal fbo.
    GetDrawingBuffer()->Bind(target);
  }
}

ScriptValue WebGL2RenderingContextBase::getParameter(ScriptState* script_state,
                                                     GLenum pname) {
  if (isContextLost())
    return ScriptValue::CreateNull(script_state->GetIsolate());
  switch (pname) {
    case GL_SHADING_LANGUAGE_VERSION: {
      return WebGLAny(
          script_state,
          "WebGL GLSL ES 3.00 (" +
              String(ContextGL()->GetString(GL_SHADING_LANGUAGE_VERSION)) +
              ")");
    }
    case GL_VERSION:
      return WebGLAny(
          script_state,
          "WebGL 2.0 (" + String(ContextGL()->GetString(GL_VERSION)) + ")");

    case GL_COPY_READ_BUFFER_BINDING:
      return WebGLAny(script_state, bound_copy_read_buffer_.Get());
    case GL_COPY_WRITE_BUFFER_BINDING:
      return WebGLAny(script_state, bound_copy_write_buffer_.Get());
    case GL_DRAW_FRAMEBUFFER_BINDING:
      return WebGLAny(script_state, framebuffer_binding_.Get());
    case GL_FRAGMENT_SHADER_DERIVATIVE_HINT:
      return GetUnsignedIntParameter(script_state, pname);
    case GL_MAX_3D_TEXTURE_SIZE:
      return GetIntParameter(script_state, pname);
    case GL_MAX_ARRAY_TEXTURE_LAYERS:
      return GetIntParameter(script_state, pname);
    case GC3D_MAX_CLIENT_WAIT_TIMEOUT_WEBGL:
      return WebGLAny(script_state, kMaxClientWaitTimeout);
    case GL_MAX_COLOR_ATTACHMENTS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_COMBINED_FRAGMENT_UNIFORM_COMPONENTS:
      return GetInt64Parameter(script_state, pname);
    case GL_MAX_COMBINED_UNIFORM_BLOCKS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_COMBINED_VERTEX_UNIFORM_COMPONENTS:
      return GetInt64Parameter(script_state, pname);
    case GL_MAX_DRAW_BUFFERS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_ELEMENT_INDEX:
      return GetInt64Parameter(script_state, pname);
    case GL_MAX_ELEMENTS_INDICES:
      return GetIntParameter(script_state, pname);
    case GL_MAX_ELEMENTS_VERTICES:
      return GetIntParameter(script_state, pname);
    case GL_MAX_FRAGMENT_INPUT_COMPONENTS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_FRAGMENT_UNIFORM_BLOCKS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_FRAGMENT_UNIFORM_COMPONENTS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_PROGRAM_TEXEL_OFFSET:
      return GetIntParameter(script_state, pname);
    case GL_MAX_SAMPLES:
      return GetIntParameter(script_state, pname);
    case GL_MAX_SERVER_WAIT_TIMEOUT:
      return GetInt64Parameter(script_state, pname);
    case GL_MAX_TEXTURE_LOD_BIAS:
      return GetFloatParameter(script_state, pname);
    case GL_MAX_TRANSFORM_FEEDBACK_INTERLEAVED_COMPONENTS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_TRANSFORM_FEEDBACK_SEPARATE_ATTRIBS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_TRANSFORM_FEEDBACK_SEPARATE_COMPONENTS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_UNIFORM_BLOCK_SIZE:
      return GetInt64Parameter(script_state, pname);
    case GL_MAX_UNIFORM_BUFFER_BINDINGS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_VARYING_COMPONENTS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_VERTEX_OUTPUT_COMPONENTS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_VERTEX_UNIFORM_BLOCKS:
      return GetIntParameter(script_state, pname);
    case GL_MAX_VERTEX_UNIFORM_COMPONENTS:
      return GetIntParameter(script_state, pname);
    case GL_MIN_PROGRAM_TEXEL_OFFSET:
      return GetIntParameter(script_state, pname);
    case GL_PACK_ROW_LENGTH:
      return GetIntParameter(script_state, pname);
    case GL_PACK_SKIP_PIXELS:
      return GetIntParameter(script_state, pname);
    case GL_PACK_SKIP_ROWS:
      return GetIntParameter(script_state, pname);
    case GL_PIXEL_PACK_BUFFER_BINDING:
      return WebGLAny(script_state, bound_pixel_pack_buffer_.Get());
    case GL_PIXEL_UNPACK_BUFFER_BINDING:
      return WebGLAny(script_state, bound_pixel_unpack_buffer_.Get());
    case GL_RASTERIZER_DISCARD:
      return GetBooleanParameter(script_state, pname);
    case GL_READ_BUFFER: {
      GLenum value = 0;
      if (!isContextLost()) {
        WebGLFramebuffer* read_framebuffer_binding =
            GetFramebufferBinding(GL_READ_FRAMEBUFFER);
        if (!read_framebuffer_binding)
          value = read_buffer_of_default_framebuffer_;
        else
          value = read_framebuffer_binding->GetReadBuffer();
      }
      return WebGLAny(script_state, value);
    }
    case GL_READ_FRAMEBUFFER_BINDING:
      return WebGLAny(script_state, read_framebuffer_binding_.Get());
    case GL_SAMPLER_BINDING:
      return WebGLAny(script_state, sampler_units_[active_texture_unit_].Get());
    case GL_TEXTURE_BINDING_2D_ARRAY:
      return WebGLAny(
          script_state,
          texture_units_[active_texture_unit_].texture2d_array_binding_.Get());
    case GL_TEXTURE_BINDING_3D:
      return WebGLAny(
          script_state,
          texture_units_[active_texture_unit_].texture3d_binding_.Get());
    case GL_TRANSFORM_FEEDBACK_ACTIVE:
      return GetBooleanParameter(script_state, pname);
    case GL_TRANSFORM_FEEDBACK_BUFFER_BINDING:
      return WebGLAny(script_state, bound_transform_feedback_buffer_.Get());
    case GL_TRANSFORM_FEEDBACK_BINDING:
      if (!transform_feedback_binding_->IsDefaultObject()) {
        return WebGLAny(script_state, transform_feedback_binding_.Get());
      }
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_TRANSFORM_FEEDBACK_PAUSED:
      return GetBooleanParameter(script_state, pname);
    case GL_UNIFORM_BUFFER_BINDING:
      return WebGLAny(script_state, bound_uniform_buffer_.Get());
    case GL_UNIFORM_BUFFER_OFFSET_ALIGNMENT:
      return GetIntParameter(script_state, pname);
    case GL_UNPACK_IMAGE_HEIGHT:
      return GetIntParameter(script_state, pname);
    case GL_UNPACK_ROW_LENGTH:
      return GetIntParameter(script_state, pname);
    case GL_UNPACK_SKIP_IMAGES:
      return GetIntParameter(script_state, pname);
    case GL_UNPACK_SKIP_PIXELS:
      return GetIntParameter(script_state, pname);
    case GL_UNPACK_SKIP_ROWS:
      return GetIntParameter(script_state, pname);
    case GL_TIMESTAMP_EXT:
      if (ExtensionEnabled(kEXTDisjointTimerQueryWebGL2Name)) {
        return WebGLAny(script_state, 0);
      }
      SynthesizeGLError(GL_INVALID_ENUM, "getParameter",
                        "invalid parameter name, "
                        "EXT_disjoint_timer_query_webgl2 not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_GPU_DISJOINT_EXT:
      if (ExtensionEnabled(kEXTDisjointTimerQueryWebGL2Name)) {
        return GetBooleanParameter(script_state, GL_GPU_DISJOINT_EXT);
      }
      SynthesizeGLError(GL_INVALID_ENUM, "getParameter",
                        "invalid parameter name, "
                        "EXT_disjoint_timer_query_webgl2 not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_PROVOKING_VERTEX_ANGLE:
      if (ExtensionEnabled(kWebGLProvokingVertexName)) {
        return GetUnsignedIntParameter(script_state, GL_PROVOKING_VERTEX_ANGLE);
      }
      SynthesizeGLError(GL_INVALID_ENUM, "getParameter",
                        "invalid parameter name, "
                        "WEBGL_provoking_vertex not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_MAX_CLIP_DISTANCES_ANGLE:
    case GL_MAX_CULL_DISTANCES_ANGLE:
    case GL_MAX_COMBINED_CLIP_AND_CULL_DISTANCES_ANGLE:
    case GL_CLIP_DISTANCE0_ANGLE:
    case GL_CLIP_DISTANCE1_ANGLE:
    case GL_CLIP_DISTANCE2_ANGLE:
    case GL_CLIP_DISTANCE3_ANGLE:
    case GL_CLIP_DISTANCE4_ANGLE:
    case GL_CLIP_DISTANCE5_ANGLE:
    case GL_CLIP_DISTANCE6_ANGLE:
    case GL_CLIP_DISTANCE7_ANGLE:
      if (ExtensionEnabled(kWebGLClipCullDistanceName)) {
        if (pname >= GL_CLIP_DISTANCE0_ANGLE &&
            pname <= GL_CLIP_DISTANCE7_ANGLE) {
          return GetBooleanParameter(script_state, pname);
        }
        return GetUnsignedIntParameter(script_state, pname);
      }
      SynthesizeGLError(GL_INVALID_ENUM, "getParameter",
                        "invalid parameter name, "
                        "WEBGL_clip_cull_distance not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_MIN_FRAGMENT_INTERPOLATION_OFFSET_OES:
    case GL_MAX_FRAGMENT_INTERPOLATION_OFFSET_OES:
    case GL_FRAGMENT_INTERPOLATION_OFFSET_BITS_OES:
      if (ExtensionEnabled(kOESShaderMultisampleInterpolationName)) {
        if (pname == GL_FRAGMENT_INTERPOLATION_OFFSET_BITS_OES) {
          return GetIntParameter(script_state, pname);
        }
        return GetFloatParameter(script_state, pname);
      }
      SynthesizeGLError(GL_INVALID_ENUM, "getParameter",
                        "invalid parameter name, "
                        "OES_shader_multisample_interpolation not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());
    case GL_MAX_PIXEL_LOCAL_STORAGE_PLANES_ANGLE:
    case GL_MAX_COLOR_ATTACHMENTS_WITH_ACTIVE_PIXEL_LOCAL_STORAGE_ANGLE:
    case GL_MAX_COMBINED_DRAW_BUFFERS_AND_PIXEL_LOCAL_STORAGE_PLANES_ANGLE:
    case GL_PIXEL_LOCAL_STORAGE_ACTIVE_PLANES_ANGLE:
      if (ExtensionEnabled(kWebGLShaderPixelLocalStorageName)) {
        return GetUnsignedIntParameter(script_state, pname);
      }
      SynthesizeGLError(GL_INVALID_ENUM, "getParameter",
                        "invalid parameter name, "
                        "WEBGL_shader_pixel_local_storage not enabled");
      return ScriptValue::CreateNull(script_state->GetIsolate());

    default:
      return WebGLRenderingContextBase::getParameter(script_state, pname);
  }
}

ScriptValue WebGL2RenderingContextBase::GetInt64Parameter(
    ScriptState* script_state,
    GLenum pname) {
  GLint64 value = 0;
  if (!isContextLost())
    ContextGL()->GetInteger64v(pname, &value);
  return WebGLAny(script_state, value);
}

bool WebGL2RenderingContextBase::ValidateCapability(const char* function_name,
                                                    GLenum cap) {
  switch (cap) {
    case GL_CLIP_DISTANCE0_ANGLE:
    case GL_CLIP_DISTANCE1_ANGLE:
    case GL_CLIP_DISTANCE2_ANGLE:
    case GL_CLIP_DISTANCE3_ANGLE:
    case GL_CLIP_DISTANCE4_ANGLE:
    case GL_CLIP_DISTANCE5_ANGLE:
    case GL_CLIP_DISTANCE6_ANGLE:
    case GL_CLIP_DISTANCE7_ANGLE:
      if (ExtensionEnabled(kWebGLClipCullDistanceName)) {
        return true;
      }
      SynthesizeGLError(
          GL_INVALID_ENUM, function_name,
          "invalid capability, WEBGL_clip_cull_distance not enabled");
      return false;
    case GL_RASTERIZER_DISCARD:
      return true;
    default:
      return WebGLRenderingContextBase::ValidateCapability(function_name, cap);
  }
}

bool WebGL2RenderingContextBase::ValidateBufferTargetCompatibility(
    const char* function_name,
    GLenum target,
    WebGLBuffer* buffer) {
  DCHECK(buffer);

  switch (buffer->GetInitialTarget()) {
    case GL_ELEMENT_ARRAY_BUFFER:
      switch (target) {
        case GL_ARRAY_BUFFER:
        case GL_PIXEL_PACK_BUFFER:
        case GL_PIXEL_UNPACK_BUFFER:
        case GL_TRANSFORM_FEEDBACK_BUFFER:
        case GL_UNIFORM_BUFFER:
          SynthesizeGLError(
              GL_INVALID_OPERATION, function_name,
              "element array buffers can not be bound to a different target");

          return false;
        default:
          break;
      }
      break;
    case GL_ARRAY_BUFFER:
    case GL_COPY_READ_BUFFER:
    case GL_COPY_WRITE_BUFFER:
    case GL_PIXEL_PACK_BUFFER:
    case GL_PIXEL_UNPACK_BUFFER:
    case GL_UNIFORM_BUFFER:
    case GL_TRANSFORM_FEEDBACK_BUFFER:
      if (target == GL_ELEMENT_ARRAY_BUFFER) {
        SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                          "buffers bound to non ELEMENT_ARRAY_BUFFER targets "
                          "can not be bound to ELEMENT_ARRAY_BUFFER target");
        return false;
      }
      break;
    default:
      break;
  }

  return true;
}

bool WebGL2RenderingContextBase::ValidateBufferTarget(const char* function_name,
                                                      GLenum target) {
  switch (target) {
    case GL_ARRAY_BUFFER:
    case GL_COPY_READ_BUFFER:
    case GL_COPY_WRITE_BUFFER:
    case GL_ELEMENT_ARRAY_BUFFER:
    case GL_PIXEL_PACK_BUFFER:
    case GL_PIXEL_UNPACK_BUFFER:
    case GL_TRANSFORM_FEEDBACK_BUFFER:
    case GL_UNIFORM_BUFFER:
      return true;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid target");
      return false;
  }
}

bool WebGL2RenderingContextBase::ValidateAndUpdateBufferBindTarget(
    const char* function_name,
    GLenum target,
    WebGLBuffer* buffer) {
  if (!ValidateBufferTarget(function_name, target))
    return false;

  if (buffer &&
      !ValidateBufferTargetCompatibility(function_name, target, buffer))
    return false;

  switch (target) {
    case GL_ARRAY_BUFFER:
      bound_array_buffer_ = buffer;
      break;
    case GL_COPY_READ_BUFFER:
      bound_copy_read_buffer_ = buffer;
      break;
    case GL_COPY_WRITE_BUFFER:
      bound_copy_write_buffer_ = buffer;
      break;
    case GL_ELEMENT_ARRAY_BUFFER:
      bound_vertex_array_object_->SetElementArrayBuffer(buffer);
      break;
    case GL_PIXEL_PACK_BUFFER:
      bound_pixel_pack_buffer_ = buffer;
      break;
    case GL_PIXEL_UNPACK_BUFFER:
      bound_pixel_unpack_buffer_ = buffer;
      break;
    case GL_TRANSFORM_FEEDBACK_BUFFER:
      bound_transform_feedback_buffer_ = buffer;
      break;
    case GL_UNIFORM_BUFFER:
      bound_uniform_buffer_ = buffer;
      break;
    default:
      NOTREACHED();
  }

  if (buffer && !buffer->GetInitialTarget())
    buffer->SetInitialTarget(target);
  return true;
}

bool WebGL2RenderingContextBase::ValidateBufferBaseTarget(
    const char* function_name,
    GLenum target) {
  switch (target) {
    case GL_TRANSFORM_FEEDBACK_BUFFER:
    case GL_UNIFORM_BUFFER:
      return true;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid target");
      return false;
  }
}

bool WebGL2RenderingContextBase::ValidateAndUpdateBufferBindBaseTarget(
    const char* function_name,
    GLenum target,
    GLuint index,
    WebGLBuffer* buffer) {
  if (!ValidateBufferBaseTarget(function_name, target))
    return false;

  if (buffer &&
      !ValidateBufferTargetCompatibility(function_name, target, buffer))
    return false;

  switch (target) {
    case GL_TRANSFORM_FEEDBACK_BUFFER:
      if (!transform_feedback_binding_->SetBoundIndexedTransformFeedbackBuffer(
              index, buffer)) {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "index out of range");
        return false;
      }
      bound_transform_feedback_buffer_ = buffer;
      break;
    case GL_UNIFORM_BUFFER:
      if (index >= bound_indexed_uniform_buffers_.size()) {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "index out of range");
        return false;
      }
      bound_indexed_uniform_buffers_[index] = buffer;
      bound_uniform_buffer_ = buffer;
      break;
    default:
      NOTREACHED();
  }

  if (buffer && !buffer->GetInitialTarget())
    buffer->SetInitialTarget(target);
  return true;
}

bool WebGL2RenderingContextBase::ValidateFramebufferTarget(GLenum target) {
  switch (target) {
    case GL_FRAMEBUFFER:
    case GL_READ_FRAMEBUFFER:
    case GL_DRAW_FRAMEBUFFER:
      return true;
    default:
      return false;
  }
}

bool WebGL2RenderingContextBase::ValidateReadPixelsFormatAndType(
    GLenum format,
    GLenum type,
    DOMArrayBufferView* buffer) {
  switch (format) {
    case GL_RED:
    case GL_RED_INTEGER:
    case GL_RG:
    case GL_RG_INTEGER:
    case GL_RGB:
    case GL_RGB_INTEGER:
    case GL_RGBA:
    case GL_RGBA_INTEGER:
    case GL_LUMINANCE_ALPHA:
    case GL_LUMINANCE:
    case GL_ALPHA:
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "readPixels", "invalid format");
      return false;
  }

  switch (type) {
    case GL_UNSIGNED_BYTE:
      if (buffer) {
        auto bufferType = buffer->GetType();
        if (bufferType != DOMArrayBufferView::kTypeUint8 &&
            bufferType != DOMArrayBufferView::kTypeUint8Clamped) {
          SynthesizeGLError(
              GL_INVALID_OPERATION, "readPixels",
              "type UNSIGNED_BYTE but ArrayBufferView not Uint8Array or "
              "Uint8ClampedArray");
          return false;
        }
      }
      return true;
    case GL_BYTE:
      if (buffer && buffer->GetType() != DOMArrayBufferView::kTypeInt8) {
        SynthesizeGLError(GL_INVALID_OPERATION, "readPixels",
                          "type BYTE but ArrayBufferView not Int8Array");
        return false;
      }
      return true;
    case GL_HALF_FLOAT:
      if (buffer && buffer->GetType() != DOMArrayBufferView::kTypeUint16) {
        SynthesizeGLError(
            GL_INVALID_OPERATION, "readPixels",
            "type HALF_FLOAT but ArrayBufferView not Uint16Array");
        return false;
      }
      return true;
    case GL_FLOAT:
      if (buffer && buffer->GetType() != DOMArrayBufferView::kTypeFloat32) {
        SynthesizeGLError(GL_INVALID_OPERATION, "readPixels",
                          "type FLOAT but ArrayBufferView not Float32Array");
        return false;
      }
      return true;
    case GL_UNSIGNED_SHORT_5_6_5:
    case GL_UNSIGNED_SHORT_4_4_4_4:
    case GL_UNSIGNED_SHORT_5_5_5_1:
      if (buffer && buffer->GetType() != DOMArrayBufferView::kTypeUint16) {
        SynthesizeGLError(
            GL_INVALID_OPERATION, "readPixels",
            "type UNSIGNED_SHORT but ArrayBufferView not Uint16Array");
        return false;
      }
      return true;
    case GL_UNSIGNED_SHORT:
      if (buffer && buffer->GetType() != DOMArrayBufferView::kTypeUint16) {
        SynthesizeGLError(
            GL_INVALID_OPERATION, "readPixels",
            "type GL_UNSIGNED_SHORT but ArrayBufferView not Uint16Array");
        return false;
      }
      if (format == GL_RGBA) {
        if (!ExtensionEnabled(kEXTTextureNorm16Name)) {
          SynthesizeGLError(
              GL_INVALID_OPERATION, "readPixels",
              "invalid format/type combination RGBA/UNSIGNED_SHORT without "
              "EXT_texture_norm16 support");
          return false;
        }
      }
      return true;
    case GL_SHORT:
      if (buffer && buffer->GetType() != DOMArrayBufferView::kTypeInt16) {
        SynthesizeGLError(GL_INVALID_OPERATION, "readPixels",
                          "type SHORT but ArrayBufferView not Int16Array");
        return false;
      }
      return true;
    case GL_UNSIGNED_INT:
    case GL_UNSIGNED_INT_2_10_10_10_REV:
    case GL_UNSIGNED_INT_10F_11F_11F_REV:
    case GL_UNSIGNED_INT_5_9_9_9_REV:
      if (buffer && buffer->GetType() != DOMArrayBufferView::kTypeUint32) {
        SynthesizeGLError(
            GL_INVALID_OPERATION, "readPixels",
            "type UNSIGNED_INT but ArrayBufferView not Uint32Array");
        return false;
      }
      return true;
    case GL_INT:
      if (buffer && buffer->GetType() != DOMArrayBufferView::kTypeInt32) {
        SynthesizeGLError(GL_INVALID_OPERATION, "readPixels",
                          "type INT but ArrayBufferView not Int32Array");
        return false;
      }
      return true;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "readPixels", "invalid type");
      return false;
  }
}

WebGLFramebuffer* WebGL2RenderingContextBase::GetFramebufferBinding(
    GLenum target) {
  switch (target) {
    case GL_READ_FRAMEBUFFER:
      return read_framebuffer_binding_.Get();
    case GL_DRAW_FRAMEBUFFER:
      return framebuffer_binding_.Get();
    default:
      return WebGLRenderingContextBase::GetFramebufferBinding(target);
  }
}

WebGLFramebuffer* WebGL2RenderingContextBase::GetReadFramebufferBinding() {
  return read_framebuffer_binding_.Get();
}

bool WebGL2RenderingContextBase::ValidateGetFramebufferAttachmentParameterFunc(
    const char* function_name,
    GLenum target,
    GLenum attachment) {
  if (!ValidateFramebufferTarget(target)) {
    SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid target");
    return false;
  }

  WebGLFramebuffer* framebuffer_binding = GetFramebufferBinding(target);
  DCHECK(framebuffer_binding || GetDrawingBuffer());
  if (!framebuffer_binding) {
    // for the default framebuffer
    switch (attachment) {
      case GL_BACK:
      case GL_DEPTH:
      case GL_STENCIL:
        break;
      default:
        SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid attachment");
        return false;
    }
  } else {
    // for the FBO
    switch (attachment) {
      case GL_COLOR_ATTACHMENT0:
      case GL_DEPTH_ATTACHMENT:
      case GL_STENCIL_ATTACHMENT:
        break;
      case GL_DEPTH_STENCIL_ATTACHMENT:
        if (framebuffer_binding->GetAttachmentObject(GL_DEPTH_ATTACHMENT) !=
            framebuffer_binding->GetAttachmentObject(GL_STENCIL_ATTACHMENT)) {
          SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                            "different objects are bound to the depth and "
                            "stencil attachment points");
          return false;
        }
        break;
      default:
        if (attachment > GL_COLOR_ATTACHMENT0 &&
            attachment < static_cast<GLenum>(GL_COLOR_ATTACHMENT0 +
                                             MaxColorAttachments()))
          break;
        SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid attachment");
        return false;
    }
  }
  return true;
}

ScriptValue WebGL2RenderingContextBase::getFramebufferAttachmentParameter(
    ScriptState* script_state,
    GLenum target,
    GLenum attachment,
    GLenum pname) {
  const char kFunctionName[] = "getFramebufferAttachmentParameter";
  if (isContextLost() || !ValidateGetFramebufferAttachmentParameterFunc(
                             kFunctionName, target, attachment))
    return ScriptValue::CreateNull(script_state->GetIsolate());

  WebGLFramebuffer* framebuffer_binding = GetFramebufferBinding(target);
  DCHECK(!framebuffer_binding || framebuffer_binding->Object());

  // Default framebuffer (an internal fbo)
  if (!framebuffer_binding) {
    // We can use creationAttributes() because in WebGL 2, they are required to
    // be honored.
    bool has_depth = CreationAttributes().depth;
    bool has_stencil = CreationAttributes().stencil;
    bool has_alpha = CreationAttributes().alpha;
    bool missing_image = (attachment == GL_DEPTH && !has_depth) ||
                         (attachment == GL_STENCIL && !has_stencil);
    if (missing_image) {
      switch (pname) {
        case GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE:
          return WebGLAny(script_state, GL_NONE);
        default:
          SynthesizeGLError(GL_INVALID_OPERATION, kFunctionName,
                            "invalid parameter name");
          return ScriptValue::CreateNull(script_state->GetIsolate());
      }
    }
    switch (pname) {
      case GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE:
        return WebGLAny(script_state, GL_FRAMEBUFFER_DEFAULT);
      case GL_FRAMEBUFFER_ATTACHMENT_RED_SIZE:
      case GL_FRAMEBUFFER_ATTACHMENT_BLUE_SIZE:
      case GL_FRAMEBUFFER_ATTACHMENT_GREEN_SIZE: {
        GLint value = attachment == GL_BACK ? 8 : 0;
        return WebGLAny(script_state, value);
      }
      case GL_FRAMEBUFFER_ATTACHMENT_ALPHA_SIZE: {
        GLint value = (attachment == GL_BACK && has_alpha) ? 8 : 0;
        return WebGLAny(script_state, value);
      }
      case GL_FRAMEBUFFER_ATTACHMENT_DEPTH_SIZE: {
        // For ES3 capable backend, DEPTH24_STENCIL8 has to be supported.
        GLint value = attachment == GL_DEPTH ? 24 : 0;
        return WebGLAny(script_state, value);
      }
      case GL_FRAMEBUFFER_ATTACHMENT_STENCIL_SIZE: {
        GLint value = attachment == GL_STENCIL ? 8 : 0;
        return WebGLAny(script_state, value);
      }
      case GL_FRAMEBUFFER_ATTACHMENT_COMPONENT_TYPE:
        return WebGLAny(script_state, GL_UNSIGNED_NORMALIZED);
      case GL_FRAMEBUFFER_ATTACHMENT_COLOR_ENCODING:
        return WebGLAny(script_state, GL_LINEAR);
      case GL_FRAMEBUFFER_ATTACHMENT_TEXTURE_BASE_VIEW_INDEX_OVR:
        if (ExtensionEnabled(kOVRMultiview2Name))
          return WebGLAny(script_state, 0);
        SynthesizeGLError(GL_INVALID_ENUM, kFunctionName,
                          "invalid parameter name, OVR_multiview2 not enabled");
        return ScriptValue::CreateNull(script_state->GetIsolate());
      case GL_FRAMEBUFFER_ATTACHMENT_TEXTURE_NUM_VIEWS_OVR:
        if (ExtensionEnabled(kOVRMultiview2Name))
          return WebGLAny(script_state, 0);
        SynthesizeGLError(GL_INVALID_ENUM, kFunctionName,
                          "invalid parameter name, OVR_multiview2 not enabled");
        return Sc
"""


```