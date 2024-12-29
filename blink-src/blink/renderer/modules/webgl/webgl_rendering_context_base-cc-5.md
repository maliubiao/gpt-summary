Response:
The user wants a summary of the functionality of the provided C++ code snippet from `webgl_rendering_context_base.cc`. I need to identify the purpose of each function within this snippet, focusing on its role in the WebGL API. Specifically, I need to:

1. **Identify the functions present:**  `getUniform`, `getUniformLocation`, `getVertexAttrib`, `getVertexAttribOffset`, `hint`, `isBuffer`, `isContextLost`, `isEnabled`, `isFramebuffer`, `isProgram`, `isRenderbuffer`, `isShader`, `isTexture`, `lineWidth`, `linkProgram`, `pixelStorei`, `polygonOffset`, `ValidateReadBufferAndGetInfo`, `ValidateReadPixelsFormatAndType`, `GetPackPixelStoreParams`, `GetUnpackPixelStoreParams`, `ValidateReadPixelsFuncParameters`, `readPixels`, `ReadPixelsHelper`, `RenderbufferStorageImpl`, `renderbufferStorage`, `sampleCoverage`, `scissor`, `shaderSource`, `stencilFunc`, `stencilFuncSeparate`, `stencilMask`, `stencilMaskSeparate`, `stencilOp`, `stencilOpSeparate`, `ConvertTexInternalFormat`.

2. **Describe the core functionality of each function:** What does each function do in the context of WebGL?  For example, `getUniform` retrieves the value of a uniform variable, `linkProgram` links a WebGL program, etc.

3. **Connect to JavaScript, HTML, and CSS:** How do these C++ functions relate to the JavaScript WebGL API used by web developers?  For example, the JavaScript `gl.getUniform()` call will eventually trigger the C++ `getUniform` function. Consider how these operations affect the rendering in the HTML canvas, and if CSS plays a role (though direct CSS interaction is unlikely).

4. **Provide examples of logic and data flow:**  For functions involving conditional logic or data manipulation, illustrate with simple input and output examples.

5. **Illustrate common user/programming errors:**  What mistakes might a web developer make that would lead to these functions being called or returning errors?

6. **Explain the user interaction leading to this code:** Describe the steps a user takes in a web browser that would cause this specific code to execute. This relates to debugging and understanding the execution flow.

7. **Summarize the overall functionality:**  Combine the individual function descriptions into a concise overview of the code's purpose.

**Constraint Checklist & Confidence Score:**

* Provide a list of the functions: Yes
* Explain the function of each: Yes
* Relation to JavaScript: Yes
* Relation to HTML: Yes (indirectly via the canvas element)
* Relation to CSS: No direct relation in this code.
* Provide logic reasoning with input/output: Yes
* Provide user/programming errors: Yes
* Explain user steps to reach the code: Yes
* This is part 6 of 11: Acknowledge this context.
* Summarize the functionality: Yes

Confidence Score: 5/5 - I can address all the requirements.

**Mental Sandbox:**

* **`getUniform`:**  Input: program, location, name, index, type. Output: uniform value (various types). Error: Invalid location, unhandled type. User error: Incorrect uniform name in JavaScript.
* **`getUniformLocation`:** Input: program, name. Output: `WebGLUniformLocation` object. Error: Program not linked, reserved prefix. User error: Typo in uniform name.
* **`getVertexAttrib`:** Input: index, pname. Output: vertex attribute value. Error: Index out of range, invalid `pname`. User error: Accessing an attribute that's not enabled.
* **`linkProgram`:** Input: program. Output: void (modifies program state). User error: Linking a program with incompatible shaders.
* **`readPixels`:** Input: coordinates, dimensions, format, type, buffer. Output: void (writes to the buffer). User error: Providing an undersized buffer, reading from an incomplete framebuffer.

By going through each function and applying these thinking points, I can construct a comprehensive answer that satisfies all the user's requirements. I need to remember to frame the explanation in the context of WebGL and the browser environment.
这是 `blink/renderer/modules/webgl/webgl_rendering_context_base.cc` 文件的第 6 部分，它主要负责实现 WebGL API 中与获取信息、状态查询、程序链接、像素存储、缓冲区操作、渲染状态设置等相关的功能。 这一部分的代码集中处理了与 WebGL 上下文状态和资源管理的关键操作。

以下是该部分代码的具体功能列表，以及与 JavaScript、HTML、CSS 的关系、逻辑推理、常见错误和调试线索：

**功能列表：**

1. **`getUniform(ScriptState* script_state, WebGLProgram* program, WebGLUniformLocation* location)`:**
    *   **功能:**  获取 WebGL Program 中指定 uniform 变量的当前值。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.getUniform(program, location)`.
    *   **HTML 关系:**  渲染结果最终会显示在 HTML 的 `<canvas>` 元素上，uniform 值的改变会影响渲染效果。
    *   **CSS 关系:**  CSS 无法直接影响 uniform 变量的值，但可能通过 JavaScript 间接影响。

2. **`getUniformLocation(WebGLProgram* program, const String& name)`:**
    *   **功能:**  获取 WebGL Program 中指定名称的 uniform 变量的位置 (WebGLUniformLocation 对象)。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.getUniformLocation(program, name)`.

3. **`getVertexAttrib(ScriptState* script_state, GLuint index, GLenum pname)`:**
    *   **功能:**  获取指定索引的顶点属性 (vertex attribute) 的信息，例如绑定缓冲区、大小、类型等。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.getVertexAttrib(index, pname)`.

4. **`getVertexAttribOffset(GLuint index, GLenum pname)`:**
    *   **功能:**  获取指定索引的顶点属性的偏移量。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.getVertexAttribOffset(index, pname)`.

5. **`hint(GLenum target, GLenum mode)`:**
    *   **功能:**  为某些操作提供提示，例如纹理mipmap生成和片元着色器导数计算。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.hint(target, mode)`.

6. **`isBuffer(WebGLBuffer* buffer)`:**
    *   **功能:**  检查给定的对象是否为有效的 WebGLBuffer 对象。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.isBuffer(buffer)`.

7. **`isContextLost() const`:**
    *   **功能:**  检查 WebGL 上下文是否丢失。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.isContextLost()`.

8. **`isEnabled(GLenum cap)`:**
    *   **功能:**  检查是否启用了指定的 WebGL 功能 (capabilities)，例如深度测试、模板测试等。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.isEnabled(cap)`.

9. **`isFramebuffer(WebGLFramebuffer* framebuffer)`:**
    *   **功能:**  检查给定的对象是否为有效的 WebGLFramebuffer 对象。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.isFramebuffer(framebuffer)`.

10. **`isProgram(WebGLProgram* program)`:**
    *   **功能:**  检查给定的对象是否为有效的 WebGLProgram 对象。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.isProgram(program)`.

11. **`isRenderbuffer(WebGLRenderbuffer* renderbuffer)`:**
    *   **功能:**  检查给定的对象是否为有效的 WebGLRenderbuffer 对象。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.isRenderbuffer(renderbuffer)`.

12. **`isShader(WebGLShader* shader)`:**
    *   **功能:**  检查给定的对象是否为有效的 WebGLShader 对象。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.isShader(shader)`.

13. **`isTexture(WebGLTexture* texture)`:**
    *   **功能:**  检查给定的对象是否为有效的 WebGLTexture 对象。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.isTexture(texture)`.

14. **`lineWidth(GLfloat width)`:**
    *   **功能:**  设置绘制线段的宽度。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.lineWidth(width)`.

15. **`linkProgram(WebGLProgram* program)`:**
    *   **功能:**  链接一个 WebGLProgram 对象，将其附加的着色器编译并链接成可执行的程序。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.linkProgram(program)`.

16. **`pixelStorei(GLenum pname, GLint param)`:**
    *   **功能:**  设置像素存储参数，例如对齐方式、Y轴翻转、Alpha 预乘等。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.pixelStorei(pname, param)`.

17. **`polygonOffset(GLfloat factor, GLfloat units)`:**
    *   **功能:**  设置多边形偏移参数，用于解决深度冲突问题。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.polygonOffset(factor, units)`.

18. **`ValidateReadBufferAndGetInfo(const char* function_name, WebGLFramebuffer*& read_framebuffer_binding)`:**
    *   **功能:**  验证读取缓冲区的有效性，并获取读取帧缓冲区的绑定信息。这是内部辅助函数。
    *   **JavaScript 关系:**  虽然 JavaScript 不直接调用，但与涉及读取像素的操作（如 `gl.readPixels`) 相关。

19. **`ValidateReadPixelsFormatAndType(GLenum format, GLenum type, DOMArrayBufferView* buffer)`:**
    *   **功能:**  验证 `readPixels` 操作的格式和类型参数是否有效，并检查提供的缓冲区类型是否匹配。这是内部辅助函数。
    *   **JavaScript 关系:**  与 `gl.readPixels` 操作密切相关。

20. **`GetPackPixelStoreParams()`:**
    *   **功能:**  获取当前像素打包 (用于 `readPixels`) 的存储参数。这是内部辅助函数。

21. **`GetUnpackPixelStoreParams(TexImageDimension)`:**
    *   **功能:**  获取当前像素解包 (用于 `texImage2D` 等) 的存储参数。这是内部辅助函数。

22. **`ValidateReadPixelsFuncParameters(GLsizei width, GLsizei height, GLenum format, GLenum type, DOMArrayBufferView* buffer, int64_t buffer_size)`:**
    *   **功能:**  验证 `readPixels` 函数的参数，包括尺寸、格式、类型和缓冲区大小。这是内部辅助函数。
    *   **JavaScript 关系:**  与 `gl.readPixels` 操作密切相关。

23. **`readPixels(GLint x, GLint y, GLsizei width, GLsizei height, GLenum format, GLenum type, MaybeShared<DOMArrayBufferView> pixels)`:**
    *   **功能:**  从帧缓冲区读取像素数据到客户端内存 (ArrayBufferView)。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.readPixels(x, y, width, height, format, type, pixels)`.

24. **`ReadPixelsHelper(GLint x, GLint y, GLsizei width, GLsizei height, GLenum format, GLenum type, DOMArrayBufferView* pixels, int64_t offset)`:**
    *   **功能:**  `readPixels` 的实际实现，处理参数校验和调用底层 OpenGL ES API。这是内部辅助函数。

25. **`RenderbufferStorageImpl(GLenum target, GLsizei samples, GLenum internalformat, GLsizei width, GLsizei height, const char* function_name)`:**
    *   **功能:**  为 Renderbuffer 对象分配数据存储空间。这是内部辅助函数，实际的 `renderbufferStorage` 会调用它。

26. **`renderbufferStorage(GLenum target, GLenum internalformat, GLsizei width, GLsizei height)`:**
    *   **功能:**  为 Renderbuffer 对象分配特定格式和尺寸的数据存储空间。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.renderbufferStorage(target, internalformat, width, height)`.

27. **`sampleCoverage(GLfloat value, GLboolean invert)`:**
    *   **功能:**  指定用于多重采样抗锯齿的覆盖率值和反转标志。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.sampleCoverage(value, invert)`.

28. **`scissor(GLint x, GLint y, GLsizei width, GLsizei height)`:**
    *   **功能:**  定义裁剪框，只有在该区域内的绘制操作才会被渲染。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.scissor(x, y, width, height)`.

29. **`shaderSource(WebGLShader* shader, const String& string)`:**
    *   **功能:**  设置 WebGLShader 对象的源代码。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.shaderSource(shader, source)`.

30. **`stencilFunc(GLenum func, GLint ref, GLuint mask)`:**
    *   **功能:**  设置模板测试函数。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.stencilFunc(func, ref, mask)`.

31. **`stencilFuncSeparate(GLenum face, GLenum func, GLint ref, GLuint mask)`:**
    *   **功能:**  为模板测试的前面和背面分别设置测试函数。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.stencilFuncSeparate(face, func, ref, mask)`.

32. **`stencilMask(GLuint mask)`:**
    *   **功能:**  控制写入模板缓冲区的位。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.stencilMask(mask)`.

33. **`stencilMaskSeparate(GLenum face, GLuint mask)`:**
    *   **功能:**  分别为模板测试的前面和背面设置模板写入掩码。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.stencilMaskSeparate(face, mask)`.

34. **`stencilOp(GLenum fail, GLenum zfail, GLenum zpass)`:**
    *   **功能:**  设置模板测试失败、深度测试失败和深度测试通过时执行的模板操作。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.stencilOp(fail, zfail, zpass)`.

35. **`stencilOpSeparate(GLenum face, GLenum fail, GLenum zfail, GLenum zpass)`:**
    *   **功能:**  分别为模板测试的前面和背面设置模板操作。
    *   **JavaScript 关系:**  对应 JavaScript 中的 `gl.stencilOpSeparate(face, fail, zfail, zpass)`.

36. **`ConvertTexInternalFormat(GLenum internalformat, GLenum type)`:**
    *   **功能:**  转换纹理的内部格式，特别是针对支持浮点数纹理的情况。这是内部辅助函数。

**与 JavaScript, HTML, CSS 的关系举例说明：**

*   **JavaScript:** 当 JavaScript 代码调用 `gl.getUniform(program, location)` 时，Blink 引擎会执行 `WebGLRenderingContextBase::getUniform` 函数来获取 uniform 变量的值。
*   **HTML:**  WebGL 的渲染结果最终会显示在 HTML 的 `<canvas>` 元素上。例如，通过 `gl.lineWidth(5)` 设置的线宽会影响在 canvas 上绘制的线条的粗细。
*   **CSS:**  CSS 可以控制 `<canvas>` 元素在页面上的布局和样式，但不能直接操作 WebGL 的状态或资源。例如，CSS 可以设置 canvas 的宽度和高度，但这与 `gl.viewport()` 的设置不同。

**逻辑推理举例说明：**

**假设输入:**

*   在 JavaScript 中，你有一个已链接的 WebGLProgram 对象 `myProgram`。
*   你已经通过 `gl.getUniformLocation(myProgram, "u_color")` 获取了一个 `WebGLUniformLocation` 对象 `colorLocation`。
*   在着色器中，`u_color` 是一个 `vec4` 类型的 uniform 变量。

**代码段:**

```c++
ScriptValue WebGLRenderingContextBase::getUniform(
    ScriptState* script_state,
    WebGLProgram* program,
    WebGLUniformLocation* location) {
  // ... (代码逻辑) ...
  case GL_FLOAT_VEC4: {
    GLfloat value[4] = {0};
    ContextGL()->GetUniformfv(ObjectOrZero(program), location, value);
    return WebGLAny(script_state, DOMFloat32Array::Create(
                                      base::span(value).first(length)));
  }
  // ...
}
```

**输出:**

*   如果 uniform `u_color` 在 GPU 上的值为 `[1.0, 0.0, 0.0, 1.0]`，那么 `getUniform` 函数会创建一个包含这些值的 `Float32Array` 并返回给 JavaScript。

**用户或编程常见的使用错误举例说明：**

1. **获取不存在的 uniform 位置:**  在 JavaScript 中调用 `gl.getUniformLocation(program, "nonExistentUniform")` 会返回 `null`。如果后续代码没有检查这个返回值就直接传递给 `gl.getUniform`，会导致错误或未定义的行为。
2. **`readPixels` 缓冲区大小不足:**  如果 `gl.readPixels` 的目标 `ArrayBufferView` 太小，无法容纳读取的像素数据，会导致 `GL_INVALID_OPERATION` 错误。
3. **在程序链接前获取 uniform 位置:**  在 JavaScript 中，如果尝试在调用 `gl.linkProgram` 之前调用 `gl.getUniformLocation`，可能会返回 `null` 或者得到一个无效的位置。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户打开一个包含 WebGL 内容的网页。**
2. **网页的 JavaScript 代码获取 `<canvas>` 元素。**
3. **JavaScript 代码通过 `canvas.getContext('webgl')` 或 `canvas.getContext('webgl2')` 获取 WebGL 上下文。**
4. **JavaScript 代码创建、编译和链接 WebGL 着色器程序。**  这一步会触发 `linkProgram` 函数。
5. **JavaScript 代码使用 `gl.getUniformLocation` 获取 uniform 变量的位置。** 触发 `getUniformLocation` 函数。
6. **JavaScript 代码使用 `gl.uniformXXX` 设置 uniform 变量的值。** (虽然这部分代码未在提供的片段中，但它与 uniform 的使用相关)。
7. **JavaScript 代码使用 `gl.drawArrays` 或 `gl.drawElements` 进行绘制。**
8. **为了调试，开发者可能在 JavaScript 中调用 `gl.getUniform` 来检查 uniform 变量的当前值。**  这将直接调用 `WebGLRenderingContextBase::getUniform` 函数。
9. **如果需要读取渲染结果，开发者可能会调用 `gl.readPixels`。** 这将触发 `readPixels` 和相关的验证函数。

**归纳一下它的功能 (第 6 部分):**

这部分代码主要实现了 WebGL API 中用于 **查询和操作 WebGL 上下文状态和资源** 的功能。 它涵盖了：

*   **信息获取:** 获取 uniform 变量的值和位置，顶点属性信息等。
*   **状态查询:** 检查上下文是否丢失，特定功能是否启用，对象是否有效等。
*   **程序链接:**  链接着色器程序。
*   **像素存储:** 设置像素数据的存储方式。
*   **缓冲区操作:**  读取帧缓冲区数据。
*   **渲染状态设置:** 设置线宽、多边形偏移、裁剪框、模板测试等。

总而言之，这部分代码是 Blink 引擎中 WebGL 实现的核心组成部分，它连接了 JavaScript API 和底层的 OpenGL ES 操作，使得开发者可以通过 JavaScript 来控制 GPU 的渲染行为并获取渲染结果。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共11部分，请归纳一下它的功能

"""
builder.Clear();
      name_builder.Append(name);
      if (size > 1 && index >= 1) {
        name_builder.Append('[');
        name_builder.AppendNumber(index);
        name_builder.Append(']');
      }
      // Now need to look this up by name again to find its location
      GLint loc = ContextGL()->GetUniformLocation(
          ObjectOrZero(program), name_builder.ToString().Utf8().c_str());
      if (loc == location) {
        // Found it. Use the type in the ActiveInfo to determine the return
        // type.
        GLenum base_type;
        unsigned length;
        switch (type) {
          case GL_BOOL:
            base_type = GL_BOOL;
            length = 1;
            break;
          case GL_BOOL_VEC2:
            base_type = GL_BOOL;
            length = 2;
            break;
          case GL_BOOL_VEC3:
            base_type = GL_BOOL;
            length = 3;
            break;
          case GL_BOOL_VEC4:
            base_type = GL_BOOL;
            length = 4;
            break;
          case GL_INT:
            base_type = GL_INT;
            length = 1;
            break;
          case GL_INT_VEC2:
            base_type = GL_INT;
            length = 2;
            break;
          case GL_INT_VEC3:
            base_type = GL_INT;
            length = 3;
            break;
          case GL_INT_VEC4:
            base_type = GL_INT;
            length = 4;
            break;
          case GL_FLOAT:
            base_type = GL_FLOAT;
            length = 1;
            break;
          case GL_FLOAT_VEC2:
            base_type = GL_FLOAT;
            length = 2;
            break;
          case GL_FLOAT_VEC3:
            base_type = GL_FLOAT;
            length = 3;
            break;
          case GL_FLOAT_VEC4:
            base_type = GL_FLOAT;
            length = 4;
            break;
          case GL_FLOAT_MAT2:
            base_type = GL_FLOAT;
            length = 4;
            break;
          case GL_FLOAT_MAT3:
            base_type = GL_FLOAT;
            length = 9;
            break;
          case GL_FLOAT_MAT4:
            base_type = GL_FLOAT;
            length = 16;
            break;
          case GL_SAMPLER_2D:
          case GL_SAMPLER_CUBE:
            base_type = GL_INT;
            length = 1;
            break;
          default:
            if (!IsWebGL2()) {
              // Can't handle this type
              SynthesizeGLError(GL_INVALID_VALUE, "getUniform",
                                "unhandled type");
              return ScriptValue::CreateNull(script_state->GetIsolate());
            }
            // handle GLenums for WebGL 2.0 or higher
            switch (type) {
              case GL_UNSIGNED_INT:
                base_type = GL_UNSIGNED_INT;
                length = 1;
                break;
              case GL_UNSIGNED_INT_VEC2:
                base_type = GL_UNSIGNED_INT;
                length = 2;
                break;
              case GL_UNSIGNED_INT_VEC3:
                base_type = GL_UNSIGNED_INT;
                length = 3;
                break;
              case GL_UNSIGNED_INT_VEC4:
                base_type = GL_UNSIGNED_INT;
                length = 4;
                break;
              case GL_FLOAT_MAT2x3:
                base_type = GL_FLOAT;
                length = 6;
                break;
              case GL_FLOAT_MAT2x4:
                base_type = GL_FLOAT;
                length = 8;
                break;
              case GL_FLOAT_MAT3x2:
                base_type = GL_FLOAT;
                length = 6;
                break;
              case GL_FLOAT_MAT3x4:
                base_type = GL_FLOAT;
                length = 12;
                break;
              case GL_FLOAT_MAT4x2:
                base_type = GL_FLOAT;
                length = 8;
                break;
              case GL_FLOAT_MAT4x3:
                base_type = GL_FLOAT;
                length = 12;
                break;
              case GL_SAMPLER_3D:
              case GL_SAMPLER_2D_ARRAY:
              case GL_SAMPLER_2D_SHADOW:
              case GL_SAMPLER_CUBE_SHADOW:
              case GL_SAMPLER_2D_ARRAY_SHADOW:
              case GL_INT_SAMPLER_2D:
              case GL_INT_SAMPLER_CUBE:
              case GL_INT_SAMPLER_3D:
              case GL_INT_SAMPLER_2D_ARRAY:
              case GL_UNSIGNED_INT_SAMPLER_2D:
              case GL_UNSIGNED_INT_SAMPLER_CUBE:
              case GL_UNSIGNED_INT_SAMPLER_3D:
              case GL_UNSIGNED_INT_SAMPLER_2D_ARRAY:
                base_type = GL_INT;
                length = 1;
                break;
              default:
                // Can't handle this type
                SynthesizeGLError(GL_INVALID_VALUE, "getUniform",
                                  "unhandled type");
                return ScriptValue::CreateNull(script_state->GetIsolate());
            }
        }
        switch (base_type) {
          case GL_FLOAT: {
            GLfloat value[16] = {0};
            ContextGL()->GetUniformfv(ObjectOrZero(program), location, value);
            if (length == 1)
              return WebGLAny(script_state, value[0]);
            return WebGLAny(script_state, DOMFloat32Array::Create(
                                              base::span(value).first(length)));
          }
          case GL_INT: {
            GLint value[4] = {0};
            ContextGL()->GetUniformiv(ObjectOrZero(program), location, value);
            if (length == 1)
              return WebGLAny(script_state, value[0]);
            return WebGLAny(script_state, DOMInt32Array::Create(
                                              base::span(value).first(length)));
          }
          case GL_UNSIGNED_INT: {
            GLuint value[4] = {0};
            ContextGL()->GetUniformuiv(ObjectOrZero(program), location, value);
            if (length == 1)
              return WebGLAny(script_state, value[0]);
            return WebGLAny(script_state, DOMUint32Array::Create(
                                              base::span(value).first(length)));
          }
          case GL_BOOL: {
            std::array<GLint, 4> value = {0};
            ContextGL()->GetUniformiv(ObjectOrZero(program), location,
                                      value.data());

            if (length > 1) {
              std::array<bool, 4> bool_value = {};
              for (unsigned j = 0; j < length; j++)
                bool_value[j] = static_cast<bool>(value[j]);
              return WebGLAny(script_state, bool_value.data(), length);
            }

            return WebGLAny(script_state, static_cast<bool>(value[0]));
          }
          default:
            NOTIMPLEMENTED();
        }
      }
    }
  }
  // If we get here, something went wrong in our unfortunately complex logic
  // above
  SynthesizeGLError(GL_INVALID_VALUE, "getUniform", "unknown error");
  return ScriptValue::CreateNull(script_state->GetIsolate());
}

WebGLUniformLocation* WebGLRenderingContextBase::getUniformLocation(
    WebGLProgram* program,
    const String& name) {
  if (!ValidateWebGLProgramOrShader("getUniformLocation", program))
    return nullptr;
  if (!ValidateLocationLength("getUniformLocation", name))
    return nullptr;
  if (!ValidateString("getUniformLocation", name))
    return nullptr;
  if (IsPrefixReserved(name))
    return nullptr;
  if (!program->LinkStatus(this)) {
    SynthesizeGLError(GL_INVALID_OPERATION, "getUniformLocation",
                      "program not linked");
    return nullptr;
  }
  GLint uniform_location = ContextGL()->GetUniformLocation(
      ObjectOrZero(program), name.Utf8().c_str());
  if (uniform_location == -1)
    return nullptr;
  return MakeGarbageCollected<WebGLUniformLocation>(program, uniform_location);
}

ScriptValue WebGLRenderingContextBase::getVertexAttrib(
    ScriptState* script_state,
    GLuint index,
    GLenum pname) {
  if (isContextLost())
    return ScriptValue::CreateNull(script_state->GetIsolate());
  if (index >= max_vertex_attribs_) {
    SynthesizeGLError(GL_INVALID_VALUE, "getVertexAttrib",
                      "index out of range");
    return ScriptValue::CreateNull(script_state->GetIsolate());
  }

  if ((ExtensionEnabled(kANGLEInstancedArraysName) || IsWebGL2()) &&
      pname == GL_VERTEX_ATTRIB_ARRAY_DIVISOR_ANGLE) {
    GLint value = 0;
    ContextGL()->GetVertexAttribiv(index, pname, &value);
    return WebGLAny(script_state, value);
  }

  switch (pname) {
    case GL_VERTEX_ATTRIB_ARRAY_BUFFER_BINDING:
      return WebGLAny(
          script_state,
          bound_vertex_array_object_->GetArrayBufferForAttrib(index));
    case GL_VERTEX_ATTRIB_ARRAY_ENABLED:
    case GL_VERTEX_ATTRIB_ARRAY_NORMALIZED: {
      GLint value = 0;
      ContextGL()->GetVertexAttribiv(index, pname, &value);
      return WebGLAny(script_state, static_cast<bool>(value));
    }
    case GL_VERTEX_ATTRIB_ARRAY_SIZE:
    case GL_VERTEX_ATTRIB_ARRAY_STRIDE: {
      GLint value = 0;
      ContextGL()->GetVertexAttribiv(index, pname, &value);
      return WebGLAny(script_state, value);
    }
    case GL_VERTEX_ATTRIB_ARRAY_TYPE: {
      GLint value = 0;
      ContextGL()->GetVertexAttribiv(index, pname, &value);
      return WebGLAny(script_state, static_cast<GLenum>(value));
    }
    case GL_CURRENT_VERTEX_ATTRIB: {
      switch (vertex_attrib_type_[index]) {
        case kFloat32ArrayType: {
          GLfloat float_value[4];
          ContextGL()->GetVertexAttribfv(index, pname, float_value);
          return WebGLAny(script_state, DOMFloat32Array::Create(float_value));
        }
        case kInt32ArrayType: {
          GLint int_value[4];
          ContextGL()->GetVertexAttribIiv(index, pname, int_value);
          return WebGLAny(script_state, DOMInt32Array::Create(int_value));
        }
        case kUint32ArrayType: {
          GLuint uint_value[4];
          ContextGL()->GetVertexAttribIuiv(index, pname, uint_value);
          return WebGLAny(script_state, DOMUint32Array::Create(uint_value));
        }
        default:
          NOTREACHED();
      }
    }
    case GL_VERTEX_ATTRIB_ARRAY_INTEGER:
      if (IsWebGL2()) {
        GLint value = 0;
        ContextGL()->GetVertexAttribiv(index, pname, &value);
        return WebGLAny(script_state, static_cast<bool>(value));
      }
      [[fallthrough]];
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "getVertexAttrib",
                        "invalid parameter name");
      return ScriptValue::CreateNull(script_state->GetIsolate());
  }
}

int64_t WebGLRenderingContextBase::getVertexAttribOffset(GLuint index,
                                                         GLenum pname) {
  if (isContextLost())
    return 0;
  GLvoid* result = nullptr;
  // NOTE: If pname is ever a value that returns more than 1 element
  // this will corrupt memory.
  ContextGL()->GetVertexAttribPointerv(index, pname, &result);
  return static_cast<int64_t>(reinterpret_cast<intptr_t>(result));
}

void WebGLRenderingContextBase::hint(GLenum target, GLenum mode) {
  if (isContextLost())
    return;
  bool is_valid = false;
  switch (target) {
    case GL_GENERATE_MIPMAP_HINT:
      is_valid = true;
      break;
    case GL_FRAGMENT_SHADER_DERIVATIVE_HINT_OES:  // OES_standard_derivatives
      if (ExtensionEnabled(kOESStandardDerivativesName) || IsWebGL2())
        is_valid = true;
      break;
  }
  if (!is_valid) {
    SynthesizeGLError(GL_INVALID_ENUM, "hint", "invalid target");
    return;
  }
  ContextGL()->Hint(target, mode);
}

bool WebGLRenderingContextBase::isBuffer(WebGLBuffer* buffer) {
  if (!buffer || isContextLost() || !buffer->Validate(ContextGroup(), this))
    return false;

  if (!buffer->HasEverBeenBound())
    return false;
  if (buffer->MarkedForDeletion())
    return false;

  return ContextGL()->IsBuffer(buffer->Object());
}

bool WebGLRenderingContextBase::isContextLost() const {
  return context_lost_mode_ != kNotLostContext;
}

bool WebGLRenderingContextBase::isEnabled(GLenum cap) {
  if (isContextLost() || !ValidateCapability("isEnabled", cap))
    return false;
  if (cap == GL_DEPTH_TEST) {
    return depth_enabled_;
  }
  if (cap == GL_STENCIL_TEST) {
    return stencil_enabled_;
  }
  return ContextGL()->IsEnabled(cap);
}

bool WebGLRenderingContextBase::isFramebuffer(WebGLFramebuffer* framebuffer) {
  if (!framebuffer || isContextLost() ||
      !framebuffer->Validate(ContextGroup(), this))
    return false;

  if (!framebuffer->HasEverBeenBound())
    return false;
  if (framebuffer->MarkedForDeletion())
    return false;

  return ContextGL()->IsFramebuffer(framebuffer->Object());
}

bool WebGLRenderingContextBase::isProgram(WebGLProgram* program) {
  if (!program || isContextLost() || !program->Validate(ContextGroup(), this))
    return false;

  // OpenGL ES special-cases the behavior of program objects; if they're deleted
  // while attached to the current context state, glIsProgram is supposed to
  // still return true. For this reason, MarkedForDeletion is not checked here.

  return ContextGL()->IsProgram(program->Object());
}

bool WebGLRenderingContextBase::isRenderbuffer(
    WebGLRenderbuffer* renderbuffer) {
  if (!renderbuffer || isContextLost() ||
      !renderbuffer->Validate(ContextGroup(), this))
    return false;

  if (!renderbuffer->HasEverBeenBound())
    return false;
  if (renderbuffer->MarkedForDeletion())
    return false;

  return ContextGL()->IsRenderbuffer(renderbuffer->Object());
}

bool WebGLRenderingContextBase::isShader(WebGLShader* shader) {
  if (!shader || isContextLost() || !shader->Validate(ContextGroup(), this))
    return false;

  // OpenGL ES special-cases the behavior of shader objects; if they're deleted
  // while attached to a program, glIsShader is supposed to still return true.
  // For this reason, MarkedForDeletion is not checked here.

  return ContextGL()->IsShader(shader->Object());
}

bool WebGLRenderingContextBase::isTexture(WebGLTexture* texture) {
  if (!texture || isContextLost() || !texture->Validate(ContextGroup(), this))
    return false;

  if (!texture->HasEverBeenBound())
    return false;
  if (texture->MarkedForDeletion())
    return false;

  return ContextGL()->IsTexture(texture->Object());
}

void WebGLRenderingContextBase::lineWidth(GLfloat width) {
  if (isContextLost())
    return;
  ContextGL()->LineWidth(width);
}

void WebGLRenderingContextBase::linkProgram(WebGLProgram* program) {
  if (!ValidateWebGLProgramOrShader("linkProgram", program))
    return;

  if (program->ActiveTransformFeedbackCount() > 0) {
    SynthesizeGLError(
        GL_INVALID_OPERATION, "linkProgram",
        "program being used by one or more active transform feedback objects");
    return;
  }

  GLuint query = 0u;
  if (ExtensionEnabled(kKHRParallelShaderCompileName)) {
    ContextGL()->GenQueriesEXT(1, &query);
    ContextGL()->BeginQueryEXT(GL_PROGRAM_COMPLETION_QUERY_CHROMIUM, query);
  }
  ContextGL()->LinkProgram(ObjectOrZero(program));
  if (ExtensionEnabled(kKHRParallelShaderCompileName)) {
    ContextGL()->EndQueryEXT(GL_PROGRAM_COMPLETION_QUERY_CHROMIUM);
    addProgramCompletionQuery(program, query);
  }

  program->IncreaseLinkCount();
}

void WebGLRenderingContextBase::pixelStorei(GLenum pname, GLint param) {
  if (isContextLost())
    return;
  switch (pname) {
    case GC3D_UNPACK_FLIP_Y_WEBGL:
      unpack_flip_y_ = param;
      break;
    case GC3D_UNPACK_PREMULTIPLY_ALPHA_WEBGL:
      unpack_premultiply_alpha_ = param;
      break;
    case GC3D_UNPACK_COLORSPACE_CONVERSION_WEBGL:
      if (static_cast<GLenum>(param) == GC3D_BROWSER_DEFAULT_WEBGL ||
          param == GL_NONE) {
        unpack_colorspace_conversion_ = static_cast<GLenum>(param);
      } else {
        SynthesizeGLError(
            GL_INVALID_VALUE, "pixelStorei",
            "invalid parameter for UNPACK_COLORSPACE_CONVERSION_WEBGL");
        return;
      }
      break;
    case GL_PACK_ALIGNMENT:
    case GL_UNPACK_ALIGNMENT:
      if (param == 1 || param == 2 || param == 4 || param == 8) {
        if (pname == GL_PACK_ALIGNMENT) {
          pack_alignment_ = param;
        } else {  // GL_UNPACK_ALIGNMENT:
          unpack_alignment_ = param;
        }
        ContextGL()->PixelStorei(pname, param);
      } else {
        SynthesizeGLError(GL_INVALID_VALUE, "pixelStorei",
                          "invalid parameter for alignment");
        return;
      }
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "pixelStorei",
                        "invalid parameter name");
      return;
  }
}

void WebGLRenderingContextBase::polygonOffset(GLfloat factor, GLfloat units) {
  if (isContextLost())
    return;
  ContextGL()->PolygonOffset(factor, units);
}

bool WebGLRenderingContextBase::ValidateReadBufferAndGetInfo(
    const char* function_name,
    WebGLFramebuffer*& read_framebuffer_binding) {
  read_framebuffer_binding = GetReadFramebufferBinding();
  if (read_framebuffer_binding) {
    const char* reason = "framebuffer incomplete";
    if (read_framebuffer_binding->CheckDepthStencilStatus(&reason) !=
        GL_FRAMEBUFFER_COMPLETE) {
      SynthesizeGLError(GL_INVALID_FRAMEBUFFER_OPERATION, function_name,
                        reason);
      return false;
    }
  } else {
    if (read_buffer_of_default_framebuffer_ == GL_NONE) {
      DCHECK(IsWebGL2());
      SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                        "no image to read from");
      return false;
    }
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateReadPixelsFormatAndType(
    GLenum format,
    GLenum type,
    DOMArrayBufferView* buffer) {
  switch (format) {
    case GL_ALPHA:
    case GL_RGB:
    case GL_RGBA:
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
    case GL_FLOAT:
      if (ExtensionEnabled(kOESTextureFloatName) ||
          ExtensionEnabled(kOESTextureHalfFloatName)) {
        if (buffer && buffer->GetType() != DOMArrayBufferView::kTypeFloat32) {
          SynthesizeGLError(GL_INVALID_OPERATION, "readPixels",
                            "type FLOAT but ArrayBufferView not Float32Array");
          return false;
        }
        return true;
      }
      SynthesizeGLError(GL_INVALID_ENUM, "readPixels", "invalid type");
      return false;
    case GL_HALF_FLOAT_OES:
      if (ExtensionEnabled(kOESTextureHalfFloatName)) {
        if (buffer && buffer->GetType() != DOMArrayBufferView::kTypeUint16) {
          SynthesizeGLError(
              GL_INVALID_OPERATION, "readPixels",
              "type HALF_FLOAT_OES but ArrayBufferView not Uint16Array");
          return false;
        }
        return true;
      }
      SynthesizeGLError(GL_INVALID_ENUM, "readPixels", "invalid type");
      return false;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "readPixels", "invalid type");
      return false;
  }
}

WebGLImageConversion::PixelStoreParams
WebGLRenderingContextBase::GetPackPixelStoreParams() {
  WebGLImageConversion::PixelStoreParams params;
  params.alignment = pack_alignment_;
  return params;
}

WebGLImageConversion::PixelStoreParams
WebGLRenderingContextBase::GetUnpackPixelStoreParams(TexImageDimension) {
  WebGLImageConversion::PixelStoreParams params;
  params.alignment = unpack_alignment_;
  return params;
}

bool WebGLRenderingContextBase::ValidateReadPixelsFuncParameters(
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    DOMArrayBufferView* buffer,
    int64_t buffer_size) {
  if (!ValidateReadPixelsFormatAndType(format, type, buffer))
    return false;

  // Calculate array size, taking into consideration of pack parameters.
  unsigned bytes_required = 0;
  unsigned skip_bytes = 0;
  GLenum error = WebGLImageConversion::ComputeImageSizeInBytes(
      format, type, width, height, 1, GetPackPixelStoreParams(),
      &bytes_required, nullptr, &skip_bytes);
  if (error != GL_NO_ERROR) {
    SynthesizeGLError(error, "readPixels", "invalid dimensions");
    return false;
  }
  int64_t total_bytes_required =
      static_cast<int64_t>(bytes_required) + static_cast<int64_t>(skip_bytes);
  if (buffer_size < total_bytes_required) {
    SynthesizeGLError(GL_INVALID_OPERATION, "readPixels",
                      "buffer is not large enough for dimensions");
    return false;
  }
  if (kMaximumSupportedArrayBufferSize <
      static_cast<size_t>(total_bytes_required)) {
    SynthesizeGLError(GL_INVALID_VALUE, "readPixels",
                      "amount of read pixels is too high");
    return false;
  }
  return true;
}

void WebGLRenderingContextBase::readPixels(
    GLint x,
    GLint y,
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> pixels) {
  ReadPixelsHelper(x, y, width, height, format, type, pixels.Get(), 0);
}

void WebGLRenderingContextBase::ReadPixelsHelper(GLint x,
                                                 GLint y,
                                                 GLsizei width,
                                                 GLsizei height,
                                                 GLenum format,
                                                 GLenum type,
                                                 DOMArrayBufferView* pixels,
                                                 int64_t offset) {
  if (isContextLost())
    return;
  // Due to WebGL's same-origin restrictions, it is not possible to
  // taint the origin using the WebGL API.
  DCHECK(Host()->OriginClean());

  // Validate input parameters.
  if (!pixels) {
    SynthesizeGLError(GL_INVALID_VALUE, "readPixels",
                      "no destination ArrayBufferView");
    return;
  }
  base::CheckedNumeric<size_t> offset_in_bytes = offset;
  offset_in_bytes *= pixels->TypeSize();
  if (!offset_in_bytes.IsValid() ||
      offset_in_bytes.ValueOrDie() > pixels->byteLength()) {
    SynthesizeGLError(GL_INVALID_VALUE, "readPixels",
                      "destination offset out of range");
    return;
  }
  const char* reason = "framebuffer incomplete";
  WebGLFramebuffer* framebuffer = GetReadFramebufferBinding();
  if (framebuffer && framebuffer->CheckDepthStencilStatus(&reason) !=
                         GL_FRAMEBUFFER_COMPLETE) {
    SynthesizeGLError(GL_INVALID_FRAMEBUFFER_OPERATION, "readPixels", reason);
    return;
  }
  base::CheckedNumeric<GLuint> buffer_size =
      pixels->byteLength() - offset_in_bytes;
  if (!buffer_size.IsValid()) {
    SynthesizeGLError(GL_INVALID_VALUE, "readPixels",
                      "destination offset out of range");
    return;
  }
  if (!ValidateReadPixelsFuncParameters(width, height, format, type, pixels,
                                        buffer_size.ValueOrDie())) {
    return;
  }
  ClearIfComposited(kClearCallerOther);

  uint8_t* data = static_cast<uint8_t*>(pixels->BaseAddressMaybeShared()) +
                  offset_in_bytes.ValueOrDie();

  // We add special handling here if the 'ArrayBufferView' is size '0' and the
  // backing store is 'nullptr'. 'ReadPixels' creates an error if the provided
  // data is 'nullptr'. However, in the case that we want to read zero pixels,
  // we want to avoid this error. Therefore we provide temporary memory here if
  // 'ArrayBufferView' does not provide a backing store but we actually read
  // zero pixels.
  std::optional<Vector<uint8_t>> buffer;
  if (!data && (width == 0 || height == 0)) {
    buffer.emplace(32);
    data = buffer->data();
  }

  // Last-chance early-out, in case somehow the context was lost during
  // the above ClearIfComposited operation.
  if (isContextLost() || !GetDrawingBuffer())
    return;

  {
    ScopedDrawingBufferBinder binder(GetDrawingBuffer(), framebuffer);
    if (!binder.Succeeded()) {
      return;
    }
    ContextGL()->ReadPixels(x, y, width, height, format, type, data);

    if (IdentifiabilityStudySettings::Get()->ShouldSampleType(
            IdentifiableSurface::Type::kWebFeature)) {
      const auto& ukm_params = GetUkmParameters();
      IdentifiabilityMetricBuilder(ukm_params.source_id)
          .AddWebFeature(WebFeature::kWebGLRenderingContextReadPixels,
                         IdentifiableToken())
          .Record(ukm_params.ukm_recorder);
    }
  }
}

void WebGLRenderingContextBase::RenderbufferStorageImpl(
    GLenum target,
    GLsizei samples,
    GLenum internalformat,
    GLsizei width,
    GLsizei height,
    const char* function_name) {
  DCHECK(!samples);     // |samples| > 0 is only valid in WebGL2's
                        // renderbufferStorageMultisample().
  DCHECK(!IsWebGL2());  // Make sure this is overridden in WebGL 2.
  switch (internalformat) {
    case GL_DEPTH_COMPONENT16:
    case GL_RGBA4:
    case GL_RGB5_A1:
    case GL_RGB565:
    case GL_STENCIL_INDEX8:
    case GL_SRGB8_ALPHA8_EXT:
    case GL_RGB16F_EXT:
    case GL_RGBA16F_EXT:
    case GL_RGBA32F_EXT:
      if (internalformat == GL_SRGB8_ALPHA8_EXT &&
          !ExtensionEnabled(kEXTsRGBName)) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "EXT_sRGB not enabled");
        break;
      }
      if ((internalformat == GL_RGB16F_EXT ||
           internalformat == GL_RGBA16F_EXT) &&
          !ExtensionEnabled(kEXTColorBufferHalfFloatName)) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "EXT_color_buffer_half_float not enabled");
        break;
      }
      if (internalformat == GL_RGBA32F_EXT &&
          !ExtensionEnabled(kWebGLColorBufferFloatName)) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "WEBGL_color_buffer_float not enabled");
        break;
      }
      ContextGL()->RenderbufferStorage(target, internalformat, width, height);
      renderbuffer_binding_->SetInternalFormat(internalformat);
      renderbuffer_binding_->SetSize(width, height);
      break;
    case GL_DEPTH_STENCIL_OES:
      DCHECK(IsDepthStencilSupported());
      ContextGL()->RenderbufferStorage(target, GL_DEPTH24_STENCIL8_OES, width,
                                       height);
      renderbuffer_binding_->SetSize(width, height);
      renderbuffer_binding_->SetInternalFormat(internalformat);
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid internalformat");
      break;
  }
  UpdateNumberOfUserAllocatedMultisampledRenderbuffers(
      renderbuffer_binding_->UpdateMultisampleState(false));
}

void WebGLRenderingContextBase::renderbufferStorage(GLenum target,
                                                    GLenum internalformat,
                                                    GLsizei width,
                                                    GLsizei height) {
  const char* function_name = "renderbufferStorage";
  if (isContextLost())
    return;
  if (target != GL_RENDERBUFFER) {
    SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid target");
    return;
  }
  if (!renderbuffer_binding_ || !renderbuffer_binding_->Object()) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "no bound renderbuffer");
    return;
  }
  if (!ValidateSize(function_name, width, height))
    return;
  RenderbufferStorageImpl(target, 0, internalformat, width, height,
                          function_name);
  ApplyDepthAndStencilTest();
}

void WebGLRenderingContextBase::sampleCoverage(GLfloat value,
                                               GLboolean invert) {
  if (isContextLost())
    return;
  ContextGL()->SampleCoverage(value, invert);
}

void WebGLRenderingContextBase::scissor(GLint x,
                                        GLint y,
                                        GLsizei width,
                                        GLsizei height) {
  if (isContextLost())
    return;
  scissor_box_[0] = x;
  scissor_box_[1] = y;
  scissor_box_[2] = width;
  scissor_box_[3] = height;
  ContextGL()->Scissor(x, y, width, height);
}

void WebGLRenderingContextBase::shaderSource(WebGLShader* shader,
                                             const String& string) {
  if (!ValidateWebGLProgramOrShader("shaderSource", shader))
    return;
  String ascii_string = ReplaceNonASCII(string).Result();
  shader->SetSource(string);
  DCHECK(ascii_string.Is8Bit() && ascii_string.ContainsOnlyASCIIOrEmpty());
  const GLchar* shader_data =
      reinterpret_cast<const GLchar*>(ascii_string.Characters8());
  const GLint shader_length = ascii_string.length();
  ContextGL()->ShaderSource(ObjectOrZero(shader), 1, &shader_data,
                            &shader_length);
}

void WebGLRenderingContextBase::stencilFunc(GLenum func,
                                            GLint ref,
                                            GLuint mask) {
  if (isContextLost())
    return;
  if (!ValidateStencilOrDepthFunc("stencilFunc", func))
    return;
  stencil_func_ref_ = ref;
  stencil_func_ref_back_ = ref;
  stencil_func_mask_ = mask;
  stencil_func_mask_back_ = mask;
  ContextGL()->StencilFunc(func, ref, mask);
}

void WebGLRenderingContextBase::stencilFuncSeparate(GLenum face,
                                                    GLenum func,
                                                    GLint ref,
                                                    GLuint mask) {
  if (isContextLost())
    return;
  if (!ValidateStencilOrDepthFunc("stencilFuncSeparate", func))
    return;
  switch (face) {
    case GL_FRONT_AND_BACK:
      stencil_func_ref_ = ref;
      stencil_func_ref_back_ = ref;
      stencil_func_mask_ = mask;
      stencil_func_mask_back_ = mask;
      break;
    case GL_FRONT:
      stencil_func_ref_ = ref;
      stencil_func_mask_ = mask;
      break;
    case GL_BACK:
      stencil_func_ref_back_ = ref;
      stencil_func_mask_back_ = mask;
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "stencilFuncSeparate", "invalid face");
      return;
  }
  ContextGL()->StencilFuncSeparate(face, func, ref, mask);
}

void WebGLRenderingContextBase::stencilMask(GLuint mask) {
  if (isContextLost())
    return;
  stencil_mask_ = mask;
  stencil_mask_back_ = mask;
  ContextGL()->StencilMask(mask);
}

void WebGLRenderingContextBase::stencilMaskSeparate(GLenum face, GLuint mask) {
  if (isContextLost())
    return;
  switch (face) {
    case GL_FRONT_AND_BACK:
      stencil_mask_ = mask;
      stencil_mask_back_ = mask;
      break;
    case GL_FRONT:
      stencil_mask_ = mask;
      break;
    case GL_BACK:
      stencil_mask_back_ = mask;
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "stencilMaskSeparate", "invalid face");
      return;
  }
  ContextGL()->StencilMaskSeparate(face, mask);
}

void WebGLRenderingContextBase::stencilOp(GLenum fail,
                                          GLenum zfail,
                                          GLenum zpass) {
  if (isContextLost())
    return;
  ContextGL()->StencilOp(fail, zfail, zpass);
}

void WebGLRenderingContextBase::stencilOpSeparate(GLenum face,
                                                  GLenum fail,
                                                  GLenum zfail,
                                                  GLenum zpass) {
  if (isContextLost())
    return;
  ContextGL()->StencilOpSeparate(face, fail, zfail, zpass);
}

GLenum WebGLRenderingContextBase::ConvertTexInternalFormat(
    GLenum internalformat,
    GLenum type) {
  // Convert to sized internal formats that are renderable with
  // GL_CHROMIUM_color_buffer_float_rgb(a).
  if (type == GL_FLOAT && internalformat == GL_RGBA &&
      ExtensionsUtil()->IsExtensionEnabled(
          "GL_CHROMIUM_color_buffer_float_rgba"))
    return GL_RGBA32F_EXT;
  if (type == GL_FLOAT && internalformat == GL_RGB &&
      ExtensionsUtil()->IsExtensionEnabled(
          "GL_CHROMIUM_color_buffer_float_rgb"))
    return GL_RGB32F_EXT
"""


```