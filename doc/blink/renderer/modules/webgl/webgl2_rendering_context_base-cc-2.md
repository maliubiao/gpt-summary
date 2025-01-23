Response:
My thinking process to analyze the provided code snippet and generate the response involved several steps:

1. **Understand the Context:** The prompt clearly states this is part of the `WebGL2RenderingContextBase` class in the Chromium Blink engine. This immediately tells me the code is responsible for implementing WebGL 2.0 functionalities within a web browser. The "part 3 of 7" indicates this is a segment of a larger file, likely organized logically.

2. **Identify Key Functionalities:** I started by scanning the method signatures. A significant number of methods relate to texture manipulation: `texSubImage2D`, `texStorage2D`, `texStorage3D`, `texImage3D`, `texSubImage3D`, `copyTexSubImage3D`, `compressedTexImage2D`, `compressedTexSubImage2D`, `compressedTexImage3D`, `compressedTexSubImage3D`. This strongly suggests that this section focuses heavily on texture-related operations in WebGL 2.0.

3. **Analyze Individual Methods:** For each method, I considered:
    * **Purpose:** What is the core action of this function?  The names are generally descriptive (e.g., `texSubImage2D` updates a portion of a 2D texture).
    * **Parameters:** What inputs does the function take?  This includes texture targets, levels of detail (mipmaps), offsets, dimensions, data formats, and data sources (like `DOMArrayBufferView`, `ImageData`, `HTMLImageElement`, etc.).
    * **Error Handling:**  The code contains numerous checks for `isContextLost()` and `bound_pixel_unpack_buffer_`. The use of `SynthesizeGLError` is a key indicator of how WebGL errors are handled and reported back to the JavaScript layer.
    * **Dependencies:**  The code interacts with `ContextGL()`, which likely represents the underlying OpenGL ES 3.0 context. It also interacts with other Blink types like `WebGLTexture`, `WebGLFramebuffer`, `ScriptState`, and various HTML elements.

4. **Look for Patterns and Groupings:** I noticed that many methods have overloaded versions accepting different types of data sources (e.g., `DOMArrayBufferView`, `ImageData`, HTML elements). This is a common pattern in WebGL to allow flexible data input. I also grouped functions based on whether they dealt with 2D or 3D textures, and whether they were about creating/defining storage (`texStorage`) or uploading/updating data (`texImage`, `texSubImage`, `compressedTexImage`, `compressedTexSubImage`).

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** I considered how these C++ functions are exposed to the web. WebGL APIs are directly callable from JavaScript. The data sources (HTML elements, canvas, images, videos) clearly show the integration of WebGL with the DOM. While CSS doesn't directly interact with these low-level texture functions, the *results* of WebGL rendering can be displayed within the context of a web page styled with CSS.

6. **Infer Logic and Assumptions:**  I made assumptions about the role of certain parameters. For example, `level` likely refers to mipmap levels. The `target` parameter specifies the type of texture being manipulated. The presence of `unpack_flip_y_` and `unpack_premultiply_alpha_` suggests internal image processing steps.

7. **Consider User Errors:**  The error handling logic provided clues about common mistakes users might make, such as using a bound pixel unpack buffer when it's not allowed or providing out-of-range offsets.

8. **Trace User Operations (Debugging Clues):**  I thought about how a web developer might end up triggering these functions. It would involve writing JavaScript code that uses the WebGL 2.0 API to load and manipulate textures. Common scenarios include loading image assets, using video as a texture source, or processing data from `<canvas>` elements.

9. **Synthesize the Summary:** Based on the analysis, I formulated a concise summary of the code's purpose, focusing on texture manipulation and the different data sources supported.

10. **Structure the Response:** I organized the information into logical sections: overall functionality, connections to web technologies, logical assumptions, user errors, debugging hints, and a final summary. This provides a comprehensive overview of the code snippet.

Essentially, I performed a static code analysis, combined with my knowledge of WebGL and the structure of the Chromium rendering engine, to deduce the functionality and purpose of the provided code. The presence of clear naming conventions and error handling made this process significantly easier.
好的，这是对代码片段的功能归纳：

**功能归纳 (第 3 部分): 专注于 WebGL 2 上传和定义纹理数据**

这段代码主要集中在 `WebGL2RenderingContextBase` 类中用于**上传和定义纹理数据**的功能，特别是针对 2D 和 3D 纹理。 它涵盖了以下关键方面：

* **纹理数据上传 (`texImage2D`, `texImage3D`):**  提供了多种重载方法，允许从不同来源上传纹理数据，包括：
    * `DOMArrayBufferView` (类型化数组，二进制数据)
    * `ImageData` (包含像素数据的对象)
    * `HTMLImageElement` (<img> 元素)
    * `HTMLCanvasElement` ( <canvas> 元素)
    * `HTMLVideoElement` ( <video> 元素)
    * `VideoFrame` (视频帧对象)
    * `ImageBitmap` (图像位图对象)
    * 已绑定到 `PIXEL_UNPACK_BUFFER` 的缓冲区对象

* **纹理子区域更新 (`texSubImage2D`, `texSubImage3D`):** 类似于 `texImage`，但允许更新纹理的特定区域，而不是整个纹理。它同样支持多种数据来源。

* **纹理存储定义 (`texStorage2D`, `texStorage3D`):**  允许预先分配纹理的存储空间，并指定纹理的格式和级别数。这在性能方面可能更优，因为可以避免在上传数据时进行隐式分配。

* **压缩纹理支持 (`compressedTexImage2D`, `compressedTexImage3D`, `compressedTexSubImage2D`, `compressedTexSubImage3D`):**  处理上传压缩格式的纹理数据，可以减少纹理占用的内存和带宽。

* **从帧缓冲区复制纹理 (`copyTexSubImage3D`):**  允许将帧缓冲区的一部分内容复制到 3D 纹理的子区域。

* **错误处理和状态检查:**  在执行操作前，会检查 WebGL 上下文是否丢失 (`isContextLost()`)，以及是否有缓冲区绑定到 `PIXEL_UNPACK_BUFFER`，并根据 WebGL 规范生成相应的错误。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**  这些 C++ 方法是 WebGL 2 API 在 Blink 引擎中的底层实现。开发者通过 JavaScript 调用 WebGL 2 API，最终会调用到这些 C++ 代码。

   **举例:**  在 JavaScript 中，你可以使用以下代码将一个 `<img>` 元素的图像数据上传到 WebGL 纹理：

   ```javascript
   const gl = canvas.getContext('webgl2');
   const texture = gl.createTexture();
   gl.bindTexture(gl.TEXTURE_2D, texture);
   const image = document.getElementById('myImage'); // 获取 HTMLImageElement
   gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, image);
   gl.generateMipmap(gl.TEXTURE_2D);
   ```
   这个 JavaScript 调用 `gl.texImage2D`  会触发 `WebGL2RenderingContextBase::texImage2D`  的相应 C++ 实现。

* **HTML:**  HTML 元素 (如 `<img>`, `<canvas>`, `<video>`) 可以作为 WebGL 纹理的数据源。

   **举例:**  如上面的 JavaScript 例子所示，`document.getElementById('myImage')`  获取的 HTML `<img>` 元素被用作 `texImage2D` 的数据来源。

* **CSS:**  CSS 本身不直接参与 WebGL 纹理数据的上传和定义。但是，WebGL 渲染的结果会被绘制到 `<canvas>` 元素上，而 `<canvas>` 元素的样式可以通过 CSS 进行控制（例如，大小、位置、边框等）。

   **举例:**  你可以使用 CSS 来设置 `<canvas>` 元素的大小：

   ```html
   <canvas id="webglCanvas" style="width: 500px; height: 300px;"></canvas>
   ```
   WebGL 在这个 canvas 上渲染的内容，其纹理数据由上述 C++ 代码处理。

**逻辑推理、假设输入与输出:**

**假设输入 (以 `texImage2D` 从 `HTMLImageElement` 上传为例):**

* `target`: `GL_TEXTURE_2D` (目标纹理类型)
* `level`: `0` (mipmap 级别)
* `internalformat`: `GL_RGBA` (纹理内部格式)
* `format`: `GL_RGBA` (源数据格式)
* `type`: `GL_UNSIGNED_BYTE` (源数据类型)
* `image`: 一个已加载完成的 `HTMLImageElement` 对象，其包含一个 64x64 像素的 PNG 图像。
* `exception_state`: 一个用于报告异常状态的对象。

**逻辑推理:**

1. 代码会首先检查 `isContextLost()`，如果上下文丢失则直接返回。
2. 检查 `bound_pixel_unpack_buffer_`，如果绑定了缓冲区，则生成 `GL_INVALID_OPERATION` 错误，因为在这种情况下不允许直接使用图像元素。
3. 创建一个 `TexImageParams` 结构体，填充相关参数，并指定数据源为 `kSourceHTMLImageElement`。
4. 调用 `ExecutionContext::From(script_state)->GetSecurityOrigin()` 获取安全源，用于跨域检查。
5. 调用 `TexImageHelperHTMLImageElement`，该函数会：
   * 检查图像是否已加载完成。
   * 检查跨域问题。
   * 从图像数据中提取像素信息。
   * 调用底层的 OpenGL ES API (`ContextGL()->TexImage2D`) 将像素数据上传到 GPU。

**假设输出:**

* 如果一切顺利，GPU 上会创建一个 64x64 的 2D 纹理，其数据来源于 `HTMLImageElement`。
* 如果出现错误（例如，上下文丢失、跨域问题、图像未加载），则 `exception_state` 对象会被设置相应的错误信息，并且可能会调用 `SynthesizeGLError` 生成 WebGL 错误。

**用户或编程常见的使用错误:**

1. **在绑定了 `PIXEL_UNPACK_BUFFER` 时，尝试直接使用图像、画布或视频元素作为 `texImage` 或 `texSubImage` 的数据源。**  WebGL 规范规定，当 `PIXEL_UNPACK_BUFFER` 被绑定时，数据来源必须是缓冲区对象。

   **错误示例 (JavaScript):**
   ```javascript
   gl.bindBuffer(gl.PIXEL_UNPACK_BUFFER, unpackBuffer);
   const image = document.getElementById('myImage');
   gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, image); // 错误！
   ```
   **C++ 代码会检测到这种情况并生成 `GL_INVALID_OPERATION` 错误。**

2. **在不支持 `unpack_flip_y` 或 `unpack_premultiply_alpha` 的情况下尝试上传 3D 纹理。**  这些参数控制着上传图像数据的预处理，但对 3D 纹理有限制。

   **错误示例 (假设 JavaScript 中设置了 `UNPACK_FLIP_Y_WEBGL` 为 true):**
   ```javascript
   gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, true);
   const data = new Uint8Array(width * height * depth * 4);
   gl.texImage3D(gl.TEXTURE_3D, 0, gl.RGBA, width, height, depth, 0, gl.RGBA, gl.UNSIGNED_BYTE, data); // 可能会导致错误
   ```
   **C++ 代码会检测到这种情况并生成 `GL_INVALID_OPERATION` 错误。**

3. **为压缩纹理上传提供了错误的 `src_offset` 或 `src_length_override`，导致访问越界。**

   **错误示例 (JavaScript):**
   ```javascript
   const compressedData = new Uint8Array(100);
   gl.compressedTexImage2D(gl.TEXTURE_2D, 0, gl.COMPRESSED_RGBA_S3TC_DXT1_EXT, width, height, 0, compressedData, 50, 100); // 错误：length 超出范围
   ```
   **C++ 代码会检查这些值，并在超出范围时生成 `GL_INVALID_VALUE` 错误。**

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在浏览器中打开一个网页。**
2. **网页的 JavaScript 代码获取一个 `<canvas>` 元素的 WebGL 2 上下文。**
3. **JavaScript 代码创建一个或多个纹理对象 (`gl.createTexture()`).**
4. **JavaScript 代码调用 `gl.bindTexture()` 将纹理绑定到特定的纹理单元。**
5. **JavaScript 代码调用 `gl.texImage2D`、`gl.texImage3D`、`gl.texSubImage2D`、`gl.texSubImage3D` 或相关的压缩纹理上传函数。**  这些调用会携带纹理的目标、级别、格式、类型以及数据源（例如，`HTMLImageElement`、`ImageData`、`ArrayBufferView` 等）。
6. **浏览器引擎接收到这些 JavaScript 调用，并将它们转换为对 Blink 渲染引擎中 `WebGL2RenderingContextBase` 相应 C++ 方法的调用。**
7. **执行到 `webgl2_rendering_context_base.cc` 文件中的对应方法，开始执行纹理数据上传和定义的逻辑，包括错误检查、数据处理以及调用底层的 OpenGL ES 3.0 API。**

在调试 WebGL 应用程序时，如果纹理相关的操作出现问题，可以通过以下方式进行排查，从而定位到这段 C++ 代码的执行：

* **检查浏览器的开发者工具控制台中的 WebGL 错误信息。** `SynthesizeGLError` 生成的错误会在这里显示。
* **在 JavaScript 代码中设置断点，查看传递给 WebGL API 函数的参数是否正确。**
* **使用 WebGL 调试器 (例如 SpectorJS) 来捕获 WebGL 调用序列，并查看纹理对象的状态。**
* **如果需要深入了解 Blink 引擎的执行流程，可以在 Blink 源代码中设置断点，例如在 `WebGL2RenderingContextBase::texImage2D` 等方法中。**

总而言之，这段代码是 WebGL 2 规范中纹理上传和定义功能的核心实现，它负责将来自各种 Web 内容的数据转化为 GPU 可以理解的纹理格式，并在过程中进行必要的错误处理和状态管理。

### 提示词
```
这是目录为blink/renderer/modules/webgl/webgl2_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
exception_state);
}

void WebGL2RenderingContextBase::texSubImage2D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLenum format,
    GLenum type,
    HTMLVideoElement* video,
    ExceptionState& exception_state) {
  WebGLRenderingContextBase::texSubImage2D(script_state, target, level, xoffset,
                                           yoffset, format, type, video,
                                           exception_state);
}

void WebGL2RenderingContextBase::texSubImage2D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLenum format,
    GLenum type,
    VideoFrame* frame,
    ExceptionState& exception_state) {
  WebGLRenderingContextBase::texSubImage2D(script_state, target, level, xoffset,
                                           yoffset, format, type, frame,
                                           exception_state);
}

void WebGL2RenderingContextBase::texSubImage2D(
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLenum format,
    GLenum type,
    ImageBitmap* bitmap,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  WebGLRenderingContextBase::texSubImage2D(
      target, level, xoffset, yoffset, format, type, bitmap, exception_state);
}

void WebGL2RenderingContextBase::texStorage2D(GLenum target,
                                              GLsizei levels,
                                              GLenum internalformat,
                                              GLsizei width,
                                              GLsizei height) {
  if (isContextLost())
    return;

  WebGLTexture* tex = nullptr;
  switch (target) {
    case GL_TEXTURE_2D:
      tex = texture_units_[active_texture_unit_].texture2d_binding_.Get();
      break;
    case GL_TEXTURE_CUBE_MAP:
      tex =
          texture_units_[active_texture_unit_].texture_cube_map_binding_.Get();
      break;
  }

  if (tex && tex->IsOpaqueTexture()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texStorage2D",
                      "cannot invoke function with an opaque texture");
    return;
  }

  ContextGL()->TexStorage2DEXT(target, levels, internalformat, width, height);
}

void WebGL2RenderingContextBase::texStorage3D(GLenum target,
                                              GLsizei levels,
                                              GLenum internalformat,
                                              GLsizei width,
                                              GLsizei height,
                                              GLsizei depth) {
  if (isContextLost())
    return;

  WebGLTexture* tex = nullptr;
  switch (target) {
    case GL_TEXTURE_3D:
      tex = texture_units_[active_texture_unit_].texture3d_binding_.Get();
      break;
    case GL_TEXTURE_2D_ARRAY:
      tex = texture_units_[active_texture_unit_].texture2d_array_binding_.Get();
      break;
  }

  if (tex && tex->IsOpaqueTexture()) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texStorage3D",
                      "cannot invoke function with an opaque texture");
    return;
  }

  ContextGL()->TexStorage3D(target, levels, internalformat, width, height,
                            depth);
}

void WebGL2RenderingContextBase::texImage3D(
    GLenum target,
    GLint level,
    GLint internalformat,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    GLint border,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> pixels) {
  if ((unpack_flip_y_ || unpack_premultiply_alpha_) && pixels) {
    SynthesizeGLError(
        GL_INVALID_OPERATION, "texImage3D",
        "FLIP_Y or PREMULTIPLY_ALPHA isn't allowed for uploading 3D textures");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_3D_PARAMS(params, kSourceArrayBufferView);
  TexImageHelperDOMArrayBufferView(params, pixels.Get(), kNullAllowed, 0);
}

void WebGL2RenderingContextBase::texImage3D(
    GLenum target,
    GLint level,
    GLint internalformat,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    GLint border,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> pixels,
    GLuint src_offset) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  if (unpack_flip_y_ || unpack_premultiply_alpha_) {
    DCHECK(pixels);
    SynthesizeGLError(
        GL_INVALID_OPERATION, "texImage3D",
        "FLIP_Y or PREMULTIPLY_ALPHA isn't allowed for uploading 3D textures");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_3D_PARAMS(params, kSourceArrayBufferView);
  TexImageHelperDOMArrayBufferView(params, pixels.Get(), kNullNotReachable,
                                   src_offset);
}

void WebGL2RenderingContextBase::texImage3D(GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLsizei depth,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            int64_t offset) {
  if (isContextLost())
    return;
  if (!ValidateTexture3DBinding("texImage3D", target, true))
    return;
  if (!bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage3D",
                      "no bound PIXEL_UNPACK_BUFFER");
    return;
  }
  if (unpack_flip_y_ || unpack_premultiply_alpha_) {
    SynthesizeGLError(
        GL_INVALID_OPERATION, "texImage3D",
        "FLIP_Y or PREMULTIPLY_ALPHA isn't allowed for uploading 3D textures");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_3D_PARAMS(params, kSourceUnpackBuffer);
  if (!ValidateTexFunc(params, std::nullopt, std::nullopt)) {
    return;
  }
  if (!ValidateValueFitNonNegInt32("texImage3D", "offset", offset))
    return;

  ContextGL()->TexImage3D(target, level,
                          ConvertTexInternalFormat(internalformat, type), width,
                          height, depth, border, format, type,
                          reinterpret_cast<const void*>(offset));
}

void WebGL2RenderingContextBase::texImage3D(GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLsizei depth,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            ImageData* pixels) {
  DCHECK(pixels);
  TexImageParams params;
  POPULATE_TEX_IMAGE_3D_PARAMS(params, kSourceImageData);
  params.border = 0;  // See https://crbug.com/1313604
  TexImageHelperImageData(params, pixels);
}

void WebGL2RenderingContextBase::texImage3D(ScriptState* script_state,
                                            GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLsizei depth,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            HTMLImageElement* image,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_3D_PARAMS(params, kSourceHTMLImageElement);
  params.border = 0;  // See https://crbug.com/1313604
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLImageElement(execution_context->GetSecurityOrigin(), params,
                                 image, exception_state);
}

void WebGL2RenderingContextBase::texImage3D(ScriptState* script_state,
                                            GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLsizei depth,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            CanvasRenderingContextHost* canvas,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_3D_PARAMS(params, kSourceHTMLCanvasElement);
  params.border = 0;  // See https://crbug.com/1313604
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperCanvasRenderingContextHost(
      execution_context->GetSecurityOrigin(), params, canvas, exception_state);
}

void WebGL2RenderingContextBase::texImage3D(ScriptState* script_state,
                                            GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLsizei depth,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            HTMLVideoElement* video,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_3D_PARAMS(params, kSourceHTMLVideoElement);
  params.border = 0;  // See https://crbug.com/1313604
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLVideoElement(execution_context->GetSecurityOrigin(), params,
                                 video, exception_state);
}

void WebGL2RenderingContextBase::texImage3D(ScriptState* script_state,
                                            GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLsizei depth,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            VideoFrame* frame,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_3D_PARAMS(params, kSourceVideoFrame);
  params.border = 0;  // See https://crbug.com/1313604
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperVideoFrame(execution_context->GetSecurityOrigin(), params,
                           frame, exception_state);
}

void WebGL2RenderingContextBase::texImage3D(GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLsizei depth,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            ImageBitmap* bitmap,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_3D_PARAMS(params, kSourceImageBitmap);
  params.border = 0;  // See https://crbug.com/1313604
  TexImageHelperImageBitmap(params, bitmap, exception_state);
}

void WebGL2RenderingContextBase::texSubImage3D(
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLint zoffset,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> pixels,
    GLuint src_offset) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  if (unpack_flip_y_ || unpack_premultiply_alpha_) {
    DCHECK(pixels);
    SynthesizeGLError(
        GL_INVALID_OPERATION, "texSubImage3D",
        "FLIP_Y or PREMULTIPLY_ALPHA isn't allowed for uploading 3D textures");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_3D_PARAMS(params, kSourceArrayBufferView);
  TexImageHelperDOMArrayBufferView(params, pixels.Get(), kNullNotReachable,
                                   src_offset);
}

void WebGL2RenderingContextBase::texSubImage3D(GLenum target,
                                               GLint level,
                                               GLint xoffset,
                                               GLint yoffset,
                                               GLint zoffset,
                                               GLsizei width,
                                               GLsizei height,
                                               GLsizei depth,
                                               GLenum format,
                                               GLenum type,
                                               int64_t offset) {
  if (isContextLost())
    return;
  if (!ValidateTexture3DBinding("texSubImage3D", target))
    return;
  if (!bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage3D",
                      "no bound PIXEL_UNPACK_BUFFER");
    return;
  }
  if (unpack_flip_y_ || unpack_premultiply_alpha_) {
    SynthesizeGLError(
        GL_INVALID_OPERATION, "texSubImage3D",
        "FLIP_Y or PREMULTIPLY_ALPHA isn't allowed for uploading 3D textures");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_3D_PARAMS(params, kSourceUnpackBuffer);
  if (!ValidateTexFunc(params, std::nullopt, std::nullopt)) {
    return;
  }
  if (!ValidateValueFitNonNegInt32("texSubImage3D", "offset", offset))
    return;

  ContextGL()->TexSubImage3D(target, level, xoffset, yoffset, zoffset, width,
                             height, depth, format, type,
                             reinterpret_cast<const void*>(offset));
}

void WebGL2RenderingContextBase::texSubImage3D(GLenum target,
                                               GLint level,
                                               GLint xoffset,
                                               GLint yoffset,
                                               GLint zoffset,
                                               GLsizei width,
                                               GLsizei height,
                                               GLsizei depth,
                                               GLenum format,
                                               GLenum type,
                                               ImageData* pixels) {
  DCHECK(pixels);
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_3D_PARAMS(params, kSourceImageData);
  TexImageHelperImageData(params, pixels);
}

void WebGL2RenderingContextBase::texSubImage3D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLint zoffset,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    GLenum format,
    GLenum type,
    HTMLImageElement* image,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_3D_PARAMS(params, kSourceHTMLImageElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLImageElement(execution_context->GetSecurityOrigin(), params,
                                 image, exception_state);
}

void WebGL2RenderingContextBase::texSubImage3D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLint zoffset,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    GLenum format,
    GLenum type,
    CanvasRenderingContextHost* context_host,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_3D_PARAMS(params, kSourceHTMLCanvasElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperCanvasRenderingContextHost(
      execution_context->GetSecurityOrigin(), params, context_host,
      exception_state);
}

void WebGL2RenderingContextBase::texSubImage3D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLint zoffset,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    GLenum format,
    GLenum type,
    HTMLVideoElement* video,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_3D_PARAMS(params, kSourceHTMLVideoElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLVideoElement(execution_context->GetSecurityOrigin(), params,
                                 video, exception_state);
}

void WebGL2RenderingContextBase::texSubImage3D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLint zoffset,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    GLenum format,
    GLenum type,
    VideoFrame* frame,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_3D_PARAMS(params, kSourceVideoFrame);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperVideoFrame(execution_context->GetSecurityOrigin(), params,
                           frame, exception_state);
}

void WebGL2RenderingContextBase::texSubImage3D(
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLint zoffset,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    GLenum format,
    GLenum type,
    ImageBitmap* bitmap,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_3D_PARAMS(params, kSourceImageBitmap);
  TexImageHelperImageBitmap(params, bitmap, exception_state);
}

void WebGL2RenderingContextBase::copyTexSubImage3D(GLenum target,
                                                   GLint level,
                                                   GLint xoffset,
                                                   GLint yoffset,
                                                   GLint zoffset,
                                                   GLint x,
                                                   GLint y,
                                                   GLsizei width,
                                                   GLsizei height) {
  if (isContextLost())
    return;
  if (!ValidateTexture3DBinding("copyTexSubImage3D", target))
    return;
  WebGLFramebuffer* read_framebuffer_binding = nullptr;
  if (!ValidateReadBufferAndGetInfo("copyTexSubImage3D",
                                    read_framebuffer_binding))
    return;
  ClearIfComposited(kClearCallerOther);
  ScopedDrawingBufferBinder binder(GetDrawingBuffer(),
                                   read_framebuffer_binding);
  if (!binder.Succeeded()) {
    return;
  }
  ContextGL()->CopyTexSubImage3D(target, level, xoffset, yoffset, zoffset, x, y,
                                 width, height);
}

void WebGL2RenderingContextBase::compressedTexImage2D(
    GLenum target,
    GLint level,
    GLenum internalformat,
    GLsizei width,
    GLsizei height,
    GLint border,
    MaybeShared<DOMArrayBufferView> data) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "compressedTexImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  WebGLRenderingContextBase::compressedTexImage2D(target, level, internalformat,
                                                  width, height, border, data);
}

void WebGL2RenderingContextBase::compressedTexImage2D(
    GLenum target,
    GLint level,
    GLenum internalformat,
    GLsizei width,
    GLsizei height,
    GLint border,
    MaybeShared<DOMArrayBufferView> data,
    GLuint src_offset,
    GLuint src_length_override) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "compressedTexImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  if (!ValidateTexture2DBinding("compressedTexImage2D", target, true))
    return;
  if (!ValidateCompressedTexFormat("compressedTexImage2D", internalformat))
    return;
  GLuint data_length;
  if (!ExtractDataLengthIfValid("compressedTexImage2D", data, &data_length))
    return;
  if (src_offset > data_length) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexImage2D",
                      "srcOffset is out of range");
    return;
  }
  if (src_length_override == 0) {
    src_length_override = data_length - src_offset;
  } else if (src_length_override > data_length - src_offset) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexImage2D",
                      "srcLengthOverride is out of range");
    return;
  }
  if (static_cast<size_t>(src_length_override) >
      kMaximumSupportedArrayBufferSize) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexImage2D",
                      "src_length_override exceeds the supported range");
    return;
  }
  ContextGL()->CompressedTexImage2D(
      target, level, internalformat, width, height, border, src_length_override,
      data->ByteSpanMaybeShared().subspan(src_offset).data());
}

void WebGL2RenderingContextBase::compressedTexImage2D(GLenum target,
                                                      GLint level,
                                                      GLenum internalformat,
                                                      GLsizei width,
                                                      GLsizei height,
                                                      GLint border,
                                                      GLsizei image_size,
                                                      int64_t offset) {
  if (isContextLost())
    return;
  if (!bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "compressedTexImage2D",
                      "no bound PIXEL_UNPACK_BUFFER");
    return;
  }
  ContextGL()->CompressedTexImage2D(target, level, internalformat, width,
                                    height, border, image_size,
                                    reinterpret_cast<uint8_t*>(offset));
}

void WebGL2RenderingContextBase::compressedTexSubImage2D(
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLsizei width,
    GLsizei height,
    GLenum format,
    MaybeShared<DOMArrayBufferView> data) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "compressedTexSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  WebGLRenderingContextBase::compressedTexSubImage2D(
      target, level, xoffset, yoffset, width, height, format, data);
}

void WebGL2RenderingContextBase::compressedTexSubImage2D(
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLsizei width,
    GLsizei height,
    GLenum format,
    MaybeShared<DOMArrayBufferView> data,
    GLuint src_offset,
    GLuint src_length_override) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "compressedTexSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  if (!ValidateTexture2DBinding("compressedTexSubImage2D", target))
    return;
  if (!ValidateCompressedTexFormat("compressedTexSubImage2D", format))
    return;
  GLuint data_length;
  if (!ExtractDataLengthIfValid("compressedTexSubImage2D", data, &data_length))
    return;
  if (src_offset > data_length) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexSubImage2D",
                      "srcOffset is out of range");
    return;
  }
  if (src_length_override == 0) {
    src_length_override = data_length - src_offset;
  } else if (src_length_override > data_length - src_offset) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexImage2D",
                      "srcLengthOverride is out of range");
    return;
  }
  if (static_cast<size_t>(src_length_override) >
      kMaximumSupportedArrayBufferSize) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexSubImage2D",
                      "src_length_override exceeds the supported range");
    return;
  }
  ContextGL()->CompressedTexSubImage2D(
      target, level, xoffset, yoffset, width, height, format,
      src_length_override,
      data->ByteSpanMaybeShared().subspan(src_offset).data());
}

void WebGL2RenderingContextBase::compressedTexSubImage2D(GLenum target,
                                                         GLint level,
                                                         GLint xoffset,
                                                         GLint yoffset,
                                                         GLsizei width,
                                                         GLsizei height,
                                                         GLenum format,
                                                         GLsizei image_size,
                                                         int64_t offset) {
  if (isContextLost())
    return;
  if (!bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "compressedTexSubImage2D",
                      "no bound PIXEL_UNPACK_BUFFER");
    return;
  }
  ContextGL()->CompressedTexSubImage2D(target, level, xoffset, yoffset, width,
                                       height, format, image_size,
                                       reinterpret_cast<uint8_t*>(offset));
}

void WebGL2RenderingContextBase::compressedTexImage3D(
    GLenum target,
    GLint level,
    GLenum internalformat,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    GLint border,
    MaybeShared<DOMArrayBufferView> data,
    GLuint src_offset,
    GLuint src_length_override) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "compressedTexImage3D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  if (!ValidateTexture3DBinding("compressedTexImage3D", target, true))
    return;
  if (!ValidateCompressedTexFormat("compressedTexImage3D", internalformat))
    return;
  GLuint data_length;
  if (!ExtractDataLengthIfValid("compressedTexImage3D", data, &data_length))
    return;
  if (src_offset > data_length) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexImage3D",
                      "srcOffset is out of range");
    return;
  }
  if (src_length_override == 0) {
    src_length_override = data_length - src_offset;
  } else if (src_length_override > data_length - src_offset) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexImage3D",
                      "srcLengthOverride is out of range");
    return;
  }
  if (static_cast<size_t>(src_length_override) >
      kMaximumSupportedArrayBufferSize) {
    SynthesizeGLError(GL_INVALID_VALUE, "compressedTexImage3D",
                      "src_length_override exceeds the supported range");
    return;
  }
  ContextGL()->CompressedTexImage3D(
      target, level, internalformat, width, height, depth, border,
      src_length_override,
      data->ByteSpanMaybeShared().subspan(src_offset).data());
}

void WebGL2RenderingContextBase::compressedTexImage3D(GLenum target,
                                                      GLint level,
                                                      GLenum internalformat,
                                                      GLsizei width,
                                                      GLsizei height,
                                                      GLsizei depth,
                                                      GLint border,
                                                      GLsizei image_size,
                                                      int64_t offset) {
  if (isContextLost())
    return;
  if (!bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "compressedTexImage3D",
                      "no bound PIXEL_UNPACK_BUFFER");
    return;
  }
  if (!ValidateTexture3DBinding("compressedTexImage3D", target, true))
    return;
  ContextGL()->CompressedTexImage3D(target, level, internalformat, width,
                                    height, depth, border, image_size,
                                    reinterpret_cast<uint8_t*>(offset));
}

void WebGL2RenderingContextBase::compressedTexSubImage3D(
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLint zoffset,
    GLsizei width,
    GLsizei height,
    GLsizei depth,
    GLenum format,
    MaybeShared<DOMArrayBufferView> data,
    GLuint src_offset,
    GLuint src_length_override) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "compresse
```