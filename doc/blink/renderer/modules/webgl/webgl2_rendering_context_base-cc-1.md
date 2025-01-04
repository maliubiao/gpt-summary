Response:
The user wants a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine, specifically the `blink/renderer/modules/webgl/webgl2_rendering_context_base.cc` file. This is the second part of a seven-part file.

I need to identify the core functions implemented in this section and explain their purpose within the WebGL 2 context. I should also look for connections to JavaScript, HTML, and CSS, provide usage examples, detail potential user errors, and describe how a user's actions might lead to this code being executed.

**Breakdown of the code:**

1. **`readPixels`**:  Reads pixel data from the framebuffer.
2. **`RenderbufferStorageHelper`**:  Helper function to allocate storage for renderbuffers, handling multisampling.
3. **`RenderbufferStorageImpl`**:  Implementation for `renderbufferStorage` and `renderbufferStorageMultisample`, validating parameters and handling different internal formats and extensions.
4. **`renderbufferStorageMultisample`**:  Allocates storage for a multisampled renderbuffer.
5. **`ResetUnpackParameters`**: Resets pixel unpack parameters to their default values.
6. **`RestoreUnpackParameters`**: Restores pixel unpack parameters to their previously set values.
7. **Various overloads of `texImage2D`**:  Define texture image data with various source types (ArrayBufferView, ImageData, HTMLImageElement, HTMLCanvasElement, HTMLVideoElement, VideoFrame, ImageBitmap). Some take an offset for reading from a Pixel Buffer Object (PBO).
8. **Various overloads of `texSubImage2D`**: Update a sub-rectangle of an existing texture image with various source types, similar to `texImage2D`. Some take an offset for reading from a PBO.

**Connections to JavaScript, HTML, and CSS:**

*   **JavaScript:** These C++ functions are the underlying implementations of WebGL 2 API methods exposed to JavaScript. For example, the JavaScript `gl.readPixels()`, `gl.renderbufferStorage()`, `gl.texImage2D()`, and `gl.texSubImage2D()` calls are dispatched to these C++ counterparts.
*   **HTML:**  HTML elements like `<canvas>`, `<img>`, `<video>` are often the source of data for WebGL textures. The `texImage2D` and `texSubImage2D` functions handle these cases.
*   **CSS:** While not directly involved in these specific functions, CSS styling can affect the rendering output displayed on the canvas, which WebGL draws to.

**User Actions and Debugging:**

I'll outline a typical scenario where a user interacting with a web page triggers these functions.

**Hypothetical Input and Output:**

For some functions, I can provide concrete examples. For others, the output is more abstract (e.g., GL errors).

**Common User Errors:**

I need to identify typical mistakes developers make when using these WebGL functions.
这是 `blink/renderer/modules/webgl/webgl2_rendering_context_base.cc` 文件的第二部分，主要包含了以下功能：

**1. 帧缓冲区像素读取 (readPixels):**

*   **功能:**  实现了 `readPixels` 方法，用于从帧缓冲区读取像素数据到客户端内存中指定的缓冲区。
*   **与 JavaScript 的关系:** 这是 WebGL 2 API 中 `gl.readPixels()` 方法的底层实现。JavaScript 调用此方法时，最终会执行这里的 C++ 代码。
*   **与 HTML 的关系:** 帧缓冲区最终渲染到 HTML 的 `<canvas>` 元素上。`readPixels` 可以将 canvas 上渲染的内容读取出来。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  JavaScript 调用 `gl.readPixels(0, 0, 100, 100, gl.RGBA, gl.UNSIGNED_BYTE, pixels)`，其中 `pixels` 是一个 `Uint8Array`。
    *   **输出:**  如果成功，`pixels` 数组会被填充来自帧缓冲区 (坐标 (0,0)，宽度 100，高度 100) 的 RGBA 格式的无符号字节像素数据。如果失败，会抛出 WebGL 错误。
*   **用户或编程常见使用错误:**
    *   读取前未绑定有效的帧缓冲区。
    *   提供的缓冲区大小不足以存储读取的像素数据。
    *   读取的帧缓冲区的状态不完整。
*   **用户操作如何到达这里 (调试线索):**
    1. 用户在浏览器中打开一个使用了 WebGL 2 的网页。
    2. 网页中的 JavaScript 代码调用 `gl.bindFramebuffer()` 绑定一个帧缓冲区。
    3. 网页中的 JavaScript 代码执行渲染操作，将内容绘制到该帧缓冲区。
    4. 网页中的 JavaScript 代码调用 `gl.readPixels()`，尝试读取该帧缓冲区的内容。

**2. 渲染缓冲区存储分配 (renderbufferStorage 和 renderbufferStorageMultisample):**

*   **功能:**  实现了 `renderbufferStorage` 和 `renderbufferStorageMultisample` 方法，用于为渲染缓冲区对象分配内存。`renderbufferStorageMultisample` 用于分配多重采样的渲染缓冲区。
*   **与 JavaScript 的关系:** 这是 WebGL 2 API 中 `gl.renderbufferStorage()` 和 `gl.renderbufferStorageMultisample()` 方法的底层实现。
*   **功能归纳:** 这部分代码负责处理不同内部格式 (internalformat) 和采样数 (samples) 的渲染缓冲区的内存分配。它会根据不同的内部格式检查是否需要启用特定的 WebGL 扩展，并合成相应的 GL 错误。对于某些 WebGL 1 兼容的格式，它会进行特殊的处理。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入 (renderbufferStorage):** JavaScript 调用 `gl.renderbufferStorage(gl.RENDERBUFFER, gl.RGBA8, 512, 512)`。
    *   **输出:**  如果成功，当前绑定的渲染缓冲区会分配 512x512 的 RGBA8 格式的存储空间。
    *   **假设输入 (renderbufferStorageMultisample):** JavaScript 调用 `gl.renderbufferStorageMultisample(gl.RENDERBUFFER, 4, gl.DEPTH_COMPONENT24, 512, 512)`。
    *   **输出:** 如果成功，当前绑定的渲染缓冲区会分配 512x512 的深度分量格式的存储空间，并启用 4 倍多重采样。
*   **用户或编程常见使用错误:**
    *   尝试为整数格式的渲染缓冲区分配多重采样。
    *   使用的内部格式需要特定的扩展，但该扩展未启用。
    *   在没有绑定渲染缓冲区的情况下调用。
    *   提供的宽度或高度无效。
*   **用户操作如何到达这里 (调试线索):**
    1. 用户在浏览器中打开一个使用了 WebGL 2 的网页。
    2. 网页中的 JavaScript 代码调用 `gl.createRenderbuffer()` 创建一个渲染缓冲区对象。
    3. 网页中的 JavaScript 代码调用 `gl.bindRenderbuffer()` 绑定该渲染缓冲区。
    4. 网页中的 JavaScript 代码调用 `gl.renderbufferStorage()` 或 `gl.renderbufferStorageMultisample()` 来分配存储空间。

**3. 重置和恢复像素解包参数 (ResetUnpackParameters 和 RestoreUnpackParameters):**

*   **功能:**  `ResetUnpackParameters` 将像素解包参数恢复到默认值，`RestoreUnpackParameters` 将像素解包参数恢复到之前设置的值。
*   **与 JavaScript 的关系:** 这些方法内部调用了 OpenGL 的 `PixelStorei` 函数来设置解包参数，这些参数可以通过 JavaScript 的 `gl.pixelStorei()` 方法设置。
*   **功能归纳:** 这部分代码确保在某些操作前后，像素的解包方式 (例如，行对齐、跳过的像素等) 可以被临时重置或恢复，以避免干扰。
*   **用户操作如何到达这里 (调试线索):**
    这些方法通常在内部被其他 WebGL 函数调用，例如 `texImage2D` 和 `texSubImage2D` 在从不同的数据源加载纹理数据时可能会用到。

**4. 纹理图像数据定义 (texImage2D):**

*   **功能:** 实现了多个重载的 `texImage2D` 方法，用于定义 2D 纹理图像的数据。这些重载可以接受不同类型的源数据，包括：
    *   来自 Pixel Buffer Object (PBO) 的数据。
    *   `ArrayBufferView` (例如，`Uint8Array`)。
    *   `ImageData` 对象。
    *   `HTMLImageElement` (图像元素)。
    *   `HTMLCanvasElement` (画布元素)。
    *   `HTMLVideoElement` (视频元素)。
    *   `VideoFrame` 对象。
    *   `ImageBitmap` 对象。
*   **与 JavaScript 的关系:** 这是 WebGL 2 API 中 `gl.texImage2D()` 方法的底层实现。JavaScript 调用此方法时，会根据传入的参数类型调用不同的 C++ 重载。
*   **与 HTML 的关系:**  `HTMLImageElement`、`HTMLCanvasElement` 和 `HTMLVideoElement` 是 WebGL 纹理数据常见的来源。
*   **功能归纳:** 这部分代码负责将各种来源的图像数据上传到 GPU，创建或替换纹理对象中的图像。它会进行参数校验，处理像素解包参数，并调用底层的 OpenGL 函数。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入 (ArrayBufferView):** JavaScript 调用 `gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 256, 256, 0, gl.RGBA, gl.UNSIGNED_BYTE, pixelData)`，其中 `pixelData` 是一个 `Uint8Array`。
    *   **输出:**  如果成功，当前绑定的 2D 纹理的 0 级 mipmap 会被 `pixelData` 中的数据填充。
    *   **假设输入 (HTMLImageElement):** JavaScript 调用 `gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, imageElement)`，其中 `imageElement` 是一个 `<img>` 元素。
    *   **输出:** 如果成功，当前绑定的 2D 纹理的 0 级 mipmap 会使用 `imageElement` 中的图像数据填充。
*   **用户或编程常见使用错误:**
    *   在绑定像素解包缓冲区 (PBO) 时，尝试使用 `HTMLImageElement` 等其他源。
    *   在从 PBO 上传数据时，设置了 `UNPACK_FLIP_Y_WEBGL` 或 `UNPACK_PREMULTIPLY_ALPHA_WEBGL` 参数。
    *   提供的图像数据格式与纹理的内部格式不匹配。
    *   在没有绑定纹理的情况下调用。
*   **用户操作如何到达这里 (调试线索):**
    1. 用户在浏览器中打开一个使用了 WebGL 2 的网页。
    2. 网页中的 JavaScript 代码加载了一张图片 (`<img>`) 或获取了画布 (`<canvas>`) 或视频 (`<video>`) 的内容。
    3. 网页中的 JavaScript 代码调用 `gl.createTexture()` 创建一个纹理对象。
    4. 网页中的 JavaScript 代码调用 `gl.bindTexture()` 绑定该纹理。
    5. 网页中的 JavaScript 代码调用 `gl.texImage2D()`，将图像数据上传到纹理。

**5. 纹理子区域图像数据定义 (texSubImage2D):**

*   **功能:** 实现了多个重载的 `texSubImage2D` 方法，用于更新现有 2D 纹理图像的指定矩形区域的数据。它与 `texImage2D` 类似，可以接受不同类型的源数据。
*   **与 JavaScript 的关系:** 这是 WebGL 2 API 中 `gl.texSubImage2D()` 方法的底层实现.
*   **与 HTML 的关系:** 类似于 `texImage2D`。
*   **功能归纳:** 这部分代码允许部分更新纹理的内容，而无需重新上传整个纹理。这在动态更新纹理时非常有用。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入 (ArrayBufferView):** JavaScript 调用 `gl.texSubImage2D(gl.TEXTURE_2D, 0, 10, 10, 64, 64, gl.RGBA, gl.UNSIGNED_BYTE, subPixelData)`，更新纹理中 (10, 10) 位置开始的 64x64 区域。
    *   **输出:** 如果成功，当前绑定的 2D 纹理的指定区域会被 `subPixelData` 中的数据更新。
*   **用户或编程常见使用错误:**
    *   尝试更新的子区域超出纹理的边界。
    *   其他错误与 `texImage2D` 类似，例如 PBO 的使用限制和数据格式不匹配。
*   **用户操作如何到达这里 (调试线索):**
    用户操作流程与 `texImage2D` 类似，只是在已经创建并填充过数据的纹理上调用 `gl.texSubImage2D()` 来更新部分内容。

**总结 (第2部分功能归纳):**

这部分代码主要负责处理 **帧缓冲区的像素读取** 和 **渲染缓冲区及 2D 纹理的存储分配和数据上传**。它实现了 WebGL 2 API 中与这些操作相关的核心功能，包括从不同来源 (包括 JavaScript 数组、HTML 元素等) 获取数据并将其传递给底层的 OpenGL 实现。同时，它也处理了相关的参数验证和错误处理。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl2_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共7部分，请归纳一下它的功能

"""
framebuffer = GetReadFramebufferBinding();
  if (framebuffer && framebuffer->CheckDepthStencilStatus(&reason) !=
                         GL_FRAMEBUFFER_COMPLETE) {
    SynthesizeGLError(GL_INVALID_FRAMEBUFFER_OPERATION, "readPixels", reason);
    return;
  }

  int64_t size = buffer->GetSize() - offset;
  // If size is negative, or size is not large enough to store pixels, those
  // cases are handled by validateReadPixelsFuncParameters to generate
  // INVALID_OPERATION.
  if (!ValidateReadPixelsFuncParameters(width, height, format, type, nullptr,
                                        size))
    return;

  ClearIfComposited(kClearCallerOther);

  {
    ScopedDrawingBufferBinder binder(GetDrawingBuffer(), framebuffer);
    if (!binder.Succeeded()) {
      return;
    }
    ContextGL()->ReadPixels(x, y, width, height, format, type,
                            reinterpret_cast<void*>(offset));
  }
}

void WebGL2RenderingContextBase::RenderbufferStorageHelper(
    GLenum target,
    GLsizei samples,
    GLenum internalformat,
    GLsizei width,
    GLsizei height,
    const char* function_name) {
  if (!samples) {
    ContextGL()->RenderbufferStorage(target, internalformat, width, height);
  } else {
    ContextGL()->RenderbufferStorageMultisampleCHROMIUM(
        target, samples, internalformat, width, height);
  }
}

void WebGL2RenderingContextBase::RenderbufferStorageImpl(
    GLenum target,
    GLsizei samples,
    GLenum internalformat,
    GLsizei width,
    GLsizei height,
    const char* function_name) {
  switch (internalformat) {
    case GL_R8UI:
    case GL_R8I:
    case GL_R16UI:
    case GL_R16I:
    case GL_R32UI:
    case GL_R32I:
    case GL_RG8UI:
    case GL_RG8I:
    case GL_RG16UI:
    case GL_RG16I:
    case GL_RG32UI:
    case GL_RG32I:
    case GL_RGBA8UI:
    case GL_RGBA8I:
    case GL_RGB10_A2UI:
    case GL_RGBA16UI:
    case GL_RGBA16I:
    case GL_RGBA32UI:
    case GL_RGBA32I:
      if (samples > 0) {
        SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                          "for integer formats, samples > 0");
        return;
      }
      [[fallthrough]];
    case GL_R8:
    case GL_RG8:
    case GL_RGB8:
    case GL_RGB565:
    case GL_RGBA8:
    case GL_SRGB8_ALPHA8:
    case GL_RGB5_A1:
    case GL_RGBA4:
    case GL_RGB10_A2:
    case GL_DEPTH_COMPONENT16:
    case GL_DEPTH_COMPONENT24:
    case GL_DEPTH_COMPONENT32F:
    case GL_DEPTH24_STENCIL8:
    case GL_DEPTH32F_STENCIL8:
    case GL_STENCIL_INDEX8:
      RenderbufferStorageHelper(target, samples, internalformat, width, height,
                                function_name);
      break;
    case GL_DEPTH_STENCIL:
      // To be WebGL 1 backward compatible.
      if (samples > 0) {
        SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                          "internalformat invalid for samples > 0");
        return;
      }
      RenderbufferStorageHelper(target, 0, GL_DEPTH24_STENCIL8, width, height,
                                function_name);
      break;
    case GL_R16F:
    case GL_RG16F:
    case GL_RGBA16F:
      if (!ExtensionEnabled(kEXTColorBufferFloatName) &&
          !ExtensionEnabled(kEXTColorBufferHalfFloatName)) {
        SynthesizeGLError(
            GL_INVALID_ENUM, function_name,
            "EXT_color_buffer_float/EXT_color_buffer_half_float not enabled");
        return;
      }
      RenderbufferStorageHelper(target, samples, internalformat, width, height,
                                function_name);
      break;
    case GL_R32F:
    case GL_RG32F:
    case GL_RGBA32F:
    case GL_R11F_G11F_B10F:
      if (!ExtensionEnabled(kEXTColorBufferFloatName)) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "EXT_color_buffer_float not enabled");
        return;
      }
      RenderbufferStorageHelper(target, samples, internalformat, width, height,
                                function_name);
      break;
    case GL_RGB9_E5:
      if (!ExtensionEnabled(kWebGLRenderSharedExponentName)) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "WEBGL_render_shared_exponent not enabled");
        return;
      }
      RenderbufferStorageHelper(target, samples, internalformat, width, height,
                                function_name);
      break;
    case GL_R16_EXT:
    case GL_RG16_EXT:
    case GL_RGBA16_EXT:
      if (!ExtensionEnabled(kEXTTextureNorm16Name)) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "EXT_texture_norm16 not enabled");
        return;
      }
      RenderbufferStorageHelper(target, samples, internalformat, width, height,
                                function_name);
      break;
    case GL_R8_SNORM:
    case GL_RG8_SNORM:
    case GL_RGBA8_SNORM:
      if (!ExtensionEnabled(kEXTRenderSnormName)) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "EXT_render_snorm not enabled");
        return;
      }
      RenderbufferStorageHelper(target, samples, internalformat, width, height,
                                function_name);
      break;
    case GL_R16_SNORM_EXT:
    case GL_RG16_SNORM_EXT:
    case GL_RGBA16_SNORM_EXT:
      if (!ExtensionEnabled(kEXTRenderSnormName) ||
          !ExtensionEnabled(kEXTTextureNorm16Name)) {
        SynthesizeGLError(GL_INVALID_ENUM, function_name,
                          "EXT_render_snorm or EXT_texture_norm16 not enabled");
        return;
      }
      RenderbufferStorageHelper(target, samples, internalformat, width, height,
                                function_name);
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid internalformat");
      return;
  }
  renderbuffer_binding_->SetInternalFormat(internalformat);
  renderbuffer_binding_->SetSize(width, height);
  UpdateNumberOfUserAllocatedMultisampledRenderbuffers(
      renderbuffer_binding_->UpdateMultisampleState(samples > 0));
}

void WebGL2RenderingContextBase::renderbufferStorageMultisample(
    GLenum target,
    GLsizei samples,
    GLenum internalformat,
    GLsizei width,
    GLsizei height) {
  const char* function_name = "renderbufferStorageMultisample";
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
  if (!ValidateSize("renderbufferStorage", width, height))
    return;
  if (samples < 0) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "samples < 0");
    return;
  }
  RenderbufferStorageImpl(target, samples, internalformat, width, height,
                          function_name);
  ApplyDepthAndStencilTest();
}

void WebGL2RenderingContextBase::ResetUnpackParameters() {
  WebGLRenderingContextBase::ResetUnpackParameters();

  if (unpack_row_length_)
    ContextGL()->PixelStorei(GL_UNPACK_ROW_LENGTH, 0);
  if (unpack_image_height_)
    ContextGL()->PixelStorei(GL_UNPACK_IMAGE_HEIGHT, 0);
  if (unpack_skip_pixels_)
    ContextGL()->PixelStorei(GL_UNPACK_SKIP_PIXELS, 0);
  if (unpack_skip_rows_)
    ContextGL()->PixelStorei(GL_UNPACK_SKIP_ROWS, 0);
  if (unpack_skip_images_)
    ContextGL()->PixelStorei(GL_UNPACK_SKIP_IMAGES, 0);
}

void WebGL2RenderingContextBase::RestoreUnpackParameters() {
  WebGLRenderingContextBase::RestoreUnpackParameters();

  if (unpack_row_length_)
    ContextGL()->PixelStorei(GL_UNPACK_ROW_LENGTH, unpack_row_length_);
  if (unpack_image_height_)
    ContextGL()->PixelStorei(GL_UNPACK_IMAGE_HEIGHT, unpack_image_height_);
  if (unpack_skip_pixels_)
    ContextGL()->PixelStorei(GL_UNPACK_SKIP_PIXELS, unpack_skip_pixels_);
  if (unpack_skip_rows_)
    ContextGL()->PixelStorei(GL_UNPACK_SKIP_ROWS, unpack_skip_rows_);
  if (unpack_skip_images_)
    ContextGL()->PixelStorei(GL_UNPACK_SKIP_IMAGES, unpack_skip_images_);
}

void WebGL2RenderingContextBase::texImage2D(GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            int64_t offset) {
  if (isContextLost())
    return;
  if (!ValidateTexture2DBinding("texImage2D", target, true))
    return;
  if (!bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "no bound PIXEL_UNPACK_BUFFER");
    return;
  }
  if (unpack_flip_y_ || unpack_premultiply_alpha_) {
    SynthesizeGLError(
        GL_INVALID_OPERATION, "texImage2D",
        "FLIP_Y or PREMULTIPLY_ALPHA isn't allowed while uploading from PBO");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceUnpackBuffer);
  if (!ValidateTexFunc(params, std::nullopt, std::nullopt)) {
    return;
  }
  if (!ValidateValueFitNonNegInt32("texImage2D", "offset", offset))
    return;

  ContextGL()->TexImage2D(
      target, level, ConvertTexInternalFormat(internalformat, type), width,
      height, border, format, type, reinterpret_cast<const void*>(offset));
}

void WebGL2RenderingContextBase::texSubImage2D(GLenum target,
                                               GLint level,
                                               GLint xoffset,
                                               GLint yoffset,
                                               GLsizei width,
                                               GLsizei height,
                                               GLenum format,
                                               GLenum type,
                                               int64_t offset) {
  if (isContextLost())
    return;
  if (!ValidateTexture2DBinding("texSubImage2D", target))
    return;
  if (!bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "no bound PIXEL_UNPACK_BUFFER");
    return;
  }
  if (unpack_flip_y_ || unpack_premultiply_alpha_) {
    SynthesizeGLError(
        GL_INVALID_OPERATION, "texSubImage2D",
        "FLIP_Y or PREMULTIPLY_ALPHA isn't allowed while uploading from PBO");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceUnpackBuffer);
  if (!ValidateTexFunc(params, std::nullopt, std::nullopt)) {
    return;
  }
  if (!ValidateValueFitNonNegInt32("texSubImage2D", "offset", offset))
    return;

  ContextGL()->TexSubImage2D(target, level, xoffset, yoffset, width, height,
                             format, type,
                             reinterpret_cast<const void*>(offset));
}

void WebGL2RenderingContextBase::texImage2D(
    GLenum target,
    GLint level,
    GLint internalformat,
    GLsizei width,
    GLsizei height,
    GLint border,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> data) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  WebGLRenderingContextBase::texImage2D(target, level, internalformat, width,
                                        height, border, format, type, data);
}

void WebGL2RenderingContextBase::texImage2D(
    GLenum target,
    GLint level,
    GLint internalformat,
    GLsizei width,
    GLsizei height,
    GLint border,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> data,
    int64_t src_offset) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceArrayBufferView);
  TexImageHelperDOMArrayBufferView(params, data.Get(), kNullNotReachable,
                                   src_offset);
}

void WebGL2RenderingContextBase::texImage2D(GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            ImageData* pixels) {
  DCHECK(pixels);
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceImageData);
  params.border = 0;  // See https://crbug.com/1313604
  TexImageHelperImageData(params, pixels);
}

void WebGL2RenderingContextBase::texImage2D(ScriptState* script_state,
                                            GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            HTMLImageElement* image,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceHTMLImageElement);
  params.border = 0;  // See https://crbug.com/1313604
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLImageElement(execution_context->GetSecurityOrigin(), params,
                                 image, exception_state);
}

void WebGL2RenderingContextBase::texImage2D(ScriptState* script_state,
                                            GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            CanvasRenderingContextHost* canvas,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceHTMLCanvasElement);
  params.border = 0;  // See https://crbug.com/1313604
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperCanvasRenderingContextHost(
      execution_context->GetSecurityOrigin(), params, canvas, exception_state);
}

void WebGL2RenderingContextBase::texImage2D(ScriptState* script_state,
                                            GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            HTMLVideoElement* video,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceHTMLVideoElement);
  params.border = 0;  // See https://crbug.com/1313604
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLVideoElement(execution_context->GetSecurityOrigin(), params,
                                 video, exception_state);
}

void WebGL2RenderingContextBase::texImage2D(ScriptState* script_state,
                                            GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            VideoFrame* frame,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceVideoFrame);
  params.border = 0;  // See https://crbug.com/1313604
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperVideoFrame(execution_context->GetSecurityOrigin(), params,
                           frame, exception_state);
}

void WebGL2RenderingContextBase::texImage2D(GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLsizei width,
                                            GLsizei height,
                                            GLint border,
                                            GLenum format,
                                            GLenum type,
                                            ImageBitmap* bitmap,
                                            ExceptionState& exception_state) {
  DCHECK(bitmap);
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceImageBitmap);
  params.border = 0;  // See https://crbug.com/1313604
  TexImageHelperImageBitmap(params, bitmap, exception_state);
}

void WebGL2RenderingContextBase::texImage2D(GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLenum format,
                                            GLenum type,
                                            ImageData* image_data) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  WebGLRenderingContextBase::texImage2D(target, level, internalformat, format,
                                        type, image_data);
}

void WebGL2RenderingContextBase::texImage2D(ScriptState* script_state,
                                            GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLenum format,
                                            GLenum type,
                                            HTMLImageElement* image,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }

  WebGLRenderingContextBase::texImage2D(script_state, target, level,
                                        internalformat, format, type, image,
                                        exception_state);
}

void WebGL2RenderingContextBase::texImage2D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint internalformat,
    GLenum format,
    GLenum type,
    CanvasRenderingContextHost* context_host,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }

  WebGLRenderingContextBase::texImage2D(script_state, target, level,
                                        internalformat, format, type,
                                        context_host, exception_state);
}

void WebGL2RenderingContextBase::texImage2D(ScriptState* script_state,
                                            GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLenum format,
                                            GLenum type,
                                            HTMLVideoElement* video,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }

  WebGLRenderingContextBase::texImage2D(script_state, target, level,
                                        internalformat, format, type, video,
                                        exception_state);
}

void WebGL2RenderingContextBase::texImage2D(ScriptState* script_state,
                                            GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLenum format,
                                            GLenum type,
                                            VideoFrame* frame,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }

  WebGLRenderingContextBase::texImage2D(script_state, target, level,
                                        internalformat, format, type, frame,
                                        exception_state);
}

void WebGL2RenderingContextBase::texImage2D(GLenum target,
                                            GLint level,
                                            GLint internalformat,
                                            GLenum format,
                                            GLenum type,
                                            ImageBitmap* image_bit_map,
                                            ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  WebGLRenderingContextBase::texImage2D(target, level, internalformat, format,
                                        type, image_bit_map, exception_state);
}

void WebGL2RenderingContextBase::texSubImage2D(
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> pixels) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  WebGLRenderingContextBase::texSubImage2D(target, level, xoffset, yoffset,
                                           width, height, format, type, pixels);
}

void WebGL2RenderingContextBase::texSubImage2D(
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> pixels,
    int64_t src_offset) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceArrayBufferView);
  TexImageHelperDOMArrayBufferView(params, pixels.Get(), kNullNotReachable,
                                   src_offset);
}

void WebGL2RenderingContextBase::texSubImage2D(GLenum target,
                                               GLint level,
                                               GLint xoffset,
                                               GLint yoffset,
                                               GLsizei width,
                                               GLsizei height,
                                               GLenum format,
                                               GLenum type,
                                               ImageData* pixels) {
  DCHECK(pixels);
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceImageData);
  TexImageHelperImageData(params, pixels);
}

void WebGL2RenderingContextBase::texSubImage2D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    HTMLImageElement* image,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceHTMLImageElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLImageElement(execution_context->GetSecurityOrigin(), params,
                                 image, exception_state);
}

void WebGL2RenderingContextBase::texSubImage2D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    CanvasRenderingContextHost* canvas,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceHTMLCanvasElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperCanvasRenderingContextHost(
      execution_context->GetSecurityOrigin(), params, canvas, exception_state);
}

void WebGL2RenderingContextBase::texSubImage2D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    HTMLVideoElement* video,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceHTMLVideoElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLVideoElement(execution_context->GetSecurityOrigin(), params,
                                 video, exception_state);
}

void WebGL2RenderingContextBase::texSubImage2D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    VideoFrame* frame,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceVideoFrame);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperVideoFrame(execution_context->GetSecurityOrigin(), params,
                           frame, exception_state);
}

void WebGL2RenderingContextBase::texSubImage2D(
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    ImageBitmap* bitmap,
    ExceptionState& exception_state) {
  DCHECK(bitmap);
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceImageBitmap);
  TexImageHelperImageBitmap(params, bitmap, exception_state);
}

void WebGL2RenderingContextBase::texSubImage2D(GLenum target,
                                               GLint level,
                                               GLint xoffset,
                                               GLint yoffset,
                                               GLenum format,
                                               GLenum type,
                                               ImageData* pixels) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  WebGLRenderingContextBase::texSubImage2D(target, level, xoffset, yoffset,
                                           format, type, pixels);
}

void WebGL2RenderingContextBase::texSubImage2D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLenum format,
    GLenum type,
    HTMLImageElement* image,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  WebGLRenderingContextBase::texSubImage2D(script_state, target, level, xoffset,
                                           yoffset, format, type, image,
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
    CanvasRenderingContextHost* context_host,
    ExceptionState& exception_state) {
  if (isContextLost())
    return;
  if (bound_pixel_unpack_buffer_) {
    SynthesizeGLError(GL_INVALID_OPERATION, "texSubImage2D",
                      "a buffer is bound to PIXEL_UNPACK_BUFFER");
    return;
  }
  WebGLRenderingContextBase::texSubImage2D(script_state, target, level, xoffset,
                                           yoffset, format, type, context_host,
                                      
"""


```