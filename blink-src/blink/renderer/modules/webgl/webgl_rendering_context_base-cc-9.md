Response:
The user wants a summary of the functionality of the provided C++ code snippet from Chromium's Blink engine. I need to analyze the code and identify its core purpose and how it interacts with web technologies like JavaScript, HTML, and CSS. Since this is part 10 of 11, I should also consider the context implied by its placement within a larger file.

Here's a breakdown of the code's functionality:

1. **Texture Parameter Validation:** The code heavily focuses on validating parameters passed to texture-related WebGL functions (`texImage2D`, `texSubImage2D`, etc.). This includes checks for:
    * Negative width, height, or depth.
    * Dimensions exceeding maximum allowed sizes for different texture types (2D, cube map, 3D, array).
    * Incompatible width and height for cube maps.
    * Invalid target enums.
    * Border values not equal to 0.

2. **Data Validation for Texture Functions:**  The `ValidateTexFuncData` function specifically checks the validity of the data source provided for texture operations. This involves:
    * Ensuring the provided `DOMArrayBufferView` (representing typed arrays in JavaScript) has a compatible data type for the specified texture `type` (e.g., `Uint8Array` for `GL_UNSIGNED_BYTE`).
    * Verifying that the `DOMArrayBufferView` is large enough to hold the texture data based on its dimensions, format, and pixel store parameters.

3. **Compressed Texture Format Validation:** The `ValidateCompressedTexFormat` function checks if a given `format` is a valid compressed texture format.

4. **Stencil and Depth Function Validation:** `ValidateStencilOrDepthFunc` ensures that the function parameter for stencil and depth tests is a valid OpenGL enum.

5. **Error and Warning Handling:** The code includes functions for printing WebGL errors and warnings to the browser's console (`PrintGLErrorToConsole`, `PrintWarningToConsole`) and notifying the browser about these events (`NotifyWebGLErrorOrWarning`, `NotifyWebGLError`, `NotifyWebGLWarning`).

6. **Framebuffer Function Parameter Validation:**  `ValidateFramebufferFuncParameters` checks the validity of target and attachment points for framebuffer operations.

7. **Blend Equation and Function Factor Validation:** Functions like `ValidateBlendEquation`, `ValidateBlendFuncFactors`, and `ValidateBlendFuncExtendedFactors` validate the parameters used for blending operations in WebGL.

8. **Capability Validation:**  `ValidateCapability` ensures that the capabilities being enabled or disabled are valid and that any required extensions are enabled.

9. **Buffer Data Validation:** `ValidateBufferDataTarget` and `ValidateBufferDataUsage` check the target and usage parameters for buffer data operations.

10. **Validation of HTML Elements as Texture Sources:** Functions like `ValidateHTMLImageElement`, `ValidateCanvasRenderingContextHost`, `ValidateHTMLVideoElement`, and `ValidateImageBitmap` check if provided HTML elements (images, canvases, videos) or `ImageBitmap` objects are valid sources for texture data and if cross-origin restrictions are met.

11. **Draw Call Validation:** `ValidateDrawArrays` and `ValidateDrawElements` perform checks before rendering calls, including verifying the framebuffer status.

12. **Context Loss and Restoration:**  The code deals with WebGL context loss and restoration, including dispatching events (`DispatchContextLostEvent`), attempting to restore the context (`MaybeRestoreContext`), and managing related state.

13. **Resource Caching:** The `LRUCanvasResourceProviderCache` class implements a least-recently-used cache for `CanvasResourceProvider` objects, likely used to optimize texture uploads from canvas elements.

14. **Internal Helper Functions:** The code includes helper functions for converting error codes to strings (`GetErrorString`) and synthesizing GL errors (`SynthesizeGLError`).

**Relationship to JavaScript, HTML, and CSS:**

* **JavaScript:** This C++ code directly implements the behavior of the WebGL API exposed to JavaScript. When a JavaScript application calls a WebGL function (e.g., `gl.texImage2D()`), the parameters are eventually passed down to this C++ code for validation and processing.
* **HTML:**  HTML elements like `<canvas>`, `<img>`, and `<video>` can be used as sources for WebGL textures. The validation functions in this code check the validity and origin of these HTML elements.
* **CSS:**  While CSS doesn't directly interact with this specific validation code, CSS styling can affect the rendering of the `<canvas>` element, which in turn is used by WebGL. For instance, the dimensions of the canvas set by CSS can influence the viewport size in WebGL.

**Hypotheses for Logic Reasoning:**

* **Input:** JavaScript calls `gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 512, 512, 0, gl.RGBA, gl.UNSIGNED_BYTE, pixelData)`.
* **Output:** The `ValidateTexFuncParameters` and `ValidateTexFuncData` functions would check if `pixelData` is a `Uint8Array` of the correct size (512 * 512 * 4 bytes), if the texture dimensions are within limits, and if the format and type are a valid combination. The functions would return `true` if valid, `false` otherwise, potentially triggering a `SynthesizeGLError` call.

* **Input:** JavaScript attempts to use a cross-origin image as a texture via `gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, imageElement)`.
* **Output:** The `ValidateHTMLImageElement` function would detect the cross-origin issue and throw a security error, preventing the texture upload.

**Common User/Programming Errors:**

* **Providing incorrect data type for texture data:**  For example, passing a `Float32Array` when `type` is `GL_UNSIGNED_BYTE`. The `ValidateTexFuncData` function catches this.
* **Using negative dimensions for textures or buffers:** The validation functions at the beginning of the code snippet check for this.
* **Exceeding maximum texture sizes:**  The dimension validation checks prevent this.
* **Using an incomplete framebuffer for rendering:** `ValidateDrawArrays` and `ValidateDrawElements` will catch this and generate an `INVALID_FRAMEBUFFER_OPERATION` error.
* **Attempting to use cross-origin images/videos without CORS enabled:** The HTML element validation functions will throw a security error.
* **Calling WebGL functions after the context is lost:** While not directly validated in this snippet, the `isContextLost()` checks in other parts of the code (and likely the calling functions) handle this.

**User Operations Leading to This Code:**

1. A user opens a webpage containing a `<canvas>` element.
2. JavaScript code on the page obtains a WebGL rendering context from the canvas (e.g., `canvas.getContext('webgl')`).
3. The JavaScript code then calls various WebGL functions to manipulate textures, buffers, framebuffers, or render content (e.g., `gl.texImage2D()`, `gl.drawArrays()`).
4. These JavaScript calls trigger corresponding C++ methods within the Blink engine, including the validation functions in this file.
5. If errors occur during validation, the `SynthesizeGLError` function is called, potentially leading to error messages in the browser's console.
6. If the WebGL context is lost due to hardware or software issues, the context loss and restoration logic in this code is executed.

**Summary of Functionality (Part 10 of 11):**

This part of `webgl_rendering_context_base.cc` primarily focuses on **input validation and error handling for various WebGL API calls**, particularly those related to **textures, framebuffers, buffer objects, and rendering**. It ensures that the parameters and data provided by the JavaScript application are valid according to the WebGL specification, preventing crashes and ensuring correct behavior. It also includes the logic for handling **context loss and attempting to restore the WebGL context**, and implements a **resource cache for canvas-backed textures**. This section plays a crucial role in the robustness and security of the WebGL implementation in Chromium.

这是 `blink/renderer/modules/webgl/webgl_rendering_context_base.cc` 文件的第 10 部分，总共 11 部分。 基于提供的代码片段，我们可以归纳出以下功能：

**核心功能：WebGL API 参数校验与错误处理**

这部分代码的核心职责是**校验**传递给各种 WebGL API 函数的参数是否合法，并在检测到错误时生成相应的 **OpenGL 错误**。它涵盖了多种 WebGL 操作的参数验证，包括：

* **纹理操作 (Textures):**
    * 校验纹理的尺寸（宽度、高度、深度）是否为负数。
    * 校验纹理的尺寸是否超过了硬件或 WebGL 规定的最大值（针对 2D 纹理、立方体贴图、3D 纹理和纹理数组）。
    * 对于立方体贴图，校验宽度和高度是否相等。
    * 校验 `texImage2D` 等函数中使用的图像来源（`HTMLImageElement`, `HTMLCanvasElement` 等）的格式和类型是否合法。
    * 校验提供给纹理函数的 `ArrayBufferView` (JavaScript 中的类型化数组) 中的数据类型是否与纹理的格式和类型匹配。
    * 校验 `ArrayBufferView` 的大小是否足够存储纹理数据。
    * 校验压缩纹理的格式是否合法。
* **帧缓冲对象 (Framebuffers):**
    * 校验帧缓冲对象操作的目标和附件点是否合法。
* **混合 (Blending):**
    * 校验混合方程式和混合函数因子是否合法。
* **能力 (Capabilities):**
    * 校验 `enable` 或 `disable` 函数中指定的能力是否合法，并考虑了扩展支持的情况。
* **缓冲区对象 (Buffers):**
    * 校验缓冲区数据操作的目标和使用方式是否合法。
* **渲染 (Rendering):**
    * 在执行 `drawArrays` 和 `drawElements` 前，校验渲染状态和帧缓冲对象的状态是否完整。
* **上下文丢失与恢复:**
    * 包含了处理 WebGL 上下文丢失和恢复的逻辑，例如触发 `webglcontextlost` 和 `webglcontextrestored` 事件，以及尝试恢复上下文。
* **资源缓存:**
    * 实现了 `LRUCanvasResourceProviderCache`，用于缓存 `CanvasResourceProvider` 对象，这可能是为了优化从 HTMLCanvasElement 创建纹理的性能。
* **错误报告:**
    * 提供了 `SynthesizeGLError` 函数用于生成 OpenGL 错误，并可以选择将错误信息打印到控制台。
    * 提供了 `PrintGLErrorToConsole` 和 `PrintWarningToConsole` 函数用于将错误和警告信息输出到浏览器的控制台。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**  这部分 C++ 代码直接响应 JavaScript 中 WebGL API 的调用。当 JavaScript 调用如 `gl.texImage2D(...)` 时，其参数会传递到这里的校验函数进行检查。
    * **举例:** 当 JavaScript 代码尝试使用一个尺寸过大的纹理调用 `gl.texImage2D` 时，例如：
      ```javascript
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, 8192, 8192, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
      ```
      这里的代码会校验 `8192` 是否超过了 `max_texture_size_ >> level` 的限制，如果超过则会生成 `GL_INVALID_VALUE` 错误。
* **HTML:**  HTML 元素如 `<img>`, `<canvas>`, `<video>` 可以作为 WebGL 纹理的数据来源。这里的代码会校验这些元素是否有效，以及是否存在跨域问题。
    * **举例:** 当 JavaScript 代码尝试使用一个跨域的图片作为纹理源时：
      ```javascript
      const image = new Image();
      image.src = 'https://example.com/image.png';
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, image);
      ```
      `ValidateHTMLImageElement` 函数会检查图片的来源，如果检测到跨域且没有配置 CORS，会抛出一个安全错误。
* **CSS:** CSS 主要影响 HTML 元素的样式和布局，间接影响 WebGL 的渲染结果，但与这里的参数校验代码没有直接的功能关系。CSS 设置的 Canvas 尺寸可能会影响 WebGL 的视口大小，但校验逻辑主要关注传递给 WebGL API 的数值参数。

**逻辑推理的假设输入与输出:**

* **假设输入:**  JavaScript 调用 `gl.blendFunc(gl.CONSTANT_COLOR, gl.CONSTANT_ALPHA)`。
* **输出:** `ValidateBlendFuncFactors` 函数会检测到源混合因子和目标混合因子都是常量颜色/alpha，这在 WebGL 1 中是不允许的，会调用 `SynthesizeGLError` 生成 `GL_INVALID_OPERATION` 错误。

* **假设输入:** JavaScript 调用 `gl.drawArrays(gl.TRIANGLES, 0, 6)`，但当前绑定的帧缓冲对象不完整（例如，缺少颜色附件）。
* **输出:** `ValidateDrawArrays` 函数会调用帧缓冲对象的 `CheckDepthStencilStatus` 方法，检测到帧缓冲不完整，然后调用 `SynthesizeGLError` 生成 `GL_INVALID_FRAMEBUFFER_OPERATION` 错误。

**用户或编程常见的使用错误举例:**

* **使用负数的纹理尺寸:** 用户可能在 JavaScript 中错误地计算或设置了负数的纹理宽度或高度。
* **提供的 ArrayBufferView 数据类型与纹理类型不匹配:**  例如，期望 `GL_UNSIGNED_BYTE` 类型的纹理数据，但提供了 `Float32Array`。
* **尝试使用超过硬件限制的纹理尺寸:**  用户可能无意中使用了非常大的纹理尺寸，超出了设备的 WebGL 能力。
* **在 WebGL 上下文丢失后调用 WebGL 函数:** 虽然这个片段主要关注参数校验，但在其他部分会检查 `isContextLost()` 的状态。如果用户在上下文丢失后尝试调用 WebGL 函数，通常会产生错误。
* **忘记正确配置跨域资源共享 (CORS) 时尝试使用跨域图片/视频作为纹理。**

**用户操作如何一步步到达这里 (调试线索):**

1. 用户访问一个包含使用 WebGL 的网站。
2. 网站的 JavaScript 代码获取 `<canvas>` 元素的 WebGL 上下文。
3. JavaScript 代码调用各种 WebGL API 函数，例如加载纹理、设置渲染状态、执行绘制命令等。
4. 当这些 WebGL 函数被调用时，Blink 引擎会将调用转发到相应的 C++ 代码中。
5. 在执行实际的 OpenGL 调用之前，这部分代码中的校验函数会被调用，检查传递的参数是否符合 WebGL 规范。
6. 如果校验失败，`SynthesizeGLError` 函数会被调用，生成 OpenGL 错误，并且错误信息可能会打印到浏览器的开发者工具控制台中。
7. 开发人员可以在浏览器开发者工具的控制台中看到这些错误信息，从而定位问题所在。他们也可以在 Blink 的源代码中设置断点，例如在 `ValidateTexFuncParameters` 或 `SynthesizeGLError` 等函数中，来跟踪参数的传递和错误的生成过程。

**总结其功能（第 10 部分，共 11 部分）:**

作为 `webgl_rendering_context_base.cc` 文件的倒数第二个部分，这部分代码的核心功能是 **对 WebGL API 的参数进行严格的校验和错误处理**。它确保了传递给 WebGL 函数的参数符合规范，防止了潜在的崩溃和错误行为，并提供了错误报告机制，帮助开发者调试 WebGL 应用。 考虑到它在整个文件中的位置，可以推断出后续的部分可能包含与资源清理、上下文销毁或其他最终处理相关的逻辑。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第10部分，共11部分，请归纳一下它的功能

"""
on_name,
                      "width, height or depth < 0");
    return false;
  }

  switch (target) {
    case GL_TEXTURE_2D:
      if (width > (max_texture_size_ >> level) ||
          height > (max_texture_size_ >> level)) {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "width or height out of range");
        return false;
      }
      break;
    case GL_TEXTURE_CUBE_MAP_POSITIVE_X:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_X:
    case GL_TEXTURE_CUBE_MAP_POSITIVE_Y:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_Y:
    case GL_TEXTURE_CUBE_MAP_POSITIVE_Z:
    case GL_TEXTURE_CUBE_MAP_NEGATIVE_Z:
      if (function_type != kTexSubImage && width != height) {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "width != height for cube map");
        return false;
      }
      // No need to check height here. For texImage width == height.
      // For texSubImage that will be checked when checking yoffset + height is
      // in range.
      if (width > (max_cube_map_texture_size_ >> level)) {
        SynthesizeGLError(GL_INVALID_VALUE, function_name,
                          "width or height out of range for cube map");
        return false;
      }
      break;
    case GL_TEXTURE_3D:
      if (IsWebGL2()) {
        if (width > (max3d_texture_size_ >> level) ||
            height > (max3d_texture_size_ >> level) ||
            depth > (max3d_texture_size_ >> level)) {
          SynthesizeGLError(GL_INVALID_VALUE, function_name,
                            "width, height or depth out of range");
          return false;
        }
        break;
      }
      [[fallthrough]];
    case GL_TEXTURE_2D_ARRAY:
      if (IsWebGL2()) {
        if (width > (max_texture_size_ >> level) ||
            height > (max_texture_size_ >> level) ||
            depth > max_array_texture_layers_) {
          SynthesizeGLError(GL_INVALID_VALUE, function_name,
                            "width, height or depth out of range");
          return false;
        }
        break;
      }
      [[fallthrough]];
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid target");
      return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateTexFuncParameters(
    const TexImageParams& params) {
  const char* function_name = GetTexImageFunctionName(params.function_id);

  // We absolutely have to validate the format and type combination.
  // The texImage2D entry points taking HTMLImage, etc. will produce
  // temporary data based on this combination, so it must be legal.
  if (params.source_type == kSourceHTMLImageElement ||
      params.source_type == kSourceHTMLCanvasElement ||
      params.source_type == kSourceHTMLVideoElement ||
      params.source_type == kSourceImageData ||
      params.source_type == kSourceImageBitmap ||
      params.source_type == kSourceVideoFrame) {
    if (!ValidateTexImageSourceFormatAndType(params)) {
      return false;
    }
  } else {
    if (!ValidateTexFuncFormatAndType(params)) {
      return false;
    }
  }

  if (!ValidateTexFuncDimensions(function_name,
                                 GetTexImageFunctionType(params.function_id),
                                 params.target, params.level, *params.width,
                                 *params.height, *params.depth)) {
    return false;
  }

  if (params.border) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "border != 0");
    return false;
  }

  return true;
}

bool WebGLRenderingContextBase::ValidateTexFuncData(
    const TexImageParams& params,
    DOMArrayBufferView* pixels,
    NullDisposition disposition,
    int64_t src_offset) {
  const char* function_name = GetTexImageFunctionName(params.function_id);
  TexImageDimension tex_dimension;
  if (params.function_id == kTexImage2D || params.function_id == kTexSubImage2D)
    tex_dimension = kTex2D;
  else
    tex_dimension = kTex3D;

  // All calling functions check isContextLost, so a duplicate check is not
  // needed here.
  if (!pixels) {
    DCHECK_NE(disposition, kNullNotReachable);
    if (disposition == kNullAllowed)
      return true;
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "no pixels");
    return false;
  }

  if (!ValidateSettableTexFormat(function_name, params.format))
    return false;

  auto pixelType = pixels->GetType();

  switch (params.type) {
    case GL_BYTE:
      if (pixelType != DOMArrayBufferView::kTypeInt8) {
        SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                          "type BYTE but ArrayBufferView not Int8Array");
        return false;
      }
      break;
    case GL_UNSIGNED_BYTE:
      if (pixelType != DOMArrayBufferView::kTypeUint8 &&
          pixelType != DOMArrayBufferView::kTypeUint8Clamped) {
        SynthesizeGLError(
            GL_INVALID_OPERATION, function_name,
            "type UNSIGNED_BYTE but ArrayBufferView not Uint8Array or "
            "Uint8ClampedArray");
        return false;
      }
      break;
    case GL_SHORT:
      if (pixelType != DOMArrayBufferView::kTypeInt16) {
        SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                          "type SHORT but ArrayBufferView not Int16Array");
        return false;
      }
      break;
    case GL_UNSIGNED_SHORT:
    case GL_UNSIGNED_SHORT_5_6_5:
    case GL_UNSIGNED_SHORT_4_4_4_4:
    case GL_UNSIGNED_SHORT_5_5_5_1:
      if (pixelType != DOMArrayBufferView::kTypeUint16) {
        SynthesizeGLError(
            GL_INVALID_OPERATION, function_name,
            "type UNSIGNED_SHORT but ArrayBufferView not Uint16Array");
        return false;
      }
      break;
    case GL_INT:
      if (pixelType != DOMArrayBufferView::kTypeInt32) {
        SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                          "type INT but ArrayBufferView not Int32Array");
        return false;
      }
      break;
    case GL_UNSIGNED_INT:
    case GL_UNSIGNED_INT_2_10_10_10_REV:
    case GL_UNSIGNED_INT_10F_11F_11F_REV:
    case GL_UNSIGNED_INT_5_9_9_9_REV:
    case GL_UNSIGNED_INT_24_8:
      if (pixelType != DOMArrayBufferView::kTypeUint32) {
        SynthesizeGLError(
            GL_INVALID_OPERATION, function_name,
            "type UNSIGNED_INT but ArrayBufferView not Uint32Array");
        return false;
      }
      break;
    case GL_FLOAT:  // OES_texture_float
      if (pixelType != DOMArrayBufferView::kTypeFloat32) {
        SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                          "type FLOAT but ArrayBufferView not Float32Array");
        return false;
      }
      break;
    case GL_HALF_FLOAT:
    case GL_HALF_FLOAT_OES:  // OES_texture_half_float
      // As per the specification, ArrayBufferView should be null or a
      // Uint16Array when OES_texture_half_float is enabled.
      if (pixelType != DOMArrayBufferView::kTypeUint16) {
        SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                          "type HALF_FLOAT_OES but ArrayBufferView is not NULL "
                          "and not Uint16Array");
        return false;
      }
      break;
    case GL_FLOAT_32_UNSIGNED_INT_24_8_REV:
      SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                        "type FLOAT_32_UNSIGNED_INT_24_8_REV but "
                        "ArrayBufferView is not NULL");
      return false;
    default:
      NOTREACHED();
  }

  unsigned total_bytes_required, skip_bytes;
  GLenum error = WebGLImageConversion::ComputeImageSizeInBytes(
      params.format, params.type, *params.width, *params.height, *params.depth,
      GetUnpackPixelStoreParams(tex_dimension), &total_bytes_required, nullptr,
      &skip_bytes);
  if (error != GL_NO_ERROR) {
    SynthesizeGLError(error, function_name, "invalid texture dimensions");
    return false;
  }
  base::CheckedNumeric<size_t> total = src_offset;
  total *= pixels->TypeSize();
  total += total_bytes_required;
  total += skip_bytes;
  size_t total_val;
  if (!total.AssignIfValid(&total_val) || pixels->byteLength() < total_val) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "ArrayBufferView not big enough for request");
    return false;
  }
#if UINTPTR_MAX == UINT32_MAX
  // 32-bit platforms have additional constraints, since src_offset is
  // added to a pointer value in calling code.
  if (total_val > kMaximumSupportedArrayBufferSize) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      "src_offset plus texture data size exceeds the "
                      "supported range");
  }
#endif
  base::CheckedNumeric<uint32_t> data_size = total_bytes_required;
  data_size += skip_bytes;
  uint32_t data_size_val;
  if (!data_size.AssignIfValid(&data_size_val) ||
      data_size_val > kMaximumSupportedArrayBufferSize) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      "texture data size exceeds the supported range");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateCompressedTexFormat(
    const char* function_name,
    GLenum format) {
  if (!compressed_texture_formats_.Contains(format)) {
    SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid format");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateStencilOrDepthFunc(
    const char* function_name,
    GLenum func) {
  switch (func) {
    case GL_NEVER:
    case GL_LESS:
    case GL_LEQUAL:
    case GL_GREATER:
    case GL_GEQUAL:
    case GL_EQUAL:
    case GL_NOTEQUAL:
    case GL_ALWAYS:
      return true;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid function");
      return false;
  }
}

void WebGLRenderingContextBase::PrintGLErrorToConsole(const String& message) {
  if (!num_gl_errors_to_console_allowed_)
    return;

  --num_gl_errors_to_console_allowed_;
  PrintWarningToConsole(message);

  if (!num_gl_errors_to_console_allowed_)
    PrintWarningToConsole(
        "WebGL: too many errors, no more errors will be reported to the "
        "console for this context.");

  return;
}

void WebGLRenderingContextBase::PrintWarningToConsole(const String& message) {
  blink::ExecutionContext* context = Host()->GetTopExecutionContext();
  if (context && !context->IsContextDestroyed()) {
    context->AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kRendering,
        mojom::blink::ConsoleMessageLevel::kWarning, message));
  }
}

void WebGLRenderingContextBase::NotifyWebGLErrorOrWarning(
    const String& message) {
  probe::DidFireWebGLErrorOrWarning(canvas(), message);
}

void WebGLRenderingContextBase::NotifyWebGLError(const String& error_type) {
  probe::DidFireWebGLError(canvas(), error_type);
}

void WebGLRenderingContextBase::NotifyWebGLWarning() {
  probe::DidFireWebGLWarning(canvas());
}

bool WebGLRenderingContextBase::ValidateFramebufferFuncParameters(
    const char* function_name,
    GLenum target,
    GLenum attachment) {
  if (!ValidateFramebufferTarget(target)) {
    SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid target");
    return false;
  }
  switch (attachment) {
    case GL_COLOR_ATTACHMENT0:
    case GL_DEPTH_ATTACHMENT:
    case GL_STENCIL_ATTACHMENT:
    case GL_DEPTH_STENCIL_ATTACHMENT:
      break;
    default:
      if ((ExtensionEnabled(kWebGLDrawBuffersName) || IsWebGL2()) &&
          attachment > GL_COLOR_ATTACHMENT0 &&
          attachment <
              static_cast<GLenum>(GL_COLOR_ATTACHMENT0 + MaxColorAttachments()))
        break;
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid attachment");
      return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateBlendEquation(const char* function_name,
                                                      GLenum mode) {
  switch (mode) {
    case GL_FUNC_ADD:
    case GL_FUNC_SUBTRACT:
    case GL_FUNC_REVERSE_SUBTRACT:
      return true;
    case GL_MIN_EXT:
    case GL_MAX_EXT:
      if (ExtensionEnabled(kEXTBlendMinMaxName) || IsWebGL2())
        return true;
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid mode");
      return false;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid mode");
      return false;
  }
}

bool WebGLRenderingContextBase::ValidateBlendFuncFactors(
    const char* function_name,
    GLenum src,
    GLenum dst) {
  if (((src == GL_CONSTANT_COLOR || src == GL_ONE_MINUS_CONSTANT_COLOR) &&
       (dst == GL_CONSTANT_ALPHA || dst == GL_ONE_MINUS_CONSTANT_ALPHA)) ||
      ((dst == GL_CONSTANT_COLOR || dst == GL_ONE_MINUS_CONSTANT_COLOR) &&
       (src == GL_CONSTANT_ALPHA || src == GL_ONE_MINUS_CONSTANT_ALPHA))) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      "incompatible src and dst");
    return false;
  }

  return ValidateBlendFuncExtendedFactors(function_name, src, dst);
}

bool WebGLRenderingContextBase::ValidateBlendFuncExtendedFactors(
    const char* function_name,
    GLenum src,
    GLenum dst) {
  // TODO(crbug.com/882580): this validation is done in the
  // passthrough command decoder; this helper can be removed once the
  // validating command decoder is completely unshipped.
  if (src == GL_SRC1_COLOR_EXT || dst == GL_SRC1_COLOR_EXT ||
      src == GL_SRC1_ALPHA_EXT || dst == GL_SRC1_ALPHA_EXT ||
      src == GL_ONE_MINUS_SRC1_COLOR_EXT ||
      dst == GL_ONE_MINUS_SRC1_COLOR_EXT ||
      src == GL_ONE_MINUS_SRC1_ALPHA_EXT ||
      dst == GL_ONE_MINUS_SRC1_ALPHA_EXT ||
      (dst == GL_SRC_ALPHA_SATURATE && !IsWebGL2())) {
    if (!ExtensionEnabled(kWebGLBlendFuncExtendedName)) {
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid value, WEBGL_blend_func_extended not enabled");
      return false;
    }
  }

  return true;
}

bool WebGLRenderingContextBase::ValidateCapability(const char* function_name,
                                                   GLenum cap) {
  switch (cap) {
    case GL_BLEND:
    case GL_CULL_FACE:
    case GL_DEPTH_TEST:
    case GL_DITHER:
    case GL_POLYGON_OFFSET_FILL:
    case GL_SAMPLE_ALPHA_TO_COVERAGE:
    case GL_SAMPLE_COVERAGE:
    case GL_SCISSOR_TEST:
    case GL_STENCIL_TEST:
      return true;
    case GL_POLYGON_OFFSET_LINE_ANGLE:
      if (ExtensionEnabled(kWebGLPolygonModeName)) {
        return true;
      }
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid capability, WEBGL_polygon_mode not enabled");
      return false;
    case GL_DEPTH_CLAMP_EXT:
      if (ExtensionEnabled(kEXTDepthClampName)) {
        return true;
      }
      SynthesizeGLError(GL_INVALID_ENUM, function_name,
                        "invalid capability, EXT_depth_clamp not enabled");
      return false;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid capability");
      return false;
  }
}

WebGLBuffer* WebGLRenderingContextBase::ValidateBufferDataTarget(
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
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid target");
      return nullptr;
  }
  if (!buffer) {
    SynthesizeGLError(GL_INVALID_OPERATION, function_name, "no buffer");
    return nullptr;
  }
  return buffer;
}

bool WebGLRenderingContextBase::ValidateBufferDataUsage(
    const char* function_name,
    GLenum usage) {
  switch (usage) {
    case GL_STREAM_DRAW:
    case GL_STATIC_DRAW:
    case GL_DYNAMIC_DRAW:
      return true;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid usage");
      return false;
  }
}

void WebGLRenderingContextBase::RemoveBoundBuffer(WebGLBuffer* buffer) {
  if (bound_array_buffer_ == buffer)
    bound_array_buffer_ = nullptr;

  bound_vertex_array_object_->UnbindBuffer(buffer);
}

bool WebGLRenderingContextBase::ValidateHTMLImageElement(
    const SecurityOrigin* security_origin,
    const char* function_name,
    HTMLImageElement* image,
    ExceptionState& exception_state) {
  if (!image || !image->CachedImage()) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "no image");
    return false;
  }
  const KURL& url = image->CachedImage()->GetResponse().CurrentRequestUrl();
  if (url.IsNull() || url.IsEmpty() || !url.IsValid()) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "invalid image");
    return false;
  }

  if (WouldTaintCanvasOrigin(image)) {
    exception_state.ThrowSecurityError(
        "The image element contains cross-origin data, and may not be loaded.");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateCanvasRenderingContextHost(
    const SecurityOrigin* security_origin,
    const char* function_name,
    CanvasRenderingContextHost* context_host,
    ExceptionState& exception_state) {
  if (!context_host || !context_host->IsPaintable()) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "no canvas");
    return false;
  }

  if (WouldTaintCanvasOrigin(context_host)) {
    exception_state.ThrowSecurityError("Tainted canvases may not be loaded.");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateHTMLVideoElement(
    const SecurityOrigin* security_origin,
    const char* function_name,
    HTMLVideoElement* video,
    ExceptionState& exception_state) {
  if (!video || !video->videoWidth() || !video->videoHeight()) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name, "no video");
    return false;
  }

  if (WouldTaintCanvasOrigin(video)) {
    exception_state.ThrowSecurityError(
        "The video element contains cross-origin data, and may not be loaded.");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateImageBitmap(
    const char* function_name,
    ImageBitmap* bitmap,
    ExceptionState& exception_state) {
  if (bitmap->IsNeutered()) {
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      "The source data has been detached.");
    return false;
  }
  if (!bitmap->OriginClean()) {
    exception_state.ThrowSecurityError(
        "The ImageBitmap contains cross-origin data, and may not be loaded.");
    return false;
  }
  return true;
}

bool WebGLRenderingContextBase::ValidateDrawArrays(const char* function_name) {
  if (isContextLost())
    return false;

  if (!ValidateRenderingState(function_name)) {
    return false;
  }

  const char* reason = "framebuffer incomplete";
  if (framebuffer_binding_ && framebuffer_binding_->CheckDepthStencilStatus(
                                  &reason) != GL_FRAMEBUFFER_COMPLETE) {
    SynthesizeGLError(GL_INVALID_FRAMEBUFFER_OPERATION, function_name, reason);
    return false;
  }

  return true;
}

bool WebGLRenderingContextBase::ValidateDrawElements(const char* function_name,
                                                     GLenum type,
                                                     int64_t offset) {
  if (isContextLost())
    return false;

  if (type == GL_UNSIGNED_INT && !IsWebGL2() &&
      !ExtensionEnabled(kOESElementIndexUintName)) {
    SynthesizeGLError(GL_INVALID_ENUM, function_name, "invalid type");
    return false;
  }

  if (!ValidateValueFitNonNegInt32(function_name, "offset", offset))
    return false;

  if (!ValidateRenderingState(function_name)) {
    return false;
  }

  const char* reason = "framebuffer incomplete";
  if (framebuffer_binding_ && framebuffer_binding_->CheckDepthStencilStatus(
                                  &reason) != GL_FRAMEBUFFER_COMPLETE) {
    SynthesizeGLError(GL_INVALID_FRAMEBUFFER_OPERATION, function_name, reason);
    return false;
  }

  return true;
}

void WebGLRenderingContextBase::OnBeforeDrawCall(
    CanvasPerformanceMonitor::DrawType draw_type) {
  ClearIfComposited(kClearCallerDrawOrClear);
  MarkContextChanged(kCanvasChanged, draw_type);
}

void WebGLRenderingContextBase::DispatchContextLostEvent(TimerBase*) {
  // WebXR spec: When the WebGL context is lost, set the xr compatible boolean
  // to false prior to firing the webglcontextlost event.
  xr_compatible_ = false;

  WebGLContextEvent* event =
      WebGLContextEvent::Create(event_type_names::kWebglcontextlost, "");
  Host()->HostDispatchEvent(event);
  restore_allowed_ = event->defaultPrevented();
  if (restore_allowed_ && auto_recovery_method_ == kAuto) {
    // Defer the restore timer to give the context loss
    // notifications time to propagate through the system: in
    // particular, to the browser process.
    restore_timer_.StartOneShot(kDurationBetweenRestoreAttempts, FROM_HERE);
  }

  if (!restore_allowed_) {
    // Per WebXR spec, reject the promise with an AbortError if the default
    // behavior wasn't prevented. CompleteXrCompatiblePromiseIfPending rejects
    // the promise if xr_compatible_ is false, which was set at the beginning of
    // this method.
    CompleteXrCompatiblePromiseIfPending(DOMExceptionCode::kAbortError);
  }
}

void WebGLRenderingContextBase::MaybeRestoreContext(TimerBase*) {
  DCHECK(isContextLost());

  // The rendering context is not restored unless the default behavior of the
  // webglcontextlost event was prevented earlier.
  //
  // Because of the way m_restoreTimer is set up for real vs. synthetic lost
  // context events, we don't have to worry about this test short-circuiting
  // the retry loop for real context lost events.
  if (!restore_allowed_)
    return;

  if (canvas()) {
    LocalFrame* frame = canvas()->GetDocument().GetFrame();
    if (!frame)
      return;

    bool blocked = false;
    mojo::Remote<mojom::blink::GpuDataManager> gpu_data_manager;
    Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
        gpu_data_manager.BindNewPipeAndPassReceiver());
    gpu_data_manager->Are3DAPIsBlockedForUrl(canvas()->GetDocument().Url(),
                                             &blocked);
    if (blocked) {
      // Notify the canvas if it wasn't already. This has the side
      // effect of scheduling a compositing update so the "sad canvas"
      // will show up properly.
      canvas()->SetContextCreationWasBlocked();
      return;
    }

    Settings* settings = frame->GetSettings();
    if (settings && ((context_type_ == Platform::kWebGL1ContextType &&
                      !settings->GetWebGL1Enabled()) ||
                     (context_type_ == Platform::kWebGL2ContextType &&
                      !settings->GetWebGL2Enabled()))) {
      return;
    }
  }

  // Drawing buffer should have aready been destroyed during context loss to
  // ensure its resources were freed.
  DCHECK(!GetDrawingBuffer());

  Platform::ContextAttributes attributes =
      ToPlatformContextAttributes(CreationAttributes(), context_type_);
  Platform::GraphicsInfo gl_info;
  const auto& url = Host()->GetExecutionContextUrl();

  std::unique_ptr<WebGraphicsContext3DProvider> context_provider =
      CreateOffscreenGraphicsContext3DProvider(attributes, &gl_info, url);
  scoped_refptr<DrawingBuffer> buffer;
  if (context_provider && context_provider->BindToCurrentSequence()) {
    // Construct a new drawing buffer with the new GL context.
    buffer = CreateDrawingBuffer(std::move(context_provider), gl_info);
    // If DrawingBuffer::create() fails to allocate a fbo, |drawingBuffer| is
    // set to null.
  }
  if (!buffer) {
    if (context_lost_mode_ == kRealLostContext) {
      restore_timer_.StartOneShot(kDurationBetweenRestoreAttempts, FROM_HERE);
    } else {
      // This likely shouldn't happen but is the best way to report it to the
      // WebGL app.
      SynthesizeGLError(GL_INVALID_OPERATION, "", "error restoring context");
    }
    return;
  }

  drawing_buffer_ = std::move(buffer);
  GetDrawingBuffer()->Bind(GL_FRAMEBUFFER);
  lost_context_errors_.clear();
  context_lost_mode_ = kNotLostContext;
  auto_recovery_method_ = kManual;
  restore_allowed_ = false;
  RemoveFromEvictedList(this);

  SetupFlags();
  InitializeNewContext();
  MarkContextChanged(kCanvasContextChanged,
                     CanvasPerformanceMonitor::DrawType::kOther);
  if (canvas()) {
    // The cc::Layer associated with this WebGL rendering context has
    // changed, so tell the canvas that a compositing update is
    // needed.
    //
    // TODO(kbr): more work likely needed for the case of a canvas
    // whose control has transferred to an OffscreenCanvas.
    canvas()->SetNeedsCompositingUpdate();
  }

  WebGLContextEvent* event =
      WebGLContextEvent::Create(event_type_names::kWebglcontextrestored, "");
  Host()->HostDispatchEvent(event);

  if (xr_compatible_) {
    CompleteXrCompatiblePromiseIfPending(DOMExceptionCode::kNoError);
  } else {
    CompleteXrCompatiblePromiseIfPending(DOMExceptionCode::kAbortError);
  }
}

String WebGLRenderingContextBase::EnsureNotNull(const String& text) const {
  if (text.IsNull())
    return WTF::g_empty_string;
  return text;
}

WebGLRenderingContextBase::LRUCanvasResourceProviderCache::
    LRUCanvasResourceProviderCache(wtf_size_t capacity, CacheType type)
    : type_(type), resource_providers_(capacity) {}

CanvasResourceProvider* WebGLRenderingContextBase::
    LRUCanvasResourceProviderCache::GetCanvasResourceProvider(
        const SkImageInfo& info) {
  wtf_size_t i;
  for (i = 0; i < resource_providers_.size(); ++i) {
    CanvasResourceProvider* resource_provider = resource_providers_[i].get();
    if (!resource_provider)
      break;
    if (resource_provider->GetSkImageInfo() != info)
      continue;
    BubbleToFront(i);
    return resource_provider;
  }

  std::unique_ptr<CanvasResourceProvider> temp;
  if (type_ == CacheType::kVideo) {
    viz::RasterContextProvider* raster_context_provider = nullptr;
    if (auto wrapper = SharedGpuContext::ContextProviderWrapper()) {
      raster_context_provider =
          wrapper->ContextProvider()->RasterContextProvider();
    }
    temp = CreateResourceProviderForVideoFrame(info, raster_context_provider);
  } else {
    // TODO(fserb): why is this a BITMAP?
    temp = CanvasResourceProvider::CreateBitmapProvider(
        info, cc::PaintFlags::FilterQuality::kLow,
        CanvasResourceProvider::ShouldInitialize::kNo);  // TODO: should this
                                                         // use the canvas's
  }

  if (!temp)
    return nullptr;
  i = std::min(resource_providers_.size() - 1, i);
  resource_providers_[i] = std::move(temp);

  CanvasResourceProvider* resource_provider = resource_providers_[i].get();
  BubbleToFront(i);
  return resource_provider;
}

void WebGLRenderingContextBase::LRUCanvasResourceProviderCache::BubbleToFront(
    wtf_size_t idx) {
  for (wtf_size_t i = idx; i > 0; --i)
    resource_providers_[i].swap(resource_providers_[i - 1]);
}

namespace {

String GetErrorString(GLenum error) {
  switch (error) {
    case GL_INVALID_ENUM:
      return "INVALID_ENUM";
    case GL_INVALID_VALUE:
      return "INVALID_VALUE";
    case GL_INVALID_OPERATION:
      return "INVALID_OPERATION";
    case GL_OUT_OF_MEMORY:
      return "OUT_OF_MEMORY";
    case GL_INVALID_FRAMEBUFFER_OPERATION:
      return "INVALID_FRAMEBUFFER_OPERATION";
    case GC3D_CONTEXT_LOST_WEBGL:
      return "CONTEXT_LOST_WEBGL";
    default:
      return String::Format("WebGL ERROR(0x%04X)", error);
  }
}

}  // namespace

void WebGLRenderingContextBase::SynthesizeGLError(
    GLenum error,
    const char* function_name,
    const char* description,
    ConsoleDisplayPreference display) {
  String error_type = GetErrorString(error);
  if (synthesized_errors_to_console_ && display == kDisplayInConsole) {
    String message = String("WebGL: ") + error_type + ": " +
                     String(function_name) + ": " + String(description);
    PrintGLErrorToConsole(message);
  }
  if (!isContextLost()) {
    if (!synthetic_errors_.Contains(error))
      synthetic_errors_.push_back(error);
  } else {
    if (!lost_context_errors_.Contains(error))
      lost_context_errors_.push_back(error);
  }
  NotifyWebGLError(error_type);
}

void WebGLRenderingContextBase::EmitGLWarning(const char* function_name,
                                              const char* description) {
  if (synthesized_errors_to_console_) {
    String message =
        String("WebGL: ") + String(function_name) + ": " + String(description);
    PrintGLErrorToConsole(message);
  }
  NotifyWebGLWarning();
}

void WebGLRenderingContextBase::ApplyDepthAndStencilTest() {
  bool have_stencil_buffer = false;
  bool have_depth_buffer = false;

  if (framebuffer_binding_) {
    have_depth_buffer = framebuffer_binding_->HasDepthBuffer();
    have_stencil_buffer = framebuffer_binding_->HasStencilBuffer();
  } else {
    have_depth_buffer = !isContextLost() && CreationAttributes().depth &&
                        GetDrawingBuffer()->HasDepthBuffer();
    have_stencil_buffer = !isContextLost() && CreationAttributes().stencil &&
                          GetDrawingBuffer()->HasStencilBuffer();
  }
  EnableOrDisable(GL_DEPTH_TEST, depth_enabled_ && have_depth_buffer);
  EnableOrDisable(GL_STENCIL_TEST, stencil_enabled_ && have_stencil_buffer);
}

void WebGLRenderingContextBase::EnableOrDisable(GLenum capability,
                                                bool enable) {
  if (isContextLost())
    return;
  if (enable)
    ContextGL()->Enable(capability);
  else
    ContextGL()->Disable(capability);
}

gfx::Size WebGLRenderingContextBase::ClampedCanvasSize() const {
  int width = Host()->Size().width();
  int height = Host()->Size().height();
  return gfx::Size(Clamp(width, 1, max_viewport_dims_[0]),
                   Clamp(height, 1, max_viewport_dims_[1]));
}

GLint WebGLRenderingContextBase::MaxDrawBuffers() {
  if (isContextLost() ||
      !(ExtensionEnabled(kWebGLDrawBuffersName) || IsWebGL2()))
    return 0;
  if (!max_draw_buffers_)
    ContextGL()->GetIntegerv(GL_MAX_DRAW_BUFFERS_EXT, &max_draw_buffers_);
  if (!max_color_attachments_)
    ContextGL()->GetIntegerv(GL_MAX_COLOR_ATTACHMENTS_EXT,
                             &max_color_attachments_);
  // WEBGL_draw_buffers requires MAX_COLOR_ATTACHMENTS >= MAX_DRAW_BUFFERS.
  return std::min(max_draw_buffers_, max_color_attachments_);
}

GLint WebGLRenderingContextBase::MaxColorAttachments() {
  if (isContextLost() ||
      !(ExtensionEnabled(kWebGLDrawBuffersName) || IsWebGL2()))
    return 0;
  if (!max_color_attachments_)
    ContextGL()->GetIntegerv(GL_MAX_COLOR_ATTACHMENTS_EXT,
                             &max_color_attachments_);
  return max_color_attachments_;
}

void WebGLRenderingContextBase::SetBackDrawBuffer(GLenum buf) {
  back_draw_buffer_ = buf;
  if (GetDrawingBuffer()) {
    GetDrawingBuffer()->SetDrawBuffer(buf);
  }
}

void WebGLRenderingContextBase::SetFramebuffer(GLenum target,
                                               WebGLFramebuffer* buffer) {
  if (buffer)
    buffer->SetHasEverBeenBound();

  if (target == GL_FRAMEBUFFER || target == GL_DRAW_FRAMEBUFFER) {
    framebuffer_binding_ = buffer;
    ApplyDepthAndStencilTest();
  }
  if (!buffer) {
    // Instead of binding fb 0, bind the drawing buffer.
    GetDrawingBuffer()->Bind(target);
  } else {
    ContextGL()->BindFramebuffer(target, buffer->Object());
  }
}

void WebGLRenderingContextBase::RestoreCurrentFramebuffer() {
  bindFramebuffer(GL_FRAMEBUFFER, framebuffer_binding_.Get());
}

void WebGLRenderingContextBase::RestoreCurrentTexture2D() {
  bindTexture(GL_TEXTURE_2D,
              texture_units_[active_texture_unit_].texture2d_binding_.Get());
}

void WebGLRenderingContextBase::RestoreCurrentTextureCubeMap() {
  bindTexture(
      GL_TEXTURE_CUBE_MAP,
      texture_units_[active_texture_unit_].texture_cube_map_binding_.Get());
}

void WebGLRenderingContextBase::FindNewMaxNonDefaultTextureUnit() {
  // Trace backwards from the current max to find the new max non-default
  // texture unit
  int start_index = one_plus_max_non_default_texture_unit_ - 1;
  for (int i = start_index; i >= 0; --i) {
    if (texture_units_[i].texture2d_binding_ ||
        texture_units_[i].texture_cube_map_binding_) {
      one_plus_max_non_default_texture_unit_ = i + 1;
      return;
    }
  }
  one_plus_max_non_default_texture_unit_ = 0;
}

void WebGLRenderingContextBase::TextureUnitState::Trace(
    blink::Visitor* visitor) const {
  visitor->Trace(texture2d_binding_);
  visitor->Trace(texture_cube_map_binding_);
  visitor->Trace(texture3d_binding_);
  visitor->Trace(texture2d_array_binding_);
  visitor->Trace(texture_video_image_binding_);
  visitor->Trace(texture_external_oes_binding_);
  visitor->Trace(texture_rectangle_arb
"""


```