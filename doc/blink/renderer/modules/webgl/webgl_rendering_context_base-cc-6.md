Response:
The user wants to understand the functionality of the provided C++ code snippet from Chromium's Blink engine. This file seems to be responsible for handling texture uploads in WebGL. I need to break down its core functionalities and relate them to web technologies like JavaScript, HTML, and CSS. I also need to cover aspects like logical reasoning, common user errors, debugging, and summarize the code's purpose as part 7 of 11.

Here's a plan:

1. **Identify core functionalities:** Analyze the code for key operations, focusing on functions like `TexImageSkImage`, `TexImageBase`, `ValidateTexFunc`, and the various `texImage2D` overloads.
2. **Relate to web technologies:** Explain how these functions interact with JavaScript WebGL APIs (like `texImage2D`), HTML elements (like `<img>`, `<video>`, `<canvas>`), and how CSS might indirectly influence texture uploads (e.g., image loading).
3. **Logical reasoning with examples:**  Provide hypothetical scenarios with inputs and expected outputs for functions like `ValidateTexImageSubRectangle` or the color space conversion logic.
4. **Common user errors:** List typical mistakes developers make when using WebGL texture APIs and how this code might catch or handle them.
5. **Debugging clues:** Describe the user actions that could lead to this code being executed, aiding in debugging.
6. **Summarize the section:** Condense the functionality of this specific part of the code.
这是 `blink/renderer/modules/webgl/webgl_rendering_context_base.cc` 文件的第 7 部分，主要负责处理将各种来源的数据上传到 WebGL 纹理的功能。以下是其功能的详细说明：

**核心功能：纹理数据上传**

这部分代码的核心职责是将不同来源的图像数据（例如来自 HTML 图像元素、HTML 视频元素、ImageData 对象、Canvas 等）转换为 WebGL 纹理对象可以使用的格式，并最终通过 OpenGL API 上传到 GPU。

**详细功能分解：**

1. **`GetCurrentUnpackState(TexImageParams& params)`:**  获取当前的纹理解包状态，例如是否预乘 Alpha，是否垂直翻转，以及是否进行颜色空间转换。这些状态会影响后续的图像处理。
    * **与 JavaScript 关系:**  这些状态对应于 WebGL 上 `pixelStorei` API 设置的参数，例如 `UNPACK_PREMULTIPLY_ALPHA_WEBGL`, `UNPACK_FLIP_Y_WEBGL`, `UNPACK_COLORSPACE_CONVERSION_WEBGL`。

2. **`TexImageSkImage(TexImageParams params, sk_sp<SkImage> image, bool image_has_flip_y)`:** 这是处理 Skia 图像 (SkImage) 上传到纹理的核心函数。它负责：
    * **验证子矩形选择:** 检查用户是否选择了图像的一部分进行上传，并进行相应的验证。
    * **颜色空间处理:** 确保源图像具有颜色空间信息，并根据需要进行颜色空间转换（例如转换为 sRGB）。
    * **格式转换:** 将 Skia 图像的像素格式转换为 WebGL 指定的格式。
    * **Alpha 预乘/反预乘:** 根据 `unpack_premultiply_alpha_` 的设置，对图像进行 Alpha 预乘或反预乘处理。
    * **垂直翻转:**  根据 `unpack_flip_y_` 和源图像的翻转状态，决定是否需要垂直翻转图像。
    * **使用 Skia 进行像素读取和转换:**  尝试直接访问 Skia 图像的像素数据，如果格式不匹配或需要进行转换，则使用 `SkImage::readPixels` 进行转换。
    * **使用 WebGLImageConversion 进行额外转换:** 如果 Skia 无法完成所有必要的转换（例如，目标格式 Skia 不支持），则使用 `WebGLImageConversion` 工具进行处理。
    * **调用 `TexImageBase` 进行最终上传:**  将处理后的像素数据传递给 `TexImageBase` 函数进行实际的 OpenGL 上传。

3. **`TexImageBase(const TexImageParams& params, const void* pixels)`:**  直接调用底层 OpenGL API (`ContextGL()`) 的 `TexImage2D`, `TexSubImage2D`, `TexImage3D`, `TexSubImage3D` 函数，将准备好的像素数据上传到 GPU 的纹理对象。

4. **`TexImageStaticBitmapImage(TexImageParams params, StaticBitmapImage* image, bool image_has_flip_y, bool allow_copy_via_gpu)`:**  处理来自 `StaticBitmapImage` (通常是 HTML 图像元素的 backing image) 的纹理上传。
    * **GPU 颜色空间转换:** 如果允许且图像是 GPU 加速的，则在 GPU 上进行颜色空间转换。
    * **GPU 拷贝优化:** 如果条件允许 (例如目标纹理格式匹配)，尝试使用 GPU 直接拷贝 (`TexImageViaGPU`) 来提高性能。
    * **处理图像方向:** 如果图像具有非默认方向，则使用 `Image::ResizeAndOrientImage` 进行调整。
    * **转换为 SkImage:** 将 `StaticBitmapImage` 转换为 `SkImage`，然后调用 `TexImageSkImage` 进行处理。

5. **`ValidateTexFunc(TexImageParams params, std::optional<GLsizei> source_width, std::optional<GLsizei> source_height)`:** 验证纹理函数的参数，例如目标、层级 (level)、以及可选的源图像尺寸。
    * **逻辑推理示例:**
        * **假设输入:** `params.target = GL_TEXTURE_2D`, `params.level = 0`, `source_width = 100`, `source_height = 50`
        * **预期输出:**  函数会检查 `level` 是否在有效范围内，以及纹理目标是否合法。如果都合法，则返回 `true`。
        * **假设输入:** `params.target = GL_TEXTURE_CUBE_MAP`, `params.level = 10`
        * **预期输出:** 函数可能会因为 `level` 超出允许范围而返回 `false`，并可能触发一个 WebGL 错误。

6. **`ValidateValueFitNonNegInt32(const char* function_name, const char* param_name, int64_t value)`:** 验证一个 int64_t 类型的值是否可以安全地转换为非负的 int32_t。

7. **`DrawImageIntoBufferForTexImage(scoped_refptr<Image> pass_image, int width, int height, const char* function_name)`:** 将图像绘制到一个临时的 Canvas 缓冲区中，用于处理例如 SVG 图像或需要调整方向的图像。
    * **与 HTML/CSS 关系:**  这个函数处理了将 HTML 中的 `<img>` 标签加载的图像数据用于 WebGL 纹理的情况。CSS 可能会影响图像的加载和渲染，但这里的核心是处理已经加载的图像数据。

8. **`ValidateTexImageBinding(const TexImageParams& params)`:** 验证指定的目标纹理是否已绑定。

9. **`GetTexImageFunctionName(TexImageFunctionID func_name)` 和 `GetTexImageFunctionType(TexImageFunctionID function_id)`:**  辅助函数，用于根据 `TexImageFunctionID` 获取对应的函数名和类型（`kTexImage` 或 `kTexSubImage`）。

10. **`SafeGetImageSize(Image* image)`:** 安全地获取图像的尺寸。

11. **`CanvasRenderingContextSkColorInfo()`:**  获取用于 Canvas 渲染上下文的 Skia 颜色信息。

12. **`GetImageDataSize(ImageData* pixels)`:** 获取 `ImageData` 对象的尺寸。

13. **`TexImageHelperDOMArrayBufferView(...)`:** 处理来自 `DOMArrayBufferView` (例如 `Uint8Array`) 的纹理数据上传。
    * **用户常见错误:**  用户可能提供的 `src_offset` 超出 `DOMArrayBufferView` 的范围，或者提供的 `width` 和 `height` 与数组的实际大小不匹配。
    * **逻辑推理示例:**
        * **假设输入:**  一个 `Uint8Array`，`params.width = 10`, `params.height = 10`, `params.format = GL_RGBA`, `params.type = GL_UNSIGNED_BYTE`。
        * **预期输出:** 函数会计算需要的字节数 (10 * 10 * 4) 并检查 `Uint8Array` 是否有足够的空间。如果空间不足，会触发 `GL_INVALID_OPERATION` 错误。

14. **`texImage2D(...)` (多个重载):**  这是 JavaScript 中 `texImage2D` API 在 Blink 引擎中的实现入口点，分别处理来自 `DOMArrayBufferView`, `ImageData`, `HTMLImageElement` 等不同来源的数据。

15. **`TexImageHelperImageData(...)`:** 处理来自 `ImageData` 对象的纹理上传。
    * **用户常见错误:**  用户可能尝试使用一个已经被 detached 的 `ImageData` 对象。

16. **`TexImageHelperHTMLImageElement(...)`:** 处理来自 `HTMLImageElement` 的纹理上传。
    * **与 HTML 关系:**  直接处理 `<img>` 标签。
    * **用户操作流程:** 用户在 HTML 中放置一个 `<img>` 标签，浏览器加载图片，JavaScript 调用 `texImage2D` 并传入该 `<img>` 元素。

17. **`CanUseTexImageViaGPU(const TexImageParams& params)`:** 判断是否可以使用 GPU 直通拷贝来上传纹理，这通常比 CPU 上传更快。该函数会考虑多种限制条件，例如纹理格式、类型和平台特性。

18. **`TexImageViaGPU(...)`:**  执行 GPU 直通拷贝纹理上传。
    * **用户操作流程:** 当 JavaScript 调用 `texImage2D` 或 `texSubImage2D` 并传入一个可以进行 GPU 拷贝的源（例如另一个 Canvas 的 WebGL 上下文的 drawing buffer），并且满足 `CanUseTexImageViaGPU` 的条件时，会执行此路径。

19. **`TexImageHelperCanvasRenderingContextHost(...)`:** 处理来自 `CanvasRenderingContextHost` (代表 `<canvas>` 元素的 2D 或 WebGL 上下文) 的纹理上传。
    * **与 HTML 关系:**  直接处理 `<canvas>` 元素。
    * **用户操作流程:** 用户在 HTML 中创建一个 `<canvas>` 元素，并在 JavaScript 中获取其 2D 或 WebGL 渲染上下文，然后调用另一个 WebGL 上下文的 `texImage2D` 或 `texSubImage2D` 并传入该 Canvas 的渲染上下文。

**作为调试线索的用户操作:**

用户通常通过以下操作触发这部分代码的执行：

1. **在 JavaScript 中调用 `gl.texImage2D()` 或 `gl.texSubImage2D()`:**  这是最直接的方式。用户会传入不同的参数，例如目标纹理、层级、内部格式、尺寸、格式、类型以及源数据（`ArrayBufferView`, `ImageData`, `HTMLImageElement`, `HTMLVideoElement`, `HTMLCanvasElement` 或另一个 WebGL 上下文）。
2. **加载包含图像的 HTML 页面:** 浏览器加载 `<img>` 标签指向的图像资源。如果 JavaScript 代码随后使用 `texImage2D()` 将该图像上传到 WebGL 纹理，就会触发相关代码。
3. **使用 `<video>` 元素播放视频:** 类似于图像，JavaScript 可以使用 `texImage2D()` 将视频的当前帧上传到 WebGL 纹理。
4. **在 Canvas 上绘制内容:**  用户可以使用 Canvas 2D API 绘制图形或图像，然后使用 WebGL 的 `texImage2D()` 将 Canvas 的内容作为纹理上传。
5. **使用另一个 Canvas 的 WebGL 上下文作为纹理源:**  用户可以创建一个 Canvas 元素，获取其 WebGL 上下文，渲染一些内容，然后在另一个 WebGL 上下文中，使用 `texImage2D()` 将前一个 Canvas 的内容作为纹理上传。

**用户或编程常见的使用错误举例说明:**

1. **类型不匹配:**  在 `texImage2D` 中指定的 `format` 和 `type` 与提供的源数据不匹配。例如，提供了一个 `Uint8Array`，但指定 `type` 为 `FLOAT`。这会导致数据解析错误或 OpenGL 错误。
2. **尺寸不匹配:**  提供的源数据的尺寸与 `texImage2D` 中指定的 `width` 和 `height` 不匹配。这可能导致部分数据丢失或读取超出范围。
3. **无效的解包参数:**  `pixelStorei` 设置的解包参数（例如 `UNPACK_ROW_LENGTH`, `UNPACK_SKIP_PIXELS`) 与源数据的实际布局不一致，导致数据读取错误。
4. **跨域问题:**  尝试将来自不同域的图像或视频上传到 WebGL 纹理，但没有配置 CORS。这会导致安全错误。
5. **使用已释放的资源:**  尝试使用已经被释放或 detached 的 `ImageData` 对象或 `ArrayBufferView`。
6. **在 WebGL 上下文丢失后尝试上传纹理:** 如果 WebGL 上下文由于某些原因丢失（例如 GPU 驱动崩溃），尝试调用 `texImage2D` 会失败。
7. **尝试将不可渲染的格式上传为可渲染的格式:** 例如，某些内部格式可能不支持渲染到纹理，但用户尝试将其作为帧缓冲附件。

**第 7 部分功能归纳:**

这部分代码主要负责处理各种来源（`ArrayBufferView`, `ImageData`, `HTMLImageElement`, `HTMLVideoElement`, `HTMLCanvasElement`）的图像数据，进行必要的预处理（例如颜色空间转换、Alpha 预乘/反预乘、垂直翻转），并最终将其上传到 WebGL 的纹理对象。它还包含了参数验证和 GPU 拷贝优化的逻辑。这部分是 WebGL 纹理功能的核心组成部分，使得开发者能够将各种视觉内容集成到 WebGL 场景中。

Prompt: 
```
这是目录为blink/renderer/modules/webgl/webgl_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共11部分，请归纳一下它的功能

"""
;
  return internalformat;
}

void WebGLRenderingContextBase::GetCurrentUnpackState(TexImageParams& params) {
  params.unpack_premultiply_alpha = unpack_premultiply_alpha_;
  params.unpack_flip_y = unpack_flip_y_;
  if (params.source_type == kSourceHTMLImageElement ||
      params.source_type == kSourceHTMLVideoElement ||
      params.source_type == kSourceVideoFrame) {
    params.unpack_colorspace_conversion =
        unpack_colorspace_conversion_ != GL_NONE;
  }
}

void WebGLRenderingContextBase::TexImageSkImage(TexImageParams params,
                                                sk_sp<SkImage> image,
                                                bool image_has_flip_y) {
  const char* func_name = GetTexImageFunctionName(params.function_id);

  bool selecting_sub_rectangle = false;
  if (!ValidateTexImageSubRectangle(params, image.get(),
                                    &selecting_sub_rectangle)) {
    return;
  }

  // Ensure that `image` have a color space, because SkImageInfo::readPixels and
  // SkPixmap::readPixels will fail if the source has no color space but the
  // destination does.
  if (!image->colorSpace())
    image = image->reinterpretColorSpace(SkColorSpace::MakeSRGB());

  // The UNSIGNED_INT_10F_11F_11F_REV type pack/unpack isn't implemented,
  // use GL_FLOAT instead.
  if (params.type == GL_UNSIGNED_INT_10F_11F_11F_REV)
    params.type = GL_FLOAT;

  // We will need to flip vertically if the unpack state for flip Y does not
  // match the source state for flip Y.
  const bool do_flip_y = image_has_flip_y != params.unpack_flip_y;

  // Let `converted_info` be `image`'s info, with adjustments for sub-rect
  // selection, alpha type, color type, and color space. Let `converted_x` and
  // `converted_y` be the origin in `image` at which the data is to be read.
  // We will convert `image` to this format (using SkImage::readPixels), if
  // it is not already in this format.
  SkImageInfo converted_info = image->imageInfo();
  int converted_x = 0;
  int converted_y = 0;
  {
    // Set the size and offset parameters for the readPixels call, so we only
    // convert the portion of `image` that is needed. Do not try this if we are
    // uploading a 3D volume (just convert the full image in that case).
    if (params.width.has_value() && params.height.has_value() &&
        params.depth.value_or(1) == 1) {
      converted_info = converted_info.makeWH(*params.width, *params.height);
      converted_x = params.unpack_skip_pixels;
      converted_y = params.unpack_skip_rows;
      if (do_flip_y) {
        converted_y = image->height() - converted_info.height() - converted_y;
      }
      params.unpack_skip_pixels = 0;
      params.unpack_skip_rows = 0;
      selecting_sub_rectangle = false;
    }

    // Set the alpha type to perform premultiplication or unmultiplication
    // during readPixels, if needed. If the input is opaque, do not change it
    // (readPixels fails if the source is opaque and the destination is not).
    if (converted_info.alphaType() != kOpaque_SkAlphaType) {
      converted_info = converted_info.makeAlphaType(
          params.unpack_premultiply_alpha ? kPremul_SkAlphaType
                                          : kUnpremul_SkAlphaType);
    }

    // Set the color type to perform pixel format conversion during readPixels,
    // if possible.
    converted_info = converted_info.makeColorType(
        WebGLImageConversion::DataFormatToSkColorType(
            WebGLImageConversion::GetDataFormat(params.format, params.type),
            converted_info.colorType()));

    // Set the color space to perform color space conversion to the unpack color
    // space during readPixels, if needed.
    if (params.unpack_colorspace_conversion) {
      converted_info = converted_info.makeColorSpace(
          PredefinedColorSpaceToSkColorSpace(unpack_color_space_));
    }
  }

  // Try to access `image`'s pixels directly. If they already match
  // `converted_info` and `converted_x` and `converted_y` are zero, then use
  // them directly. Otherwise, convert them using SkImage::readPixels.
  SkBitmap converted_bitmap;
  SkPixmap pixmap;
  if (!image->peekPixels(&pixmap) || pixmap.info() != converted_info ||
      pixmap.rowBytes() != converted_info.minRowBytes() || converted_x != 0 ||
      converted_y != 0) {
    converted_bitmap.allocPixels(converted_info);
    pixmap = converted_bitmap.pixmap();
    if (!image->readPixels(pixmap, converted_x, converted_y)) {
      SynthesizeGLError(GL_OUT_OF_MEMORY, func_name, "bad image data");
      return;
    }
  }

  // Let `gl_data` be the data that is passed to the GL upload function.
  const void* gl_data = pixmap.addr();

  // We will premultiply or unpremultiply only if there is a mismatch between
  // the source and the requested premultiplication format.
  WebGLImageConversion::AlphaOp alpha_op =
      WebGLImageConversion::kAlphaDoNothing;
  if (params.unpack_premultiply_alpha &&
      pixmap.alphaType() == kUnpremul_SkAlphaType) {
    alpha_op = WebGLImageConversion::kAlphaDoPremultiply;
  }
  if (!params.unpack_premultiply_alpha &&
      pixmap.alphaType() == kPremul_SkAlphaType) {
    alpha_op = WebGLImageConversion::kAlphaDoUnmultiply;
  }

  // If there are required conversions that Skia could not do above, then use
  // WebGLImageConversion to convert the data, and point `gl_data` at the
  // temporary buffer `image_conversion_data`.
  Vector<uint8_t> image_conversion_data;
  if (WebGLImageConversion::SkColorTypeToDataFormat(pixmap.colorType()) !=
          WebGLImageConversion::GetDataFormat(params.format, params.type) ||
      alpha_op != WebGLImageConversion::kAlphaDoNothing || do_flip_y ||
      selecting_sub_rectangle || params.depth != 1) {
    // Adjust the source image rectangle if doing a y-flip.
    gfx::Rect adjusted_source_rect(params.unpack_skip_pixels,
                                   params.unpack_skip_rows,
                                   params.width.value_or(pixmap.width()),
                                   params.height.value_or(pixmap.height()));
    if (do_flip_y) {
      adjusted_source_rect.set_y(pixmap.height() -
                                 adjusted_source_rect.bottom());
    }
    if (!WebGLImageConversion::PackSkPixmap(
            &pixmap, params.format, params.type, do_flip_y, alpha_op,
            adjusted_source_rect, params.depth.value_or(1),
            /*source_unpack_alignment=*/0, params.unpack_image_height,
            image_conversion_data)) {
      SynthesizeGLError(GL_INVALID_VALUE, func_name, "packImage error");
      return;
    }
    gl_data = image_conversion_data.data();
  }

  // Upload using GL.
  ScopedUnpackParametersResetRestore temporary_reset_unpack(this);
  if (!params.width)
    params.width = pixmap.width();
  if (!params.height)
    params.height = pixmap.height();
  if (!params.depth)
    params.depth = 1;
  TexImageBase(params, gl_data);
}

void WebGLRenderingContextBase::TexImageBase(const TexImageParams& params,
                                             const void* pixels) {
  // All calling functions check isContextLost, so a duplicate check is not
  // needed here.
  DCHECK(params.width && params.height);
  switch (params.function_id) {
    case kTexImage2D:
      ContextGL()->TexImage2D(
          params.target, params.level,
          ConvertTexInternalFormat(params.internalformat, params.type),
          *params.width, *params.height, params.border, params.format,
          params.type, pixels);
      break;
    case kTexSubImage2D:
      ContextGL()->TexSubImage2D(params.target, params.level, params.xoffset,
                                 params.yoffset, *params.width, *params.height,
                                 params.format, params.type, pixels);
      break;
    case kTexImage3D:
      DCHECK(params.depth);
      ContextGL()->TexImage3D(
          params.target, params.level,
          ConvertTexInternalFormat(params.internalformat, params.type),
          *params.width, *params.height, *params.depth, params.border,
          params.format, params.type, pixels);
      break;
    case kTexSubImage3D:
      DCHECK(params.depth);
      ContextGL()->TexSubImage3D(params.target, params.level, params.xoffset,
                                 params.yoffset, params.zoffset, *params.width,
                                 *params.height, *params.depth, params.format,
                                 params.type, pixels);
      break;
  }
}

void WebGLRenderingContextBase::TexImageStaticBitmapImage(
    TexImageParams params,
    StaticBitmapImage* image,
    bool image_has_flip_y,
    bool allow_copy_via_gpu) {
  // All calling functions check isContextLost, so a duplicate check is not
  // needed here.
  const char* func_name = GetTexImageFunctionName(params.function_id);

  // If `image` is accelerated, then convert to the unpack color space while
  // still on the GPU. Unaccelerated images will be converted on the CPU below
  // in TexImageSkImage.
  scoped_refptr<StaticBitmapImage> color_converted_image;
  if (params.unpack_colorspace_conversion && image->IsTextureBacked()) {
    color_converted_image = StaticBitmapImageTransform::ConvertToColorSpace(
        FlushReason::kWebGLTexImage, image,
        PredefinedColorSpaceToSkColorSpace(unpack_color_space_));
    if (!color_converted_image) {
      SynthesizeGLError(GL_OUT_OF_MEMORY, func_name,
                        "ImageBitmap in unpack color space unexpectedly empty");
      return;
    }
    image = color_converted_image.get();
  }

  // Copy using the GPU, if possible.
  if (allow_copy_via_gpu && image->IsTextureBacked() &&
      CanUseTexImageViaGPU(params)) {
    TexImageViaGPU(params, static_cast<AcceleratedStaticBitmapImage*>(image),
                   nullptr);
    return;
  }

  // Apply orientation if necessary. This should be merged into the
  // transformations performed inside TexImageSkImage.
  PaintImage paint_image = image->PaintImageForCurrentFrame();
  if (!image->HasDefaultOrientation()) {
    paint_image = Image::ResizeAndOrientImage(
        paint_image, image->CurrentFrameOrientation(), gfx::Vector2dF(1, 1), 1,
        kInterpolationNone);
  }

  sk_sp<SkImage> sk_image = paint_image.GetSwSkImage();
  if (!sk_image) {
    SynthesizeGLError(GL_INVALID_VALUE, func_name, "bad image data");
    return;
  }
  DCHECK_EQ(sk_image->width(), image->width());
  DCHECK_EQ(sk_image->height(), image->height());

  TexImageSkImage(params, std::move(sk_image), image_has_flip_y);
}

bool WebGLRenderingContextBase::ValidateTexFunc(
    TexImageParams params,
    std::optional<GLsizei> source_width,
    std::optional<GLsizei> source_height) {
  // Overwrite `params.width` and `params.height` with `source_width` and
  // `source_height`. If `params.depth` is unspecified, set it to 1.
  if (source_width)
    params.width = *source_width;
  if (source_height)
    params.height = *source_height;
  if (!params.depth)
    params.depth = 1;

  const char* function_name = GetTexImageFunctionName(params.function_id);
  if (!ValidateTexFuncLevel(function_name, params.target, params.level))
    return false;

  if (!ValidateTexFuncParameters(params)) {
    return false;
  }

  if (GetTexImageFunctionType(params.function_id) == kTexSubImage) {
    if (!ValidateSettableTexFormat(function_name, params.format))
      return false;
    if (!ValidateSize(function_name, params.xoffset, params.yoffset,
                      params.zoffset))
      return false;
  } else {
    // For SourceArrayBufferView, function ValidateTexFuncData() would handle
    // whether to validate the SettableTexFormat
    // by checking if the ArrayBufferView is null or not.
    if (params.source_type != kSourceArrayBufferView) {
      if (!ValidateSettableTexFormat(function_name, params.format))
        return false;
    }
  }

  return true;
}

bool WebGLRenderingContextBase::ValidateValueFitNonNegInt32(
    const char* function_name,
    const char* param_name,
    int64_t value) {
  if (value < 0) {
    String error_msg = String(param_name) + " < 0";
    SynthesizeGLError(GL_INVALID_VALUE, function_name,
                      error_msg.Ascii().c_str());
    return false;
  }
  if (value > static_cast<int64_t>(std::numeric_limits<int>::max())) {
    String error_msg = String(param_name) + " more than 32-bit";
    SynthesizeGLError(GL_INVALID_OPERATION, function_name,
                      error_msg.Ascii().c_str());
    return false;
  }
  return true;
}

// TODO(fmalita): figure why ImageExtractor can't handle
// SVG-backed images, and get rid of this intermediate step.
scoped_refptr<Image> WebGLRenderingContextBase::DrawImageIntoBufferForTexImage(
    scoped_refptr<Image> pass_image,
    int width,
    int height,
    const char* function_name) {
  scoped_refptr<Image> image(std::move(pass_image));
  DCHECK(image);

  // TODO(https://crbug.com/1341235): The choice of color type should match the
  // format of the TexImage function. The choice of alpha type should opaque for
  // opaque images. The color space should match the unpack color space.
  const auto resource_provider_info = SkImageInfo::Make(
      width, height, kN32_SkColorType, kPremul_SkAlphaType, nullptr);
  CanvasResourceProvider* resource_provider =
      generated_image_cache_.GetCanvasResourceProvider(resource_provider_info);
  if (!resource_provider) {
    SynthesizeGLError(GL_OUT_OF_MEMORY, function_name, "out of memory");
    return nullptr;
  }

  if (!image->CurrentFrameKnownToBeOpaque())
    resource_provider->Canvas().clear(SkColors::kTransparent);

  gfx::Rect src_rect(image->Size());
  gfx::Rect dest_rect(0, 0, width, height);
  cc::PaintFlags flags;
  // TODO(ccameron): WebGL should produce sRGB images.
  // https://crbug.com/672299
  ImageDrawOptions draw_options;
  draw_options.clamping_mode = Image::kDoNotClampImageToSourceRect;
  image->Draw(&resource_provider->Canvas(), flags, gfx::RectF(dest_rect),
              gfx::RectF(src_rect), draw_options);
  return resource_provider->Snapshot(FlushReason::kWebGLTexImage);
}

WebGLTexture* WebGLRenderingContextBase::ValidateTexImageBinding(
    const TexImageParams& params) {
  const char* func_name = GetTexImageFunctionName(params.function_id);
  return ValidateTexture2DBinding(func_name, params.target, true);
}

const char* WebGLRenderingContextBase::GetTexImageFunctionName(
    TexImageFunctionID func_name) {
  switch (func_name) {
    case kTexImage2D:
      return "texImage2D";
    case kTexSubImage2D:
      return "texSubImage2D";
    case kTexSubImage3D:
      return "texSubImage3D";
    case kTexImage3D:
      return "texImage3D";
    default:  // Adding default to prevent compile error
      return "";
  }
}

WebGLRenderingContextBase::TexImageFunctionType
WebGLRenderingContextBase::GetTexImageFunctionType(
    TexImageFunctionID function_id) {
  switch (function_id) {
    case kTexImage2D:
      return kTexImage;
    case kTexSubImage2D:
      return kTexSubImage;
    case kTexImage3D:
      return kTexImage;
    case kTexSubImage3D:
      return kTexSubImage;
  }
}

gfx::Rect WebGLRenderingContextBase::SafeGetImageSize(Image* image) {
  if (!image)
    return gfx::Rect();

  return GetTextureSourceSize(image);
}

SkColorInfo WebGLRenderingContextBase::CanvasRenderingContextSkColorInfo()
    const {
  // This selection of alpha type disregards whether or not the drawing buffer
  // is premultiplied. This is to match historical behavior that may or may not
  // have been intentional.
  const SkAlphaType alpha_type =
      CreationAttributes().alpha ? kPremul_SkAlphaType : kOpaque_SkAlphaType;
  SkColorType color_type = kN32_SkColorType;
  if (drawing_buffer_ && drawing_buffer_->StorageFormat() == GL_RGBA16F) {
    color_type = kRGBA_F16_SkColorType;
  }
  return SkColorInfo(
      color_type, alpha_type,
      PredefinedColorSpaceToSkColorSpace(drawing_buffer_color_space_));
}

gfx::Rect WebGLRenderingContextBase::GetImageDataSize(ImageData* pixels) {
  DCHECK(pixels);
  return GetTextureSourceSize(pixels);
}

void WebGLRenderingContextBase::TexImageHelperDOMArrayBufferView(
    TexImageParams params,
    DOMArrayBufferView* pixels,
    NullDisposition null_disposition,
    int64_t src_offset) {
  const char* func_name = GetTexImageFunctionName(params.function_id);
  if (isContextLost())
    return;
  if (!ValidateTexImageBinding(params))
    return;
  if (!ValidateTexFunc(params, std::nullopt, std::nullopt)) {
    return;
  }
  if (!ValidateTexFuncData(params, pixels, null_disposition, src_offset))
    return;
  // No need to check overflow because validateTexFuncData() already did.
  base::span<const uint8_t> data;
  if (pixels) {
    data = pixels->ByteSpanMaybeShared().subspan(
        static_cast<size_t>(src_offset) * pixels->TypeSize());
  }
  Vector<uint8_t> temp_data;
  bool change_unpack_params = false;
  if (!data.empty() && *params.width && *params.height &&
      (unpack_flip_y_ || unpack_premultiply_alpha_)) {
    DCHECK(params.function_id == kTexImage2D ||
           params.function_id == kTexSubImage2D);
    // Only enter here if width or height is non-zero. Otherwise, call to the
    // underlying driver to generate appropriate GL errors if needed.
    WebGLImageConversion::PixelStoreParams unpack_params =
        GetUnpackPixelStoreParams(kTex2D);
    GLint data_store_width =
        unpack_params.row_length ? unpack_params.row_length : *params.width;
    if (unpack_params.skip_pixels + *params.width > data_store_width) {
      SynthesizeGLError(GL_INVALID_OPERATION, func_name,
                        "Invalid unpack params combination.");
      return;
    }
    if (!WebGLImageConversion::ExtractTextureData(
            *params.width, *params.height, params.format, params.type,
            unpack_params, unpack_flip_y_, unpack_premultiply_alpha_,
            data.data(), temp_data)) {
      SynthesizeGLError(GL_INVALID_OPERATION, func_name,
                        "Invalid params.format/params.type combination.");
      return;
    }
    data = temp_data;
    change_unpack_params = true;
  }
  if (params.function_id == kTexImage3D ||
      params.function_id == kTexSubImage3D) {
    TexImageBase(params, data.data());
    return;
  }

  ScopedUnpackParametersResetRestore temporary_reset_unpack(
      this, change_unpack_params);
  TexImageBase(params, data.data());
}

void WebGLRenderingContextBase::texImage2D(
    GLenum target,
    GLint level,
    GLint internalformat,
    GLsizei width,
    GLsizei height,
    GLint border,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> pixels) {
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceArrayBufferView);
  params.width = width;
  params.height = height;
  params.depth = 1;
  params.border = border;
  TexImageHelperDOMArrayBufferView(params, pixels.Get(), kNullAllowed, 0);
}

void WebGLRenderingContextBase::TexImageHelperImageData(TexImageParams params,
                                                        ImageData* pixels) {
  const char* func_name = GetTexImageFunctionName(params.function_id);
  if (isContextLost())
    return;
  DCHECK(pixels);
  DCHECK(pixels->data());
  if (pixels->IsBufferBaseDetached()) {
    SynthesizeGLError(GL_INVALID_VALUE, func_name,
                      "The source data has been detached.");
    return;
  }

  if (!ValidateTexImageBinding(params))
    return;
  if (!ValidateTexFunc(params, pixels->width(), pixels->height())) {
    return;
  }

  auto pixmap = pixels->GetSkPixmap();
  auto image = SkImages::RasterFromPixmap(pixmap, nullptr, nullptr);
  TexImageSkImage(params, std::move(image), /*image_has_flip_y=*/false);
}

void WebGLRenderingContextBase::texImage2D(GLenum target,
                                           GLint level,
                                           GLint internalformat,
                                           GLenum format,
                                           GLenum type,
                                           ImageData* pixels) {
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceImageData);
  TexImageHelperImageData(params, pixels);
}

void WebGLRenderingContextBase::TexImageHelperHTMLImageElement(
    const SecurityOrigin* security_origin,
    const TexImageParams& params,
    HTMLImageElement* image,
    ExceptionState& exception_state) {
  const char* func_name = GetTexImageFunctionName(params.function_id);
  if (isContextLost())
    return;

  // TODO(crbug.com/1210718): It may be possible to simplify this code
  // by consolidating on CanvasImageSource::GetSourceImageForCanvas().

  if (!ValidateHTMLImageElement(security_origin, func_name, image,
                                exception_state))
    return;
  if (!ValidateTexImageBinding(params))
    return;

  scoped_refptr<Image> image_for_render = image->CachedImage()->GetImage();
  bool have_svg_image = IsA<SVGImage>(image_for_render.get());
  if (have_svg_image || !image_for_render->HasDefaultOrientation()) {
    if (have_svg_image && canvas()) {
      UseCounter::Count(canvas()->GetDocument(), WebFeature::kSVGInWebGL);
    }
    // DrawImageIntoBuffer always respects orientation
    image_for_render = DrawImageIntoBufferForTexImage(
        std::move(image_for_render), image->width(), image->height(),
        func_name);
  }
  if (!image_for_render || !ValidateTexFunc(params, image_for_render->width(),
                                            image_for_render->height())) {
    return;
  }

  ImageExtractor image_extractor(
      image_for_render.get(), params.unpack_premultiply_alpha,
      params.unpack_colorspace_conversion
          ? PredefinedColorSpaceToSkColorSpace(unpack_color_space_)
          : nullptr);
  auto sk_image = image_extractor.GetSkImage();
  if (!sk_image) {
    SynthesizeGLError(GL_INVALID_VALUE, func_name, "bad image data");
    return;
  }
  TexImageSkImage(params, std::move(sk_image), /*image_has_flip_y=*/false);
}

void WebGLRenderingContextBase::texImage2D(ScriptState* script_state,
                                           GLenum target,
                                           GLint level,
                                           GLint internalformat,
                                           GLenum format,
                                           GLenum type,
                                           HTMLImageElement* image,
                                           ExceptionState& exception_state) {
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceHTMLImageElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLImageElement(execution_context->GetSecurityOrigin(), params,
                                 image, exception_state);
}

bool WebGLRenderingContextBase::CanUseTexImageViaGPU(
    const TexImageParams& params) {
#if BUILDFLAG(IS_MAC)
  // RGB5_A1 is not color-renderable on NVIDIA Mac, see crbug.com/676209.
  // Though, glCopyTextureCHROMIUM can handle RGB5_A1 internalformat by doing a
  // fallback path, but it doesn't know the type info. So, we still cannot do
  // the fallback path in glCopyTextureCHROMIUM for
  // RGBA/RGBA/UNSIGNED_SHORT_5_5_5_1 format and type combination.
  if (params.type == GL_UNSIGNED_SHORT_5_5_5_1)
    return false;
#endif

  // TODO(kbr): continued bugs are seen on Linux with AMD's drivers handling
  // uploads to R8UI textures. crbug.com/710673
  if (params.format == GL_RED_INTEGER)
    return false;

#if BUILDFLAG(IS_ANDROID)
  // TODO(kbr): bugs were seen on Android devices with NVIDIA GPUs
  // when copying hardware-accelerated video textures to
  // floating-point textures. Investigate the root cause of this and
  // fix it. crbug.com/710874
  if (params.type == GL_FLOAT)
    return false;
#endif

  // OES_texture_half_float doesn't support HALF_FLOAT_OES type for
  // CopyTexImage/CopyTexSubImage. And OES_texture_half_float doesn't require
  // HALF_FLOAT_OES type texture to be renderable. So, HALF_FLOAT_OES type
  // texture cannot be copied to or drawn to by glCopyTextureCHROMIUM.
  if (params.type == GL_HALF_FLOAT_OES)
    return false;

  // TODO(https://crbug.com/612542): Implement GPU-to-GPU copy path for more
  // cases, like copying to layers of 3D textures, and elements of 2D texture
  // arrays.
  if (params.function_id != kTexImage2D && params.function_id != kTexSubImage2D)
    return false;

  return true;
}

void WebGLRenderingContextBase::TexImageViaGPU(
    TexImageParams params,
    AcceleratedStaticBitmapImage* source_image,
    WebGLRenderingContextBase* source_canvas_webgl_context) {
  WebGLTexture* texture = ValidateTexImageBinding(params);
  if (!texture)
    return;

  // source in Y-down coordinate space -> is_source_origin_top_left = true
  // source in Y-up coordinate space -> is_source_origin_top_left = false
  bool is_source_origin_top_left = false;
  gfx::Size source_size;
  // Only one of `source_image` and `source_canvas_webgl_context` may be
  // specified.
  if (source_image) {
    DCHECK(source_image->IsTextureBacked());
    DCHECK(!source_canvas_webgl_context);
    source_size = source_image->Size();
    is_source_origin_top_left = source_image->IsOriginTopLeft();
  }
  if (source_canvas_webgl_context) {
    DCHECK(!source_image);
    if (source_canvas_webgl_context->isContextLost()) {
      SynthesizeGLError(GL_INVALID_OPERATION,
                        GetTexImageFunctionName(params.function_id),
                        "Can't upload a texture from a lost WebGL context.");
      return;
    }
    source_size = source_canvas_webgl_context->GetDrawingBuffer()->Size();
    is_source_origin_top_left = source_canvas_webgl_context->IsOriginTopLeft();
  }
  if (!params.width)
    params.width = source_size.width();
  if (!params.height)
    params.height = source_size.height();

  if (params.function_id == kTexImage2D)
    TexImageBase(params, nullptr);

  ScopedPixelLocalStorageInterrupt scoped_pls_interrupt(this);
  ScopedTexture2DRestorer restorer(this);

  GLuint target_texture = texture->Object();
  bool possible_direct_copy = false;
  if (params.function_id == kTexImage2D ||
      params.function_id == kTexSubImage2D) {
    possible_direct_copy =
        Extensions3DUtil::CanUseCopyTextureCHROMIUM(params.target);
  }

  // if direct copy is not possible, create a temporary texture and then copy
  // from canvas to temporary texture to target texture.
  if (!possible_direct_copy) {
    ContextGL()->GenTextures(1, &target_texture);
    ContextGL()->BindTexture(GL_TEXTURE_2D, target_texture);
    ContextGL()->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER,
                               GL_NEAREST);
    ContextGL()->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER,
                               GL_NEAREST);
    ContextGL()->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,
                               GL_CLAMP_TO_EDGE);
    ContextGL()->TexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T,
                               GL_CLAMP_TO_EDGE);
    ContextGL()->TexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, *params.width,
                            *params.height, 0, GL_RGBA, GL_UNSIGNED_BYTE,
                            nullptr);
  }

  {
    // The GPU-GPU copy path uses the Y-up coordinate system.
    gfx::Rect source_sub_rectangle(params.unpack_skip_pixels,
                                   params.unpack_skip_rows, *params.width,
                                   *params.height);

    // source_sub_rectangle is always specified in Y-down coordinate space.
    // Adjust if source is in Y-up coordinate space.
    // If unpack_flip_y is true specified by the caller, adjust it back again.
    // This is equivalent of is_source_origin_top_left == params.unpack_flip_y.
    bool adjust_source_sub_rectangle =
        is_source_origin_top_left == params.unpack_flip_y;
    if (adjust_source_sub_rectangle) {
      source_sub_rectangle.set_y(source_size.height() -
                                 source_sub_rectangle.bottom());
    }

    // The various underlying copy functions require a Y-up rectangle.
    // We need to set flip_y according to source_coordinate system and the
    // unpack_flip_y value specified by the caller.
    // The first transferred pixel should be the upper left corner of the source
    // when params.unpack_flip_y is false. And bottom left corner of the source
    // when params.unpack_flip_y is true.
    bool flip_y = is_source_origin_top_left == params.unpack_flip_y;

    // glCopyTextureCHROMIUM has a DRAW_AND_READBACK path which will call
    // texImage2D. So, reset unpack buffer parameters before that.
    ScopedUnpackParametersResetRestore temporaryResetUnpack(this);
    if (source_image) {
      source_image->CopyToTexture(
          ContextGL(), params.target, target_texture, params.level,
          params.unpack_premultiply_alpha, flip_y,
          gfx::Point(params.xoffset, params.yoffset), source_sub_rectangle);
    } else {
      WebGLRenderingContextBase* gl = source_canvas_webgl_context;
      ScopedTexture2DRestorer inner_restorer(gl);
      if (!gl->GetDrawingBuffer()->CopyToPlatformTexture(
              ContextGL(), params.target, target_texture, params.level,
              params.unpack_premultiply_alpha, flip_y,
              gfx::Point(params.xoffset, params.yoffset), source_sub_rectangle,
              kBackBuffer)) {
        NOTREACHED();
      }
    }
  }

  if (!possible_direct_copy) {
    GLuint tmp_fbo;
    ContextGL()->GenFramebuffers(1, &tmp_fbo);
    ContextGL()->BindFramebuffer(GL_FRAMEBUFFER, tmp_fbo);
    ContextGL()->FramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                                      GL_TEXTURE_2D, target_texture, 0);
    ContextGL()->BindTexture(texture->GetTarget(), texture->Object());
    if (params.function_id == kTexImage2D) {
      ContextGL()->CopyTexSubImage2D(params.target, params.level, 0, 0, 0, 0,
                                     *params.width, *params.height);
    } else if (params.function_id == kTexSubImage2D) {
      ContextGL()->CopyTexSubImage2D(params.target, params.level,
                                     params.xoffset, params.yoffset, 0, 0,
                                     *params.width, *params.height);
    } else if (params.function_id == kTexSubImage3D) {
      ContextGL()->CopyTexSubImage3D(
          params.target, params.level, params.xoffset, params.yoffset,
          params.zoffset, 0, 0, *params.width, *params.height);
    }
    ContextGL()->FramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                                      GL_TEXTURE_2D, 0, 0);
    RestoreCurrentFramebuffer();
    ContextGL()->DeleteFramebuffers(1, &tmp_fbo);
    ContextGL()->DeleteTextures(1, &target_texture);
  }
}

void WebGLRenderingContextBase::TexImageHelperCanvasRenderingContextHost(
    const SecurityOrigin* security_origin,
    TexImageParams params,
    CanvasRenderingContextHost* context_host,
    ExceptionState& exception_state) {
  const char* func_name = GetTexImageFunctionName(params.function_id);
  if (isContextLost())
    return;
  if (!params.width)
    params.width = context_host->width();
  if (!params.height)
    params.height = context_host->height();
  if (!params.depth)
    params.depth = 1;

  // TODO(crbug.com/1210718): It may be possible to simplify this code
  // by consolidating on CanvasImageSource::GetSourceImageForCanvas().

  if (!ValidateCanvasRenderingContextHost(security_origin, func_name,
                                          context_host, exception_state)) {
    return;
  }
  if (!ValidateTexImageBinding(params))
    return;
  if (!ValidateTexFunc(params, *params.width, *params.height)) {
    return;
  }

  // Note that the sub-rectangle validation is needed for the GPU-GPU
  // copy case, but is redundant for the software upload case
  // (texImageImpl).
  bool selecting_sub_rectangle = false;
  if (!ValidateTexImageSubRectangle(params, context_host,
                                    &selecting_sub_rectangle)) {
    return;
  }

  // If the source is a WebGL context, then that context can blit its buffer
  // directly into a texture in this context. This path does not perform color
  // space conversion, so only use it if the source and unpack color spaces are
  // the same.
  if (auto* source_canvas_webgl_context = DynamicTo<WebGLRenderingContextBase>(
          context_host->RenderingContext())) {
    if (CanUseTexImageViaGPU(params) &&
        source_canvas_webgl_context->drawing_buffer_color_space_ ==
            unpack_color_space_) {
      TexImageViaGPU(params, nullptr, source_canvas_webgl_context);
      return;
    }
  }

  SourceImageStatus source_image_status = kInvalidSourceImageStatus;
  scoped_refptr<Ima
"""


```