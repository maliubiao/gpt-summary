Response:
The user wants a summary of the provided C++ code for a WebGL implementation within the Chromium Blink engine. Specifically, they are interested in:

1. **Functionality:** What does this code do?
2. **Relation to web technologies:** How does this code interact with JavaScript, HTML, and CSS?
3. **Logic and examples:** Provide examples of inputs and outputs if there's logic.
4. **Common errors:** What are some typical mistakes users or programmers make that relate to this code?
5. **Debugging:** How does a user end up at this code during debugging?
6. **Summary:** A concise overview of the code's purpose.

This is the 8th of 11 parts, suggesting a focus on a specific area within the larger WebGL context. Looking at the code, the primary functions appear to be related to:

* **Texture manipulation:** `texImage2D`, `texSubImage2D`, `TexParameter`
* **Uniform variable setting:** `uniform1f`, `uniform1fv`, `uniform1i`, `uniform1iv`, etc., up to `uniformMatrix2fv`.

Therefore, the core functionality revolves around getting data into textures and setting uniform variables within WebGL shaders.

**Plan:**

1. Summarize the functions related to texture manipulation, highlighting how they load data from various sources (images, canvases, videos, etc.) into WebGL textures. Explain the role of parameters like `target`, `level`, `internalformat`, `format`, and `type`.
2. Explain how these texture functions relate to JavaScript's WebGL API and how they enable rendering images, videos, and other visual data in WebGL contexts. Provide a simple JavaScript example.
3. Summarize the functions related to setting uniform variables. Explain their purpose in passing data from the JavaScript side to the shaders running on the GPU. Provide a simple JavaScript example.
4. Discuss common errors related to texture uploads (e.g., incorrect dimensions, data types, cross-origin issues) and uniform setting (e.g., incorrect data types, using a uniform that doesn't exist in the shader).
5. Describe how user actions in a web page (drawing on a canvas, playing a video, loading an image) can trigger these functions within the WebGL implementation. Mention the role of the WebGL API calls in the JavaScript code.
6. Provide a concise summary that captures the essence of this code section.
这是 `blink/renderer/modules/webgl/webgl_rendering_context_base.cc` 文件的第 8 部分，主要负责 **WebGL 纹理数据上传和纹理参数设置**，以及 **设置 uniform 变量** 的功能。

**功能列举:**

1. **纹理数据上传 (Texture Data Upload):**
   - `texImage2D`: 定义了将各种来源的数据（例如 `HTMLCanvasElement`, `HTMLVideoElement`, `ImageBitmap`, `ImageData`, `ArrayBufferView`）上传到 2D 纹理的方法。
   - `texSubImage2D`: 定义了更新 2D 纹理特定区域数据的方法，同样支持多种数据来源。
   - 这些函数内部会调用辅助函数（例如 `TexImageHelperHTMLCanvasRenderingContextHost`, `TexImageHelperHTMLVideoElement` 等）来处理不同数据来源的特定逻辑，包括数据验证、格式转换和实际的 GPU 纹理上传操作。

2. **纹理参数设置 (Texture Parameter Setting):**
   - `TexParameter`, `texParameterf`, `texParameteri`:  用于设置纹理的各种参数，例如过滤方式 (`GL_TEXTURE_MIN_FILTER`, `GL_TEXTURE_MAG_FILTER`)、纹理环绕方式 (`GL_TEXTURE_WRAP_S`, `GL_TEXTURE_WRAP_T`)、各向异性过滤 (`GL_TEXTURE_MAX_ANISOTROPY_EXT`) 等。

3. **Uniform 变量设置 (Uniform Variable Setting):**
   - 提供了一系列 `uniform` 函数，用于将数据传递给 WebGL shader 中的 uniform 变量。 这些函数根据 uniform 变量的类型和数量进行区分，例如：
     - `uniform1f`, `uniform1fv`: 设置单个或多个浮点数 uniform 变量。
     - `uniform1i`, `uniform1iv`: 设置单个或多个整数 uniform 变量。
     - `uniform2f`, `uniform2fv`, `uniform2i`, `uniform2iv`: 设置 2 分量向量 uniform 变量。
     - `uniform3f`, `uniform3fv`, `uniform3i`, `uniform3iv`: 设置 3 分量向量 uniform 变量。
     - `uniform4f`, `uniform4fv`, `uniform4i`, `uniform4iv`: 设置 4 分量向量 uniform 变量。
     - `uniformMatrix2fv`: 设置 2x2 矩阵 uniform 变量。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** 这些 C++ 函数直接对应 WebGL API 在 JavaScript 中的方法。例如：
    - JavaScript 中的 `gl.texImage2D()` 会调用 C++ 中的 `WebGLRenderingContextBase::texImage2D()`。
    - JavaScript 中的 `gl.texSubImage2D()` 会调用 C++ 中的 `WebGLRenderingContextBase::texSubImage2D()`。
    - JavaScript 中的 `gl.texParameteri()` 会调用 C++ 中的 `WebGLRenderingContextBase::texParameteri()`。
    - JavaScript 中的 `gl.uniform1f()`, `gl.uniformMatrix4fv()` 等会调用相应的 C++ `WebGLRenderingContextBase::uniform...()` 函数。

    **JavaScript 示例 (纹理上传):**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const gl = canvas.getContext('webgl');
    const texture = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, texture);
    const image = new Image();
    image.onload = function() {
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, image);
      gl.generateMipmap(gl.TEXTURE_2D);
    };
    image.src = 'myimage.png';
    ```
    这段 JavaScript 代码通过 `gl.texImage2D()` 将一个 HTML `<img>` 元素加载到 WebGL 纹理中。

    **JavaScript 示例 (Uniform 变量设置):**
    ```javascript
    const gl = canvas.getContext('webgl');
    const program = gl.createProgram(); // ... (shader 编译和链接) ...
    gl.useProgram(program);
    const colorLocation = gl.getUniformLocation(program, 'u_color');
    gl.uniform4f(colorLocation, 1.0, 0.0, 0.0, 1.0); // 设置 uniform 颜色为红色
    ```
    这段 JavaScript 代码通过 `gl.uniform4f()` 设置了一个名为 `u_color` 的 uniform 变量。

* **HTML:** HTML 元素，如 `<canvas>`, `<img>`, `<video>` 等，可以作为 `texImage2D` 和 `texSubImage2D` 的数据来源。
* **CSS:** CSS 的样式不会直接影响到这些 C++ 代码的执行，因为这部分代码主要处理 WebGL 的底层纹理和 uniform 管理。然而，CSS 可以影响包含 WebGL 上下文的 `<canvas>` 元素的尺寸和布局，这间接地影响了 WebGL 的渲染结果。

**逻辑推理与假设输入/输出:**

以 `TexImageHelperHTMLVideoElement` 函数为例，假设输入为一个指向 `HTMLVideoElement` 对象的指针，且该视频正在播放，并且纹理绑定是有效的。

**假设输入:**
- `security_origin`: 当前页面的安全源。
- `params`: `TexImageParams` 结构体，包含纹理目标、层级、内部格式等信息。
- `video`: 一个正在播放的 `HTMLVideoElement` 的指针。
- `exception_state`: 用于报告错误的异常状态对象。

**逻辑推理:**
1. 函数首先检查 WebGL 上下文是否丢失。
2. 调用 `ValidateHTMLVideoElement` 验证视频元素是否有效，包括是否可以跨域访问等。
3. 调用 `ValidateTexImageBinding` 验证纹理绑定是否有效。
4. 调用 `ValidateTexFunc` 验证纹理尺寸是否合法。
5. 获取视频的当前帧（`media_video_frame`）和用于渲染视频帧的渲染器（`video_renderer`）。
6. 调用 `TexImageHelperMediaVideoFrame` 将视频帧数据上传到纹理。

**假设输出:**
- 如果所有验证都通过，且视频帧成功上传，则函数没有明显的返回值，但会在 GPU 上更新相应的纹理数据。
- 如果验证失败，`exception_state` 对象会被设置相应的错误信息，函数会提前返回。

**用户或编程常见的使用错误举例:**

1. **纹理尺寸不匹配:** 使用 `texImage2D` 或 `texSubImage2D` 上传的数据尺寸与纹理对象本身定义的大小不一致。
   - **假设输入:** 创建了一个 256x256 的纹理，然后尝试上传一个 128x128 的 `ImageData` 对象，且没有指定偏移量和尺寸。
   - **预期结果:** WebGL 会报错，或者只更新纹理的一部分区域。

2. **数据类型不匹配:**  `texImage2D` 的 `format` 和 `type` 参数与上传的数据类型不匹配。
   - **假设输入:**  `format` 设置为 `gl.RGBA`，`type` 设置为 `gl.UNSIGNED_BYTE`，但上传的 `ArrayBufferView` 包含的是浮点数数据。
   - **预期结果:** 纹理数据可能出现错误或渲染异常。

3. **跨域问题:** 尝试将来自不同域的图像或视频上传到纹理，但没有配置 CORS。
   - **假设输入:**  JavaScript 代码尝试将一个 `<img>` 元素（`image.crossOrigin = 'anonymous'; image.src = 'https://another-domain.com/image.png';`) 上传到纹理，但服务器没有设置 `Access-Control-Allow-Origin` 头。
   - **预期结果:** WebGL 会报错，并阻止纹理上传。

4. **使用错误的 Uniform 变量类型:** 在 JavaScript 中使用 `gl.uniform1f` 设置一个在 shader 中声明为 `vec4` 的 uniform 变量。
   - **假设输入:** Shader 中有 `uniform vec4 u_color;`，但在 JavaScript 中调用 `gl.uniform1f(colorLocation, 1.0);`。
   - **预期结果:** uniform 变量的值不会被正确设置，导致渲染结果不符合预期。

5. **在错误的程序中使用 Uniform Location:**  使用从一个 shader program 获取的 uniform location 去设置另一个 shader program 的 uniform 变量。
   - **假设输入:** 获取了 `programA` 的 uniform location，然后尝试在 `programB` 被激活时使用该 location 设置 uniform。
   - **预期结果:** uniform 变量的值不会被正确设置，因为 location 在不同的 program 中是独立的。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在网页上与 WebGL 内容交互:** 例如，用户加载了一个包含 WebGL 动画或 3D 模型的网页。
2. **JavaScript 代码调用 WebGL API:** 网页的 JavaScript 代码会调用 `gl.texImage2D()`、`gl.texSubImage2D()` 或 `gl.uniform...()` 等函数来更新纹理数据或设置 shader 参数。
3. **浏览器引擎处理 WebGL API 调用:**  浏览器引擎（例如 Chromium 的 Blink 渲染引擎）接收到这些 JavaScript 调用。
4. **调用到 C++ WebGL 实现:**  JavaScript 的 WebGL API 调用会被映射到对应的 C++ 函数，例如 `WebGLRenderingContextBase::texImage2D` 或 `WebGLRenderingContextBase::uniform1f`。
5. **执行 C++ 代码:**  C++ 代码负责执行底层的 WebGL 操作，包括数据验证、与 GPU 通信等。

**调试线索:** 如果在调试 WebGL 应用时遇到纹理显示错误或 shader 渲染异常，并且怀疑是纹理数据上传或 uniform 变量设置的问题，开发者可能会：

- **在 JavaScript 代码中设置断点:**  在调用 `gl.texImage2D()`、`gl.texSubImage2D()` 或 `gl.uniform...()` 的地方设置断点，检查传递的参数是否正确。
- **查看 WebGL 错误信息:**  使用 `gl.getError()` 检查是否有 WebGL 错误发生。
- **使用浏览器开发者工具的 WebGL Inspector:**  查看当前绑定的纹理对象、其属性以及 uniform 变量的值。
- **深入 Blink 源码调试 (高级):**  如果需要更深入地了解问题，开发者可能会尝试在 Blink 源码中设置断点，例如在 `WebGLRenderingContextBase::texImage2D` 或 `WebGLRenderingContextBase::uniform1f` 等函数入口处，来检查 C++ 层的参数和执行流程。

**功能归纳 (针对第 8 部分):**

这部分代码主要负责 **将各种来源的图像、视频和像素数据加载到 WebGL 纹理中，设置纹理的过滤和环绕等参数，以及将数据传递给 WebGL shader 中的 uniform 变量**。它是 WebGL 渲染管线中至关重要的一部分，负责为 GPU 提供渲染所需的纹理数据和控制参数。

### 提示词
```
这是目录为blink/renderer/modules/webgl/webgl_rendering_context_base.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共11部分，请归纳一下它的功能
```

### 源代码
```cpp
ge> image = context_host->GetSourceImageForCanvas(
      FlushReason::kWebGLTexImage, &source_image_status,
      gfx::SizeF(*params.width, *params.height), kPremultiplyAlpha);
  if (source_image_status != kNormalSourceImageStatus)
    return;

  // The implementation of GetSourceImageForCanvas for both subclasses of
  // CanvasRenderingContextHost (HTMLCanvasElement and OffscreenCanvas) always
  // return a StaticBitmapImage.
  StaticBitmapImage* static_bitmap_image =
      DynamicTo<StaticBitmapImage>(image.get());
  DCHECK(static_bitmap_image);

  const bool source_has_flip_y =
      GetDrawingBuffer()->IsOriginTopLeft() && context_host->IsWebGL();
  const bool allow_copy_via_gpu = true;
  TexImageStaticBitmapImage(params, static_bitmap_image, source_has_flip_y,
                            allow_copy_via_gpu);
}

void WebGLRenderingContextBase::texImage2D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint internalformat,
    GLenum format,
    GLenum type,
    CanvasRenderingContextHost* context_host,
    ExceptionState& exception_state) {
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceHTMLCanvasElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperCanvasRenderingContextHost(
      execution_context->GetSecurityOrigin(), params, context_host,
      exception_state);
}

void WebGLRenderingContextBase::TexImageHelperHTMLVideoElement(
    const SecurityOrigin* security_origin,
    TexImageParams params,
    HTMLVideoElement* video,
    ExceptionState& exception_state) {
  const char* func_name = GetTexImageFunctionName(params.function_id);
  if (isContextLost())
    return;

  // TODO(crbug.com/1210718): It may be possible to simplify this code
  // by consolidating on CanvasImageSource::GetSourceImageForCanvas().

  if (!ValidateHTMLVideoElement(security_origin, func_name, video,
                                exception_state)) {
    return;
  }

  WebGLTexture* texture = ValidateTexImageBinding(params);
  if (!texture)
    return;
  if (!ValidateTexFunc(params, video->videoWidth(), video->videoHeight())) {
    return;
  }

  media::PaintCanvasVideoRenderer* video_renderer = nullptr;
  scoped_refptr<media::VideoFrame> media_video_frame;
  if (auto* wmp = video->GetWebMediaPlayer()) {
    media_video_frame = wmp->GetCurrentFrameThenUpdate();
    video_renderer = wmp->GetPaintCanvasVideoRenderer();
  }

  if (!media_video_frame || !video_renderer)
    return;

  // This is enforced by ValidateHTMLVideoElement(), but DCHECK to be sure.
  DCHECK(!WouldTaintCanvasOrigin(video));
  TexImageHelperMediaVideoFrame(params, texture, std::move(media_video_frame),
                                video_renderer);
}

void WebGLRenderingContextBase::TexImageHelperVideoFrame(
    const SecurityOrigin* security_origin,
    TexImageParams params,
    VideoFrame* frame,
    ExceptionState& exception_state) {
  const char* func_name = GetTexImageFunctionName(params.function_id);
  if (isContextLost())
    return;

  // TODO(crbug.com/1210718): It may be possible to simplify this code
  // by consolidating on CanvasImageSource::GetSourceImageForCanvas().

  WebGLTexture* texture = ValidateTexImageBinding(params);
  if (!texture)
    return;

  auto local_handle = frame->handle()->CloneForInternalUse();
  if (!local_handle) {
    SynthesizeGLError(GL_INVALID_OPERATION, func_name,
                      "can't texture a closed VideoFrame.");
    return;
  }

  const auto natural_size = local_handle->frame()->natural_size();
  if (!ValidateTexFunc(params, natural_size.width(), natural_size.height())) {
    return;
  }

  // Some blink::VideoFrame objects reference a SkImage which can be used
  // directly instead of making a copy through the VideoFrame.
  if (auto sk_img = local_handle->sk_image()) {
    DCHECK(!sk_img->isTextureBacked());
    auto image = UnacceleratedStaticBitmapImage::Create(std::move(sk_img));
    // Note: kHtmlDomVideo means alpha won't be unmultiplied.
    TexImageStaticBitmapImage(params, image.get(), /*image_has_flip_y=*/false,
                              /*allow_copy_via_gpu=*/false);
    return;
  }

  TexImageHelperMediaVideoFrame(params, texture, local_handle->frame(),
                                nullptr);
}

void WebGLRenderingContextBase::TexImageHelperMediaVideoFrame(
    TexImageParams params,
    WebGLTexture* texture,
    scoped_refptr<media::VideoFrame> media_video_frame,
    media::PaintCanvasVideoRenderer* video_renderer) {
  DCHECK(!isContextLost());
  DCHECK(texture);
  DCHECK(media_video_frame);

  // Paths that use the PaintCanvasVideoRenderer assume the target is sRGB, and
  // produce incorrect results when the unpack color space is not sRGB.
  const bool unpack_color_space_is_srgb =
      unpack_color_space_ == PredefinedColorSpace::kSRGB;

  // The CopyTexImage fast paths can't handle orientation, so if a non-default
  // orientation is provided, we must disable them.
  const auto transform = media_video_frame->metadata().transformation.value_or(
      media::kNoTransformation);
  const GLint adjusted_internalformat =
      ConvertTexInternalFormat(params.internalformat, params.type);
  const bool source_image_rect_is_default =
      params.unpack_skip_pixels == 0 && params.unpack_skip_rows == 0 &&
      (!params.width ||
       *params.width == media_video_frame->natural_size().width()) &&
      (!params.height ||
       *params.height == media_video_frame->natural_size().height());
  const auto& caps = GetDrawingBuffer()->ContextProvider()->GetCapabilities();
  const bool may_need_image_external_essl3 =
      caps.egl_image_external &&
      Extensions3DUtil::CopyTextureCHROMIUMNeedsESSL3(params.internalformat);
  const bool have_image_external_essl3 = caps.egl_image_external_essl3;
  const bool use_copy_texture_chromium =
      params.function_id == kTexImage2D && source_image_rect_is_default &&
      params.depth.value_or(1) == 1 && GL_TEXTURE_2D == params.target &&
      (have_image_external_essl3 || !may_need_image_external_essl3) &&
      CanUseTexImageViaGPU(params) && transform == media::kNoTransformation &&
      unpack_color_space_is_srgb;

  // Callers may chose to provide a renderer which ensures that generated
  // intermediates will be cached across TexImage calls for the same frame.
  std::unique_ptr<media::PaintCanvasVideoRenderer> local_video_renderer;
  if (!video_renderer) {
    local_video_renderer = std::make_unique<media::PaintCanvasVideoRenderer>();
    video_renderer = local_video_renderer.get();
  }

  // Format of source VideoFrame may be 16-bit format, e.g. Y16
  // format. glCopyTextureCHROMIUM requires the source texture to be in
  // 8-bit format. Converting 16-bits formatted source texture to 8-bits
  // formatted texture will cause precision lost. So, uploading such video
  // texture to half float or float texture can not use GPU-GPU path.
  if (use_copy_texture_chromium) {
    DCHECK(Extensions3DUtil::CanUseCopyTextureCHROMIUM(params.target));
    DCHECK_EQ(params.xoffset, 0);
    DCHECK_EQ(params.yoffset, 0);
    DCHECK_EQ(params.zoffset, 0);

    viz::RasterContextProvider* raster_context_provider = nullptr;
    if (auto wrapper = SharedGpuContext::ContextProviderWrapper()) {
      raster_context_provider =
          wrapper->ContextProvider()->RasterContextProvider();
    }

    // Go through the fast path doing a GPU-GPU textures copy without a readback
    // to system memory if possible.  Otherwise, it will fall back to the normal
    // SW path.

    if (media_video_frame->HasSharedImage() &&
        video_renderer->CopyVideoFrameTexturesToGLTexture(
            raster_context_provider, ContextGL(), media_video_frame,
            params.target, texture->Object(), adjusted_internalformat,
            params.format, params.type, params.level, unpack_premultiply_alpha_,
            unpack_flip_y_)) {
      return;
    }

    // For certain video frame formats (e.g. I420/YUV), if they start on the CPU
    // (e.g. video camera frames): upload them to the GPU, do a GPU decode, and
    // then copy into the target texture.
    //
    // TODO(crbug.com/1180879): I420A should be supported, but currently fails
    // conformance/textures/misc/texture-video-transparent.html.
    if (!media_video_frame->HasSharedImage() &&
        media::IsOpaque(media_video_frame->format()) &&
        video_renderer->CopyVideoFrameYUVDataToGLTexture(
            raster_context_provider, ContextGL(), media_video_frame,
            params.target, texture->Object(), adjusted_internalformat,
            params.format, params.type, params.level, unpack_premultiply_alpha_,
            unpack_flip_y_)) {
      return;
    }
  }

  if (source_image_rect_is_default && media_video_frame->IsMappable() &&
      media_video_frame->format() == media::PIXEL_FORMAT_Y16 &&
      unpack_color_space_is_srgb) {
    // Try using optimized CPU-GPU path for some formats: e.g. Y16 and Y8. It
    // leaves early for other formats or if frame is stored on GPU.
    ScopedUnpackParametersResetRestore unpack_params(
        this, unpack_flip_y_ || unpack_premultiply_alpha_);

    const bool premultiply_alpha =
        unpack_premultiply_alpha_ && unpack_colorspace_conversion_ == GL_NONE;

    if (params.function_id == kTexImage2D &&
        media::PaintCanvasVideoRenderer::TexImage2D(
            params.target, texture->Object(), ContextGL(), caps,
            media_video_frame.get(), params.level, adjusted_internalformat,
            params.format, params.type, unpack_flip_y_, premultiply_alpha)) {
      return;
    } else if (params.function_id == kTexSubImage2D &&
               media::PaintCanvasVideoRenderer::TexSubImage2D(
                   params.target, ContextGL(), media_video_frame.get(),
                   params.level, params.format, params.type, params.xoffset,
                   params.yoffset, unpack_flip_y_, premultiply_alpha)) {
      return;
    }
  }

  // TODO(crbug.com/1175907): Double check that the premultiply alpha settings
  // are all correct below. When we go through the CanvasResourceProvider for
  // Image creation, SkImageInfo { kPremul_SkAlphaType } is used.
  //
  // We probably need some stronger checks on the accelerated upload path if
  // unmultiply has been requested or we need to never premultiply for Image
  // creation from a VideoFrame.

#if BUILDFLAG(IS_MAC)
  // TODO(crbug.com/1180726): Sampling from macOS IOSurfaces requires
  // GL_ARB_texture_rectangle which is not available in the WebGL context.
  constexpr bool kAllowZeroCopyImages = false;
#else
  constexpr bool kAllowZeroCopyImages = true;
#endif

#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_LINUX)
  // TODO(crbug.com/1175907): Only TexImage2D seems to work with the GPU path on
  // Android M -- appears to work fine on R, but to avoid regressions in <video>
  // limit to TexImage2D only for now. Fails conformance test on Nexus 5X:
  // conformance/textures/misc/texture-corner-case-videos.html
  //
  // TODO(crbug.com/1181562): TexSubImage2D via the GPU path performs poorly on
  // Linux when used with ShMem GpuMemoryBuffer backed frames. We don't have a
  // way to differentiate between true texture backed frames and ShMem GMBs, so
  // for now limit GPU texturing to TexImage2D.
  const bool function_supports_gpu_teximage = params.function_id == kTexImage2D;
#else
  const bool function_supports_gpu_teximage =
      params.function_id == kTexImage2D || params.function_id == kTexSubImage2D;
#endif

  const bool can_upload_via_gpu = function_supports_gpu_teximage &&
                                  CanUseTexImageViaGPU(params) &&
                                  source_image_rect_is_default;

  // If we can upload via GPU, try to to use an accelerated resource provider
  // configured appropriately for video. Otherwise use the software cache.
  auto& image_cache =
      can_upload_via_gpu ? generated_video_cache_ : generated_image_cache_;

  // Orient the destination rect based on the frame's transform.
  const auto& visible_rect = media_video_frame->visible_rect();
  auto dest_rect = gfx::Rect(visible_rect.size());
  if (transform.rotation == media::VIDEO_ROTATION_90 ||
      transform.rotation == media::VIDEO_ROTATION_270) {
    dest_rect.Transpose();
  }

  // TODO(https://crbug.com/1341235): The choice of color type will clamp
  // higher precision sources to 8 bit per color.
  const auto resource_provider_info = SkImageInfo::Make(
      gfx::SizeToSkISize(dest_rect.size()), kN32_SkColorType,
      media::IsOpaque(media_video_frame->format()) ? kOpaque_SkAlphaType
                                                   : kPremul_SkAlphaType,
      params.unpack_colorspace_conversion
          ? media_video_frame->CompatRGBColorSpace().ToSkColorSpace()
          : SkColorSpace::MakeSRGB());

  // Since TexImageStaticBitmapImage() and TexImageGPU() don't know how to
  // handle tagged orientation, we set |prefer_tagged_orientation| to false.
  scoped_refptr<StaticBitmapImage> image = CreateImageFromVideoFrame(
      std::move(media_video_frame), kAllowZeroCopyImages,
      image_cache.GetCanvasResourceProvider(resource_provider_info),
      video_renderer, dest_rect, /*prefer_tagged_orientation=*/false,
      /*reinterpret_video_as_srgb=*/!params.unpack_colorspace_conversion);
  if (!image)
    return;

  TexImageStaticBitmapImage(params, image.get(), /*image_has_flip_y=*/false,
                            can_upload_via_gpu);
}

void WebGLRenderingContextBase::texImage2D(ScriptState* script_state,
                                           GLenum target,
                                           GLint level,
                                           GLint internalformat,
                                           GLenum format,
                                           GLenum type,
                                           HTMLVideoElement* video,
                                           ExceptionState& exception_state) {
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceHTMLVideoElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLVideoElement(execution_context->GetSecurityOrigin(), params,
                                 video, exception_state);
}

void WebGLRenderingContextBase::texImage2D(ScriptState* script_state,
                                           GLenum target,
                                           GLint level,
                                           GLint internalformat,
                                           GLenum format,
                                           GLenum type,
                                           VideoFrame* frame,
                                           ExceptionState& exception_state) {
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceVideoFrame);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperVideoFrame(execution_context->GetSecurityOrigin(), params,
                           frame, exception_state);
}

void WebGLRenderingContextBase::TexImageHelperImageBitmap(
    TexImageParams params,
    ImageBitmap* bitmap,
    ExceptionState& exception_state) {
  const char* func_name = GetTexImageFunctionName(params.function_id);
  if (isContextLost())
    return;

  // TODO(crbug.com/1210718): It may be possible to simplify this code
  // by consolidating on CanvasImageSource::GetSourceImageForCanvas().

  if (!ValidateImageBitmap(func_name, bitmap, exception_state))
    return;
  if (!ValidateTexImageBinding(params))
    return;

  if (!params.width)
    params.width = bitmap->width();
  if (!params.height)
    params.height = bitmap->height();
  if (!params.depth)
    params.depth = 1;
  bool selecting_sub_rectangle = false;
  if (!ValidateTexImageSubRectangle(params, bitmap, &selecting_sub_rectangle)) {
    return;
  }

  if (!ValidateTexFunc(params, std::nullopt, std::nullopt)) {
    return;
  }

  auto static_bitmap_image = bitmap->BitmapImage();
  DCHECK(static_bitmap_image);

  // When TexImage is called with an ImageBitmap, the values of UNPACK_FLIP_Y,
  // UNPACK_PREMULTIPLY_ALPHA, and UNPACK_COLORSPACE_CONVERSION are to be
  // ignored. Set `adjusted_params` such that no conversions will be made using
  // that state.
  params.unpack_premultiply_alpha =
      static_bitmap_image->GetSkColorInfo().alphaType() == kPremul_SkAlphaType;
  params.unpack_flip_y = false;
  const bool image_has_flip_y = false;
  // TODO(kbr): make this work for sub-rectangles of ImageBitmaps.
  const bool can_copy_via_gpu = !selecting_sub_rectangle;
  TexImageStaticBitmapImage(params, static_bitmap_image.get(), image_has_flip_y,
                            can_copy_via_gpu);
}

void WebGLRenderingContextBase::texImage2D(GLenum target,
                                           GLint level,
                                           GLint internalformat,
                                           GLenum format,
                                           GLenum type,
                                           ImageBitmap* bitmap,
                                           ExceptionState& exception_state) {
  TexImageParams params;
  POPULATE_TEX_IMAGE_2D_PARAMS(params, kSourceImageBitmap);
  TexImageHelperImageBitmap(params, bitmap, exception_state);
}

void WebGLRenderingContextBase::TexParameter(GLenum target,
                                             GLenum pname,
                                             GLfloat paramf,
                                             GLint parami,
                                             bool is_float) {
  if (isContextLost())
    return;
  if (!ValidateTextureBinding("texParameter", target))
    return;
  switch (pname) {
    case GL_TEXTURE_MIN_FILTER:
      break;
    case GL_TEXTURE_MAG_FILTER:
      break;
    case GL_TEXTURE_WRAP_R:
      if (!IsWebGL2()) {
        SynthesizeGLError(GL_INVALID_ENUM, "texParameter",
                          "invalid parameter name");
        return;
      }
      [[fallthrough]];
    case GL_TEXTURE_WRAP_S:
    case GL_TEXTURE_WRAP_T:
      if (paramf == GL_MIRROR_CLAMP_TO_EDGE_EXT ||
          parami == GL_MIRROR_CLAMP_TO_EDGE_EXT) {
        if (!ExtensionEnabled(kEXTTextureMirrorClampToEdgeName)) {
          SynthesizeGLError(GL_INVALID_ENUM, "texParameter",
                            "invalid parameter, "
                            "EXT_texture_mirror_clamp_to_edge not enabled");
          return;
        }
        break;
      }
      if ((is_float && paramf != GL_CLAMP_TO_EDGE &&
           paramf != GL_MIRRORED_REPEAT && paramf != GL_REPEAT) ||
          (!is_float && parami != GL_CLAMP_TO_EDGE &&
           parami != GL_MIRRORED_REPEAT && parami != GL_REPEAT)) {
        SynthesizeGLError(GL_INVALID_ENUM, "texParameter", "invalid parameter");
        return;
      }
      break;
    case GL_TEXTURE_MAX_ANISOTROPY_EXT:  // EXT_texture_filter_anisotropic
      if (!ExtensionEnabled(kEXTTextureFilterAnisotropicName)) {
        SynthesizeGLError(
            GL_INVALID_ENUM, "texParameter",
            "invalid parameter, EXT_texture_filter_anisotropic not enabled");
        return;
      }
      break;
    case GL_TEXTURE_COMPARE_FUNC:
    case GL_TEXTURE_COMPARE_MODE:
    case GL_TEXTURE_BASE_LEVEL:
    case GL_TEXTURE_MAX_LEVEL:
    case GL_TEXTURE_MAX_LOD:
    case GL_TEXTURE_MIN_LOD:
      if (!IsWebGL2()) {
        SynthesizeGLError(GL_INVALID_ENUM, "texParameter",
                          "invalid parameter name");
        return;
      }
      break;
    case GL_DEPTH_STENCIL_TEXTURE_MODE_ANGLE:
      if (!ExtensionEnabled(kWebGLStencilTexturingName)) {
        SynthesizeGLError(
            GL_INVALID_ENUM, "texParameter",
            "invalid parameter name, WEBGL_stencil_texturing not enabled");
        return;
      }
      break;
    default:
      SynthesizeGLError(GL_INVALID_ENUM, "texParameter",
                        "invalid parameter name");
      return;
  }
  if (is_float) {
    ContextGL()->TexParameterf(target, pname, paramf);
  } else {
    ContextGL()->TexParameteri(target, pname, parami);
  }
}

void WebGLRenderingContextBase::texParameterf(GLenum target,
                                              GLenum pname,
                                              GLfloat param) {
  TexParameter(target, pname, param, 0, true);
}

void WebGLRenderingContextBase::texParameteri(GLenum target,
                                              GLenum pname,
                                              GLint param) {
  TexParameter(target, pname, 0, param, false);
}

void WebGLRenderingContextBase::texSubImage2D(
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLsizei width,
    GLsizei height,
    GLenum format,
    GLenum type,
    MaybeShared<DOMArrayBufferView> pixels) {
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceArrayBufferView);
  params.width = width;
  params.height = height;
  params.depth = 1;
  TexImageHelperDOMArrayBufferView(params, pixels.Get(), kNullNotAllowed, 0);
}

void WebGLRenderingContextBase::texSubImage2D(GLenum target,
                                              GLint level,
                                              GLint xoffset,
                                              GLint yoffset,
                                              GLenum format,
                                              GLenum type,
                                              ImageData* pixels) {
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceImageData);
  TexImageHelperImageData(params, pixels);
}

void WebGLRenderingContextBase::texSubImage2D(ScriptState* script_state,
                                              GLenum target,
                                              GLint level,
                                              GLint xoffset,
                                              GLint yoffset,
                                              GLenum format,
                                              GLenum type,
                                              HTMLImageElement* image,
                                              ExceptionState& exception_state) {
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceHTMLImageElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLImageElement(execution_context->GetSecurityOrigin(), params,
                                 image, exception_state);
}

void WebGLRenderingContextBase::texSubImage2D(
    ScriptState* script_state,
    GLenum target,
    GLint level,
    GLint xoffset,
    GLint yoffset,
    GLenum format,
    GLenum type,
    CanvasRenderingContextHost* context_host,
    ExceptionState& exception_state) {
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceHTMLCanvasElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperCanvasRenderingContextHost(
      execution_context->GetSecurityOrigin(), params, context_host,
      exception_state);
}

void WebGLRenderingContextBase::texSubImage2D(ScriptState* script_state,
                                              GLenum target,
                                              GLint level,
                                              GLint xoffset,
                                              GLint yoffset,
                                              GLenum format,
                                              GLenum type,
                                              HTMLVideoElement* video,
                                              ExceptionState& exception_state) {
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceHTMLVideoElement);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperHTMLVideoElement(execution_context->GetSecurityOrigin(), params,
                                 video, exception_state);
}

void WebGLRenderingContextBase::texSubImage2D(ScriptState* script_state,
                                              GLenum target,
                                              GLint level,
                                              GLint xoffset,
                                              GLint yoffset,
                                              GLenum format,
                                              GLenum type,
                                              VideoFrame* frame,
                                              ExceptionState& exception_state) {
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceVideoFrame);
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  TexImageHelperVideoFrame(execution_context->GetSecurityOrigin(), params,
                           frame, exception_state);
}

void WebGLRenderingContextBase::texSubImage2D(GLenum target,
                                              GLint level,
                                              GLint xoffset,
                                              GLint yoffset,
                                              GLenum format,
                                              GLenum type,
                                              ImageBitmap* bitmap,
                                              ExceptionState& exception_state) {
  TexImageParams params;
  POPULATE_TEX_SUB_IMAGE_2D_PARAMS(params, kSourceImageBitmap);
  TexImageHelperImageBitmap(params, bitmap, exception_state);
}

void WebGLRenderingContextBase::uniform1f(const WebGLUniformLocation* location,
                                          GLfloat x) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform1f", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform1f(location->Location(), x);
}

void WebGLRenderingContextBase::uniform1fv(const WebGLUniformLocation* location,
                                           base::span<const GLfloat> v) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform1fv", location, v, 1, 0, v.size(),
                                 &data, &length)) {
    return;
  }

  ContextGL()->Uniform1fv(location->Location(), length, data);
}

void WebGLRenderingContextBase::uniform1i(const WebGLUniformLocation* location,
                                          GLint x) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform1i", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform1i(location->Location(), x);
}

void WebGLRenderingContextBase::uniform1iv(const WebGLUniformLocation* location,
                                           base::span<const GLint> v) {
  const GLint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform1iv", location, v, 1, 0, v.size(),
                                 &data, &length)) {
    return;
  }

  ContextGL()->Uniform1iv(location->Location(), length, data);
}

void WebGLRenderingContextBase::uniform2f(const WebGLUniformLocation* location,
                                          GLfloat x,
                                          GLfloat y) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform2f", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform2f(location->Location(), x, y);
}

void WebGLRenderingContextBase::uniform2fv(const WebGLUniformLocation* location,
                                           base::span<const GLfloat> v) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform2fv", location, v, 2, 0, v.size(),
                                 &data, &length)) {
    return;
  }

  ContextGL()->Uniform2fv(location->Location(), length, data);
}

void WebGLRenderingContextBase::uniform2i(const WebGLUniformLocation* location,
                                          GLint x,
                                          GLint y) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform2i", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform2i(location->Location(), x, y);
}

void WebGLRenderingContextBase::uniform2iv(const WebGLUniformLocation* location,
                                           base::span<const GLint> v) {
  const GLint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform2iv", location, v, 2, 0, v.size(),
                                 &data, &length)) {
    return;
  }

  ContextGL()->Uniform2iv(location->Location(), length, data);
}

void WebGLRenderingContextBase::uniform3f(const WebGLUniformLocation* location,
                                          GLfloat x,
                                          GLfloat y,
                                          GLfloat z) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform3f", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform3f(location->Location(), x, y, z);
}

void WebGLRenderingContextBase::uniform3fv(const WebGLUniformLocation* location,
                                           base::span<const GLfloat> v) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform3fv", location, v, 3, 0, v.size(),
                                 &data, &length)) {
    return;
  }

  ContextGL()->Uniform3fv(location->Location(), length, data);
}

void WebGLRenderingContextBase::uniform3i(const WebGLUniformLocation* location,
                                          GLint x,
                                          GLint y,
                                          GLint z) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform3i", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform3i(location->Location(), x, y, z);
}

void WebGLRenderingContextBase::uniform3iv(const WebGLUniformLocation* location,
                                           base::span<const GLint> v) {
  const GLint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform3iv", location, v, 3, 0, v.size(),
                                 &data, &length)) {
    return;
  }

  ContextGL()->Uniform3iv(location->Location(), length, data);
}

void WebGLRenderingContextBase::uniform4f(const WebGLUniformLocation* location,
                                          GLfloat x,
                                          GLfloat y,
                                          GLfloat z,
                                          GLfloat w) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform4f", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform4f(location->Location(), x, y, z, w);
}

void WebGLRenderingContextBase::uniform4fv(const WebGLUniformLocation* location,
                                           base::span<const GLfloat> v) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform4fv", location, v, 4, 0, v.size(),
                                 &data, &length)) {
    return;
  }

  ContextGL()->Uniform4fv(location->Location(), length, data);
}

void WebGLRenderingContextBase::uniform4i(const WebGLUniformLocation* location,
                                          GLint x,
                                          GLint y,
                                          GLint z,
                                          GLint w) {
  if (isContextLost() || !location)
    return;

  if (!ValidateUniformLocation("uniform4i", location, current_program_)) {
    return;
  }

  ContextGL()->Uniform4i(location->Location(), x, y, z, w);
}

void WebGLRenderingContextBase::uniform4iv(const WebGLUniformLocation* location,
                                           base::span<const GLint> v) {
  const GLint* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformParameters("uniform4iv", location, v, 4, 0, v.size(),
                                 &data, &length)) {
    return;
  }

  ContextGL()->Uniform4iv(location->Location(), length, data);
}

void WebGLRenderingContextBase::uniformMatrix2fv(
    const WebGLUniformLocation* location,
    GLboolean transpose,
    base::span<const GLfloat> v) {
  const GLfloat* data;
  GLuint length;
  if (isContextLost() ||
      !ValidateUniformMatrixParameters("uniformMatrix2fv", location, transpose,
                                       v, 4, 0, v.size(), &data, &length)) {
    return;
  }
  ContextGL()->Unifor
```