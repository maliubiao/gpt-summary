Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from `drawing_buffer.cc`. I need to identify the core purpose of the code and how it interacts with graphics resources, especially in the context of Chromium's rendering pipeline. I should also look for connections to JavaScript, HTML, and CSS concepts, common usage patterns, potential errors, and logical inferences with hypothetical inputs and outputs.

**Functionality Breakdown:**

1. **Resource Management:** The code deals with managing GPU resources, specifically `SharedImage` objects, for rendering. This involves creating, accessing, and releasing these resources.
2. **Canvas Export:**  It provides mechanisms to export the drawing buffer's content as a `CanvasResource`, making it available for compositing or other GPU-based operations.
3. **Color Buffer Handling:** It manages color buffers (`ColorBuffer` class), which are essentially wrappers around `SharedImage` and related OpenGL resources. This includes managing access (read/write) and cleanup.
4. **Initialization and Resizing:**  The code handles the initialization of the drawing buffer, including setting up framebuffers (FBOs) and renderbuffers, and resizing these resources as needed. It also considers multisampling (MSAA) and different anti-aliasing modes.
5. **Copying Operations:** It implements functions to copy the drawing buffer's content to various destinations, including platform textures, mailboxes, and video frames. These copies often involve synchronization to ensure data integrity.
6. **Layer Integration:** The code interacts with Chromium's compositing layer system (`cc::Layer`), allowing the drawing buffer to be represented as a texture layer for rendering.
7. **Destruction and Reallocation:** It handles the cleanup and destruction of drawing buffer resources and provides mechanisms for reallocating the framebuffer.
8. **Framebuffer Operations:** It includes functions for clearing framebuffers and resolving multisampled framebuffers.
9. **Color Space Management:** The code allows setting and updating the color space of the drawing buffer.
10. **Synchronization:** The code uses `gpu::SyncToken` to ensure proper synchronization between different GPU operations, especially when sharing resources.

**Connections to Web Technologies:**

*   **JavaScript/HTML Canvas:** The `DrawingBuffer` is the underlying implementation for the `<canvas>` element. When JavaScript code draws on a canvas, those drawing commands are ultimately rendered into this buffer. The exported `CanvasResource` can be used in JavaScript through mechanisms like `transferToImageBitmap()`.
*   **CSS Compositing:** The `cc::Layer` integration connects the drawing buffer to the browser's compositing process. CSS properties like `opacity`, `transform`, and `filter` can trigger compositing, which utilizes the content of the `DrawingBuffer`.

**Logical Inferences and Hypothetical Scenarios:**

*   **Input:** A JavaScript call to `canvas.getContext('webgl').drawImage(...)`
*   **Output:** The `DrawingBuffer`'s `back_color_buffer_` will be updated with the image content. A new `ExternalCanvasResource` might be created to represent this updated content for the compositor.
*   **Input:** A CSS animation that transforms a canvas element.
*   **Output:** The `CcLayer()` associated with the `DrawingBuffer` will have its transformation properties updated, causing the compositor to render the transformed canvas content.

**Common Errors:**

*   **Context Loss:**  The code includes checks for `GL_NO_ERROR` to handle situations where the GPU context is lost. Users might encounter a blank canvas if the context is lost and not properly restored.
*   **Incorrect Synchronization:**  If synchronization using `gpu::SyncToken` is not handled correctly, it can lead to rendering glitches or data corruption.
*   **Resource Management Issues:** Failing to properly release resources can lead to memory leaks or other GPU-related errors.

**Part 2 Summary:**

This section of `drawing_buffer.cc` focuses on the management and manipulation of the drawing buffer's color buffer and its integration with external resources and the compositing system. It includes functionalities for:

*   Exporting the color buffer as an external resource.
*   Managing the lifecycle of the color buffer, including creation, access, and destruction.
*   Initializing and resizing the framebuffer associated with the color buffer.
*   Copying the color buffer's content to other GPU resources like textures, mailboxes, and video frames, ensuring proper synchronization.
*   Integrating the drawing buffer as a texture layer within the Chromium compositing pipeline.
*   Handling framebuffer clearing and resolution, especially in the context of multisampling.
*   Managing the color space of the drawing buffer.
这是 blink 渲染引擎中 `drawing_buffer.cc` 文件的一部分，主要负责管理用于渲染的图形缓冲区及其相关资源。从这段代码来看，它的功能可以归纳为以下几点：

**核心功能：管理和导出颜色缓冲区资源**

1. **创建和配置可导出的外部 Canvas 资源 (ExternalCanvasResource):**
    *   `PrepareTransferableResourceInternal` 函数（虽然代码中未直接展示，但被调用了）负责准备用于跨进程或跨线程传输的图形资源。它会获取或创建 `gpu::ClientSharedImage` 作为底层纹理。
    *   `CreateExternalCanvasResource` 函数负责将 `gpu::ClientSharedImage` 打包成 `ExternalCanvasResource`，使其可以被其他组件（例如 Compositor）使用。
    *   这个过程中会设置资源的各种属性，例如纹理的 mailbox、target、大小、格式、颜色空间、是否是 Overlay 候选等。
    *   如果内容发生变化且未使用交换链，会重新开始对 `SharedImage` 的访问，确保生成写栅栏，保证显示器读取到完整的当前帧。

2. **导出用于 GPU 合成的 Canvas 资源 (ExportCanvasResource):**
    *   这个函数专门用于导出 GPU 合成的内容。
    *   它强制创建 GPU 资源 (`force_gpu_result = true`)，确保后续操作能在 GPU 上进行。
    *   通过 `PrepareTransferableResourceInternal` 获取 `gpu::ClientSharedImage` 和 `viz::TransferableResource`。
    *   最终创建一个 `ExternalCanvasResource`，但不提供 `resource_provider`，因为它是用于 GPU 合成的。

3. **管理颜色缓冲区 (ColorBuffer):**
    *   `ColorBuffer` 类封装了与颜色缓冲区相关的资源，包括 `gpu::ClientSharedImage` 和 `gpu::SharedImageTexture`。
    *   它记录了缓冲区的属性，例如大小、颜色空间、格式、Alpha 类型、是否是 Overlay 候选等。
    *   它维护了对拥有 `DrawingBuffer` 的弱引用，以及拥有线程的引用。
    *   **开始和结束对 `SharedImage` 的访问:** `BeginAccess` 和 `EndAccess` 函数用于控制对底层 `SharedImage` 的读写访问，并处理同步令牌 (SyncToken)。这对于多线程或跨进程的图形操作至关重要，确保数据一致性。
    *   **清理资源:** `~ColorBuffer` 析构函数负责清理 `SharedImageTexture`，并根据线程和 `DrawingBuffer` 的状态决定是否需要更新销毁同步令牌。`ForceCleanUp` 可以强制清理 `SharedImageTexture`。

**与 JavaScript, HTML, CSS 的关系举例说明:**

*   **JavaScript 和 HTML Canvas:** 当 JavaScript 代码在 `<canvas>` 元素上进行绘制时，最终的像素数据会被写入到 `DrawingBuffer` 的颜色缓冲区中。`ExportCanvasResource` 提供的功能可以将这个缓冲区的内容作为纹理传递给 Compositor，用于页面的最终渲染。例如，一个使用 WebGL 绘制的 3D 图形，其渲染结果会存储在 `DrawingBuffer` 中，并通过 `ExportCanvasResource` 提供给浏览器进行合成显示。

*   **CSS Compositing:** 当浏览器进行图层合成时，`DrawingBuffer` 中的内容可以作为纹理被 Compositor 使用。例如，一个带有 CSS `transform` 属性的 `<canvas>` 元素，其内容会先渲染到 `DrawingBuffer`，然后 Compositor 会根据 `transform` 属性对这个纹理进行变换，最终合成到屏幕上。`ExternalCanvasResource` 就是用于在 Compositor 中表示这个纹理资源的。

**逻辑推理与假设输入输出:**

假设输入：

*   `contents_changed_ = true;` (DrawingBuffer 的内容已更改)
*   `using_swap_chain_ = false;` (未使用交换链)
*   `color_buffer` 是一个有效的 `ColorBuffer` 对象。

输出（在 `CreateExternalCanvasResource` 函数中）：

1. `resource` 对象会被设置正确的 mailbox、texture target、size、format 等属性，这些属性来源于 `color_buffer`。
2. 由于 `contents_changed_` 为 true 且未使用交换链，`color_buffer->EndAccess()` 会被调用以结束当前的访问，并生成一个写栅栏。
3. `color_buffer->BeginAccess(gpu::SyncToken(), /*readonly=*/false)` 会被调用以重新开始访问，确保显示器可以读取到完整的帧。
4. 最终返回一个使用 `color_buffer->shared_image` 创建的 `ExternalCanvasResource`。

**用户或编程常见的使用错误举例说明:**

*   **忘记调用 `BeginAccess` 和 `EndAccess`:** 如果在对 `ColorBuffer` 的 `SharedImage` 进行操作前后忘记调用 `BeginAccess` 和 `EndAccess`，可能会导致数据竞争和渲染错误。例如，在一个线程中写入 `SharedImage` 后，另一个线程立即读取，如果没有正确的同步机制，可能会读取到不完整或过时的数据。

*   **在错误的线程访问 `ColorBuffer`:**  `ColorBuffer` 记录了拥有线程的引用。如果在非拥有线程中直接访问和操作 `ColorBuffer` 的内部资源（例如 `shared_image_texture_`），可能会导致线程安全问题。析构函数中的检查 `base::PlatformThread::CurrentRef() != owning_thread_ref` 就是为了捕获这类错误。

**归纳一下它的功能 (第 2 部分):**

这部分 `drawing_buffer.cc` 的代码主要负责将 `DrawingBuffer` 中渲染的内容（存储在 `ColorBuffer` 中）以 `ExternalCanvasResource` 的形式导出，以便其他 Chromium 组件（特别是 Compositor）能够使用这些渲染结果进行后续的合成显示。它还详细管理了 `ColorBuffer` 的生命周期、访问控制和资源清理，并提供了将渲染结果导出为可用于 GPU 合成的资源的能力。核心在于提供了一种安全且高效的方式来共享和同步 GPU 上的渲染纹理资源。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/gpu/drawing_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
rce resource;

  resource.set_mailbox(color_buffer->shared_image->mailbox());
  resource.set_texture_target(color_buffer->shared_image->GetTextureTarget());
  resource.size = color_buffer->size;
  resource.format = color_buffer->format;
  resource.is_overlay_candidate = color_buffer->is_overlay_candidate;
  resource.color_space = color_buffer->color_space;
  resource.hdr_metadata = hdr_metadata_;
  resource.resource_source =
      viz::TransferableResource::ResourceSource::kDrawingBuffer;

  if (contents_changed_ && !using_swap_chain_) {
    // Restart SharedImage access on the single SharedImage to ensure a write
    // fence is generated on the shared image to guarantee display reads this
    // frame completely. Display may still read parts of subsequent frames,
    // which is okay.
    color_buffer->EndAccess();
    color_buffer->BeginAccess(gpu::SyncToken(), /*readonly=*/false);
  }

  return ExternalCanvasResource::Create(
      color_buffer->shared_image, resource, viz::ReleaseCallback(),
      context_provider_->GetWeakPtr(), resource_provider, filter_quality_);
}

scoped_refptr<CanvasResource> DrawingBuffer::ExportCanvasResource() {
  ScopedStateRestorer scoped_state_restorer(this);
  TRACE_EVENT0("blink", "DrawingBuffer::ExportCanvasResource");

  // Using PrepareTransferableResourceInternal, with force_gpu_result as we
  // will use this ExportCanvasResource only for gpu_composited content.
  viz::TransferableResource out_resource;
  viz::ReleaseCallback out_release_callback;
  const bool force_gpu_result = true;
  scoped_refptr<gpu::ClientSharedImage> client_si;
  if (!PrepareTransferableResourceInternal(
          &client_si, &out_resource, &out_release_callback, force_gpu_result)) {
    return nullptr;
  }
  // If PrepareTransferableResourceInternal() succeeded, the ClientSI must be
  // valid:
  // * We forced a GPU resource to be created, meaning that
  //   FinishPrepareTransferableResourceGpu() will have been invoked
  // * FinishPrepareTransferableResourceGpu() always populates `client_si` if it
  //   returns true
  CHECK(client_si);
  return ExternalCanvasResource::Create(
      client_si, out_resource, std::move(out_release_callback),
      context_provider_->GetWeakPtr(), /*resource_provider=*/nullptr,
      filter_quality_);
}

DrawingBuffer::ColorBuffer::ColorBuffer(
    base::WeakPtr<DrawingBuffer> drawing_buffer,
    const gfx::Size& size,
    const gfx::ColorSpace& color_space,
    viz::SharedImageFormat format,
    SkAlphaType alpha_type,
    bool is_overlay_candidate,
    scoped_refptr<gpu::ClientSharedImage> shared_image,
    std::unique_ptr<gpu::SharedImageTexture> shared_image_texture)
    : owning_thread_ref(base::PlatformThread::CurrentRef()),
      drawing_buffer(std::move(drawing_buffer)),
      size(size),
      color_space(color_space),
      format(format),
      alpha_type(alpha_type),
      is_overlay_candidate(is_overlay_candidate),
      shared_image(std::move(shared_image)),
      shared_image_texture_(std::move(shared_image_texture)) {
  CHECK(this->shared_image);
}

DrawingBuffer::ColorBuffer::~ColorBuffer() {
  if (scoped_shared_image_access_) {
    gpu::SharedImageTexture::ScopedAccess::EndAccess(
        std::move(scoped_shared_image_access_));
  }

  if (base::PlatformThread::CurrentRef() != owning_thread_ref ||
      !drawing_buffer) {
    // If the context has been destroyed no cleanup is necessary since all
    // resources below are automatically destroyed. Note that if a ColorBuffer
    // is being destroyed on a different thread, it implies that the owning
    // thread was destroyed which means the associated context was also
    // destroyed.
    CHECK(!shared_image_texture_);
    return;
  }

  gpu::gles2::GLES2Interface* gl = drawing_buffer->gl_;
  if (!gl) {
    // Guard against in-flight destruction of the DrawingBuffer, while
    // still performing cleanup during BeginDestruction().
    return;
  }
  WebGraphicsContext3DProvider* provider = drawing_buffer->ContextProvider();
  if (!provider) {
    // Guard against in-flight destruction of the DrawingBuffer, while
    // still performing cleanup during BeginDestruction().
    return;
  }
  gpu::SharedImageInterface* sii = provider->SharedImageInterface();
  if (!sii) {
    // Guard against in-flight destruction of the DrawingBuffer, while
    // still performing cleanup during BeginDestruction().
    return;
  }

  shared_image->UpdateDestructionSyncToken(receive_sync_token);
  shared_image_texture_.reset();
}

void DrawingBuffer::ColorBuffer::BeginAccess(const gpu::SyncToken& sync_token,
                                             bool readonly) {
  scoped_shared_image_access_ =
      shared_image_texture_->BeginAccess(sync_token, readonly);
}

gpu::SyncToken DrawingBuffer::ColorBuffer::EndAccess() {
  return gpu::SharedImageTexture::ScopedAccess::EndAccess(
      std::move(scoped_shared_image_access_));
}

void DrawingBuffer::ColorBuffer::ForceCleanUp() {
  if (scoped_shared_image_access_) {
    EndAccess();
  }
  shared_image_texture_.reset();
}

bool DrawingBuffer::Initialize(const gfx::Size& size, bool use_multisampling) {
  ScopedStateRestorer scoped_state_restorer(this);

  if (gl_->GetGraphicsResetStatusKHR() != GL_NO_ERROR) {
    // Need to try to restore the context again later.
    DLOG(ERROR) << "Cannot initialize with lost context.";
    return false;
  }

  gl_->GetIntegerv(GL_MAX_TEXTURE_SIZE, &max_texture_size_);

  int max_sample_count = 0;
  if (use_multisampling) {
    gl_->GetIntegerv(GL_MAX_SAMPLES_ANGLE, &max_sample_count);
  }

  auto webgl_preferences = ContextProvider()->GetWebglPreferences();

  // We can't use anything other than explicit resolve for swap chain.
  bool supports_implicit_resolve =
      !using_swap_chain_ && extensions_util_->SupportsExtension(
                                "GL_EXT_multisampled_render_to_texture");

  const auto& gpu_feature_info = ContextProvider()->GetGpuFeatureInfo();
  // With graphite, Skia is not using ANGLE, so ANGLE will never be able to know
  // when the back buffer is sampled by Skia, so we can't use implicit resolve.
  supports_implicit_resolve =
      supports_implicit_resolve &&
      gpu_feature_info.status_values[gpu::GPU_FEATURE_TYPE_SKIA_GRAPHITE] !=
          gpu::kGpuFeatureStatusEnabled;

  if (webgl_preferences.anti_aliasing_mode == kAntialiasingModeUnspecified) {
    if (use_multisampling) {
      anti_aliasing_mode_ = kAntialiasingModeMSAAExplicitResolve;
      if (supports_implicit_resolve) {
        anti_aliasing_mode_ = kAntialiasingModeMSAAImplicitResolve;
      }
    } else {
      anti_aliasing_mode_ = kAntialiasingModeNone;
    }
  } else {
    bool prefer_implicit_resolve = (webgl_preferences.anti_aliasing_mode ==
                                    kAntialiasingModeMSAAImplicitResolve);
    if (prefer_implicit_resolve && !supports_implicit_resolve) {
      DLOG(ERROR) << "Invalid anti-aliasing mode specified.";
      return false;
    }
    anti_aliasing_mode_ = webgl_preferences.anti_aliasing_mode;
  }

  sample_count_ = std::min(
      static_cast<int>(webgl_preferences.msaa_sample_count), max_sample_count);
  eqaa_storage_sample_count_ = webgl_preferences.eqaa_storage_sample_count;
  if (ContextProvider()->GetGpuFeatureInfo().IsWorkaroundEnabled(
          gpu::USE_EQAA_STORAGE_SAMPLES_2))
    eqaa_storage_sample_count_ = 2;
  if (extensions_util_->SupportsExtension(
          "GL_AMD_framebuffer_multisample_advanced"))
    has_eqaa_support = true;

  state_restorer_->SetFramebufferBindingDirty();
  gl_->GenFramebuffers(1, &fbo_);
  gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo_);
  if (opengl_flip_y_extension_)
    gl_->FramebufferParameteri(GL_FRAMEBUFFER, GL_FRAMEBUFFER_FLIP_Y_MESA, 1);

  if (WantExplicitResolve()) {
    gl_->GenFramebuffers(1, &multisample_fbo_);
    gl_->BindFramebuffer(GL_FRAMEBUFFER, multisample_fbo_);
    gl_->GenRenderbuffers(1, &multisample_renderbuffer_);
    if (opengl_flip_y_extension_)
      gl_->FramebufferParameteri(GL_FRAMEBUFFER, GL_FRAMEBUFFER_FLIP_Y_MESA, 1);
  }

  if (!ResizeFramebufferInternal(requested_format_, requested_alpha_type_,
                                 size)) {
    DLOG(ERROR) << "Initialization failed to allocate backbuffer of size "
                << size.width() << " x " << size.height() << ".";
    return false;
  }

  if (depth_stencil_buffer_) {
    DCHECK(WantDepthOrStencil());
    has_implicit_stencil_buffer_ = !want_stencil_;
  }

  if (gl_->GetGraphicsResetStatusKHR() != GL_NO_ERROR) {
    // It's possible that the drawing buffer allocation provokes a context loss,
    // so check again just in case. http://crbug.com/512302
    DLOG(ERROR) << "Context lost during initialization.";
    return false;
  }

  return true;
}

void DrawingBuffer::CopyStagingTextureToBackColorBufferIfNeeded() {
  if (!staging_texture_) {
    return;
  }

  // The rendering results are in `staging_texture_` rather than the
  // `back_color_buffer_`'s texture. Copy them over, doing any conversion
  // from the requested format to the SharedImage-supported format.
  const GLboolean do_flip_y = GL_FALSE;
  const GLboolean do_premultiply_alpha =
      back_color_buffer_->alpha_type == kPremul_SkAlphaType &&
      requested_alpha_type_ == kUnpremul_SkAlphaType;
  const GLboolean do_unpremultiply_alpha = GL_FALSE;
  gl_->CopySubTextureCHROMIUM(
      staging_texture_, 0, back_color_buffer_->shared_image->GetTextureTarget(),
      back_color_buffer_->texture_id(), 0, 0, 0, 0, 0, size_.width(),
      size_.height(), do_flip_y, do_premultiply_alpha, do_unpremultiply_alpha);
}

bool DrawingBuffer::CopyToPlatformInternal(gpu::InterfaceBase* dst_interface,
                                           bool dst_is_unpremul_gl,
                                           SourceDrawingBuffer src_buffer,
                                           CopyFunctionRef copy_function) {
  ScopedStateRestorer scoped_state_restorer(this);

  gpu::gles2::GLES2Interface* src_gl = gl_;

  if (contents_changed_) {
    ResolveIfNeeded(kDontDiscard);
    src_gl->Flush();
  }

  // Contexts may be in a different share group. We must transfer the texture
  // through a mailbox first.
  gpu::SyncToken produce_sync_token;
  bool need_restore_access = false;
  scoped_refptr<ColorBuffer> src_color_buffer;
  SkAlphaType src_alpha_type = kUnknown_SkAlphaType;
  if (src_buffer == kFrontBuffer && front_color_buffer_) {
    src_color_buffer = front_color_buffer_;
    src_alpha_type = src_color_buffer->alpha_type;
    produce_sync_token = src_color_buffer->produce_sync_token;
  } else {
    src_color_buffer = back_color_buffer_;
    src_alpha_type = src_color_buffer->alpha_type;
    need_restore_access = true;
    if (staging_texture_) {
      // The source for the copy must be a SharedImage that is accessible to
      // `dst_interface`. If the rendering results are in `staging_texture_`,
      // then they cannot be accessed by `dst_interface`. Copy the results
      // to `back_color_buffer`, without any (e.g alpha premultiplication)
      // conversion.
      if (dst_is_unpremul_gl) {
        // In this situation we are copying to another WebGL context that has
        // unpremultiplied alpha, and it is required that we do not lose the
        // precision that premultiplication would cause.
        const GLboolean do_flip_y = GL_FALSE;
        const GLboolean do_premultiply_alpha = GL_FALSE;
        const GLboolean do_unpremultiply_alpha = GL_FALSE;
        gl_->CopySubTextureCHROMIUM(
            staging_texture_, 0,
            back_color_buffer_->shared_image->GetTextureTarget(),
            back_color_buffer_->texture_id(), 0, 0, 0, 0, 0, size_.width(),
            size_.height(), do_flip_y, do_premultiply_alpha,
            do_unpremultiply_alpha);
        src_alpha_type = requested_alpha_type_;
      } else {
        CopyStagingTextureToBackColorBufferIfNeeded();
      }
    }
    produce_sync_token = back_color_buffer_->EndAccess();
  }

  if (!produce_sync_token.HasData()) {
    // This should only happen if the context has been lost.
    return false;
  }

  std::optional<gpu::SyncToken> sync_token =
      copy_function(src_color_buffer->shared_image, produce_sync_token,
                    src_alpha_type, src_color_buffer->size);

  if (need_restore_access) {
    src_color_buffer->BeginAccess(sync_token.value_or(gpu::SyncToken()),
                                  /*readonly=*/false);
  }
  return sync_token.has_value();
}

bool DrawingBuffer::CopyToPlatformTexture(gpu::gles2::GLES2Interface* dst_gl,
                                          GLenum dst_texture_target,
                                          GLuint dst_texture,
                                          GLint dst_level,
                                          bool premultiply_alpha,
                                          bool flip_y,
                                          const gfx::Point& dst_texture_offset,
                                          const gfx::Rect& src_sub_rectangle,
                                          SourceDrawingBuffer src_buffer) {
  if (!Extensions3DUtil::CanUseCopyTextureCHROMIUM(dst_texture_target))
    return false;

  auto copy_function =
      [&](scoped_refptr<gpu::ClientSharedImage> src_shared_image,
          const gpu::SyncToken& produce_sync_token, SkAlphaType src_alpha_type,
          const gfx::Size&) -> std::optional<gpu::SyncToken> {
    dst_gl->WaitSyncTokenCHROMIUM(produce_sync_token.GetConstData());

    GLboolean unpack_premultiply_alpha_needed = GL_FALSE;
    GLboolean unpack_unpremultiply_alpha_needed = GL_FALSE;
    if (src_alpha_type == kPremul_SkAlphaType && !premultiply_alpha) {
      unpack_unpremultiply_alpha_needed = GL_TRUE;
    } else if (src_alpha_type == kUnpremul_SkAlphaType && premultiply_alpha) {
      unpack_premultiply_alpha_needed = GL_TRUE;
    }

    auto src_si_texture = src_shared_image->CreateGLTexture(dst_gl);
    auto src_si_access =
        src_si_texture->BeginAccess(produce_sync_token, /*readonly=*/true);
    dst_gl->CopySubTextureCHROMIUM(
        src_si_access->texture_id(), 0, dst_texture_target, dst_texture,
        dst_level, dst_texture_offset.x(), dst_texture_offset.y(),
        src_sub_rectangle.x(), src_sub_rectangle.y(), src_sub_rectangle.width(),
        src_sub_rectangle.height(), flip_y, unpack_premultiply_alpha_needed,
        unpack_unpremultiply_alpha_needed);
    auto sync_token = gpu::SharedImageTexture::ScopedAccess::EndAccess(
        std::move(src_si_access));
    src_si_texture.reset();
    return sync_token;
  };
  return CopyToPlatformInternal(dst_gl, !premultiply_alpha, src_buffer,
                                copy_function);
}

bool DrawingBuffer::CopyToPlatformMailbox(
    gpu::raster::RasterInterface* dst_raster_interface,
    gpu::Mailbox dst_mailbox,
    const gfx::Point& dst_texture_offset,
    const gfx::Rect& src_sub_rectangle,
    SourceDrawingBuffer src_buffer) {
  auto copy_function =
      [&](scoped_refptr<gpu::ClientSharedImage> src_shared_image,
          const gpu::SyncToken& produce_sync_token, SkAlphaType src_alpha_type,
          const gfx::Size&) -> std::optional<gpu::SyncToken> {
    dst_raster_interface->WaitSyncTokenCHROMIUM(
        produce_sync_token.GetConstData());

    dst_raster_interface->CopySharedImage(
        src_shared_image->mailbox(), dst_mailbox, dst_texture_offset.x(),
        dst_texture_offset.y(), src_sub_rectangle.x(), src_sub_rectangle.y(),
        src_sub_rectangle.width(), src_sub_rectangle.height());

    gpu::SyncToken sync_token;
    dst_raster_interface->GenUnverifiedSyncTokenCHROMIUM(sync_token.GetData());
    return sync_token;
  };

  return CopyToPlatformInternal(dst_raster_interface,
                                /*dst_is_unpremul_gl=*/false, src_buffer,
                                copy_function);
}

bool DrawingBuffer::CopyToVideoFrame(
    WebGraphicsContext3DVideoFramePool* frame_pool,
    SourceDrawingBuffer src_buffer,
    const gfx::ColorSpace& dst_color_space,
    WebGraphicsContext3DVideoFramePool::FrameReadyCallback callback) {
  // Ensure that `frame_pool` has not experienced a context loss.
  // https://crbug.com/1269230
  auto* raster_interface = frame_pool->GetRasterInterface();
  if (!raster_interface)
    return false;
  auto copy_function =
      [&](scoped_refptr<gpu::ClientSharedImage> src_shared_image,
          const gpu::SyncToken& produce_sync_token, SkAlphaType src_alpha_type,
          const gfx::Size& src_size) -> std::optional<gpu::SyncToken> {
    raster_interface->WaitSyncTokenCHROMIUM(produce_sync_token.GetConstData());
    bool succeeded = frame_pool->CopyRGBATextureToVideoFrame(
        src_size, src_shared_image, gpu::SyncToken(), dst_color_space,
        std::move(callback));
    if (!succeeded) {
      return std::nullopt;
    }

    gpu::SyncToken sync_token;
    raster_interface->GenUnverifiedSyncTokenCHROMIUM(sync_token.GetData());
    return sync_token;
  };
  return CopyToPlatformInternal(raster_interface, /*dst_is_unpremul_gl=*/false,
                                src_buffer, copy_function);
}

cc::Layer* DrawingBuffer::CcLayer() {
  if (!layer_) {
    layer_ = cc::TextureLayer::CreateForMailbox(this);

    layer_->SetIsDrawable(true);
    layer_->SetHitTestable(true);
    layer_->SetContentsOpaque(requested_alpha_type_ == kOpaque_SkAlphaType);
    layer_->SetBlendBackgroundColor(requested_alpha_type_ !=
                                    kOpaque_SkAlphaType);
    if (staging_texture_) {
      // If staging_texture_ exists, then premultiplication
      // has already been handled via CopySubTextureCHROMIUM.
      DCHECK(requested_alpha_type_ == kUnpremul_SkAlphaType);
      layer_->SetPremultipliedAlpha(true);
    } else {
      layer_->SetPremultipliedAlpha(requested_alpha_type_ !=
                                    kUnpremul_SkAlphaType);
    }
    layer_->SetNearestNeighbor(filter_quality_ ==
                               cc::PaintFlags::FilterQuality::kNone);

    if (opengl_flip_y_extension_ && IsUsingGpuCompositing())
      layer_->SetFlipped(false);
  }

  return layer_.get();
}

void DrawingBuffer::ClearCcLayer() {
  if (layer_)
    layer_->ClearTexture();

  gl_->Flush();
}

void DrawingBuffer::BeginDestruction() {
  DCHECK(!destruction_in_progress_);
  destruction_in_progress_ = true;

  ClearCcLayer();
  recycled_color_buffer_queue_.clear();

  // If the drawing buffer is being destroyed due to a real context loss these
  // calls will be ineffective, but won't be harmful.
  if (multisample_fbo_)
    gl_->DeleteFramebuffers(1, &multisample_fbo_);

  if (fbo_)
    gl_->DeleteFramebuffers(1, &fbo_);

  if (multisample_renderbuffer_)
    gl_->DeleteRenderbuffers(1, &multisample_renderbuffer_);

  if (depth_stencil_buffer_)
    gl_->DeleteRenderbuffers(1, &depth_stencil_buffer_);

  if (staging_texture_) {
    gl_->DeleteTextures(1, &staging_texture_);
    staging_texture_ = 0;
  }

  size_ = gfx::Size();

  back_color_buffer_ = nullptr;
  front_color_buffer_ = nullptr;
  multisample_renderbuffer_ = 0;
  depth_stencil_buffer_ = 0;
  multisample_fbo_ = 0;
  fbo_ = 0;

  client_ = nullptr;
}

bool DrawingBuffer::ReallocateDefaultFramebuffer(const gfx::Size& size,
                                                 bool only_reallocate_color) {
  DCHECK(state_restorer_);
  // Recreate back_color_buffer_.
  back_color_buffer_ = CreateColorBuffer(size);

  if (staging_texture_) {
    state_restorer_->SetTextureBindingDirty();
    gl_->DeleteTextures(1, &staging_texture_);
    staging_texture_ = 0;
  }
  if (staging_texture_needed_) {
    state_restorer_->SetTextureBindingDirty();
    gl_->GenTextures(1, &staging_texture_);
    gl_->BindTexture(GL_TEXTURE_2D, staging_texture_);
    GLenum internal_format = requested_format_;

    // TexStorage is not core in GLES2 (webgl1) and enabling (or emulating) it
    // universally can cause issues with BGRA formats.
    // See: crbug.com/1443160#c38
    bool use_tex_image =
        !texture_storage_enabled_ &&
        base::FeatureList::IsEnabled(
            features::kUseImageInsteadOfStorageForStagingBuffer);
    if (webgl_version_ == kWebGL1 && requested_format_ == GL_SRGB8_ALPHA8) {
      // On GLES2:
      //   * SRGB_ALPHA_EXT is not a valid internal format for TexStorage2DEXT.
      //   * SRGB8_ALPHA8 is not a renderable texture internal format.
      // Just use TexImage2D instead of TexStorage2DEXT.
      use_tex_image = true;
    }
    if (use_tex_image) {
      switch (requested_format_) {
        case GL_RGB8:
          internal_format = color_buffer_format_.HasAlpha() ? GL_RGBA : GL_RGB;
          break;
        case GL_SRGB8_ALPHA8:
          internal_format = GL_SRGB_ALPHA_EXT;
          break;
        case GL_RGBA8:
        case GL_RGBA16F:
          internal_format = GL_RGBA;
          break;
        default:
          NOTREACHED();
      }

      gl_->TexImage2D(GL_TEXTURE_2D, 0, internal_format, size.width(),
                      size.height(), 0, internal_format,
                      requested_format_ == GL_RGBA16F ? GL_HALF_FLOAT_OES
                                                      : GL_UNSIGNED_BYTE,
                      nullptr);
    } else {
      if (requested_format_ == GL_RGB8) {
        internal_format = color_buffer_format_.HasAlpha() ? GL_RGBA8 : GL_RGB8;
      }
      gl_->TexStorage2DEXT(GL_TEXTURE_2D, 1, internal_format, size.width(),
                           size.height());
    }
  }

  AttachColorBufferToReadFramebuffer();

  if (WantExplicitResolve()) {
    if (!ReallocateMultisampleRenderbuffer(size)) {
      return false;
    }
  }

  if (WantDepthOrStencil() && !only_reallocate_color) {
    state_restorer_->SetFramebufferBindingDirty();
    state_restorer_->SetRenderbufferBindingDirty();
    gl_->BindFramebuffer(GL_FRAMEBUFFER,
                         multisample_fbo_ ? multisample_fbo_ : fbo_);
    if (!depth_stencil_buffer_)
      gl_->GenRenderbuffers(1, &depth_stencil_buffer_);
    gl_->BindRenderbuffer(GL_RENDERBUFFER, depth_stencil_buffer_);
    if (anti_aliasing_mode_ == kAntialiasingModeMSAAImplicitResolve) {
      gl_->RenderbufferStorageMultisampleEXT(GL_RENDERBUFFER, sample_count_,
                                             GL_DEPTH24_STENCIL8_OES,
                                             size.width(), size.height());
    } else if (anti_aliasing_mode_ == kAntialiasingModeMSAAExplicitResolve) {
      gl_->RenderbufferStorageMultisampleCHROMIUM(
          GL_RENDERBUFFER, sample_count_, GL_DEPTH24_STENCIL8_OES, size.width(),
          size.height());
    } else {
      gl_->RenderbufferStorage(GL_RENDERBUFFER, GL_DEPTH24_STENCIL8_OES,
                               size.width(), size.height());
    }
    // For ES 2.0 contexts DEPTH_STENCIL is not available natively, so we
    // emulate
    // it at the command buffer level for WebGL contexts.
    gl_->FramebufferRenderbuffer(GL_FRAMEBUFFER, GL_DEPTH_STENCIL_ATTACHMENT,
                                 GL_RENDERBUFFER, depth_stencil_buffer_);
    gl_->BindRenderbuffer(GL_RENDERBUFFER, 0);
  }

  if (WantExplicitResolve()) {
    state_restorer_->SetFramebufferBindingDirty();
    gl_->BindFramebuffer(GL_FRAMEBUFFER, multisample_fbo_);
    if (gl_->CheckFramebufferStatus(GL_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE)
      return false;
  }

  state_restorer_->SetFramebufferBindingDirty();
  gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo_);
  return gl_->CheckFramebufferStatus(GL_FRAMEBUFFER) == GL_FRAMEBUFFER_COMPLETE;
}

void DrawingBuffer::ClearFramebuffers(GLbitfield clear_mask) {
  ScopedStateRestorer scoped_state_restorer(this);
  ClearFramebuffersInternal(clear_mask, kClearAllFBOs);
}

void DrawingBuffer::ClearFramebuffersInternal(GLbitfield clear_mask,
                                              ClearOption clear_option) {
  DCHECK(state_restorer_);
  state_restorer_->SetFramebufferBindingDirty();

  GLenum prev_draw_buffer =
      draw_buffer_ == GL_BACK ? GL_COLOR_ATTACHMENT0 : draw_buffer_;

  // Clear the multisample FBO, but also clear the non-multisampled buffer if
  // requested.
  if (multisample_fbo_ && clear_option == kClearAllFBOs) {
    gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo_);
    ScopedDrawBuffer scoped_draw_buffer(gl_, prev_draw_buffer,
                                        GL_COLOR_ATTACHMENT0);
    gl_->Clear(GL_COLOR_BUFFER_BIT);
  }

  if (multisample_fbo_ || clear_option == kClearAllFBOs) {
    gl_->BindFramebuffer(GL_FRAMEBUFFER,
                         multisample_fbo_ ? multisample_fbo_ : fbo_);
    ScopedDrawBuffer scoped_draw_buffer(gl_, prev_draw_buffer,
                                        GL_COLOR_ATTACHMENT0);
    gl_->Clear(clear_mask);
  }
}

void DrawingBuffer::ClearNewlyAllocatedFramebuffers(ClearOption clear_option) {
  DCHECK(state_restorer_);

  state_restorer_->SetClearStateDirty();
  gl_->Disable(GL_SCISSOR_TEST);
  gl_->ClearColor(0, 0, 0,
                  DefaultBufferRequiresAlphaChannelToBePreserved() ? 1 : 0);
  gl_->ColorMask(true, true, true, true);

  GLbitfield clear_mask = GL_COLOR_BUFFER_BIT;
  if (!!depth_stencil_buffer_) {
    gl_->ClearDepthf(1.0f);
    clear_mask |= GL_DEPTH_BUFFER_BIT;
    gl_->DepthMask(true);
  }
  if (!!depth_stencil_buffer_) {
    gl_->ClearStencil(0);
    clear_mask |= GL_STENCIL_BUFFER_BIT;
    gl_->StencilMaskSeparate(GL_FRONT, 0xFFFFFFFF);
  }

  ClearFramebuffersInternal(clear_mask, clear_option);
}

gfx::Size DrawingBuffer::AdjustSize(const gfx::Size& desired_size,
                                    const gfx::Size& cur_size,
                                    int max_texture_size) {
  gfx::Size adjusted_size = desired_size;

  // Clamp if the desired size is greater than the maximum texture size for the
  // device.
  if (adjusted_size.height() > max_texture_size)
    adjusted_size.set_height(max_texture_size);

  if (adjusted_size.width() > max_texture_size)
    adjusted_size.set_width(max_texture_size);

  return adjusted_size;
}

bool DrawingBuffer::Resize(const gfx::Size& new_size) {
  ScopedStateRestorer scoped_state_restorer(this);
  return ResizeFramebufferInternal(requested_format_, requested_alpha_type_,
                                   new_size);
}

bool DrawingBuffer::ResizeWithFormat(GLenum requested_format,
                                     SkAlphaType requested_alpha_type,
                                     const gfx::Size& new_size) {
  ScopedStateRestorer scoped_state_restorer(this);
  return ResizeFramebufferInternal(requested_format, requested_alpha_type,
                                   new_size);
}

bool DrawingBuffer::ResizeFramebufferInternal(GLenum requested_format,
                                              SkAlphaType requested_alpha_type,
                                              const gfx::Size& new_size) {
  DCHECK(state_restorer_);
  DCHECK(!new_size.IsEmpty());
  bool needs_reallocate = false;

  gfx::Size adjusted_size = AdjustSize(new_size, size_, max_texture_size_);
  if (adjusted_size.IsEmpty()) {
    return false;
  }
  needs_reallocate |= adjusted_size != size_;

  // Initialize the alpha allocation settings based on the features and
  // workarounds in use.
  needs_reallocate |= requested_format_ != requested_format;
  requested_format_ = requested_format;
  switch (requested_format_) {
    case GL_RGB8:
      color_buffer_format_ = viz::SinglePlaneFormat::kRGBX_8888;
      // The following workarounds are used in order of importance; the
      // first is a correctness issue, the second a major performance
      // issue, and the third a minor performance issue.
      if (ContextProvider()->GetGpuFeatureInfo().IsWorkaroundEnabled(
              gpu::DISABLE_GL_RGB_FORMAT)) {
        // This configuration will
        //  - allow invalid CopyTexImage to RGBA targets
        //  - fail valid FramebufferBlit from RGB targets
        // https://crbug.com/776269
        color_buffer_format_ = viz::SinglePlaneFormat::kRGBA_8888;
      } else if (WantExplicitResolve() &&
                 ContextProvider()->GetGpuFeatureInfo().IsWorkaroundEnabled(
                     gpu::DISABLE_WEBGL_RGB_MULTISAMPLING_USAGE)) {
        // This configuration avoids the above issues because
        //  - CopyTexImage is invalid from multisample renderbuffers
        //  - FramebufferBlit is invalid to multisample renderbuffers
        color_buffer_format_ = viz::SinglePlaneFormat::kRGBA_8888;
      }
      break;
    case GL_RGBA8:
    case GL_SRGB8_ALPHA8:
      color_buffer_format_ = viz::SinglePlaneFormat::kRGBA_8888;
      break;
    case GL_RGBA16F:
      color_buffer_format_ = viz::SinglePlaneFormat::kRGBA_F16;
      break;
    default:
      NOTREACHED();
  }
  needs_reallocate |= requested_alpha_type_ != requested_alpha_type;
  requested_alpha_type_ = requested_alpha_type;

  if (needs_reallocate) {
    do {
      if (!ReallocateDefaultFramebuffer(adjusted_size,
                                        /*only_reallocate_color=*/false)) {
        adjusted_size =
            gfx::ScaleToFlooredSize(adjusted_size, kResourceAdjustedRatio);
        continue;
      }
      break;
    } while (!adjusted_size.IsEmpty());

    size_ = adjusted_size;
    // Free all mailboxes, because they are now of the wrong size. Only the
    // first call in this loop has any effect.
    recycled_color_buffer_queue_.clear();
    recycled_bitmaps_.clear();

    if (adjusted_size.IsEmpty())
      return false;
  }

  ClearNewlyAllocatedFramebuffers(kClearAllFBOs);
  return true;
}

void DrawingBuffer::SetColorSpace(PredefinedColorSpace predefined_color_space) {
  // Color space changes that are no-ops should not reach this point.
  const gfx::ColorSpace color_space =
      PredefinedColorSpaceToGfxColorSpace(predefined_color_space);
  DCHECK_NE(color_space, color_space_);
  color_space_ = color_space;

  ScopedStateRestorer scoped_state_restorer(this);

  // Free all mailboxes, because they are now of the wrong color space.
  recycled_color_buffer_queue_.clear();
  recycled_bitmaps_.clear();

  if (!ReallocateDefaultFramebuffer(size_, /*only_reallocate_color=*/true)) {
    // TODO(https://crbug.com/1208480): What is the correct behavior is we fail
    // to re-allocate the buffer.
    DLOG(ERROR) << "Failed to allocate color buffer with new color space.";
  }

  ClearNewlyAllocatedFramebuffers(kClearAllFBOs);
}

bool DrawingBuffer::ResolveAndBindForReadAndDraw() {
  {
    ScopedStateRestorer scoped_state_restorer(this);
    ResolveIfNeeded(kDontDiscard);
    // Note that in rare situations on macOS the drawing buffer can be
    // destroyed during the resolve process, specifically during
    // automatic graphics switching. Guard against this.
    if (destruction_in_progress_)
      return false;
  }
  gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo_);
  return true;
}

void DrawingBuffer::ResolveMultisampleFramebufferInternal() {
  DCHECK(state_restorer_);
  state_restorer_->SetFramebufferBindingDirty();
  if (WantExplicitResolve()) {
    state_restorer_->SetClearStateDirty();
    gl_->BindFramebuffer(GL_READ_FRAMEBUFFER_ANGLE, multisample_fbo_);
    gl_->BindFramebuffer(GL_DRAW_FRAMEBUFFER_ANGLE, fbo_);
    gl_->Disable(GL_SCISSOR_TEST);

    int width = size_.width();
    int height = size_.height();
    // Use NEAREST, because there is no scale performed during the blit.
    GLuint filter = GL_NEAREST;

    gl_->BlitFramebufferCHROMIUM(0, 0, width, height, 0, 0, width, height,
                                 GL_COLOR_BUFFER_BIT, filter);

    // On old AMD GPUs on OS X, glColorMask doesn't work correctly for
    // multisampled renderbuffers and the alpha channel can be overwritten.
    // Clear the alpha channel of |m_fbo|.
    if (DefaultBufferRequiresAlphaChannelToBePreserved() &&
        ContextProvider()->GetGpuFeatureInfo().IsWorkaroundEnabled(
            gpu::DISABLE_MULTISAMPLING_COLOR_MASK_USAGE)) {
      gl_->ClearColor(0, 0, 0, 1);
      gl_->ColorMask(false, false, false, true);
      gl_->Clear(GL_COLOR_BUFFER_BIT);
    }
  }

  gl_->BindFramebuffer(GL_FRAMEBUFFER, fbo_);
}

void DrawingBuffer::ResolveIfNeeded(DiscardBehavior discardBehavior) {
  DCHECK(state_restorer_);
  if (anti_aliasing_mode_ != kAntialiasingModeNone) {
    if (preserve_drawing_buffer_ == kDiscard &&
        discard_framebuffer_supported_ && discardBehavior == kDiscardAllowed &&
        !transient_framebuffers_discarded_) {
      // Discard the depth and stencil buffers as early as possible, before
      // making any potentially-unneeded calls to BindFramebuffer (even no-ops),
      // in order to maximize the chances that their storage can be kept in tile
      // memory.
      const GLenum kAttachments[2] = {GL_DEPTH_ATTACHMENT,
                                      GL_STENCIL_ATTACHMENT};

"""


```