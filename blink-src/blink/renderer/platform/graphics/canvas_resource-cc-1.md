Response:
The user wants a summary of the functionality of the `canvas_resource.cc` file in the Chromium Blink engine. They also want to know how it relates to JavaScript, HTML, and CSS, including examples. I also need to consider logical inferences and common usage errors.

**Plan:**

1. **Identify the core classes:** The file defines `ExternalCanvasResource` and `CanvasResourceSwapChain`.
2. **Summarize the purpose of each class:**
    *   `ExternalCanvasResource`: Represents a canvas resource backed by a GPU shared image, likely coming from an external source.
    *   `CanvasResourceSwapChain`: Represents a double-buffered canvas resource for rendering.
3. **Analyze key methods:**  Focus on methods like `Create`, `Bitmap`, `GetSyncTokenWithOptionalVerification`, `PresentSwapChain`, and the destructors.
4. **Relate to web technologies:** Explain how these resources are used in the context of `<canvas>` elements, WebGL, and potentially CSS (for rendering and compositing).
5. **Provide examples:** Create hypothetical scenarios illustrating the interaction with JavaScript, HTML, and CSS.
6. **Consider logical inferences:** Think about the flow of data and synchronization between different components.
7. **Address common errors:**  Identify potential pitfalls in using these resources, especially related to thread safety and context management.
```cpp
scoped_refptr<CanvasResourceSwapChain> CanvasResourceSwapChain::Create(
    gfx::Size size,
    SkColorType sk_color_type,
    SkAlphaType sk_alpha_type,
    sk_sp<SkColorSpace> sk_color_space,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality) {
  TRACE_EVENT0("blink", "CanvasResourceSwapChain::Create");
  auto resource = AdoptRef(new CanvasResourceSwapChain(
      size, sk_color_type, sk_alpha_type, std::move(sk_color_space),
      std::move(context_provider_wrapper), std::move(provider),
      filter_quality));
  return resource->IsValid() ? resource : nullptr;
}

CanvasResourceSwapChain::~CanvasResourceSwapChain() {
  if (is_cross_thread()) {
    // Destroyed on wrong thread. This can happen when the thread of origin was
    // torn down, in which case the GPU context owning any underlying resources
    // no longer exists and it is not possible to do cleanup of any GPU
    // context-associated state.
    return;
  }

  if (Provider()) {
    Provider()->OnDestroyResource();
  }

  // The context deletes all shared images on destruction which means no
  // cleanup is needed if the context was lost.
  if (!context_provider_wrapper_) {
    return;
  }

  if (!use_oop_rasterization_) {
    auto* raster_interface =
        context_provider_wrapper_->ContextProvider()->RasterInterface();
    DCHECK(raster_interface);
    raster_interface->EndSharedImageAccessDirectCHROMIUM(
        back_buffer_texture_id_);
    raster_interface->DeleteGpuRasterTexture(back_buffer_texture_id_);
  }

  // No synchronization is needed here because the GL SharedImageRepresentation
  // will keep the backing alive on the service until the textures are deleted.
  front_buffer_shared_image_->UpdateDestructionSyncToken(gpu::SyncToken());
  back_buffer_shared_image_->UpdateDestructionSyncToken(gpu::SyncToken());
}

bool CanvasResourceSwapChain::IsValid() const {
  return !!context_provider_wrapper_;
}

scoped_refptr<StaticBitmapImage> CanvasResourceSwapChain::Bitmap() {
  SkImageInfo image_info = CreateSkImageInfo();

  // It's safe to share the back buffer texture id if we're on the same thread
  // since the |release_callback| ensures this resource will be alive.
  GLuint shared_texture_id = !is_cross_thread() ? back_buffer_texture_id_ : 0u;

  // The |release_callback| keeps a ref on this resource to ensure the backing
  // shared image is kept alive until the lifetime of the image.
  auto release_callback = base::BindOnce(
      [](scoped_refptr<CanvasResourceSwapChain>, const gpu::SyncToken&, bool) {
        // Do nothing but hold onto the refptr.
      },
      base::RetainedRef(this));

  return AcceleratedStaticBitmapImage::CreateFromCanvasSharedImage(
      back_buffer_shared_image_, GetSyncToken(), shared_texture_id, image_info,
      back_buffer_shared_image_->GetTextureTarget(),
      true /*is_origin_top_left*/, context_provider_wrapper_,
      owning_thread_ref_, owning_thread_task_runner_,
      std::move(release_callback), /*supports_display_compositing=*/true,
      /*is_overlay_candidate=*/true);
}

scoped_refptr<gpu::ClientSharedImage>
CanvasResourceSwapChain::GetClientSharedImage() {
  return front_buffer_shared_image_;
}

const gpu::SyncToken
CanvasResourceSwapChain::GetSyncTokenWithOptionalVerification(
    bool needs_verified_token) {
  DCHECK(sync_token_.verified_flush());
  return sync_token_;
}

void CanvasResourceSwapChain::PresentSwapChain() {
  DCHECK(!is_cross_thread());
  DCHECK(context_provider_wrapper_);
  TRACE_EVENT0("blink", "CanvasResourceSwapChain::PresentSwapChain");

  auto* raster_interface =
      context_provider_wrapper_->ContextProvider()->RasterInterface();
  DCHECK(raster_interface);

  auto* sii =
      context_provider_wrapper_->ContextProvider()->SharedImageInterface();
  DCHECK(sii);

  // Synchronize presentation and rendering.
  raster_interface->GenUnverifiedSyncTokenCHROMIUM(sync_token_.GetData());
  sii->PresentSwapChain(sync_token_, back_buffer_shared_image_->mailbox());
  // This only gets called via the CanvasResourceDispatcher export path so a
  // verified sync token will be needed ultimately.
  sync_token_ = sii->GenVerifiedSyncToken();
  raster_interface->WaitSyncTokenCHROMIUM(sync_token_.GetData());

  // Relinquish shared image access before copy when using legacy GL raster.
  if (!use_oop_rasterization_) {
    raster_interface->EndSharedImageAccessDirectCHROMIUM(
        back_buffer_texture_id_);
  }
  // PresentSwapChain() flips the front and back buffers, but the mailboxes
  // still refer to the current front and back buffer after present. So the
  // front buffer contains the content we just rendered, and it needs to be
  // copied into the back buffer to support a retained mode like canvas expects.
  // The wait sync token ensure that the present executes before we do the copy.
  // Don't generate sync token after the copy so that it's not on critical path.
  raster_interface->CopySharedImage(front_buffer_shared_image_->mailbox(),
                                    back_buffer_shared_image_->mailbox(), 0, 0,
                                    0, 0, Size().width(), Size().height());
  // Restore shared image access after copy when using legacy GL raster.
  if (!use_oop_rasterization_) {
    raster_interface->BeginSharedImageAccessDirectCHROMIUM(
        back_buffer_texture_id_,
        GL_SHARED_IMAGE_ACCESS_MODE_READWRITE_CHROMIUM);
  }
}

base::WeakPtr<WebGraphicsContext3DProviderWrapper>
CanvasResourceSwapChain::ContextProviderWrapper() const {
  return context_provider_wrapper_;
}

CanvasResourceSwapChain::CanvasResourceSwapChain(
    gfx::Size size,
    SkColorType sk_color_type,
    SkAlphaType sk_alpha_type,
    sk_sp<SkColorSpace> sk_color_space,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality)
    : CanvasResource(
          std::move(provider),
          filter_quality,
          size,
          viz::SkColorTypeToSinglePlaneSharedImageFormat(sk_color_type),
          sk_alpha_type,
          std::move(sk_color_space)),
      context_provider_wrapper_(std::move(context_provider_wrapper)),
      use_oop_rasterization_(context_provider_wrapper_->ContextProvider()
                                 ->GetCapabilities()
                                 .gpu_rasterization) {
  if (!context_provider_wrapper_)
    return;

  // These SharedImages are both read and written by the raster interface (both
  // occur, for example, when copying canvas resources between canvases).
  // Additionally, these SharedImages can be put into
  // AcceleratedStaticBitmapImages (via Bitmap()) that are then copied into GL
  // textures by WebGL (via AcceleratedStaticBitmapImage::CopyToTexture()).
  // Hence, GLES2_READ usage is necessary regardless of whether raster is over
  // GLES.
  gpu::SharedImageUsageSet usage = gpu::SHARED_IMAGE_USAGE_DISPLAY_READ |
                                   gpu::SHARED_IMAGE_USAGE_GLES2_READ |
                                   gpu::SHARED_IMAGE_USAGE_SCANOUT |
                                   gpu::SHARED_IMAGE_USAGE_RASTER_READ |
                                   gpu::SHARED_IMAGE_USAGE_RASTER_WRITE;
  if (use_oop_rasterization_) {
    usage = usage | gpu::SHARED_IMAGE_USAGE_OOP_RASTERIZATION;
  } else {
    // The GLES2_WRITE flag is needed due to raster being over GL.
    usage = usage | gpu::SHARED_IMAGE_USAGE_GLES2_WRITE;
  }

  auto* sii =
      context_provider_wrapper_->ContextProvider()->SharedImageInterface();
  DCHECK(sii);
  gpu::SharedImageInterface::SwapChainSharedImages shared_images =
      sii->CreateSwapChain(GetSharedImageFormat(), Size(), GetColorSpace(),
                           kTopLeft_GrSurfaceOrigin, kPremul_SkAlphaType,
                           usage);
  CHECK(shared_images.back_buffer);
  CHECK(shared_images.front_buffer);
  back_buffer_shared_image_ = std::move(shared_images.back_buffer);
  front_buffer_shared_image_ = std::move(shared_images.front_buffer);
  sync_token_ = sii->GenVerifiedSyncToken();

  // Wait for the mailboxes to be ready to be used.
  auto* raster_interface =
      context_provider_wrapper_->ContextProvider()->RasterInterface();
  DCHECK(raster_interface);
  raster_interface->WaitSyncTokenCHROMIUM(sync_token_.GetData());

  // In OOPR mode we use mailboxes directly. We early out here because
  // we don't need a texture id, as access is managed in the gpu process.
  if (use_oop_rasterization_)
    return;

  back_buffer_texture_id_ = raster_interface->CreateAndConsumeForGpuRaster(
      back_buffer_shared_image_->mailbox());
  raster_interface->BeginSharedImageAccessDirectCHROMIUM(
      back_buffer_texture_id_, GL_SHARED_IMAGE_ACCESS_MODE_READWRITE_CHROMIUM);
}

}  // namespace blink
```

这是 `blink/renderer/platform/graphics/canvas_resource.cc` 文件的第二部分，主要定义了 `CanvasResourceSwapChain` 类及其相关功能。

**`CanvasResourceSwapChain` 的功能归纳:**

`CanvasResourceSwapChain` 类是用来管理用于 canvas 渲染的**双缓冲资源**。它负责创建、维护和呈现用于在 `<canvas>` 元素上绘制内容的 GPU 资源。 核心功能包括：

1. **创建双缓冲共享图像:**  通过 `Create` 方法，它创建一对 `gpu::ClientSharedImage` 对象，分别作为前缓冲区和后缓冲区。这允许在后台缓冲区进行渲染，完成后再切换到前缓冲区显示，避免画面撕裂。
2. **管理 GPU 资源生命周期:** 构造函数负责分配 GPU 资源，析构函数 `~CanvasResourceSwapChain` 负责清理这些资源，包括在跨线程销毁时进行特殊处理，以及在非 OOP-Rasterization 模式下释放纹理 ID。
3. **提供位图访问:** `Bitmap()` 方法返回一个 `StaticBitmapImage` 对象，允许将 canvas 的内容作为位图使用，例如用于绘制到其他 canvas 或进行图像处理。
4. **获取共享图像:** `GetClientSharedImage()` 方法返回底层的 `gpu::ClientSharedImage` 对象，这在某些高级场景下可能需要直接访问。
5. **同步管理:** 通过 `GetSyncTokenWithOptionalVerification()` 方法获取 GPU 同步令牌，用于确保渲染操作的顺序和完成。
6. **呈现交换链:** `PresentSwapChain()` 方法执行关键的双缓冲切换操作。它将后缓冲区的内容显示到屏幕上，并执行必要的同步和缓冲区拷贝操作，以支持 canvas 的保留模式。 该方法还会根据是否使用 OOP-Rasterization (Out-of-Process Rasterization) 来执行不同的 GPU 指令。
7. **上下文管理:**  持有 `WebGraphicsContext3DProviderWrapper` 的弱引用，用于访问 GPU 上下文和相关接口。
8. **支持 OOP-Rasterization:** 根据 GPU 的能力，该类可以工作在 OOP-Rasterization 模式下，利用 GPU 进程进行栅格化，提高性能。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`CanvasResourceSwapChain` 的功能直接支撑了 HTML `<canvas>` 元素的渲染。

*   **HTML (`<canvas>`)**:  当 JavaScript 代码在 `<canvas>` 元素上进行绘制操作时（例如使用 `2D` 上下文的 `fillRect()`, `drawImage()` 或 `WebGL` 上下文的渲染调用），Blink 引擎会使用 `CanvasResourceSwapChain` 来管理用于存储这些绘制结果的 GPU 资源。
    *   **例子:**
        ```html
        <canvas id="myCanvas" width="200" height="1
Prompt: 
```
这是目录为blink/renderer/platform/graphics/canvas_resource.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
sResource> ExternalCanvasResource::Create(
    scoped_refptr<gpu::ClientSharedImage> client_si,
    const viz::TransferableResource& transferable_resource,
    viz::ReleaseCallback release_callback,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality) {
  TRACE_EVENT0("blink", "ExternalCanvasResource::Create");
  CHECK(client_si);
  CHECK(client_si->mailbox() == transferable_resource.mailbox());
  auto resource = AdoptRef(new ExternalCanvasResource(
      std::move(client_si), transferable_resource, std::move(release_callback),
      std::move(context_provider_wrapper), std::move(provider),
      filter_quality));
  return resource->IsValid() ? resource : nullptr;
}

ExternalCanvasResource::~ExternalCanvasResource() {
  if (is_cross_thread()) {
    // Destroyed on wrong thread. This can happen when the thread of origin was
    // torn down, in which case the GPU context owning any underlying resources
    // no longer exists and it is not possible to do cleanup of any GPU
    // context-associated state.
    return;
  }

  if (Provider()) {
    Provider()->OnDestroyResource();
  }

  if (release_callback_) {
    std::move(release_callback_).Run(GetSyncToken(), resource_is_lost_);
  }
}

bool ExternalCanvasResource::IsValid() const {
  // On same thread we need to make sure context was not dropped, but
  // in the cross-thread case, checking a WeakPtr in not thread safe, not
  // to mention that we will use a shared context rather than the context
  // of origin to access the resource. In that case we will find out
  // whether the resource was dropped later, when we attempt to access the
  // mailbox.
  return is_cross_thread() || context_provider_wrapper_;
}

scoped_refptr<StaticBitmapImage> ExternalCanvasResource::Bitmap() {
  TRACE_EVENT0("blink", "ExternalCanvasResource::Bitmap");
  if (!IsValid())
    return nullptr;

  // The |release_callback| keeps a ref on this resource to ensure the backing
  // shared image is kept alive until the lifetime of the image.
  auto release_callback = base::BindOnce(
      [](scoped_refptr<ExternalCanvasResource> resource,
         const gpu::SyncToken& sync_token, bool is_lost) {
        // Do nothing but hold onto the refptr.
      },
      base::RetainedRef(this));

  const bool is_origin_top_left =
      client_si_->surface_origin() == kTopLeft_GrSurfaceOrigin;
  return AcceleratedStaticBitmapImage::CreateFromCanvasSharedImage(
      client_si_, GetSyncToken(), /*shared_image_texture_id=*/0u,
      CreateSkImageInfo(), transferable_resource_.texture_target(),
      is_origin_top_left, context_provider_wrapper_, owning_thread_ref_,
      owning_thread_task_runner_, std::move(release_callback),
      /*supports_display_compositing=*/true,
      transferable_resource_.is_overlay_candidate);
}

const gpu::SyncToken
ExternalCanvasResource::GetSyncTokenWithOptionalVerification(
    bool needs_verified_token) {
  GenOrFlushSyncToken();
  return transferable_resource_.sync_token();
}

void ExternalCanvasResource::GenOrFlushSyncToken() {
  TRACE_EVENT0("blink", "ExternalCanvasResource::GenOrFlushSyncToken");
  auto& sync_token = transferable_resource_.mutable_sync_token();
  // This method is expected to be used both in WebGL and WebGPU, that's why it
  // uses InterfaceBase.
  if (!sync_token.HasData()) {
    auto* interface = InterfaceBase();
    if (interface)
      interface->GenSyncTokenCHROMIUM(sync_token.GetData());
  } else if (!sync_token.verified_flush()) {
    // The offscreencanvas usage needs the sync_token to be verified in order to
    // be able to use it by the compositor.
    int8_t* token_data = sync_token.GetData();
    auto* interface = InterfaceBase();
    DCHECK(interface);
    interface->ShallowFlushCHROMIUM();
    interface->VerifySyncTokensCHROMIUM(&token_data, 1);
    sync_token.SetVerifyFlush();
  }
}

base::WeakPtr<WebGraphicsContext3DProviderWrapper>
ExternalCanvasResource::ContextProviderWrapper() const {
  // The context provider is not thread-safe, nor is the WeakPtr that holds it.
  DCHECK(!is_cross_thread());
  return context_provider_wrapper_;
}

bool ExternalCanvasResource::
    PrepareAcceleratedTransferableResourceWithoutClientSI(
        viz::TransferableResource* out_resource) {
  TRACE_EVENT0(
      "blink",
      "ExternalCanvasResource::PrepareAcceleratedTransferableResource");
  GenOrFlushSyncToken();
  *out_resource = transferable_resource_;
  return true;
}

ExternalCanvasResource::ExternalCanvasResource(
    scoped_refptr<gpu::ClientSharedImage> client_si,
    const viz::TransferableResource& transferable_resource,
    viz::ReleaseCallback out_callback,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality)
    : CanvasResource(std::move(provider),
                     filter_quality,
                     transferable_resource.size,
                     transferable_resource.format,
                     kPremul_SkAlphaType,
                     transferable_resource.color_space.ToSkColorSpace()),
      client_si_(std::move(client_si)),
      context_provider_wrapper_(std::move(context_provider_wrapper)),
      transferable_resource_(transferable_resource),
      release_callback_(std::move(out_callback)) {
  CHECK(client_si_);
  CHECK(client_si_->mailbox() == transferable_resource_.mailbox());
  DCHECK(!release_callback_ || transferable_resource_.sync_token().HasData());
}

// CanvasResourceSwapChain
//==============================================================================
scoped_refptr<CanvasResourceSwapChain> CanvasResourceSwapChain::Create(
    gfx::Size size,
    SkColorType sk_color_type,
    SkAlphaType sk_alpha_type,
    sk_sp<SkColorSpace> sk_color_space,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality) {
  TRACE_EVENT0("blink", "CanvasResourceSwapChain::Create");
  auto resource = AdoptRef(new CanvasResourceSwapChain(
      size, sk_color_type, sk_alpha_type, std::move(sk_color_space),
      std::move(context_provider_wrapper), std::move(provider),
      filter_quality));
  return resource->IsValid() ? resource : nullptr;
}

CanvasResourceSwapChain::~CanvasResourceSwapChain() {
  if (is_cross_thread()) {
    // Destroyed on wrong thread. This can happen when the thread of origin was
    // torn down, in which case the GPU context owning any underlying resources
    // no longer exists and it is not possible to do cleanup of any GPU
    // context-associated state.
    return;
  }

  if (Provider()) {
    Provider()->OnDestroyResource();
  }

  // The context deletes all shared images on destruction which means no
  // cleanup is needed if the context was lost.
  if (!context_provider_wrapper_) {
    return;
  }

  if (!use_oop_rasterization_) {
    auto* raster_interface =
        context_provider_wrapper_->ContextProvider()->RasterInterface();
    DCHECK(raster_interface);
    raster_interface->EndSharedImageAccessDirectCHROMIUM(
        back_buffer_texture_id_);
    raster_interface->DeleteGpuRasterTexture(back_buffer_texture_id_);
  }

  // No synchronization is needed here because the GL SharedImageRepresentation
  // will keep the backing alive on the service until the textures are deleted.
  front_buffer_shared_image_->UpdateDestructionSyncToken(gpu::SyncToken());
  back_buffer_shared_image_->UpdateDestructionSyncToken(gpu::SyncToken());
}

bool CanvasResourceSwapChain::IsValid() const {
  return !!context_provider_wrapper_;
}

scoped_refptr<StaticBitmapImage> CanvasResourceSwapChain::Bitmap() {
  SkImageInfo image_info = CreateSkImageInfo();

  // It's safe to share the back buffer texture id if we're on the same thread
  // since the |release_callback| ensures this resource will be alive.
  GLuint shared_texture_id = !is_cross_thread() ? back_buffer_texture_id_ : 0u;

  // The |release_callback| keeps a ref on this resource to ensure the backing
  // shared image is kept alive until the lifetime of the image.
  auto release_callback = base::BindOnce(
      [](scoped_refptr<CanvasResourceSwapChain>, const gpu::SyncToken&, bool) {
        // Do nothing but hold onto the refptr.
      },
      base::RetainedRef(this));

  return AcceleratedStaticBitmapImage::CreateFromCanvasSharedImage(
      back_buffer_shared_image_, GetSyncToken(), shared_texture_id, image_info,
      back_buffer_shared_image_->GetTextureTarget(),
      true /*is_origin_top_left*/, context_provider_wrapper_,
      owning_thread_ref_, owning_thread_task_runner_,
      std::move(release_callback), /*supports_display_compositing=*/true,
      /*is_overlay_candidate=*/true);
}

scoped_refptr<gpu::ClientSharedImage>
CanvasResourceSwapChain::GetClientSharedImage() {
  return front_buffer_shared_image_;
}

const gpu::SyncToken
CanvasResourceSwapChain::GetSyncTokenWithOptionalVerification(
    bool needs_verified_token) {
  DCHECK(sync_token_.verified_flush());
  return sync_token_;
}

void CanvasResourceSwapChain::PresentSwapChain() {
  DCHECK(!is_cross_thread());
  DCHECK(context_provider_wrapper_);
  TRACE_EVENT0("blink", "CanvasResourceSwapChain::PresentSwapChain");

  auto* raster_interface =
      context_provider_wrapper_->ContextProvider()->RasterInterface();
  DCHECK(raster_interface);

  auto* sii =
      context_provider_wrapper_->ContextProvider()->SharedImageInterface();
  DCHECK(sii);

  // Synchronize presentation and rendering.
  raster_interface->GenUnverifiedSyncTokenCHROMIUM(sync_token_.GetData());
  sii->PresentSwapChain(sync_token_, back_buffer_shared_image_->mailbox());
  // This only gets called via the CanvasResourceDispatcher export path so a
  // verified sync token will be needed ultimately.
  sync_token_ = sii->GenVerifiedSyncToken();
  raster_interface->WaitSyncTokenCHROMIUM(sync_token_.GetData());

  // Relinquish shared image access before copy when using legacy GL raster.
  if (!use_oop_rasterization_) {
    raster_interface->EndSharedImageAccessDirectCHROMIUM(
        back_buffer_texture_id_);
  }
  // PresentSwapChain() flips the front and back buffers, but the mailboxes
  // still refer to the current front and back buffer after present.  So the
  // front buffer contains the content we just rendered, and it needs to be
  // copied into the back buffer to support a retained mode like canvas expects.
  // The wait sync token ensure that the present executes before we do the copy.
  // Don't generate sync token after the copy so that it's not on critical path.
  raster_interface->CopySharedImage(front_buffer_shared_image_->mailbox(),
                                    back_buffer_shared_image_->mailbox(), 0, 0,
                                    0, 0, Size().width(), Size().height());
  // Restore shared image access after copy when using legacy GL raster.
  if (!use_oop_rasterization_) {
    raster_interface->BeginSharedImageAccessDirectCHROMIUM(
        back_buffer_texture_id_,
        GL_SHARED_IMAGE_ACCESS_MODE_READWRITE_CHROMIUM);
  }
}

base::WeakPtr<WebGraphicsContext3DProviderWrapper>
CanvasResourceSwapChain::ContextProviderWrapper() const {
  return context_provider_wrapper_;
}

CanvasResourceSwapChain::CanvasResourceSwapChain(
    gfx::Size size,
    SkColorType sk_color_type,
    SkAlphaType sk_alpha_type,
    sk_sp<SkColorSpace> sk_color_space,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceProvider> provider,
    cc::PaintFlags::FilterQuality filter_quality)
    : CanvasResource(
          std::move(provider),
          filter_quality,
          size,
          viz::SkColorTypeToSinglePlaneSharedImageFormat(sk_color_type),
          sk_alpha_type,
          std::move(sk_color_space)),
      context_provider_wrapper_(std::move(context_provider_wrapper)),
      use_oop_rasterization_(context_provider_wrapper_->ContextProvider()
                                 ->GetCapabilities()
                                 .gpu_rasterization) {
  if (!context_provider_wrapper_)
    return;

  // These SharedImages are both read and written by the raster interface (both
  // occur, for example, when copying canvas resources between canvases).
  // Additionally, these SharedImages can be put into
  // AcceleratedStaticBitmapImages (via Bitmap()) that are then copied into GL
  // textures by WebGL (via AcceleratedStaticBitmapImage::CopyToTexture()).
  // Hence, GLES2_READ usage is necessary regardless of whether raster is over
  // GLES.
  gpu::SharedImageUsageSet usage = gpu::SHARED_IMAGE_USAGE_DISPLAY_READ |
                                   gpu::SHARED_IMAGE_USAGE_GLES2_READ |
                                   gpu::SHARED_IMAGE_USAGE_SCANOUT |
                                   gpu::SHARED_IMAGE_USAGE_RASTER_READ |
                                   gpu::SHARED_IMAGE_USAGE_RASTER_WRITE;
  if (use_oop_rasterization_) {
    usage = usage | gpu::SHARED_IMAGE_USAGE_OOP_RASTERIZATION;
  } else {
    // The GLES2_WRITE flag is needed due to raster being over GL.
    usage = usage | gpu::SHARED_IMAGE_USAGE_GLES2_WRITE;
  }

  auto* sii =
      context_provider_wrapper_->ContextProvider()->SharedImageInterface();
  DCHECK(sii);
  gpu::SharedImageInterface::SwapChainSharedImages shared_images =
      sii->CreateSwapChain(GetSharedImageFormat(), Size(), GetColorSpace(),
                           kTopLeft_GrSurfaceOrigin, kPremul_SkAlphaType,
                           usage);
  CHECK(shared_images.back_buffer);
  CHECK(shared_images.front_buffer);
  back_buffer_shared_image_ = std::move(shared_images.back_buffer);
  front_buffer_shared_image_ = std::move(shared_images.front_buffer);
  sync_token_ = sii->GenVerifiedSyncToken();

  // Wait for the mailboxes to be ready to be used.
  auto* raster_interface =
      context_provider_wrapper_->ContextProvider()->RasterInterface();
  DCHECK(raster_interface);
  raster_interface->WaitSyncTokenCHROMIUM(sync_token_.GetData());

  // In OOPR mode we use mailboxes directly. We early out here because
  // we don't need a texture id, as access is managed in the gpu process.
  if (use_oop_rasterization_)
    return;

  back_buffer_texture_id_ = raster_interface->CreateAndConsumeForGpuRaster(
      back_buffer_shared_image_->mailbox());
  raster_interface->BeginSharedImageAccessDirectCHROMIUM(
      back_buffer_texture_id_, GL_SHARED_IMAGE_ACCESS_MODE_READWRITE_CHROMIUM);
}

}  // namespace blink

"""


```