Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from the Chromium Blink engine. This is the second part of a three-part code listing for the file `canvas_resource_provider.cc`.

My plan is to:
1. **Identify the main classes:**  Scan the code for class definitions and their inheritance.
2. **Summarize the functionality of each class:** Based on the member functions and their names, deduce the purpose of each class.
3. **Relate to Javascript, HTML, and CSS:** Think about how these classes might be used in the context of web development, specifically canvas rendering.
4. **Identify logical inferences and provide examples:** Look for conditional statements and operations that suggest a logical flow. Create hypothetical inputs and outputs to illustrate this.
5. **Point out potential usage errors:** Based on the class functionalities, consider common mistakes a developer might make when using these features.
6. **Synthesize the overall functionality:**  Combine the summaries of the individual classes to describe the broader purpose of this section of the code.
这是`blink/renderer/platform/graphics/canvas_resource_provider.cc`文件的第二部分，主要定义了以下 `CanvasResourceProvider` 的子类，并提供了一些创建这些 Provider 的工厂方法：

**主要功能归纳：**

1. **`CanvasResourceProviderPassThrough` 类:**
    *   **功能:**  作为一种“直通”的 CanvasResourceProvider。它本身不创建或持有 Canvas 资源，而是依赖于外部导入的资源。
    *   **特点:**  始终被认为是有效且加速的。支持直接合成和单缓冲。
    *   **与 Javascript/HTML/CSS 的关系:**  当需要将外部的图形资源（例如，来自视频帧或WebGL的纹理）集成到 Canvas 渲染管线时使用。在 Javascript 中，可以使用类似 `drawImage()` 或 `texImage2D()`  将这些外部资源导入到 Canvas 中。
    *   **逻辑推理:**
        *   **假设输入:**  一个已经创建好的 GPU 纹理 (作为外部资源)，并通过 `ImportResource()` 方法导入到 `CanvasResourceProviderPassThrough` 实例中。
        *   **输出:**  对该 `CanvasResourceProviderPassThrough` 进行绘制操作，会将对该外部纹理的引用传递到渲染管线中，最终显示在 Canvas 上。
    *   **用户/编程常见错误:**  如果尝试在没有通过 `ImportResource()` 导入有效外部资源的情况下调用 `Snapshot()`，将会返回 `nullptr`。

2. **`CanvasResourceProviderSwapChain` 类:**
    *   **功能:**  为使用共享图像交换链进行渲染的 Canvas 提供资源管理。它渲染到交换链的后缓冲区，并在必要时呈现交换链，并将前缓冲区的 mailbox 导出给 compositor 以支持低延迟模式。
    *   **特点:**  始终被认为是有效且加速的。支持直接合成和单缓冲。可以作为 Layer 的 overlay 候选。可以支持 OOP (Out-of-Process) 光栅化。
    *   **与 Javascript/HTML/CSS 的关系:**  常用于 `<canvas>` 元素，尤其是在需要高性能和低延迟渲染的场景，例如动画或游戏。Javascript 中的 Canvas API 调用会触发对该 Provider 的操作。
    *   **逻辑推理:**
        *   **假设输入:**  Javascript 代码在 `<canvas>` 上执行了一系列的绘制命令（例如，`fillRect()`, `drawImage()`）。
        *   **输出:**  `CanvasResourceProviderSwapChain` 会将这些绘制命令记录下来，并在 `ProduceCanvasResource()` 被调用时，将渲染结果提交到后缓冲区，然后通过 `PresentSwapChain()` 呈现到屏幕上。
    *   **用户/编程常见错误:**
        *   在 OOP 光栅化启用的情况下，直接调用 `GetSkSurface()` 可能会返回 `nullptr`，应该依赖光栅化机制来渲染。
        *   在未调用任何绘制操作的情况下，`PresentSwapChain()` 不会被调用，屏幕上可能不会有更新。

3. **工厂方法 (`Create...Provider`)：**
    *   **`CreateBitmapProvider`:** 创建一个基于位图的 `CanvasResourceProvider`。
    *   **`CreateSharedBitmapProvider`:** 创建一个基于共享位图的 `CanvasResourceProvider`。需要有效的 `CanvasResourceDispatcher`。
    *   **`CreateSharedImageProvider`:** 创建一个基于共享图像的 `CanvasResourceProvider`，这是 GPU 加速 Canvas 的常用方式。会根据硬件和配置选择合适的共享图像格式。
    *   **`CreateWebGPUImageProvider`:**  创建一个用于 WebGPU 互操作的 `CanvasResourceProvider`，它创建的共享图像可以被 WebGPU 读取和写入。
    *   **`CreatePassThroughProvider`:** 创建一个 `CanvasResourceProviderPassThrough` 实例，用于集成外部 GPU 资源。
    *   **`CreateSwapChainProvider`:** 创建一个 `CanvasResourceProviderSwapChain` 实例，用于使用共享图像交换链进行渲染。

4. **`CanvasResourceProvider::CanvasImageProvider` 内部类:**
    *   **功能:**  作为 Canvas 渲染过程中的图像提供者，用于获取需要绘制的图像内容，并管理图像的解码和缓存。
    *   **与 Javascript/HTML/CSS 的关系:** 当 Javascript 代码中使用 `drawImage()` 绘制 `<img>` 元素或者其他 `PaintImage` 对象时，`CanvasImageProvider` 负责提供这些图像的像素数据。
    *   **逻辑推理:**
        *   **假设输入:**  Javascript 调用 `drawImage()` 绘制一个大型的 JPEG 图片。
        *   **输出:**  `CanvasImageProvider` 会从缓存中查找该图像，如果不存在则触发解码过程，最终返回解码后的像素数据用于渲染。
    *   **用户/编程常见错误:**  如果绘制大量不同的、未缓存的图片，可能会导致频繁的解码操作，影响性能。

**整体功能归纳：**

这段代码定义了多种不同类型的 `CanvasResourceProvider`，它们负责管理 Canvas 渲染所需的底层图形资源。不同的 Provider 类型适用于不同的渲染场景，例如：

*   **软件渲染:** 使用位图。
*   **GPU 加速渲染:** 使用共享纹理或交换链。
*   **外部资源集成:**  直接使用外部 GPU 纹理。
*   **WebGPU 互操作:**  使用可以被 WebGPU 读取和写入的共享图像。

这些 Provider 的创建通过一系列工厂方法进行，这些方法会根据系统环境（例如，是否启用 GPU 合成，GPU 的能力）选择合适的 Provider 类型。`CanvasImageProvider` 作为辅助类，负责提供绘制所需的图像数据，并进行缓存优化。

这段代码是 Blink 引擎中 Canvas 渲染管线的重要组成部分，它抽象了不同渲染方式下的资源管理，为上层的 Canvas API 提供了统一的接口。
### 提示词
```
这是目录为blink/renderer/platform/graphics/canvas_resource_provider.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
der_wrapper,
      base::WeakPtr<CanvasResourceDispatcher> resource_dispatcher,
      bool is_origin_top_left,
      CanvasResourceHost* resource_host)
      : CanvasResourceProvider(kPassThrough,
                               info,
                               filter_quality,
                               std::move(context_provider_wrapper),
                               std::move(resource_dispatcher),
                               resource_host),
        is_origin_top_left_(is_origin_top_left) {}

  ~CanvasResourceProviderPassThrough() override = default;
  bool IsValid() const final { return true; }
  bool IsAccelerated() const final { return true; }
  bool SupportsDirectCompositing() const override { return true; }
  bool SupportsSingleBuffering() const override { return true; }
  bool IsOriginTopLeft() const override { return is_origin_top_left_; }

 private:
  scoped_refptr<CanvasResource> CreateResource() final {
    // This class has no CanvasResource to provide: this must be imported via
    // ImportResource() and kept in the parent class.
    NOTREACHED();
  }

  scoped_refptr<CanvasResource> ProduceCanvasResource(FlushReason) final {
    return NewOrRecycledResource();
  }

  sk_sp<SkSurface> CreateSkSurface() const override { NOTREACHED(); }

  scoped_refptr<StaticBitmapImage> Snapshot(FlushReason,
                                            ImageOrientation) override {
    auto resource = GetImportedResource();
    if (IsGpuContextLost() || !resource)
      return nullptr;
    return resource->Bitmap();
  }

  const bool is_origin_top_left_;
};

// * Renders to back buffer of a shared image swap chain.
// * Presents swap chain and exports front buffer mailbox to compositor to
//   support low latency mode.
// * Layers are overlay candidates.
class CanvasResourceProviderSwapChain final : public CanvasResourceProvider {
 public:
  CanvasResourceProviderSwapChain(
      const SkImageInfo& info,
      cc::PaintFlags::FilterQuality filter_quality,
      base::WeakPtr<WebGraphicsContext3DProviderWrapper>
          context_provider_wrapper,
      base::WeakPtr<CanvasResourceDispatcher> resource_dispatcher,
      CanvasResourceHost* resource_host)
      : CanvasResourceProvider(kSwapChain,
                               info,
                               filter_quality,
                               std::move(context_provider_wrapper),
                               std::move(resource_dispatcher),
                               resource_host),
        use_oop_rasterization_(ContextProviderWrapper()
                                   ->ContextProvider()
                                   ->GetCapabilities()
                                   .gpu_rasterization) {
    resource_ = CanvasResourceSwapChain::Create(
        gfx::Size(info.width(), info.height()), info.colorInfo().colorType(),
        info.colorInfo().alphaType(), info.colorInfo().refColorSpace(),
        ContextProviderWrapper(), CreateWeakPtr(), FilterQuality());
    // CanvasResourceProviderSwapChain can only operate in a single buffered
    // mode so enable it as soon as possible.
    TryEnableSingleBuffering();
    DCHECK(IsSingleBuffered());
  }
  ~CanvasResourceProviderSwapChain() override = default;

  bool IsValid() const final {
    if (!use_oop_rasterization_)
      return GetSkSurface() && !IsGpuContextLost();
    else
      return !IsGpuContextLost();
  }

  bool IsAccelerated() const final { return true; }
  bool SupportsDirectCompositing() const override { return true; }
  bool SupportsSingleBuffering() const override { return true; }

 private:
  void WillDraw() override {
    needs_present_ = true;
    needs_flush_ = true;
  }

  scoped_refptr<CanvasResource> CreateResource() final {
    TRACE_EVENT0("blink", "CanvasResourceProviderSwapChain::CreateResource");
    return resource_;
  }

  scoped_refptr<CanvasResource> ProduceCanvasResource(
      FlushReason reason) override {
    DCHECK(IsSingleBuffered());
    TRACE_EVENT0("blink",
                 "CanvasResourceProviderSwapChain::ProduceCanvasResource");
    if (!IsValid())
      return nullptr;

    FlushIfNeeded(reason);

    if (needs_present_) {
      resource_->PresentSwapChain();
      needs_present_ = false;
    }
    return resource_;
  }

  scoped_refptr<StaticBitmapImage> Snapshot(FlushReason reason,
                                            ImageOrientation) override {
    TRACE_EVENT0("blink", "CanvasResourceProviderSwapChain::Snapshot");

    if (!IsValid())
      return nullptr;

    FlushIfNeeded(reason);

    return resource_->Bitmap();
  }

  sk_sp<SkSurface> CreateSkSurface() const override {
    TRACE_EVENT0("blink", "CanvasResourceProviderSwapChain::CreateSkSurface");
    if (IsGpuContextLost() || !resource_)
      return nullptr;

    GrGLTextureInfo texture_info = {};
    texture_info.fID = resource_->GetBackBufferTextureId();
    texture_info.fTarget =
        resource_->GetBackBufferClientSharedImage()->GetTextureTarget();
    texture_info.fFormat =
        ContextProviderWrapper()->ContextProvider()->GetGrGLTextureFormat(
            viz::SkColorTypeToSinglePlaneSharedImageFormat(
                GetSkImageInfo().colorType()));

    auto backend_texture = GrBackendTextures::MakeGL(
        Size().width(), Size().height(), skgpu::Mipmapped::kNo, texture_info);

    const auto props = GetSkSurfaceProps();
    return SkSurfaces::WrapBackendTexture(
        GetGrContext(), backend_texture, kTopLeft_GrSurfaceOrigin,
        0 /* msaa_sample_count */, GetSkImageInfo().colorType(),
        GetSkImageInfo().refColorSpace(), &props);
  }

  void RasterRecord(cc::PaintRecord last_recording) override {
    TRACE_EVENT0("blink", "CanvasResourceProviderSwapChain::RasterRecord");
    if (!use_oop_rasterization_) {
      CanvasResourceProvider::RasterRecord(std::move(last_recording));
      return;
    }
    WillDraw();
    RasterRecordOOP(last_recording, initial_needs_clear_,
                    resource_->GetBackBufferClientSharedImage()->mailbox());
    initial_needs_clear_ = false;
  }

  bool UseOopRasterization() final { return use_oop_rasterization_; }

  bool WritePixels(const SkImageInfo& orig_info,
                   const void* pixels,
                   size_t row_bytes,
                   int x,
                   int y) override {
    if (!use_oop_rasterization_) {
      return CanvasResourceProvider::WritePixels(orig_info, pixels, row_bytes,
                                                 x, y);
    }

    TRACE_EVENT0("blink", "CanvasResourceProviderSwapChain::WritePixels");
    if (IsGpuContextLost())
      return false;

    WillDraw();
    RasterInterface()->WritePixels(
        resource_->GetBackBufferClientSharedImage()->mailbox(), x, y,
        resource_->GetBackBufferClientSharedImage()->GetTextureTarget(),
        SkPixmap(orig_info, pixels, row_bytes));
    return true;
  }

  void FlushIfNeeded(FlushReason reason) {
    if (needs_flush_) {
      // This only flushes recorded draw ops.
      FlushCanvas(reason);
      // Call flushAndSubmit() explicitly so that any non-draw-op rendering by
      // Skia is flushed to GL.  This is needed specifically for WritePixels().
      if (!use_oop_rasterization_)
        GetGrContext()->flushAndSubmit();

      needs_flush_ = false;
    }
  }

  bool needs_present_ = false;
  bool needs_flush_ = false;
  const bool use_oop_rasterization_;
  // This only matters for the initial backbuffer mailbox, since the frontbuffer
  // will always have the back texture copied to it prior to any new commands.
  bool initial_needs_clear_ = true;
  scoped_refptr<CanvasResourceSwapChain> resource_;
};

std::unique_ptr<CanvasResourceProvider>
CanvasResourceProvider::CreateBitmapProvider(
    const SkImageInfo& info,
    cc::PaintFlags::FilterQuality filter_quality,
    ShouldInitialize should_initialize,
    CanvasResourceHost* resource_host) {
  auto provider = std::make_unique<CanvasResourceProviderBitmap>(
      info, filter_quality, /*resource_dispatcher=*/nullptr, resource_host);
  if (provider->IsValid()) {
    if (should_initialize ==
        CanvasResourceProvider::ShouldInitialize::kCallClear)
      provider->Clear();
    return provider;
  }
  return nullptr;
}

std::unique_ptr<CanvasResourceProvider>
CanvasResourceProvider::CreateSharedBitmapProvider(
    const SkImageInfo& info,
    cc::PaintFlags::FilterQuality filter_quality,
    ShouldInitialize should_initialize,
    base::WeakPtr<CanvasResourceDispatcher> resource_dispatcher,
    WebGraphicsSharedImageInterfaceProvider* shared_image_interface_provider,
    CanvasResourceHost* resource_host) {
  // SharedBitmapProvider has to have a valid resource_dispatecher to be able to
  // be created.

  // TODO:: Remove |resource_dispatcher| because it's not used by SharedImage.
  // |resource_dispatcher| is nullptr in some tests. (e.g. PixelIntegrationTest
  // Pixel_Canvas2DTabSwitch_SoftwareCompositing, and
  // Pixel_CanvasUnacceleratedLowLatency2D, etc) Removing
  // |resource_dispatcher| causes this function to continue with
  // CanvasResourceProviderSharedBitmap here instead of CreateBitmapProvider()
  // later. The final images are different. Some windows and Linux tests would
  // crash.
  if (!resource_dispatcher) {
    return nullptr;
  }

  auto provider = std::make_unique<CanvasResourceProviderSharedBitmap>(
      info, filter_quality, std::move(resource_dispatcher),
      shared_image_interface_provider, resource_host);
  if (provider->IsValid()) {
    if (should_initialize ==
        CanvasResourceProvider::ShouldInitialize::kCallClear)
      provider->Clear();
    return provider;
  }

  return nullptr;
}

std::unique_ptr<CanvasResourceProvider>
CanvasResourceProvider::CreateSharedImageProvider(
    const SkImageInfo& info,
    cc::PaintFlags::FilterQuality filter_quality,
    ShouldInitialize should_initialize,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    RasterMode raster_mode,
    gpu::SharedImageUsageSet shared_image_usage_flags,
    CanvasResourceHost* resource_host) {
  // IsGpuCompositingEnabled can re-create the context if it has been lost, do
  // this up front so that we can fail early and not expose ourselves to
  // use after free bugs (crbug.com/1126424)
  const bool is_gpu_compositing_enabled =
      SharedGpuContext::IsGpuCompositingEnabled();

  // If the context is lost we don't want to re-create it here, the resulting
  // resource provider would be invalid anyway
  if (!context_provider_wrapper ||
      context_provider_wrapper->ContextProvider()->IsContextLost())
    return nullptr;

  const auto& capabilities =
      context_provider_wrapper->ContextProvider()->GetCapabilities();
  if ((info.width() < 1 || info.height() < 1 ||
       info.width() > capabilities.max_texture_size ||
       info.height() > capabilities.max_texture_size)) {
    return nullptr;
  }

  const bool is_accelerated = raster_mode == RasterMode::kGPU;

  SkImageInfo adjusted_info = info;
  // TODO(https://crbug.com/1210946): Pass in info as is for all cases.
  // Overriding the info to use RGBA instead of N32 is needed because code
  // elsewhere assumes RGBA. OTOH the software path seems to be assuming N32
  // somewhere in the later pipeline but for offscreen canvas only.
  if (!shared_image_usage_flags.HasAny(gpu::SHARED_IMAGE_USAGE_WEBGPU_READ |
                                       gpu::SHARED_IMAGE_USAGE_WEBGPU_WRITE)) {
    adjusted_info = adjusted_info.makeColorType(
        is_accelerated && info.colorType() != kRGBA_F16_SkColorType
            ? kRGBA_8888_SkColorType
            : info.colorType());
  }

  const bool is_gpu_memory_buffer_image_allowed =
      is_gpu_compositing_enabled && IsGMBAllowed(adjusted_info, capabilities) &&
      SharedGpuContext::GetGpuMemoryBufferManager();

  if (raster_mode == RasterMode::kCPU && !is_gpu_memory_buffer_image_allowed)
    return nullptr;

  // If we cannot use overlay, we have to remove the scanout flag and the
  // concurrent read write flag.
  const auto& shared_image_caps = context_provider_wrapper->ContextProvider()
                                      ->SharedImageInterface()
                                      ->GetCapabilities();
  if (!is_gpu_memory_buffer_image_allowed ||
      (is_accelerated && !shared_image_caps.supports_scanout_shared_images)) {
    shared_image_usage_flags.RemoveAll(
        gpu::SHARED_IMAGE_USAGE_CONCURRENT_READ_WRITE |
        gpu::SHARED_IMAGE_USAGE_SCANOUT);
  }

  if (resource_host && resource_host->TransferToGPUTextureWasInvoked()) {
    shared_image_usage_flags.PutAll(gpu::SHARED_IMAGE_USAGE_WEBGPU_READ |
                                    gpu::SHARED_IMAGE_USAGE_WEBGPU_WRITE);
  }

#if BUILDFLAG(IS_MAC)
  if ((shared_image_usage_flags & gpu::SHARED_IMAGE_USAGE_SCANOUT) &&
      is_accelerated && adjusted_info.colorType() == kRGBA_8888_SkColorType) {
    // GPU-accelerated scannout usage on Mac uses IOSurface.  Must switch from
    // RGBA_8888 to BGRA_8888 in that case.
    adjusted_info = adjusted_info.makeColorType(kBGRA_8888_SkColorType);
  }
#endif

  auto provider = std::make_unique<CanvasResourceProviderSharedImage>(
      adjusted_info, filter_quality, context_provider_wrapper, is_accelerated,
      shared_image_usage_flags, resource_host);
  if (provider->IsValid()) {
    if (should_initialize ==
        CanvasResourceProvider::ShouldInitialize::kCallClear)
      provider->Clear();
    return provider;
  }

  return nullptr;
}

std::unique_ptr<CanvasResourceProvider>
CanvasResourceProvider::CreateWebGPUImageProvider(
    const SkImageInfo& info,
    gpu::SharedImageUsageSet shared_image_usage_flags,
    CanvasResourceHost* resource_host) {
  auto context_provider_wrapper = SharedGpuContext::ContextProviderWrapper();
  // The SharedImages created by this provider serve as a means of import/export
  // between VideoFrames/canvas and WebGPU, e.g.:
  // * Import from VideoFrames into WebGPU via CreateExternalTexture() (the
  //   WebGPU textures will then be read by clients)
  // * Export from WebGPU into canvas via
  //   GpuCanvasContext::CopyTextureToResourceProvider() (the export happens via
  //   the WebGPU interface)
  // Hence, both WEBGPU_READ and WEBGPU_WRITE usage are needed here.
  return CreateSharedImageProvider(
      info, cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kNo,
      std::move(context_provider_wrapper), RasterMode::kGPU,
      shared_image_usage_flags | gpu::SHARED_IMAGE_USAGE_WEBGPU_READ |
          gpu::SHARED_IMAGE_USAGE_WEBGPU_WRITE,
      resource_host);
}

std::unique_ptr<CanvasResourceProvider>
CanvasResourceProvider::CreatePassThroughProvider(
    const SkImageInfo& info,
    cc::PaintFlags::FilterQuality filter_quality,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceDispatcher> resource_dispatcher,
    bool is_origin_top_left,
    CanvasResourceHost* resource_host) {
  // SharedGpuContext::IsGpuCompositingEnabled can potentially replace the
  // context_provider_wrapper, so it's important to call that first as it can
  // invalidate the weak pointer.
  if (!SharedGpuContext::IsGpuCompositingEnabled() || !context_provider_wrapper)
    return nullptr;

  const auto& capabilities =
      context_provider_wrapper->ContextProvider()->GetCapabilities();
  if (info.width() > capabilities.max_texture_size ||
      info.height() > capabilities.max_texture_size) {
    return nullptr;
  }

  const auto& shared_image_capabilities =
      context_provider_wrapper->ContextProvider()
          ->SharedImageInterface()
          ->GetCapabilities();
  // Either swap_chain or gpu memory buffer should be enabled for this be used
  if (!shared_image_capabilities.shared_image_swap_chain &&
      (!IsGMBAllowed(info, capabilities) ||
       !Platform::Current()->GetGpuMemoryBufferManager())) {
    return nullptr;
  }

  // Note: Unlike other CanvasResourceProvider subclasses, a
  // CanvasResourceProviderPassThrough instance is always valid and does not
  // require clearing as part of initialization (both of these being due to the
  // fact that it simply delegates the internal parts of the resource to other
  // classes).
  auto provider = std::make_unique<CanvasResourceProviderPassThrough>(
      info, filter_quality, context_provider_wrapper, resource_dispatcher,
      is_origin_top_left, resource_host);
  CHECK(provider->IsValid());
  return provider;
}

std::unique_ptr<CanvasResourceProvider>
CanvasResourceProvider::CreateSwapChainProvider(
    const SkImageInfo& info,
    cc::PaintFlags::FilterQuality filter_quality,
    ShouldInitialize should_initialize,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceDispatcher> resource_dispatcher,
    CanvasResourceHost* resource_host) {
  // SharedGpuContext::IsGpuCompositingEnabled can potentially replace the
  // context_provider_wrapper, so it's important to call that first as it can
  // invalidate the weak pointer.
  if (!SharedGpuContext::IsGpuCompositingEnabled() || !context_provider_wrapper)
    return nullptr;

  const auto& capabilities =
      context_provider_wrapper->ContextProvider()->GetCapabilities();
  const auto& shared_image_capabilities =
      context_provider_wrapper->ContextProvider()
          ->SharedImageInterface()
          ->GetCapabilities();

  if (info.width() > capabilities.max_texture_size ||
      info.height() > capabilities.max_texture_size ||
      !shared_image_capabilities.shared_image_swap_chain) {
    return nullptr;
  }

  auto provider = std::make_unique<CanvasResourceProviderSwapChain>(
      info, filter_quality, context_provider_wrapper, resource_dispatcher,
      resource_host);
  if (provider->IsValid()) {
    if (should_initialize ==
        CanvasResourceProvider::ShouldInitialize::kCallClear)
      provider->Clear();
    return provider;
  }

  return nullptr;
}

CanvasResourceProvider::CanvasImageProvider::CanvasImageProvider(
    cc::ImageDecodeCache* cache_n32,
    cc::ImageDecodeCache* cache_f16,
    const gfx::ColorSpace& target_color_space,
    SkColorType canvas_color_type,
    cc::PlaybackImageProvider::RasterMode raster_mode)
    : raster_mode_(raster_mode) {
  std::optional<cc::PlaybackImageProvider::Settings> settings =
      cc::PlaybackImageProvider::Settings();
  settings->raster_mode = raster_mode_;

  cc::TargetColorParams target_color_params;
  target_color_params.color_space = target_color_space;
  playback_image_provider_n32_.emplace(cache_n32, target_color_params,
                                       std::move(settings));
  // If the image provider may require to decode to half float instead of
  // uint8, create a f16 PlaybackImageProvider with the passed cache.
  if (canvas_color_type == kRGBA_F16_SkColorType) {
    DCHECK(cache_f16);
    settings = cc::PlaybackImageProvider::Settings();
    settings->raster_mode = raster_mode_;
    playback_image_provider_f16_.emplace(cache_f16, target_color_params,
                                         std::move(settings));
  }
}

cc::ImageProvider::ScopedResult
CanvasResourceProvider::CanvasImageProvider::GetRasterContent(
    const cc::DrawImage& draw_image) {
  cc::PaintImage paint_image = draw_image.paint_image();
  if (paint_image.IsDeferredPaintRecord()) {
    CHECK(!paint_image.IsPaintWorklet());
    scoped_refptr<CanvasDeferredPaintRecord> canvas_deferred_paint_record(
        static_cast<CanvasDeferredPaintRecord*>(
            paint_image.deferred_paint_record().get()));
    return cc::ImageProvider::ScopedResult(
        canvas_deferred_paint_record->GetPaintRecord());
  }

  // TODO(xidachen): Ensure this function works for paint worklet generated
  // images.
  // If we like to decode high bit depth image source to half float backed
  // image, we need to sniff the image bit depth here to avoid double decoding.
  ImageProvider::ScopedResult scoped_decoded_image;
  if (playback_image_provider_f16_ &&
      draw_image.paint_image().is_high_bit_depth()) {
    DCHECK(playback_image_provider_f16_);
    scoped_decoded_image =
        playback_image_provider_f16_->GetRasterContent(draw_image);
  } else {
    scoped_decoded_image =
        playback_image_provider_n32_->GetRasterContent(draw_image);
  }

  // Holding onto locked images here is a performance optimization for the
  // gpu image decode cache.  For that cache, it is expensive to lock and
  // unlock gpu discardable, and so it is worth it to hold the lock on
  // these images across multiple potential decodes.  In the software case,
  // locking in this manner makes it easy to run out of discardable memory
  // (backed by shared memory sometimes) because each per-colorspace image
  // decode cache has its own limit.  In the software case, just unlock
  // immediately and let the discardable system manage the cache logic
  // behind the scenes.
  if (!scoped_decoded_image.needs_unlock() || !IsHardwareDecodeCache()) {
    return scoped_decoded_image;
  }

  constexpr int kMaxLockedImagesCount = 500;
  if (!scoped_decoded_image.decoded_image().is_budgeted() ||
      locked_images_.size() > kMaxLockedImagesCount) {
    // If we have exceeded the budget, ReleaseLockedImages any locked decodes.
    ReleaseLockedImages();
  }

  auto decoded_draw_image = scoped_decoded_image.decoded_image();
  return ScopedResult(decoded_draw_image,
                      base::BindOnce(&CanvasImageProvider::CanUnlockImage,
                                     weak_factory_.GetWeakPtr(),
                                     std::move(scoped_decoded_image)));
}

void CanvasResourceProvider::CanvasImageProvider::CanUnlockImage(
    ScopedResult image) {
  // We should early out and avoid calling this function for software decodes.
  DCHECK(IsHardwareDecodeCache());

  // Because these image decodes are being done in javascript calling into
  // canvas code, there's no obvious time to do the cleanup.  To handle this,
  // post a cleanup task to run after javascript is done running.
  if (!cleanup_task_pending_) {
    cleanup_task_pending_ = true;
    ThreadScheduler::Current()->CleanupTaskRunner()->PostTask(
        FROM_HERE, base::BindOnce(&CanvasImageProvider::CleanupLockedImages,
                                  weak_factory_.GetWeakPtr()));
  }

  locked_images_.push_back(std::move(image));
}

void CanvasResourceProvider::CanvasImageProvider::CleanupLockedImages() {
  cleanup_task_pending_ = false;
  ReleaseLockedImages();
}

bool CanvasResourceProvider::CanvasImageProvider::IsHardwareDecodeCache()
    const {
  return raster_mode_ != cc::PlaybackImageProvider::RasterMode::kSoftware;
}

BASE_FEATURE(kCanvas2DAutoFlushParams,
             "Canvas2DAutoFlushParams",
             base::FEATURE_DISABLED_BY_DEFAULT);

// When enabled, unused resources (ready to be recycled) are reclaimed after a
// delay.
BASE_FEATURE(kCanvas2DReclaimUnusedResources,
             "Canvas2DReclaimUnusedResources",
             base::FEATURE_DISABLED_BY_DEFAULT);

// The following parameters attempt to reach a compromise between not flushing
// too often, and not accumulating an unreasonable backlog. Flushing too
// often will hurt performance due to overhead costs. Accumulating large
// backlogs, in the case of OOPR-Canvas, results in poor parellelism and
// janky UI. With OOPR-Canvas disabled, it is still desirable to flush
// periodically to guard against run-away memory consumption caused by
// PaintOpBuffers that grow indefinitely. The OOPR-related jank is caused by
// long-running RasterCHROMIUM calls that monopolize the main thread
// of the GPU process. By flushing periodically, we allow the rasterization
// of canvas contents to be interleaved with other compositing and UI work.
//
// The default values for these parameters were initially determined
// empirically. They were selected to maximize the MotionMark score on
// desktop computers. Field trials may be used to tune these parameters
// further by using metrics data from the field.
const base::FeatureParam<int> kMaxRecordedOpKB(&kCanvas2DAutoFlushParams,
                                               "max_recorded_op_kb",
                                               2 * 1024);

const base::FeatureParam<int> kMaxPinnedImageKB(&kCanvas2DAutoFlushParams,
                                                "max_pinned_image_kb",
                                                32 * 1024);

// Graphite can generally handle more ops, increase the size accordingly.
const base::FeatureParam<int> kMaxRecordedOpGraphiteKB(
    &kCanvas2DAutoFlushParams,
    "max_recorded_op_graphite_kb",
    6 * 1024);

CanvasResourceProvider::CanvasResourceProvider(
    const ResourceProviderType& type,
    const SkImageInfo& info,
    cc::PaintFlags::FilterQuality filter_quality,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::WeakPtr<CanvasResourceDispatcher> resource_dispatcher,
    CanvasResourceHost* resource_host)
    : type_(type),
      context_provider_wrapper_(std::move(context_provider_wrapper)),
      resource_dispatcher_(resource_dispatcher),
      info_(info),
      filter_quality_(filter_quality),
      resource_host_(resource_host),
      recorder_(std::make_unique<MemoryManagedPaintRecorder>(Size(), this)),
      snapshot_paint_image_id_(cc::PaintImage::GetNextId()) {
  max_recorded_op_bytes_ = static_cast<size_t>(kMaxRecordedOpKB.Get()) * 1024;
  max_pinned_image_bytes_ = static_cast<size_t>(kMaxPinnedImageKB.Get()) * 1024;
  if (context_provider_wrapper_) {
    context_provider_wrapper_->AddObserver(this);
    const auto& caps =
        context_provider_wrapper_->ContextProvider()->GetCapabilities();
    oopr_uses_dmsaa_ = !caps.msaa_is_slow && !caps.avoid_stencil_buffers;
    // Graphite can handle a large buffer size.
    if (context_provider_wrapper_->ContextProvider()
            ->GetGpuFeatureInfo()
            .status_values[gpu::GPU_FEATURE_TYPE_SKIA_GRAPHITE] ==
        gpu::kGpuFeatureStatusEnabled) {
      max_recorded_op_bytes_ =
          static_cast<size_t>(kMaxRecordedOpGraphiteKB.Get()) * 1024;
      recorder_->DisableLineDrawingAsPaths();
    }
  }

  CanvasMemoryDumpProvider::Instance()->RegisterClient(this);
}

CanvasResourceProvider::~CanvasResourceProvider() {
  UMA_HISTOGRAM_EXACT_LINEAR("Blink.Canvas.MaximumInflightResources",
                             max_inflight_resources_, 20);
  if (context_provider_wrapper_)
    context_provider_wrapper_->RemoveObserver(this);
  CanvasMemoryDumpProvider::Instance()->UnregisterClient(this);

  // Last chance for outstanding GPU timers to record metrics.
  if (RasterInterface()) {
    CheckGpuTimers(RasterInterface());
  }
}

std::unique_ptr<MemoryManagedPaintRecorder>
CanvasResourceProvider::ReleaseRecorder() {
  // When releasing the recorder, we swap it with a new, valid one. This way,
  // the `recorder_` member is guarantied to be always valid.
  auto recorder = std::make_unique<MemoryManagedPaintRecorder>(Size(), this);
  recorder_->SetClient(nullptr);
  recorder_.swap(recorder);
  DisableLineDrawingAsPathsIfNecessary();
  return recorder;
}

void CanvasResourceProvider::SetRecorder(
    std::unique_ptr<MemoryManagedPaintRecorder> recorder) {
  recorder->SetClient(this);
  recorder_ = std::move(recorder);
  DisableLineDrawingAsPathsIfNecessary();
}

void CanvasResourceProvider::FlushIfRecordingLimitExceeded() {
  // When printing we avoid flushing if it is still possible to print in
  // vector mode.
  if (IsPrinting() && clear_frame_) {
    return;
  }
  if (recorder_->ReleasableOpBytesUsed() > max_recorded_op_bytes_ ||
      recorder_->ReleasableImageBytesUsed() > max_pinned_image_bytes_)
      [[unlikely]] {
    FlushCanvas(FlushReason::kRecordingLimitExceeded);
  }
}

SkSurface* CanvasResourceProvider::GetSkSurface() const {
  if (!surface_)
    surface_ = CreateSkSurface();
  return surface_.get();
}

void CanvasResourceProvider::NotifyWillTransfer(
    cc::PaintImage::ContentId content_id) {
  // This is called when an ImageBitmap is about to be transferred. All
  // references to such a bitmap on the current thread must be released, which
  // means that DisplayItemLists that reference it must be flushed.
  GetFlushForImageListener()->NotifyFlushForImage(content_id);
}

bool CanvasResourceProvider::OverwriteImage(
    const gpu::Mailbox& shared_image_mailbox,
    const gfx::Rect& copy_rect,
    const gpu::SyncToken& ready_sync_token,
    gpu::SyncToken& completion_sync_token) {
  gpu::raster::RasterInterface* raster = RasterInterface();
  if (!raster) {
    return false;
  }
  auto dst_client_si = GetBackingClientSharedImageForOverwrite();
  if (!dst_client_si) {
    return false;
  }

  raster->WaitSyncTokenCHROMIUM(ready_sync_token.GetConstData());
  raster->CopySharedImage(shared_image_mailbox, dst_client_si->mailbox(),
                          /*xoffset=*/0,
                          /*yoffset=*/0, copy_rect.x(), copy_rect.y(),
                          copy_rect.width(), copy_rect.height());
  raster->GenUnverifiedSyncTokenCHROMIUM(completion_sync_token.GetData());
  return true;
}

void CanvasResourceProvider::EnsureSkiaCanvas() {
  WillDraw();

  if (skia_canvas_)
    return;

  cc::SkiaPaintCanvas::ContextFlushes context_flushes;
  if (IsAccelerated() && ContextProviderWrapper() &&
      !ContextProviderWrapper()
           ->ContextProvider()
           ->GetGpuFeatureInfo()
           .IsWorkaroundEnabled(gpu::DISABLE_2D_CANVAS_AUTO_FLUSH)) {
    context_flushes.enable = true;
    context_flushes.max_draws_before_flush = kMaxDrawsBeforeContextFlush;
  }
  skia_canvas_ = std::make_unique<cc::SkiaPaintCanvas>(
      GetSkSurface()->getCanvas(), GetOrCreateCanvasImageProvider(),
      context_flushes);
}

CanvasResourceProvider::CanvasImageProvider*
CanvasResourceProvider::GetOrCreateCanvasImageProvider() {
  if (!canvas_image_provider_) {
    // Create an ImageDecodeCache for half float images only if the canvas is
    // using half float back storage.
    cc::ImageDecodeCache* cache_f16 = nullptr;
    if (GetSkImageInfo().colorType() == kRGBA_F16_SkColorType)
      cache_f16 = ImageDecodeCacheF16();

    auto raster_mode = cc::PlaybackImageProvider::RasterMode::kSoftware;
    if (UseHardwareDecodeCache()) {
      raster_mode = UseOopRasterization()
                        ? cc::PlaybackImageProvider::RasterMode::kOop
                        : cc::PlaybackImageProvider::RasterMode::kGpu;
    }
    canvas_image_provider_ = std::make_unique<CanvasImageProvider>(
        ImageDecodeCacheRGBA8(), cache_f16, GetColorSpace(), info_.colorType(),
        raster_mode);
  }
  return canvas_image_provider_.get();
}

void CanvasResourceProvider::InitializeForRecording(
    cc::PaintCanvas* canvas) const {
  if (resource_host_) {
    resource_host_->InitializeForRecording(canvas);
  }
}

void CanvasResourceProvider::RecordingCleared() {
  // Since the recording has been cleared, it contains no draw commands and it
  // is now safe to update `mode_` to discard the old copy of canvas content.
  mode_ = SkSurface::kDiscard_ContentChangeMode;
  clear_frame_ = true;
  last_flush_reason_ = FlushReason::kNone;
  printing_fallback_reason_ = FlushReason::kNone;
}

MemoryManagedPaintCanvas& CanvasResourceProvider::Canvas(bool needs_will_draw) {
  // TODO(https://crbug.com/1211912): Video frames don't work without
  // WillDrawIfNeeded(), but we are getting memory leak on CreatePattern
  // with it. There should be a better way to solve this.
  if (needs_will_draw)
    WillDrawIfNeeded();

  return recorder_->getRecordingCanvas();
}

void CanvasResourceProvider::OnContextDestroyed() {
  if (skia_canvas_)
    skia_canvas_->reset_image_provider();
  canvas_image_provider_.reset();
}

void CanvasResourceProvider::OnFlushForImage(PaintImage::ContentId content_id) {
  if (Canvas().IsCachingImage(content_id)) {
    FlushCanvas(FlushReason::kSourceImageWillChange);
  }
}

void CanvasResourceProvider::ReleaseLockedImages() {
  if (canvas_image_provider_)
    canvas_image_provider_->ReleaseLockedImages();
}

scoped_refptr<StaticBitmapImage> CanvasResourceProvider::SnapshotInternal(
    ImageOrientation orientation,
    FlushReason reason) {
  if (!IsValid())
    return nullptr;

  auto paint_image = MakeImageSnapshot(reason);
  DCHECK(!paint_image.IsTextureBacked());
  return UnacceleratedStaticBitmapImage::Create(std::move(paint_image),
                                                orientation);
}

cc::PaintImage CanvasResourceProvider::MakeImageSnapshot(FlushReason reason) {
  FlushCanvas(reason);
  auto sk_image = GetSkSurface()->makeImageSnapshot();
  if (!sk_image)
    return cc::PaintImage();

  auto
```