Response:
The user wants a summary of the functionality of the provided C++ code file `canvas_resource_provider.cc`. I need to:

1. **Identify the core purpose** of this file within the Chromium Blink rendering engine.
2. **List its key functionalities**.
3. **Explain its relationship** with JavaScript, HTML, and CSS, providing examples if applicable.
4. **Illustrate logical reasoning** with input and output examples if present.
5. **Point out common usage errors** for developers.
6. **Condense this information** into a concise summary.

Based on the code, it appears this file is responsible for managing resources used by the HTML `<canvas>` element. It deals with both software (CPU-based) and hardware (GPU-based) rendering, utilizing Skia and potentially shared memory/images for optimization.
这是 `blink/renderer/platform/graphics/canvas_resource_provider.cc` 文件的第一部分，它主要负责 **管理和提供用于 HTML Canvas 元素渲染的图形资源**。

**功能归纳:**

1. **资源管理:**  `CanvasResourceProvider` 及其子类负责创建、持有、回收和管理 Canvas 渲染所需的图形资源，例如 Skia Surface、纹理、共享内存位图等。
2. **渲染目标抽象:** 它抽象了不同的 Canvas 渲染目标，例如：
    * **Bitmap:**  基于系统内存的位图渲染。
    * **SharedBitmap:**  基于共享内存的位图渲染，用于直接传递到合成器。
    * **SharedImage:**  基于 GPU 共享图像的渲染，利用 GPU 加速。
    * **PassThrough:** 用于处理外部导入的 Canvas 资源。
3. **硬件/软件渲染支持:**  它支持 Canvas 的硬件加速 (GPU) 和软件 (CPU) 渲染，并根据环境选择合适的渲染方式。
4. **资源同步和共享:**  处理多线程环境下的资源同步，尤其是在使用共享内存或共享图像时，确保数据一致性。
5. **Snapshot 功能:**  提供 Canvas 内容的快照功能，生成可以用于其他操作的 `StaticBitmapImage` 对象。
6. **GPU 上下文管理:**  在 GPU 加速模式下，管理与 GPU 上下文的交互，包括上下文丢失处理。
7. **内存管理:**  通过跟踪和回收不使用的资源来管理 Canvas 的内存使用。
8. **与 Compositor 集成:**  提供资源给 Chromium 的合成器 (Compositor) 进行最终的页面渲染。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**  JavaScript 代码通过 Canvas API (如 `getContext('2d')`) 来操作 Canvas 元素。 `CanvasResourceProvider` 负责在底层为这些 API 调用提供渲染资源。 例如，当 JavaScript 调用 `canvasContext.drawImage()` 时，`CanvasResourceProvider` 提供的资源将被用于绘制图像。
* **HTML:**  `<canvas>` 标签在 HTML 中定义了一个绘图区域。 `CanvasResourceProvider` 为这个绘图区域提供实际的渲染能力。
* **CSS:** CSS 可以影响 Canvas 元素的尺寸和样式，但 `CanvasResourceProvider` 主要关注的是 Canvas 内部的渲染资源管理，与 CSS 的直接功能关联较少。

**逻辑推理 (假设输入与输出):**

假设 JavaScript 代码在 Canvas 上绘制了一个矩形：

* **假设输入:**  JavaScript 调用 `canvasContext.fillRect(10, 10, 50, 50)`。
* **逻辑推理:**
    *  `CanvasResourceProvider` 会确保当前有一个可用的渲染目标 (例如，一个 Skia Surface)。
    *  Skia 库会被用来在这个 Surface 上绘制矩形。
    *  如果启用了硬件加速，绘制操作可能会在 GPU 上进行。
    *  绘制结果会被存储在 `CanvasResourceProvider` 管理的资源中。
* **输出:**  Canvas 元素在浏览器中显示一个填充的矩形。

**用户或编程常见的使用错误:**

* **在 GPU 上下文丢失后未处理资源:**  如果 GPU 上下文丢失，依赖于 GPU 资源的 Canvas 操作会失败。开发者需要监听 GPU 上下文丢失事件并采取适当的措施，例如重新创建 Canvas 或回退到软件渲染。`CanvasResourceProviderSharedBitmap` 中通过 `BitmapGpuChannelLostObserver` 提供了部分处理机制。
* **过度创建 Canvas 对象:**  频繁创建和销毁 Canvas 对象会带来性能开销。 开发者应该尽量复用 Canvas 对象。
* **在 WebWorker 中不当使用 Canvas:**  某些类型的 `CanvasResourceProvider` 可能无法直接在 WebWorker 中使用，或者需要特殊的处理才能共享资源。

**总结:**

总而言之，`blink/renderer/platform/graphics/canvas_resource_provider.cc` 的核心职责是为 HTML Canvas 元素提供底层的图形资源管理和渲染支持，它根据不同的渲染需求和硬件环境，负责创建和维护合适的渲染目标，并处理资源同步和与 Chromium 合成器的集成。

### 提示词
```
这是目录为blink/renderer/platform/graphics/canvas_resource_provider.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"

#include <string>

#include "base/debug/dump_without_crashing.h"
#include "base/debug/stack_trace.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/observer_list.h"
#include "base/strings/stringprintf.h"
#include "base/task/bind_post_task.h"
#include "base/time/time.h"
#include "base/trace_event/memory_allocator_dump.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/process_memory_dump.h"
#include "build/build_config.h"
#include "cc/paint/decode_stashing_image_provider.h"
#include "cc/paint/display_item_list.h"
#include "cc/tiles/software_image_decode_cache.h"
#include "components/viz/common/resources/shared_image_format_utils.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/context_support.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "gpu/command_buffer/common/capabilities.h"
#include "gpu/command_buffer/common/gpu_memory_buffer_support.h"
#include "gpu/command_buffer/common/shared_image_capabilities.h"
#include "gpu/command_buffer/common/shared_image_trace_utils.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "gpu/config/gpu_driver_bug_workaround_type.h"
#include "gpu/config/gpu_feature_info.h"
#include "gpu/config/gpu_feature_type.h"
#include "skia/buildflags.h"
#include "skia/ext/legacy_display_globals.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_graphics_shared_image_interface_provider.h"
#include "third_party/blink/renderer/platform/graphics/accelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/canvas_color_params.h"
#include "third_party/blink/renderer/platform/graphics/canvas_deferred_paint_record.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/memory_managed_paint_canvas.h"
#include "third_party/blink/renderer/platform/graphics/memory_managed_paint_recorder.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/instrumentation/canvas_memory_dump_provider.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/skia/include/core/SkSurface.h"
#include "third_party/skia/include/gpu/GpuTypes.h"
#include "third_party/skia/include/gpu/ganesh/GrBackendSurface.h"
#include "third_party/skia/include/gpu/ganesh/GrDirectContext.h"
#include "third_party/skia/include/gpu/ganesh/GrTypes.h"
#include "third_party/skia/include/gpu/ganesh/SkSurfaceGanesh.h"
#include "third_party/skia/include/gpu/ganesh/gl/GrGLBackendSurface.h"
#include "third_party/skia/include/gpu/ganesh/gl/GrGLTypes.h"

namespace blink {

class FlushForImageListener {
  // With deferred rendering it's possible for a drawImage operation on a canvas
  // to trigger a copy-on-write if another canvas has a read reference to it.
  // This can cause serious regressions due to extra allocations:
  // crbug.com/1030108. FlushForImageListener keeps a list of all active 2d
  // contexts on a thread and notifies them when one is attempting copy-on
  // write. If the notified context has a read reference to the canvas
  // attempting a copy-on-write it then flushes so as to make the copy-on-write
  // unnecessary.
 public:
  static FlushForImageListener* GetFlushForImageListener();
  void AddObserver(CanvasResourceProvider* observer) {
    observers_.AddObserver(observer);
  }

  void RemoveObserver(CanvasResourceProvider* observer) {
    observers_.RemoveObserver(observer);
  }

  void NotifyFlushForImage(cc::PaintImage::ContentId content_id) {
    for (CanvasResourceProvider& obs : observers_)
      obs.OnFlushForImage(content_id);
  }

 private:
  friend class WTF::ThreadSpecific<FlushForImageListener>;
  base::ObserverList<CanvasResourceProvider> observers_;
};

static FlushForImageListener* GetFlushForImageListener() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(ThreadSpecific<FlushForImageListener>,
                                  flush_for_image_listener, ());
  return flush_for_image_listener;
}

namespace {

bool IsGMBAllowed(const SkImageInfo& info, const gpu::Capabilities& caps) {
  const gfx::Size size(info.width(), info.height());
  const gfx::BufferFormat buffer_format =
      viz::SinglePlaneSharedImageFormatToBufferFormat(
          viz::SkColorTypeToSinglePlaneSharedImageFormat(info.colorType()));
  return gpu::IsImageSizeValidForGpuMemoryBufferFormat(size, buffer_format) &&
         gpu::IsImageFromGpuMemoryBufferFormatSupported(buffer_format, caps);
}

}  // namespace

class CanvasResourceProvider::CanvasImageProvider : public cc::ImageProvider {
 public:
  CanvasImageProvider(cc::ImageDecodeCache* cache_n32,
                      cc::ImageDecodeCache* cache_f16,
                      const gfx::ColorSpace& target_color_space,
                      SkColorType target_color_type,
                      cc::PlaybackImageProvider::RasterMode raster_mode);
  CanvasImageProvider(const CanvasImageProvider&) = delete;
  CanvasImageProvider& operator=(const CanvasImageProvider&) = delete;
  ~CanvasImageProvider() override = default;

  // cc::ImageProvider implementation.
  cc::ImageProvider::ScopedResult GetRasterContent(
      const cc::DrawImage&) override;

  void ReleaseLockedImages() { locked_images_.clear(); }

 private:
  void CanUnlockImage(ScopedResult);
  void CleanupLockedImages();
  bool IsHardwareDecodeCache() const;

  cc::PlaybackImageProvider::RasterMode raster_mode_;
  bool cleanup_task_pending_ = false;
  Vector<ScopedResult> locked_images_;
  std::optional<cc::PlaybackImageProvider> playback_image_provider_n32_;
  std::optional<cc::PlaybackImageProvider> playback_image_provider_f16_;

  base::WeakPtrFactory<CanvasImageProvider> weak_factory_{this};
};

// * Renders to a Skia RAM-backed bitmap.
// * Mailboxing is not supported : cannot be directly composited.
class CanvasResourceProviderBitmap : public CanvasResourceProvider {
 public:
  CanvasResourceProviderBitmap(
      const SkImageInfo& info,
      cc::PaintFlags::FilterQuality filter_quality,
      base::WeakPtr<CanvasResourceDispatcher> resource_dispatcher,
      CanvasResourceHost* resource_host)
      : CanvasResourceProvider(kBitmap,
                               info,
                               filter_quality,
                               /*context_provider_wrapper=*/nullptr,
                               std::move(resource_dispatcher),
                               resource_host) {}

  ~CanvasResourceProviderBitmap() override = default;

  bool IsValid() const override { return GetSkSurface(); }
  bool IsAccelerated() const final { return false; }
  bool SupportsDirectCompositing() const override { return false; }

 private:
  scoped_refptr<CanvasResource> ProduceCanvasResource(FlushReason) override {
    return nullptr;  // Does not support direct compositing
  }

  scoped_refptr<StaticBitmapImage> Snapshot(
      FlushReason reason,
      ImageOrientation orientation) override {
    TRACE_EVENT0("blink", "CanvasResourceProviderBitmap::Snapshot");
    return SnapshotInternal(orientation, reason);
  }

  sk_sp<SkSurface> CreateSkSurface() const override {
    TRACE_EVENT0("blink", "CanvasResourceProviderBitmap::CreateSkSurface");

    const auto info = GetSkImageInfo().makeAlphaType(kPremul_SkAlphaType);
    const auto props = GetSkSurfaceProps();
    return SkSurfaces::Raster(info, &props);
  }
};

// * Renders to a shared memory bitmap.
// * Uses SharedBitmaps to pass frames directly to the compositor.
class CanvasResourceProviderSharedBitmap : public CanvasResourceProviderBitmap,
                                           public BitmapGpuChannelLostObserver {
 public:
  CanvasResourceProviderSharedBitmap(
      const SkImageInfo& info,
      cc::PaintFlags::FilterQuality filter_quality,
      base::WeakPtr<CanvasResourceDispatcher> resource_dispatcher,
      WebGraphicsSharedImageInterfaceProvider* shared_image_interface_provider,
      CanvasResourceHost* resource_host)
      : CanvasResourceProviderBitmap(info,
                                     filter_quality,
                                     std::move(resource_dispatcher),
                                     resource_host),
        shared_image_interface_provider_(
            shared_image_interface_provider
                ? shared_image_interface_provider->GetWeakPtr()
                : nullptr) {
    DCHECK(ResourceDispatcher());
    type_ = kSharedBitmap;

    if (shared_image_interface_provider_) {
      shared_image_interface_provider_->AddGpuChannelLostObserver(this);
    }
  }

  ~CanvasResourceProviderSharedBitmap() override {
    if (shared_image_interface_provider_) {
      shared_image_interface_provider_->RemoveGpuChannelLostObserver(this);
    }
  }

  // BitmapGpuChannelLostObserver implementation.
  void OnGpuChannelLost() override { resource_host()->NotifyGpuContextLost(); }

  bool IsValid() const final {
    return !IsSharedBitmapGpuChannelLost() && GetSkSurface();
  }

  bool SupportsDirectCompositing() const override { return true; }
  base::WeakPtr<WebGraphicsSharedImageInterfaceProvider>
      shared_image_interface_provider_;

  bool IsSharedBitmapGpuChannelLost() const override {
    return !shared_image_interface_provider_ ||
           !shared_image_interface_provider_->SharedImageInterface();
  }

 private:
  scoped_refptr<CanvasResource> CreateResource() final {
    SkImageInfo info = GetSkImageInfo();
    if (!viz::SkColorTypeToSinglePlaneSharedImageFormat(info.colorType())
             .IsBitmapFormatSupported()) {
      // If the rendering format is not supported, downgrade to 8-bits.
      // TODO(junov): Should we try 12-12-12-12 and 10-10-10-2?
      info = info.makeColorType(kN32_SkColorType);
    }

    return CanvasResourceSharedBitmap::Create(
        gfx::Size(info.width(), info.height()), info.colorInfo().colorType(),
        info.colorInfo().alphaType(), info.colorInfo().refColorSpace(),
        CreateWeakPtr(), shared_image_interface_provider_, FilterQuality());
  }

  scoped_refptr<CanvasResource> ProduceCanvasResource(
      FlushReason reason) final {
    DCHECK(GetSkSurface());
    scoped_refptr<CanvasResource> output_resource = NewOrRecycledResource();
    if (!output_resource)
      return nullptr;

    FlushCanvas(reason);

    // Note that the resource *must* be a CanvasResourceSharedBitmap as this
    // class creates CanvasResourceSharedBitmap instances exclusively.
    static_cast<CanvasResourceSharedBitmap*>(output_resource.get())
        ->UploadSoftwareRenderingResults(GetSkSurface());

    return output_resource;
  }
};

// * Renders to a SharedImage, which manages memory internally.
// * Layers are overlay candidates.
class CanvasResourceProviderSharedImage : public CanvasResourceProvider {
 public:
  CanvasResourceProviderSharedImage(
      const SkImageInfo& info,
      cc::PaintFlags::FilterQuality filter_quality,
      base::WeakPtr<WebGraphicsContext3DProviderWrapper>
          context_provider_wrapper,
      bool is_accelerated,
      gpu::SharedImageUsageSet shared_image_usage_flags,
      CanvasResourceHost* resource_host)
      : CanvasResourceProvider(kSharedImage,
                               info,
                               filter_quality,
                               std::move(context_provider_wrapper),
                               /*resource_dispatcher=*/nullptr,
                               resource_host),
        is_accelerated_(is_accelerated),
        shared_image_usage_flags_(shared_image_usage_flags),
        use_oop_rasterization_(is_accelerated && ContextProviderWrapper()
                                                     ->ContextProvider()
                                                     ->GetCapabilities()
                                                     .gpu_rasterization) {
    resource_ = NewOrRecycledResource();
    GetFlushForImageListener()->AddObserver(this);

    if (resource_)
      EnsureWriteAccess();
  }

  ~CanvasResourceProviderSharedImage() override {
    GetFlushForImageListener()->RemoveObserver(this);
    // Issue any skia work using this resource before destroying any buffer
    // that may have a reference in skia.
    if (is_accelerated_ && !use_oop_rasterization_)
      FlushGrContext();
  }

  bool IsAccelerated() const final { return is_accelerated_; }
  bool SupportsDirectCompositing() const override { return true; }
  bool IsValid() const final {
    if (!use_oop_rasterization_)
      return GetSkSurface() && !IsGpuContextLost();
    else
      return !IsGpuContextLost();
  }

  bool SupportsSingleBuffering() const override {
    return shared_image_usage_flags_.Has(
        gpu::SHARED_IMAGE_USAGE_CONCURRENT_READ_WRITE);
  }
  scoped_refptr<gpu::ClientSharedImage>
  GetBackingClientSharedImageForExternalWrite(
      gpu::SyncToken* internal_access_sync_token,
      gpu::SharedImageUsageSet required_shared_image_usages,
      bool* was_copy_performed) override {
    // This may cause the current resource and all cached resources to become
    // unusable. WillDrawInternal() will detect this case, drop all cached
    // resources, and copy the current resource to a newly-created resource
    // which will by definition be usable.
    shared_image_usage_flags_.PutAll(required_shared_image_usages);

    DCHECK(is_accelerated_);

    if (IsGpuContextLost())
      return nullptr;

    // End the internal write access before calling WillDrawInternal(), which
    // has a precondition that there should be no current write access on the
    // resource.
    EndWriteAccess();

    const CanvasResource* const original_resource = resource_.get();
    WillDrawInternal(false);
    if (was_copy_performed != nullptr) {
      *was_copy_performed = resource_.get() != original_resource;
    }

    // NOTE: The above invocation of WillDrawInternal() ensures that this
    // invocation of GetSyncToken() will generate a new sync token.
    if (internal_access_sync_token) {
      *internal_access_sync_token = resource_->GetSyncToken();
    }

    return resource_->GetClientSharedImage();
  }

  void EndExternalWrite(
      const gpu::SyncToken& external_write_sync_token) override {
    resource_->WaitSyncToken(external_write_sync_token);
  }

  gpu::SharedImageUsageSet GetSharedImageUsageFlags() const override {
    return shared_image_usage_flags_;
  }

  bool WritePixels(const SkImageInfo& orig_info,
                   const void* pixels,
                   size_t row_bytes,
                   int x,
                   int y) override {
    if (!use_oop_rasterization_) {
      return CanvasResourceProvider::WritePixels(orig_info, pixels, row_bytes,
                                                 x, y);
    }

    TRACE_EVENT0("blink", "CanvasResourceProviderSharedImage::WritePixels");
    if (IsGpuContextLost())
      return false;

    // TODO(crbug.com/352263194): This code calls WillDrawInternal(true)
    // followed immediately by GetBackingClientSharedImageForOverwrite(), which
    // calls WillDrawInternal(false). The former calls EnsureWriteAccess() and
    // then the latter immediately calls EndWriteAccess(). Figure out what is
    // actually intended here and either don't call the former (preserving
    // current behavior) or call resource()->GetClientSharedImage() rather than
    // the latter (if the current behavior is a bug).
    WillDrawInternal(true);
    RasterInterface()->WritePixels(
        GetBackingClientSharedImageForOverwrite()->mailbox(), x, y,
        resource()->GetClientSharedImage()->GetTextureTarget(),
        SkPixmap(orig_info, pixels, row_bytes));

    // If the overdraw optimization kicked in, we need to indicate that the
    // pixels do not need to be cleared, otherwise the subsequent
    // rasterizations will clobber canvas contents.
    if (x <= 0 && y <= 0 && orig_info.width() >= Size().width() &&
        orig_info.height() >= Size().height())
      is_cleared_ = true;

    return true;
  }

  scoped_refptr<CanvasResource> CreateResource() final {
    TRACE_EVENT0("blink", "CanvasResourceProviderSharedImage::CreateResource");
    if (IsGpuContextLost())
      return nullptr;

    CHECK(IsOriginTopLeft());
    const SkImageInfo& info = GetSkImageInfo();
    return CanvasResourceSharedImage::Create(
        gfx::Size(info.width(), info.height()), info.colorInfo().colorType(),
        info.colorInfo().alphaType(), info.colorInfo().refColorSpace(),
        ContextProviderWrapper(), CreateWeakPtr(), FilterQuality(),
        is_accelerated_, shared_image_usage_flags_);
  }

  bool UseOopRasterization() final { return use_oop_rasterization_; }

  void NotifyTexParamsModified(const CanvasResource* resource) override {
    if (!is_accelerated_ || use_oop_rasterization_)
      return;

    if (resource_.get() == resource) {
      DCHECK(!current_resource_has_write_access_);
      // Note that the call below is guarenteed to not issue any GPU work for
      // the backend texture since we ensure that all skia work on the resource
      // is issued before releasing write access.
      auto tex = SkSurfaces::GetBackendTexture(
          surface_.get(), SkSurfaces::BackendHandleAccess::kFlushRead);
      GrBackendTextures::GLTextureParametersModified(&tex);
    }
  }

 protected:
  scoped_refptr<CanvasResource> ProduceCanvasResource(
      FlushReason reason) override {
    TRACE_EVENT0("blink",
                 "CanvasResourceProviderSharedImage::ProduceCanvasResource");
    if (IsGpuContextLost())
      return nullptr;

    FlushCanvas(reason);
    // Its important to end read access and ref the resource before the WillDraw
    // call below. Since it relies on resource ref-count to trigger
    // copy-on-write and asserts that we only have write access when the
    // provider has the only ref to the resource, to ensure there are no other
    // readers.
    EndWriteAccess();
    if (!resource_) {
      return nullptr;
    }
    scoped_refptr<CanvasResource> resource = resource_;
    resource->SetFilterQuality(FilterQuality());
    if (ContextProviderWrapper()
            ->ContextProvider()
            ->GetCapabilities()
            .disable_2d_canvas_copy_on_write) {
      // A readback operation may alter the texture parameters, which may affect
      // the compositor's behavior. Therefore, we must trigger copy-on-write
      // even though we are not technically writing to the texture, only to its
      // parameters. This issue is Android-WebView specific: crbug.com/585250.
      WillDraw();
    }

    return resource;
  }

  scoped_refptr<StaticBitmapImage> Snapshot(
      FlushReason reason,
      ImageOrientation orientation) override {
    TRACE_EVENT0("blink", "CanvasResourceProviderSharedImage::Snapshot");
    if (!IsValid())
      return nullptr;

    // We don't need to EndWriteAccess here since that's required to make the
    // rendering results visible on the GpuMemoryBuffer while we return cpu
    // memory, rendererd to by skia, here.
    if (!is_accelerated_)
      return SnapshotInternal(orientation, reason);

    if (!cached_snapshot_) {
      FlushCanvas(reason);
      EndWriteAccess();
      cached_snapshot_ = resource_->Bitmap();

      // We'll record its content_id to be used by the FlushForImageListener.
      // This will be needed in WillDrawInternal, but we are doing it now, as we
      // don't know if later on we will be in the same thread the
      // cached_snapshot_ was created and we wouldn't be able to
      // PaintImageForCurrentFrame in AcceleratedStaticBitmapImage just to check
      // the content_id. ShouldReplaceTargetBuffer needs this ID in order to let
      // other contexts know to flush to avoid unnecessary copy-on-writes.
      if (cached_snapshot_) {
        cached_content_id_ =
            cached_snapshot_->PaintImageForCurrentFrame().GetContentIdForFrame(
                0u);
      }
    }

    DCHECK(cached_snapshot_);
    DCHECK(!current_resource_has_write_access_);
    return cached_snapshot_;
  }

  void WillDrawIfNeeded() final {
    if (cached_snapshot_) {
      WillDraw();
    }
  }

  void WillDrawInternal(bool write_to_local_texture) {
    DCHECK(resource_);

    if (IsGpuContextLost())
      return;

    // Since the resource will be updated, the cached snapshot is no longer
    // valid. Note that it is important to release this reference here to not
    // trigger copy-on-write below from the resource ref in the snapshot.
    // Note that this is valid for single buffered mode also, since while the
    // resource/mailbox remains the same, the snapshot needs an updated sync
    // token for these writes.
    cached_snapshot_.reset();

    // Determine if a copy is needed for accelerated resources. This could be
    // for one of two reasons: (1) copy-on-write is required, or (2) the
    // SharedImage usages with which this provider should create resources has
    // changed since this resource was created (this can occur, for example,
    // when a client requests the backing ClientSharedImage with a specific
    // required set of usages for an external write). Note that for
    // unaccelerated resources, neither of these apply: writes to the
    // SharedImage are deferred to ProduceCanvasResource and hence
    // copy-on-write is never needed here, and the set of SharedImage usages
    // doesn't change over the lifetime of the provider.
    if (is_accelerated_ && (ShouldReplaceTargetBuffer(cached_content_id_) ||
                            !IsResourceUsable(resource_.get()))) {
      cached_content_id_ = PaintImage::kInvalidContentId;
      DCHECK(!current_resource_has_write_access_)
          << "Write access must be released before sharing the resource";

      auto old_resource = std::move(resource_);
      auto* old_resource_shared_image =
          static_cast<CanvasResourceSharedImage*>(old_resource.get());

      if (!IsResourceUsable(old_resource.get())) {
        // If this resource has become unusable, all cached resources have also
        // become unusable. Drop them to ensure that a new usable resource gets
        // created in the below call to NewOrRecycledResource().
        ClearRecycledResources();
      }
      resource_ = NewOrRecycledResource();
      DCHECK(IsResourceUsable(resource_.get()));

      if (!use_oop_rasterization_) {
        TearDownSkSurface();
      }

      if (mode_ == SkSurface::kRetain_ContentChangeMode) {
        auto old_mailbox =
            old_resource_shared_image->GetClientSharedImage()->mailbox();
        auto mailbox = resource()->GetClientSharedImage()->mailbox();

        RasterInterface()->CopySharedImage(old_mailbox, mailbox, 0, 0, 0, 0,
                                           Size().width(), Size().height());
      } else if (use_oop_rasterization_) {
        // If we're not copying over the previous contents, we need to ensure
        // that the image is cleared on the next BeginRasterCHROMIUM.
        is_cleared_ = false;
      }

      // In non-OOPR mode we need to update the client side SkSurface with the
      // copied texture. Recreating SkSurface here matches the GPU process
      // behaviour that will happen in OOPR mode.
      if (!use_oop_rasterization_) {
        EnsureWriteAccess();
        GetSkSurface();
      }
      UMA_HISTOGRAM_BOOLEAN("Blink.Canvas.ContentChangeMode",
                            mode_ == SkSurface::kRetain_ContentChangeMode);
      mode_ = SkSurface::kRetain_ContentChangeMode;
    }

    if (write_to_local_texture)
      EnsureWriteAccess();
    else
      EndWriteAccess();

    if (resource()) {
      resource()->WillDraw();
    }
  }

  void WillDraw() override { WillDrawInternal(true); }

  void RasterRecord(cc::PaintRecord last_recording) override {
    if (!use_oop_rasterization_) {
      CanvasResourceProvider::RasterRecord(std::move(last_recording));
      return;
    }
    WillDrawInternal(true);
    const bool needs_clear = !is_cleared_;
    is_cleared_ = true;
    RasterRecordOOP(std::move(last_recording), needs_clear,
                    resource()->GetClientSharedImage()->mailbox());
  }

  bool ShouldReplaceTargetBuffer(
      PaintImage::ContentId content_id = PaintImage::kInvalidContentId) {
    // If the canvas is single buffered, concurrent read/writes to the resource
    // are allowed. Note that we ignore the resource lost case as well since
    // that only indicates that we did not get a sync token for read/write
    // synchronization which is not a requirement for single buffered canvas.
    if (IsSingleBuffered())
      return false;

    // If the resource was lost, we can not use it for writes again.
    if (resource()->IsLost())
      return true;

    // We have the only ref to the resource which implies there are no active
    // readers.
    if (resource_->HasOneRef())
      return false;

    // Its possible to have deferred work in skia which uses this resource. Try
    // flushing once to see if that releases the read refs. We can avoid a copy
    // by queuing this work before writing to this resource.
    if (is_accelerated_) {
      // Another context may have a read reference to this resource. Flush the
      // deferred queue in that context so that we don't need to copy.
      GetFlushForImageListener()->NotifyFlushForImage(content_id);

      if (!use_oop_rasterization_) {
        skgpu::ganesh::FlushAndSubmit(surface_);
      }
    }

    return !resource_->HasOneRef();
  }

  sk_sp<SkSurface> CreateSkSurface() const override {
    TRACE_EVENT0("blink", "CanvasResourceProviderSharedImage::CreateSkSurface");
    if (IsGpuContextLost() || !resource_)
      return nullptr;

    const auto props = GetSkSurfaceProps();
    if (is_accelerated_) {
      return SkSurfaces::WrapBackendTexture(
          GetGrContext(), CreateGrTextureForResource(),
          kTopLeft_GrSurfaceOrigin, 0 /* msaa_sample_count */,
          GetSkImageInfo().colorType(), GetSkImageInfo().refColorSpace(),
          &props);
    }

    // For software raster path, we render into cpu memory managed internally
    // by SkSurface and copy the rendered results to the GMB before dispatching
    // it to the display compositor.
    return SkSurfaces::Raster(resource_->CreateSkImageInfo(), &props);
  }

  GrBackendTexture CreateGrTextureForResource() const {
    DCHECK(is_accelerated_);

    return resource()->CreateGrTexture();
  }

  void FlushGrContext() {
    DCHECK(is_accelerated_);

    // The resource may have been imported and used in skia. Make sure any
    // operations using this resource are flushed to the underlying context.
    // Note that its not sufficient to flush the SkSurface here since it will
    // only perform a GrContext flush if that SkSurface has any pending ops. And
    // this resource may be written to or read from skia without using the
    // SkSurface here.
    if (IsGpuContextLost())
      return;
    GetGrContext()->flushAndSubmit();
  }

  void EnsureWriteAccess() {
    DCHECK(resource_);
    // In software mode, we don't need write access to the resource during
    // drawing since it is executed on cpu memory managed by skia. We ensure
    // exclusive access to the resource when the results are copied onto the
    // GMB in EndWriteAccess.
    DCHECK(resource_->HasOneRef() || IsSingleBuffered() || !is_accelerated_)
        << "Write access requires exclusive access to the resource";
    DCHECK(!resource()->is_cross_thread())
        << "Write access is only allowed on the owning thread";

    if (current_resource_has_write_access_ || IsGpuContextLost())
      return;

    if (is_accelerated_ && !use_oop_rasterization_) {
      resource()->BeginWriteAccess();
    }

    // For the non-accelerated path, we don't need a texture for writes since
    // its on the CPU, but we set this bit to know whether the GMB needs to be
    // updated.
    current_resource_has_write_access_ = true;
  }

  void EndWriteAccess() {
    DCHECK(!resource()->is_cross_thread());

    if (!current_resource_has_write_access_ || IsGpuContextLost())
      return;

    if (is_accelerated_) {
      // We reset |mode_| here since the draw commands which overwrite the
      // complete canvas must have been flushed at this point without triggering
      // copy-on-write.
      mode_ = SkSurface::kRetain_ContentChangeMode;

      if (!use_oop_rasterization_) {
        // Issue any skia work using this resource before releasing write
        // access.
        FlushGrContext();
        resource()->EndWriteAccess();
      }
    } else {
      // Currently we never use OOP raster when the resource is not accelerated
      // so we check that assumption here.
      DCHECK(!use_oop_rasterization_);
      if (ShouldReplaceTargetBuffer())
        resource_ = NewOrRecycledResource();
      if (!resource() || !GetSkSurface()) {
        return;
      }
      resource()->UploadSoftwareRenderingResults(GetSkSurface());
    }

    current_resource_has_write_access_ = false;
  }

  CanvasResourceSharedImage* resource() {
    return static_cast<CanvasResourceSharedImage*>(resource_.get());
  }
  const CanvasResourceSharedImage* resource() const {
    return static_cast<const CanvasResourceSharedImage*>(resource_.get());
  }

  // For WebGpu RecyclableCanvasResource.
  void OnAcquireRecyclableCanvasResource() override { EnsureWriteAccess(); }
  void OnDestroyRecyclableCanvasResource(
      const gpu::SyncToken& sync_token) override {
    // RecyclableCanvasResource should be the only one that holds onto
    // |resource_|.
    DCHECK(resource_->HasOneRef());
    resource_->WaitSyncToken(sync_token);
  }

  void OnFlushForImage(cc::PaintImage::ContentId content_id) override {
    CanvasResourceProvider::OnFlushForImage(content_id);
    if (cached_snapshot_ &&
        cached_snapshot_->PaintImageForCurrentFrame().GetContentIdForFrame(0) ==
            content_id) {
      // This handles the case where the cached snapshot is referenced by an
      // ImageBitmap that is being transferred to a worker.
      cached_snapshot_.reset();
    }
  }

 private:
  bool IsResourceUsable(CanvasResource* resource) final {
    // The only resources that should be coming in here are
    // CanvasResourceSharedImage instances, since that is the only type of
    // resource that this class creates.
    CHECK(resource->UsesClientSharedImage());
    return resource->GetClientSharedImage()->usage().HasAll(
        shared_image_usage_flags_);
  }

  void OnMemoryDump(base::trace_event::ProcessMemoryDump* pmd) override {
    std::string path = base::StringPrintf("canvas/ResourceProvider_0x%" PRIXPTR,
                                          reinterpret_cast<uintptr_t>(this));

    resource()->OnMemoryDump(pmd, path, GetSkImageInfo().bytesPerPixel());

    std::string cached_path = path + "/cached";
    for (const auto& canvas_resource : CanvasResources()) {
      auto* resource_pointer = static_cast<CanvasResourceSharedImage*>(
          canvas_resource.resource.get());
      // In single buffered mode, `resource_` is not removed from
      // `canvas_resources_`.
      if (resource_pointer == resource()) {
        continue;
      }
      resource_pointer->OnMemoryDump(pmd, cached_path,
                                     GetSkImageInfo().bytesPerPixel());
    }
  }

  const bool is_accelerated_;
  gpu::SharedImageUsageSet shared_image_usage_flags_;
  bool current_resource_has_write_access_ = false;
  const bool use_oop_rasterization_;
  bool is_cleared_ = false;
  scoped_refptr<CanvasResource> resource_;
  scoped_refptr<StaticBitmapImage> cached_snapshot_;
  PaintImage::ContentId cached_content_id_ = PaintImage::kInvalidContentId;
};

// This class does nothing except answering to ProduceCanvasResource() by piping
// it to NewOrRecycledResource().  This ResourceProvider is meant to be used
// with an imported external CanvasResource, and all drawing and lifetime logic
// must be kept at a higher level.
class CanvasResourceProviderPassThrough final : public CanvasResourceProvider {
 public:
  CanvasResourceProviderPassThrough(
      const SkImageInfo& info,
      cc::PaintFlags::FilterQuality filter_quality,
      base::WeakPtr<WebGraphicsContext3DProviderWrapper>
          context_provi
```