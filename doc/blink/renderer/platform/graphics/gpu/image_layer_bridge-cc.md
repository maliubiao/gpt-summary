Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

**1. Initial Understanding of the File and its Purpose:**

The file name `image_layer_bridge.cc` immediately suggests its function: acting as an intermediary or bridge. The location in the `blink/renderer/platform/graphics/gpu/` directory indicates it deals with graphics, GPU interactions, and is part of the Blink rendering engine. The `#include` directives confirm this, bringing in concepts like `cc::TextureLayer`, `viz::TransferableResource`, and `gpu::SharedImageInterface`. The core idea is likely managing how images are displayed on screen using the GPU.

**2. Identifying Core Functionality:**

A quick scan reveals the `ImageLayerBridge` class. Its constructor, destructor, and methods like `SetImage`, `SetFilterQuality`, `SetUV`, `Dispose`, and `PrepareTransferableResource` are key. These suggest it's responsible for:

* **Holding an image:**  The `image_` member.
* **Creating and managing a compositing layer:** The `layer_` (a `cc::TextureLayer`).
* **Transferring image data to the compositor:**  The `PrepareTransferableResource` method.
* **Releasing resources:** The `Dispose` method and the resource release callbacks.
* **Handling different compositing modes:** GPU and software.

**3. Dissecting Key Methods (Especially `PrepareTransferableResource`):**

This is the most complex and crucial method. The code branches based on `gpu_compositing`.

* **GPU Compositing Path:**
    * It attempts to create an accelerated (GPU-backed) version of the image using `MakeAccelerated`.
    * It obtains a mailbox (a GPU resource handle) for the image.
    * It creates a `viz::TransferableResource` of type `MakeGpu`, encapsulating the mailbox and other GPU-related information.
    * It sets up a release callback (`ResourceReleasedGpu`) to handle the eventual release of the GPU resource.

* **Software Compositing Path:**
    * It retrieves the software-backed `SkImage`.
    * It allocates or recycles a `cc::CrossThreadSharedBitmap` to hold the image data in shared memory.
    * It copies the image data into the shared memory.
    * It creates a `viz::TransferableResource` of type `MakeSoftwareSharedBitmap` or `MakeSoftwareSharedImage`.
    * It sets up a release callback (`ResourceReleasedSoftware`) to handle the release of the shared memory.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

This requires understanding how the rendering pipeline works.

* **HTML:**  The `<img>` tag is the most direct connection. The `ImageLayerBridge` would be involved in rendering the image content of an `<img>` element.
* **CSS:** Styles like `opacity`, `filter`, and `transform` can influence how the image is rendered. The `ImageLayerBridge` respects the `opacity_mode_` and allows setting filter quality. Transformations are likely handled by the `cc::TextureLayer` it manages.
* **JavaScript:**  The Canvas API (`<canvas>`) is explicitly mentioned in the comments and code (e.g., `CanvasResourceProvider`). JavaScript can manipulate canvas elements, and the `ImageLayerBridge` would be involved when the canvas content needs to be displayed as an image layer. The `ImageBitmap` API is also mentioned in the context of WebGL interoperability.

**5. Identifying Assumptions and Inputs/Outputs:**

Focus on `PrepareTransferableResource`.

* **Assumptions:**  The method assumes it has a valid `image_` to work with. It also assumes the existence of the GPU context (if GPU compositing is enabled).
* **Inputs:** The state of the `ImageLayerBridge` (e.g., the current `image_`), whether GPU compositing is enabled.
* **Outputs:** A `viz::TransferableResource` (containing either GPU mailbox info or shared memory info) and a `viz::ReleaseCallback`.

**6. Identifying Potential User/Programming Errors:**

Think about how a developer using this (indirectly through higher-level APIs) could cause issues.

* **Setting an invalid image:**  The code checks for a null `PaintImageForCurrentFrame`, indicating potential issues during image creation.
* **Not disposing of the bridge:**  Resource leaks could occur if `Dispose()` isn't called.
* **Unexpected GPU context loss:** The code handles situations where the WebGL context is lost.
* **Mixing opaque and transparent images inappropriately:** While the code tries to manage opacity, incorrect usage at higher levels could lead to unexpected blending.

**7. Structuring the Answer:**

Organize the findings into clear sections as requested by the prompt:

* **Functionality:** Describe the core responsibilities of the class.
* **Relationship to Web Technologies:** Provide concrete examples linking the code to HTML, CSS, and JavaScript.
* **Logical Reasoning (Assumptions/Inputs/Outputs):** Focus on the `PrepareTransferableResource` method.
* **Common Errors:**  Highlight potential mistakes users or programmers could make.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This just moves image data to the GPU."  **Correction:** It also handles software compositing and the details of resource management and synchronization.
* **Initial thought:** "The connection to JavaScript is only through Canvas." **Correction:**  `<img>` tags and `ImageBitmap` are also relevant.
* **Focusing too much on low-level details:**  Need to connect the low-level operations to the higher-level concepts of web page rendering.

By following this structured thought process, analyzing the code snippets, and connecting them to broader web development concepts, a comprehensive and accurate answer can be constructed.
好的，让我们来分析一下 `blink/renderer/platform/graphics/gpu/image_layer_bridge.cc` 这个文件的功能。

**主要功能:**

`ImageLayerBridge` 的主要功能是**在 Blink 渲染引擎中，将 `StaticBitmapImage` 对象（代表位图图像）转换为可以在合成线程（Compositor Thread）上使用的纹理图层（Texture Layer）的资源。**  它充当了图像数据和 GPU 图层之间的桥梁。

更具体地说，它的职责包括：

1. **管理图像数据:** 接收 `StaticBitmapImage` 对象，并持有其引用。
2. **创建和配置合成图层:**  创建一个 `cc::TextureLayer` 对象，并根据图像的属性（例如，是否透明）进行必要的配置，例如设置 `ContentsOpaque` 和 `BlendBackgroundColor`。
3. **准备可传输的资源:** 这是核心功能。`PrepareTransferableResource` 方法负责将 `StaticBitmapImage` 的数据转换为 `viz::TransferableResource`，以便它可以被发送到合成器线程进行绘制。这个过程可能涉及：
    * **GPU 加速:** 如果启用了 GPU 合成，它会将图像数据上传到 GPU，并创建一个指向 GPU 纹理的 mailbox。
    * **软件合成:** 如果没有启用 GPU 合成，它会将图像数据复制到共享内存中，并创建一个指向共享内存的句柄。
4. **资源释放:**  处理 GPU 资源或共享内存的释放，以防止内存泄漏。
5. **处理图像属性:**  例如，设置纹理的 UV 坐标（用于实现图像的部分显示或翻转），以及设置过滤质量（影响图像缩放时的平滑度）。

**与 JavaScript, HTML, CSS 的关系及举例:**

`ImageLayerBridge` 虽然是 C++ 代码，但它在 Web 页面的渲染过程中扮演着关键角色，因此与 JavaScript, HTML, CSS 的功能息息相关。

* **HTML (`<img>` 标签):**
    * 当浏览器解析到 `<img>` 标签时，会下载图片数据并创建一个 `StaticBitmapImage` 对象来表示该图片。
    * `ImageLayerBridge` 就负责将这个 `StaticBitmapImage` 转换为合成器线程可以使用的纹理图层，最终在屏幕上渲染出图片。
    * **举例:**  HTML 中有一个 `<img src="image.png">`，浏览器会创建一个 `ImageLayerBridge` 来处理 `image.png` 的渲染。

* **CSS (`background-image`, `opacity`, `filter`, `transform` 等):**
    * 当 CSS 样式中使用了 `background-image` 时，其背后的图片数据也会被表示为 `StaticBitmapImage`，并由 `ImageLayerBridge` 处理。
    * CSS 的 `opacity` 属性会影响图层的透明度，`ImageLayerBridge` 的构造函数中的 `opacity_mode_` 参数就与此相关。
    * CSS 的 `filter` 属性可以应用各种图像效果，虽然 `ImageLayerBridge` 本身不直接处理这些效果，但它提供的纹理图层是这些效果应用的基础。
    * CSS 的 `transform` 属性可以对元素进行旋转、缩放等变换，这些变换会作用在 `ImageLayerBridge` 创建的 `cc::TextureLayer` 上。
    * **举例:**  一个 `div` 元素的 CSS 样式为 `background-image: url(bg.jpg); opacity: 0.5;`。`ImageLayerBridge` 会处理 `bg.jpg` 的渲染，并且合成器会根据 `opacity: 0.5` 设置图层的透明度。

* **JavaScript (Canvas API, ImageBitmap API 等):**
    * 当 JavaScript 使用 Canvas API 绘制图像时，Canvas 的内容最终也会被转换为纹理图层进行渲染，`ImageLayerBridge` 可能会参与这个过程。
    * ImageBitmap API 允许 JavaScript 直接创建位图图像，这些图像也可以通过 `ImageLayerBridge` 转化为合成器线程的资源。
    * **举例:** JavaScript 代码在 Canvas 上绘制了一个图像 `ctx.drawImage(image, 0, 0)`。Blink 可能会使用 `ImageLayerBridge` 将 Canvas 的内容（包括绘制的图像）上传到 GPU 作为纹理。

**逻辑推理 (假设输入与输出):**

假设输入一个代表一张不透明 PNG 图片的 `StaticBitmapImage` 对象，并且 GPU 合成是启用的。

* **假设输入:**
    * `image`:  一个指向 `StaticBitmapImage` 对象的智能指针，该对象包含一张不透明 PNG 图片的数据，尺寸为 100x100 像素。
    * GPU 合成已启用。
* **逻辑推理过程:**
    1. `ImageLayerBridge::SetImage(image)` 被调用，设置了内部的 `image_` 成员。
    2. 当需要将该图像渲染到屏幕上时，会调用 `PrepareTransferableResource`。
    3. 由于 GPU 合成已启用，代码会尝试使用 `MakeAccelerated` 将 `image` 转换为 GPU 纹理。
    4. 如果转换成功，会从 GPU 获取一个 mailbox (GPU 纹理的标识符)。
    5. 创建一个 `viz::TransferableResource` 对象，类型为 `MakeGpu`，包含 mailbox、纹理目标、同步令牌、尺寸、格式等信息。
    6. 设置一个资源释放的回调函数 `ResourceReleasedGpu`。
* **输出:**
    * `out_resource`: 一个 `viz::TransferableResource` 对象，其类型为 GPU，包含了指向 GPU 上纹理的 mailbox 和其他相关信息。
    * `out_release_callback`: 一个指向 `ImageLayerBridge::ResourceReleasedGpu` 的回调函数，用于在合成器线程完成对该资源的使用后释放 GPU 资源。

如果 GPU 合成未启用，那么 `PrepareTransferableResource` 的逻辑会有所不同：

* **假设输入:**
    * 同上，一个指向不透明 PNG 图片的 `StaticBitmapImage` 对象，尺寸为 100x100 像素。
    * GPU 合成未启用。
* **逻辑推理过程:**
    1. `ImageLayerBridge::SetImage(image)` 被调用。
    2. 调用 `PrepareTransferableResource`。
    3. 由于 GPU 合成未启用，代码会尝试将 `image` 转换为非加速版本 (`image_->MakeUnaccelerated()`)。
    4. 创建或重用一个共享位图 (`cc::CrossThreadSharedBitmap`) 来存储图像数据。
    5. 将 `image` 的像素数据复制到共享位图的内存中。
    6. 创建一个 `viz::TransferableResource` 对象，类型为 `MakeSoftwareSharedBitmap` 或 `MakeSoftwareSharedImage`，包含共享位图的 ID、同步令牌、尺寸、格式等信息。
    7. 设置一个资源释放的回调函数 `ResourceReleasedSoftware`.
* **输出:**
    * `out_resource`: 一个 `viz::TransferableResource` 对象，其类型为 Software Shared Bitmap 或 Software Shared Image，包含了共享内存的句柄和相关信息.
    * `out_release_callback`: 一个指向 `ImageLayerBridge::ResourceReleasedSoftware` 的回调函数，用于在合成器线程完成使用后释放共享内存。

**用户或编程常见的使用错误举例:**

* **忘记调用 `Dispose()`:**  `ImageLayerBridge` 持有 GPU 资源或共享内存，如果对象不再使用时没有调用 `Dispose()` 方法来释放这些资源，可能会导致内存泄漏。
    * **错误示例:** 创建了一个 `ImageLayerBridge` 对象并设置了图像，但在对象生命周期结束时忘记调用 `Dispose()`。
* **在图像设置后立即进行可能触发 GPU 操作的操作，而没有等待合成:**  例如，在设置了图像后立即尝试强制刷新 GPU 上下文，可能会因为资源尚未完全准备好而导致错误。
    * **错误示例:**
    ```c++
    auto bridge = new ImageLayerBridge();
    bridge->SetImage(my_image);
    SharedGpuContext::ContextProvider()->ContextGL()->Flush(); // 可能过早调用
    ```
* **在非 GPU 合成模式下假设图像始终是纹理支持的:** 代码中可以看到对 `image_->IsTextureBacked()` 的检查，在软件合成模式下，图像可能不是纹理支持的。错误的假设可能导致逻辑错误。
* **多次 `SetImage` 但没有触发合成:** 如果连续多次调用 `SetImage` 但合成器没有及时处理，可能会导致不必要的资源分配和释放。代码中 `has_presented_since_last_set_image_` 这个标志就是用来优化这种情况的。
* **在不适当的时候修改 `cc::TextureLayer` 的属性:** 虽然 `ImageLayerBridge` 暴露了 `CcLayer()` 方法来获取底层的 `cc::TextureLayer` 对象，但直接修改该对象的某些属性可能会与 `ImageLayerBridge` 的内部逻辑冲突。

总而言之，`ImageLayerBridge` 是 Blink 渲染引擎中处理图像渲染的关键组件，它负责将各种来源的图像数据转化为可以在 GPU 或 CPU 上高效渲染的图层资源，并与浏览器的其他部分（包括 JavaScript, HTML, CSS）紧密配合，最终将图像呈现在用户面前。

### 提示词
```
这是目录为blink/renderer/platform/graphics/gpu/image_layer_bridge.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/gpu/image_layer_bridge.h"

#include "base/memory/read_only_shared_memory_region.h"
#include "cc/layers/texture_layer.h"
#include "cc/resources/cross_thread_shared_bitmap.h"
#include "components/viz/common/resources/bitmap_allocation.h"
#include "components/viz/common/resources/shared_bitmap.h"
#include "components/viz/common/resources/shared_image_format_utils.h"
#include "components/viz/common/resources/transferable_resource.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "gpu/command_buffer/client/shared_image_interface.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/public/platform/web_graphics_shared_image_interface_provider.h"
#include "third_party/blink/renderer/platform/graphics/accelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/canvas_color_params.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/color_behavior.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/image_orientation.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/gfx/geometry/size.h"

namespace blink {
namespace {

scoped_refptr<StaticBitmapImage> MakeAccelerated(
    const scoped_refptr<StaticBitmapImage>& source,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper>
        context_provider_wrapper) {
#if BUILDFLAG(IS_MAC)
  // On MacOS, if |source| is not an overlay candidate, it is worth copying it
  // to a new buffer that is an overlay candidate, even when |source| is
  // already on the GPU.
  if (source->IsOverlayCandidate()) {
#else
  if (source->IsTextureBacked()) {
#endif
    return source;
  }

  const auto paint_image = source->PaintImageForCurrentFrame();
  const auto image_info = paint_image.GetSkImageInfo().makeWH(
      source->Size().width(), source->Size().height());
#if BUILDFLAG(IS_LINUX)
  // TODO(b/330865436): On Linux, CanvasResourceProvider doesn't always check
  // for SCANOUT support correctly on X11 and it's never supported in
  // practice. Therefore, don't include it until this flow is reworked.
  constexpr gpu::SharedImageUsageSet kSharedImageUsageFlags =
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ;
#else
  // Always request gpu::SHARED_IMAGE_USAGE_SCANOUT when using gpu compositing,
  // if possible. This is safe because the prerequisite capabilities are checked
  // downstream in CanvasResourceProvider::CreateSharedImageProvider.
  constexpr gpu::SharedImageUsageSet kSharedImageUsageFlags =
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ | gpu::SHARED_IMAGE_USAGE_SCANOUT;
#endif  // BUILDFLAG(IS_LINUX)
  auto provider = CanvasResourceProvider::CreateSharedImageProvider(
      image_info, cc::PaintFlags::FilterQuality::kLow,
      CanvasResourceProvider::ShouldInitialize::kNo, context_provider_wrapper,
      RasterMode::kGPU, kSharedImageUsageFlags);
  if (!provider || !provider->IsAccelerated())
    return nullptr;

  cc::PaintFlags paint;
  paint.setBlendMode(SkBlendMode::kSrc);
  provider->Canvas().drawImage(paint_image, 0, 0, SkSamplingOptions(), &paint);
  return provider->Snapshot(FlushReason::kNon2DCanvas);
}

}  // namespace

ImageLayerBridge::ImageLayerBridge(OpacityMode opacity_mode)
    : opacity_mode_(opacity_mode) {
  layer_ = cc::TextureLayer::CreateForMailbox(this);
  layer_->SetIsDrawable(true);
  layer_->SetHitTestable(true);
  layer_->SetNearestNeighbor(false);
  if (opacity_mode_ == kOpaque) {
    layer_->SetContentsOpaque(true);
    layer_->SetBlendBackgroundColor(false);
  }
}

ImageLayerBridge::~ImageLayerBridge() {
  if (!disposed_)
    Dispose();
}

void ImageLayerBridge::SetImage(scoped_refptr<StaticBitmapImage> image) {
  if (disposed_)
    return;
  // There could be the case that the current PaintImage is null, meaning
  // that something went wrong during the creation of the image and we should
  // not try and setImage with it
  if (image && !image->PaintImageForCurrentFrame())
    return;

  image_ = std::move(image);
  if (image_) {
    if (opacity_mode_ == kNonOpaque) {
      layer_->SetContentsOpaque(image_->CurrentFrameKnownToBeOpaque());
      layer_->SetBlendBackgroundColor(!image_->CurrentFrameKnownToBeOpaque());
    }
    if (opacity_mode_ == kOpaque) {
      // If we in opaque mode but image might have transparency we need to
      // ensure its opacity is not used.
      layer_->SetForceTextureToOpaque(!image_->CurrentFrameKnownToBeOpaque());
    }
    if (!has_presented_since_last_set_image_ && image_->IsTextureBacked()) {
      // If the layer bridge is not presenting, the GrContext may not be getting
      // flushed regularly.  The flush is normally triggered inside the
      // m_image->EnsureMailbox() call of
      // ImageLayerBridge::PrepareTransferableResource. To prevent a potential
      // memory leak we must flush the GrContext here.
      image_->PaintImageForCurrentFrame().FlushPendingSkiaOps();
    }
  }
  has_presented_since_last_set_image_ = false;
}

void ImageLayerBridge::SetFilterQuality(
    cc::PaintFlags::FilterQuality filter_quality) {
  if (disposed_) {
    return;
  }

  layer_->SetNearestNeighbor(filter_quality ==
                             cc::PaintFlags::FilterQuality::kNone);
}

void ImageLayerBridge::SetUV(const gfx::PointF& left_top,
                             const gfx::PointF& right_bottom) {
  if (disposed_)
    return;

  layer_->SetUV(left_top, right_bottom);
}

void ImageLayerBridge::Dispose() {
  if (layer_) {
    layer_->ClearClient();
    layer_ = nullptr;
  }
  image_ = nullptr;
  disposed_ = true;
}

bool ImageLayerBridge::PrepareTransferableResource(
    viz::TransferableResource* out_resource,
    viz::ReleaseCallback* out_release_callback) {
  if (disposed_)
    return false;

  if (!image_)
    return false;

  if (has_presented_since_last_set_image_)
    return false;

  has_presented_since_last_set_image_ = true;

  const bool gpu_compositing = SharedGpuContext::IsGpuCompositingEnabled();

  if (!gpu_compositing) {
    // Readback if needed and retain the readback in image_ to prevent future
    // readbacks.
    // Note: Switching to unaccelerated may change the value of
    // image_->IsOriginTopLeft(), so it is important to make the switch before
    // calling IsOriginTopLeft().
    image_ = image_->MakeUnaccelerated();
    if (!image_) {
      return false;
    }
  }

  layer_->SetFlipped(!image_->IsOriginTopLeft());

  if (gpu_compositing) {
    scoped_refptr<StaticBitmapImage> image_for_compositor =
        MakeAccelerated(image_, SharedGpuContext::ContextProviderWrapper());
    if (!image_for_compositor || !image_for_compositor->ContextProvider())
      return false;

    auto mailbox_holder = image_for_compositor->GetMailboxHolder();

    if (mailbox_holder.mailbox.IsZero()) {
      // This can happen, for example, if an ImageBitmap is produced from a
      // WebGL-rendered OffscreenCanvas and then the WebGL context is forcibly
      // lost. This seems to be the only reliable point where this can be
      // detected.
      return false;
    }

    layer_->SetFlipped(!image_for_compositor->IsOriginTopLeft());

    const gfx::Size size(image_for_compositor->width(),
                         image_for_compositor->height());

    auto* sii = image_for_compositor->ContextProvider()->SharedImageInterface();
    bool is_overlay_candidate = sii->UsageForMailbox(mailbox_holder.mailbox)
                                    .Has(gpu::SHARED_IMAGE_USAGE_SCANOUT);

    SkColorType color_type = image_for_compositor->GetSkColorInfo().colorType();
    *out_resource = viz::TransferableResource::MakeGpu(
        mailbox_holder.mailbox, mailbox_holder.texture_target,
        mailbox_holder.sync_token, size,
        viz::SkColorTypeToSinglePlaneSharedImageFormat(color_type),
        is_overlay_candidate,
        viz::TransferableResource::ResourceSource::kImageLayerBridge);

    auto func = WTF::BindOnce(&ImageLayerBridge::ResourceReleasedGpu,
                              WrapWeakPersistent(this),
                              std::move(image_for_compositor));
    *out_release_callback = std::move(func);
  } else {
    sk_sp<SkImage> sk_image =
        image_->PaintImageForCurrentFrame().GetSwSkImage();
    if (!sk_image)
      return false;

    const gfx::Size size(image_->width(), image_->height());

    // Always convert to N32 format.  This is a constraint of the software
    // compositor.
    constexpr SkColorType dst_color_type = kN32_SkColorType;
    // TODO(vasilyt): this used to be
    // viz::SkColorTypeToResourceFormat(dst_color_type), but on some platforms
    // (including Mac), kN32_SkColorType is BGRA8888 which is disallowed as a
    // bitmap format. Deeper refactorings are needed to fix this properly; in
    // the meantime, force the use of viz::SinglePlaneFormat::kRGBA_8888 as the
    // resource format. This addresses assertion failures when serializing these
    // bitmaps to the GPU process.
    viz::SharedImageFormat format = viz::SinglePlaneFormat::kBGRA_8888;
    RegisteredBitmap registered = CreateOrRecycleBitmap(size, format);
    if (!registered.bitmap) {
      return false;
    }

    SkImageInfo dst_info =
        SkImageInfo::Make(size.width(), size.height(), dst_color_type,
                          kPremul_SkAlphaType, sk_image->refColorSpace());
    void* pixels = registered.bitmap->memory();

    // Copy from SkImage into SharedMemory owned by |registered|.
    if (!sk_image->readPixels(dst_info, pixels, dst_info.minRowBytes(), 0, 0))
      return false;

    if (registered.shared_image) {
      *out_resource = viz::TransferableResource::MakeSoftwareSharedImage(
          registered.shared_image, registered.sync_token, size, format,
          viz::TransferableResource::ResourceSource::kImageLayerBridge);
    } else {
      *out_resource = viz::TransferableResource::MakeSoftwareSharedBitmap(
          registered.bitmap->id(), gpu::SyncToken(), size, format,
          viz::TransferableResource::ResourceSource::kImageLayerBridge);
    }
    out_resource->color_space = sk_image->colorSpace()
                                    ? gfx::ColorSpace(*sk_image->colorSpace())
                                    : gfx::ColorSpace::CreateSRGB();
    auto func = WTF::BindOnce(&ImageLayerBridge::ResourceReleasedSoftware,
                              WrapWeakPersistent(this), std::move(registered));
    *out_release_callback = std::move(func);
  }

  return true;
}

ImageLayerBridge::RegisteredBitmap ImageLayerBridge::CreateOrRecycleBitmap(
    const gfx::Size& size,
    viz::SharedImageFormat format) {
  // Must call SharedImageInterfaceProvider() first so all base::WeakPtr
  // restored in |registered.sii_provider| is updated.
  auto* sii_provider = SharedGpuContext::SharedImageInterfaceProvider();
  DCHECK(sii_provider);
  auto it = std::remove_if(recycled_bitmaps_.begin(), recycled_bitmaps_.end(),
                           [&size](const RegisteredBitmap& registered) {
                             return registered.bitmap->size() != size ||
                                    !registered.sii_provider;
                           });

  recycled_bitmaps_.Shrink(
      static_cast<wtf_size_t>(it - recycled_bitmaps_.begin()));

  if (!recycled_bitmaps_.empty()) {
    RegisteredBitmap registered = std::move(recycled_bitmaps_.back());
    recycled_bitmaps_.pop_back();
    return registered;
  }

  // There are no bitmaps to recycle so allocate a new one.
  RegisteredBitmap registered;
  auto* shared_image_interface = sii_provider->SharedImageInterface();
  if (!shared_image_interface) {
    return registered;
  }
  auto shared_image_mapping = shared_image_interface->CreateSharedImage(
      {format, size, gfx::ColorSpace(), gpu::SHARED_IMAGE_USAGE_CPU_WRITE,
       "ImageLayerBridgeBitmap"});

  registered.sii_provider = sii_provider->GetWeakPtr();
  registered.sync_token = shared_image_interface->GenVerifiedSyncToken();
  registered.shared_image = std::move(shared_image_mapping.shared_image);
  registered.bitmap = base::MakeRefCounted<cc::CrossThreadSharedBitmap>(
      viz::SharedBitmapId(), base::ReadOnlySharedMemoryRegion(),
      std::move(shared_image_mapping.mapping), size, format);

  return registered;
}

void ImageLayerBridge::ResourceReleasedGpu(
    scoped_refptr<StaticBitmapImage> image,
    const gpu::SyncToken& token,
    bool lost_resource) {
  if (image && image->IsValid()) {
    DCHECK(image->IsTextureBacked());
    if (token.HasData() && image->ContextProvider() &&
        image->ContextProvider()->InterfaceBase()) {
      image->ContextProvider()->InterfaceBase()->WaitSyncTokenCHROMIUM(
          token.GetConstData());
    }
  }
  // let 'image' go out of scope to release gpu resources.
}

void ImageLayerBridge::ResourceReleasedSoftware(
    RegisteredBitmap registered,
    const gpu::SyncToken& sync_token,
    bool lost_resource) {
  if (!disposed_ && !lost_resource) {
    recycled_bitmaps_.push_back(std::move(registered));
  }
}

cc::Layer* ImageLayerBridge::CcLayer() const {
  return layer_.get();
}

ImageLayerBridge::RegisteredBitmap::RegisteredBitmap() = default;
ImageLayerBridge::RegisteredBitmap::RegisteredBitmap(RegisteredBitmap&& other) =
    default;
ImageLayerBridge::RegisteredBitmap& ImageLayerBridge::RegisteredBitmap::
operator=(RegisteredBitmap&& other) = default;

}  // namespace blink
```