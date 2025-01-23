Response:
Let's break down the thought process for analyzing this C++ source code.

1. **Understand the Goal:** The request asks for the functionality of the `AcceleratedStaticBitmapImage` class, its relation to web technologies (JavaScript, HTML, CSS), and examples of logic, usage errors, and input/output.

2. **Initial Scan and Keywords:**  Start by quickly reading through the code, looking for keywords and class names. Key terms jump out: `Accelerated`, `StaticBitmapImage`, `SharedImage`, `Mailbox`, `Texture`, `SkImage`, `Canvas`, `GLES2`, `RasterInterface`, `SyncToken`. These immediately suggest this class is about managing images in the GPU, likely for rendering in the browser. The inheritance from `StaticBitmapImage` implies a base class for bitmap images.

3. **Identify Core Functionality (What does the class *do*?):**  Focus on the public methods and their names.

    * `CreateFromCanvasSharedImage`:  Creates an image from a canvas's shared image. This links directly to the `<canvas>` element in HTML.
    * `CreateFromExternalMailbox`: Creates an image from an external GPU mailbox. This suggests inter-process or inter-context sharing of textures.
    * `ReleaseTexture`: A static helper for releasing GPU textures.
    * `GetSkImageInfo`: Returns image information (dimensions, color type, etc.).
    * `MakeUnaccelerated`: Creates a CPU-based version of the image. This is important for fallback scenarios or operations not suitable for the GPU.
    * `CopyToTexture`: Copies the image to another GPU texture.
    * `CopyToResourceProvider`:  Copies the image to a `CanvasResourceProvider`. This seems like a Blink-specific abstraction for managing canvas resources.
    * `PaintImageForCurrentFrame`:  Prepares the image for painting within Blink's rendering pipeline. The return type `PaintImage` is a strong indicator of this.
    * `Draw`:  Draws the image onto a `cc::PaintCanvas`. This is part of the Chromium Compositor (cc) and crucial for rendering.
    * `IsValid`: Checks if the image is in a valid state (GPU resources are available).
    * `ContextProvider`/`ContextProviderWrapper`: Provides access to the GPU context.
    * `CreateImageFromMailboxIfNeeded`/`InitializeTextureBacking`:  Handles the creation of the Skia `SkImage` from the underlying GPU texture. The "if needed" suggests lazy initialization.
    * `EnsureSyncTokenVerified`: Manages synchronization between the CPU and GPU.
    * `GetMailboxHolder`/`GetSharedImage`/`GetSyncToken`:  Provide access to the underlying GPU resources.
    * `Transfer`: Likely related to moving the image ownership or resources (perhaps across threads).
    * `CurrentFrameKnownToBeOpaque`: An optimization hint for rendering.
    * `GetUsage`:  Returns the GPU usage flags.

4. **Connect to Web Technologies:**

    * **HTML `<canvas>`:** The `CreateFromCanvasSharedImage` method directly relates to this. When JavaScript draws on a canvas, the underlying data can be represented as a shared image accessible to the GPU.
    * **CSS `background-image`, `content`, `mask-image`:**  These properties can use images. While this class doesn't directly *load* images from URLs, it's a core part of how *rendered* images (including those from CSS) are handled on the GPU.
    * **JavaScript (Canvas API, OffscreenCanvas):**  The Canvas API is the primary way JavaScript interacts with the `<canvas>` element. OffscreenCanvas further enables GPU-accelerated rendering in background threads. The methods here are the *implementation details* of how those APIs achieve GPU acceleration.

5. **Logic Reasoning (Hypothetical Input/Output):**

    * Focus on methods that transform or process data. `MakeUnaccelerated` is a good example:
        * **Input:** An `AcceleratedStaticBitmapImage` object potentially backed by a GPU texture.
        * **Output:** An `UnacceleratedStaticBitmapImage` object backed by CPU memory (an `SkImage` in CPU mode).
    * Consider drawing:
        * **Input:**  `AcceleratedStaticBitmapImage`, `cc::PaintCanvas`, drawing parameters (rectangles, flags).
        * **Output:**  The image is drawn onto the canvas. The state of the canvas changes.

6. **Common Usage Errors:** Think about scenarios where developers might misuse this class or its underlying concepts.

    * **Incorrect Sync Token Handling:**  Messing with sync tokens can lead to race conditions and rendering artifacts.
    * **Accessing After Release:**  Trying to use the `AcceleratedStaticBitmapImage` after its resources have been freed is a classic error.
    * **Cross-Context Issues:**  If an image is created in one GPU context and used in another without proper transfer mechanisms, it will fail.
    * **Premultiplied Alpha Confusion:**  Misunderstanding how alpha is handled can lead to incorrect blending.

7. **Refine and Organize:**  Structure the findings logically. Start with a general overview of functionality, then delve into specific aspects like web technology connections, logic, and potential errors. Use clear and concise language. The bullet points in the final answer help with readability.

8. **Review and Verify:**  Read through the generated response and double-check against the source code to ensure accuracy and completeness. Are there any obvious omissions?  Is the language clear and understandable?

Self-Correction Example during the process:

* **Initial Thought:**  "This class directly loads images from the network."
* **Correction:**  Upon closer inspection, the code deals with *already loaded* or *created* image data (from canvas, external mailboxes). It doesn't handle the loading process itself. Adjust the description accordingly.
* **Initial Thought:** "The `Draw` method directly interacts with the browser's display."
* **Correction:** The `Draw` method draws onto a `cc::PaintCanvas`, which is an abstraction used by the Chromium Compositor. The compositor then handles the final rendering to the screen. Clarify the role of the compositor.
这个C++源代码文件 `accelerated_static_bitmap_image.cc` 定义了 `AcceleratedStaticBitmapImage` 类，它是 Blink 渲染引擎中用于表示 GPU 加速的静态位图图像的。 它的主要功能是：

**核心功能:**

1. **管理 GPU 加速的位图图像:**  `AcceleratedStaticBitmapImage` 类负责管理存储在 GPU 内存中的位图图像数据。它使用 `gpu::ClientSharedImage` 来持有共享的图像资源。

2. **创建 GPU 纹理:**  它可以基于共享的图像数据创建 GPU 纹理，以便在 GPU 上进行高效渲染。

3. **与其他 GPU 资源交互:**  它能够与其他 GPU 资源进行交互，例如通过 `gpu::gles2::GLES2Interface` 进行纹理拷贝，或者通过 `CanvasResourceProvider` 将图像数据传递给 Canvas 相关的资源。

4. **提供 Skia Image 接口:**  它内部维护一个 `SkImage` 对象，该对象基于 GPU 纹理创建，并提供了 Skia 图形库的接口，以便进行各种图像操作和渲染。

5. **支持跨线程访问:**  通过 `MailboxRef` 和 `gpu::SyncToken` 机制，它允许在不同的线程之间安全地共享和访问 GPU 图像资源。

6. **支持 Display Compositing 和 Overlay:**  该类可以指示图像是否适合用于 Display Compositing 或 Overlay，这有助于浏览器进行性能优化。

7. **提供非加速版本的转换:**  可以将其转换为非加速的 `UnacceleratedStaticBitmapImage` 版本，用于在不支持 GPU 加速的环境或者需要进行 CPU 操作时使用。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

`AcceleratedStaticBitmapImage` 类是 Blink 渲染流水线中的关键组件，它直接参与了网页内容的渲染，因此与 JavaScript, HTML, CSS 都有密切的关系：

* **HTML `<canvas>` 元素:**
    * **功能关系:** 当 JavaScript 代码在 `<canvas>` 元素上进行绘制时，Blink 可以选择将绘制结果存储为 GPU 加速的图像。 `AcceleratedStaticBitmapImage::CreateFromCanvasSharedImage` 方法就是用于从 Canvas 的共享图像中创建加速位图图像。
    * **举例说明:**  假设 JavaScript 代码在 Canvas 上绘制了一个复杂的图形：
      ```javascript
      const canvas = document.getElementById('myCanvas');
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = 'blue';
      ctx.fillRect(10, 10, 100, 100);
      // ... 更多绘制操作
      ```
      Blink 可能会将 Canvas 的内容创建为 `AcceleratedStaticBitmapImage`，以便后续的渲染操作可以利用 GPU 加速。

* **CSS `background-image`, `content`, `mask-image` 等属性:**
    * **功能关系:** 当 CSS 属性引用图像资源（例如 PNG, JPEG）时，Blink 会解码这些图像，并可能将其存储为 `AcceleratedStaticBitmapImage` 以便进行高效的渲染和合成。
    * **举例说明:**
      ```css
      .my-div {
        background-image: url('image.png');
      }
      ```
      当浏览器加载并解码 `image.png` 后，可能会将其创建为 `AcceleratedStaticBitmapImage`。

* **JavaScript `Image` 对象和 `drawImage()` 方法:**
    * **功能关系:**  当 JavaScript 使用 `Image` 对象加载图像，并通过 `drawImage()` 方法将其绘制到 Canvas 上时，加载的图像数据最终也可能被表示为 `AcceleratedStaticBitmapImage`。
    * **举例说明:**
      ```javascript
      const img = new Image();
      img.onload = function() {
        ctx.drawImage(img, 0, 0);
      };
      img.src = 'another_image.jpg';
      ```
      `another_image.jpg` 加载后，Blink 内部可能会创建 `AcceleratedStaticBitmapImage` 来管理其 GPU 资源。

**逻辑推理和假设输入与输出:**

假设有一个 `AcceleratedStaticBitmapImage` 对象 `image`，它持有一个在 GPU 上的蓝色正方形图像。

* **假设输入:** 调用 `image->PaintImageForCurrentFrame()` 方法。
* **逻辑推理:**  该方法会创建一个 `PaintImage` 对象，其中包含了指向 GPU 纹理的引用 (`texture_backing_`) 和同步令牌 (`paint_image_content_id_`)。
* **假设输出:** 返回一个 `PaintImage` 对象，该对象可用于在 Blink 的渲染流水线中绘制该蓝色正方形。

* **假设输入:** 调用 `image->MakeUnaccelerated()` 方法。
* **逻辑推理:** 该方法会将 GPU 上的图像数据拷贝到 CPU 内存，并创建一个新的 `UnacceleratedStaticBitmapImage` 对象。
* **假设输出:** 返回一个新的 `UnacceleratedStaticBitmapImage` 对象，该对象包含蓝色正方形的 CPU 内存表示。

**用户或编程常见的使用错误:**

1. **在错误的线程访问:**  `AcceleratedStaticBitmapImage` 内部使用了线程检查 (`DCHECK_CALLED_ON_VALID_THREAD`)，如果在创建或主要操作的线程之外访问，可能会导致崩溃或未定义的行为。
    * **错误示例:** 在一个线程中创建了 `AcceleratedStaticBitmapImage` 对象，然后在另一个线程中调用其 `Draw` 方法。

2. **在资源释放后访问:**  一旦 `AcceleratedStaticBitmapImage` 相关的 GPU 资源被释放（例如，由于页面卸载或图像被销毁），继续使用该对象会导致错误。
    * **错误示例:**  持有 `AcceleratedStaticBitmapImage` 指针，但在其关联的 `gpu::ClientSharedImage` 被释放后仍然尝试调用其方法。

3. **不正确的同步处理:**  在跨线程使用时，如果没有正确处理 `gpu::SyncToken`，可能会导致渲染不同步或数据竞争。
    * **错误示例:**  在一个线程中修改了共享图像，但在另一个线程渲染之前没有等待同步令牌。

4. **假设纹理总是立即可用:**  GPU 操作是异步的，纹理可能需要一些时间才能真正上传到 GPU。直接使用未完成上传的纹理可能会导致渲染错误。
    * **错误示例:**  创建 `AcceleratedStaticBitmapImage` 后立即尝试用它进行绘制，而没有等待 `mailbox_ref_->sync_token()` 完成。

5. **忘记考虑 `IsValid()` 的返回值:** 在使用 `AcceleratedStaticBitmapImage` 之前，应该检查 `IsValid()` 的返回值，以确保其内部的 GPU 资源仍然有效。
    * **错误示例:**  直接调用 `PaintImageForCurrentFrame()` 而没有先检查 `IsValid()`。

总之，`AcceleratedStaticBitmapImage` 是 Blink 渲染引擎中一个重要的类，它负责管理和操作 GPU 加速的位图图像，并在网页内容的渲染过程中发挥着至关重要的作用。正确理解和使用它可以显著提升网页的渲染性能。

### 提示词
```
这是目录为blink/renderer/platform/graphics/accelerated_static_bitmap_image.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/accelerated_static_bitmap_image.h"

#include <memory>
#include <utility>

#include "base/task/single_thread_task_runner.h"
#include "components/viz/common/resources/release_callback.h"
#include "components/viz/common/resources/shared_image_format_utils.h"
#include "gpu/GLES2/gl2extchromium.h"
#include "gpu/command_buffer/client/gles2_interface.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "gpu/command_buffer/client/shared_image_interface.h"
#include "gpu/command_buffer/common/capabilities.h"
#include "gpu/command_buffer/common/shared_image_usage.h"
#include "gpu/command_buffer/common/sync_token.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/mailbox_ref.h"
#include "third_party/blink/renderer/platform/graphics/mailbox_texture_backing.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/skia/include/core/SkBlendMode.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkColorType.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkImageInfo.h"
#include "third_party/skia/include/core/SkSamplingOptions.h"
#include "third_party/skia/include/gpu/ganesh/GrBackendSurface.h"
#include "third_party/skia/include/gpu/ganesh/GrDirectContext.h"
#include "third_party/skia/include/gpu/ganesh/GrTypes.h"
#include "third_party/skia/include/gpu/ganesh/SkImageGanesh.h"
#include "third_party/skia/include/gpu/ganesh/gl/GrGLBackendSurface.h"
#include "third_party/skia/include/gpu/ganesh/gl/GrGLTypes.h"

namespace blink {

// static
void AcceleratedStaticBitmapImage::ReleaseTexture(void* ctx) {
  auto* release_ctx = static_cast<ReleaseContext*>(ctx);
  if (release_ctx->context_provider_wrapper) {
    if (release_ctx->texture_id) {
      auto* ri = release_ctx->context_provider_wrapper->ContextProvider()
                     ->RasterInterface();
      ri->EndSharedImageAccessDirectCHROMIUM(release_ctx->texture_id);
      ri->DeleteGpuRasterTexture(release_ctx->texture_id);
    }
  }

  delete release_ctx;
}

// static
scoped_refptr<AcceleratedStaticBitmapImage>
AcceleratedStaticBitmapImage::CreateFromCanvasSharedImage(
    scoped_refptr<gpu::ClientSharedImage> shared_image,
    const gpu::SyncToken& sync_token,
    GLuint shared_image_texture_id,
    const SkImageInfo& sk_image_info,
    GLenum texture_target,
    bool is_origin_top_left,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::PlatformThreadRef context_thread_ref,
    scoped_refptr<base::SingleThreadTaskRunner> context_task_runner,
    viz::ReleaseCallback release_callback,
    bool supports_display_compositing,
    bool is_overlay_candidate) {
  return base::AdoptRef(new AcceleratedStaticBitmapImage(
      std::move(shared_image), sync_token, shared_image_texture_id,
      sk_image_info, texture_target, is_origin_top_left,
      supports_display_compositing, is_overlay_candidate,
      ImageOrientationEnum::kDefault, std::move(context_provider_wrapper),
      context_thread_ref, std::move(context_task_runner),
      std::move(release_callback)));
}

// static
scoped_refptr<AcceleratedStaticBitmapImage>
AcceleratedStaticBitmapImage::CreateFromExternalMailbox(
    const gpu::MailboxHolder& mailbox_holder,
    gpu::SharedImageUsageSet usage,
    const SkImageInfo& sk_image_info,
    bool is_origin_top_left,
    bool supports_display_compositing,
    bool is_overlay_candidate,
    base::OnceCallback<void(const gpu::SyncToken&)> external_callback) {
  auto shared_gpu_context = blink::SharedGpuContext::ContextProviderWrapper();
  if (!shared_gpu_context) {
    return nullptr;
  }
  auto* sii = shared_gpu_context->ContextProvider()->SharedImageInterface();
  if (!sii) {
    return nullptr;
  }
  // TODO(crbug.com/1494911): Obtain metadata from the original
  // ClientSharedImage instead once we add the code that allows
  // ClientSharedImage data to be sent over Mojo.
  gfx::ColorSpace color_space =
      sk_image_info.colorSpace()
          ? gfx::ColorSpace(*(sk_image_info.colorSpace()))
          : gfx::ColorSpace::CreateSRGB();
  scoped_refptr<gpu::ClientSharedImage> shared_image =
      sii->AddReferenceToSharedImage(
          mailbox_holder.sync_token, mailbox_holder.mailbox,
          viz::SkColorTypeToSinglePlaneSharedImageFormat(
              sk_image_info.colorType()),
          gfx::SkISizeToSize(sk_image_info.dimensions()), color_space,
          (is_origin_top_left) ? kTopLeft_GrSurfaceOrigin
                               : kBottomLeft_GrSurfaceOrigin,
          sk_image_info.alphaType(), gpu::SharedImageUsageSet(usage),
          mailbox_holder.texture_target);
  auto release_token = sii->GenVerifiedSyncToken();
  // No need to keep the original image after the new reference has been added.
  // Need to update the sync token, however.
  std::move(external_callback).Run(release_token);

  auto release_callback = WTF::BindOnce(
      [](base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider,
         scoped_refptr<gpu::ClientSharedImage> shared_image,
         const gpu::SyncToken& sync_token, bool is_lost) {
        if (is_lost || !context_provider) {
          return;
        }
        shared_image->UpdateDestructionSyncToken(sync_token);
      },
      shared_gpu_context, shared_image);

  return base::AdoptRef(new AcceleratedStaticBitmapImage(
      std::move(shared_image), release_token, 0u, sk_image_info,
      mailbox_holder.texture_target, is_origin_top_left,
      supports_display_compositing, is_overlay_candidate,
      ImageOrientationEnum::kDefault, shared_gpu_context,
      base::PlatformThreadRef(),
      ThreadScheduler::Current()->CleanupTaskRunner(),
      std::move(release_callback)));
}

AcceleratedStaticBitmapImage::AcceleratedStaticBitmapImage(
    scoped_refptr<gpu::ClientSharedImage> shared_image,
    const gpu::SyncToken& sync_token,
    GLuint shared_image_texture_id,
    const SkImageInfo& sk_image_info,
    GLenum texture_target,
    bool is_origin_top_left,
    bool supports_display_compositing,
    bool is_overlay_candidate,
    const ImageOrientation& orientation,
    base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider_wrapper,
    base::PlatformThreadRef context_thread_ref,
    scoped_refptr<base::SingleThreadTaskRunner> context_task_runner,
    viz::ReleaseCallback release_callback)
    : StaticBitmapImage(orientation),
      shared_image_(std::move(shared_image)),
      sk_image_info_(sk_image_info),
      texture_target_(texture_target),
      is_origin_top_left_(is_origin_top_left),
      supports_display_compositing_(supports_display_compositing),
      is_overlay_candidate_(is_overlay_candidate),
      context_provider_wrapper_(std::move(context_provider_wrapper)),
      mailbox_ref_(
          base::MakeRefCounted<MailboxRef>(sync_token,
                                           context_thread_ref,
                                           std::move(context_task_runner),
                                           std::move(release_callback))),
      paint_image_content_id_(cc::PaintImage::GetNextContentId()) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (shared_image_texture_id)
    InitializeTextureBacking(shared_image_texture_id);
}

AcceleratedStaticBitmapImage::~AcceleratedStaticBitmapImage() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

SkImageInfo AcceleratedStaticBitmapImage::GetSkImageInfo() const {
  return sk_image_info_;
}

scoped_refptr<StaticBitmapImage>
AcceleratedStaticBitmapImage::MakeUnaccelerated() {
  CreateImageFromMailboxIfNeeded();
  return UnacceleratedStaticBitmapImage::Create(
      PaintImageForCurrentFrame().GetSwSkImage(), orientation_);
}

bool AcceleratedStaticBitmapImage::CopyToTexture(
    gpu::gles2::GLES2Interface* dest_gl,
    GLenum dest_target,
    GLuint dest_texture_id,
    GLint dest_level,
    bool unpack_premultiply_alpha,
    bool unpack_flip_y,
    const gfx::Point& dest_point,
    const gfx::Rect& source_sub_rectangle) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!IsValid())
    return false;

  // This method should only be used for cross-context copying, otherwise it's
  // wasting overhead.
  DCHECK(mailbox_ref_->is_cross_thread() ||
         dest_gl != ContextProvider()->ContextGL());

  // Create a texture that |destProvider| knows about and copy from it.
  auto source_si_texture = shared_image_->CreateGLTexture(dest_gl);
  auto source_scoped_si_access = source_si_texture->BeginAccess(
      mailbox_ref_->sync_token(), /*readonly=*/true);
  dest_gl->CopySubTextureCHROMIUM(
      source_scoped_si_access->texture_id(), 0, dest_target, dest_texture_id,
      dest_level, dest_point.x(), dest_point.y(), source_sub_rectangle.x(),
      source_sub_rectangle.y(), source_sub_rectangle.width(),
      source_sub_rectangle.height(), unpack_flip_y,
      /*unpack_premultiply_alpha=*/GL_FALSE,
      /*unpack_unmultiply_alpha=*/
      unpack_premultiply_alpha ? GL_FALSE : GL_TRUE);
  auto sync_token = gpu::SharedImageTexture::ScopedAccess::EndAccess(
      std::move(source_scoped_si_access));

  // We need to update the texture holder's sync token to ensure that when this
  // mailbox is recycled or deleted, it is done after the copy operation above.
  mailbox_ref_->set_sync_token(sync_token);

  return true;
}

bool AcceleratedStaticBitmapImage::CopyToResourceProvider(
    CanvasResourceProvider* resource_provider,
    const gfx::Rect& copy_rect) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  DCHECK(resource_provider);

  if (!IsValid())
    return false;

  const gpu::SyncToken& ready_sync_token = mailbox_ref_->sync_token();
  gpu::SyncToken completion_sync_token;
  if (!resource_provider->OverwriteImage(shared_image_->mailbox(), copy_rect,
                                         ready_sync_token,
                                         completion_sync_token)) {
    return false;
  }

  // We need to update the texture holder's sync token to ensure that when this
  // mailbox is recycled or deleted, it is done after the copy operation above.
  mailbox_ref_->set_sync_token(completion_sync_token);
  return true;
}

PaintImage AcceleratedStaticBitmapImage::PaintImageForCurrentFrame() {
  // TODO(ccameron): This function should not ignore |colorBehavior|.
  // https://crbug.com/672306
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (!IsValid())
    return PaintImage();

  CreateImageFromMailboxIfNeeded();

  return CreatePaintImageBuilder()
      .set_texture_backing(texture_backing_, paint_image_content_id_)
      .set_completion_state(PaintImage::CompletionState::kDone)
      .TakePaintImage();
}

void AcceleratedStaticBitmapImage::Draw(cc::PaintCanvas* canvas,
                                        const cc::PaintFlags& flags,
                                        const gfx::RectF& dst_rect,
                                        const gfx::RectF& src_rect,
                                        const ImageDrawOptions& draw_options) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  auto paint_image = PaintImageForCurrentFrame();
  if (!paint_image)
    return;
  auto paint_image_decoding_mode =
      ToPaintImageDecodingMode(draw_options.decode_mode);
  if (paint_image.decoding_mode() != paint_image_decoding_mode ||
      paint_image.may_be_lcp_candidate() != draw_options.may_be_lcp_candidate) {
    paint_image =
        PaintImageBuilder::WithCopy(std::move(paint_image))
            .set_decoding_mode(paint_image_decoding_mode)
            .set_may_be_lcp_candidate(draw_options.may_be_lcp_candidate)
            .TakePaintImage();
  }
  StaticBitmapImage::DrawHelper(canvas, flags, dst_rect, src_rect, draw_options,
                                paint_image);
}

bool AcceleratedStaticBitmapImage::IsValid() const {
  if (texture_backing_ && !skia_context_provider_wrapper_)
    return false;

  if (mailbox_ref_->is_cross_thread()) {
    // If context is is from another thread, validity cannot be verified. Just
    // assume valid. Potential problem will be detected later.
    return true;
  }

  return !!context_provider_wrapper_;
}

WebGraphicsContext3DProvider* AcceleratedStaticBitmapImage::ContextProvider()
    const {
  auto context = ContextProviderWrapper();
  return context ? context->ContextProvider() : nullptr;
}

base::WeakPtr<WebGraphicsContext3DProviderWrapper>
AcceleratedStaticBitmapImage::ContextProviderWrapper() const {
  return texture_backing_ ? skia_context_provider_wrapper_
                          : context_provider_wrapper_;
}

void AcceleratedStaticBitmapImage::CreateImageFromMailboxIfNeeded() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  if (texture_backing_)
    return;
  InitializeTextureBacking(0u);
}

void AcceleratedStaticBitmapImage::InitializeTextureBacking(
    GLuint shared_image_texture_id) {
  DCHECK(!shared_image_texture_id || !mailbox_ref_->is_cross_thread());

  auto context_provider_wrapper = SharedGpuContext::ContextProviderWrapper();
  if (!context_provider_wrapper)
    return;

  gpu::raster::RasterInterface* shared_ri =
      context_provider_wrapper->ContextProvider()->RasterInterface();
  shared_ri->WaitSyncTokenCHROMIUM(mailbox_ref_->sync_token().GetConstData());

  const auto& capabilities =
      context_provider_wrapper->ContextProvider()->GetCapabilities();

  if (capabilities.gpu_rasterization) {
    DCHECK_EQ(shared_image_texture_id, 0u);
    skia_context_provider_wrapper_ = context_provider_wrapper;
    texture_backing_ = sk_make_sp<MailboxTextureBacking>(
        shared_image_->mailbox(), mailbox_ref_, sk_image_info_,
        std::move(context_provider_wrapper));
    return;
  }

  GrDirectContext* shared_gr_context =
      context_provider_wrapper->ContextProvider()->GetGrContext();
  DCHECK(shared_ri &&
         shared_gr_context);  // context isValid already checked in callers

  GLuint shared_context_texture_id = 0u;
  bool should_delete_texture_on_release = true;

  if (shared_image_texture_id) {
    shared_context_texture_id = shared_image_texture_id;
    should_delete_texture_on_release = false;
  } else {
    shared_context_texture_id =
        shared_ri->CreateAndConsumeForGpuRaster(shared_image_->mailbox());
    shared_ri->BeginSharedImageAccessDirectCHROMIUM(
        shared_context_texture_id, GL_SHARED_IMAGE_ACCESS_MODE_READ_CHROMIUM);
  }

  GrGLTextureInfo texture_info;
  texture_info.fTarget = texture_target_;
  texture_info.fID = shared_context_texture_id;
  texture_info.fFormat =
      context_provider_wrapper->ContextProvider()->GetGrGLTextureFormat(
          viz::SkColorTypeToSinglePlaneSharedImageFormat(
              sk_image_info_.colorType()));
  auto backend_texture =
      GrBackendTextures::MakeGL(sk_image_info_.width(), sk_image_info_.height(),
                                skgpu::Mipmapped::kNo, texture_info);

  GrSurfaceOrigin origin = IsOriginTopLeft() ? kTopLeft_GrSurfaceOrigin
                                             : kBottomLeft_GrSurfaceOrigin;

  auto* release_ctx = new ReleaseContext;
  release_ctx->mailbox_ref = mailbox_ref_;
  if (should_delete_texture_on_release)
    release_ctx->texture_id = shared_context_texture_id;
  release_ctx->context_provider_wrapper = context_provider_wrapper;

  sk_sp<SkImage> sk_image = SkImages::BorrowTextureFrom(
      shared_gr_context, backend_texture, origin, sk_image_info_.colorType(),
      sk_image_info_.alphaType(), sk_image_info_.refColorSpace(),
      &ReleaseTexture, release_ctx);

  if (sk_image) {
    skia_context_provider_wrapper_ = context_provider_wrapper;
    texture_backing_ = sk_make_sp<MailboxTextureBacking>(
        std::move(sk_image), mailbox_ref_, sk_image_info_,
        std::move(context_provider_wrapper));
  }
}

void AcceleratedStaticBitmapImage::EnsureSyncTokenVerified() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  if (mailbox_ref_->verified_flush())
    return;

  // If the original context was created on a different thread, we need to
  // fallback to using the shared GPU context.
  auto context_provider_wrapper =
      mailbox_ref_->is_cross_thread()
          ? SharedGpuContext::ContextProviderWrapper()
          : ContextProviderWrapper();
  if (!context_provider_wrapper)
    return;

  auto sync_token = mailbox_ref_->sync_token();
  int8_t* token_data = sync_token.GetData();
  ContextProvider()->InterfaceBase()->VerifySyncTokensCHROMIUM(&token_data, 1);
  sync_token.SetVerifyFlush();
  mailbox_ref_->set_sync_token(sync_token);
}

gpu::MailboxHolder AcceleratedStaticBitmapImage::GetMailboxHolder() const {
  if (!IsValid()) {
    return gpu::MailboxHolder();
  }
  return gpu::MailboxHolder(shared_image_->mailbox(),
                            mailbox_ref_->sync_token(), texture_target_);
}

scoped_refptr<gpu::ClientSharedImage>
AcceleratedStaticBitmapImage::GetSharedImage() const {
  if (!IsValid()) {
    return nullptr;
  }
  return shared_image_;
}

gpu::SyncToken AcceleratedStaticBitmapImage::GetSyncToken() const {
  if (!IsValid()) {
    return gpu::SyncToken();
  }
  return mailbox_ref_->sync_token();
}

void AcceleratedStaticBitmapImage::Transfer() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  // SkImage is bound to the current thread so is no longer valid to use
  // cross-thread.
  texture_backing_.reset();

  DETACH_FROM_THREAD(thread_checker_);
}

bool AcceleratedStaticBitmapImage::CurrentFrameKnownToBeOpaque() {
  return sk_image_info_.isOpaque();
}

gpu::SharedImageUsageSet AcceleratedStaticBitmapImage::GetUsage() const {
  return ContextProviderWrapper()
      ->ContextProvider()
      ->SharedImageInterface()
      ->UsageForMailbox(shared_image_->mailbox());
}

}  // namespace blink
```