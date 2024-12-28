Response:
Let's break down the thought process for analyzing the provided C++ code and generating the explanation.

**1. Understanding the Core Goal:**

The filename `static_bitmap_image_to_video_frame_copier.cc` immediately suggests the primary function: taking a static bitmap image and converting it into a video frame. The `copier` part implies this isn't just about changing formats, but likely involves efficient transfer or duplication of data.

**2. Identifying Key Classes and Methods:**

Scanning the code reveals the central class: `StaticBitmapImageToVideoFrameCopier`. The `Convert` method stands out as the main entry point for the conversion process. Other important methods include:

* `GetAcceleratedVideoFramePool`: Suggests optimization using a pool of video frames, likely leveraging hardware acceleration.
* `ReadARGBPixelsSync`, `ReadARGBPixelsAsync`, `ReadYUVPixelsAsync`: Indicate different strategies for reading pixel data, with synchronous and asynchronous versions, and different color formats (ARGB and YUV).
* `OnARGBPixelsReadAsync`, `OnYUVPixelsReadAsync`: Callback functions for the asynchronous read operations.
* `OnReleaseMailbox`:  Implies managing resources, likely related to shared memory or GPU textures.

**3. Tracing the Conversion Flow (The `Convert` Method):**

The `Convert` method is the heart of the logic. Let's analyze its steps:

* **Input Validation:** Checks for null image and valid size.
* **Small Image Handling:** Special case for very small images (1x1), which are unsuitable for I420 conversion.
* **Texture Check:** Determines if the image is backed by a GPU texture (`IsTextureBacked`). This is a major branching point in the logic.
* **Direct Pixel Access (Software Path):** If not texture-backed, it attempts to get the Skia image directly (`GetSwSkImage`). If the alpha type is not pre-multiplied, it tries to create a `media::VideoFrame` directly. If that fails, it falls back to `ReadARGBPixelsSync`. This path implies software-based pixel manipulation.
* **GPU Texture Handling (Hardware Accelerated Path):**  If texture-backed:
    * Checks for a valid `WebGraphicsContext3DProviderWrapper` (indicating an active GPU context).
    * Determines if YUV readback is supported by the GPU.
    * **Accelerated Path:** If YUV readback is supported and enabled, it tries to use the `WebGraphicsContext3DVideoFramePool` for an efficient copy (`CopyRGBATextureToVideoFrame`).
    * **Asynchronous YUV Readback:** If the accelerated path fails or is not applicable, it uses `ReadYUVPixelsAsync`.
    * **Asynchronous ARGB Readback:**  If YUV readback is not suitable, it falls back to `ReadARGBPixelsAsync`.

**4. Understanding the Different Pixel Reading Methods:**

* **`ReadARGBPixelsSync`:** Reads pixel data directly from the `PaintImage` into a CPU-backed `media::VideoFrame` synchronously. This blocks the main thread.
* **`ReadARGBPixelsAsync`:** Reads pixel data from a GPU texture asynchronously using the `RasterInterface`. This avoids blocking the main thread and involves callbacks.
* **`ReadYUVPixelsAsync`:** Reads pixel data from a GPU texture directly into a YUV format (`media::PIXEL_FORMAT_I420`) asynchronously. This is often more efficient for video processing.

**5. Identifying Connections to Web Technologies:**

* **JavaScript:**  JavaScript in a web page can trigger actions that lead to image rendering (e.g., `<canvas>`, `<img>` tags, WebGL). The captured output of these elements is often represented as `StaticBitmapImage`. Therefore, this code is indirectly involved in making these rendered outputs available for video processing.
* **HTML:** The structure of the HTML page defines the elements that need to be rendered. The content of `<img>` tags or the drawing commands on a `<canvas>` ultimately lead to the creation of `StaticBitmapImage` instances that might be processed by this code.
* **CSS:** CSS styles the visual appearance of HTML elements. This styling affects the pixel data of the rendered output, which will be captured in the `StaticBitmapImage` and subsequently processed by this code.

**6. Formulating Examples and Scenarios:**

Based on the understanding of the code's functionality, we can create scenarios to illustrate its use and potential issues:

* **Successful Conversion:** Capture a simple `<img>` element and convert it to a video frame. Demonstrate the accelerated path.
* **Fallback to Software:**  Capture a complex canvas with non-premultiplied alpha, forcing the synchronous path.
* **GPU Context Loss:** Simulate a scenario where the GPU context is lost, showing how the code handles this gracefully (by skipping the frame).
* **User Errors:**  Highlight common mistakes like providing invalid image sizes or neglecting to handle asynchronous operations correctly.

**7. Structuring the Explanation:**

Finally, organize the information logically, using headings and bullet points for clarity. Start with a high-level summary of the file's purpose, then delve into the details of the key methods, connections to web technologies, and illustrative examples. Emphasize potential issues and best practices.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe this code only deals with canvas elements.
* **Correction:**  The presence of `StaticBitmapImage` and the general nature of "bitmap image" suggest broader applicability, including `<img>` tags.
* **Initial Thought:** Focus solely on the technical implementation details.
* **Refinement:** Realize the importance of explaining the *why* and the connection to the broader web development context (JavaScript, HTML, CSS).
* **Initial Thought:**  Oversimplify the different pixel reading paths.
* **Refinement:**  Clearly distinguish between synchronous and asynchronous methods and the conditions under which each is used.

By following this detailed thought process, systematically analyzing the code, and considering the broader context, we can generate a comprehensive and accurate explanation like the example provided in the initial prompt.
这个文件 `static_bitmap_image_to_video_frame_copier.cc` 的主要功能是将静态位图图像 (`StaticBitmapImage`) 转换为视频帧 (`media::VideoFrame`)。这个过程是为了让静态图像能够被视频相关的处理流程所使用，例如视频编码、解码、渲染等。

以下是该文件功能的详细列举：

**主要功能:**

1. **将 `StaticBitmapImage` 转换为 `media::VideoFrame`:** 这是核心功能。它接收一个 `StaticBitmapImage` 对象，并将其像素数据转换为 `media::VideoFrame` 对象，以便用于视频处理管道。

2. **支持同步和异步转换:**  根据图像是否由 GPU 纹理支持以及 GPU 的能力，它可以使用同步或异步的方式读取像素数据。异步方式可以避免阻塞主渲染线程。

3. **支持不同的像素格式转换:**  它可以将位图图像转换为不同的视频帧像素格式，例如 ARGB 和 YUV (I420)。YUV 格式通常更适合视频编码，因为它可以减少数据量。

4. **利用 GPU 加速:** 如果图像是 GPU 纹理支持的，并且 GPU 支持相应的操作，它可以利用 GPU 的能力进行更高效的转换，例如使用 `WebGraphicsContext3DVideoFramePool` 进行纹理拷贝。

5. **处理透明度:**  代码中考虑了图像的透明度信息 (`can_discard_alpha`)，可以根据需要保留或丢弃 alpha 通道。

6. **处理不同的颜色空间:**  在转换过程中，它会设置视频帧的颜色空间信息，例如 sRGB 或 REC601/REC709。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件本身是用 C++ 编写的，属于 Blink 渲染引擎的底层代码，**不直接**与 JavaScript, HTML, CSS 代码交互。但是，它处理的对象 (`StaticBitmapImage`) 往往是渲染 HTML 元素（例如 `<img>` 标签、`<canvas>` 元素等）的结果。

* **HTML:**  当浏览器解析 HTML 代码，遇到 `<img>` 标签时，会加载图片并将其解码为 `StaticBitmapImage` 对象。类似地，`<canvas>` 元素上的绘制操作也会产生 `StaticBitmapImage`。`StaticBitmapImageToVideoFrameCopier` 可以将这些来自 HTML 内容的静态图像转换为视频帧。

   **举例:** 一个网页包含一个 `<img src="image.png">` 标签。当浏览器渲染这个标签时，`image.png` 会被解码成 `StaticBitmapImage`。如果网页需要将这个图片作为视频的一部分进行处理（例如，作为视频编辑器的输入），那么 `StaticBitmapImageToVideoFrameCopier` 就负责将其转换为 `media::VideoFrame`。

* **CSS:** CSS 样式会影响 HTML 元素的最终渲染结果，包括图片和 Canvas 的外观。这些 CSS 样式（例如 `width`, `height`, `opacity`, `filter` 等）会直接影响 `StaticBitmapImage` 的像素数据。

   **举例:** 一个 Canvas 元素通过 CSS 设置了 `filter: blur(5px);`。当 `StaticBitmapImageToVideoFrameCopier` 处理这个 Canvas 的内容时，转换后的视频帧会包含模糊效果，因为这是 CSS 样式作用后的结果。

* **JavaScript:** JavaScript 代码可以动态地创建、修改 HTML 元素，或者在 Canvas 上进行绘制操作。这些操作最终会产生 `StaticBitmapImage` 对象。JavaScript 可以调用浏览器提供的 API (可能间接涉及到此代码) 来处理这些图像，例如将 Canvas 内容录制成视频。

   **举例:**  一段 JavaScript 代码使用 Canvas API 绘制了一个动画，并定期调用 `canvas.toBlob()` 或类似的方法来获取 Canvas 内容的快照。在某些内部实现中，这个快照可能以 `StaticBitmapImage` 的形式存在，并可能通过 `StaticBitmapImageToVideoFrameCopier` 转换为视频帧以便进行进一步处理或传输。

**逻辑推理，假设输入与输出:**

**假设输入:**

* `image`: 一个指向 `StaticBitmapImage` 对象的智能指针，代表一个 1920x1080 的 PNG 图片，不带透明度，并且是 GPU 纹理支持的。
* `can_discard_alpha`: `false` (虽然图像不带透明度，但调用者可能要求保留 alpha 通道)
* `context_provider_wrapper`: 一个有效的指向 `WebGraphicsContext3DProviderWrapper` 的弱指针，表示 GPU 上下文可用且支持 YUV 读取。

**预期输出:**

* `callback` 会被调用，并传入一个指向 `media::VideoFrame` 的智能指针。
* 这个 `media::VideoFrame` 的尺寸为 1920x1080。
* 由于 GPU 支持 YUV 读取且 `accelerated_frame_pool_enabled_` 为 true (假设)，并且图像不透明，最可能的情况是使用 `accelerated_frame_pool_->CopyRGBATextureToVideoFrame` 将 GPU 纹理直接转换为 YUV 视频帧（例如 I420 格式）。
* 因此，`media::VideoFrame` 的像素格式很可能是 `media::PIXEL_FORMAT_I420`。
* 视频帧的颜色空间将被设置为 `gfx::ColorSpace::CreateREC709()`。

**假设输入 (另一种情况):**

* `image`: 一个指向 `StaticBitmapImage` 对象的智能指针，代表一个 640x480 的 GIF 图片，带透明度，并且不是 GPU 纹理支持的。
* `can_discard_alpha`: `false`
* `context_provider_wrapper`: 可以为 null，因为图像不是纹理支持的。

**预期输出:**

* `callback` 会被调用，并传入一个指向 `media::VideoFrame` 的智能指针。
* 这个 `media::VideoFrame` 的尺寸为 640x480。
* 由于图像不是纹理支持的，会走 `ReadARGBPixelsSync` 路径，同步读取像素数据。
* `media::VideoFrame` 的像素格式很可能是 `media::PIXEL_FORMAT_ARGB` 或 `media::PIXEL_FORMAT_BGRA`，具体取决于 Skia 的颜色类型。
* 视频帧的颜色空间将被设置为 `gfx::ColorSpace::CreateSRGB()`.

**涉及用户或者编程常见的使用错误，举例说明:**

1. **在 GPU 上下文失效后尝试转换纹理支持的图像:**
   * **错误:**  如果 `context_provider_wrapper` 指向的上下文已经失效（例如，GPU 进程崩溃），尝试调用 `Convert` 处理一个 GPU 纹理支持的 `StaticBitmapImage` 会导致转换失败，`callback` 不会被调用或会收到一个空指针。
   * **代码体现:**  在 `Convert` 方法中，会检查 `context_provider_wrapper` 和 `context_provider` 是否有效，如果无效则直接返回。
   * **用户/编程错误:**  没有正确处理 GPU 上下文失效的情况，例如在依赖 GPU 操作之前没有检查上下文的有效性。

2. **假设异步操作会立即完成:**
   * **错误:** `ReadARGBPixelsAsync` 和 `ReadYUVPixelsAsync` 是异步操作，依赖于 GPU 的完成。如果代码在调用 `Convert` 后立即尝试使用尚未完成转换的视频帧，会导致数据错误或程序崩溃。
   * **代码体现:** 这些异步方法使用回调函数 (`callback`) 来通知转换完成。
   * **用户/编程错误:** 没有正确处理异步操作，没有在回调函数中处理转换后的视频帧。

3. **没有考虑图像尺寸的限制:**
   * **错误:** 代码中提到 1x1 的图像不能被读取回 I420 格式。如果尝试转换一个非常小的纹理支持的图像到 YUV 格式，可能会失败。
   * **代码体现:**  `Convert` 方法中检查了图像尺寸，对于太小的图像会避免尝试 YUV 异步读取。
   * **用户/编程错误:**  没有考虑到视频帧格式对图像尺寸的要求。

4. **错误地设置 `can_discard_alpha`:**
   * **错误:** 如果图像包含重要的透明度信息，但 `can_discard_alpha` 被设置为 `true`，那么转换后的视频帧可能会丢失透明度信息，导致渲染结果不正确。
   * **代码体现:**  `can_discard_alpha` 影响是否尝试 YUV 转换（YUV 格式通常不包含 alpha 通道）。
   * **用户/编程错误:**  没有根据实际需求正确设置是否丢弃 alpha 通道。

5. **在非主线程调用需要主线程上下文的方法:**
   * **错误:** 某些操作，例如直接读取像素数据 (`ReadARGBPixelsSync`)，需要在主渲染线程上执行。如果在非主线程调用这些方法，可能会导致线程安全问题。
   * **代码体现:** 代码中使用了 `DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);` 来进行断言检查。
   * **用户/编程错误:**  没有理解 Blink 引擎的线程模型，在错误的线程上执行操作。

总而言之，`static_bitmap_image_to_video_frame_copier.cc` 是 Blink 渲染引擎中一个关键的组件，负责将静态图像数据转换为视频帧格式，以便在视频处理流程中使用。它涉及到 GPU 加速、异步操作、多种像素格式转换和颜色空间管理，与 JavaScript, HTML, CSS 的交互主要体现在它处理的图像数据来源于网页内容的渲染结果。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/static_bitmap_image_to_video_frame_copier.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/static_bitmap_image_to_video_frame_copier.h"

#include "base/functional/callback_helpers.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "components/viz/common/resources/shared_image_format_utils.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "gpu/command_buffer/common/capabilities.h"
#include "media/base/video_frame.h"
#include "media/base/video_util.h"
#include "third_party/blink/public/platform/web_graphics_context_3d_provider.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_provider_wrapper.h"
#include "third_party/blink/renderer/platform/graphics/web_graphics_context_3d_video_frame_pool.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/libyuv/include/libyuv.h"
#include "third_party/skia/include/core/SkImage.h"
#include "ui/gfx/color_space.h"

namespace blink {

StaticBitmapImageToVideoFrameCopier::StaticBitmapImageToVideoFrameCopier(
    bool accelerated_frame_pool_enabled)
    : accelerated_frame_pool_enabled_(accelerated_frame_pool_enabled),
      weak_ptr_factory_(this) {}

StaticBitmapImageToVideoFrameCopier::~StaticBitmapImageToVideoFrameCopier() =
    default;

WebGraphicsContext3DVideoFramePool*
StaticBitmapImageToVideoFrameCopier::GetAcceleratedVideoFramePool(
    base::WeakPtr<blink::WebGraphicsContext3DProviderWrapper>
        context_provider) {
  if (accelerated_frame_pool_enabled_ && !accelerated_frame_pool_) {
    accelerated_frame_pool_ =
        std::make_unique<WebGraphicsContext3DVideoFramePool>(context_provider);
  }
  return accelerated_frame_pool_.get();
}

void StaticBitmapImageToVideoFrameCopier::Convert(
    scoped_refptr<StaticBitmapImage> image,
    bool can_discard_alpha,
    base::WeakPtr<blink::WebGraphicsContext3DProviderWrapper>
        context_provider_wrapper,
    FrameReadyCallback callback) {
  can_discard_alpha_ = can_discard_alpha;
  if (!image)
    return;

  const auto size = image->Size();
  if (!media::VideoFrame::IsValidSize(size, gfx::Rect(size), size)) {
    DVLOG(1) << __func__ << " received frame with invalid size "
             << size.ToString();
    return;
  }

  // We might need to convert the frame into I420 pixel format, and 1x1 frame
  // can't be read back into I420.
  const bool too_small_for_i420 = image->width() == 1 || image->height() == 1;
  if (!image->IsTextureBacked()) {
    // Initially try accessing pixels directly if they are in memory.
    sk_sp<SkImage> sk_image = image->PaintImageForCurrentFrame().GetSwSkImage();
    if (sk_image->alphaType() != kPremul_SkAlphaType) {
      const gfx::Size sk_image_size(sk_image->width(), sk_image->height());
      auto sk_image_video_frame = media::CreateFromSkImage(
          std::move(sk_image), gfx::Rect(sk_image_size), sk_image_size,
          base::TimeDelta());
      if (sk_image_video_frame) {
        std::move(callback).Run(std::move(sk_image_video_frame));
        return;
      }
    }

    // Copy the pixels into memory synchronously. This call may block the main
    // render thread.
    ReadARGBPixelsSync(image, std::move(callback));
    return;
  }

  if (!context_provider_wrapper) {
    DLOG(ERROR) << "Context lost, skipping frame";
    return;
  }

  auto* context_provider = context_provider_wrapper->ContextProvider();
  if (!context_provider) {
    DLOG(ERROR) << "Context lost, skipping frame";
    return;
  }

  // Readback to YUV is only used when result is opaque.
  const bool result_is_opaque =
      image->CurrentFrameKnownToBeOpaque() || can_discard_alpha_;

  const bool supports_yuv_readback =
      context_provider->GetCapabilities().supports_yuv_readback;
  // If supports_rgb_to_yuv_conversion is true, supports_yuv_readback must also
  // be.
  CHECK(!context_provider->GetCapabilities().supports_rgb_to_yuv_conversion ||
        supports_yuv_readback);

  // Try async reading if image is texture backed.
  if (!too_small_for_i420 && result_is_opaque && supports_yuv_readback) {
    // Split the callback so it can be used for both the GMB frame pool copy and
    // ReadYUVPixelsAsync fallback paths.
    auto split_callback = base::SplitOnceCallback(std::move(callback));
    if (accelerated_frame_pool_enabled_) {
      if (!accelerated_frame_pool_) {
        accelerated_frame_pool_ =
            std::make_unique<WebGraphicsContext3DVideoFramePool>(
                context_provider_wrapper);
      }
      if (accelerated_frame_pool_->CopyRGBATextureToVideoFrame(
              gfx::Size(image->width(), image->height()),
              image->GetSharedImage(), image->GetSyncToken(),
              gfx::ColorSpace::CreateREC709(),
              std::move(split_callback.first))) {
        TRACE_EVENT1("blink", "StaticBitmapImageToVideoFrameCopier::Convert",
                     "accelerated_frame_pool_copy", true);
        // Early out on success, otherwise fallback to ReadYUVPixelsAsync path.
        return;
      }
    }
    ReadYUVPixelsAsync(image, context_provider,
                       std::move(split_callback.second));
  } else {
    ReadARGBPixelsAsync(image, context_provider, std::move(callback));
  }

  TRACE_EVENT1("blink", "StaticBitmapImageToVideoFrameCopier::Convert",
               "accelerated_frame_pool_copy", false);
}

void StaticBitmapImageToVideoFrameCopier::ReadARGBPixelsSync(
    scoped_refptr<StaticBitmapImage> image,
    FrameReadyCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);

  PaintImage paint_image = image->PaintImageForCurrentFrame();
  const gfx::Size image_size(paint_image.width(), paint_image.height());
  const bool is_opaque = paint_image.IsOpaque();
  const media::VideoPixelFormat temp_argb_pixel_format =
      media::VideoPixelFormatFromSkColorType(kN32_SkColorType, is_opaque);
  scoped_refptr<media::VideoFrame> temp_argb_frame = frame_pool_.CreateFrame(
      temp_argb_pixel_format, image_size, gfx::Rect(image_size), image_size,
      base::TimeDelta());
  if (!temp_argb_frame) {
    DLOG(ERROR) << "Couldn't allocate video frame";
    return;
  }
  SkImageInfo image_info = SkImageInfo::MakeN32(
      image_size.width(), image_size.height(),
      is_opaque ? kPremul_SkAlphaType : kUnpremul_SkAlphaType);
  if (!paint_image.readPixels(
          image_info,
          temp_argb_frame->GetWritableVisibleData(
              media::VideoFrame::Plane::kARGB),
          temp_argb_frame->stride(media::VideoFrame::Plane::kARGB), 0 /*srcX*/,
          0 /*srcY*/)) {
    DLOG(ERROR) << "Couldn't read pixels from PaintImage";
    return;
  }
  temp_argb_frame->set_color_space(gfx::ColorSpace::CreateSRGB());
  std::move(callback).Run(std::move(temp_argb_frame));
}

void StaticBitmapImageToVideoFrameCopier::ReadARGBPixelsAsync(
    scoped_refptr<StaticBitmapImage> image,
    blink::WebGraphicsContext3DProvider* context_provider,
    FrameReadyCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  DCHECK(context_provider);

  const media::VideoPixelFormat temp_argb_pixel_format =
      media::VideoPixelFormatFromSkColorType(kN32_SkColorType,
                                             /*is_opaque = */ false);
  const gfx::Size image_size(image->width(), image->height());
  scoped_refptr<media::VideoFrame> temp_argb_frame = frame_pool_.CreateFrame(
      temp_argb_pixel_format, image_size, gfx::Rect(image_size), image_size,
      base::TimeDelta());
  if (!temp_argb_frame) {
    DLOG(ERROR) << "Couldn't allocate video frame";
    return;
  }

  static_assert(kN32_SkColorType == kRGBA_8888_SkColorType ||
                    kN32_SkColorType == kBGRA_8888_SkColorType,
                "CanvasCaptureHandler::ReadARGBPixelsAsync supports only "
                "kRGBA_8888_SkColorType and kBGRA_8888_SkColorType.");
  SkImageInfo info = SkImageInfo::MakeN32(
      image_size.width(), image_size.height(), kUnpremul_SkAlphaType);
  GrSurfaceOrigin image_origin = image->IsOriginTopLeft()
                                     ? kTopLeft_GrSurfaceOrigin
                                     : kBottomLeft_GrSurfaceOrigin;

  gfx::Point src_point;
  gpu::MailboxHolder mailbox_holder = image->GetMailboxHolder();
  DCHECK(context_provider->RasterInterface());
  context_provider->RasterInterface()->WaitSyncTokenCHROMIUM(
      mailbox_holder.sync_token.GetConstData());
  context_provider->RasterInterface()->ReadbackARGBPixelsAsync(
      mailbox_holder.mailbox, mailbox_holder.texture_target, image_origin,
      image_size, src_point, info,
      temp_argb_frame->stride(media::VideoFrame::Plane::kARGB),
      temp_argb_frame->GetWritableVisibleData(media::VideoFrame::Plane::kARGB),
      WTF::BindOnce(&StaticBitmapImageToVideoFrameCopier::OnARGBPixelsReadAsync,
                    weak_ptr_factory_.GetWeakPtr(), image, temp_argb_frame,
                    std::move(callback)));
}

void StaticBitmapImageToVideoFrameCopier::ReadYUVPixelsAsync(
    scoped_refptr<StaticBitmapImage> image,
    blink::WebGraphicsContext3DProvider* context_provider,
    FrameReadyCallback callback) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  DCHECK(context_provider);

  // Our ReadbackYUVPixelsAsync() implementations either cut off odd pixels or
  // simply fail. So, there is no point even trying reading odd sized images
  // into I420.
  const gfx::Size image_size(image->width() & ~1u, image->height() & ~1u);
  scoped_refptr<media::VideoFrame> output_frame = frame_pool_.CreateFrame(
      media::PIXEL_FORMAT_I420, image_size, gfx::Rect(image_size), image_size,
      base::TimeDelta());
  if (!output_frame) {
    DLOG(ERROR) << "Couldn't allocate video frame";
    return;
  }

  gpu::MailboxHolder mailbox_holder = image->GetMailboxHolder();
  context_provider->RasterInterface()->WaitSyncTokenCHROMIUM(
      mailbox_holder.sync_token.GetConstData());
  context_provider->RasterInterface()->ReadbackYUVPixelsAsync(
      mailbox_holder.mailbox, mailbox_holder.texture_target, image_size,
      gfx::Rect(image_size), !image->IsOriginTopLeft(),
      output_frame->stride(media::VideoFrame::Plane::kY),
      output_frame->GetWritableVisibleData(media::VideoFrame::Plane::kY),
      output_frame->stride(media::VideoFrame::Plane::kU),
      output_frame->GetWritableVisibleData(media::VideoFrame::Plane::kU),
      output_frame->stride(media::VideoFrame::Plane::kV),
      output_frame->GetWritableVisibleData(media::VideoFrame::Plane::kV),
      gfx::Point(0, 0),
      WTF::BindOnce(&StaticBitmapImageToVideoFrameCopier::OnReleaseMailbox,
                    weak_ptr_factory_.GetWeakPtr(), image),
      WTF::BindOnce(&StaticBitmapImageToVideoFrameCopier::OnYUVPixelsReadAsync,
                    weak_ptr_factory_.GetWeakPtr(), output_frame,
                    std::move(callback)));
}

void StaticBitmapImageToVideoFrameCopier::OnARGBPixelsReadAsync(
    scoped_refptr<StaticBitmapImage> image,
    scoped_refptr<media::VideoFrame> argb_frame,
    FrameReadyCallback callback,
    bool success) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);
  if (!success) {
    DLOG(ERROR) << "Couldn't read SkImage using async callback";
    // Async reading is not supported on some platforms, see
    // http://crbug.com/788386.
    ReadARGBPixelsSync(image, std::move(callback));
    return;
  }
  argb_frame->set_color_space(gfx::ColorSpace::CreateSRGB());
  std::move(callback).Run(std::move(argb_frame));
}

void StaticBitmapImageToVideoFrameCopier::OnYUVPixelsReadAsync(
    scoped_refptr<media::VideoFrame> yuv_frame,
    FrameReadyCallback callback,
    bool success) {
  DCHECK_CALLED_ON_VALID_THREAD(main_render_thread_checker_);

  if (!success) {
    DLOG(ERROR) << "Couldn't read SkImage using async callback";
    return;
  }
  yuv_frame->set_color_space(gfx::ColorSpace::CreateREC601());
  std::move(callback).Run(yuv_frame);
}

void StaticBitmapImageToVideoFrameCopier::OnReleaseMailbox(
    scoped_refptr<StaticBitmapImage> image) {
  // All shared image operations have been completed, stop holding the ref.
  image = nullptr;
}

}  // namespace blink

"""

```