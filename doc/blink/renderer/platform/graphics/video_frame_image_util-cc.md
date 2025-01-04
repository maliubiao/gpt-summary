Response:
Let's break down the thought process for analyzing the C++ code and generating the response.

1. **Understand the Goal:** The request asks for the functionalities of `video_frame_image_util.cc`, its relationship to web technologies (JavaScript, HTML, CSS), logical reasoning examples, and common usage errors.

2. **Initial Code Scan (Headers and Namespaces):**  Start by looking at the included headers and the namespace (`blink`). This provides immediate context:
    * **Headers:**  Keywords like `video_frame`, `media`, `graphics`, `canvas`, `gpu`, `skia`, `image`, `bitmap` suggest this code deals with converting video frames into images, likely for display in the browser. The presence of `viz` (the Chromium compositor) further reinforces this.
    * **Namespace `blink`:** This confirms we're dealing with the rendering engine of Chromium.

3. **Identify Key Functions:** Look for the main functions and their purpose based on their names:
    * `VideoTransformationToImageOrientation`:  Clearly converts video rotation/mirroring to image orientation metadata.
    * `ImageOrientationToVideoTransformation`: Does the reverse.
    * `WillCreateAcceleratedImagesFromVideoFrame`: Determines if GPU-accelerated image creation is possible.
    * `CreateImageFromVideoFrame`: The core function for creating an `StaticBitmapImage` from a `media::VideoFrame`. The arguments (like `allow_zero_copy_images`, `CanvasResourceProvider`) hint at different creation paths.
    * `DrawVideoFrameIntoResourceProvider`: Draws the video frame onto a pre-existing graphics resource.
    * `DrawVideoFrameIntoCanvas`: Draws directly onto a `cc::PaintCanvas`.
    * `GetRasterContextProvider`: Obtains access to the GPU's rasterization context.
    * `CreateResourceProviderForVideoFrame`: Creates a resource provider (either CPU or GPU based) for storing the image.

4. **Analyze Individual Functions:**  Dive deeper into each key function:

    * **`*Transformation*` functions:** These are straightforward mappings between video transformations and image orientations. They establish a connection to how video and images are oriented on screen (relevant to CSS transformations).

    * **`WillCreateAcceleratedImagesFromVideoFrame`:** Notice the conditions for using zero-copy images (shared image, specific pixel formats, platform limitations). Also, the check for GPU compositing and the `DISABLE_IMAGEBITMAP_FROM_VIDEO_USING_GPU` flag is important for understanding optimization and potential workarounds.

    * **`CreateImageFromVideoFrame`:**  This is the most complex. Identify the two main branches:
        * **Zero-copy:** If allowed, efficient shared image creation is attempted. Note the handling of sync tokens for GPU resource management. This is a performance optimization.
        * **Copying/Drawing:** If zero-copy isn't possible, the video frame is drawn onto a `CanvasResourceProvider`. This involves potentially creating a new provider. The use of `PaintCanvasVideoRenderer` is key here.

    * **`DrawVideoFrameIntoResourceProvider`:**  Focus on the different paths based on whether the video frame has a shared image (GPU path) or needs to be rendered via `PaintCanvasVideoRenderer` (potentially CPU path). The handling of mappable GPU buffers is another important detail.

    * **`DrawVideoFrameIntoCanvas`:**  A simpler version of the previous function, drawing directly to a canvas.

    * **`GetRasterContextProvider`:** Straightforward access to the GPU context.

    * **`CreateResourceProviderForVideoFrame`:**  The logic for choosing between bitmap (CPU) and shared image (GPU) providers based on GPU availability.

5. **Relate to Web Technologies:**  Think about how these functions connect to JavaScript, HTML, and CSS:

    * **JavaScript `drawImage()`/`putImageData()`:** The functions here are the underlying implementations for drawing video frames onto a canvas element in JavaScript. `CreateImageFromVideoFrame` provides the `StaticBitmapImage` that can be used by the canvas API.
    * **HTML `<video>` element:**  This code is part of the rendering pipeline for displaying video. The transformations handled here directly influence how the video appears.
    * **CSS `transform` property:** The `VideoTransformationToImageOrientation` and `ImageOrientationToVideoTransformation` functions are related to how CSS transformations on video elements are interpreted and applied. While this C++ doesn't *execute* the CSS, it ensures consistency in how rotations and mirroring are handled. The image orientation is metadata that can affect how CSS interacts with the image.

6. **Logical Reasoning (Assumptions and Outputs):**  For functions like the transformation converters and `WillCreateAcceleratedImagesFromVideoFrame`, it's easy to create input-output examples. For `CreateImageFromVideoFrame`, consider the different execution paths based on the `allow_zero_copy_images` flag and the video frame's properties.

7. **Common Usage Errors:** Think about situations where things could go wrong from a programmer's perspective:
    * **Incorrect destination rectangle:**  Providing a `dest_rect` that doesn't fit the `CanvasResourceProvider`.
    * **Missing `CanvasResourceProvider`:** For scenarios requiring a specific drawing target.
    * **GPU context issues:**  The code handles cases where the GPU context is lost, but users might not be aware of this underlying complexity.
    * **Incorrectly assuming zero-copy:**  Not understanding the limitations of zero-copy image creation.

8. **Structure the Response:** Organize the information logically:
    * **Functionality Summary:**  Provide a high-level overview.
    * **Relationships to Web Technologies:** Explain how the code interacts with JavaScript, HTML, and CSS, providing specific examples.
    * **Logical Reasoning Examples:** Illustrate the behavior of certain functions with inputs and outputs.
    * **Common Usage Errors:** Highlight potential pitfalls for developers.

9. **Refine and Elaborate:** Review the generated response for clarity, accuracy, and completeness. Add details where necessary to make the explanations more understandable. For instance, explicitly mentioning the performance implications of zero-copy. Also, ensure the technical terms are used correctly.
This C++ source file, `video_frame_image_util.cc`, within the Chromium Blink rendering engine, provides **utilities for converting `media::VideoFrame` objects into `StaticBitmapImage` or `AcceleratedStaticBitmapImage` objects.**  Essentially, it bridges the gap between video frame data and the image representation used for rendering in the browser.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Creating Images from Video Frames:** The primary function is `CreateImageFromVideoFrame`. This function takes a `media::VideoFrame` as input and returns a `scoped_refptr<StaticBitmapImage>`. This involves:
    * **Optionally using zero-copy optimization:** If the video frame format and system support it, it can create an `AcceleratedStaticBitmapImage` directly from the shared memory backing the video frame, avoiding a data copy. This is a significant performance optimization.
    * **Drawing onto a `CanvasResourceProvider`:** If zero-copy is not possible or a specific destination rectangle is provided, it draws the video frame onto a `CanvasResourceProvider`. This provider can be either CPU-backed (bitmap) or GPU-backed (shared image).
    * **Handling video transformations:** It takes into account any rotation or mirroring metadata associated with the video frame and applies it to the resulting image.
    * **Color space management:** It handles the color space of the video frame and ensures the resulting image has the correct color information.

2. **Drawing Video Frames onto Canvases:** The `DrawVideoFrameIntoCanvas` function allows directly drawing a `media::VideoFrame` onto a `cc::PaintCanvas`. This is useful for rendering video content directly within a canvas element.

3. **Managing Image Orientation and Video Transformations:**
    * `VideoTransformationToImageOrientation`: Converts `media::VideoTransformation` (rotation and mirroring) to `ImageOrientationEnum` used by the image representation.
    * `ImageOrientationToVideoTransformation`: Performs the reverse conversion. This is crucial for ensuring consistency between how video transformations are represented in the media pipeline and how images are oriented for rendering.

4. **Determining Accelerated Image Creation:** `WillCreateAcceleratedImagesFromVideoFrame` checks if it's possible and beneficial to create an accelerated image from a given video frame. This considers factors like shared image availability, pixel format, and GPU capabilities.

5. **Creating `CanvasResourceProvider`:** The `CreateResourceProviderForVideoFrame` function creates an appropriate `CanvasResourceProvider` (either bitmap-based or shared-image based) based on GPU availability and other factors.

6. **Drawing onto a `CanvasResourceProvider`:** `DrawVideoFrameIntoResourceProvider` handles the actual drawing of the `media::VideoFrame` onto a given `CanvasResourceProvider`.

7. **Accessing Raster Context:** `GetRasterContextProvider` provides access to the GPU's raster context, which is needed for GPU-accelerated operations.

**Relationship to JavaScript, HTML, and CSS:**

This C++ code is a fundamental part of how the browser renders video content that is often exposed and manipulated through web technologies:

* **JavaScript and the `<canvas>` element:**
    * When JavaScript code uses the `drawImage()` method of a `<canvas>` element to draw a video frame (often obtained using `requestVideoFrameCallback`), this C++ code is involved in converting the underlying `media::VideoFrame` into an image that Skia (the graphics library used by Chromium) can render on the canvas.
    * **Example:**
      ```javascript
      const video = document.querySelector('video');
      const canvas = document.querySelector('canvas');
      const ctx = canvas.getContext('2d');

      video.requestVideoFrameCallback( (now, metadata) => {
        ctx.drawImage(video, 0, 0); // Internally uses the functionalities of video_frame_image_util.cc
        video.requestVideoFrameCallback(arguments.callee);
      });
      ```
      In this example, `ctx.drawImage(video, 0, 0)` will eventually lead to `CreateImageFromVideoFrame` being called to get a renderable image from the video frame.

* **HTML `<video>` element:**
    * When a `<video>` element is displayed, the browser needs to render the video frames. This C++ code plays a crucial role in converting the decoded video frames into images that can be composited onto the screen.
    * The video transformations (rotation, mirroring) defined in the video stream or potentially manipulated by JavaScript are handled by functions like `VideoTransformationToImageOrientation` to ensure the video is displayed correctly.

* **CSS `transform` property on `<video>` or canvas elements:**
    * While this C++ code doesn't directly *interpret* CSS, the image orientation metadata it generates (using `VideoTransformationToImageOrientation`) can influence how CSS transformations are applied. For example, if the video has a natural rotation, this information might be used to ensure CSS rotations are applied relative to the correct initial orientation.

**Logical Reasoning (Assumptions, Inputs, and Outputs):**

Let's consider the `VideoTransformationToImageOrientation` function:

* **Assumption:** The input `media::VideoTransformation` object correctly represents the rotation and mirroring applied to the video frame.
* **Input 1:** `media::VideoTransformation{media::VIDEO_ROTATION_90, false}` (Rotate 90 degrees, not mirrored).
* **Output 1:** `ImageOrientationEnum::kOriginRightTop`

* **Input 2:** `media::VideoTransformation{media::VIDEO_ROTATION_0, true}` (No rotation, mirrored).
* **Output 2:** `ImageOrientationEnum::kOriginTopRight`

Let's consider the `WillCreateAcceleratedImagesFromVideoFrame` function:

* **Assumption:** We have a valid `media::VideoFrame` object.
* **Input 1:** A `media::VideoFrame` with format `media::PIXEL_FORMAT_ARGB`, `HasSharedImage()` returns `true`, and the platform is not Android or macOS.
* **Output 1:** `true` (Zero-copy accelerated image creation is likely possible).

* **Input 2:** A `media::VideoFrame` with format `media::PIXEL_FORMAT_YUV420P`, regardless of `HasSharedImage()`.
* **Output 2:** `false` (Zero-copy is currently disabled for YUV formats in this code).

**User or Programming Common Usage Errors:**

1. **Providing an inappropriate `dest_rect` to `CreateImageFromVideoFrame`:** If you provide a `dest_rect` that is larger than the target `CanvasResourceProvider`'s size, the drawing operation might fail or produce unexpected results. The code includes checks for this, logging an error.

   ```c++
   // Potential error if resource_provider is smaller than the requested dest_rect
   CreateImageFromVideoFrame(video_frame, false, my_resource_provider, nullptr, gfx::Rect(0, 0, 500, 500));
   ```

2. **Assuming zero-copy will always happen:** Developers might assume that providing a shared image backed video frame will automatically result in zero-copy. However, platform limitations, pixel format restrictions, or GPU feature flags can prevent zero-copy. It's important to check the conditions in `CanUseZeroCopyImages`.

3. **Not handling the asynchronous nature of GPU operations:** When dealing with accelerated images, the underlying texture might not be immediately available on the CPU. Incorrectly assuming synchronous access could lead to errors or race conditions. The release callback mechanism in `CreateImageFromVideoFrame` is designed to handle this.

4. **Forgetting to provide a `CanvasResourceProvider` when needed:** If you call `CreateImageFromVideoFrame` with a non-empty `dest_rect`, you *must* provide a valid `CanvasResourceProvider`. Failing to do so will result in an error and a `nullptr` return.

   ```c++
   // Error: resource_provider is null but dest_rect is not empty
   CreateImageFromVideoFrame(video_frame, false, nullptr, nullptr, gfx::Rect(10, 10, 100, 100));
   ```

5. **Incorrectly assuming image orientation:**  If developers manually manipulate video frames or images and don't correctly account for the image orientation metadata, they might encounter issues with how the images are displayed or transformed. The functions for converting between video transformations and image orientation are crucial for maintaining consistency.

In summary, `video_frame_image_util.cc` is a crucial piece of the Blink rendering engine responsible for efficiently converting video frames into renderable images, handling transformations, and leveraging GPU acceleration when possible. It directly supports the display of video content within web pages and interacts closely with JavaScript and the HTML canvas API. Understanding its functionalities is important for comprehending how video is rendered in Chromium-based browsers.

Prompt: 
```
这是目录为blink/renderer/platform/graphics/video_frame_image_util.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/graphics/video_frame_image_util.h"

#include "base/logging.h"
#include "build/build_config.h"
#include "components/viz/common/gpu/raster_context_provider.h"
#include "components/viz/common/resources/release_callback.h"
#include "gpu/command_buffer/client/raster_interface.h"
#include "gpu/config/gpu_feature_info.h"
#include "media/base/video_frame.h"
#include "media/base/video_types.h"
#include "media/base/video_util.h"
#include "media/base/wait_and_replace_sync_token_client.h"
#include "media/renderers/paint_canvas_video_renderer.h"
#include "third_party/blink/renderer/platform/graphics/accelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkImageInfo.h"
#include "third_party/skia/include/gpu/ganesh/GrDriverBugWorkarounds.h"
#include "ui/gfx/color_space.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {

namespace {

bool CanUseZeroCopyImages(const media::VideoFrame& frame) {
  // SharedImage optimization: create AcceleratedStaticBitmapImage directly.
  // Disabled on Android because the hardware decode implementation may neuter
  // frames, which would violate ImageBitmap requirements.
  // TODO(sandersd): Handle YUV pixel formats.
  // TODO(sandersd): Handle high bit depth formats.
  // TODO(crbug.com/1203713): Figure out why macOS zero copy ends up with y-flip
  // images in zero copy mode.
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_MAC)
  return false;
#else
  return frame.HasSharedImage() &&
         (frame.format() == media::PIXEL_FORMAT_ARGB ||
          frame.format() == media::PIXEL_FORMAT_XRGB ||
          frame.format() == media::PIXEL_FORMAT_ABGR ||
          frame.format() == media::PIXEL_FORMAT_XBGR ||
          frame.format() == media::PIXEL_FORMAT_BGRA);
#endif
}

bool ShouldCreateAcceleratedImages(
    viz::RasterContextProvider* raster_context_provider) {
  if (!SharedGpuContext::IsGpuCompositingEnabled())
    return false;

  if (!raster_context_provider)
    return false;

  if (raster_context_provider->GetGpuFeatureInfo().IsWorkaroundEnabled(
          DISABLE_IMAGEBITMAP_FROM_VIDEO_USING_GPU)) {
    return false;
  }

  return true;
}

}  // namespace

ImageOrientationEnum VideoTransformationToImageOrientation(
    media::VideoTransformation transform) {
  if (!transform.mirrored) {
    switch (transform.rotation) {
      case media::VIDEO_ROTATION_0:
        return ImageOrientationEnum::kOriginTopLeft;
      case media::VIDEO_ROTATION_90:
        return ImageOrientationEnum::kOriginRightTop;
      case media::VIDEO_ROTATION_180:
        return ImageOrientationEnum::kOriginBottomRight;
      case media::VIDEO_ROTATION_270:
        return ImageOrientationEnum::kOriginLeftBottom;
    }
  }

  switch (transform.rotation) {
    case media::VIDEO_ROTATION_0:
      return ImageOrientationEnum::kOriginTopRight;
    case media::VIDEO_ROTATION_90:
      return ImageOrientationEnum::kOriginLeftTop;
    case media::VIDEO_ROTATION_180:
      return ImageOrientationEnum::kOriginBottomLeft;
    case media::VIDEO_ROTATION_270:
      return ImageOrientationEnum::kOriginRightBottom;
  }
}

media::VideoTransformation ImageOrientationToVideoTransformation(
    ImageOrientationEnum orientation) {
  switch (orientation) {
    case ImageOrientationEnum::kOriginTopLeft:
      return media::kNoTransformation;
    case ImageOrientationEnum::kOriginTopRight:
      return media::VideoTransformation(media::VIDEO_ROTATION_0,
                                        /*mirrored=*/true);
    case ImageOrientationEnum::kOriginBottomRight:
      return media::VIDEO_ROTATION_180;
    case ImageOrientationEnum::kOriginBottomLeft:
      return media::VideoTransformation(media::VIDEO_ROTATION_180,
                                        /*mirrored=*/true);
    case ImageOrientationEnum::kOriginLeftTop:
      return media::VideoTransformation(media::VIDEO_ROTATION_90,
                                        /*mirrored=*/true);
    case ImageOrientationEnum::kOriginRightTop:
      return media::VIDEO_ROTATION_90;
    case ImageOrientationEnum::kOriginRightBottom:
      return media::VideoTransformation(media::VIDEO_ROTATION_270,
                                        /*mirrored=*/true);
    case ImageOrientationEnum::kOriginLeftBottom:
      return media::VIDEO_ROTATION_270;
  };
}

bool WillCreateAcceleratedImagesFromVideoFrame(const media::VideoFrame* frame) {
  return CanUseZeroCopyImages(*frame) ||
         ShouldCreateAcceleratedImages(GetRasterContextProvider().get());
}

scoped_refptr<StaticBitmapImage> CreateImageFromVideoFrame(
    scoped_refptr<media::VideoFrame> frame,
    bool allow_zero_copy_images,
    CanvasResourceProvider* resource_provider,
    media::PaintCanvasVideoRenderer* video_renderer,
    const gfx::Rect& dest_rect,
    bool prefer_tagged_orientation,
    bool reinterpret_video_as_srgb) {
  auto frame_sk_color_space = frame->CompatRGBColorSpace().ToSkColorSpace();
  if (!frame_sk_color_space) {
    frame_sk_color_space = SkColorSpace::MakeSRGB();
  }

  DCHECK(frame);
  const auto transform =
      frame->metadata().transformation.value_or(media::kNoTransformation);
  if (allow_zero_copy_images && !reinterpret_video_as_srgb &&
      dest_rect.IsEmpty() && transform == media::kNoTransformation &&
      CanUseZeroCopyImages(*frame)) {
    // TODO(sandersd): Do we need to be able to handle limited-range RGB? It
    // may never happen, and SkColorSpace doesn't know about it.
    const SkImageInfo sk_image_info = SkImageInfo::Make(
        frame->coded_size().width(), frame->coded_size().height(),
        kN32_SkColorType, kUnpremul_SkAlphaType, frame_sk_color_space);

    // Hold a ref by storing it in the release callback.
    auto release_callback = WTF::BindOnce(
        [](scoped_refptr<media::VideoFrame> frame,
           base::WeakPtr<WebGraphicsContext3DProviderWrapper> context_provider,
           const gpu::SyncToken& sync_token, bool is_lost) {
          if (is_lost || !context_provider)
            return;
          auto* ri = context_provider->ContextProvider()->RasterInterface();
          media::WaitAndReplaceSyncTokenClient client(ri);
          frame->UpdateReleaseSyncToken(&client);
        },
        frame, SharedGpuContext::ContextProviderWrapper());

    return AcceleratedStaticBitmapImage::CreateFromCanvasSharedImage(
        frame->shared_image(), frame->acquire_sync_token(), 0u, sk_image_info,
        frame->shared_image()->GetTextureTarget(),
        frame->metadata().texture_origin_is_top_left,
        // Pass nullptr for |context_provider_wrapper|, because we don't
        // know which context the mailbox came from. It is used only to
        // detect when the mailbox is invalid due to context loss, and is
        // ignored when |is_cross_thread|.
        base::WeakPtr<WebGraphicsContext3DProviderWrapper>(),
        // Pass null |context_thread_ref|, again because we don't know
        // which context the mailbox came from. This should always trigger
        // |is_cross_thread|.
        base::PlatformThreadRef(),
        // The task runner is only used for |release_callback|.
        ThreadScheduler::Current()->CleanupTaskRunner(),
        std::move(release_callback),
        /*supports_display_compositing=*/true,
        // TODO(junov): Figure out how to determine whether frame is an
        // overlay candidate. StorageType info seems insufficient.
        /*is_overlay_candidate=*/false);
  }

  gfx::Rect final_dest_rect = dest_rect;
  if (final_dest_rect.IsEmpty()) {
    // Since we're copying, the destination is always aligned with the origin.
    const auto& visible_rect = frame->visible_rect();
    final_dest_rect =
        gfx::Rect(0, 0, visible_rect.width(), visible_rect.height());
    if (transform.rotation == media::VIDEO_ROTATION_90 ||
        transform.rotation == media::VIDEO_ROTATION_270) {
      final_dest_rect.Transpose();
    }
  } else if (!resource_provider) {
    DLOG(ERROR) << "An external CanvasResourceProvider must be provided when "
                   "providing a custom destination rect.";
    return nullptr;
  } else if (!gfx::Rect(resource_provider->Size()).Contains(final_dest_rect)) {
    DLOG(ERROR)
        << "Provided CanvasResourceProvider is too small. Expected at least "
        << final_dest_rect.ToString() << " got "
        << resource_provider->Size().ToString();
    return nullptr;
  }

  auto raster_context_provider = GetRasterContextProvider();
  // TODO(https://crbug.com/1341235): The choice of color type and alpha type
  // inappropriate in many circumstances.
  const auto resource_provider_info = SkImageInfo::Make(
      gfx::SizeToSkISize(final_dest_rect.size()), kN32_SkColorType,
      kPremul_SkAlphaType, frame_sk_color_space);
  std::unique_ptr<CanvasResourceProvider> local_resource_provider;
  if (!resource_provider) {
    local_resource_provider = CreateResourceProviderForVideoFrame(
        resource_provider_info, raster_context_provider.get());
    if (!local_resource_provider) {
      DLOG(ERROR) << "Failed to create CanvasResourceProvider.";
      return nullptr;
    }

    resource_provider = local_resource_provider.get();
  }

  if (resource_provider->IsAccelerated())
    prefer_tagged_orientation = false;

  if (!DrawVideoFrameIntoResourceProvider(
          std::move(frame), resource_provider, raster_context_provider.get(),
          final_dest_rect, video_renderer,
          /*ignore_video_transformation=*/prefer_tagged_orientation,
          /*reinterpret_video_as_srgb=*/reinterpret_video_as_srgb)) {
    return nullptr;
  }

  return resource_provider->Snapshot(
      FlushReason::kNon2DCanvas,
      prefer_tagged_orientation
          ? VideoTransformationToImageOrientation(transform)
          : ImageOrientationEnum::kDefault);
}

bool DrawVideoFrameIntoResourceProvider(
    scoped_refptr<media::VideoFrame> frame,
    CanvasResourceProvider* resource_provider,
    viz::RasterContextProvider* raster_context_provider,
    const gfx::Rect& dest_rect,
    media::PaintCanvasVideoRenderer* video_renderer,
    bool ignore_video_transformation,
    bool reinterpret_video_as_srgb) {
  DCHECK(frame);
  DCHECK(resource_provider);
  DCHECK(gfx::Rect(resource_provider->Size()).Contains(dest_rect));

  if (frame->HasSharedImage()) {
    if (!raster_context_provider) {
      DLOG(ERROR) << "Unable to process a texture backed VideoFrame w/o a "
                     "RasterContextProvider.";
      return false;  // Unable to get/create a shared main thread context.
    }
    if (!raster_context_provider->GrContext() &&
        !raster_context_provider->ContextCapabilities().gpu_rasterization) {
      DLOG(ERROR) << "Unable to process a texture backed VideoFrame w/o a "
                     "GrContext or OOP raster support.";
      return false;  // The context has been lost.
    }
  }

  cc::PaintFlags media_flags;
  media_flags.setAlphaf(1.0f);
  media_flags.setFilterQuality(cc::PaintFlags::FilterQuality::kLow);
  media_flags.setBlendMode(SkBlendMode::kSrc);

  std::unique_ptr<media::PaintCanvasVideoRenderer> local_video_renderer;
  if (!video_renderer) {
    local_video_renderer = std::make_unique<media::PaintCanvasVideoRenderer>();
    video_renderer = local_video_renderer.get();
  }

  // If the provider isn't accelerated, avoid GPU round trips to upload frame
  // data from GpuMemoryBuffer backed frames which aren't mappable.
  if (frame->HasMappableGpuBuffer() && !frame->IsMappable() &&
      !resource_provider->IsAccelerated()) {
    frame = media::ConvertToMemoryMappedFrame(std::move(frame));
    if (!frame) {
      DLOG(ERROR) << "Failed to map VideoFrame.";
      return false;
    }
  }

  media::PaintCanvasVideoRenderer::PaintParams params;
  params.dest_rect = gfx::RectF(dest_rect);
  params.transformation =
      ignore_video_transformation
          ? media::kNoTransformation
          : frame->metadata().transformation.value_or(media::kNoTransformation);
  params.reinterpret_as_srgb = reinterpret_video_as_srgb;
  video_renderer->Paint(frame.get(),
                        &resource_provider->Canvas(/*needs_will_draw*/ true),
                        media_flags, params, raster_context_provider);
  return true;
}

void DrawVideoFrameIntoCanvas(scoped_refptr<media::VideoFrame> frame,
                              cc::PaintCanvas* canvas,
                              cc::PaintFlags& flags,
                              bool ignore_video_transformation) {
  viz::RasterContextProvider* raster_context_provider = nullptr;
  if (auto wrapper = SharedGpuContext::ContextProviderWrapper()) {
    raster_context_provider =
        wrapper->ContextProvider()->RasterContextProvider();
  }

  media::PaintCanvasVideoRenderer video_renderer;
  media::PaintCanvasVideoRenderer::PaintParams params;
  params.dest_rect =
      gfx::RectF(frame->natural_size().width(), frame->natural_size().height());
  params.transformation =
      ignore_video_transformation
          ? media::kNoTransformation
          : frame->metadata().transformation.value_or(media::kNoTransformation);
  video_renderer.Paint(frame, canvas, flags, params, raster_context_provider);
}

scoped_refptr<viz::RasterContextProvider> GetRasterContextProvider() {
  auto wrapper = SharedGpuContext::ContextProviderWrapper();
  if (!wrapper)
    return nullptr;

  return base::WrapRefCounted(
      wrapper->ContextProvider()->RasterContextProvider());
}

std::unique_ptr<CanvasResourceProvider> CreateResourceProviderForVideoFrame(
    const SkImageInfo& info,
    viz::RasterContextProvider* raster_context_provider) {
  constexpr auto kFilterQuality = cc::PaintFlags::FilterQuality::kLow;
  constexpr auto kShouldInitialize =
      CanvasResourceProvider::ShouldInitialize::kNo;
  if (!ShouldCreateAcceleratedImages(raster_context_provider)) {
    return CanvasResourceProvider::CreateBitmapProvider(info, kFilterQuality,
                                                        kShouldInitialize);
  }
  return CanvasResourceProvider::CreateSharedImageProvider(
      info, kFilterQuality, kShouldInitialize,
      SharedGpuContext::ContextProviderWrapper(), RasterMode::kGPU,
      gpu::SHARED_IMAGE_USAGE_DISPLAY_READ);
}

}  // namespace blink

"""

```