Response:
My thinking process to analyze the `image.cc` file goes like this:

1. **Understand the Goal:** The primary request is to understand the functionalities of this file, its relation to web technologies (HTML, CSS, JavaScript), provide examples with hypothetical input/output, and highlight potential usage errors.

2. **Initial Skimming for Keywords and Structure:**  I'd quickly scan the code for obvious keywords related to images, drawing, rendering, and web concepts. I'd notice includes like `<SkCanvas.h>`, `"third_party/blink/public/platform/WebData.h"`, `"third_party/blink/renderer/platform/graphics/BitmapImage.h"`, `"third_party/blink/renderer/platform/graphics/GraphicsContext.h"`, and `"third_party/blink/renderer/platform/graphics/paint/PaintImage.h"`. This immediately tells me it's a core file for handling image data and rendering within the Blink engine. The namespace `blink` confirms this.

3. **Identify Key Classes and Functions:**  I'd then look for class definitions and important function names. `Image`, `BitmapImage`, `PaintImage`, `GraphicsContext`, `ImageObserver`, `ResizeAndOrientImage`, `DrawPattern`, `ApplyShader`, `SetData`, and `AsSkBitmapForCurrentFrame` stand out. These likely represent the core responsibilities of this file.

4. **Analyze Core Functionalities (Grouping by Purpose):** I'd start categorizing the identified functions based on their apparent purpose:

    * **Image Loading and Data Handling:** `Image::SetData`, `Image::LoadPlatformResource`. These deal with bringing image data into the system. The inclusion of `SharedBuffer` suggests handling of potentially large image data.
    * **Image Rendering and Drawing:** `Image::DrawPattern`, `Image::ApplyShader`, `GraphicsContext::DrawRect`, `SkCanvas::drawImage`, `SkSurface::makeImageSnapshot`. These are the workhorses for actually displaying images on the screen. The presence of "pattern" suggests handling of repeating background images.
    * **Image Manipulation and Transformation:** `Image::ResizeAndOrientImage`, `Image::CorrectSrcRectForImageOrientation`, `ImageOrientation`. This highlights functionalities like resizing, rotating, and handling EXIF orientation data.
    * **Image Representation and Abstraction:** `Image`, `BitmapImage`, `PaintImage`. I'd infer that `Image` is an abstract base class, with `BitmapImage` likely handling raster images. `PaintImage` appears to be a more modern representation used with Skia.
    * **Caching and Optimization:** `cc::ImageDecodeCache`, `DarkModeImageCache`. These point to mechanisms for improving performance by storing decoded image data.
    * **Animation:**  `Image::AnimationPolicy`, `Image::StartAnimation`. These indicate support for animated images.
    * **Null Image Handling:** `Image::NullImage`. This is a common pattern for representing the absence of an image.
    * **Dark Mode Support:**  `DarkModeImageCache`, `DarkModeImageClassifier`, and the usage of `draw_options.dark_mode_filter`.

5. **Relate to Web Technologies:**  Now, I'd connect these functionalities to HTML, CSS, and JavaScript:

    * **HTML:** The `<image>` tag is the most direct link. The `src` attribute would trigger image loading (handled by `SetData`, `LoadPlatformResource`). The `alt` attribute (not directly in this file, but related to image handling) provides alternative text.
    * **CSS:**  CSS properties like `background-image`, `list-style-image`, `content` (with `url()`), `image-orientation`, `object-fit`, `object-position`, `background-repeat`, and `background-size` directly influence how images are loaded, rendered, and manipulated. The `DrawPattern` function is clearly related to `background-repeat`. `ResizeAndOrientImage` relates to `image-orientation` and potentially `object-fit`.
    * **JavaScript:**  The JavaScript `Image()` constructor and the `<img>` element's properties and methods (`src`, `onload`, `onerror`, `getContext('2d').drawImage()`, `createImageBitmap()`) interact with the underlying image loading and rendering mechanisms provided by this file. Fetching images via `fetch()` or `XMLHttpRequest` also leads to data being processed by these functions.

6. **Construct Hypothetical Input/Output Examples:** For each key functionality, I'd create simple scenarios:

    * **Loading:** A URL as input, a `PaintImage` object as output (success) or a null image (failure).
    * **Resizing:**  A `PaintImage`, target dimensions, and orientation as input, a new `PaintImage` with the transformed properties as output.
    * **Pattern Drawing:**  Destination rectangle, tiling information, and a `PaintImage` as input, the image rendered repeatedly in the specified area.
    * **Shader Application:** A `PaintImage`, transformation matrix, and source rectangle as input, the `PaintFlags` object modified with the image shader.

7. **Identify Potential Usage Errors:** I'd think about common mistakes developers make with images:

    * **Incorrect Paths/URLs:** Leading to failed image loads.
    * **Large Images Without Optimization:**  Causing performance issues.
    * **Incorrect Image Orientation Handling:** Leading to unexpected image display.
    * **Misunderstanding Tiling and Spacing:** Resulting in incorrect background patterns.
    * **Using `drawImage` in Canvas without waiting for `onload`:** Trying to draw an image before it's loaded.
    * **Memory Leaks:** (Though not directly evidenced in this snippet, I might mention it as a general concern with image handling).

8. **Structure the Output:**  Finally, I'd organize the information logically, starting with a high-level summary of the file's purpose, then detailing the functionalities, the connections to web technologies with examples, the hypothetical input/output scenarios, and the potential usage errors. Using bullet points and clear headings helps improve readability.

By following these steps, I could systematically analyze the provided code snippet and generate a comprehensive and informative response. The key is to understand the domain (web browser rendering), identify the core responsibilities of the code, and connect them to the higher-level concepts of web development.
这个 `blink/renderer/platform/graphics/image.cc` 文件是 Chromium Blink 渲染引擎中负责处理图像的核心组件之一。它定义了 `Image` 类及其相关功能，提供了加载、解码、绘制和操作各种图像的基础设施。

以下是该文件主要的功能以及与 JavaScript、HTML 和 CSS 的关系：

**主要功能：**

1. **图像抽象基类:** `Image` 是一个抽象基类，定义了所有图像类型（例如，位图、SVG）的通用接口。它提供了一些基本属性和方法，如获取图像尺寸、检查是否已加载完成等。

2. **图像数据管理:**
   - **`SetData(scoped_refptr<SharedBuffer> data, bool all_data_received)`:**  负责接收和存储图像的二进制数据。`SharedBuffer` 用于高效地管理内存中的数据。`all_data_received` 标志指示是否已接收到完整的图像数据。
   - **`encoded_image_data_`:** 存储接收到的图像数据。

3. **图像加载:**
   - **`LoadPlatformResource(int resource_id, ui::ResourceScaleFactor scale_factor)`:** 用于加载平台相关的资源，例如浏览器自带的图标。

4. **图像绘制:**
   - **`DrawPattern(GraphicsContext& context, const cc::PaintFlags& base_flags, const gfx::RectF& dest_rect, const ImageTilingInfo& tiling_info, const ImageDrawOptions& draw_options)`:**  核心功能之一，用于在指定的区域内绘制图像，并支持平铺（pattern）效果。它考虑了图像的缩放、平铺方式、相位偏移等。
   - **`ApplyShader(cc::PaintFlags& flags, const SkMatrix& local_matrix, const gfx::RectF& src_rect, const ImageDrawOptions& draw_options)`:**  允许将图像作为 shader 应用到绘制操作中，例如用图像填充形状。

5. **图像变换和方向处理:**
   - **`ResizeAndOrientImage(const PaintImage& image, ImageOrientation orientation, gfx::Vector2dF image_scale, float opacity, InterpolationQuality interpolation_quality, sk_sp<SkColorSpace> color_space)`:**  用于调整图像的大小、应用方向信息（例如，从 EXIF 元数据中读取的方向），并调整透明度。
   - **`CorrectSrcRectForImageOrientation(gfx::SizeF image_size, gfx::RectF src_rect) const`:**  根据图像的方向校正源矩形。

6. **图像表示:**
   - **`PaintImage`:**  使用 Skia 的 `PaintImage` 对象来表示图像，这是一个更现代和高效的图像表示方式，支持各种图像格式和特性。
   - **`AsSkBitmapForCurrentFrame(RespectImageOrientationEnum respect_image_orientation)`:**  将当前帧的图像转换为 Skia 的 `SkBitmap` 对象。

7. **动画支持:**
   - **`AnimationPolicy()`:**  返回图像的动画策略。
   - **`StartAnimation()`:**  启动图像动画。

8. **暗黑模式支持:**
   - **`DarkModeImageCache`:**  用于缓存暗黑模式下的图像变体。
   - **`DarkModeImageClassifier`:**  用于判断图像是否适合进行暗黑模式调整。

9. **缓存:**
   - **`SharedCCDecodeCache(SkColorType color_type)`:**  使用 Chromium 合成器的解码缓存来加速图像的解码。

10. **NullImage:**
    - **`NullImage()`:** 提供一个静态的空图像实例，用于表示图像加载失败或其他需要空图像的情况。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML (`<img>` 标签, CSS `background-image` 等):**
    - 当浏览器解析 HTML 遇到 `<img>` 标签时，会创建一个 `Image` 对象（通常是 `BitmapImage` 或其他子类）。
    - `<img>` 标签的 `src` 属性指向的图像 URL 会触发图像数据的加载，最终数据会传递给 `Image::SetData`。
    - CSS 的 `background-image` 属性也会触发类似的过程，加载并使用图像作为背景。
    - CSS 的 `image-orientation` 属性会影响 `ResizeAndOrientImage` 的行为。
    - CSS 的 `background-repeat`, `background-size`, `background-position` 等属性与 `DrawPattern` 函数中的 `ImageTilingInfo` 和绘制逻辑密切相关。

    **举例说明 (HTML):**
    ```html
    <img src="image.png" alt="An example image">
    ```
    **假设输入:**  `src` 属性对应的 "image.png" 的二进制数据。
    **输出:**  一个 `Image` 对象，其 `encoded_image_data_` 存储了图像数据，并且可以用于后续的渲染。

    **举例说明 (CSS):**
    ```css
    .element {
      background-image: url("pattern.png");
      background-repeat: repeat-x;
    }
    ```
    **假设输入:** "pattern.png" 的二进制数据，以及 `background-repeat: repeat-x` 的信息。
    **输出:** 在绘制 `.element` 的背景时，`DrawPattern` 函数会被调用，使用 "pattern.png" 的图像数据进行水平平铺。

* **JavaScript (Image 对象, Canvas API):**
    - JavaScript 可以通过 `new Image()` 创建图像对象，并设置其 `src` 属性来触发图像加载。加载完成后，可以通过 `onload` 事件来处理。
    - Canvas API 的 `drawImage()` 方法最终会调用 Blink 引擎底层的图像绘制功能，包括 `Image::DrawPattern` 或其他的绘制方法。
    - JavaScript 可以通过 `createImageBitmap()` API 创建 `ImageBitmap` 对象，这也会涉及到 Blink 的图像处理流程。

    **举例说明 (JavaScript):**
    ```javascript
    const img = new Image();
    img.onload = function() {
      console.log("Image loaded!");
      // 可以将 img 绘制到 canvas 上
    };
    img.src = "another_image.jpg";
    ```
    **假设输入:** "another_image.jpg" 的二进制数据。
    **输出:**  当图像加载完成时，`onload` 事件被触发。如果之后使用 Canvas API 绘制此图像，`Image` 对象的数据会被传递给底层的渲染函数。

    **举例说明 (Canvas API):**
    ```javascript
    const canvas = document.getElementById('myCanvas');
    const ctx = canvas.getContext('2d');
    const image = new Image();
    image.onload = function() {
      ctx.drawImage(image, 10, 10);
    };
    image.src = 'canvas_image.png';
    ```
    **假设输入:**  `canvas_image.png` 的 `Image` 对象，以及绘制的坐标 (10, 10)。
    **输出:**  在 Canvas 上 (10, 10) 的位置绘制出 `canvas_image.png` 的内容。这个过程会调用 `Image` 类的相关绘制方法。

**逻辑推理的假设输入与输出:**

* **假设输入 (ResizeAndOrientImage):**
    - `image`: 一个 `PaintImage` 对象，宽度 100px，高度 50px。
    - `orientation`: `ImageOrientation::kRotate90` (旋转 90 度)。
    - `image_scale`: `gfx::Vector2dF(0.5, 0.5)` (缩放 50%)。
    - `opacity`: `1.0` (不透明)。
    - `interpolation_quality`: `kInterpolationLow`.
* **输出 (ResizeAndOrientImage):**
    - 一个新的 `PaintImage` 对象，宽度 25px (50 * 0.5)，高度 50px (100 * 0.5)，并且内容是原始图像旋转 90 度并缩小后的结果。

* **假设输入 (DrawPattern):**
    - `dest_rect`: `gfx::RectF(0, 0, 200, 100)` (目标绘制区域)。
    - `tiling_info`:
        - `image_rect`: `gfx::RectF(0, 0, 50, 50)` (源图像的子区域)。
        - `scale`: `gfx::Vector2dF(1, 1)` (不缩放)。
        - `phase`: `gfx::PointF(10, 10)` (相位偏移)。
        - `spacing`: `gfx::SizeF(5, 5)` (间距)。
    - `image`: 一个 50x50 的 `PaintImage` 对象。
* **输出 (DrawPattern):**
    - 在 `GraphicsContext` 中，以 (10, 10) 作为起始点，平铺绘制 `image` 对象中 (0, 0, 50, 50) 的区域，平铺间距为 5px，最终在 (0, 0, 200, 100) 的区域内形成平铺图案。

**涉及用户或编程常见的使用错误:**

1. **加载不存在的图像 URL:**
   - **错误:**  在 HTML 或 JavaScript 中使用了错误的图像路径或 URL。
   - **后果:**  `Image::SetData` 可能接收到空数据或错误的数据，导致图像加载失败，`NullImage()` 可能被使用。在页面上可能显示 broken image 图标或者背景无法显示。

2. **处理图像加载完成事件不当:**
   - **错误:**  在 JavaScript 中尝试在图像加载完成之前就使用它，例如在 Canvas 上绘制。
   - **后果:**  可能绘制不出图像或者绘制不完整。应该确保在 `onload` 事件触发后才进行操作。

3. **大尺寸图像未进行优化:**
   - **错误:**  使用非常大的图像作为背景或 `<img>` 的 `src`，但没有进行压缩或调整尺寸。
   - **后果:**  会导致页面加载缓慢，占用大量内存，可能导致性能问题甚至崩溃。

4. **不理解图像方向 (orientation) 信息:**
   - **错误:**  直接使用图像的原始尺寸和数据进行绘制，而忽略了 EXIF 元数据中可能存在的方向信息。
   - **后果:**  图像可能旋转了 90 度、180 度或 270 度，导致显示方向错误。应该使用类似 `ResizeAndOrientImage` 的方法进行处理。

5. **错误地使用平铺参数:**
   - **错误:**  在 CSS 或通过 `ImageTilingInfo` 设置错误的平铺模式、相位或间距。
   - **后果:**  背景图案可能无法正确显示，出现错位、重叠或空白。

6. **跨域问题 (CORS):**
   - **错误:**  尝试在 Canvas 中使用来自不同域名的图像，而目标服务器没有设置正确的 CORS 头。
   - **后果:**  可能导致 Canvas 污染，无法进行某些操作，例如 `getImageData()`。

7. **内存泄漏:**
   - **错误:**  在某些情况下，如果图像对象没有被正确释放，可能会导致内存泄漏，尤其是在处理大量动态加载的图像时。尽管 `scoped_refptr` 有助于管理内存，但仍然需要注意避免循环引用等问题。

理解 `blink/renderer/platform/graphics/image.cc` 的功能对于理解 Blink 引擎如何处理图像至关重要，也能够帮助开发者避免一些常见的图像使用错误，并优化 Web 应用的性能。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/image.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2006 Samuel Weinig (sam.weinig@gmail.com)
 * Copyright (C) 2004, 2005, 2006 Apple Computer, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/graphics/image.h"

#include <math.h>

#include <tuple>

#include "base/numerics/checked_math.h"
#include "build/build_config.h"
#include "cc/tiles/software_image_decode_cache.h"
#include "third_party/blink/public/mojom/webpreferences/web_preferences.mojom-blink.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/web_data.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"
#include "third_party/blink/renderer/platform/graphics/dark_mode_image_cache.h"
#include "third_party/blink/renderer/platform/graphics/dark_mode_image_classifier.h"
#include "third_party/blink/renderer/platform/graphics/deferred_image_decoder.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_image.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_recorder.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_shader.h"
#include "third_party/blink/renderer/platform/instrumentation/histogram.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkSurface.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/rect_f.h"
#include "ui/gfx/geometry/size_f.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {

Image::Image(ImageObserver* observer, bool is_multipart)
    : image_observer_disabled_(false),
      image_observer_(observer),
      stable_image_id_(PaintImage::GetNextId()),
      is_multipart_(is_multipart) {}

Image::~Image() = default;

Image* Image::NullImage() {
  DCHECK(IsMainThread());
  DEFINE_STATIC_REF(Image, null_image, (BitmapImage::Create()));
  return null_image;
}

// static
cc::ImageDecodeCache& Image::SharedCCDecodeCache(SkColorType color_type) {
  // This denotes the allocated locked memory budget for the cache used for
  // book-keeping. The cache indicates when the total memory locked exceeds this
  // budget in cc::DecodedDrawImage.
  DCHECK(color_type == kN32_SkColorType || color_type == kRGBA_F16_SkColorType);
  static const size_t kLockedMemoryLimitBytes = 64 * 1024 * 1024;
  if (color_type == kRGBA_F16_SkColorType) {
    DEFINE_THREAD_SAFE_STATIC_LOCAL(
        cc::SoftwareImageDecodeCache, image_decode_cache,
        (kRGBA_F16_SkColorType, kLockedMemoryLimitBytes));
    return image_decode_cache;
  }
  DEFINE_THREAD_SAFE_STATIC_LOCAL(cc::SoftwareImageDecodeCache,
                                  image_decode_cache,
                                  (kN32_SkColorType, kLockedMemoryLimitBytes));
  return image_decode_cache;
}

scoped_refptr<Image> Image::LoadPlatformResource(
    int resource_id,
    ui::ResourceScaleFactor scale_factor) {
  const WebData& resource =
      Platform::Current()->GetDataResource(resource_id, scale_factor);
  if (resource.IsEmpty())
    return Image::NullImage();

  scoped_refptr<Image> image = BitmapImage::Create();
  image->SetData(resource, true);
  return image;
}

PaintImage Image::ResizeAndOrientImage(
    const PaintImage& image,
    ImageOrientation orientation,
    gfx::Vector2dF image_scale,
    float opacity,
    InterpolationQuality interpolation_quality) {
  return ResizeAndOrientImage(image, orientation, image_scale, opacity,
                              interpolation_quality, nullptr);
}

// static
PaintImage Image::ResizeAndOrientImage(
    const PaintImage& image,
    ImageOrientation orientation,
    gfx::Vector2dF image_scale,
    float opacity,
    InterpolationQuality interpolation_quality,
    sk_sp<SkColorSpace> color_space) {
  gfx::Size size(image.width(), image.height());
  size = gfx::ScaleToFlooredSize(size, image_scale.x(), image_scale.y());
  AffineTransform transform;
  if (orientation != ImageOrientationEnum::kDefault) {
    if (orientation.UsesWidthAsHeight())
      size.Transpose();
    transform *= orientation.TransformFromDefault(gfx::SizeF(size));
  }
  transform.ScaleNonUniform(image_scale.x(), image_scale.y());

  if (size.IsEmpty())
    return PaintImage();

  const auto image_color_space = image.GetSkImageInfo().colorSpace()
                                     ? image.GetSkImageInfo().refColorSpace()
                                     : SkColorSpace::MakeSRGB();
  const auto surface_color_space =
      color_space ? color_space : image_color_space;
  const bool needs_color_conversion =
      !SkColorSpace::Equals(image_color_space.get(), surface_color_space.get());

  if (transform.IsIdentity() && opacity == 1 && !needs_color_conversion) {
    // Nothing to adjust, just use the original.
    DCHECK_EQ(image.width(), size.width());
    DCHECK_EQ(image.height(), size.height());
    return image;
  }

  const SkImageInfo surface_info = SkImageInfo::MakeN32(
      size.width(), size.height(), image.GetSkImageInfo().alphaType(),
      surface_color_space);
  sk_sp<SkSurface> surface = SkSurfaces::Raster(surface_info);
  if (!surface)
    return PaintImage();

  SkPaint paint;
  DCHECK_GE(opacity, 0);
  DCHECK_LE(opacity, 1);
  paint.setAlpha(opacity * 255);
  SkSamplingOptions sampling;
  if (interpolation_quality != kInterpolationNone)
    sampling = SkSamplingOptions(SkCubicResampler::CatmullRom());

  SkCanvas* canvas = surface->getCanvas();
  canvas->concat(AffineTransformToSkMatrix(transform));
  canvas->drawImage(image.GetSwSkImage(), 0, 0, sampling, &paint);

  return PaintImageBuilder::WithProperties(std::move(image))
      .set_image(surface->makeImageSnapshot(), PaintImage::GetNextContentId())
      .TakePaintImage();
}

Image::SizeAvailability Image::SetData(scoped_refptr<SharedBuffer> data,
                                       bool all_data_received) {
  encoded_image_data_ = std::move(data);
  if (!encoded_image_data_.get())
    return kSizeAvailable;

  size_t length = encoded_image_data_->size();
  if (!length)
    return kSizeAvailable;

  return DataChanged(all_data_received);
}

String Image::FilenameExtension() const {
  return String();
}

const AtomicString& Image::MimeType() const {
  return g_empty_atom;
}

namespace {

sk_sp<PaintShader> CreatePatternShader(const PaintImage& image,
                                       const SkMatrix& shader_matrix,
                                       const SkSamplingOptions& sampling,
                                       bool should_antialias,
                                       const gfx::SizeF& spacing,
                                       SkTileMode tmx,
                                       SkTileMode tmy,
                                       const gfx::Rect& subset_rect) {
  if (spacing.IsZero() &&
      subset_rect == gfx::Rect(image.width(), image.height())) {
    return PaintShader::MakeImage(image, tmx, tmy, &shader_matrix);
  }

  // Arbitrary tiling is currently only supported for SkPictureShader, so we use
  // that instead of a plain bitmap shader to implement spacing.
  const SkRect tile_rect =
      SkRect::MakeWH(subset_rect.width() + spacing.width(),
                     subset_rect.height() + spacing.height());

  PaintRecorder recorder;
  cc::PaintCanvas* canvas = recorder.beginRecording();
  cc::PaintFlags flags;
  flags.setAntiAlias(should_antialias);
  canvas->drawImageRect(
      image, gfx::RectToSkRect(subset_rect),
      SkRect::MakeWH(subset_rect.width(), subset_rect.height()), sampling,
      &flags, SkCanvas::kStrict_SrcRectConstraint);

  return PaintShader::MakePaintRecord(recorder.finishRecordingAsPicture(),
                                      tile_rect, tmx, tmy, &shader_matrix);
}

SkTileMode ComputeTileMode(float left, float right, float min, float max) {
  DCHECK(left < right);
  return left >= min && right <= max ? SkTileMode::kClamp : SkTileMode::kRepeat;
}

}  // anonymous namespace

void Image::DrawPattern(GraphicsContext& context,
                        const cc::PaintFlags& base_flags,
                        const gfx::RectF& dest_rect,
                        const ImageTilingInfo& tiling_info,
                        const ImageDrawOptions& draw_options) {
  TRACE_EVENT0("skia", "Image::drawPattern");

  if (dest_rect.IsEmpty())
    return;  // nothing to draw

  PaintImage image = PaintImageForCurrentFrame();
  if (!image)
    return;  // nothing to draw

  // Fetch orientation data if needed.
  ImageOrientation orientation = ImageOrientationEnum::kDefault;
  if (draw_options.respect_orientation)
    orientation = CurrentFrameOrientation();

  // |tiling_info.image_rect| is in source image space, unscaled but oriented.
  // image-resolution information is baked into |tiling_info.scale|,
  // so we do not want to use it in computing the subset. That requires
  // explicitly applying orientation here.
  gfx::Rect subset_rect = gfx::ToEnclosingRect(tiling_info.image_rect);
  gfx::Size oriented_image_size(image.width(), image.height());
  if (orientation.UsesWidthAsHeight())
    oriented_image_size.Transpose();
  subset_rect.Intersect(gfx::Rect(oriented_image_size));
  if (subset_rect.IsEmpty())
    return;  // nothing to draw

  // Apply image orientation, if necessary
  if (orientation != ImageOrientationEnum::kDefault)
    image = ResizeAndOrientImage(image, orientation);

  // We also need to translate it such that the origin of the pattern is the
  // origin of the destination rect, which is what Blink expects. Skia uses
  // the coordinate system origin as the base for the pattern. If Blink wants
  // a shifted image, it will shift it from there using the localMatrix.
  gfx::RectF tile_rect(subset_rect);
  tile_rect.Scale(tiling_info.scale.x(), tiling_info.scale.y());
  tile_rect.Offset(tiling_info.phase.OffsetFromOrigin());
  tile_rect.set_size(tile_rect.size() + tiling_info.spacing);

  SkMatrix local_matrix;
  local_matrix.setTranslate(tile_rect.x(), tile_rect.y());
  // Apply the scale to have the subset correctly fill the destination.
  local_matrix.preScale(tiling_info.scale.x(), tiling_info.scale.y());

  const auto tmx = ComputeTileMode(dest_rect.x(), dest_rect.right(),
                                   tile_rect.x(), tile_rect.right());
  const auto tmy = ComputeTileMode(dest_rect.y(), dest_rect.bottom(),
                                   tile_rect.y(), tile_rect.bottom());

  // Fetch this now as subsetting may swap the image.
  auto image_id = image.stable_id();

  SkSamplingOptions sampling_to_use =
      context.ComputeSamplingOptions(*this, dest_rect, gfx::RectF(subset_rect));
  sk_sp<PaintShader> tile_shader = CreatePatternShader(
      image, local_matrix, sampling_to_use, context.ShouldAntialias(),
      gfx::SizeF(tiling_info.spacing.width() / tiling_info.scale.x(),
                 tiling_info.spacing.height() / tiling_info.scale.y()),
      tmx, tmy, subset_rect);

  // If the shader could not be instantiated (e.g. non-invertible matrix),
  // draw transparent.
  // Note: we can't simply bail, because of arbitrary blend mode.
  cc::PaintFlags flags(base_flags);
  flags.setColor(tile_shader ? SK_ColorBLACK : SK_ColorTRANSPARENT);
  flags.setShader(std::move(tile_shader));
  if (draw_options.dark_mode_filter) {
    draw_options.dark_mode_filter->ApplyFilterToImage(
        this, &flags, gfx::RectToSkRect(subset_rect));
  }

  context.DrawRect(gfx::RectFToSkRect(dest_rect), flags,
                   AutoDarkMode::Disabled());

  StartAnimation();

  if (CurrentFrameIsLazyDecoded()) {
    TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                         "Draw LazyPixelRef", TRACE_EVENT_SCOPE_THREAD,
                         "LazyPixelRef", image_id);
  }
}

mojom::blink::ImageAnimationPolicy Image::AnimationPolicy() {
  return mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAllowed;
}

scoped_refptr<Image> Image::ImageForDefaultFrame() {
  scoped_refptr<Image> image(this);

  return image;
}

PaintImageBuilder Image::CreatePaintImageBuilder() {
  auto animation_type = MaybeAnimated() ? PaintImage::AnimationType::kAnimated
                                        : PaintImage::AnimationType::kStatic;
  return PaintImageBuilder::WithDefault()
      .set_id(stable_image_id_)
      .set_animation_type(animation_type)
      .set_is_multipart(is_multipart_);
}

bool Image::ApplyShader(cc::PaintFlags& flags,
                        const SkMatrix& local_matrix,
                        const gfx::RectF& src_rect,
                        const ImageDrawOptions& draw_options) {
  // Default shader impl: attempt to build a shader based on the current frame
  // SkImage.
  PaintImage image = PaintImageForCurrentFrame();
  if (!image)
    return false;

  if (draw_options.dark_mode_filter) {
    draw_options.dark_mode_filter->ApplyFilterToImage(
        this, &flags, gfx::RectFToSkRect(src_rect));
  }
  flags.setShader(PaintShader::MakeImage(image, SkTileMode::kClamp,
                                         SkTileMode::kClamp, &local_matrix));
  if (!flags.HasShader())
    return false;

  // Animation is normally refreshed in draw() impls, which we don't call when
  // painting via shaders.
  StartAnimation();

  return true;
}

SkBitmap Image::AsSkBitmapForCurrentFrame(
    RespectImageOrientationEnum respect_image_orientation) {
  PaintImage paint_image = PaintImageForCurrentFrame();
  if (!paint_image)
    return {};

  if (auto* bitmap_image = DynamicTo<BitmapImage>(this)) {
    const gfx::Size paint_image_size(paint_image.width(), paint_image.height());
    const gfx::Size density_corrected_size =
        bitmap_image->DensityCorrectedSize();

    ImageOrientation orientation = ImageOrientationEnum::kDefault;
    if (respect_image_orientation == kRespectImageOrientation)
      orientation = bitmap_image->CurrentFrameOrientation();

    gfx::Vector2dF image_scale(1, 1);
    if (density_corrected_size != paint_image_size) {
      image_scale = gfx::Vector2dF(
          density_corrected_size.width() / paint_image_size.width(),
          density_corrected_size.height() / paint_image_size.height());
    }

    paint_image = ResizeAndOrientImage(paint_image, orientation, image_scale);
    if (!paint_image)
      return {};
  }

  sk_sp<SkImage> sk_image = paint_image.GetSwSkImage();
  if (!sk_image)
    return {};

  SkBitmap bitmap;
  sk_image->asLegacyBitmap(&bitmap);
  return bitmap;
}

DarkModeImageCache* Image::GetDarkModeImageCache() {
  if (!dark_mode_image_cache_)
    dark_mode_image_cache_ = std::make_unique<DarkModeImageCache>();

  return dark_mode_image_cache_.get();
}

gfx::RectF Image::CorrectSrcRectForImageOrientation(gfx::SizeF image_size,
                                                    gfx::RectF src_rect) const {
  ImageOrientation orientation = CurrentFrameOrientation();
  DCHECK(orientation != ImageOrientationEnum::kDefault);
  AffineTransform forward_map = orientation.TransformFromDefault(image_size);
  AffineTransform inverse_map = forward_map.Inverse();
  return inverse_map.MapRect(src_rect);
}

}  // namespace blink

"""

```