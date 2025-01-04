Response:
Let's break down the thought process for analyzing the `bitmap_image.cc` file.

**1. Initial Skim and Identify Core Purpose:**

The first thing I'd do is quickly read through the code, paying attention to class names, method names, and included headers. I see `BitmapImage`, inheritance from `Image`, and inclusions like `ImageDecoder`, `PaintImage`, `cc::PaintCanvas`, and `gfx::RectF`. This immediately suggests that this file is responsible for handling bitmap images within the Blink rendering engine. The "graphics" directory in the path reinforces this.

**2. Focus on Public Methods - Functionality:**

Next, I'd focus on the public methods of the `BitmapImage` class. These are the primary ways other parts of the engine interact with this class. I'd list them out and try to understand their purpose:

* `BitmapImage(ImageObserver* observer, bool is_multipart)`: Constructor. Takes an observer (for notifications) and a flag for multipart images.
* `~BitmapImage()`: Destructor.
* `CurrentFrameHasSingleSecurityOrigin()`: Related to security.
* `DestroyDecodedData()`:  Frees up memory.
* `Data()`: Accesses the raw image data.
* `HasData()`: Checks if there's data.
* `DataSize()`: Gets the size of the data.
* `NotifyMemoryChanged()`:  Informs the observer about memory changes.
* `TotalFrameBytes()`: Calculates the memory used by the current frame.
* `PaintImageForTesting()` and `CreatePaintImage()`: Methods for creating a `PaintImage` (likely for drawing).
* `UpdateSize()`: Updates the image dimensions.
* `SizeWithConfig()`: Gets the size with optional transformations.
* `RecordDecodedImageType()`:  Logs the image type.
* `GetHotSpot()`: Gets the image's hotspot (for cursors, etc.).
* `SetData()`:  Sets the image data.
* `DataChanged()`: Handles data updates.
* `HasColorProfile()`: Checks for embedded color profiles.
* `FilenameExtension()`: Gets the file extension.
* `MimeType()`: Gets the MIME type.
* `Draw()`:  The core drawing function.
* `FrameCount()`: Gets the number of frames (for animated images).
* `IsSizeAvailable()`: Checks if the image size is known.
* `PaintImageForCurrentFrame()`: Gets the `PaintImage` for the current frame.
* `ImageForDefaultFrame()`:  Gets a static version of the image.
* `CurrentFrameKnownToBeOpaque()`: Checks for opacity.
* `CurrentFrameIsComplete()`: Checks if the current frame is fully loaded.
* `CurrentFrameIsLazyDecoded()`: Checks if it's lazy loaded.
* `CurrentFrameOrientation()`: Gets the orientation.
* `RepetitionCount()`: Gets the animation loop count.
* `ResetAnimation()`: Resets the animation.
* `MaybeAnimated()`: Checks if the image might be animated.
* `SetAnimationPolicy()`: Controls animation behavior.

From this list, I can infer the primary functions: loading, decoding, storing, drawing, and managing animated bitmap images.

**3. Identify Relationships with Web Technologies:**

Now, I'd think about how these functions relate to JavaScript, HTML, and CSS:

* **HTML `<img>` tag:**  The `BitmapImage` class is fundamental to rendering images loaded through the `<img>` tag. The `src` attribute of the `<img>` tag triggers the loading of image data, which would eventually be processed by `BitmapImage`.
* **CSS `background-image`:**  Similar to the `<img>` tag, CSS `background-image` properties also rely on `BitmapImage` to render background images.
* **JavaScript Image API:**  The JavaScript `Image()` constructor allows for programmatic image loading. The resulting `Image` object in JavaScript is backed by the Blink rendering engine, likely involving `BitmapImage` for bitmap formats.
* **Canvas API:** The `<canvas>` element and its 2D rendering context (`CanvasRenderingContext2D`) offer methods like `drawImage()`. The `BitmapImage::Draw()` method is directly involved in drawing the image onto the canvas.
* **Animation (CSS and JavaScript):**  The methods related to animation (`RepetitionCount`, `ResetAnimation`, `SetAnimationPolicy`, `MaybeAnimated`) are crucial for handling animated GIFs, APNGs, and potentially other animated bitmap formats, whether driven by CSS animations/transitions or JavaScript.

**4. Logical Reasoning and Hypothetical Scenarios:**

Consider specific methods and how they might work:

* **`SetData()` and `DataChanged()`:** Imagine providing image data in chunks. `SetData()` would append the data, and `DataChanged()` would trigger partial decoding and size updates as more data arrives.
    * *Input (Hypothetical):* A series of `SetData()` calls with increasing amounts of JPEG data, with the final call having `all_data_received = true`.
    * *Output:*  Initially, `IsSizeAvailable()` would be `false`. As more data arrives and `DataChanged()` is called, it would eventually become `true`. `FrameCount()` would likely be 1 for a static JPEG.

* **`Draw()`:** Think about scaling and transformations.
    * *Input:* A `BitmapImage` object, a destination rectangle smaller than the image's source rectangle.
    * *Output:* The `Draw()` method, using the `src_rect` and `dst_rect`, would draw a scaled-down portion of the image within the specified destination.

**5. Common Usage Errors:**

Think about how developers might misuse image loading and rendering:

* **Not waiting for image load:**  Trying to draw an image to a canvas before it's fully loaded (`IsSizeAvailable()` is false) could result in nothing being drawn or incomplete images.
* **Incorrectly sized destination rectangle:** Providing a zero-width or zero-height destination rectangle to `Draw()` will result in nothing being drawn. The code explicitly checks for this.
* **Misunderstanding animation policies:**  A developer might expect an animated GIF to loop indefinitely but hasn't set the appropriate animation policy or the GIF itself might have a limited loop count.
* **Memory Leaks (Less likely to be a *direct* user error with *this* class but worth considering):** While the code manages memory, holding onto large `BitmapImage` objects unnecessarily can lead to memory issues in the browser.

**6. Review and Refine:**

Finally, review the generated points for clarity, accuracy, and completeness. Ensure the explanations for the relationships with web technologies are specific and provide concrete examples. Make sure the hypothetical scenarios and usage errors are realistic and helpful. For example, initially, I might just say "handles drawing," but refining it to mention the Canvas API and the `drawImage()` method makes it more specific and useful.

This iterative process of skimming, focusing on key elements, connecting to web technologies, reasoning through scenarios, and considering errors allows for a comprehensive understanding of the `bitmap_image.cc` file's role.
这个文件 `blink/renderer/platform/graphics/bitmap_image.cc` 是 Chromium Blink 引擎中处理位图图像的核心组件。它负责管理和表示各种位图图像格式（如 JPEG, PNG, GIF 等）。

以下是它的主要功能：

**1. 图像数据的管理和解码:**

* **加载图像数据:**  它接收来自网络或其他来源的原始图像数据 (`scoped_refptr<SharedBuffer> data`)。
* **使用解码器:**  它内部使用 `DeferredImageDecoder` 来处理不同图像格式的解码。`DeferredImageDecoder` 会根据图像的 MIME 类型选择合适的解码器。
* **管理解码状态:** 跟踪图像数据是否完整接收 (`all_data_received_`)，以及图像尺寸是否已知 (`have_size_`, `size_available_`)。
* **缓存解码后的帧:**  解码后的图像帧会缓存到 `cached_frame_` 中，以提高重复绘制的性能。
* **处理动画:**  对于动画图像（如 GIF, APNG），它会管理帧数 (`frame_count_`) 和循环次数 (`repetition_count_`)。
* **延迟解码:** 支持延迟解码，只在需要绘制时才真正解码图像，提高初始页面加载速度。

**2. 图像属性的获取:**

* **获取图像尺寸:** 提供获取图像原始尺寸 (`size_`) 和考虑设备像素比后的尺寸 (`density_corrected_size_`) 的方法。
* **获取帧数和循环次数:**  对于动画图像，可以获取帧数 (`FrameCount()`) 和循环次数 (`RepetitionCount()`)。
* **获取MIME类型和文件名扩展名:**  可以获取图像的 MIME 类型 (`MimeType()`) 和文件名扩展名 (`FilenameExtension()`)。
* **获取热点:**  如果图像包含热点信息（用于光标等），可以获取 (`GetHotSpot()`).
* **判断透明度:** 可以判断当前帧是否已知是不透明的 (`CurrentFrameKnownToBeOpaque()`).
* **判断完整性:**  可以判断当前帧是否已完全接收 (`CurrentFrameIsComplete()`).
* **判断是否支持颜色配置文件:**  可以判断图像是否包含嵌入的颜色配置文件 (`HasColorProfile()`).

**3. 图像的绘制:**

* **提供绘制接口:**  核心功能是通过 `Draw()` 方法将图像绘制到 `cc::PaintCanvas` 上。
* **处理缩放和裁剪:**  `Draw()` 方法接受源矩形 (`src_rect`) 和目标矩形 (`dst_rect`) 参数，用于指定绘制图像的哪一部分以及绘制到哪里。
* **应用绘制选项:**  支持 `ImageDrawOptions`，允许指定解码模式、是否考虑图像方向 (`respect_orientation`) 等。
* **处理图像方向:**  根据图像的 Exif 信息或其他元数据，调整绘制方向 (`CurrentFrameOrientation()`).
* **支持暗黑模式滤镜:**  可以应用暗黑模式滤镜 (`draw_options.dark_mode_filter`).
* **启动动画:**  在绘制后可能会启动动画 (`StartAnimation()`).

**4. 与其他 Blink 组件的交互:**

* **`ImageObserver`:**  通过 `ImageObserver` 接口通知其他组件图像解码状态、尺寸变化等事件。
* **`PaintImage`:**  创建 `PaintImage` 对象，这是 Blink 中用于绘制的基础图像表示。`BitmapImage` 将其解码后的数据封装到 `PaintImage` 中供渲染管线使用。
* **`SharedBuffer`:**  用于存储原始的图像数据。
* **`DeferredImageDecoder`:**  委托图像解码任务。
* **`cc::PaintCanvas`:**  Skia 图形库提供的画布，`BitmapImage` 将图像绘制到这个画布上。

**它与 Javascript, HTML, CSS 的功能关系:**

`BitmapImage` 是浏览器渲染引擎的核心部分，直接参与了网页上图像的显示。

* **HTML (`<img>` 标签):** 当浏览器解析 HTML，遇到 `<img>` 标签时，会根据 `src` 属性加载图像资源。加载的图像数据最终会传递给 `BitmapImage` 进行处理和渲染。
    * **举例:**  `<img src="image.png">`  当浏览器加载 `image.png` 时，`BitmapImage` 会负责解码这个 PNG 文件，并最终在页面上渲染出来。
* **CSS (`background-image` 属性):** CSS 的 `background-image` 属性用于设置元素的背景图像。浏览器加载背景图像的过程也涉及到 `BitmapImage`。
    * **举例:**  `.element { background-image: url("bg.jpg"); }`  加载 `bg.jpg` 作为背景图时，`BitmapImage` 负责解码和渲染。
* **Javascript (Image API, Canvas API):**
    * **`Image()` 构造函数:**  JavaScript 可以使用 `new Image()` 创建 Image 对象，然后设置 `src` 属性来加载图像。这个过程在 Blink 内部会使用 `BitmapImage` 来处理加载的图像。
        * **假设输入:** JavaScript 代码 `const img = new Image(); img.src = 'animated.gif';`
        * **输出:**  Blink 会创建 `BitmapImage` 对象来加载和解码 `animated.gif`。`BitmapImage` 会识别出这是一个 GIF 动画，并管理其帧和动画循环。
    * **Canvas API (`drawImage()` 方法):**  Canvas 允许开发者通过 JavaScript 动态绘制图像。`drawImage()` 方法可以直接使用 Image 对象作为参数。
        * **假设输入:**  一个已经加载完成的 `Image` 对象 `img` (背后由 `BitmapImage` 支持)，以及 Canvas 的 2D 渲染上下文 `ctx`。
        * **输出:**  `ctx.drawImage(img, 0, 0);` 会调用 `BitmapImage` 的 `Draw()` 方法，将 `img` 代表的位图图像绘制到 Canvas 上。

**逻辑推理与假设输入/输出:**

* **假设输入:** 一个包含多个帧的 GIF 动画文件被加载。
* **输出:**
    * `BitmapImage` 会使用 `DeferredImageDecoder` (可能具体是 GIF 解码器) 来解析 GIF 文件。
    * `FrameCount()` 会返回 GIF 动画的帧数。
    * `RepetitionCount()` 会返回 GIF 动画的循环次数。
    * 每次绘制动画帧时，`Draw()` 方法会被调用，根据当前动画状态绘制相应的帧。

* **假设输入:** 一个损坏的 JPEG 文件被加载。
* **输出:**
    * `DeferredImageDecoder` 可能无法成功解码该文件。
    * `IsSizeAvailable()` 可能会返回 `false`。
    * `Draw()` 方法在尝试绘制时可能会因为没有有效的 `PaintImage` 而不执行任何操作。
    * 可能会触发 `ImageObserver` 的相关错误通知。

**用户或编程常见的使用错误:**

* **尝试在图像未加载完成时绘制:**
    * **错误:**  JavaScript 代码在 `<img>` 标签的 `onload` 事件触发之前就尝试使用该图像进行 Canvas 绘制。
    * **后果:**  `BitmapImage` 可能尚未完成解码或尺寸未知，导致 `Draw()` 方法无法正确绘制，或者绘制出不完整的图像。
* **未处理图像加载错误:**
    * **错误:**  没有为 `<img>` 标签的 `onerror` 事件添加处理程序，导致在图像加载失败时无法得知。
    * **后果:**  如果图像加载失败（例如 404 错误），`BitmapImage` 可能无法创建，页面上将不会显示图像，并且开发者可能不会收到任何错误提示。
* **过度使用大型未优化的图像:**
    * **错误:**  在网页中使用大量高分辨率的图像而没有进行适当的压缩和优化。
    * **后果:**  `BitmapImage` 需要处理大量的数据，占用大量内存，可能导致页面加载缓慢，甚至崩溃。
* **对动画图像的循环次数理解错误:**
    * **错误:**  开发者可能错误地认为设置 `repetition_count_` 可以直接控制 GIF 动画的循环次数，而忽略了 GIF 文件本身可能已经定义了循环次数。
    * **后果:**  可能导致动画循环次数与预期不符。需要理解 `BitmapImage` 中的 `animation_policy_` 和 GIF 文件本身的循环设置之间的关系。

总而言之，`bitmap_image.cc` 是 Blink 渲染引擎中负责处理和渲染位图图像的关键组件，它与 HTML、CSS 和 JavaScript 中的图像相关功能紧密相连，是网页图像显示的基础。理解其功能有助于开发者更好地理解浏览器如何处理图像，并避免常见的图像使用错误。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/bitmap_image.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2006 Samuel Weinig (sam.weinig@gmail.com)
 * Copyright (C) 2004, 2005, 2006, 2008 Apple Inc. All rights reserved.
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

#include "third_party/blink/renderer/platform/graphics/bitmap_image.h"

#include <algorithm>
#include <memory>
#include <utility>

#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_macros.h"
#include "cc/paint/paint_flags.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image_metrics.h"
#include "third_party/blink/renderer/platform/graphics/deferred_image_decoder.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/image_observer.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_canvas.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_image.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {

int GetRepetitionCountWithPolicyOverride(
    int actual_count,
    mojom::blink::ImageAnimationPolicy policy) {
  if (actual_count == kAnimationNone ||
      policy == mojom::blink::ImageAnimationPolicy::
                    kImageAnimationPolicyNoAnimation) {
    return kAnimationNone;
  }

  if (actual_count == kAnimationLoopOnce ||
      policy == mojom::blink::ImageAnimationPolicy::
                    kImageAnimationPolicyAnimateOnce) {
    return kAnimationLoopOnce;
  }

  return actual_count;
}

BitmapImage::BitmapImage(ImageObserver* observer, bool is_multipart)
    : Image(observer, is_multipart),
      animation_policy_(
          mojom::blink::ImageAnimationPolicy::kImageAnimationPolicyAllowed),
      all_data_received_(false),
      have_size_(false),
      preferred_size_is_transposed_(false),
      size_available_(false),
      have_frame_count_(false),
      repetition_count_status_(kUnknown),
      repetition_count_(kAnimationNone),
      frame_count_(0) {}

BitmapImage::~BitmapImage() {}

bool BitmapImage::CurrentFrameHasSingleSecurityOrigin() const {
  return true;
}

void BitmapImage::DestroyDecodedData() {
  cached_frame_ = PaintImage();
  NotifyMemoryChanged();
}

scoped_refptr<SharedBuffer> BitmapImage::Data() {
  return decoder_ ? decoder_->Data() : nullptr;
}

bool BitmapImage::HasData() const {
  return decoder_ ? decoder_->HasData() : false;
}

size_t BitmapImage::DataSize() const {
  DCHECK(decoder_);
  return decoder_->DataSize();
}

void BitmapImage::NotifyMemoryChanged() {
  if (GetImageObserver())
    GetImageObserver()->DecodedSizeChangedTo(this, TotalFrameBytes());
}

size_t BitmapImage::TotalFrameBytes() {
  if (cached_frame_)
    return ClampTo<size_t>(Size().Area64() * sizeof(ImageFrame::PixelData));
  return 0u;
}

PaintImage BitmapImage::PaintImageForTesting() {
  return CreatePaintImage();
}

PaintImage BitmapImage::CreatePaintImage() {
  sk_sp<PaintImageGenerator> generator =
      decoder_ ? decoder_->CreateGenerator() : nullptr;
  if (!generator)
    return PaintImage();

  auto completion_state = all_data_received_
                              ? PaintImage::CompletionState::kDone
                              : PaintImage::CompletionState::kPartiallyDone;
  auto builder =
      CreatePaintImageBuilder()
          .set_paint_image_generator(std::move(generator))
          .set_repetition_count(GetRepetitionCountWithPolicyOverride(
              RepetitionCount(), animation_policy_))
          .set_is_high_bit_depth(decoder_->ImageIsHighBitDepth())
          .set_completion_state(completion_state)
          .set_reset_animation_sequence_id(reset_animation_sequence_id_);

  sk_sp<PaintImageGenerator> gainmap_generator;
  SkGainmapInfo gainmap_info;
  if (decoder_->CreateGainmapGenerator(gainmap_generator, gainmap_info)) {
    DCHECK(gainmap_generator);
    builder = builder.set_gainmap_paint_image_generator(
        std::move(gainmap_generator), gainmap_info);
  }

  return builder.TakePaintImage();
}

void BitmapImage::UpdateSize() const {
  if (have_size_ || !size_available_ || !decoder_)
    return;
  size_ = decoder_->FrameSizeAtIndex(0);
  density_corrected_size_ = decoder_->DensityCorrectedSizeAtIndex(0);
  preferred_size_is_transposed_ =
      decoder_->OrientationAtIndex(0).UsesWidthAsHeight();
  have_size_ = true;
}

gfx::Size BitmapImage::SizeWithConfig(SizeConfig config) const {
  UpdateSize();
  gfx::Size size = size_;
  if (config.apply_density && !density_corrected_size_.IsEmpty())
    size = density_corrected_size_;
  if (config.apply_orientation && preferred_size_is_transposed_)
    return gfx::TransposeSize(size);
  return size;
}

void BitmapImage::RecordDecodedImageType(UseCounter* use_counter) {
  BitmapImageMetrics::CountDecodedImageType(decoder_->FilenameExtension(),
                                            use_counter);
}

bool BitmapImage::GetHotSpot(gfx::Point& hot_spot) const {
  return decoder_ && decoder_->HotSpot(hot_spot);
}

// We likely don't need to confirm that this is the first time all data has
// been received as a way to avoid reporting the UMA multiple times for the
// same image. However, we err on the side of caution.
bool BitmapImage::ShouldReportByteSizeUMAs(bool data_now_completely_received) {
  if (!decoder_)
    return false;
  return !all_data_received_ && data_now_completely_received &&
         decoder_->ByteSize() != 0 && IsSizeAvailable() &&
         decoder_->RepetitionCount() == kAnimationNone &&
         !decoder_->ImageIsHighBitDepth();
}

Image::SizeAvailability BitmapImage::SetData(scoped_refptr<SharedBuffer> data,
                                             bool all_data_received) {
  if (!data)
    return kSizeAvailable;

  size_t length = data->size();
  if (!length)
    return kSizeAvailable;

  if (decoder_) {
    decoder_->SetData(std::move(data), all_data_received);
    return DataChanged(all_data_received);
  }

  bool has_enough_data = ImageDecoder::HasSufficientDataToSniffMimeType(*data);
  decoder_ = DeferredImageDecoder::Create(std::move(data), all_data_received,
                                          ImageDecoder::kAlphaPremultiplied,
                                          ColorBehavior::kTag);
  // If we had enough data but couldn't create a decoder, it implies a decode
  // failure.
  if (has_enough_data && !decoder_)
    return kSizeAvailable;
  return DataChanged(all_data_received);
}

// Return the image density in 0.01 "bits per pixel" rounded to the nearest
// integer.
static inline uint64_t ImageDensityInCentiBpp(gfx::Size size,
                                              size_t image_size_bytes) {
  uint64_t image_area = size.Area64();
  return (static_cast<uint64_t>(image_size_bytes) * 100 * 8 + image_area / 2) /
         image_area;
}

Image::SizeAvailability BitmapImage::DataChanged(bool all_data_received) {
  TRACE_EVENT0("blink", "BitmapImage::dataChanged");

  // If the data was updated, clear the |cached_frame_| to push it to the
  // compositor thread. Its necessary to clear the frame since more data
  // requires a new PaintImageGenerator instance.
  cached_frame_ = PaintImage();

  // Report the image density metric right after we received all the data. The
  // SetData() call on the decoder_ (if there is one) should have decoded the
  // images and we should know the image size at this point.
  if (ShouldReportByteSizeUMAs(all_data_received)) {
    BitmapImageMetrics::CountDecodedImageDensity(
        decoder_->FilenameExtension(),
        std::min(Size().width(), Size().height()),
        ImageDensityInCentiBpp(Size(), decoder_->ByteSize()),
        decoder_->ByteSize());
  }

  // Feed all the data we've seen so far to the image decoder.
  all_data_received_ = all_data_received;
  have_frame_count_ = false;

  return IsSizeAvailable() ? kSizeAvailable : kSizeUnavailable;
}

bool BitmapImage::HasColorProfile() const {
  return decoder_ && decoder_->HasEmbeddedColorProfile();
}

String BitmapImage::FilenameExtension() const {
  return decoder_ ? decoder_->FilenameExtension() : String();
}

const AtomicString& BitmapImage::MimeType() const {
  return decoder_ ? decoder_->MimeType() : g_null_atom;
}

void BitmapImage::Draw(cc::PaintCanvas* canvas,
                       const cc::PaintFlags& flags,
                       const gfx::RectF& dst_rect,
                       const gfx::RectF& src_rect,
                       const ImageDrawOptions& draw_options) {
  TRACE_EVENT0("skia", "BitmapImage::draw");

  PaintImage image = PaintImageForCurrentFrame();
  if (!image)
    return;  // It's too early and we don't have an image yet.

  auto paint_image_decoding_mode =
      ToPaintImageDecodingMode(draw_options.decode_mode);
  if (image.decoding_mode() != paint_image_decoding_mode ||
      image.may_be_lcp_candidate() != draw_options.may_be_lcp_candidate) {
    image = PaintImageBuilder::WithCopy(std::move(image))
                .set_decoding_mode(paint_image_decoding_mode)
                .set_may_be_lcp_candidate(draw_options.may_be_lcp_candidate)
                .TakePaintImage();
  }

  gfx::RectF adjusted_src_rect = src_rect;
  if (!density_corrected_size_.IsEmpty()) {
    adjusted_src_rect.Scale(
        static_cast<float>(size_.width()) / density_corrected_size_.width(),
        static_cast<float>(size_.height()) / density_corrected_size_.height());
  }

  adjusted_src_rect.Intersect(gfx::RectF(image.width(), image.height()));

  if (adjusted_src_rect.IsEmpty() || dst_rect.IsEmpty())
    return;  // Nothing to draw.

  ImageOrientation orientation = ImageOrientationEnum::kDefault;
  if (draw_options.respect_orientation == kRespectImageOrientation)
    orientation = CurrentFrameOrientation();

  PaintCanvasAutoRestore auto_restore(canvas, false);
  gfx::RectF adjusted_dst_rect = dst_rect;
  if (orientation != ImageOrientationEnum::kDefault) {
    canvas->save();

    // ImageOrientation expects the origin to be at (0, 0)
    canvas->translate(adjusted_dst_rect.x(), adjusted_dst_rect.y());
    adjusted_dst_rect.set_origin(gfx::PointF());

    canvas->concat(AffineTransformToSkM44(
        orientation.TransformFromDefault(adjusted_dst_rect.size())));

    if (orientation.UsesWidthAsHeight()) {
      // The destination rect will have its width and height already reversed
      // for the orientation of the image, as it was needed for page layout, so
      // we need to reverse it back here.
      adjusted_dst_rect.set_size(gfx::TransposeSize(adjusted_dst_rect.size()));
    }
  }

  uint32_t stable_id = image.stable_id();
  bool is_lazy_generated = image.IsLazyGenerated();

  const cc::PaintFlags* image_flags = &flags;
  std::optional<cc::PaintFlags> dark_mode_flags;
  if (draw_options.dark_mode_filter) {
    dark_mode_flags = flags;
    draw_options.dark_mode_filter->ApplyFilterToImage(
        this, &dark_mode_flags.value(), gfx::RectFToSkRect(src_rect));
    image_flags = &dark_mode_flags.value();
  }
  canvas->drawImageRect(
      std::move(image), gfx::RectFToSkRect(adjusted_src_rect),
      gfx::RectFToSkRect(adjusted_dst_rect), draw_options.sampling_options,
      image_flags,
      WebCoreClampingModeToSkiaRectConstraint(draw_options.clamping_mode));

  if (is_lazy_generated) {
    TRACE_EVENT_INSTANT1(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                         "Draw LazyPixelRef", TRACE_EVENT_SCOPE_THREAD,
                         "LazyPixelRef", stable_id);
  }

  StartAnimation();
}

size_t BitmapImage::FrameCount() {
  if (!have_frame_count_) {
    frame_count_ = decoder_ ? decoder_->FrameCount() : 0;
    have_frame_count_ = frame_count_ > 0;
  }
  return frame_count_;
}

static inline bool HasVisibleImageSize(gfx::Size size) {
  return (size.width() > 1 || size.height() > 1);
}

bool BitmapImage::IsSizeAvailable() {
  if (size_available_)
    return true;

  size_available_ = decoder_ && decoder_->IsSizeAvailable();
  if (size_available_ && HasVisibleImageSize(Size()))
    BitmapImageMetrics::CountDecodedImageType(decoder_->FilenameExtension());

  return size_available_;
}

PaintImage BitmapImage::PaintImageForCurrentFrame() {
  auto alpha_type = decoder_ ? decoder_->AlphaType() : kUnknown_SkAlphaType;
  if (cached_frame_ && cached_frame_.GetAlphaType() == alpha_type)
    return cached_frame_;

  cached_frame_ = CreatePaintImage();

  // BitmapImage should not be texture backed.
  DCHECK(!cached_frame_.IsTextureBacked());

  // Create the SkImage backing for this PaintImage here to ensure that copies
  // of the PaintImage share the same SkImage. Skia's caching of the decoded
  // output of this image is tied to the lifetime of the SkImage. So we create
  // the SkImage here and cache the PaintImage to keep the decode alive in
  // skia's cache.
  cached_frame_.GetSwSkImage();
  NotifyMemoryChanged();

  return cached_frame_;
}

scoped_refptr<Image> BitmapImage::ImageForDefaultFrame() {
  if (FrameCount() > 1) {
    PaintImage paint_image = PaintImageForCurrentFrame();
    if (!paint_image)
      return nullptr;

    if (paint_image.ShouldAnimate()) {
      // To prevent the compositor from animating this image, we set the
      // animation count to kAnimationNone. This makes the image essentially
      // static.
      paint_image = PaintImageBuilder::WithCopy(std::move(paint_image))
                        .set_repetition_count(kAnimationNone)
                        .TakePaintImage();
    }
    return StaticBitmapImage::Create(std::move(paint_image));
  }

  return Image::ImageForDefaultFrame();
}

bool BitmapImage::CurrentFrameKnownToBeOpaque() {
  return decoder_ ? decoder_->AlphaType() == kOpaque_SkAlphaType : false;
}

bool BitmapImage::CurrentFrameIsComplete() {
  return decoder_ && decoder_->FrameIsReceivedAtIndex(0);
}

bool BitmapImage::CurrentFrameIsLazyDecoded() {
  // BitmapImage supports only lazy generated images.
  return true;
}

ImageOrientation BitmapImage::CurrentFrameOrientation() const {
  return decoder_ ? decoder_->OrientationAtIndex(0)
                  : ImageOrientationEnum::kDefault;
}

int BitmapImage::RepetitionCount() {
  if ((repetition_count_status_ == kUnknown) ||
      ((repetition_count_status_ == kUncertain) && all_data_received_)) {
    // Snag the repetition count.  If |imageKnownToBeComplete| is false, the
    // repetition count may not be accurate yet for GIFs; in this case the
    // decoder will default to cAnimationLoopOnce, and we'll try and read
    // the count again once the whole image is decoded.
    repetition_count_ = decoder_ ? decoder_->RepetitionCount() : kAnimationNone;

    // When requesting more than a single loop, repetition count is one less
    // than the actual number of loops.
    if (repetition_count_ > 0)
      repetition_count_++;

    repetition_count_status_ =
        (all_data_received_ || repetition_count_ == kAnimationNone)
            ? kCertain
            : kUncertain;
  }
  return repetition_count_;
}

void BitmapImage::ResetAnimation() {
  cached_frame_ = PaintImage();
  reset_animation_sequence_id_++;
}

bool BitmapImage::MaybeAnimated() {
  if (FrameCount() > 1)
    return true;

  return decoder_ && decoder_->RepetitionCount() != kAnimationNone;
}

void BitmapImage::SetAnimationPolicy(
    mojom::blink::ImageAnimationPolicy policy) {
  if (animation_policy_ == policy)
    return;

  animation_policy_ = policy;
  ResetAnimation();
}

}  // namespace blink

"""

```