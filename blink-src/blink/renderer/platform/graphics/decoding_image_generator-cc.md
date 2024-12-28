Response:
Let's break down the thought process for analyzing the `DecodingImageGenerator.cc` file.

1. **Understand the Goal:** The request is to analyze the functionality of this specific Chromium Blink source code file. This means identifying its purpose, its relationships to other web technologies (JavaScript, HTML, CSS), how it works internally (logic), and potential error scenarios.

2. **High-Level Reading and Keyword Spotting:**  Start by skimming the code. Look for class names, function names, included headers, and any descriptive comments. In this file, immediately noticeable are:
    * `DecodingImageGenerator` (the core class)
    * Includes like `ImageDecoder.h`, `ImageFrameGenerator.h`, `SegmentReader.h`
    * Mentions of Skia (`sk_sp`, `SkImageInfo`, `SkPixmap`, etc.)
    * Functions like `CreateAsSkImageGenerator`, `Create`, `GetPixels`, `QueryYUVA`, `GetYUVAPlanes`, `GetEncodedData`.
    * A namespace `blink`.
    *  Copyright information indicating Google as the origin.

3. **Infer the Core Functionality:** Based on the class name and the included headers, the primary function is likely *generating Skia image objects by decoding image data*. The presence of `ImageDecoder`, `SegmentReader`, and `ImageFrameGenerator` suggests a pipeline:  raw data is read in segments, decoded into frames, and then converted into a format Skia can use for rendering.

4. **Analyze Key Functions:**  Go through the significant functions and understand their roles:
    * **`CreateAsSkImageGenerator`:** Seems like a factory method specifically for creating an `SkImageGenerator` from raw data (`SkData`). The comment confirms it's primarily for out-of-process printing and MSKP (Mojo Serialized Keyed Properties). It uses `ImageDecoder` to get image size and then creates `ImageFrameGenerator` and `DecodingImageGenerator`.
    * **`Create`:**  Another factory method, but it takes pre-existing `ImageFrameGenerator`, `SegmentReader`, and frame metadata. This suggests a more direct instantiation path.
    * **Constructor:**  Initializes the `DecodingImageGenerator` with its dependencies.
    * **`GetEncodedData`:**  Returns the raw, potentially incomplete, image data. The comment explains its use in serialization.
    * **`GetPixels`:** The core decoding function. It takes a destination `SkPixmap`, decodes the image frame, and writes the pixels to it. It handles color space conversions and potential dithering. The locking mechanism using `ScopedSegmentReaderDataLocker` is important for thread safety.
    * **`QueryYUVA` and `GetYUVAPlanes`:**  These functions deal with YUV color space decoding, likely for video or more efficient image processing in specific scenarios. The `can_yuv_decode_` flag suggests this is an optional capability.
    * **`GetSupportedDecodeSize`:**  Allows querying for the closest supported size for decoding, potentially for scaling.
    * **`GetContentIdForFrame`:**  Manages content IDs for caching and invalidation, important for performance and correct updates in a web browser.
    * **`GetMetadataForDecodeAcceleration`:**  Provides metadata that can be used for hardware acceleration of decoding.

5. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):**  Think about how images are used on the web:
    * **HTML `<img>` tag:** The most direct link. The `src` attribute points to image data that needs to be decoded.
    * **CSS `background-image`:** Similar to `<img>`, CSS can also specify image sources.
    * **JavaScript `Image()` constructor and Canvas API:** JavaScript can dynamically load and manipulate images, often using the Canvas API for drawing.

    Connect these concepts to the functions in the code:  When an `<img>` tag or CSS background requires an image, the browser fetches the data. This data (or parts of it) will be passed to the `DecodingImageGenerator` (indirectly, through other parts of the rendering engine). `GetPixels` is the function that ultimately provides the pixel data needed to paint the image on the screen, either directly or onto a canvas manipulated by JavaScript.

6. **Consider Logic and Reasoning (Hypothetical Inputs/Outputs):**  Focus on the `GetPixels` function as it's the most complex.
    * **Input:**  A `SkPixmap` (destination buffer), `frame_index`, `client_id`. Imagine a small PNG image being requested.
    * **Processing:** The function checks if the requested size is supported. It might need to allocate a temporary buffer for intermediate decoding. It locks the data, tells the `ImageFrameGenerator` to decode the relevant frame, and potentially performs color space conversions.
    * **Output:** The `SkPixmap` is filled with the decoded pixel data. The function returns `true` if successful, `false` otherwise.

    Think about YUV decoding:
    * **Input:**  `SkYUVAPixmaps` structure, `frame_index`.
    * **Processing:**  The function ensures YUV decoding is supported, then calls the `ImageFrameGenerator` to decode into the provided YUV planes.
    * **Output:** The planes in `SkYUVAPixmaps` are filled with the decoded YUV data.

7. **Identify Potential User/Programming Errors:**  Think about how developers might misuse image loading:
    * **Incorrect image format:**  Providing data that doesn't match the expected format. The `ImageDecoder::Create` function would likely return `nullptr`.
    * **Incomplete image data:**  Trying to decode an image before all the data has been received. The rendering might show a partially loaded image or an error.
    * **Requesting unsupported decode sizes:**  If the requested `SkPixmap` size is not a supported decode size, `GetPixels` will return `false`.
    * **Mismatched color spaces:** While the code tries to handle conversions, there might be edge cases where the desired color space is not supported or the conversion introduces artifacts.
    * **Using YUV decoding incorrectly:**  Trying to use YUV decoding when the image format doesn't support it, or providing incorrect plane configurations.

8. **Structure the Answer:** Organize the findings logically:
    * **Core Functionality:** Start with a concise summary.
    * **Relationship to Web Technologies:** Explain how the file interacts with HTML, CSS, and JavaScript, providing concrete examples.
    * **Logic and Reasoning:**  Illustrate with hypothetical inputs and outputs, focusing on key functions.
    * **Common Errors:** List potential pitfalls for developers.

9. **Refine and Elaborate:** Go back through the analysis and add details or clarifications where needed. For instance, explaining *why* out-of-process printing uses this or the importance of content IDs.

By following this systematic approach, covering the different aspects of the code (purpose, relationships, logic, errors), you can create a comprehensive and informative analysis of the `DecodingImageGenerator.cc` file.
好的，我们来分析一下 `blink/renderer/platform/graphics/decoding_image_generator.cc` 这个文件。

**核心功能:**

`DecodingImageGenerator` 的核心功能是**按需解码图像数据，并生成 Skia 可以使用的图像对象 (`SkImageGenerator`)**。它充当了图像解码器（`ImageDecoder`）和 Skia 图形库之间的桥梁。  更具体地说，它负责：

1. **管理图像的解码过程:** 它持有图像数据 (`SegmentReader`) 和用于解码的 `ImageFrameGenerator`。
2. **按需提供像素数据:** 当 Skia 需要特定区域或尺寸的图像像素时，`DecodingImageGenerator` 会调用 `ImageFrameGenerator` 来解码相应的图像部分。
3. **处理图像帧:** 对于动画图像，它管理多个帧的解码。
4. **支持 YUV 解码:**  对于某些图像格式或硬件加速场景，它支持直接解码到 YUV 色彩空间。
5. **提供编码后的数据:**  它可以返回原始的编码后的图像数据。
6. **管理内容 ID:** 用于跟踪图像内容的变化，以便进行缓存和更新。
7. **提供解码加速元数据:**  提供给解码器进行硬件加速的必要信息。

**与 JavaScript, HTML, CSS 的关系 (及其举例):**

`DecodingImageGenerator` 本身不直接与 JavaScript, HTML, CSS 代码交互。它的工作发生在渲染引擎的底层，处理浏览器解析 HTML, CSS 并执行 JavaScript 后，需要显示图像的阶段。

* **HTML `<img src="...">`:** 当浏览器遇到 `<img>` 标签时，会下载 `src` 指定的图像数据。这部分数据最终会被传递到 `DecodingImageGenerator`，以便在屏幕上渲染图像。`DecodingImageGenerator` 会按需解码图像数据，提供给渲染管线进行绘制。

    * **假设输入:**  HTML 中有 `<img src="image.png">`，`image.png` 是一个 PNG 图片文件。
    * **输出:** `DecodingImageGenerator` 会解码 `image.png` 的数据，并生成 Skia 可以使用的图像对象，最终在浏览器窗口中显示该图像。

* **CSS `background-image: url(...)`:** 类似于 `<img>` 标签，CSS 中的 `background-image` 属性指定的图像也会被 `DecodingImageGenerator` 处理。

    * **假设输入:**  CSS 中有 `body { background-image: url("background.jpg"); }`，`background.jpg` 是一个 JPEG 图片文件。
    * **输出:** `DecodingImageGenerator` 会解码 `background.jpg` 的数据，并生成 Skia 图像对象，用于绘制页面的背景。

* **JavaScript Canvas API (`drawImage()`):** JavaScript 可以使用 Canvas API 来绘制图像。当调用 `drawImage()` 方法时，如果传入的是一个 Image 对象，这个 Image 对象内部会使用 `DecodingImageGenerator` 来提供需要绘制的像素数据。

    * **假设输入:**  JavaScript 代码中有：
      ```javascript
      const image = new Image();
      image.src = 'my_image.gif';
      image.onload = () => {
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        ctx.drawImage(image, 0, 0);
      };
      ```
    * **输出:** 当 `image` 加载完成后，`DecodingImageGenerator` 会解码 `my_image.gif` 的帧数据。`ctx.drawImage(image, 0, 0)` 会利用 `DecodingImageGenerator` 提供的像素数据在 canvas 上绘制 GIF 动画的当前帧。

**逻辑推理 (假设输入与输出):**

让我们关注 `GetPixels` 方法，这是获取图像像素的核心方法。

* **假设输入:**
    * `dst_pixmap`: 一个 Skia 的 `SkPixmap` 对象，表示目标像素缓冲区，例如一个 100x100 像素的缓冲区，颜色类型为 `kN32_SkColorType` (RGBA)。
    * `frame_index`:  0 (表示第一帧，假设是静态图像)。
    * `client_id`: 一个唯一的客户端 ID。

* **处理过程:**
    1. `GetPixels` 首先检查请求的目标尺寸是否是支持的解码尺寸。
    2. 它会获取解码所需的颜色空间信息。
    3. 如果需要，它会分配一个临时的缓冲区进行解码（例如，如果目标颜色类型不是 `kN32_SkColorType` 或 `kRGBA_F16_SkColorType`）。
    4. 它使用 `ScopedSegmentReaderDataLocker` 来锁定图像数据，确保线程安全。
    5. 调用 `frame_generator_->DecodeAndScale()` 方法，传入图像数据、是否所有数据都已接收、帧索引、目标像素缓冲区和客户端 ID。`ImageFrameGenerator` 负责实际的解码和缩放操作。
    6. 如果解码成功，并且需要进行颜色空间转换，则进行转换。
    7. 如果解码成功，并且目标颜色类型与解码后的颜色类型不同，则进行颜色类型转换，可能涉及到抖动处理。

* **假设输出:**
    * 如果解码成功，`dst_pixmap` 的像素缓冲区会被填充上 `image.png` (假设输入的图像是 PNG) 的解码后的 100x100 像素数据。方法返回 `true`。
    * 如果解码失败（例如，图像数据损坏或不支持的解码尺寸），方法返回 `false`。

**用户或编程常见的使用错误 (及其举例):**

虽然用户和程序员不直接与 `DecodingImageGenerator` 交互，但与图像加载和处理相关的错误会影响其工作。

* **提供了损坏的图像数据:** 如果 HTML 或 CSS 引用了一个损坏的图像文件，当 `DecodingImageGenerator` 尝试解码时会失败。

    * **例子:**  一个用户上传了一个部分损坏的 JPEG 文件，并且网站尝试显示它。`DecodingImageGenerator` 在解码过程中可能会抛出错误，导致图像无法显示或显示不完整。

* **尝试解码未完成下载的图像:**  在网络环境不佳的情况下，浏览器可能在图像数据完全下载之前就尝试解码。`DecodingImageGenerator` 需要处理这种情况，通常会先解码已有的部分，或者等待更多数据。

    * **例子:**  一个网页加载速度很慢，图片会先显示一部分，然后逐渐加载完成。`DecodingImageGenerator` 可能会被多次调用，随着更多数据的到达逐步解码图像。

* **请求过大的解码尺寸导致内存问题:**  如果 JavaScript 代码请求解码一个非常大的图像到 Canvas 上，可能会导致 `DecodingImageGenerator` 尝试分配大量内存，最终导致性能问题或崩溃。

    * **例子:**  一个使用 Canvas API 的图片编辑器，允许用户放大显示一张非常高分辨率的图片。如果没有合理的缩放和裁剪策略，`DecodingImageGenerator` 可能会尝试解码整个大图，消耗大量内存。

* **YUV 解码相关的错误配置:**  如果开发者错误地配置了 YUV 解码参数（例如，错误的平面大小或地址），`DecodingImageGenerator` 的 `GetYUVAPlanes` 方法会返回 `false`。

    * **例子:**  一个视频播放器尝试使用硬件加速解码视频帧到 YUV 缓冲区，但传递给 `DecodingImageGenerator` 的 YUV 平面信息不正确，导致解码失败，视频无法正常播放。

总而言之，`DecodingImageGenerator` 是 Blink 渲染引擎中一个关键的图像处理模块，它负责将各种格式的图像数据解码成 Skia 可以使用的像素信息，最终使得图像能够在浏览器中正确显示。虽然开发者不直接调用它，但理解其功能有助于理解浏览器如何处理图像以及相关错误的根源。

Prompt: 
```
这是目录为blink/renderer/platform/graphics/decoding_image_generator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
/*
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/platform/graphics/decoding_image_generator.h"

#include <array>
#include <memory>
#include <utility>

#include "base/containers/heap_array.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/graphics/image_frame_generator.h"
#include "third_party/blink/renderer/platform/graphics/skia/skia_utils.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder.h"
#include "third_party/blink/renderer/platform/image-decoders/segment_reader.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkData.h"
#include "third_party/skia/include/core/SkImageInfo.h"

namespace {
class ScopedSegmentReaderDataLocker {
  STACK_ALLOCATED();

 public:
  explicit ScopedSegmentReaderDataLocker(blink::SegmentReader* segment_reader)
      : segment_reader_(segment_reader) {
    segment_reader_->LockData();
  }
  ~ScopedSegmentReaderDataLocker() { segment_reader_->UnlockData(); }

 private:
  blink::SegmentReader* const segment_reader_;
};
}  // namespace

namespace blink {

// static
std::unique_ptr<SkImageGenerator>
DecodingImageGenerator::CreateAsSkImageGenerator(sk_sp<SkData> data) {
  // This image generator is used only by code in Skia, which in practice means
  // out of process printing deserialization (MSKP) and a few odds and ends.
  // Blink side code uses DecodingImageGenerator::Create directly instead.
  scoped_refptr<SegmentReader> segment_reader =
      SegmentReader::CreateFromSkData(std::move(data));
  const bool data_complete = true;
  std::unique_ptr<ImageDecoder> decoder = ImageDecoder::Create(
      segment_reader, data_complete, ImageDecoder::kAlphaPremultiplied,
      ImageDecoder::kDefaultBitDepth, ColorBehavior::kTag,
      cc::AuxImage::kDefault, Platform::GetMaxDecodedImageBytes());
  if (!decoder || !decoder->IsSizeAvailable())
    return nullptr;

  const gfx::Size size = decoder->Size();
  const SkImageInfo info =
      SkImageInfo::MakeN32(size.width(), size.height(), kPremul_SkAlphaType,
                           decoder->ColorSpaceForSkImages());

  scoped_refptr<ImageFrameGenerator> frame = ImageFrameGenerator::Create(
      SkISize::Make(size.width(), size.height()), false,
      decoder->GetColorBehavior(), cc::AuxImage::kDefault,
      decoder->GetSupportedDecodeSizes());
  if (!frame)
    return nullptr;

  WebVector<FrameMetadata> frames;
  frames.emplace_back(FrameMetadata());
  cc::ImageHeaderMetadata image_metadata =
      decoder->MakeMetadataForDecodeAcceleration();
  image_metadata.all_data_received_prior_to_decode = true;
  sk_sp<DecodingImageGenerator> generator = DecodingImageGenerator::Create(
      std::move(frame), info, std::move(segment_reader), std::move(frames),
      PaintImage::GetNextContentId(), true /* all_data_received */,
      false /* can_yuv_decode */, image_metadata);
  return std::make_unique<SkiaPaintImageGenerator>(
      std::move(generator), PaintImage::kDefaultFrameIndex,
      PaintImage::kDefaultGeneratorClientId);
}

// static
sk_sp<DecodingImageGenerator> DecodingImageGenerator::Create(
    scoped_refptr<ImageFrameGenerator> frame_generator,
    const SkImageInfo& info,
    scoped_refptr<SegmentReader> data,
    WebVector<FrameMetadata> frames,
    PaintImage::ContentId content_id,
    bool all_data_received,
    bool can_yuv_decode,
    const cc::ImageHeaderMetadata& image_metadata) {
  return sk_sp<DecodingImageGenerator>(new DecodingImageGenerator(
      std::move(frame_generator), info, std::move(data), std::move(frames),
      content_id, all_data_received, can_yuv_decode, image_metadata));
}

DecodingImageGenerator::DecodingImageGenerator(
    scoped_refptr<ImageFrameGenerator> frame_generator,
    const SkImageInfo& info,
    scoped_refptr<SegmentReader> data,
    WebVector<FrameMetadata> frames,
    PaintImage::ContentId complete_frame_content_id,
    bool all_data_received,
    bool can_yuv_decode,
    const cc::ImageHeaderMetadata& image_metadata)
    : PaintImageGenerator(info, frames.ReleaseVector()),
      frame_generator_(std::move(frame_generator)),
      data_(std::move(data)),
      all_data_received_(all_data_received),
      can_yuv_decode_(can_yuv_decode),
      complete_frame_content_id_(complete_frame_content_id),
      image_metadata_(image_metadata) {}

DecodingImageGenerator::~DecodingImageGenerator() = default;

sk_sp<SkData> DecodingImageGenerator::GetEncodedData() const {
  TRACE_EVENT0("blink", "DecodingImageGenerator::refEncodedData");

  // getAsSkData() may require copying, but the clients of this function are
  // serializers, which want the data even if it requires copying, and even
  // if the data is incomplete. (Otherwise they would potentially need to
  // decode the partial image in order to re-encode it.)
  return data_->GetAsSkData();
}

bool DecodingImageGenerator::GetPixels(SkPixmap dst_pixmap,
                                       size_t frame_index,
                                       PaintImage::GeneratorClientId client_id,
                                       uint32_t lazy_pixel_ref) {
  TRACE_EVENT2("blink", "DecodingImageGenerator::getPixels", "frame index",
               static_cast<int>(frame_index), "client_id", client_id);
  const SkImageInfo& dst_info = dst_pixmap.info();

  // Implementation only supports decoding to a supported size.
  if (dst_info.dimensions() != GetSupportedDecodeSize(dst_info.dimensions())) {
    return false;
  }

  // Color type can be N32 or F16. Otherwise, decode to N32 and convert to
  // the requested color type from N32.
  SkImageInfo target_info = dst_info;
  char* memory = static_cast<char*>(dst_pixmap.writable_addr());
  base::HeapArray<char> adjusted_memory;
  size_t adjusted_row_bytes = dst_pixmap.rowBytes();
  if ((target_info.colorType() != kN32_SkColorType) &&
      (target_info.colorType() != kRGBA_F16_SkColorType)) {
    target_info = target_info.makeColorType(kN32_SkColorType);
    // dst_info.rowBytes is the size of scanline, so it should be >=
    // info.minRowBytes().
    DCHECK(dst_pixmap.rowBytes() >= dst_info.minRowBytes());
    // dst_info.rowBytes must be a multiple of dst_info.bytesPerPixel().
    DCHECK_EQ(0ul, dst_pixmap.rowBytes() % dst_info.bytesPerPixel());
    adjusted_row_bytes = target_info.bytesPerPixel() *
                         (dst_pixmap.rowBytes() / dst_info.bytesPerPixel());
    adjusted_memory =
        base::HeapArray<char>::Uninit(target_info.computeMinByteSize());
    memory = adjusted_memory.data();
  }

  // Skip the check for alphaType.  blink::ImageFrame may have changed the
  // owning SkBitmap to kOpaque_SkAlphaType after fully decoding the image
  // frame, so if we see a request for opaque, that is ok even if our initial
  // alpha type was not opaque.

  // Pass decodeColorSpace to the decoder.  That is what we can expect the
  // output to be.
  sk_sp<SkColorSpace> decode_color_space = GetSkImageInfo().refColorSpace();
  SkImageInfo decode_info = target_info.makeColorSpace(decode_color_space);

  const bool needs_color_xform = !ApproximatelyEqualSkColorSpaces(
      decode_color_space, target_info.refColorSpace());
  if (needs_color_xform && !decode_info.isOpaque()) {
    decode_info = decode_info.makeAlphaType(kUnpremul_SkAlphaType);
  } else {
    DCHECK(decode_info.alphaType() != kUnpremul_SkAlphaType);
  }
  SkPixmap decode_pixmap(decode_info, memory, adjusted_row_bytes);

  bool decoded = false;
  {
    TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
                 "Decode LazyPixelRef", "LazyPixelRef", lazy_pixel_ref);

    ScopedSegmentReaderDataLocker lock_data(data_.get());
    decoded = frame_generator_->DecodeAndScale(
        data_.get(), all_data_received_, static_cast<wtf_size_t>(frame_index),
        decode_pixmap, client_id);
  }

  if (decoded && needs_color_xform) {
    TRACE_EVENT0("blink", "DecodingImageGenerator::getPixels - apply xform");
    SkPixmap src(decode_info, memory, adjusted_row_bytes);
    decoded = src.readPixels(target_info, memory, adjusted_row_bytes);
    DCHECK(decoded);
  }

  // Convert the color type to the requested one if necessary
  if (decoded && target_info.colorType() != dst_info.colorType()) {
    // Convert the color type by readPixels if dithering is not necessary
    // (readPixels is potentially cheaper than a full-blown drawBitmap).
    if (SkColorTypeBytesPerPixel(target_info.colorType()) <=
        SkColorTypeBytesPerPixel(dst_info.colorType())) {
      decoded = SkPixmap{target_info, memory, adjusted_row_bytes}.readPixels(
          dst_pixmap);
      DCHECK(decoded);
    } else {  // Do dithering by drawBitmap() if dithering is necessary
      auto canvas = SkCanvas::MakeRasterDirect(
          dst_pixmap.info(), dst_pixmap.writable_addr(), dst_pixmap.rowBytes());
      DCHECK(canvas);

      SkPaint paint;
      paint.setDither(true);
      paint.setBlendMode(SkBlendMode::kSrc);

      SkBitmap bitmap;
      decoded = bitmap.installPixels(target_info, memory, adjusted_row_bytes);
      DCHECK(decoded);

      canvas->drawImage(bitmap.asImage(), 0, 0, SkSamplingOptions(), &paint);
    }
  }
  return decoded;
}

bool DecodingImageGenerator::QueryYUVA(
    const SkYUVAPixmapInfo::SupportedDataTypes& supported_data_types,
    SkYUVAPixmapInfo* yuva_pixmap_info) const {
  if (!can_yuv_decode_)
    return false;

  TRACE_EVENT0("blink", "DecodingImageGenerator::QueryYUVAInfo");

  DCHECK(all_data_received_);

  ScopedSegmentReaderDataLocker lock_data(data_.get());
  return frame_generator_->GetYUVAInfo(data_.get(), supported_data_types,
                                       yuva_pixmap_info);
}

bool DecodingImageGenerator::GetYUVAPlanes(
    const SkYUVAPixmaps& pixmaps,
    size_t frame_index,
    uint32_t lazy_pixel_ref,
    PaintImage::GeneratorClientId client_id) {
  // TODO(crbug.com/943519): YUV decoding does not currently support incremental
  // decoding. See comment in image_frame_generator.h.
  DCHECK(can_yuv_decode_);
  DCHECK(all_data_received_);

  TRACE_EVENT0("blink", "DecodingImageGenerator::GetYUVAPlanes");
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("devtools.timeline"),
               "Decode LazyPixelRef", "LazyPixelRef", lazy_pixel_ref);

  std::array<SkISize, 3> plane_sizes;
  std::array<wtf_size_t, 3> plane_row_bytes;
  std::array<void*, 3> plane_addrs;

  // Verify sizes and extract DecodeToYUV parameters
  for (int i = 0; i < 3; ++i) {
    const SkPixmap& plane = pixmaps.plane(i);
    if (plane.dimensions().isEmpty() || !plane.rowBytes())
      return false;
    if (plane.colorType() != pixmaps.plane(0).colorType())
      return false;
    plane_sizes[i] = plane.dimensions();
    plane_row_bytes[i] = base::checked_cast<wtf_size_t>(plane.rowBytes());
    plane_addrs[i] = plane.writable_addr();
  }
  if (!pixmaps.plane(3).dimensions().isEmpty()) {
    return false;
  }

  ScopedSegmentReaderDataLocker lock_data(data_.get());
  return frame_generator_->DecodeToYUV(
      data_.get(), static_cast<wtf_size_t>(frame_index),
      pixmaps.plane(0).colorType(), plane_sizes, plane_addrs, plane_row_bytes,
      client_id);
}

SkISize DecodingImageGenerator::GetSupportedDecodeSize(
    const SkISize& requested_size) const {
  return frame_generator_->GetSupportedDecodeSize(requested_size);
}

PaintImage::ContentId DecodingImageGenerator::GetContentIdForFrame(
    size_t frame_index) const {
  DCHECK_LT(frame_index, GetFrameMetadata().size());

  // If we have all the data for the image, or this particular frame, we can
  // consider the decoded frame constant.
  if (all_data_received_ || GetFrameMetadata().at(frame_index).complete)
    return complete_frame_content_id_;

  return PaintImageGenerator::GetContentIdForFrame(frame_index);
}

const cc::ImageHeaderMetadata*
DecodingImageGenerator::GetMetadataForDecodeAcceleration() const {
  return &image_metadata_;
}

}  // namespace blink

"""

```