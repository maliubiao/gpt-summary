Response:
Let's break down the thought process for analyzing the `ImageFrame.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the `ImageFrame` class, its relationships with web technologies, logical reasoning with input/output, and potential usage errors.

2. **Initial Skim and Keyword Spotting:**  Quickly read through the code, looking for important keywords and class names. Notice: `ImageFrame`, `bitmap_`, `status_`, `has_alpha_`, `AllocatePixelData`, `FinalizePixelsAndGetImage`, `Blend...`, `Skia`, `gfx::Rect`. This gives a high-level overview of what the class deals with – image data, state management, and blending.

3. **Core Functionality Identification (Step-by-step):** Go through the methods and understand their purpose:

    * **Constructors/Destructor/Assignment:** Standard C++ memory management. Important to note the copy constructor and assignment operator handle deep copying of the bitmap data.
    * **`ClearPixelData()`:**  Releases the pixel data. Note the comment about *not* resetting other metadata. This suggests a potential decoupling of pixel data and metadata.
    * **`ZeroFillPixelData()`:** Fills the bitmap with transparent black. This is for initialization or clearing purposes.
    * **`CopyBitmapData()`:** Deep copies pixel data from another `ImageFrame`. This is crucial for creating independent copies of frames.
    * **`TakeBitmapDataIfWritable()`:** Efficiently moves the bitmap data if the source bitmap is mutable. This avoids unnecessary copying. This optimization is a key point.
    * **`AllocatePixelData()`:**  Allocates memory for the bitmap. The `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` check is a good indicator of resource management considerations. The color space and alpha type are set here.
    * **`FinalizePixelsAndGetImage()`:** Makes the bitmap immutable and creates an `SkImage`. This signifies the completion of processing for a frame.
    * **`SetHasAlpha()`:** Sets the `has_alpha_` flag and updates the Skia alpha type. This is important for rendering.
    * **`SetStatus()`:** Updates the frame's status and triggers pixel change notifications. The interaction with `NotifyBitmapIfPixelsChanged()` and immutability is important.
    * **`ZeroFillFrameRect()`:** Clears a specific rectangular region of the frame. This is for partial updates or clearing parts of an image.
    * **`BlendRGBAF16Buffer`, `BlendRGBARawF16Buffer`, `BlendRGBAPremultipliedF16Buffer`:**  Blending operations using Skia for high-precision floating-point color data. The separate functions for premultiplied and non-premultiplied alpha are key.
    * **`BlendChannel`, `BlendSrcOverDstNonPremultiplied`:**  Blending operations for standard 8-bit color data. The implementation of "source-over" blending is a core compositing concept.
    * **`BlendRGBARaw()`:** Blends a solid color onto the frame.
    * **`BlendSrcOverDstRaw()`:** Blends one frame onto another.
    * **`ComputeAlphaType()`:** Determines the appropriate Skia alpha type based on the frame's state and whether it has alpha.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**  Think about how images are used on the web:

    * **HTML `<img>` tag:** This is the most direct connection. The `ImageFrame` holds the decoded pixel data that will eventually be displayed.
    * **CSS `background-image`:**  Similar to `<img>`, CSS can display images.
    * **Canvas API:**  JavaScript's `CanvasRenderingContext2D` allows direct manipulation of image data. The `ImageFrame`'s `FinalizePixelsAndGetImage()` provides the `SkImage` which could be used with the Canvas API (though the connection isn't direct in *this* file, it's a likely usage scenario).
    * **Animation (GIF, WebP, APNG):**  The concept of "frames" and their durations directly relates to animated images. The `ImageFrame` stores the data for each individual frame.

5. **Logical Reasoning (Input/Output):** Select a few methods for this:

    * **`AllocatePixelData()`:**  Input: dimensions, color space. Output: Success/failure, and if successful, the bitmap is allocated.
    * **`BlendSrcOverDstRaw()`:** Input: Two `ImageFrame::PixelData` pointers. Output: The `src` pixel data is modified to be the blended result.
    * **`SetStatus(kFrameComplete)`:** Input: `kFrameComplete`. Output:  Triggers `NotifyBitmapIfPixelsChanged()` and sets the bitmap's alpha type.

6. **Common Usage Errors:** Think about potential mistakes a developer (even within the browser engine) could make:

    * **Incorrect `SetStatus()` calls:** Setting the status prematurely or incorrectly could lead to issues.
    * **Forgetting to call `FinalizePixelsAndGetImage()`:** The bitmap remains mutable, potentially leading to unexpected modifications.
    * **Mixing premultiplied and non-premultiplied alpha incorrectly:**  This is a common source of visual artifacts.
    * **Not checking return values:**  Failing to check the return values of allocation or copying methods can lead to crashes or incorrect behavior.
    * **Modifying immutable bitmaps:** Once `FinalizePixelsAndGetImage()` is called, the bitmap should not be modified.

7. **Structure and Refine:** Organize the findings into clear sections as requested. Use bullet points and clear explanations. Ensure the examples are concrete and easy to understand. Double-check for accuracy and completeness. For example, initially, I might have overlooked the detail about `TakeBitmapDataIfWritable()` being an optimization. Rereading the code and comments clarifies this. Similarly, the explanation of premultiplied alpha might need to be refined for clarity.

8. **Review and Iterate:**  Read through the entire answer to make sure it's coherent, addresses all parts of the prompt, and is free of errors. Consider if there are any nuances or subtleties that could be added. For instance, emphasizing the role of `ImageFrame` as a central data structure in the image decoding pipeline.

This detailed thought process, moving from a high-level understanding to specific details, helps in comprehensively analyzing the given source code and addressing all aspects of the request.
这个文件 `blink/renderer/platform/image-decoders/image_frame.cc` 定义了 `ImageFrame` 类，它是 Chromium Blink 渲染引擎中处理图像解码的核心数据结构之一。  它主要负责存储和管理单个图像帧的像素数据和相关元数据。

以下是它的主要功能：

**1. 存储图像帧的像素数据:**

*   `bitmap_`:  使用 Skia 库的 `SkBitmap` 对象来存储实际的像素数据。可以理解为一块内存区域，存放着图像的颜色信息。
*   `pixel_format_`:  存储像素数据的格式，例如 `RGBA_8888`, `RGBA_F16` 等。

**2. 存储图像帧的元数据:**

*   `status_`:  表示图像帧的解码状态，例如 `kFrameEmpty` (空), `kFrameInitialized` (已初始化), `kFrameComplete` (解码完成)。
*   `has_alpha_`:  布尔值，指示图像帧是否包含 alpha (透明度) 通道。
*   `timestamp_`:  可选的时间戳，用于动画图像帧的时间控制。
*   `duration_`:  图像帧的显示持续时间，通常用于动画图像。
*   `disposal_method_`:  用于 GIF 等动画格式的帧处理方式，例如 `kDisposeDoNotDispose`, `kDisposeBackground`, `kDisposePrevious`.
*   `alpha_blend_source_`:  定义如何与之前的帧进行 alpha 混合。
*   `premultiply_alpha_`:  布尔值，指示像素数据是否已预乘 alpha。
*   `original_frame_rect_`:  原始帧的矩形区域，用于处理图像的部分更新。
*   `required_previous_frame_index_`:  用于指示当前帧是否依赖于之前的特定帧。

**3. 提供操作像素数据的方法:**

*   `ClearPixelData()`: 清空像素数据，释放 `bitmap_` 占用的内存。
*   `ZeroFillPixelData()`: 将像素数据填充为透明黑色。
*   `CopyBitmapData()`: 从另一个 `ImageFrame` 对象复制像素数据。
*   `TakeBitmapDataIfWritable()`:  如果另一个 `ImageFrame` 的 `bitmap_` 可写，则将像素数据的所有权转移给当前对象，避免不必要的复制。
*   `AllocatePixelData()`:  为 `bitmap_` 分配内存。
*   `FinalizePixelsAndGetImage()`:  将 `bitmap_` 标记为不可变，并创建一个 `SkImage` 对象，方便后续渲染。
*   `ZeroFillFrameRect()`:  将指定矩形区域内的像素填充为透明黑色。
*   `BlendRGBARaw()` / `BlendSrcOverDstRaw()`: 提供像素级别的混合操作。

**4. 管理帧的状态和属性:**

*   `SetStatus()`: 设置帧的解码状态。
*   `SetHasAlpha()`: 设置是否包含 alpha 通道。
*   `SetDuration()` / `SetDisposalMethod()` / `SetAlphaBlendSource()` / `SetPremultiplyAlpha()` / `SetOriginalFrameRect()` / `SetRequiredPreviousFrameIndex()`:  设置相应的元数据。
*   `ComputeAlphaType()`:  根据帧的状态和 `has_alpha_` 属性计算 Skia 的 alpha 类型。

**与 JavaScript, HTML, CSS 的关系：**

`ImageFrame` 处于 Blink 渲染引擎的底层，直接与 JavaScript, HTML, CSS 没有直接的 API 交互。但是，它的功能是支撑这些上层技术的关键：

*   **HTML `<img>` 标签:** 当浏览器解析到 `<img>` 标签，并需要显示图片时，图像解码器（如 JPEGDecoder, PNGDecoder 等）会将解码后的每一帧像素数据存储在 `ImageFrame` 对象中。这些 `ImageFrame` 对象最终会被用于渲染到屏幕上。
    *   **假设输入:** 一个包含 JPEG 图片的 HTML 文件： `<img src="image.jpg">`
    *   **逻辑推理:**  Blink 引擎会请求 `image.jpg`，JPEG 解码器会解码图像，并将解码后的像素数据填充到 `ImageFrame` 中。
    *   **输出:**  浏览器最终在页面上渲染出 `image.jpg` 的内容，`ImageFrame` 存储的像素数据是渲染的基础。

*   **CSS `background-image` 属性:** 类似于 `<img>` 标签，当 CSS 中使用 `background-image` 指定图片时，也会经历类似的解码和 `ImageFrame` 的创建过程。
    *   **假设输入:** 一个包含 CSS 规则的 HTML 文件： `<div style="background-image: url('background.png')"></div>`
    *   **逻辑推理:** Blink 引擎会请求 `background.png`，PNG 解码器会解码图像，并将解码后的像素数据存储在 `ImageFrame` 中。
    *   **输出:** `<div>` 元素的背景会显示 `background.png` 的内容，`ImageFrame` 存储的像素数据是渲染的基础。

*   **Canvas API (`<canvas>`)**: JavaScript 的 Canvas API 允许直接操作像素数据。虽然 `ImageFrame` 本身不直接暴露给 JavaScript，但通过一些内部机制，可以将 `ImageFrame` 中存储的像素数据传递给 Canvas 进行绘制或其他操作。例如，可以使用 `drawImage()` 方法将一个图片 (`ImageBitmap` 或 `HTMLImageElement`) 绘制到 Canvas 上，而这些对象底层可能就包含了由 `ImageFrame` 产生的像素数据。
    *   **假设输入:** JavaScript 代码使用 Canvas API 绘制图片：
        ```javascript
        const canvas = document.getElementById('myCanvas');
        const ctx = canvas.getContext('2d');
        const image = new Image();
        image.onload = function() {
          ctx.drawImage(image, 0, 0);
        };
        image.src = 'animated.gif';
        ```
    *   **逻辑推理:** 当 `animated.gif` 加载完成后，其每一帧会被解码并存储在 `ImageFrame` 中。当 `drawImage()` 被调用时，Canvas 会访问这些 `ImageFrame` 的像素数据进行绘制。
    *   **输出:** Canvas 上会显示 `animated.gif` 的内容，包括动画的每一帧，这些帧的像素数据来源于 `ImageFrame`。

*   **动画图像 (GIF, WebP, APNG):**  `ImageFrame` 对于处理动画图像至关重要。动画图像由多个帧组成，每个帧的数据都存储在一个 `ImageFrame` 对象中。`duration_`, `disposal_method_` 等元数据用于控制动画的播放。
    *   **假设输入:** 一个包含 GIF 动画的 HTML 文件： `<img src="animation.gif">`
    *   **逻辑推理:** GIF 解码器会解码 `animation.gif` 的每一帧，为每一帧创建一个 `ImageFrame` 对象，并设置其 `duration_` 和 `disposal_method_` 等属性。
    *   **输出:** 浏览器会按照 GIF 动画的帧顺序和持续时间播放动画，每个显示的帧的像素数据都来自一个对应的 `ImageFrame` 对象。

**用户或编程常见的使用错误：**

由于 `ImageFrame` 是 Blink 内部使用的类，普通 Web 开发者不会直接操作它。然而，在 Blink 引擎的开发过程中，可能会出现以下编程错误：

1. **内存管理错误:**
    *   **未正确释放 `bitmap_`:** 如果 `ImageFrame` 对象被销毁时，`bitmap_` 占用的内存没有被释放，会导致内存泄漏。
    *   **过度复制像素数据:**  不必要地调用 `CopyBitmapData()` 而不是 `TakeBitmapDataIfWritable()`，会导致性能下降和内存占用增加。

    *   **假设输入 (错误代码):**
        ```c++
        void processImageFrame(const ImageFrame& frame) {
          ImageFrame new_frame = frame; // 应该尽可能避免这种深拷贝
          // ... 使用 new_frame ...
        }
        ```
    *   **输出 (错误):**  每次调用 `processImageFrame` 都会进行一次深拷贝，如果图像很大，会消耗大量时间和内存。应该考虑传递引用或者使用智能指针。

2. **状态管理错误:**
    *   **在 `status_` 为 `kFrameEmpty` 时访问 `bitmap_`:**  这会导致程序崩溃，因为此时像素数据尚未分配。
    *   **在帧未完成解码时就尝试渲染:**  可能会显示不完整或错误的图像。

    *   **假设输入 (错误代码):**
        ```c++
        void renderFrame(const ImageFrame& frame) {
          if (frame.GetStatus() != ImageFrame::kFrameComplete) {
            // 忘记处理未完成的情况
          }
          // ... 使用 frame.GetBitmap() 进行渲染 ...
        }
        ```
    *   **输出 (错误):** 如果 `frame` 的状态不是 `kFrameComplete`，直接使用其 `bitmap_` 可能会导致未定义的行为。

3. **混合模式错误:**
    *   **在需要预乘 alpha 的情况下使用了非预乘的像素数据，或者反之。** 这会导致颜色不正确。

    *   **假设输入 (错误场景):** 一个图像解码器错误地将非预乘 alpha 的 PNG 数据标记为预乘 alpha。
    *   **输出 (错误):**  渲染出来的图像颜色会偏亮或出现白边等不正常的现象。

4. **资源竞争和同步问题 (在多线程环境中):**
    *   多个线程同时访问或修改同一个 `ImageFrame` 对象，可能导致数据损坏。

    *   **假设输入 (错误代码):**
        ```c++
        // 线程 1
        image_frame->ZeroFillPixelData();

        // 线程 2
        SkColor color = image_frame->bitmap().getColor(x, y); // 可能在线程 1 正在填充时读取
        ```
    *   **输出 (错误):**  读取到的颜色可能是不确定的，因为两个线程同时操作了 `image_frame` 的 `bitmap_`。

5. **未正确处理 `DisposalMethod` (针对动画):**
    *   在处理 GIF 等动画时，没有根据 `DisposalMethod` 正确更新画布，会导致动画显示错误，例如留下上一帧的残影。

    *   **假设输入 (错误逻辑):**  在处理 GIF 动画时，总是简单地绘制下一帧，而忽略了 `DisposalMethod` 为 `kDisposeBackground` 或 `kDisposePrevious` 的情况。
    *   **输出 (错误):**  动画可能会出现叠影或者不正确的背景。

总而言之，`ImageFrame` 类在 Chromium Blink 引擎中扮演着至关重要的角色，它封装了图像帧的像素数据和元数据，是图像解码和渲染流程中的核心数据结构。虽然普通 Web 开发者不会直接操作它，但理解其功能有助于更好地理解浏览器如何处理和显示图像。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/image_frame.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
/*
 * Copyright (C) 2006 Apple Computer, Inc.  All rights reserved.
 * Copyright (C) 2008, 2009 Google, Inc.
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

#include "third_party/blink/renderer/platform/image-decoders/image_frame.h"

#include "third_party/blink/renderer/platform/image-decoders/image_decoder.h"
#include "third_party/skia/include/core/SkCanvas.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkSurface.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {

ImageFrame::ImageFrame() = default;

ImageFrame::~ImageFrame() = default;

ImageFrame::ImageFrame(const ImageFrame& other) : has_alpha_(false) {
  operator=(other);
}

ImageFrame& ImageFrame::operator=(const ImageFrame& other) {
  if (this == &other) {
    return *this;
  }

  bitmap_ = other.bitmap_;
  // Be sure to assign this before calling SetStatus(), since SetStatus() may
  // call NotifyBitmapIfPixelsChanged().
  pixels_changed_ = other.pixels_changed_;
  SetMemoryAllocator(other.GetAllocator());
  SetOriginalFrameRect(other.OriginalFrameRect());
  SetStatus(other.GetStatus());
  if (other.Timestamp()) {
    SetTimestamp(*other.Timestamp());
  } else {
    timestamp_.reset();
  }
  SetDuration(other.Duration());
  SetDisposalMethod(other.GetDisposalMethod());
  SetAlphaBlendSource(other.GetAlphaBlendSource());
  SetPremultiplyAlpha(other.PremultiplyAlpha());
  // Be sure that this is called after we've called SetStatus(), since we
  // look at our status to know what to do with the alpha value.
  SetHasAlpha(other.HasAlpha());
  pixel_format_ = other.pixel_format_;
  SetRequiredPreviousFrameIndex(other.RequiredPreviousFrameIndex());
  return *this;
}

void ImageFrame::ClearPixelData() {
  bitmap_.reset();
  status_ = kFrameEmpty;
  // NOTE: Do not reset other members here; ClearFrameBufferCache()
  // calls this to free the bitmap data, but other functions like
  // InitFrameBuffer() and FrameComplete() may still need to read
  // other metadata out of this frame later.
}

void ImageFrame::ZeroFillPixelData() {
  bitmap_.eraseARGB(0, 0, 0, 0);
  has_alpha_ = true;
}

bool ImageFrame::CopyBitmapData(const ImageFrame& other) {
  DCHECK_NE(this, &other);
  has_alpha_ = other.has_alpha_;
  pixel_format_ = other.pixel_format_;
  bitmap_.reset();
  SkImageInfo info = other.bitmap_.info();
  if (!bitmap_.tryAllocPixels(info)) {
    return false;
  }

  if (!other.bitmap_.readPixels(info, bitmap_.getPixels(), bitmap_.rowBytes(),
                                0, 0)) {
    return false;
  }

  status_ = kFrameInitialized;
  return true;
}

bool ImageFrame::TakeBitmapDataIfWritable(ImageFrame* other) {
  DCHECK(other);
  DCHECK_EQ(kFrameComplete, other->status_);
  DCHECK_EQ(kFrameEmpty, status_);
  DCHECK_NE(this, other);
  if (other->bitmap_.isImmutable()) {
    return false;
  }
  has_alpha_ = other->has_alpha_;
  pixel_format_ = other->pixel_format_;
  bitmap_.reset();
  bitmap_.swap(other->bitmap_);
  other->status_ = kFrameEmpty;
  status_ = kFrameInitialized;
  return true;
}

bool ImageFrame::AllocatePixelData(int new_width,
                                   int new_height,
                                   sk_sp<SkColorSpace> color_space) {
  // AllocatePixelData() should only be called once.
  DCHECK(!Width() && !Height());
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
  if (new_width > 1000 || new_height > 1000) {
    return false;
  }
#endif

  SkImageInfo info = SkImageInfo::MakeN32(
      new_width, new_height,
      premultiply_alpha_ ? kPremul_SkAlphaType : kUnpremul_SkAlphaType,
      std::move(color_space));
  if (pixel_format_ == kRGBA_F16) {
    info = info.makeColorType(kRGBA_F16_SkColorType);
  }
  bool success = bitmap_.setInfo(info);
  DCHECK(success);
  success = bitmap_.tryAllocPixels(allocator_);
  if (success) {
    status_ = kFrameInitialized;
  }

  return success;
}

sk_sp<SkImage> ImageFrame::FinalizePixelsAndGetImage() {
  DCHECK_EQ(kFrameComplete, status_);
  bitmap_.setImmutable();
  return SkImages::RasterFromBitmap(bitmap_);
}

void ImageFrame::SetHasAlpha(bool alpha) {
  has_alpha_ = alpha;

  bitmap_.setAlphaType(ComputeAlphaType());
}

void ImageFrame::SetStatus(Status status) {
  status_ = status;
  if (status_ == kFrameComplete) {
    bitmap_.setAlphaType(ComputeAlphaType());
    // Send pending pixels changed notifications now, because we can't do
    // this after the bitmap has been marked immutable.  We don't set the
    // bitmap immutable here because it would defeat
    // TakeBitmapDataIfWritable().  Instead we let the bitmap stay mutable
    // until someone calls FinalizePixelsAndGetImage() to actually get the
    // SkImage.
    NotifyBitmapIfPixelsChanged();
  }
}

void ImageFrame::ZeroFillFrameRect(const gfx::Rect& rect) {
  if (rect.IsEmpty()) {
    return;
  }

  bitmap_.eraseArea(gfx::RectToSkIRect(rect), SkColorSetARGB(0, 0, 0, 0));
  SetHasAlpha(true);
}

static void BlendRGBAF16Buffer(ImageFrame::PixelDataF16* dst,
                               ImageFrame::PixelDataF16* src,
                               size_t num_pixels,
                               SkAlphaType dst_alpha_type) {
  // Source is always unpremul, but the blending result might be premul or
  // unpremul, depending on the alpha type of the destination pixel passed to
  // this function.
  SkImageInfo info = SkImageInfo::Make(base::checked_cast<int>(num_pixels), 1,
                                       kRGBA_F16_SkColorType, dst_alpha_type,
                                       SkColorSpace::MakeSRGBLinear());
  sk_sp<SkSurface> surface =
      SkSurfaces::WrapPixels(info, dst, info.minRowBytes());

  SkPixmap src_pixmap(info.makeAlphaType(kUnpremul_SkAlphaType), src,
                      info.minRowBytes());
  sk_sp<SkImage> src_image =
      SkImages::RasterFromPixmap(src_pixmap, nullptr, nullptr);

  surface->getCanvas()->drawImage(src_image, 0, 0);
}

void ImageFrame::BlendRGBARawF16Buffer(PixelDataF16* dst,
                                       PixelDataF16* src,
                                       size_t num_pixels) {
  BlendRGBAF16Buffer(dst, src, num_pixels, kUnpremul_SkAlphaType);
}

void ImageFrame::BlendRGBAPremultipliedF16Buffer(PixelDataF16* dst,
                                                 PixelDataF16* src,
                                                 size_t num_pixels) {
  BlendRGBAF16Buffer(dst, src, num_pixels, kPremul_SkAlphaType);
}

static uint8_t BlendChannel(uint8_t src,
                            uint8_t src_a,
                            uint8_t dst,
                            uint8_t dst_a,
                            unsigned scale) {
  unsigned blend_unscaled = src * src_a + dst * dst_a;
  DCHECK(blend_unscaled < (1ULL << 32) / scale);
  return (blend_unscaled * scale) >> 24;
}

static uint32_t BlendSrcOverDstNonPremultiplied(uint32_t src, uint32_t dst) {
  uint8_t src_a = SkGetPackedA32(src);
  if (src_a == 0) {
    return dst;
  }

  uint8_t dst_a = SkGetPackedA32(dst);
  uint8_t dst_factor_a = (dst_a * SkAlpha255To256(255 - src_a)) >> 8;
  DCHECK(src_a + dst_factor_a < (1U << 8));
  uint8_t blend_a = src_a + dst_factor_a;
  unsigned scale = (1UL << 24) / blend_a;

  uint8_t blend_r = BlendChannel(SkGetPackedR32(src), src_a,
                                 SkGetPackedR32(dst), dst_factor_a, scale);
  uint8_t blend_g = BlendChannel(SkGetPackedG32(src), src_a,
                                 SkGetPackedG32(dst), dst_factor_a, scale);
  uint8_t blend_b = BlendChannel(SkGetPackedB32(src), src_a,
                                 SkGetPackedB32(dst), dst_factor_a, scale);

  return SkPackARGB32(blend_a, blend_r, blend_g, blend_b);
}

void ImageFrame::BlendRGBARaw(PixelData* dest,
                              unsigned r,
                              unsigned g,
                              unsigned b,
                              unsigned a) {
  *dest = BlendSrcOverDstNonPremultiplied(SkPackARGB32(a, r, g, b), *dest);
}

void ImageFrame::BlendSrcOverDstRaw(PixelData* src, PixelData dst) {
  *src = BlendSrcOverDstNonPremultiplied(*src, dst);
}

SkAlphaType ImageFrame::ComputeAlphaType() const {
  // If the frame is not fully loaded, there will be transparent pixels,
  // so we can't tell skia we're opaque, even for image types that logically
  // always are (e.g. jpeg).
  if (!has_alpha_ && status_ == kFrameComplete) {
    return kOpaque_SkAlphaType;
  }

  return premultiply_alpha_ ? kPremul_SkAlphaType : kUnpremul_SkAlphaType;
}

}  // namespace blink
```