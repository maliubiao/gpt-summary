Response:
Let's break down the thought process for analyzing this C++ code and generating the response.

1. **Understand the Goal:** The core request is to understand the functionality of `webp_image_decoder.cc` within the Chromium Blink engine. Specifically, it asks for its purpose, relationships with web technologies (HTML, CSS, JS), logical reasoning examples, and common usage errors.

2. **Identify Key Components:**  The first step is to scan the code and pick out the important parts. Keywords and structural elements are helpful here:
    * `#include`: Indicates dependencies and the purpose of the file (decoding WebP images).
    * `namespace blink`:  Confirms it's part of the Blink rendering engine.
    * Class definition: `WEBPImageDecoder`. This is the main entity.
    * Member functions:  `Decode`, `DecodeSize`, `InitializeNewFrame`, `UpdateDemuxer`, `Clear`, `OnSetData`, etc. These are the actions the class can perform.
    * Private member variables: `demux_`, `decoder_`, `frame_buffer_cache_`, `consolidated_data_`, etc. These hold the state and data.
    * Helper functions within the anonymous namespace: `findBlendRangeAtRow`, `alphaBlendPremultiplied`, `alphaBlendNonPremultiplied`, `IsSimpleLossyWebPImage`, `UpdateWebPFileFormatUMA`. These provide supporting logic.
    * Use of external libraries/APIs: `libwebp` (through `WebPDemux*`, `WebPINewDecoder*`), Skia (`SkData`, color space related functions).
    * Usage of Chromium/Blink specific classes: `ImageDecoder`, `ImageFrame`, `SegmentReader`, `ColorProfile`, `ColorProfileTransform`, histogram macros (`UMA_HISTOGRAM_ENUMERATION`).

3. **Infer Functionality (High-Level):** Based on the includes and class name, it's clear this class is responsible for decoding WebP image data. The presence of animation-related members suggests it handles animated WebP images as well.

4. **Delve into Specific Functions (Mid-Level):** Now, go through the member functions and helper functions to understand the details of the decoding process:
    * **`UpdateDemuxer()`:**  Parses the WebP header, extracts metadata (size, animation info, etc.), and uses `libwebp`'s demuxing capabilities.
    * **`Decode()`:**  The main decoding logic. Iterates through frames, calls `DecodeSingleFrame()`.
    * **`DecodeSingleFrame()`:**  Uses `libwebp`'s decoding API (`WebPIUpdate`) to decode a single frame. Handles alpha blending and color space transformations.
    * **`InitializeNewFrame()`:** Sets up the `ImageFrame` object for a new frame based on information from the demuxer.
    * **`Clear()`/`ClearDecoder()`:** Releases resources.
    * **`OnSetData()`:** Handles incoming image data.
    * **Blending functions:**  Implement alpha blending.
    * **`IsSimpleLossyWebPImage()`:** Detects a specific type of WebP.
    * **`UpdateWebPFileFormatUMA()`:**  Logs WebP format statistics.
    * **YUV related functions:** Indicate support for YUV decoding (primarily for hardware acceleration).

5. **Connect to Web Technologies (HTML, CSS, JS):**  Think about how image decoding fits into the web rendering pipeline:
    * **HTML `<img>` tag:** The browser fetches the image data, and this decoder is used to process the WebP format.
    * **CSS `background-image`:** Similar to `<img>`, the decoder handles WebP background images.
    * **JavaScript `Image` object/Canvas API:**  JavaScript can load images, and the decoded pixel data can be manipulated on a canvas. Animated WebP playback is often handled by the browser itself, but JS could interact with the `Image` object.

6. **Identify Logical Reasoning Opportunities:** Look for conditional logic and data transformations:
    * **Alpha blending:** The blending logic depends on the alpha option and the disposal method of previous frames. Consider scenarios with different alpha values and disposal methods.
    * **Animation:** The frame decoding order and the use of previous frames for blending involve logical steps.
    * **YUV decoding:**  The decision to use YUV decoding is based on specific conditions (lossy, not animated, no alpha, no ICCP).

7. **Consider User/Programming Errors:**  Think about what could go wrong:
    * **Incomplete image data:**  The decoder needs to handle partial downloads gracefully.
    * **Corrupted image data:** `libwebp` might return errors.
    * **Incorrect usage of the API (though this is internal Blink code, so less direct user interaction).**
    * **Memory allocation failures.**

8. **Structure the Response:** Organize the information into clear sections:
    * **Functionality:**  A concise summary of the file's purpose.
    * **Relationship with Web Technologies:**  Concrete examples of how the decoder interacts with HTML, CSS, and JS.
    * **Logical Reasoning Examples:** Illustrative scenarios with input and output.
    * **Common Usage Errors:**  Potential pitfalls.

9. **Refine and Elaborate:** Review the generated response for clarity, accuracy, and completeness. Add more detail where necessary and ensure the examples are understandable. For example, in the logical reasoning section, providing specific pixel values or image dimensions can make the explanation clearer. Initially, I might have just said "alpha blending is performed," but elaborating on the conditions (`BlendAtopPreviousFrame`, disposal methods) provides more insight. Similarly,  simply stating "handles animations" is less informative than explaining how it uses `WebPDemuxGetFrame` and the `frame_buffer_cache_`.

This iterative process of scanning, identifying key parts, inferring functionality, connecting to broader concepts, and refining helps to produce a comprehensive and accurate understanding of the code.
这个文件 `webp_image_decoder.cc` 是 Chromium Blink 引擎中用于解码 WebP 图片格式的关键组件。它的主要功能是将 WebP 格式的图像数据转换为浏览器可以渲染和显示的像素数据。

以下是该文件的详细功能列表，并解释了它与 JavaScript, HTML, CSS 的关系，以及可能的逻辑推理和常见错误：

**主要功能:**

1. **WebP 解码:**  核心功能是将 WebP 格式的字节流解码成像素数据。它使用 `libwebp` 库来完成底层的解码工作。
2. **支持静态和动态 (动画) WebP:** 可以处理静态的单帧 WebP 图片，也可以处理动画 WebP 图片。
3. **帧管理 (动画 WebP):** 对于动画 WebP，它负责管理多个帧，包括帧的解码、持续时间和清除方式（dispose method）。
4. **Alpha 通道处理:** 支持处理 WebP 图片中的 Alpha 透明度信息，并提供预乘 (premultiplied) 和非预乘 (non-premultiplied) 两种 Alpha 混合模式。
5. **颜色空间管理:**  处理 WebP 图片中的颜色空间信息，并进行必要的颜色空间转换，确保在浏览器中正确渲染颜色。它支持读取和应用 ICC 颜色配置文件 (ICCP profile)。
6. **YUV 解码 (可选):**  在特定条件下（例如，简单的无损耗静态 WebP），可以选择将图像解码为 YUV 格式，这可以用于硬件加速解码。
7. **增量解码:** 支持逐步解码 WebP 数据，这意味着即使图片数据尚未完全下载，也可以开始解码和渲染已接收的部分。
8. **内存管理:**  有效地管理用于解码和存储像素数据的内存。
9. **性能优化:**  通过一些优化手段，例如内联函数和针对不同 Alpha 选项的优化分支，提高解码性能。
10. **统计和监控:** 使用 UMA (User Metrics Analysis) 记录 WebP 文件格式的统计信息，用于性能分析和问题追踪。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML `<img>` 标签:** 当 HTML 中使用 `<img>` 标签加载 WebP 图片时，Blink 引擎会调用 `WEBPImageDecoder` 来解码图片数据，并将解码后的像素数据用于渲染到页面上。
    ```html
    <img src="image.webp">
    ```
* **CSS `background-image` 属性:**  类似地，当 CSS 样式中使用 `background-image` 加载 WebP 图片时，`WEBPImageDecoder` 也会被调用进行解码。
    ```css
    .element {
      background-image: url("background.webp");
    }
    ```
* **JavaScript `Image` 对象和 Canvas API:** JavaScript 可以创建 `Image` 对象来加载图片，或者使用 Canvas API 来绘制图片。当加载 WebP 图片时，`WEBPImageDecoder` 负责解码工作，解码后的数据可以被 JavaScript 或 Canvas API 使用。
    ```javascript
    const image = new Image();
    image.src = 'image.webp';
    image.onload = function() {
      const canvas = document.getElementById('myCanvas');
      const ctx = canvas.getContext('2d');
      ctx.drawImage(image, 0, 0);
    };
    ```

**逻辑推理举例:**

**假设输入:** 一个包含动画的 WebP 图片数据，其中第二帧的混合方法 (blend method) 设置为 `WEBP_MUX_BLEND` (即 `ImageFrame::kBlendAtopPreviousFrame`)，且该帧的 Alpha 通道并非完全不透明。

**逻辑推理:**

1. **解码第二帧:** `Decode()` 函数会调用 `DecodeSingleFrame()` 来解码第二帧的数据。
2. **检查混合方法:** `ApplyPostProcessing()` 函数会被调用，它会检查第二帧的 `blend_method` 是否为 `ImageFrame::kBlendAtopPreviousFrame`。
3. **查找前一帧:** 如果是，并且前一帧 (第一帧) 已经解码完成，则会获取第一帧的像素数据。
4. **执行 Alpha 混合:**  `blend_function_` (根据 Alpha 选项选择 `alphaBlendPremultiplied` 或 `alphaBlendNonPremultiplied`) 会被调用，将第二帧的像素与第一帧的对应像素进行 Alpha 混合。只有第二帧中 Alpha 值小于 255 的像素才会与前一帧混合。
5. **输出:**  第二帧的最终像素数据将是其原始像素与前一帧像素进行 Alpha 混合后的结果。

**假设输入:** 一个静态的 WebP 图片数据，没有 Alpha 通道，且浏览器支持 YUV 解码。

**逻辑推理:**

1. **检查条件:** `OnSetData()` 中 `UpdateDemuxer()` 会解析 WebP 头部信息，确定图片是静态的、无 Alpha 通道。`CanAllowYUVDecodingForWebP()` 会检查是否满足 YUV 解码的条件。
2. **选择 YUV 解码:** 如果条件满足，`allow_decode_to_yuv_` 将被设置为 `true`。
3. **解码到 YUV:** 当调用 `DecodeToYUV()` 时，会使用 `libwebp` 将 WebP 数据直接解码为 YUV 格式的平面数据，而不是 RGBA。
4. **输出:**  图像数据将以 YUV 格式存储在 `image_planes_` 中，可以被用于后续的硬件加速渲染。

**用户或编程常见的使用错误举例:**

1. **提供不完整的 WebP 数据:**  如果 `WEBPImageDecoder` 接收到不完整的 WebP 数据，解码过程可能会失败。这通常发生在网络连接不稳定导致图片下载不完整时。
    * **错误现象:** 图片显示不完整，或者根本无法显示。
    * **代码处理:**  `UpdateDemuxer()` 和 `DecodeSingleFrame()` 会检查数据是否足够，如果不足，会返回错误或暂停解码，等待更多数据。
2. **假设 WebP 一定支持 YUV 解码:** 开发者可能会错误地假设所有 WebP 图片都可以进行 YUV 解码。实际上，只有满足特定条件的 WebP 图片才能进行 YUV 解码。
    * **错误现象:**  如果尝试强制进行 YUV 解码，但图片不满足条件，解码可能会失败或得到错误的结果。
    * **代码处理:** `CanAllowYUVDecodingForWebP()` 会进行严格的条件检查，确保只在支持的情况下才启用 YUV 解码。
3. **在动画 WebP 中错误地处理帧的清除方式 (disposal method):**  开发者在处理动画 WebP 时，可能会忽略或错误地理解帧的清除方式 (`kDisposeOverwriteBgcolor` 或 `kDisposeKeep`)，导致动画渲染出现闪烁或不正确的背景。
    * **错误现象:** 动画播放时，帧之间出现残留，或者背景没有正确更新。
    * **代码处理:** `InitializeNewFrame()` 中会解析帧的清除方式，并在 `ApplyPostProcessing()` 中根据清除方式进行相应的处理，例如，对于 `kDisposeOverwriteBgcolor`，会将当前帧的区域用背景色覆盖。
4. **不考虑 Alpha 混合:**  在处理带有透明度的 WebP 图片时，开发者可能会忽略 Alpha 混合的重要性，导致透明效果显示不正确。
    * **错误现象:**  透明区域显示为黑色或其他不透明颜色。
    * **代码处理:** `WEBPImageDecoder` 提供了 `alphaBlendPremultiplied` 和 `alphaBlendNonPremultiplied` 两种混合模式，确保透明度能正确地与背景或其他元素混合。开发者（实际上是 Blink 引擎的渲染流程）需要根据具体需求选择合适的 Alpha 选项。

总而言之，`webp_image_decoder.cc` 是 Blink 引擎处理 WebP 图片的核心，它负责将 WebP 数据解码为可渲染的像素，并处理各种 WebP 特性，如动画、透明度和颜色空间。理解其功能对于理解浏览器如何显示 WebP 图片至关重要。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/webp/webp_image_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2010 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/webp/webp_image_decoder.h"

#include <string.h>

#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkData.h"

#if defined(ARCH_CPU_BIG_ENDIAN)
#error Blink assumes a little-endian target.
#endif

namespace {

// Returns two point ranges (<left, width> pairs) at row |canvasY| which belong
// to |src| but not |dst|. A range is empty if its width is 0.
inline void findBlendRangeAtRow(const gfx::Rect& src,
                                const gfx::Rect& dst,
                                int canvasY,
                                int& left1,
                                int& width1,
                                int& left2,
                                int& width2) {
  SECURITY_DCHECK(canvasY >= src.y() && canvasY < src.bottom());
  left1 = -1;
  width1 = 0;
  left2 = -1;
  width2 = 0;

  if (canvasY < dst.y() || canvasY >= dst.bottom() || src.x() >= dst.right() ||
      src.right() <= dst.x()) {
    left1 = src.x();
    width1 = src.width();
    return;
  }

  if (src.x() < dst.x()) {
    left1 = src.x();
    width1 = dst.x() - src.x();
  }

  if (src.right() > dst.right()) {
    left2 = dst.right();
    width2 = src.right() - dst.right();
  }
}

// alphaBlendPremultiplied and alphaBlendNonPremultiplied are separate methods,
// even though they only differ by one line. This is done so that the compiler
// can inline BlendSrcOverDstPremultiplied() and BlensSrcOverDstRaw() calls.
// For GIF images, this optimization reduces decoding time by 15% for 3MB
// images.
void alphaBlendPremultiplied(blink::ImageFrame& src,
                             blink::ImageFrame& dst,
                             int canvasY,
                             int left,
                             int width) {
  for (int x = 0; x < width; ++x) {
    int canvasX = left + x;
    blink::ImageFrame::PixelData* pixel = src.GetAddr(canvasX, canvasY);
    if (SkGetPackedA32(*pixel) != 0xff) {
      blink::ImageFrame::PixelData prevPixel = *dst.GetAddr(canvasX, canvasY);
      blink::ImageFrame::BlendSrcOverDstPremultiplied(pixel, prevPixel);
    }
  }
}

void alphaBlendNonPremultiplied(blink::ImageFrame& src,
                                blink::ImageFrame& dst,
                                int canvasY,
                                int left,
                                int width) {
  for (int x = 0; x < width; ++x) {
    int canvasX = left + x;
    blink::ImageFrame::PixelData* pixel = src.GetAddr(canvasX, canvasY);
    if (SkGetPackedA32(*pixel) != 0xff) {
      blink::ImageFrame::PixelData prevPixel = *dst.GetAddr(canvasX, canvasY);
      blink::ImageFrame::BlendSrcOverDstRaw(pixel, prevPixel);
    }
  }
}

// Do not rename entries nor reuse numeric values. See the following link for
// descriptions: https://developers.google.com/speed/webp/docs/riff_container.
enum class WebPFileFormat {
  kSimpleLossy = 0,
  kSimpleLossless = 1,
  kExtendedAlpha = 2,
  kExtendedAnimation = 3,
  kExtendedAnimationWithAlpha = 4,
  kUnknown = 5,
  kMaxValue = kUnknown,
};

// Validates that |blob| is a simple lossy WebP image. Note that this explicitly
// checks "WEBPVP8 " to exclude extended lossy WebPs that don't actually use any
// extended features.
//
// TODO(crbug.com/1009237): consider combining this with the logic to detect
// WebPs that can be decoded to YUV.
bool IsSimpleLossyWebPImage(const sk_sp<SkData>& blob) {
  if (blob->size() < 20UL) {
    return false;
  }
  DCHECK(blob->bytes());
  return !memcmp(blob->bytes(), "RIFF", 4) &&
         !memcmp(blob->bytes() + 8UL, "WEBPVP8 ", 8);
}

// This method parses |blob|'s header and emits a UMA with the file format, as
// defined by WebP, see WebPFileFormat.
void UpdateWebPFileFormatUMA(const sk_sp<SkData>& blob) {
  if (!IsMainThread()) {
    return;
  }

  WebPBitstreamFeatures features;
  if (WebPGetFeatures(blob->bytes(), blob->size(), &features) !=
      VP8_STATUS_OK) {
    return;
  }

  // These constants are defined verbatim in
  // webp_dec.c::ParseHeadersInternal().
  constexpr int kLossyFormat = 1;
  constexpr int kLosslessFormat = 2;

  WebPFileFormat file_format = WebPFileFormat::kUnknown;
  if (features.has_alpha && features.has_animation) {
    file_format = WebPFileFormat::kExtendedAnimationWithAlpha;
  } else if (features.has_animation) {
    file_format = WebPFileFormat::kExtendedAnimation;
  } else if (features.has_alpha) {
    file_format = WebPFileFormat::kExtendedAlpha;
  } else if (features.format == kLossyFormat) {
    file_format = WebPFileFormat::kSimpleLossy;
  } else if (features.format == kLosslessFormat) {
    file_format = WebPFileFormat::kSimpleLossless;
  }

  UMA_HISTOGRAM_ENUMERATION("Blink.DecodedImage.WebPFileFormat", file_format);
}

}  // namespace

namespace blink {

WEBPImageDecoder::WEBPImageDecoder(AlphaOption alpha_option,
                                   ColorBehavior color_behavior,
                                   wtf_size_t max_decoded_bytes)
    : ImageDecoder(alpha_option,
                   ImageDecoder::kDefaultBitDepth,
                   color_behavior,
                   cc::AuxImage::kDefault,
                   max_decoded_bytes) {
  blend_function_ = (alpha_option == kAlphaPremultiplied)
                        ? alphaBlendPremultiplied
                        : alphaBlendNonPremultiplied;
}

WEBPImageDecoder::~WEBPImageDecoder() {
  Clear();
}

String WEBPImageDecoder::FilenameExtension() const {
  return "webp";
}

const AtomicString& WEBPImageDecoder::MimeType() const {
  DEFINE_STATIC_LOCAL(const AtomicString, webp_mime_type, ("image/webp"));
  return webp_mime_type;
}
void WEBPImageDecoder::Clear() {
  WebPDemuxDelete(demux_);
  demux_ = nullptr;
  consolidated_data_.reset();
  ClearDecoder();
}

void WEBPImageDecoder::ClearDecoder() {
  WebPIDelete(decoder_);
  decoder_ = nullptr;
  decoded_height_ = 0;
  frame_background_has_alpha_ = false;
}

WEBP_CSP_MODE WEBPImageDecoder::RGBOutputMode() {
  DCHECK(!IsDoingYuvDecode());
  if (ColorTransform()) {
    // Swizzling between RGBA and BGRA is zero cost in a color transform.
    // So when we have a color transform, we should decode to whatever is
    // easiest for libwebp, and then let the color transform swizzle if
    // necessary.
    // Lossy webp is encoded as YUV (so RGBA and BGRA are the same cost).
    // Lossless webp is encoded as BGRA. This means decoding to BGRA is
    // either faster or the same cost as RGBA.
    return MODE_BGRA;
  }
  bool premultiply = (format_flags_ & ALPHA_FLAG) && premultiply_alpha_;
#if SK_B32_SHIFT  // Output little-endian RGBA pixels (Android)
  return premultiply ? MODE_rgbA : MODE_RGBA;
#else  // Output little-endian BGRA pixels.
  return premultiply ? MODE_bgrA : MODE_BGRA;
#endif
}

bool WEBPImageDecoder::CanAllowYUVDecodingForWebP() const {
  // Should have been updated with a recent call to UpdateDemuxer().
  if (demux_state_ >= WEBP_DEMUX_PARSED_HEADER &&
      WebPDemuxGetI(demux_, WEBP_FF_FRAME_COUNT)) {
    // TODO(crbug/910276): Change after alpha support.
    if (!is_lossy_not_animated_no_alpha_) {
      return false;
    }

    // TODO(crbug/911246): Stop vetoing images with ICCP after Skia supports
    // transforming colorspace within YUV, which would allow colorspace
    // conversion during decode. Alternatively, look into passing along
    // transform for raster-time.
    bool has_iccp = !!(format_flags_ & ICCP_FLAG);
    return !has_iccp;
  }
  return false;
}

void WEBPImageDecoder::OnSetData(scoped_refptr<SegmentReader> data) {
  have_parsed_current_data_ = false;
  // TODO(crbug.com/943519): Modify this approach for incremental YUV (when
  // we don't require IsAllDataReceived() to be true before decoding).
  if (IsAllDataReceived()) {
    UpdateDemuxer();
    allow_decode_to_yuv_ = CanAllowYUVDecodingForWebP();
  }
}

int WEBPImageDecoder::RepetitionCount() const {
  return Failed() ? kAnimationLoopOnce : repetition_count_;
}

bool WEBPImageDecoder::FrameIsReceivedAtIndex(wtf_size_t index) const {
  if (!demux_ || demux_state_ < WEBP_DEMUX_PARSED_HEADER) {
    return false;
  }
  if (!(format_flags_ & ANIMATION_FLAG)) {
    return ImageDecoder::FrameIsReceivedAtIndex(index);
  }
  // frame_buffer_cache_.size() is equal to the return value of
  // DecodeFrameCount(). WebPDemuxGetI(demux_, WEBP_FF_FRAME_COUNT) returns the
  // number of ANMF chunks that have been received. (See also the DCHECK on
  // animated_frame.complete in InitializeNewFrame().) Therefore we can return
  // true if |index| is valid for frame_buffer_cache_.
  bool frame_is_received_at_index = index < frame_buffer_cache_.size();
  return frame_is_received_at_index;
}

base::TimeDelta WEBPImageDecoder::FrameDurationAtIndex(wtf_size_t index) const {
  return index < frame_buffer_cache_.size()
             ? frame_buffer_cache_[index].Duration()
             : base::TimeDelta();
}

bool WEBPImageDecoder::UpdateDemuxer() {
  if (Failed()) {
    return false;
  }

  // RIFF header (12 bytes) + data chunk header (8 bytes).
  const unsigned kWebpHeaderSize = 20;
  // The number of bytes needed to retrieve the size will vary based on the
  // type of chunk (VP8/VP8L/VP8X). This check just serves as an early out
  // before bitstream validation can occur.
  if (data_->size() < kWebpHeaderSize) {
    return IsAllDataReceived() ? SetFailed() : false;
  }

  if (have_parsed_current_data_) {
    return true;
  }
  have_parsed_current_data_ = true;

  if (consolidated_data_ && consolidated_data_->size() >= data_->size()) {
    // Less data provided than last time. |consolidated_data_| is guaranteed
    // to be its own copy of the data, so it is safe to keep it.
    return true;
  }

  if (IsAllDataReceived() && !consolidated_data_) {
    consolidated_data_ = data_->GetAsSkData();
  } else {
    buffer_.reserve(base::checked_cast<wtf_size_t>(data_->size()));
    while (buffer_.size() < data_->size()) {
      buffer_.AppendSpan(data_->GetSomeData(buffer_.size()));
    }
    DCHECK_EQ(buffer_.size(), data_->size());
    consolidated_data_ =
        SkData::MakeWithoutCopy(buffer_.data(), buffer_.size());
  }

  WebPDemuxDelete(demux_);
  WebPData input_data = {
      reinterpret_cast<const uint8_t*>(consolidated_data_->data()),
      consolidated_data_->size()};
  demux_ = WebPDemuxPartial(&input_data, &demux_state_);
  const bool truncated_file =
      IsAllDataReceived() && demux_state_ != WEBP_DEMUX_DONE;
  if (!demux_ || demux_state_ < WEBP_DEMUX_PARSED_HEADER || truncated_file) {
    if (!demux_) {
      consolidated_data_.reset();
    } else {
      // We delete the demuxer early to avoid breaking the expectation that
      // frame count == 0 when IsSizeAvailable() is false.
      WebPDemuxDelete(demux_);
      demux_ = nullptr;
    }
    return truncated_file ? SetFailed() : false;
  }

  DCHECK_GE(demux_state_, WEBP_DEMUX_PARSED_HEADER);
  if (!WebPDemuxGetI(demux_, WEBP_FF_FRAME_COUNT)) {
    return false;  // Wait until the encoded image frame data arrives.
  }

  if (!IsDecodedSizeAvailable()) {
    uint32_t width = WebPDemuxGetI(demux_, WEBP_FF_CANVAS_WIDTH);
    uint32_t height = WebPDemuxGetI(demux_, WEBP_FF_CANVAS_HEIGHT);
    if (!SetSize(base::strict_cast<unsigned>(width),
                 base::strict_cast<unsigned>(height))) {
      return SetFailed();
    }

    UpdateWebPFileFormatUMA(consolidated_data_);

    format_flags_ = WebPDemuxGetI(demux_, WEBP_FF_FORMAT_FLAGS);
    if (!(format_flags_ & ANIMATION_FLAG)) {
      repetition_count_ = kAnimationNone;
    } else {
      // Since we have parsed at least one frame, even if partially,
      // the global animation (ANIM) properties have been read since
      // an ANIM chunk must precede the ANMF frame chunks.
      repetition_count_ = WebPDemuxGetI(demux_, WEBP_FF_LOOP_COUNT);
      // Repetition count is always <= 16 bits.
      DCHECK_EQ(repetition_count_, repetition_count_ & 0xffff);
      // Repetition count is treated as n + 1 cycles for GIF. WebP defines loop
      // count as the number of cycles, with 0 meaning infinite.
      repetition_count_ = repetition_count_ == 0 ? kAnimationLoopInfinite
                                                 : repetition_count_ - 1;
      // FIXME: Implement ICC profile support for animated images.
      format_flags_ &= ~ICCP_FLAG;
    }

    if ((format_flags_ & ICCP_FLAG) && !IgnoresColorSpace()) {
      ReadColorProfile();
    }

    // Record bpp information only for lossy still images that do not have
    // alpha.
    if (!(format_flags_ & (ANIMATION_FLAG | ALPHA_FLAG))) {
      WebPBitstreamFeatures features;
      CHECK_EQ(WebPGetFeatures(consolidated_data_->bytes(),
                               consolidated_data_->size(), &features),
               VP8_STATUS_OK);
      if (features.format == CompressionFormat::kLossyFormat) {
        is_lossy_not_animated_no_alpha_ = true;
        static constexpr char kType[] = "WebP";
        update_bpp_histogram_callback_ =
            base::BindOnce(&UpdateBppHistogram<kType>);
      }
    }
  }

  DCHECK(IsDecodedSizeAvailable());

  wtf_size_t frame_count = WebPDemuxGetI(demux_, WEBP_FF_FRAME_COUNT);
  UpdateAggressivePurging(frame_count);

  return true;
}

void WEBPImageDecoder::OnInitFrameBuffer(wtf_size_t frame_index) {
  // ImageDecoder::InitFrameBuffer does a DCHECK if |frame_index| exists.
  ImageFrame& buffer = frame_buffer_cache_[frame_index];

  const wtf_size_t required_previous_frame_index =
      buffer.RequiredPreviousFrameIndex();
  if (required_previous_frame_index == kNotFound) {
    frame_background_has_alpha_ =
        !buffer.OriginalFrameRect().Contains(gfx::Rect(Size()));
  } else {
    const ImageFrame& prev_buffer =
        frame_buffer_cache_[required_previous_frame_index];
    frame_background_has_alpha_ =
        prev_buffer.HasAlpha() || (prev_buffer.GetDisposalMethod() ==
                                   ImageFrame::kDisposeOverwriteBgcolor);
  }

  // The buffer is transparent outside the decoded area while the image is
  // loading. The correct alpha value for the frame will be set when it is fully
  // decoded.
  buffer.SetHasAlpha(true);
}

void WEBPImageDecoder::DecodeToYUV() {
  DCHECK(IsDoingYuvDecode());

  // Only 8-bit YUV decode is currently supported.
  DCHECK_EQ(image_planes_->color_type(), kGray_8_SkColorType);

  if (Failed()) {
    return;
  }

  DCHECK(demux_);
  DCHECK(!(format_flags_ & ANIMATION_FLAG));

  WebPIterator webp_iter;
  // libwebp is 1-indexed.
  if (!WebPDemuxGetFrame(demux_, 1 /* frame */, &webp_iter)) {
    SetFailed();
  } else {
    std::unique_ptr<WebPIterator, void (*)(WebPIterator*)> webp_frame(
        &webp_iter, WebPDemuxReleaseIterator);
    DecodeSingleFrameToYUV(
        webp_frame->fragment.bytes,
        base::checked_cast<wtf_size_t>(webp_frame->fragment.size));
  }
}

gfx::Size WEBPImageDecoder::DecodedYUVSize(cc::YUVIndex index) const {
  DCHECK(IsDecodedSizeAvailable());
  switch (index) {
    case cc::YUVIndex::kY:
      return Size();
    case cc::YUVIndex::kU:
    case cc::YUVIndex::kV:
      return gfx::Size((Size().width() + 1) / 2, (Size().height() + 1) / 2);
  }
  NOTREACHED();
}

wtf_size_t WEBPImageDecoder::DecodedYUVWidthBytes(cc::YUVIndex index) const {
  switch (index) {
    case cc::YUVIndex::kY:
      return base::checked_cast<wtf_size_t>(Size().width());
    case cc::YUVIndex::kU:
    case cc::YUVIndex::kV:
      return base::checked_cast<wtf_size_t>((Size().width() + 1) / 2);
  }
  NOTREACHED();
}

SkYUVColorSpace WEBPImageDecoder::GetYUVColorSpace() const {
  return SkYUVColorSpace::kRec601_SkYUVColorSpace;
}

cc::YUVSubsampling WEBPImageDecoder::GetYUVSubsampling() const {
  DCHECK(consolidated_data_);
  if (IsSimpleLossyWebPImage(consolidated_data_)) {
    return cc::YUVSubsampling::k420;
  }
  // It is possible for a non-simple lossy WebP to also be YUV 4:2:0. However,
  // we're being conservative here because this is currently only used for
  // hardware decode acceleration, and WebPs other than simple lossy are not
  // supported in that path anyway.
  return cc::YUVSubsampling::kUnknown;
}

bool WEBPImageDecoder::CanReusePreviousFrameBuffer(
    wtf_size_t frame_index) const {
  DCHECK(frame_index < frame_buffer_cache_.size());
  return frame_buffer_cache_[frame_index].GetAlphaBlendSource() !=
         ImageFrame::kBlendAtopPreviousFrame;
}

void WEBPImageDecoder::ClearFrameBuffer(wtf_size_t frame_index) {
  if (demux_ && demux_state_ >= WEBP_DEMUX_PARSED_HEADER &&
      frame_buffer_cache_[frame_index].GetStatus() ==
          ImageFrame::kFramePartial) {
    // Clear the decoder state so that this partial frame can be decoded again
    // when requested.
    ClearDecoder();
  }
  ImageDecoder::ClearFrameBuffer(frame_index);
}

void WEBPImageDecoder::ReadColorProfile() {
  WebPChunkIterator chunk_iterator;
  if (!WebPDemuxGetChunk(demux_, "ICCP", 1, &chunk_iterator)) {
    WebPDemuxReleaseChunkIterator(&chunk_iterator);
    return;
  }

  wtf_size_t profile_size =
      base::checked_cast<wtf_size_t>(chunk_iterator.chunk.size);

  if (auto profile = ColorProfile::Create(
          base::span(chunk_iterator.chunk.bytes, profile_size))) {
    if (profile->GetProfile()->data_color_space == skcms_Signature_RGB) {
      SetEmbeddedColorProfile(std::move(profile));
    }
  } else {
    DLOG(ERROR) << "Failed to parse image ICC profile";
  }

  WebPDemuxReleaseChunkIterator(&chunk_iterator);
}

void WEBPImageDecoder::ApplyPostProcessing(wtf_size_t frame_index) {
  ImageFrame& buffer = frame_buffer_cache_[frame_index];
  int width;
  int decoded_height;
  // TODO(crbug.com/911246): Do post-processing once skcms_Transform
  // supports multiplanar formats.
  DCHECK(!IsDoingYuvDecode());

  if (!WebPIDecGetRGB(decoder_, &decoded_height, &width, nullptr, nullptr)) {
    return;  // See also https://bugs.webkit.org/show_bug.cgi?id=74062
  }
  if (decoded_height <= 0) {
    return;
  }

  const gfx::Rect& frame_rect = buffer.OriginalFrameRect();
  SECURITY_DCHECK(width == frame_rect.width());
  SECURITY_DCHECK(decoded_height <= frame_rect.height());
  const int left = frame_rect.x();
  const int top = frame_rect.y();

  // TODO (msarett):
  // Here we apply the color space transformation to the dst space.
  // It does not really make sense to transform to a gamma-encoded
  // space and then immediately after, perform a linear premultiply
  // and linear blending.  Can we find a way to perform the
  // premultiplication and blending in a linear space?
  ColorProfileTransform* xform = ColorTransform();
  if (xform) {
    skcms_PixelFormat kSrcFormat = skcms_PixelFormat_BGRA_8888;
    skcms_PixelFormat kDstFormat = skcms_PixelFormat_RGBA_8888;
    skcms_AlphaFormat alpha_format = skcms_AlphaFormat_Unpremul;
    for (int y = decoded_height_; y < decoded_height; ++y) {
      const int canvas_y = top + y;
      uint8_t* row = reinterpret_cast<uint8_t*>(buffer.GetAddr(left, canvas_y));
      bool color_conversion_successful = skcms_Transform(
          row, kSrcFormat, alpha_format, xform->SrcProfile(), row, kDstFormat,
          alpha_format, xform->DstProfile(), width);
      DCHECK(color_conversion_successful);
      uint8_t* pixel = row;
      for (int x = 0; x < width; ++x, pixel += 4) {
        const int canvas_x = left + x;
        buffer.SetRGBA(canvas_x, canvas_y, pixel[0], pixel[1], pixel[2],
                       pixel[3]);
      }
    }
  }

  // During the decoding of the current frame, we may have set some pixels to be
  // transparent (i.e. alpha < 255). If the alpha blend source was
  // 'BlendAtopPreviousFrame', the values of these pixels should be
  // determined by blending them against the pixels of the corresponding
  // previous frame. Compute the correct opaque values now.
  // FIXME: This could be avoided if libwebp decoder had an API that used the
  // previous required frame to do the alpha-blending by itself.
  if ((format_flags_ & ANIMATION_FLAG) && frame_index &&
      buffer.GetAlphaBlendSource() == ImageFrame::kBlendAtopPreviousFrame &&
      buffer.RequiredPreviousFrameIndex() != kNotFound) {
    ImageFrame& prev_buffer = frame_buffer_cache_[frame_index - 1];
    DCHECK_EQ(prev_buffer.GetStatus(), ImageFrame::kFrameComplete);
    ImageFrame::DisposalMethod prev_disposal_method =
        prev_buffer.GetDisposalMethod();
    if (prev_disposal_method == ImageFrame::kDisposeKeep) {
      // Blend transparent pixels with pixels in previous canvas.
      for (int y = decoded_height_; y < decoded_height; ++y) {
        blend_function_(buffer, prev_buffer, top + y, left, width);
      }
    } else if (prev_disposal_method == ImageFrame::kDisposeOverwriteBgcolor) {
      const gfx::Rect& prev_rect = prev_buffer.OriginalFrameRect();
      // We need to blend a transparent pixel with the starting value (from just
      // after the InitFrame() call). If the pixel belongs to prev_rect, the
      // starting value was fully transparent, so this is a no-op. Otherwise, we
      // need to blend against the pixel from the previous canvas.
      for (int y = decoded_height_; y < decoded_height; ++y) {
        int canvas_y = top + y;
        int left1, width1, left2, width2;
        findBlendRangeAtRow(frame_rect, prev_rect, canvas_y, left1, width1,
                            left2, width2);
        if (width1 > 0) {
          blend_function_(buffer, prev_buffer, canvas_y, left1, width1);
        }
        if (width2 > 0) {
          blend_function_(buffer, prev_buffer, canvas_y, left2, width2);
        }
      }
    }
  }

  decoded_height_ = decoded_height;
  buffer.SetPixelsChanged(true);
}

void WEBPImageDecoder::DecodeSize() {
  UpdateDemuxer();
}

wtf_size_t WEBPImageDecoder::DecodeFrameCount() {
  // If UpdateDemuxer() fails, return the existing number of frames. This way if
  // we get halfway through the image before decoding fails, we won't suddenly
  // start reporting that the image has zero frames.
  return UpdateDemuxer() ? WebPDemuxGetI(demux_, WEBP_FF_FRAME_COUNT)
                         : frame_buffer_cache_.size();
}

void WEBPImageDecoder::InitializeNewFrame(wtf_size_t index) {
  if (!(format_flags_ & ANIMATION_FLAG)) {
    DCHECK(!index);
    return;
  }
  WebPIterator animated_frame;
  if (!WebPDemuxGetFrame(demux_, index + 1, &animated_frame)) {
    SetFailed();
    return;
  }
  DCHECK_EQ(animated_frame.complete, 1);
  ImageFrame* buffer = &frame_buffer_cache_[index];
  gfx::Rect frame_rect(animated_frame.x_offset, animated_frame.y_offset,
                       animated_frame.width, animated_frame.height);
  buffer->SetOriginalFrameRect(IntersectRects(frame_rect, gfx::Rect(Size())));
  buffer->SetDuration(base::Milliseconds(animated_frame.duration));
  buffer->SetDisposalMethod(animated_frame.dispose_method ==
                                    WEBP_MUX_DISPOSE_BACKGROUND
                                ? ImageFrame::kDisposeOverwriteBgcolor
                                : ImageFrame::kDisposeKeep);
  buffer->SetAlphaBlendSource(animated_frame.blend_method == WEBP_MUX_BLEND
                                  ? ImageFrame::kBlendAtopPreviousFrame
                                  : ImageFrame::kBlendAtopBgcolor);
  buffer->SetRequiredPreviousFrameIndex(
      FindRequiredPreviousFrame(index, !animated_frame.has_alpha));
  WebPDemuxReleaseIterator(&animated_frame);
}

void WEBPImageDecoder::Decode(wtf_size_t index) {
  DCHECK(!IsDoingYuvDecode());

  if (Failed()) {
    return;
  }

  Vector<wtf_size_t> frames_to_decode = FindFramesToDecode(index);

  DCHECK(demux_);
  for (auto i = frames_to_decode.rbegin(); i != frames_to_decode.rend(); ++i) {
    if ((format_flags_ & ANIMATION_FLAG) && !InitFrameBuffer(*i)) {
      SetFailed();
      return;
    }

    WebPIterator webp_iter;
    if (!WebPDemuxGetFrame(demux_, *i + 1, &webp_iter)) {
      SetFailed();
    } else {
      std::unique_ptr<WebPIterator, void (*)(WebPIterator*)> webp_frame(
          &webp_iter, WebPDemuxReleaseIterator);
      DecodeSingleFrame(
          webp_frame->fragment.bytes,
          base::checked_cast<wtf_size_t>(webp_frame->fragment.size), *i);
    }

    if (Failed()) {
      return;
    }

    // If this returns false, we need more data to continue decoding.
    if (!PostDecodeProcessing(*i)) {
      break;
    }
  }

  // It is also a fatal error if all data is received and we have decoded all
  // frames available but the file is truncated.
  if (index >= frame_buffer_cache_.size() - 1 && IsAllDataReceived() &&
      demux_ && demux_state_ != WEBP_DEMUX_DONE) {
    SetFailed();
  }
}

bool WEBPImageDecoder::DecodeSingleFrameToYUV(const uint8_t* data_bytes,
                                              wtf_size_t data_size) {
  DCHECK(IsDoingYuvDecode());
  DCHECK(!Failed());

  bool size_available_after_init = IsSizeAvailable();
  DCHECK(size_available_after_init);

  // Set up decoder_buffer_ with output mode
  if (!decoder_) {
    if (!WebPInitDecBuffer(&decoder_buffer_)) {
      return SetFailed();
    }
    decoder_buffer_.colorspace = MODE_YUV;  // TODO(crbug.com/910276): Change
                                            // after alpha YUV support is added.
  }

  ImagePlanes* image_planes = image_planes_.get();
  DCHECK(image_planes);
  // Even if |decoder_| already exists, we must get most up-to-date pointers
  // because memory location might change e.g. upon tab resume.
  decoder_buffer_.u.YUVA.y =
      static_cast<uint8_t*>(image_planes->Plane(cc::YUVIndex::kY));
  decoder_buffer_.u.YUVA.u =
      static_cast<uint8_t*>(image_planes->Plane(cc::YUVIndex::kU));
  decoder_buffer_.u.YUVA.v =
      static_cast<uint8_t*>(image_planes->Plane(cc::YUVIndex::kV));

  if (!decoder_) {
    // libwebp only supports YUV 420 subsampling
    decoder_buffer_.u.YUVA.y_stride = image_planes->RowBytes(cc::YUVIndex::kY);
    decoder_buffer_.u.YUVA.y_size = decoder_buffer_.u.YUVA.y_stride *
                                    DecodedYUVSize(cc::YUVIndex::kY).height();
    decoder_buffer_.u.YUVA.u_stride = image_planes->RowBytes(cc::YUVIndex::kU);
    decoder_buffer_.u.YUVA.u_size = decoder_buffer_.u.YUVA.u_stride *
                                    DecodedYUVSize(cc::YUVIndex::kU).height();
    decoder_buffer_.u.YUVA.v_stride = image_planes->RowBytes(cc::YUVIndex::kV);
    decoder_buffer_.u.YUVA.v_size = decoder_buffer_.u.YUVA.v_stride *
                                    DecodedYUVSize(cc::YUVIndex::kV).height();

    decoder_buffer_.is_external_memory = 1;
    decoder_ = WebPINewDecoder(&decoder_buffer_);
    if (!decoder_) {
      return SetFailed();
    }
  }

  if (WebPIUpdate(decoder_, data_bytes, data_size) != VP8_STATUS_OK) {
    Clear();
    return SetFailed();
  }

  // TODO(crbug.com/911246): Do post-processing once skcms_Transform
  // supports multiplanar formats.
  ClearDecoder();
  image_planes->SetHasCompleteScan();
  if (IsAllDataReceived() && update_bpp_histogram_callback_) {
    std::move(update_bpp_histogram_callback_).Run(Size(), data_->size());
  }
  return true;
}

bool WEBPImageDecoder::DecodeSingleFrame(const uint8_t* data_bytes,
                                         wtf_size_t data_size,
                                         wtf_size_t frame_index) {
  DCHECK(!IsDoingYuvDecode());
  if (Failed()) {
    return false;
  }
  DCHECK(IsDecodedSizeAvailable());

  DCHECK_GT(frame_buffer_cache_.size(), frame_index);
  ImageFrame& buffer = frame_buffer_cache_[frame_index];
  DCHECK_NE(buffer.GetStatus(), ImageFrame::kFrameComplete);

  if (buffer.GetStatus() == ImageFrame::kFrameEmpty) {
    if (!buffer.AllocatePixelData(Size().width(), Size().height(),
                                  ColorSpaceForSkImages())) {
      return SetFailed();
    }
    buffer.ZeroFillPixelData();
    buffer.SetStatus(ImageFrame::kFramePartial);
    // The buffer is transparent outside the decoded area while the image
    // is loading. The correct alpha value for the frame will be set when
    // it is fully decoded.
    buffer.SetHasAlpha(true);
    buffer.SetOriginalFrameRect(gfx::Rect(Size()));
  }

  const gfx::Rect& frame_rect = buffer.OriginalFrameRect();
  if (!decoder_) {
    // Set up decoder_buffer_ with output mode
    if (!WebPInitDecBuffer(&decoder_buffer_)) {
      return SetFailed();
    }
    decoder_buffer_.colorspace = RGBOutputMode();
    decoder_buffer_.u.RGBA.stride =
        Size().width() * sizeof(ImageFrame::PixelData);
    decoder_buffer_.u.RGBA.size =
        decoder_buffer_.u.RGBA.stride * frame_rect.height();
    decoder_buffer_.is_external_memory = 1;
    decoder_ = WebPINewDecoder(&decoder_buffer_);
    if (!decoder_) {
      return SetFailed();
    }
  }
  decoder_buffer_.u.RGBA.rgba = reinterpret_cast<uint8_t*>(
      buffer.GetAddr(frame_rect.x(), frame_rect.y()));

  switch (WebPIUpdate(decoder_, data_bytes, data_size)) {
    case VP8_STATUS_OK:
      ApplyPostProcessing(frame_index);
      buffer.SetHasAlpha((format_flags_ & ALPHA_FLAG) ||
                         frame_background_has_alpha_);
      buffer.SetStatus(ImageFrame::kFrameComplete);
      ClearDecoder();
      if (IsAllDataReceived() && update_bpp_histogram_callback_) {
        std::move(update_bpp_histogram_callback_).Run(Size(), data_->size());
      }
      return true;
    case VP8_STATUS_SUSPENDED:
      if (!IsAllDataReceived() && !FrameIsReceivedAtIndex(frame_index)) {
        ApplyPostProcessing(frame_index);
        return false;
      }
      [[fallthrough]];
    default:
      Clear();
      return SetFailed();
  }
}

cc::ImageHeaderMetadata WEBPImageDecoder::MakeMetadataForDecodeAcceleration()
    const {
  cc::ImageHeaderMetadata image_metadata =
      ImageDecoder::MakeMetadataForDecodeAcceleration();

  DCHECK(consolidated_data_);
  image_metadata.webp_is_non_extended_lossy =
      IsSimpleLossyWebPImage(consolidated_data_);
  return image_metadata;
}

bool WEBPImageDecoder::FrameStatusSufficientForSuccessors(wtf_size_t index) {
  DCHECK(index < frame_buffer_cache_.size());
  return frame_buffer_cache_[index].GetStatus() == ImageFrame::kFrameComplete;
}

}  // namespace blink
```