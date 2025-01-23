Response:
My thought process to analyze the provided C++ code snippet for the `CrabbyAVIFImageDecoder` class goes like this:

1. **Identify the Core Functionality:** The filename and the `#include` directives immediately tell me this is an image decoder specifically for the AVIF format within the Chromium Blink rendering engine. The class name `CrabbyAVIFImageDecoder` confirms this.

2. **Break Down the Functionality by Code Sections:** I'll go through the code block by block, noting the key actions and data structures involved.

    * **Headers and Namespaces:**  This section imports necessary libraries (standard C++, Chromium/Blink specific, `crabbyavif`, `libyuv`, `skia`). The `blink` namespace indicates its integration within the browser's rendering pipeline.

    * **Internal Helpers and Constants:**  The anonymous namespace contains helper functions and constants. These are usually crucial for understanding the core logic. I see things like:
        * `kMaxAvifFileSize`: A limit on the decoded file size, likely for security.
        * `AvifDecoderErrorMessage`:  Handles error reporting from the underlying AVIF library.
        * `GetColorSpace`:  Crucial for handling color information in AVIF images. It maps AVIF color properties to Chromium's color space representation.
        * `UVSize`:  Deals with chroma subsampling, a key aspect of YUV formats.
        * `FractionToFloat`:  A utility for converting fractional values.
        * `GetAltImageColorSpace`:  Specific to gain maps in HDR AVIF images.

    * **Class Definition (`CrabbyAVIFImageDecoder`):**  This is the heart of the decoder. I'll look for key methods:
        * **Constructor/Destructor:** Sets up and cleans up the decoder.
        * **`FilenameExtension`, `MimeType`:**  Standard methods for identifying the image format.
        * **`ImageIsHighBitDepth`:** Determines if the image uses more than 8 bits per color component.
        * **`OnSetData`:**  Handles receiving image data. This is a critical point where the decoding process begins. It also calls `ParseMetadata`.
        * **`GetYUVSubsampling`, `DecodedYUVSize`, `DecodedYUVWidthBytes`, `GetYUVColorSpace`, `GetYUVBitDepth`:** Methods related to decoding directly to a YUV color space, often used for video processing or hardware overlays.
        * **`GetHDRMetadata`:**  Retrieves HDR-related metadata.
        * **`DecodeToYUV`:**  The actual method for decoding the image into YUV planes.
        * **`RepetitionCount`:**  Handles animation looping information.
        * **`FrameIsReceivedAtIndex`, `FrameTimestampAtIndex`, `FrameDurationAtIndex`:**  Methods for managing animation frames.
        * **`ImageHasBothStillAndAnimatedSubImages`:**  Checks for combined still and animated content.
        * **`MatchesAVIFSignature`:**  A static method to quickly check if a data stream is likely an AVIF image.
        * **`GetColorSpaceForTesting`:**  For internal testing purposes.
        * **`ParseMetadata`:**  A core function that uses the `crabbyavif` library to extract image information without fully decoding the pixels.
        * **`DecodeSize`, `DecodeFrameCount`:** Methods for getting basic image dimensions and the number of frames.
        * **`InitializeNewFrame`:** Sets up a new animation frame.
        * **`Decode`:**  The primary method for decoding an individual frame's pixel data.
        * **`CanReusePreviousFrameBuffer`:**  A hint for memory management, though the comment indicates it's always true for AVIF.
        * **`ReadFromSegmentReader`:**  A crucial static method that acts as an interface between the `crabbyavif` library and Chromium's data handling mechanisms. It fetches chunks of image data on demand.
        * **`UpdateDemuxer`:**  Manages the underlying `crabbyavif` decoder object, parsing the image header and extracting metadata.

3. **Identify Relationships with Web Technologies (JavaScript, HTML, CSS):**  Think about how image decoders fit into the web rendering pipeline.

    * **HTML `<img>` tag:**  The most direct connection. When the browser encounters an `<img>` tag with an AVIF `src`, this decoder will be used to fetch and decode the image data.
    * **CSS `background-image`:** Similar to the `<img>` tag, CSS can also load AVIF images.
    * **`<canvas>` element:**  JavaScript can use the Canvas API to draw images, including those decoded by this class. The `ImageData` object created from a decoded AVIF would be used here.
    * **JavaScript `Image()` constructor:**  JavaScript can programmatically load images using the `Image()` constructor. AVIF images would be handled by this decoder.

4. **Look for Logic and Assumptions:**  Pay attention to conditional statements, loops, and specific library calls.

    * **Error Handling:** The code uses `crabbyavif`'s error reporting and also sets the `Failed()` state of the `ImageDecoder`.
    * **Progressive Decoding:**  The code supports progressive decoding, where an image is displayed gradually as more data arrives.
    * **Animation Handling:**  The presence of `frame_buffer_cache_` and related methods indicates support for animated AVIFs.
    * **Color Space Conversion:**  The `GetColorSpace` functions highlight the importance of handling color information correctly.
    * **Memory Management:** The use of `scoped_refptr` and the `frame_buffer_cache_` suggests careful memory management.

5. **Consider User/Programming Errors:**  Think about how incorrect usage or malformed AVIF files could lead to issues.

    * **Invalid AVIF Files:**  The decoder needs to handle corrupted or malformed AVIF files gracefully, likely by failing the decoding process.
    * **Large Image Sizes:**  The `kMaxAvifFileSize` constant indicates a potential issue with extremely large images.
    * **Incorrect Color Profiles:**  Problems with embedded ICC profiles could lead to incorrect color rendering.
    * **Memory Exhaustion:**  Decoding very large or complex AVIF files could potentially consume a lot of memory.

6. **Synthesize a Summary:** Based on the above analysis, I'll create a concise summary of the class's functionalities. I'll focus on the main responsibilities: decoding AVIF images, handling metadata, supporting animations, and integrating with the browser's rendering pipeline.

By following these steps, I can systematically analyze the code and arrive at a comprehensive understanding of the `CrabbyAVIFImageDecoder`'s role and capabilities within the Chromium project. This detailed analysis helps in answering the user's specific questions about functionality, relationships to web technologies, logical assumptions, and potential errors.
这是 `blink/renderer/platform/image-decoders/avif/crabbyavif_image_decoder.cc` 文件的第一部分，该文件是 Chromium Blink 渲染引擎中用于解码 AVIF 图像的源代码。

**主要功能归纳:**

1. **AVIF 图像解码:**  这个类的核心功能是解码 AVIF (AV1 Image File Format) 图像数据。它使用了第三方库 `crabbyavif` 来实现 AVIF 的解码。

2. **元数据解析:**  它能够解析 AVIF 文件的元数据，例如图像的尺寸、颜色空间、帧数（对于动画图像）、重复次数等。

3. **YUV 解码支持:**  该解码器支持将 AVIF 图像解码为 YUV 颜色空间，这对于视频处理或者 GPU 渲染优化非常有用。它可以提供 YUV 平面的尺寸、步幅和颜色空间信息。

4. **HDR 元数据提取:**  对于高动态范围 (HDR) 的 AVIF 图像，它可以提取 HDR 元数据。

5. **动画支持:**  它能够处理动画 AVIF 图像，并提供关于动画帧数、帧持续时间、时间戳和重复次数的信息。

6. **渐进式解码:**  支持渐进式解码，允许在所有数据接收完毕之前逐步显示图像。

7. **颜色空间管理:**  负责处理 AVIF 图像的颜色空间信息，并将其转换为 Chromium 可以理解的 `gfx::ColorSpace` 或 `SkColorSpace` 对象。这包括处理 ICC 配置文件和 CICP (Color Information Chunk Payload) 数据。

8. **错误处理:**  具备一定的错误处理能力，能够捕获和报告解码过程中出现的错误。

9. **数据读取:**  使用 `SegmentReader` 来读取图像数据，并将其提供给 `crabbyavif` 库进行解码。

10. **内存管理:**  使用智能指针 (`std::unique_ptr`, `scoped_refptr`) 来管理内存。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML `<img>` 标签:** 当 HTML 中使用 `<img>` 标签加载一个 AVIF 格式的图片时，Blink 引擎会调用 `CrabbyAVIFImageDecoder` 来解码该图片并显示在页面上。
    ```html
    <img src="image.avif" alt="An AVIF image">
    ```

* **CSS `background-image` 属性:**  CSS 可以使用 `background-image` 属性来设置 AVIF 图片作为元素的背景。Blink 引擎同样会使用这个解码器来处理。
    ```css
    .container {
      background-image: url("background.avif");
    }
    ```

* **JavaScript Canvas API:** JavaScript 可以使用 Canvas API 来绘制图像，包括 AVIF 图像。当使用 JavaScript 加载 AVIF 图片并通过 Canvas 渲染时，`CrabbyAVIFImageDecoder` 负责解码图像数据，然后 Canvas 可以使用解码后的像素数据进行绘制。
    ```javascript
    const image = new Image();
    image.onload = function() {
      const canvas = document.getElementById('myCanvas');
      const ctx = canvas.getContext('2d');
      ctx.drawImage(image, 0, 0);
    };
    image.src = 'image.avif';
    ```

**逻辑推理 (假设输入与输出):**

**假设输入:**

* 一个包含完整 AVIF 图像数据的 `SegmentReader` 对象。
* 调用 `OnSetData` 方法将数据传递给解码器。

**输出:**

* 调用 `ParseMetadata` 后，解码器内部的 `decoder_` 对象会被初始化，并且会解析出图像的基本信息，例如尺寸 (`container_width_`, `container_height_`)，位深度 (`bit_depth_`)，是否是渐进式 (`progressive_`)，以及帧数 (`decoded_frame_count_`)。
* 如果是动画图像，`frame_buffer_cache_` 会被填充，其中包含每个帧的元数据信息，如时间戳和持续时间。

**用户或编程常见的使用错误及举例说明:**

1. **提供不完整的 AVIF 数据:** 如果在 `IsAllDataReceived()` 返回 `false` 的情况下尝试解码，解码过程可能会失败或只能解码部分数据。
    ```c++
    // 假设 reader 只包含了部分 AVIF 数据
    auto reader = base::MakeRefCounted<FakeSegmentReader>(incomplete_avif_data);
    decoder->SetData(reader);
    decoder->DecodeSize(); // 可能会失败或者得到不完整的尺寸信息
    ```

2. **在高位深度解码选项下使用了不支持的颜色行为:** 例如，尝试在高位深度解码时强制使用 8 位颜色格式可能会导致错误或数据丢失。
    ```c++
    auto decoder = new CrabbyAVIFImageDecoder(
        ImageDecoder::AlphaOption::kDefault,
        ImageDecoder::HighBitDepthDecodingOption::kAs8Bit, // 假设 AVIF 是 10 位
        ImageDecoder::ColorBehavior::kPreferInt8, // 与高位深度解码选项冲突
        cc::AuxImage::kNone, 1024 * 1024);
    ```

3. **假设所有 AVIF 文件都包含动画:**  如果代码假设所有加载的 AVIF 文件都是动画，并尝试访问 `frame_buffer_cache_`，但在加载静态 AVIF 文件时可能会导致访问越界或空指针错误。
    ```c++
    // 假设加载的是静态 AVIF 图片，decoded_frame_count_ 为 1
    if (decoder->DecodeFrameCount() > 1) {
      auto frame_duration = decoder->FrameDurationAtIndex(1); // 对于静态图片，index 1 可能越界
    }
    ```

**总结:**

`CrabbyAVIFImageDecoder` 类的主要功能是为 Chromium 渲染引擎提供 AVIF 图像的解码能力，包括静态图像和动画图像，并处理相关的元数据和颜色空间信息。它在浏览器中扮演着关键角色，使得用户可以在网页上查看 AVIF 格式的图片。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/avif/crabbyavif_image_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
// WARNING: Auto-generated by gen_crabbyavif_wrapper.py.
// Do not modify manually.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/avif/crabbyavif_image_decoder.h"

#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <array>
#include <memory>
#include <optional>
#include <utility>

#include "base/bits.h"
#include "base/containers/adapters.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/logging.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_functions.h"
#include "base/numerics/safe_conversions.h"
#include "base/timer/elapsed_timer.h"
#include "build/build_config.h"
#include "cc/base/math_util.h"
#include "media/base/video_color_space.h"
#include "skia/ext/cicp.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/image-decoders/fast_shared_buffer_reader.h"
#include "third_party/blink/renderer/platform/image-decoders/image_animation.h"
#include "third_party/blink/renderer/platform/image-decoders/image_decoder.h"
#include "third_party/blink/renderer/platform/image-decoders/rw_buffer.h"
#include "third_party/crabbyavif/src/include/avif/avif.h"
#include "third_party/libyuv/include/libyuv.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/core/SkTypes.h"
#include "third_party/skia/include/private/SkXmp.h"
#include "ui/gfx/color_space.h"
#include "ui/gfx/icc_profile.h"

#if defined(ARCH_CPU_BIG_ENDIAN)
#error Blink assumes a little-endian target.
#endif

namespace blink {

namespace {

// The maximum AVIF file size we are willing to decode. This helps libavif
// detect invalid sizes and offsets in an AVIF file before the file size is
// known.
constexpr uint64_t kMaxAvifFileSize = 0x10000000;  // 256 MB

const char* AvifDecoderErrorMessage(const crabbyavif::avifDecoder* decoder) {
  // decoder->diag.error is a char array that stores a null-terminated C string.
  return *decoder->diag.error != '\0' ? decoder->diag.error
                                      : "(no error message)";
}

// Builds a gfx::ColorSpace from the ITU-T H.273 (CICP) color description.
gfx::ColorSpace GetColorSpace(
    crabbyavif::avifColorPrimaries color_primaries,
    crabbyavif::avifTransferCharacteristics transfer_characteristics,
    crabbyavif::avifMatrixCoefficients matrix_coefficients,
    crabbyavif::avifRange yuv_range,
    bool grayscale) {
  // (As of ISO/IEC 23000-22:2019 Amendment 2) MIAF Section 7.3.6.4 says:
  //   If a coded image has no associated colour property, the default property
  //   is defined as having colour_type equal to 'nclx' with properties as
  //   follows:
  //   – colour_primaries equal to 1,
  //   - transfer_characteristics equal to 13,
  //   - matrix_coefficients equal to 5 or 6 (which are functionally identical),
  //     and
  //   - full_range_flag equal to 1.
  //   ...
  // These values correspond to crabbyavif::AVIF_COLOR_PRIMARIES_BT709,
  // crabbyavif::AVIF_TRANSFER_CHARACTERISTICS_SRGB, and
  // crabbyavif::AVIF_MATRIX_COEFFICIENTS_BT601, respectively.
  //
  // Note that this only specifies the default color property when the color
  // property is absent. It does not really specify the default values for
  // colour_primaries, transfer_characteristics, and matrix_coefficients when
  // they are equal to 2 (unspecified). But we will interpret it as specifying
  // the default values for these variables because we must choose some defaults
  // and these are the most reasonable defaults to choose. We also advocate that
  // all AVIF decoders choose these defaults:
  // https://github.com/AOMediaCodec/av1-avif/issues/84
  const auto primaries =
      color_primaries == crabbyavif::AVIF_COLOR_PRIMARIES_UNSPECIFIED
          ? crabbyavif::AVIF_COLOR_PRIMARIES_BT709
          : color_primaries;
  const auto transfer =
      transfer_characteristics ==
              crabbyavif::AVIF_TRANSFER_CHARACTERISTICS_UNSPECIFIED
          ? crabbyavif::AVIF_TRANSFER_CHARACTERISTICS_SRGB
          : transfer_characteristics;
  const auto matrix =
      (grayscale ||
       matrix_coefficients == crabbyavif::AVIF_MATRIX_COEFFICIENTS_UNSPECIFIED)
          ? crabbyavif::AVIF_MATRIX_COEFFICIENTS_BT601
          : matrix_coefficients;
  const auto range = yuv_range == crabbyavif::AVIF_RANGE_FULL
                         ? gfx::ColorSpace::RangeID::FULL
                         : gfx::ColorSpace::RangeID::LIMITED;
  media::VideoColorSpace color_space(primaries, transfer, matrix, range);
  if (color_space.IsSpecified()) {
    return color_space.ToGfxColorSpace();
  }
  // media::VideoColorSpace and gfx::ColorSpace do not support CICP
  // MatrixCoefficients 12, 13, 14.
  DCHECK_GE(matrix, 12);
  DCHECK_LE(matrix, 14);
  if (yuv_range == crabbyavif::AVIF_RANGE_FULL) {
    return gfx::ColorSpace::CreateJpeg();
  }
  return gfx::ColorSpace::CreateREC709();
}

// Builds a gfx::ColorSpace from the ITU-T H.273 (CICP) color description in the
// image.
gfx::ColorSpace GetColorSpace(const crabbyavif::avifImage* image) {
  const bool grayscale =
      image->yuvFormat == crabbyavif::AVIF_PIXEL_FORMAT_YUV400;
  return GetColorSpace(image->colorPrimaries, image->transferCharacteristics,
                       image->matrixCoefficients, image->yuvRange, grayscale);
}

// |y_size| is the width or height of the Y plane. Returns the width or height
// of the U and V planes. |chroma_shift| represents the subsampling of the
// chroma (U and V) planes in the x (for width) or y (for height) direction.
int UVSize(int y_size, int chroma_shift) {
  DCHECK(chroma_shift == 0 || chroma_shift == 1);
  return (y_size + chroma_shift) >> chroma_shift;
}

float FractionToFloat(auto numerator, uint32_t denominator) {
  // First cast to double and not float because uint32_t->float conversion can
  // cause precision loss.
  return static_cast<double>(numerator) / denominator;
}

// If the image has a gain map, returns the alternate image's color space, if
// it's different from the base image's and can be converted to a SkColorSpace.
// If the alternate image color space is the same as the base image, there is no
// need to specify it in SkGainmapInfo, and using the base image's color space
// may be more accurate if the profile cannot be exactly represented as a
// SkColorSpace object.
sk_sp<SkColorSpace> GetAltImageColorSpace(const crabbyavif::avifImage& image) {
  const crabbyavif::avifGainMap* gain_map = image.gainMap;
  if (!gain_map) {
    return nullptr;
  }
  sk_sp<SkColorSpace> color_space;
  if (gain_map->altICC.size) {
    if (image.icc.size == gain_map->altICC.size &&
        memcmp(gain_map->altICC.data, image.icc.data, gain_map->altICC.size) ==
            0) {
      // Same ICC as the base image, no need to specify it.
      return nullptr;
    }
    std::unique_ptr<ColorProfile> profile = ColorProfile::Create(
        base::span(gain_map->altICC.data, gain_map->altICC.size));
    if (!profile) {
      DVLOG(1) << "Failed to parse gain map ICC profile";
      return nullptr;
    }
    const skcms_ICCProfile* icc_profile = profile->GetProfile();
    if (icc_profile->has_CICP) {
      color_space =
          skia::CICPGetSkColorSpace(icc_profile->CICP.color_primaries,
                                    icc_profile->CICP.transfer_characteristics,
                                    icc_profile->CICP.matrix_coefficients,
                                    icc_profile->CICP.video_full_range_flag,
                                    /*prefer_srgb_trfn=*/true);
    } else if (icc_profile->has_toXYZD50) {
      // The transfer function is irrelevant for gain map tone mapping,
      // set it to something standard in case it's not set or not
      // supported.
      skcms_ICCProfile with_srgb = *icc_profile;
      skcms_SetTransferFunction(&with_srgb, skcms_sRGB_TransferFunction());
      color_space = SkColorSpace::Make(with_srgb);
    }
  } else if (gain_map->altColorPrimaries !=
             crabbyavif::AVIF_COLOR_PRIMARIES_UNSPECIFIED) {
    if (image.icc.size == 0 &&
        image.colorPrimaries == gain_map->altColorPrimaries) {
      // Same as base image, no need to specify it.
      return nullptr;
    }
    const bool grayscale = (gain_map->altPlaneCount == 1);
    const gfx::ColorSpace alt_color_space = GetColorSpace(
        gain_map->altColorPrimaries, gain_map->altTransferCharacteristics,
        gain_map->altMatrixCoefficients, gain_map->altYUVRange, grayscale);
    color_space = alt_color_space.GetAsFullRangeRGB().ToSkColorSpace();
  }

  if (!color_space) {
    DVLOG(1) << "Gain map image contains an unsupported color space";
  }

  return color_space;
}

}  // namespace

CrabbyAVIFImageDecoder::CrabbyAVIFImageDecoder(
    AlphaOption alpha_option,
    HighBitDepthDecodingOption hbd_option,
    ColorBehavior color_behavior,
    cc::AuxImage aux_image,
    wtf_size_t max_decoded_bytes,
    AnimationOption animation_option)
    : ImageDecoder(alpha_option,
                   hbd_option,
                   color_behavior,
                   aux_image,
                   max_decoded_bytes),
      animation_option_(animation_option) {}

CrabbyAVIFImageDecoder::~CrabbyAVIFImageDecoder() = default;

String CrabbyAVIFImageDecoder::FilenameExtension() const {
  return "avif";
}

const AtomicString& CrabbyAVIFImageDecoder::MimeType() const {
  DEFINE_STATIC_LOCAL(const AtomicString, avif_mime_type, ("image/avif"));
  return avif_mime_type;
}

bool CrabbyAVIFImageDecoder::ImageIsHighBitDepth() {
  return bit_depth_ > 8;
}

void CrabbyAVIFImageDecoder::OnSetData(scoped_refptr<SegmentReader> data) {
  have_parsed_current_data_ = false;
  const bool all_data_received = IsAllDataReceived();
  avif_io_data_.reader = data_;
  avif_io_data_.all_data_received = all_data_received;
  avif_io_.sizeHint = all_data_received ? data_->size() : kMaxAvifFileSize;

  // ImageFrameGenerator::GetYUVAInfo() and ImageFrameGenerator::DecodeToYUV()
  // assume that allow_decode_to_yuv_ and other image metadata are available
  // after calling ImageDecoder::Create() with data_complete=true.
  if (all_data_received) {
    ParseMetadata();
  }
}

cc::YUVSubsampling CrabbyAVIFImageDecoder::GetYUVSubsampling() const {
  switch (avif_yuv_format_) {
    case crabbyavif::AVIF_PIXEL_FORMAT_YUV420:
      return cc::YUVSubsampling::k420;
    case crabbyavif::AVIF_PIXEL_FORMAT_YUV422:
      return cc::YUVSubsampling::k422;
    case crabbyavif::AVIF_PIXEL_FORMAT_YUV444:
      return cc::YUVSubsampling::k444;
    case crabbyavif::AVIF_PIXEL_FORMAT_YUV400:
      return cc::YUVSubsampling::kUnknown;
    case crabbyavif::AVIF_PIXEL_FORMAT_NONE:
      // avif_yuv_format_ is initialized to crabbyavif::AVIF_PIXEL_FORMAT_NONE
      // in the constructor. If we have called SetSize() successfully at the end
      // of UpdateDemuxer(), avif_yuv_format_ cannot possibly be
      // crabbyavif::AVIF_PIXEL_FORMAT_NONE.
      CHECK(!IsDecodedSizeAvailable());
      return cc::YUVSubsampling::kUnknown;
    default:
      break;
  }
  NOTREACHED() << "Invalid YUV format: " << avif_yuv_format_;
}

gfx::Size CrabbyAVIFImageDecoder::DecodedYUVSize(cc::YUVIndex index) const {
  DCHECK(IsDecodedSizeAvailable());
  if (index == cc::YUVIndex::kU || index == cc::YUVIndex::kV) {
    return gfx::Size(UVSize(Size().width(), chroma_shift_x_),
                     UVSize(Size().height(), chroma_shift_y_));
  }
  return Size();
}

wtf_size_t CrabbyAVIFImageDecoder::DecodedYUVWidthBytes(
    cc::YUVIndex index) const {
  DCHECK(IsDecodedSizeAvailable());
  // Try to return the same width bytes as used by the dav1d library. This will
  // allow DecodeToYUV() to copy each plane with a single memcpy() call.
  //
  // The comments for Dav1dPicAllocator in dav1d/picture.h require the pixel
  // width be padded to a multiple of 128 pixels.
  wtf_size_t aligned_width = static_cast<wtf_size_t>(
      base::bits::AlignUpDeprecatedDoNotUse(Size().width(), 128));
  if (index == cc::YUVIndex::kU || index == cc::YUVIndex::kV) {
    aligned_width >>= chroma_shift_x_;
  }
  // When the stride is a multiple of 1024, dav1d_default_picture_alloc()
  // slightly pads the stride to avoid a reduction in cache hit rate in most
  // L1/L2 cache implementations. Match that trick here. (Note that this padding
  // is not documented in dav1d/picture.h.)
  if ((aligned_width & 1023) == 0) {
    aligned_width += 64;
  }

  // High bit depth YUV is stored as a uint16_t, double the number of bytes.
  if (bit_depth_ > 8) {
    DCHECK_LE(bit_depth_, 16);
    aligned_width *= 2;
  }

  return aligned_width;
}

SkYUVColorSpace CrabbyAVIFImageDecoder::GetYUVColorSpace() const {
  DCHECK(CanDecodeToYUV());
  DCHECK_NE(yuv_color_space_, SkYUVColorSpace::kIdentity_SkYUVColorSpace);
  return yuv_color_space_;
}

uint8_t CrabbyAVIFImageDecoder::GetYUVBitDepth() const {
  DCHECK(CanDecodeToYUV());
  return bit_depth_;
}

std::optional<gfx::HDRMetadata> CrabbyAVIFImageDecoder::GetHDRMetadata() const {
  return hdr_metadata_;
}

void CrabbyAVIFImageDecoder::DecodeToYUV() {
  DCHECK(image_planes_);
  DCHECK(CanDecodeToYUV());

  if (Failed()) {
    return;
  }

  DCHECK(decoder_);
  DCHECK_EQ(decoded_frame_count_, 1u);  // Not animation.

  // If the image is decoded progressively, just render the highest progressive
  // frame in image_planes_ because the callers of DecodeToYUV() assume that a
  // complete scan will not be updated.
  const int frame_index = progressive_ ? (decoder_->imageCount - 1) : 0;
  // TODO(crbug.com/943519): Implement YUV incremental decoding as in Decode().
  decoder_->allowIncremental = crabbyavif::CRABBY_AVIF_FALSE;

  // libavif cannot decode to an external buffer. So we need to copy from
  // libavif's internal buffer to |image_planes_|.
  // TODO(crbug.com/1099825): Enhance libavif to decode to an external buffer.
  auto ret = DecodeImage(frame_index);
  if (ret != crabbyavif::AVIF_RESULT_OK) {
    if (ret != crabbyavif::AVIF_RESULT_WAITING_ON_IO) {
      SetFailed();
    }
    return;
  }
  const crabbyavif::avifImage* image = decoded_image_;

  DCHECK(!image->alphaPlane);
  static_assert(
      cc::YUVIndex::kY == static_cast<cc::YUVIndex>(crabbyavif::AVIF_CHAN_Y),
      "");
  static_assert(
      cc::YUVIndex::kU == static_cast<cc::YUVIndex>(crabbyavif::AVIF_CHAN_U),
      "");
  static_assert(
      cc::YUVIndex::kV == static_cast<cc::YUVIndex>(crabbyavif::AVIF_CHAN_V),
      "");

  // Disable subnormal floats which can occur when converting to half float.
  std::unique_ptr<cc::ScopedSubnormalFloatDisabler> disable_subnormals;
  const bool is_f16 = image_planes_->color_type() == kA16_float_SkColorType;
  if (is_f16) {
    disable_subnormals = std::make_unique<cc::ScopedSubnormalFloatDisabler>();
  }
  const float kHighBitDepthMultiplier =
      (is_f16 ? 1.0f : 65535.0f) / ((1 << bit_depth_) - 1);

  // Initialize |width| and |height| to the width and height of the luma plane.
  uint32_t width = image->width;
  uint32_t height = image->height;

  for (wtf_size_t plane_index = 0; plane_index < cc::kNumYUVPlanes;
       ++plane_index) {
    const cc::YUVIndex plane = static_cast<cc::YUVIndex>(plane_index);
    const wtf_size_t src_row_bytes =
        base::strict_cast<wtf_size_t>(image->yuvRowBytes[plane_index]);
    const wtf_size_t dst_row_bytes = image_planes_->RowBytes(plane);

    if (bit_depth_ == 8) {
      DCHECK_EQ(image_planes_->color_type(), kGray_8_SkColorType);
      const uint8_t* src = image->yuvPlanes[plane_index];
      uint8_t* dst = static_cast<uint8_t*>(image_planes_->Plane(plane));
      libyuv::CopyPlane(src, src_row_bytes, dst, dst_row_bytes, width, height);
    } else {
      DCHECK_GT(bit_depth_, 8u);
      DCHECK_LE(bit_depth_, 16u);
      const uint16_t* src =
          reinterpret_cast<uint16_t*>(image->yuvPlanes[plane_index]);
      uint16_t* dst = static_cast<uint16_t*>(image_planes_->Plane(plane));
      if (image_planes_->color_type() == kA16_unorm_SkColorType) {
        const wtf_size_t src_stride = src_row_bytes / 2;
        const wtf_size_t dst_stride = dst_row_bytes / 2;
        for (uint32_t j = 0; j < height; ++j) {
          for (uint32_t i = 0; i < width; ++i) {
            dst[j * dst_stride + i] =
                src[j * src_stride + i] * kHighBitDepthMultiplier + 0.5f;
          }
        }
      } else if (image_planes_->color_type() == kA16_float_SkColorType) {
        // Note: Unlike CopyPlane_16, HalfFloatPlane wants the stride in bytes.
        libyuv::HalfFloatPlane(src, src_row_bytes, dst, dst_row_bytes,
                               kHighBitDepthMultiplier, width, height);
      } else {
        NOTREACHED() << "Unsupported color type: "
                     << static_cast<int>(image_planes_->color_type());
      }
    }
    if (plane == cc::YUVIndex::kY) {
      // Having processed the luma plane, change |width| and |height| to the
      // width and height of the chroma planes.
      width = UVSize(width, chroma_shift_x_);
      height = UVSize(height, chroma_shift_y_);
    }
  }
  image_planes_->SetHasCompleteScan();
}

int CrabbyAVIFImageDecoder::RepetitionCount() const {
  if (decoded_frame_count_ > 1) {
    switch (decoder_->repetitionCount) {
      case crabbyavif::CRABBY_AVIF_REPETITION_COUNT_INFINITE:
        return kAnimationLoopInfinite;
      case crabbyavif::CRABBY_AVIF_REPETITION_COUNT_UNKNOWN:
        // The AVIF file does not have repetitions specified using an EditList
        // box. Loop infinitely for backward compatibility with older versions
        // of Chrome.
        return kAnimationLoopInfinite;
      default:
        return decoder_->repetitionCount;
    }
  }
  return kAnimationNone;
}

bool CrabbyAVIFImageDecoder::FrameIsReceivedAtIndex(wtf_size_t index) const {
  if (!IsDecodedSizeAvailable()) {
    return false;
  }
  if (decoded_frame_count_ == 1) {
    return ImageDecoder::FrameIsReceivedAtIndex(index);
  }
  if (index >= frame_buffer_cache_.size()) {
    return false;
  }
  if (IsAllDataReceived()) {
    return true;
  }
  crabbyavif::avifExtent data_extent;
  if (crabbyavif::crabby_avifDecoderNthImageMaxExtent(
          decoder_.get(), index, &data_extent) != crabbyavif::AVIF_RESULT_OK) {
    return false;
  }
  return data_extent.size == 0 ||
         data_extent.offset + data_extent.size <= data_->size();
}

std::optional<base::TimeDelta> CrabbyAVIFImageDecoder::FrameTimestampAtIndex(
    wtf_size_t index) const {
  return index < frame_buffer_cache_.size()
             ? frame_buffer_cache_[index].Timestamp()
             : std::nullopt;
}

base::TimeDelta CrabbyAVIFImageDecoder::FrameDurationAtIndex(
    wtf_size_t index) const {
  return index < frame_buffer_cache_.size()
             ? frame_buffer_cache_[index].Duration()
             : base::TimeDelta();
}

bool CrabbyAVIFImageDecoder::ImageHasBothStillAndAnimatedSubImages() const {
  // Per MIAF, all animated AVIF files must have a still image, even if it's
  // just a pointer to the first frame of the animation.
  return decoder_ && decoder_->imageSequenceTrackPresent;
}

// static
bool CrabbyAVIFImageDecoder::MatchesAVIFSignature(
    const FastSharedBufferReader& fast_reader) {
  // crabbyavif::crabby_avifPeekCompatibleFileType() clamps compatible brands at
  // 32 when reading in the ftyp box in ISO BMFF for the 'avif' or 'avis' brand.
  // So the maximum number of bytes read is 144 bytes (size 4 bytes, type 4
  // bytes, major brand 4 bytes, minor version 4 bytes, and 4 bytes * 32
  // compatible brands).
  char buffer[144];
  crabbyavif::avifROData input;
  input.size = std::min(sizeof(buffer), fast_reader.size());
  input.data = reinterpret_cast<const uint8_t*>(
      fast_reader.GetConsecutiveData(0, input.size, buffer));
  return crabbyavif::crabby_avifPeekCompatibleFileType(&input);
}

gfx::ColorSpace CrabbyAVIFImageDecoder::GetColorSpaceForTesting() const {
  return GetColorSpace(GetDecoderImage());
}

void CrabbyAVIFImageDecoder::ParseMetadata() {
  if (!UpdateDemuxer()) {
    SetFailed();
  }
}

void CrabbyAVIFImageDecoder::DecodeSize() {
  ParseMetadata();
}

wtf_size_t CrabbyAVIFImageDecoder::DecodeFrameCount() {
  if (!Failed()) {
    ParseMetadata();
  }
  return IsDecodedSizeAvailable() ? decoded_frame_count_
                                  : frame_buffer_cache_.size();
}

void CrabbyAVIFImageDecoder::InitializeNewFrame(wtf_size_t index) {
  auto& buffer = frame_buffer_cache_[index];
  if (decode_to_half_float_) {
    buffer.SetPixelFormat(ImageFrame::PixelFormat::kRGBA_F16);
  }

  // For AVIFs, the frame always fills the entire image.
  buffer.SetOriginalFrameRect(gfx::Rect(Size()));

  crabbyavif::avifImageTiming timing;
  auto ret = crabbyavif::crabby_avifDecoderNthImageTiming(decoder_.get(), index,
                                                          &timing);
  DCHECK_EQ(ret, crabbyavif::AVIF_RESULT_OK);
  buffer.SetTimestamp(base::Seconds(timing.pts));
  buffer.SetDuration(base::Seconds(timing.duration));
}

void CrabbyAVIFImageDecoder::Decode(wtf_size_t index) {
  if (Failed()) {
    return;
  }

  UpdateAggressivePurging(index);

  int frame_index = index;
  // If the image is decoded progressively, find the highest progressive
  // frame that we have received and decode from that frame index. Internally
  // decoder_ still decodes the lower progressive frames, but they are only used
  // as reference frames and not rendered.
  if (progressive_) {
    DCHECK_EQ(index, 0u);
    // decoder_->imageIndex is the current image index. decoder_->imageIndex is
    // initialized to -1. decoder_->imageIndex + 1 is the next image index.
    DCHECK_LT(decoder_->imageIndex + 1, decoder_->imageCount);
    for (frame_index = decoder_->imageIndex + 1;
         frame_index + 1 < decoder_->imageCount; ++frame_index) {
      crabbyavif::avifExtent data_extent;
      auto rv = crabbyavif::crabby_avifDecoderNthImageMaxExtent(
          decoder_.get(), frame_index + 1, &data_extent);
      if (rv != crabbyavif::AVIF_RESULT_OK) {
        DVLOG(1) << "crabbyavif::crabby_avifDecoderNthImageMaxExtent("
                 << frame_index + 1
                 << ") failed: " << crabbyavif::crabby_avifResultToString(rv)
                 << ": " << AvifDecoderErrorMessage(decoder_.get());
        SetFailed();
        return;
      }
      if (data_extent.size != 0 &&
          data_extent.offset + data_extent.size > data_->size()) {
        break;
      }
    }
  }

  // Allow AVIF frames to be partially decoded before all data is received.
  // Only enabled for non-progressive still images because animations look
  // better without incremental decoding and because progressive decoding makes
  // incremental decoding unnecessary.
  decoder_->allowIncremental = (decoder_->imageCount == 1);

  auto ret = DecodeImage(frame_index);
  if (ret != crabbyavif::AVIF_RESULT_OK &&
      ret != crabbyavif::AVIF_RESULT_WAITING_ON_IO) {
    SetFailed();
    return;
  }
  const crabbyavif::avifImage* image = decoded_image_;

  // ImageDecoder::SizeCalculationMayOverflow(), called by UpdateDemuxer()
  // before being here, made sure the image height fits in an int.
  int displayable_height = static_cast<int>(
      crabbyavif::crabby_avifDecoderDecodedRowCount(decoder_.get()));
  if (image == cropped_image_.get()) {
    displayable_height -= clap_origin_.y();
    displayable_height =
        std::clamp(displayable_height, 0, static_cast<int>(image->height));
  }

  if (displayable_height == 0) {
    return;  // There is nothing to display.
  }

  ImageFrame& buffer = frame_buffer_cache_[index];
  DCHECK_NE(buffer.GetStatus(), ImageFrame::kFrameComplete);

  if (buffer.GetStatus() == ImageFrame::kFrameEmpty) {
    if (!InitFrameBuffer(index)) {
      DVLOG(1) << "Failed to create frame buffer...";
      SetFailed();
      return;
    }
    DCHECK_EQ(buffer.GetStatus(), ImageFrame::kFramePartial);
    // The buffer is transparent outside the decoded area while the image is
    // loading. The correct alpha value for the frame will be set when it is
    // fully decoded.
    buffer.SetHasAlpha(true);
    if (decoder_->allowIncremental) {
      // In case of buffer disposal after decoding.
      incrementally_displayed_height_ = 0;
    }
  }

  const int last_displayed_height =
      decoder_->allowIncremental ? incrementally_displayed_height_ : 0;
  if (displayable_height == last_displayed_height) {
    return;  // There is no new row to display.
  }
  DCHECK_GT(displayable_height, last_displayed_height);

  // Only render the newly decoded rows.
  if (!RenderImage(image, last_displayed_height, &displayable_height,
                   &buffer)) {
    SetFailed();
    return;
  }
  if (displayable_height == last_displayed_height) {
    return;  // There is no new row to display.
  }
  DCHECK_GT(displayable_height, last_displayed_height);
  ColorCorrectImage(last_displayed_height, displayable_height, &buffer);
  buffer.SetPixelsChanged(true);
  if (decoder_->allowIncremental) {
    incrementally_displayed_height_ = displayable_height;
  }

  if (static_cast<uint32_t>(displayable_height) == image->height &&
      (!progressive_ || frame_index + 1 == decoder_->imageCount)) {
    buffer.SetHasAlpha(!!image->alphaPlane);
    buffer.SetStatus(ImageFrame::kFrameComplete);
    PostDecodeProcessing(index);
  }
}

bool CrabbyAVIFImageDecoder::CanReusePreviousFrameBuffer(
    wtf_size_t index) const {
  // (a) Technically we can reuse the bitmap of the previous frame because the
  // AVIF decoder handles frame dependence internally and we never need to
  // preserve previous frames to decode later ones, and (b) since this function
  // will not currently be called, this is really more for the reader than any
  // functional purpose.
  return true;
}

// static
crabbyavif::avifResult CrabbyAVIFImageDecoder::ReadFromSegmentReader(
    crabbyavif::avifIO* io,
    uint32_t read_flags,
    uint64_t offset,
    size_t size,
    crabbyavif::avifROData* out) {
  if (read_flags != 0) {
    // Unsupported read_flags
    return crabbyavif::AVIF_RESULT_IO_ERROR;
  }

  AvifIOData* io_data = static_cast<AvifIOData*>(io->data);

  // Sanitize/clamp incoming request
  if (offset > io_data->reader->size()) {
    // The offset is past the end of the buffer or available data.
    return io_data->all_data_received ? crabbyavif::AVIF_RESULT_IO_ERROR
                                      : crabbyavif::AVIF_RESULT_WAITING_ON_IO;
  }

  // It is more convenient to work with a variable of the size_t type. Since
  // offset <= io_data->reader->size() <= SIZE_MAX, this cast is safe.
  size_t position = static_cast<size_t>(offset);
  const size_t available_size = io_data->reader->size() - position;
  if (size > available_size) {
    if (!io_data->all_data_received) {
      return crabbyavif::AVIF_RESULT_WAITING_ON_IO;
    }
    size = available_size;
  }

  out->size = size;

  base::span<const uint8_t> data = io_data->reader->GetSomeData(position);
  if (data.size() >= size) {
    out->data = data.data();
    return crabbyavif::AVIF_RESULT_OK;
  }

  io_data->buffer.clear();
  io_data->buffer.reserve(size);

  while (size != 0) {
    data = io_data->reader->GetSomeData(position);
    size_t copy_size = std::min(data.size(), size);
    io_data->buffer.insert(io_data->buffer.end(), data.begin(), data.end());
    position += copy_size;
    size -= copy_size;
  }

  out->data = io_data->buffer.data();
  return crabbyavif::AVIF_RESULT_OK;
}

bool CrabbyAVIFImageDecoder::UpdateDemuxer() {
  DCHECK(!Failed());
  if (IsDecodedSizeAvailable()) {
    return true;
  }

  if (have_parsed_current_data_) {
    return true;
  }
  have_parsed_current_data_ = true;

  if (!decoder_) {
    decoder_.reset(crabbyavif::crabby_avifDecoderCreate());
    if (!decoder_) {
      return false;
    }

    // For simplicity, use a hardcoded maxThreads of 2, independent of the image
    // size and processor count. Note: even if we want maxThreads to depend on
    // the image size, it is impossible to do so because maxThreads is passed to
    // dav1d_open() inside crabbyavif::crabby_avifDecoderParse(), but the image
    // size is not known until crabbyavif::crabby_avifDecoderParse() returns
    // successfully. See https://github.com/AOMediaCodec/libavif/issues/636.
    decoder_->maxThreads = 2;

    if (animation_option_ != AnimationOption::kUnspecified &&
        crabbyavif::crabby_avifDecoderSetSource(
            decoder_.get(),
            animation_option_ == AnimationOption::kPreferAnimation
                ? crabbyavif::AVIF_DECODER_SOURCE_TRACKS
                : crabbyavif::AVIF_DECODER_SOURCE_PRIMARY_ITEM) !=
            crabbyavif::AVIF_RESULT_OK) {
      return false;
    }

    // Chrome doesn't use XMP and Exif metadata. Ignoring XMP and Exif will
    // ensure crabbyavif::crabby_avifDecoderParse() isn't waiting for some tiny
    // Exif payload hiding at the end of a file.
    decoder_->ignoreXMP = crabbyavif::CRABBY_AVIF_TRUE;
    decoder_->ignoreExif = crabbyavif::CRABBY_AVIF_TRUE;

    // Turn off libavif's 'clap' (clean aperture) property validation. We
    // validate 'clap' ourselves and ignore invalid 'clap' properties.
    decoder_->strictFlags &= ~crabbyavif::AVIF_STRICT_CLAP_VALID;
    // Allow the PixelInformationProperty ('pixi') to be missing in AV1 image
    // items. libheif v1.11.0 or older does not add the 'pixi' item property to
    // AV1 image items. (This issue has been corrected in libheif v1.12.0.) See
    // crbug.com/1198455.
    decoder_->strictFlags &= ~crabbyavif::AVIF_STRICT_PIXI_REQUIRED;

    if (base::FeatureList::IsEnabled(features::kAvifGainmapHdrImages) &&
        aux_image_ == cc::AuxImage::kGainmap) {
      decoder_->imageContentToDecode = crabbyavif::AVIF_IMAGE_CONTENT_GAIN_MAP;
    }

    avif_io_.destroy = nullptr;
    avif_io_.read = ReadFromSegmentReader;
    avif_io_.write = nullptr;
    avif_io_.persistent = crabbyavif::CRABBY_AVIF_FALSE;
    avif_io_.data = &avif_io_data_;
    crabbyavif::crabby_avifDecoderSetIO(decoder_.get(), &avif_io_);
  }

  // If all data is received, there is no point in decoding progressively.
  decoder_->allowProgressive = !IsAllDataReceived();

  auto ret = crabbyavif::crabby_avifDecoderParse(decoder_.get());
  if (ret == crabbyavif::AVIF_RESULT_WAITING_ON_IO) {
    return true;
  }
  if (ret != crabbyavif::AVIF_RESULT_OK) {
    DVLOG(1) << "crabbyavif::crabby_avifDecoderParse failed: "
             << crabbyavif::crabby_avifResultToString(ret) << ". "
             << decoder_->diag.error;
    return false;
  }

  // Image metadata is available in decoder_->image after
  // crabbyavif::crabby_avifDecoderParse() even though decoder_->imageIndex is
  // invalid (-1).
  DCHECK_EQ(decoder_->imageIndex, -1);
  // This variable is named |container| to emphasize the fact that the current
  // contents of decoder_->image come from the container, not any frame.
  const auto* container = GetDecoderImage();

  // The container width and container height are read from either the tkhd
  // (track header) box of a track or the ispe (image spatial extents) property
  // of an image item, both of which are mandatory in the spec.
  if (container->width == 0 || container->height == 0) {
    DVLOG(1) << "Container width and height must be present";
    return false;
  }

  // The container depth is read from either the av1C box of a track or the av1C
  // property of an image item, both of which are mandatory in the spec.
  if (container->depth == 0) {
    DVLOG(1) << "Container depth must be present";
    return false;
  }

  DCHECK_GT(decoder_->imageCount, 0);
  progressive_ =
      decoder_->progressiveState == crabbyavif::AVIF_PROGRESSIVE_STATE_ACTIVE;
  // If the image is progressive, decoder_->imageCount is the number of
  // progressive frames, but there is only one still image.
  decoded_frame_count_ = progressive_ ? 1 : decoder_->imageCount;
  container_width_ = container->width;
  container_height_ = container->height;
  bit_depth_ = container->depth;
  decode_to_half_float_ =
      ImageIsHighBitDepth() &&
      high_bit_depth_decoding_option_ == kHighBitDepthToHalfFloat;

  // Verify that crabbyavif::AVIF_PIXEL_FORMAT_{YUV444,YUV422,YUV420,YUV400} are
  // consecutive.
  static_assert(crabbyavif::AVIF_PIXEL_FORMAT_YUV422 ==
                crabbyavif::AVIF_PIXEL_FORMAT_YUV444 + 1);
  static_assert(crabbyavif::AVIF_PIXEL_FORMAT_YUV420 ==
                crabbyavif::AVIF_PIXEL_FORMAT_YUV422 + 1);
  static_assert(crabbya
```