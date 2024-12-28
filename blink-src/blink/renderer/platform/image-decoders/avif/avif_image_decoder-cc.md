Response:
The user wants a summary of the functionality of the `avif_image_decoder.cc` file in the Chromium Blink engine. I need to identify the main purpose of the file, how it interacts with web technologies, and any potential errors related to its usage.

**Plan:**

1. **Identify the core function:** The filename suggests this file is responsible for decoding AVIF images.
2. **Analyze the includes:** These reveal dependencies and functionalities, like image decoding (`image_decoder.h`), animation handling (`image_animation.h`), and interaction with the underlying AVIF library (`third_party/libavif`).
3. **Scan for key methods and data members:** Look for functions related to decoding, size determination, frame handling, color space management, and error handling.
4. **Connect to web technologies:** Look for connections to HTML (`<img>` tag), CSS (image properties), and JavaScript (image loading/manipulation).
5. **Infer logic and error scenarios:** Based on the code, identify potential issues like invalid file formats, missing data, or incorrect usage.
6. **Formulate assumptions for input/output:** Create hypothetical scenarios to illustrate the decoder's behavior.```
这是目录为blink/renderer/platform/image-decoders/avif/avif_image_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

**功能归纳 (基于提供的代码片段):**

`avif_image_decoder.cc` 文件的主要功能是**解码 AVIF (AV1 Image File Format) 图像**，使其能够在 Chromium 浏览器中显示。更具体地说，它负责以下任务：

1. **AVIF 数据解析:** 接收 AVIF 格式的图像数据流，并解析其结构和元数据。
2. **解码器管理:** 创建和管理 `libavif` 库的解码器实例，这是实际执行 AVIF 解码的外部库。
3. **图像属性提取:** 从 AVIF 文件中提取图像的各种属性，例如宽度、高度、颜色空间、位深度、动画信息（帧数、帧延迟、循环次数）等。
4. **YUV 图像数据处理:**  AVIF 图像通常以 YUV 格式存储。该解码器处理 YUV 数据的转换和管理，并能提供 YUV 格式的数据供其他组件使用。
5. **帧缓冲区管理:**  对于动画 AVIF 图像，它管理帧缓冲区，存储解码后的每一帧图像数据。
6. **解码控制:**  控制解码过程，包括是否允许增量解码（逐步显示部分解码的图像），以及处理渐进式 AVIF 图像。
7. **颜色空间处理:**  处理 AVIF 图像的颜色空间信息 (ICC 配置文件或 CICP 参数)，并将其转换为 Chromium 可以理解的 `gfx::ColorSpace` 和 `SkColorSpace`。
8. **HDR 元数据处理:**  如果 AVIF 图像包含 HDR (高动态范围) 元数据 (如 CLLI)，则提取并存储这些信息。
9. **增益图支持:**  如果 AVIF 图像包含增益图（用于 HDR 内容的色调映射），则会处理相关的颜色空间信息。
10. **错误处理:**  处理 `libavif` 解码过程中可能出现的错误，并设置解码失败状态。
11. **内存管理:**  有效地管理解码过程中的内存使用。
12. **性能优化:**  考虑性能优化，例如设置解码线程数。
13. **与 Chromium 其他组件集成:**  作为 Blink 渲染引擎的一部分，它与 Chromium 的其他图像处理和显示组件协同工作。

**与 JavaScript, HTML, CSS 的关系：**

*   **HTML (`<img>` 标签):** 当 HTML 中使用 `<img>` 标签加载 AVIF 图像时，Blink 引擎会调用 `AVIFImageDecoder` 来解码图像数据，最终将解码后的像素数据用于渲染和显示在网页上。
    *   **举例:**  `<img src="image.avif">` 当浏览器解析到这行 HTML 代码时，会尝试下载 `image.avif` 文件，并使用 `AVIFImageDecoder` 进行解码。

*   **CSS (背景图像等):**  类似地，当 CSS 中指定 AVIF 图像作为背景图像时，`AVIFImageDecoder` 也会参与解码过程。
    *   **举例:**  `.my-element { background-image: url("background.avif"); }`  浏览器会解码 `background.avif` 并将其设置为 `.my-element` 的背景。

*   **JavaScript (Canvas API, Image API 等):**  JavaScript 可以通过 `Image` 对象或者 Canvas API 来加载和操作图像。当加载 AVIF 图像时，`AVIFImageDecoder` 负责解码。解码后的图像数据可以通过 Canvas API 进行绘制和进一步处理。
    *   **假设输入:**  JavaScript 代码 `const img = new Image(); img.src = 'animated.avif';`
    *   **逻辑推理:**  当 `img.src` 设置为 AVIF 文件时，`AVIFImageDecoder` 会被调用来解码 `animated.avif`。如果这是一个动画 AVIF，解码器会解析出多帧图像。
    *   **假设输出:**  当图像加载完成后，可以通过 `img` 对象访问到图像的属性（如宽度、高度），对于动画图像，可以通过 Canvas API 绘制每一帧。

**逻辑推理的例子 (基于代码片段):**

*   **假设输入:** 一个损坏的 AVIF 文件，其文件大小信息不一致。
*   **逻辑推理:** 代码中 `kMaxAvifFileSize` 定义了允许解码的最大 AVIF 文件大小。同时，`libavif` 内部也会进行文件大小和偏移的校验。如果文件头的尺寸信息与实际数据不符，或者超过了 `kMaxAvifFileSize`，`libavif` 可能会检测到错误并返回失败状态。
*   **假设输出:** `avifDecoderParse` 方法返回非 `AVIF_RESULT_OK` 的错误码，`AVIFImageDecoder` 会调用 `SetFailed()` 将解码器标记为失败，并且不会继续解码。

**用户或编程常见的使用错误举例：**

*   **依赖小端序:** 代码中 `#if defined(ARCH_CPU_BIG_ENDIAN)` 有一个错误提示，表明 Blink 假设目标架构是小端序。如果开发者在非小端序架构上编译 Chromium，可能会遇到问题。这虽然不是用户直接的错误，但属于架构兼容性问题。
*   **忽略异步加载:**  图像加载通常是异步的。如果 JavaScript 代码尝试在图像完全加载和解码完成之前就访问图像数据或属性，可能会得到不完整或错误的结果。开发者需要确保在图像的 `onload` 事件触发后才进行操作。
*   **假设所有 AVIF 都支持所有特性:**  AVIF 标准支持很多特性，但并非所有编码器都会使用所有特性。开发者不应该假设所有的 AVIF 文件都包含特定的元数据（例如，所有的动画 AVIF 都有明确的循环次数）。代码中对于 `AVIF_REPETITION_COUNT_UNKNOWN` 的处理就是一个例子，它为了兼容旧版本 Chrome 而假设无限循环。
*   **在高 DPI 环境下对解码尺寸的误解:**  在高 DPI 屏幕上，图像的显示尺寸可能与解码尺寸不同。开发者如果直接使用解码尺寸来布局或者计算，可能会出现偏差。

**总结 `avif_image_decoder.cc` 的功能 (基于第 1 部分代码):**

总而言之，`avif_image_decoder.cc` 的主要职责是作为 Chromium 中解码 AVIF 图像的核心组件。它负责与底层的 `libavif` 库交互，解析 AVIF 数据，提取图像元数据，管理帧缓冲区（对于动画），处理颜色空间信息，并在解码过程中进行错误处理。它的成功运作对于在网页上正确显示 AVIF 图像至关重要，并直接影响到用户浏览网页的体验。它通过 Blink 引擎与 HTML、CSS 和 JavaScript 等 Web 技术紧密结合，使得开发者能够方便地在网页中使用 AVIF 这种高效的图像格式。

Prompt: 
```
这是目录为blink/renderer/platform/image-decoders/avif/avif_image_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/avif/avif_image_decoder.h"

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
#include "third_party/libavif/src/include/avif/avif.h"
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

const char* AvifDecoderErrorMessage(const avifDecoder* decoder) {
  // decoder->diag.error is a char array that stores a null-terminated C string.
  return *decoder->diag.error != '\0' ? decoder->diag.error
                                      : "(no error message)";
}

// Builds a gfx::ColorSpace from the ITU-T H.273 (CICP) color description.
gfx::ColorSpace GetColorSpace(
    avifColorPrimaries color_primaries,
    avifTransferCharacteristics transfer_characteristics,
    avifMatrixCoefficients matrix_coefficients,
    avifRange yuv_range,
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
  // These values correspond to AVIF_COLOR_PRIMARIES_BT709,
  // AVIF_TRANSFER_CHARACTERISTICS_SRGB, and AVIF_MATRIX_COEFFICIENTS_BT601,
  // respectively.
  //
  // Note that this only specifies the default color property when the color
  // property is absent. It does not really specify the default values for
  // colour_primaries, transfer_characteristics, and matrix_coefficients when
  // they are equal to 2 (unspecified). But we will interpret it as specifying
  // the default values for these variables because we must choose some defaults
  // and these are the most reasonable defaults to choose. We also advocate that
  // all AVIF decoders choose these defaults:
  // https://github.com/AOMediaCodec/av1-avif/issues/84
  const auto primaries = color_primaries == AVIF_COLOR_PRIMARIES_UNSPECIFIED
                             ? AVIF_COLOR_PRIMARIES_BT709
                             : color_primaries;
  const auto transfer =
      transfer_characteristics == AVIF_TRANSFER_CHARACTERISTICS_UNSPECIFIED
          ? AVIF_TRANSFER_CHARACTERISTICS_SRGB
          : transfer_characteristics;
  const auto matrix =
      (grayscale || matrix_coefficients == AVIF_MATRIX_COEFFICIENTS_UNSPECIFIED)
          ? AVIF_MATRIX_COEFFICIENTS_BT601
          : matrix_coefficients;
  const auto range = yuv_range == AVIF_RANGE_FULL
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
  if (yuv_range == AVIF_RANGE_FULL) {
    return gfx::ColorSpace::CreateJpeg();
  }
  return gfx::ColorSpace::CreateREC709();
}

// Builds a gfx::ColorSpace from the ITU-T H.273 (CICP) color description in the
// image.
gfx::ColorSpace GetColorSpace(const avifImage* image) {
  const bool grayscale = image->yuvFormat == AVIF_PIXEL_FORMAT_YUV400;
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
sk_sp<SkColorSpace> GetAltImageColorSpace(const avifImage& image) {
  const avifGainMap* gain_map = image.gainMap;
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
  } else if (gain_map->altColorPrimaries != AVIF_COLOR_PRIMARIES_UNSPECIFIED) {
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

AVIFImageDecoder::AVIFImageDecoder(AlphaOption alpha_option,
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

AVIFImageDecoder::~AVIFImageDecoder() = default;

String AVIFImageDecoder::FilenameExtension() const {
  return "avif";
}

const AtomicString& AVIFImageDecoder::MimeType() const {
  DEFINE_STATIC_LOCAL(const AtomicString, avif_mime_type, ("image/avif"));
  return avif_mime_type;
}

bool AVIFImageDecoder::ImageIsHighBitDepth() {
  return bit_depth_ > 8;
}

void AVIFImageDecoder::OnSetData(scoped_refptr<SegmentReader> data) {
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

cc::YUVSubsampling AVIFImageDecoder::GetYUVSubsampling() const {
  switch (avif_yuv_format_) {
    case AVIF_PIXEL_FORMAT_YUV420:
      return cc::YUVSubsampling::k420;
    case AVIF_PIXEL_FORMAT_YUV422:
      return cc::YUVSubsampling::k422;
    case AVIF_PIXEL_FORMAT_YUV444:
      return cc::YUVSubsampling::k444;
    case AVIF_PIXEL_FORMAT_YUV400:
      return cc::YUVSubsampling::kUnknown;
    case AVIF_PIXEL_FORMAT_NONE:
      // avif_yuv_format_ is initialized to AVIF_PIXEL_FORMAT_NONE in the
      // constructor. If we have called SetSize() successfully at the end
      // of UpdateDemuxer(), avif_yuv_format_ cannot possibly be
      // AVIF_PIXEL_FORMAT_NONE.
      CHECK(!IsDecodedSizeAvailable());
      return cc::YUVSubsampling::kUnknown;
    default:
      break;
  }
  NOTREACHED() << "Invalid YUV format: " << avif_yuv_format_;
}

gfx::Size AVIFImageDecoder::DecodedYUVSize(cc::YUVIndex index) const {
  DCHECK(IsDecodedSizeAvailable());
  if (index == cc::YUVIndex::kU || index == cc::YUVIndex::kV) {
    return gfx::Size(UVSize(Size().width(), chroma_shift_x_),
                     UVSize(Size().height(), chroma_shift_y_));
  }
  return Size();
}

wtf_size_t AVIFImageDecoder::DecodedYUVWidthBytes(cc::YUVIndex index) const {
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

SkYUVColorSpace AVIFImageDecoder::GetYUVColorSpace() const {
  DCHECK(CanDecodeToYUV());
  DCHECK_NE(yuv_color_space_, SkYUVColorSpace::kIdentity_SkYUVColorSpace);
  return yuv_color_space_;
}

uint8_t AVIFImageDecoder::GetYUVBitDepth() const {
  DCHECK(CanDecodeToYUV());
  return bit_depth_;
}

std::optional<gfx::HDRMetadata> AVIFImageDecoder::GetHDRMetadata() const {
  return hdr_metadata_;
}

void AVIFImageDecoder::DecodeToYUV() {
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
  decoder_->allowIncremental = AVIF_FALSE;

  // libavif cannot decode to an external buffer. So we need to copy from
  // libavif's internal buffer to |image_planes_|.
  // TODO(crbug.com/1099825): Enhance libavif to decode to an external buffer.
  auto ret = DecodeImage(frame_index);
  if (ret != AVIF_RESULT_OK) {
    if (ret != AVIF_RESULT_WAITING_ON_IO) {
      SetFailed();
    }
    return;
  }
  const avifImage* image = decoded_image_;

  DCHECK(!image->alphaPlane);
  static_assert(cc::YUVIndex::kY == static_cast<cc::YUVIndex>(AVIF_CHAN_Y), "");
  static_assert(cc::YUVIndex::kU == static_cast<cc::YUVIndex>(AVIF_CHAN_U), "");
  static_assert(cc::YUVIndex::kV == static_cast<cc::YUVIndex>(AVIF_CHAN_V), "");

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

int AVIFImageDecoder::RepetitionCount() const {
  if (decoded_frame_count_ > 1) {
    switch (decoder_->repetitionCount) {
      case AVIF_REPETITION_COUNT_INFINITE:
        return kAnimationLoopInfinite;
      case AVIF_REPETITION_COUNT_UNKNOWN:
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

bool AVIFImageDecoder::FrameIsReceivedAtIndex(wtf_size_t index) const {
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
  avifExtent data_extent;
  if (avifDecoderNthImageMaxExtent(decoder_.get(), index, &data_extent) !=
      AVIF_RESULT_OK) {
    return false;
  }
  return data_extent.size == 0 ||
         data_extent.offset + data_extent.size <= data_->size();
}

std::optional<base::TimeDelta> AVIFImageDecoder::FrameTimestampAtIndex(
    wtf_size_t index) const {
  return index < frame_buffer_cache_.size()
             ? frame_buffer_cache_[index].Timestamp()
             : std::nullopt;
}

base::TimeDelta AVIFImageDecoder::FrameDurationAtIndex(wtf_size_t index) const {
  return index < frame_buffer_cache_.size()
             ? frame_buffer_cache_[index].Duration()
             : base::TimeDelta();
}

bool AVIFImageDecoder::ImageHasBothStillAndAnimatedSubImages() const {
  // Per MIAF, all animated AVIF files must have a still image, even if it's
  // just a pointer to the first frame of the animation.
  return decoder_ && decoder_->imageSequenceTrackPresent;
}

// static
bool AVIFImageDecoder::MatchesAVIFSignature(
    const FastSharedBufferReader& fast_reader) {
  // avifPeekCompatibleFileType() clamps compatible brands at 32 when reading in
  // the ftyp box in ISO BMFF for the 'avif' or 'avis' brand. So the maximum
  // number of bytes read is 144 bytes (size 4 bytes, type 4 bytes, major brand
  // 4 bytes, minor version 4 bytes, and 4 bytes * 32 compatible brands).
  char buffer[144];
  avifROData input;
  input.size = std::min(sizeof(buffer), fast_reader.size());
  input.data = reinterpret_cast<const uint8_t*>(
      fast_reader.GetConsecutiveData(0, input.size, buffer));
  return avifPeekCompatibleFileType(&input);
}

gfx::ColorSpace AVIFImageDecoder::GetColorSpaceForTesting() const {
  return GetColorSpace(GetDecoderImage());
}

void AVIFImageDecoder::ParseMetadata() {
  if (!UpdateDemuxer()) {
    SetFailed();
  }
}

void AVIFImageDecoder::DecodeSize() {
  ParseMetadata();
}

wtf_size_t AVIFImageDecoder::DecodeFrameCount() {
  if (!Failed()) {
    ParseMetadata();
  }
  return IsDecodedSizeAvailable() ? decoded_frame_count_
                                  : frame_buffer_cache_.size();
}

void AVIFImageDecoder::InitializeNewFrame(wtf_size_t index) {
  auto& buffer = frame_buffer_cache_[index];
  if (decode_to_half_float_) {
    buffer.SetPixelFormat(ImageFrame::PixelFormat::kRGBA_F16);
  }

  // For AVIFs, the frame always fills the entire image.
  buffer.SetOriginalFrameRect(gfx::Rect(Size()));

  avifImageTiming timing;
  auto ret = avifDecoderNthImageTiming(decoder_.get(), index, &timing);
  DCHECK_EQ(ret, AVIF_RESULT_OK);
  buffer.SetTimestamp(base::Seconds(timing.pts));
  buffer.SetDuration(base::Seconds(timing.duration));
}

void AVIFImageDecoder::Decode(wtf_size_t index) {
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
      avifExtent data_extent;
      auto rv = avifDecoderNthImageMaxExtent(decoder_.get(), frame_index + 1,
                                             &data_extent);
      if (rv != AVIF_RESULT_OK) {
        DVLOG(1) << "avifDecoderNthImageMaxExtent(" << frame_index + 1
                 << ") failed: " << avifResultToString(rv) << ": "
                 << AvifDecoderErrorMessage(decoder_.get());
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
  if (ret != AVIF_RESULT_OK && ret != AVIF_RESULT_WAITING_ON_IO) {
    SetFailed();
    return;
  }
  const avifImage* image = decoded_image_;

  // ImageDecoder::SizeCalculationMayOverflow(), called by UpdateDemuxer()
  // before being here, made sure the image height fits in an int.
  int displayable_height =
      static_cast<int>(avifDecoderDecodedRowCount(decoder_.get()));
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

bool AVIFImageDecoder::CanReusePreviousFrameBuffer(wtf_size_t index) const {
  // (a) Technically we can reuse the bitmap of the previous frame because the
  // AVIF decoder handles frame dependence internally and we never need to
  // preserve previous frames to decode later ones, and (b) since this function
  // will not currently be called, this is really more for the reader than any
  // functional purpose.
  return true;
}

// static
avifResult AVIFImageDecoder::ReadFromSegmentReader(avifIO* io,
                                                   uint32_t read_flags,
                                                   uint64_t offset,
                                                   size_t size,
                                                   avifROData* out) {
  if (read_flags != 0) {
    // Unsupported read_flags
    return AVIF_RESULT_IO_ERROR;
  }

  AvifIOData* io_data = static_cast<AvifIOData*>(io->data);

  // Sanitize/clamp incoming request
  if (offset > io_data->reader->size()) {
    // The offset is past the end of the buffer or available data.
    return io_data->all_data_received ? AVIF_RESULT_IO_ERROR
                                      : AVIF_RESULT_WAITING_ON_IO;
  }

  // It is more convenient to work with a variable of the size_t type. Since
  // offset <= io_data->reader->size() <= SIZE_MAX, this cast is safe.
  size_t position = static_cast<size_t>(offset);
  const size_t available_size = io_data->reader->size() - position;
  if (size > available_size) {
    if (!io_data->all_data_received) {
      return AVIF_RESULT_WAITING_ON_IO;
    }
    size = available_size;
  }

  out->size = size;

  base::span<const uint8_t> data = io_data->reader->GetSomeData(position);
  if (data.size() >= size) {
    out->data = data.data();
    return AVIF_RESULT_OK;
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
  return AVIF_RESULT_OK;
}

bool AVIFImageDecoder::UpdateDemuxer() {
  DCHECK(!Failed());
  if (IsDecodedSizeAvailable()) {
    return true;
  }

  if (have_parsed_current_data_) {
    return true;
  }
  have_parsed_current_data_ = true;

  if (!decoder_) {
    decoder_.reset(avifDecoderCreate());
    if (!decoder_) {
      return false;
    }

    // For simplicity, use a hardcoded maxThreads of 2, independent of the image
    // size and processor count. Note: even if we want maxThreads to depend on
    // the image size, it is impossible to do so because maxThreads is passed to
    // dav1d_open() inside avifDecoderParse(), but the image size is not known
    // until avifDecoderParse() returns successfully. See
    // https://github.com/AOMediaCodec/libavif/issues/636.
    decoder_->maxThreads = 2;

    if (animation_option_ != AnimationOption::kUnspecified &&
        avifDecoderSetSource(
            decoder_.get(),
            animation_option_ == AnimationOption::kPreferAnimation
                ? AVIF_DECODER_SOURCE_TRACKS
                : AVIF_DECODER_SOURCE_PRIMARY_ITEM) != AVIF_RESULT_OK) {
      return false;
    }

    // Chrome doesn't use XMP and Exif metadata. Ignoring XMP and Exif will
    // ensure avifDecoderParse() isn't waiting for some tiny Exif payload hiding
    // at the end of a file.
    decoder_->ignoreXMP = AVIF_TRUE;
    decoder_->ignoreExif = AVIF_TRUE;

    // Turn off libavif's 'clap' (clean aperture) property validation. We
    // validate 'clap' ourselves and ignore invalid 'clap' properties.
    decoder_->strictFlags &= ~AVIF_STRICT_CLAP_VALID;
    // Allow the PixelInformationProperty ('pixi') to be missing in AV1 image
    // items. libheif v1.11.0 or older does not add the 'pixi' item property to
    // AV1 image items. (This issue has been corrected in libheif v1.12.0.) See
    // crbug.com/1198455.
    decoder_->strictFlags &= ~AVIF_STRICT_PIXI_REQUIRED;

    if (base::FeatureList::IsEnabled(features::kAvifGainmapHdrImages) &&
        aux_image_ == cc::AuxImage::kGainmap) {
      decoder_->imageContentToDecode = AVIF_IMAGE_CONTENT_GAIN_MAP;
    }

    avif_io_.destroy = nullptr;
    avif_io_.read = ReadFromSegmentReader;
    avif_io_.write = nullptr;
    avif_io_.persistent = AVIF_FALSE;
    avif_io_.data = &avif_io_data_;
    avifDecoderSetIO(decoder_.get(), &avif_io_);
  }

  // If all data is received, there is no point in decoding progressively.
  decoder_->allowProgressive = !IsAllDataReceived();

  auto ret = avifDecoderParse(decoder_.get());
  if (ret == AVIF_RESULT_WAITING_ON_IO) {
    return true;
  }
  if (ret != AVIF_RESULT_OK) {
    DVLOG(1) << "avifDecoderParse failed: " << avifResultToString(ret) << ". "
             << decoder_->diag.error;
    return false;
  }

  // Image metadata is available in decoder_->image after avifDecoderParse()
  // even though decoder_->imageIndex is invalid (-1).
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
  progressive_ = decoder_->progressiveState == AVIF_PROGRESSIVE_STATE_ACTIVE;
  // If the image is progressive, decoder_->imageCount is the number of
  // progressive frames, but there is only one still image.
  decoded_frame_count_ = progressive_ ? 1 : decoder_->imageCount;
  container_width_ = container->width;
  container_height_ = container->height;
  bit_depth_ = container->depth;
  decode_to_half_float_ =
      ImageIsHighBitDepth() &&
      high_bit_depth_decoding_option_ == kHighBitDepthToHalfFloat;

  // Verify that AVIF_PIXEL_FORMAT_{YUV444,YUV422,YUV420,YUV400} are
  // consecutive.
  static_assert(AVIF_PIXEL_FORMAT_YUV422 == AVIF_PIXEL_FORMAT_YUV444 + 1);
  static_assert(AVIF_PIXEL_FORMAT_YUV420 == AVIF_PIXEL_FORMAT_YUV422 + 1);
  static_assert(AVIF_PIXEL_FORMAT_YUV400 == AVIF_PIXEL_FORMAT_YUV420 + 1);
  // Assert that after avifDecoderParse() returns AVIF_RESULT_OK,
  // decoder_->image->yuvFormat (the same as container->yuvFormat) is one of the
  // four YUV formats in AV1.
  CHECK(container->yuvFormat >= AVIF_PIXEL_FORMAT_YUV444 &&
        container->yuvFormat <= AVIF_PIXEL_FORMAT_YUV400)
      << "Invalid YUV format: " << container->yuvFormat;
  avif_yuv_format_ = container->yuvFormat;
  avifPixelFormatInfo format_info;
  avifGetPixelFormatInfo(container->yuvFormat, &format_info);
  chroma_shift_x_ = format_info.chromaShiftX;
  chroma_shift_y_ = format_info.chromaShiftY;

  if (container->clli.maxCLL || container->clli.maxPALL) {
    hdr_metadata_ = gfx::HDRMetadata();
    hdr_metadata_->cta_861_3 = gfx::HdrMetadataCta861_3(
        container->clli.maxCLL, container->clli.maxPALL);
  }

  // SetEmbeddedColorProfile() must be called before IsSizeAvailable() becomes
  // true. So call SetEmbeddedColorProfile() before calling SetSize(). The color
  // profile is either an ICC profile or the CICP color description.

  if (!IgnoresColorSpace()) {
    // The CICP color description is always present because we can always get it
    // from the AV1 sequence header for the frames. If an ICC profile is
    // present, use it instead of the CICP color description.
    if (container->icc.size) {
      std::unique_ptr<Col
"""


```