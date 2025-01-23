Response:
The user wants a summary of the functionality of the provided C++ code. I need to identify the core purpose of the `PNGImageDecoder` class and its relationship to web technologies like JavaScript, HTML, and CSS. I also need to look for logical inferences, potential user errors, and common programming mistakes. Since this is part 1 of 2, I should focus on the functionalities covered in this specific code snippet.

**Plan:**

1. **Identify the class's core function:** Based on the name and context, it decodes PNG image data.
2. **Analyze key methods:** Look at methods like `Decode`, `Parse`, `SetColorSpace`, `RowAvailable` to understand the decoding process and handling of image properties.
3. **Relate to web technologies:**  Consider how decoded images are used in HTML (e.g., `<img>` tag), styled with CSS (e.g., background images), and potentially manipulated by JavaScript (e.g., canvas).
4. **Look for logical inferences:**  Identify any decision-making processes within the code based on input data.
5. **Identify potential errors:** Consider scenarios where incorrect or malformed PNG data could lead to errors or unexpected behavior.
6. **Synthesize a summary:** Combine the above points into a concise description of the class's functionality as presented in this part of the code.
这个 `blink/renderer/platform/image-decoders/png/png_image_decoder.cc` 文件是 Chromium Blink 引擎中用于解码 PNG 图像的核心组件。以下是根据提供的代码片段对其功能的归纳：

**核心功能:**

1. **PNG图像解码:** 该类的主要职责是将 PNG 格式的图像数据解码成浏览器可以渲染的位图数据。
2. **渐进式解码:**  代码支持渐进式解码，允许在接收到部分图像数据时就开始解码和渲染，提升用户体验。
3. **动画支持:**  尽管在提供的代码片段中没有明显的动画处理逻辑，但代码结构（如 `current_frame_`, `frame_buffer_cache_`, `repetition_count_`）表明它具备处理动画 PNG (APNG) 的能力。
4. **颜色管理:**  代码集成了颜色管理功能，能够解析 PNG 文件中嵌入的颜色配置文件 (如 cICP, sRGB, iCCP) 以及 cHRM 和 gAMA 信息，并将其转换为 Skia 库的颜色空间表示，以确保跨不同显示设备的颜色一致性。
5. **HDR元数据处理:** 代码能够读取 PNG 文件中嵌入的 HDR 元数据块 (cLLi, mDCv)，为高动态范围图像的渲染提供必要的信息。
6. **Exif 元数据处理:**  代码可以提取 PNG 文件中的 eXIf 块，并将其包含的 Exif 元数据应用到图像。
7. **内存管理:**  代码使用帧缓冲区缓存 (`frame_buffer_cache_`) 来管理解码后的图像帧数据，并支持在不再需要时清除帧缓冲区以节省内存。
8. **错误处理:**  代码包含了基本的错误处理机制，例如在解析或解码失败时设置 `Failed()` 标志。
9. **图像大小限制:** 代码对解码的图像尺寸进行了限制，防止因解码过大的 PNG 图像而导致内存溢出或其他问题。
10. **隔行扫描处理 (Adam7):** 代码支持处理隔行扫描的 PNG 图像。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **HTML (`<img>` 标签):** 当浏览器遇到一个 `<img>` 标签，其 `src` 属性指向一个 PNG 图片时，Blink 引擎会调用 `PNGImageDecoder` 来解码该 PNG 图片数据，最终将解码后的位图数据用于在页面上渲染图像。
*   **CSS (`background-image` 属性):**  CSS 的 `background-image` 属性也可以引用 PNG 图片。浏览器处理方式类似，会使用 `PNGImageDecoder` 解码图像并在元素背景中显示。
*   **JavaScript (`Canvas API`):** JavaScript 可以通过 Canvas API 来操作图像数据。当使用 `drawImage()` 方法绘制一个 PNG 图片到 canvas 上时，Blink 引擎也会使用 `PNGImageDecoder` 来解码该图片，然后 JavaScript 才能访问和操作其像素数据。

**逻辑推理举例:**

*   **假设输入:**  PNG 文件头包含 cICP 块，描述了 Display P3 颜色空间。
*   **输出:** `PNGImageDecoder` 会解析该 cICP 块，创建一个 `ColorProfile` 对象，并将其设置为该 PNG 图像的颜色空间。后续的解码和渲染会基于这个 Display P3 颜色空间进行。

*   **假设输入:** PNG 文件是隔行扫描的 (interlace\_type == PNG\_INTERLACE\_ADAM7)。
*   **输出:** `PNGImageDecoder` 会调用 `png_set_interlace_handling(png)` 来指示 libpng 处理隔行扫描，并在 `RowAvailable` 中使用 `png_progressive_combine_row` 来组合不同扫描通道的数据。

**用户或编程常见的使用错误举例:**

*   **用户错误:** 提供损坏的 PNG 文件作为输入。`PNGImageDecoder` 在解析或解码过程中可能会遇到错误，最终调用 `SetFailed()`。虽然代码会处理这种情况，但用户看到的可能是无法加载的图片。
*   **编程错误:**  Blink 引擎内部使用 `PNGImageDecoder`，如果上层调用没有正确处理 `Failed()` 状态，可能会导致后续的渲染逻辑出现问题。例如，没有检查解码是否成功就尝试访问解码后的图像数据。
*   **安全问题:**  如果不对 PNG 图像的大小进行限制，恶意用户可能会提供一个非常大的 PNG 文件，导致浏览器内存消耗过大甚至崩溃。代码中 `kMaxPNGSize` 的检查就是为了防止这种问题。

**总结 (针对第1部分):**

`blink/renderer/platform/image-decoders/png/png_image_decoder.cc` 文件的主要功能是解码 PNG 格式的图像数据，并处理与颜色管理、HDR元数据、Exif 元数据以及隔行扫描相关的特性。它是 Blink 引擎中渲染 PNG 图像的关键组成部分，直接影响到在 HTML 页面和通过 JavaScript Canvas API 使用 PNG 图像的能力。 代码具备一定的错误处理和安全机制，以应对潜在的输入错误和恶意攻击。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/png/png_image_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2006 Apple Computer, Inc.
 * Copyright (C) Research In Motion Limited 2009-2010. All rights reserved.
 *
 * Portions are Copyright (C) 2001 mozilla.org
 *
 * Other contributors:
 *   Stuart Parmenter <stuart@mozilla.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Alternatively, the contents of this file may be used under the terms
 * of either the Mozilla Public License Version 1.1, found at
 * http://www.mozilla.org/MPL/ (the "MPL") or the GNU General Public
 * License Version 2.0, found at http://www.fsf.org/copyleft/gpl.html
 * (the "GPL"), in which case the provisions of the MPL or the GPL are
 * applicable instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of one of those two
 * licenses (the MPL or the GPL) and not to allow others to use your
 * version of this file under the LGPL, indicate your decision by
 * deletingthe provisions above and replace them with the notice and
 * other provisions required by the MPL or the GPL, as the case may be.
 * If you do not delete the provisions above, a recipient may use your
 * version of this file under any of the LGPL, the MPL or the GPL.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/png/png_image_decoder.h"

#include <memory>

#include "base/containers/adapters.h"
#include "base/numerics/checked_math.h"
#include "media/base/video_color_space.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/modules/skcms/skcms.h"

#if (defined(__ARM_NEON__) || defined(__ARM_NEON))
#include <arm_neon.h>
#endif

namespace blink {

PNGImageDecoder::PNGImageDecoder(
    AlphaOption alpha_option,
    HighBitDepthDecodingOption high_bit_depth_decoding_option,
    ColorBehavior color_behavior,
    wtf_size_t max_decoded_bytes,
    wtf_size_t offset)
    : ImageDecoder(alpha_option,
                   high_bit_depth_decoding_option,
                   color_behavior,
                   cc::AuxImage::kDefault,
                   max_decoded_bytes),
      offset_(offset),
      current_frame_(0),
      // It would be logical to default to kAnimationNone, but BitmapImage uses
      // that as a signal to never check again, meaning the actual count will
      // never be respected.
      repetition_count_(kAnimationLoopOnce),
      has_alpha_channel_(false),
      current_buffer_saw_alpha_(false),
      decode_to_half_float_(false),
      bit_depth_(0) {}

PNGImageDecoder::~PNGImageDecoder() = default;

String PNGImageDecoder::FilenameExtension() const {
  return "png";
}

const AtomicString& PNGImageDecoder::MimeType() const {
  DEFINE_STATIC_LOCAL(const AtomicString, png_mime_type, ("image/png"));
  return png_mime_type;
}

bool PNGImageDecoder::SetFailed() {
  reader_.reset();
  return ImageDecoder::SetFailed();
}

wtf_size_t PNGImageDecoder::DecodeFrameCount() {
  Parse(ParseQuery::kMetaData);
  return Failed() ? frame_buffer_cache_.size() : reader_->FrameCount();
}

void PNGImageDecoder::DecodeSize() {
  Parse(ParseQuery::kSize);
}

void PNGImageDecoder::Decode(wtf_size_t index) {
  Parse(ParseQuery::kMetaData);

  if (Failed()) {
    return;
  }

  UpdateAggressivePurging(index);

  Vector<wtf_size_t> frames_to_decode = FindFramesToDecode(index);
  for (const auto& frame : base::Reversed(frames_to_decode)) {
    current_frame_ = frame;
    if (!reader_->Decode(*data_, frame)) {
      SetFailed();
      return;
    }

    // If this returns false, we need more data to continue decoding.
    if (!PostDecodeProcessing(frame)) {
      break;
    }
  }

  // It is also a fatal error if all data is received and we have decoded all
  // frames available but the file is truncated.
  if (index >= frame_buffer_cache_.size() - 1 && IsAllDataReceived() &&
      reader_ && !reader_->ParseCompleted()) {
    SetFailed();
  }
}

void PNGImageDecoder::Parse(ParseQuery query) {
  if (Failed() || (reader_ && reader_->ParseCompleted())) {
    return;
  }

  if (!reader_) {
    reader_ = std::make_unique<PNGImageReader>(this, offset_);
  }

  if (!reader_->Parse(*data_, query)) {
    SetFailed();
  }
}

void PNGImageDecoder::ClearFrameBuffer(wtf_size_t index) {
  if (reader_) {
    reader_->ClearDecodeState(index);
  }
  ImageDecoder::ClearFrameBuffer(index);
}

bool PNGImageDecoder::CanReusePreviousFrameBuffer(wtf_size_t index) const {
  DCHECK(index < frame_buffer_cache_.size());
  return frame_buffer_cache_[index].GetDisposalMethod() !=
         ImageFrame::kDisposeOverwritePrevious;
}

void PNGImageDecoder::SetRepetitionCount(int repetition_count) {
  repetition_count_ = repetition_count;
}

int PNGImageDecoder::RepetitionCount() const {
  return Failed() ? kAnimationLoopOnce : repetition_count_;
}

void PNGImageDecoder::InitializeNewFrame(wtf_size_t index) {
  const PNGImageReader::FrameInfo& frame_info = reader_->GetFrameInfo(index);
  ImageFrame& buffer = frame_buffer_cache_[index];
  if (decode_to_half_float_) {
    buffer.SetPixelFormat(ImageFrame::PixelFormat::kRGBA_F16);
  }

  DCHECK(gfx::Rect(Size()).Contains(frame_info.frame_rect));
  buffer.SetOriginalFrameRect(frame_info.frame_rect);

  buffer.SetDuration(base::Milliseconds(frame_info.duration));
  buffer.SetDisposalMethod(frame_info.disposal_method);
  buffer.SetAlphaBlendSource(frame_info.alpha_blend);

  wtf_size_t previous_frame_index = FindRequiredPreviousFrame(index, false);
  buffer.SetRequiredPreviousFrameIndex(previous_frame_index);
}

// Returns nullptr if the cICP chunk is invalid, or if it describes an
// unsupported color profile.
// See https://w3c.github.io/PNG-spec/#11cICP for the definition of this chunk.
static std::unique_ptr<ColorProfile> ParseCicpChunk(
    const png_unknown_chunk& chunk) {
  // First, validate the cICP chunk.
  // cICP must be 4 bytes.
  if (chunk.size != 4) {
    return nullptr;
  }

  // Memory layout: ptmf, with p representing the colour primaries, t
  // representing the transfer characteristics, m the matrix coefficients, and f
  // whether the data is full or limited range.
  uint8_t primaries = chunk.data[0];
  uint8_t trc = chunk.data[1];
  uint8_t matrix_coefficients = chunk.data[2];
  uint8_t range_u8 = chunk.data[3];

  // Per PNG spec, matrix_coefficients must be 0, i.e. RGB (YUV is explicitly
  // disallowed).
  if (matrix_coefficients) {
    return nullptr;
  }
  // range must be 0 or 1.
  if (range_u8 != 0 && range_u8 != 1) {
    return nullptr;
  }
  const auto range = range_u8 == 1 ? gfx::ColorSpace::RangeID::FULL
                                   : gfx::ColorSpace::RangeID::LIMITED;
  if (range == gfx::ColorSpace::RangeID::LIMITED) {
    // TODO(crbug/1339019): Implement this if needed.
    DLOG(WARNING) << "Limited range RGB is not fully supported";
  }
  media::VideoColorSpace color_space(primaries, trc, 0, range);

  // If not valid, do not return anything.
  if (!color_space.IsSpecified()) {
    return nullptr;
  }

  sk_sp<SkColorSpace> sk_color_space =
      color_space.ToGfxColorSpace().GetAsFullRangeRGB().ToSkColorSpace();
  if (!sk_color_space) {
    return nullptr;
  }

  skcms_ICCProfile profile;
  sk_color_space->toProfile(&profile);

  return std::make_unique<ColorProfile>(profile);
}

static inline std::unique_ptr<ColorProfile> ReadColorProfile(png_structp png,
                                                             png_infop info) {
  png_unknown_chunkp unknown_chunks;
  size_t num_unknown_chunks =
      png_get_unknown_chunks(png, info, &unknown_chunks);
  for (size_t i = 0; i < num_unknown_chunks; i++) {
    const auto& chunk = unknown_chunks[i];
    if (strcmp(reinterpret_cast<const char*>(chunk.name), "cICP") == 0) {
      // We found a cICP chunk, which takes priority over other chunks.
      std::unique_ptr<ColorProfile> cicp_color_profile = ParseCicpChunk(chunk);
      // Ignore cICP if it is invalid or if the color profile it describes is
      // not supported.
      if (cicp_color_profile) {
        return cicp_color_profile;
      }
    }
  }

  if (png_get_valid(png, info, PNG_INFO_sRGB)) {
    return std::make_unique<ColorProfile>(*skcms_sRGB_profile());
  }

  png_charp name;
  int compression;
  png_bytep buffer;
  png_uint_32 length;
  if (png_get_iCCP(png, info, &name, &compression, &buffer, &length)) {
    return ColorProfile::Create(base::as_bytes(base::span(buffer, length)));
  }

  png_fixed_point chrm[8];
  if (!png_get_cHRM_fixed(png, info, &chrm[0], &chrm[1], &chrm[2], &chrm[3],
                          &chrm[4], &chrm[5], &chrm[6], &chrm[7])) {
    return nullptr;
  }

  png_fixed_point inverse_gamma;
  if (!png_get_gAMA_fixed(png, info, &inverse_gamma)) {
    return nullptr;
  }

  // cHRM and gAMA tags are both present. The PNG spec states that cHRM is
  // valid even without gAMA but we cannot apply the cHRM without guessing
  // a gAMA. Color correction is not a guessing game: match the behavior
  // of Safari and Firefox instead (compat).

  struct pngFixedToFloat {
    explicit pngFixedToFloat(png_fixed_point value)
        : float_value(.00001f * value) {}
    operator float() { return float_value; }
    float float_value;
  };

  float rx = pngFixedToFloat(chrm[2]);
  float ry = pngFixedToFloat(chrm[3]);
  float gx = pngFixedToFloat(chrm[4]);
  float gy = pngFixedToFloat(chrm[5]);
  float bx = pngFixedToFloat(chrm[6]);
  float by = pngFixedToFloat(chrm[7]);
  float wx = pngFixedToFloat(chrm[0]);
  float wy = pngFixedToFloat(chrm[1]);
  skcms_Matrix3x3 to_xyzd50;
  if (!skcms_PrimariesToXYZD50(rx, ry, gx, gy, bx, by, wx, wy, &to_xyzd50)) {
    return nullptr;
  }

  skcms_TransferFunction fn;
  fn.g = 1.0f / pngFixedToFloat(inverse_gamma);
  fn.a = 1.0f;
  fn.b = fn.c = fn.d = fn.e = fn.f = 0.0f;

  skcms_ICCProfile profile;
  skcms_Init(&profile);
  skcms_SetTransferFunction(&profile, &fn);
  skcms_SetXYZD50(&profile, &to_xyzd50);

  return std::make_unique<ColorProfile>(profile);
}

static inline void ReadHDRMetadata(
    png_structp png,
    png_infop info,
    std::optional<gfx::HDRMetadata>* hdr_metadata) {
  std::optional<gfx::HdrMetadataCta861_3> clli;
  std::optional<gfx::HdrMetadataSmpteSt2086> mdcv;
  png_unknown_chunkp unknown_chunks;
  size_t num_unknown_chunks =
      png_get_unknown_chunks(png, info, &unknown_chunks);
  for (size_t chunk_index = 0; chunk_index < num_unknown_chunks;
       chunk_index++) {
    const auto& chunk = unknown_chunks[chunk_index];
    if (strcmp(reinterpret_cast<const char*>(chunk.name), "cLLi") == 0) {
      if (chunk.size != 8) {
        continue;
      }
      const uint32_t max_cll_times_10000 = (chunk.data[0] << 24) |
                                           (chunk.data[1] << 16) |
                                           (chunk.data[2] << 8) | chunk.data[3];
      const uint32_t max_fall_times_10000 =
          (chunk.data[4] << 24) | (chunk.data[5] << 16) | (chunk.data[6] << 8) |
          chunk.data[7];
      clli.emplace(max_cll_times_10000 / 10000, max_fall_times_10000 / 10000);
      continue;
    }
    if (strcmp(reinterpret_cast<const char*>(chunk.name), "mDCv") == 0) {
      if (chunk.size != 24) {
        continue;
      }
      // Red, green, blue, white, each with x and y.
      uint16_t chromaticities_times_50000[8];
      for (int i = 0; i < 8; ++i) {
        chromaticities_times_50000[i] =
            (chunk.data[2 * i] << 8) | chunk.data[2 * i + 1];
      }
      const uint32_t max_luminance_times_10000 =
          (chunk.data[16] << 24) | (chunk.data[17] << 16) |
          (chunk.data[18] << 8) | chunk.data[19];
      const uint32_t min_luminance_times_10000 =
          (chunk.data[20] << 24) | (chunk.data[21] << 16) |
          (chunk.data[22] << 8) | chunk.data[23];
      SkColorSpacePrimaries primaries = {
          chromaticities_times_50000[0] / 50000.f,
          chromaticities_times_50000[1] / 50000.f,
          chromaticities_times_50000[2] / 50000.f,
          chromaticities_times_50000[3] / 50000.f,
          chromaticities_times_50000[4] / 50000.f,
          chromaticities_times_50000[5] / 50000.f,
          chromaticities_times_50000[6] / 50000.f,
          chromaticities_times_50000[7] / 50000.f,
      };
      mdcv.emplace(primaries, max_luminance_times_10000 * 1e-4f,
                   min_luminance_times_10000 * 1e-4f);
      continue;
    }
  }
  if (clli || mdcv) {
    if (!hdr_metadata->has_value()) {
      hdr_metadata->emplace();
    }
    if (clli) {
      (*hdr_metadata)->cta_861_3 = clli;
    }
    if (mdcv) {
      (*hdr_metadata)->smpte_st_2086 = mdcv;
    }
  }
}

void PNGImageDecoder::SetColorSpace() {
  if (IgnoresColorSpace()) {
    return;
  }
  png_structp png = reader_->PngPtr();
  png_infop info = reader_->InfoPtr();
  const int color_type = png_get_color_type(png, info);
  if (!(color_type & PNG_COLOR_MASK_COLOR)) {
    return;
  }
  // We only support color profiles for color PALETTE and RGB[A] PNG.
  // TODO(msarett): Add GRAY profile support, block CYMK?
  if (auto profile = ReadColorProfile(png, info)) {
    SetEmbeddedColorProfile(std::move(profile));
  }
  ReadHDRMetadata(png, info, &hdr_metadata_);
}

void PNGImageDecoder::SetBitDepth() {
  if (bit_depth_) {
    return;
  }
  png_structp png = reader_->PngPtr();
  png_infop info = reader_->InfoPtr();
  bit_depth_ = png_get_bit_depth(png, info);
  decode_to_half_float_ =
      bit_depth_ == 16 &&
      high_bit_depth_decoding_option_ == kHighBitDepthToHalfFloat &&
      // TODO(crbug.com/874057): Implement support for 16-bit PNGs w/
      // ImageFrame::kBlendAtopPreviousFrame.
      repetition_count_ == kAnimationNone;
}

bool PNGImageDecoder::ImageIsHighBitDepth() {
  SetBitDepth();
  return bit_depth_ == 16 &&
         // TODO(crbug.com/874057): Implement support for 16-bit PNGs w/
         // ImageFrame::kBlendAtopPreviousFrame.
         repetition_count_ == kAnimationNone;
}

std::optional<gfx::HDRMetadata> PNGImageDecoder::GetHDRMetadata() const {
  return hdr_metadata_;
}

bool PNGImageDecoder::SetSize(unsigned width, unsigned height) {
  DCHECK(!IsDecodedSizeAvailable());
  // Protect against large PNGs. See http://bugzil.la/251381 for more details.
  const uint32_t kMaxPNGSize = 1000000;
  return (width <= kMaxPNGSize) && (height <= kMaxPNGSize) &&
         ImageDecoder::SetSize(width, height);
}

void PNGImageDecoder::HeaderAvailable() {
  DCHECK(IsDecodedSizeAvailable());

  png_structp png = reader_->PngPtr();
  png_infop info = reader_->InfoPtr();

  png_uint_32 width, height;
  int bit_depth, color_type, interlace_type, compression_type;
  png_get_IHDR(png, info, &width, &height, &bit_depth, &color_type,
               &interlace_type, &compression_type, nullptr);

  // The options we set here match what Mozilla does.

  // Expand to ensure we use 24-bit for RGB and 32-bit for RGBA.
  if (color_type == PNG_COLOR_TYPE_PALETTE ||
      (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8)) {
    png_set_expand(png);
  }

  if (png_get_valid(png, info, PNG_INFO_tRNS)) {
    png_set_expand(png);
  }

  if (!decode_to_half_float_) {
    png_set_strip_16(png);
  }

  if (color_type == PNG_COLOR_TYPE_GRAY ||
      color_type == PNG_COLOR_TYPE_GRAY_ALPHA) {
    png_set_gray_to_rgb(png);
  }

  if (!HasEmbeddedColorProfile()) {
    const double kInverseGamma = 0.45455;
    const double kDefaultGamma = 2.2;
    double gamma;
    if (!IgnoresColorSpace() && png_get_gAMA(png, info, &gamma)) {
      const double kMaxGamma = 21474.83;
      if ((gamma <= 0.0) || (gamma > kMaxGamma)) {
        gamma = kInverseGamma;
        png_set_gAMA(png, info, gamma);
      }
      png_set_gamma(png, kDefaultGamma, gamma);
    } else {
      png_set_gamma(png, kDefaultGamma, kInverseGamma);
    }
  }

  // process eXIf chunk
  png_uint_32 exif_size = 0;
  png_bytep exif_buffer = nullptr;
  if (png_get_eXIf_1(png, info, &exif_size, &exif_buffer) != 0) {
    // exif data exists
    if (exif_size != 0 && exif_buffer) {
      ApplyExifMetadata(SkData::MakeWithoutCopy(exif_buffer, exif_size).get(),
                        gfx::Size(width, height));
    }
  }

  // Tell libpng to send us rows for interlaced pngs.
  if (interlace_type == PNG_INTERLACE_ADAM7) {
    png_set_interlace_handling(png);
  }

  // Update our info now (so we can get color channel info).
  png_read_update_info(png, info);

  int channels = png_get_channels(png, info);
  DCHECK(channels == 3 || channels == 4);
  has_alpha_channel_ = (channels == 4);
}

#if (defined(__ARM_NEON__) || defined(__ARM_NEON))
// Premultiply RGB color channels by alpha, swizzle RGBA to SkPMColor
// order, and return the AND of all alpha channels.
static inline void SetRGBAPremultiplyRowNeon(png_bytep src_ptr,
                                             const int pixel_count,
                                             ImageFrame::PixelData* dst_pixel,
                                             unsigned* const alpha_mask) {
  assert(dst_pixel);
  assert(alpha_mask);

  constexpr int kPixelsPerLoad = 8;
  // Input registers.
  uint8x8x4_t rgba;
  // Alpha mask.
  uint8x8_t alpha_mask_vector = vdup_n_u8(255);

  // Scale the color channel by alpha - the opacity coefficient.
  auto premultiply = [](uint8x8_t c, uint8x8_t a) {
    // First multiply the color by alpha, expanding to 16-bit (max 255*255).
    uint16x8_t ca = vmull_u8(c, a);
    // Now we need to round back down to 8-bit, returning (x+127)/255.
    // (x+127)/255 == (x + ((x+128)>>8) + 128)>>8.  This form is well suited
    // to NEON: vrshrq_n_u16(...,8) gives the inner (x+128)>>8, and
    // vraddhn_u16() both the outer add-shift and our conversion back to 8-bit.
    return vraddhn_u16(ca, vrshrq_n_u16(ca, 8));
  };

  int i = pixel_count;
  for (; i >= kPixelsPerLoad; i -= kPixelsPerLoad) {
    // Reads 8 pixels at once, each color channel in a different
    // 64-bit register.
    rgba = vld4_u8(src_ptr);
    // AND pixel alpha values into the alpha detection mask.
    alpha_mask_vector = vand_u8(alpha_mask_vector, rgba.val[3]);

    uint64_t alphas_u64 = vget_lane_u64(vreinterpret_u64_u8(rgba.val[3]), 0);

    // If all of the pixels are opaque, no need to premultiply.
    if (~alphas_u64 == 0) {
#if SK_PMCOLOR_BYTE_ORDER(R, G, B, A)
      // Already in right order, write back (interleaved) results to memory.
      vst4_u8(reinterpret_cast<uint8_t*>(dst_pixel), rgba);

#elif SK_PMCOLOR_BYTE_ORDER(B, G, R, A)
      // Re-order color channels for BGRA.
      uint8x8x4_t bgra = {rgba.val[2], rgba.val[1], rgba.val[0], rgba.val[3]};
      // Write back (interleaved) results to memory.
      vst4_u8(reinterpret_cast<uint8_t*>(dst_pixel), bgra);

#endif

    } else {
#if SK_PMCOLOR_BYTE_ORDER(R, G, B, A)
      // Premultiply color channels, already in right order.
      rgba.val[0] = premultiply(rgba.val[0], rgba.val[3]);
      rgba.val[1] = premultiply(rgba.val[1], rgba.val[3]);
      rgba.val[2] = premultiply(rgba.val[2], rgba.val[3]);
      // Write back (interleaved) results to memory.
      vst4_u8(reinterpret_cast<uint8_t*>(dst_pixel), rgba);

#elif SK_PMCOLOR_BYTE_ORDER(B, G, R, A)
      uint8x8x4_t bgra;
      // Premultiply and re-order color channels for BGRA.
      bgra.val[0] = premultiply(rgba.val[2], rgba.val[3]);
      bgra.val[1] = premultiply(rgba.val[1], rgba.val[3]);
      bgra.val[2] = premultiply(rgba.val[0], rgba.val[3]);
      bgra.val[3] = rgba.val[3];
      // Write back (interleaved) results to memory.
      vst4_u8(reinterpret_cast<uint8_t*>(dst_pixel), bgra);

#endif
    }

    // Advance to next elements.
    src_ptr += kPixelsPerLoad * 4;
    dst_pixel += kPixelsPerLoad;
  }

  // AND together the 8 alpha values in the alpha_mask_vector.
  uint64_t alpha_mask_u64 =
      vget_lane_u64(vreinterpret_u64_u8(alpha_mask_vector), 0);
  alpha_mask_u64 &= (alpha_mask_u64 >> 32);
  alpha_mask_u64 &= (alpha_mask_u64 >> 16);
  alpha_mask_u64 &= (alpha_mask_u64 >> 8);
  *alpha_mask &= alpha_mask_u64;

  // Handle the tail elements.
  for (; i > 0; i--, dst_pixel++, src_ptr += 4) {
    ImageFrame::SetRGBAPremultiply(dst_pixel, src_ptr[0], src_ptr[1],
                                   src_ptr[2], src_ptr[3]);
    *alpha_mask &= src_ptr[3];
  }
}

// Swizzle RGBA to SkPMColor order, and return the AND of all alpha channels.
static inline void SetRGBARawRowNeon(png_bytep src_ptr,
                                     const int pixel_count,
                                     ImageFrame::PixelData* dst_pixel,
                                     unsigned* const alpha_mask) {
  assert(dst_pixel);
  assert(alpha_mask);

  constexpr int kPixelsPerLoad = 16;
  // Input registers.
  uint8x16x4_t rgba;
  // Alpha mask.
  uint8x16_t alpha_mask_vector = vdupq_n_u8(255);

  int i = pixel_count;
  for (; i >= kPixelsPerLoad; i -= kPixelsPerLoad) {
    // Reads 16 pixels at once, each color channel in a different
    // 128-bit register.
    rgba = vld4q_u8(src_ptr);
    // AND pixel alpha values into the alpha detection mask.
    alpha_mask_vector = vandq_u8(alpha_mask_vector, rgba.val[3]);

#if SK_PMCOLOR_BYTE_ORDER(R, G, B, A)
    // Already in right order, write back (interleaved) results to memory.
    vst4q_u8(reinterpret_cast<uint8_t*>(dst_pixel), rgba);

#elif SK_PMCOLOR_BYTE_ORDER(B, G, R, A)
    // Re-order color channels for BGRA.
    uint8x16x4_t bgra = {rgba.val[2], rgba.val[1], rgba.val[0], rgba.val[3]};
    // Write back (interleaved) results to memory.
    vst4q_u8(reinterpret_cast<uint8_t*>(dst_pixel), bgra);

#endif

    // Advance to next elements.
    src_ptr += kPixelsPerLoad * 4;
    dst_pixel += kPixelsPerLoad;
  }

  // AND together the 16 alpha values in the alpha_mask_vector.
  uint64_t alpha_mask_u64 =
      vget_lane_u64(vreinterpret_u64_u8(vget_low_u8(alpha_mask_vector)), 0);
  alpha_mask_u64 &=
      vget_lane_u64(vreinterpret_u64_u8(vget_high_u8(alpha_mask_vector)), 0);
  alpha_mask_u64 &= (alpha_mask_u64 >> 32);
  alpha_mask_u64 &= (alpha_mask_u64 >> 16);
  alpha_mask_u64 &= (alpha_mask_u64 >> 8);
  *alpha_mask &= alpha_mask_u64;

  // Handle the tail elements.
  for (; i > 0; i--, dst_pixel++, src_ptr += 4) {
    ImageFrame::SetRGBARaw(dst_pixel, src_ptr[0], src_ptr[1], src_ptr[2],
                           src_ptr[3]);
    *alpha_mask &= src_ptr[3];
  }
}

// Swizzle RGB to opaque SkPMColor order, and return the AND
// of all alpha channels.
static inline void SetRGBARawRowNoAlphaNeon(png_bytep src_ptr,
                                            const int pixel_count,
                                            ImageFrame::PixelData* dst_pixel) {
  assert(dst_pixel);

  constexpr int kPixelsPerLoad = 16;
  // Input registers.
  uint8x16x3_t rgb;

  int i = pixel_count;
  for (; i >= kPixelsPerLoad; i -= kPixelsPerLoad) {
    // Reads 16 pixels at once, each color channel in a different
    // 128-bit register.
    rgb = vld3q_u8(src_ptr);

#if SK_PMCOLOR_BYTE_ORDER(R, G, B, A)
    // RGB already in right order, add opaque alpha channel.
    uint8x16x4_t rgba = {rgb.val[0], rgb.val[1], rgb.val[2], vdupq_n_u8(255)};
    // Write back (interleaved) results to memory.
    vst4q_u8(reinterpret_cast<uint8_t*>(dst_pixel), rgba);

#elif SK_PMCOLOR_BYTE_ORDER(B, G, R, A)
    // Re-order color channels for BGR, add opaque alpha channel.
    uint8x16x4_t bgra = {rgb.val[2], rgb.val[1], rgb.val[0], vdupq_n_u8(255)};
    // Write back (interleaved) results to memory.
    vst4q_u8(reinterpret_cast<uint8_t*>(dst_pixel), bgra);

#endif

    // Advance to next elements.
    src_ptr += kPixelsPerLoad * 3;
    dst_pixel += kPixelsPerLoad;
  }

  // Handle the tail elements.
  for (; i > 0; i--, dst_pixel++, src_ptr += 3) {
    ImageFrame::SetRGBARaw(dst_pixel, src_ptr[0], src_ptr[1], src_ptr[2], 255);
  }
}
#endif

void PNGImageDecoder::RowAvailable(unsigned char* row_buffer,
                                   unsigned row_index,
                                   int) {
  if (current_frame_ >= frame_buffer_cache_.size()) {
    return;
  }

  ImageFrame& buffer = frame_buffer_cache_[current_frame_];
  if (buffer.GetStatus() == ImageFrame::kFrameEmpty) {
    png_structp png = reader_->PngPtr();
    if (!InitFrameBuffer(current_frame_)) {
      longjmp(JMPBUF(png), 1);
    }

    DCHECK_EQ(ImageFrame::kFramePartial, buffer.GetStatus());

    if (PNG_INTERLACE_ADAM7 ==
        png_get_interlace_type(png, reader_->InfoPtr())) {
      unsigned color_channels = has_alpha_channel_ ? 4 : 3;
      base::CheckedNumeric<int> interlace_buffer_size = color_channels;
      interlace_buffer_size *= Size().GetCheckedArea();
      if (decode_to_half_float_) {
        interlace_buffer_size *= 2;
      }
      if (!interlace_buffer_size.IsValid()) {
        longjmp(JMPBUF(png), 1);
      }
      reader_->CreateInterlaceBuffer(interlace_buffer_size.ValueOrDie());
      if (!reader_->InterlaceBuffer()) {
        longjmp(JMPBUF(png), 1);
      }
    }

    current_buffer_saw_alpha_ = false;
  }

  const gfx::Rect& frame_rect = buffer.OriginalFrameRect();
  DCHECK(gfx::Rect(Size()).Contains(frame_rect));

  /* libpng comments (here to explain what follows).
   *
   * this function is called for every row in the image. If the
   * image is interlacing, and you turned on the interlace handler,
   * this function will be called for every row in every pass.
   * Some of these rows will not be changed from the previous pass.
   * When the row is not changed, the new_row variable will be NULL.
   * The rows and passes are called in order, so you don't really
   * need the row_num and pass, but I'm supplying them because it
   * may make your life easier.
   */

  // Nothing to do if the row is unchanged, or the row is outside the image
  // bounds. In the case that a frame presents more data than the indicated
  // frame size, ignore the extra rows and use the frame size as the source
  // of truth. libpng can send extra rows: ignore them too, this to prevent
  // memory writes outside of the image bounds (security).
  if (!row_buffer) {
    return;
  }

  DCHECK_GT(frame_rect.height(), 0);
  if (row_index >= static_cast<unsigned>(frame_rect.height())) {
    return;
  }

  int y = row_index + frame_rect.y();
  if (y < 0) {
    return;
  }
  DCHECK_LT(y, Size().height());

  /* libpng comments (continued).
   *
   * For the non-NULL rows of interlaced images, you must call
   * png_progressive_combine_row() passing in the row and the
   * old row.  You can call this function for NULL rows (it will
   * just return) and for non-interlaced images (it just does the
   * memcpy for you) if it will make the code easier. Thus, you
   * can just do this for all cases:
   *
   *    png_progressive_combine_row(png_ptr, old_row, new_row);
   *
   * where old_row is what was displayed for previous rows. Note
   * that the first pass (pass == 0 really) will completely cover
   * the old row, so the rows do not have to be initialized. After
   * the first pass (and only for interlaced images), you will have
   * to pass the current row, and the function will combine the
   * old row and the new row.
   */

  bool has_alpha = has_alpha_channel_;
  png_bytep row = row_buffer;

  if (png_bytep interlace_buffer = reader_->InterlaceBuffer()) {
    unsigned bytes_per_pixel = has_alpha ? 4 : 3;
    if (decode_to_half_float_) {
      bytes_per_pixel *= 2;
    }
    row = interlace_buffer + (row_index * bytes_per_pixel * Size().width());
    png_progressive_combine_row(reader_->PngPtr(), row, row_buffer);
  }

  // Write the decoded row pixels to the frame buffer. The repetitive
  // form of the row write loops is for speed.
  const int width = frame_rect.width();
  png_bytep src_ptr = row;

  if (!decode_to_half_float_) {
    ImageFrame::PixelData* const dst_row = buffer.GetAddr(frame_rect.x(), y);
    if (has_alpha) {
      if (ColorProfileTransform* xform = ColorTransform()) {
        ImageFrame::PixelData* xform_dst = dst_row;
        // If we're blending over the previous frame, we can't overwrite that
        // when we do the color transform. So we allocate another row of pixels
        // to hold the temporary result before blending. In all other cases,
        // we can safely transform directly to the destination buffer, then do
        // any operations in-place (premul, swizzle).
        if (frame_buffer_cache_[current_frame_].GetAlphaBlendSource() ==
            ImageFrame::kBlendAtopPreviousFrame) {
          if (!color_transform_scanline_) {
            // This buffer may be wider than necessary for this frame, but by
            // allocating the full width of the PNG, we know it will be able to
            // hold temporary data for any subsequent frame.
            color_transform_scanline_.reset(
                new ImageFrame::PixelData[Size().width()]);
          }
          xform_dst = color_transform_scanline_.get();
        }
        skcms_PixelFormat color_format = skcms_PixelFormat_RGBA_8888;
        skcms_AlphaFormat alpha_format = skcms_AlphaFormat_Unpremul;
        bool color_conversion_successful = skcms_Transform(
            src_ptr, color_format, alpha_format, xform->SrcProfile(), xform_dst,
            color_format, alpha_format, xform->DstProfile(), width);
        DCHECK(color_conversion_successful);
        src_ptr = png_bytep(xform_dst);
      }

      unsigned alpha_mask = 255;
      if (frame_buffer_cache_[current_frame_].GetAlphaBlendSource() ==
          ImageFrame::kBlendAtopBgcolor) {
        if (buffer.PremultiplyAlpha()) {
#if (defined(__ARM_NEON__) || defined(__ARM_NEON))
          SetRGBAPremultiplyRowNeon(src_ptr, width, dst_row, &alpha_mask);
#else
          for (auto* dst_pixel = dst_row; dst_pixel < dst_row + width;
               dst_pixel++, src_ptr += 4) {
            ImageFrame::SetRGBAPremultiply(dst_pixel, src_ptr[0], src_ptr[1],
                                           src_ptr[2], src_ptr[3]);
            alpha_mask &= src_ptr[3];
          }
#endif
        } else {
#if (defined(__ARM_NEON__) || defined(__ARM_NEON))
          SetRGBARawRowNeon(src_ptr, width, dst_row, &alpha_mask);
#else
          for (auto* dst_pixel = dst_row; dst_pixel < dst_row + width;
               dst_pixel++, src_ptr += 4) {
            ImageFrame::SetRGBARaw(dst_pixel, src_ptr[0], src_ptr[1],
                                   src_ptr[2], src_ptr[3]);
            alpha_mask &= src_ptr[3];
          }
#endif
        }
      } else {
        // Now, the blend method is ImageFrame::BlendAtopPreviousFrame. Since
        // the frame data of the previous frame is copied at InitFrameBuffer, we
        // can blend the pixel of this frame, stored in |src_ptr|, over the
        // previous pixel stored in |dst_pixel|.
        if (buffer.PremultiplyAlpha()) {
          for (auto* dst_pixel = dst_row; dst_pixel < dst_row + width;
               dst_pixel++, src_ptr += 4) {
            ImageFrame::BlendRGBAPremultiplied(
                dst_pixel, src_ptr[0], src_ptr[1], src_ptr[2], src_ptr[3]);
            alpha_mask &= src_ptr[3];
          }
        } else {
          for (auto* dst_pixel = dst_row; dst_pixel < dst_row + width;
               dst_pixel++, src_ptr += 4) {
            ImageFrame::BlendRGBARaw(dst_pixel, src_ptr[0], src_ptr[1],
                                     src_ptr[2], src_ptr[3]);
            alpha_mask &= src_ptr[3];
          }
        }
      }

      if (alpha_mask != 255) {
        current_buffer_saw_alpha_ = true;
      }

    } else {
#if (defined(__ARM_NEON__) || defined(__ARM_NEON))
      SetRGBARawRowNoAlphaNeon(src_ptr, width, dst_row);
#else
      for (auto* dst_pixel = dst_row; dst_pixel < dst_row + width;
           src_ptr += 3, ++dst_pixel) {
        ImageFrame::SetRGBARaw(dst_pixel, src_ptr[0], src_ptr[1], src_ptr[2],
                               255);
      }
#endif
      // We'll apply the color space xform to opaque pixels after they have been
      // written to the ImageFrame.
      // TODO: Apply the xform to the RGB pixels, skipping second pass over
      // data.
      if (ColorProfileTransform* xform =
```