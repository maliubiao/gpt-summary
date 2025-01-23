Response:
My thinking process to answer the request about the `jpeg_image_decoder.cc` file goes like this:

1. **Understand the Core Request:** The user wants to know the *functionality* of this C++ file within the Chromium Blink engine. They also want to know how it relates to web technologies (HTML, CSS, JavaScript) and if there are any common usage errors or logical deductions I can make. Crucially, they've marked this as "part 1 of 2" and want a summary of the functionality *so far*.

2. **Analyze the File Path:** `blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder.cc`  This path immediately tells me:
    * It's part of the Blink rendering engine.
    * It's located in the "platform" layer, suggesting it interacts with OS-level graphics or decoding libraries.
    * It's specifically for "image decoders," narrowing down its purpose significantly.
    * It's for "JPEG" images, making its primary function clear.

3. **Skim the Initial Comments:** The copyright and licensing information are important for context but don't directly describe functionality. The `#ifdef UNSAFE_BUFFERS_BUILD` section is a potential area of interest for safety concerns but is conditional and marked as a TODO, so I'll note it but not dwell on it for the initial summary.

4. **Identify Key Includes:**  The `#include` directives are crucial:
    * Standard C++ libraries (`limits`, `memory`).
    * Chromium base libraries (`logging`, `memory`, `numerics`, `trace_event`). This indicates integration with Chromium's infrastructure.
    * Blink platform libraries (`bitmap_image_metrics`).
    * Skia graphics library (`SkColorSpace`, `SkJpegMetadataDecoder`). This is a major dependency for image processing in Chrome.
    * `jpeglib.h`. This confirms the file uses the standard libjpeg (or a variant) for JPEG decoding.

5. **Focus on the `namespace blink {` Section:** This is where the core logic resides.

6. **Identify Key Structures and Classes:**
    * `decoder_error_mgr`: Handles error conditions during JPEG decoding, using `setjmp`/`longjmp` for non-local control flow.
    * `decoder_source_mgr`: Manages the input data stream for libjpeg.
    * `JPEGImageReader`:  This is the central class. It encapsulates the libjpeg decompression state, manages input data, and interacts with the `JPEGImageDecoder`. I'll focus on its methods.
    * `JPEGImageDecoder`:  The public interface for decoding JPEG images. It likely integrates with Blink's image loading pipeline.

7. **Analyze `JPEGImageReader` Methods (High-Level):**  I'll go through the methods and summarize their purpose:
    * Constructor/Destructor: Initializes and cleans up libjpeg structures.
    * `SkipBytes`, `FillBuffer`, `SetData`: Methods for managing the input data stream, crucial for handling potentially incomplete downloads and data updates.
    * `ShouldDecodeToOriginalSize`, `AreValidSampleFactorsAvailable`: Helper methods for determining decoding parameters.
    * `Decode`: The main decoding logic. This method handles the different stages of JPEG decoding (header parsing, decompression, progressive vs. sequential decoding). I'll note the different `jstate` values.
    * `Info`, `Samples`, `Decoder`, `UvSize`, `HasStartedDecompression`, `GetMetadataDecoder`: Accessors and utility methods.
    * `AllocateSampleArray`, `UpdateRestartPosition`, `ClearBuffer`: Internal helper methods for managing memory and state.

8. **Analyze `JPEGImageDecoder` Methods (High-Level):**
    * Constructor/Destructor: Initialization.
    * `FilenameExtension`, `MimeType`:  Provides metadata about the supported image type.
    * `SetSize`, `OnSetData`, `DecodedSize`, `SetDecodedSize`, `DecodeImage`:  These methods are part of Blink's image decoding interface, handling setting image dimensions, providing data, and performing the actual decoding.

9. **Identify Relationships to Web Technologies:**
    * **HTML `<img>` tag:**  This decoder is used when the browser encounters an `<img>` tag with a `src` attribute pointing to a JPEG image.
    * **CSS `background-image`:** Similar to the `<img>` tag, this decoder is invoked when a CSS rule specifies a JPEG image as a background.
    * **JavaScript (via Canvas API or Fetch API):** When JavaScript loads or manipulates image data (e.g., using `drawImage` on a canvas or processing the response of a `fetch` request), this decoder might be involved.

10. **Look for Logical Deductions/Assumptions:**
    * **Progressive JPEG handling:** The code mentions `kJpegDecompressProgressive`, indicating support for progressively loaded JPEGs.
    * **Error Handling:** The use of `setjmp`/`longjmp` suggests a mechanism for handling fatal decoding errors.
    * **Metadata Extraction:** The use of `SkJpegMetadataDecoder` indicates the ability to extract EXIF and ICC profile data.
    * **YUV Decoding:** The presence of `kDecodeToYuv` suggests optimizations for video or other use cases where direct YUV data is needed.

11. **Scan for Potential User/Programming Errors:**
    * **Corrupt JPEGs:** The code has logic to detect and handle "Corrupt JPEG" warnings.
    * **Memory Limits:** The `max_decoded_bytes` parameter and the logic around `DesiredScaleNumerator` point to preventing excessive memory usage.
    * **Incomplete Data:** The handling of `JPEG_SUSPENDED` suggests the decoder can deal with partially downloaded images.

12. **Structure the Summary for Part 1:** Since this is part 1, I will focus on the core decoding functionality, the main classes involved, and the interactions with web technologies. I will avoid going into too much detail about the later stages of decoding or potential optimizations, as those might be covered in part 2.

13. **Review and Refine:** I will read through my summary to ensure it's accurate, concise, and addresses all aspects of the user's request for part 1. I will make sure to explicitly mention that this is a summary of the functionality *covered in the provided code snippet*.

By following these steps, I can systematically analyze the provided code and generate a comprehensive and informative answer that meets the user's request. The key is to move from the general to the specific, identifying the main components and their roles before delving into the finer details.
好的，根据您提供的 blink 引擎源代码文件 `jpeg_image_decoder.cc` 的内容，以下是其功能的归纳：

**核心功能：JPEG 图像解码**

这个文件的主要功能是实现 JPEG 图像的解码。它负责将 JPEG 格式的图像数据转换成浏览器可以渲染的像素数据（通常是 RGBA 格式）。

**具体功能点：**

1. **数据接收与管理:**
   -  接收包含 JPEG 图像数据的 `SegmentReader` 对象。
   -  维护解码过程中的数据读取位置、缓冲区状态等信息。
   -  支持分段读取数据，能够处理网络传输等场景下逐步到达的图像数据。

2. **Libjpeg 接口封装:**
   -  作为 libjpeg 库的接口，用于实际的 JPEG 解码操作。
   -  配置 libjpeg 的解码参数，例如输出颜色空间、缩放比例、抖动模式等。
   -  处理 libjpeg 的错误和警告信息。

3. **JPEG 头信息解析:**
   -  使用 libjpeg 读取 JPEG 文件的头信息 (`jpeg_read_header`)，获取图像的尺寸、颜色空间等基本信息。
   -  提取 JPEG 文件中的 APP1 和 APP2 段，用于获取 EXIF、XMP 和 ICC Profile 等元数据。

4. **图像缩放:**
   -  根据需要，支持对 JPEG 图像进行缩放解码。
   -  `DesiredScaleNumerator()` 函数可能用于确定合适的缩放比例，以优化内存使用或满足特定需求。
   -  能根据内存限制和图像尺寸，决定是否应该使用 libjpeg 进行缩放，或者解码到原始大小。

5. **逐行解码 (Scanline Output):**
   -  支持顺序解码和渐进式解码两种模式。
   -  将解码后的像素数据逐行输出，供 Blink 引擎的后续渲染流程使用。

6. **元数据处理:**
   -  使用 `SkJpegMetadataDecoder` 解析 JPEG 文件中的元数据。
   -  应用 EXIF 元数据，例如图像方向，用于正确的图像显示。
   -  处理 ICC Profile 信息，用于色彩管理，确保颜色显示的准确性。

7. **YUV 解码支持 (可选):**
   -  可能支持直接解码成 YUV 格式，用于某些特定的渲染或处理场景，例如视频解码。
   -  通过 `kDecodeToYuv` 解码模式，可以绕过转换为 RGB 的步骤，直接输出 YUV 数据。

8. **错误处理与恢复:**
   -  使用 `setjmp`/`longjmp` 机制处理 libjpeg 抛出的致命错误。
   -  统计并处理 JPEG 解码过程中的警告信息，特别是关于图像损坏的警告。

9. **性能优化:**
   -  使用 libjpeg-turbo 库（通过条件编译 `#ifdef TURBO_JPEG_RGB_SWIZZLE` 可以看出），可能利用其 SIMD 等优化特性来提升解码速度。
   -  对于渐进式 JPEG，会控制解码的 scan 次数，避免因 scan 过多而导致的性能问题。

**与 JavaScript, HTML, CSS 的关系举例:**

1. **HTML `<img>` 标签:** 当 HTML 中使用 `<img>` 标签加载一个 JPEG 图片时，Blink 引擎会调用 `JPEGImageDecoder` 来解码该图片数据，并将解码后的像素信息用于渲染到页面上。

   ```html
   <img src="image.jpg">
   ```

   **假设输入:** `image.jpg` 的 JPEG 数据流。
   **输出:** 解码后的 RGBA 像素数据，供渲染引擎使用。

2. **CSS `background-image` 属性:**  类似地，当 CSS 中使用 `background-image` 属性指定一个 JPEG 图片作为背景时，`JPEGImageDecoder` 也会被调用进行解码。

   ```css
   .element {
     background-image: url("background.jpeg");
   }
   ```

   **假设输入:** `background.jpeg` 的 JPEG 数据流。
   **输出:** 解码后的 RGBA 像素数据，用于绘制元素的背景。

3. **JavaScript Canvas API:** JavaScript 可以通过 Canvas API 加载和绘制图片。当加载的图片是 JPEG 格式时，`JPEGImageDecoder` 负责解码。

   ```javascript
   const image = new Image();
   image.onload = function() {
     const canvas = document.getElementById('myCanvas');
     const ctx = canvas.getContext('2d');
     ctx.drawImage(image, 0, 0);
   };
   image.src = 'my_image.jpg';
   ```

   **假设输入:** `my_image.jpg` 的 JPEG 数据流。
   **输出:** 解码后的 RGBA 像素数据，可以通过 Canvas API 绘制到画布上。

4. **JavaScript Fetch API:**  使用 Fetch API 获取 JPEG 图像数据后，Blink 引擎在渲染或进一步处理该数据时，会使用 `JPEGImageDecoder` 进行解码。

   ```javascript
   fetch('data.jpg')
     .then(response => response.blob())
     .then(blob => createImageBitmap(blob))
     .then(imageBitmap => {
       // 使用 imageBitmap 进行渲染
     });
   ```

   **假设输入:** `data.jpg` 的 JPEG 数据流。
   **输出:** 解码后的 `ImageBitmap` 对象，其中包含了像素数据。

**逻辑推理的假设输入与输出:**

* **假设输入:** 一个包含有效 JPEG 图像数据的 `SegmentReader` 对象。
* **输出:**  成功解码后，会调用 `ImageDecoder::SetSize()` 设置图像尺寸，调用 `ImageDecoder::SetDecodedSize()` 设置解码后的尺寸，并通过 `OutputScanlines()` 输出解码后的像素行数据。如果解码失败，则调用 `SetFailed()`。

* **假设输入:** 一个包含渐进式 JPEG 图像数据的 `SegmentReader` 对象。
* **输出:**  会先解码出部分数据用于初步渲染，随着更多数据到达，会逐步解码并更新图像显示，最终完成完整解码。

**用户或编程常见的使用错误举例:**

1. **加载损坏的 JPEG 文件:**
   - **错误:** 用户可能尝试加载一个文件内容被破坏或不完整的 JPEG 文件。
   - **结果:** `JPEGImageDecoder` 可能会检测到错误，并调用 `SetFailed()`，导致图像无法正常显示或显示不完整。控制台可能会输出 libjpeg 的警告信息 "Corrupt JPEG"。

2. **内存限制不足:**
   - **错误:**  如果解码的图像尺寸过大，超过了浏览器或系统的内存限制。
   - **结果:**  解码可能会失败，或者为了避免内存溢出，解码器可能会选择解码到较小的尺寸。

3. **尝试在解码开始后更改 YUV 解码模式:**
   - **错误:**  在调用 `Decode()` 开始解码后，尝试修改是否解码为 YUV 格式的设置。
   - **结果:**  代码中 `reader_->HasStartedDecompression()` 的检查会阻止这种修改，因为在解码过程中改变输出格式可能会导致不可预测的结果。

**功能归纳 (第 1 部分):**

在您提供的代码片段中，`JPEGImageDecoder` 的主要功能可以归纳为：

* **初始化和配置 JPEG 解码器:**  创建和配置 libjpeg 的解码对象，设置错误处理、数据源等。
* **接收和管理 JPEG 图像数据:**  从 `SegmentReader` 中读取 JPEG 数据，并维护解码过程中的数据读取状态。
* **解析 JPEG 文件头信息:**  读取并解析 JPEG 文件头，获取图像的基本信息和元数据。
* **初步处理解码参数:**  根据需求计算和设置解码的缩放比例等参数。
* **支持从 JPEG 头信息中提取元数据:**  使用 `SkJpegMetadataDecoder` 提取 EXIF 和 ICC Profile 信息。
* **准备开始进行 JPEG 解码:**  设置解码器的状态为开始解码。

这部分代码主要关注于解码前的准备工作，包括数据接收、头信息解析和参数配置。 实际的像素解码操作可能会在 `Decode()` 方法的后续状态中进行（`kJpegDecompressSequential` 或 `kJpegDecompressProgressive`）。

### 提示词
```
这是目录为blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2006 Apple Computer, Inc.
 *
 * Portions are Copyright (C) 2001-6 mozilla.org
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

#include "third_party/blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder.h"

#include <limits>
#include <memory>

#include "base/logging.h"
#include "base/memory/raw_ptr.h"
#include "base/numerics/checked_math.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/platform/graphics/bitmap_image_metrics.h"
#include "third_party/skia/include/core/SkColorSpace.h"
#include "third_party/skia/include/private/SkJpegMetadataDecoder.h"

extern "C" {
#include <setjmp.h>
#include <stdio.h>  // jpeglib.h needs stdio FILE.
#include "jpeglib.h"
}

#if defined(ARCH_CPU_BIG_ENDIAN)
#error Blink assumes a little-endian target.
#endif

#if defined(JCS_ALPHA_EXTENSIONS)
#define TURBO_JPEG_RGB_SWIZZLE
#if SK_B32_SHIFT  // Output little-endian RGBA pixels (Android).
inline J_COLOR_SPACE rgbOutputColorSpace() {
  return JCS_EXT_RGBA;
}
#else  // Output little-endian BGRA pixels.
inline J_COLOR_SPACE rgbOutputColorSpace() {
  return JCS_EXT_BGRA;
}
#endif
inline bool turboSwizzled(J_COLOR_SPACE colorSpace) {
  return colorSpace == JCS_EXT_RGBA || colorSpace == JCS_EXT_BGRA;
}
#else
inline J_COLOR_SPACE rgbOutputColorSpace() {
  return JCS_RGB;
}
#endif

namespace {

// JPEG only supports a denominator of 8.
const unsigned g_scale_denominator = 8;

// Extracts the YUV subsampling format of an image given |info| which is assumed
// to have gone through a jpeg_read_header() call.
cc::YUVSubsampling YuvSubsampling(const jpeg_decompress_struct& info) {
  if (info.jpeg_color_space == JCS_YCbCr && info.num_components == 3 &&
      info.comp_info && info.comp_info[1].h_samp_factor == 1 &&
      info.comp_info[1].v_samp_factor == 1 &&
      info.comp_info[2].h_samp_factor == 1 &&
      info.comp_info[2].v_samp_factor == 1) {
    const int h = info.comp_info[0].h_samp_factor;
    const int v = info.comp_info[0].v_samp_factor;
    if (v == 1) {
      switch (h) {
        case 1:
          return cc::YUVSubsampling::k444;
        case 2:
          return cc::YUVSubsampling::k422;
        case 4:
          return cc::YUVSubsampling::k411;
      }
    } else if (v == 2) {
      switch (h) {
        case 1:
          return cc::YUVSubsampling::k440;
        case 2:
          return cc::YUVSubsampling::k420;
        case 4:
          return cc::YUVSubsampling::k410;
      }
    }
  }
  return cc::YUVSubsampling::kUnknown;
}

bool SubsamplingSupportedByDecodeToYUV(cc::YUVSubsampling subsampling) {
  // Only subsamplings 4:4:4, 4:2:2, and 4:2:0 are supported.
  return subsampling == cc::YUVSubsampling::k444 ||
         subsampling == cc::YUVSubsampling::k422 ||
         subsampling == cc::YUVSubsampling::k420;
}

// Rounds |size| to the smallest multiple of |alignment| that is greater than or
// equal to |size|.
// Note that base::bits::Align is not used here because the alignment is not
// guaranteed to be a power of two.
int Align(int size, int alignment) {
  // Width and height are 16 bits for a JPEG (i.e. < 65536) and the maximum
  // size of a JPEG MCU in either dimension is 8 * 4 == 32.
  DCHECK_GE(size, 0);
  DCHECK_LT(size, 1 << 16);
  DCHECK_GT(alignment, 0);
  DCHECK_LE(alignment, 32);

  if (size % alignment == 0) {
    return size;
  }

  return ((size + alignment) / alignment) * alignment;
}

}  // namespace

namespace blink {

struct decoder_error_mgr {
  DISALLOW_NEW();
  struct jpeg_error_mgr pub;  // "public" fields for IJG library
  int num_corrupt_warnings;   // Counts corrupt warning messages
  jmp_buf setjmp_buffer;      // For handling catastropic errors
};

struct decoder_source_mgr {
  DISALLOW_NEW();
  struct jpeg_source_mgr pub;  // "public" fields for IJG library
  raw_ptr<JPEGImageReader> reader;
};

enum jstate {
  kJpegHeader,  // Reading JFIF headers
  kJpegStartDecompress,
  kJpegDecompressProgressive,  // Output progressive pixels
  kJpegDecompressSequential,   // Output sequential pixels
  kJpegDone
};

void init_source(j_decompress_ptr jd);
boolean fill_input_buffer(j_decompress_ptr jd);
void skip_input_data(j_decompress_ptr jd, long num_bytes);
void term_source(j_decompress_ptr jd);
void error_exit(j_common_ptr cinfo);
void emit_message(j_common_ptr cinfo, int msg_level);

static gfx::Size ComputeYUVSize(const jpeg_decompress_struct* info,
                                int component) {
  return gfx::Size(info->comp_info[component].downsampled_width,
                   info->comp_info[component].downsampled_height);
}

static wtf_size_t ComputeYUVWidthBytes(const jpeg_decompress_struct* info,
                                       int component) {
  return info->comp_info[component].width_in_blocks * DCTSIZE;
}

static void ProgressMonitor(j_common_ptr info) {
  int scan = ((j_decompress_ptr)info)->input_scan_number;
  // Progressive images with a very large number of scans can cause the
  // decoder to hang.  Here we use the progress monitor to abort on
  // a very large number of scans.  100 is arbitrary, but much larger
  // than the number of scans we might expect in a normal image.
  if (scan >= 100) {
    error_exit(info);
  }
}

class JPEGImageReader final {
  USING_FAST_MALLOC(JPEGImageReader);

 public:
  JPEGImageReader(JPEGImageDecoder* decoder, wtf_size_t initial_offset)
      : decoder_(decoder),
        needs_restart_(false),
        restart_position_(initial_offset),
        next_read_position_(initial_offset),
        last_set_byte_(nullptr),
        state_(kJpegHeader),
        samples_(nullptr) {
    memset(&info_, 0, sizeof(jpeg_decompress_struct));

    // Set up the normal JPEG error routines, then override error_exit.
    info_.err = jpeg_std_error(&err_.pub);
    err_.pub.error_exit = error_exit;

    // Allocate and initialize JPEG decompression object.
    jpeg_create_decompress(&info_);

    // Initialize source manager.
    memset(&src_, 0, sizeof(decoder_source_mgr));
    info_.src = reinterpret_cast_ptr<jpeg_source_mgr*>(&src_);

    // Set up callback functions.
    src_.pub.init_source = init_source;
    src_.pub.fill_input_buffer = fill_input_buffer;
    src_.pub.skip_input_data = skip_input_data;
    src_.pub.resync_to_restart = jpeg_resync_to_restart;
    src_.pub.term_source = term_source;
    src_.reader = this;

    // Set up a progress monitor.
    info_.progress = &progress_mgr_;
    progress_mgr_.progress_monitor = ProgressMonitor;

    // Keep APP1 blocks, for obtaining exif and XMP data.
    jpeg_save_markers(&info_, JPEG_APP0 + 1, 0xFFFF);

    // Keep APP2 blocks, for obtaining ICC and MPF data.
    jpeg_save_markers(&info_, JPEG_APP0 + 2, 0xFFFF);
  }

  JPEGImageReader(const JPEGImageReader&) = delete;
  JPEGImageReader& operator=(const JPEGImageReader&) = delete;

  ~JPEGImageReader() {
    // Reset `metadata_decoder_` before `info_` because `metadata_decoder_`
    // points to memory owned by `info_`.
    metadata_decoder_ = nullptr;
    jpeg_destroy_decompress(&info_);
  }

  void SkipBytes(long num_bytes) {
    if (num_bytes <= 0) {
      return;
    }

    wtf_size_t bytes_to_skip = static_cast<wtf_size_t>(num_bytes);

    if (bytes_to_skip < info_.src->bytes_in_buffer) {
      // The next byte needed is in the buffer. Move to it.
      info_.src->bytes_in_buffer -= bytes_to_skip;
      info_.src->next_input_byte += bytes_to_skip;
    } else {
      // Move beyond the buffer and empty it.
      next_read_position_ = static_cast<wtf_size_t>(
          next_read_position_ + bytes_to_skip - info_.src->bytes_in_buffer);
      info_.src->bytes_in_buffer = 0;
      info_.src->next_input_byte = nullptr;
    }

    // This is a valid restart position.
    restart_position_ = static_cast<wtf_size_t>(next_read_position_ -
                                                info_.src->bytes_in_buffer);
    // We updated |next_input_byte|, so we need to update |last_byte_set_|
    // so we know not to update |restart_position_| again.
    last_set_byte_ = info_.src->next_input_byte;
  }

  bool FillBuffer() {
    if (needs_restart_) {
      needs_restart_ = false;
      next_read_position_ = restart_position_;
    } else {
      UpdateRestartPosition();
    }

    base::span<const uint8_t> segment = data_->GetSomeData(next_read_position_);
    if (segment.empty()) {
      // We had to suspend. When we resume, we will need to start from the
      // restart position.
      needs_restart_ = true;
      ClearBuffer();
      return false;
    }

    next_read_position_ += segment.size();
    info_.src->bytes_in_buffer = segment.size();
    auto* next_byte = reinterpret_cast_ptr<const JOCTET*>(segment.data());
    info_.src->next_input_byte = next_byte;
    last_set_byte_ = next_byte;
    return true;
  }

  void SetData(scoped_refptr<SegmentReader> data) {
    if (data_ == data) {
      return;
    }

    data_ = std::move(data);

    // If a restart is needed, the next call to fillBuffer will read from the
    // new SegmentReader.
    if (needs_restart_) {
      return;
    }

    // Otherwise, empty the buffer, and leave the position the same, so
    // FillBuffer continues reading from the same position in the new
    // SegmentReader.
    next_read_position_ -= info_.src->bytes_in_buffer;
    ClearBuffer();
  }

  bool ShouldDecodeToOriginalSize() const {
    // We should decode only to original size if either dimension cannot fit a
    // whole number of MCUs.
    const int max_h_samp_factor = info_.max_h_samp_factor;
    const int max_v_samp_factor = info_.max_v_samp_factor;
    DCHECK_GE(max_h_samp_factor, 1);
    DCHECK_GE(max_v_samp_factor, 1);
    DCHECK_LE(max_h_samp_factor, 4);
    DCHECK_LE(max_v_samp_factor, 4);
    const int mcu_width = info_.max_h_samp_factor * DCTSIZE;
    const int mcu_height = info_.max_v_samp_factor * DCTSIZE;
    return info_.image_width % mcu_width != 0 ||
           info_.image_height % mcu_height != 0;
  }

  // Whether or not the horizontal and vertical sample factors of all components
  // hold valid values (i.e. 1, 2, 3, or 4). It also returns the maximal
  // horizontal and vertical sample factors via |max_h| and |max_v|.
  bool AreValidSampleFactorsAvailable(int* max_h, int* max_v) const {
    if (!info_.num_components) {
      return false;
    }

    const jpeg_component_info* comp_info = info_.comp_info;
    if (!comp_info) {
      return false;
    }

    *max_h = 0;
    *max_v = 0;
    for (int i = 0; i < info_.num_components; ++i) {
      if (comp_info[i].h_samp_factor < 1 || comp_info[i].h_samp_factor > 4 ||
          comp_info[i].v_samp_factor < 1 || comp_info[i].v_samp_factor > 4) {
        return false;
      }

      *max_h = std::max(*max_h, comp_info[i].h_samp_factor);
      *max_v = std::max(*max_v, comp_info[i].v_samp_factor);
    }
    return true;
  }

  // Decode the JPEG data.
  bool Decode(JPEGImageDecoder::DecodingMode decoding_mode) {
    // We need to do the setjmp here. Otherwise bad things will happen
    if (setjmp(err_.setjmp_buffer)) {
      return decoder_->SetFailed();
    }

    switch (state_) {
      case kJpegHeader: {
        // Read file parameters with jpeg_read_header().
        if (jpeg_read_header(&info_, true) == JPEG_SUSPENDED) {
          return false;  // I/O suspension.
        }

        switch (info_.jpeg_color_space) {
          case JCS_YCbCr:
            [[fallthrough]];  // libjpeg can convert YCbCr image pixels to RGB.
          case JCS_GRAYSCALE:
            [[fallthrough]];  // libjpeg can convert GRAYSCALE image pixels to
                              // RGB.
          case JCS_RGB:
            info_.out_color_space = rgbOutputColorSpace();
            break;
          case JCS_CMYK:
          case JCS_YCCK:
            // libjpeg can convert YCCK to CMYK, but neither to RGB, so we
            // manually convert CMKY to RGB.
            info_.out_color_space = JCS_CMYK;
            break;
          default:
            return decoder_->SetFailed();
        }

        state_ = kJpegStartDecompress;

        // Build the SkJpegMetadataDecoder to extract metadata from the
        // now-complete header.
        {
          std::vector<SkJpegMetadataDecoder::Segment> segments;
          for (auto* marker = info_.marker_list; marker;
               marker = marker->next) {
            segments.emplace_back(
                marker->marker,
                SkData::MakeWithoutCopy(marker->data, marker->data_length));
          }
          metadata_decoder_ = SkJpegMetadataDecoder::Make(std::move(segments));
        }

        // We can fill in the size now that the header is available.
        if (!decoder_->SetSize(info_.image_width, info_.image_height)) {
          return false;
        }

        // Calculate and set decoded size.
        int max_numerator = decoder_->DesiredScaleNumerator();
        info_.scale_denom = g_scale_denominator;

        if (decoder_->ShouldGenerateAllSizes()) {
          // Some images should not be scaled down by libjpeg_turbo because
          // doing so may cause artifacts. Specifically, if the image contains a
          // non-whole number of MCUs in either dimension, it's possible that
          // the encoder used bogus data to create the last row or column of
          // MCUs. This data may manifest when downscaling using libjpeg_turbo.
          // See https://crbug.com/890745 and
          // https://github.com/libjpeg-turbo/libjpeg-turbo/issues/297. Hence,
          // we'll only allow downscaling an image if both dimensions fit a
          // whole number of MCUs or if decoding to the original size would
          // cause us to exceed memory limits. The latter case is detected by
          // checking the |max_numerator| returned by DesiredScaleNumerator():
          // this method will return either |g_scale_denominator| if decoding to
          // the original size won't exceed the memory limit (see
          // |max_decoded_bytes_| in ImageDecoder) or something less than
          // |g_scale_denominator| otherwise to ensure the image is downscaled.
          Vector<SkISize> sizes;
          if (max_numerator == g_scale_denominator &&
              ShouldDecodeToOriginalSize()) {
            sizes.push_back(
                SkISize::Make(info_.image_width, info_.image_height));
          } else {
            sizes.reserve(max_numerator);
            for (int numerator = 1; numerator <= max_numerator; ++numerator) {
              info_.scale_num = numerator;
              jpeg_calc_output_dimensions(&info_);
              sizes.push_back(
                  SkISize::Make(info_.output_width, info_.output_height));
            }
          }
          decoder_->SetSupportedDecodeSizes(std::move(sizes));
        }

        info_.scale_num = max_numerator;
        jpeg_calc_output_dimensions(&info_);
        decoder_->SetDecodedSize(info_.output_width, info_.output_height);

        decoder_->ApplyExifMetadata(
            metadata_decoder_->getExifMetadata(/*copyData=*/false).get(),
            gfx::Size(info_.output_width, info_.output_height));

        // Allow color management of the decoded RGBA pixels if possible.
        if (!decoder_->IgnoresColorSpace()) {
          // Extract the ICC profile data without copying it (the function
          // ColorProfile::Create will make its own copy).
          sk_sp<SkData> profile_data =
              metadata_decoder_->getICCProfileData(/*copyData=*/false);
          if (profile_data) {
            std::unique_ptr<ColorProfile> profile = ColorProfile::Create(
                base::span(profile_data->bytes(), profile_data->size()));
            if (profile) {
              uint32_t data_color_space =
                  profile->GetProfile()->data_color_space;
              switch (info_.jpeg_color_space) {
                case JCS_CMYK:
                case JCS_YCCK:
                  if (data_color_space != skcms_Signature_CMYK) {
                    profile = nullptr;
                  }
                  break;
                case JCS_GRAYSCALE:
                  if (data_color_space != skcms_Signature_Gray &&
                      data_color_space != skcms_Signature_RGB) {
                    profile = nullptr;
                  }
                  break;
                default:
                  if (data_color_space != skcms_Signature_RGB) {
                    profile = nullptr;
                  }
                  break;
              }
              if (profile) {
                Decoder()->SetEmbeddedColorProfile(std::move(profile));
              }
            } else {
              DLOG(ERROR) << "Failed to parse image ICC profile";
            }
          }
        }

        // Don't allocate a giant and superfluous memory buffer when the
        // image is a sequential JPEG.
        info_.buffered_image = jpeg_has_multiple_scans(&info_);
        if (info_.buffered_image) {
          err_.pub.emit_message = emit_message;
          err_.num_corrupt_warnings = 0;
        }

        if (decoding_mode == JPEGImageDecoder::DecodingMode::kDecodeHeader) {
          // This exits the function while there is still potentially
          // data in the buffer. Before this function is called again,
          // the SharedBuffer may be collapsed (by a call to
          // MergeSegmentsIntoBuffer), invalidating the "buffer" (which
          // in reality is a pointer into the SharedBuffer's data).
          // Defensively empty the buffer, but first find the latest
          // restart position and signal to restart, so the next call to
          // FillBuffer will resume from the correct point.
          needs_restart_ = true;
          UpdateRestartPosition();
          ClearBuffer();
          return true;
        }
      }
        [[fallthrough]];
      case kJpegStartDecompress:
        if (decoding_mode == JPEGImageDecoder::DecodingMode::kDecodeToYuv) {
          DCHECK(decoder_->CanDecodeToYUV());
          DCHECK(decoder_->HasImagePlanes());
          info_.out_color_space = JCS_YCbCr;
          info_.raw_data_out = TRUE;
          uv_size_ = ComputeYUVSize(&info_, 1);
          // U size and V size have to be the same if we got here
          DCHECK_EQ(uv_size_, ComputeYUVSize(&info_, 2));
        }

        // Set parameters for decompression.
        // FIXME -- Should reset dct_method and dither mode for final pass
        // of progressive JPEG.
        info_.dct_method = JDCT_ISLOW;
        info_.dither_mode = JDITHER_FS;
        info_.do_fancy_upsampling = true;
        info_.do_block_smoothing = true;
        info_.enable_2pass_quant = false;
        // FIXME: should we just assert these?
        info_.enable_external_quant = false;
        info_.enable_1pass_quant = false;
        info_.quantize_colors = false;
        info_.colormap = nullptr;

        // Make a one-row-high sample array that will go away when done with
        // image. Always make it big enough to hold one RGBA row. Since this
        // uses the IJG memory manager, it must be allocated before the call
        // to jpeg_start_decompress().
        samples_ = AllocateSampleArray();

        // Start decompressor.
        if (!jpeg_start_decompress(&info_)) {
          return false;  // I/O suspension.
        }

        // If this is a progressive JPEG ...
        state_ = (info_.buffered_image) ? kJpegDecompressProgressive
                                        : kJpegDecompressSequential;
        [[fallthrough]];

      case kJpegDecompressSequential:
        if (state_ == kJpegDecompressSequential) {
          if (!decoder_->OutputScanlines()) {
            return false;  // I/O suspension.
          }

          // If we've completed image output...
          DCHECK_EQ(info_.output_scanline, info_.output_height);
          state_ = kJpegDone;
        }
        [[fallthrough]];

      case kJpegDecompressProgressive:
        if (state_ == kJpegDecompressProgressive) {
          auto all_components_seen = [](const jpeg_decompress_struct& info) {
            if (info.coef_bits) {
              for (int c = 0; c < info.num_components; ++c) {
                if (info.coef_bits[c][0] == -1) {
                  // Haven't seen this component yet.
                  return false;
                }
              }
            }
            return true;
          };
          int status = 0;
          int first_scan_to_display =
              all_components_seen(info_) ? info_.input_scan_number : 0;
          do {
            decoder_error_mgr* err =
                reinterpret_cast_ptr<decoder_error_mgr*>(info_.err);
            if (err->num_corrupt_warnings) {
              break;
            }
            status = jpeg_consume_input(&info_);
            if (status == JPEG_REACHED_SOS || status == JPEG_REACHED_EOI ||
                status == JPEG_SUSPENDED) {
              // record the first scan where all components are present
              if (!first_scan_to_display && all_components_seen(info_)) {
                first_scan_to_display = info_.input_scan_number;
              }
            }
          } while (!(status == JPEG_SUSPENDED || status == JPEG_REACHED_EOI));

          if (!first_scan_to_display) {
            return false;  // I/O suspension
          }

          for (;;) {
            if (!info_.output_scanline) {
              int scan = info_.input_scan_number;

              // If we haven't displayed anything yet
              // (output_scan_number == 0) and we have enough data for
              // a complete scan, force output of the last full scan, but only
              // if this last scan has seen DC data from all components.
              if (!info_.output_scan_number && (scan > first_scan_to_display) &&
                  (status != JPEG_REACHED_EOI)) {
                --scan;
              }

              if (!jpeg_start_output(&info_, scan)) {
                return false;  // I/O suspension.
              }
            }

            if (info_.output_scanline == 0xffffff) {
              info_.output_scanline = 0;
            }

            if (!decoder_->OutputScanlines()) {
              if (decoder_->Failed()) {
                return false;
              }
              // If no scan lines were read, flag it so we don't call
              // jpeg_start_output() multiple times for the same scan.
              if (!info_.output_scanline) {
                info_.output_scanline = 0xffffff;
              }

              return false;  // I/O suspension.
            }

            if (info_.output_scanline == info_.output_height) {
              if (!jpeg_finish_output(&info_)) {
                return false;  // I/O suspension.
              }

              if (jpeg_input_complete(&info_) &&
                  (info_.input_scan_number == info_.output_scan_number)) {
                break;
              }

              info_.output_scanline = 0;
            }
          }

          state_ = kJpegDone;
        }
        [[fallthrough]];

      case kJpegDone:
        // Finish decompression.
        if (info_.jpeg_color_space != JCS_GRAYSCALE &&
            decoder_->IsAllDataReceived()) {
          static constexpr char kType[] = "Jpeg";
          ImageDecoder::UpdateBppHistogram<kType>(decoder_->Size(),
                                                  data_->size());
        }
        return jpeg_finish_decompress(&info_);
    }

    return true;
  }

  jpeg_decompress_struct* Info() { return &info_; }
  JSAMPARRAY Samples() const { return samples_; }
  JPEGImageDecoder* Decoder() { return decoder_; }
  gfx::Size UvSize() const { return uv_size_; }
  bool HasStartedDecompression() const { return state_ > kJpegStartDecompress; }
  SkJpegMetadataDecoder* GetMetadataDecoder() {
    return metadata_decoder_.get();
  }

 private:
#if defined(USE_SYSTEM_LIBJPEG)
  NO_SANITIZE_CFI_ICALL
#endif
  JSAMPARRAY AllocateSampleArray() {
// Some output color spaces don't need the sample array: don't allocate in that
// case.
#if defined(TURBO_JPEG_RGB_SWIZZLE)
    if (turboSwizzled(info_.out_color_space)) {
      return nullptr;
    }
#endif

    if (info_.out_color_space != JCS_YCbCr) {
      return (*info_.mem->alloc_sarray)(
          reinterpret_cast_ptr<j_common_ptr>(&info_), JPOOL_IMAGE,
          4 * info_.output_width, 1);
    }

    // Compute the width of the Y plane in bytes.  This may be larger than the
    // output width, since the jpeg library requires that the allocated width be
    // a multiple of DCTSIZE.  Note that this buffer will be used as garbage
    // memory for rows that extend below the actual height of the image.  We can
    // reuse the same memory for the U and V planes, since we are guaranteed
    // that the Y plane width is at least as large as the U and V plane widths.
    int width_bytes = ComputeYUVWidthBytes(&info_, 0);
    return (*info_.mem->alloc_sarray)(
        reinterpret_cast_ptr<j_common_ptr>(&info_), JPOOL_IMAGE, width_bytes,
        1);
  }

  void UpdateRestartPosition() {
    if (last_set_byte_ != info_.src->next_input_byte) {
      // next_input_byte was updated by jpeg, meaning that it found a restart
      // position.
      restart_position_ = static_cast<wtf_size_t>(next_read_position_ -
                                                  info_.src->bytes_in_buffer);
    }
  }

  void ClearBuffer() {
    // Let libjpeg know that the buffer needs to be refilled.
    info_.src->bytes_in_buffer = 0;
    info_.src->next_input_byte = nullptr;
    last_set_byte_ = nullptr;
  }

  scoped_refptr<SegmentReader> data_;
  raw_ptr<JPEGImageDecoder> decoder_;

  // Input reading: True if we need to back up to restart_position_.
  bool needs_restart_;
  // If libjpeg needed to restart, this is the position to restart from.
  wtf_size_t restart_position_;
  // This is the position where we will read from, unless there is a restart.
  wtf_size_t next_read_position_;
  // This is how we know to update the restart position. It is the last value
  // we set to next_input_byte. libjpeg will update next_input_byte when it
  // has found the next restart position, so if it no longer matches this
  // value, we know we've reached the next restart position.
  raw_ptr<const JOCTET> last_set_byte_;

  jpeg_decompress_struct info_;
  decoder_error_mgr err_;
  decoder_source_mgr src_;
  jpeg_progress_mgr progress_mgr_;
  jstate state_;

  // The metadata decoder is populated once the full header (all segments up to
  // the first StartOfScan) has been received.
  std::unique_ptr<SkJpegMetadataDecoder> metadata_decoder_;

  JSAMPARRAY samples_;
  gfx::Size uv_size_;
};

void error_exit(
    j_common_ptr cinfo)  // Decoding failed: return control to the setjmp point.
{
  longjmp(reinterpret_cast_ptr<decoder_error_mgr*>(cinfo->err)->setjmp_buffer,
          -1);
}

void emit_message(j_common_ptr cinfo, int msg_level) {
  if (msg_level >= 0) {
    return;
  }

  decoder_error_mgr* err = reinterpret_cast_ptr<decoder_error_mgr*>(cinfo->err);
  err->pub.num_warnings++;

  // Detect and count corrupt JPEG warning messages.
  const char* warning = nullptr;
  int code = err->pub.msg_code;
  if (code > 0 && code <= err->pub.last_jpeg_message) {
    warning = err->pub.jpeg_message_table[code];
  }
  if (warning && !strncmp("Corrupt JPEG", warning, 12)) {
    err->num_corrupt_warnings++;
  }
}

void init_source(j_decompress_ptr) {}

void skip_input_data(j_decompress_ptr jd, long num_bytes) {
  reinterpret_cast_ptr<decoder_source_mgr*>(jd->src)->reader->SkipBytes(
      num_bytes);
}

boolean fill_input_buffer(j_decompress_ptr jd) {
  return reinterpret_cast_ptr<decoder_source_mgr*>(jd->src)
      ->reader->FillBuffer();
}

void term_source(j_decompress_ptr jd) {
  reinterpret_cast_ptr<decoder_source_mgr*>(jd->src)
      ->reader->Decoder()
      ->Complete();
}

JPEGImageDecoder::JPEGImageDecoder(AlphaOption alpha_option,
                                   ColorBehavior color_behavior,
                                   cc::AuxImage aux_image,
                                   wtf_size_t max_decoded_bytes,
                                   wtf_size_t offset)
    : ImageDecoder(alpha_option,
                   ImageDecoder::kDefaultBitDepth,
                   color_behavior,
                   aux_image,
                   max_decoded_bytes),
      offset_(offset) {}

JPEGImageDecoder::~JPEGImageDecoder() = default;

String JPEGImageDecoder::FilenameExtension() const {
  return "jpg";
}

const AtomicString& JPEGImageDecoder::MimeType() const {
  DEFINE_STATIC_LOCAL(const AtomicString, jpeg_mime_type, ("image/jpeg"));
  return jpeg_mime_type;
}

bool JPEGImageDecoder::SetSize(unsigned width, unsigned height) {
  if (!ImageDecoder::SetSize(width, height)) {
    return false;
  }

  if (!DesiredScaleNumerator()) {
    return SetFailed();
  }

  SetDecodedSize(width, height);
  return true;
}

void JPEGImageDecoder::OnSetData(scoped_refptr<SegmentReader> data) {
  // If we are decoding the gainmap image, replace `data` with the subset of
  // `data` that corresponds to the gainmap image itself. This strategy is
  // used because the underlying decoder is unaware of gainmap metadata, and
  // because the gainmap image itself is is a self-contained JPEG image (see
  // multi-picture format, also known as CIPA DC-007). This is in contrast with
  // other decoders (e.g AVIF), which are aware of gainmap metadata.
  if (data && aux_image_ == cc::AuxImage::kGainmap) {
    sk_sp<SkData> base_image_data = data->GetAsSkData();
    DCHECK(base_image_data);
    SkGainmapInfo gainmap_info;
    sk_sp<SkData> gainmap_image_data;
    auto base_metadata_decoder = SkJpegMetadataDecoder::Make(base_image_data);
    if (!base_metadata_decoder->findGainmapImage(
            base_image_data, gainmap_image_data, gainmap_info)) {
      SetFailed();
      return;
    }
    data = SegmentReader::CreateFromSkData(std::move(gainmap_image_data));
    data_ = data;
  }

  if (reader_) {
    reader_->SetData(std::move(data));

    // Changing YUV decoding mode is not allowed after decompression starts.
    if (reader_->HasStartedDecompression()) {
      return;
    }
  }

  if (allow_decode_to_yuv_) {
    return;
  }

  allow_decode_to_yuv_ =
      // Incremental YUV decoding is not currently supported (crbug.com/943519).
      IsAllDataReceived() &&
      // Ensures that the reader is created, the scale numbers are known,
      // the color profile is known, and the subsampling is known.
      IsSizeAvailable() &&
      // YUV decoding to a smaller size is not supported.
      reader_ && reader_->Info()->scale_num == reader_->Info()->scale_denom &&
      // TODO(crbug.com/911246): Support color space transformations on planar
      // data.
      !ColorTransform() &&
      SubsamplingSupportedByDecodeToYUV(GetYUVSubsampling());
}

gfx::Size JPEGImageDecoder::DecodedSize() const {
  return decoded_size_;
}

void JPEGImageDecoder::SetDecodedSize(un
```