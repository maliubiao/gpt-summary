Response:
The user wants to understand the functionality of the `bmp_image_reader.cc` file in the Chromium Blink rendering engine. I need to:

1. **Identify the core purpose of the file:** This file is responsible for decoding BMP image data.
2. **Explain its interactions with web technologies:**  How does BMP decoding relate to displaying images in HTML, and how might JavaScript and CSS be involved?
3. **Illustrate logical reasoning with examples:** Provide hypothetical inputs (BMP data characteristics) and outputs (decoded image dimensions, pixel data).
4. **Highlight potential user/programmer errors:**  What mistakes can occur when working with BMP images or using this decoder?
5. **Summarize the file's functionalities based on the provided code snippet.**

**Mental Sandbox:**

* **Function Identification:** Scan the code for key actions like reading headers, processing color tables, decoding pixel data, and handling different BMP compression schemes.
* **Web Technology Relation:**  BMP images are directly used in `<img>` tags in HTML. CSS might influence how these images are displayed (sizing, styling), but the decoding itself is separate. JavaScript could potentially trigger image loading or manipulation, but this file focuses on the decoding stage.
* **Logical Reasoning Examples:**  Consider scenarios like a BMP with a specific header size leading to correct parsing, or a BMP with RLE compression requiring special decoding.
* **Error Scenarios:**  Think about invalid BMP headers, unsupported compression types, or corrupted image data.
* **Code Snippet Analysis:** Focus on the function calls and data structures within the provided code to summarize its key responsibilities.
```
功能归纳：

BMPImageReader 类的主要功能是**解析和解码 BMP (Bitmap) 图像文件格式**，以便在 Chromium 浏览器中渲染和显示 BMP 图像。它负责从原始字节流中提取图像数据，并将其转换为可供渲染引擎使用的像素格式。

以下是该类功能的详细分解：

1. **读取和解析 BMP 文件头信息：**
   -  `ReadInfoHeaderSize()`:  读取 BMP 信息头的大小。
   -  `ReadInfoHeader()`: 读取并解析 BMP 的各种信息头 (BITMAPCOREHEADER, BITMAPINFOHEADER 等)，从中提取图像的关键属性，例如宽度、高度、位深度、压缩类型等。
   -  `ProcessInfoHeader()`: 对读取到的信息头进行处理和校验，确保其有效性。

2. **处理颜色表（Color Table）：**
   -  `ProcessColorTable()`: 对于使用颜色索引的 BMP 图像（例如 1位、4位、8位），读取和解析颜色表，将索引值映射到实际的 RGB 颜色。

3. **处理位掩码（Bitmasks）：**
   -  `ProcessBitmasks()`:  对于高位深度的 BMP 图像（例如 16位、32位），读取和解析位掩码，确定 RGB 和 Alpha 通道在像素数据中的位置和位数。

4. **解码像素数据：**
   -  `DecodePixelData()`: 根据 BMP 的位深度和压缩类型，实际解码图像的像素数据。
   -  `ProcessNonRLEData()`: 处理非 RLE (Run-Length Encoding) 压缩的像素数据。
   -  `ProcessRLEData()`: 处理 RLE 压缩的像素数据 (RLE4, RLE8, RLE24)。

5. **处理嵌入的颜色配置文件（Color Profile）：**
   -  `ProcessEmbeddedColorProfile()`:  读取和解析 BMP 文件中可能嵌入的 ICC 颜色配置文件，用于更精确的颜色渲染。

6. **处理其他图像格式（JPEG/PNG）：**
   -  `DecodeAlternateFormat()`:  对于 BMP 文件中嵌入的 JPEG 或 PNG 格式的图像数据（通常用于 ICO 文件），创建相应的 `JPEGImageDecoder` 或 `PngImageDecoder` 进行解码。

7. **管理解码状态和数据：**
   -  `SetData()`: 接收图像数据。
   -  维护内部状态，例如解码偏移量 (`decoded_offset_`)、信息头数据 (`info_header_`)、颜色表 (`color_table_`) 等。

8. **与父类 `ImageDecoder` 交互：**
   -  使用父类 `ImageDecoder` 的接口 (`parent_->SetSize()`, `parent_->SetFailed()`, `parent_->SetEmbeddedColorProfile()`) 来传递解码结果、错误信息和颜色配置信息。

9. **初始化和管理图像帧缓冲区：**
   -  `InitFrame()`:  分配和初始化用于存储解码后像素数据的缓冲区。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML (`<img>` 标签):**  当 HTML 中使用 `<img>` 标签加载一个 BMP 图像时，Blink 渲染引擎会调用 `BMPImageReader` 来解码该图像。解码后的像素数据会被用于在浏览器窗口中绘制图像。

   **举例说明:**
   ```html
   <img src="image.bmp">
   ```
   当浏览器解析到这行 HTML 时，会尝试加载 `image.bmp` 文件。`BMPImageReader` 负责读取并解码这个 BMP 文件，最终将解码后的图像显示在网页上。

* **CSS (背景图像):** CSS 可以将 BMP 图像设置为元素的背景图像。

   **举例说明:**
   ```css
   .my-div {
     background-image: url("background.bmp");
   }
   ```
   与 `<img>` 标签类似，Blink 引擎会使用 `BMPImageReader` 解码 `background.bmp`，然后将其作为 `my-div` 元素的背景绘制出来。

* **JavaScript (Image 对象, Canvas API):** JavaScript 可以通过 `Image` 对象加载 BMP 图像，或者使用 Canvas API 来操作 BMP 图像的像素数据。

   **举例说明 (Image 对象):**
   ```javascript
   let img = new Image();
   img.src = "dynamic_image.bmp";
   document.body.appendChild(img);
   ```
   当 JavaScript 创建一个新的 `Image` 对象并设置其 `src` 属性为 BMP 文件时，`BMPImageReader` 仍然会参与解码过程。

   **举例说明 (Canvas API):**
   ```javascript
   let canvas = document.getElementById('myCanvas');
   let ctx = canvas.getContext('2d');
   let img = new Image();
   img.onload = function() {
     ctx.drawImage(img, 0, 0);
   };
   img.src = "canvas_image.bmp";
   ```
   在这个例子中，Canvas API 可以将解码后的 BMP 图像绘制到 `<canvas>` 元素上。

**逻辑推理示例 (假设输入与输出):**

**假设输入：** 一个简单的未压缩的 24 位 BMP 图像文件数据。

* **信息头部分：** 指示宽度为 100 像素，高度为 50 像素，位深度为 24，压缩类型为 RGB。
* **像素数据部分：** 包含 100 * 50 * 3 字节的 RGB 像素数据。

**逻辑推理过程：**

1. `BMPImageReader` 首先读取信息头，解析出宽度、高度和位深度。
2. 由于是 24 位 RGB 图像，不需要处理颜色表或位掩码。
3. `DecodePixelData()` 函数会读取像素数据部分，每次读取 3 个字节代表一个像素的红、绿、蓝分量。
4. 解码器会将这些 RGB 值写入到图像帧缓冲区中。

**假设输出：**

* `parent_->SetSize(100, 50)` 被调用，告知父 `ImageDecoder` 图像的尺寸。
* 图像帧缓冲区中填充了 5000 个像素的 RGB 值。
* `buffer_->SetStatus(ImageFrame::kFrameComplete)` 被调用，表示解码完成。

**用户或编程常见的使用错误举例说明：**

1. **损坏的 BMP 文件：**  如果 BMP 文件的头部信息被破坏（例如，宽度或高度值错误），`BMPImageReader` 的 `IsInfoHeaderValid()` 可能会返回 `false`，导致解码失败。
   * **错误情况：** 用户上传了一个部分下载或修改过的 BMP 文件。
   * **结果：** 浏览器无法显示该图像，可能会显示一个占位符或者完全不显示。

2. **不支持的 BMP 格式：**  `BMPImageReader` 可能不支持某些罕见的 BMP 格式或压缩类型。
   * **错误情况：** 开发者使用了特殊的 BMP 编码工具创建了使用了 `HUFFMAN1D` 压缩的单色 BMP 图像。
   * **结果：** `IsInfoHeaderValid()` 或 `ReadInfoHeader()` 中会识别出不支持的格式，导致解码失败。

3. **内存不足：** 对于非常大的 BMP 图像，解码过程可能需要大量的内存来存储像素数据。
   * **错误情况：** 用户尝试加载一个几千兆像素的巨型 BMP 文件。
   * **结果：**  `InitFrame()` 中 `buffer_->AllocatePixelData()` 可能会因为内存分配失败而返回 `false`，导致解码失败。

4. **假设 BMP 始终是简单的 RGB 格式：** 开发者可能会错误地假设所有 BMP 图像都是简单的未压缩的 RGB 格式，而忽略了颜色表、位掩码和不同的压缩类型。
   * **错误情况：** 开发者编写代码直接读取 BMP 文件的像素数据，而没有使用专门的 BMP 解码器，并且处理的是一个索引颜色 BMP。
   * **结果：** 显示的图像颜色会错乱，因为索引值没有被正确映射到 RGB 颜色。

**功能归纳（基于提供的代码片段）：**

提供的代码片段主要集中在 `BMPImageReader` 类的 **读取和解析 BMP 文件头信息** 部分，以及一些辅助功能，例如：

* **定义了用于将不同位深度值映射到 8 位值的查找表 (`nBitTo8BitlookupTable`)。**
* **实现了构造函数，用于初始化 `BMPImageReader` 对象，并确定信息头和图像数据的偏移量。**
* **实现了 `SetData()` 方法，用于接收图像数据。**
* **实现了 `DecodeBMP()` 方法，作为主要的解码入口点，负责协调信息头的读取、处理、颜色表/位掩码的处理，以及最终的像素数据解码。**
* **实现了 `ReadInfoHeaderSize()` 和 `ProcessInfoHeader()` 方法，用于读取和初步处理 BMP 的信息头大小和内容。**
* **实现了 `ReadInfoHeader()` 方法，用于详细读取各种类型的 BMP 信息头，并提取关键信息。**
* **实现了 `IsInfoHeaderValid()` 方法，用于对读取到的信息头进行有效性检查，防止后续处理出现错误。**
* **实现了 `DecodeAlternateFormat()` 方法，用于处理嵌入的 JPEG 或 PNG 图像数据。**

总而言之，这段代码是 `BMPImageReader` 类的核心组成部分，负责 BMP 文件格式的初步解析和元数据提取，为后续的像素数据解码奠定基础。
```
Prompt: 
```
这是目录为blink/renderer/platform/image-decoders/bmp/bmp_image_reader.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2008 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/bmp/bmp_image_reader.h"

#include "third_party/blink/renderer/platform/image-decoders/jpeg/jpeg_image_decoder.h"
#include "third_party/blink/renderer/platform/image-decoders/png/png_decoder_factory.h"
#include "third_party/skia/include/core/SkColorSpace.h"

namespace {

// See comments on lookup_table_addresses_ in the header.
constexpr uint8_t nBitTo8BitlookupTable[] = {
    // clang-format off
    // 1 bit
    0, 255,
    // 2 bits
    0, 85, 170, 255,
    // 3 bits
    0, 36, 73, 109, 146, 182, 219, 255,
    // 4 bits
    0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255,
    // 5 bits
    0, 8, 16, 25, 33, 41, 49, 58, 66, 74, 82, 90, 99, 107, 115, 123, 132, 140,
    148, 156, 165, 173, 181, 189, 197, 206, 214, 222, 230, 239, 247, 255,
    // 6 bits
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 45, 49, 53, 57, 61, 65, 69, 73, 77,
    81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 130, 134, 138, 142,
    146, 150, 154, 158, 162, 166, 170, 174, 178, 182, 186, 190, 194, 198, 202,
    206, 210, 215, 219, 223, 227, 231, 235, 239, 243, 247, 251, 255,
    // 7 bits
    0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38,
    40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 66, 68, 70, 72, 74, 76,
    78, 80, 82, 84, 86, 88, 90, 92, 94, 96, 98, 100, 102, 104, 106, 108, 110,
    112, 114, 116, 118, 120, 122, 124, 126, 129, 131, 133, 135, 137, 139, 141,
    143, 145, 147, 149, 151, 153, 155, 157, 159, 161, 163, 165, 167, 169, 171,
    173, 175, 177, 179, 181, 183, 185, 187, 189, 191, 193, 195, 197, 199, 201,
    203, 205, 207, 209, 211, 213, 215, 217, 219, 221, 223, 225, 227, 229, 231,
    233, 235, 237, 239, 241, 243, 245, 247, 249, 251, 253, 255,
    // clang-format on
};

}  // namespace

namespace blink {

BMPImageReader::BMPImageReader(ImageDecoder* parent,
                               wtf_size_t decoded_and_header_offset,
                               wtf_size_t img_data_offset,
                               bool is_in_ico)
    : parent_(parent),
      decoded_offset_(decoded_and_header_offset),
      header_offset_(decoded_and_header_offset),
      img_data_offset_(img_data_offset),
      is_in_ico_(is_in_ico) {
  // Clue-in decodeBMP() that we need to detect the correct info header size.
  memset(&info_header_, 0, sizeof(info_header_));
}

BMPImageReader::~BMPImageReader() = default;

void BMPImageReader::SetData(scoped_refptr<SegmentReader> data) {
  data_ = data;
  fast_reader_.SetData(std::move(data));
  if (alternate_decoder_) {
    alternate_decoder_->SetData(data_.get(), parent_->IsAllDataReceived());
  }
}

bool BMPImageReader::DecodeBMP(bool only_size) {
  // Defensively clear the FastSharedBufferReader's cache, as another caller
  // may have called SharedBuffer::MergeSegmentsIntoBuffer().
  fast_reader_.ClearCache();

  // Calculate size of info header.
  if (!info_header_.size && !ReadInfoHeaderSize()) {
    return false;
  }

  const wtf_size_t header_end = header_offset_ + info_header_.size;
  // Read and process info header.
  if ((decoded_offset_ < header_end) && !ProcessInfoHeader()) {
    return false;
  }

  // If there is an applicable color profile, it must be processed now, since
  // once the image size is available, the decoding machinery assumes the color
  // space is as well.  Unfortunately, since the profile appears after
  // everything else, this may delay processing until all data is received.
  // Luckily, few BMPs have an embedded color profile.
  const bool use_alternate_decoder =
      (info_header_.compression == JPEG) || (info_header_.compression == PNG);
  if (!use_alternate_decoder && info_header_.profile_data &&
      !ProcessEmbeddedColorProfile()) {
    return false;
  }

  // Set our size if we haven't already.  In ICO files, IsDecodedSizeAvailable()
  // always returns true (since it reflects the size in the directory, which has
  // already been read); call SetSize() anyway, since it sanity-checks that the
  // size here matches the directory.
  if ((is_in_ico_ || !parent_->IsDecodedSizeAvailable()) &&
      !parent_->SetSize(static_cast<unsigned>(info_header_.width),
                        static_cast<unsigned>(info_header_.height))) {
    return false;
  }

  if (only_size) {
    return true;
  }

  if (use_alternate_decoder) {
    return DecodeAlternateFormat();
  }

  // Read and process the bitmasks, if needed.
  if (need_to_process_bitmasks_ && !ProcessBitmasks()) {
    return false;
  }

  // Read and process the color table, if needed.
  if (need_to_process_color_table_ && !ProcessColorTable()) {
    return false;
  }

  // Initialize the framebuffer if needed.
  DCHECK(buffer_);  // Parent should set this before asking us to decode!
  if ((buffer_->GetStatus() == ImageFrame::kFrameEmpty) && !InitFrame()) {
    return false;
  }

  // Decode the data.
  if (!decoding_and_mask_ && !PastEndOfImage(0) &&
      !DecodePixelData((info_header_.compression != RLE4) &&
                       (info_header_.compression != RLE8) &&
                       (info_header_.compression != RLE24))) {
    return false;
  }

  // If the image has an AND mask and there was no alpha data, process the
  // mask.
  if (is_in_ico_ && !decoding_and_mask_ &&
      ((info_header_.bit_count < 16) || !bit_masks_[3] ||
       !seen_non_zero_alpha_pixel_)) {
    // Reset decoding coordinates to start of image.
    coord_.set_x(0);
    coord_.set_y(is_top_down_ ? 0 : (parent_->Size().height() - 1));

    // The AND mask is stored as 1-bit data.
    info_header_.bit_count = 1;

    decoding_and_mask_ = true;
  }
  if (decoding_and_mask_ && !DecodePixelData(true)) {
    return false;
  }

  // Done!
  buffer_->SetStatus(ImageFrame::kFrameComplete);
  return true;
}

bool BMPImageReader::ReadInfoHeaderSize() {
  // Get size of info header.
  DCHECK_EQ(decoded_offset_, header_offset_);
  if ((decoded_offset_ > data_->size()) ||
      ((data_->size() - decoded_offset_) < 4)) {
    return false;
  }
  info_header_.size = ReadUint32(0);
  // Don't increment decoded_offset here, it just makes the code in
  // ProcessInfoHeader() more confusing.

  // Don't allow the header to overflow (which would be harmless here, but
  // problematic or at least confusing in other places), or to overrun the
  // image data.
  const wtf_size_t header_end = header_offset_ + info_header_.size;
  if ((header_end < header_offset_) ||
      (img_data_offset_ && (img_data_offset_ < header_end))) {
    return parent_->SetFailed();
  }

  // See if this is a header size we understand.  See comments in
  // ReadInfoHeader() for more.
  if (info_header_.size == 12) {
    // OS/2 1.x (and Windows V2): 12
    is_os21x_ = true;
  } else if ((info_header_.size == 40) || HasRGBMasksInHeader()) {
    // Windows V3+: 40, 52, 56, 108, 124
  } else if ((info_header_.size >= 16) && (info_header_.size <= 64) &&
             (!(info_header_.size & 3) || (info_header_.size == 42) ||
              (info_header_.size == 46))) {
    // OS/2 2.x: any multiple of 4 between 16 and 64, inclusive, or 42 or 46
    is_os22x_ = true;
  } else {
    return parent_->SetFailed();
  }

  return true;
}

bool BMPImageReader::ProcessInfoHeader() {
  // Read info header.
  DCHECK_EQ(decoded_offset_, header_offset_);
  if ((decoded_offset_ > data_->size()) ||
      ((data_->size() - decoded_offset_) < info_header_.size) ||
      !ReadInfoHeader()) {
    return false;
  }

  // Sanity-check header values before doing further fixup.
  if (!IsInfoHeaderValid()) {
    return parent_->SetFailed();
  }

  // For paletted images, bitmaps can set clr_used to 0 to mean "all colors", so
  // set it to the maximum number of colors for this bit depth.  Also do this
  // for bitmaps that put too large a value here.
  if (info_header_.bit_count < 16) {
    const uint32_t max_colors = uint32_t{1} << info_header_.bit_count;
    if (!info_header_.clr_used || (info_header_.clr_used > max_colors)) {
      info_header_.clr_used = max_colors;
    }
  }

  // For any bitmaps that set their BitCount to the wrong value, reset the
  // counts now that we've calculated the number of necessary colors, since
  // other code relies on this value being correct.
  if (info_header_.compression == RLE8) {
    info_header_.bit_count = 8;
  } else if (info_header_.compression == RLE4) {
    info_header_.bit_count = 4;
  }

  // Tell caller what still needs to be processed.
  if (info_header_.bit_count >= 16) {
    need_to_process_bitmasks_ = true;
  } else if (info_header_.bit_count) {
    need_to_process_color_table_ = true;
  }

  decoded_offset_ += info_header_.size;
  return true;
}

bool BMPImageReader::ReadInfoHeader() {
  // Supported info header formats:
  // * BITMAPCOREHEADER/OS21XBITMAPHEADER/"Windows V2".  Windows 2.x (?),
  //   OS/2 1.x.  12 bytes.  Incompatible with all below headers.
  // * BITMAPINFOHEADER/"Windows V3".  Windows 3.x.  40 bytes.  Changes width/
  //   height fields to 32 bit and adds features such as compression types.
  //   (Nomenclature: Note that "Windows V3" here and "BITMAPV3..." below are
  //   different things.)
  // * OS22XBITMAPHEADER/BITMAPCOREHEADER2.  OS/2 2.x.  16-64 bytes.  The first
  //   40 bytes are basically identical to BITMAPINFOHEADER, save that most
  //   fields are optional.  Further fields, if present, are incompatible with
  //   all below headers.  Adds features such as halftoning and color spaces
  //   (not implemented here).
  // * BITMAPV2HEADER/BITMAPV2INFOHEADER.  52 bytes.  Extends BITMAPINFOHEADER
  //   with R/G/B masks.  Poorly-documented and obscure.
  // * BITMAPV3HEADER/BITMAPV3INFOHEADER.  56 bytes.  Extends BITMAPV2HEADER
  //   with an alpha mask.  Poorly-documented and obscure.
  // * BITMAPV4HEADER/"Windows V4".  Windows 95.  108 bytes.  Extends
  //   BITMAPV3HEADER with color space support.
  // * BITMAPV5HEADER/"Windows V5".  Windows 98.  124 bytes.  Extends
  //   BITMAPV4HEADER with ICC profile support.

  // Pre-initialize some fields that not all headers set.
  info_header_.compression = RGB;
  info_header_.clr_used = 0;
  info_header_.profile_data = 0;
  info_header_.profile_size = 0;

  if (is_os21x_) {
    info_header_.width = ReadUint16(4);
    info_header_.height = ReadUint16(6);
    info_header_.bit_count = ReadUint16(10);
    return true;
  }

  info_header_.width = ReadUint32(4);
  info_header_.height = ReadUint32(8);
  if (is_in_ico_) {
    info_header_.height /= 2;
  }
  // Detect top-down BMPs.
  if (info_header_.height < 0) {
    // We can't negate INT32_MIN below to get a positive int32_t.
    // IsInfoHeaderValid() will reject heights of 1 << 16 or larger anyway,
    // so just reject this bitmap now.
    if (info_header_.height == INT32_MIN) {
      return parent_->SetFailed();
    }
    is_top_down_ = true;
    info_header_.height = -info_header_.height;
  }

  info_header_.bit_count = ReadUint16(14);

  // Read compression type, if present.
  if (info_header_.size >= 20) {
    const uint32_t compression = ReadUint32(16);

    // Detect OS/2 2.x-specific compression types.
    if ((compression == 3) && (info_header_.bit_count == 1)) {
      info_header_.compression = HUFFMAN1D;
      is_os22x_ = true;
    } else if ((compression == 4) && (info_header_.bit_count == 24)) {
      info_header_.compression = RLE24;
      is_os22x_ = true;
    } else if (compression > ALPHABITFIELDS) {
      return parent_->SetFailed();  // Some type we don't understand.
    } else {
      info_header_.compression = static_cast<CompressionType>(compression);
    }
  }

  // Read colors used, if present.
  if (info_header_.size >= 36) {
    info_header_.clr_used = ReadUint32(32);
  }

  // If we can safely read the four bitmasks from 40-56 bytes in, do that here.
  // If the bit depth is less than 16, these values will be ignored by the image
  // data decoders. If the bit depth is at least 16 but the compression format
  // isn't [ALPHA]BITFIELDS, the RGB bitmasks will be ignored and overwritten in
  // processBitmasks(). (The alpha bitmask will never be overwritten: images
  // that actually want alpha have to specify a valid alpha mask. See comments
  // in ProcessBitmasks().)
  //
  // For other BMPs, bit_masks_[] et. al will be initialized later during
  // ProcessBitmasks().
  if (HasRGBMasksInHeader()) {
    bit_masks_[0] = ReadUint32(40);
    bit_masks_[1] = ReadUint32(44);
    bit_masks_[2] = ReadUint32(48);
  }
  if (HasAlphaMaskInHeader()) {
    bit_masks_[3] = ReadUint32(52);
  }

  // Read color space information, if present and desirable.
  if (HasColorSpaceInfoInHeader() && !parent_->IgnoresColorSpace()) {
    enum {
      kLcsCalibratedRGB = 0x00000000,
      kLcssRGB = 0x73524742,               // "sRGB"
      kLcsWindowsColorSpace = 0x57696E20,  // "Win "
      kProfileLinked = 0x4c494e4b,         // "LINK"
      kProfileEmbedded = 0x4d424544,       // "MBED"
    };

    const uint32_t cs_type = ReadUint32(56);
    switch (cs_type) {
      case kLcsCalibratedRGB: {  // Endpoints and gamma specified directly
        skcms_ICCProfile profile;
        skcms_Init(&profile);

        // Convert chromaticity values from 2.30 fixed point to floating point.
        const auto fxpt2dot30_to_float = [](uint32_t fxpt2dot30) {
          return fxpt2dot30 * 9.31322574615478515625e-10f;
        };
        const float rx = fxpt2dot30_to_float(ReadUint32(60));
        const float ry = fxpt2dot30_to_float(ReadUint32(64));
        const float gx = fxpt2dot30_to_float(ReadUint32(72));
        const float gy = fxpt2dot30_to_float(ReadUint32(76));
        const float bx = fxpt2dot30_to_float(ReadUint32(84));
        const float by = fxpt2dot30_to_float(ReadUint32(88));
        // BMPs do not explicitly encode a white point.  Using the sRGB
        // illuminant (D65) seems reasonable given that Windows' system color
        // space is sRGB.
        constexpr float kD65x = 0.31271;
        constexpr float kD65y = 0.32902;
        skcms_Matrix3x3 to_xyzd50;
        if (!skcms_PrimariesToXYZD50(rx, ry, gx, gy, bx, by, kD65x, kD65y,
                                     &to_xyzd50)) {
          // Some real-world images have bogus values, e.g. all zeros.  Ignore
          // the color space data in such cases, rather than failing.
          break;
        }
        skcms_SetXYZD50(&profile, &to_xyzd50);

        // Convert gamma values from 16.16 fixed point to transfer functions.
        const auto fxpt16dot16_to_fn = [](uint32_t fxpt16dot16) {
          skcms_TransferFunction fn;
          fn.a = 1.0f;
          fn.b = fn.c = fn.d = fn.e = fn.f = 0.0f;
          // Petzold's "Programming Windows" claims the gamma here is a decoding
          // gamma (e.g. 2.2), as opposed to the inverse, an encoding gamma
          // (like PNG encodes in its gAMA chunk).
          fn.g = SkFixedToFloat(fxpt16dot16);
          return fn;
        };
        profile.has_trc = true;
        profile.trc[0].table_entries = 0;
        profile.trc[0].parametric = fxpt16dot16_to_fn(ReadUint32(96));
        profile.trc[1].table_entries = 0;
        profile.trc[1].parametric = fxpt16dot16_to_fn(ReadUint32(100));
        profile.trc[2].table_entries = 0;
        profile.trc[2].parametric = fxpt16dot16_to_fn(ReadUint32(104));

        parent_->SetEmbeddedColorProfile(
            std::make_unique<ColorProfile>(profile));
        break;
      }

      case kLcssRGB:               // sRGB
      case kLcsWindowsColorSpace:  // "The Windows default color space" (sRGB)
        parent_->SetEmbeddedColorProfile(
            std::make_unique<ColorProfile>(*skcms_sRGB_profile()));
        break;

      case kProfileEmbedded:  // Embedded ICC profile
        if (info_header_.size >= 120) {
          info_header_.profile_data = header_offset_ + ReadUint32(112);
          info_header_.profile_size = ReadUint32(116);
        }
        break;

      case kProfileLinked:  // Linked ICC profile.  Unsupported; presents
                            // security concerns.
      default:              // Unknown.
        break;
    }
  }

  return true;
}

bool BMPImageReader::IsInfoHeaderValid() const {
  // Non-positive widths/heights are invalid.  (We've already flipped the
  // sign of the height for top-down bitmaps.)
  if ((info_header_.width <= 0) || !info_header_.height) {
    return false;
  }

  // Only Windows V3+ has ICOs and top-down bitmaps.
  if ((is_in_ico_ || is_top_down_) && (is_os21x_ || is_os22x_)) {
    return false;
  }

  // Only bit depths of 1, 4, 8, or 24 are universally supported.
  if ((info_header_.bit_count != 1) && (info_header_.bit_count != 4) &&
      (info_header_.bit_count != 8) && (info_header_.bit_count != 24)) {
    // Windows V3+ additionally supports bit depths of 0 (for embedded
    // JPEG/PNG images), 2 (on Windows CE), 16, and 32.
    if (is_os21x_ || is_os22x_ ||
        (info_header_.bit_count && (info_header_.bit_count != 2) &&
         (info_header_.bit_count != 16) && (info_header_.bit_count != 32))) {
      return false;
    }
  }

  // Each compression type is only valid with certain bit depths (except RGB,
  // which can be used with any bit depth). Also, some formats do not support
  // some compression types.
  switch (info_header_.compression) {
    case RGB:
      if (!info_header_.bit_count) {
        return false;
      }
      break;

    case RLE8:
      // Supposedly there are undocumented formats like "BitCount = 1,
      // Compression = RLE4" (which means "4 bit, but with a 2-color table"),
      // so also allow the paletted RLE compression types to have too low a
      // bit count; we'll correct this later.
      if (!info_header_.bit_count || (info_header_.bit_count > 8)) {
        return false;
      }
      break;

    case RLE4:
      // See comments in RLE8.
      if (!info_header_.bit_count || (info_header_.bit_count > 4)) {
        return false;
      }
      break;

    case BITFIELDS:
    case ALPHABITFIELDS:
      // Only valid for Windows V3+.
      if (is_os21x_ || is_os22x_ ||
          ((info_header_.bit_count != 16) && (info_header_.bit_count != 32))) {
        return false;
      }
      break;

    case JPEG:
    case PNG:
      // Only valid for Windows V3+.  We don't support embedding these inside
      // ICO files.
      if (is_os21x_ || is_os22x_ || info_header_.bit_count ||
          !img_data_offset_) {
        return false;
      }
      break;

    case HUFFMAN1D:
      // Only valid for OS/2 2.x.
      if (!is_os22x_ || (info_header_.bit_count != 1)) {
        return false;
      }
      break;

    case RLE24:
      // Only valid for OS/2 2.x.
      if (!is_os22x_ || (info_header_.bit_count != 24)) {
        return false;
      }
      break;

    default:
      // Some type we don't understand.  This should have been caught in
      // ReadInfoHeader().
      NOTREACHED();
  }

  // Reject the following valid bitmap types that we don't currently bother
  // decoding.  Few other people decode these either, they're unlikely to be
  // in much use.
  // TODO(pkasting): Consider supporting these someday.
  //   * Bitmaps larger than 2^16 pixels in either dimension.
  if ((info_header_.width >= (1 << 16)) || (info_header_.height >= (1 << 16))) {
    return false;
  }
  //   * OS/2 2.x Huffman-encoded monochrome bitmaps (see
  //      http://www.fileformat.info/mirror/egff/ch09_05.htm , re: "G31D"
  //      algorithm; this seems to be used in TIFF files as well).
  if (info_header_.compression == HUFFMAN1D) {
    return false;
  }

  return true;
}

bool BMPImageReader::DecodeAlternateFormat() {
  // Create decoder if necessary.
  if (!alternate_decoder_) {
    if (info_header_.compression == JPEG) {
      alternate_decoder_ = std::make_unique<JPEGImageDecoder>(
          parent_->GetAlphaOption(), parent_->GetColorBehavior(),
          parent_->GetAuxImage(), parent_->GetMaxDecodedBytes(),
          img_data_offset_);
    } else {
      alternate_decoder_ = CreatePngImageDecoder(
          parent_->GetAlphaOption(), ImageDecoder::kDefaultBitDepth,
          parent_->GetColorBehavior(), parent_->GetMaxDecodedBytes(),
          img_data_offset_);
    }
    alternate_decoder_->SetData(data_.get(), parent_->IsAllDataReceived());
  }

  // Decode the image.
  if (alternate_decoder_->IsSizeAvailable()) {
    if (alternate_decoder_->Size() != parent_->Size()) {
      return parent_->SetFailed();
    }

    alternate_decoder_->SetMemoryAllocator(buffer_->GetAllocator());
    const auto* frame = alternate_decoder_->DecodeFrameBufferAtIndex(0);
    alternate_decoder_->SetMemoryAllocator(nullptr);

    if (frame) {
      *buffer_ = *frame;
    }
  }
  return alternate_decoder_->Failed()
             ? parent_->SetFailed()
             : (buffer_->GetStatus() == ImageFrame::kFrameComplete);
}

bool BMPImageReader::ProcessEmbeddedColorProfile() {
  // Ensure we have received the whole profile.
  if ((info_header_.profile_data > data_->size()) ||
      ((data_->size() - info_header_.profile_data) <
       info_header_.profile_size)) {
    return false;
  }

  // Parse the profile.
  auto owned_buffer = std::make_unique<char[]>(info_header_.profile_size);
  const char* buffer = fast_reader_.GetConsecutiveData(
      info_header_.profile_data, info_header_.profile_size, owned_buffer.get());
  auto profile = ColorProfile::Create(
      base::as_bytes(base::span(buffer, info_header_.profile_size)));
  if (!profile) {
    return parent_->SetFailed();
  }
  parent_->SetEmbeddedColorProfile(std::move(profile));

  // Zero |profile_data| so we don't try to process the profile again in the
  // future.
  info_header_.profile_data = 0;
  return true;
}

bool BMPImageReader::ProcessBitmasks() {
  // Create bit_masks_[] values for R/G/B.
  if ((info_header_.compression != BITFIELDS) &&
      (info_header_.compression != ALPHABITFIELDS)) {
    // The format doesn't actually use bitmasks.  To simplify the decode
    // logic later, create bitmasks for the RGB data.  For Windows V4+,
    // this overwrites the masks we read from the header, which are
    // supposed to be ignored in non-BITFIELDS cases.
    // 16 bits:    MSB <-                     xRRRRRGG GGGBBBBB -> LSB
    // 24/32 bits: MSB <- [AAAAAAAA] RRRRRRRR GGGGGGGG BBBBBBBB -> LSB
    const int num_bits = (info_header_.bit_count == 16) ? 5 : 8;
    for (int i = 0; i <= 2; ++i) {
      bit_masks_[i] = ((uint32_t{1} << (num_bits * (3 - i))) - 1) ^
                      ((uint32_t{1} << (num_bits * (2 - i))) - 1);
    }
  } else if (!HasRGBMasksInHeader()) {
    // For HasRGBMasksInHeader() bitmaps, this was already done when we read the
    // info header.

    // Fail if we don't have enough file space for the bitmasks.
    const wtf_size_t header_end = header_offset_ + info_header_.size;
    const bool read_alpha = info_header_.compression == ALPHABITFIELDS;
    const wtf_size_t kBitmasksSize = read_alpha ? 16 : 12;
    const wtf_size_t bitmasks_end = header_end + kBitmasksSize;
    if ((bitmasks_end < header_end) ||
        (img_data_offset_ && (img_data_offset_ < bitmasks_end))) {
      return parent_->SetFailed();
    }

    // Read bitmasks.
    if ((data_->size() - decoded_offset_) < kBitmasksSize) {
      return false;
    }
    bit_masks_[0] = ReadUint32(0);
    bit_masks_[1] = ReadUint32(4);
    bit_masks_[2] = ReadUint32(8);
    if (read_alpha) {
      bit_masks_[3] = ReadUint32(12);
    }

    decoded_offset_ += kBitmasksSize;
  }

  // Alpha is a poorly-documented and inconsistently-used feature.
  //
  // BITMAPV3HEADER+ have an alpha bitmask in the info header.  Unlike the R/G/B
  // bitmasks, the MSDN docs don't indicate that it is only valid for the
  // BITFIELDS compression format, so we respect it at all times.
  //
  // Windows CE supports the ALPHABITFIELDS compression format, which is rare.
  // We assume any mask specified by this format is valid as well.
  //
  // To complicate things, Windows V3 BMPs, which lack a mask, can specify 32bpp
  // format, which to any sane reader would imply an 8-bit alpha channel -- and
  // for BMPs-in-ICOs, that's precisely what's intended to happen. There also
  // exist standalone BMPs in this format which clearly expect the alpha channel
  // to be respected. However, there are many other BMPs which, for example,
  // fill this channel with all 0s, yet clearly expect to not be displayed as a
  // fully-transparent rectangle.
  //
  // If these were the only two types of Windows V3, 32bpp BMPs in the wild,
  // we could distinguish between them by scanning the alpha channel in the
  // image, looking for nonzero values, and only enabling alpha if we found
  // some. (It turns out we have to do this anyway, because, crazily, there
  // are also Windows V4+ BMPs with an explicit, non-zero alpha mask, which
  // then zero-fill their alpha channels! See comments in
  // processNonRLEData().)
  //
  // Unfortunately there are also V3 BMPs -- indeed, probably more than the
  // number of 32bpp, V3 BMPs which intentionally use alpha -- which specify
  // 32bpp format, use nonzero (and non-255) alpha values, and yet expect to
  // be rendered fully-opaque. And other browsers do so.
  //
  // So it's impossible to display every BMP in the way its creators intended,
  // and we have to choose what to break. Given the paragraph above, we match
  // other browsers and ignore alpha in Windows V3 BMPs except inside ICO
  // files.
  if (!HasAlphaMaskInHeader() && (info_header_.compression != ALPHABITFIELDS)) {
    const bool use_mask = is_in_ico_ &&
                          (info_header_.compression != BITFIELDS) &&
                          (info_header_.bit_count == 32);
    bit_masks_[3] = use_mask ? uint32_t{0xff000000} : 0;
  }

  // Check masks and set shift and LUT address values.
  for (int i = 0; i < 4; ++i) {
    // Trim the mask to the allowed bit depth.  Some Windows V4+ BMPs
    // specify a bogus alpha channel in bits that don't exist in the pixel
    // data (for example, bits 25-31 in a 24-bit RGB format).
    if (info_header_.bit_count < 32) {
      bit_masks_[i] &= ((uint32_t{1} << info_header_.bit_count) - 1);
    }

    // For empty masks (common on the alpha channel, especially after the
    // trimming above), quickly clear the shift and LUT address and
    // continue, to avoid an infinite loop in the counting code below.
    uint32_t temp_mask = bit_masks_[i];
    if (!temp_mask) {
      bit_shifts_right_[i] = 0;
      lookup_table_addresses_[i] = nullptr;
      continue;
    }

    // Make sure bitmask does not overlap any other bitmasks.
    for (int j = 0; j < i; ++j) {
      if (temp_mask & bit_masks_[j]) {
        return parent_->SetFailed();
      }
    }

    // Count offset into pixel data.
    for (bit_shifts_right_[i] = 0; !(temp_mask & 1); temp_mask >>= 1) {
      ++bit_shifts_right_[i];
    }

    // Count size of mask.
    wtf_size_t num_bits = 0;
    for (; temp_mask & 1; temp_mask >>= 1) {
      ++num_bits;
    }

    // Make sure bitmask is contiguous.
    if (temp_mask) {
      return parent_->SetFailed();
    }

    // Since RGBABuffer tops out at 8 bits per channel, adjust the shift
    // amounts to use the most significant 8 bits of the channel.
    if (num_bits >= 8) {
      bit_shifts_right_[i] += (num_bits - 8);
      num_bits = 0;
    }

    // Calculate LUT address.
    lookup_table_addresses_[i] =
        num_bits ? (nBitTo8BitlookupTable + (1 << num_bits) - 2) : nullptr;
  }

  // We've now decoded all the non-image data we care about.  Skip anything
  // else before the actual raster data.
  if (img_data_offset_) {
    decoded_offset_ = img_data_offset_;
  }
  need_to_process_bitmasks_ = false;
  return true;
}

bool BMPImageReader::ProcessColorTable() {
  // On non-OS/2 1.x, an extra padding byte is present, which we need to skip.
  const wtf_size_t bytes_per_color = is_os21x_ ? 3 : 4;

  const wtf_size_t header_end = header_offset_ + info_header_.size;
  wtf_size_t colors_in_palette = info_header_.clr_used;
  CHECK_LE(colors_in_palette, 256u);  // Enforced by ProcessInfoHeader().
  wtf_size_t table_size_in_bytes = colors_in_palette * bytes_per_color;
  const wtf_size_t table_end = header_end + table_size_in_bytes;
  if (table_end < header_end) {
    return parent_->SetFailed();
  }

  // Some BMPs don't contain a complete palette.  Truncate it instead of reading
  // off the end of the palette.
  if (img_data_offset_ && (img_data_offset_ < table_end)) {
    wtf_size_t colors_in_truncated_palette =
        (img_data_offset_ - header_end) / bytes_per_color;
    CHECK_LE(colors_in_truncated_palette, colors_in_palette);
    colors_in_palette = colors_in_truncated_palette;
    table_size_in_bytes = colors_in_palette * bytes_per_color;
  }

  // If we don't have enough data to read in the whole palette yet, stop here.
  if ((decoded_offset_ > data_->size()) ||
      ((data_->size() - decoded_offset_) < table_size_in_bytes)) {
    return false;
  }

  // Read the color table.
  color_table_.resize(colors_in_palette);

  for (wtf_size_t i = 0; i < colors_in_palette; ++i) {
    color_table_[i].rgb_blue = ReadUint8(0);
    color_table_[i].rgb_green = ReadUint8(1);
    color_table_[i].rgb_red = ReadUint8(2);
    decoded_offset_ += bytes_per_color;
  }

  // We've now decoded all the non-image data we care about.  Skip anything
  // else before the actual raster data.
  if (img_data_offset_) {
    decoded_offset_ = img_data_offset_;
  }
  need_to_process_color_table_ = false;
  return true;
}

bool BMPImageReader::InitFrame() {
  if (!buffer_->AllocatePixelData(parent_->Size().width(),
                                  parent_->Size().height(),
                                  parent_->ColorSpaceForSkImages())) {
    return parent_->SetFailed();  // Unable to allocate.
  }

  buffer_->ZeroFillPixelData();
  buffer_->SetStatus(ImageFrame::kFramePartial);
  // SetSize() calls EraseARGB(), which resets the alpha flag, so we force it
  // back to false here.  We'll set it to true later in all cases where these 0s
  // could actually show through.
  buffer_->SetHasAlpha(false);

  // For BMPs, the frame always fills the entire image.
  buffer_->SetOriginalFrameRect(gfx::Rect(parent_->Size()));

  if (!is_top_down_) {
    coord_.set_y(parent_->Size().height() - 1);
  }
  return true;
}

bool BMPImageReader::DecodePixelData(bool non_rle) {
  const gfx::Point coord(coord_);
  const ProcessingResult result =
      non_rle ? ProcessNonRLEData(false, 0) : ProcessRLEData();
  if (coord_ != coord) {
    buffer_->SetPixelsChanged(true);
  }
  return (result == kFailure) ? parent_->SetFailed() : (result == kSuccess);
}

BMPImageReader::ProcessingResult BMPImageReader::ProcessRLEData() {
  if (decoded_offset_ > data_->size()) {
    return kInsufficientData;
  }

  // RLE decoding is poorly specified.  Two main problems:
  // (1) Are EOL markers necessary?  What happens when we have too many
  //     pixels for one row?
  //     http://www.fileformat.info/format/bmp/egff.htm says extra pixels
  //     should wrap to the next line.  Real BMPs I've encountered seem to
  //     instead expect extra pixels to be ignored until the EOL marker is
  //     seen, although this has only happened in a few cases and I suspect
  //     those BMPs may be invalid.  So we only change lines on EOL (or Delta
  //     with dy > 0), and fail in most cases when pixels extend past the end
  //     of the line.
  // (2) When Delta, EOL, or EOF are seen, what happens to the "skipped"
  //     pixels?
  //     http://www.daubnet.com/formats/BMP.html says these should be filled
  //     with color 0.  However, the "do nothing" and "don't care" comments
  //     of other references suggest leaving these alone, i.e. letting them
  //     be transparent to the background behind the image.  This seems to
  //     match how MSPAINT treats BMPs, so we do that.  Note that when we
  //     actually skip pixels for a case like this, we need to note on the
  //     framebuffer that we have alpha.

  // Impossible to decode row-at-a-time, so just do things as a stream of
  // bytes.
  while (true) {
    // Every entry takes at least two bytes; bail if there isn't enough
    // data.
    if ((data_->size() - decoded_offset_) < 2) {
      return kInsufficientData;
    }

    // For every entry except EOF, we'd better not have reached the end of
    // the image.
    const uint8_t count = ReadUint8(0);
    const uint8_t code = Read
"""


```