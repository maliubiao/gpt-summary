Response:
Let's break down the thought process for analyzing the provided C++ code for `ICOImageDecoder`.

1. **Understand the Goal:** The request asks for the functionality of the `ICOImageDecoder`, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common user/programming errors.

2. **Initial Scan for Keywords and Structure:**  Quickly scan the code for important terms: `ICO`, `ImageDecoder`, `BMP`, `PNG`, `Size`, `Decode`, `Directory`, `Frame`, `MimeType`, `FilenameExtension`. Notice the constructor, destructor, and various methods. The `#include` directives also give hints (`png_decoder_factory.h`).

3. **Identify Core Functionality:** Based on the class name and the methods, the primary function is clearly *decoding ICO image files*. This involves reading the file structure, extracting individual image frames (which could be BMP or PNG), and making the image data available.

4. **Break Down Key Methods:** Go through the important methods one by one and understand their purpose:

    * **Constructor (`ICOImageDecoder`)**:  Sets up initial state, including handling alpha and color options. The `max_decoded_bytes` parameter suggests a mechanism for preventing excessive memory usage.
    * **`FilenameExtension()` and `MimeType()`**: Clearly define the file type and how it's identified on the web.
    * **`OnSetData()`**: Handles the input data. It appears to manage separate readers for BMP and PNG within the ICO file. The looping over `bmp_readers_` and `png_decoders_` is important.
    * **`Size()` and `FrameSizeAtIndex()`**: Deal with the dimensions of the image and individual frames.
    * **`FrameIsReceivedAtIndex()`**: Checks if enough data has been received for a specific frame.
    * **`SetFailed()`**: Handles error conditions.
    * **`HotSpot()` and `HotSpotAtIndex()`**:  Specifically for cursor files (`.cur`), handling the hotspot information.
    * **`CompareEntries()`**:  A crucial method for selecting the "best" icon from multiple sizes/bit-depths within the ICO file.
    * **`DecodeSize()` and `DecodeFrameCount()`**:  Determine the number of frames without fully decoding them. This is likely used for lazy loading or displaying progress.
    * **`Decode(wtf_size_t index)` and `Decode(wtf_size_t index, bool only_size)`**: The core decoding logic, handling both full decoding and just size information. Notice the branching for BMP and PNG.
    * **`SetDataForPNGDecoderAtIndex()`**:  Specifically updates the data for individual PNG decoders.
    * **`DecodeDirectory()`**: Reads and parses the ICO file's directory structure.
    * **`DecodeAtIndex()`**: Decodes a specific frame, handling BMP and PNG differently.
    * **`ProcessDirectory()`**:  Parses the main ICO header.
    * **`ProcessDirectoryEntries()`**: Parses the entries within the ICO directory, extracting information about each contained image.
    * **`ReadDirectoryEntry()`**: Reads the data for a single directory entry.
    * **`ImageTypeAtIndex()`**: Determines whether a frame is a BMP or PNG.

5. **Identify Connections to Web Technologies:**

    * **`MimeType()` (`image/vnd.microsoft.icon`):** This directly relates to how web browsers identify and handle ICO files within HTML (`<img>` tags, `<link rel="icon">`, CSS `url()` for backgrounds/cursors).
    * **`FilenameExtension()` (`ico`):**  While not directly used in the rendering process, it's a common way users and systems identify ICO files.
    * **Icons/Cursors:** The entire purpose of ICO files is to provide icons for web pages (favicons, taskbar icons) and cursors. The `HotSpot` methods are a clear indicator of cursor functionality.
    * **Underlying Rendering:** While not directly interacting with JavaScript, the *decoded image data* produced by this class is eventually used by the Blink rendering engine to display the image on the web page. JavaScript can manipulate the `<img>` tag or CSS properties that cause these images to be loaded and rendered.

6. **Logical Reasoning Examples:** Focus on places where the code makes decisions:

    * **`CompareEntries()`:**  The logic for choosing the best icon based on size and bit-depth is a prime example of a defined rule.
    * **`DecodeFrameCount()` and incomplete data:** The code handles the case where the ICO file is partially downloaded, returning the number of *complete* frames.
    * **`ImageTypeAtIndex()`:**  The "magic number" check (`strncmp(data, "\x89PNG", 4)`) demonstrates a clear rule for identifying the image format.
    * **Handling of zero width/height in `ReadDirectoryEntry()`**: The code explicitly handles the special case where width or height is 0, interpreting it as 256.

7. **Common Usage Errors:** Think about how developers might misuse image loading or what problems could arise:

    * **Invalid or Corrupt ICO Files:** The decoder needs to handle cases where the input data doesn't conform to the ICO format. The `SetFailed()` method is an indicator of this.
    * **Large ICO Files:** The `max_decoded_bytes` parameter suggests a concern about memory usage. Trying to load very large or complex ICO files could lead to performance issues or even crashes if memory limits are exceeded.
    * **Incorrect Mime Type:** While the decoder itself doesn't directly handle this, serving an ICO file with the wrong MIME type could prevent the browser from correctly interpreting it.

8. **Structure the Output:** Organize the findings into clear categories (Functionality, Relationship to Web Technologies, Logical Reasoning, User/Programming Errors) as requested. Use bullet points and code snippets where appropriate to make the explanation clear and concise. For logical reasoning, explicitly state the "input" (condition) and "output" (result).

9. **Review and Refine:** Read through the generated explanation to ensure accuracy, clarity, and completeness. Make sure the examples are relevant and easy to understand. For instance, initially, I might have just said "handles errors," but expanding that to "invalid or corrupt ICO files" makes it more specific. Similarly, instead of just saying "chooses the best icon," detailing the size and bit-depth logic is much better.
这个C++源代码文件 `ico_image_decoder.cc` 实现了 Chromium Blink 引擎中用于解码 ICO (Windows Icon) 和 CUR (Windows Cursor) 图像格式的功能。以下是其主要功能和相关说明：

**主要功能：**

1. **ICO 和 CUR 文件解码:**  `ICOImageDecoder` 类的核心职责是解析 ICO 和 CUR 文件的二进制数据，将其解码成可供浏览器渲染的位图图像。

2. **处理多个图像条目:** ICO 文件可以包含多个不同尺寸和颜色深度的图像版本。`ICOImageDecoder` 能够解析文件中的目录，识别并存储这些不同的图像条目。

3. **支持 BMP 和 PNG 编码:**  ICO 文件中的每个图像条目可以是 BMP (Bitmap) 格式或 PNG (Portable Network Graphics) 格式。`ICOImageDecoder` 内部使用了 `BMPImageReader` 和 `PNGImageDecoder` 来处理这两种不同的编码方式。

4. **选择最佳图像:** 当 ICO 文件包含多个图像时，`ICOImageDecoder` 会根据一定的规则（尺寸更大、位深更高）选择最合适的图像进行解码和显示。`CompareEntries` 函数实现了这个比较逻辑。

5. **提取图像尺寸和帧数:**  可以快速获取 ICO 文件中图像的尺寸（宽度和高度）以及包含的帧数（对于包含多个图像条目的 ICO 文件）。

6. **处理光标热点 (Hotspot):** 对于 CUR 文件（光标文件），`ICOImageDecoder` 能够解析并提取光标的热点坐标，这决定了鼠标点击时的实际作用位置。

7. **增量解码:** `ICOImageDecoder` 支持增量解码，即可以随着数据接收逐步解码图像，这对于网络加载大型 ICO 文件很有用。

8. **错误处理:**  包含了错误处理机制，例如当文件格式不正确或数据不完整时，会将解码状态设置为失败。

**与 JavaScript, HTML, CSS 的关系：**

`ICOImageDecoder` 位于渲染引擎的底层，负责图像数据的解码。解码后的图像数据会被传递到渲染流水线的后续阶段，最终在浏览器中显示出来。它与 JavaScript、HTML 和 CSS 的关系体现在以下几个方面：

* **HTML `<img>` 标签和 `<link rel="icon">`:**  当 HTML 中使用 `<img>` 标签加载 ICO 文件作为图片，或者使用 `<link rel="icon">` 加载 ICO 文件作为网站图标（favicon）时，浏览器会调用 `ICOImageDecoder` 来解码这些 ICO 文件。

   **举例说明 (HTML):**
   ```html
   <img src="my-icon.ico" alt="My Icon">
   <link rel="icon" href="favicon.ico" type="image/vnd.microsoft.icon">
   ```
   在这个例子中，浏览器会使用 `ICOImageDecoder` 来解码 `my-icon.ico` 和 `favicon.ico` 文件，以便在页面上显示图标。`type="image/vnd.microsoft.icon"`  明确指定了 MIME 类型，浏览器会据此选择合适的解码器。

* **CSS `background-image` 和 `cursor` 属性:** CSS 可以使用 ICO 文件作为元素的背景图像或鼠标光标。

   **举例说明 (CSS):**
   ```css
   .my-element {
     background-image: url("background.ico");
   }

   .interactive-element {
     cursor: url("my-cursor.cur"), auto;
   }
   ```
   当浏览器遇到这样的 CSS 规则时，会使用 `ICOImageDecoder` 来解码 `background.ico` 或 `my-cursor.cur` 文件。对于光标文件，解码器还会提取热点信息。

* **JavaScript 操作 DOM 和 CSSOM:** JavaScript 可以动态创建 `<img>` 元素或者修改元素的 CSS 样式，从而间接地触发 ICO 文件的加载和解码。

   **举例说明 (JavaScript):**
   ```javascript
   const icon = document.createElement('img');
   icon.src = 'dynamic-icon.ico';
   document.body.appendChild(icon);
   ```
   这段 JavaScript 代码会创建一个新的 `<img>` 元素，并将其 `src` 属性设置为一个 ICO 文件。浏览器会使用 `ICOImageDecoder` 来解码这个文件。

**逻辑推理示例：**

假设输入为一个包含两个 ICO 图像条目的文件，一个尺寸为 16x16，位深 8；另一个尺寸为 32x32，位深 32。

* **假设输入 (ICO 文件数据):**
    * 目录信息指示存在两个图像条目。
    * 条目 1 信息：宽度=16，高度=16，位深=8，偏移量=X1，大小=S1
    * 条目 2 信息：宽度=32，高度=32，位深=32，偏移量=X2，大小=S2
    * 从偏移量 X1 开始是 16x16 像素的图像数据。
    * 从偏移量 X2 开始是 32x32 像素的图像数据。

* **逻辑推理 (基于 `CompareEntries` 函数):**
    * `a_entry_area` (条目 1) = 16 * 16 = 256
    * `b_entry_area` (条目 2) = 32 * 32 = 1024
    * 由于 `a_entry_area` < `b_entry_area`，因此认为条目 2 比条目 1 更优。

* **输出 (选择的图像):**
    * `ICOImageDecoder` 会选择尺寸为 32x32，位深为 32 的图像进行解码和显示。最终 `Size()` 方法会返回 `gfx::Size(32, 32)`。

**用户或编程常见的使用错误：**

1. **提供无效的 ICO 文件:** 用户可能会提供一个损坏的或者不符合 ICO/CUR 文件格式的文件。
   * **后果:** `ICOImageDecoder` 在 `ProcessDirectory()` 或 `ProcessDirectoryEntries()` 阶段可能会检测到文件格式错误，调用 `SetFailed()`，导致图像解码失败，浏览器可能显示占位符或者无法加载图像。

2. **MIME 类型设置错误:**  服务器在提供 ICO 文件时，如果设置了错误的 MIME 类型（例如 `image/png`），浏览器可能不会选择 `ICOImageDecoder` 来处理，或者解码过程可能出错。
   * **后果:** 浏览器可能无法正确解析图像数据。

3. **加载过大的 ICO 文件:**  如果 ICO 文件包含非常多的图像条目或者非常大的单个图像，可能会消耗过多的内存和 CPU 资源，导致页面性能下降甚至崩溃。
   * **代码中的防范措施:** `max_decoded_bytes` 参数可以限制解码的最大字节数，防止无限消耗内存。

4. **假设所有 ICO 都是 BMP 或 PNG:**  虽然当前实现主要处理 BMP 和 PNG 格式的 ICO 内容，但理论上 ICO 文件可以包含其他格式的图像数据。如果开发者假设所有 ICO 都是 BMP 或 PNG 并进行特定处理，可能会导致兼容性问题。
   * **代码中的处理:** `ImageTypeAtIndex()` 函数用于检测当前图像条目是 BMP 还是 PNG，避免了盲目假设。

5. **忽略光标热点信息:** 对于光标文件，如果没有正确处理 `HotSpot()` 方法返回的热点信息，可能会导致鼠标点击行为不符合预期。

总而言之，`ico_image_decoder.cc` 是 Chromium 渲染引擎中一个关键的组件，它使得浏览器能够理解和显示 Windows 平台常见的图标和光标文件，直接影响了网页的视觉呈现和用户交互体验。

Prompt: 
```
这是目录为blink/renderer/platform/image-decoders/ico/ico_image_decoder.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2008 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/image-decoders/ico/ico_image_decoder.h"

#include <algorithm>

#include "third_party/blink/renderer/platform/image-decoders/png/png_decoder_factory.h"

namespace blink {

// Number of bits in .ICO/.CUR used to store the directory and its entries,
// respectively (doesn't match sizeof values for member structs since we omit
// some fields).
static const wtf_size_t kSizeOfDirectory = 6;
static const wtf_size_t kSizeOfDirEntry = 16;

ICOImageDecoder::ICOImageDecoder(AlphaOption alpha_option,
                                 ColorBehavior color_behavior,
                                 wtf_size_t max_decoded_bytes)
    : ImageDecoder(alpha_option,
                   ImageDecoder::kDefaultBitDepth,
                   color_behavior,
                   cc::AuxImage::kDefault,
                   max_decoded_bytes) {}

ICOImageDecoder::~ICOImageDecoder() = default;

String ICOImageDecoder::FilenameExtension() const {
  return "ico";
}

const AtomicString& ICOImageDecoder::MimeType() const {
  DEFINE_STATIC_LOCAL(const AtomicString, ico_mime_type,
                      ("image/vnd.microsoft.icon"));
  return ico_mime_type;
}

void ICOImageDecoder::OnSetData(scoped_refptr<SegmentReader> data) {
  fast_reader_.SetData(data);

  for (BMPReaders::iterator i(bmp_readers_.begin()); i != bmp_readers_.end();
       ++i) {
    if (*i) {
      (*i)->SetData(data);
    }
  }
  for (wtf_size_t i = 0; i < png_decoders_.size(); ++i) {
    SetDataForPNGDecoderAtIndex(i);
  }
}

gfx::Size ICOImageDecoder::Size() const {
  return frame_size_.IsEmpty() ? ImageDecoder::Size() : frame_size_;
}

gfx::Size ICOImageDecoder::FrameSizeAtIndex(wtf_size_t index) const {
  return (index && (index < dir_entries_.size())) ? dir_entries_[index].size_
                                                  : Size();
}

bool ICOImageDecoder::SetSize(unsigned width, unsigned height) {
  // The size calculated inside the BMPImageReader had better match the one in
  // the icon directory.
  return frame_size_.IsEmpty()
             ? ImageDecoder::SetSize(width, height)
             : ((gfx::Size(width, height) == frame_size_) || SetFailed());
}

bool ICOImageDecoder::FrameIsReceivedAtIndex(wtf_size_t index) const {
  if (index >= dir_entries_.size()) {
    return false;
  }

  SECURITY_DCHECK(data_);
  const IconDirectoryEntry& dir_entry = dir_entries_[index];
  return (dir_entry.image_offset_ + dir_entry.byte_size_) <= data_->size();
}

bool ICOImageDecoder::SetFailed() {
  bmp_readers_.clear();
  png_decoders_.clear();
  return ImageDecoder::SetFailed();
}

bool ICOImageDecoder::HotSpot(gfx::Point& hot_spot) const {
  // When unspecified, the default frame is always frame 0. This is consistent
  // with BitmapImage, where CurrentFrame() starts at 0 and only increases when
  // animation is requested.
  return HotSpotAtIndex(0, hot_spot);
}

bool ICOImageDecoder::HotSpotAtIndex(wtf_size_t index,
                                     gfx::Point& hot_spot) const {
  if (index >= dir_entries_.size() || file_type_ != CURSOR) {
    return false;
  }

  hot_spot = dir_entries_[index].hot_spot_;
  return true;
}

// static
bool ICOImageDecoder::CompareEntries(const IconDirectoryEntry& a,
                                     const IconDirectoryEntry& b) {
  // Larger icons are better.  After that, higher bit-depth icons are better.
  const int a_entry_area = a.size_.width() * a.size_.height();
  const int b_entry_area = b.size_.width() * b.size_.height();
  return (a_entry_area == b_entry_area) ? (a.bit_count_ > b.bit_count_)
                                        : (a_entry_area > b_entry_area);
}

void ICOImageDecoder::DecodeSize() {
  Decode(0, true);
}

wtf_size_t ICOImageDecoder::DecodeFrameCount() {
  DecodeSize();

  // If DecodeSize() fails, return the existing number of frames.  This way
  // if we get halfway through the image before decoding fails, we won't
  // suddenly start reporting that the image has zero frames.
  if (Failed() || !data_) {
    return frame_buffer_cache_.size();
  }

  // If the file is incomplete, return the length of the sequence of completely
  // received frames.  We don't do this when the file is fully received, since
  // some ICOs have entries whose claimed offset + size extends past the end of
  // the file, and we still want to display these if they don't trigger decoding
  // failures elsewhere.
  if (!IsAllDataReceived()) {
    for (wtf_size_t i = 0; i < dir_entries_.size(); ++i) {
      const IconDirectoryEntry& dir_entry = dir_entries_[i];
      if ((dir_entry.image_offset_ + dir_entry.byte_size_) > data_->size()) {
        return i;
      }
    }
  }
  return dir_entries_.size();
}

void ICOImageDecoder::Decode(wtf_size_t index) {
  Decode(index, false);
}

void ICOImageDecoder::SetDataForPNGDecoderAtIndex(wtf_size_t index) {
  if (!png_decoders_[index]) {
    return;
  }

  png_decoders_[index]->SetData(data_.get(), IsAllDataReceived());
}

void ICOImageDecoder::Decode(wtf_size_t index, bool only_size) {
  if (Failed() || !data_) {
    return;
  }

  // Defensively clear the FastSharedBufferReader's cache, as another caller
  // may have called SharedBuffer::MergeSegmentsIntoBuffer().
  fast_reader_.ClearCache();

  // If we couldn't decode the image but we've received all the data, decoding
  // has failed.
  if ((!DecodeDirectory() || (!only_size && !DecodeAtIndex(index))) &&
      IsAllDataReceived()) {
    SetFailed();
    // If we're done decoding this frame, we don't need the BMPImageReader or
    // PNGImageDecoder anymore.  (If we failed, these have already been
    // cleared.)
  } else if ((frame_buffer_cache_.size() > index) &&
             (frame_buffer_cache_[index].GetStatus() ==
              ImageFrame::kFrameComplete)) {
    bmp_readers_[index].reset();
    png_decoders_[index].reset();
  }
}

bool ICOImageDecoder::DecodeDirectory() {
  // Read and process directory.
  if ((decoded_offset_ < kSizeOfDirectory) && !ProcessDirectory()) {
    return false;
  }

  // Read and process directory entries.
  return (decoded_offset_ >=
          (kSizeOfDirectory + (dir_entries_count_ * kSizeOfDirEntry))) ||
         ProcessDirectoryEntries();
}

bool ICOImageDecoder::DecodeAtIndex(wtf_size_t index) {
  SECURITY_DCHECK(index < dir_entries_.size());
  const IconDirectoryEntry& dir_entry = dir_entries_[index];
  const ImageType image_type = ImageTypeAtIndex(index);
  if (image_type == kUnknown) {
    return false;  // Not enough data to determine image type yet.
  }

  if (image_type == BMP) {
    if (!bmp_readers_[index]) {
      bmp_readers_[index] = std::make_unique<BMPImageReader>(
          this, dir_entry.image_offset_, 0, true);
      bmp_readers_[index]->SetData(data_);
    }
    // Update the pointer to the buffer as it could change after
    // frame_buffer_cache_.resize().
    bmp_readers_[index]->SetBuffer(&frame_buffer_cache_[index]);
    frame_size_ = dir_entry.size_;
    bool result = bmp_readers_[index]->DecodeBMP(false);
    frame_size_ = gfx::Size();
    return result;
  }

  if (!png_decoders_[index]) {
    AlphaOption alpha_option =
        premultiply_alpha_ ? kAlphaPremultiplied : kAlphaNotPremultiplied;
    png_decoders_[index] = CreatePngImageDecoder(
        alpha_option, ImageDecoder::kDefaultBitDepth, color_behavior_,
        max_decoded_bytes_, dir_entry.image_offset_);
    SetDataForPNGDecoderAtIndex(index);
  }
  auto* png_decoder = png_decoders_[index].get();
  if (png_decoder->IsSizeAvailable()) {
    // Fail if the size the PNGImageDecoder calculated does not match the size
    // in the directory.
    if (png_decoder->Size() != dir_entry.size_) {
      return SetFailed();
    }

    png_decoder->SetMemoryAllocator(frame_buffer_cache_[index].GetAllocator());
    const auto* frame = png_decoder->DecodeFrameBufferAtIndex(0);
    png_decoder->SetMemoryAllocator(nullptr);

    if (frame) {
      frame_buffer_cache_[index] = *frame;
    }
  }
  if (png_decoder->Failed()) {
    return SetFailed();
  }
  return frame_buffer_cache_[index].GetStatus() == ImageFrame::kFrameComplete;
}

bool ICOImageDecoder::ProcessDirectory() {
  // Read directory.
  SECURITY_DCHECK(data_);
  DCHECK(!decoded_offset_);
  if (data_->size() < kSizeOfDirectory) {
    return false;
  }
  const uint16_t file_type = ReadUint16(2);
  dir_entries_count_ = ReadUint16(4);
  decoded_offset_ = kSizeOfDirectory;

  // See if this is an icon filetype we understand, and make sure we have at
  // least one entry in the directory.
  if (((file_type != ICON) && (file_type != CURSOR)) || (!dir_entries_count_)) {
    return SetFailed();
  }

  file_type_ = static_cast<FileType>(file_type);
  return true;
}

bool ICOImageDecoder::ProcessDirectoryEntries() {
  // Read directory entries.
  SECURITY_DCHECK(data_);
  DCHECK_EQ(decoded_offset_, kSizeOfDirectory);
  if ((decoded_offset_ > data_->size()) ||
      ((data_->size() - decoded_offset_) <
       (dir_entries_count_ * kSizeOfDirEntry))) {
    return false;
  }

  // Enlarge member vectors to hold all the entries.
  dir_entries_.resize(dir_entries_count_);
  bmp_readers_.resize(dir_entries_count_);
  png_decoders_.resize(dir_entries_count_);

  for (auto& dir_entrie : dir_entries_) {
    dir_entrie = ReadDirectoryEntry();  // Updates decoded_offset_.
  }

  // Make sure the specified image offsets are past the end of the directory
  // entries.
  for (IconDirectoryEntries::iterator i(dir_entries_.begin());
       i != dir_entries_.end(); ++i) {
    if (i->image_offset_ < decoded_offset_) {
      return SetFailed();
    }
  }

  // Arrange frames in decreasing quality order.
  std::sort(dir_entries_.begin(), dir_entries_.end(), CompareEntries);

  // The image size is the size of the largest entry.
  const IconDirectoryEntry& dir_entry = dir_entries_.front();
  // Technically, this next call shouldn't be able to fail, since the width
  // and height here are each <= 256, and |frame_size_| is empty.
  return SetSize(static_cast<unsigned>(dir_entry.size_.width()),
                 static_cast<unsigned>(dir_entry.size_.height()));
}

ICOImageDecoder::IconDirectoryEntry ICOImageDecoder::ReadDirectoryEntry() {
  // Read icon data.
  // The following calls to ReadUint8() return a uint8_t, which is appropriate
  // because that's the on-disk type of the width and height values.  Storing
  // them in ints (instead of matching uint8_ts) is so we can record dimensions
  // of size 256 (which is what a zero byte really means).
  int width = ReadUint8(0);
  if (!width) {
    width = 256;
  }
  int height = ReadUint8(1);
  if (!height) {
    height = 256;
  }
  IconDirectoryEntry entry;
  entry.size_ = gfx::Size(width, height);
  if (file_type_ == CURSOR) {
    entry.bit_count_ = 0;
    entry.hot_spot_ = gfx::Point(ReadUint16(4), ReadUint16(6));
  } else {
    entry.bit_count_ = ReadUint16(6);
    entry.hot_spot_ = gfx::Point();
  }
  entry.byte_size_ = ReadUint32(8);
  entry.image_offset_ = ReadUint32(12);

  // Some icons don't have a bit depth, only a color count.  Convert the
  // color count to the minimum necessary bit depth.  It doesn't matter if
  // this isn't quite what the bitmap info header says later, as we only use
  // this value to determine which icon entry is best.
  if (!entry.bit_count_) {
    int color_count = ReadUint8(2);
    if (!color_count) {
      color_count = 256;  // Vague in the spec, needed by real-world icons.
    }
    for (--color_count; color_count; color_count >>= 1) {
      ++entry.bit_count_;
    }
  }

  decoded_offset_ += kSizeOfDirEntry;
  return entry;
}

ICOImageDecoder::ImageType ICOImageDecoder::ImageTypeAtIndex(wtf_size_t index) {
  // Check if this entry is a BMP or a PNG; we need 4 bytes to check the magic
  // number.
  SECURITY_DCHECK(data_);
  SECURITY_DCHECK(index < dir_entries_.size());
  const uint32_t image_offset = dir_entries_[index].image_offset_;
  if ((image_offset > data_->size()) || ((data_->size() - image_offset) < 4)) {
    return kUnknown;
  }
  char buffer[4];
  const char* data = fast_reader_.GetConsecutiveData(image_offset, 4, buffer);
  return strncmp(data, "\x89PNG", 4) ? BMP : PNG;
}

}  // namespace blink

"""

```